use std::collections::{HashMap, HashSet};
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, Once, OnceLock};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use crossbeam_channel::bounded;
use md5::Md5;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
#[cfg(unix)]
use signal_hook::consts::signal::{SIGINT, SIGTERM, SIGUSR1};
use yara_x::{Compiler as YaraCompiler, Rules as YaraRules, Scanner as YaraScanner};

use crate::candidate::query_plan::{
    FixedLiteralMatchPlan, evaluate_fixed_literal_match, fixed_literal_match_plan,
};
#[cfg(test)]
use crate::candidate::write_candidate_shard_count;
use crate::candidate::{
    BoundedCache, CandidateConfig, CandidateStore, GramSizes, HLL_DEFAULT_PRECISION,
    candidate_shard_index, candidate_shard_root, choose_filter_bytes_for_file_size,
    compile_query_plan_from_file_with_gram_sizes, derive_document_bloom_hash_count,
    encode_grams_delta_u64, estimate_unique_grams_for_size_hll, read_candidate_shard_count,
    scan_file_features_with_gram_sizes,
};
use crate::perf;
use crate::rpc::{
    self, CandidateDocumentWire, ClientConfig as RpcClientConfig, ServerConfig as RpcServerConfig,
    TgsdbClient,
};
use crate::{Result, TgsError};

pub const DEFAULT_CANDIDATE_ROOT: &str = "candidate_db";
pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: u16 = 17653;
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:17653";
pub const DEFAULT_RPC_TIMEOUT: f64 = 30.0;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_SEARCH_RESULT_CHUNK_SIZE: usize = 1024;
pub const DEFAULT_FILE_READ_CHUNK_SIZE: usize = 1024 * 1024;
pub const DEFAULT_MEMORY_BUDGET_GB: u64 = 16;
pub const DEFAULT_MEMORY_BUDGET_BYTES: u64 = DEFAULT_MEMORY_BUDGET_GB * 1024 * 1024 * 1024;
pub const DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR: u64 = 4;
const ESTIMATED_INDEX_QUEUE_ITEM_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INDEX_QUEUE_CAPACITY: usize = 256;

struct ServeSignalFlags {
    shutdown: Arc<AtomicBool>,
    status_dump: Arc<AtomicBool>,
}

fn serve_signal_flags() -> Result<ServeSignalFlags> {
    static SHUTDOWN_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    static STATUS_FLAG: OnceLock<Arc<AtomicBool>> = OnceLock::new();
    static INSTALL: Once = Once::new();
    static INSTALL_ERROR: OnceLock<String> = OnceLock::new();
    let shutdown = SHUTDOWN_FLAG
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone();
    let status_dump = STATUS_FLAG
        .get_or_init(|| Arc::new(AtomicBool::new(false)))
        .clone();
    let shutdown_handler = shutdown.clone();
    let status_dump_handler = status_dump.clone();
    INSTALL.call_once(|| {
        #[cfg(unix)]
        {
            let result = (|| -> std::result::Result<(), String> {
                signal_hook::flag::register(SIGINT, shutdown_handler.clone())
                    .map_err(|err| err.to_string())?;
                signal_hook::flag::register(SIGTERM, shutdown_handler.clone())
                    .map_err(|err| err.to_string())?;
                signal_hook::flag::register(SIGUSR1, status_dump_handler.clone())
                    .map_err(|err| err.to_string())?;
                Ok(())
            })();
            if let Err(err) = result {
                let _ = INSTALL_ERROR.set(err);
            }
        }
        #[cfg(not(unix))]
        {
            if let Err(err) = ctrlc::set_handler(move || {
                shutdown_handler.store(true, Ordering::SeqCst);
            }) {
                let _ = INSTALL_ERROR.set(err.to_string());
            }
        }
    });
    if let Some(err) = INSTALL_ERROR.get() {
        return Err(TgsError::from(format!(
            "failed to install shutdown handler: {err}"
        )));
    }
    shutdown.store(false, Ordering::SeqCst);
    status_dump.store(false, Ordering::SeqCst);
    Ok(ServeSignalFlags {
        shutdown,
        status_dump,
    })
}

fn default_ingest_workers_for(cpus: usize) -> usize {
    let cpus = cpus.max(1);
    if cpus < 8 {
        (cpus / 2).max(1)
    } else {
        ((cpus * 3) / 4).max(1)
    }
}

fn default_ingest_workers() -> usize {
    default_ingest_workers_for(
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1),
    )
}

fn default_search_workers_for(cpus: usize) -> usize {
    (cpus.max(1) / 4).max(1)
}

fn default_search_workers() -> usize {
    default_search_workers_for(
        std::thread::available_parallelism()
            .map(|value| value.get())
            .unwrap_or(1),
    )
}

#[derive(Debug, Clone, clap::Args)]
struct ClientConnectionArgs {
    #[arg(
        long = "addr",
        env = "YAYA_ADDR",
        default_value = DEFAULT_RPC_ADDR,
        help = "Server address as host:port."
    )]
    addr: String,
    #[arg(long = "timeout", default_value_t = DEFAULT_RPC_TIMEOUT, help = "Connection/read timeout in seconds.")]
    timeout: f64,
}

impl ClientConnectionArgs {
    fn host_port(&self) -> Result<(String, u16)> {
        parse_host_port(&self.addr)
    }
}

fn parse_host_port(value: &str) -> Result<(String, u16)> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(TgsError::from("addr must be a non-empty host:port value."));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port_text) = rest
            .split_once("]:")
            .ok_or_else(|| TgsError::from("addr must use [ipv6]:port for IPv6 addresses."))?;
        let port = port_text
            .parse::<u16>()
            .map_err(|_| TgsError::from("addr port must be a valid u16 value."))?;
        return Ok((host.to_owned(), port));
    }
    let (host, port_text) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| TgsError::from("addr must be formatted as host:port."))?;
    if host.is_empty() {
        return Err(TgsError::from("addr host must not be empty."));
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| TgsError::from("addr port must be a valid u16 value."))?;
    Ok((host.to_owned(), port))
}

fn resolved_file_path(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(TgsError::from)
}

fn current_process_memory_kb() -> (usize, usize) {
    let status = fs::read_to_string("/proc/self/status").unwrap_or_default();
    let mut current_rss_kb = 0usize;
    let mut peak_rss_kb = 0usize;
    for line in status.lines() {
        if let Some(value) = line.strip_prefix("VmRSS:") {
            current_rss_kb = value
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<usize>().ok())
                .unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("VmHWM:") {
            peak_rss_kb = value
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<usize>().ok())
                .unwrap_or(0);
        }
    }
    (current_rss_kb, peak_rss_kb)
}

fn available_memory_bytes() -> Option<u64> {
    let meminfo = fs::read_to_string("/proc/meminfo").ok()?;
    for line in meminfo.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb = rest
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<u64>().ok())?;
            return Some(kb.saturating_mul(1024));
        }
    }
    None
}

fn effective_memory_budget_bytes(configured_budget_bytes: u64) -> u64 {
    if configured_budget_bytes == 0 {
        return 0;
    }
    match available_memory_bytes() {
        Some(available) if available > 0 => {
            configured_budget_bytes.min(available.saturating_mul(3) / 4)
        }
        _ => configured_budget_bytes,
    }
}

fn index_queue_capacity(memory_budget_bytes: u64, workers: usize) -> usize {
    let workers = workers.max(1);
    let worker_floor = workers.saturating_mul(2).max(4);
    if memory_budget_bytes == 0 {
        return worker_floor.min(MAX_INDEX_QUEUE_CAPACITY);
    }
    let budget_capacity = usize::try_from(memory_budget_bytes / ESTIMATED_INDEX_QUEUE_ITEM_BYTES)
        .unwrap_or(usize::MAX);
    budget_capacity.clamp(worker_floor, MAX_INDEX_QUEUE_CAPACITY)
}

fn server_memory_kb(connection: &ClientConnectionArgs) -> Result<Option<(u64, u64)>> {
    let stats = rpc_client(connection).candidate_stats()?;
    let current = stats.get("current_rss_kb").and_then(|value| value.as_u64());
    let peak = stats.get("peak_rss_kb").and_then(|value| value.as_u64());
    Ok(match (current, peak) {
        (Some(current), Some(peak)) => Some((current, peak)),
        _ => None,
    })
}

#[cfg(test)]
fn path_identity_sha256(path: &Path) -> Result<[u8; 32]> {
    let canonical = resolved_file_path(path)?;
    let mut digest = Sha256::new();
    digest.update(canonical.to_string_lossy().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.finalize());
    Ok(out)
}

fn normalize_identity_digest(kind: &str, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"yaya-identity\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.finalize());
    out
}

fn sha256_file(path: &Path, chunk_size: usize) -> Result<[u8; 32]> {
    if chunk_size == 0 {
        return Err(TgsError::from("chunk_size must be a positive integer."));
    }

    let mut digest = Sha256::new();
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.finalize());
    Ok(out)
}

fn md5_file(path: &Path, chunk_size: usize) -> Result<[u8; 16]> {
    if chunk_size == 0 {
        return Err(TgsError::from("chunk_size must be a positive integer."));
    }

    let mut digest = Md5::new();
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    let mut out = [0u8; 16];
    out.copy_from_slice(&digest.finalize());
    Ok(out)
}

fn sha1_file(path: &Path, chunk_size: usize) -> Result<[u8; 20]> {
    if chunk_size == 0 {
        return Err(TgsError::from("chunk_size must be a positive integer."));
    }

    let mut digest = Sha1::new();
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    let mut out = [0u8; 20];
    out.copy_from_slice(&digest.finalize());
    Ok(out)
}

fn sha512_file(path: &Path, chunk_size: usize) -> Result<[u8; 64]> {
    if chunk_size == 0 {
        return Err(TgsError::from("chunk_size must be a positive integer."));
    }

    let mut digest = Sha512::new();
    let mut file = fs::File::open(path)?;
    let mut buf = vec![0u8; chunk_size];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        digest.update(&buf[..n]);
    }
    let mut out = [0u8; 64];
    out.copy_from_slice(&digest.finalize());
    Ok(out)
}

#[cfg(test)]
fn decode_sha256_hex(value: &str) -> Result<[u8; 32]> {
    let text = value.trim().to_ascii_lowercase();
    if text.len() != 64 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(TgsError::from(
            "sha256 must be exactly 64 hexadecimal characters.",
        ));
    }
    let mut out = [0u8; 32];
    hex::decode_to_slice(text, &mut out)?;
    Ok(out)
}

fn decode_exact_hex<const N: usize>(value: &str, label: &str) -> Result<[u8; N]> {
    let text = value.trim().to_ascii_lowercase();
    if text.len() != N * 2 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(TgsError::from(format!(
            "{label} must be exactly {} hexadecimal characters.",
            N * 2
        )));
    }
    let mut out = [0u8; N];
    hex::decode_to_slice(text, &mut out)?;
    Ok(out)
}

fn identity_from_file(
    path: &Path,
    chunk_size: usize,
    id_source: CandidateIdSource,
) -> Result<[u8; 32]> {
    match id_source {
        CandidateIdSource::Sha256 => sha256_file(path, chunk_size),
        CandidateIdSource::Md5 => Ok(normalize_identity_digest(
            "md5",
            &md5_file(path, chunk_size)?,
        )),
        CandidateIdSource::Sha1 => Ok(normalize_identity_digest(
            "sha1",
            &sha1_file(path, chunk_size)?,
        )),
        CandidateIdSource::Sha512 => Ok(normalize_identity_digest(
            "sha512",
            &sha512_file(path, chunk_size)?,
        )),
    }
}

fn identity_from_hex(value: &str, id_source: CandidateIdSource) -> Result<[u8; 32]> {
    match id_source {
        CandidateIdSource::Sha256 => decode_exact_hex::<32>(value, "sha256"),
        CandidateIdSource::Md5 => Ok(normalize_identity_digest(
            "md5",
            &decode_exact_hex::<16>(value, "md5")?,
        )),
        CandidateIdSource::Sha1 => Ok(normalize_identity_digest(
            "sha1",
            &decode_exact_hex::<20>(value, "sha1")?,
        )),
        CandidateIdSource::Sha512 => Ok(normalize_identity_digest(
            "sha512",
            &decode_exact_hex::<64>(value, "sha512")?,
        )),
    }
}

#[cfg(test)]
fn resolve_delete_identity(
    sha256: Option<&str>,
    md5: Option<&str>,
    sha1: Option<&str>,
    sha512: Option<&str>,
    file_path: Option<&str>,
    id_source: CandidateIdSource,
    chunk_size: usize,
) -> Result<String> {
    let mut chosen = None::<[u8; 32]>;
    let mut count = 0usize;
    for (value, source) in [
        (sha256, CandidateIdSource::Sha256),
        (md5, CandidateIdSource::Md5),
        (sha1, CandidateIdSource::Sha1),
        (sha512, CandidateIdSource::Sha512),
    ] {
        if let Some(value) = value {
            count += 1;
            chosen = Some(identity_from_hex(value, source)?);
        }
    }
    if let Some(file_path) = file_path {
        count += 1;
        chosen = Some(identity_from_file(
            Path::new(file_path),
            chunk_size,
            id_source,
        )?);
    }
    if count != 1 {
        return Err(TgsError::from(
            "Provide exactly one of `--sha256`, `--md5`, `--sha1`, `--sha512`, or `--file-path`.",
        ));
    }
    Ok(hex::encode(chosen.expect("chosen identity")))
}

fn sorted_directory_children(path: &Path) -> Result<Vec<PathBuf>> {
    let mut children = fs::read_dir(path)?
        .map(|entry| entry.map(|value| value.path()).map_err(TgsError::from))
        .collect::<Result<Vec<_>>>()?;
    children.sort();
    Ok(children)
}

fn visit_files_recursive(path: &Path, visit: &mut impl FnMut(PathBuf) -> Result<()>) -> Result<()> {
    if path.is_file() {
        visit(path.to_path_buf())?;
        return Ok(());
    }
    if !path.is_dir() {
        return Ok(());
    }
    for child in sorted_directory_children(path)? {
        visit_files_recursive(&child, visit)?;
    }
    Ok(())
}

#[cfg(test)]
fn collect_files_recursive(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    visit_files_recursive(path, &mut |child| {
        out.push(child);
        Ok(())
    })
}

fn count_files_recursive(path: &Path) -> Result<usize> {
    if path.is_file() {
        return Ok(1);
    }
    if !path.is_dir() {
        return Ok(0);
    }
    let mut total = 0usize;
    for child in sorted_directory_children(path)? {
        total = total.saturating_add(count_files_recursive(&child)?);
    }
    Ok(total)
}

fn normalize_input_paths(paths: &[String]) -> Vec<PathBuf> {
    let mut roots = Vec::new();
    for root_path in paths {
        let path = PathBuf::from(root_path);
        if path.exists() {
            roots.push(path);
        } else {
            println!("Skipping missing path: {}", path.display());
        }
    }
    roots.sort();
    roots
}

fn count_input_files(paths: &[PathBuf]) -> Result<usize> {
    let mut total = 0usize;
    for path in paths {
        total = total.saturating_add(count_files_recursive(path)?);
    }
    Ok(total)
}

fn stream_input_files(
    paths: &[PathBuf],
    mut visit: impl FnMut(PathBuf) -> Result<()>,
) -> Result<()> {
    for path in paths {
        visit_files_recursive(path, &mut visit)?;
    }
    Ok(())
}

fn maybe_report_index_progress(
    enabled: bool,
    processed: usize,
    total: usize,
    last_reported: &mut usize,
    last_report_at: &mut Instant,
    force: bool,
) {
    if !enabled || total == 0 {
        return;
    }
    let now = Instant::now();
    let processed_delta = processed.saturating_sub(*last_reported);
    let time_ready = now.duration_since(*last_report_at) >= Duration::from_secs(5);
    if !force && processed_delta < 250 && !time_ready {
        return;
    }
    let percent = (processed as f64 / total as f64) * 100.0;
    eprintln!("progress.index: {percent:.1}% ({processed}/{total})");
    *last_reported = processed;
    *last_report_at = now;
}

fn rpc_client(connection: &ClientConnectionArgs) -> TgsdbClient {
    let (host, port) = connection
        .host_port()
        .expect("client connection addr should parse");
    TgsdbClient::new(RpcClientConfig::new(
        host,
        port,
        Duration::from_secs_f64(connection.timeout.max(0.0)),
        None,
    ))
}

struct RemoteIndexSessionGuard<'a> {
    client: &'a TgsdbClient,
}

impl Drop for RemoteIndexSessionGuard<'_> {
    fn drop(&mut self) {
        let _ = self.client.end_index_session();
    }
}

fn maybe_report_remote_index_session_progress(
    client: &TgsdbClient,
    processed: usize,
    total: usize,
    last_reported: &mut usize,
    last_report_at: &mut Instant,
    force: bool,
) -> Result<()> {
    if total == 0 {
        return Ok(());
    }
    let now = Instant::now();
    let processed_delta = processed.saturating_sub(*last_reported);
    let time_ready = now.duration_since(*last_report_at) >= Duration::from_secs(5);
    if !force && processed_delta < 250 && !time_ready {
        return Ok(());
    }
    client.update_index_session_progress(Some(total), processed, processed)?;
    *last_reported = processed;
    *last_report_at = now;
    Ok(())
}

#[cfg(test)]
fn json_usize(
    stats: &serde_json::Map<String, serde_json::Value>,
    key: &str,
    default: usize,
) -> usize {
    stats
        .get(key)
        .and_then(|value| value.as_u64())
        .map(|value| value as usize)
        .unwrap_or(default)
}

fn json_f64_opt(stats: &serde_json::Map<String, serde_json::Value>, key: &str) -> Option<f64> {
    stats.get(key).and_then(|value| value.as_f64())
}

const INTERNAL_FILTER_BYTES: usize = 2048;
const INTERNAL_FILTER_MIN_BYTES: usize = 1;
const INTERNAL_FILTER_MAX_BYTES: usize = 0;
const INTERNAL_FILTER_SIZE_DIVISOR: usize = 1;
const INTERNAL_BLOOM_HASHES: usize = 7;
const INTERNAL_TIER1_GRAM_BUDGET: usize = 4096;
const INTERNAL_TIER1_GRAM_SAMPLE_MOD: usize = 1;
const INTERNAL_TIER1_GRAM_HASH_SEED: u64 = 1337;

#[derive(Clone, Copy, Debug, PartialEq)]
struct ServerScanPolicy {
    id_source: CandidateIdSource,
    store_path: bool,
    filter_target_fp: Option<f64>,
    gram_sizes: GramSizes,
    memory_budget_bytes: u64,
}

fn server_scan_policy(connection: &ClientConnectionArgs) -> Result<ServerScanPolicy> {
    let stats = rpc_client(connection).candidate_stats()?;
    let gram_sizes = stats
        .get("gram_sizes")
        .and_then(|value| value.as_str())
        .ok_or_else(|| TgsError::from("candidate stats missing gram_sizes"))?;
    let gram_sizes = GramSizes::parse(gram_sizes)?;
    let id_source = CandidateIdSource::parse_config_value(
        stats
            .get("id_source")
            .and_then(|value| value.as_str())
            .unwrap_or("sha256"),
    )?;
    Ok(ServerScanPolicy {
        id_source,
        store_path: stats
            .get("store_path")
            .and_then(|value| value.as_bool())
            .unwrap_or(false),
        filter_target_fp: json_f64_opt(&stats, "filter_target_fp"),
        gram_sizes,
        memory_budget_bytes: stats
            .get("memory_budget_bytes")
            .and_then(|value| value.as_u64())
            .unwrap_or(DEFAULT_MEMORY_BUDGET_BYTES),
    })
}

fn server_identity_source(connection: &ClientConnectionArgs) -> Result<CandidateIdSource> {
    let stats = rpc_client(connection).candidate_stats()?;
    CandidateIdSource::parse_config_value(
        stats
            .get("id_source")
            .and_then(|value| value.as_str())
            .unwrap_or("sha256"),
    )
}

fn detect_digest_identity_source(value: &str) -> Option<CandidateIdSource> {
    let text = value.trim();
    if !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    match text.len() {
        32 => Some(CandidateIdSource::Md5),
        40 => Some(CandidateIdSource::Sha1),
        64 => Some(CandidateIdSource::Sha256),
        128 => Some(CandidateIdSource::Sha512),
        _ => None,
    }
}

fn resolve_delete_value(
    value: &str,
    server_id_source: CandidateIdSource,
    chunk_size: usize,
) -> Result<String> {
    let path = Path::new(value);
    if path.exists() {
        if !path.is_file() {
            return Err(TgsError::from("delete value exists but is not a file."));
        }
        return Ok(hex::encode(identity_from_file(
            path,
            chunk_size,
            server_id_source,
        )?));
    }
    let detected = detect_digest_identity_source(value).ok_or_else(|| {
        TgsError::from(
            "delete value is neither an existing file path nor a valid md5/sha1/sha256/sha512 hex digest.",
        )
    })?;
    if detected != server_id_source {
        return Err(TgsError::from(format!(
            "delete value is a {} digest but the server identity source is {}.",
            detected.as_str(),
            server_id_source.as_str()
        )));
    }
    Ok(hex::encode(identity_from_hex(value, detected)?))
}

fn batch_row_to_wire(row: IndexBatchRow) -> CandidateDocumentWire {
    CandidateDocumentWire {
        sha256: hex::encode(row.sha256),
        file_size: row.file_size,
        bloom_filter_b64: {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(row.bloom_filter)
        },
        gram_count_estimate: row.gram_count_estimate.map(|value| value as i64),
        bloom_hashes: Some(row.bloom_hashes),
        tier2_bloom_filter_b64: Some({
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(row.tier2_bloom_filter)
        }),
        tier2_gram_count_estimate: row.tier2_gram_count_estimate.map(|value| value as i64),
        tier2_bloom_hashes: Some(row.tier2_bloom_hashes),
        grams_delta_b64: Some({
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(encode_grams_delta_u64(row.grams))
        }),
        grams: Vec::new(),
        grams_complete: row.grams_complete,
        effective_diversity: row.effective_diversity,
        external_id: row.external_id,
    }
}

const REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES: usize = DEFAULT_MAX_REQUEST_BYTES - 1024;

fn flush_remote_batch(
    client: &TgsdbClient,
    pending: &mut Vec<CandidateDocumentWire>,
    processed: &mut usize,
) -> Result<()> {
    if pending.is_empty() {
        return Ok(());
    }
    *processed += client.candidate_insert_batch(pending)?.inserted_count;
    pending.clear();
    Ok(())
}

fn push_remote_batch_row(
    client: &TgsdbClient,
    pending: &mut Vec<CandidateDocumentWire>,
    row: CandidateDocumentWire,
    batch_size: usize,
    processed: &mut usize,
) -> Result<()> {
    pending.push(row);
    let payload_size = TgsdbClient::candidate_insert_batch_payload_size(pending)?;
    if payload_size > REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES {
        let row = pending
            .pop()
            .ok_or_else(|| TgsError::from("remote ingest batch unexpectedly empty"))?;
        flush_remote_batch(client, pending, processed)?;
        pending.push(row);
        let single_payload_size = TgsdbClient::candidate_insert_batch_payload_size(pending)?;
        if single_payload_size > REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES {
            return Err(TgsError::from(format!(
                "single document insert request exceeds payload limit ({} bytes)",
                single_payload_size
            )));
        }
    }
    if pending.len() >= batch_size {
        flush_remote_batch(client, pending, processed)?;
    }
    Ok(())
}

fn flush_local_pending_rows(
    stores: &mut [CandidateStore],
    pending: &mut Vec<IndexBatchRow>,
    processed: &mut usize,
    submit_time: &mut Duration,
    show_progress: bool,
    total_files: usize,
    last_progress_reported: &mut usize,
    last_progress_at: &mut Instant,
) -> Result<()> {
    for row in pending.drain(..) {
        let started_submit = Instant::now();
        let shard_idx = candidate_shard_index(&row.sha256, stores.len());
        let _ = stores[shard_idx].insert_document(
            row.sha256,
            row.file_size,
            row.gram_count_estimate,
            Some(row.bloom_hashes),
            row.tier2_gram_count_estimate,
            Some(row.tier2_bloom_hashes),
            row.filter_bytes,
            &row.bloom_filter,
            row.tier2_filter_bytes,
            &row.tier2_bloom_filter,
            &row.grams,
            row.grams_complete,
            row.effective_diversity,
            row.external_id,
            true,
        )?;
        *submit_time += started_submit.elapsed();
        *processed += 1;
        maybe_report_index_progress(
            show_progress,
            *processed,
            total_files,
            last_progress_reported,
            last_progress_at,
            false,
        );
    }
    Ok(())
}

fn flush_remote_pending_rows(
    client: &TgsdbClient,
    pending: &mut Vec<CandidateDocumentWire>,
    processed: &mut usize,
    submit_time: &mut Duration,
    show_progress: bool,
    total_files: usize,
    last_progress_reported: &mut usize,
    last_progress_at: &mut Instant,
) -> Result<()> {
    let started_submit = Instant::now();
    flush_remote_batch(client, pending, processed)?;
    *submit_time += started_submit.elapsed();
    maybe_report_index_progress(
        show_progress,
        *processed,
        total_files,
        last_progress_reported,
        last_progress_at,
        false,
    );
    Ok(())
}

fn store_config_from_parts(
    root: PathBuf,
    id_source: CandidateIdSource,
    store_path: bool,
    filter_target_fp: f64,
    tier2_gram_size: usize,
    tier1_gram_size: usize,
    compaction_idle_cooldown_s: f64,
) -> CandidateConfig {
    CandidateConfig {
        root,
        id_source: id_source.as_str().to_owned(),
        store_path,
        tier2_gram_size,
        tier1_gram_size,
        filter_target_fp: Some(filter_target_fp),
        compaction_idle_cooldown_s: compaction_idle_cooldown_s.max(0.0),
        ..CandidateConfig::default()
    }
}

fn store_config_from_serve_args(args: &ServeArgs) -> CandidateConfig {
    let gram_sizes =
        GramSizes::parse(&args.gram_sizes).expect("validated by clap-compatible serve args");
    store_config_from_parts(
        PathBuf::from(&args.root),
        args.id_source,
        args.store_path,
        args.filter_target_fp,
        gram_sizes.tier2,
        gram_sizes.tier1,
        CandidateConfig::default().compaction_idle_cooldown_s,
    )
}

#[cfg(test)]
fn store_config_from_init_args(args: &InternalInitArgs) -> CandidateConfig {
    let gram_sizes =
        GramSizes::parse(&args.gram_sizes).expect("validated by clap-compatible init args");
    store_config_from_parts(
        PathBuf::from(&args.root),
        CandidateIdSource::Sha256,
        false,
        args.filter_target_fp,
        gram_sizes.tier2,
        gram_sizes.tier1,
        args.compaction_idle_cooldown_s,
    )
}

#[cfg(test)]
fn ensure_store(config: CandidateConfig, force: bool) -> Result<CandidateStore> {
    let meta_path = config.root.join("meta.json");
    if force || !meta_path.exists() {
        return CandidateStore::init(config, force);
    }
    CandidateStore::open(config.root)
}

fn candidate_shard_count(root: &Path) -> Result<usize> {
    Ok(read_candidate_shard_count(root)?.unwrap_or(1).max(1))
}

fn store_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let shard_count = candidate_shard_count(root)?;
    Ok((0..shard_count)
        .map(|shard_idx| candidate_shard_root(root, shard_count, shard_idx))
        .collect())
}

fn open_stores(root: &Path) -> Result<Vec<CandidateStore>> {
    store_roots(root)?
        .into_iter()
        .map(CandidateStore::open)
        .collect()
}

#[cfg(test)]
fn merge_tier_used<I>(values: I) -> String
where
    I: IntoIterator<Item = String>,
{
    let normalized = values
        .into_iter()
        .map(|value| value.trim().to_ascii_lowercase())
        .filter(|value| !value.is_empty())
        .collect::<HashSet<_>>();
    if normalized.is_empty() {
        "unknown".to_owned()
    } else if normalized.len() == 1 {
        normalized
            .into_iter()
            .next()
            .unwrap_or_else(|| "unknown".to_owned())
    } else {
        "tier1+tier2".to_owned()
    }
}

#[derive(Debug)]
struct IndexBatchRow {
    sha256: [u8; 32],
    file_size: u64,
    filter_bytes: usize,
    gram_count_estimate: Option<usize>,
    bloom_hashes: usize,
    bloom_filter: Vec<u8>,
    tier2_filter_bytes: usize,
    tier2_gram_count_estimate: Option<usize>,
    tier2_bloom_hashes: usize,
    tier2_bloom_filter: Vec<u8>,
    grams: Vec<u64>,
    grams_complete: bool,
    effective_diversity: Option<f64>,
    external_id: Option<String>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, ValueEnum)]
enum CandidateIdSource {
    Sha256,
    Md5,
    Sha1,
    Sha512,
}

impl CandidateIdSource {
    fn as_str(self) -> &'static str {
        match self {
            CandidateIdSource::Sha256 => "sha256",
            CandidateIdSource::Md5 => "md5",
            CandidateIdSource::Sha1 => "sha1",
            CandidateIdSource::Sha512 => "sha512",
        }
    }

    fn parse_config_value(value: &str) -> Result<Self> {
        match value {
            "sha256" => Ok(CandidateIdSource::Sha256),
            "md5" => Ok(CandidateIdSource::Md5),
            "sha1" => Ok(CandidateIdSource::Sha1),
            "sha512" => Ok(CandidateIdSource::Sha512),
            _ => Err(TgsError::from(format!(
                "invalid candidate id_source `{value}`; expected one of sha256, md5, sha1, sha512"
            ))),
        }
    }
}

#[derive(Clone, Copy)]
struct ScanPolicy {
    fixed_filter_bytes: Option<usize>,
    filter_target_fp: Option<f64>,
    gram_sizes: GramSizes,
    chunk_size: usize,
    max_unique_grams: Option<usize>,
    _no_grams: bool,
    store_path: bool,
    id_source: CandidateIdSource,
}

fn scan_index_batch_row(file_path: &Path, policy: ScanPolicy) -> Result<IndexBatchRow> {
    let resolved_path = resolved_file_path(file_path)?;
    let file_size = file_path.metadata()?.len();
    let gram_count_estimate = if policy.filter_target_fp.is_some() {
        Some(estimate_unique_grams_for_size_hll(
            file_path,
            policy.gram_sizes.tier1,
            policy.chunk_size,
            HLL_DEFAULT_PRECISION,
        )?)
    } else {
        None
    };
    let tier2_gram_count_estimate = if policy.filter_target_fp.is_some() {
        Some(estimate_unique_grams_for_size_hll(
            file_path,
            policy.gram_sizes.tier2,
            policy.chunk_size,
            HLL_DEFAULT_PRECISION,
        )?)
    } else {
        None
    };
    let filter_bytes = if let Some(value) = policy.fixed_filter_bytes {
        value
    } else {
        choose_filter_bytes_for_file_size(
            file_size,
            INTERNAL_FILTER_BYTES,
            Some(INTERNAL_FILTER_MIN_BYTES),
            Some(INTERNAL_FILTER_MAX_BYTES),
            INTERNAL_FILTER_SIZE_DIVISOR,
            policy.filter_target_fp,
            gram_count_estimate,
        )?
    };
    let tier2_filter_bytes = if let Some(value) = policy.fixed_filter_bytes {
        value
    } else {
        choose_filter_bytes_for_file_size(
            file_size,
            INTERNAL_FILTER_BYTES,
            Some(INTERNAL_FILTER_MIN_BYTES),
            Some(INTERNAL_FILTER_MAX_BYTES),
            INTERNAL_FILTER_SIZE_DIVISOR,
            policy.filter_target_fp,
            tier2_gram_count_estimate,
        )?
    };
    let bloom_hashes =
        derive_document_bloom_hash_count(filter_bytes, gram_count_estimate, INTERNAL_BLOOM_HASHES);
    let tier2_bloom_hashes = derive_document_bloom_hash_count(
        tier2_filter_bytes,
        tier2_gram_count_estimate,
        INTERNAL_BLOOM_HASHES,
    );
    let started = Instant::now();
    let features = scan_file_features_with_gram_sizes(
        file_path,
        policy.gram_sizes,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes,
        tier2_bloom_hashes,
        policy.chunk_size,
        true,
        policy.max_unique_grams,
        gram_count_estimate,
        INTERNAL_TIER1_GRAM_BUDGET,
        INTERNAL_TIER1_GRAM_SAMPLE_MOD,
        INTERNAL_TIER1_GRAM_HASH_SEED,
    )?;
    perf::record_sample(
        "candidate.scan_file_features.file",
        resolved_path.display().to_string(),
        started.elapsed().as_nanos(),
        file_size,
        features.unique_grams.len() as u64,
    );
    Ok(IndexBatchRow {
        sha256: if policy.id_source == CandidateIdSource::Sha256 {
            features.sha256
        } else {
            identity_from_file(file_path, policy.chunk_size, policy.id_source)?
        },
        file_size: features.file_size,
        filter_bytes,
        gram_count_estimate,
        bloom_hashes,
        bloom_filter: features.bloom_filter,
        tier2_filter_bytes,
        tier2_gram_count_estimate,
        tier2_bloom_hashes,
        tier2_bloom_filter: features.tier2_bloom_filter,
        grams: features.unique_grams,
        grams_complete: !features.unique_grams_truncated,
        effective_diversity: features.effective_diversity,
        external_id: if policy.store_path {
            Some(resolved_path.display().to_string())
        } else {
            None
        },
    })
}

fn legacy_operand_from_gram(gram: u64, gram_size: usize) -> String {
    hex::encode(&gram.to_le_bytes()[..gram_size.min(8)])
}

fn legacy_query_from_plan(plan: &crate::candidate::CompiledQueryPlan) -> Option<String> {
    let mut pattern_expr = HashMap::<String, String>::new();
    for pattern in &plan.patterns {
        let mut alternatives = Vec::<String>::new();
        for alternative in &pattern.alternatives {
            if alternative.is_empty() {
                continue;
            }
            let terms = alternative
                .iter()
                .map(|value| legacy_operand_from_gram(*value, plan.tier1_gram_size))
                .collect::<Vec<_>>();
            let mut alt_expr = terms.join(" and ");
            if terms.len() > 1 {
                alt_expr = format!("({alt_expr})");
            }
            alternatives.push(alt_expr);
        }
        let expr = if alternatives.is_empty() {
            String::new()
        } else if alternatives.len() == 1 {
            alternatives.remove(0)
        } else {
            format!("({})", alternatives.join(" or "))
        };
        pattern_expr.insert(pattern.pattern_id.clone(), expr);
    }

    fn visit(
        node: &crate::candidate::QueryNode,
        pattern_expr: &HashMap<String, String>,
    ) -> Option<String> {
        match node.kind.as_str() {
            "pattern" => {
                let expr = pattern_expr
                    .get(node.pattern_id.as_ref()?)
                    .cloned()
                    .unwrap_or_default();
                if expr.is_empty() { None } else { Some(expr) }
            }
            "and" | "or" => {
                let parts = node
                    .children
                    .iter()
                    .map(|child| visit(child, pattern_expr))
                    .collect::<Option<Vec<_>>>()?;
                let body = parts.join(&format!(" {} ", node.kind));
                if parts.len() > 1 {
                    Some(format!("({body})"))
                } else {
                    Some(body)
                }
            }
            "n_of" => {
                let parts = node
                    .children
                    .iter()
                    .map(|child| visit(child, pattern_expr))
                    .collect::<Option<Vec<_>>>()?;
                let threshold = node.threshold.unwrap_or(0);
                if threshold == 0 {
                    return None;
                }
                if threshold == 1 {
                    let body = parts.join(" or ");
                    return Some(if parts.len() > 1 {
                        format!("({body})")
                    } else {
                        body
                    });
                }
                if threshold >= parts.len() {
                    let body = parts.join(" and ");
                    return Some(if parts.len() > 1 {
                        format!("({body})")
                    } else {
                        body
                    });
                }
                None
            }
            _ => None,
        }
    }

    visit(&plan.root, &pattern_expr)
}

fn compile_yara_verifier(rule_path: &Path) -> Result<YaraRules> {
    let source = fs::read_to_string(rule_path)?;
    let mut compiler = YaraCompiler::new();
    compiler
        .add_source(source.as_str())
        .map_err(|err| TgsError::from(err.to_string()))?;
    Ok(compiler.build())
}

fn yara_rule_cache_key(rule_path: &Path) -> Result<String> {
    let canonical = fs::canonicalize(rule_path).unwrap_or_else(|_| rule_path.to_path_buf());
    let metadata = fs::metadata(rule_path)?;
    let modified = metadata
        .modified()
        .ok()
        .and_then(|value| value.duration_since(UNIX_EPOCH).ok())
        .map(|value| value.as_nanos())
        .unwrap_or(0);
    Ok(format!(
        "{}:{}:{modified}",
        canonical.display(),
        metadata.len()
    ))
}

fn compile_yara_verifier_cached(rule_path: &Path) -> Result<Arc<YaraRules>> {
    static CACHE: OnceLock<Mutex<BoundedCache<String, Arc<YaraRules>>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(BoundedCache::new(64)));
    let key = yara_rule_cache_key(rule_path)?;
    if let Some(rules) = cache
        .lock()
        .map_err(|_| TgsError::from("YARA verifier cache lock poisoned."))?
        .get(&key)
    {
        return Ok(rules);
    }
    let rules = Arc::new(compile_yara_verifier(rule_path)?);
    let mut guard = cache
        .lock()
        .map_err(|_| TgsError::from("YARA verifier cache lock poisoned."))?;
    guard.insert(key, rules.clone());
    Ok(rules)
}

fn rule_file_has_single_rule(rule_path: &Path) -> Option<bool> {
    let content = fs::read_to_string(rule_path).ok()?;
    let mut count = 0usize;
    for line in content.lines() {
        let trimmed = line.trim_start();
        if trimmed.starts_with("rule ") {
            count += 1;
            if count > 1 {
                return Some(false);
            }
        }
    }
    Some(count == 1)
}

fn fixed_literal_plan_from_rule(rule_path: &Path) -> Option<FixedLiteralMatchPlan> {
    if !rule_file_has_single_rule(rule_path)? {
        return None;
    }
    let plan = compile_query_plan_from_file_with_gram_sizes(
        rule_path,
        GramSizes::new(
            crate::candidate::DEFAULT_TIER2_GRAM_SIZE,
            crate::candidate::DEFAULT_TIER1_GRAM_SIZE,
        )
        .ok()?,
        None,
        16,
        false,
        true,
        1,
    )
    .ok()?;
    fixed_literal_match_plan(&plan)
}

fn file_contains_literal(haystack: &[u8], needle: &[u8]) -> bool {
    needle.is_empty()
        || (haystack.len() >= needle.len() && haystack.windows(needle.len()).any(|w| w == needle))
}

fn verify_fixed_literal_plan_on_file(path: &Path, plan: &FixedLiteralMatchPlan) -> Result<bool> {
    let bytes = fs::read(path)?;
    let mut matches = HashMap::with_capacity(plan.literals.len());
    for (pattern_id, literals) in &plan.literals {
        let matched = literals
            .iter()
            .any(|literal| file_contains_literal(&bytes, literal));
        matches.insert(pattern_id.clone(), matched);
    }
    evaluate_fixed_literal_match(&plan.root, &matches)
}

fn cmd_yara_check(args: &YaraArgs) -> i32 {
    match (|| -> Result<i32> {
        let rule_path = Path::new(&args.rule);
        let file_path = Path::new(&args.file_path);
        if !rule_path.is_file() {
            return Err(TgsError::from(format!(
                "Rule file not found: {}",
                rule_path.display()
            )));
        }
        if !file_path.is_file() {
            return Err(TgsError::from(format!(
                "Target file not found: {}",
                file_path.display()
            )));
        }

        if let Some(literal_plan) = fixed_literal_plan_from_rule(rule_path) {
            match verify_fixed_literal_plan_on_file(file_path, &literal_plan) {
                Ok(false) => {
                    println!("file: {}", file_path.display());
                    println!("rule: {}", rule_path.display());
                    println!("matched: no");
                    println!("match_count: 0");
                    return Ok(0);
                }
                Ok(true) => {}
                Err(_) => {}
            }
        }

        let rules = compile_yara_verifier_cached(rule_path)?;
        let mut scanner = YaraScanner::new(&rules);
        scanner.set_timeout(Duration::from_secs(args.scan_timeout.max(1)));
        let scan = scanner
            .scan_file(file_path)
            .map_err(|err| TgsError::from(err.to_string()))?;

        let matches = scan
            .matching_rules()
            .map(|rule| {
                (
                    rule.identifier().to_owned(),
                    rule.tags()
                        .map(|tag| tag.identifier().to_owned())
                        .collect::<Vec<_>>(),
                )
            })
            .collect::<Vec<_>>();

        println!("file: {}", file_path.display());
        println!("rule: {}", rule_path.display());
        println!("matched: {}", if matches.is_empty() { "no" } else { "yes" });
        println!("match_count: {}", matches.len());
        for (rule_name, tags) in matches {
            println!("match_rule: {rule_name}");
            if args.show_tags && !tags.is_empty() {
                println!("match_tags: {}", tags.join(","));
            }
        }
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

fn cmd_serve(args: &ServeArgs) -> i32 {
    match (|| -> Result<i32> {
        let (host, port) = parse_host_port(&args.addr)?;
        let signals = serve_signal_flags()?;
        rpc::serve_with_signal_flags(
            &host,
            port,
            None,
            args.max_request_bytes,
            RpcServerConfig {
                candidate_config: store_config_from_serve_args(args),
                candidate_shards: args.shards.max(1),
                search_workers: args.search_workers.max(1),
                memory_budget_bytes: args.memory_budget_gb.saturating_mul(1024 * 1024 * 1024),
                tier2_superblock_budget_divisor: args.tier2_superblock_budget_divisor.max(1),
                workspace_mode: true,
            },
            signals.shutdown.clone(),
            Some(signals.status_dump.clone()),
        )?;
        signals.shutdown.store(false, Ordering::SeqCst);
        signals.status_dump.store(false, Ordering::SeqCst);
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

#[cfg(test)]
fn cmd_internal_init(args: &InternalInitArgs) -> i32 {
    match (|| -> Result<i32> {
        let root = Path::new(&args.root);
        let shard_count = args.candidate_shards.max(1);
        if !args.force {
            if let Some(existing) = read_candidate_shard_count(root)? {
                if existing == shard_count {
                    if shard_count == 1 {
                        println!("Candidate store already initialized at {}", args.root);
                    } else {
                        println!(
                            "Candidate store already initialized at {} with {} shard(s)",
                            args.root, shard_count
                        );
                    }
                    return Ok(0);
                }
                return Err(TgsError::from(format!(
                    "{} already initialized with {existing} shard(s)",
                    args.root
                )));
            }

            let meta_path = root.join("meta.json");
            let first_meta = root.join("shard_000").join("meta.json");
            if shard_count == 1 && meta_path.exists() {
                println!("Candidate store already initialized at {}", args.root);
                return Ok(0);
            }
            if shard_count > 1 && first_meta.exists() {
                println!(
                    "Candidate store already initialized at {} with {} shard(s)",
                    args.root, shard_count
                );
                return Ok(0);
            }
        }

        let mut stats = None;
        for shard_idx in 0..shard_count {
            let mut config = store_config_from_init_args(args);
            config.root = candidate_shard_root(root, shard_count, shard_idx);
            let store = ensure_store(config, args.force)?;
            if stats.is_none() {
                stats = Some(store.stats());
            }
        }
        write_candidate_shard_count(root, shard_count)?;
        let stats = stats.expect("candidate init must create at least one shard");
        println!("Initialized candidate store at {}", args.root);
        println!("candidate_shards: {shard_count}");
        println!("id_source: {}", stats.id_source);
        println!("store_path: {}", stats.store_path);
        println!(
            "gram_sizes: {},{}",
            stats.tier2_gram_size, stats.tier1_gram_size
        );
        println!(
            "filter_target_fp: {}",
            stats
                .filter_target_fp
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned())
        );
        println!(
            "compaction_idle_cooldown_s: {}",
            stats.compaction_idle_cooldown_s
        );
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

#[cfg(test)]
fn cmd_internal_index(args: &InternalIndexArgs) -> i32 {
    match (|| -> Result<i32> {
        let result = if let Some(root) = &args.root {
            let mut stores = open_stores(Path::new(root))?;
            let config = stores
                .first()
                .ok_or_else(|| TgsError::from("Candidate store is not initialized."))?
                .config();
            let id_source = CandidateIdSource::parse_config_value(&config.id_source)?;
            let gram_sizes = GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)?;
            let mut row = scan_index_batch_row(
                Path::new(&args.file_path),
                ScanPolicy {
                    fixed_filter_bytes: None,
                    filter_target_fp: config.filter_target_fp,
                    gram_sizes,
                    chunk_size: args.chunk_size,
                    max_unique_grams: args.max_unique_grams,
                    _no_grams: args.no_grams,
                    store_path: false,
                    id_source,
                },
            )?;
            row.external_id = args.external_id.clone().or(row.external_id);
            let shard_idx = candidate_shard_index(&row.sha256, stores.len());
            let result = stores[shard_idx].insert_document(
                row.sha256,
                row.file_size,
                row.gram_count_estimate,
                Some(row.bloom_hashes),
                row.tier2_gram_count_estimate,
                Some(row.tier2_bloom_hashes),
                row.filter_bytes,
                &row.bloom_filter,
                row.tier2_filter_bytes,
                &row.tier2_bloom_filter,
                &row.grams,
                row.grams_complete,
                row.effective_diversity,
                row.external_id,
                true,
            )?;
            rpc::CandidateInsertResponse {
                status: result.status,
                doc_id: result.doc_id,
                sha256: result.sha256,
                grams_received: result.grams_received,
                grams_indexed: result.grams_indexed,
                grams_complete: result.grams_complete,
            }
        } else {
            let server_policy = server_scan_policy(&args.connection)?;
            let mut row = scan_index_batch_row(
                Path::new(&args.file_path),
                ScanPolicy {
                    fixed_filter_bytes: None,
                    filter_target_fp: server_policy.filter_target_fp,
                    gram_sizes: server_policy.gram_sizes,
                    chunk_size: args.chunk_size,
                    max_unique_grams: args.max_unique_grams,
                    _no_grams: args.no_grams,
                    store_path: server_policy.store_path,
                    id_source: server_policy.id_source,
                },
            )?;
            row.external_id = args.external_id.clone().or(row.external_id);
            rpc_client(&args.connection).candidate_insert_document(&batch_row_to_wire(row))?
        };

        println!("status: {}", result.status);
        println!("doc_id: {}", result.doc_id);
        println!("sha256: {}", result.sha256);
        println!("grams_received: {}", result.grams_received);
        println!("grams_indexed: {}", result.grams_indexed);
        println!("grams_complete: {}", result.grams_complete);
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

fn cmd_internal_index_batch(args: &InternalIndexBatchArgs) -> i32 {
    match (|| -> Result<i32> {
        let started_total = Instant::now();
        let mut scan_time = Duration::ZERO;
        let mut submit_time = Duration::ZERO;
        let mut server_rss_kb = None::<(u64, u64)>;
        let input_roots = normalize_input_paths(&args.paths);
        let total_files = count_input_files(&input_roots)?;
        if total_files == 0 {
            return Err(TgsError::from("No input files found."));
        }
        let show_progress = args.verbose && input_roots.iter().any(|path| path.is_dir());
        let mut last_progress_reported = 0usize;
        let mut last_progress_at = Instant::now();
        let mut processed = 0usize;
        let batch_size = args.batch_size.max(1);
        if let Some(root) = &args.root {
            let mut stores = open_stores(Path::new(root))?;
            let config = stores
                .first()
                .ok_or_else(|| TgsError::from("Candidate store is not initialized."))?
                .config();
            let id_source = CandidateIdSource::parse_config_value(&config.id_source)?;
            let gram_sizes = GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)?;
            let policy = ScanPolicy {
                fixed_filter_bytes: None,
                filter_target_fp: config.filter_target_fp,
                gram_sizes,
                chunk_size: args.chunk_size,
                max_unique_grams: args.max_unique_grams,
                _no_grams: args.no_grams,
                store_path: args.external_id_from_path,
                id_source,
            };
            let configured_budget_bytes = DEFAULT_MEMORY_BUDGET_BYTES;
            let effective_budget_bytes = effective_memory_budget_bytes(configured_budget_bytes);
            let queue_capacity = index_queue_capacity(effective_budget_bytes, args.workers.max(1));
            let mut pending = Vec::<IndexBatchRow>::new();
            if args.workers <= 1 {
                stream_input_files(&input_roots, |file_path| {
                    let started_scan = Instant::now();
                    pending.push(scan_index_batch_row(&file_path, policy)?);
                    scan_time += started_scan.elapsed();
                    if pending.len() >= batch_size {
                        flush_local_pending_rows(
                            &mut stores,
                            &mut pending,
                            &mut processed,
                            &mut submit_time,
                            show_progress,
                            total_files,
                            &mut last_progress_reported,
                            &mut last_progress_at,
                        )?;
                    }
                    Ok(())
                })?;
            } else {
                let (job_tx, job_rx) = bounded::<PathBuf>(queue_capacity);
                let (result_tx, result_rx) = bounded::<Result<IndexBatchRow>>(queue_capacity);
                let worker_count = args.workers.max(1);
                thread::scope(|scope| {
                    for _ in 0..worker_count {
                        let job_rx = job_rx.clone();
                        let result_tx = result_tx.clone();
                        scope.spawn(move || {
                            for file_path in job_rx.iter() {
                                let result = scan_index_batch_row(&file_path, policy);
                                let _ = result_tx.send(result);
                            }
                        });
                    }
                    let producer_tx = job_tx.clone();
                    let producer_result_tx = result_tx.clone();
                    let producer_roots = input_roots.clone();
                    scope.spawn(move || {
                        let produce = stream_input_files(&producer_roots, |file_path| {
                            producer_tx.send(file_path).map_err(|_| {
                                TgsError::from(
                                    "candidate ingest file producer terminated unexpectedly",
                                )
                            })?;
                            Ok(())
                        });
                        if let Err(err) = produce {
                            let _ = producer_result_tx.send(Err(err));
                        }
                        drop(producer_tx);
                    });

                    drop(job_tx);
                    drop(result_tx);

                    for _ in 0..total_files {
                        let started_scan = Instant::now();
                        pending.push(result_rx.recv().map_err(|_| {
                            TgsError::from("candidate ingest workers terminated unexpectedly")
                        })??);
                        scan_time += started_scan.elapsed();
                        if pending.len() >= batch_size {
                            flush_local_pending_rows(
                                &mut stores,
                                &mut pending,
                                &mut processed,
                                &mut submit_time,
                                show_progress,
                                total_files,
                                &mut last_progress_reported,
                                &mut last_progress_at,
                            )?;
                        }
                    }
                    Ok::<(), TgsError>(())
                })?;
            }

            flush_local_pending_rows(
                &mut stores,
                &mut pending,
                &mut processed,
                &mut submit_time,
                show_progress,
                total_files,
                &mut last_progress_reported,
                &mut last_progress_at,
            )?;

            if args.verbose {
                eprintln!("verbose.index.memory_budget_bytes: {configured_budget_bytes}");
                eprintln!("verbose.index.effective_memory_budget_bytes: {effective_budget_bytes}");
                eprintln!("verbose.index.queue_capacity: {queue_capacity}");
            }
        } else {
            let server_policy = server_scan_policy(&args.connection)?;
            let policy = ScanPolicy {
                fixed_filter_bytes: None,
                filter_target_fp: server_policy.filter_target_fp,
                gram_sizes: server_policy.gram_sizes,
                chunk_size: args.chunk_size,
                max_unique_grams: args.max_unique_grams,
                _no_grams: args.no_grams,
                store_path: server_policy.store_path,
                id_source: server_policy.id_source,
            };
            let client = rpc_client(&args.connection);
            client.begin_index_session()?;
            let _session = RemoteIndexSessionGuard { client: &client };
            client.update_index_session_progress(Some(total_files), 0, 0)?;
            let configured_budget_bytes = server_policy.memory_budget_bytes;
            let effective_budget_bytes = effective_memory_budget_bytes(configured_budget_bytes);
            let queue_capacity = index_queue_capacity(effective_budget_bytes, args.workers.max(1));
            let mut pending = Vec::<CandidateDocumentWire>::new();
            let mut last_server_progress_reported = 0usize;
            let mut last_server_progress_at = Instant::now();
            if args.workers <= 1 {
                stream_input_files(&input_roots, |file_path| {
                    let started_scan = Instant::now();
                    let row = batch_row_to_wire(scan_index_batch_row(&file_path, policy)?);
                    scan_time += started_scan.elapsed();
                    push_remote_batch_row(&client, &mut pending, row, batch_size, &mut processed)?;
                    maybe_report_index_progress(
                        show_progress,
                        processed,
                        total_files,
                        &mut last_progress_reported,
                        &mut last_progress_at,
                        false,
                    );
                    maybe_report_remote_index_session_progress(
                        &client,
                        processed,
                        total_files,
                        &mut last_server_progress_reported,
                        &mut last_server_progress_at,
                        false,
                    )?;
                    Ok(())
                })?;
            } else {
                let (job_tx, job_rx) = bounded::<PathBuf>(queue_capacity);
                let (result_tx, result_rx) = bounded::<Result<IndexBatchRow>>(queue_capacity);
                let worker_count = args.workers.max(1);
                thread::scope(|scope| {
                    for _ in 0..worker_count {
                        let job_rx = job_rx.clone();
                        let result_tx = result_tx.clone();
                        scope.spawn(move || {
                            for file_path in job_rx.iter() {
                                let result = scan_index_batch_row(&file_path, policy);
                                let _ = result_tx.send(result);
                            }
                        });
                    }
                    let producer_tx = job_tx.clone();
                    let producer_result_tx = result_tx.clone();
                    let producer_roots = input_roots.clone();
                    scope.spawn(move || {
                        let produce = stream_input_files(&producer_roots, |file_path| {
                            producer_tx.send(file_path).map_err(|_| {
                                TgsError::from(
                                    "candidate ingest file producer terminated unexpectedly",
                                )
                            })?;
                            Ok(())
                        });
                        if let Err(err) = produce {
                            let _ = producer_result_tx.send(Err(err));
                        }
                        drop(producer_tx);
                    });

                    drop(job_tx);
                    drop(result_tx);

                    for _ in 0..total_files {
                        let started_scan = Instant::now();
                        let row = batch_row_to_wire(result_rx.recv().map_err(|_| {
                            TgsError::from("candidate ingest workers terminated unexpectedly")
                        })??);
                        scan_time += started_scan.elapsed();
                        push_remote_batch_row(
                            &client,
                            &mut pending,
                            row,
                            batch_size,
                            &mut processed,
                        )?;
                        maybe_report_index_progress(
                            show_progress,
                            processed,
                            total_files,
                            &mut last_progress_reported,
                            &mut last_progress_at,
                            false,
                        );
                        maybe_report_remote_index_session_progress(
                            &client,
                            processed,
                            total_files,
                            &mut last_server_progress_reported,
                            &mut last_server_progress_at,
                            false,
                        )?;
                    }
                    Ok::<(), TgsError>(())
                })?;
            }

            flush_remote_pending_rows(
                &client,
                &mut pending,
                &mut processed,
                &mut submit_time,
                show_progress,
                total_files,
                &mut last_progress_reported,
                &mut last_progress_at,
            )?;
            maybe_report_remote_index_session_progress(
                &client,
                processed,
                total_files,
                &mut last_server_progress_reported,
                &mut last_server_progress_at,
                true,
            )?;
            if args.verbose {
                server_rss_kb = server_memory_kb(&args.connection)?;
                eprintln!("verbose.index.memory_budget_bytes: {configured_budget_bytes}");
                eprintln!("verbose.index.effective_memory_budget_bytes: {effective_budget_bytes}");
                eprintln!("verbose.index.queue_capacity: {queue_capacity}");
            }
        }

        maybe_report_index_progress(
            show_progress,
            processed,
            total_files,
            &mut last_progress_reported,
            &mut last_progress_at,
            true,
        );

        println!("submitted_documents: {total_files}");
        println!("processed_documents: {processed}");
        if args.verbose {
            let total_ms = started_total.elapsed().as_secs_f64() * 1000.0;
            let scan_ms = scan_time.as_secs_f64() * 1000.0;
            let submit_ms = submit_time.as_secs_f64() * 1000.0;
            eprintln!("verbose.index.total_ms: {total_ms:.3}");
            eprintln!("verbose.index.scan_ms: {scan_ms:.3}");
            eprintln!("verbose.index.submit_ms: {submit_ms:.3}");
            eprintln!("verbose.index.batch_size: {}", batch_size);
            eprintln!("verbose.index.workers: {}", args.workers.max(1));
            eprintln!("verbose.index.submitted_documents: {total_files}");
            eprintln!("verbose.index.processed_documents: {processed}");
            let (client_current_rss_kb, client_peak_rss_kb) = current_process_memory_kb();
            eprintln!("verbose.index.client_current_rss_kb: {client_current_rss_kb}");
            eprintln!("verbose.index.client_peak_rss_kb: {client_peak_rss_kb}");
            if let Some((server_current_rss_kb, server_peak_rss_kb)) = server_rss_kb {
                eprintln!("verbose.index.server_current_rss_kb: {server_current_rss_kb}");
                eprintln!("verbose.index.server_peak_rss_kb: {server_peak_rss_kb}");
            }
            if let Ok(stats) = rpc_client(&args.connection).candidate_stats() {
                let stats_scope = stats
                    .get("work")
                    .and_then(serde_json::Value::as_object)
                    .unwrap_or(&stats);
                for (key, label) in [
                    ("disk_usage_bytes", "verbose.index.server_disk_usage_bytes"),
                    (
                        "tier2_superblock_summary_bytes",
                        "verbose.index.server_tier2_superblock_summary_bytes",
                    ),
                    (
                        "tier2_superblock_memory_budget_bytes",
                        "verbose.index.server_tier2_superblock_budget_bytes",
                    ),
                    (
                        "tier2_superblock_docs",
                        "verbose.index.server_tier2_superblock_docs_per_block",
                    ),
                    (
                        "df_counts_delta_bytes",
                        "verbose.index.server_df_counts_delta_bytes",
                    ),
                    (
                        "df_counts_delta_entries",
                        "verbose.index.server_df_counts_delta_entries",
                    ),
                    (
                        "df_counts_delta_compact_threshold_bytes",
                        "verbose.index.server_df_counts_delta_compact_threshold_bytes",
                    ),
                ] {
                    if let Some(value) = stats_scope.get(key).and_then(|value| value.as_u64()) {
                        eprintln!("{label}: {value}");
                    }
                }
                if let Some(publish) = stats.get("publish").and_then(serde_json::Value::as_object) {
                    for (key, label) in [
                        ("pending", "verbose.index.server_publish_pending"),
                        ("eligible", "verbose.index.server_publish_eligible"),
                    ] {
                        if let Some(value) = publish.get(key).and_then(|value| value.as_bool()) {
                            eprintln!("{label}: {value}");
                        }
                    }
                    if let Some(value) = publish
                        .get("blocked_reason")
                        .and_then(serde_json::Value::as_str)
                    {
                        eprintln!("verbose.index.server_publish_blocked_reason: {value}");
                    }
                    for (key, label) in [
                        (
                            "idle_elapsed_ms",
                            "verbose.index.server_publish_idle_elapsed_ms",
                        ),
                        (
                            "idle_remaining_ms",
                            "verbose.index.server_publish_idle_remaining_ms",
                        ),
                        (
                            "published_doc_count",
                            "verbose.index.server_published_doc_count",
                        ),
                        ("work_doc_count", "verbose.index.server_work_doc_count"),
                        (
                            "work_doc_delta_vs_published",
                            "verbose.index.server_work_doc_delta_vs_published",
                        ),
                        (
                            "published_disk_usage_bytes",
                            "verbose.index.server_published_disk_usage_bytes",
                        ),
                        (
                            "work_disk_usage_bytes",
                            "verbose.index.server_work_disk_usage_bytes",
                        ),
                        (
                            "work_disk_usage_delta_vs_published",
                            "verbose.index.server_work_disk_usage_delta_vs_published",
                        ),
                        (
                            "last_publish_duration_ms",
                            "verbose.index.server_last_publish_duration_ms",
                        ),
                        (
                            "last_publish_swap_ms",
                            "verbose.index.server_last_publish_swap_ms",
                        ),
                        (
                            "last_publish_promote_work_ms",
                            "verbose.index.server_last_publish_promote_work_ms",
                        ),
                        (
                            "last_publish_persist_df_counts_ms",
                            "verbose.index.server_last_publish_persist_df_counts_ms",
                        ),
                        (
                            "last_publish_df_snapshot_persist_failures",
                            "verbose.index.server_last_publish_df_snapshot_persist_failures",
                        ),
                        (
                            "last_publish_init_work_ms",
                            "verbose.index.server_last_publish_init_work_ms",
                        ),
                        (
                            "last_publish_persist_tier2_superblocks_ms",
                            "verbose.index.server_last_publish_persist_tier2_superblocks_ms",
                        ),
                        (
                            "last_publish_tier2_snapshot_persist_failures",
                            "verbose.index.server_last_publish_tier2_snapshot_persist_failures",
                        ),
                        (
                            "last_publish_persisted_snapshot_shards",
                            "verbose.index.server_last_publish_persisted_snapshot_shards",
                        ),
                        (
                            "publish_runs_total",
                            "verbose.index.server_publish_runs_total",
                        ),
                    ] {
                        if let Some(value) = publish.get(key).and_then(|value| value.as_i64()) {
                            eprintln!("{label}: {value}");
                        } else if let Some(value) =
                            publish.get(key).and_then(|value| value.as_u64())
                        {
                            eprintln!("{label}: {value}");
                        }
                    }
                    if let Some(value) = publish
                        .get("last_publish_reused_work_stores")
                        .and_then(serde_json::Value::as_bool)
                    {
                        eprintln!("verbose.index.server_last_publish_reused_work_stores: {value}");
                    }
                }
                if let Some(index_session) = stats
                    .get("index_session")
                    .and_then(serde_json::Value::as_object)
                {
                    if let Some(value) = index_session
                        .get("active")
                        .and_then(serde_json::Value::as_bool)
                    {
                        eprintln!("verbose.index.server_index_session_active: {value}");
                    }
                    for (key, label) in [
                        (
                            "total_documents",
                            "verbose.index.server_index_total_documents",
                        ),
                        (
                            "submitted_documents",
                            "verbose.index.server_index_submitted_documents",
                        ),
                        (
                            "processed_documents",
                            "verbose.index.server_index_processed_documents",
                        ),
                        (
                            "remaining_documents",
                            "verbose.index.server_index_remaining_documents",
                        ),
                    ] {
                        if let Some(value) =
                            index_session.get(key).and_then(serde_json::Value::as_u64)
                        {
                            eprintln!("{label}: {value}");
                        }
                    }
                    if let Some(value) = index_session
                        .get("progress_percent")
                        .and_then(serde_json::Value::as_f64)
                    {
                        eprintln!("verbose.index.server_index_progress_percent: {value:.3}");
                    }
                }
                if let Some(seal) = stats
                    .get("published_df_snapshot_seal")
                    .and_then(serde_json::Value::as_object)
                {
                    if let Some(value) = seal
                        .get("pending_shards")
                        .and_then(serde_json::Value::as_u64)
                    {
                        eprintln!(
                            "verbose.index.server_published_df_snapshot_seal_pending_shards: {value}"
                        );
                    }
                    if let Some(value) =
                        seal.get("in_progress").and_then(serde_json::Value::as_bool)
                    {
                        eprintln!(
                            "verbose.index.server_published_df_snapshot_seal_in_progress: {value}"
                        );
                    }
                    for (key, label) in [
                        (
                            "last_duration_ms",
                            "verbose.index.server_published_df_snapshot_seal_last_duration_ms",
                        ),
                        (
                            "last_persisted_shards",
                            "verbose.index.server_published_df_snapshot_seal_last_persisted_shards",
                        ),
                        (
                            "last_failures",
                            "verbose.index.server_published_df_snapshot_seal_last_failures",
                        ),
                    ] {
                        if let Some(value) = seal.get(key).and_then(serde_json::Value::as_u64) {
                            eprintln!("{label}: {value}");
                        }
                    }
                }
            }
        }
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

#[cfg(test)]
fn cmd_internal_delete(args: &InternalDeleteArgs) -> i32 {
    match (|| -> Result<i32> {
        if args.values.is_empty() {
            return Err(TgsError::from("delete requires at least one value"));
        }
        let mut any_failed = false;
        let mut results = Vec::with_capacity(args.values.len());
        if let Some(root) = &args.root {
            let mut stores = open_stores(Path::new(root))?;
            let id_source = stores
                .first()
                .ok_or_else(|| TgsError::from("Candidate store is not initialized."))?
                .config()
                .id_source;
            let id_source = CandidateIdSource::parse_config_value(&id_source)?;
            for value in &args.values {
                let sha256_hex =
                    resolve_delete_value(value, id_source, DEFAULT_FILE_READ_CHUNK_SIZE)?;
                let sha256 = decode_sha256_hex(&sha256_hex)?;
                let shard_idx = candidate_shard_index(&sha256, stores.len());
                results.push(stores[shard_idx].delete_document(&sha256_hex)?);
            }
        } else {
            let server_id_source = server_identity_source(&args.connection)?;
            let client = rpc_client(&args.connection);
            for value in &args.values {
                let sha256_hex =
                    resolve_delete_value(value, server_id_source, DEFAULT_FILE_READ_CHUNK_SIZE)?;
                let deleted = client.candidate_delete_sha256(&sha256_hex)?;
                results.push(crate::candidate::CandidateDeleteResult {
                    status: deleted.status,
                    doc_id: deleted.doc_id,
                    sha256: deleted.sha256,
                });
            }
        }
        for result in results {
            println!("status: {}", result.status);
            println!(
                "doc_id: {}",
                result
                    .doc_id
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "none".to_owned())
            );
            println!("sha256: {}", result.sha256);
            if result.status != "deleted" {
                any_failed = true;
            }
        }
        if any_failed {
            return Ok(1);
        }
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

#[cfg(test)]
fn cmd_internal_query(args: &InternalQueryArgs) -> i32 {
    match (|| -> Result<i32> {
        let result = if let Some(root) = &args.root {
            let mut stores = open_stores(Path::new(root))?;
            let gram_sizes = stores
                .first()
                .map(|store| {
                    let config = store.config();
                    GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)
                })
                .transpose()?
                .unwrap_or(GramSizes::new(3, 4)?);
            let df_counts = if args.no_df_lookup {
                None
            } else {
                let mut merged = HashMap::<u64, usize>::new();
                for store in &stores {
                    for (gram, count) in store.df_counts() {
                        *merged.entry(gram).or_insert(0) += count;
                    }
                }
                Some(merged)
            };
            let plan = compile_query_plan_from_file_with_gram_sizes(
                &args.rule,
                gram_sizes,
                df_counts.as_ref(),
                args.max_anchors_per_pattern,
                args.force_tier1_only,
                !args.no_tier2_fallback,
                args.max_candidates,
            )?;
            if stores.len() == 1 {
                let result = stores[0].query_candidates(&plan, args.cursor, args.chunk_size)?;
                rpc::CandidateQueryResponse {
                    sha256: result.sha256,
                    total_candidates: result.total_candidates,
                    returned_count: result.returned_count,
                    cursor: result.cursor,
                    next_cursor: result.next_cursor,
                    tier_used: result.tier_used,
                    external_ids: None,
                }
            } else {
                let mut hashes = std::collections::BTreeSet::<String>::new();
                let mut tier_used = Vec::<String>::new();
                let collect_chunk = plan.max_candidates.max(1).min(4096);
                for store in &mut stores {
                    let mut cursor = 0usize;
                    loop {
                        let local = store.query_candidates(&plan, cursor, collect_chunk)?;
                        tier_used.push(local.tier_used.clone());
                        hashes.extend(local.sha256);
                        if let Some(next) = local.next_cursor {
                            cursor = next;
                        } else {
                            break;
                        }
                    }
                }
                let mut ordered = hashes.into_iter().collect::<Vec<_>>();
                if ordered.len() > plan.max_candidates {
                    ordered.truncate(plan.max_candidates);
                }
                let total_candidates = ordered.len();
                let start = args.cursor.min(total_candidates);
                let end = (start + args.chunk_size.max(1)).min(total_candidates);
                rpc::CandidateQueryResponse {
                    returned_count: end.saturating_sub(start),
                    sha256: ordered[start..end].to_vec(),
                    total_candidates,
                    cursor: start,
                    next_cursor: (end < total_candidates).then_some(end),
                    tier_used: merge_tier_used(tier_used),
                    external_ids: None,
                }
            }
        } else {
            let client = rpc_client(&args.connection);
            let server_policy = server_scan_policy(&args.connection)?;
            let initial_plan = compile_query_plan_from_file_with_gram_sizes(
                &args.rule,
                server_policy.gram_sizes,
                None,
                args.max_anchors_per_pattern.saturating_mul(4).max(1),
                args.force_tier1_only,
                !args.no_tier2_fallback,
                args.max_candidates,
            )?;
            let df_counts = if args.no_df_lookup {
                None
            } else {
                let mut grams = HashSet::<u64>::new();
                for pattern in &initial_plan.patterns {
                    for alternative in &pattern.alternatives {
                        grams.extend(alternative.iter().copied());
                    }
                }
                if grams.is_empty() {
                    None
                } else {
                    Some(client.candidate_df(&grams.into_iter().collect::<Vec<_>>())?)
                }
            };
            let plan = compile_query_plan_from_file_with_gram_sizes(
                &args.rule,
                server_policy.gram_sizes,
                df_counts.as_ref(),
                args.max_anchors_per_pattern,
                args.force_tier1_only,
                !args.no_tier2_fallback,
                args.max_candidates,
            )?;
            client.candidate_query_plan(&plan, args.cursor, Some(args.chunk_size))?
        };

        println!("total_candidates: {}", result.total_candidates);
        println!("returned_count: {}", result.returned_count);
        println!("cursor: {}", result.cursor);
        println!(
            "next_cursor: {}",
            result
                .next_cursor
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned())
        );
        println!("tier_used: {}", result.tier_used);
        println!("candidates: {}", result.total_candidates);
        for sha256 in result.sha256 {
            println!("sha256: {sha256}");
        }
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

#[cfg(test)]
fn cmd_internal_stats(args: &InternalStatsArgs) -> i32 {
    match (|| -> Result<i32> {
        let stats = if let Some(root) = &args.root {
            let stores = open_stores(Path::new(root))?;
            serde_json::Value::Object(rpc::candidate_stats_json_for_stores(
                Path::new(root),
                &stores,
            ))
        } else {
            serde_json::Value::Object(rpc_client(&args.connection).candidate_stats()?)
        };
        println!("{}", serde_json::to_string_pretty(&stats)?);
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

fn cmd_ingest(args: &IndexArgs) -> i32 {
    let server_policy = match server_scan_policy(&args.connection) {
        Ok(server_policy) => server_policy,
        Err(err) => {
            println!("{err}");
            return 1;
        }
    };
    cmd_internal_index_batch(&InternalIndexBatchArgs {
        connection: args.connection.clone(),
        paths: args.paths.clone(),
        root: None,
        batch_size: args.batch_size,
        workers: args.workers,
        chunk_size: DEFAULT_FILE_READ_CHUNK_SIZE,
        max_unique_grams: None,
        no_grams: false,
        external_id_from_path: server_policy.store_path,
        verbose: args.verbose,
    })
}

fn cmd_delete(args: &DeleteArgs) -> i32 {
    match (|| -> Result<i32> {
        let server_id_source = server_identity_source(&args.connection)?;
        let client = rpc_client(&args.connection);
        let mut exit_code = 0;
        for value in &args.values {
            match (|| -> Result<()> {
                let sha256_hex =
                    resolve_delete_value(value, server_id_source, DEFAULT_FILE_READ_CHUNK_SIZE)?;
                let result = client.candidate_delete_sha256(&sha256_hex)?;
                println!("value: {value}");
                println!("status: {}", result.status);
                println!("sha256: {}", result.sha256);
                println!(
                    "doc_id: {}",
                    result
                        .doc_id
                        .map(|doc_id| doc_id.to_string())
                        .unwrap_or_else(|| "None".to_owned())
                );
                if result.status != "deleted" {
                    return Err(TgsError::from(format!(
                        "delete failed for `{value}`: {}",
                        result.status
                    )));
                }
                Ok(())
            })() {
                Ok(()) => {}
                Err(err) => {
                    println!("{err}");
                    exit_code = 1;
                }
            }
        }
        Ok(exit_code)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

fn cmd_search_candidates(args: &SearchCommandArgs) -> i32 {
    match (|| -> Result<i32> {
        let started_total = Instant::now();
        let mut plan_time = Duration::ZERO;
        let mut df_lookup_time = Duration::ZERO;
        let mut query_time = Duration::ZERO;
        let mut verify_time = Duration::ZERO;
        let mut server_rss_kb = None::<(u64, u64)>;
        let client = rpc_client(&args.connection);
        let verify_yara_files = args.verify_yara_files;
        let server_policy = server_scan_policy(&args.connection)?;

        let started_plan = Instant::now();
        let initial_plan = compile_query_plan_from_file_with_gram_sizes(
            &args.rule,
            server_policy.gram_sizes,
            None,
            args.max_anchors_per_pattern.saturating_mul(4).max(1),
            false,
            true,
            args.max_candidates,
        )?;
        plan_time += started_plan.elapsed();

        let mut grams = HashSet::<u64>::new();
        for pattern in &initial_plan.patterns {
            for alternative in &pattern.alternatives {
                grams.extend(alternative.iter().copied());
            }
        }
        let df_counts = if grams.is_empty() {
            None
        } else {
            let started_df = Instant::now();
            let result = client.candidate_df(&grams.into_iter().collect::<Vec<_>>())?;
            df_lookup_time += started_df.elapsed();
            Some(result)
        };

        let started_plan = Instant::now();
        let plan = compile_query_plan_from_file_with_gram_sizes(
            &args.rule,
            server_policy.gram_sizes,
            df_counts.as_ref(),
            args.max_anchors_per_pattern,
            false,
            true,
            args.max_candidates,
        )?;
        plan_time += started_plan.elapsed();
        let legacy_query = legacy_query_from_plan(&plan);
        let literal_plan = if verify_yara_files {
            fixed_literal_match_plan(&plan)
        } else {
            None
        };
        let mut yara_rules = None::<Arc<YaraRules>>;

        let mut cursor = 0usize;
        let mut rows = Vec::<String>::new();
        let mut verified_rows = Vec::<String>::new();
        let mut verified_checked = 0usize;
        let mut verified_matched = 0usize;
        let mut verified_skipped = 0usize;
        let (total, tier_used) = loop {
            let started_query = Instant::now();
            let result = client.candidate_query_plan_with_options(
                &plan,
                cursor,
                Some(DEFAULT_SEARCH_RESULT_CHUNK_SIZE),
                verify_yara_files,
            )?;
            query_time += started_query.elapsed();
            if !verify_yara_files {
                rows.extend(result.sha256.iter().cloned());
            } else {
                let mut external_ids = result.external_ids.unwrap_or_default();
                if external_ids.len() < result.sha256.len() {
                    external_ids.resize(result.sha256.len(), None);
                }
                let mut page_results = vec![None::<bool>; result.sha256.len()];
                let mut verify_jobs = Vec::<(usize, String, PathBuf)>::new();
                for (index, (sha256, external_id)) in result
                    .sha256
                    .iter()
                    .cloned()
                    .zip(external_ids.into_iter())
                    .enumerate()
                {
                    let Some(path_text) = external_id else {
                        verified_skipped += 1;
                        rows.push(sha256);
                        continue;
                    };
                    let candidate_path = PathBuf::from(path_text);
                    if !candidate_path.is_file() {
                        verified_skipped += 1;
                        rows.push(sha256);
                        continue;
                    }
                    verify_jobs.push((index, sha256, candidate_path));
                }
                verify_jobs.sort_by(|left, right| left.2.cmp(&right.2));
                for (index, _sha256, candidate_path) in verify_jobs {
                    verified_checked += 1;
                    let started_verify = Instant::now();
                    let matched = if let Some(plan) = &literal_plan {
                        match verify_fixed_literal_plan_on_file(&candidate_path, plan) {
                            Ok(matched) => matched,
                            Err(_) => {
                                if yara_rules.is_none() {
                                    yara_rules =
                                        Some(compile_yara_verifier_cached(Path::new(&args.rule))?);
                                }
                                let mut scanner = YaraScanner::new(
                                    yara_rules.as_ref().expect("cached YARA rules"),
                                );
                                scanner
                                    .scan_file(&candidate_path)
                                    .map_err(|err| TgsError::from(err.to_string()))?
                                    .matching_rules()
                                    .len()
                                    > 0
                            }
                        }
                    } else {
                        if yara_rules.is_none() {
                            yara_rules = Some(compile_yara_verifier_cached(Path::new(&args.rule))?);
                        }
                        let mut scanner =
                            YaraScanner::new(yara_rules.as_ref().expect("cached YARA rules"));
                        scanner
                            .scan_file(&candidate_path)
                            .map_err(|err| TgsError::from(err.to_string()))?
                            .matching_rules()
                            .len()
                            > 0
                    };
                    verify_time += started_verify.elapsed();
                    page_results[index] = Some(matched);
                }
                for (index, sha256) in result.sha256.iter().cloned().enumerate() {
                    match page_results.get(index).copied().flatten() {
                        Some(true) => {
                            verified_matched += 1;
                            verified_rows.push(sha256);
                        }
                        Some(false) => {}
                        None => {
                            if !rows.iter().any(|value| value == &sha256) {
                                rows.push(sha256);
                            }
                        }
                    }
                }
            }
            match result.next_cursor {
                Some(next) => cursor = next,
                None => break (result.total_candidates, result.tier_used),
            }
        };

        if let Some(query) = legacy_query {
            println!("legacy_query: {query}");
        }
        println!("tier_used: {tier_used}");
        println!("candidates: {total}");
        if verify_yara_files {
            println!("verified_checked: {verified_checked}");
            println!("verified_matched: {verified_matched}");
            println!("verified_skipped: {verified_skipped}");
            verified_rows.extend(rows);
            for row in verified_rows {
                println!("{row}");
            }
        } else {
            for row in rows {
                println!("{row}");
            }
        }
        if args.verbose {
            server_rss_kb = server_memory_kb(&args.connection)?;
        }
        if args.verbose {
            let total_ms = started_total.elapsed().as_secs_f64() * 1000.0;
            let plan_ms = plan_time.as_secs_f64() * 1000.0;
            let df_ms = df_lookup_time.as_secs_f64() * 1000.0;
            let query_ms = query_time.as_secs_f64() * 1000.0;
            let verify_ms = verify_time.as_secs_f64() * 1000.0;
            eprintln!("verbose.search.total_ms: {total_ms:.3}");
            eprintln!("verbose.search.plan_ms: {plan_ms:.3}");
            eprintln!("verbose.search.df_lookup_ms: {df_ms:.3}");
            eprintln!("verbose.search.query_ms: {query_ms:.3}");
            eprintln!("verbose.search.verify_ms: {verify_ms:.3}");
            eprintln!("verbose.search.max_candidates: {}", args.max_candidates);
            eprintln!(
                "verbose.search.max_anchors_per_pattern: {}",
                args.max_anchors_per_pattern
            );
            eprintln!("verbose.search.candidates: {total}");
            eprintln!("verbose.search.verify_enabled: {}", verify_yara_files);
            let (client_current_rss_kb, client_peak_rss_kb) = current_process_memory_kb();
            eprintln!("verbose.search.client_current_rss_kb: {client_current_rss_kb}");
            eprintln!("verbose.search.client_peak_rss_kb: {client_peak_rss_kb}");
            if let Some((server_current_rss_kb, server_peak_rss_kb)) = server_rss_kb {
                eprintln!("verbose.search.server_current_rss_kb: {server_current_rss_kb}");
                eprintln!("verbose.search.server_peak_rss_kb: {server_peak_rss_kb}");
            }
            if verify_yara_files {
                eprintln!("verbose.search.verified_checked: {verified_checked}");
                eprintln!("verbose.search.verified_matched: {verified_matched}");
                eprintln!("verbose.search.verified_skipped: {verified_skipped}");
            }
        }
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

fn cmd_info(args: &InfoCommandArgs) -> i32 {
    match (|| -> Result<i32> {
        let stats = rpc_client(&args.connection).candidate_stats()?;
        println!("{}", serde_json::to_string_pretty(&stats)?);
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

fn cmd_shutdown(args: &ShutdownArgs) -> i32 {
    match (|| -> Result<i32> {
        let response = rpc_client(&args.connection).shutdown()?;
        println!("{response}");
        Ok(0)
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

#[derive(Debug, Parser)]
#[command(name = "yaya", about = "YAYA server/client CLI (candidate mode only).")]
struct Cli {
    #[arg(
        long = "perf-report",
        global = true,
        help = "Write JSON performance report to this path."
    )]
    perf_report: Option<String>,
    #[arg(long = "perf-stdout", global = true, action = ArgAction::SetTrue, help = "Print JSON performance report on exit.")]
    perf_stdout: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    Serve(ServeArgs),
    Index(IndexArgs),
    Delete(DeleteArgs),
    Search(SearchCommandArgs),
    Info(InfoCommandArgs),
    Shutdown(ShutdownArgs),
    Yara(YaraArgs),
}

#[derive(Debug, clap::Args)]
struct IndexArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(required = true, help = "File or directory paths.")]
    paths: Vec<String>,
    #[arg(
        long = "batch-size",
        default_value_t = 64,
        help = "Documents per insert_batch request."
    )]
    batch_size: usize,
    #[arg(
        long = "workers",
        default_value_t = default_ingest_workers(),
        help = "Process workers for recursive file scan/feature extraction before batched inserts."
    )]
    workers: usize,
    #[arg(long = "verbose", action = ArgAction::SetTrue, help = "Print timing details to stderr.")]
    verbose: bool,
}

#[derive(Debug, clap::Args)]
struct DeleteArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(
        required = true,
        help = "Existing file paths or hex digests in the server's configured identity format."
    )]
    values: Vec<String>,
}

#[derive(Debug, clap::Args)]
struct SearchCommandArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "rule", required = true, help = "Path to YARA rule file.")]
    rule: String,
    #[arg(
        long = "max-anchors-per-pattern",
        default_value_t = 16,
        help = "Keep at most this many anchors per pattern alternative."
    )]
    max_anchors_per_pattern: usize,
    #[arg(
        long = "max-candidates",
        default_value_t = 15000,
        help = "Server-side cap on returned candidate set size; 0 means unlimited."
    )]
    max_candidates: usize,
    #[arg(
        long = "verify",
        action = ArgAction::SetTrue,
        default_value_t = false,
        help = "Enable local YARA verification over candidate file paths."
    )]
    verify_yara_files: bool,
    #[arg(long = "verbose", action = ArgAction::SetTrue, help = "Print timing details to stderr.")]
    verbose: bool,
}

#[derive(Debug, clap::Args)]
struct InfoCommandArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
}

#[derive(Debug, clap::Args)]
struct ShutdownArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
}

#[derive(Debug, clap::Args)]
struct YaraArgs {
    #[arg(long = "rule", required = true, help = "Path to YARA rule file.")]
    rule: String,
    #[arg(help = "Path to the file to scan.")]
    file_path: String,
    #[arg(
        long = "scan-timeout",
        default_value_t = 60,
        help = "YARA scan timeout in seconds (default: 60)."
    )]
    scan_timeout: u64,
    #[arg(
        long = "show-tags",
        action = ArgAction::SetTrue,
        help = "Print matched rule tags."
    )]
    show_tags: bool,
}

#[derive(Debug, clap::Args)]
struct ServeArgs {
    #[arg(
        long = "addr",
        env = "YAYA_ADDR",
        default_value = DEFAULT_RPC_ADDR,
        help = "Bind address as host:port."
    )]
    addr: String,
    #[arg(long = "max-request-bytes", default_value_t = DEFAULT_MAX_REQUEST_BYTES, help = "Maximum accepted request size in bytes.")]
    max_request_bytes: usize,
    #[arg(
        long = "search-workers",
        default_value_t = default_search_workers(),
        help = "Server-side shard query workers. Default is max(1, cpus/4)."
    )]
    search_workers: usize,
    #[arg(
        long = "memory-budget-gb",
        default_value_t = DEFAULT_MEMORY_BUDGET_GB,
        help = "Configured indexing memory budget in GiB. Client-side indexing backpressure will use the lower of this value and available memory."
    )]
    memory_budget_gb: u64,
    #[arg(
        long = "tier2-superblock-budget-divisor",
        default_value_t = DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
        help = "Divides the server memory budget to derive the per-shard Tier2 summary-memory budget. Lower values allow more RAM for Tier2 summaries."
    )]
    tier2_superblock_budget_divisor: u64,
    #[arg(
        long = "root",
        default_value = DEFAULT_CANDIDATE_ROOT,
        help = "Workspace root directory. YAYA will manage current/, work/, and retired/ under this path."
    )]
    root: String,
    #[arg(
        long = "shards",
        default_value_t = 256,
        help = "Number of independent candidate shards (lock stripes) for ingest/write paths."
    )]
    shards: usize,
    #[arg(
        long = "set-fp",
        default_value_t = 0.35,
        help = "Target Bloom false-positive rate (default: 0.35)."
    )]
    filter_target_fp: f64,
    #[arg(
        long = "id-source",
        value_enum,
        default_value_t = CandidateIdSource::Sha256,
        help = "DB-wide document identity source used by ingest and delete."
    )]
    id_source: CandidateIdSource,
    #[arg(
        long = "store-path",
        action = ArgAction::SetTrue,
        help = "Store the canonical file path as external_id for each inserted document."
    )]
    store_path: bool,
    #[arg(
        long = "gram-sizes",
        default_value = "3,4",
        help = "DB-wide gram-size pair as tier2,tier1. Supported pairs: 3,4 4,5 5,6 7,8."
    )]
    gram_sizes: String,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
struct InternalInitArgs {
    #[arg(long = "root", default_value = DEFAULT_CANDIDATE_ROOT, help = "Candidate store root directory.")]
    root: String,
    #[arg(
        long = "candidate-shards",
        default_value_t = 1,
        help = "Number of independent candidate shards (lock stripes) to initialize."
    )]
    candidate_shards: usize,
    #[arg(long = "force", action = ArgAction::SetTrue, help = "Overwrite an existing candidate store.")]
    force: bool,
    #[arg(
        long = "set-fp",
        default_value_t = 0.35,
        help = "Optional bloom false-positive target used to size variable filters."
    )]
    filter_target_fp: f64,
    #[arg(
        long = "gram-sizes",
        default_value = "3,4",
        help = "DB-wide gram-size pair as tier2,tier1. Supported pairs: 3,4 4,5 5,6 7,8."
    )]
    gram_sizes: String,
    #[arg(
        long = "compaction-idle-cooldown-s",
        default_value_t = 5.0,
        help = "Minimum idle time after writes before compaction is allowed to run."
    )]
    compaction_idle_cooldown_s: f64,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
struct InternalIndexArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    file_path: String,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    #[arg(
        long = "external-id",
        help = "Optional external identifier to associate with the document."
    )]
    external_id: Option<String>,
    #[arg(long = "chunk-size", default_value_t = 1024 * 1024, help = "File read chunk size in bytes.")]
    chunk_size: usize,
    #[arg(
        long = "max-unique-grams",
        help = "Optional hard cap on unique grams collected before sampling."
    )]
    max_unique_grams: Option<usize>,
    #[arg(long = "no-grams", action = ArgAction::SetTrue, help = "Store only tier2 bloom data for this document.")]
    no_grams: bool,
}

#[derive(Debug, clap::Args)]
struct InternalIndexBatchArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    paths: Vec<String>,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    #[arg(
        long = "batch-size",
        default_value_t = 64,
        help = "Documents per batch request."
    )]
    batch_size: usize,
    #[arg(
        long = "workers",
        default_value_t = default_ingest_workers(),
        help = "Workers for recursive file scan before batched inserts."
    )]
    workers: usize,
    #[arg(long = "chunk-size", default_value_t = 1024 * 1024, help = "Client read chunk size in bytes.")]
    chunk_size: usize,
    #[arg(
        long = "max-unique-grams",
        help = "Optional cap for unique grams sent to the store."
    )]
    max_unique_grams: Option<usize>,
    #[arg(long = "no-grams", action = ArgAction::SetTrue, help = "Do not send grams to Tier1 postings; only bloom coverage is sent.")]
    no_grams: bool,
    #[arg(long = "external-id-from-path", action = ArgAction::SetTrue, help = "Set external_id=<file path> for each inserted document.")]
    external_id_from_path: bool,
    #[arg(long = "verbose", action = ArgAction::SetTrue, help = "Print timing details to stderr.")]
    verbose: bool,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
struct InternalDeleteArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    values: Vec<String>,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
struct InternalQueryArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    #[arg(long = "rule", help = "Path to a restricted-YARA rule file.")]
    rule: String,
    #[arg(long = "cursor", default_value_t = 0, help = "Result cursor offset.")]
    cursor: usize,
    #[arg(long = "chunk-size", default_value_t = 128, help = "Page size.")]
    chunk_size: usize,
    #[arg(
        long = "max-anchors-per-pattern",
        alias = "max-anchors-per-alt",
        default_value_t = 16,
        help = "Maximum grams kept per pattern alternative after DF ranking."
    )]
    max_anchors_per_pattern: usize,
    #[arg(long = "force-tier1-only", action = ArgAction::SetTrue, help = "Disable tier2 fallback for complete documents.")]
    force_tier1_only: bool,
    #[arg(long = "no-tier2-fallback", action = ArgAction::SetTrue, help = "Disable optional tier2 fallback on complete documents.")]
    no_tier2_fallback: bool,
    #[arg(
        long = "max-candidates",
        default_value_t = 15000,
        help = "Maximum candidate hashes returned before paging; 0 means unlimited."
    )]
    max_candidates: usize,
    #[arg(long = "no-df-lookup", action = ArgAction::SetTrue, help = "Skip DF lookup when selecting rare anchors.")]
    no_df_lookup: bool,
}

#[cfg(test)]
#[derive(Debug, clap::Args)]
struct InternalStatsArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
}

pub fn main(argv: Option<Vec<String>>) -> i32 {
    let cli = match argv {
        Some(values) => Cli::parse_from(values),
        None => Cli::parse(),
    };
    perf::configure(cli.perf_report.as_ref().map(PathBuf::from), cli.perf_stdout);

    let exit_code = match cli.command {
        Commands::Serve(args) => cmd_serve(&args),
        Commands::Index(args) => cmd_ingest(&args),
        Commands::Delete(args) => cmd_delete(&args),
        Commands::Search(args) => cmd_search_candidates(&args),
        Commands::Info(args) => cmd_info(&args),
        Commands::Shutdown(args) => cmd_shutdown(&args),
        Commands::Yara(args) => cmd_yara_check(&args),
    };
    if let Err(err) = perf::write_report(exit_code) {
        eprintln!("failed to write perf report: {err}");
        if exit_code == 0 {
            return 1;
        }
    }
    exit_code
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    use crate::candidate::{CandidateConfig, CompiledQueryPlan, PatternPlan, QueryNode};

    fn default_connection() -> ClientConnectionArgs {
        ClientConnectionArgs {
            addr: DEFAULT_RPC_ADDR.to_owned(),
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    fn default_internal_init_args(
        root: &Path,
        candidate_shards: usize,
        force: bool,
    ) -> InternalInitArgs {
        InternalInitArgs {
            root: root.display().to_string(),
            candidate_shards,
            force,
            filter_target_fp: 0.35,
            gram_sizes: "3,4".to_owned(),
            compaction_idle_cooldown_s: 5.0,
        }
    }

    fn start_tcp_test_server(base: &Path, shard_count: usize) -> ClientConnectionArgs {
        start_tcp_test_server_with_config(RpcServerConfig {
            candidate_config: CandidateConfig {
                root: base.join("server_candidate_db"),
                ..CandidateConfig::default()
            },
            candidate_shards: shard_count,
            search_workers: default_search_workers_for(4),
            memory_budget_bytes: DEFAULT_MEMORY_BUDGET_BYTES,
            tier2_superblock_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
            workspace_mode: true,
        })
    }

    fn start_tcp_test_server_with_config(config: RpcServerConfig) -> ClientConnectionArgs {
        let listener =
            std::net::TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind test listener");
        let port = listener.local_addr().expect("listener addr").port();
        drop(listener);
        thread::spawn(move || {
            let _ = rpc::serve(
                DEFAULT_RPC_HOST,
                port,
                None,
                DEFAULT_MAX_REQUEST_BYTES,
                config,
            );
        });
        let connection = ClientConnectionArgs {
            addr: format!("{DEFAULT_RPC_HOST}:{port}"),
            timeout: 0.5,
        };
        for _ in 0..100 {
            if rpc_client(&connection).ping().is_ok() {
                return connection;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("test rpc server did not become ready");
    }

    fn default_serve_args() -> ServeArgs {
        ServeArgs {
            addr: DEFAULT_RPC_ADDR.to_owned(),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            search_workers: default_search_workers_for(4),
            memory_budget_gb: DEFAULT_MEMORY_BUDGET_GB,
            tier2_superblock_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
            root: DEFAULT_CANDIDATE_ROOT.to_owned(),
            shards: 256,
            filter_target_fp: 0.35,
            id_source: CandidateIdSource::Sha256,
            store_path: false,
            gram_sizes: "3,4".to_owned(),
        }
    }

    #[test]
    fn parse_host_port_accepts_common_forms() {
        assert_eq!(
            parse_host_port("127.0.0.1:17653").expect("ipv4"),
            ("127.0.0.1".to_owned(), 17653)
        );
        assert_eq!(
            parse_host_port("example.com:443").expect("hostname"),
            ("example.com".to_owned(), 443)
        );
        assert_eq!(
            parse_host_port("[::1]:17653").expect("ipv6"),
            ("::1".to_owned(), 17653)
        );
    }

    #[test]
    fn parse_host_port_rejects_invalid_values() {
        assert!(parse_host_port("").is_err());
        assert!(parse_host_port("127.0.0.1").is_err());
        assert!(parse_host_port(":17653").is_err());
        assert!(parse_host_port("127.0.0.1:notaport").is_err());
        assert!(parse_host_port("[::1]").is_err());
    }

    #[test]
    fn file_path_collection_and_hash_helpers_work() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let nested = tmp.path().join("nested");
        let child = nested.join("child");
        fs::create_dir_all(&child).expect("mkdir");
        let sample = child.join("sample.bin");
        fs::write(&sample, b"abcdef").expect("write sample");

        let resolved = resolved_file_path(&sample).expect("resolve");
        assert_eq!(resolved, fs::canonicalize(&sample).expect("canonicalize"));
        assert_eq!(
            path_identity_sha256(&sample).expect("path hash"),
            path_identity_sha256(&resolved).expect("path hash again")
        );
        let file_digest = sha256_file(&sample, 2).expect("sha256 file");
        assert_ne!(
            file_digest,
            path_identity_sha256(&sample).expect("path digest")
        );
        assert!(
            sha256_file(&sample, 0)
                .expect_err("zero chunk size")
                .to_string()
                .contains("positive integer")
        );

        let mut files = Vec::new();
        collect_files_recursive(tmp.path(), &mut files).expect("collect files");
        files.sort();
        assert!(files.contains(&sample));
        let mut singleton = Vec::new();
        collect_files_recursive(&sample, &mut singleton).expect("collect single file");
        assert_eq!(singleton, vec![sample.clone()]);
        let mut missing = Vec::new();
        collect_files_recursive(&tmp.path().join("missing.bin"), &mut missing)
            .expect("missing path should be ignored");
        assert!(missing.is_empty());
        assert!(resolved_file_path(&tmp.path().join("missing.bin")).is_err());
        assert!(path_identity_sha256(&tmp.path().join("missing.bin")).is_err());
        assert!(decode_sha256_hex("abcd").is_err());
    }

    #[test]
    fn json_config_and_row_wire_helpers_work() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let mut stats = serde_json::Map::new();
        stats.insert("count".to_owned(), serde_json::json!(7));
        stats.insert("ratio".to_owned(), serde_json::json!(0.25));
        assert_eq!(json_usize(&stats, "count", 0), 7);
        assert_eq!(json_usize(&stats, "missing", 5), 5);
        assert_eq!(json_f64_opt(&stats, "ratio"), Some(0.25));
        assert_eq!(json_f64_opt(&stats, "missing"), None);

        let fixed = store_config_from_parts(
            PathBuf::from("root"),
            CandidateIdSource::Sha256,
            true,
            0.001,
            3,
            4,
            33.5,
        );
        assert_eq!(fixed.root, PathBuf::from("root"));
        assert_eq!(fixed.id_source, "sha256");
        assert!(fixed.store_path);
        assert_eq!(fixed.tier2_gram_size, 3);
        assert_eq!(fixed.tier1_gram_size, 4);
        assert_eq!(fixed.filter_target_fp, Some(0.001));
        assert_eq!(fixed.compaction_idle_cooldown_s, 33.5);

        let variable = store_config_from_parts(
            PathBuf::from("root"),
            CandidateIdSource::Sha256,
            false,
            0.01,
            5,
            4,
            9.25,
        );
        assert_eq!(variable.root, PathBuf::from("root"));
        assert_eq!(variable.id_source, "sha256");
        assert!(!variable.store_path);
        assert_eq!(variable.filter_target_fp, Some(0.01));
        assert_eq!(variable.tier2_gram_size, 5);
        assert_eq!(variable.tier1_gram_size, 4);
        assert_eq!(variable.compaction_idle_cooldown_s, 9.25);

        let wire = batch_row_to_wire(IndexBatchRow {
            sha256: [0xAA; 32],
            file_size: 123,
            filter_bytes: 2048,
            gram_count_estimate: Some(77),
            bloom_hashes: 3,
            bloom_filter: vec![1, 2, 3, 4],
            tier2_filter_bytes: 0,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: 0,
            tier2_bloom_filter: Vec::new(),
            grams: vec![1, 2, 3],
            grams_complete: true,
            effective_diversity: None,
            external_id: Some("x".to_owned()),
        });
        assert_eq!(wire.sha256, hex::encode([0xAA; 32]));
        assert_eq!(wire.file_size, 123);
        assert!(wire.grams.is_empty());
        assert_eq!(
            crate::candidate::decode_grams_delta_u32(
                &base64::Engine::decode(
                    &base64::engine::general_purpose::STANDARD,
                    wire.grams_delta_b64.expect("packed grams"),
                )
                .expect("decode b64")
            )
            .expect("decode grams"),
            vec![1, 2, 3]
        );
        assert_eq!(wire.external_id.as_deref(), Some("x"));

        let tmp = tempdir().expect("tmp");
        let config = CandidateConfig {
            root: tmp.path().join("candidate_db"),
            ..CandidateConfig::default()
        };
        let store = ensure_store(config.clone(), true).expect("init store");
        assert_eq!(store.stats().doc_count, 0);
        let reopened = ensure_store(config, false).expect("reopen store");
        assert_eq!(reopened.stats().doc_count, 0);
    }

    #[test]
    fn default_ingest_workers_matches_python_formula() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        assert_eq!(default_ingest_workers_for(1), 1);
        assert_eq!(default_ingest_workers_for(2), 1);
        assert_eq!(default_ingest_workers_for(3), 1);
        assert_eq!(default_ingest_workers_for(4), 2);
        assert_eq!(default_ingest_workers_for(7), 3);
        assert_eq!(default_ingest_workers_for(8), 6);
        assert_eq!(default_ingest_workers_for(9), 6);
        assert_eq!(default_ingest_workers_for(16), 12);
    }

    #[test]
    fn default_search_workers_is_quarter_cpu_floor() {
        assert_eq!(default_search_workers_for(1), 1);
        assert_eq!(default_search_workers_for(2), 1);
        assert_eq!(default_search_workers_for(3), 1);
        assert_eq!(default_search_workers_for(4), 1);
        assert_eq!(default_search_workers_for(7), 1);
        assert_eq!(default_search_workers_for(8), 2);
        assert_eq!(default_search_workers_for(16), 4);
        assert_eq!(default_search_workers_for(20), 5);
    }

    #[test]
    fn scan_candidate_batch_and_legacy_query_helpers_work() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let sample = tmp.path().join("sample.bin");
        fs::write(&sample, b"well hello there").expect("sample");

        let row = scan_index_batch_row(
            &sample,
            ScanPolicy {
                fixed_filter_bytes: Some(2048),
                filter_target_fp: None,
                gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
                chunk_size: 4,
                max_unique_grams: None,
                _no_grams: false,
                store_path: true,
                id_source: CandidateIdSource::Sha256,
            },
        )
        .expect("scan row");
        assert_eq!(
            row.external_id.as_deref(),
            Some(
                sample
                    .canonicalize()
                    .expect("canon")
                    .to_string_lossy()
                    .as_ref()
            )
        );
        assert!(!row.grams.is_empty());
        assert!(row.grams_complete);

        let md5_row = scan_index_batch_row(
            &sample,
            ScanPolicy {
                fixed_filter_bytes: Some(2048),
                filter_target_fp: None,
                gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
                chunk_size: 4,
                max_unique_grams: Some(2),
                _no_grams: true,
                store_path: false,
                id_source: CandidateIdSource::Md5,
            },
        )
        .expect("scan md5 row");
        assert_eq!(
            md5_row.sha256,
            identity_from_file(&sample, 4, CandidateIdSource::Md5).expect("md5 id")
        );
        assert!(!md5_row.grams.is_empty());
        assert!(!md5_row.grams_complete);
        assert!(md5_row.external_id.is_none());

        assert_eq!(legacy_operand_from_gram(0x01020304, 4), "04030201");
        let plan = CompiledQueryPlan {
            patterns: vec![
                PatternPlan {
                    pattern_id: "$a".to_owned(),
                    alternatives: vec![vec![0x01020304]],
                    tier2_alternatives: vec![Vec::new()],
                    fixed_literals: vec![Vec::new()],
                },
                PatternPlan {
                    pattern_id: "$b".to_owned(),
                    alternatives: vec![vec![0x05060708], vec![0x11121314, 0x21222324]],
                    tier2_alternatives: vec![Vec::new(), Vec::new()],
                    fixed_literals: vec![Vec::new(), Vec::new()],
                },
            ],
            root: QueryNode {
                kind: "and".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$a".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "n_of".to_owned(),
                        pattern_id: None,
                        threshold: Some(1),
                        children: vec![QueryNode {
                            kind: "pattern".to_owned(),
                            pattern_id: Some("$b".to_owned()),
                            threshold: None,
                            children: Vec::new(),
                        }],
                    },
                ],
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 100,
            tier2_gram_size: 3,
            tier1_gram_size: 4,
        };
        let legacy = legacy_query_from_plan(&plan).expect("legacy query");
        assert!(legacy.contains("04030201"));
        assert!(legacy.contains("08070605"));
        assert_eq!(merge_tier_used(Vec::<String>::new()), "unknown");
        assert_eq!(merge_tier_used(vec![" tier1 ".to_owned()]), "tier1");
        assert_eq!(
            merge_tier_used(vec!["tier1".to_owned(), "tier2".to_owned()]),
            "tier1+tier2"
        );

        let rule_path = tmp.path().join("rule.yar");
        fs::write(
            &rule_path,
            "rule test { strings: $a = \"hello\" condition: $a }\n",
        )
        .expect("rule");
        assert!(compile_yara_verifier(&rule_path).is_ok());
        let bad_rule_path = tmp.path().join("bad_rule.yar");
        fs::write(&bad_rule_path, "rule {").expect("bad rule");
        assert!(compile_yara_verifier(&bad_rule_path).is_err());

        let single_rule_path = tmp.path().join("single_rule.yar");
        fs::write(
            &single_rule_path,
            "rule single_rule { strings: $a = { 41 42 43 44 } condition: $a }\n",
        )
        .expect("single rule");
        assert_eq!(rule_file_has_single_rule(&single_rule_path), Some(true));

        let multi_rule_path = tmp.path().join("multi_rule.yar");
        fs::write(
            &multi_rule_path,
            concat!(
                "rule first { strings: $a = { 41 42 43 44 } condition: $a }\n",
                "rule second { strings: $a = { 45 46 47 48 } condition: $a }\n",
            ),
        )
        .expect("multi rule");
        assert_eq!(rule_file_has_single_rule(&multi_rule_path), Some(false));
        assert!(fixed_literal_plan_from_rule(&multi_rule_path).is_none());

        let fixed_match_path = tmp.path().join("fixed.bin");
        fs::write(&fixed_match_path, b"--ABCDEFGH--").expect("fixed match");
        let fixed_plan = FixedLiteralMatchPlan {
            literals: HashMap::from([
                ("$a".to_owned(), vec![b"ABCD".to_vec()]),
                ("$b".to_owned(), vec![b"EFGH".to_vec()]),
            ]),
            root: QueryNode {
                kind: "and".to_owned(),
                pattern_id: None,
                threshold: None,
                children: vec![
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$a".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$b".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                ],
            },
        };
        assert!(verify_fixed_literal_plan_on_file(&fixed_match_path, &fixed_plan).expect("match"));
        fs::write(&fixed_match_path, b"--ABCD----").expect("fixed miss");
        assert!(!verify_fixed_literal_plan_on_file(&fixed_match_path, &fixed_plan).expect("miss"));

        let degenerate = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$empty".to_owned(),
                alternatives: vec![Vec::new()],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
            }],
            root: QueryNode {
                kind: "n_of".to_owned(),
                pattern_id: None,
                threshold: Some(0),
                children: vec![QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("$empty".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                }],
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 1,
            tier2_gram_size: 3,
            tier1_gram_size: 4,
        };
        assert!(legacy_query_from_plan(&degenerate).is_none());
    }

    #[test]
    fn candidate_helper_commands_work() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let base = tmp.path();
        let sample_dir = base.join("samples");
        let candidate_root = base.join("candidate_db");
        let rule_path = base.join("rule.yar");
        fs::create_dir_all(&sample_dir).expect("sample dir");
        let sample_a = sample_dir.join("a.bin");
        let sample_b = sample_dir.join("b.bin");
        fs::write(&sample_a, b"xxABCDyy").expect("sample a");
        fs::write(&sample_b, b"zzABCDqq").expect("sample b");
        fs::write(
            &rule_path,
            r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
        )
        .expect("rule");

        let candidate_init_args = default_internal_init_args(&candidate_root, 1, true);
        assert_eq!(cmd_internal_init(&candidate_init_args), 0);

        let ingest_one = InternalIndexArgs {
            connection: default_connection(),
            file_path: sample_a.display().to_string(),
            root: Some(candidate_root.display().to_string()),
            external_id: Some("manual-a".to_owned()),
            chunk_size: 1024,
            max_unique_grams: None,
            no_grams: false,
        };
        assert_eq!(cmd_internal_index(&ingest_one), 0);

        let ingest_batch = InternalIndexBatchArgs {
            connection: default_connection(),
            paths: vec![sample_dir.display().to_string()],
            root: Some(candidate_root.display().to_string()),
            batch_size: 1,
            workers: 2,
            chunk_size: 1024,
            max_unique_grams: None,
            no_grams: false,
            external_id_from_path: true,
            verbose: false,
        };
        assert_eq!(cmd_internal_index_batch(&ingest_batch), 0);

        let query_args = InternalQueryArgs {
            connection: default_connection(),
            root: Some(candidate_root.display().to_string()),
            rule: rule_path.display().to_string(),
            cursor: 0,
            chunk_size: 10,
            max_anchors_per_pattern: 8,
            force_tier1_only: false,
            no_tier2_fallback: false,
            max_candidates: 100,
            no_df_lookup: false,
        };
        assert_eq!(cmd_internal_query(&query_args), 0);

        let stats_args = InternalStatsArgs {
            connection: default_connection(),
            root: Some(candidate_root.display().to_string()),
        };
        assert_eq!(cmd_internal_stats(&stats_args), 0);

        let delete_args = InternalDeleteArgs {
            connection: default_connection(),
            root: Some(candidate_root.display().to_string()),
            values: vec![sample_a.display().to_string()],
        };
        assert_eq!(cmd_internal_delete(&delete_args), 0);
        assert_eq!(
            cmd_internal_delete(&InternalDeleteArgs {
                connection: default_connection(),
                root: Some(candidate_root.display().to_string()),
                values: Vec::new(),
            }),
            1
        );
    }

    #[test]
    fn yara_check_and_main_dispatch_work() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let rule_path = tmp.path().join("rule.yar");
        let hit_path = tmp.path().join("hit.bin");
        fs::write(
            &rule_path,
            "rule TestLiteral : tag_a { strings: $a = \"hello\" condition: $a }\n",
        )
        .expect("rule");
        fs::write(&hit_path, b"well hello there").expect("hit");

        assert_eq!(
            cmd_yara_check(&YaraArgs {
                rule: rule_path.display().to_string(),
                file_path: hit_path.display().to_string(),
                scan_timeout: 1,
                show_tags: true,
            }),
            0
        );
        assert_eq!(
            cmd_yara_check(&YaraArgs {
                rule: tmp.path().join("missing.yar").display().to_string(),
                file_path: hit_path.display().to_string(),
                scan_timeout: 1,
                show_tags: false,
            }),
            1
        );
        assert_eq!(
            main(Some(vec![
                "yaya".to_owned(),
                "yara".to_owned(),
                "--rule".to_owned(),
                rule_path.display().to_string(),
                hit_path.display().to_string(),
            ])),
            0
        );
    }

    #[test]
    fn local_multishard_candidate_commands_cover_root_branches() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let base = tmp.path();
        let sample_dir = base.join("samples");
        let candidate_root = base.join("candidate_db");
        let rule_path = base.join("rule.yar");
        fs::create_dir_all(&sample_dir).expect("sample dir");
        let sample_a = sample_dir.join("a.bin");
        let sample_b = sample_dir.join("b.bin");
        let sample_c = sample_dir.join("c.bin");
        fs::write(&sample_a, b"ABCD tail").expect("sample a");
        fs::write(&sample_b, b"prefix ABCD").expect("sample b");
        fs::write(&sample_c, b"ABCD extra").expect("sample c");
        fs::write(
            &rule_path,
            r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
        )
        .expect("rule");

        assert_eq!(
            cmd_internal_init(&default_internal_init_args(&candidate_root, 2, true)),
            0
        );
        assert_eq!(
            cmd_internal_init(&default_internal_init_args(&candidate_root, 2, false)),
            0
        );
        assert_eq!(
            cmd_internal_init(&default_internal_init_args(&candidate_root, 1, false)),
            1
        );

        assert_eq!(
            cmd_internal_index_batch(&InternalIndexBatchArgs {
                connection: default_connection(),
                paths: vec![
                    sample_dir.display().to_string(),
                    base.join("missing").display().to_string(),
                ],
                root: Some(candidate_root.display().to_string()),
                batch_size: 1,
                workers: 1,
                chunk_size: 1024,
                max_unique_grams: Some(128),
                no_grams: false,
                external_id_from_path: true,
                verbose: false,
            }),
            0
        );
        assert_eq!(
            cmd_internal_index_batch(&InternalIndexBatchArgs {
                connection: default_connection(),
                paths: vec![base.join("missing_only").display().to_string()],
                root: Some(candidate_root.display().to_string()),
                batch_size: 1,
                workers: 1,
                chunk_size: 1024,
                max_unique_grams: None,
                no_grams: false,
                external_id_from_path: false,
                verbose: false,
            }),
            1
        );
        assert_eq!(
            cmd_internal_index(&InternalIndexArgs {
                connection: default_connection(),
                file_path: sample_a.display().to_string(),
                root: Some(candidate_root.display().to_string()),
                external_id: Some("manual-root-id".to_owned()),
                chunk_size: 1024,
                max_unique_grams: Some(64),
                no_grams: false,
            }),
            0
        );
        assert_eq!(
            cmd_internal_query(&InternalQueryArgs {
                connection: default_connection(),
                root: Some(candidate_root.display().to_string()),
                rule: rule_path.display().to_string(),
                cursor: 0,
                chunk_size: 1,
                max_anchors_per_pattern: 2,
                force_tier1_only: false,
                no_tier2_fallback: false,
                max_candidates: 2,
                no_df_lookup: false,
            }),
            0
        );
        assert_eq!(
            cmd_internal_query(&InternalQueryArgs {
                connection: default_connection(),
                root: Some(candidate_root.display().to_string()),
                rule: rule_path.display().to_string(),
                cursor: 0,
                chunk_size: 4,
                max_anchors_per_pattern: 4,
                force_tier1_only: true,
                no_tier2_fallback: true,
                max_candidates: 8,
                no_df_lookup: true,
            }),
            0
        );
        assert_eq!(
            cmd_internal_stats(&InternalStatsArgs {
                connection: default_connection(),
                root: Some(candidate_root.display().to_string()),
            }),
            0
        );
        let path_sha = hex::encode(sha256_file(&sample_b, 1024).expect("sha256"));
        assert_eq!(
            cmd_internal_delete(&InternalDeleteArgs {
                connection: default_connection(),
                root: Some(candidate_root.display().to_string()),
                values: vec![path_sha],
            }),
            0
        );
    }

    #[cfg(unix)]
    #[test]
    fn remote_candidate_commands_cover_rpc_branches() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let base = tmp.path();
        let sample_dir = base.join("remote_samples");
        fs::create_dir_all(&sample_dir).expect("sample dir");
        let sample_a = sample_dir.join("a.bin");
        let sample_b = sample_dir.join("b.bin");
        let sample_c = sample_dir.join("c.bin");
        fs::write(&sample_a, b"ABCD remote one").expect("sample a");
        fs::write(&sample_b, b"prefix ABCD remote two").expect("sample b");
        fs::write(&sample_c, b"ABCD remote three").expect("sample c");
        let rule_path = base.join("remote_rule.yar");
        fs::write(
            &rule_path,
            r#"
rule remote_q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
        )
        .expect("rule");
        let connection = start_tcp_test_server(base, 2);
        let policy = server_scan_policy(&connection).expect("scan policy from server");
        assert_eq!(policy.id_source, CandidateIdSource::Sha256);
        assert!(!policy.store_path);
        assert_eq!(policy.filter_target_fp, Some(0.35));
        assert_eq!(policy.gram_sizes, GramSizes::new(3, 4).expect("gram sizes"));

        assert_eq!(
            cmd_internal_index(&InternalIndexArgs {
                connection: connection.clone(),
                file_path: sample_a.display().to_string(),
                root: None,
                external_id: Some(base.join("missing-match.bin").display().to_string()),
                chunk_size: 1024,
                max_unique_grams: Some(64),
                no_grams: false,
            }),
            0
        );
        assert_eq!(
            cmd_ingest(&IndexArgs {
                connection: connection.clone(),
                paths: vec![
                    sample_b.display().to_string(),
                    sample_c.display().to_string()
                ],
                batch_size: 1,
                workers: 2,
                verbose: false,
            }),
            0
        );
        assert_eq!(
            cmd_internal_query(&InternalQueryArgs {
                connection: connection.clone(),
                root: None,
                rule: rule_path.display().to_string(),
                cursor: 0,
                chunk_size: 1,
                max_anchors_per_pattern: 1,
                force_tier1_only: false,
                no_tier2_fallback: false,
                max_candidates: 4,
                no_df_lookup: false,
            }),
            0
        );
        assert_eq!(
            cmd_internal_query(&InternalQueryArgs {
                connection: connection.clone(),
                root: None,
                rule: rule_path.display().to_string(),
                cursor: 0,
                chunk_size: 4,
                max_anchors_per_pattern: 2,
                force_tier1_only: true,
                no_tier2_fallback: true,
                max_candidates: 4,
                no_df_lookup: true,
            }),
            0
        );
        assert_eq!(
            cmd_search_candidates(&SearchCommandArgs {
                connection: connection.clone(),
                rule: rule_path.display().to_string(),
                max_anchors_per_pattern: 2,
                max_candidates: 8,
                verify_yara_files: false,
                verbose: false,
            }),
            0
        );
        assert_eq!(
            cmd_search_candidates(&SearchCommandArgs {
                connection: connection.clone(),
                rule: rule_path.display().to_string(),
                max_anchors_per_pattern: 2,
                max_candidates: 8,
                verify_yara_files: true,
                verbose: false,
            }),
            0
        );
        assert_eq!(
            cmd_internal_stats(&InternalStatsArgs {
                connection: connection.clone(),
                root: None,
            }),
            0
        );
        assert_eq!(
            cmd_info(&InfoCommandArgs {
                connection: connection.clone(),
            }),
            0
        );
        assert_eq!(
            cmd_delete(&DeleteArgs {
                connection: connection.clone(),
                values: vec![sample_a.display().to_string()],
            }),
            0
        );
        assert_eq!(
            main(Some(vec![
                "yaya".to_owned(),
                "--perf-report".to_owned(),
                base.join("perf").join("stats.json").display().to_string(),
                "info".to_owned(),
                "--addr".to_owned(),
                connection.addr.clone(),
            ])),
            0
        );
    }

    #[test]
    fn main_returns_error_when_perf_report_path_is_unwritable() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let perf_dir = tmp.path().join("perf-as-dir");
        let rule_path = tmp.path().join("rule.yar");
        let hit_path = tmp.path().join("hit.bin");
        fs::create_dir_all(&perf_dir).expect("perf dir");
        fs::write(
            &rule_path,
            "rule TestLiteral { strings: $a = \"hello\" condition: $a }\n",
        )
        .expect("rule");
        fs::write(&hit_path, b"hello").expect("hit");
        assert_eq!(
            main(Some(vec![
                "yaya".to_owned(),
                "--perf-report".to_owned(),
                perf_dir.display().to_string(),
                "yara".to_owned(),
                "--rule".to_owned(),
                rule_path.display().to_string(),
                hit_path.display().to_string(),
            ])),
            1
        );
        crate::perf::configure(None, false);
    }

    #[test]
    fn cmd_serve_reports_tcp_bind_errors() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let listener =
            std::net::TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind occupied port");
        let port = listener.local_addr().expect("listener addr").port();
        let mut args = default_serve_args();
        args.addr = format!("{DEFAULT_RPC_HOST}:{port}");
        assert_eq!(cmd_serve(&args), 1);
    }

    #[test]
    fn local_command_error_paths_report_failures() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let sample = tmp.path().join("sample.bin");
        let missing_root = tmp.path().join("missing_root");
        let missing_rule = tmp.path().join("missing_rule.yar");
        fs::write(&sample, b"ABCD").expect("sample");

        assert_eq!(
            cmd_internal_index(&InternalIndexArgs {
                connection: default_connection(),
                file_path: sample.display().to_string(),
                root: Some(missing_root.display().to_string()),
                external_id: None,
                chunk_size: 1024,
                max_unique_grams: None,
                no_grams: false,
            }),
            1
        );
        assert_eq!(
            cmd_internal_stats(&InternalStatsArgs {
                connection: default_connection(),
                root: Some(missing_root.display().to_string()),
            }),
            1
        );
        assert_eq!(
            cmd_internal_query(&InternalQueryArgs {
                connection: default_connection(),
                root: Some(missing_root.display().to_string()),
                rule: missing_rule.display().to_string(),
                cursor: 0,
                chunk_size: 1,
                max_anchors_per_pattern: 1,
                force_tier1_only: false,
                no_tier2_fallback: false,
                max_candidates: 1,
                no_df_lookup: false,
            }),
            1
        );
        assert_eq!(
            cmd_delete(&DeleteArgs {
                connection: default_connection(),
                values: vec!["not-a-valid-digest".to_owned()],
            }),
            1
        );
    }

    #[cfg(unix)]
    #[test]
    fn public_ingest_and_delete_follow_server_identity_source() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let base = tmp.path();
        let sample = base.join("identity.bin");
        fs::write(&sample, b"ABCD identity").expect("sample");

        let connection = start_tcp_test_server_with_config(RpcServerConfig {
            candidate_config: CandidateConfig {
                root: base.join("candidate_db"),
                id_source: "md5".to_owned(),
                ..CandidateConfig::default()
            },
            candidate_shards: 1,
            search_workers: default_search_workers_for(4),
            memory_budget_bytes: DEFAULT_MEMORY_BUDGET_BYTES,
            tier2_superblock_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
            workspace_mode: true,
        });

        assert_eq!(
            cmd_ingest(&IndexArgs {
                connection: connection.clone(),
                paths: vec![sample.display().to_string()],
                batch_size: 1,
                workers: 1,
                verbose: false,
            }),
            0
        );

        assert_eq!(
            cmd_delete(&DeleteArgs {
                connection: connection.clone(),
                values: vec![hex::encode(sha256_file(&sample, 1024).expect("sha256"))],
            }),
            1
        );

        assert_eq!(
            cmd_delete(&DeleteArgs {
                connection,
                values: vec![hex::encode(md5_file(&sample, 1024).expect("md5"))],
            }),
            0
        );
    }

    #[test]
    fn non_sha256_identity_sources_normalize_consistently() {
        let tmp = tempdir().expect("tmp");
        let sample = tmp.path().join("sample.bin");
        fs::write(&sample, b"identity-check-bytes").expect("sample");

        let md5_bytes = md5_file(&sample, 1024).expect("md5");
        let sha1_bytes = sha1_file(&sample, 1024).expect("sha1");
        let sha512_bytes = sha512_file(&sample, 1024).expect("sha512");

        assert_eq!(
            identity_from_file(&sample, 1024, CandidateIdSource::Md5).expect("md5 file"),
            identity_from_hex(&hex::encode(md5_bytes), CandidateIdSource::Md5).expect("md5 hex")
        );
        assert_eq!(
            identity_from_file(&sample, 1024, CandidateIdSource::Sha1).expect("sha1 file"),
            identity_from_hex(&hex::encode(sha1_bytes), CandidateIdSource::Sha1).expect("sha1 hex")
        );
        assert_eq!(
            identity_from_file(&sample, 1024, CandidateIdSource::Sha512).expect("sha512 file"),
            identity_from_hex(&hex::encode(sha512_bytes), CandidateIdSource::Sha512)
                .expect("sha512 hex")
        );

        assert_ne!(
            identity_from_file(&sample, 1024, CandidateIdSource::Md5).expect("md5 file"),
            sha256_file(&sample, 1024).expect("sha256 file")
        );
    }

    #[test]
    fn digest_helpers_and_delete_resolution_cover_remaining_branches() {
        let tmp = tempdir().expect("tmp");
        let sample = tmp.path().join("sample.bin");
        fs::write(&sample, b"identity-check-bytes").expect("sample");

        assert!(
            md5_file(&sample, 0)
                .expect_err("md5 zero chunk")
                .to_string()
                .contains("positive integer")
        );
        assert!(
            sha1_file(&sample, 0)
                .expect_err("sha1 zero chunk")
                .to_string()
                .contains("positive integer")
        );
        assert!(
            sha512_file(&sample, 0)
                .expect_err("sha512 zero chunk")
                .to_string()
                .contains("positive integer")
        );

        assert_eq!(
            detect_digest_identity_source(&"aa".repeat(16)),
            Some(CandidateIdSource::Md5)
        );
        assert_eq!(
            detect_digest_identity_source(&"bb".repeat(20)),
            Some(CandidateIdSource::Sha1)
        );
        assert_eq!(
            detect_digest_identity_source(&"cc".repeat(32)),
            Some(CandidateIdSource::Sha256)
        );
        assert_eq!(
            detect_digest_identity_source(&"dd".repeat(64)),
            Some(CandidateIdSource::Sha512)
        );
        assert_eq!(detect_digest_identity_source("not-hex"), None);
        assert_eq!(detect_digest_identity_source(&"ee".repeat(12)), None);

        let sha256_hex = hex::encode(sha256_file(&sample, 1024).expect("sha256"));
        let md5_hex = hex::encode(md5_file(&sample, 1024).expect("md5"));
        let sha1_hex = hex::encode(sha1_file(&sample, 1024).expect("sha1"));
        let sha512_hex = hex::encode(sha512_file(&sample, 1024).expect("sha512"));

        assert_eq!(
            resolve_delete_value(
                sample.to_str().expect("sample"),
                CandidateIdSource::Sha256,
                1024,
            )
            .expect("path delete resolution"),
            hex::encode(
                identity_from_file(&sample, 1024, CandidateIdSource::Sha256)
                    .expect("path identity")
            )
        );
        assert_eq!(
            resolve_delete_value(&md5_hex, CandidateIdSource::Md5, 1024)
                .expect("md5 delete resolution"),
            hex::encode(
                identity_from_hex(&md5_hex, CandidateIdSource::Md5).expect("normalized md5")
            )
        );
        assert_eq!(
            resolve_delete_value(&sha1_hex, CandidateIdSource::Sha1, 1024)
                .expect("sha1 delete resolution"),
            hex::encode(
                identity_from_hex(&sha1_hex, CandidateIdSource::Sha1).expect("normalized sha1")
            )
        );
        assert_eq!(
            resolve_delete_value(&sha512_hex, CandidateIdSource::Sha512, 1024)
                .expect("sha512 delete resolution"),
            hex::encode(
                identity_from_hex(&sha512_hex, CandidateIdSource::Sha512)
                    .expect("normalized sha512")
            )
        );
        assert!(
            resolve_delete_value(&md5_hex, CandidateIdSource::Sha256, 1024)
                .expect_err("mismatched digest type")
                .to_string()
                .contains("server identity source is")
        );
        assert!(
            resolve_delete_value("not-a-path-or-digest", CandidateIdSource::Sha256, 1024)
                .expect_err("invalid delete value")
                .to_string()
                .contains("is neither an existing file path nor a valid")
        );

        assert_eq!(
            resolve_delete_identity(
                Some(&sha256_hex),
                None,
                None,
                None,
                None,
                CandidateIdSource::Sha256,
                1024,
            )
            .expect("legacy helper"),
            hex::encode(
                identity_from_hex(&sha256_hex, CandidateIdSource::Sha256)
                    .expect("normalized sha256")
            )
        );
    }
}
