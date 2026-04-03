use std::collections::{HashMap, HashSet, VecDeque};
use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, Once, OnceLock};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

use clap::{ArgAction, Parser, Subcommand, ValueEnum};
use crossbeam_channel::bounded;
use md5::Md5;
use serde::Serialize;
use sha1::Sha1;
use sha2::{Digest, Sha256, Sha512};
#[cfg(unix)]
use signal_hook::consts::signal::{SIGINT, SIGTERM, SIGUSR1};
use yara_x::{Compiler as YaraCompiler, Rules as YaraRules, Scanner as YaraScanner};

use crate::candidate::filter_policy::align_filter_bytes;
use crate::candidate::query_plan::{
    FixedLiteralMatchPlan, evaluate_fixed_literal_match, fixed_literal_match_plan,
};
use crate::candidate::write_candidate_shard_count;
use crate::candidate::{
    BoundedCache, CandidateConfig, CandidateStore, DEFAULT_TIER1_FILTER_TARGET_FP,
    DEFAULT_TIER2_FILTER_TARGET_FP, GramSizes, HLL_DEFAULT_PRECISION, candidate_shard_index,
    candidate_shard_root, choose_filter_bytes_for_file_size,
    compile_query_plan_from_file_with_gram_sizes,
    compile_query_plan_from_file_with_gram_sizes_and_identity_source,
    derive_document_bloom_hash_count, estimate_unique_grams_for_size_hll,
    estimate_unique_grams_pair_hll, extract_compact_document_metadata, read_candidate_shard_count,
    resolve_max_candidates, scan_file_features_bloom_only_with_gram_sizes,
};
use crate::perf;
use crate::rpc::{
    self, ClientConfig as RpcClientConfig, PersistentSspryClient, ServerConfig as RpcServerConfig,
    SspryClient,
};
use crate::{Result, SspryError};

pub const DEFAULT_CANDIDATE_ROOT: &str = "candidate_db";
pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: u16 = 17653;
pub const DEFAULT_RPC_ADDR: &str = "127.0.0.1:17653";
pub const DEFAULT_RPC_TIMEOUT: f64 = 30.0;
pub const DEFAULT_SEARCH_RPC_TIMEOUT: f64 = 180.0;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
pub const DEFAULT_SEARCH_RESULT_CHUNK_SIZE: usize = 1024;
pub const DEFAULT_FILE_READ_CHUNK_SIZE: usize = 1024 * 1024;
pub const DEFAULT_MEMORY_BUDGET_GB: u64 = 16;
pub const DEFAULT_MEMORY_BUDGET_BYTES: u64 = DEFAULT_MEMORY_BUDGET_GB * 1024 * 1024 * 1024;
pub const DEFAULT_STANDARD_SHARDS: usize = 256;
pub const DEFAULT_INCREMENTAL_SHARDS: usize = 32;
const ESTIMATED_INDEX_QUEUE_ITEM_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INDEX_QUEUE_CAPACITY: usize = 256;
const STORAGE_CLASS_SAMPLE_LIMIT: usize = 16;
const REMOTE_INDEX_ROTATION_RETRY_LIMIT: usize = 2400;
const REMOTE_INDEX_ROTATION_RETRY_SLEEP_MS: u64 = 50;
const INDEX_CLIENT_HEARTBEAT_INTERVAL_MS: u64 = 1_000;

fn parse_max_candidates_percent(value: &str) -> std::result::Result<f64, String> {
    let parsed = value
        .parse::<f64>()
        .map_err(|_| "max-candidates must be a percentage between 0 and 100".to_owned())?;
    if parsed.is_finite() && (0.0..=100.0).contains(&parsed) {
        Ok(parsed)
    } else {
        Err("max-candidates must be a percentage between 0 and 100".to_owned())
    }
}

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
        return Err(SspryError::from(format!(
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IngestStorageClass {
    Unknown,
    SolidState,
    Rotational,
}

impl IngestStorageClass {
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::SolidState => "solid-state",
            Self::Rotational => "rotational",
        }
    }
}

#[cfg(unix)]
fn dev_major_minor(dev: u64) -> (u64, u64) {
    let major = ((dev >> 8) & 0x0fff) | ((dev >> 32) & !0x0fff);
    let minor = (dev & 0x00ff) | ((dev >> 12) & !0x00ff);
    (major, minor)
}

#[cfg(unix)]
fn nearest_existing_path(path: &Path) -> Option<PathBuf> {
    let mut current = path.to_path_buf();
    loop {
        if current.exists() {
            return Some(current);
        }
        if !current.pop() {
            return None;
        }
    }
}

#[cfg(unix)]
fn detect_storage_class_for_path(path: &Path) -> IngestStorageClass {
    use std::os::unix::fs::MetadataExt;

    let Some(existing_path) = nearest_existing_path(path) else {
        return IngestStorageClass::Unknown;
    };
    let Ok(metadata) = fs::metadata(existing_path) else {
        return IngestStorageClass::Unknown;
    };
    let (major, minor) = dev_major_minor(metadata.dev());
    let sys_block = PathBuf::from(format!("/sys/dev/block/{major}:{minor}"));
    let canonical = fs::canonicalize(&sys_block).unwrap_or(sys_block);
    for ancestor in canonical.ancestors() {
        let rotational_path = ancestor.join("queue").join("rotational");
        if let Ok(raw) = fs::read_to_string(&rotational_path) {
            return match raw.trim() {
                "0" => IngestStorageClass::SolidState,
                "1" => IngestStorageClass::Rotational,
                _ => IngestStorageClass::Unknown,
            };
        }
    }
    IngestStorageClass::Unknown
}

#[cfg(not(unix))]
fn detect_storage_class_for_path(_path: &Path) -> IngestStorageClass {
    IngestStorageClass::Unknown
}

fn detect_storage_class_for_paths(paths: &[PathBuf]) -> IngestStorageClass {
    let mut saw_solid_state = false;
    for path in paths.iter().take(STORAGE_CLASS_SAMPLE_LIMIT) {
        match detect_storage_class_for_path(path) {
            IngestStorageClass::Rotational => return IngestStorageClass::Rotational,
            IngestStorageClass::SolidState => saw_solid_state = true,
            IngestStorageClass::Unknown => {}
        }
    }
    if saw_solid_state {
        IngestStorageClass::SolidState
    } else {
        IngestStorageClass::Unknown
    }
}

fn adaptive_publish_prior_for_root(root: &Path) -> (String, u64) {
    match detect_storage_class_for_path(root) {
        IngestStorageClass::SolidState => ("solid-state".to_owned(), 0),
        IngestStorageClass::Rotational => ("rotational".to_owned(), 1_500),
        IngestStorageClass::Unknown => ("unknown".to_owned(), 500),
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResolvedIngestWorkers {
    workers: usize,
    auto: bool,
    input_storage: IngestStorageClass,
    output_storage: IngestStorageClass,
}

fn auto_ingest_workers_for(
    cpus: usize,
    total_files: usize,
    input_storage: IngestStorageClass,
    output_storage: IngestStorageClass,
) -> usize {
    let cpu_default = default_ingest_workers_for(cpus);
    let workload_cap = total_files.max(1).min(cpu_default);
    let storage_cap = if matches!(input_storage, IngestStorageClass::Rotational)
        || matches!(output_storage, IngestStorageClass::Rotational)
    {
        4
    } else {
        cpu_default
    };
    workload_cap.min(storage_cap).max(1)
}

fn resolve_ingest_workers(
    requested_workers: usize,
    total_files: usize,
    input_roots: &[PathBuf],
    output_root: Option<&Path>,
) -> ResolvedIngestWorkers {
    let input_storage = detect_storage_class_for_paths(input_roots);
    let output_storage = output_root
        .map(detect_storage_class_for_path)
        .unwrap_or(IngestStorageClass::Unknown);
    if requested_workers > 0 {
        return ResolvedIngestWorkers {
            workers: requested_workers.max(1),
            auto: false,
            input_storage,
            output_storage,
        };
    }
    let cpus = std::thread::available_parallelism()
        .map(|value| value.get())
        .unwrap_or(1);
    ResolvedIngestWorkers {
        workers: auto_ingest_workers_for(cpus, total_files, input_storage, output_storage),
        auto: true,
        input_storage,
        output_storage,
    }
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

#[derive(Clone, Copy, Debug, ValueEnum, PartialEq, Eq)]
enum ServeLayoutProfile {
    Standard,
    Incremental,
}

fn default_shards_for_profile(profile: ServeLayoutProfile) -> usize {
    match profile {
        ServeLayoutProfile::Standard => DEFAULT_STANDARD_SHARDS,
        ServeLayoutProfile::Incremental => DEFAULT_INCREMENTAL_SHARDS,
    }
}

fn serve_candidate_shard_count(args: &ServeArgs) -> usize {
    args.shards
        .unwrap_or_else(|| default_shards_for_profile(args.layout_profile))
        .max(1)
}

#[derive(Debug, Clone, clap::Args)]
struct ClientConnectionArgs {
    #[arg(
        long = "addr",
        env = "SSPRY_ADDR",
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
        return Err(SspryError::from(
            "addr must be a non-empty host:port value.",
        ));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let (host, port_text) = rest
            .split_once("]:")
            .ok_or_else(|| SspryError::from("addr must use [ipv6]:port for IPv6 addresses."))?;
        let port = port_text
            .parse::<u16>()
            .map_err(|_| SspryError::from("addr port must be a valid u16 value."))?;
        return Ok((host.to_owned(), port));
    }
    let (host, port_text) = trimmed
        .rsplit_once(':')
        .ok_or_else(|| SspryError::from("addr must be formatted as host:port."))?;
    if host.is_empty() {
        return Err(SspryError::from("addr host must not be empty."));
    }
    let port = port_text
        .parse::<u16>()
        .map_err(|_| SspryError::from("addr port must be a valid u16 value."))?;
    Ok((host.to_owned(), port))
}

fn resolved_file_path(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(SspryError::from)
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

#[derive(Debug, Default, Clone, Copy)]
struct ProcessSmapsRollupKb {
    rss_kb: u64,
    anonymous_kb: u64,
    private_clean_kb: u64,
    private_dirty_kb: u64,
    shared_clean_kb: u64,
}

fn current_process_smaps_rollup_kb() -> ProcessSmapsRollupKb {
    let text = fs::read_to_string("/proc/self/smaps_rollup").unwrap_or_default();
    let mut out = ProcessSmapsRollupKb::default();
    for line in text.lines() {
        if let Some(value) = line.strip_prefix("Rss:") {
            out.rss_kb = value
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("Anonymous:") {
            out.anonymous_kb = value
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("Private_Clean:") {
            out.private_clean_kb = value
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("Private_Dirty:") {
            out.private_dirty_kb = value
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(0);
        } else if let Some(value) = line.strip_prefix("Shared_Clean:") {
            out.shared_clean_kb = value
                .split_whitespace()
                .next()
                .and_then(|text| text.parse::<u64>().ok())
                .unwrap_or(0);
        }
    }
    out
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
    let status = rpc_client(connection).candidate_status()?;
    let current = status
        .get("current_rss_kb")
        .and_then(|value| value.as_u64());
    let peak = status.get("peak_rss_kb").and_then(|value| value.as_u64());
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

pub(crate) fn normalize_identity_digest(kind: &str, bytes: &[u8]) -> [u8; 32] {
    let mut digest = Sha256::new();
    digest.update(b"sspry-identity\0");
    digest.update(kind.as_bytes());
    digest.update(b"\0");
    digest.update(bytes);
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.finalize());
    out
}

fn sha256_file(path: &Path, chunk_size: usize) -> Result<[u8; 32]> {
    if chunk_size == 0 {
        return Err(SspryError::from("chunk_size must be a positive integer."));
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
        return Err(SspryError::from("chunk_size must be a positive integer."));
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
        return Err(SspryError::from("chunk_size must be a positive integer."));
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
        return Err(SspryError::from("chunk_size must be a positive integer."));
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
        return Err(SspryError::from(
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
        return Err(SspryError::from(format!(
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
        return Err(SspryError::from(
            "Provide exactly one of `--sha256`, `--md5`, `--sha1`, `--sha512`, or `--file-path`.",
        ));
    }
    Ok(hex::encode(chosen.expect("chosen identity")))
}

fn sorted_directory_children(path: &Path) -> Result<Vec<PathBuf>> {
    let mut children = fs::read_dir(path)?
        .map(|entry| entry.map(|value| value.path()).map_err(SspryError::from))
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

fn expand_input_paths(paths: &[String], path_list: bool) -> Result<Vec<PathBuf>> {
    let mut candidates = Vec::new();
    if path_list {
        for list_path_text in paths {
            let list_path = PathBuf::from(list_path_text);
            if !list_path.exists() {
                println!("Skipping missing path: {}", list_path.display());
                continue;
            }
            let base_dir = list_path
                .parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| PathBuf::from("."));
            for line in fs::read_to_string(&list_path)?.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() {
                    continue;
                }
                let entry_path = PathBuf::from(trimmed);
                let resolved = if entry_path.is_absolute() {
                    entry_path
                } else {
                    base_dir.join(entry_path)
                };
                candidates.push(resolved);
            }
        }
        candidates.sort();
        candidates.dedup();
        return Ok(candidates);
    } else {
        candidates.extend(paths.iter().map(PathBuf::from));
    }
    let mut roots = Vec::new();
    for path in candidates {
        if path.exists() {
            roots.push(path);
        } else {
            println!("Skipping missing path: {}", path.display());
        }
    }
    roots.sort();
    roots.dedup();
    Ok(roots)
}

fn count_input_files(paths: &[PathBuf]) -> Result<usize> {
    let mut total = 0usize;
    for path in paths {
        total = total.saturating_add(count_files_recursive(path)?);
    }
    Ok(total)
}

fn input_paths_are_file_only(paths: &[PathBuf]) -> bool {
    !paths.is_empty() && paths.iter().all(|path| path.is_file())
}

fn stream_selected_input_files(
    paths: &[PathBuf],
    path_list: bool,
    mut visit: impl FnMut(PathBuf) -> Result<()>,
) -> Result<()> {
    if path_list {
        for path in paths {
            visit(path.clone())?;
        }
        Ok(())
    } else {
        stream_input_files(paths, &mut visit)
    }
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

fn rpc_client(connection: &ClientConnectionArgs) -> SspryClient {
    rpc_client_with_timeout(connection, connection.timeout)
}

fn rpc_client_with_timeout(connection: &ClientConnectionArgs, timeout_secs: f64) -> SspryClient {
    let (host, port) = connection
        .host_port()
        .expect("client connection addr should parse");
    SspryClient::new(RpcClientConfig::new(
        host,
        port,
        Duration::from_secs_f64(timeout_secs.max(0.0)),
        None,
    ))
}

fn search_rpc_client(connection: &ClientConnectionArgs) -> SspryClient {
    rpc_client_with_timeout(
        connection,
        connection.timeout.max(DEFAULT_SEARCH_RPC_TIMEOUT),
    )
}

struct ScannedIndexBatchRow {
    row: IndexBatchRow,
    scan_elapsed: Duration,
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
const INTERNAL_BLOOM_HASHES: usize = 7;

#[derive(Clone, Copy, Debug, PartialEq)]
struct ServerScanPolicy {
    id_source: CandidateIdSource,
    store_path: bool,
    tier1_filter_target_fp: Option<f64>,
    tier2_filter_target_fp: Option<f64>,
    gram_sizes: GramSizes,
    memory_budget_bytes: u64,
}

fn server_scan_policy(connection: &ClientConnectionArgs) -> Result<ServerScanPolicy> {
    let stats = rpc_client(connection).candidate_stats()?;
    let legacy_filter_target_fp = json_f64_opt(&stats, "filter_target_fp");
    let gram_sizes = GramSizes::new(
        stats
            .get("tier1_gram_size")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| SspryError::from("candidate stats missing tier1_gram_size"))?
            as usize,
        stats
            .get("tier2_gram_size")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| SspryError::from("candidate stats missing tier2_gram_size"))?
            as usize,
    )?;
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
        tier1_filter_target_fp: json_f64_opt(&stats, "tier1_filter_target_fp")
            .or(legacy_filter_target_fp),
        tier2_filter_target_fp: json_f64_opt(&stats, "tier2_filter_target_fp")
            .or(legacy_filter_target_fp),
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
            return Err(SspryError::from("delete value exists but is not a file."));
        }
        return Ok(hex::encode(identity_from_file(
            path,
            chunk_size,
            server_id_source,
        )?));
    }
    let detected = detect_digest_identity_source(value).ok_or_else(|| {
        SspryError::from(
            "delete value is neither an existing file path nor a valid md5/sha1/sha256/sha512 hex digest.",
        )
    })?;
    if detected != server_id_source {
        return Err(SspryError::from(format!(
            "delete value is a {} digest but the server identity source is {}.",
            detected.as_str(),
            server_id_source.as_str()
        )));
    }
    Ok(hex::encode(identity_from_hex(value, detected)?))
}

fn serialize_candidate_document_binary_row(row: &IndexBatchRow) -> Result<Vec<u8>> {
    rpc::serialize_candidate_insert_binary_row_parts(
        &row.sha256,
        row.file_size,
        row.bloom_item_estimate,
        &row.bloom_filter,
        row.tier2_bloom_item_estimate,
        &row.tier2_bloom_filter,
        row.special_population,
        &row.metadata,
        row.external_id.as_deref(),
    )
}

const REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES: usize = DEFAULT_MAX_REQUEST_BYTES - 1024;
const REMOTE_INDEX_SESSION_MAX_DOCUMENTS: usize = 2048;
const REMOTE_INDEX_SESSION_MIN_INPUT_BYTES: u64 = 1 << 30;
const REMOTE_INDEX_SESSION_MAX_INPUT_BYTES: u64 = 4 << 30;
const REMOTE_UPLOAD_QUEUE_MAX_BYTES: usize = 512 * 1024 * 1024;

struct RemotePendingBatch {
    rows: Vec<Vec<u8>>,
    payload_size: usize,
}

struct RemoteUploadRow {
    row_bytes: Vec<u8>,
    file_size: u64,
}

struct RemoteUploadQueueState {
    rows: VecDeque<RemoteUploadRow>,
    queued_bytes: usize,
    closed: bool,
}

struct RemoteUploadQueue {
    state: Mutex<RemoteUploadQueueState>,
    not_empty: Condvar,
    not_full: Condvar,
    byte_limit: usize,
}

impl RemoteUploadQueue {
    fn new(byte_limit: usize) -> Self {
        Self {
            state: Mutex::new(RemoteUploadQueueState {
                rows: VecDeque::new(),
                queued_bytes: 0,
                closed: false,
            }),
            not_empty: Condvar::new(),
            not_full: Condvar::new(),
            byte_limit,
        }
    }

    fn push(&self, row: RemoteUploadRow) -> Result<()> {
        let row_bytes = row.row_bytes.len();
        if row_bytes > self.byte_limit {
            return Err(SspryError::from(format!(
                "serialized remote row exceeds upload queue limit ({} bytes > {} bytes)",
                row_bytes, self.byte_limit
            )));
        }
        let mut state = self
            .state
            .lock()
            .map_err(|_| SspryError::from("remote upload queue lock poisoned"))?;
        while !state.closed
            && state.queued_bytes.saturating_add(row_bytes) > self.byte_limit
            && !state.rows.is_empty()
        {
            state = self
                .not_full
                .wait(state)
                .map_err(|_| SspryError::from("remote upload queue lock poisoned"))?;
        }
        if state.closed {
            return Err(SspryError::from("remote upload queue closed"));
        }
        state.queued_bytes = state.queued_bytes.saturating_add(row_bytes);
        state.rows.push_back(row);
        self.not_empty.notify_one();
        Ok(())
    }

    fn pop(&self) -> Result<Option<RemoteUploadRow>> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SspryError::from("remote upload queue lock poisoned"))?;
        loop {
            if let Some(row) = state.rows.pop_front() {
                state.queued_bytes = state.queued_bytes.saturating_sub(row.row_bytes.len());
                self.not_full.notify_all();
                return Ok(Some(row));
            }
            if state.closed {
                return Ok(None);
            }
            state = self
                .not_empty
                .wait(state)
                .map_err(|_| SspryError::from("remote upload queue lock poisoned"))?;
        }
    }

    fn close(&self) -> Result<()> {
        let mut state = self
            .state
            .lock()
            .map_err(|_| SspryError::from("remote upload queue lock poisoned"))?;
        state.closed = true;
        self.not_empty.notify_all();
        self.not_full.notify_all();
        Ok(())
    }
}

struct RemoteEncodeStats {
    scan_time: Duration,
    result_wait_time: Duration,
    encode_time: Duration,
}

fn remote_index_session_document_limit(effective_budget_bytes: u64, batch_size: usize) -> usize {
    if effective_budget_bytes == 0 {
        return REMOTE_INDEX_SESSION_MAX_DOCUMENTS.max(batch_size);
    }
    let derived = usize::try_from(effective_budget_bytes / (640 * 1024) / 4).unwrap_or(usize::MAX);
    derived.clamp(batch_size.max(1), REMOTE_INDEX_SESSION_MAX_DOCUMENTS)
}

fn remote_index_session_input_bytes_limit(effective_budget_bytes: u64) -> u64 {
    if effective_budget_bytes == 0 {
        return REMOTE_INDEX_SESSION_MAX_INPUT_BYTES;
    }
    (effective_budget_bytes / 4).clamp(
        REMOTE_INDEX_SESSION_MIN_INPUT_BYTES,
        REMOTE_INDEX_SESSION_MAX_INPUT_BYTES,
    )
}

fn remote_upload_queue_byte_limit(
    effective_budget_bytes: u64,
    remote_batch_soft_limit_bytes: usize,
) -> usize {
    let minimum = remote_batch_soft_limit_bytes.saturating_mul(2);
    if effective_budget_bytes == 0 {
        return minimum.min(REMOTE_UPLOAD_QUEUE_MAX_BYTES);
    }
    let derived =
        usize::try_from(effective_budget_bytes / 8).unwrap_or(REMOTE_UPLOAD_QUEUE_MAX_BYTES);
    derived.clamp(minimum, REMOTE_UPLOAD_QUEUE_MAX_BYTES)
}

fn empty_remote_batch_payload_size() -> Result<usize> {
    Ok(rpc::serialized_candidate_insert_binary_batch_payload(&[]).len())
}

fn prepare_serialized_remote_batch_row(
    pending: &RemotePendingBatch,
    row_payload_size: usize,
    empty_payload_size: usize,
    remote_batch_soft_limit_bytes: usize,
) -> Result<bool> {
    let single_payload_size = empty_payload_size.saturating_add(row_payload_size);
    if single_payload_size > remote_batch_soft_limit_bytes {
        return Err(SspryError::from(format!(
            "single document insert request exceeds payload limit ({} bytes)",
            single_payload_size
        )));
    }
    Ok(!pending.rows.is_empty()
        && pending
            .payload_size
            .saturating_add(1)
            .saturating_add(row_payload_size)
            > remote_batch_soft_limit_bytes)
}

fn flush_remote_batch(
    client: &mut PersistentSspryClient,
    pending: &mut RemotePendingBatch,
    processed: &mut usize,
    empty_payload_size: usize,
    verbose: bool,
) -> Result<()> {
    if pending.rows.is_empty() {
        return Ok(());
    }
    let flush_rows = pending.rows.len();
    let flush_payload_size = pending.payload_size;
    let started = Instant::now();
    let inserted_count = client
        .candidate_insert_batch_binary_rows(&pending.rows)?
        .inserted_count;
    if verbose {
        eprintln!(
            "verbose.index.remote_flush rows={} payload_bytes={} inserted={} elapsed_ms={:.3}",
            flush_rows,
            flush_payload_size,
            inserted_count,
            started.elapsed().as_secs_f64() * 1000.0
        );
    }
    *processed += inserted_count;
    pending.rows.clear();
    pending.payload_size = empty_payload_size;
    Ok(())
}

fn push_serialized_remote_upload_row(
    client: &mut PersistentSspryClient,
    pending: &mut RemotePendingBatch,
    row_bytes: Vec<u8>,
    batch_size: usize,
    processed: &mut usize,
    submit_time: &mut Duration,
    show_progress: bool,
    total_files: usize,
    last_progress_reported: &mut usize,
    last_progress_at: &mut Instant,
    empty_payload_size: usize,
    remote_batch_soft_limit_bytes: usize,
    verbose: bool,
) -> Result<Duration> {
    let started_buffer = Instant::now();
    let flush_before = prepare_serialized_remote_batch_row(
        pending,
        row_bytes.len(),
        empty_payload_size,
        remote_batch_soft_limit_bytes,
    )?;
    let mut buffer_time = started_buffer.elapsed();
    if flush_before {
        flush_remote_pending_rows(
            client,
            pending,
            processed,
            submit_time,
            show_progress,
            total_files,
            last_progress_reported,
            last_progress_at,
            empty_payload_size,
            verbose,
        )?;
    }
    let started_buffer = Instant::now();
    let flush_after = push_serialized_remote_batch_row(
        pending,
        row_bytes,
        batch_size,
        remote_batch_soft_limit_bytes,
    )?;
    buffer_time += started_buffer.elapsed();
    if flush_after {
        flush_remote_pending_rows(
            client,
            pending,
            processed,
            submit_time,
            show_progress,
            total_files,
            last_progress_reported,
            last_progress_at,
            empty_payload_size,
            verbose,
        )?;
    }
    Ok(buffer_time)
}

fn push_serialized_remote_batch_row(
    pending: &mut RemotePendingBatch,
    row_bytes: Vec<u8>,
    batch_size: usize,
    remote_batch_soft_limit_bytes: usize,
) -> Result<bool> {
    let row_payload_size = row_bytes.len();
    let separator_bytes = usize::from(!pending.rows.is_empty());
    let payload_size = pending
        .payload_size
        .saturating_add(separator_bytes)
        .saturating_add(row_payload_size);
    if payload_size > remote_batch_soft_limit_bytes {
        return Err(SspryError::from(
            "remote batch row exceeded payload limit before flush",
        ));
    }
    pending.rows.push(row_bytes);
    pending.payload_size = payload_size;
    Ok(pending.rows.len() >= batch_size)
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
        let _ = stores[shard_idx].insert_document_with_metadata(
            row.sha256,
            row.file_size,
            row.bloom_item_estimate,
            None,
            row.tier2_bloom_item_estimate,
            None,
            row.filter_bytes,
            &row.bloom_filter,
            row.tier2_filter_bytes,
            &row.tier2_bloom_filter,
            &row.metadata,
            row.special_population,
            row.external_id,
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
    client: &mut PersistentSspryClient,
    pending: &mut RemotePendingBatch,
    processed: &mut usize,
    submit_time: &mut Duration,
    show_progress: bool,
    total_files: usize,
    last_progress_reported: &mut usize,
    last_progress_at: &mut Instant,
    empty_payload_size: usize,
    verbose: bool,
) -> Result<()> {
    let started_submit = Instant::now();
    flush_remote_batch(client, pending, processed, empty_payload_size, verbose)?;
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

fn rotate_remote_index_session(
    base_client: &SspryClient,
    client: &mut PersistentSspryClient,
    pending: &mut RemotePendingBatch,
    processed: &mut usize,
    submit_time: &mut Duration,
    show_progress: bool,
    total_files: usize,
    last_progress_reported: &mut usize,
    last_progress_at: &mut Instant,
    empty_payload_size: usize,
    progress_rpc_time: &mut Duration,
    verbose: bool,
) -> Result<()> {
    flush_remote_pending_rows(
        client,
        pending,
        processed,
        submit_time,
        show_progress,
        total_files,
        last_progress_reported,
        last_progress_at,
        empty_payload_size,
        verbose,
    )?;
    let started_progress_rpc = Instant::now();
    client.end_index_session()?;
    *progress_rpc_time += started_progress_rpc.elapsed();
    base_client.publish()?;
    let started_progress_rpc = Instant::now();
    let mut retries = 0usize;
    loop {
        *client = base_client.connect_persistent()?;
        let resume = (|| -> Result<()> {
            client.begin_index_session()?;
            client.update_index_session_progress(Some(total_files), *processed, *processed)?;
            Ok(())
        })();
        match resume {
            Ok(()) => break,
            Err(err)
                if is_retryable_remote_index_rotation_error(&err)
                    && retries < REMOTE_INDEX_ROTATION_RETRY_LIMIT =>
            {
                retries = retries.saturating_add(1);
                thread::sleep(Duration::from_millis(REMOTE_INDEX_ROTATION_RETRY_SLEEP_MS));
            }
            Err(err) => return Err(err),
        }
    }
    *progress_rpc_time += started_progress_rpc.elapsed();
    Ok(())
}

fn is_retryable_remote_index_rotation_error(err: &SspryError) -> bool {
    let text = err.to_string();
    (text.contains("server is publishing") && text.contains("retry later"))
        || (text.contains("another index session is already active")
            && text.contains("retry later"))
        || text.contains("no active index session; cannot update progress")
}

fn store_config_from_parts(
    root: PathBuf,
    id_source: CandidateIdSource,
    store_path: bool,
    tier1_filter_target_fp: f64,
    tier2_filter_target_fp: f64,
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
        tier1_filter_target_fp: Some(tier1_filter_target_fp),
        tier2_filter_target_fp: Some(tier2_filter_target_fp),
        filter_target_fp: if (tier1_filter_target_fp - tier2_filter_target_fp).abs() < f64::EPSILON
        {
            Some(tier1_filter_target_fp)
        } else {
            None
        },
        compaction_idle_cooldown_s: compaction_idle_cooldown_s.max(0.0),
    }
}

fn resolve_filter_target_fps(
    filter_target_fp: Option<f64>,
    tier1_filter_target_fp: Option<f64>,
    tier2_filter_target_fp: Option<f64>,
) -> (f64, f64) {
    let tier1_default = filter_target_fp.unwrap_or(DEFAULT_TIER1_FILTER_TARGET_FP);
    let tier2_default = filter_target_fp.unwrap_or(DEFAULT_TIER2_FILTER_TARGET_FP);
    (
        tier1_filter_target_fp.unwrap_or(tier1_default),
        tier2_filter_target_fp.unwrap_or(tier2_default),
    )
}

fn store_config_from_serve_args(args: &ServeArgs) -> CandidateConfig {
    let gram_sizes =
        GramSizes::parse(&args.gram_sizes).expect("validated by clap-compatible serve args");
    let (tier1_filter_target_fp, tier2_filter_target_fp) = resolve_filter_target_fps(
        args.filter_target_fp,
        args.tier1_filter_target_fp,
        args.tier2_filter_target_fp,
    );
    store_config_from_parts(
        PathBuf::from(&args.root),
        args.id_source,
        args.store_path,
        tier1_filter_target_fp,
        tier2_filter_target_fp,
        gram_sizes.tier2,
        gram_sizes.tier1,
        CandidateConfig::default().compaction_idle_cooldown_s,
    )
}

fn store_config_from_init_args(args: &InitArgs) -> CandidateConfig {
    let gram_sizes =
        GramSizes::parse(&args.gram_sizes).expect("validated by clap-compatible init args");
    let (tier1_filter_target_fp, tier2_filter_target_fp) = resolve_filter_target_fps(
        args.filter_target_fp,
        args.tier1_filter_target_fp,
        args.tier2_filter_target_fp,
    );
    store_config_from_parts(
        PathBuf::from(&args.root),
        CandidateIdSource::Sha256,
        false,
        tier1_filter_target_fp,
        tier2_filter_target_fp,
        gram_sizes.tier2,
        gram_sizes.tier1,
        args.compaction_idle_cooldown_s,
    )
}

fn ensure_store(config: CandidateConfig, force: bool) -> Result<CandidateStore> {
    let local_meta_path = config.root.join("store_meta.json");
    let legacy_meta_path = config.root.join("meta.json");
    if force || (!local_meta_path.exists() && !legacy_meta_path.exists()) {
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
struct TreeStoreGroup {
    stores: Vec<CandidateStore>,
}

#[derive(Debug, Default)]
struct LocalTreeQueryAggregate {
    hashes: HashSet<String>,
    external_ids: HashMap<String, Option<String>>,
    tier_used: Vec<String>,
    query_profile: crate::candidate::CandidateQueryProfile,
}

#[derive(Debug)]
struct LocalForestQueryAggregate {
    hashes: Vec<String>,
    total_candidates: usize,
    truncated: bool,
    truncated_limit: Option<usize>,
    tier_used: String,
    query_profile: crate::candidate::CandidateQueryProfile,
    external_ids: Option<Vec<Option<String>>>,
}

#[derive(Debug, Serialize)]
struct BatchSearchRecord {
    rule: String,
    rule_path: String,
    exit_code: i32,
    elapsed_ms_wall: f64,
    error: Option<String>,
    candidates: Option<usize>,
    truncated: Option<bool>,
    truncated_limit: Option<usize>,
    tier_used: Option<String>,
    verified_checked: Option<usize>,
    verified_matched: Option<usize>,
    verified_skipped: Option<usize>,
    verbose_search_total_ms: Option<f64>,
    verbose_search_plan_ms: Option<f64>,
    verbose_search_query_ms: Option<f64>,
    verbose_search_verify_ms: Option<f64>,
    verbose_search_tree_gate_trees_considered: Option<u64>,
    verbose_search_tree_gate_passed: Option<u64>,
    verbose_search_tree_gate_tier1_pruned: Option<u64>,
    verbose_search_tree_gate_tier2_pruned: Option<u64>,
    verbose_search_tree_gate_special_docs_bypass: Option<u64>,
    verbose_search_docs_scanned: Option<u64>,
    verbose_search_metadata_loads: Option<u64>,
    verbose_search_metadata_bytes: Option<u64>,
    verbose_search_tier1_bloom_loads: Option<u64>,
    verbose_search_tier1_bloom_bytes: Option<u64>,
    verbose_search_tier2_bloom_loads: Option<u64>,
    verbose_search_tier2_bloom_bytes: Option<u64>,
    verbose_search_prepared_query_bytes: Option<u64>,
    verbose_search_prepared_pattern_plan_bytes: Option<u64>,
    verbose_search_prepared_mask_cache_bytes: Option<u64>,
    verbose_search_prepared_pattern_count: Option<u64>,
    verbose_search_prepared_mask_cache_entries: Option<u64>,
    verbose_search_prepared_fixed_literal_count: Option<u64>,
    verbose_search_prepared_tier1_alternatives: Option<u64>,
    verbose_search_prepared_tier2_alternatives: Option<u64>,
    verbose_search_prepared_tier1_shift_variants: Option<u64>,
    verbose_search_prepared_tier2_shift_variants: Option<u64>,
    verbose_search_prepared_tier1_any_lane_alternatives: Option<u64>,
    verbose_search_prepared_tier2_any_lane_alternatives: Option<u64>,
    verbose_search_prepared_tier1_compacted_any_lane_alternatives: Option<u64>,
    verbose_search_prepared_tier2_compacted_any_lane_alternatives: Option<u64>,
    verbose_search_prepared_any_lane_variant_sets: Option<u64>,
    verbose_search_prepared_compacted_any_lane_grams: Option<u64>,
    verbose_search_prepared_max_pattern_bytes: Option<u64>,
    verbose_search_prepared_max_pattern_id: Option<String>,
    verbose_search_prepared_impossible_query: Option<bool>,
    verbose_search_max_candidates: Option<f64>,
    verbose_search_max_anchors_per_pattern: Option<usize>,
    verbose_search_candidates: Option<usize>,
    verbose_search_verify_enabled: Option<bool>,
    verbose_search_client_current_rss_kb: Option<usize>,
    verbose_search_client_peak_rss_kb: Option<usize>,
    verbose_search_client_smaps_rss_kb: Option<u64>,
    verbose_search_client_anonymous_kb: Option<u64>,
    verbose_search_client_private_clean_kb: Option<u64>,
    verbose_search_client_private_dirty_kb: Option<u64>,
    verbose_search_client_shared_clean_kb: Option<u64>,
    verbose_search_server_current_rss_kb: Option<u64>,
    verbose_search_server_peak_rss_kb: Option<u64>,
    verbose_search_tree_count: Option<usize>,
    verbose_search_tree_search_workers: Option<usize>,
}

struct SearchVerificationResult {
    rows: Vec<String>,
    verified_checked: usize,
    verified_matched: usize,
    verified_skipped: usize,
}

struct BatchSearchRecordStream {
    json_out: PathBuf,
    partial_json_out: PathBuf,
    json_writer: BufWriter<File>,
    jsonl_out: PathBuf,
    jsonl_writer: BufWriter<File>,
    first_record: bool,
    count: usize,
}

impl BatchSearchRecordStream {
    fn new(json_out: &Path) -> Result<Self> {
        if let Some(parent) = json_out.parent() {
            fs::create_dir_all(parent)?;
        }
        let partial_json_out = append_path_suffix(json_out, ".partial.json");
        let jsonl_out = append_path_suffix(json_out, ".jsonl");
        let mut json_writer = BufWriter::new(File::create(&partial_json_out)?);
        json_writer.write_all(b"[\n")?;
        let jsonl_writer = BufWriter::new(File::create(&jsonl_out)?);
        Ok(Self {
            json_out: json_out.to_path_buf(),
            partial_json_out,
            json_writer,
            jsonl_out,
            jsonl_writer,
            first_record: true,
            count: 0,
        })
    }

    fn push(&mut self, record: &BatchSearchRecord) -> Result<()> {
        if !self.first_record {
            self.json_writer.write_all(b",\n")?;
        } else {
            self.first_record = false;
        }
        serde_json::to_writer_pretty(&mut self.json_writer, record)?;
        self.json_writer.write_all(b"\n")?;
        self.json_writer.flush()?;

        serde_json::to_writer(&mut self.jsonl_writer, record)?;
        self.jsonl_writer.write_all(b"\n")?;
        self.jsonl_writer.flush()?;
        self.count += 1;
        Ok(())
    }

    fn finish(mut self) -> Result<usize> {
        self.json_writer.write_all(b"]\n")?;
        self.json_writer.flush()?;
        self.jsonl_writer.flush()?;
        drop(self.json_writer);
        drop(self.jsonl_writer);
        fs::rename(&self.partial_json_out, &self.json_out)?;
        Ok(self.count)
    }

    fn jsonl_out(&self) -> &Path {
        &self.jsonl_out
    }
}

fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    path.with_file_name(format!("{file_name}{suffix}"))
}

fn forest_tree_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let direct_current = root.join("current");
    if direct_current.is_dir() {
        return Ok(vec![direct_current]);
    }
    let mut tree_roots = fs::read_dir(root)?
        .filter_map(|entry| entry.ok())
        .map(|entry| {
            let path = entry.path();
            let current = path.join("current");
            if current.is_dir() { current } else { path }
        })
        .filter(|path| {
            path.is_dir()
                && path
                    .parent()
                    .and_then(|value| value.file_name().or_else(|| path.file_name()))
                    .and_then(|value| value.to_str())
                    .map(|name| name.starts_with("tree_"))
                    .unwrap_or(false)
        })
        .collect::<Vec<_>>();
    tree_roots.sort();
    if tree_roots.is_empty() {
        Ok(vec![root.to_path_buf()])
    } else {
        Ok(tree_roots)
    }
}

fn open_forest_tree_groups(root: &Path) -> Result<Vec<TreeStoreGroup>> {
    forest_tree_roots(root)?
        .into_iter()
        .map(|tree_root| {
            Ok(TreeStoreGroup {
                stores: open_stores(&tree_root)?,
            })
        })
        .collect()
}

fn validate_forest_search_policy(
    tree_groups: &[TreeStoreGroup],
) -> Result<(GramSizes, Option<String>, usize)> {
    let mut gram_sizes = None::<GramSizes>;
    let mut id_source = None::<String>;
    for group in tree_groups {
        for store in &group.stores {
            let config = store.config();
            let candidate_gram_sizes =
                GramSizes::new(config.tier1_gram_size, config.tier2_gram_size)?;
            if let Some(existing) = gram_sizes {
                if existing != candidate_gram_sizes {
                    return Err(SspryError::from(
                        "candidate stores use mixed gram-size pairs across the forest",
                    ));
                }
            } else {
                gram_sizes = Some(candidate_gram_sizes);
            }
            if let Some(existing) = &id_source {
                if existing != &config.id_source {
                    return Err(SspryError::from(
                        "candidate stores use mixed identity sources across the forest",
                    ));
                }
            } else {
                id_source = Some(config.id_source.clone());
            }
        }
    }
    Ok((gram_sizes.unwrap_or(GramSizes::new(3, 4)?), id_source, 0))
}

fn forest_prepared_query_profile(
    tree_groups: &[TreeStoreGroup],
    plan: &crate::candidate::CompiledQueryPlan,
    _summary_cap_bytes: usize,
) -> Result<crate::candidate::CandidatePreparedQueryProfile> {
    let mut tier1_filter_keys = HashSet::<(usize, usize)>::new();
    let mut tier2_filter_keys = HashSet::<(usize, usize)>::new();
    for group in tree_groups {
        for store in &group.stores {
            tier1_filter_keys.extend(store.tier1_doc_filter_keys());
            tier2_filter_keys.extend(store.tier2_doc_filter_keys());
        }
    }
    let mut ordered_tier1_filter_keys = tier1_filter_keys.into_iter().collect::<Vec<_>>();
    ordered_tier1_filter_keys.sort_unstable();
    let mut ordered_tier2_filter_keys = tier2_filter_keys.into_iter().collect::<Vec<_>>();
    ordered_tier2_filter_keys.sort_unstable();
    Ok(crate::candidate::store::prepared_query_artifacts_profile(
        crate::candidate::store::build_prepared_query_artifacts(
            plan,
            &ordered_tier1_filter_keys,
            &ordered_tier2_filter_keys,
        )?
        .as_ref(),
    ))
}

fn query_store_group_all_candidates(
    stores: &mut [CandidateStore],
    plan: &crate::candidate::CompiledQueryPlan,
    include_external_ids: bool,
) -> Result<LocalTreeQueryAggregate> {
    let mut out = LocalTreeQueryAggregate::default();
    let mut scan_plan = plan.clone();
    scan_plan.max_candidates = 0.0;
    let collect_chunk = DEFAULT_SEARCH_RESULT_CHUNK_SIZE.max(1);
    for store in stores {
        let mut cursor = 0usize;
        loop {
            let local = store.query_candidates(&scan_plan, cursor, collect_chunk)?;
            out.tier_used.push(local.tier_used.clone());
            out.query_profile.merge_from(&local.query_profile);
            if include_external_ids {
                let external_ids = store.external_ids_for_sha256(&local.sha256);
                for (sha256, external_id) in local.sha256.into_iter().zip(external_ids.into_iter())
                {
                    out.hashes.insert(sha256.clone());
                    out.external_ids.entry(sha256).or_insert(external_id);
                }
            } else {
                out.hashes.extend(local.sha256);
            }
            if let Some(next) = local.next_cursor {
                cursor = next;
            } else {
                break;
            }
        }
    }
    Ok(out)
}

fn query_local_forest_all_candidates(
    tree_groups: &mut Vec<TreeStoreGroup>,
    plan: &crate::candidate::CompiledQueryPlan,
    include_external_ids: bool,
    tree_search_workers: usize,
) -> Result<LocalForestQueryAggregate> {
    let searchable_doc_count = tree_groups
        .iter()
        .flat_map(|group| group.stores.iter())
        .map(CandidateStore::live_doc_count)
        .sum::<usize>();
    let resolved_limit = resolve_max_candidates(searchable_doc_count, plan.max_candidates);
    let worker_count = tree_search_workers.max(1).min(tree_groups.len().max(1));
    let mut partials = Vec::<LocalTreeQueryAggregate>::new();
    if tree_groups.len() <= 1 || worker_count <= 1 {
        for group in tree_groups {
            partials.push(query_store_group_all_candidates(
                &mut group.stores,
                plan,
                include_external_ids,
            )?);
        }
    } else {
        let chunk_size = tree_groups.len().div_ceil(worker_count);
        let scoped = thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in tree_groups.chunks_mut(chunk_size) {
                handles.push(scope.spawn(move || -> Result<LocalTreeQueryAggregate> {
                    let mut merged = LocalTreeQueryAggregate::default();
                    for group in chunk {
                        let partial = query_store_group_all_candidates(
                            &mut group.stores,
                            plan,
                            include_external_ids,
                        )?;
                        merged.hashes.extend(partial.hashes);
                        merged.tier_used.extend(partial.tier_used);
                        merged.query_profile.merge_from(&partial.query_profile);
                        for (sha256, external_id) in partial.external_ids {
                            merged.external_ids.entry(sha256).or_insert(external_id);
                        }
                    }
                    Ok(merged)
                }));
            }
            let mut merged = Vec::with_capacity(handles.len());
            for handle in handles {
                merged.push(
                    handle
                        .join()
                        .map_err(|_| SspryError::from("Forest search worker panicked."))??,
                );
            }
            Ok::<Vec<LocalTreeQueryAggregate>, SspryError>(merged)
        })?;
        partials = scoped;
    }

    let mut hashes = HashSet::<String>::new();
    let mut external_id_map = HashMap::<String, Option<String>>::new();
    let mut tier_used = Vec::<String>::new();
    let mut query_profile = crate::candidate::CandidateQueryProfile::default();
    for partial in partials {
        hashes.extend(partial.hashes);
        tier_used.extend(partial.tier_used);
        query_profile.merge_from(&partial.query_profile);
        for (sha256, external_id) in partial.external_ids {
            external_id_map.entry(sha256).or_insert(external_id);
        }
    }
    let mut hashes = hashes.into_iter().collect::<Vec<_>>();
    let truncated = resolved_limit != usize::MAX && hashes.len() > resolved_limit;
    if truncated {
        hashes.truncate(resolved_limit);
    }
    let external_ids = if include_external_ids {
        Some(
            hashes
                .iter()
                .map(|sha256| external_id_map.get(sha256).cloned().flatten())
                .collect::<Vec<_>>(),
        )
    } else {
        None
    };
    Ok(LocalForestQueryAggregate {
        total_candidates: hashes.len(),
        truncated,
        truncated_limit: truncated.then_some(resolved_limit),
        tier_used: merge_tier_used(tier_used),
        query_profile,
        external_ids,
        hashes,
    })
}

fn query_store_group_tree_gates(
    stores: &mut [CandidateStore],
    plan: &crate::candidate::CompiledQueryPlan,
) -> Result<crate::candidate::CandidateQueryProfile> {
    let mut out = crate::candidate::CandidateQueryProfile::default();
    for store in stores {
        out.merge_from(&store.query_tree_gate_profile(plan)?);
    }
    Ok(out)
}

fn query_local_forest_tree_gates(
    tree_groups: &mut Vec<TreeStoreGroup>,
    plan: &crate::candidate::CompiledQueryPlan,
    tree_search_workers: usize,
) -> Result<crate::candidate::CandidateQueryProfile> {
    let worker_count = tree_search_workers.max(1).min(tree_groups.len().max(1));
    let mut partials = Vec::<crate::candidate::CandidateQueryProfile>::new();
    if tree_groups.len() <= 1 || worker_count <= 1 {
        for group in tree_groups {
            partials.push(query_store_group_tree_gates(&mut group.stores, plan)?);
        }
    } else {
        let chunk_size = tree_groups.len().div_ceil(worker_count);
        let scoped = thread::scope(|scope| {
            let mut handles = Vec::new();
            for chunk in tree_groups.chunks_mut(chunk_size) {
                handles.push(scope.spawn(
                    move || -> Result<crate::candidate::CandidateQueryProfile> {
                        let mut merged = crate::candidate::CandidateQueryProfile::default();
                        for group in chunk {
                            merged.merge_from(&query_store_group_tree_gates(
                                &mut group.stores,
                                plan,
                            )?);
                        }
                        Ok(merged)
                    },
                ));
            }
            let mut merged = Vec::with_capacity(handles.len());
            for handle in handles {
                merged.push(
                    handle
                        .join()
                        .map_err(|_| SspryError::from("Forest tree-gate worker panicked."))??,
                );
            }
            Ok::<Vec<crate::candidate::CandidateQueryProfile>, SspryError>(merged)
        })?;
        partials = scoped;
    }
    let mut query_profile = crate::candidate::CandidateQueryProfile::default();
    for partial in partials {
        query_profile.merge_from(&partial);
    }
    Ok(query_profile)
}

fn clear_local_forest_search_caches(tree_groups: &mut [TreeStoreGroup]) {
    for group in tree_groups {
        for store in &mut group.stores {
            store.clear_search_caches();
        }
    }
}

fn verify_search_candidates(
    rule_path: &Path,
    plan: &crate::candidate::CompiledQueryPlan,
    rows: Vec<String>,
    mut external_ids: Vec<Option<String>>,
    verify_yara_files: bool,
) -> Result<SearchVerificationResult> {
    if !verify_yara_files {
        return Ok(SearchVerificationResult {
            rows,
            verified_checked: 0,
            verified_matched: 0,
            verified_skipped: 0,
        });
    }
    if external_ids.len() < rows.len() {
        external_ids.resize(rows.len(), None);
    }
    let literal_plan = fixed_literal_match_plan(plan);
    let mut yara_rules = None::<Arc<YaraRules>>;
    let mut verified_rows = Vec::<String>::new();
    let mut verified_checked = 0usize;
    let mut verified_matched = 0usize;
    let mut verified_skipped = 0usize;
    let mut unverified_rows = Vec::<String>::new();
    let mut page_results = vec![None::<bool>; rows.len()];
    let mut skipped_results = vec![false; rows.len()];
    let mut verify_jobs = Vec::<(usize, String, PathBuf)>::new();
    for (index, (sha256, external_id)) in rows
        .iter()
        .cloned()
        .zip(external_ids.into_iter())
        .enumerate()
    {
        let Some(path_text) = external_id else {
            verified_skipped += 1;
            skipped_results[index] = true;
            continue;
        };
        let candidate_path = PathBuf::from(path_text);
        if !candidate_path.is_file() {
            verified_skipped += 1;
            skipped_results[index] = true;
            continue;
        }
        verify_jobs.push((index, sha256, candidate_path));
    }
    for (index, _sha256, candidate_path) in verify_jobs {
        verified_checked += 1;
        let matched = if let Some(plan) = &literal_plan {
            match verify_fixed_literal_plan_on_file(&candidate_path, plan) {
                Ok(matched) => matched,
                Err(_) => {
                    if yara_rules.is_none() {
                        yara_rules = Some(compile_yara_verifier_cached(rule_path)?);
                    }
                    let mut scanner =
                        YaraScanner::new(yara_rules.as_ref().expect("cached YARA rules"));
                    scanner
                        .scan_file(&candidate_path)
                        .map_err(|err| SspryError::from(err.to_string()))?
                        .matching_rules()
                        .len()
                        > 0
                }
            }
        } else {
            if yara_rules.is_none() {
                yara_rules = Some(compile_yara_verifier_cached(rule_path)?);
            }
            let mut scanner = YaraScanner::new(yara_rules.as_ref().expect("cached YARA rules"));
            scanner
                .scan_file(&candidate_path)
                .map_err(|err| SspryError::from(err.to_string()))?
                .matching_rules()
                .len()
                > 0
        };
        page_results[index] = Some(matched);
    }
    for (index, sha256) in rows.iter().cloned().enumerate() {
        match page_results.get(index).copied().flatten() {
            Some(true) => {
                verified_matched += 1;
                verified_rows.push(sha256);
            }
            Some(false) => {}
            None => {
                if skipped_results[index] {
                    unverified_rows.push(sha256);
                }
            }
        }
    }
    verified_rows.extend(unverified_rows);
    Ok(SearchVerificationResult {
        rows: verified_rows,
        verified_checked,
        verified_matched,
        verified_skipped,
    })
}

#[derive(Debug)]
struct IndexBatchRow {
    sha256: [u8; 32],
    file_size: u64,
    filter_bytes: usize,
    bloom_item_estimate: Option<usize>,
    bloom_filter: Vec<u8>,
    tier2_filter_bytes: usize,
    tier2_bloom_item_estimate: Option<usize>,
    tier2_bloom_filter: Vec<u8>,
    special_population: bool,
    metadata: Vec<u8>,
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
            _ => Err(SspryError::from(format!(
                "invalid candidate id_source `{value}`; expected one of sha256, md5, sha1, sha512"
            ))),
        }
    }
}

#[derive(Clone, Copy)]
struct ScanPolicy {
    fixed_filter_bytes: Option<usize>,
    tier1_filter_target_fp: Option<f64>,
    tier2_filter_target_fp: Option<f64>,
    gram_sizes: GramSizes,
    chunk_size: usize,
    store_path: bool,
    id_source: CandidateIdSource,
}

fn scan_index_batch_row(file_path: &Path, policy: ScanPolicy) -> Result<IndexBatchRow> {
    let resolved_path = if policy.store_path {
        Some(resolved_file_path(file_path)?)
    } else {
        None
    };
    let scan_path = resolved_path.as_deref().unwrap_or(file_path);
    let file_size = scan_path.metadata()?.len();
    let (bloom_item_estimate, tier2_bloom_item_estimate) =
        if policy.tier1_filter_target_fp.is_some() || policy.tier2_filter_target_fp.is_some() {
            if policy.gram_sizes.tier1 == policy.gram_sizes.tier2 {
                let estimate = estimate_unique_grams_for_size_hll(
                    scan_path,
                    policy.gram_sizes.tier1,
                    policy.chunk_size,
                    HLL_DEFAULT_PRECISION,
                )?;
                (Some(estimate), Some(estimate))
            } else {
                let (tier1_estimate, tier2_estimate) = estimate_unique_grams_pair_hll(
                    scan_path,
                    policy.gram_sizes.tier1,
                    policy.gram_sizes.tier2,
                    policy.chunk_size,
                    HLL_DEFAULT_PRECISION,
                )?;
                (Some(tier1_estimate), Some(tier2_estimate))
            }
        } else {
            (None, None)
        };
    let filter_bytes = if let Some(value) = policy.fixed_filter_bytes {
        align_filter_bytes(value)
    } else {
        choose_filter_bytes_for_file_size(
            file_size,
            INTERNAL_FILTER_BYTES,
            Some(INTERNAL_FILTER_MIN_BYTES),
            Some(INTERNAL_FILTER_MAX_BYTES),
            policy.tier1_filter_target_fp,
            bloom_item_estimate,
        )?
    };
    let tier2_filter_bytes = if let Some(value) = policy.fixed_filter_bytes {
        align_filter_bytes(value)
    } else {
        choose_filter_bytes_for_file_size(
            file_size,
            INTERNAL_FILTER_BYTES,
            Some(INTERNAL_FILTER_MIN_BYTES),
            Some(INTERNAL_FILTER_MAX_BYTES),
            policy.tier2_filter_target_fp,
            tier2_bloom_item_estimate,
        )?
    };
    let bloom_hashes =
        derive_document_bloom_hash_count(filter_bytes, bloom_item_estimate, INTERNAL_BLOOM_HASHES);
    let tier2_bloom_hashes = derive_document_bloom_hash_count(
        tier2_filter_bytes,
        tier2_bloom_item_estimate,
        INTERNAL_BLOOM_HASHES,
    );
    let started = Instant::now();
    let features = scan_file_features_bloom_only_with_gram_sizes(
        scan_path,
        policy.gram_sizes,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes,
        tier2_bloom_hashes,
        policy.chunk_size,
    )?;
    perf::record_sample(
        "candidate.scan_file_features.file",
        scan_path.display().to_string(),
        started.elapsed().as_nanos(),
        file_size,
        0,
    );
    let metadata = extract_compact_document_metadata(scan_path)?;
    let sha256 = if policy.id_source == CandidateIdSource::Sha256 {
        features.sha256
    } else {
        identity_from_file(scan_path, policy.chunk_size, policy.id_source)?
    };
    Ok(IndexBatchRow {
        sha256,
        file_size: features.file_size,
        filter_bytes,
        bloom_item_estimate,
        bloom_filter: features.bloom_filter,
        tier2_filter_bytes,
        tier2_bloom_item_estimate,
        tier2_bloom_filter: features.tier2_bloom_filter,
        special_population: features.special_population,
        metadata,
        external_id: resolved_path.map(|path| path.display().to_string()),
    })
}

fn compile_yara_verifier(rule_path: &Path) -> Result<YaraRules> {
    let source = fs::read_to_string(rule_path)?;
    let mut compiler = YaraCompiler::new();
    compiler
        .add_source(source.as_str())
        .map_err(|err| SspryError::from(err.to_string()))?;
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
        .map_err(|_| SspryError::from("YARA verifier cache lock poisoned."))?
        .get(&key)
    {
        return Ok(rules);
    }
    let rules = Arc::new(compile_yara_verifier(rule_path)?);
    let mut guard = cache
        .lock()
        .map_err(|_| SspryError::from("YARA verifier cache lock poisoned."))?;
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
            crate::candidate::DEFAULT_TIER1_GRAM_SIZE,
            crate::candidate::DEFAULT_TIER2_GRAM_SIZE,
        )
        .ok()?,
        16,
        false,
        true,
        1,
    )
    .ok()?;
    fixed_literal_match_plan(&plan)
}

fn is_ascii_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

fn is_wide_word_unit(unit: &[u8]) -> bool {
    unit.len() == 2 && unit[1] == 0 && is_ascii_word_byte(unit[0])
}

fn file_contains_literal_with_mode(
    haystack: &[u8],
    needle: &[u8],
    wide: bool,
    fullword: bool,
) -> bool {
    if needle.is_empty() {
        return true;
    }
    if haystack.len() < needle.len() {
        return false;
    }
    for index in 0..=(haystack.len() - needle.len()) {
        if &haystack[index..index + needle.len()] != needle {
            continue;
        }
        if !fullword {
            return true;
        }
        if wide {
            let left_ok = if index >= 2 {
                !is_wide_word_unit(&haystack[index - 2..index])
            } else {
                true
            };
            let right_ok = if index + needle.len() + 2 <= haystack.len() {
                !is_wide_word_unit(&haystack[index + needle.len()..index + needle.len() + 2])
            } else {
                true
            };
            if left_ok && right_ok {
                return true;
            }
        } else {
            let left_ok = if index > 0 {
                !is_ascii_word_byte(haystack[index - 1])
            } else {
                true
            };
            let right_ok = if index + needle.len() < haystack.len() {
                !is_ascii_word_byte(haystack[index + needle.len()])
            } else {
                true
            };
            if left_ok && right_ok {
                return true;
            }
        }
    }
    false
}

fn verify_fixed_literal_plan_on_file(path: &Path, plan: &FixedLiteralMatchPlan) -> Result<bool> {
    let bytes = fs::read(path)?;
    let mut matches = HashMap::with_capacity(plan.literals.len());
    for (pattern_id, literals) in &plan.literals {
        let wide_flags = plan
            .literal_wide
            .get(pattern_id)
            .ok_or_else(|| SspryError::from("fixed literal plan missing wide flags"))?;
        let fullword_flags = plan
            .literal_fullword
            .get(pattern_id)
            .ok_or_else(|| SspryError::from("fixed literal plan missing fullword flags"))?;
        let matched = literals.iter().enumerate().any(|(index, literal)| {
            file_contains_literal_with_mode(
                &bytes,
                literal,
                wide_flags.get(index).copied().unwrap_or(false),
                fullword_flags.get(index).copied().unwrap_or(false),
            )
        });
        matches.insert(pattern_id.clone(), matched);
    }
    evaluate_fixed_literal_match(&plan.root, &matches)
}

fn cmd_yara(args: &YaraArgs) -> i32 {
    match (|| -> Result<i32> {
        let rule_path = Path::new(&args.rule);
        let file_path = Path::new(&args.file_path);
        if !rule_path.is_file() {
            return Err(SspryError::from(format!(
                "Rule file not found: {}",
                rule_path.display()
            )));
        }
        if !file_path.is_file() {
            return Err(SspryError::from(format!(
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
            .map_err(|err| SspryError::from(err.to_string()))?;

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
        let candidate_shards = serve_candidate_shard_count(args);
        let serve_workspace_mode = serve_uses_workspace_mode(Path::new(&args.root));
        let (auto_publish_storage_class, auto_publish_initial_idle_ms) =
            adaptive_publish_prior_for_root(Path::new(&args.root));
        let signals = serve_signal_flags()?;
        rpc::serve_with_signal_flags(
            &host,
            port,
            None,
            args.max_request_bytes,
            RpcServerConfig {
                candidate_config: store_config_from_serve_args(args),
                candidate_shards,
                search_workers: args.search_workers.max(1),
                memory_budget_bytes: args.memory_budget_gb.saturating_mul(1024 * 1024 * 1024),
                auto_publish_initial_idle_ms,
                auto_publish_storage_class,
                workspace_mode: serve_workspace_mode,
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

fn serve_uses_workspace_mode(root: &Path) -> bool {
    if root.join("current").is_dir() || root.join("work_a").is_dir() || root.join("work_b").is_dir()
    {
        return true;
    }
    if root.join("store_meta.json").exists()
        || root.join("meta.json").exists()
        || root.join("sha256_by_docid.dat").exists()
        || root.join("doc_meta.bin").exists()
        || root.join("shard_000").join("store_meta.json").exists()
        || root.join("shard_000").join("meta.json").exists()
        || root.join("shard_000").join("sha256_by_docid.dat").exists()
        || root.join("shard_000").join("doc_meta.bin").exists()
    {
        return false;
    }
    fs::read_dir(root)
        .ok()
        .map(|entries| {
            entries.flatten().any(|entry| {
                entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false)
                    && entry
                        .file_name()
                        .to_str()
                        .map(|name| name.starts_with("tree_"))
                        .unwrap_or(false)
                    && entry.path().join("current").is_dir()
            })
        })
        .map(|has_forest_trees| !has_forest_trees)
        .unwrap_or(true)
}

fn cmd_init(args: &InitArgs) -> i32 {
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
                return Err(SspryError::from(format!(
                    "{} already initialized with {existing} shard(s)",
                    args.root
                )));
            }

            let local_meta_path = root.join("store_meta.json");
            let legacy_meta_path = root.join("meta.json");
            let first_local_meta = root.join("shard_000").join("store_meta.json");
            let first_legacy_meta = root.join("shard_000").join("meta.json");
            if shard_count == 1 && (local_meta_path.exists() || legacy_meta_path.exists()) {
                println!("Candidate store already initialized at {}", args.root);
                return Ok(0);
            }
            if shard_count > 1 && (first_local_meta.exists() || first_legacy_meta.exists()) {
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
            "tier1_filter_target_fp: {}",
            stats
                .tier1_filter_target_fp
                .map(|value| value.to_string())
                .unwrap_or_else(|| "none".to_owned())
        );
        println!(
            "tier2_filter_target_fp: {}",
            stats
                .tier2_filter_target_fp
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
                .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?
                .config();
            let id_source = CandidateIdSource::parse_config_value(&config.id_source)?;
            let gram_sizes = GramSizes::new(config.tier1_gram_size, config.tier2_gram_size)?;
            let mut row = scan_index_batch_row(
                Path::new(&args.file_path),
                ScanPolicy {
                    fixed_filter_bytes: None,
                    tier1_filter_target_fp: config.resolved_tier1_filter_target_fp(),
                    tier2_filter_target_fp: config.resolved_tier2_filter_target_fp(),
                    gram_sizes,
                    chunk_size: args.chunk_size,
                    store_path: false,
                    id_source,
                },
            )?;
            row.external_id = args.external_id.clone().or(row.external_id);
            let shard_idx = candidate_shard_index(&row.sha256, stores.len());
            let result = stores[shard_idx].insert_document_with_metadata(
                row.sha256,
                row.file_size,
                row.bloom_item_estimate,
                None,
                row.tier2_bloom_item_estimate,
                None,
                row.filter_bytes,
                &row.bloom_filter,
                row.tier2_filter_bytes,
                &row.tier2_bloom_filter,
                &row.metadata,
                row.special_population,
                row.external_id,
            )?;
            rpc::CandidateInsertResponse {
                status: result.status,
                doc_id: result.doc_id,
                sha256: result.sha256,
            }
        } else {
            let server_policy = server_scan_policy(&args.connection)?;
            let mut row = scan_index_batch_row(
                Path::new(&args.file_path),
                ScanPolicy {
                    fixed_filter_bytes: None,
                    tier1_filter_target_fp: server_policy.tier1_filter_target_fp,
                    tier2_filter_target_fp: server_policy.tier2_filter_target_fp,
                    gram_sizes: server_policy.gram_sizes,
                    chunk_size: args.chunk_size,
                    store_path: server_policy.store_path,
                    id_source: server_policy.id_source,
                },
            )?;
            row.external_id = args.external_id.clone().or(row.external_id);
            let row_bytes = serialize_candidate_document_binary_row(&row)?;
            rpc_client(&args.connection).candidate_insert_binary_row(&row_bytes)?
        };

        println!("status: {}", result.status);
        println!("doc_id: {}", result.doc_id);
        println!("sha256: {}", result.sha256);
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
        let mut result_wait_time = Duration::ZERO;
        let mut encode_time = Duration::ZERO;
        let mut client_buffer_time = Duration::ZERO;
        let mut progress_rpc_time = Duration::ZERO;
        let mut submit_time = Duration::ZERO;
        let mut server_rss_kb = None::<(u64, u64)>;
        let input_roots = expand_input_paths(&args.paths, args.path_list)?;
        let total_files = if args.path_list || input_paths_are_file_only(&input_roots) {
            input_roots.len()
        } else {
            count_input_files(&input_roots)?
        };
        if total_files == 0 {
            return Err(SspryError::from("No input files found."));
        }
        let show_progress = args.verbose
            && (args.path_list
                || input_roots.iter().any(|path| path.is_dir())
                || total_files > input_roots.len());
        let mut last_progress_reported = 0usize;
        let mut last_progress_at = Instant::now();
        let mut processed = 0usize;
        let batch_size = args.batch_size.max(1);
        let resolved_workers = resolve_ingest_workers(
            args.workers,
            total_files,
            &input_roots,
            args.root.as_deref().map(Path::new),
        );
        let workers = resolved_workers.workers;
        if let Some(root) = &args.root {
            let mut stores = open_stores(Path::new(root))?;
            let config = stores
                .first()
                .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?
                .config();
            let id_source = CandidateIdSource::parse_config_value(&config.id_source)?;
            let gram_sizes = GramSizes::new(config.tier1_gram_size, config.tier2_gram_size)?;
            let policy = ScanPolicy {
                fixed_filter_bytes: None,
                tier1_filter_target_fp: config.resolved_tier1_filter_target_fp(),
                tier2_filter_target_fp: config.resolved_tier2_filter_target_fp(),
                gram_sizes,
                chunk_size: args.chunk_size,
                store_path: config.store_path,
                id_source,
            };
            let configured_budget_bytes = DEFAULT_MEMORY_BUDGET_BYTES;
            let effective_budget_bytes = effective_memory_budget_bytes(configured_budget_bytes);
            let queue_capacity = index_queue_capacity(effective_budget_bytes, workers);
            let mut pending = Vec::<IndexBatchRow>::new();
            if workers <= 1 {
                stream_selected_input_files(&input_roots, args.path_list, |file_path| {
                    let started_scan = Instant::now();
                    pending.push(scan_index_batch_row(&file_path, policy)?);
                    scan_time += started_scan.elapsed();
                    maybe_report_index_progress(
                        show_progress,
                        processed.saturating_add(pending.len()),
                        total_files,
                        &mut last_progress_reported,
                        &mut last_progress_at,
                        false,
                    );
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
                let (result_tx, result_rx) =
                    bounded::<Result<ScannedIndexBatchRow>>(queue_capacity);
                let worker_count = workers;
                thread::scope(|scope| {
                    for _ in 0..worker_count {
                        let job_rx = job_rx.clone();
                        let result_tx = result_tx.clone();
                        scope.spawn(move || {
                            for file_path in job_rx.iter() {
                                let started_scan = Instant::now();
                                let result = scan_index_batch_row(&file_path, policy).map(|row| {
                                    ScannedIndexBatchRow {
                                        row,
                                        scan_elapsed: started_scan.elapsed(),
                                    }
                                });
                                let _ = result_tx.send(result);
                            }
                        });
                    }
                    let producer_tx = job_tx.clone();
                    let producer_result_tx = result_tx.clone();
                    let producer_roots = input_roots.clone();
                    let producer_path_list = args.path_list;
                    scope.spawn(move || {
                        let produce = stream_selected_input_files(
                            &producer_roots,
                            producer_path_list,
                            |file_path| {
                                producer_tx.send(file_path).map_err(|_| {
                                    SspryError::from(
                                        "candidate ingest file producer terminated unexpectedly",
                                    )
                                })?;
                                Ok(())
                            },
                        );
                        if let Err(err) = produce {
                            let _ = producer_result_tx.send(Err(err));
                        }
                        drop(producer_tx);
                    });

                    drop(job_tx);
                    drop(result_tx);

                    let mut received = 0usize;
                    loop {
                        let started_wait = Instant::now();
                        let Some(scanned) = result_rx.recv().ok() else {
                            break;
                        };
                        result_wait_time += started_wait.elapsed();
                        let scanned = scanned?;
                        received = received.saturating_add(1);
                        scan_time += scanned.scan_elapsed;
                        pending.push(scanned.row);
                        maybe_report_index_progress(
                            show_progress,
                            processed.saturating_add(pending.len()),
                            total_files,
                            &mut last_progress_reported,
                            &mut last_progress_at,
                            false,
                        );
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
                    if received != total_files {
                        return Err(SspryError::from(format!(
                            "candidate ingest worker result count mismatch: counted {total_files} input files but received {received} scan results"
                        )));
                    }
                    Ok::<(), SspryError>(())
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
            for store in &mut stores {
                let _ = store.persist_meta_if_dirty()?;
            }

            if args.verbose {
                eprintln!("verbose.index.memory_budget_bytes: {configured_budget_bytes}");
                eprintln!("verbose.index.effective_memory_budget_bytes: {effective_budget_bytes}");
                eprintln!("verbose.index.queue_capacity: {queue_capacity}");
                eprintln!("verbose.index.worker_auto: {}", resolved_workers.auto);
                eprintln!(
                    "verbose.index.input_storage_class: {}",
                    resolved_workers.input_storage.as_str()
                );
                eprintln!(
                    "verbose.index.output_storage_class: {}",
                    resolved_workers.output_storage.as_str()
                );
            }
        } else {
            let server_policy = server_scan_policy(&args.connection)?;
            let policy = ScanPolicy {
                fixed_filter_bytes: None,
                tier1_filter_target_fp: server_policy.tier1_filter_target_fp,
                tier2_filter_target_fp: server_policy.tier2_filter_target_fp,
                gram_sizes: server_policy.gram_sizes,
                chunk_size: args.chunk_size,
                store_path: server_policy.store_path,
                id_source: server_policy.id_source,
            };
            let base_client = rpc_client(&args.connection);
            let configured_budget_bytes = server_policy.memory_budget_bytes;
            let effective_budget_bytes = effective_memory_budget_bytes(configured_budget_bytes);
            let queue_capacity = index_queue_capacity(effective_budget_bytes, workers);
            let remote_session_document_limit = if args.rotate_remote_sessions {
                remote_index_session_document_limit(effective_budget_bytes, batch_size)
            } else {
                usize::MAX
            };
            let remote_session_input_bytes_limit = if args.rotate_remote_sessions {
                remote_index_session_input_bytes_limit(effective_budget_bytes)
            } else {
                u64::MAX
            };
            let empty_payload_size = empty_remote_batch_payload_size()?;
            let remote_batch_soft_limit_bytes = args
                .remote_batch_soft_limit_bytes
                .max(empty_payload_size.saturating_add(1));
            let remote_upload_queue_limit_bytes = remote_upload_queue_byte_limit(
                effective_budget_bytes,
                remote_batch_soft_limit_bytes,
            );
            let mut pending = RemotePendingBatch {
                rows: Vec::new(),
                payload_size: empty_payload_size,
            };
            let mut session_submitted_documents = 0usize;
            let mut session_submitted_input_bytes = 0u64;
            let mut session_publish_rotations = 0usize;
            let (index_client_id, _) =
                base_client.begin_index_client(INDEX_CLIENT_HEARTBEAT_INTERVAL_MS)?;
            let heartbeat_stop = Arc::new(AtomicBool::new(false));
            let heartbeat_error = Arc::new(Mutex::new(None::<String>));
            let heartbeat_client = rpc_client(&args.connection);
            let heartbeat_stop_flag = heartbeat_stop.clone();
            let heartbeat_error_slot = heartbeat_error.clone();
            let heartbeat_handle = thread::spawn(move || {
                while !heartbeat_stop_flag.load(Ordering::Acquire) {
                    thread::sleep(Duration::from_millis(INDEX_CLIENT_HEARTBEAT_INTERVAL_MS));
                    if heartbeat_stop_flag.load(Ordering::Acquire) {
                        break;
                    }
                    if let Err(err) = heartbeat_client.heartbeat_index_client(index_client_id) {
                        if let Ok(mut slot) = heartbeat_error_slot.lock() {
                            if slot.is_none() {
                                *slot = Some(err.to_string());
                            }
                        }
                        break;
                    }
                }
            });
            let remote_result = (|| -> Result<()> {
                let mut client = base_client.connect_persistent()?;
                client.begin_index_session()?;
                let started_progress_rpc = Instant::now();
                client.update_index_session_progress(Some(total_files), 0, 0)?;
                progress_rpc_time += started_progress_rpc.elapsed();
                let body_result = (|| -> Result<()> {
                    if workers <= 1 {
                        stream_selected_input_files(&input_roots, args.path_list, |file_path| {
                            let started_scan = Instant::now();
                            let scanned = scan_index_batch_row(&file_path, policy)?;
                            scan_time += started_scan.elapsed();
                            session_submitted_documents =
                                session_submitted_documents.saturating_add(1);
                            session_submitted_input_bytes =
                                session_submitted_input_bytes.saturating_add(scanned.file_size);
                            let started_encode = Instant::now();
                            let row_bytes = serialize_candidate_document_binary_row(&scanned)?;
                            encode_time += started_encode.elapsed();
                            client_buffer_time += push_serialized_remote_upload_row(
                                &mut client,
                                &mut pending,
                                row_bytes,
                                batch_size,
                                &mut processed,
                                &mut submit_time,
                                show_progress,
                                total_files,
                                &mut last_progress_reported,
                                &mut last_progress_at,
                                empty_payload_size,
                                remote_batch_soft_limit_bytes,
                                args.verbose,
                            )?;
                            maybe_report_index_progress(
                                show_progress,
                                processed.saturating_add(pending.rows.len()),
                                total_files,
                                &mut last_progress_reported,
                                &mut last_progress_at,
                                false,
                            );
                            if args.rotate_remote_sessions
                                && (session_submitted_documents >= remote_session_document_limit
                                    || session_submitted_input_bytes
                                        >= remote_session_input_bytes_limit)
                            {
                                rotate_remote_index_session(
                                    &base_client,
                                    &mut client,
                                    &mut pending,
                                    &mut processed,
                                    &mut submit_time,
                                    show_progress,
                                    total_files,
                                    &mut last_progress_reported,
                                    &mut last_progress_at,
                                    empty_payload_size,
                                    &mut progress_rpc_time,
                                    args.verbose,
                                )?;
                                session_submitted_documents = 0;
                                session_submitted_input_bytes = 0;
                                session_publish_rotations =
                                    session_publish_rotations.saturating_add(1);
                            }
                            Ok(())
                        })?;
                    } else {
                        let (job_tx, job_rx) = bounded::<PathBuf>(queue_capacity);
                        let (result_tx, result_rx) =
                            bounded::<Result<ScannedIndexBatchRow>>(queue_capacity);
                        let upload_queue =
                            Arc::new(RemoteUploadQueue::new(remote_upload_queue_limit_bytes));
                        let worker_count = workers;
                        thread::scope(|scope| {
                            for _worker_idx in 0..worker_count {
                                let job_rx = job_rx.clone();
                                let result_tx = result_tx.clone();
                                scope.spawn(move || {
                                    for file_path in job_rx.iter() {
                                        let started_scan = Instant::now();
                                        let result =
                                            scan_index_batch_row(&file_path, policy).map(|row| {
                                                ScannedIndexBatchRow {
                                                    row,
                                                    scan_elapsed: started_scan.elapsed(),
                                                }
                                            });
                                        let _ = result_tx.send(result);
                                    }
                                });
                            }
                            let producer_tx = job_tx.clone();
                            let producer_result_tx = result_tx.clone();
                            let producer_roots = input_roots.clone();
                            let producer_path_list = args.path_list;
                            scope.spawn(move || {
                                let produce = stream_selected_input_files(
                                    &producer_roots,
                                    producer_path_list,
                                    |file_path| {
                                        producer_tx.send(file_path).map_err(|_| {
                                            SspryError::from(
                                                "candidate ingest file producer terminated unexpectedly",
                                            )
                                        })?;
                                        Ok(())
                                    },
                                );
                                if let Err(err) = produce {
                                    let _ = producer_result_tx.send(Err(err));
                                }
                                drop(producer_tx);
                            });

                            drop(job_tx);
                            drop(result_tx);

                            let scope_result = (|| -> Result<()> {
                                let upload_queue_consumer = upload_queue.clone();
                                let encoder_handle = scope.spawn(move || -> Result<RemoteEncodeStats> {
                                    let mut received = 0usize;
                                    let mut local_scan_time = Duration::ZERO;
                                    let mut local_result_wait_time = Duration::ZERO;
                                    let mut local_encode_time = Duration::ZERO;
                                    let encoder_result = (|| -> Result<()> {
                                        loop {
                                            let started_wait = Instant::now();
                                            let Some(scanned) = result_rx.recv().ok() else {
                                                break;
                                            };
                                            local_result_wait_time += started_wait.elapsed();
                                            let scanned = scanned?;
                                            received = received.saturating_add(1);
                                            local_scan_time += scanned.scan_elapsed;
                                            let file_size = scanned.row.file_size;
                                            let started_encode = Instant::now();
                                            let row_bytes =
                                                serialize_candidate_document_binary_row(&scanned.row)?;
                                            local_encode_time += started_encode.elapsed();
                                            upload_queue_consumer.push(RemoteUploadRow {
                                                row_bytes,
                                                file_size,
                                            })?;
                                        }
                                        if received != total_files {
                                            return Err(SspryError::from(format!(
                                                "candidate ingest worker result count mismatch: counted {total_files} input files but received {received} scan results"
                                            )));
                                        }
                                        Ok(())
                                    })();
                                    let _ = upload_queue_consumer.close();
                                    encoder_result?;
                                    Ok(RemoteEncodeStats {
                                        scan_time: local_scan_time,
                                        result_wait_time: local_result_wait_time,
                                        encode_time: local_encode_time,
                                    })
                                });

                                let upload_result = (|| -> Result<()> {
                                    loop {
                                        let Some(upload_row) = upload_queue.pop()? else {
                                            break;
                                        };
                                        session_submitted_documents =
                                            session_submitted_documents.saturating_add(1);
                                        session_submitted_input_bytes =
                                            session_submitted_input_bytes
                                                .saturating_add(upload_row.file_size);
                                        client_buffer_time += push_serialized_remote_upload_row(
                                            &mut client,
                                            &mut pending,
                                            upload_row.row_bytes,
                                            batch_size,
                                            &mut processed,
                                            &mut submit_time,
                                            show_progress,
                                            total_files,
                                            &mut last_progress_reported,
                                            &mut last_progress_at,
                                            empty_payload_size,
                                            remote_batch_soft_limit_bytes,
                                            args.verbose,
                                        )?;
                                        maybe_report_index_progress(
                                            show_progress,
                                            processed.saturating_add(pending.rows.len()),
                                            total_files,
                                            &mut last_progress_reported,
                                            &mut last_progress_at,
                                            false,
                                        );
                                        if args.rotate_remote_sessions
                                            && (session_submitted_documents
                                                >= remote_session_document_limit
                                                || session_submitted_input_bytes
                                                    >= remote_session_input_bytes_limit)
                                        {
                                            rotate_remote_index_session(
                                                &base_client,
                                                &mut client,
                                                &mut pending,
                                                &mut processed,
                                                &mut submit_time,
                                                show_progress,
                                                total_files,
                                                &mut last_progress_reported,
                                                &mut last_progress_at,
                                                empty_payload_size,
                                                &mut progress_rpc_time,
                                                args.verbose,
                                            )?;
                                            session_submitted_documents = 0;
                                            session_submitted_input_bytes = 0;
                                            session_publish_rotations =
                                                session_publish_rotations.saturating_add(1);
                                        }
                                    }
                                    Ok(())
                                })();
                                if let Err(upload_err) = upload_result {
                                    let _ = upload_queue.close();
                                    let _ = encoder_handle.join();
                                    return Err(upload_err);
                                }
                                let encoder_stats = encoder_handle.join().map_err(|_| {
                                    SspryError::from("candidate ingest encoder thread panicked")
                                })??;
                                scan_time += encoder_stats.scan_time;
                                result_wait_time += encoder_stats.result_wait_time;
                                encode_time += encoder_stats.encode_time;
                                Ok(())
                            })();
                            scope_result?;
                            Ok::<(), SspryError>(())
                        })?;
                    }

                    flush_remote_pending_rows(
                        &mut client,
                        &mut pending,
                        &mut processed,
                        &mut submit_time,
                        show_progress,
                        total_files,
                        &mut last_progress_reported,
                        &mut last_progress_at,
                        empty_payload_size,
                        args.verbose,
                    )?;
                    Ok(())
                })();
                let end_session_result = client.end_index_session();
                body_result?;
                end_session_result?;
                Ok(())
            })();
            heartbeat_stop.store(true, Ordering::SeqCst);
            let _ = heartbeat_handle.join();
            let heartbeat_result = heartbeat_error
                .lock()
                .map_err(|_| SspryError::from("Index heartbeat error slot poisoned."))?
                .clone()
                .map(|message| Err(SspryError::from(message)))
                .unwrap_or(Ok(()));
            let end_client_result = base_client.end_index_client(index_client_id);
            remote_result?;
            heartbeat_result?;
            end_client_result?;
            if args.verbose {
                server_rss_kb = server_memory_kb(&args.connection)?;
                eprintln!("verbose.index.memory_budget_bytes: {configured_budget_bytes}");
                eprintln!("verbose.index.effective_memory_budget_bytes: {effective_budget_bytes}");
                eprintln!("verbose.index.queue_capacity: {queue_capacity}");
                eprintln!(
                    "verbose.index.remote_batch_soft_limit_bytes: {remote_batch_soft_limit_bytes}"
                );
                eprintln!(
                    "verbose.index.remote_upload_queue_limit_bytes: {}",
                    remote_upload_queue_limit_bytes
                );
                eprintln!(
                    "verbose.index.rotate_remote_sessions: {}",
                    args.rotate_remote_sessions
                );
                if args.rotate_remote_sessions {
                    eprintln!(
                        "verbose.index.remote_session_document_limit: {}",
                        remote_session_document_limit
                    );
                    eprintln!(
                        "verbose.index.remote_session_input_bytes_limit: {}",
                        remote_session_input_bytes_limit
                    );
                } else {
                    eprintln!("verbose.index.remote_session_document_limit: disabled");
                    eprintln!("verbose.index.remote_session_input_bytes_limit: disabled");
                }
                eprintln!(
                    "verbose.index.remote_session_publish_rotations: {}",
                    session_publish_rotations
                );
                eprintln!("verbose.index.worker_auto: {}", resolved_workers.auto);
                eprintln!(
                    "verbose.index.input_storage_class: {}",
                    resolved_workers.input_storage.as_str()
                );
                eprintln!(
                    "verbose.index.output_storage_class: {}",
                    resolved_workers.output_storage.as_str()
                );
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
            let result_wait_ms = result_wait_time.as_secs_f64() * 1000.0;
            let encode_ms = encode_time.as_secs_f64() * 1000.0;
            let client_buffer_ms = client_buffer_time.as_secs_f64() * 1000.0;
            let progress_rpc_ms = progress_rpc_time.as_secs_f64() * 1000.0;
            eprintln!("verbose.index.total_ms: {total_ms:.3}");
            eprintln!("verbose.index.scan_ms: {scan_ms:.3}");
            eprintln!("verbose.index.worker_scan_cpu_ms: {scan_ms:.3}");
            eprintln!("verbose.index.result_wait_ms: {result_wait_ms:.3}");
            eprintln!("verbose.index.encode_ms: {encode_ms:.3}");
            eprintln!("verbose.index.client_buffer_ms: {client_buffer_ms:.3}");
            eprintln!("verbose.index.submit_ms: {submit_ms:.3}");
            eprintln!("verbose.index.progress_rpc_ms: {progress_rpc_ms:.3}");
            eprintln!("verbose.index.batch_size: {}", batch_size);
            eprintln!("verbose.index.workers: {workers}");
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
                        "tree_tier1_gate_bytes",
                        "verbose.index.server_tree_tier1_gate_bytes",
                    ),
                    (
                        "tree_tier2_gate_bytes",
                        "verbose.index.server_tree_tier2_gate_bytes",
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
                            "adaptive_idle_ms",
                            "verbose.index.server_publish_adaptive_idle_ms",
                        ),
                        (
                            "idle_remaining_ms",
                            "verbose.index.server_publish_idle_remaining_ms",
                        ),
                        (
                            "adaptive_recent_publish_p95_ms",
                            "verbose.index.server_publish_adaptive_recent_publish_p95_ms",
                        ),
                        (
                            "adaptive_recent_submit_p95_ms",
                            "verbose.index.server_publish_adaptive_recent_submit_p95_ms",
                        ),
                        (
                            "adaptive_recent_store_p95_ms",
                            "verbose.index.server_publish_adaptive_recent_store_p95_ms",
                        ),
                        (
                            "adaptive_recent_publishes_in_window",
                            "verbose.index.server_publish_adaptive_recent_publishes_in_window",
                        ),
                        (
                            "adaptive_tier2_pending_shards",
                            "verbose.index.server_publish_adaptive_tier2_pending_shards",
                        ),
                        (
                            "adaptive_healthy_cycles",
                            "verbose.index.server_publish_adaptive_healthy_cycles",
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
                            "last_publish_lock_wait_ms",
                            "verbose.index.server_last_publish_lock_wait_ms",
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
                            "last_publish_promote_work_export_ms",
                            "verbose.index.server_last_publish_promote_work_export_ms",
                        ),
                        (
                            "last_publish_promote_work_import_ms",
                            "verbose.index.server_last_publish_promote_work_import_ms",
                        ),
                        (
                            "last_publish_promote_work_import_resolve_doc_state_ms",
                            "verbose.index.server_last_publish_promote_work_import_resolve_doc_state_ms",
                        ),
                        (
                            "last_publish_promote_work_import_build_payloads_ms",
                            "verbose.index.server_last_publish_promote_work_import_build_payloads_ms",
                        ),
                        (
                            "last_publish_promote_work_import_append_sidecars_ms",
                            "verbose.index.server_last_publish_promote_work_import_append_sidecars_ms",
                        ),
                        (
                            "last_publish_promote_work_import_install_docs_ms",
                            "verbose.index.server_last_publish_promote_work_import_install_docs_ms",
                        ),
                        (
                            "last_publish_promote_work_import_tier2_update_ms",
                            "verbose.index.server_last_publish_promote_work_import_tier2_update_ms",
                        ),
                        (
                            "last_publish_promote_work_import_persist_meta_ms",
                            "verbose.index.server_last_publish_promote_work_import_persist_meta_ms",
                        ),
                        (
                            "last_publish_promote_work_import_rebalance_tier2_ms",
                            "verbose.index.server_last_publish_promote_work_import_rebalance_tier2_ms",
                        ),
                        (
                            "last_publish_promote_work_remove_work_root_ms",
                            "verbose.index.server_last_publish_promote_work_remove_work_root_ms",
                        ),
                        (
                            "last_publish_promote_work_other_ms",
                            "verbose.index.server_last_publish_promote_work_other_ms",
                        ),
                        (
                            "last_publish_promote_work_imported_docs",
                            "verbose.index.server_last_publish_promote_work_imported_docs",
                        ),
                        (
                            "last_publish_promote_work_imported_shards",
                            "verbose.index.server_last_publish_promote_work_imported_shards",
                        ),
                        (
                            "last_publish_init_work_ms",
                            "verbose.index.server_last_publish_init_work_ms",
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
                    for (key, label) in [
                        (
                            "adaptive_mode",
                            "verbose.index.server_publish_adaptive_mode",
                        ),
                        (
                            "adaptive_reason",
                            "verbose.index.server_publish_adaptive_reason",
                        ),
                        (
                            "adaptive_storage_class",
                            "verbose.index.server_publish_adaptive_storage_class",
                        ),
                    ] {
                        if let Some(value) = publish.get(key).and_then(|value| value.as_str()) {
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
                    if let Some(server_insert_batch_profile) = index_session
                        .get("server_insert_batch_profile")
                        .and_then(serde_json::Value::as_object)
                    {
                        for (key, label) in [
                            ("batches", "verbose.index.server_index_insert_batch_count"),
                            (
                                "documents",
                                "verbose.index.server_index_insert_batch_documents",
                            ),
                            (
                                "shards_touched_total",
                                "verbose.index.server_index_insert_batch_shards_touched_total",
                            ),
                            (
                                "total_us",
                                "verbose.index.server_index_insert_batch_total_us",
                            ),
                            (
                                "parse_us",
                                "verbose.index.server_index_insert_batch_parse_us",
                            ),
                            (
                                "group_us",
                                "verbose.index.server_index_insert_batch_group_us",
                            ),
                            (
                                "build_us",
                                "verbose.index.server_index_insert_batch_build_us",
                            ),
                            (
                                "store_us",
                                "verbose.index.server_index_insert_batch_store_us",
                            ),
                            (
                                "finalize_us",
                                "verbose.index.server_index_insert_batch_finalize_us",
                            ),
                            (
                                "store_resolve_doc_state_us",
                                "verbose.index.server_index_insert_batch_store_resolve_doc_state_us",
                            ),
                            (
                                "store_append_sidecars_us",
                                "verbose.index.server_index_insert_batch_store_append_sidecars_us",
                            ),
                            (
                                "store_append_sidecar_payloads_us",
                                "verbose.index.server_index_insert_batch_store_append_sidecar_payloads_us",
                            ),
                            (
                                "store_append_bloom_payload_assemble_us",
                                "verbose.index.server_index_insert_batch_store_append_bloom_payload_assemble_us",
                            ),
                            (
                                "store_append_bloom_payload_us",
                                "verbose.index.server_index_insert_batch_store_append_bloom_payload_us",
                            ),
                            (
                                "store_append_bloom_payload_bytes",
                                "verbose.index.server_index_insert_batch_store_append_bloom_payload_bytes",
                            ),
                            (
                                "store_append_metadata_payload_us",
                                "verbose.index.server_index_insert_batch_store_append_metadata_payload_us",
                            ),
                            (
                                "store_append_metadata_payload_bytes",
                                "verbose.index.server_index_insert_batch_store_append_metadata_payload_bytes",
                            ),
                            (
                                "store_append_external_id_payload_us",
                                "verbose.index.server_index_insert_batch_store_append_external_id_payload_us",
                            ),
                            (
                                "store_append_external_id_payload_bytes",
                                "verbose.index.server_index_insert_batch_store_append_external_id_payload_bytes",
                            ),
                            (
                                "store_append_tier2_bloom_payload_us",
                                "verbose.index.server_index_insert_batch_store_append_tier2_bloom_payload_us",
                            ),
                            (
                                "store_append_tier2_bloom_payload_bytes",
                                "verbose.index.server_index_insert_batch_store_append_tier2_bloom_payload_bytes",
                            ),
                            (
                                "store_append_doc_row_build_us",
                                "verbose.index.server_index_insert_batch_store_append_doc_row_build_us",
                            ),
                            (
                                "store_append_doc_records_us",
                                "verbose.index.server_index_insert_batch_store_append_doc_records_us",
                            ),
                            (
                                "store_write_existing_us",
                                "verbose.index.server_index_insert_batch_store_write_existing_us",
                            ),
                            (
                                "store_install_docs_us",
                                "verbose.index.server_index_insert_batch_store_install_docs_us",
                            ),
                            (
                                "store_tier2_update_us",
                                "verbose.index.server_index_insert_batch_store_tier2_update_us",
                            ),
                            (
                                "store_persist_meta_us",
                                "verbose.index.server_index_insert_batch_store_persist_meta_us",
                            ),
                            (
                                "store_rebalance_tier2_us",
                                "verbose.index.server_index_insert_batch_store_rebalance_tier2_us",
                            ),
                        ] {
                            if let Some(value) = server_insert_batch_profile
                                .get(key)
                                .and_then(serde_json::Value::as_u64)
                            {
                                eprintln!("{label}: {value}");
                            }
                        }
                    }
                }
                if let Some(seal) = stats
                    .get("published_tier2_snapshot_seal")
                    .and_then(serde_json::Value::as_object)
                {
                    if let Some(value) = seal
                        .get("pending_shards")
                        .and_then(serde_json::Value::as_u64)
                    {
                        eprintln!(
                            "verbose.index.server_published_tier2_snapshot_seal_pending_shards: {value}"
                        );
                    }
                    if let Some(value) =
                        seal.get("in_progress").and_then(serde_json::Value::as_bool)
                    {
                        eprintln!(
                            "verbose.index.server_published_tier2_snapshot_seal_in_progress: {value}"
                        );
                    }
                    for (key, label) in [
                        (
                            "last_duration_ms",
                            "verbose.index.server_published_tier2_snapshot_seal_last_duration_ms",
                        ),
                        (
                            "last_persisted_shards",
                            "verbose.index.server_published_tier2_snapshot_seal_last_persisted_shards",
                        ),
                        (
                            "last_failures",
                            "verbose.index.server_published_tier2_snapshot_seal_last_failures",
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
            return Err(SspryError::from("delete requires at least one value"));
        }
        let mut any_failed = false;
        let mut results = Vec::with_capacity(args.values.len());
        if let Some(root) = &args.root {
            let mut stores = open_stores(Path::new(root))?;
            let id_source = stores
                .first()
                .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?
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
            let (gram_sizes, active_identity_source) = stores
                .first()
                .map(|store| {
                    let config = store.config();
                    Ok::<_, SspryError>((
                        GramSizes::new(config.tier1_gram_size, config.tier2_gram_size)?,
                        Some(config.id_source),
                    ))
                })
                .transpose()?
                .unwrap_or((GramSizes::new(3, 4)?, None));
            let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
                &args.rule,
                gram_sizes,
                active_identity_source.as_deref(),
                args.max_anchors_per_pattern,
                args.force_tier1_only,
                !args.no_tier2_fallback,
                args.max_candidates,
            )?;
            let mut tier1_filter_keys = std::collections::HashSet::<(usize, usize)>::new();
            let mut tier2_filter_keys = std::collections::HashSet::<(usize, usize)>::new();
            for store in &stores {
                tier1_filter_keys.extend(store.tier1_doc_filter_keys());
                tier2_filter_keys.extend(store.tier2_doc_filter_keys());
            }
            let mut ordered_tier1_filter_keys = tier1_filter_keys.into_iter().collect::<Vec<_>>();
            ordered_tier1_filter_keys.sort_unstable();
            let mut ordered_tier2_filter_keys = tier2_filter_keys.into_iter().collect::<Vec<_>>();
            ordered_tier2_filter_keys.sort_unstable();
            let prepared_query_profile = crate::candidate::store::prepared_query_artifacts_profile(
                crate::candidate::store::build_prepared_query_artifacts(
                    &plan,
                    &ordered_tier1_filter_keys,
                    &ordered_tier2_filter_keys,
                )?
                .as_ref(),
            );
            if stores.len() == 1 {
                let mut resolved_plan = plan.clone();
                resolved_plan.max_candidates =
                    resolve_max_candidates(stores[0].live_doc_count(), plan.max_candidates) as f64;
                let result =
                    stores[0].query_candidates(&resolved_plan, args.cursor, args.chunk_size)?;
                rpc::CandidateQueryResponse {
                    sha256: result.sha256,
                    total_candidates: result.total_candidates,
                    returned_count: result.returned_count,
                    cursor: result.cursor,
                    next_cursor: result.next_cursor,
                    truncated: result.truncated,
                    truncated_limit: result.truncated_limit,
                    tier_used: result.tier_used,
                    query_profile: result.query_profile,
                    prepared_query_profile,
                    external_ids: None,
                }
            } else {
                let mut hashes = std::collections::HashSet::<String>::new();
                let mut tier_used = Vec::<String>::new();
                let mut query_profile = crate::candidate::CandidateQueryProfile::default();
                let mut scan_plan = plan.clone();
                scan_plan.max_candidates = 0.0;
                let collect_chunk = DEFAULT_SEARCH_RESULT_CHUNK_SIZE.max(1);
                let searchable_doc_count = stores
                    .iter()
                    .map(CandidateStore::live_doc_count)
                    .sum::<usize>();
                let resolved_limit =
                    resolve_max_candidates(searchable_doc_count, plan.max_candidates);
                for store in &mut stores {
                    let mut cursor = 0usize;
                    loop {
                        let local = store.query_candidates(&scan_plan, cursor, collect_chunk)?;
                        tier_used.push(local.tier_used.clone());
                        query_profile.merge_from(&local.query_profile);
                        hashes.extend(local.sha256);
                        if let Some(next) = local.next_cursor {
                            cursor = next;
                        } else {
                            break;
                        }
                    }
                }
                let mut hashes = hashes.into_iter().collect::<Vec<_>>();
                let truncated = resolved_limit != usize::MAX && hashes.len() > resolved_limit;
                if truncated {
                    hashes.truncate(resolved_limit);
                }
                let total_candidates = hashes.len();
                let start = args.cursor.min(total_candidates);
                let end = (start + args.chunk_size.max(1)).min(total_candidates);
                rpc::CandidateQueryResponse {
                    returned_count: end.saturating_sub(start),
                    sha256: hashes[start..end].to_vec(),
                    total_candidates,
                    cursor: start,
                    next_cursor: (end < total_candidates).then_some(end),
                    truncated,
                    truncated_limit: truncated.then_some(resolved_limit),
                    tier_used: merge_tier_used(tier_used),
                    query_profile,
                    prepared_query_profile,
                    external_ids: None,
                }
            }
        } else {
            let client = search_rpc_client(&args.connection);
            let server_policy = server_scan_policy(&args.connection)?;
            // Bloom-only search compiles directly against the server's gram sizes.
            let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
                &args.rule,
                server_policy.gram_sizes,
                Some(server_policy.id_source.as_str()),
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
        println!("truncated: {}", result.truncated);
        if let Some(limit) = result.truncated_limit {
            println!("truncated_limit: {limit}");
        }
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

fn cmd_index(args: &IndexArgs) -> i32 {
    if args.root.is_some() {
        return cmd_internal_index_batch(&InternalIndexBatchArgs {
            connection: args.connection.clone(),
            paths: args.paths.clone(),
            path_list: args.path_list,
            root: args.root.clone(),
            batch_size: args.batch_size,
            remote_batch_soft_limit_bytes: args.remote_batch_soft_limit_bytes,
            workers: args.workers.unwrap_or(0),
            chunk_size: DEFAULT_FILE_READ_CHUNK_SIZE,
            external_id_from_path: false,
            verbose: args.verbose,
            rotate_remote_sessions: false,
        });
    }
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
        path_list: args.path_list,
        root: None,
        batch_size: args.batch_size,
        remote_batch_soft_limit_bytes: args.remote_batch_soft_limit_bytes,
        workers: args.workers.unwrap_or(0),
        chunk_size: DEFAULT_FILE_READ_CHUNK_SIZE,
        external_id_from_path: server_policy.store_path,
        verbose: args.verbose,
        rotate_remote_sessions: false,
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
                    return Err(SspryError::from(format!(
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

fn cmd_search(args: &SearchCommandArgs) -> i32 {
    match (|| -> Result<i32> {
        let started_total = Instant::now();
        let mut plan_time = Duration::ZERO;
        let mut query_time = Duration::ZERO;
        let mut verify_time = Duration::ZERO;
        let mut server_rss_kb = None::<(u64, u64)>;
        if args.gate_only && args.root.is_none() {
            return Err(SspryError::from(
                "--gate-only currently requires --root local search mode.",
            ));
        }
        let verify_yara_files = args.verify_yara_files && !args.gate_only;
        let mut tree_count = None::<usize>;
        let mut tree_search_workers = None::<usize>;

        let started_plan = Instant::now();
        let (
            plan,
            total,
            tier_used,
            truncated,
            truncated_limit,
            rows,
            query_profile,
            prepared_query_profile,
            external_ids,
        ) = if let Some(root) = &args.root {
            let mut tree_groups = open_forest_tree_groups(Path::new(root))?;
            tree_count = Some(tree_groups.len());
            let (gram_sizes, active_identity_source, summary_cap_bytes) =
                validate_forest_search_policy(&tree_groups)?;
            let worker_count = args
                .tree_search_workers
                .max(1)
                .min(tree_groups.len().max(1));
            tree_search_workers = Some(worker_count);
            let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
                &args.rule,
                gram_sizes,
                active_identity_source.as_deref(),
                args.max_anchors_per_pattern,
                false,
                true,
                args.max_candidates,
            )?;
            plan_time += started_plan.elapsed();
            let started_query = Instant::now();
            if args.gate_only {
                let query_profile =
                    query_local_forest_tree_gates(&mut tree_groups, &plan, worker_count)?;
                query_time += started_query.elapsed();
                (
                    plan,
                    0usize,
                    "gate-only".to_owned(),
                    false,
                    None,
                    Vec::new(),
                    query_profile,
                    crate::candidate::CandidatePreparedQueryProfile::default(),
                    Vec::new(),
                )
            } else {
                let prepared_query_profile =
                    forest_prepared_query_profile(&tree_groups, &plan, summary_cap_bytes)?;
                let local = query_local_forest_all_candidates(
                    &mut tree_groups,
                    &plan,
                    verify_yara_files,
                    worker_count,
                )?;
                query_time += started_query.elapsed();
                (
                    plan,
                    local.total_candidates,
                    local.tier_used,
                    local.truncated,
                    local.truncated_limit,
                    local.hashes,
                    local.query_profile,
                    prepared_query_profile,
                    local.external_ids.unwrap_or_default(),
                )
            }
        } else {
            let client = search_rpc_client(&args.connection);
            let server_policy = server_scan_policy(&args.connection)?;
            let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
                &args.rule,
                server_policy.gram_sizes,
                Some(server_policy.id_source.as_str()),
                args.max_anchors_per_pattern,
                false,
                true,
                args.max_candidates,
            )?;
            plan_time += started_plan.elapsed();
            let started_query = Instant::now();
            let mut buffered_rows = Vec::<String>::new();
            let mut buffered_external_ids = Vec::<Option<String>>::new();
            let mut accepted_positions = HashMap::<String, usize>::new();
            let mut query_profile = crate::candidate::CandidateQueryProfile::default();
            let mut prepared_query_profile =
                crate::candidate::CandidatePreparedQueryProfile::default();
            let mut total = 0usize;
            let mut tier_used = String::new();
            let mut truncated = false;
            let mut truncated_limit = None::<usize>;
            client.candidate_query_plan_stream_with_options(
                &plan,
                Some(DEFAULT_SEARCH_RESULT_CHUNK_SIZE),
                verify_yara_files,
                |frame| {
                    if truncated_limit.is_none() {
                        truncated_limit = frame.candidate_limit;
                    }
                    if frame.stream_complete {
                        tier_used = frame.tier_used;
                        query_profile = frame.query_profile;
                        prepared_query_profile = frame.prepared_query_profile;
                        return Ok(());
                    }
                    let mut frame_external_ids = frame.external_ids.unwrap_or_default();
                    if verify_yara_files && frame_external_ids.len() < frame.sha256.len() {
                        frame_external_ids.resize(frame.sha256.len(), None);
                    }
                    for (idx, sha256) in frame.sha256.into_iter().enumerate() {
                        let external_id = if verify_yara_files {
                            frame_external_ids.get(idx).cloned().flatten()
                        } else {
                            None
                        };
                        if let Some(existing_idx) = accepted_positions.get(&sha256).copied() {
                            if verify_yara_files
                                && buffered_external_ids
                                    .get(existing_idx)
                                    .is_some_and(Option::is_none)
                                && external_id.is_some()
                            {
                                buffered_external_ids[existing_idx] = external_id;
                            }
                            continue;
                        }
                        if truncated_limit.is_some_and(|limit| buffered_rows.len() >= limit) {
                            truncated = true;
                            continue;
                        }
                        accepted_positions.insert(sha256.clone(), buffered_rows.len());
                        total = total.saturating_add(1);
                        if verify_yara_files {
                            buffered_external_ids.push(external_id);
                        } else {
                            println!("{sha256}");
                        }
                        buffered_rows.push(sha256);
                    }
                    Ok(())
                },
            )?;
            query_time += started_query.elapsed();
            (
                plan,
                total,
                tier_used,
                truncated,
                truncated_limit,
                buffered_rows,
                query_profile,
                prepared_query_profile,
                buffered_external_ids,
            )
        };

        let started_verify = Instant::now();
        let verification = verify_search_candidates(
            Path::new(&args.rule),
            &plan,
            rows,
            external_ids,
            verify_yara_files,
        )?;
        verify_time += started_verify.elapsed();
        let SearchVerificationResult {
            rows,
            verified_checked,
            verified_matched,
            verified_skipped,
        } = verification;

        println!("tier_used: {tier_used}");
        println!("candidates: {total}");
        println!("truncated: {truncated}");
        if let Some(limit) = truncated_limit {
            println!("truncated_limit: {limit}");
        }
        if verify_yara_files {
            println!("verified_checked: {verified_checked}");
            println!("verified_matched: {verified_matched}");
            println!("verified_skipped: {verified_skipped}");
            for row in rows {
                println!("{row}");
            }
        } else {
            for row in rows {
                println!("{row}");
            }
        }
        if args.verbose && args.root.is_none() {
            server_rss_kb = server_memory_kb(&args.connection)?;
        }
        if args.verbose {
            let total_ms = started_total.elapsed().as_secs_f64() * 1000.0;
            let plan_ms = plan_time.as_secs_f64() * 1000.0;
            let query_ms = query_time.as_secs_f64() * 1000.0;
            let verify_ms = verify_time.as_secs_f64() * 1000.0;
            eprintln!("verbose.search.total_ms: {total_ms:.3}");
            eprintln!("verbose.search.plan_ms: {plan_ms:.3}");
            eprintln!("verbose.search.query_ms: {query_ms:.3}");
            eprintln!("verbose.search.verify_ms: {verify_ms:.3}");
            eprintln!(
                "verbose.search.docs_scanned: {}",
                query_profile.docs_scanned
            );
            eprintln!(
                "verbose.search.metadata_loads: {}",
                query_profile.metadata_loads
            );
            eprintln!(
                "verbose.search.metadata_bytes: {}",
                query_profile.metadata_bytes
            );
            eprintln!(
                "verbose.search.tier1_bloom_loads: {}",
                query_profile.tier1_bloom_loads
            );
            eprintln!(
                "verbose.search.tier1_bloom_bytes: {}",
                query_profile.tier1_bloom_bytes
            );
            eprintln!(
                "verbose.search.tier2_bloom_loads: {}",
                query_profile.tier2_bloom_loads
            );
            eprintln!(
                "verbose.search.tier2_bloom_bytes: {}",
                query_profile.tier2_bloom_bytes
            );
            eprintln!(
                "verbose.search.prepared_query_bytes: {}",
                prepared_query_profile.prepared_query_bytes
            );
            eprintln!(
                "verbose.search.prepared_pattern_plan_bytes: {}",
                prepared_query_profile.prepared_pattern_plan_bytes
            );
            eprintln!(
                "verbose.search.prepared_mask_cache_bytes: {}",
                prepared_query_profile.prepared_mask_cache_bytes
            );
            eprintln!(
                "verbose.search.prepared_pattern_count: {}",
                prepared_query_profile.pattern_count
            );
            eprintln!(
                "verbose.search.prepared_mask_cache_entries: {}",
                prepared_query_profile.mask_cache_entries
            );
            eprintln!(
                "verbose.search.prepared_fixed_literal_count: {}",
                prepared_query_profile.fixed_literal_count
            );
            eprintln!(
                "verbose.search.prepared_tier1_alternatives: {}",
                prepared_query_profile.tier1_alternatives
            );
            eprintln!(
                "verbose.search.prepared_tier2_alternatives: {}",
                prepared_query_profile.tier2_alternatives
            );
            eprintln!(
                "verbose.search.prepared_tier1_shift_variants: {}",
                prepared_query_profile.tier1_shift_variants
            );
            eprintln!(
                "verbose.search.prepared_tier2_shift_variants: {}",
                prepared_query_profile.tier2_shift_variants
            );
            eprintln!(
                "verbose.search.prepared_tier1_any_lane_alternatives: {}",
                prepared_query_profile.tier1_any_lane_alternatives
            );
            eprintln!(
                "verbose.search.prepared_tier2_any_lane_alternatives: {}",
                prepared_query_profile.tier2_any_lane_alternatives
            );
            eprintln!(
                "verbose.search.prepared_tier1_compacted_any_lane_alternatives: {}",
                prepared_query_profile.tier1_compacted_any_lane_alternatives
            );
            eprintln!(
                "verbose.search.prepared_tier2_compacted_any_lane_alternatives: {}",
                prepared_query_profile.tier2_compacted_any_lane_alternatives
            );
            eprintln!(
                "verbose.search.prepared_any_lane_variant_sets: {}",
                prepared_query_profile.any_lane_variant_sets
            );
            eprintln!(
                "verbose.search.prepared_compacted_any_lane_grams: {}",
                prepared_query_profile.compacted_any_lane_grams
            );
            eprintln!(
                "verbose.search.prepared_max_pattern_bytes: {}",
                prepared_query_profile.max_pattern_bytes
            );
            eprintln!(
                "verbose.search.prepared_impossible_query: {}",
                prepared_query_profile.impossible_query
            );
            if let Some(max_pattern_id) = &prepared_query_profile.max_pattern_id {
                eprintln!("verbose.search.prepared_max_pattern_id: {max_pattern_id}");
            }
            eprintln!("verbose.search.max_candidates: {}", args.max_candidates);
            eprintln!(
                "verbose.search.max_anchors_per_pattern: {}",
                args.max_anchors_per_pattern
            );
            eprintln!("verbose.search.candidates: {total}");
            eprintln!("verbose.search.verify_enabled: {}", verify_yara_files);
            eprintln!(
                "verbose.search.tree_gate_trees_considered: {}",
                query_profile.tree_gate_trees_considered
            );
            eprintln!(
                "verbose.search.tree_gate_passed: {}",
                query_profile.tree_gate_passed
            );
            eprintln!(
                "verbose.search.tree_gate_tier1_pruned: {}",
                query_profile.tree_gate_tier1_pruned
            );
            eprintln!(
                "verbose.search.tree_gate_tier2_pruned: {}",
                query_profile.tree_gate_tier2_pruned
            );
            eprintln!(
                "verbose.search.tree_gate_special_docs_bypass: {}",
                query_profile.tree_gate_special_docs_bypass
            );
            eprintln!("verbose.search.gate_only: {}", args.gate_only);
            let (client_current_rss_kb, client_peak_rss_kb) = current_process_memory_kb();
            let smaps_rollup = current_process_smaps_rollup_kb();
            eprintln!("verbose.search.client_current_rss_kb: {client_current_rss_kb}");
            eprintln!("verbose.search.client_peak_rss_kb: {client_peak_rss_kb}");
            eprintln!(
                "verbose.search.client_smaps_rss_kb: {}",
                smaps_rollup.rss_kb
            );
            eprintln!(
                "verbose.search.client_anonymous_kb: {}",
                smaps_rollup.anonymous_kb
            );
            eprintln!(
                "verbose.search.client_private_clean_kb: {}",
                smaps_rollup.private_clean_kb
            );
            eprintln!(
                "verbose.search.client_private_dirty_kb: {}",
                smaps_rollup.private_dirty_kb
            );
            eprintln!(
                "verbose.search.client_shared_clean_kb: {}",
                smaps_rollup.shared_clean_kb
            );
            if let Some((server_current_rss_kb, server_peak_rss_kb)) = server_rss_kb {
                eprintln!("verbose.search.server_current_rss_kb: {server_current_rss_kb}");
                eprintln!("verbose.search.server_peak_rss_kb: {server_peak_rss_kb}");
            }
            if let Some(tree_count) = tree_count {
                eprintln!("verbose.search.tree_count: {tree_count}");
            }
            if let Some(tree_search_workers) = tree_search_workers {
                eprintln!("verbose.search.tree_search_workers: {tree_search_workers}");
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

fn collect_rules_from_args(
    rules_dir: &Option<String>,
    rule_manifest: &Option<String>,
) -> Result<Vec<PathBuf>> {
    let mut rules = if let Some(dir) = rules_dir {
        let mut values = fs::read_dir(dir)?
            .filter_map(|entry| entry.ok())
            .map(|entry| entry.path())
            .filter(|path| path.extension().and_then(|value| value.to_str()) == Some("yar"))
            .collect::<Vec<_>>();
        values.sort();
        values
    } else if let Some(manifest) = rule_manifest {
        fs::read_to_string(manifest)?
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(PathBuf::from)
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    if rules.is_empty() {
        return Err(SspryError::from(
            "search-batch requires at least one rule from --rules-dir or --rule-manifest",
        ));
    }
    rules.sort();
    Ok(rules)
}

fn cmd_search_batch(args: &SearchBatchArgs) -> i32 {
    match (|| -> Result<i32> {
        let root = Path::new(&args.root);
        let rules = collect_rules_from_args(&args.rules_dir, &args.rule_manifest)?;
        let mut tree_groups = open_forest_tree_groups(root)?;
        let tree_count = tree_groups.len();
        let (gram_sizes, active_identity_source, summary_cap_bytes) =
            validate_forest_search_policy(&tree_groups)?;
        let tree_search_workers = args.tree_search_workers.max(1).min(tree_count.max(1));
        eprintln!(
            "search.batch.start rules={} trees={} tree_workers={}",
            rules.len(),
            tree_count,
            tree_search_workers
        );
        let mut out = BatchSearchRecordStream::new(Path::new(&args.json_out))?;
        eprintln!(
            "search.batch.stream json_out={} jsonl_out={}",
            args.json_out,
            out.jsonl_out().display()
        );
        for rule in rules {
            let started_total = Instant::now();
            let rule_name = rule
                .file_name()
                .and_then(|value| value.to_str())
                .unwrap_or_default()
                .to_owned();
            eprintln!("search.batch.rule.start rule={rule_name}");
            let record = match (|| -> Result<BatchSearchRecord> {
                let started_plan = Instant::now();
                let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
                    &rule,
                    gram_sizes,
                    active_identity_source.as_deref(),
                    args.max_anchors_per_pattern,
                    false,
                    true,
                    args.max_candidates,
                )?;
                let prepared_query_profile =
                    forest_prepared_query_profile(&tree_groups, &plan, summary_cap_bytes)?;
                let plan_ms = started_plan.elapsed().as_secs_f64() * 1000.0;
                let started_query = Instant::now();
                let local = query_local_forest_all_candidates(
                    &mut tree_groups,
                    &plan,
                    args.verify_yara_files,
                    tree_search_workers,
                )?;
                let query_ms = started_query.elapsed().as_secs_f64() * 1000.0;
                let started_verify = Instant::now();
                let verification = verify_search_candidates(
                    &rule,
                    &plan,
                    local.hashes,
                    local.external_ids.unwrap_or_default(),
                    args.verify_yara_files,
                )?;
                let verify_ms = started_verify.elapsed().as_secs_f64() * 1000.0;
                clear_local_forest_search_caches(&mut tree_groups);
                let total_ms = started_total.elapsed().as_secs_f64() * 1000.0;
                let (client_current_rss_kb, client_peak_rss_kb) = current_process_memory_kb();
                let smaps_rollup = current_process_smaps_rollup_kb();
                Ok(BatchSearchRecord {
                    rule: rule_name.clone(),
                    rule_path: rule.display().to_string(),
                    exit_code: 0,
                    elapsed_ms_wall: total_ms,
                    error: None,
                    candidates: Some(local.total_candidates),
                    truncated: Some(local.truncated),
                    truncated_limit: local.truncated_limit,
                    tier_used: Some(local.tier_used),
                    verified_checked: Some(verification.verified_checked),
                    verified_matched: Some(verification.verified_matched),
                    verified_skipped: Some(verification.verified_skipped),
                    verbose_search_total_ms: Some(total_ms),
                    verbose_search_plan_ms: Some(plan_ms),
                    verbose_search_query_ms: Some(query_ms),
                    verbose_search_verify_ms: Some(verify_ms),
                    verbose_search_tree_gate_trees_considered: Some(
                        local.query_profile.tree_gate_trees_considered,
                    ),
                    verbose_search_tree_gate_passed: Some(local.query_profile.tree_gate_passed),
                    verbose_search_tree_gate_tier1_pruned: Some(
                        local.query_profile.tree_gate_tier1_pruned,
                    ),
                    verbose_search_tree_gate_tier2_pruned: Some(
                        local.query_profile.tree_gate_tier2_pruned,
                    ),
                    verbose_search_tree_gate_special_docs_bypass: Some(
                        local.query_profile.tree_gate_special_docs_bypass,
                    ),
                    verbose_search_docs_scanned: Some(local.query_profile.docs_scanned),
                    verbose_search_metadata_loads: Some(local.query_profile.metadata_loads),
                    verbose_search_metadata_bytes: Some(local.query_profile.metadata_bytes),
                    verbose_search_tier1_bloom_loads: Some(local.query_profile.tier1_bloom_loads),
                    verbose_search_tier1_bloom_bytes: Some(local.query_profile.tier1_bloom_bytes),
                    verbose_search_tier2_bloom_loads: Some(local.query_profile.tier2_bloom_loads),
                    verbose_search_tier2_bloom_bytes: Some(local.query_profile.tier2_bloom_bytes),
                    verbose_search_prepared_query_bytes: Some(
                        prepared_query_profile.prepared_query_bytes,
                    ),
                    verbose_search_prepared_pattern_plan_bytes: Some(
                        prepared_query_profile.prepared_pattern_plan_bytes,
                    ),
                    verbose_search_prepared_mask_cache_bytes: Some(
                        prepared_query_profile.prepared_mask_cache_bytes,
                    ),
                    verbose_search_prepared_pattern_count: Some(
                        prepared_query_profile.pattern_count,
                    ),
                    verbose_search_prepared_mask_cache_entries: Some(
                        prepared_query_profile.mask_cache_entries,
                    ),
                    verbose_search_prepared_fixed_literal_count: Some(
                        prepared_query_profile.fixed_literal_count,
                    ),
                    verbose_search_prepared_tier1_alternatives: Some(
                        prepared_query_profile.tier1_alternatives,
                    ),
                    verbose_search_prepared_tier2_alternatives: Some(
                        prepared_query_profile.tier2_alternatives,
                    ),
                    verbose_search_prepared_tier1_shift_variants: Some(
                        prepared_query_profile.tier1_shift_variants,
                    ),
                    verbose_search_prepared_tier2_shift_variants: Some(
                        prepared_query_profile.tier2_shift_variants,
                    ),
                    verbose_search_prepared_tier1_any_lane_alternatives: Some(
                        prepared_query_profile.tier1_any_lane_alternatives,
                    ),
                    verbose_search_prepared_tier2_any_lane_alternatives: Some(
                        prepared_query_profile.tier2_any_lane_alternatives,
                    ),
                    verbose_search_prepared_tier1_compacted_any_lane_alternatives: Some(
                        prepared_query_profile.tier1_compacted_any_lane_alternatives,
                    ),
                    verbose_search_prepared_tier2_compacted_any_lane_alternatives: Some(
                        prepared_query_profile.tier2_compacted_any_lane_alternatives,
                    ),
                    verbose_search_prepared_any_lane_variant_sets: Some(
                        prepared_query_profile.any_lane_variant_sets,
                    ),
                    verbose_search_prepared_compacted_any_lane_grams: Some(
                        prepared_query_profile.compacted_any_lane_grams,
                    ),
                    verbose_search_prepared_max_pattern_bytes: Some(
                        prepared_query_profile.max_pattern_bytes,
                    ),
                    verbose_search_prepared_max_pattern_id: prepared_query_profile.max_pattern_id,
                    verbose_search_prepared_impossible_query: Some(
                        prepared_query_profile.impossible_query,
                    ),
                    verbose_search_max_candidates: Some(args.max_candidates),
                    verbose_search_max_anchors_per_pattern: Some(args.max_anchors_per_pattern),
                    verbose_search_candidates: Some(local.total_candidates),
                    verbose_search_verify_enabled: Some(args.verify_yara_files),
                    verbose_search_client_current_rss_kb: Some(client_current_rss_kb),
                    verbose_search_client_peak_rss_kb: Some(client_peak_rss_kb),
                    verbose_search_client_smaps_rss_kb: Some(smaps_rollup.rss_kb),
                    verbose_search_client_anonymous_kb: Some(smaps_rollup.anonymous_kb),
                    verbose_search_client_private_clean_kb: Some(smaps_rollup.private_clean_kb),
                    verbose_search_client_private_dirty_kb: Some(smaps_rollup.private_dirty_kb),
                    verbose_search_client_shared_clean_kb: Some(smaps_rollup.shared_clean_kb),
                    verbose_search_server_current_rss_kb: None,
                    verbose_search_server_peak_rss_kb: None,
                    verbose_search_tree_count: Some(tree_count),
                    verbose_search_tree_search_workers: Some(tree_search_workers),
                })
            })() {
                Ok(record) => record,
                Err(err) => BatchSearchRecord {
                    rule: rule_name.clone(),
                    rule_path: rule.display().to_string(),
                    exit_code: 1,
                    elapsed_ms_wall: started_total.elapsed().as_secs_f64() * 1000.0,
                    error: Some(err.to_string()),
                    candidates: None,
                    truncated: None,
                    truncated_limit: None,
                    tier_used: None,
                    verified_checked: None,
                    verified_matched: None,
                    verified_skipped: None,
                    verbose_search_total_ms: None,
                    verbose_search_plan_ms: None,
                    verbose_search_query_ms: None,
                    verbose_search_verify_ms: None,
                    verbose_search_tree_gate_trees_considered: None,
                    verbose_search_tree_gate_passed: None,
                    verbose_search_tree_gate_tier1_pruned: None,
                    verbose_search_tree_gate_tier2_pruned: None,
                    verbose_search_tree_gate_special_docs_bypass: None,
                    verbose_search_docs_scanned: None,
                    verbose_search_metadata_loads: None,
                    verbose_search_metadata_bytes: None,
                    verbose_search_tier1_bloom_loads: None,
                    verbose_search_tier1_bloom_bytes: None,
                    verbose_search_tier2_bloom_loads: None,
                    verbose_search_tier2_bloom_bytes: None,
                    verbose_search_prepared_query_bytes: None,
                    verbose_search_prepared_pattern_plan_bytes: None,
                    verbose_search_prepared_mask_cache_bytes: None,
                    verbose_search_prepared_pattern_count: None,
                    verbose_search_prepared_mask_cache_entries: None,
                    verbose_search_prepared_fixed_literal_count: None,
                    verbose_search_prepared_tier1_alternatives: None,
                    verbose_search_prepared_tier2_alternatives: None,
                    verbose_search_prepared_tier1_shift_variants: None,
                    verbose_search_prepared_tier2_shift_variants: None,
                    verbose_search_prepared_tier1_any_lane_alternatives: None,
                    verbose_search_prepared_tier2_any_lane_alternatives: None,
                    verbose_search_prepared_tier1_compacted_any_lane_alternatives: None,
                    verbose_search_prepared_tier2_compacted_any_lane_alternatives: None,
                    verbose_search_prepared_any_lane_variant_sets: None,
                    verbose_search_prepared_compacted_any_lane_grams: None,
                    verbose_search_prepared_max_pattern_bytes: None,
                    verbose_search_prepared_max_pattern_id: None,
                    verbose_search_prepared_impossible_query: None,
                    verbose_search_max_candidates: Some(args.max_candidates),
                    verbose_search_max_anchors_per_pattern: Some(args.max_anchors_per_pattern),
                    verbose_search_candidates: None,
                    verbose_search_verify_enabled: Some(args.verify_yara_files),
                    verbose_search_client_current_rss_kb: None,
                    verbose_search_client_peak_rss_kb: None,
                    verbose_search_client_smaps_rss_kb: None,
                    verbose_search_client_anonymous_kb: None,
                    verbose_search_client_private_clean_kb: None,
                    verbose_search_client_private_dirty_kb: None,
                    verbose_search_client_shared_clean_kb: None,
                    verbose_search_server_current_rss_kb: None,
                    verbose_search_server_peak_rss_kb: None,
                    verbose_search_tree_count: Some(tree_count),
                    verbose_search_tree_search_workers: Some(tree_search_workers),
                },
            };
            eprintln!(
                "search.batch.rule.done rule={} exit={} wall_ms={:.3}",
                record.rule, record.exit_code, record.elapsed_ms_wall
            );
            out.push(&record)?;
        }
        let count = out.finish()?;
        eprintln!("search.batch.done rules={count}");
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
        let stats = if args.light {
            rpc_client(&args.connection).candidate_status()?
        } else {
            rpc_client(&args.connection).candidate_stats()?
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
#[command(
    name = "sspry",
    about = "Scalable Screening and Prefiltering of Rules for YARA."
)]
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
    Init(InitArgs),
    Index(IndexArgs),
    Delete(DeleteArgs),
    Search(SearchCommandArgs),
    SearchBatch(SearchBatchArgs),
    Info(InfoCommandArgs),
    Shutdown(ShutdownArgs),
    Yara(YaraArgs),
}

#[derive(Debug, clap::Args)]
struct IndexArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(
        long = "root",
        help = "Candidate store root directory for direct local indexing. When set, indexing bypasses RPC and writes directly to this initialized root."
    )]
    root: Option<String>,
    #[arg(required = true, help = "File or directory paths.")]
    paths: Vec<String>,
    #[arg(
        long = "path-list",
        action = ArgAction::SetTrue,
        help = "Treat each input path as a newline-delimited manifest of file paths."
    )]
    path_list: bool,
    #[arg(
        long = "batch-size",
        default_value_t = 64,
        help = "Documents per insert_batch request."
    )]
    batch_size: usize,
    #[arg(
        long = "remote-batch-soft-limit-bytes",
        default_value_t = REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
        help = "Client-side soft payload cap in bytes for remote insert_batch requests."
    )]
    remote_batch_soft_limit_bytes: usize,
    #[arg(
        long = "workers",
        help = "Process workers for recursive file scan/feature extraction before batched inserts. Default is auto: CPU-based on solid-state input, capped conservatively on rotational storage."
    )]
    workers: Option<usize>,
    #[arg(
        long = "verbose",
        action = ArgAction::SetTrue,
        help = "Print timing details to stderr."
    )]
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
    #[arg(
        long = "root",
        help = "Candidate forest root for in-process search. When set, search runs directly against tree_*/current stores instead of RPC servers."
    )]
    root: Option<String>,
    #[arg(long = "rule", required = true, help = "Path to YARA rule file.")]
    rule: String,
    #[arg(
        long = "tree-search-workers",
        default_value_t = 0,
        help = "Forest-level tree search workers for --root mode. 0 means auto up to the tree count."
    )]
    tree_search_workers: usize,
    #[arg(
        long = "max-anchors-per-pattern",
        default_value_t = 16,
        help = "Keep at most this many anchors per pattern alternative."
    )]
    max_anchors_per_pattern: usize,
    #[arg(
        long = "max-candidates",
        default_value_t = 7.5,
        value_parser = parse_max_candidates_percent,
        help = "Server-side candidate cap as a percentage of searchable documents; 0 means unlimited."
    )]
    max_candidates: f64,
    #[arg(
        long = "gate-only",
        action = ArgAction::SetTrue,
        default_value_t = false,
        help = "In --root mode, evaluate only the tree-gate layer and skip candidate/doc scanning."
    )]
    gate_only: bool,
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
struct SearchBatchArgs {
    #[arg(
        long = "root",
        required = true,
        help = "Candidate forest root for in-process batch search."
    )]
    root: String,
    #[arg(
        long = "rules-dir",
        conflicts_with = "rule_manifest",
        help = "Directory containing .yar files to search in sorted filename order."
    )]
    rules_dir: Option<String>,
    #[arg(
        long = "rule-manifest",
        conflicts_with = "rules_dir",
        help = "Newline-delimited manifest of rule file paths."
    )]
    rule_manifest: Option<String>,
    #[arg(
        long = "json-out",
        required = true,
        help = "Write batch JSON results to this path."
    )]
    json_out: String,
    #[arg(
        long = "tree-search-workers",
        default_value_t = 0,
        help = "Forest-level tree search workers. 0 means auto up to the tree count."
    )]
    tree_search_workers: usize,
    #[arg(
        long = "max-anchors-per-pattern",
        default_value_t = 16,
        help = "Keep at most this many anchors per pattern alternative."
    )]
    max_anchors_per_pattern: usize,
    #[arg(
        long = "max-candidates",
        default_value_t = 7.5,
        value_parser = parse_max_candidates_percent,
        help = "Candidate cap per rule as a percentage of searchable documents; 0 means unlimited."
    )]
    max_candidates: f64,
    #[arg(
        long = "verify",
        action = ArgAction::SetTrue,
        help = "Enable local YARA verification over candidate file paths."
    )]
    verify_yara_files: bool,
}

#[derive(Debug, clap::Args)]
struct InfoCommandArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    #[arg(
        long = "light",
        action = ArgAction::SetTrue,
        help = "Return lightweight server status without walking shard stats."
    )]
    light: bool,
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
        env = "SSPRY_ADDR",
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
        long = "root",
        default_value = DEFAULT_CANDIDATE_ROOT,
        help = "Workspace root directory. SSPRY will manage current/, work_a/, work_b/, and retired/ under this path."
    )]
    root: String,
    #[arg(
        long = "layout-profile",
        value_enum,
        default_value_t = ServeLayoutProfile::Standard,
        help = "Shard-layout profile. `standard` defaults to 256 shards; `incremental` defaults to 32 shards for denser ingest batches and lower publish fanout."
    )]
    layout_profile: ServeLayoutProfile,
    #[arg(
        long = "shards",
        help = "Number of independent candidate shards (lock stripes) for ingest/write paths. Overrides --layout-profile when set."
    )]
    shards: Option<usize>,
    #[arg(
        long = "set-fp",
        help = "Fallback Bloom false-positive rate applied to both tiers when tier-specific values are not set."
    )]
    filter_target_fp: Option<f64>,
    #[arg(
        long = "tier1-set-fp",
        help = "Tier1 Bloom false-positive rate. Defaults to --set-fp or 0.40 when omitted."
    )]
    tier1_filter_target_fp: Option<f64>,
    #[arg(
        long = "tier2-set-fp",
        help = "Tier2 Bloom false-positive rate. Defaults to --set-fp or 0.23 when omitted."
    )]
    tier2_filter_target_fp: Option<f64>,
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
        help = "DB-wide gram-size pair as tier1,tier2. Supported pairs: 3,4 4,5 5,6 7,8."
    )]
    gram_sizes: String,
}

#[derive(Debug, clap::Args)]
struct InitArgs {
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
        help = "Fallback Bloom false-positive rate applied to both tiers when tier-specific values are not set."
    )]
    filter_target_fp: Option<f64>,
    #[arg(
        long = "tier1-set-fp",
        help = "Tier1 Bloom false-positive rate. Defaults to --set-fp or 0.40 when omitted."
    )]
    tier1_filter_target_fp: Option<f64>,
    #[arg(
        long = "tier2-set-fp",
        help = "Tier2 Bloom false-positive rate. Defaults to --set-fp or 0.23 when omitted."
    )]
    tier2_filter_target_fp: Option<f64>,
    #[arg(
        long = "gram-sizes",
        default_value = "3,4",
        help = "DB-wide gram-size pair as tier1,tier2. Supported pairs: 3,4 4,5 5,6 7,8."
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
}

#[derive(Debug, clap::Args)]
struct InternalIndexBatchArgs {
    #[command(flatten)]
    connection: ClientConnectionArgs,
    paths: Vec<String>,
    #[arg(long = "path-list", action = ArgAction::SetTrue, help = "Treat input paths as newline-delimited file manifests.")]
    path_list: bool,
    #[arg(long = "root", help = "Candidate store root directory.")]
    root: Option<String>,
    #[arg(
        long = "batch-size",
        default_value_t = 64,
        help = "Documents per batch request."
    )]
    batch_size: usize,
    #[arg(
        long = "remote-batch-soft-limit-bytes",
        default_value_t = REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
        help = "Client-side soft payload cap in bytes for remote insert_batch requests."
    )]
    remote_batch_soft_limit_bytes: usize,
    #[arg(
        long = "workers",
        default_value_t = default_ingest_workers(),
        help = "Workers for recursive file scan before batched inserts."
    )]
    workers: usize,
    #[arg(long = "chunk-size", default_value_t = 1024 * 1024, help = "Client read chunk size in bytes.")]
    chunk_size: usize,
    #[arg(long = "external-id-from-path", action = ArgAction::SetTrue, help = "Set external_id=<file path> for each inserted document.")]
    external_id_from_path: bool,
    #[arg(long = "verbose", action = ArgAction::SetTrue, help = "Print timing details to stderr.")]
    verbose: bool,
    #[arg(
        long = "rotate-remote-sessions",
        action = ArgAction::SetTrue,
        help = "Allow remote indexing to end the current server session and publish mid-job when session limits are hit."
    )]
    rotate_remote_sessions: bool,
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
        help = "Maximum anchor grams kept per pattern alternative after planner reduction."
    )]
    max_anchors_per_pattern: usize,
    #[arg(long = "force-tier1-only", action = ArgAction::SetTrue, help = "Disable tier2 fallback for complete documents.")]
    force_tier1_only: bool,
    #[arg(long = "no-tier2-fallback", action = ArgAction::SetTrue, help = "Disable optional tier2 fallback on complete documents.")]
    no_tier2_fallback: bool,
    #[arg(
        long = "max-candidates",
        default_value_t = 7.5,
        value_parser = parse_max_candidates_percent,
        help = "Maximum candidate percentage returned before paging; 0 means unlimited."
    )]
    max_candidates: f64,
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
        Commands::Init(args) => cmd_init(&args),
        Commands::Index(args) => cmd_index(&args),
        Commands::Delete(args) => cmd_delete(&args),
        Commands::Search(args) => cmd_search(&args),
        Commands::SearchBatch(args) => cmd_search_batch(&args),
        Commands::Info(args) => cmd_info(&args),
        Commands::Shutdown(args) => cmd_shutdown(&args),
        Commands::Yara(args) => cmd_yara(&args),
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

    use crate::candidate::{CandidateConfig, QueryNode};

    fn default_connection() -> ClientConnectionArgs {
        ClientConnectionArgs {
            addr: DEFAULT_RPC_ADDR.to_owned(),
            timeout: DEFAULT_RPC_TIMEOUT,
        }
    }

    fn default_internal_init_args(root: &Path, candidate_shards: usize, force: bool) -> InitArgs {
        InitArgs {
            root: root.display().to_string(),
            candidate_shards,
            force,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
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
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
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

    #[test]
    fn incremental_remote_batch_size_matches_full_payload_size() {
        let empty = empty_remote_batch_payload_size().expect("empty payload size");
        let rows = vec![
            crate::rpc::serialize_candidate_insert_binary_row_parts(
                &[0x11; 32],
                123,
                Some(3),
                &[1, 2, 3],
                Some(2),
                &[4, 5, 6],
                false,
                &[],
                Some("doc-1"),
            )
            .expect("row a"),
            crate::rpc::serialize_candidate_insert_binary_row_parts(
                &[0x22; 32],
                456,
                None,
                &[10, 11, 12],
                None,
                &[13, 14, 15],
                false,
                &[],
                None,
            )
            .expect("row b"),
        ];
        let mut running = empty;
        let mut pending_rows = Vec::new();
        for row in rows {
            running += 4 + row.len();
            pending_rows.push(row);
            let exact =
                crate::rpc::serialized_candidate_insert_binary_batch_payload(&pending_rows).len();
            assert_eq!(running, exact);
        }
    }

    fn default_serve_args() -> ServeArgs {
        ServeArgs {
            addr: DEFAULT_RPC_ADDR.to_owned(),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            search_workers: default_search_workers_for(4),
            memory_budget_gb: DEFAULT_MEMORY_BUDGET_GB,
            root: DEFAULT_CANDIDATE_ROOT.to_owned(),
            layout_profile: ServeLayoutProfile::Standard,
            shards: None,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            id_source: CandidateIdSource::Sha256,
            store_path: false,
            gram_sizes: "3,4".to_owned(),
        }
    }

    #[test]
    fn serve_candidate_shard_count_uses_profile_default() {
        let mut args = default_serve_args();
        args.layout_profile = ServeLayoutProfile::Incremental;
        assert_eq!(
            serve_candidate_shard_count(&args),
            DEFAULT_INCREMENTAL_SHARDS
        );
    }

    #[test]
    fn serve_candidate_shard_count_explicit_override_wins() {
        let mut args = default_serve_args();
        args.layout_profile = ServeLayoutProfile::Incremental;
        args.shards = Some(17);
        assert_eq!(serve_candidate_shard_count(&args), 17);
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
    fn json_config_and_binary_row_helpers_work() {
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
            0.002,
            3,
            4,
            33.5,
        );
        assert_eq!(fixed.root, PathBuf::from("root"));
        assert_eq!(fixed.id_source, "sha256");
        assert!(fixed.store_path);
        assert_eq!(fixed.tier2_gram_size, 3);
        assert_eq!(fixed.tier1_gram_size, 4);
        assert_eq!(fixed.tier1_filter_target_fp, Some(0.001));
        assert_eq!(fixed.tier2_filter_target_fp, Some(0.002));
        assert_eq!(fixed.filter_target_fp, None);
        assert_eq!(fixed.compaction_idle_cooldown_s, 33.5);

        let variable = store_config_from_parts(
            PathBuf::from("root"),
            CandidateIdSource::Sha256,
            false,
            0.01,
            0.01,
            5,
            4,
            9.25,
        );
        assert_eq!(variable.root, PathBuf::from("root"));
        assert_eq!(variable.id_source, "sha256");
        assert!(!variable.store_path);
        assert_eq!(variable.tier1_filter_target_fp, Some(0.01));
        assert_eq!(variable.tier2_filter_target_fp, Some(0.01));
        assert_eq!(variable.filter_target_fp, Some(0.01));
        assert_eq!(variable.tier2_gram_size, 5);
        assert_eq!(variable.tier1_gram_size, 4);
        assert_eq!(variable.compaction_idle_cooldown_s, 9.25);

        let row = IndexBatchRow {
            sha256: [0xAA; 32],
            file_size: 123,
            filter_bytes: 2048,
            bloom_item_estimate: Some(77),
            bloom_filter: vec![1, 2, 3, 4],
            tier2_filter_bytes: 0,
            tier2_bloom_item_estimate: None,
            tier2_bloom_filter: Vec::new(),
            special_population: false,
            metadata: vec![9, 8, 7],
            external_id: Some("x".to_owned()),
        };
        let wire = serialize_candidate_document_binary_row(&row).expect("binary row");
        let parsed =
            crate::rpc::parse_candidate_insert_binary_row_for_test(&wire).expect("parse row");
        assert_eq!(parsed.0, [0xAA; 32]);
        assert_eq!(parsed.1, 123);
        assert_eq!(parsed.2, Some(77));
        assert_eq!(parsed.3, vec![1, 2, 3, 4]);
        assert_eq!(parsed.7, vec![9, 8, 7]);
        assert_eq!(parsed.8.as_deref(), Some("x"));

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
    fn auto_ingest_workers_caps_rotational_and_small_workloads() {
        assert_eq!(
            auto_ingest_workers_for(
                16,
                500,
                IngestStorageClass::SolidState,
                IngestStorageClass::Unknown
            ),
            12
        );
        assert_eq!(
            auto_ingest_workers_for(
                16,
                500,
                IngestStorageClass::Rotational,
                IngestStorageClass::Unknown
            ),
            4
        );
        assert_eq!(
            auto_ingest_workers_for(
                16,
                3,
                IngestStorageClass::SolidState,
                IngestStorageClass::Unknown
            ),
            3
        );
        assert_eq!(
            auto_ingest_workers_for(
                16,
                2,
                IngestStorageClass::Rotational,
                IngestStorageClass::Unknown
            ),
            2
        );
    }

    #[test]
    fn resolve_ingest_workers_respects_explicit_override() {
        let resolved = resolve_ingest_workers(7, 500, &[], None);
        assert_eq!(resolved.workers, 7);
        assert!(!resolved.auto);
        assert_eq!(resolved.input_storage, IngestStorageClass::Unknown);
        assert_eq!(resolved.output_storage, IngestStorageClass::Unknown);
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
    fn scan_candidate_batch_helpers_work() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let sample = tmp.path().join("sample.bin");
        fs::write(&sample, b"well hello there").expect("sample");

        let row = scan_index_batch_row(
            &sample,
            ScanPolicy {
                fixed_filter_bytes: Some(2048),
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
                chunk_size: 4,
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

        let md5_row = scan_index_batch_row(
            &sample,
            ScanPolicy {
                fixed_filter_bytes: Some(2048),
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
                chunk_size: 4,
                store_path: false,
                id_source: CandidateIdSource::Md5,
            },
        )
        .expect("scan md5 row");
        assert_eq!(row.filter_bytes % 8, 0);
        assert_eq!(row.tier2_filter_bytes % 8, 0);
        assert_eq!(
            md5_row.sha256,
            identity_from_file(&sample, 4, CandidateIdSource::Md5).expect("md5 id")
        );
        assert!(md5_row.external_id.is_none());

        let aligned_row = scan_index_batch_row(
            &sample,
            ScanPolicy {
                fixed_filter_bytes: Some(2051),
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
                chunk_size: 4,
                store_path: false,
                id_source: CandidateIdSource::Sha256,
            },
        )
        .expect("scan aligned row");
        assert_eq!(aligned_row.filter_bytes, 2056);
        assert_eq!(aligned_row.tier2_filter_bytes, 2056);

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
            literal_wide: HashMap::from([
                ("$a".to_owned(), vec![false]),
                ("$b".to_owned(), vec![false]),
            ]),
            literal_fullword: HashMap::from([
                ("$a".to_owned(), vec![false]),
                ("$b".to_owned(), vec![false]),
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

        let fullword_path = tmp.path().join("fullword.bin");
        fs::write(&fullword_path, b".WORD! xWORDx").expect("fullword bytes");
        let fullword_plan = FixedLiteralMatchPlan {
            literals: HashMap::from([("$a".to_owned(), vec![b"WORD".to_vec()])]),
            literal_wide: HashMap::from([("$a".to_owned(), vec![false])]),
            literal_fullword: HashMap::from([("$a".to_owned(), vec![true])]),
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
        };
        assert!(
            verify_fixed_literal_plan_on_file(&fullword_path, &fullword_plan).expect("fullword")
        );
        fs::write(&fullword_path, b"xWORDx").expect("fullword miss bytes");
        assert!(
            !verify_fixed_literal_plan_on_file(&fullword_path, &fullword_plan)
                .expect("fullword miss")
        );
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
        assert_eq!(cmd_init(&candidate_init_args), 0);

        let ingest_one = InternalIndexArgs {
            connection: default_connection(),
            file_path: sample_a.display().to_string(),
            root: Some(candidate_root.display().to_string()),
            external_id: Some("manual-a".to_owned()),
            chunk_size: 1024,
        };
        assert_eq!(cmd_internal_index(&ingest_one), 0);

        let ingest_batch = InternalIndexBatchArgs {
            connection: default_connection(),
            paths: vec![sample_dir.display().to_string()],
            path_list: false,
            root: Some(candidate_root.display().to_string()),
            batch_size: 1,
            remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
            workers: 2,
            chunk_size: 1024,
            external_id_from_path: true,
            verbose: false,
            rotate_remote_sessions: false,
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
            max_candidates: 100.0,
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
    fn expand_input_paths_supports_path_lists() {
        let tmp = tempdir().expect("tmp");
        let base = tmp.path();
        let rel_dir = base.join("rel");
        fs::create_dir_all(&rel_dir).expect("rel dir");
        let rel_file = rel_dir.join("a.bin");
        let abs_file = base.join("b.bin");
        fs::write(&rel_file, b"a").expect("rel");
        fs::write(&abs_file, b"b").expect("abs");
        let list_path = base.join("dataset.txt");
        fs::write(&list_path, format!("rel/a.bin\n{}\n\n", abs_file.display())).expect("list");

        let expanded = expand_input_paths(&[list_path.display().to_string()], true).expect("list");
        assert_eq!(expanded, vec![abs_file, rel_file]);
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
            cmd_yara(&YaraArgs {
                rule: rule_path.display().to_string(),
                file_path: hit_path.display().to_string(),
                scan_timeout: 1,
                show_tags: true,
            }),
            0
        );
        assert_eq!(
            cmd_yara(&YaraArgs {
                rule: tmp.path().join("missing.yar").display().to_string(),
                file_path: hit_path.display().to_string(),
                scan_timeout: 1,
                show_tags: false,
            }),
            1
        );
        assert_eq!(
            main(Some(vec![
                "sspry".to_owned(),
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
            cmd_init(&default_internal_init_args(&candidate_root, 2, true)),
            0
        );
        assert_eq!(
            cmd_init(&default_internal_init_args(&candidate_root, 2, false)),
            0
        );
        assert_eq!(
            cmd_init(&default_internal_init_args(&candidate_root, 1, false)),
            1
        );

        assert_eq!(
            cmd_internal_index_batch(&InternalIndexBatchArgs {
                connection: default_connection(),
                paths: vec![
                    sample_dir.display().to_string(),
                    base.join("missing").display().to_string(),
                ],
                path_list: false,
                root: Some(candidate_root.display().to_string()),
                batch_size: 1,
                remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
                workers: 1,
                chunk_size: 1024,
                external_id_from_path: true,
                verbose: false,
                rotate_remote_sessions: false,
            }),
            0
        );
        assert_eq!(
            cmd_internal_index_batch(&InternalIndexBatchArgs {
                connection: default_connection(),
                paths: vec![base.join("missing_only").display().to_string()],
                path_list: false,
                root: Some(candidate_root.display().to_string()),
                batch_size: 1,
                remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
                workers: 1,
                chunk_size: 1024,
                external_id_from_path: false,
                verbose: false,
                rotate_remote_sessions: false,
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
                max_candidates: 2.0,
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
                max_candidates: 8.0,
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
        assert_eq!(policy.tier1_filter_target_fp, Some(0.40));
        assert_eq!(policy.tier2_filter_target_fp, Some(0.23));
        assert_eq!(policy.gram_sizes, GramSizes::new(3, 4).expect("gram sizes"));

        assert_eq!(
            cmd_internal_index(&InternalIndexArgs {
                connection: connection.clone(),
                file_path: sample_a.display().to_string(),
                root: None,
                external_id: Some(base.join("missing-match.bin").display().to_string()),
                chunk_size: 1024,
            }),
            0
        );
        assert_eq!(
            cmd_index(&IndexArgs {
                connection: connection.clone(),
                root: None,
                paths: vec![
                    sample_b.display().to_string(),
                    sample_c.display().to_string()
                ],
                path_list: false,
                batch_size: 1,
                remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
                workers: Some(2),
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
                max_candidates: 4.0,
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
                max_candidates: 4.0,
            }),
            0
        );
        assert_eq!(
            cmd_search(&SearchCommandArgs {
                connection: connection.clone(),
                root: None,
                rule: rule_path.display().to_string(),
                tree_search_workers: 0,
                max_anchors_per_pattern: 2,
                max_candidates: 8.0,
                gate_only: false,
                verify_yara_files: false,
                verbose: false,
            }),
            0
        );
        assert_eq!(
            cmd_search(&SearchCommandArgs {
                connection: connection.clone(),
                root: None,
                rule: rule_path.display().to_string(),
                tree_search_workers: 0,
                max_anchors_per_pattern: 2,
                max_candidates: 8.0,
                gate_only: false,
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
                light: false,
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
                "sspry".to_owned(),
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
                "sspry".to_owned(),
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
                max_candidates: 1.0,
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
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: true,
        });

        assert_eq!(
            cmd_index(&IndexArgs {
                connection: connection.clone(),
                root: None,
                paths: vec![sample.display().to_string()],
                path_list: false,
                batch_size: 1,
                remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
                workers: Some(1),
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
            .expect("resolved identity"),
            hex::encode(
                identity_from_hex(&sha256_hex, CandidateIdSource::Sha256)
                    .expect("normalized sha256")
            )
        );
    }

    #[test]
    fn batch_search_helper_functions_cover_local_forest_paths() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let base = tmp.path();

        assert!(default_ingest_workers() >= 1);
        assert_eq!(
            remote_index_session_document_limit(0, 64),
            REMOTE_INDEX_SESSION_MAX_DOCUMENTS
        );
        assert_eq!(
            remote_index_session_document_limit(640 * 1024 * 4 * 8, 64),
            64
        );
        assert_eq!(
            remote_index_session_document_limit(640 * 1024 * 4 * 4096, 1),
            REMOTE_INDEX_SESSION_MAX_DOCUMENTS
        );
        assert_eq!(
            remote_index_session_input_bytes_limit(0),
            REMOTE_INDEX_SESSION_MAX_INPUT_BYTES
        );
        assert_eq!(
            remote_index_session_input_bytes_limit(4 << 30),
            REMOTE_INDEX_SESSION_MIN_INPUT_BYTES
        );
        assert_eq!(
            remote_index_session_input_bytes_limit(40 << 30),
            REMOTE_INDEX_SESSION_MAX_INPUT_BYTES
        );
        assert!(is_retryable_remote_index_rotation_error(&SspryError::from(
            "server is publishing; retry later"
        )));
        assert!(is_retryable_remote_index_rotation_error(&SspryError::from(
            "another index session is already active; retry later"
        )));
        assert!(is_retryable_remote_index_rotation_error(&SspryError::from(
            "no active index session; cannot update progress"
        )));
        assert!(!is_retryable_remote_index_rotation_error(
            &SspryError::from("fatal publish failure")
        ));
        assert_eq!(
            append_path_suffix(Path::new("/tmp/out.json"), ".jsonl"),
            PathBuf::from("/tmp/out.json.jsonl")
        );
        assert!(is_wide_word_unit(b"A\0"));
        assert!(!is_wide_word_unit(b"A"));
        assert!(!is_wide_word_unit(&[0xff, 0x00]));

        let direct_root = base.join("direct");
        fs::create_dir_all(direct_root.join("current")).expect("direct current");
        assert_eq!(
            forest_tree_roots(&direct_root).expect("direct tree roots"),
            vec![direct_root.join("current")]
        );

        let empty_root = base.join("empty");
        fs::create_dir_all(&empty_root).expect("empty root");
        assert_eq!(
            forest_tree_roots(&empty_root).expect("fallback tree roots"),
            vec![empty_root.clone()]
        );

        let connection = start_tcp_test_server(base, 1);
        let base_client = rpc_client(&connection);
        let mut client = base_client.connect_persistent().expect("persistent client");
        client.begin_index_session().expect("begin session");
        let empty_payload_size = empty_remote_batch_payload_size().expect("empty payload");
        let mut pending = RemotePendingBatch {
            rows: Vec::new(),
            payload_size: empty_payload_size,
        };
        let mut processed = 3usize;
        let mut submit_time = Duration::ZERO;
        let mut progress_rpc_time = Duration::ZERO;
        let mut last_progress_reported = 0usize;
        let mut last_progress_at = Instant::now();
        rotate_remote_index_session(
            &base_client,
            &mut client,
            &mut pending,
            &mut processed,
            &mut submit_time,
            false,
            10,
            &mut last_progress_reported,
            &mut last_progress_at,
            empty_payload_size,
            &mut progress_rpc_time,
            false,
        )
        .expect("rotate remote index session");
        assert!(progress_rpc_time > Duration::ZERO);
        client.end_index_session().expect("end session");
    }

    #[test]
    fn batch_search_record_stream_roundtrips_json_outputs() {
        let tmp = tempdir().expect("tmp");
        let json_out = tmp.path().join("batch").join("search_summary.json");
        let partial_json_out = append_path_suffix(&json_out, ".partial.json");
        let jsonl_out = append_path_suffix(&json_out, ".jsonl");
        let mut stream = BatchSearchRecordStream::new(&json_out).expect("stream");
        assert_eq!(stream.jsonl_out(), jsonl_out.as_path());

        let record_a = BatchSearchRecord {
            rule: "rule_a".to_owned(),
            rule_path: "/tmp/rule_a.yar".to_owned(),
            exit_code: 0,
            elapsed_ms_wall: 12.5,
            error: None,
            candidates: Some(2),
            truncated: Some(false),
            truncated_limit: None,
            tier_used: Some("tier1+tier2".to_owned()),
            verified_checked: Some(0),
            verified_matched: Some(0),
            verified_skipped: Some(0),
            verbose_search_total_ms: Some(12.5),
            verbose_search_plan_ms: Some(1.0),
            verbose_search_query_ms: Some(11.0),
            verbose_search_verify_ms: Some(0.5),
            verbose_search_tree_gate_trees_considered: Some(2),
            verbose_search_tree_gate_passed: Some(2),
            verbose_search_tree_gate_tier1_pruned: Some(0),
            verbose_search_tree_gate_tier2_pruned: Some(0),
            verbose_search_tree_gate_special_docs_bypass: Some(0),
            verbose_search_docs_scanned: Some(2),
            verbose_search_metadata_loads: Some(0),
            verbose_search_metadata_bytes: Some(0),
            verbose_search_tier1_bloom_loads: Some(2),
            verbose_search_tier1_bloom_bytes: Some(128),
            verbose_search_tier2_bloom_loads: Some(1),
            verbose_search_tier2_bloom_bytes: Some(64),
            verbose_search_prepared_query_bytes: Some(32),
            verbose_search_prepared_pattern_plan_bytes: Some(16),
            verbose_search_prepared_mask_cache_bytes: Some(8),
            verbose_search_prepared_pattern_count: Some(1),
            verbose_search_prepared_mask_cache_entries: Some(1),
            verbose_search_prepared_fixed_literal_count: Some(1),
            verbose_search_prepared_tier1_alternatives: Some(1),
            verbose_search_prepared_tier2_alternatives: Some(1),
            verbose_search_prepared_tier1_shift_variants: Some(1),
            verbose_search_prepared_tier2_shift_variants: Some(1),
            verbose_search_prepared_tier1_any_lane_alternatives: Some(0),
            verbose_search_prepared_tier2_any_lane_alternatives: Some(0),
            verbose_search_prepared_tier1_compacted_any_lane_alternatives: Some(0),
            verbose_search_prepared_tier2_compacted_any_lane_alternatives: Some(0),
            verbose_search_prepared_any_lane_variant_sets: Some(0),
            verbose_search_prepared_compacted_any_lane_grams: Some(0),
            verbose_search_prepared_max_pattern_bytes: Some(4),
            verbose_search_prepared_max_pattern_id: Some("$a".to_owned()),
            verbose_search_prepared_impossible_query: Some(false),
            verbose_search_max_candidates: Some(100.0),
            verbose_search_max_anchors_per_pattern: Some(8),
            verbose_search_candidates: Some(2),
            verbose_search_verify_enabled: Some(false),
            verbose_search_client_current_rss_kb: Some(1024),
            verbose_search_client_peak_rss_kb: Some(2048),
            verbose_search_client_smaps_rss_kb: Some(1024),
            verbose_search_client_anonymous_kb: Some(512),
            verbose_search_client_private_clean_kb: Some(64),
            verbose_search_client_private_dirty_kb: Some(128),
            verbose_search_client_shared_clean_kb: Some(256),
            verbose_search_server_current_rss_kb: Some(4096),
            verbose_search_server_peak_rss_kb: Some(8192),
            verbose_search_tree_count: Some(2),
            verbose_search_tree_search_workers: Some(2),
        };
        let record_b = BatchSearchRecord {
            rule: "rule_b".to_owned(),
            rule_path: "/tmp/rule_b.yar".to_owned(),
            exit_code: 1,
            elapsed_ms_wall: 3.5,
            error: Some("boom".to_owned()),
            candidates: None,
            truncated: None,
            truncated_limit: None,
            tier_used: None,
            verified_checked: None,
            verified_matched: None,
            verified_skipped: None,
            verbose_search_total_ms: None,
            verbose_search_plan_ms: None,
            verbose_search_query_ms: None,
            verbose_search_verify_ms: None,
            verbose_search_tree_gate_trees_considered: None,
            verbose_search_tree_gate_passed: None,
            verbose_search_tree_gate_tier1_pruned: None,
            verbose_search_tree_gate_tier2_pruned: None,
            verbose_search_tree_gate_special_docs_bypass: None,
            verbose_search_docs_scanned: None,
            verbose_search_metadata_loads: None,
            verbose_search_metadata_bytes: None,
            verbose_search_tier1_bloom_loads: None,
            verbose_search_tier1_bloom_bytes: None,
            verbose_search_tier2_bloom_loads: None,
            verbose_search_tier2_bloom_bytes: None,
            verbose_search_prepared_query_bytes: None,
            verbose_search_prepared_pattern_plan_bytes: None,
            verbose_search_prepared_mask_cache_bytes: None,
            verbose_search_prepared_pattern_count: None,
            verbose_search_prepared_mask_cache_entries: None,
            verbose_search_prepared_fixed_literal_count: None,
            verbose_search_prepared_tier1_alternatives: None,
            verbose_search_prepared_tier2_alternatives: None,
            verbose_search_prepared_tier1_shift_variants: None,
            verbose_search_prepared_tier2_shift_variants: None,
            verbose_search_prepared_tier1_any_lane_alternatives: None,
            verbose_search_prepared_tier2_any_lane_alternatives: None,
            verbose_search_prepared_tier1_compacted_any_lane_alternatives: None,
            verbose_search_prepared_tier2_compacted_any_lane_alternatives: None,
            verbose_search_prepared_any_lane_variant_sets: None,
            verbose_search_prepared_compacted_any_lane_grams: None,
            verbose_search_prepared_max_pattern_bytes: None,
            verbose_search_prepared_max_pattern_id: None,
            verbose_search_prepared_impossible_query: None,
            verbose_search_max_candidates: None,
            verbose_search_max_anchors_per_pattern: None,
            verbose_search_candidates: None,
            verbose_search_verify_enabled: None,
            verbose_search_client_current_rss_kb: None,
            verbose_search_client_peak_rss_kb: None,
            verbose_search_client_smaps_rss_kb: None,
            verbose_search_client_anonymous_kb: None,
            verbose_search_client_private_clean_kb: None,
            verbose_search_client_private_dirty_kb: None,
            verbose_search_client_shared_clean_kb: None,
            verbose_search_server_current_rss_kb: None,
            verbose_search_server_peak_rss_kb: None,
            verbose_search_tree_count: None,
            verbose_search_tree_search_workers: None,
        };

        stream.push(&record_a).expect("push record a");
        stream.push(&record_b).expect("push record b");
        assert_eq!(stream.finish().expect("finish"), 2);

        let json_rows: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(&json_out).expect("json output")).expect("json rows");
        assert_eq!(json_rows.len(), 2);

        let jsonl_lines = fs::read_to_string(&jsonl_out)
            .expect("jsonl output")
            .lines()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(jsonl_lines.len(), 2);
        assert!(!partial_json_out.exists());
    }

    #[test]
    fn local_forest_search_wrappers_and_cmd_search_batch_work() {
        let _guard = crate::perf::test_lock().lock().expect("perf lock");
        crate::perf::configure(None, false);
        let tmp = tempdir().expect("tmp");
        let base = tmp.path();
        let forest_root = base.join("forest");
        let rules_dir = base.join("rules");
        fs::create_dir_all(&forest_root).expect("forest root");
        fs::create_dir_all(&rules_dir).expect("rules dir");

        for (tree_idx, files) in [
            (
                0usize,
                vec![
                    ("match_a.bin", b"tree zero ABCD hit one".as_slice()),
                    ("miss_a.bin", b"tree zero miss".as_slice()),
                ],
            ),
            (
                1usize,
                vec![
                    ("match_b.bin", b"tree one prefix ABCD hit two".as_slice()),
                    ("miss_b.bin", b"tree one miss".as_slice()),
                ],
            ),
        ] {
            let tree_root = forest_root
                .join(format!("tree_{tree_idx:02}"))
                .join("current");
            let sample_dir = base.join(format!("tree_{tree_idx:02}_samples"));
            fs::create_dir_all(&sample_dir).expect("sample dir");
            for (name, bytes) in files {
                fs::write(sample_dir.join(name), bytes).expect("sample file");
            }
            assert_eq!(
                cmd_init(&default_internal_init_args(&tree_root, 1, true)),
                0
            );
            assert_eq!(
                cmd_internal_index_batch(&InternalIndexBatchArgs {
                    connection: default_connection(),
                    paths: vec![sample_dir.display().to_string()],
                    path_list: false,
                    root: Some(tree_root.display().to_string()),
                    batch_size: 1,
                    remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
                    workers: 1,
                    chunk_size: 1024,
                    external_id_from_path: true,
                    verbose: false,
                    rotate_remote_sessions: false,
                }),
                0
            );
        }

        let match_rule = rules_dir.join("0001_match.yar");
        let miss_rule = rules_dir.join("0002_miss.yar");
        fs::write(
            &match_rule,
            r#"
rule match_rule {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
        )
        .expect("match rule");
        fs::write(
            &miss_rule,
            r#"
rule miss_rule {
  strings:
    $a = "WXYZ"
  condition:
    $a
}
"#,
        )
        .expect("miss rule");

        let manifest = base.join("rules.txt");
        fs::write(
            &manifest,
            format!("{}\n{}\n", miss_rule.display(), match_rule.display()),
        )
        .expect("manifest");
        assert_eq!(
            collect_rules_from_args(&Some(rules_dir.display().to_string()), &None)
                .expect("rules dir"),
            vec![match_rule.clone(), miss_rule.clone()]
        );
        assert_eq!(
            collect_rules_from_args(&None, &Some(manifest.display().to_string()))
                .expect("manifest rules"),
            vec![match_rule.clone(), miss_rule.clone()]
        );
        assert!(collect_rules_from_args(&None, &None).is_err());

        assert_eq!(
            forest_tree_roots(&forest_root).expect("forest tree roots"),
            vec![
                forest_root.join("tree_00").join("current"),
                forest_root.join("tree_01").join("current")
            ]
        );

        let mut tree_groups = open_forest_tree_groups(&forest_root).expect("open forest");
        assert_eq!(tree_groups.len(), 2);
        let (gram_sizes, active_identity_source, summary_cap_bytes) =
            validate_forest_search_policy(&tree_groups).expect("search policy");
        assert_eq!(gram_sizes, GramSizes::new(3, 4).expect("gram sizes"));
        assert_eq!(active_identity_source.as_deref(), Some("sha256"));
        assert_eq!(summary_cap_bytes, 0);

        let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
            &match_rule,
            gram_sizes,
            active_identity_source.as_deref(),
            8,
            false,
            true,
            100,
        )
        .expect("compile plan");
        let prepared =
            forest_prepared_query_profile(&tree_groups, &plan, summary_cap_bytes).expect("profile");
        assert!(prepared.pattern_count >= 1);

        let tree_gate_profile =
            query_store_group_tree_gates(&mut tree_groups[0].stores, &plan).expect("tree gates");
        assert_eq!(tree_gate_profile.tree_gate_trees_considered, 1);

        let local_tree = query_store_group_all_candidates(&mut tree_groups[0].stores, &plan, true)
            .expect("local tree query");
        assert_eq!(local_tree.hashes.len(), 1);
        assert_eq!(local_tree.external_ids.len(), 1);

        let forest_tree_gate_profile =
            query_local_forest_tree_gates(&mut tree_groups, &plan, 2).expect("forest gates");
        assert_eq!(forest_tree_gate_profile.tree_gate_trees_considered, 2);
        assert_eq!(forest_tree_gate_profile.tree_gate_passed, 2);

        let local_forest = query_local_forest_all_candidates(&mut tree_groups, &plan, true, 2)
            .expect("forest query");
        assert_eq!(local_forest.total_candidates, 2);
        assert_eq!(local_forest.hashes.len(), 2);
        assert_eq!(
            local_forest
                .external_ids
                .as_ref()
                .expect("external ids")
                .len(),
            2
        );
        assert!(local_forest.query_profile.docs_scanned >= 2);
        assert!(!local_forest.tier_used.is_empty());

        clear_local_forest_search_caches(&mut tree_groups);
        let after_clear = query_local_forest_all_candidates(&mut tree_groups, &plan, false, 2)
            .expect("forest query after clear");
        assert_eq!(after_clear.total_candidates, 2);
        assert!(after_clear.external_ids.is_none());

        let json_out = base.join("batch_results.json");
        assert_eq!(
            cmd_search_batch(&SearchBatchArgs {
                root: forest_root.display().to_string(),
                rules_dir: Some(rules_dir.display().to_string()),
                rule_manifest: None,
                json_out: json_out.display().to_string(),
                tree_search_workers: 2,
                max_anchors_per_pattern: 8,
                max_candidates: 100.0,
                verify_yara_files: false,
            }),
            0
        );

        let batch_rows: Vec<serde_json::Value> =
            serde_json::from_slice(&fs::read(&json_out).expect("batch json")).expect("batch rows");
        assert_eq!(batch_rows.len(), 2);
        let candidates_by_rule = batch_rows
            .iter()
            .map(|row| {
                (
                    row.get("rule")
                        .and_then(serde_json::Value::as_str)
                        .expect("rule name")
                        .to_owned(),
                    row.get("candidates")
                        .and_then(serde_json::Value::as_u64)
                        .unwrap_or(0),
                )
            })
            .collect::<HashMap<_, _>>();
        assert_eq!(candidates_by_rule.get("0001_match.yar"), Some(&2));
        assert_eq!(candidates_by_rule.get("0002_miss.yar"), Some(&0));
        assert!(append_path_suffix(&json_out, ".jsonl").exists());
    }
}
