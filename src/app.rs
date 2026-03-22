use std::collections::HashMap;
#[cfg(test)]
use std::collections::HashSet;
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

use crate::candidate::filter_policy::align_filter_bytes;
use crate::candidate::query_plan::{
    FixedLiteralMatchPlan, evaluate_fixed_literal_match, fixed_literal_match_plan,
};
#[cfg(test)]
use crate::candidate::write_candidate_shard_count;
use crate::candidate::{
    BoundedCache, CandidateConfig, CandidateStore, DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES,
    GramSizes, HLL_DEFAULT_PRECISION, candidate_shard_index, candidate_shard_root,
    choose_filter_bytes_for_file_size, compile_query_plan_from_file_with_gram_sizes,
    compile_query_plan_from_file_with_gram_sizes_and_identity_source,
    derive_document_bloom_hash_count, estimate_unique_grams_for_size_hll,
    estimate_unique_grams_pair_hll, extract_compact_document_metadata,
    normalize_tier1_filter_class_bytes, read_candidate_shard_count,
    scan_file_features_bloom_only_with_gram_sizes,
};
use crate::perf;
use crate::rpc::{
    self, CandidateDocumentWire, ClientConfig as RpcClientConfig, PersistentSspryClient,
    ServerConfig as RpcServerConfig, SspryClient,
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
pub const DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR: u64 = 4;
pub const DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_KIB: usize =
    DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES / 1024;
pub const DEFAULT_STANDARD_SHARDS: usize = 256;
pub const DEFAULT_INCREMENTAL_SHARDS: usize = 32;
const ESTIMATED_INDEX_QUEUE_ITEM_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INDEX_QUEUE_CAPACITY: usize = 256;
const STORAGE_CLASS_SAMPLE_LIMIT: usize = 16;

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
            .get("tier2_gram_size")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| SspryError::from("candidate stats missing tier2_gram_size"))?
            as usize,
        stats
            .get("tier1_gram_size")
            .and_then(|value| value.as_u64())
            .ok_or_else(|| SspryError::from("candidate stats missing tier1_gram_size"))?
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

fn batch_row_to_wire(row: IndexBatchRow) -> CandidateDocumentWire {
    CandidateDocumentWire {
        sha256: hex::encode(row.sha256),
        file_size: row.file_size,
        bloom_filter_b64: {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(row.bloom_filter)
        },
        bloom_item_estimate: row.bloom_item_estimate.map(|value| value as i64),
        tier2_bloom_filter_b64: Some({
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(row.tier2_bloom_filter)
        }),
        tier2_bloom_item_estimate: row.tier2_bloom_item_estimate.map(|value| value as i64),
        special_population: row.special_population,
        metadata_b64: Some({
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(row.metadata)
        }),
        external_id: row.external_id,
    }
}

const REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES: usize = DEFAULT_MAX_REQUEST_BYTES - 1024;
const REMOTE_INDEX_SESSION_MAX_DOCUMENTS: usize = 2048;
const REMOTE_INDEX_SESSION_MIN_INPUT_BYTES: u64 = 1 << 30;
const REMOTE_INDEX_SESSION_MAX_INPUT_BYTES: u64 = 4 << 30;

struct RemotePendingBatch {
    rows: Vec<Vec<u8>>,
    payload_size: usize,
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

fn empty_remote_batch_payload_size() -> Result<usize> {
    SspryClient::candidate_insert_batch_payload_size(&[])
}

fn serialize_candidate_document_wire(document: &CandidateDocumentWire) -> Result<Vec<u8>> {
    serde_json::to_vec(document).map_err(SspryError::from)
}

fn flush_remote_batch(
    client: &mut PersistentSspryClient,
    pending: &mut RemotePendingBatch,
    processed: &mut usize,
    empty_payload_size: usize,
) -> Result<()> {
    if pending.rows.is_empty() {
        return Ok(());
    }
    *processed += client
        .candidate_insert_batch_serialized_rows(&pending.rows)?
        .inserted_count;
    pending.rows.clear();
    pending.payload_size = empty_payload_size;
    Ok(())
}

fn prepare_remote_batch_row(
    pending: &RemotePendingBatch,
    row: CandidateDocumentWire,
    empty_payload_size: usize,
) -> Result<(Vec<u8>, bool)> {
    let row_bytes = serialize_candidate_document_wire(&row)?;
    let row_payload_size = row_bytes.len();
    let single_payload_size = empty_payload_size.saturating_add(row_payload_size);
    if single_payload_size > REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES {
        return Err(SspryError::from(format!(
            "single document insert request exceeds payload limit ({} bytes)",
            single_payload_size
        )));
    }
    let flush_before = !pending.rows.is_empty()
        && pending
            .payload_size
            .saturating_add(1)
            .saturating_add(row_payload_size)
            > REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES;
    Ok((row_bytes, flush_before))
}

fn push_serialized_remote_batch_row(
    pending: &mut RemotePendingBatch,
    row_bytes: Vec<u8>,
    batch_size: usize,
) -> Result<bool> {
    let row_payload_size = row_bytes.len();
    let separator_bytes = usize::from(!pending.rows.is_empty());
    let payload_size = pending
        .payload_size
        .saturating_add(separator_bytes)
        .saturating_add(row_payload_size);
    if payload_size > REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES {
        return Err(SspryError::from(
            "remote batch row exceeded payload limit before flush",
        ));
    }
    pending.rows.push(row_bytes);
    pending.payload_size = payload_size;
    Ok(pending.rows.len() >= batch_size)
}

fn push_remote_batch_row(
    client: &mut PersistentSspryClient,
    pending: &mut RemotePendingBatch,
    row: CandidateDocumentWire,
    batch_size: usize,
    processed: &mut usize,
    submit_time: &mut Duration,
    show_progress: bool,
    total_files: usize,
    last_progress_reported: &mut usize,
    last_progress_at: &mut Instant,
    empty_payload_size: usize,
) -> Result<Duration> {
    let started_buffer = Instant::now();
    let (row_bytes, flush_before) = prepare_remote_batch_row(pending, row, empty_payload_size)?;
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
        )?;
    }
    let started_buffer = Instant::now();
    let flush_after = push_serialized_remote_batch_row(pending, row_bytes, batch_size)?;
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
        )?;
    }
    Ok(buffer_time)
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
) -> Result<()> {
    let started_submit = Instant::now();
    flush_remote_batch(client, pending, processed, empty_payload_size)?;
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
    )?;
    let started_progress_rpc = Instant::now();
    client.end_index_session()?;
    *progress_rpc_time += started_progress_rpc.elapsed();
    base_client.publish()?;
    *client = base_client.connect_persistent()?;
    let started_progress_rpc = Instant::now();
    client.begin_index_session()?;
    client.update_index_session_progress(Some(total_files), *processed, *processed)?;
    *progress_rpc_time += started_progress_rpc.elapsed();
    Ok(())
}

fn store_config_from_parts(
    root: PathBuf,
    id_source: CandidateIdSource,
    store_path: bool,
    tier1_filter_target_fp: f64,
    tier2_filter_target_fp: f64,
    tier2_gram_size: usize,
    tier1_gram_size: usize,
    tier2_superblock_summary_cap_kib: usize,
    compaction_idle_cooldown_s: f64,
) -> CandidateConfig {
    CandidateConfig {
        root,
        id_source: id_source.as_str().to_owned(),
        store_path,
        tier2_gram_size,
        tier1_gram_size,
        tier2_superblock_summary_cap_bytes: tier2_superblock_summary_cap_kib
            .max(1)
            .saturating_mul(1024),
        tier1_filter_target_fp: Some(tier1_filter_target_fp),
        tier2_filter_target_fp: Some(tier2_filter_target_fp),
        filter_target_fp: if (tier1_filter_target_fp - tier2_filter_target_fp).abs() < f64::EPSILON
        {
            Some(tier1_filter_target_fp)
        } else {
            None
        },
        compaction_idle_cooldown_s: compaction_idle_cooldown_s.max(0.0),
        ..CandidateConfig::default()
    }
}

fn resolve_filter_target_fps(
    filter_target_fp: Option<f64>,
    tier1_filter_target_fp: Option<f64>,
    tier2_filter_target_fp: Option<f64>,
) -> (f64, f64) {
    let shared = filter_target_fp.unwrap_or(0.35);
    (
        tier1_filter_target_fp.unwrap_or(shared),
        tier2_filter_target_fp.unwrap_or(shared),
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
        args.tier2_superblock_summary_cap_kib,
        CandidateConfig::default().compaction_idle_cooldown_s,
    )
}

#[cfg(test)]
fn store_config_from_init_args(args: &InternalInitArgs) -> CandidateConfig {
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
        args.tier2_superblock_summary_cap_kib,
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
        let selected = choose_filter_bytes_for_file_size(
            file_size,
            INTERNAL_FILTER_BYTES,
            Some(INTERNAL_FILTER_MIN_BYTES),
            Some(INTERNAL_FILTER_MAX_BYTES),
            policy.tier1_filter_target_fp,
            bloom_item_estimate,
        )?;
        if policy.tier1_filter_target_fp.is_some() {
            normalize_tier1_filter_class_bytes(selected)
        } else {
            selected
        }
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
    Ok(IndexBatchRow {
        sha256: if policy.id_source == CandidateIdSource::Sha256 {
            features.sha256
        } else {
            identity_from_file(scan_path, policy.chunk_size, policy.id_source)?
        },
        file_size: features.file_size,
        filter_bytes,
        bloom_item_estimate,
        bloom_filter: features.bloom_filter,
        tier2_filter_bytes,
        tier2_bloom_item_estimate,
        tier2_bloom_filter: features.tier2_bloom_filter,
        special_population: features.special_population,
        metadata: extract_compact_document_metadata(scan_path)?,
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
            crate::candidate::DEFAULT_TIER2_GRAM_SIZE,
            crate::candidate::DEFAULT_TIER1_GRAM_SIZE,
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
                tier2_superblock_budget_divisor: args.tier2_superblock_budget_divisor.max(1),
                auto_publish_initial_idle_ms,
                auto_publish_storage_class,
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
                return Err(SspryError::from(format!(
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
            let gram_sizes = GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)?;
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
            rpc_client(&args.connection).candidate_insert_document(&batch_row_to_wire(row))?
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
        let workers = if args.root.is_none() && args.workers == 0 {
            1
        } else {
            resolved_workers.workers
        };
        if let Some(root) = &args.root {
            let mut stores = open_stores(Path::new(root))?;
            let config = stores
                .first()
                .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?
                .config();
            let id_source = CandidateIdSource::parse_config_value(&config.id_source)?;
            let gram_sizes = GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)?;
            let policy = ScanPolicy {
                fixed_filter_bytes: None,
                tier1_filter_target_fp: config.resolved_tier1_filter_target_fp(),
                tier2_filter_target_fp: config.resolved_tier2_filter_target_fp(),
                gram_sizes,
                chunk_size: args.chunk_size,
                store_path: args.external_id_from_path,
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
                    while let Ok(scanned) = result_rx.recv() {
                        let started_wait = Instant::now();
                        result_wait_time += started_wait.elapsed();
                        let scanned = scanned?;
                        received = received.saturating_add(1);
                        scan_time += scanned.scan_elapsed;
                        pending.push(scanned.row);
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
            let mut client = base_client.connect_persistent()?;
            client.begin_index_session()?;
            let started_progress_rpc = Instant::now();
            client.update_index_session_progress(Some(total_files), 0, 0)?;
            progress_rpc_time += started_progress_rpc.elapsed();
            let configured_budget_bytes = server_policy.memory_budget_bytes;
            let effective_budget_bytes = effective_memory_budget_bytes(configured_budget_bytes);
            let queue_capacity = index_queue_capacity(effective_budget_bytes, workers);
            let remote_session_document_limit =
                remote_index_session_document_limit(effective_budget_bytes, batch_size);
            let remote_session_input_bytes_limit =
                remote_index_session_input_bytes_limit(effective_budget_bytes);
            let empty_payload_size = empty_remote_batch_payload_size()?;
            let mut pending = RemotePendingBatch {
                rows: Vec::new(),
                payload_size: empty_payload_size,
            };
            let mut session_submitted_documents = 0usize;
            let mut session_submitted_input_bytes = 0u64;
            let mut session_publish_rotations = 0usize;
            let remote_result = (|| -> Result<()> {
                if workers <= 1 {
                    stream_selected_input_files(&input_roots, args.path_list, |file_path| {
                        let started_scan = Instant::now();
                        let scanned = scan_index_batch_row(&file_path, policy)?;
                        scan_time += started_scan.elapsed();
                        session_submitted_documents = session_submitted_documents.saturating_add(1);
                        session_submitted_input_bytes =
                            session_submitted_input_bytes.saturating_add(scanned.file_size);
                        let started_encode = Instant::now();
                        let row = batch_row_to_wire(scanned);
                        encode_time += started_encode.elapsed();
                        client_buffer_time += push_remote_batch_row(
                            &mut client,
                            &mut pending,
                            row,
                            batch_size,
                            &mut processed,
                            &mut submit_time,
                            show_progress,
                            total_files,
                            &mut last_progress_reported,
                            &mut last_progress_at,
                            empty_payload_size,
                        )?;
                        if session_submitted_documents >= remote_session_document_limit
                            || session_submitted_input_bytes >= remote_session_input_bytes_limit
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
                            )?;
                            session_submitted_documents = 0;
                            session_submitted_input_bytes = 0;
                            session_publish_rotations = session_publish_rotations.saturating_add(1);
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

                        let mut received = 0usize;
                        while let Ok(scanned) = result_rx.recv() {
                            let started_wait = Instant::now();
                            result_wait_time += started_wait.elapsed();
                            let scanned = scanned?;
                            received = received.saturating_add(1);
                            scan_time += scanned.scan_elapsed;
                            session_submitted_documents =
                                session_submitted_documents.saturating_add(1);
                            session_submitted_input_bytes =
                                session_submitted_input_bytes.saturating_add(scanned.row.file_size);
                            let started_encode = Instant::now();
                            let row = batch_row_to_wire(scanned.row);
                            encode_time += started_encode.elapsed();
                            client_buffer_time += push_remote_batch_row(
                                &mut client,
                                &mut pending,
                                row,
                                batch_size,
                                &mut processed,
                                &mut submit_time,
                                show_progress,
                                total_files,
                                &mut last_progress_reported,
                                &mut last_progress_at,
                                empty_payload_size,
                            )?;
                            if session_submitted_documents >= remote_session_document_limit
                                || session_submitted_input_bytes >= remote_session_input_bytes_limit
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
                                )?;
                                session_submitted_documents = 0;
                                session_submitted_input_bytes = 0;
                                session_publish_rotations =
                                    session_publish_rotations.saturating_add(1);
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
                )?;
                Ok(())
            })();
            let end_session_result = client.end_index_session();
            remote_result?;
            end_session_result?;
            if args.verbose {
                server_rss_kb = server_memory_kb(&args.connection)?;
                eprintln!("verbose.index.memory_budget_bytes: {configured_budget_bytes}");
                eprintln!("verbose.index.effective_memory_budget_bytes: {effective_budget_bytes}");
                eprintln!("verbose.index.queue_capacity: {queue_capacity}");
                eprintln!(
                    "verbose.index.remote_session_document_limit: {}",
                    remote_session_document_limit
                );
                eprintln!(
                    "verbose.index.remote_session_input_bytes_limit: {}",
                    remote_session_input_bytes_limit
                );
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
                        GramSizes::new(config.tier2_gram_size, config.tier1_gram_size)?,
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
            let mut summary_cap_bytes = None::<usize>;
            for store in &stores {
                tier1_filter_keys.extend(store.tier1_superblock_filter_keys());
                tier2_filter_keys.extend(store.tier2_doc_filter_keys());
                let shard_summary_cap = store.config().tier2_superblock_summary_cap_bytes;
                if let Some(existing) = summary_cap_bytes {
                    if existing != shard_summary_cap {
                        return Err(SspryError::from(
                            "candidate stores use mixed tier2 superblock summary caps",
                        ));
                    }
                } else {
                    summary_cap_bytes = Some(shard_summary_cap);
                }
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
                    summary_cap_bytes
                        .unwrap_or(crate::candidate::DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES),
                )?
                .as_ref(),
            );
            if stores.len() == 1 {
                let result = stores[0].query_candidates(&plan, args.cursor, args.chunk_size)?;
                rpc::CandidateQueryResponse {
                    sha256: result.sha256,
                    total_candidates: result.total_candidates,
                    returned_count: result.returned_count,
                    cursor: result.cursor,
                    next_cursor: result.next_cursor,
                    tier_used: result.tier_used,
                    query_profile: result.query_profile,
                    prepared_query_profile,
                    external_ids: None,
                }
            } else {
                let mut hashes = std::collections::BTreeSet::<String>::new();
                let mut tier_used = Vec::<String>::new();
                let mut query_profile = crate::candidate::CandidateQueryProfile::default();
                let collect_chunk = plan.max_candidates.max(1).min(4096);
                for store in &mut stores {
                    let mut cursor = 0usize;
                    loop {
                        let local = store.query_candidates(&plan, cursor, collect_chunk)?;
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
        workers: args.workers.unwrap_or(0),
        chunk_size: DEFAULT_FILE_READ_CHUNK_SIZE,
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
        let client = search_rpc_client(&args.connection);
        let verify_yara_files = args.verify_yara_files;
        let server_policy = server_scan_policy(&args.connection)?;

        let started_plan = Instant::now();
        // The default search path now plans directly from the restricted rule shape.
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
        let mut query_profile = None::<crate::candidate::CandidateQueryProfile>;
        let mut prepared_query_profile = None::<crate::candidate::CandidatePreparedQueryProfile>;
        let (total, tier_used) = loop {
            let started_query = Instant::now();
            let result = client.candidate_query_plan_with_options(
                &plan,
                cursor,
                Some(DEFAULT_SEARCH_RESULT_CHUNK_SIZE),
                verify_yara_files,
            )?;
            query_time += started_query.elapsed();
            if query_profile.is_none() {
                query_profile = Some(result.query_profile.clone());
            }
            if prepared_query_profile.is_none() {
                prepared_query_profile = Some(result.prepared_query_profile.clone());
            }
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
                                    .map_err(|err| SspryError::from(err.to_string()))?
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
                            .map_err(|err| SspryError::from(err.to_string()))?
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
            let query_profile = query_profile.unwrap_or_default();
            let prepared_query_profile = prepared_query_profile.unwrap_or_default();
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
                "verbose.search.superblocks_skipped: {}",
                query_profile.superblocks_skipped
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
        long = "workers",
        help = "Process workers for recursive file scan/feature extraction before batched inserts. Default is auto: CPU-based on solid-state input, capped conservatively on rotational storage."
    )]
    workers: Option<usize>,
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
        long = "tier2-superblock-budget-divisor",
        default_value_t = DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
        help = "Divides the server memory budget to derive the per-shard Tier2 summary-memory budget. Lower values allow more RAM for Tier2 summaries."
    )]
    tier2_superblock_budget_divisor: u64,
    #[arg(
        long = "tier2-superblock-summary-cap-kib",
        default_value_t = DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_KIB,
        help = "Cap per-superblock summary bytes in KiB. Larger values spend more block-level bytes to reduce coarse-filter collisions."
    )]
    tier2_superblock_summary_cap_kib: usize,
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
        help = "Tier1 Bloom false-positive rate. Defaults to --set-fp or 0.35 when omitted."
    )]
    tier1_filter_target_fp: Option<f64>,
    #[arg(
        long = "tier2-set-fp",
        help = "Tier2 Bloom false-positive rate. Defaults to --set-fp or 0.35 when omitted."
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
        help = "Fallback Bloom false-positive rate applied to both tiers when tier-specific values are not set."
    )]
    filter_target_fp: Option<f64>,
    #[arg(
        long = "tier1-set-fp",
        help = "Tier1 Bloom false-positive rate. Defaults to --set-fp or 0.35 when omitted."
    )]
    tier1_filter_target_fp: Option<f64>,
    #[arg(
        long = "tier2-set-fp",
        help = "Tier2 Bloom false-positive rate. Defaults to --set-fp or 0.35 when omitted."
    )]
    tier2_filter_target_fp: Option<f64>,
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
    #[arg(
        long = "tier2-superblock-summary-cap-kib",
        default_value_t = DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_KIB,
        help = "Cap per-superblock summary bytes in KiB."
    )]
    tier2_superblock_summary_cap_kib: usize,
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
        default_value_t = 15000,
        help = "Maximum candidate hashes returned before paging; 0 means unlimited."
    )]
    max_candidates: usize,
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
        Commands::Index(args) => cmd_index(&args),
        Commands::Delete(args) => cmd_delete(&args),
        Commands::Search(args) => cmd_search(&args),
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

    fn default_internal_init_args(
        root: &Path,
        candidate_shards: usize,
        force: bool,
    ) -> InternalInitArgs {
        InternalInitArgs {
            root: root.display().to_string(),
            candidate_shards,
            force,
            filter_target_fp: Some(0.35),
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            gram_sizes: "3,4".to_owned(),
            compaction_idle_cooldown_s: 5.0,
            tier2_superblock_summary_cap_kib: DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_KIB,
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
        let docs = vec![
            CandidateDocumentWire {
                sha256: "11".repeat(32),
                file_size: 123,
                bloom_filter_b64: "AQID".to_owned(),
                bloom_item_estimate: Some(3),
                tier2_bloom_filter_b64: Some("BAUG".to_owned()),
                tier2_bloom_item_estimate: Some(2),
                special_population: false,
                metadata_b64: None,
                external_id: Some("doc-1".to_owned()),
            },
            CandidateDocumentWire {
                sha256: "22".repeat(32),
                file_size: 456,
                bloom_filter_b64: "CgsM".to_owned(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: Some("DQ4P".to_owned()),
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            },
        ];
        let mut running = empty;
        let mut pending_rows = Vec::new();
        for doc in docs {
            let row = serialize_candidate_document_wire(&doc).expect("row payload size");
            running += row.len() + usize::from(!pending_rows.is_empty());
            pending_rows.push(row);
            let exact = crate::rpc::serialized_candidate_insert_batch_payload(&pending_rows).len();
            assert_eq!(running, exact);
        }
    }

    fn default_serve_args() -> ServeArgs {
        ServeArgs {
            addr: DEFAULT_RPC_ADDR.to_owned(),
            max_request_bytes: DEFAULT_MAX_REQUEST_BYTES,
            search_workers: default_search_workers_for(4),
            memory_budget_gb: DEFAULT_MEMORY_BUDGET_GB,
            tier2_superblock_budget_divisor: DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
            tier2_superblock_summary_cap_kib: DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_KIB,
            root: DEFAULT_CANDIDATE_ROOT.to_owned(),
            layout_profile: ServeLayoutProfile::Standard,
            shards: None,
            filter_target_fp: Some(0.35),
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
            0.002,
            3,
            4,
            8,
            33.5,
        );
        assert_eq!(fixed.root, PathBuf::from("root"));
        assert_eq!(fixed.id_source, "sha256");
        assert!(fixed.store_path);
        assert_eq!(fixed.tier2_gram_size, 3);
        assert_eq!(fixed.tier1_gram_size, 4);
        assert_eq!(fixed.tier2_superblock_summary_cap_bytes, 8 * 1024);
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
            16,
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
        assert_eq!(variable.tier2_superblock_summary_cap_bytes, 16 * 1024);
        assert_eq!(variable.compaction_idle_cooldown_s, 9.25);

        let wire = batch_row_to_wire(IndexBatchRow {
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
        });
        assert_eq!(wire.sha256, hex::encode([0xAA; 32]));
        assert_eq!(wire.file_size, 123);
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
        assert_eq!(cmd_internal_init(&candidate_init_args), 0);

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
            workers: 2,
            chunk_size: 1024,
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
                path_list: false,
                root: Some(candidate_root.display().to_string()),
                batch_size: 1,
                workers: 1,
                chunk_size: 1024,
                external_id_from_path: true,
                verbose: false,
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
                workers: 1,
                chunk_size: 1024,
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
        assert_eq!(policy.tier1_filter_target_fp, Some(0.35));
        assert_eq!(policy.tier2_filter_target_fp, Some(0.35));
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
                paths: vec![
                    sample_b.display().to_string(),
                    sample_c.display().to_string()
                ],
                path_list: false,
                batch_size: 1,
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
                max_candidates: 4,
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
            }),
            0
        );
        assert_eq!(
            cmd_search(&SearchCommandArgs {
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
            cmd_search(&SearchCommandArgs {
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
                max_candidates: 1,
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
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: true,
        });

        assert_eq!(
            cmd_index(&IndexArgs {
                connection: connection.clone(),
                paths: vec![sample.display().to_string()],
                path_list: false,
                batch_size: 1,
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
}
