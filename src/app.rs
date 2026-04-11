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

use crate::candidate::features::AdditionalDigestKind;
use crate::candidate::filter_policy::align_filter_bytes;
use crate::candidate::query_plan::{
    FixedLiteralMatchPlan, evaluate_fixed_literal_match, fixed_literal_match_plan,
};
use crate::candidate::write_candidate_shard_count;
use crate::candidate::{
    BoundedCache, CandidateConfig, CandidatePreparedQueryProfile, CandidateQueryProfile,
    CandidateStore, CompiledQueryPlan, DEFAULT_TIER1_FILTER_TARGET_FP,
    DEFAULT_TIER2_FILTER_TARGET_FP, GramSizes, HLL_DEFAULT_PRECISION, candidate_shard_index,
    candidate_shard_root, choose_filter_bytes_for_file_size,
    compile_query_plan_from_file_with_gram_sizes,
    compile_query_plan_from_file_with_gram_sizes_and_identity_source,
    derive_document_bloom_hash_count, estimate_unique_grams_for_size_hll,
    estimate_unique_grams_pair_hll, extract_compact_document_metadata_with_entropy,
    read_candidate_shard_count, resolve_max_candidates,
    rule_check_all_from_file_with_gram_sizes_and_identity_source,
    scan_file_features_bloom_only_with_gram_sizes,
};
use crate::grpc::{self, BlockingGrpcClient};
use crate::perf;
#[cfg(test)]
use crate::rpc::ServerConfig as RpcServerConfig;
use crate::rpc::{self};
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
pub const DEFAULT_STANDARD_SHARDS: usize = 8;
pub const DEFAULT_INCREMENTAL_SHARDS: usize = 8;
const ESTIMATED_INDEX_QUEUE_ITEM_BYTES: u64 = 32 * 1024 * 1024;
const MAX_INDEX_QUEUE_CAPACITY: usize = 256;
const STORAGE_CLASS_SAMPLE_LIMIT: usize = 16;
const INDEX_CLIENT_HEARTBEAT_INTERVAL_MS: u64 = 1_000;

/// Parses the CLI `--max-candidates` value as a bounded percentage in the
/// inclusive range `0..=100`.
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

/// Returns process-wide shutdown and status-dump flags, installing the
/// platform-specific signal handlers on first use.
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

/// Chooses a default ingest worker count from the available CPU count.
fn default_ingest_workers_for(cpus: usize) -> usize {
    let cpus = cpus.max(1);
    if cpus < 8 {
        (cpus / 2).max(1)
    } else {
        ((cpus * 3) / 4).max(1)
    }
}

/// Chooses the process default ingest worker count from host parallelism.
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
    /// Returns the stable configuration/status label for the detected storage
    /// class.
    fn as_str(self) -> &'static str {
        match self {
            Self::Unknown => "unknown",
            Self::SolidState => "solid-state",
            Self::Rotational => "rotational",
        }
    }
}

#[cfg(unix)]
/// Splits a Unix device number into its major and minor components.
fn dev_major_minor(dev: u64) -> (u64, u64) {
    let major = ((dev >> 8) & 0x0fff) | ((dev >> 32) & !0x0fff);
    let minor = (dev & 0x00ff) | ((dev >> 12) & !0x00ff);
    (major, minor)
}

#[cfg(unix)]
/// Walks up the filesystem until it finds an existing path that can be probed
/// for storage characteristics.
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
/// Detects whether a path resolves to rotational or solid-state storage by
/// inspecting Linux block-device metadata.
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
/// Returns `Unknown` on platforms where block-device storage probing is not
/// implemented.
fn detect_storage_class_for_path(_path: &Path) -> IngestStorageClass {
    IngestStorageClass::Unknown
}

/// Samples input paths and returns the most restrictive detected storage class.
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

/// Returns the adaptive-publish storage hint and initial idle bias for a store
/// root.
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

/// Chooses an automatic ingest worker count using CPU limits, workload size,
/// and detected storage constraints.
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

/// Resolves the ingest worker policy, preserving an explicit user override or
/// deriving an automatic value when `requested_workers` is zero.
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

/// Chooses a conservative default search worker count from the available CPUs.
fn default_search_workers_for(cpus: usize) -> usize {
    (cpus.max(1) / 4).max(1)
}

/// Chooses the process default search worker count from host parallelism.
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

#[derive(Clone, Copy, Debug, Default)]
struct ServeInitOptionSources {
    layout_profile: bool,
    shards: bool,
    tier1_filter_target_fp: bool,
    tier2_filter_target_fp: bool,
    id_source: bool,
    store_path: bool,
    gram_sizes: bool,
}

/// Returns whether the CLI argv contains the requested long flag, including the
/// `--flag=value` form.
fn argv_has_long_flag(argv: &[String], flag: &str) -> bool {
    argv.iter().any(|arg| {
        arg == flag
            || arg
                .strip_prefix(flag)
                .is_some_and(|suffix| suffix.starts_with('='))
    })
}

/// Records which serve-time initialization options were explicitly supplied on
/// the command line.
fn serve_init_option_sources_from_argv(argv: &[String]) -> ServeInitOptionSources {
    ServeInitOptionSources {
        layout_profile: argv_has_long_flag(argv, "--layout-profile"),
        shards: argv_has_long_flag(argv, "--shards"),
        tier1_filter_target_fp: argv_has_long_flag(argv, "--tier1-set-fp"),
        tier2_filter_target_fp: argv_has_long_flag(argv, "--tier2-set-fp"),
        id_source: argv_has_long_flag(argv, "--id-source"),
        store_path: argv_has_long_flag(argv, "--store-path"),
        gram_sizes: argv_has_long_flag(argv, "--gram-sizes"),
    }
}

/// Returns the default shard count associated with the chosen serve layout
/// profile.
fn default_shards_for_profile(profile: ServeLayoutProfile) -> usize {
    match profile {
        ServeLayoutProfile::Standard => DEFAULT_STANDARD_SHARDS,
        ServeLayoutProfile::Incremental => DEFAULT_INCREMENTAL_SHARDS,
    }
}

/// Resolves the effective candidate shard count for a serve invocation.
fn serve_candidate_shard_count(args: &ServeCommonArgs) -> usize {
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
    #[arg(
        long = "max-message-bytes",
        default_value_t = DEFAULT_MAX_REQUEST_BYTES,
        help = "Maximum remote message size in bytes."
    )]
    max_message_bytes: usize,
}

/// Parses a `host:port` or `[ipv6]:port` address string into its components.
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

/// Canonicalizes a file path for stable downstream identity or display use.
fn resolved_file_path(path: &Path) -> Result<PathBuf> {
    fs::canonicalize(path).map_err(SspryError::from)
}

/// Reads current and peak resident memory usage for the CLI process from
/// `/proc/self/status`.
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

/// Reads detailed memory accounting for the CLI process from
/// `/proc/self/smaps_rollup`.
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

/// Returns the kernel-reported available system memory in bytes when present.
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

/// Caps the configured memory budget against currently available system memory.
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

/// Chooses the bounded ingest queue capacity implied by the effective memory
/// budget and worker count.
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

#[cfg(test)]
/// Builds a stable test identity from the canonical file path.
fn path_identity_sha256(path: &Path) -> Result<[u8; 32]> {
    let canonical = resolved_file_path(path)?;
    let mut digest = Sha256::new();
    digest.update(canonical.to_string_lossy().as_bytes());
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest.finalize());
    Ok(out)
}

/// Folds an alternate digest into the canonical 32-byte candidate identity
/// namespace.
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

/// Streams a file through SHA-256 and returns the raw digest bytes.
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

/// Streams a file through MD5 and returns the raw digest bytes.
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

/// Streams a file through SHA-1 and returns the raw digest bytes.
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

/// Streams a file through SHA-512 and returns the raw digest bytes.
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

/// Decodes a canonical 64-character SHA-256 hex string.
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

/// Decodes a fixed-width hexadecimal digest and validates its exact size.
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

/// Computes the normalized candidate identity for a file using the configured
/// identity source.
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

/// Decodes a textual digest into the normalized candidate identity for the
/// configured identity source.
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
/// Resolves exactly one delete target from explicit digests or a file path into
/// the canonical SHA-256 hex identity stored by the index.
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

/// Returns the direct children of a directory in stable sorted order.
fn sorted_directory_children(path: &Path) -> Result<Vec<PathBuf>> {
    let mut children = fs::read_dir(path)?
        .map(|entry| entry.map(|value| value.path()).map_err(SspryError::from))
        .collect::<Result<Vec<_>>>()?;
    children.sort();
    Ok(children)
}

/// Walks a file or directory tree depth-first and invokes `visit` for each
/// file encountered.
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
/// Collects every file reachable from `path` into `out` for test assertions.
fn collect_files_recursive(path: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    visit_files_recursive(path, &mut |child| {
        out.push(child);
        Ok(())
    })
}

/// Counts the number of files reachable from the provided path.
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

/// Expands CLI input roots, optionally interpreting them as newline-delimited
/// path-list files and discarding missing entries.
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

/// Counts the total number of input files represented by the provided roots.
fn count_input_files(paths: &[PathBuf]) -> Result<usize> {
    let mut total = 0usize;
    for path in paths {
        total = total.saturating_add(count_files_recursive(path)?);
    }
    Ok(total)
}

/// Returns whether the provided inputs are already a flat list of files with no
/// directory traversal required.
fn input_paths_are_file_only(paths: &[PathBuf]) -> bool {
    !paths.is_empty() && paths.iter().all(|path| path.is_file())
}

/// Streams the selected input files, honoring the pre-expanded `path_list`
/// behavior when paths already identify individual files.
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

/// Recursively streams every file rooted at the provided input paths.
fn stream_input_files(
    paths: &[PathBuf],
    mut visit: impl FnMut(PathBuf) -> Result<()>,
) -> Result<()> {
    for path in paths {
        visit_files_recursive(path, &mut visit)?;
    }
    Ok(())
}

/// Emits periodic ingest progress updates based on processed-count and elapsed
/// time thresholds.
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

/// Creates a gRPC client using the connection's configured timeout.
fn grpc_client(connection: &ClientConnectionArgs) -> Result<BlockingGrpcClient> {
    grpc_client_with_timeout(connection, connection.timeout)
}

/// Creates a gRPC client using an explicit timeout override.
fn grpc_client_with_timeout(
    connection: &ClientConnectionArgs,
    timeout_secs: f64,
) -> Result<BlockingGrpcClient> {
    BlockingGrpcClient::connect_with_limits(
        &connection.addr,
        Duration::from_secs_f64(timeout_secs.max(0.0)),
        connection.max_message_bytes.max(1),
    )
}

/// Creates a gRPC client for search workloads, ensuring the longer search
/// timeout floor is respected.
fn search_grpc_client(connection: &ClientConnectionArgs) -> Result<BlockingGrpcClient> {
    grpc_client_with_timeout(
        connection,
        connection.timeout.max(DEFAULT_SEARCH_RPC_TIMEOUT),
    )
}

struct ScannedIndexBatchRow {
    row: IndexBatchRow,
    scan_elapsed: Duration,
}

#[cfg(test)]
/// Reads a `usize` value from a JSON stats map with a test default fallback.
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

#[cfg(test)]
/// Reads an optional `f64` from a JSON stats map for test assertions.
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
    workspace_mode: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RuleCheckPolicySource {
    Defaults,
    Explicit,
    LocalRoot,
    Server,
}

impl RuleCheckPolicySource {
    /// Returns the stable label describing where the effective rule-check
    /// policy came from.
    fn as_str(self) -> &'static str {
        match self {
            Self::Defaults => "defaults",
            Self::Explicit => "explicit",
            Self::LocalRoot => "local-root",
            Self::Server => "server",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RuleCheckPolicy {
    source: RuleCheckPolicySource,
    id_source: CandidateIdSource,
    gram_sizes: GramSizes,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RuleCheckPolicyOutput {
    source: String,
    id_source: String,
    gram_sizes: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
struct RuleCheckOutput {
    status: crate::candidate::RuleCheckStatus,
    policy: RuleCheckPolicyOutput,
    issues: Vec<crate::candidate::RuleCheckIssue>,
    verifier_only_kinds: Vec<String>,
    ignored_module_calls: Vec<String>,
    rules: Vec<crate::candidate::RuleCheckRuleReport>,
}

/// Loads the current remote scan policy by querying server stats over gRPC.
fn server_scan_policy(connection: &ClientConnectionArgs) -> Result<ServerScanPolicy> {
    let mut client = grpc_client(connection)?;
    let stats = client.stats()?;
    server_scan_policy_from_grpc_stats(&stats)
}

/// Extracts the scan policy fields used by the CLI from a raw gRPC stats
/// response.
fn server_scan_policy_from_grpc_stats(stats: &grpc::v1::StatsResponse) -> Result<ServerScanPolicy> {
    let store = stats
        .stats
        .as_ref()
        .ok_or_else(|| SspryError::from("grpc stats missing store summary"))?;
    let id_source = CandidateIdSource::parse_config_value(&store.id_source)?;
    Ok(ServerScanPolicy {
        id_source,
        store_path: store.store_path,
        tier1_filter_target_fp: Some(store.tier1_filter_target_fp),
        tier2_filter_target_fp: Some(store.tier2_filter_target_fp),
        gram_sizes: GramSizes::new(
            store.tier1_gram_size as usize,
            store.tier2_gram_size as usize,
        )?,
        memory_budget_bytes: stats.memory_budget_bytes,
        workspace_mode: stats.workspace_mode,
    })
}

// gRPC status and telemetry JSON shaping lives in a sibling file so the CLI
// command handlers stay easier to scan.
include!("app/status.rs");

/// Returns just the configured identity source from the remote server.
fn server_identity_source(connection: &ClientConnectionArgs) -> Result<CandidateIdSource> {
    Ok(server_scan_policy(connection)?.id_source)
}

/// Infers which digest algorithm produced a hex string from its length.
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

/// Resolves a delete CLI value into the canonical candidate identity expected
/// by the server.
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

/// Serializes one scanned index row into the binary insert format used by the
/// RPC path.
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
const GRPC_REMOTE_BATCH_SOFT_LIMIT_BYTES: usize = 8 * 1024 * 1024;
const GRPC_REMOTE_BATCH_MAX_ROWS: usize = 16;
#[cfg(test)]
const REMOTE_INDEX_SESSION_MAX_DOCUMENTS: usize = 2048;
#[cfg(test)]
const REMOTE_INDEX_SESSION_MIN_INPUT_BYTES: u64 = 1 << 30;
#[cfg(test)]
const REMOTE_INDEX_SESSION_MAX_INPUT_BYTES: u64 = 4 << 30;
const REMOTE_UPLOAD_QUEUE_MAX_BYTES: usize = 512 * 1024 * 1024;

struct RemotePendingBatch {
    rows: Vec<Vec<u8>>,
    payload_size: usize,
}

trait RemoteBinaryInsertClient {
    /// Sends a batch of pre-serialized insert rows and returns how many the
    /// remote endpoint accepted.
    fn candidate_insert_binary_rows(&mut self, rows: Vec<Vec<u8>>) -> Result<usize>;
}

impl RemoteBinaryInsertClient for BlockingGrpcClient {
    /// Sends one serialized binary insert batch over gRPC and returns the
    /// server-reported insert count.
    fn candidate_insert_binary_rows(&mut self, rows: Vec<Vec<u8>>) -> Result<usize> {
        let response = self.insert_binary_rows(rows)?;
        Ok(usize::try_from(response.inserted_count).unwrap_or(usize::MAX))
    }
}

struct RemoteUploadRow {
    row_bytes: Vec<u8>,
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
    /// Creates a bounded in-memory queue used to decouple scanning/encoding
    /// from remote upload.
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

    /// Enqueues one serialized row, blocking when the queue would exceed its
    /// byte budget.
    fn push(&self, row: RemoteUploadRow) -> Result<()> {
        let row_bytes = row.row_bytes.len();
        if row_bytes > self.byte_limit && self.byte_limit > 0 {
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
            && self.byte_limit > 0
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

    /// Pops the next queued row, blocking until data arrives or the queue is
    /// closed.
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

    /// Closes the queue and wakes all waiting producers and consumers.
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

#[cfg(test)]
/// Derives the test-only remote index session document cap from the effective
/// client memory budget and requested batch size.
fn remote_index_session_document_limit(effective_budget_bytes: u64, batch_size: usize) -> usize {
    if effective_budget_bytes == 0 {
        return REMOTE_INDEX_SESSION_MAX_DOCUMENTS.max(batch_size);
    }
    let derived = usize::try_from(effective_budget_bytes / (640 * 1024) / 4).unwrap_or(usize::MAX);
    derived.clamp(batch_size.max(1), REMOTE_INDEX_SESSION_MAX_DOCUMENTS)
}

#[cfg(test)]
/// Derives the test-only remote index session input-byte cap from the
/// effective client memory budget.
fn remote_index_session_input_bytes_limit(effective_budget_bytes: u64) -> u64 {
    if effective_budget_bytes == 0 {
        return REMOTE_INDEX_SESSION_MAX_INPUT_BYTES;
    }
    (effective_budget_bytes / 4).clamp(
        REMOTE_INDEX_SESSION_MIN_INPUT_BYTES,
        REMOTE_INDEX_SESSION_MAX_INPUT_BYTES,
    )
}

/// Chooses the maximum upload-queue byte budget for remote indexing.
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

/// Returns the serialized payload size of an empty remote insert batch.
fn empty_remote_batch_payload_size() -> Result<usize> {
    Ok(rpc::serialized_candidate_insert_binary_batch_payload(&[]).len())
}

/// Clamps the effective gRPC remote batch row count.
fn grpc_remote_batch_size(batch_size: usize) -> usize {
    batch_size.max(1).min(GRPC_REMOTE_BATCH_MAX_ROWS)
}

/// Clamps the effective remote batch payload limit to both the configured limit
/// and the gRPC transport ceiling.
fn grpc_remote_batch_soft_limit_bytes(
    configured_limit_bytes: usize,
    empty_payload_size: usize,
) -> usize {
    configured_limit_bytes
        .max(empty_payload_size.saturating_add(1))
        .min(GRPC_REMOTE_BATCH_SOFT_LIMIT_BYTES.max(empty_payload_size.saturating_add(1)))
}

/// Determines whether a pending remote batch must be flushed before a new row
/// can be added.
fn prepare_serialized_remote_batch_row(
    pending: &RemotePendingBatch,
    row_payload_size: usize,
    empty_payload_size: usize,
    remote_batch_soft_limit_bytes: usize,
    allow_oversize_single_row: bool,
) -> Result<bool> {
    let single_payload_size = empty_payload_size.saturating_add(row_payload_size);
    if single_payload_size > remote_batch_soft_limit_bytes {
        if allow_oversize_single_row {
            return Ok(!pending.rows.is_empty());
        }
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

/// Submits the current pending remote batch and resets the accumulation state.
fn flush_remote_batch<C: RemoteBinaryInsertClient>(
    client: &mut C,
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
    let flush_payload = std::mem::take(&mut pending.rows);
    let started = Instant::now();
    let inserted_count = client.candidate_insert_binary_rows(flush_payload)?;
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
    pending.payload_size = empty_payload_size;
    Ok(())
}

/// Adds one serialized row to the remote upload pipeline, flushing before or
/// after the push when size or row-count limits require it.
fn push_serialized_remote_upload_row<C: RemoteBinaryInsertClient>(
    client: &mut C,
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
    allow_oversize_single_row: bool,
    verbose: bool,
) -> Result<Duration> {
    let started_buffer = Instant::now();
    let flush_before = prepare_serialized_remote_batch_row(
        pending,
        row_bytes.len(),
        empty_payload_size,
        remote_batch_soft_limit_bytes,
        allow_oversize_single_row,
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
        allow_oversize_single_row,
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

/// Pushes one serialized row into the current remote batch and reports whether
/// the caller should flush immediately afterward.
fn push_serialized_remote_batch_row(
    pending: &mut RemotePendingBatch,
    row_bytes: Vec<u8>,
    batch_size: usize,
    remote_batch_soft_limit_bytes: usize,
    allow_oversize_single_row: bool,
) -> Result<bool> {
    let row_payload_size = row_bytes.len();
    let separator_bytes = usize::from(!pending.rows.is_empty());
    let payload_size = pending
        .payload_size
        .saturating_add(separator_bytes)
        .saturating_add(row_payload_size);
    if payload_size > remote_batch_soft_limit_bytes {
        if allow_oversize_single_row && pending.rows.is_empty() {
            pending.rows.push(row_bytes);
            pending.payload_size = payload_size;
            return Ok(true);
        }
        return Err(SspryError::from(
            "remote batch row exceeded payload limit before flush",
        ));
    }
    pending.rows.push(row_bytes);
    pending.payload_size = payload_size;
    Ok(pending.rows.len() >= batch_size)
}

/// Flushes a local pending batch into the correct shard stores and updates
/// progress accounting.
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

/// Flushes a pending remote batch, updates progress, and accumulates submit
/// timing.
fn flush_remote_pending_rows<C: RemoteBinaryInsertClient>(
    client: &mut C,
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

#[cfg(test)]
/// Returns whether an RPC error represents a transient publish or session
/// rotation conflict.
fn is_retryable_remote_index_rotation_error(err: &SspryError) -> bool {
    let text = err.to_string();
    (text.contains("server is publishing") && text.contains("retry later"))
        || (text.contains("another index session is already active")
            && text.contains("retry later"))
        || text.contains("no active index session; cannot update progress")
}

/// Builds a `CandidateConfig` from the resolved CLI/runtime configuration
/// pieces.
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

/// Resolves effective tier-1 and tier-2 false-positive targets, applying
/// defaults when the caller left them unset.
fn resolve_filter_target_fps(
    tier1_filter_target_fp: Option<f64>,
    tier2_filter_target_fp: Option<f64>,
) -> (f64, f64) {
    (
        tier1_filter_target_fp.unwrap_or(DEFAULT_TIER1_FILTER_TARGET_FP),
        tier2_filter_target_fp.unwrap_or(DEFAULT_TIER2_FILTER_TARGET_FP),
    )
}

/// Converts serve arguments into the candidate-store configuration used at
/// startup.
fn store_config_from_serve_args(args: &ServeCommonArgs) -> CandidateConfig {
    let gram_sizes =
        GramSizes::parse(&args.gram_sizes).expect("validated by clap-compatible serve args");
    let (tier1_filter_target_fp, tier2_filter_target_fp) =
        resolve_filter_target_fps(args.tier1_filter_target_fp, args.tier2_filter_target_fp);
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

/// Converts init arguments into the candidate-store configuration used for
/// local initialization.
fn store_config_from_init_args(args: &InitArgs) -> CandidateConfig {
    let gram_sizes =
        GramSizes::parse(&args.gram_sizes).expect("validated by clap-compatible init args");
    let (tier1_filter_target_fp, tier2_filter_target_fp) =
        resolve_filter_target_fps(args.tier1_filter_target_fp, args.tier2_filter_target_fp);
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

/// Returns whether a root already contains any files that identify it as an
/// initialized store or shard tree.
fn store_root_has_markers(root: &Path) -> bool {
    root.join("store_meta.json").exists()
        || root.join("meta.json").exists()
        || root.join("sha256_by_docid.dat").exists()
        || root.join("doc_meta.bin").exists()
        || root.join("shard_000").join("store_meta.json").exists()
        || root.join("shard_000").join("meta.json").exists()
        || root.join("shard_000").join("sha256_by_docid.dat").exists()
        || root.join("shard_000").join("doc_meta.bin").exists()
}

/// Returns a placeholder connection used by local-only command wrappers that do
/// not actually talk to a remote server.
fn placeholder_connection() -> ClientConnectionArgs {
    ClientConnectionArgs {
        addr: DEFAULT_RPC_ADDR.to_owned(),
        timeout: DEFAULT_RPC_TIMEOUT,
        max_message_bytes: DEFAULT_MAX_REQUEST_BYTES,
    }
}

/// Opens an existing store or initializes a new one when `force` or missing
/// metadata requires it.
fn ensure_store(config: CandidateConfig, force: bool) -> Result<CandidateStore> {
    let local_meta_path = config.root.join("store_meta.json");
    let legacy_meta_path = config.root.join("meta.json");
    if force || (!local_meta_path.exists() && !legacy_meta_path.exists()) {
        return CandidateStore::init(config, force);
    }
    CandidateStore::open(config.root)
}

/// Reads the configured shard count for a store root, defaulting to one when
/// no manifest exists yet.
fn candidate_shard_count(root: &Path) -> Result<usize> {
    Ok(read_candidate_shard_count(root)?.unwrap_or(1).max(1))
}

/// Returns the concrete store roots for every shard under the requested root.
fn store_roots(root: &Path) -> Result<Vec<PathBuf>> {
    let shard_count = candidate_shard_count(root)?;
    Ok((0..shard_count)
        .map(|shard_idx| candidate_shard_root(root, shard_count, shard_idx))
        .collect())
}

/// Opens every store shard under the requested root.
fn open_stores(root: &Path) -> Result<Vec<CandidateStore>> {
    store_roots(root)?
        .into_iter()
        .map(CandidateStore::open)
        .collect()
}

#[allow(dead_code)]
struct LocalInitOutcome {
    shard_count: usize,
    stats: crate::candidate::CandidateStats,
}

/// Ensures the local root is initialized with the requested shard layout and
/// returns the resulting shard count and initial stats.
fn ensure_local_root_initialized(args: &InitArgs) -> Result<LocalInitOutcome> {
    let root = Path::new(&args.root);
    let shard_count = args.candidate_shards.max(1);
    if !args.force {
        if let Some(existing) = read_candidate_shard_count(root)? {
            if existing == shard_count {
                let stats = open_stores(root)?
                    .into_iter()
                    .next()
                    .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?
                    .stats();
                return Ok(LocalInitOutcome { shard_count, stats });
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
            let stats = open_stores(root)?
                .into_iter()
                .next()
                .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?
                .stats();
            return Ok(LocalInitOutcome { shard_count, stats });
        }
        if shard_count > 1 && (first_local_meta.exists() || first_legacy_meta.exists()) {
            let stats = open_stores(root)?
                .into_iter()
                .next()
                .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?
                .stats();
            return Ok(LocalInitOutcome { shard_count, stats });
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
    Ok(LocalInitOutcome {
        shard_count,
        stats: stats.expect("candidate init must create at least one shard"),
    })
}

/// Merges per-store tier labels into a single user-facing summary string.
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

#[derive(Debug)]
struct SearchExecution {
    plan: CompiledQueryPlan,
    total_candidates: usize,
    tier_used: String,
    truncated: bool,
    truncated_limit: Option<usize>,
    rows: Vec<String>,
    query_profile: CandidateQueryProfile,
    prepared_query_profile: CandidatePreparedQueryProfile,
    external_ids: Vec<Option<String>>,
    tree_count: Option<usize>,
    tree_search_workers: Option<usize>,
    server_rss_kb: Option<(u64, u64)>,
    plan_time: Duration,
    query_time: Duration,
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
    /// Opens the JSON and JSONL outputs used by `search-batch`, writing JSON
    /// records atomically via a temporary file.
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

    /// Appends one completed batch-search record to both JSON outputs.
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

    /// Finalizes the JSON array output and atomically promotes the partial file
    /// into place.
    fn finish(mut self) -> Result<usize> {
        self.json_writer.write_all(b"]\n")?;
        self.json_writer.flush()?;
        self.jsonl_writer.flush()?;
        drop(self.json_writer);
        drop(self.jsonl_writer);
        fs::rename(&self.partial_json_out, &self.json_out)?;
        Ok(self.count)
    }

    /// Returns the sidecar JSONL path used for incremental batch-search
    /// consumption.
    fn jsonl_out(&self) -> &Path {
        &self.jsonl_out
    }
}

/// Appends a suffix to the final path component while preserving the parent
/// directory.
fn append_path_suffix(path: &Path, suffix: &str) -> PathBuf {
    let file_name = path
        .file_name()
        .and_then(|value| value.to_str())
        .unwrap_or("output");
    path.with_file_name(format!("{file_name}{suffix}"))
}

/// Returns the searchable tree roots within a forest or falls back to the
/// provided root for single-tree layouts.
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

/// Opens each searchable tree in a forest as one grouped set of candidate
/// stores.
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

/// Verifies that every tree in the forest agrees on gram sizes and identity
/// source before a shared search runs.
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

// Rule-check policy resolution and human-readable formatting live in a sibling
// file so search/indexing code is easier to navigate.
include!("app/rule_check.rs");

/// Builds the prepared-query profile that reflects the union of filter layouts
/// across all trees in the forest.
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

/// Executes a full candidate scan across one tree group's stores and merges the
/// resulting hashes, external IDs, and query profile counters.
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

/// Executes a candidate search across all trees in the forest and combines the
/// results into one local aggregate.
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

/// Clears all per-store search caches for the currently opened forest.
fn clear_local_forest_search_caches(tree_groups: &mut [TreeStoreGroup]) {
    for group in tree_groups {
        for store in &mut group.stores {
            store.clear_search_caches();
        }
    }
}

/// Rechecks candidate rows against the original rule file when file-backed
/// verification is enabled.
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
    /// Returns the stable configuration label for the selected document
    /// identity source.
    fn as_str(self) -> &'static str {
        match self {
            CandidateIdSource::Sha256 => "sha256",
            CandidateIdSource::Md5 => "md5",
            CandidateIdSource::Sha1 => "sha1",
            CandidateIdSource::Sha512 => "sha512",
        }
    }

    /// Parses the stored configuration value for candidate identity source.
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

    /// Returns the auxiliary digest kind that must be computed during ingest
    /// when the primary identity is not SHA-256.
    fn additional_digest_kind(self) -> Option<AdditionalDigestKind> {
        match self {
            CandidateIdSource::Sha256 => None,
            CandidateIdSource::Md5 => Some(AdditionalDigestKind::Md5),
            CandidateIdSource::Sha1 => Some(AdditionalDigestKind::Sha1),
            CandidateIdSource::Sha512 => Some(AdditionalDigestKind::Sha512),
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

/// Scans one file into the index row representation used by both local and
/// remote ingestion paths.
fn scan_index_batch_row(file_path: &Path, policy: ScanPolicy) -> Result<IndexBatchRow> {
    let resolved_path = if policy.store_path {
        Some(resolved_file_path(file_path)?)
    } else {
        None
    };
    let scan_path = resolved_path.as_deref().unwrap_or(file_path);
    let file_size = scan_path.metadata()?.len();
    let mut total_scope = perf::scope("candidate.scan_index_batch_row");
    total_scope.add_bytes(file_size);
    total_scope.add_items(1);
    let (bloom_item_estimate, tier2_bloom_item_estimate) =
        if policy.tier1_filter_target_fp.is_some() || policy.tier2_filter_target_fp.is_some() {
            let mut estimate_scope =
                perf::scope("candidate.scan_index_batch_row.estimate_unique_grams");
            estimate_scope.add_bytes(file_size);
            estimate_scope.add_items(1);
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
    let (filter_bytes, tier2_filter_bytes, bloom_hashes, tier2_bloom_hashes) = {
        let mut filter_scope = perf::scope("candidate.scan_index_batch_row.filter_sizing");
        filter_scope.add_items(1);
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
        let bloom_hashes = derive_document_bloom_hash_count(
            filter_bytes,
            bloom_item_estimate,
            INTERNAL_BLOOM_HASHES,
        );
        let tier2_bloom_hashes = derive_document_bloom_hash_count(
            tier2_filter_bytes,
            tier2_bloom_item_estimate,
            INTERNAL_BLOOM_HASHES,
        );
        (
            filter_bytes,
            tier2_filter_bytes,
            bloom_hashes,
            tier2_bloom_hashes,
        )
    };
    let started = Instant::now();
    let features = scan_file_features_bloom_only_with_gram_sizes(
        scan_path,
        policy.gram_sizes,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes,
        tier2_bloom_hashes,
        policy.chunk_size,
        policy.id_source.additional_digest_kind(),
    )?;
    perf::record_sample(
        "candidate.scan_file_features.file",
        scan_path.display().to_string(),
        started.elapsed().as_nanos(),
        file_size,
        0,
    );
    let metadata = {
        let mut metadata_scope = perf::scope("candidate.scan_index_batch_row.metadata");
        metadata_scope.add_items(1);
        extract_compact_document_metadata_with_entropy(scan_path, features.entropy_bits_per_byte)?
    };
    let sha256 = if policy.id_source == CandidateIdSource::Sha256 {
        features.sha256
    } else {
        features
            .alternate_identity
            .expect("alternate identity when non-sha256 source requested")
    };
    let row = {
        let mut row_build_scope = perf::scope("candidate.scan_index_batch_row.row_build");
        row_build_scope.add_items(1);
        IndexBatchRow {
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
        }
    };
    Ok(row)
}

/// Compiles the supplied rule file into a YARA verifier ruleset.
fn compile_yara_verifier(rule_path: &Path) -> Result<YaraRules> {
    let source = fs::read_to_string(rule_path)?;
    let mut compiler = YaraCompiler::new();
    compiler
        .add_source(source.as_str())
        .map_err(|err| SspryError::from(err.to_string()))?;
    Ok(compiler.build())
}

/// Builds the cache key used to reuse compiled YARA verifier rules across
/// repeated checks of the same file.
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

/// Returns a cached compiled YARA verifier ruleset for the requested rule file.
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

/// Returns whether a rule file contains exactly one `rule` declaration.
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

/// Attempts to derive a fixed-literal verification plan from a simple
/// single-rule file.
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

/// Returns whether one byte counts as an ASCII word boundary character for
/// fullword matching.
fn is_ascii_word_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || byte == b'_'
}

/// Returns whether a two-byte UTF-16LE unit encodes an ASCII word character.
fn is_wide_word_unit(unit: &[u8]) -> bool {
    unit.len() == 2 && unit[1] == 0 && is_ascii_word_byte(unit[0])
}

/// Checks whether a file buffer contains a literal under the requested wide and
/// fullword matching semantics.
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

/// Verifies a fixed-literal plan directly against file bytes without invoking
/// the YARA engine.
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

/// Implements the standalone `yara` command used to verify one rule file
/// against one target file.
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

#[cfg(test)]
/// Test wrapper around `cmd_serve_with_sources` with no explicit init-option
/// provenance.
fn cmd_serve(args: &ServeArgs) -> i32 {
    cmd_serve_with_sources(args, ServeInitOptionSources::default())
}

/// Implements the `serve` command, resolving startup settings and running the
/// gRPC server until shutdown.
fn cmd_serve_with_sources(args: &ServeArgs, option_sources: ServeInitOptionSources) -> i32 {
    match (|| -> Result<i32> {
        let (host, port) = parse_host_port(&args.common.addr)?;
        let resolved = resolve_serve_runtime_settings(&args.common, option_sources)?;
        let (auto_publish_storage_class, auto_publish_initial_idle_ms) =
            adaptive_publish_prior_for_root(Path::new(&args.common.root));
        let signals = serve_signal_flags()?;
        for warning in &resolved.warnings {
            eprintln!("{warning}");
        }
        rpc::serve_grpc_with_signal_flags(
            &host,
            port,
            args.max_message_bytes,
            rpc::ServerConfig {
                candidate_config: resolved.candidate_config,
                candidate_shards: resolved.candidate_shards,
                search_workers: args.common.search_workers.max(1),
                memory_budget_bytes: DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms,
                auto_publish_storage_class,
                workspace_mode: resolved.workspace_mode,
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

/// Infers whether the target root should run in workspace mode based on its
/// current on-disk layout.
fn serve_uses_workspace_mode(root: &Path) -> bool {
    if root.join("current").is_dir() || root.join("work_a").is_dir() || root.join("work_b").is_dir()
    {
        return true;
    }
    if store_root_has_markers(root) {
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

#[derive(Debug)]
struct ResolvedServeRuntimeSettings {
    candidate_config: CandidateConfig,
    candidate_shards: usize,
    workspace_mode: bool,
    warnings: Vec<String>,
}

/// Returns the existing store root that a serve command should reuse, if one is
/// already initialized.
fn existing_serve_store_root(root: &Path, workspace_mode: bool) -> Result<Option<PathBuf>> {
    if workspace_mode {
        let current_root = root.join("current");
        if store_root_has_markers(&current_root) {
            return Ok(Some(current_root));
        }
        return Ok(None);
    }
    if store_root_has_markers(root) {
        return Ok(Some(root.to_path_buf()));
    }
    let tree_roots = forest_tree_roots(root)?;
    Ok(tree_roots
        .into_iter()
        .find(|tree_root| tree_root != root && store_root_has_markers(tree_root)))
}

/// Resolves the effective serve-time runtime settings, reusing on-disk store
/// configuration when the target root already exists.
fn resolve_serve_runtime_settings(
    args: &ServeCommonArgs,
    option_sources: ServeInitOptionSources,
) -> Result<ResolvedServeRuntimeSettings> {
    let root = Path::new(&args.root);
    let workspace_mode = serve_uses_workspace_mode(root);
    if let Some(existing_root) = existing_serve_store_root(root, workspace_mode)? {
        let stores = open_stores(&existing_root)?;
        let first = stores
            .first()
            .ok_or_else(|| SspryError::from("Candidate store is not initialized."))?;
        let stats = first.stats();
        let id_source = CandidateIdSource::parse_config_value(&stats.id_source)?;
        let candidate_config = store_config_from_parts(
            root.to_path_buf(),
            id_source,
            stats.store_path,
            stats
                .tier1_filter_target_fp
                .unwrap_or(DEFAULT_TIER1_FILTER_TARGET_FP),
            stats
                .tier2_filter_target_fp
                .unwrap_or(DEFAULT_TIER2_FILTER_TARGET_FP),
            stats.tier2_gram_size,
            stats.tier1_gram_size,
            stats.compaction_idle_cooldown_s,
        );
        let mut ignored = Vec::<String>::new();
        if option_sources.shards && serve_candidate_shard_count(args) != stores.len().max(1) {
            ignored.push(format!(
                "--shards {} (using existing candidate_shards={})",
                serve_candidate_shard_count(args),
                stores.len().max(1)
            ));
        }
        if option_sources.layout_profile
            && default_shards_for_profile(args.layout_profile) != stores.len().max(1)
        {
            let layout_name = match args.layout_profile {
                ServeLayoutProfile::Standard => "standard",
                ServeLayoutProfile::Incremental => "incremental",
            };
            ignored.push(format!(
                "--layout-profile {} (using existing candidate_shards={})",
                layout_name,
                stores.len().max(1)
            ));
        }
        if option_sources.tier1_filter_target_fp
            && args.tier1_filter_target_fp
                != Some(
                    stats
                        .tier1_filter_target_fp
                        .unwrap_or(DEFAULT_TIER1_FILTER_TARGET_FP),
                )
        {
            let value = args
                .tier1_filter_target_fp
                .unwrap_or(DEFAULT_TIER1_FILTER_TARGET_FP);
            ignored.push(format!(
                "--tier1-set-fp {} (using existing {})",
                value,
                stats
                    .tier1_filter_target_fp
                    .unwrap_or(DEFAULT_TIER1_FILTER_TARGET_FP)
            ));
        }
        if option_sources.tier2_filter_target_fp
            && args.tier2_filter_target_fp
                != Some(
                    stats
                        .tier2_filter_target_fp
                        .unwrap_or(DEFAULT_TIER2_FILTER_TARGET_FP),
                )
        {
            let value = args
                .tier2_filter_target_fp
                .unwrap_or(DEFAULT_TIER2_FILTER_TARGET_FP);
            ignored.push(format!(
                "--tier2-set-fp {} (using existing {})",
                value,
                stats
                    .tier2_filter_target_fp
                    .unwrap_or(DEFAULT_TIER2_FILTER_TARGET_FP)
            ));
        }
        if option_sources.id_source && args.id_source.as_str() != stats.id_source {
            ignored.push(format!(
                "--id-source {} (using existing {})",
                args.id_source.as_str(),
                stats.id_source
            ));
        }
        if option_sources.store_path && !stats.store_path {
            ignored.push(format!(
                "--store-path (using existing store_path={})",
                stats.store_path
            ));
        }
        let existing_gram_sizes = format!("{},{}", stats.tier1_gram_size, stats.tier2_gram_size);
        if option_sources.gram_sizes && args.gram_sizes != existing_gram_sizes {
            ignored.push(format!(
                "--gram-sizes {} (using existing {},{})",
                args.gram_sizes, stats.tier1_gram_size, stats.tier2_gram_size
            ));
        }
        let warnings = if ignored.is_empty() {
            Vec::new()
        } else {
            vec![format!(
                "warning: {} already exists; ignoring serve initialization options for this startup: {}",
                root.display(),
                ignored.join(", ")
            )]
        };
        return Ok(ResolvedServeRuntimeSettings {
            candidate_config,
            candidate_shards: stores.len().max(1),
            workspace_mode,
            warnings,
        });
    }
    Ok(ResolvedServeRuntimeSettings {
        candidate_config: store_config_from_serve_args(args),
        candidate_shards: serve_candidate_shard_count(args),
        workspace_mode,
        warnings: Vec::new(),
    })
}

#[cfg(test)]
/// Implements the local-only `init` command used by tests and helper flows.
fn cmd_init(args: &InitArgs) -> i32 {
    match (|| -> Result<i32> {
        let outcome = ensure_local_root_initialized(args)?;
        let shard_count = outcome.shard_count;
        let stats = outcome.stats;
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
/// Implements the local-or-remote single-document indexing test command.
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
            let mut client = grpc_client(&args.connection)?;
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
            let inserted = client.insert_binary_rows(vec![row_bytes])?;
            let result = inserted
                .results
                .into_iter()
                .next()
                .ok_or_else(|| SspryError::from("binary insert returned no result row"))?;
            rpc::CandidateInsertResponse {
                status: result.status,
                doc_id: result.doc_id,
                sha256: result.sha256,
            }
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

/// Implements the local-or-remote delete command over one or more input values.
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
            let mut client = grpc_client(&args.connection)?;
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
        Ok(if any_failed { 1 } else { 0 })
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

#[cfg(test)]
/// Implements the local-only internal query command used by tests and fixtures.
fn cmd_internal_query(args: &InternalQueryArgs) -> i32 {
    match (|| -> Result<i32> {
        let Some(root) = &args.root else {
            return Err(SspryError::from(
                "internal remote query was removed; use `search`",
            ));
        };
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
        let result = if stores.len() == 1 {
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
            let searchable_doc_count = stores.iter().map(CandidateStore::live_doc_count).sum();
            let resolved_limit = resolve_max_candidates(searchable_doc_count, plan.max_candidates);
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
/// Implements the local-or-remote stats command used by tests and fixtures.
fn cmd_internal_stats(args: &InternalStatsArgs) -> i32 {
    match (|| -> Result<i32> {
        let stats = if let Some(root) = &args.root {
            let stores = open_stores(Path::new(root))?;
            serde_json::Value::Object(rpc::candidate_stats_json_for_stores(
                Path::new(root),
                &stores,
            ))
        } else {
            let mut client = grpc_client(&args.connection)?;
            let stats = client.stats()?;
            let mut map = grpc_store_summary_json_map(
                stats
                    .stats
                    .as_ref()
                    .ok_or_else(|| SspryError::from("grpc stats missing store summary"))?,
            );
            map.insert(
                "memory_budget_bytes".to_owned(),
                serde_json::json!(stats.memory_budget_bytes),
            );
            map.insert(
                "workspace_mode".to_owned(),
                serde_json::json!(stats.workspace_mode),
            );
            map.insert(
                "search_workers".to_owned(),
                serde_json::json!(stats.search_workers),
            );
            map.insert(
                "current_rss_kb".to_owned(),
                serde_json::json!(stats.current_rss_kb),
            );
            map.insert(
                "peak_rss_kb".to_owned(),
                serde_json::json!(stats.peak_rss_kb),
            );
            serde_json::Value::Object(map)
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

/// Implements the batch indexing command used by both local and remote ingest
/// wrappers.
fn cmd_internal_index_batch(args: &InternalIndexBatchArgs) -> i32 {
    match (|| -> Result<i32> {
        let root = args.root.as_deref().ok_or_else(|| {
            SspryError::from("internal remote batch indexing was removed; use `index`")
        })?;
        let started_total = Instant::now();
        let mut scan_time = Duration::ZERO;
        let result_wait_time = Duration::ZERO;
        let mut submit_time = Duration::ZERO;
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
            Some(Path::new(root)),
        );
        let workers = resolved_workers.workers;
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
            let (result_tx, result_rx) = bounded::<Result<ScannedIndexBatchRow>>(queue_capacity);
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
                while let Some(scanned) = result_rx.recv().ok() {
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
            let result_wait_ms = result_wait_time.as_secs_f64() * 1000.0;
            let submit_ms = submit_time.as_secs_f64() * 1000.0;
            eprintln!("verbose.index.total_ms: {total_ms:.3}");
            eprintln!("verbose.index.scan_ms: {scan_ms:.3}");
            eprintln!("verbose.index.worker_scan_cpu_ms: {scan_ms:.3}");
            eprintln!("verbose.index.result_wait_ms: {result_wait_ms:.3}");
            eprintln!("verbose.index.submit_ms: {submit_ms:.3}");
            eprintln!("verbose.index.batch_size: {}", batch_size);
            eprintln!("verbose.index.workers: {workers}");
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
            eprintln!("verbose.index.submitted_documents: {total_files}");
            eprintln!("verbose.index.processed_documents: {processed}");
            let (current_rss_kb, peak_rss_kb) = current_process_memory_kb();
            eprintln!("verbose.index.client_current_rss_kb: {current_rss_kb}");
            eprintln!("verbose.index.client_peak_rss_kb: {peak_rss_kb}");
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

/// Converts `local-index` arguments into the shared `init` argument shape used
/// by store initialization helpers.
fn init_args_from_local_index(args: &LocalIndexArgs) -> InitArgs {
    InitArgs {
        root: args.root.clone(),
        candidate_shards: args.candidate_shards,
        force: args.force,
        tier1_filter_target_fp: args.tier1_filter_target_fp,
        tier2_filter_target_fp: args.tier2_filter_target_fp,
        gram_sizes: args.gram_sizes.clone(),
        compaction_idle_cooldown_s: args.compaction_idle_cooldown_s,
    }
}

/// Default `index` entrypoint, currently routed through the gRPC client path.
fn cmd_index(args: &IndexArgs) -> i32 {
    cmd_grpc_index(args)
}

/// Executes remote indexing by scanning files locally, batching encoded rows,
/// and streaming them to the server.
fn cmd_grpc_index(args: &IndexArgs) -> i32 {
    match (|| -> Result<i32> {
        let started_total = Instant::now();
        let mut scan_time = Duration::ZERO;
        let mut result_wait_time = Duration::ZERO;
        let mut encode_time = Duration::ZERO;
        let mut client_buffer_time = Duration::ZERO;
        let mut submit_time = Duration::ZERO;
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
        let batch_size = grpc_remote_batch_size(args.batch_size);
        let server_policy = server_scan_policy(&args.connection)?;
        let resolved_workers =
            resolve_ingest_workers(args.workers.unwrap_or(0), total_files, &input_roots, None);
        let workers = resolved_workers.workers;
        let policy = ScanPolicy {
            fixed_filter_bytes: None,
            tier1_filter_target_fp: server_policy.tier1_filter_target_fp,
            tier2_filter_target_fp: server_policy.tier2_filter_target_fp,
            gram_sizes: server_policy.gram_sizes,
            chunk_size: DEFAULT_FILE_READ_CHUNK_SIZE,
            store_path: server_policy.store_path,
            id_source: server_policy.id_source,
        };
        let configured_budget_bytes = server_policy.memory_budget_bytes;
        let effective_budget_bytes = effective_memory_budget_bytes(configured_budget_bytes);
        let queue_capacity = index_queue_capacity(effective_budget_bytes, workers);
        let empty_payload_size = empty_remote_batch_payload_size()?;
        let remote_batch_soft_limit_bytes = grpc_remote_batch_soft_limit_bytes(
            args.remote_batch_soft_limit_bytes,
            empty_payload_size,
        );
        let remote_upload_queue_limit_bytes =
            remote_upload_queue_byte_limit(effective_budget_bytes, remote_batch_soft_limit_bytes);
        let mut pending = RemotePendingBatch {
            rows: Vec::new(),
            payload_size: empty_payload_size,
        };
        let mut base_client = grpc_client(&args.connection)?;
        base_client.set_insert_chunk_bytes(
            args.grpc_insert_chunk_bytes
                .max(1)
                .min(args.connection.max_message_bytes.max(1)),
        );
        let (index_client_id, _) =
            base_client.begin_index_client(INDEX_CLIENT_HEARTBEAT_INTERVAL_MS)?;
        let heartbeat_stop = Arc::new(AtomicBool::new(false));
        let heartbeat_error = Arc::new(Mutex::new(None::<String>));
        let mut heartbeat_client = grpc_client(&args.connection)?;
        heartbeat_client.set_insert_chunk_bytes(
            args.grpc_insert_chunk_bytes
                .max(1)
                .min(args.connection.max_message_bytes.max(1)),
        );
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
            let mut client = base_client;
            client.begin_index_session()?;
            client.update_index_session_progress(Some(total_files), 0, 0)?;

            let body_result = (|| -> Result<()> {
                if workers <= 1 {
                    stream_selected_input_files(&input_roots, args.path_list, |file_path| {
                        let started_scan = Instant::now();
                        let scanned = scan_index_batch_row(&file_path, policy)?;
                        scan_time += started_scan.elapsed();
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
                            true,
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
                        Ok(())
                    })?;
                } else {
                    let (job_tx, job_rx) = bounded::<PathBuf>(queue_capacity);
                    let (result_tx, result_rx) =
                        bounded::<Result<ScannedIndexBatchRow>>(queue_capacity);
                    let upload_queue =
                        Arc::new(RemoteUploadQueue::new(remote_upload_queue_limit_bytes));
                    thread::scope(|scope| {
                        for _worker_idx in 0..workers {
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
                                        let started_encode = Instant::now();
                                        let row_bytes =
                                            serialize_candidate_document_binary_row(&scanned.row)?;
                                        local_encode_time += started_encode.elapsed();
                                        upload_queue_consumer.push(RemoteUploadRow { row_bytes })?;
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
                                        true,
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
                        let _ = upload_queue.close();
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
                client.update_index_session_progress(Some(total_files), processed, processed)?;
                if server_policy.workspace_mode {
                    let _ = client.publish()?;
                }
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
        let mut end_client = grpc_client(&args.connection)?;
        end_client.set_insert_chunk_bytes(
            args.grpc_insert_chunk_bytes
                .max(1)
                .min(args.connection.max_message_bytes.max(1)),
        );
        let end_client_result = end_client.end_index_client(index_client_id);
        remote_result?;
        heartbeat_result?;
        end_client_result?;

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
            eprintln!("verbose.index.total_ms: {total_ms:.3}");
            eprintln!("verbose.index.scan_ms: {scan_ms:.3}");
            eprintln!("verbose.index.worker_scan_cpu_ms: {scan_ms:.3}");
            eprintln!("verbose.index.result_wait_ms: {result_wait_ms:.3}");
            eprintln!("verbose.index.encode_ms: {encode_ms:.3}");
            eprintln!("verbose.index.client_buffer_ms: {client_buffer_ms:.3}");
            eprintln!("verbose.index.submit_ms: {submit_ms:.3}");
            eprintln!("verbose.index.batch_size: {}", batch_size);
            eprintln!("verbose.index.workers: {workers}");
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
            eprintln!("verbose.index.worker_auto: {}", resolved_workers.auto);
            eprintln!(
                "verbose.index.input_storage_class: {}",
                resolved_workers.input_storage.as_str()
            );
            eprintln!(
                "verbose.index.output_storage_class: {}",
                resolved_workers.output_storage.as_str()
            );
            eprintln!("verbose.index.submitted_documents: {total_files}");
            eprintln!("verbose.index.processed_documents: {processed}");
            let (client_current_rss_kb, client_peak_rss_kb) = current_process_memory_kb();
            eprintln!("verbose.index.client_current_rss_kb: {client_current_rss_kb}");
            eprintln!("verbose.index.client_peak_rss_kb: {client_peak_rss_kb}");
            if let Ok(mut status_client) = grpc_client(&args.connection) {
                if let Ok(status) = status_client.status() {
                    let stats = grpc_status_output_json(&status, true);
                    if let Some(stats) = stats.as_object() {
                        if let Some(value) =
                            stats.get("current_rss_kb").and_then(|value| value.as_u64())
                        {
                            eprintln!("verbose.index.server_current_rss_kb: {value}");
                        }
                        if let Some(value) =
                            stats.get("peak_rss_kb").and_then(|value| value.as_u64())
                        {
                            eprintln!("verbose.index.server_peak_rss_kb: {value}");
                        }
                        let stats_scope = stats
                            .get("work")
                            .and_then(serde_json::Value::as_object)
                            .unwrap_or(stats);
                        for (key, label) in
                            [("disk_usage_bytes", "verbose.index.server_disk_usage_bytes")]
                        {
                            if let Some(value) =
                                stats_scope.get(key).and_then(|value| value.as_u64())
                            {
                                eprintln!("{label}: {value}");
                            }
                        }
                        if let Some(publish) =
                            stats.get("publish").and_then(serde_json::Value::as_object)
                        {
                            for (key, label) in [
                                ("pending", "verbose.index.server_publish_pending"),
                                ("eligible", "verbose.index.server_publish_eligible"),
                            ] {
                                if let Some(value) =
                                    publish.get(key).and_then(|value| value.as_bool())
                                {
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
                                    "recent_publish_p95_ms",
                                    "verbose.index.server_publish_adaptive_recent_publish_p95_ms",
                                ),
                                (
                                    "recent_submit_p95_ms",
                                    "verbose.index.server_publish_adaptive_recent_submit_p95_ms",
                                ),
                                (
                                    "recent_store_p95_ms",
                                    "verbose.index.server_publish_adaptive_recent_store_p95_ms",
                                ),
                                (
                                    "recent_publishes_in_window",
                                    "verbose.index.server_publish_adaptive_recent_publishes_in_window",
                                ),
                                (
                                    "tier2_pending_shards",
                                    "verbose.index.server_publish_adaptive_tier2_pending_shards",
                                ),
                                (
                                    "healthy_cycles",
                                    "verbose.index.server_publish_adaptive_healthy_cycles",
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
                                    "last_publish_promote_work_ms",
                                    "verbose.index.server_last_publish_promote_work_ms",
                                ),
                                (
                                    "last_publish_init_work_ms",
                                    "verbose.index.server_last_publish_init_work_ms",
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
                                if let Some(value) =
                                    publish.get(key).and_then(|value| value.as_i64())
                                {
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
                                eprintln!(
                                    "verbose.index.server_last_publish_reused_work_stores: {value}"
                                );
                            }
                        }
                        if let Some(adaptive) = stats
                            .get("adaptive_publish")
                            .and_then(serde_json::Value::as_object)
                        {
                            for (key, label) in [
                                ("mode", "verbose.index.server_publish_adaptive_mode"),
                                ("reason", "verbose.index.server_publish_adaptive_reason"),
                                (
                                    "storage_class",
                                    "verbose.index.server_publish_adaptive_storage_class",
                                ),
                            ] {
                                if let Some(value) =
                                    adaptive.get(key).and_then(serde_json::Value::as_str)
                                {
                                    eprintln!("{label}: {value}");
                                }
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
                                eprintln!(
                                    "verbose.index.server_index_progress_percent: {value:.3}"
                                );
                            }
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

/// Implements the high-level local indexing command by initializing the store
/// and delegating to batch indexing.
fn cmd_local_index(args: &LocalIndexArgs) -> i32 {
    match ensure_local_root_initialized(&init_args_from_local_index(args)) {
        Ok(_) => cmd_internal_index_batch(&InternalIndexBatchArgs {
            paths: args.paths.clone(),
            path_list: args.path_list,
            root: Some(args.root.clone()),
            batch_size: args.batch_size,
            workers: args.workers.unwrap_or(0),
            chunk_size: DEFAULT_FILE_READ_CHUNK_SIZE,
            verbose: args.verbose,
        }),
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

/// Top-level delete entrypoint, currently routed through the gRPC delete path.
fn cmd_delete(args: &DeleteArgs) -> i32 {
    cmd_grpc_delete(args)
}

/// Implements the remote delete command against the running server.
fn cmd_grpc_delete(args: &DeleteArgs) -> i32 {
    match (|| -> Result<i32> {
        let server_policy = server_scan_policy(&args.connection)?;
        let mut client = grpc_client(&args.connection)?;
        let mut exit_code = 0;
        for value in &args.values {
            match (|| -> Result<()> {
                let sha256_hex = resolve_delete_value(
                    value,
                    server_policy.id_source,
                    DEFAULT_FILE_READ_CHUNK_SIZE,
                )?;
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

/// Implements the local delete wrapper by delegating to the internal delete
/// path.
fn cmd_local_delete(args: &LocalDeleteArgs) -> i32 {
    cmd_internal_delete(&InternalDeleteArgs {
        connection: placeholder_connection(),
        root: Some(args.root.clone()),
        values: args.values.clone(),
    })
}

/// Implements the rule-check command and renders either JSON or human-readable
/// output.
fn cmd_rule_check(args: &RuleCheckArgs) -> i32 {
    match (|| -> Result<i32> {
        let policy = rule_check_policy(args)?;
        let report = rule_check_all_from_file_with_gram_sizes_and_identity_source(
            &args.rule,
            policy.gram_sizes,
            Some(policy.id_source.as_str()),
            args.max_anchors_per_pattern,
            false,
            true,
            10.0,
        )?;
        let exit_code = if report.status == crate::candidate::RuleCheckStatus::Unsupported {
            1
        } else {
            0
        };
        let output = rule_check_output(policy, report);
        if args.json {
            println!("{}", serde_json::to_string_pretty(&output)?);
        } else {
            print_rule_check_output(&output);
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

/// Drains a streaming search response into one deduplicated `SearchExecution`
/// summary, optionally preserving external ids for verification.
fn collect_streamed_search_execution<F>(
    args: &SearchCommandArgs,
    plan: CompiledQueryPlan,
    plan_time: Duration,
    server_rss_kb: Option<(u64, u64)>,
    mut pump: F,
) -> Result<SearchExecution>
where
    F: FnMut(&mut dyn FnMut(rpc::CandidateQueryStreamFrame) -> Result<()>) -> Result<()>,
{
    let started_query = Instant::now();
    let mut buffered_rows = Vec::<String>::new();
    let mut buffered_external_ids = Vec::<Option<String>>::new();
    let mut accepted_positions = HashMap::<String, usize>::new();
    let mut query_profile = CandidateQueryProfile::default();
    let mut prepared_query_profile = CandidatePreparedQueryProfile::default();
    let mut total_candidates = 0usize;
    let mut tier_used = String::new();
    let mut truncated = false;
    let mut truncated_limit = None::<usize>;
    pump(&mut |frame| {
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
        if args.verify_yara_files && frame_external_ids.len() < frame.sha256.len() {
            frame_external_ids.resize(frame.sha256.len(), None);
        }
        for (idx, sha256) in frame.sha256.into_iter().enumerate() {
            let external_id = if args.verify_yara_files {
                frame_external_ids.get(idx).cloned().flatten()
            } else {
                None
            };
            if let Some(existing_idx) = accepted_positions.get(&sha256).copied() {
                if args.verify_yara_files
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
            total_candidates = total_candidates.saturating_add(1);
            buffered_rows.push(sha256);
            if args.verify_yara_files {
                buffered_external_ids.push(external_id);
            }
        }
        Ok(())
    })?;
    Ok(SearchExecution {
        plan,
        total_candidates,
        tier_used,
        truncated,
        truncated_limit,
        rows: buffered_rows,
        query_profile,
        prepared_query_profile,
        external_ids: buffered_external_ids,
        tree_count: None,
        tree_search_workers: None,
        server_rss_kb,
        plan_time,
        query_time: started_query.elapsed(),
    })
}

/// Converts the gRPC wire frame into the internal streaming frame used by the
/// shared search-collection path.
fn grpc_search_frame_to_internal(frame: grpc::GrpcSearchFrame) -> rpc::CandidateQueryStreamFrame {
    rpc::CandidateQueryStreamFrame {
        sha256: frame.sha256,
        external_ids: Some(frame.external_ids),
        candidate_limit: frame.candidate_limit,
        stream_complete: frame.stream_complete,
        tier_used: frame.tier_used,
        query_profile: frame.query_profile,
        prepared_query_profile: frame.prepared_query_profile,
    }
}

/// Executes a remote search by compiling the rule against the server policy and
/// draining the streamed result frames.
fn execute_grpc_search(args: &SearchCommandArgs) -> Result<SearchExecution> {
    let started_plan = Instant::now();
    let mut client = search_grpc_client(&args.connection)?;
    let server_policy = server_scan_policy(&args.connection)?;
    let rule_text = fs::read_to_string(&args.rule)?;
    let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
        &args.rule,
        server_policy.gram_sizes,
        Some(server_policy.id_source.as_str()),
        args.max_anchors_per_pattern,
        false,
        true,
        args.max_candidates,
    )?;
    let plan_time = started_plan.elapsed();
    collect_streamed_search_execution(args, plan, plan_time, None, |on_frame| {
        client.search_stream(
            grpc::v1::SearchRequest {
                yara_rule_source: rule_text.clone(),
                chunk_size: DEFAULT_SEARCH_RESULT_CHUNK_SIZE as u32,
                include_external_ids: args.verify_yara_files,
                max_candidates_percent: args.max_candidates,
                max_anchors_per_pattern: args.max_anchors_per_pattern as u32,
                force_tier1_only: false,
                allow_tier2_fallback: true,
            },
            |frame| on_frame(grpc_search_frame_to_internal(frame)),
        )
    })
}

/// Executes a local forest search by compiling once, preparing the shared plan
/// artifacts, and scanning every tree group.
fn execute_local_search(args: &LocalSearchArgs) -> Result<SearchExecution> {
    let started_plan = Instant::now();
    let mut tree_groups = open_forest_tree_groups(Path::new(&args.root))?;
    let tree_count = tree_groups.len();
    let (gram_sizes, active_identity_source, summary_cap_bytes) =
        validate_forest_search_policy(&tree_groups)?;
    let worker_count = args
        .tree_search_workers
        .max(1)
        .min(tree_groups.len().max(1));
    let plan = compile_query_plan_from_file_with_gram_sizes_and_identity_source(
        &args.rule,
        gram_sizes,
        active_identity_source.as_deref(),
        args.max_anchors_per_pattern,
        false,
        true,
        args.max_candidates,
    )?;
    let plan_time = started_plan.elapsed();
    let started_query = Instant::now();
    let prepared_query_profile =
        forest_prepared_query_profile(&tree_groups, &plan, summary_cap_bytes)?;
    let local = query_local_forest_all_candidates(
        &mut tree_groups,
        &plan,
        args.verify_yara_files,
        worker_count,
    )?;
    let query_time = started_query.elapsed();
    Ok(SearchExecution {
        plan,
        total_candidates: local.total_candidates,
        tier_used: local.tier_used,
        truncated: local.truncated,
        truncated_limit: local.truncated_limit,
        rows: local.hashes,
        query_profile: local.query_profile,
        prepared_query_profile,
        external_ids: local.external_ids.unwrap_or_default(),
        tree_count: Some(tree_count),
        tree_search_workers: Some(worker_count),
        server_rss_kb: None,
        plan_time,
        query_time,
    })
}

/// Finalizes a search execution by optionally verifying candidates, printing
/// the result rows, and emitting verbose timing and memory diagnostics.
fn finish_search_execution(
    rule: &str,
    verify_yara_files: bool,
    verbose: bool,
    max_candidates: f64,
    max_anchors_per_pattern: usize,
    started_total: Instant,
    execution: SearchExecution,
) -> Result<i32> {
    let started_verify = Instant::now();
    let verification = verify_search_candidates(
        Path::new(rule),
        &execution.plan,
        execution.rows,
        execution.external_ids,
        verify_yara_files,
    )?;
    let verify_time = started_verify.elapsed();
    let SearchVerificationResult {
        rows,
        verified_checked,
        verified_matched,
        verified_skipped,
    } = verification;

    println!("tier_used: {}", execution.tier_used);
    println!("candidates: {}", execution.total_candidates);
    println!("truncated: {}", execution.truncated);
    if let Some(limit) = execution.truncated_limit {
        println!("truncated_limit: {limit}");
    }
    if verify_yara_files {
        println!("verified_checked: {verified_checked}");
        println!("verified_matched: {verified_matched}");
        println!("verified_skipped: {verified_skipped}");
    }
    for row in rows {
        println!("{row}");
    }
    if verbose {
        let total_ms = started_total.elapsed().as_secs_f64() * 1000.0;
        let plan_ms = execution.plan_time.as_secs_f64() * 1000.0;
        let query_ms = execution.query_time.as_secs_f64() * 1000.0;
        let verify_ms = verify_time.as_secs_f64() * 1000.0;
        eprintln!("verbose.search.total_ms: {total_ms:.3}");
        eprintln!("verbose.search.plan_ms: {plan_ms:.3}");
        eprintln!("verbose.search.query_ms: {query_ms:.3}");
        eprintln!("verbose.search.verify_ms: {verify_ms:.3}");
        eprintln!(
            "verbose.search.docs_scanned: {}",
            execution.query_profile.docs_scanned
        );
        eprintln!(
            "verbose.search.metadata_loads: {}",
            execution.query_profile.metadata_loads
        );
        eprintln!(
            "verbose.search.metadata_bytes: {}",
            execution.query_profile.metadata_bytes
        );
        eprintln!(
            "verbose.search.tier1_bloom_loads: {}",
            execution.query_profile.tier1_bloom_loads
        );
        eprintln!(
            "verbose.search.tier1_bloom_bytes: {}",
            execution.query_profile.tier1_bloom_bytes
        );
        eprintln!(
            "verbose.search.tier2_bloom_loads: {}",
            execution.query_profile.tier2_bloom_loads
        );
        eprintln!(
            "verbose.search.tier2_bloom_bytes: {}",
            execution.query_profile.tier2_bloom_bytes
        );
        eprintln!(
            "verbose.search.prepared_query_bytes: {}",
            execution.prepared_query_profile.prepared_query_bytes
        );
        eprintln!(
            "verbose.search.prepared_pattern_plan_bytes: {}",
            execution.prepared_query_profile.prepared_pattern_plan_bytes
        );
        eprintln!(
            "verbose.search.prepared_mask_cache_bytes: {}",
            execution.prepared_query_profile.prepared_mask_cache_bytes
        );
        eprintln!(
            "verbose.search.prepared_pattern_count: {}",
            execution.prepared_query_profile.pattern_count
        );
        eprintln!(
            "verbose.search.prepared_mask_cache_entries: {}",
            execution.prepared_query_profile.mask_cache_entries
        );
        eprintln!(
            "verbose.search.prepared_fixed_literal_count: {}",
            execution.prepared_query_profile.fixed_literal_count
        );
        eprintln!(
            "verbose.search.prepared_tier1_alternatives: {}",
            execution.prepared_query_profile.tier1_alternatives
        );
        eprintln!(
            "verbose.search.prepared_tier2_alternatives: {}",
            execution.prepared_query_profile.tier2_alternatives
        );
        eprintln!(
            "verbose.search.prepared_tier1_shift_variants: {}",
            execution.prepared_query_profile.tier1_shift_variants
        );
        eprintln!(
            "verbose.search.prepared_tier2_shift_variants: {}",
            execution.prepared_query_profile.tier2_shift_variants
        );
        eprintln!(
            "verbose.search.prepared_tier1_any_lane_alternatives: {}",
            execution.prepared_query_profile.tier1_any_lane_alternatives
        );
        eprintln!(
            "verbose.search.prepared_tier2_any_lane_alternatives: {}",
            execution.prepared_query_profile.tier2_any_lane_alternatives
        );
        eprintln!(
            "verbose.search.prepared_tier1_compacted_any_lane_alternatives: {}",
            execution
                .prepared_query_profile
                .tier1_compacted_any_lane_alternatives
        );
        eprintln!(
            "verbose.search.prepared_tier2_compacted_any_lane_alternatives: {}",
            execution
                .prepared_query_profile
                .tier2_compacted_any_lane_alternatives
        );
        eprintln!(
            "verbose.search.prepared_any_lane_variant_sets: {}",
            execution.prepared_query_profile.any_lane_variant_sets
        );
        eprintln!(
            "verbose.search.prepared_compacted_any_lane_grams: {}",
            execution.prepared_query_profile.compacted_any_lane_grams
        );
        eprintln!(
            "verbose.search.prepared_max_pattern_bytes: {}",
            execution.prepared_query_profile.max_pattern_bytes
        );
        eprintln!(
            "verbose.search.prepared_impossible_query: {}",
            execution.prepared_query_profile.impossible_query
        );
        if let Some(max_pattern_id) = &execution.prepared_query_profile.max_pattern_id {
            eprintln!("verbose.search.prepared_max_pattern_id: {max_pattern_id}");
        }
        eprintln!("verbose.search.max_candidates: {max_candidates}");
        eprintln!("verbose.search.max_anchors_per_pattern: {max_anchors_per_pattern}");
        eprintln!("verbose.search.candidates: {}", execution.total_candidates);
        eprintln!("verbose.search.verify_enabled: {verify_yara_files}");
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
        if let Some((server_current_rss_kb, server_peak_rss_kb)) = execution.server_rss_kb {
            eprintln!("verbose.search.server_current_rss_kb: {server_current_rss_kb}");
            eprintln!("verbose.search.server_peak_rss_kb: {server_peak_rss_kb}");
        }
        if let Some(tree_count) = execution.tree_count {
            eprintln!("verbose.search.tree_count: {tree_count}");
        }
        if let Some(tree_search_workers) = execution.tree_search_workers {
            eprintln!("verbose.search.tree_search_workers: {tree_search_workers}");
        }
        if verify_yara_files {
            eprintln!("verbose.search.verified_checked: {verified_checked}");
            eprintln!("verbose.search.verified_matched: {verified_matched}");
            eprintln!("verbose.search.verified_skipped: {verified_skipped}");
        }
    }
    Ok(0)
}

/// Default `search` entrypoint, currently routed through the gRPC client path.
fn cmd_search(args: &SearchCommandArgs) -> i32 {
    cmd_grpc_search(args)
}

/// Runs the remote `search` command and prints any resulting candidates.
fn cmd_grpc_search(args: &SearchCommandArgs) -> i32 {
    match (|| -> Result<i32> {
        let started_total = Instant::now();
        let execution = execute_grpc_search(args)?;
        finish_search_execution(
            &args.rule,
            args.verify_yara_files,
            args.verbose,
            args.max_candidates,
            args.max_anchors_per_pattern,
            started_total,
            execution,
        )
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

/// Runs the local forest `search` command and prints any resulting candidates.
fn cmd_local_search(args: &LocalSearchArgs) -> i32 {
    match (|| -> Result<i32> {
        let started_total = Instant::now();
        let execution = execute_local_search(args)?;
        finish_search_execution(
            &args.rule,
            args.verify_yara_files,
            args.verbose,
            args.max_candidates,
            args.max_anchors_per_pattern,
            started_total,
            execution,
        )
    })() {
        Ok(code) => code,
        Err(err) => {
            println!("{err}");
            1
        }
    }
}

/// Resolves the search-batch rule list from either a directory scan or a
/// manifest file.
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

/// Executes `search-batch`, writing one JSON record per rule plus a JSONL
/// stream for incremental consumption.
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

/// Default `info` entrypoint, currently routed through the gRPC client path.
fn cmd_info(args: &InfoCommandArgs) -> i32 {
    cmd_grpc_info(args)
}

/// Queries a remote server for status and prints the response as JSON.
fn cmd_grpc_info(args: &InfoCommandArgs) -> i32 {
    match (|| -> Result<i32> {
        let mut client = grpc_client(&args.connection)?;
        let status = client.status()?;
        println!(
            "{}",
            serde_json::to_string_pretty(&grpc_status_output_json(&status, !args.light))?
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

/// Loads local store or forest stats directly from disk and prints the result
/// as JSON.
fn cmd_local_info(args: &LocalInfoArgs) -> i32 {
    match (|| -> Result<i32> {
        let root = Path::new(&args.root);
        let stats = if root.is_dir()
            && fs::read_dir(root)
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
                .unwrap_or(false)
        {
            let tree_groups = open_forest_tree_groups(root)?;
            let stores = tree_groups
                .into_iter()
                .flat_map(|group| group.stores)
                .collect::<Vec<_>>();
            serde_json::Value::Object(rpc::candidate_stats_json_for_stores(root, &stores))
        } else {
            let stores = open_stores(root)?;
            serde_json::Value::Object(rpc::candidate_stats_json_for_stores(root, &stores))
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

/// Default `shutdown` entrypoint, currently routed through the gRPC client
/// path.
fn cmd_shutdown(args: &ShutdownArgs) -> i32 {
    cmd_grpc_shutdown(args)
}

/// Sends the remote shutdown RPC and prints the server response.
fn cmd_grpc_shutdown(args: &ShutdownArgs) -> i32 {
    match (|| -> Result<i32> {
        let mut client = grpc_client(&args.connection)?;
        let response = client.shutdown()?;
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

include!("app/cli.rs");
#[cfg(test)]
mod tests;

/// Parses CLI arguments, configures perf reporting, dispatches the selected
/// command, and flushes perf output before exiting.
pub fn main(argv: Option<Vec<String>>) -> i32 {
    let argv_values = argv.unwrap_or_else(|| std::env::args().collect::<Vec<_>>());
    let cli = Cli::parse_from(argv_values.clone());
    perf::configure(cli.perf_report.as_ref().map(PathBuf::from), cli.perf_stdout);

    let exit_code = match cli.command {
        Commands::Serve(args) => {
            cmd_serve_with_sources(&args, serve_init_option_sources_from_argv(&argv_values))
        }
        Commands::Index(args) => cmd_index(&args),
        Commands::LocalIndex(args) => cmd_local_index(&args),
        Commands::Delete(args) => cmd_delete(&args),
        Commands::LocalDelete(args) => cmd_local_delete(&args),
        Commands::RuleCheck(args) => cmd_rule_check(&args),
        Commands::Search(args) => cmd_search(&args),
        Commands::LocalSearch(args) => cmd_local_search(&args),
        Commands::SearchBatch(args) => cmd_search_batch(&args),
        Commands::Info(args) => cmd_info(&args),
        Commands::LocalInfo(args) => cmd_local_info(&args),
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
