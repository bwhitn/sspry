use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, TryLockError};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::candidate::store::{
    CandidateCompactionResult, CandidateCompactionSnapshot, CandidateImportBatchProfile,
    CandidateInsertBatchProfile, CandidateStoreOpenProfile, PreparedQueryArtifacts,
    build_prepared_query_artifacts, cleanup_abandoned_compaction_roots, compaction_work_root,
    write_compacted_snapshot,
};
use crate::candidate::{
    BoundedCache, CandidateConfig, CandidateQueryProfile, CandidateStore, CompiledQueryPlan,
    PatternPlan, QueryNode, candidate_shard_index, candidate_shard_root, metadata_field_is_boolean,
    metadata_field_is_integer, normalize_max_candidates, normalize_query_metadata_field,
    read_candidate_shard_count, write_candidate_shard_count,
};
use crate::perf::{record_counter, scope};
use crate::{Result, SspryError};

pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: u16 = 17653;
pub const DEFAULT_RPC_TIMEOUT: f64 = 30.0;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;

const PROTOCOL_VERSION: u8 = 1;
const STATUS_OK: u8 = 0;
const STATUS_ERROR: u8 = 1;
const HEADER_LEN: usize = 6;

const ACTION_PING: u8 = 1;
const ACTION_CANDIDATE_INSERT: u8 = 2;
const ACTION_CANDIDATE_INSERT_BATCH: u8 = 3;
const ACTION_CANDIDATE_DELETE: u8 = 4;
const ACTION_CANDIDATE_QUERY: u8 = 5;
const ACTION_CANDIDATE_STATS: u8 = 6;
const ACTION_SHUTDOWN: u8 = 8;
const ACTION_PUBLISH: u8 = 9;
const ACTION_INDEX_SESSION_BEGIN: u8 = 10;
const ACTION_INDEX_SESSION_END: u8 = 11;
const ACTION_INDEX_SESSION_PROGRESS: u8 = 12;
const ACTION_CANDIDATE_STATUS: u8 = 13;
const TEMPORARY_PUBLISH_RETRY_LIMIT: usize = 400;
const TEMPORARY_PUBLISH_RETRY_SLEEP_MS: u64 = 50;

const DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE: usize = 128;
const QUERY_CACHE_CAPACITY: usize = 64;
const DEFAULT_CANDIDATE_SHARD_LOCK_TIMEOUT_MS: u64 = 1000;
const CANDIDATE_SHARD_LOCK_POLL_INTERVAL_MS: u64 = 10;
pub const DEFAULT_AUTO_PUBLISH_IDLE_MS: u64 = 5_000;
const DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP: usize = 1;

fn lock_candidate_store_with_timeout<'a>(
    store_lock: &'a Mutex<CandidateStore>,
    shard_idx: usize,
    operation: &str,
) -> Result<MutexGuard<'a, CandidateStore>> {
    let timeout = Duration::from_millis(DEFAULT_CANDIDATE_SHARD_LOCK_TIMEOUT_MS);
    let deadline = Instant::now() + timeout;
    loop {
        match store_lock.try_lock() {
            Ok(guard) => return Ok(guard),
            Err(TryLockError::Poisoned(_)) => {
                return Err(SspryError::from("Candidate store lock poisoned."));
            }
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(SspryError::from(format!(
                        "candidate shard {shard_idx} busy during {operation}; retry later"
                    )));
                }
                thread::sleep(Duration::from_millis(CANDIDATE_SHARD_LOCK_POLL_INTERVAL_MS));
            }
        }
    }
}

fn lock_candidate_store_blocking<'a>(
    store_lock: &'a Mutex<CandidateStore>,
) -> Result<MutexGuard<'a, CandidateStore>> {
    store_lock
        .lock()
        .map_err(|_| SspryError::from("Candidate store lock poisoned."))
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

#[derive(Clone, Debug)]
pub struct ClientConfig {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub socket_path: Option<PathBuf>,
}

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub candidate_config: CandidateConfig,
    pub candidate_shards: usize,
    pub search_workers: usize,
    pub memory_budget_bytes: u64,
    pub tier2_superblock_budget_divisor: u64,
    pub auto_publish_initial_idle_ms: u64,
    pub auto_publish_storage_class: String,
    pub workspace_mode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateInsertResponse {
    pub status: String,
    pub doc_id: u64,
    pub sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateInsertBatchResponse {
    pub inserted_count: usize,
    pub results: Vec<CandidateInsertResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateDeleteResponse {
    pub status: String,
    pub sha256: String,
    pub doc_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateQueryResponse {
    pub sha256: Vec<String>,
    pub total_candidates: usize,
    pub returned_count: usize,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
    pub tier_used: String,
    #[serde(default)]
    pub query_profile: CandidateQueryProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ids: Option<Vec<Option<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateDocumentWire {
    pub sha256: String,
    pub file_size: u64,
    pub bloom_filter_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bloom_item_estimate: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier2_bloom_filter_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier2_bloom_item_estimate: Option<i64>,
    #[serde(default)]
    pub special_population: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub metadata_b64: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateDeleteRequest {
    sha256: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateInsertBatchRequest {
    documents: Vec<CandidateDocumentWire>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateQueryRequest {
    plan: Value,
    #[serde(default)]
    cursor: usize,
    chunk_size: Option<usize>,
    #[serde(default)]
    include_external_ids: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidatePublishResponse {
    message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateIndexSessionResponse {
    message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateIndexSessionProgressRequest {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    total_documents: Option<u64>,
    #[serde(default)]
    submitted_documents: u64,
    #[serde(default)]
    processed_documents: u64,
}

type ParsedCandidateInsertDocument = (
    [u8; 32],
    u64,
    Option<usize>,
    Vec<u8>,
    Option<usize>,
    Vec<u8>,
    bool,
    Vec<u8>,
    Option<String>,
);

#[derive(Debug)]
struct StoreSet {
    root: Mutex<PathBuf>,
    stores: Vec<Mutex<CandidateStore>>,
    stats_cache: Mutex<Option<CachedStoreSetStats>>,
}

#[derive(Clone, Debug)]
struct CachedStoreSetStats {
    stats: Map<String, Value>,
    deleted_storage_bytes: u64,
}

impl StoreSet {
    fn new(root: PathBuf, stores: Vec<CandidateStore>) -> Self {
        Self {
            root: Mutex::new(root),
            stores: stores.into_iter().map(Mutex::new).collect(),
            stats_cache: Mutex::new(None),
        }
    }

    #[cfg(test)]
    fn into_stores(self) -> Result<Vec<CandidateStore>> {
        self.stores
            .into_iter()
            .map(|store| {
                store
                    .into_inner()
                    .map_err(|_| SspryError::from("Candidate store lock poisoned."))
            })
            .collect()
    }

    fn root(&self) -> Result<PathBuf> {
        self.root
            .lock()
            .map(|root| root.clone())
            .map_err(|_| SspryError::from("Store set root lock poisoned."))
    }

    fn retarget_root(&self, root: &Path, shard_count: usize) -> Result<()> {
        {
            let mut current_root = self
                .root
                .lock()
                .map_err(|_| SspryError::from("Store set root lock poisoned."))?;
            *current_root = root.to_path_buf();
        }
        for (shard_idx, store_lock) in self.stores.iter().enumerate() {
            let mut store = lock_candidate_store_with_timeout(
                store_lock,
                shard_idx,
                "retarget published work root",
            )?;
            store.retarget_root(candidate_shard_root(root, shard_count, shard_idx));
        }
        let mut cache = self
            .stats_cache
            .lock()
            .map_err(|_| SspryError::from("Store set stats cache lock poisoned."))?;
        *cache = None;
        Ok(())
    }

    fn cached_stats(&self) -> Result<Option<(Map<String, Value>, u64)>> {
        let cache = self
            .stats_cache
            .lock()
            .map_err(|_| SspryError::from("Store set stats cache lock poisoned."))?;
        Ok(cache
            .as_ref()
            .map(|entry| (entry.stats.clone(), entry.deleted_storage_bytes)))
    }

    fn set_cached_stats(
        &self,
        stats: Map<String, Value>,
        deleted_storage_bytes: u64,
    ) -> Result<()> {
        let mut cache = self
            .stats_cache
            .lock()
            .map_err(|_| SspryError::from("Store set stats cache lock poisoned."))?;
        *cache = Some(CachedStoreSetStats {
            stats,
            deleted_storage_bytes,
        });
        Ok(())
    }

    fn invalidate_stats_cache(&self) -> Result<()> {
        let mut cache = self
            .stats_cache
            .lock()
            .map_err(|_| SspryError::from("Store set stats cache lock poisoned."))?;
        *cache = None;
        Ok(())
    }
}

#[derive(Debug)]
enum StoreMode {
    Direct {
        stores: Arc<StoreSet>,
    },
    Workspace {
        root: PathBuf,
        published: Arc<StoreSet>,
        work_active: Arc<StoreSet>,
        work_idle: Option<Arc<StoreSet>>,
    },
}

#[derive(Debug)]
struct ServerState {
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    operation_gate: RwLock<()>,
    store_mode: Mutex<StoreMode>,
    publish_requested: AtomicBool,
    mutations_paused: AtomicBool,
    publish_in_progress: AtomicBool,
    active_mutations: AtomicUsize,
    active_index_sessions: AtomicUsize,
    work_dirty: AtomicBool,
    work_active_estimated_documents: AtomicU64,
    work_active_estimated_input_bytes: AtomicU64,
    index_backpressure_events_total: AtomicU64,
    index_backpressure_sleep_ms_total: AtomicU64,
    last_index_backpressure_delay_ms: AtomicU64,
    last_work_mutation_unix_ms: AtomicU64,
    index_session_total_documents: AtomicU64,
    index_session_submitted_documents: AtomicU64,
    index_session_processed_documents: AtomicU64,
    index_session_started_unix_ms: AtomicU64,
    index_session_last_update_unix_ms: AtomicU64,
    index_session_server_insert_batch_count: AtomicU64,
    index_session_server_insert_batch_documents: AtomicU64,
    index_session_server_insert_batch_shards_touched: AtomicU64,
    index_session_server_insert_batch_total_us: AtomicU64,
    index_session_server_insert_batch_parse_us: AtomicU64,
    index_session_server_insert_batch_group_us: AtomicU64,
    index_session_server_insert_batch_build_us: AtomicU64,
    index_session_server_insert_batch_store_us: AtomicU64,
    index_session_server_insert_batch_finalize_us: AtomicU64,
    index_session_server_insert_batch_store_resolve_doc_state_us: AtomicU64,
    index_session_server_insert_batch_store_append_sidecars_us: AtomicU64,
    index_session_server_insert_batch_store_append_sidecar_payloads_us: AtomicU64,
    index_session_server_insert_batch_store_append_bloom_payload_assemble_us: AtomicU64,
    index_session_server_insert_batch_store_append_bloom_payload_us: AtomicU64,
    index_session_server_insert_batch_store_append_metadata_payload_us: AtomicU64,
    index_session_server_insert_batch_store_append_external_id_payload_us: AtomicU64,
    index_session_server_insert_batch_store_append_tier2_bloom_payload_us: AtomicU64,
    index_session_server_insert_batch_store_append_doc_row_build_us: AtomicU64,
    index_session_server_insert_batch_store_append_bloom_payload_bytes: AtomicU64,
    index_session_server_insert_batch_store_append_metadata_payload_bytes: AtomicU64,
    index_session_server_insert_batch_store_append_external_id_payload_bytes: AtomicU64,
    index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes: AtomicU64,
    index_session_server_insert_batch_store_append_doc_records_us: AtomicU64,
    index_session_server_insert_batch_store_write_existing_us: AtomicU64,
    index_session_server_insert_batch_store_install_docs_us: AtomicU64,
    index_session_server_insert_batch_store_tier2_update_us: AtomicU64,
    index_session_server_insert_batch_store_persist_meta_us: AtomicU64,
    index_session_server_insert_batch_store_rebalance_tier2_us: AtomicU64,
    last_publish_started_unix_ms: AtomicU64,
    last_publish_completed_unix_ms: AtomicU64,
    last_publish_duration_ms: AtomicU64,
    last_publish_lock_wait_ms: AtomicU64,
    last_publish_swap_ms: AtomicU64,
    last_publish_promote_work_ms: AtomicU64,
    last_publish_promote_work_export_ms: AtomicU64,
    last_publish_promote_work_import_ms: AtomicU64,
    last_publish_promote_work_import_resolve_doc_state_ms: AtomicU64,
    last_publish_promote_work_import_build_payloads_ms: AtomicU64,
    last_publish_promote_work_import_append_sidecars_ms: AtomicU64,
    last_publish_promote_work_import_install_docs_ms: AtomicU64,
    last_publish_promote_work_import_tier2_update_ms: AtomicU64,
    last_publish_promote_work_import_persist_meta_ms: AtomicU64,
    last_publish_promote_work_import_rebalance_tier2_ms: AtomicU64,
    last_publish_promote_work_remove_work_root_ms: AtomicU64,
    last_publish_promote_work_other_ms: AtomicU64,
    last_publish_promote_work_imported_docs: AtomicU64,
    last_publish_promote_work_imported_shards: AtomicU64,
    last_publish_init_work_ms: AtomicU64,
    last_publish_persist_tier2_superblocks_ms: AtomicU64,
    last_publish_tier2_snapshot_persist_failures: AtomicU64,
    last_publish_persisted_snapshot_shards: AtomicU64,
    last_publish_reused_work_stores: AtomicBool,
    publish_runs_total: AtomicU64,
    pending_published_tier2_snapshot_shards: Mutex<HashSet<usize>>,
    published_tier2_snapshot_seal_in_progress: AtomicBool,
    published_tier2_snapshot_seal_runs_total: AtomicU64,
    last_published_tier2_snapshot_seal_duration_ms: AtomicU64,
    last_published_tier2_snapshot_seal_persisted_shards: AtomicU64,
    last_published_tier2_snapshot_seal_failures: AtomicU64,
    last_published_tier2_snapshot_seal_completed_unix_ms: AtomicU64,
    adaptive_publish: Mutex<AdaptivePublishState>,
    normalized_plan_cache: Mutex<BoundedCache<String, Arc<CompiledQueryPlan>>>,
    prepared_plan_cache: Mutex<BoundedCache<String, Arc<PreparedQueryArtifacts>>>,
    query_cache: Mutex<BoundedCache<String, Arc<CachedCandidateQuery>>>,
    compaction_runtime: Mutex<CompactionRuntime>,
    next_compaction_shard: AtomicUsize,
    active_connections: AtomicUsize,
    startup_cleanup_removed_roots: usize,
    startup_profile: StartupProfile,
}

#[derive(Clone, Debug)]
struct CachedCandidateQuery {
    ordered_hashes: Vec<String>,
    tier_used: String,
    query_profile: CandidateQueryProfile,
}

#[derive(Clone, Debug, Default)]
struct CompactionRuntime {
    running_shard: Option<usize>,
    runs_total: u64,
    mutation_retries_total: u64,
    last_reclaimed_docs: usize,
    last_reclaimed_bytes: u64,
    last_completed_unix_ms: Option<u64>,
    last_error: Option<String>,
}

#[derive(Clone, Debug, Default)]
struct StoreRootStartupProfile {
    total_ms: u64,
    opened_existing_shards: u64,
    initialized_new_shards: u64,
    doc_count: u64,
    store_open_total_ms: u64,
    store_open_manifest_ms: u64,
    store_open_meta_ms: u64,
    store_open_load_state_ms: u64,
    store_open_sidecars_ms: u64,
    store_open_rebuild_indexes_ms: u64,
    store_open_rebuild_sha_index_ms: u64,
    store_open_load_tier2_superblocks_ms: u64,
    store_open_loaded_tier2_superblocks_from_snapshot_shards: u64,
    store_open_rebuild_tier2_superblocks_ms: u64,
}

#[derive(Clone, Debug, Default)]
struct StartupProfile {
    total_ms: u64,
    current: StoreRootStartupProfile,
    work: StoreRootStartupProfile,
}

struct ActiveMutationGuard<'a> {
    state: &'a ServerState,
}

#[derive(Clone, Copy, Debug)]
struct PublishReadiness {
    eligible: bool,
    blocked_reason: &'static str,
    trigger_mode: &'static str,
    trigger_reason: &'static str,
    idle_elapsed_ms: u64,
    idle_threshold_ms: u64,
    idle_remaining_ms: u64,
    work_buffer_estimated_documents: u64,
    work_buffer_estimated_input_bytes: u64,
    work_buffer_document_threshold: u64,
    work_buffer_input_bytes_threshold: u64,
    work_buffer_rss_threshold_bytes: u64,
    current_rss_bytes: u64,
    pressure_publish_blocked_by_seal_backlog: bool,
    pending_tier2_snapshot_shards: u64,
    index_backpressure_delay_ms: u64,
}

#[derive(Clone, Copy, Debug)]
struct WorkBufferPressure {
    estimated_documents: u64,
    estimated_input_bytes: u64,
    current_rss_bytes: u64,
    document_threshold: u64,
    input_bytes_threshold: u64,
    rss_threshold_bytes: u64,
    pressure_publish_blocked_by_seal_backlog: bool,
    pending_tier2_snapshot_shards: u64,
    index_backpressure_delay_ms: u64,
}

const ADAPTIVE_PUBLISH_RECENT_PUBLISH_WINDOW: usize = 16;
const ADAPTIVE_PUBLISH_RECENT_PRESSURE_WINDOW: usize = 16;
const ADAPTIVE_PUBLISH_RATE_WINDOW_MS: u64 = 10_000;
const ADAPTIVE_PUBLISH_FAST_P95_MS: u64 = 500;
const ADAPTIVE_PUBLISH_BACKOFF_P95_MS: u64 = 2_000;
const ADAPTIVE_PUBLISH_FAST_SUBMIT_MS: u64 = 2_000;
const ADAPTIVE_PUBLISH_BACKOFF_SUBMIT_MS: u64 = 5_000;
const ADAPTIVE_PUBLISH_FAST_STORE_MS: u64 = 1_500;
const ADAPTIVE_PUBLISH_BACKOFF_STORE_MS: u64 = 4_000;
const ADAPTIVE_PUBLISH_GROW_STEP_MS: u64 = 500;
const ADAPTIVE_PUBLISH_SHRINK_STEP_MS: u64 = 100;
const ADAPTIVE_PUBLISH_HEALTHY_CYCLES_TO_SHRINK: u64 = 3;
const WORK_BUFFER_MIN_DOCUMENT_THRESHOLD: u64 = 64;
const WORK_BUFFER_MAX_DOCUMENT_THRESHOLD: u64 = 12_500;
const WORK_BUFFER_DOCUMENT_BUDGET_BYTES: u64 = 640 * 1024;
const WORK_BUFFER_INPUT_BYTES_MULTIPLIER: u64 = 2;
const WORK_BUFFER_MIN_INPUT_BYTES_THRESHOLD: u64 = 1 << 30;
const WORK_BUFFER_REPUBLISH_MAX_DOCUMENT_THRESHOLD: u64 = 2_048;
const WORK_BUFFER_REPUBLISH_INPUT_BYTES_DIVISOR: u64 = 4;
const WORK_BUFFER_REPUBLISH_MIN_INPUT_BYTES_THRESHOLD: u64 = 4 << 30;
const WORK_BUFFER_RSS_TRIGGER_NUMERATOR: u64 = 3;
const WORK_BUFFER_RSS_TRIGGER_DENOMINATOR: u64 = 4;
const INDEX_BACKPRESSURE_PUBLISH_DELAY_MS: u64 = 10;
const INDEX_BACKPRESSURE_HEAVY_DELAY_MS: u64 = 50;

#[derive(Clone, Debug)]
struct AdaptivePublishSnapshot {
    storage_class: String,
    current_idle_ms: u64,
    mode: &'static str,
    reason: &'static str,
    recent_publish_p95_ms: u64,
    recent_submit_p95_ms: u64,
    recent_store_p95_ms: u64,
    recent_publishes_in_window: u64,
    tier2_pending_shards: u64,
    healthy_cycles: u64,
}

#[derive(Clone, Debug)]
struct AdaptivePublishState {
    storage_class: String,
    candidate_shards: usize,
    current_idle_ms: u64,
    recent_publish_ms: VecDeque<u64>,
    recent_submit_ms: VecDeque<u64>,
    recent_store_ms: VecDeque<u64>,
    recent_publish_completed_unix_ms: VecDeque<u64>,
    last_tier2_pending_shards: usize,
    healthy_cycles: u64,
    mode: &'static str,
    reason: &'static str,
}

impl AdaptivePublishState {
    fn new(storage_class: String, initial_idle_ms: u64, candidate_shards: usize) -> Self {
        Self {
            storage_class,
            candidate_shards: candidate_shards.max(1),
            current_idle_ms: initial_idle_ms.min(DEFAULT_AUTO_PUBLISH_IDLE_MS),
            recent_publish_ms: VecDeque::with_capacity(ADAPTIVE_PUBLISH_RECENT_PUBLISH_WINDOW),
            recent_submit_ms: VecDeque::with_capacity(ADAPTIVE_PUBLISH_RECENT_PRESSURE_WINDOW),
            recent_store_ms: VecDeque::with_capacity(ADAPTIVE_PUBLISH_RECENT_PRESSURE_WINDOW),
            recent_publish_completed_unix_ms: VecDeque::with_capacity(
                ADAPTIVE_PUBLISH_RECENT_PUBLISH_WINDOW,
            ),
            last_tier2_pending_shards: 0,
            healthy_cycles: 0,
            mode: "moderate",
            reason: "startup_bias",
        }
    }

    fn push_recent(window: &mut VecDeque<u64>, value: u64, limit: usize) {
        if window.len() >= limit {
            window.pop_front();
        }
        window.push_back(value);
    }

    fn p95(window: &VecDeque<u64>) -> u64 {
        if window.is_empty() {
            return 0;
        }
        let mut values = window.iter().copied().collect::<Vec<_>>();
        values.sort_unstable();
        let idx = ((values.len() - 1) * 95) / 100;
        values[idx]
    }

    fn recent_publishes_in_window(&self, now_unix_ms: u64) -> u64 {
        self.recent_publish_completed_unix_ms
            .iter()
            .filter(|completed| {
                now_unix_ms.saturating_sub(**completed) <= ADAPTIVE_PUBLISH_RATE_WINDOW_MS
            })
            .count()
            .try_into()
            .unwrap_or(u64::MAX)
    }

    fn update_completed_index_session(&mut self, submit_ms: u64, store_ms: u64) {
        if submit_ms > 0 {
            Self::push_recent(
                &mut self.recent_submit_ms,
                submit_ms,
                ADAPTIVE_PUBLISH_RECENT_PRESSURE_WINDOW,
            );
        }
        if store_ms > 0 {
            Self::push_recent(
                &mut self.recent_store_ms,
                store_ms,
                ADAPTIVE_PUBLISH_RECENT_PRESSURE_WINDOW,
            );
        }
    }

    fn update_completed_publish(
        &mut self,
        now_unix_ms: u64,
        visible_publish_ms: u64,
        tier2_pending_shards: usize,
    ) {
        Self::push_recent(
            &mut self.recent_publish_ms,
            visible_publish_ms,
            ADAPTIVE_PUBLISH_RECENT_PUBLISH_WINDOW,
        );
        Self::push_recent(
            &mut self.recent_publish_completed_unix_ms,
            now_unix_ms,
            ADAPTIVE_PUBLISH_RECENT_PUBLISH_WINDOW,
        );
        self.recompute(now_unix_ms, tier2_pending_shards);
    }

    fn update_seal_backlog(&mut self, now_unix_ms: u64, tier2_pending_shards: usize) {
        self.recompute(now_unix_ms, tier2_pending_shards);
    }

    fn recompute(&mut self, now_unix_ms: u64, tier2_pending_shards: usize) {
        let publish_p95_ms = Self::p95(&self.recent_publish_ms);
        let submit_p95_ms = Self::p95(&self.recent_submit_ms);
        let store_p95_ms = Self::p95(&self.recent_store_ms);
        let publish_rate = self.recent_publishes_in_window(now_unix_ms);
        let backlog_rising = tier2_pending_shards > self.last_tier2_pending_shards;
        let backlog_present = tier2_pending_shards > 0;
        let backlog_drained = !backlog_present && self.last_tier2_pending_shards > 0;
        let one_shard_set = self.candidate_shards.max(1);
        let backlog_high = tier2_pending_shards >= one_shard_set;

        let (target_idle_ms, mode, reason) = if publish_p95_ms > ADAPTIVE_PUBLISH_BACKOFF_P95_MS
            || backlog_high
            || backlog_rising
            || publish_rate >= 4
            || submit_p95_ms > ADAPTIVE_PUBLISH_BACKOFF_SUBMIT_MS
            || store_p95_ms > ADAPTIVE_PUBLISH_BACKOFF_STORE_MS
        {
            self.healthy_cycles = 0;
            (
                match self.storage_class.as_str() {
                    "rotational" => 3_000,
                    "solid-state" => 2_000,
                    _ => 2_500,
                },
                "backoff",
                if backlog_rising {
                    "seal_backlog_rising"
                } else if backlog_high {
                    "seal_backlog_high"
                } else if publish_p95_ms > ADAPTIVE_PUBLISH_BACKOFF_P95_MS {
                    "publish_latency_high"
                } else if publish_rate >= 4 {
                    "publish_rate_high"
                } else if submit_p95_ms > ADAPTIVE_PUBLISH_BACKOFF_SUBMIT_MS {
                    "submit_pressure_high"
                } else {
                    "store_pressure_high"
                },
            )
        } else if publish_p95_ms >= ADAPTIVE_PUBLISH_FAST_P95_MS
            || backlog_present
            || publish_rate >= 2
            || submit_p95_ms > ADAPTIVE_PUBLISH_FAST_SUBMIT_MS
            || store_p95_ms > ADAPTIVE_PUBLISH_FAST_STORE_MS
        {
            self.healthy_cycles = 0;
            (
                match self.storage_class.as_str() {
                    "rotational" => 1_000,
                    "solid-state" => 250,
                    _ => 500,
                },
                "moderate",
                if backlog_present {
                    "seal_backlog_present"
                } else if publish_p95_ms >= ADAPTIVE_PUBLISH_FAST_P95_MS {
                    "publish_latency_moderate"
                } else if publish_rate >= 2 {
                    "publish_rate_moderate"
                } else if submit_p95_ms > ADAPTIVE_PUBLISH_FAST_SUBMIT_MS {
                    "submit_pressure_moderate"
                } else {
                    "store_pressure_moderate"
                },
            )
        } else {
            self.healthy_cycles = self.healthy_cycles.saturating_add(1);
            (
                match self.storage_class.as_str() {
                    "rotational" => 250,
                    "solid-state" => 0,
                    _ => 100,
                },
                "fast",
                "healthy",
            )
        };

        let new_idle_ms = if backlog_drained && mode == "fast" {
            target_idle_ms
        } else if target_idle_ms > self.current_idle_ms {
            self.current_idle_ms
                .saturating_add(ADAPTIVE_PUBLISH_GROW_STEP_MS)
                .max(target_idle_ms)
                .min(DEFAULT_AUTO_PUBLISH_IDLE_MS)
        } else if self.healthy_cycles >= ADAPTIVE_PUBLISH_HEALTHY_CYCLES_TO_SHRINK {
            self.current_idle_ms
                .saturating_sub(ADAPTIVE_PUBLISH_SHRINK_STEP_MS)
                .max(target_idle_ms)
        } else {
            self.current_idle_ms.max(target_idle_ms)
        };

        self.current_idle_ms = new_idle_ms.min(DEFAULT_AUTO_PUBLISH_IDLE_MS);
        self.mode = mode;
        self.reason = reason;
        self.last_tier2_pending_shards = tier2_pending_shards;
    }

    fn snapshot(&self, now_unix_ms: u64, tier2_pending_shards: usize) -> AdaptivePublishSnapshot {
        AdaptivePublishSnapshot {
            storage_class: self.storage_class.clone(),
            current_idle_ms: self.current_idle_ms,
            mode: self.mode,
            reason: self.reason,
            recent_publish_p95_ms: Self::p95(&self.recent_publish_ms),
            recent_submit_p95_ms: Self::p95(&self.recent_submit_ms),
            recent_store_p95_ms: Self::p95(&self.recent_store_ms),
            recent_publishes_in_window: self.recent_publishes_in_window(now_unix_ms),
            tier2_pending_shards: tier2_pending_shards.try_into().unwrap_or(u64::MAX),
            healthy_cycles: self.healthy_cycles,
        }
    }
}

impl Drop for ActiveMutationGuard<'_> {
    fn drop(&mut self) {
        self.state.active_mutations.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub struct SspryClient {
    config: ClientConfig,
}

#[derive(Debug)]
pub(crate) struct PersistentSspryClient {
    stream: ClientStream,
}

impl ClientConfig {
    pub fn new(host: String, port: u16, timeout: Duration, socket_path: Option<PathBuf>) -> Self {
        Self {
            host,
            port,
            timeout,
            socket_path,
        }
    }
}

impl SspryClient {
    pub fn new(config: ClientConfig) -> Self {
        Self { config }
    }

    pub fn ping(&self) -> Result<String> {
        let response: Map<String, Value> = self.request_json_value(ACTION_PING, &json!({}))?;
        Ok(response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("pong")
            .to_owned())
    }

    pub fn candidate_insert_document(
        &self,
        document: &CandidateDocumentWire,
    ) -> Result<CandidateInsertResponse> {
        self.request_typed_json(ACTION_CANDIDATE_INSERT, document)
    }

    pub fn candidate_insert_batch(
        &self,
        documents: &[CandidateDocumentWire],
    ) -> Result<CandidateInsertBatchResponse> {
        if documents.is_empty() {
            return Ok(CandidateInsertBatchResponse {
                inserted_count: 0,
                results: Vec::new(),
            });
        }
        match self.request_typed_json(
            ACTION_CANDIDATE_INSERT_BATCH,
            &CandidateInsertBatchRequest {
                documents: documents.to_vec(),
            },
        ) {
            Ok(response) => Ok(response),
            Err(err) if documents.len() > 1 && is_payload_too_large_error(&err) => {
                let mid = documents.len() / 2;
                let mut left = self.candidate_insert_batch(&documents[..mid])?;
                let right = self.candidate_insert_batch(&documents[mid..])?;
                left.inserted_count += right.inserted_count;
                left.results.extend(right.results);
                Ok(left)
            }
            Err(err) if documents.len() == 1 && is_payload_too_large_error(&err) => Err(
                SspryError::from("Single document insert request is too large to send."),
            ),
            Err(err) => Err(err),
        }
    }

    pub(crate) fn connect_persistent(&self) -> Result<PersistentSspryClient> {
        Ok(PersistentSspryClient {
            stream: self.connect()?,
        })
    }

    pub fn candidate_insert_batch_payload_size(
        documents: &[CandidateDocumentWire],
    ) -> Result<usize> {
        Ok(serde_json::to_vec(&CandidateInsertBatchRequest {
            documents: documents.to_vec(),
        })?
        .len())
    }

    pub fn candidate_delete_sha256(&self, sha256: &str) -> Result<CandidateDeleteResponse> {
        self.request_typed_json(
            ACTION_CANDIDATE_DELETE,
            &CandidateDeleteRequest {
                sha256: normalize_sha256_hex(sha256)?,
            },
        )
    }

    pub fn candidate_query_plan(
        &self,
        plan: &CompiledQueryPlan,
        cursor: usize,
        chunk_size: Option<usize>,
    ) -> Result<CandidateQueryResponse> {
        self.candidate_query_plan_with_options(plan, cursor, chunk_size, false)
    }

    pub fn candidate_query_plan_with_options(
        &self,
        plan: &CompiledQueryPlan,
        cursor: usize,
        chunk_size: Option<usize>,
        include_external_ids: bool,
    ) -> Result<CandidateQueryResponse> {
        let mut payload = Map::new();
        payload.insert("plan".to_owned(), compiled_query_plan_to_wire(plan));
        payload.insert("cursor".to_owned(), Value::from(cursor));
        if let Some(value) = chunk_size {
            payload.insert("chunk_size".to_owned(), Value::from(value));
        }
        if include_external_ids {
            payload.insert("include_external_ids".to_owned(), Value::Bool(true));
        }
        self.request_typed_json(ACTION_CANDIDATE_QUERY, &Value::Object(payload))
    }

    pub fn candidate_stats(&self) -> Result<Map<String, Value>> {
        self.request_json_value(ACTION_CANDIDATE_STATS, &json!({}))
    }

    pub fn candidate_status(&self) -> Result<Map<String, Value>> {
        self.request_json_value(ACTION_CANDIDATE_STATUS, &json!({}))
    }

    pub fn shutdown(&self) -> Result<String> {
        let response: Map<String, Value> = self.request_json_value(ACTION_SHUTDOWN, &json!({}))?;
        Ok(response
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("shutdown requested")
            .to_owned())
    }

    pub fn publish(&self) -> Result<String> {
        let response: CandidatePublishResponse =
            self.request_typed_json(ACTION_PUBLISH, &json!({}))?;
        Ok(response.message)
    }

    pub fn begin_index_session(&self) -> Result<String> {
        let response: CandidateIndexSessionResponse =
            self.request_typed_json(ACTION_INDEX_SESSION_BEGIN, &json!({}))?;
        Ok(response.message)
    }

    pub fn update_index_session_progress(
        &self,
        total_documents: Option<usize>,
        submitted_documents: usize,
        processed_documents: usize,
    ) -> Result<()> {
        let _: CandidateIndexSessionResponse = self.request_typed_json(
            ACTION_INDEX_SESSION_PROGRESS,
            &CandidateIndexSessionProgressRequest {
                total_documents: total_documents.map(|value| value as u64),
                submitted_documents: submitted_documents as u64,
                processed_documents: processed_documents as u64,
            },
        )?;
        Ok(())
    }

    pub fn end_index_session(&self) -> Result<String> {
        let response: CandidateIndexSessionResponse =
            self.request_typed_json(ACTION_INDEX_SESSION_END, &json!({}))?;
        Ok(response.message)
    }

    fn request_typed_json<T, U>(&self, action: u8, payload: &U) -> Result<T>
    where
        T: DeserializeOwned,
        U: Serialize,
    {
        let bytes = serde_json::to_vec(payload)?;
        self.request_typed_bytes(action, &bytes)
    }

    fn request_json_value<U>(&self, action: u8, payload: &U) -> Result<Map<String, Value>>
    where
        U: Serialize,
    {
        let value: Value = self.request_typed_json(action, payload)?;
        value
            .as_object()
            .cloned()
            .ok_or_else(|| SspryError::from("Server returned invalid JSON object."))
    }

    fn request_typed_bytes<T>(&self, action: u8, payload: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let bytes = self.request_bytes(action, payload)?;
        serde_json::from_slice(&bytes).map_err(SspryError::from)
    }

    fn request_bytes(&self, action: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.connect()?;
        write_frame(&mut stream, PROTOCOL_VERSION, action, payload)?;
        let (version, status, response_payload) = read_frame(&mut stream)?;
        if version != PROTOCOL_VERSION {
            return Err(SspryError::from(format!(
                "Unsupported protocol version from server: {version}"
            )));
        }
        if status == STATUS_OK {
            return Ok(response_payload);
        }
        let value: Value = serde_json::from_slice(&response_payload)?;
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Server returned an error.");
        Err(SspryError::from(message.to_owned()))
    }

    fn connect(&self) -> Result<ClientStream> {
        if let Some(path) = &self.config.socket_path {
            #[cfg(unix)]
            {
                let stream = UnixStream::connect(path)?;
                stream.set_read_timeout(Some(self.config.timeout))?;
                stream.set_write_timeout(Some(self.config.timeout))?;
                return Ok(ClientStream::Unix(stream));
            }
            #[cfg(not(unix))]
            {
                let _ = path;
                return Err(SspryError::from(
                    "Unix sockets are not supported on this platform.",
                ));
            }
        }

        let stream = TcpStream::connect_timeout(
            &format!("{}:{}", self.config.host, self.config.port)
                .parse()
                .map_err(|_| SspryError::from("Invalid TCP address."))?,
            self.config.timeout,
        )?;
        stream.set_nodelay(true)?;
        stream.set_read_timeout(Some(self.config.timeout))?;
        stream.set_write_timeout(Some(self.config.timeout))?;
        Ok(ClientStream::Tcp(stream))
    }
}

impl PersistentSspryClient {
    pub(crate) fn begin_index_session(&mut self) -> Result<String> {
        let response: CandidateIndexSessionResponse =
            self.request_typed_json_with_publish_retry(ACTION_INDEX_SESSION_BEGIN, &json!({}))?;
        Ok(response.message)
    }

    pub(crate) fn update_index_session_progress(
        &mut self,
        total_documents: Option<usize>,
        submitted_documents: usize,
        processed_documents: usize,
    ) -> Result<()> {
        let _: CandidateIndexSessionResponse = self.request_typed_json(
            ACTION_INDEX_SESSION_PROGRESS,
            &CandidateIndexSessionProgressRequest {
                total_documents: total_documents.map(|value| value as u64),
                submitted_documents: submitted_documents as u64,
                processed_documents: processed_documents as u64,
            },
        )?;
        Ok(())
    }

    pub(crate) fn end_index_session(&mut self) -> Result<String> {
        let response: CandidateIndexSessionResponse =
            self.request_typed_json(ACTION_INDEX_SESSION_END, &json!({}))?;
        Ok(response.message)
    }

    pub(crate) fn candidate_insert_batch_serialized_rows(
        &mut self,
        rows: &[Vec<u8>],
    ) -> Result<CandidateInsertBatchResponse> {
        if rows.is_empty() {
            return Ok(CandidateInsertBatchResponse {
                inserted_count: 0,
                results: Vec::new(),
            });
        }
        let payload = serialized_candidate_insert_batch_payload(rows);
        match self.request_typed_bytes_with_publish_retry(ACTION_CANDIDATE_INSERT_BATCH, &payload) {
            Ok(response) => Ok(response),
            Err(err) if rows.len() > 1 && is_payload_too_large_error(&err) => {
                let mid = rows.len() / 2;
                let mut left = self.candidate_insert_batch_serialized_rows(&rows[..mid])?;
                let right = self.candidate_insert_batch_serialized_rows(&rows[mid..])?;
                left.inserted_count += right.inserted_count;
                left.results.extend(right.results);
                Ok(left)
            }
            Err(err) if rows.len() == 1 && is_payload_too_large_error(&err) => Err(
                SspryError::from("Single document insert request is too large to send."),
            ),
            Err(err) => Err(err),
        }
    }

    fn request_typed_json<T, U>(&mut self, action: u8, payload: &U) -> Result<T>
    where
        T: DeserializeOwned,
        U: Serialize,
    {
        let bytes = serde_json::to_vec(payload)?;
        self.request_typed_bytes(action, &bytes)
    }

    fn request_typed_json_with_publish_retry<T, U>(&mut self, action: u8, payload: &U) -> Result<T>
    where
        T: DeserializeOwned,
        U: Serialize,
    {
        let bytes = serde_json::to_vec(payload)?;
        self.request_typed_bytes_with_publish_retry(action, &bytes)
    }

    fn request_typed_bytes<T>(&mut self, action: u8, payload: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let bytes = self.request_bytes(action, payload)?;
        serde_json::from_slice(&bytes).map_err(SspryError::from)
    }

    fn request_typed_bytes_with_publish_retry<T>(&mut self, action: u8, payload: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let mut retries = 0usize;
        loop {
            match self.request_typed_bytes(action, payload) {
                Ok(response) => return Ok(response),
                Err(err)
                    if is_temporary_publish_retry_error(&err)
                        && retries < TEMPORARY_PUBLISH_RETRY_LIMIT =>
                {
                    retries = retries.saturating_add(1);
                    thread::sleep(Duration::from_millis(TEMPORARY_PUBLISH_RETRY_SLEEP_MS));
                }
                Err(err) => return Err(err),
            }
        }
    }

    fn request_bytes(&mut self, action: u8, payload: &[u8]) -> Result<Vec<u8>> {
        write_frame(&mut self.stream, PROTOCOL_VERSION, action, payload)?;
        let (version, status, response_payload) = read_frame(&mut self.stream)?;
        if version != PROTOCOL_VERSION {
            return Err(SspryError::from(format!(
                "Unsupported protocol version from server: {version}"
            )));
        }
        if status == STATUS_OK {
            return Ok(response_payload);
        }
        let value: Value = serde_json::from_slice(&response_payload)?;
        let message = value
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Server returned an error.");
        Err(SspryError::from(message.to_owned()))
    }
}

fn is_payload_too_large_error(err: &SspryError) -> bool {
    let text = err.to_string();
    text.contains("Request payload is too large") || text.contains("Payload is too large")
}

fn is_temporary_publish_retry_error(err: &SspryError) -> bool {
    let text = err.to_string();
    text.contains("server is publishing") && text.contains("retry later")
}

pub fn serve(
    host: &str,
    port: u16,
    socket_path: Option<&Path>,
    max_request_bytes: usize,
    config: ServerConfig,
) -> Result<()> {
    serve_with_shutdown(
        host,
        port,
        socket_path,
        max_request_bytes,
        config,
        Arc::new(AtomicBool::new(false)),
    )
}

pub fn serve_with_signal_flags(
    host: &str,
    port: u16,
    socket_path: Option<&Path>,
    max_request_bytes: usize,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    status_dump: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let state = Arc::new(ServerState::new(config, shutdown)?);
    let compaction_worker = start_compaction_worker(state.clone());
    let auto_publish_worker = start_auto_publish_worker(state.clone());
    let published_tier2_snapshot_seal_worker =
        start_published_tier2_snapshot_seal_worker(state.clone());
    let status_worker = start_status_dump_worker(state.clone(), status_dump);

    let accept_result = if let Some(path) = socket_path {
        #[cfg(unix)]
        {
            if path.exists() {
                fs::remove_file(path)?;
            }
            if let Some(parent) = path.parent() {
                fs::create_dir_all(parent)?;
            }
            let listener = UnixListener::bind(path)?;
            println!("sspry server listening on unix://{}", path.display());
            accept_unix(listener, state.clone(), max_request_bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, state, max_request_bytes);
            return Err(SspryError::from(
                "Unix sockets are not supported on this platform.",
            ));
        }
    } else {
        let listener = TcpListener::bind((host, port))?;
        let local = listener.local_addr()?;
        println!("sspry server listening on {}:{}", local.ip(), local.port());
        accept_tcp(listener, state.clone(), max_request_bytes)
    };

    if state.is_shutting_down() {
        eprintln!("sspry: shutdown requested, draining");
        if let Ok(stats) = state.current_stats_json() {
            if let Ok(text) = serde_json::to_string_pretty(&stats) {
                eprintln!("{text}");
            }
        }
    }
    state.shutdown.store(true, Ordering::Relaxed);
    if let Some(worker) = status_worker {
        let _ = worker.join();
    }
    let _ = compaction_worker.join();
    let _ = auto_publish_worker.join();
    let _ = published_tier2_snapshot_seal_worker.join();
    let mut last_reported_connections = usize::MAX;
    while state.active_connections.load(Ordering::Acquire) > 0 {
        let active_connections = state.active_connections.load(Ordering::Acquire);
        if active_connections != last_reported_connections {
            eprintln!("sspry: waiting for {active_connections} active connection(s) to drain");
            last_reported_connections = active_connections;
        }
        thread::sleep(Duration::from_millis(25));
    }
    if let Err(err) = state.flush_store_meta_if_dirty() {
        eprintln!("sspry: failed to flush dirty store metadata during shutdown: {err}");
    }
    eprintln!("sspry: shutdown complete");
    accept_result
}

pub fn serve_with_shutdown(
    host: &str,
    port: u16,
    socket_path: Option<&Path>,
    max_request_bytes: usize,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
) -> Result<()> {
    serve_with_signal_flags(
        host,
        port,
        socket_path,
        max_request_bytes,
        config,
        shutdown,
        None,
    )
}

fn candidate_stats_json_from_parts_with_disk_usage(
    stats_rows: &[crate::candidate::CandidateStats],
    disk_usage_bytes: u64,
) -> Map<String, Value> {
    let stats = stats_rows
        .first()
        .cloned()
        .expect("candidate stats rows must not be empty");
    let active_doc_count = stats_rows.iter().map(|item| item.doc_count).sum::<usize>();
    let deleted_doc_count = stats_rows
        .iter()
        .map(|item| item.deleted_doc_count)
        .sum::<usize>();
    let compaction_generation = stats_rows
        .iter()
        .map(|item| item.compaction_generation)
        .max()
        .unwrap_or(1);
    let retired_generation_count = stats_rows
        .iter()
        .map(|item| item.retired_generation_count)
        .sum::<usize>();
    let tier2_superblock_summary_bytes = stats_rows
        .iter()
        .map(|item| item.tier2_superblock_summary_bytes)
        .sum::<u64>();
    let tier1_superblock_summary_bytes = stats_rows
        .iter()
        .map(|item| item.tier1_superblock_summary_bytes)
        .sum::<u64>();
    let tier2_pattern_superblock_summary_bytes = stats_rows
        .iter()
        .map(|item| item.tier2_pattern_superblock_summary_bytes)
        .sum::<u64>();
    let tier1_superblock_positions_bytes = stats_rows
        .iter()
        .map(|item| item.tier1_superblock_positions_bytes)
        .sum::<u64>();
    let tier2_pattern_superblock_positions_bytes = stats_rows
        .iter()
        .map(|item| item.tier2_pattern_superblock_positions_bytes)
        .sum::<u64>();
    let tree_tier1_gate_bytes = stats_rows
        .iter()
        .map(|item| item.tree_tier1_gate_bytes)
        .sum::<u64>();
    let tree_tier2_gate_bytes = stats_rows
        .iter()
        .map(|item| item.tree_tier2_gate_bytes)
        .sum::<u64>();
    let mapped_bloom_bytes = stats_rows
        .iter()
        .map(|item| item.mapped_bloom_bytes)
        .sum::<u64>();
    let mapped_tier2_bloom_bytes = stats_rows
        .iter()
        .map(|item| item.mapped_tier2_bloom_bytes)
        .sum::<u64>();
    let mapped_metadata_bytes = stats_rows
        .iter()
        .map(|item| item.mapped_metadata_bytes)
        .sum::<u64>();
    let mapped_external_id_bytes = stats_rows
        .iter()
        .map(|item| item.mapped_external_id_bytes)
        .sum::<u64>();
    let tier2_superblock_memory_budget_bytes = stats_rows
        .iter()
        .map(|item| item.tier2_superblock_memory_budget_bytes)
        .sum::<u64>();
    let mut out = Map::<String, Value>::new();
    out.insert("active_doc_count".to_owned(), json!(active_doc_count));
    out.insert(
        "candidate_shards".to_owned(),
        json!(stats_rows.len().max(1)),
    );
    out.insert("id_source".to_owned(), json!(stats.id_source));
    out.insert("store_path".to_owned(), json!(stats.store_path));
    out.insert("deleted_doc_count".to_owned(), json!(deleted_doc_count));
    out.insert(
        "tier2_superblock_summary_bytes".to_owned(),
        json!(tier2_superblock_summary_bytes),
    );
    out.insert(
        "tier1_superblock_summary_bytes".to_owned(),
        json!(tier1_superblock_summary_bytes),
    );
    out.insert(
        "tier2_pattern_superblock_summary_bytes".to_owned(),
        json!(tier2_pattern_superblock_summary_bytes),
    );
    out.insert(
        "tier1_superblock_positions_bytes".to_owned(),
        json!(tier1_superblock_positions_bytes),
    );
    out.insert(
        "tier2_pattern_superblock_positions_bytes".to_owned(),
        json!(tier2_pattern_superblock_positions_bytes),
    );
    out.insert(
        "tree_tier1_gate_bytes".to_owned(),
        json!(tree_tier1_gate_bytes),
    );
    out.insert(
        "tree_tier2_gate_bytes".to_owned(),
        json!(tree_tier2_gate_bytes),
    );
    out.insert("mapped_bloom_bytes".to_owned(), json!(mapped_bloom_bytes));
    out.insert(
        "mapped_tier2_bloom_bytes".to_owned(),
        json!(mapped_tier2_bloom_bytes),
    );
    out.insert(
        "mapped_metadata_bytes".to_owned(),
        json!(mapped_metadata_bytes),
    );
    out.insert(
        "mapped_external_id_bytes".to_owned(),
        json!(mapped_external_id_bytes),
    );
    out.insert(
        "tier2_superblock_memory_budget_bytes".to_owned(),
        json!(tier2_superblock_memory_budget_bytes),
    );
    out.insert("disk_usage_bytes".to_owned(), json!(disk_usage_bytes));
    out.insert(
        "doc_count".to_owned(),
        json!(active_doc_count + deleted_doc_count),
    );
    out.insert(
        "compaction_generation".to_owned(),
        json!(compaction_generation),
    );
    out.insert(
        "tier1_filter_target_fp".to_owned(),
        stats
            .tier1_filter_target_fp
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "tier2_filter_target_fp".to_owned(),
        stats
            .tier2_filter_target_fp
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    out.insert(
        "filter_target_fp".to_owned(),
        stats
            .filter_target_fp
            .map(Value::from)
            .unwrap_or(Value::Null),
    );
    out.insert("tier2_gram_size".to_owned(), json!(stats.tier2_gram_size));
    out.insert("tier1_gram_size".to_owned(), json!(stats.tier1_gram_size));
    out.insert("query_count".to_owned(), json!(stats.query_count));
    out.insert(
        "retired_generation_count".to_owned(),
        json!(retired_generation_count),
    );
    out.insert(
        "tier2_docs_matched_total".to_owned(),
        json!(stats.tier2_docs_matched_total),
    );
    out.insert(
        "tier2_match_ratio".to_owned(),
        json!(stats.tier2_match_ratio),
    );
    out.insert(
        "tier2_scanned_docs_total".to_owned(),
        json!(stats.tier2_scanned_docs_total),
    );
    out.insert("tier2_superblock_adaptive".to_owned(), json!(false));
    out.insert("tier2_superblock_adapt_interval_scans".to_owned(), json!(0));
    out.insert(
        "tier2_superblock_count".to_owned(),
        json!(stats.tier2_superblock_count),
    );
    out.insert(
        "tier2_superblock_docs".to_owned(),
        json!(stats.tier2_superblock_docs),
    );
    out.insert(
        "tier2_superblocks_skipped_total".to_owned(),
        json!(stats.tier2_superblocks_skipped_total),
    );
    out.insert("version".to_owned(), json!(1));
    out
}

fn candidate_stats_json_from_parts(
    root: &Path,
    stats_rows: &[crate::candidate::CandidateStats],
) -> Map<String, Value> {
    candidate_stats_json_from_parts_with_disk_usage(stats_rows, disk_usage_under(root))
}

#[derive(Clone, Copy, Debug, Default)]
struct CandidateStatsBuildProfile {
    collect_store_stats_ms: u64,
    disk_usage_ms: u64,
    build_json_ms: u64,
}

pub fn candidate_stats_json(root: &Path, store: &CandidateStore) -> Map<String, Value> {
    candidate_stats_json_from_parts(root, &[store.stats()])
}

pub fn candidate_stats_json_for_stores(
    root: &Path,
    stores: &[CandidateStore],
) -> Map<String, Value> {
    let stats_rows = stores.iter().map(CandidateStore::stats).collect::<Vec<_>>();
    candidate_stats_json_from_parts(root, &stats_rows)
}

fn start_compaction_worker(state: Arc<ServerState>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if state.is_shutting_down() {
                break;
            }
            thread::sleep(Duration::from_millis(200));
            if state.is_shutting_down() {
                break;
            }
            let _ = state.run_compaction_cycle();
        }
    })
}

fn start_auto_publish_worker(state: Arc<ServerState>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if state.is_shutting_down() {
                break;
            }
            thread::sleep(Duration::from_millis(200));
            if state.is_shutting_down() {
                break;
            }
            let _ = state.run_auto_publish_cycle();
            let _ = state.run_retired_root_prune_cycle();
        }
    })
}

fn start_published_tier2_snapshot_seal_worker(state: Arc<ServerState>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        loop {
            if state.is_shutting_down()
                && state
                    .pending_published_tier2_snapshot_shard_count()
                    .unwrap_or(0)
                    == 0
            {
                break;
            }
            thread::sleep(Duration::from_millis(50));
            let _ = state.run_published_tier2_snapshot_seal_cycle();
        }
    })
}

fn start_status_dump_worker(
    state: Arc<ServerState>,
    status_dump: Option<Arc<AtomicBool>>,
) -> Option<thread::JoinHandle<()>> {
    let status_dump = status_dump?;
    Some(thread::spawn(move || {
        while !state.is_shutting_down() {
            if status_dump.swap(false, Ordering::SeqCst) {
                match state.current_stats_json() {
                    Ok(stats) => match serde_json::to_string_pretty(&stats) {
                        Ok(text) => eprintln!("{text}"),
                        Err(err) => eprintln!("failed to serialize status snapshot: {err}"),
                    },
                    Err(err) => eprintln!("failed to collect status snapshot: {err}"),
                }
            }
            thread::sleep(Duration::from_millis(50));
        }
    }))
}

fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn signed_delta_i64(current: u64, baseline: u64) -> i64 {
    if current >= baseline {
        let delta = current.saturating_sub(baseline);
        delta.min(i64::MAX as u64) as i64
    } else {
        let delta = baseline.saturating_sub(current);
        -(delta.min(i64::MAX as u64) as i64)
    }
}

#[derive(Debug)]
enum ClientStream {
    Tcp(TcpStream),
    #[cfg(unix)]
    Unix(UnixStream),
}

impl Read for ClientStream {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.read(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.read(buf),
        }
    }
}

impl Write for ClientStream {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self {
            Self::Tcp(stream) => stream.write(buf),
            #[cfg(unix)]
            Self::Unix(stream) => stream.write(buf),
        }
    }

    fn flush(&mut self) -> std::io::Result<()> {
        match self {
            Self::Tcp(stream) => stream.flush(),
            #[cfg(unix)]
            Self::Unix(stream) => stream.flush(),
        }
    }
}

impl ServerState {
    fn new(config: ServerConfig, shutdown: Arc<AtomicBool>) -> Result<Self> {
        let started = Instant::now();
        let (store_mode, startup_cleanup_removed_roots, mut startup_profile) =
            ensure_candidate_stores(&config)?;
        startup_profile.total_ms = started.elapsed().as_millis().try_into().unwrap_or(u64::MAX);
        let startup_work_documents = match &store_mode {
            StoreMode::Workspace { .. } => startup_profile.work.doc_count,
            StoreMode::Direct { .. } => 0,
        };
        let auto_publish_storage_class = config.auto_publish_storage_class.clone();
        let auto_publish_initial_idle_ms = config.auto_publish_initial_idle_ms;
        let candidate_shards = config.candidate_shards;
        Ok(Self {
            config,
            shutdown,
            operation_gate: RwLock::new(()),
            store_mode: Mutex::new(store_mode),
            publish_requested: AtomicBool::new(false),
            mutations_paused: AtomicBool::new(false),
            publish_in_progress: AtomicBool::new(false),
            active_mutations: AtomicUsize::new(0),
            active_index_sessions: AtomicUsize::new(0),
            work_dirty: AtomicBool::new(false),
            work_active_estimated_documents: AtomicU64::new(startup_work_documents),
            work_active_estimated_input_bytes: AtomicU64::new(0),
            index_backpressure_events_total: AtomicU64::new(0),
            index_backpressure_sleep_ms_total: AtomicU64::new(0),
            last_index_backpressure_delay_ms: AtomicU64::new(0),
            last_work_mutation_unix_ms: AtomicU64::new(0),
            index_session_total_documents: AtomicU64::new(0),
            index_session_submitted_documents: AtomicU64::new(0),
            index_session_processed_documents: AtomicU64::new(0),
            index_session_started_unix_ms: AtomicU64::new(0),
            index_session_last_update_unix_ms: AtomicU64::new(0),
            index_session_server_insert_batch_count: AtomicU64::new(0),
            index_session_server_insert_batch_documents: AtomicU64::new(0),
            index_session_server_insert_batch_shards_touched: AtomicU64::new(0),
            index_session_server_insert_batch_total_us: AtomicU64::new(0),
            index_session_server_insert_batch_parse_us: AtomicU64::new(0),
            index_session_server_insert_batch_group_us: AtomicU64::new(0),
            index_session_server_insert_batch_build_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_us: AtomicU64::new(0),
            index_session_server_insert_batch_finalize_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_resolve_doc_state_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_sidecars_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_sidecar_payloads_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_bloom_payload_assemble_us:
                AtomicU64::new(0),
            index_session_server_insert_batch_store_append_bloom_payload_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_metadata_payload_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_external_id_payload_us: AtomicU64::new(
                0,
            ),
            index_session_server_insert_batch_store_append_tier2_bloom_payload_us: AtomicU64::new(
                0,
            ),
            index_session_server_insert_batch_store_append_doc_row_build_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_bloom_payload_bytes: AtomicU64::new(0),
            index_session_server_insert_batch_store_append_metadata_payload_bytes: AtomicU64::new(
                0,
            ),
            index_session_server_insert_batch_store_append_external_id_payload_bytes:
                AtomicU64::new(0),
            index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes:
                AtomicU64::new(0),
            index_session_server_insert_batch_store_append_doc_records_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_write_existing_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_install_docs_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_tier2_update_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_persist_meta_us: AtomicU64::new(0),
            index_session_server_insert_batch_store_rebalance_tier2_us: AtomicU64::new(0),
            last_publish_started_unix_ms: AtomicU64::new(0),
            last_publish_completed_unix_ms: AtomicU64::new(0),
            last_publish_duration_ms: AtomicU64::new(0),
            last_publish_lock_wait_ms: AtomicU64::new(0),
            last_publish_swap_ms: AtomicU64::new(0),
            last_publish_promote_work_ms: AtomicU64::new(0),
            last_publish_promote_work_export_ms: AtomicU64::new(0),
            last_publish_promote_work_import_ms: AtomicU64::new(0),
            last_publish_promote_work_import_resolve_doc_state_ms: AtomicU64::new(0),
            last_publish_promote_work_import_build_payloads_ms: AtomicU64::new(0),
            last_publish_promote_work_import_append_sidecars_ms: AtomicU64::new(0),
            last_publish_promote_work_import_install_docs_ms: AtomicU64::new(0),
            last_publish_promote_work_import_tier2_update_ms: AtomicU64::new(0),
            last_publish_promote_work_import_persist_meta_ms: AtomicU64::new(0),
            last_publish_promote_work_import_rebalance_tier2_ms: AtomicU64::new(0),
            last_publish_promote_work_remove_work_root_ms: AtomicU64::new(0),
            last_publish_promote_work_other_ms: AtomicU64::new(0),
            last_publish_promote_work_imported_docs: AtomicU64::new(0),
            last_publish_promote_work_imported_shards: AtomicU64::new(0),
            last_publish_init_work_ms: AtomicU64::new(0),
            last_publish_persist_tier2_superblocks_ms: AtomicU64::new(0),
            last_publish_tier2_snapshot_persist_failures: AtomicU64::new(0),
            last_publish_persisted_snapshot_shards: AtomicU64::new(0),
            last_publish_reused_work_stores: AtomicBool::new(false),
            publish_runs_total: AtomicU64::new(0),
            pending_published_tier2_snapshot_shards: Mutex::new(HashSet::new()),
            published_tier2_snapshot_seal_in_progress: AtomicBool::new(false),
            published_tier2_snapshot_seal_runs_total: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_duration_ms: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_persisted_shards: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_failures: AtomicU64::new(0),
            last_published_tier2_snapshot_seal_completed_unix_ms: AtomicU64::new(0),
            adaptive_publish: Mutex::new(AdaptivePublishState::new(
                auto_publish_storage_class,
                auto_publish_initial_idle_ms,
                candidate_shards,
            )),
            normalized_plan_cache: Mutex::new(BoundedCache::new(QUERY_CACHE_CAPACITY)),
            prepared_plan_cache: Mutex::new(BoundedCache::new(QUERY_CACHE_CAPACITY)),
            query_cache: Mutex::new(BoundedCache::new(QUERY_CACHE_CAPACITY)),
            compaction_runtime: Mutex::new(CompactionRuntime::default()),
            next_compaction_shard: AtomicUsize::new(0),
            active_connections: AtomicUsize::new(0),
            startup_cleanup_removed_roots,
            startup_profile,
        })
    }

    fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    fn published_store_set(&self) -> Result<Arc<StoreSet>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { stores } => stores.clone(),
            StoreMode::Workspace { published, .. } => published.clone(),
        })
    }

    fn work_store_set(&self) -> Result<Arc<StoreSet>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { stores } => stores.clone(),
            StoreMode::Workspace { work_active, .. } => work_active.clone(),
        })
    }

    fn flush_store_meta_if_dirty(&self) -> Result<()> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        match &*mode {
            StoreMode::Direct { stores } => {
                for (shard_idx, store_lock) in stores.stores.iter().enumerate() {
                    let mut store =
                        lock_candidate_store_with_timeout(store_lock, shard_idx, "flush meta")?;
                    let _ = store.persist_meta_if_dirty()?;
                }
            }
            StoreMode::Workspace {
                published,
                work_active,
                work_idle,
                ..
            } => {
                for (shard_idx, store_lock) in published.stores.iter().enumerate() {
                    let mut store = lock_candidate_store_with_timeout(
                        store_lock,
                        shard_idx,
                        "flush published meta",
                    )?;
                    let _ = store.persist_meta_if_dirty()?;
                }
                for (shard_idx, store_lock) in work_active.stores.iter().enumerate() {
                    let mut store = lock_candidate_store_with_timeout(
                        store_lock,
                        shard_idx,
                        "flush active work meta",
                    )?;
                    let _ = store.persist_meta_if_dirty()?;
                }
                if let Some(work_idle) = work_idle {
                    for (shard_idx, store_lock) in work_idle.stores.iter().enumerate() {
                        let mut store = lock_candidate_store_with_timeout(
                            store_lock,
                            shard_idx,
                            "flush idle work meta",
                        )?;
                        let _ = store.persist_meta_if_dirty()?;
                    }
                }
            }
        }
        Ok(())
    }

    fn workspace_roots(&self) -> Result<Option<(PathBuf, PathBuf)>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { .. } => None,
            StoreMode::Workspace {
                published,
                work_active,
                ..
            } => Some((published.root()?, work_active.root()?)),
        })
    }

    fn mutation_affects_published_queries(&self) -> Result<bool> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
        Ok(matches!(*mode, StoreMode::Direct { .. }))
    }

    fn begin_mutation(&self, operation: &str) -> Result<ActiveMutationGuard<'_>> {
        self.active_mutations.fetch_add(1, Ordering::AcqRel);
        if self.mutations_paused.load(Ordering::Acquire) {
            self.active_mutations.fetch_sub(1, Ordering::AcqRel);
            return Err(SspryError::from(format!(
                "server is publishing; {operation} temporarily disabled; retry later"
            )));
        }
        Ok(ActiveMutationGuard { state: self })
    }

    fn mark_work_mutation(&self) {
        self.work_dirty.store(true, Ordering::SeqCst);
        self.last_work_mutation_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        let _ = self.invalidate_work_stats_cache();
    }

    fn invalidate_work_stats_cache(&self) -> Result<()> {
        let work = self.work_store_set()?;
        work.invalidate_stats_cache()
    }

    fn invalidate_published_stats_cache(&self) -> Result<()> {
        let published = self.published_store_set()?;
        published.invalidate_stats_cache()
    }

    fn work_buffer_document_threshold(&self) -> u64 {
        let scaled = self
            .config
            .memory_budget_bytes
            .checked_div(WORK_BUFFER_DOCUMENT_BUDGET_BYTES)
            .unwrap_or(0);
        scaled.clamp(
            WORK_BUFFER_MIN_DOCUMENT_THRESHOLD,
            WORK_BUFFER_MAX_DOCUMENT_THRESHOLD,
        )
    }

    fn work_buffer_input_bytes_threshold(&self) -> u64 {
        self.config
            .memory_budget_bytes
            .saturating_mul(WORK_BUFFER_INPUT_BYTES_MULTIPLIER)
            .max(WORK_BUFFER_MIN_INPUT_BYTES_THRESHOLD)
    }

    fn work_buffer_rss_threshold_bytes(&self) -> u64 {
        self.config
            .memory_budget_bytes
            .saturating_mul(WORK_BUFFER_RSS_TRIGGER_NUMERATOR)
            / WORK_BUFFER_RSS_TRIGGER_DENOMINATOR
    }

    fn work_buffer_pressure_snapshot(
        &self,
        current_rss_bytes: u64,
        pending_tier2_snapshot_shards: u64,
    ) -> WorkBufferPressure {
        let estimated_documents = self.work_active_estimated_documents.load(Ordering::Acquire);
        let estimated_input_bytes = self
            .work_active_estimated_input_bytes
            .load(Ordering::Acquire);
        let active_index_sessions = self.active_index_sessions.load(Ordering::Acquire);
        let publish_runs_total = self.publish_runs_total.load(Ordering::Acquire);
        let mut document_threshold = self.work_buffer_document_threshold();
        let mut input_bytes_threshold = self.work_buffer_input_bytes_threshold();
        if active_index_sessions > 0 && publish_runs_total > 0 {
            document_threshold =
                document_threshold.min(WORK_BUFFER_REPUBLISH_MAX_DOCUMENT_THRESHOLD);
            input_bytes_threshold = input_bytes_threshold.min(
                (self
                    .config
                    .memory_budget_bytes
                    .checked_div(WORK_BUFFER_REPUBLISH_INPUT_BYTES_DIVISOR)
                    .unwrap_or(0))
                .max(WORK_BUFFER_REPUBLISH_MIN_INPUT_BYTES_THRESHOLD),
            );
        }
        let rss_threshold_bytes = self.work_buffer_rss_threshold_bytes();
        let pressure_publish_blocked_by_seal_backlog = pending_tier2_snapshot_shards > 0;
        let index_backpressure_delay_ms = if self.active_index_sessions.load(Ordering::Acquire) == 0
        {
            0
        } else if self.publish_in_progress.load(Ordering::Acquire) {
            if estimated_documents >= document_threshold
                || estimated_input_bytes >= input_bytes_threshold
                || current_rss_bytes >= rss_threshold_bytes
            {
                INDEX_BACKPRESSURE_HEAVY_DELAY_MS
            } else {
                INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
            }
        } else if self.publish_requested.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
        {
            INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
        } else {
            0
        };
        WorkBufferPressure {
            estimated_documents,
            estimated_input_bytes,
            current_rss_bytes,
            document_threshold,
            input_bytes_threshold,
            rss_threshold_bytes,
            pressure_publish_blocked_by_seal_backlog,
            pending_tier2_snapshot_shards,
            index_backpressure_delay_ms,
        }
    }

    fn record_work_buffer_growth(&self, inserted_documents: u64, inserted_input_bytes: u64) {
        if !self.config.workspace_mode {
            return;
        }
        if inserted_documents > 0 {
            self.work_active_estimated_documents
                .fetch_add(inserted_documents, Ordering::SeqCst);
        }
        if inserted_input_bytes > 0 {
            self.work_active_estimated_input_bytes
                .fetch_add(inserted_input_bytes, Ordering::SeqCst);
        }
    }

    fn reset_work_buffer_estimates(&self) {
        self.work_active_estimated_documents
            .store(0, Ordering::SeqCst);
        self.work_active_estimated_input_bytes
            .store(0, Ordering::SeqCst);
    }

    fn maybe_apply_index_backpressure(&self, batch_documents: usize, batch_input_bytes: u64) {
        if !self.config.workspace_mode || batch_documents == 0 {
            self.last_index_backpressure_delay_ms
                .store(0, Ordering::SeqCst);
            return;
        }
        let adaptive = self.adaptive_publish_snapshot_or_default(current_unix_ms());
        let (current_rss_kb, _) = current_process_memory_kb();
        let mut pressure = self.work_buffer_pressure_snapshot(
            current_rss_kb
                .saturating_mul(1024)
                .try_into()
                .unwrap_or(u64::MAX),
            adaptive.tier2_pending_shards,
        );
        pressure.estimated_documents = pressure
            .estimated_documents
            .saturating_add(batch_documents as u64);
        pressure.estimated_input_bytes = pressure
            .estimated_input_bytes
            .saturating_add(batch_input_bytes);
        let delay_ms = if self.active_index_sessions.load(Ordering::Acquire) == 0 {
            0
        } else if self.publish_in_progress.load(Ordering::Acquire) {
            if pressure.estimated_documents >= pressure.document_threshold
                || pressure.estimated_input_bytes >= pressure.input_bytes_threshold
                || pressure.current_rss_bytes >= pressure.rss_threshold_bytes
            {
                INDEX_BACKPRESSURE_HEAVY_DELAY_MS
            } else {
                INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
            }
        } else if self.publish_requested.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
        {
            INDEX_BACKPRESSURE_PUBLISH_DELAY_MS
        } else {
            0
        };
        self.last_index_backpressure_delay_ms
            .store(delay_ms, Ordering::SeqCst);
        if delay_ms == 0 {
            return;
        }
        self.index_backpressure_events_total
            .fetch_add(1, Ordering::SeqCst);
        self.index_backpressure_sleep_ms_total
            .fetch_add(delay_ms, Ordering::SeqCst);
        thread::sleep(Duration::from_millis(delay_ms));
    }

    fn enqueue_published_tier2_snapshot_shards<I>(&self, shard_indexes: I) -> Result<()>
    where
        I: IntoIterator<Item = usize>,
    {
        let mut pending = self
            .pending_published_tier2_snapshot_shards
            .lock()
            .map_err(|_| SspryError::from("Published Tier2 snapshot queue lock poisoned."))?;
        for shard_idx in shard_indexes {
            pending.insert(shard_idx);
        }
        Ok(())
    }

    fn pending_published_tier2_snapshot_shard_count(&self) -> Result<usize> {
        let pending = self
            .pending_published_tier2_snapshot_shards
            .lock()
            .map_err(|_| SspryError::from("Published Tier2 snapshot queue lock poisoned."))?;
        Ok(pending.len())
    }

    fn adaptive_publish_snapshot(&self, now_unix_ms: u64) -> Result<AdaptivePublishSnapshot> {
        let tier2_pending_shards = self.pending_published_tier2_snapshot_shard_count()?;
        let adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        Ok(adaptive.snapshot(now_unix_ms, tier2_pending_shards))
    }

    fn adaptive_publish_snapshot_or_default(&self, now_unix_ms: u64) -> AdaptivePublishSnapshot {
        self.adaptive_publish_snapshot(now_unix_ms)
            .unwrap_or(AdaptivePublishSnapshot {
                storage_class: self.config.auto_publish_storage_class.clone(),
                current_idle_ms: self.config.auto_publish_initial_idle_ms,
                mode: "moderate",
                reason: "adaptive_snapshot_unavailable",
                recent_publish_p95_ms: 0,
                recent_submit_p95_ms: 0,
                recent_store_p95_ms: 0,
                recent_publishes_in_window: 0,
                tier2_pending_shards: 0,
                healthy_cycles: 0,
            })
    }

    fn update_adaptive_publish_from_index_session(&self) -> Result<()> {
        let submit_ms = self
            .index_session_server_insert_batch_total_us
            .load(Ordering::Acquire)
            / 1_000;
        let store_ms = self
            .index_session_server_insert_batch_store_us
            .load(Ordering::Acquire)
            / 1_000;
        let mut adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        adaptive.update_completed_index_session(submit_ms, store_ms);
        Ok(())
    }

    fn update_adaptive_publish_from_publish(&self, now_unix_ms: u64) -> Result<()> {
        let tier2_pending_shards = self.pending_published_tier2_snapshot_shard_count()?;
        let visible_publish_ms = self.last_publish_duration_ms.load(Ordering::Acquire);
        let mut adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        adaptive.update_completed_publish(now_unix_ms, visible_publish_ms, tier2_pending_shards);
        Ok(())
    }

    fn update_adaptive_publish_from_seal_backlog(&self, now_unix_ms: u64) -> Result<()> {
        let tier2_pending_shards = self.pending_published_tier2_snapshot_shard_count()?;
        let mut adaptive = self
            .adaptive_publish
            .lock()
            .map_err(|_| SspryError::from("Adaptive publish state lock poisoned."))?;
        adaptive.update_seal_backlog(now_unix_ms, tier2_pending_shards);
        Ok(())
    }

    fn run_published_tier2_snapshot_seal_cycle(&self) -> Result<()> {
        if self.publish_in_progress.load(Ordering::Acquire) {
            return Ok(());
        }
        let shard_idx = {
            let mut pending = self
                .pending_published_tier2_snapshot_shards
                .lock()
                .map_err(|_| SspryError::from("Published Tier2 snapshot queue lock poisoned."))?;
            let Some(shard_idx) = pending.iter().next().copied() else {
                return Ok(());
            };
            pending.remove(&shard_idx);
            shard_idx
        };

        self.published_tier2_snapshot_seal_in_progress
            .store(true, Ordering::SeqCst);
        let started = Instant::now();
        let result = (|| -> Result<(u64, u64)> {
            let published = self.published_store_set()?;
            let Some(store_lock) = published.stores.get(shard_idx) else {
                return Ok((0, 0));
            };
            match store_lock.try_lock() {
                Ok(store) => {
                    store.remove_tree_gate_snapshots()?;
                    store.persist_tier2_superblocks_snapshot()?;
                    Ok((1, 0))
                }
                Err(TryLockError::WouldBlock) => {
                    self.enqueue_published_tier2_snapshot_shards([shard_idx])?;
                    Ok((0, 0))
                }
                Err(TryLockError::Poisoned(_)) => {
                    Err(SspryError::from("Candidate store lock poisoned."))
                }
            }
        })();
        self.published_tier2_snapshot_seal_in_progress
            .store(false, Ordering::SeqCst);

        let (persisted_shards, failures) = match result {
            Ok(values) => values,
            Err(_) => {
                let _ = self.enqueue_published_tier2_snapshot_shards([shard_idx]);
                (0, 1)
            }
        };
        self.last_published_tier2_snapshot_seal_duration_ms.store(
            started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
            Ordering::SeqCst,
        );
        self.last_published_tier2_snapshot_seal_persisted_shards
            .store(persisted_shards, Ordering::SeqCst);
        self.last_published_tier2_snapshot_seal_failures
            .store(failures, Ordering::SeqCst);
        if persisted_shards > 0 || failures > 0 {
            self.published_tier2_snapshot_seal_runs_total
                .fetch_add(1, Ordering::SeqCst);
            self.last_published_tier2_snapshot_seal_completed_unix_ms
                .store(current_unix_ms(), Ordering::SeqCst);
        }
        let _ = self.update_adaptive_publish_from_seal_backlog(current_unix_ms());
        Ok(())
    }

    fn handle_begin_index_session(&self) -> Result<CandidateIndexSessionResponse> {
        if self.publish_requested.load(Ordering::Acquire)
            || self.publish_in_progress.load(Ordering::Acquire)
            || self.mutations_paused.load(Ordering::Acquire)
        {
            return Err(SspryError::from(
                "server is publishing; index session unavailable; retry later",
            ));
        }
        match self
            .active_index_sessions
            .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
        {
            Ok(_) => {
                let now = current_unix_ms();
                self.index_session_total_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_submitted_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_processed_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_started_unix_ms
                    .store(now, Ordering::SeqCst);
                self.index_session_last_update_unix_ms
                    .store(now, Ordering::SeqCst);
                self.index_session_server_insert_batch_count
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_shards_touched
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_total_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_parse_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_group_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_build_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_finalize_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_resolve_doc_state_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_sidecars_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_sidecar_payloads_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_bloom_payload_assemble_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_bloom_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_metadata_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_external_id_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_doc_row_build_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_bloom_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_metadata_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_external_id_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_append_doc_records_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_write_existing_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_install_docs_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_tier2_update_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_persist_meta_us
                    .store(0, Ordering::SeqCst);
                self.index_session_server_insert_batch_store_rebalance_tier2_us
                    .store(0, Ordering::SeqCst);
                Ok(CandidateIndexSessionResponse {
                    message: "index session started".to_owned(),
                })
            }
            Err(_) => Err(SspryError::from(
                "another index session is already active; retry later",
            )),
        }
    }

    fn handle_update_index_session_progress(
        &self,
        request: &CandidateIndexSessionProgressRequest,
    ) -> Result<CandidateIndexSessionResponse> {
        if self.active_index_sessions.load(Ordering::Acquire) == 0 {
            return Err(SspryError::from(
                "no active index session; cannot update progress",
            ));
        }
        if let Some(total) = request.total_documents {
            self.index_session_total_documents
                .store(total, Ordering::SeqCst);
        }
        self.index_session_submitted_documents
            .store(request.submitted_documents, Ordering::SeqCst);
        self.index_session_processed_documents
            .store(request.processed_documents, Ordering::SeqCst);
        self.index_session_last_update_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        Ok(CandidateIndexSessionResponse {
            message: "index session progress updated".to_owned(),
        })
    }

    fn record_index_session_insert_progress(&self, inserted_count: usize) {
        if inserted_count == 0 || self.active_index_sessions.load(Ordering::Acquire) == 0 {
            return;
        }
        let inserted_count = inserted_count as u64;
        self.index_session_submitted_documents
            .fetch_add(inserted_count, Ordering::SeqCst);
        self.index_session_processed_documents
            .fetch_add(inserted_count, Ordering::SeqCst);
        self.index_session_last_update_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
    }

    fn record_index_session_insert_batch_profile(
        &self,
        documents: usize,
        shards_touched: usize,
        total: Duration,
        parse: Duration,
        group: Duration,
        build: Duration,
        store: Duration,
        finalize: Duration,
        store_profile: &CandidateInsertBatchProfile,
    ) {
        if documents == 0 || self.active_index_sessions.load(Ordering::Acquire) == 0 {
            return;
        }
        self.index_session_server_insert_batch_count
            .fetch_add(1, Ordering::SeqCst);
        self.index_session_server_insert_batch_documents
            .fetch_add(documents as u64, Ordering::SeqCst);
        self.index_session_server_insert_batch_shards_touched
            .fetch_add(shards_touched as u64, Ordering::SeqCst);
        self.index_session_server_insert_batch_total_us.fetch_add(
            total.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_parse_us.fetch_add(
            parse.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_group_us.fetch_add(
            group.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_build_us.fetch_add(
            build.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_store_us.fetch_add(
            store.as_micros().min(u128::from(u64::MAX)) as u64,
            Ordering::SeqCst,
        );
        self.index_session_server_insert_batch_finalize_us
            .fetch_add(
                finalize.as_micros().min(u128::from(u64::MAX)) as u64,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_resolve_doc_state_us
            .fetch_add(store_profile.resolve_doc_state_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_sidecars_us
            .fetch_add(store_profile.append_sidecars_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_sidecar_payloads_us
            .fetch_add(store_profile.append_sidecar_payloads_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_bloom_payload_assemble_us
            .fetch_add(
                store_profile.append_bloom_payload_assemble_us,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_bloom_payload_us
            .fetch_add(store_profile.append_bloom_payload_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_metadata_payload_us
            .fetch_add(store_profile.append_metadata_payload_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_external_id_payload_us
            .fetch_add(
                store_profile.append_external_id_payload_us,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_tier2_bloom_payload_us
            .fetch_add(
                store_profile.append_tier2_bloom_payload_us,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_doc_row_build_us
            .fetch_add(store_profile.append_doc_row_build_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_bloom_payload_bytes
            .fetch_add(store_profile.append_bloom_payload_bytes, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_append_metadata_payload_bytes
            .fetch_add(
                store_profile.append_metadata_payload_bytes,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_external_id_payload_bytes
            .fetch_add(
                store_profile.append_external_id_payload_bytes,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes
            .fetch_add(
                store_profile.append_tier2_bloom_payload_bytes,
                Ordering::SeqCst,
            );
        self.index_session_server_insert_batch_store_append_doc_records_us
            .fetch_add(store_profile.append_doc_records_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_write_existing_us
            .fetch_add(store_profile.write_existing_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_install_docs_us
            .fetch_add(store_profile.install_docs_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_tier2_update_us
            .fetch_add(store_profile.tier2_update_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_persist_meta_us
            .fetch_add(store_profile.persist_meta_us, Ordering::SeqCst);
        self.index_session_server_insert_batch_store_rebalance_tier2_us
            .fetch_add(store_profile.rebalance_tier2_us, Ordering::SeqCst);
    }

    fn handle_end_index_session(&self) -> Result<CandidateIndexSessionResponse> {
        let previous = self.active_index_sessions.swap(0, Ordering::SeqCst);
        if previous == 0 {
            return Ok(CandidateIndexSessionResponse {
                message: "no active index session".to_owned(),
            });
        }
        self.index_session_last_update_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        let _ = self.update_adaptive_publish_from_index_session();
        Ok(CandidateIndexSessionResponse {
            message: "index session finished".to_owned(),
        })
    }

    fn index_server_insert_batch_profile_json(&self) -> Value {
        let mut out = Map::new();
        for (key, value) in [
            (
                "batches",
                self.index_session_server_insert_batch_count
                    .load(Ordering::Acquire),
            ),
            (
                "documents",
                self.index_session_server_insert_batch_documents
                    .load(Ordering::Acquire),
            ),
            (
                "shards_touched_total",
                self.index_session_server_insert_batch_shards_touched
                    .load(Ordering::Acquire),
            ),
            (
                "total_us",
                self.index_session_server_insert_batch_total_us
                    .load(Ordering::Acquire),
            ),
            (
                "parse_us",
                self.index_session_server_insert_batch_parse_us
                    .load(Ordering::Acquire),
            ),
            (
                "group_us",
                self.index_session_server_insert_batch_group_us
                    .load(Ordering::Acquire),
            ),
            (
                "build_us",
                self.index_session_server_insert_batch_build_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_us",
                self.index_session_server_insert_batch_store_us
                    .load(Ordering::Acquire),
            ),
            (
                "finalize_us",
                self.index_session_server_insert_batch_finalize_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_resolve_doc_state_us",
                self.index_session_server_insert_batch_store_resolve_doc_state_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_sidecars_us",
                self.index_session_server_insert_batch_store_append_sidecars_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_sidecar_payloads_us",
                self.index_session_server_insert_batch_store_append_sidecar_payloads_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_bloom_payload_assemble_us",
                self.index_session_server_insert_batch_store_append_bloom_payload_assemble_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_bloom_payload_us",
                self.index_session_server_insert_batch_store_append_bloom_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_metadata_payload_us",
                self.index_session_server_insert_batch_store_append_metadata_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_external_id_payload_us",
                self.index_session_server_insert_batch_store_append_external_id_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_tier2_bloom_payload_us",
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_doc_row_build_us",
                self.index_session_server_insert_batch_store_append_doc_row_build_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_bloom_payload_bytes",
                self.index_session_server_insert_batch_store_append_bloom_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_metadata_payload_bytes",
                self.index_session_server_insert_batch_store_append_metadata_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_external_id_payload_bytes",
                self.index_session_server_insert_batch_store_append_external_id_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_tier2_bloom_payload_bytes",
                self.index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes
                    .load(Ordering::Acquire),
            ),
            (
                "store_append_doc_records_us",
                self.index_session_server_insert_batch_store_append_doc_records_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_write_existing_us",
                self.index_session_server_insert_batch_store_write_existing_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_install_docs_us",
                self.index_session_server_insert_batch_store_install_docs_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_tier2_update_us",
                self.index_session_server_insert_batch_store_tier2_update_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_persist_meta_us",
                self.index_session_server_insert_batch_store_persist_meta_us
                    .load(Ordering::Acquire),
            ),
            (
                "store_rebalance_tier2_us",
                self.index_session_server_insert_batch_store_rebalance_tier2_us
                    .load(Ordering::Acquire),
            ),
        ] {
            out.insert(key.to_owned(), json!(value));
        }
        Value::Object(out)
    }

    fn publish_readiness(&self, now_unix_ms: u64) -> PublishReadiness {
        let work_dirty = self.work_dirty.load(Ordering::Acquire);
        let publish_requested = self.publish_requested.load(Ordering::Acquire);
        let publish_in_progress = self.publish_in_progress.load(Ordering::Acquire);
        let mutations_paused = self.mutations_paused.load(Ordering::Acquire);
        let active_index_sessions = self.active_index_sessions.load(Ordering::Acquire);
        let active_mutations = self.active_mutations.load(Ordering::Acquire);
        let last_mutation = self.last_work_mutation_unix_ms.load(Ordering::Acquire);
        let idle_elapsed_ms = if last_mutation == 0 {
            0
        } else {
            now_unix_ms.saturating_sub(last_mutation)
        };
        let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
        let idle_threshold_ms = adaptive.current_idle_ms;
        let idle_remaining_ms = idle_threshold_ms.saturating_sub(idle_elapsed_ms);
        let (current_rss_kb, _) = current_process_memory_kb();
        let pressure = self.work_buffer_pressure_snapshot(
            current_rss_kb
                .saturating_mul(1024)
                .try_into()
                .unwrap_or(u64::MAX),
            adaptive.tier2_pending_shards,
        );
        let idle_eligible = self.config.workspace_mode
            && work_dirty
            && active_index_sessions == 0
            && active_mutations == 0
            && !publish_requested
            && !publish_in_progress
            && !mutations_paused
            && last_mutation != 0
            && idle_elapsed_ms >= idle_threshold_ms;
        let eligible = idle_eligible;
        let blocked_reason = if !self.config.workspace_mode {
            "workspace_disabled"
        } else if idle_eligible {
            "ready"
        } else if !work_dirty {
            "work_clean"
        } else if publish_requested {
            "publish_requested"
        } else if publish_in_progress {
            "publish_in_progress"
        } else if mutations_paused {
            "mutations_paused"
        } else if active_index_sessions > 0 {
            "active_index_sessions"
        } else if active_mutations > 0 {
            "active_mutations"
        } else if last_mutation == 0 {
            "awaiting_work_mutation_timestamp"
        } else if idle_elapsed_ms < idle_threshold_ms {
            "waiting_for_idle_window"
        } else {
            "ready"
        };
        PublishReadiness {
            eligible,
            blocked_reason,
            trigger_mode: if idle_eligible { "idle" } else { "blocked" },
            trigger_reason: adaptive.reason,
            idle_elapsed_ms,
            idle_threshold_ms,
            idle_remaining_ms,
            work_buffer_estimated_documents: pressure.estimated_documents,
            work_buffer_estimated_input_bytes: pressure.estimated_input_bytes,
            work_buffer_document_threshold: pressure.document_threshold,
            work_buffer_input_bytes_threshold: pressure.input_bytes_threshold,
            work_buffer_rss_threshold_bytes: pressure.rss_threshold_bytes,
            current_rss_bytes: pressure.current_rss_bytes,
            pressure_publish_blocked_by_seal_backlog: pressure
                .pressure_publish_blocked_by_seal_backlog,
            pending_tier2_snapshot_shards: pressure.pending_tier2_snapshot_shards,
            index_backpressure_delay_ms: pressure.index_backpressure_delay_ms,
        }
    }

    fn run_auto_publish_cycle(&self) -> Result<()> {
        let readiness = self.publish_readiness(current_unix_ms());
        if !readiness.eligible {
            return Ok(());
        }
        let _ = self.handle_publish()?;
        Ok(())
    }

    fn run_retired_root_prune_cycle(&self) -> Result<()> {
        if self.publish_in_progress.load(Ordering::Acquire)
            || self.active_index_sessions.load(Ordering::Acquire) > 0
            || self.active_mutations.load(Ordering::Acquire) > 0
        {
            return Ok(());
        }
        let retired_root = {
            let store_mode = self
                .store_mode
                .lock()
                .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
            match &*store_mode {
                StoreMode::Workspace { root, .. } => workspace_retired_root(root),
                StoreMode::Direct { .. } => return Ok(()),
            }
        };
        let _ =
            prune_workspace_retired_roots(&retired_root, DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP)?;
        Ok(())
    }

    fn candidate_stats_json_for_store_set_profiled(
        &self,
        store_set: &StoreSet,
        operation: &str,
    ) -> Result<(Map<String, Value>, u64, CandidateStatsBuildProfile)> {
        if let Some((stats, deleted_storage_bytes)) = store_set.cached_stats()? {
            return Ok((
                stats,
                deleted_storage_bytes,
                CandidateStatsBuildProfile::default(),
            ));
        }
        let started_collect = Instant::now();
        let mut stats_rows = Vec::with_capacity(store_set.stores.len());
        let mut deleted_storage_bytes = 0u64;
        for (shard_idx, store_lock) in store_set.stores.iter().enumerate() {
            let store = lock_candidate_store_with_timeout(store_lock, shard_idx, operation)?;
            stats_rows.push(store.stats());
            deleted_storage_bytes =
                deleted_storage_bytes.saturating_add(store.deleted_storage_bytes());
        }
        let collect_store_stats_ms = started_collect
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let started_disk_usage = Instant::now();
        let disk_usage_bytes = disk_usage_under(&store_set.root()?);
        let disk_usage_ms = started_disk_usage
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        let started_build_json = Instant::now();
        let stats = candidate_stats_json_from_parts_with_disk_usage(&stats_rows, disk_usage_bytes);
        let build_json_ms = started_build_json
            .elapsed()
            .as_millis()
            .try_into()
            .unwrap_or(u64::MAX);
        store_set.set_cached_stats(stats.clone(), deleted_storage_bytes)?;
        Ok((
            stats,
            deleted_storage_bytes,
            CandidateStatsBuildProfile {
                collect_store_stats_ms,
                disk_usage_ms,
                build_json_ms,
            },
        ))
    }

    fn current_stats_json(&self) -> Result<Map<String, Value>> {
        let started_total = Instant::now();
        let now_unix_ms = current_unix_ms();
        let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let published = self.published_store_set()?;
        let (mut stats, deleted_storage_bytes, published_stats_profile) =
            self.candidate_stats_json_for_store_set_profiled(&published, "stats")?;
        let mut work_stats_profile = CandidateStatsBuildProfile::default();
        let mut retired_stats_ms = 0u64;
        stats.insert("draining".to_owned(), json!(self.is_shutting_down()));
        stats.insert(
            "active_connections".to_owned(),
            json!(self.active_connections.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_mutations".to_owned(),
            json!(self.active_mutations.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_requested".to_owned(),
            json!(self.publish_requested.load(Ordering::Acquire)),
        );
        stats.insert(
            "mutations_paused".to_owned(),
            json!(self.mutations_paused.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_in_progress".to_owned(),
            json!(self.publish_in_progress.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_index_sessions".to_owned(),
            json!(self.active_index_sessions.load(Ordering::Acquire)),
        );
        stats.insert(
            "work_dirty".to_owned(),
            json!(self.work_dirty.load(Ordering::Acquire)),
        );
        stats.insert(
            "last_work_mutation_unix_ms".to_owned(),
            json!(self.last_work_mutation_unix_ms.load(Ordering::Acquire)),
        );
        stats.insert(
            "adaptive_publish".to_owned(),
            json!({
                "storage_class": adaptive.storage_class,
                "current_idle_ms": adaptive.current_idle_ms,
                "mode": adaptive.mode,
                "reason": adaptive.reason,
                "recent_publish_p95_ms": adaptive.recent_publish_p95_ms,
                "recent_submit_p95_ms": adaptive.recent_submit_p95_ms,
                "recent_store_p95_ms": adaptive.recent_store_p95_ms,
                "recent_publishes_in_window": adaptive.recent_publishes_in_window,
                "tier2_pending_shards": adaptive.tier2_pending_shards,
                "healthy_cycles": adaptive.healthy_cycles,
            }),
        );
        stats.insert(
            "search_workers".to_owned(),
            json!(self.config.search_workers),
        );
        stats.insert(
            "memory_budget_bytes".to_owned(),
            json!(self.config.memory_budget_bytes),
        );
        stats.insert(
            "tier2_superblock_budget_divisor".to_owned(),
            json!(self.config.tier2_superblock_budget_divisor),
        );
        let (current_rss_kb, peak_rss_kb) = current_process_memory_kb();
        stats.insert("current_rss_kb".to_owned(), json!(current_rss_kb));
        stats.insert("peak_rss_kb".to_owned(), json!(peak_rss_kb));
        stats.insert(
            "startup_cleanup_removed_roots".to_owned(),
            json!(self.startup_cleanup_removed_roots),
        );
        let index_total_documents = self.index_session_total_documents.load(Ordering::Acquire);
        let index_processed_documents = self
            .index_session_processed_documents
            .load(Ordering::Acquire);
        let index_submitted_documents = self
            .index_session_submitted_documents
            .load(Ordering::Acquire);
        let index_remaining_documents =
            index_total_documents.saturating_sub(index_processed_documents);
        let index_progress_percent = if index_total_documents == 0 {
            0.0
        } else {
            (index_processed_documents as f64 / index_total_documents as f64) * 100.0
        };
        let index_server_insert_batch_profile = self.index_server_insert_batch_profile_json();
        let mut index_session = Map::new();
        index_session.insert(
            "active".to_owned(),
            json!(self.active_index_sessions.load(Ordering::Acquire) > 0),
        );
        index_session.insert("total_documents".to_owned(), json!(index_total_documents));
        index_session.insert(
            "submitted_documents".to_owned(),
            json!(index_submitted_documents),
        );
        index_session.insert(
            "processed_documents".to_owned(),
            json!(index_processed_documents),
        );
        index_session.insert(
            "remaining_documents".to_owned(),
            json!(index_remaining_documents),
        );
        index_session.insert("progress_percent".to_owned(), json!(index_progress_percent));
        index_session.insert(
            "started_unix_ms".to_owned(),
            json!(self.index_session_started_unix_ms.load(Ordering::Acquire)),
        );
        index_session.insert(
            "last_update_unix_ms".to_owned(),
            json!(
                self.index_session_last_update_unix_ms
                    .load(Ordering::Acquire)
            ),
        );
        index_session.insert(
            "server_insert_batch_profile".to_owned(),
            index_server_insert_batch_profile,
        );
        stats.insert("index_session".to_owned(), Value::Object(index_session));
        if let Ok(runtime) = self.compaction_runtime.lock() {
            stats.insert(
                "compaction_running".to_owned(),
                json!(runtime.running_shard.is_some()),
            );
            stats.insert(
                "compaction_running_shard".to_owned(),
                runtime
                    .running_shard
                    .map(Value::from)
                    .unwrap_or(Value::Null),
            );
            stats.insert(
                "compaction_runs_total".to_owned(),
                json!(runtime.runs_total),
            );
            stats.insert(
                "compaction_mutation_retries_total".to_owned(),
                json!(runtime.mutation_retries_total),
            );
            stats.insert(
                "last_compaction_reclaimed_docs".to_owned(),
                json!(runtime.last_reclaimed_docs),
            );
            stats.insert(
                "last_compaction_reclaimed_bytes".to_owned(),
                json!(runtime.last_reclaimed_bytes),
            );
            stats.insert(
                "last_compaction_completed_unix_ms".to_owned(),
                runtime
                    .last_completed_unix_ms
                    .map(Value::from)
                    .unwrap_or(Value::Null),
            );
            stats.insert(
                "last_compaction_error".to_owned(),
                runtime
                    .last_error
                    .as_ref()
                    .map(|value| Value::from(value.clone()))
                    .unwrap_or(Value::Null),
            );
        }
        let startup_root_json = |profile: &StoreRootStartupProfile| {
            json!({
                "total_ms": profile.total_ms,
                "opened_existing_shards": profile.opened_existing_shards,
                "initialized_new_shards": profile.initialized_new_shards,
                "doc_count": profile.doc_count,
                "store_open_total_ms": profile.store_open_total_ms,
                "store_open_manifest_ms": profile.store_open_manifest_ms,
                "store_open_meta_ms": profile.store_open_meta_ms,
                "store_open_load_state_ms": profile.store_open_load_state_ms,
                "store_open_sidecars_ms": profile.store_open_sidecars_ms,
                "store_open_rebuild_indexes_ms": profile.store_open_rebuild_indexes_ms,
                "store_open_rebuild_sha_index_ms": profile.store_open_rebuild_sha_index_ms,
                "store_open_load_tier2_superblocks_ms": profile.store_open_load_tier2_superblocks_ms,
                "store_open_loaded_tier2_superblocks_from_snapshot_shards": profile.store_open_loaded_tier2_superblocks_from_snapshot_shards,
                "store_open_rebuild_tier2_superblocks_ms": profile.store_open_rebuild_tier2_superblocks_ms,
            })
        };
        stats.insert(
            "startup".to_owned(),
            json!({
                "total_ms": self.startup_profile.total_ms,
                "startup_cleanup_removed_roots": self.startup_cleanup_removed_roots,
                "current": startup_root_json(&self.startup_profile.current),
                "work": startup_root_json(&self.startup_profile.work),
            }),
        );
        stats.insert(
            "deleted_storage_bytes".to_owned(),
            json!(deleted_storage_bytes),
        );
        if let Some((published_root, work_root)) = self.workspace_roots()? {
            let work = self.work_store_set()?;
            let (work_stats, work_deleted_storage_bytes, work_profile) =
                self.candidate_stats_json_for_store_set_profiled(&work, "work stats")?;
            work_stats_profile = work_profile;
            let retired_root = workspace_retired_root(&self.config.candidate_config.root);
            let started_retired = Instant::now();
            let (retired_published_root_count, retired_published_disk_usage_bytes) =
                workspace_retired_stats(&retired_root);
            retired_stats_ms = started_retired
                .elapsed()
                .as_millis()
                .try_into()
                .unwrap_or(u64::MAX);
            stats.insert("workspace_mode".to_owned(), json!(true));
            stats.insert(
                "published_root".to_owned(),
                Value::String(published_root.display().to_string()),
            );
            stats.insert(
                "work_root".to_owned(),
                Value::String(work_root.display().to_string()),
            );
            let mut work_stats = work_stats;
            work_stats.insert(
                "deleted_storage_bytes".to_owned(),
                json!(work_deleted_storage_bytes),
            );
            let now_unix_ms = current_unix_ms();
            let readiness = self.publish_readiness(now_unix_ms);
            let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
            let published_doc_count = stats.get("doc_count").and_then(Value::as_u64).unwrap_or(0);
            let published_active_doc_count = stats
                .get("active_doc_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let published_disk_usage_bytes = stats
                .get("disk_usage_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let work_doc_count = work_stats
                .get("doc_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let work_active_doc_count = work_stats
                .get("active_doc_count")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let work_disk_usage_bytes = work_stats
                .get("disk_usage_bytes")
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let mut publish = Map::new();
            publish.insert(
                "pending".to_owned(),
                json!(self.work_dirty.load(Ordering::Acquire)),
            );
            publish.insert("eligible".to_owned(), json!(readiness.eligible));
            publish.insert(
                "blocked_reason".to_owned(),
                Value::String(readiness.blocked_reason.to_owned()),
            );
            publish.insert(
                "idle_elapsed_ms".to_owned(),
                json!(readiness.idle_elapsed_ms),
            );
            publish.insert(
                "idle_remaining_ms".to_owned(),
                json!(readiness.idle_remaining_ms),
            );
            publish.insert(
                "adaptive_idle_ms".to_owned(),
                json!(readiness.idle_threshold_ms),
            );
            publish.insert(
                "adaptive_mode".to_owned(),
                Value::String(adaptive.mode.to_owned()),
            );
            publish.insert(
                "adaptive_reason".to_owned(),
                Value::String(adaptive.reason.to_owned()),
            );
            publish.insert(
                "adaptive_storage_class".to_owned(),
                Value::String(adaptive.storage_class),
            );
            publish.insert(
                "trigger_mode".to_owned(),
                Value::String(readiness.trigger_mode.to_owned()),
            );
            publish.insert(
                "trigger_reason".to_owned(),
                Value::String(readiness.trigger_reason.to_owned()),
            );
            publish.insert(
                "work_buffer_estimated_documents".to_owned(),
                json!(readiness.work_buffer_estimated_documents),
            );
            publish.insert(
                "work_buffer_estimated_input_bytes".to_owned(),
                json!(readiness.work_buffer_estimated_input_bytes),
            );
            publish.insert(
                "work_buffer_document_threshold".to_owned(),
                json!(readiness.work_buffer_document_threshold),
            );
            publish.insert(
                "work_buffer_input_bytes_threshold".to_owned(),
                json!(readiness.work_buffer_input_bytes_threshold),
            );
            publish.insert(
                "work_buffer_rss_threshold_bytes".to_owned(),
                json!(readiness.work_buffer_rss_threshold_bytes),
            );
            publish.insert(
                "current_rss_bytes".to_owned(),
                json!(readiness.current_rss_bytes),
            );
            publish.insert(
                "pressure_publish_blocked_by_seal_backlog".to_owned(),
                json!(readiness.pressure_publish_blocked_by_seal_backlog),
            );
            publish.insert(
                "pending_tier2_snapshot_shards".to_owned(),
                json!(readiness.pending_tier2_snapshot_shards),
            );
            publish.insert(
                "index_backpressure_delay_ms".to_owned(),
                json!(readiness.index_backpressure_delay_ms),
            );
            publish.insert(
                "index_backpressure_events_total".to_owned(),
                json!(self.index_backpressure_events_total.load(Ordering::Acquire)),
            );
            publish.insert(
                "index_backpressure_sleep_ms_total".to_owned(),
                json!(
                    self.index_backpressure_sleep_ms_total
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "adaptive_recent_publish_p95_ms".to_owned(),
                json!(adaptive.recent_publish_p95_ms),
            );
            publish.insert(
                "adaptive_recent_submit_p95_ms".to_owned(),
                json!(adaptive.recent_submit_p95_ms),
            );
            publish.insert(
                "adaptive_recent_store_p95_ms".to_owned(),
                json!(adaptive.recent_store_p95_ms),
            );
            publish.insert(
                "adaptive_recent_publishes_in_window".to_owned(),
                json!(adaptive.recent_publishes_in_window),
            );
            publish.insert(
                "adaptive_tier2_pending_shards".to_owned(),
                json!(adaptive.tier2_pending_shards),
            );
            publish.insert(
                "adaptive_healthy_cycles".to_owned(),
                json!(adaptive.healthy_cycles),
            );
            publish.insert("published_doc_count".to_owned(), json!(published_doc_count));
            publish.insert(
                "published_active_doc_count".to_owned(),
                json!(published_active_doc_count),
            );
            publish.insert(
                "published_disk_usage_bytes".to_owned(),
                json!(published_disk_usage_bytes),
            );
            publish.insert("work_doc_count".to_owned(), json!(work_doc_count));
            publish.insert(
                "work_active_doc_count".to_owned(),
                json!(work_active_doc_count),
            );
            publish.insert(
                "work_disk_usage_bytes".to_owned(),
                json!(work_disk_usage_bytes),
            );
            publish.insert(
                "work_doc_delta_vs_published".to_owned(),
                json!(signed_delta_i64(work_doc_count, published_doc_count)),
            );
            publish.insert(
                "work_active_doc_delta_vs_published".to_owned(),
                json!(signed_delta_i64(
                    work_active_doc_count,
                    published_active_doc_count
                )),
            );
            publish.insert(
                "work_disk_usage_delta_vs_published".to_owned(),
                json!(signed_delta_i64(
                    work_disk_usage_bytes,
                    published_disk_usage_bytes
                )),
            );
            publish.insert(
                "retired_published_root_count".to_owned(),
                json!(retired_published_root_count),
            );
            publish.insert(
                "retired_published_disk_usage_bytes".to_owned(),
                json!(retired_published_disk_usage_bytes),
            );
            publish.insert(
                "retired_published_roots_to_keep".to_owned(),
                json!(DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP as u64),
            );
            publish.insert(
                "last_publish_started_unix_ms".to_owned(),
                json!(self.last_publish_started_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_completed_unix_ms".to_owned(),
                json!(self.last_publish_completed_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_duration_ms".to_owned(),
                json!(self.last_publish_duration_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_lock_wait_ms".to_owned(),
                json!(self.last_publish_lock_wait_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_swap_ms".to_owned(),
                json!(self.last_publish_swap_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_ms".to_owned(),
                json!(self.last_publish_promote_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_export_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_export_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_resolve_doc_state_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_resolve_doc_state_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_build_payloads_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_build_payloads_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_append_sidecars_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_append_sidecars_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_install_docs_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_install_docs_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_tier2_update_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_tier2_update_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_persist_meta_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_persist_meta_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_rebalance_tier2_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_rebalance_tier2_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_remove_work_root_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_remove_work_root_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_other_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_other_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_imported_docs".to_owned(),
                json!(
                    self.last_publish_promote_work_imported_docs
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_imported_shards".to_owned(),
                json!(
                    self.last_publish_promote_work_imported_shards
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_init_work_ms".to_owned(),
                json!(self.last_publish_init_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_persist_tier2_superblocks_ms".to_owned(),
                json!(
                    self.last_publish_persist_tier2_superblocks_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_tier2_snapshot_persist_failures".to_owned(),
                json!(
                    self.last_publish_tier2_snapshot_persist_failures
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_persisted_snapshot_shards".to_owned(),
                json!(
                    self.last_publish_persisted_snapshot_shards
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_reused_work_stores".to_owned(),
                json!(self.last_publish_reused_work_stores.load(Ordering::Acquire)),
            );
            publish.insert(
                "publish_runs_total".to_owned(),
                json!(self.publish_runs_total.load(Ordering::Acquire)),
            );
            publish.insert("observed_at_unix_ms".to_owned(), json!(now_unix_ms));
            stats.insert("work".to_owned(), Value::Object(work_stats));
            stats.insert("publish".to_owned(), Value::Object(publish));
            stats.insert(
                "published_tier2_snapshot_seal".to_owned(),
                json!({
                    "pending_shards": self.pending_published_tier2_snapshot_shard_count().unwrap_or(0),
                    "in_progress": self.published_tier2_snapshot_seal_in_progress.load(Ordering::Acquire),
                    "runs_total": self.published_tier2_snapshot_seal_runs_total.load(Ordering::Acquire),
                    "last_duration_ms": self.last_published_tier2_snapshot_seal_duration_ms.load(Ordering::Acquire),
                    "last_persisted_shards": self.last_published_tier2_snapshot_seal_persisted_shards.load(Ordering::Acquire),
                    "last_failures": self.last_published_tier2_snapshot_seal_failures.load(Ordering::Acquire),
                    "last_completed_unix_ms": self.last_published_tier2_snapshot_seal_completed_unix_ms.load(Ordering::Acquire),
                }),
            );
        } else {
            stats.insert("workspace_mode".to_owned(), json!(false));
        }
        stats.insert(
            "stats_profile".to_owned(),
            json!({
                "total_ms": started_total.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                "published": {
                    "collect_store_stats_ms": published_stats_profile.collect_store_stats_ms,
                    "disk_usage_ms": published_stats_profile.disk_usage_ms,
                    "build_json_ms": published_stats_profile.build_json_ms,
                },
                "work": {
                    "collect_store_stats_ms": work_stats_profile.collect_store_stats_ms,
                    "disk_usage_ms": work_stats_profile.disk_usage_ms,
                    "build_json_ms": work_stats_profile.build_json_ms,
                },
                "retired_stats_ms": retired_stats_ms,
            }),
        );
        Ok(stats)
    }

    fn status_json(&self) -> Result<Map<String, Value>> {
        let now_unix_ms = current_unix_ms();
        let adaptive = self.adaptive_publish_snapshot_or_default(now_unix_ms);
        let mut stats = Map::new();
        stats.insert("draining".to_owned(), json!(self.is_shutting_down()));
        stats.insert(
            "active_connections".to_owned(),
            json!(self.active_connections.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_mutations".to_owned(),
            json!(self.active_mutations.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_requested".to_owned(),
            json!(self.publish_requested.load(Ordering::Acquire)),
        );
        stats.insert(
            "mutations_paused".to_owned(),
            json!(self.mutations_paused.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_in_progress".to_owned(),
            json!(self.publish_in_progress.load(Ordering::Acquire)),
        );
        stats.insert(
            "active_index_sessions".to_owned(),
            json!(self.active_index_sessions.load(Ordering::Acquire)),
        );
        stats.insert(
            "work_dirty".to_owned(),
            json!(self.work_dirty.load(Ordering::Acquire)),
        );
        stats.insert(
            "last_work_mutation_unix_ms".to_owned(),
            json!(self.last_work_mutation_unix_ms.load(Ordering::Acquire)),
        );
        stats.insert(
            "adaptive_publish".to_owned(),
            json!({
                "storage_class": adaptive.storage_class,
                "current_idle_ms": adaptive.current_idle_ms,
                "mode": adaptive.mode,
                "reason": adaptive.reason,
                "recent_publish_p95_ms": adaptive.recent_publish_p95_ms,
                "recent_submit_p95_ms": adaptive.recent_submit_p95_ms,
                "recent_store_p95_ms": adaptive.recent_store_p95_ms,
                "recent_publishes_in_window": adaptive.recent_publishes_in_window,
                "tier2_pending_shards": adaptive.tier2_pending_shards,
                "healthy_cycles": adaptive.healthy_cycles,
            }),
        );
        stats.insert(
            "search_workers".to_owned(),
            json!(self.config.search_workers),
        );
        stats.insert(
            "memory_budget_bytes".to_owned(),
            json!(self.config.memory_budget_bytes),
        );
        stats.insert(
            "tier2_superblock_budget_divisor".to_owned(),
            json!(self.config.tier2_superblock_budget_divisor),
        );
        let (current_rss_kb, peak_rss_kb) = current_process_memory_kb();
        stats.insert("current_rss_kb".to_owned(), json!(current_rss_kb));
        stats.insert("peak_rss_kb".to_owned(), json!(peak_rss_kb));
        stats.insert(
            "startup_cleanup_removed_roots".to_owned(),
            json!(self.startup_cleanup_removed_roots),
        );

        let index_total_documents = self.index_session_total_documents.load(Ordering::Acquire);
        let index_processed_documents = self
            .index_session_processed_documents
            .load(Ordering::Acquire);
        let index_submitted_documents = self
            .index_session_submitted_documents
            .load(Ordering::Acquire);
        let index_remaining_documents =
            index_total_documents.saturating_sub(index_processed_documents);
        let index_progress_percent = if index_total_documents == 0 {
            0.0
        } else {
            (index_processed_documents as f64 / index_total_documents as f64) * 100.0
        };
        let index_server_insert_batch_profile = self.index_server_insert_batch_profile_json();
        stats.insert(
            "index_session".to_owned(),
            json!({
                "active": self.active_index_sessions.load(Ordering::Acquire) > 0,
                "total_documents": index_total_documents,
                "submitted_documents": index_submitted_documents,
                "processed_documents": index_processed_documents,
                "remaining_documents": index_remaining_documents,
                "progress_percent": index_progress_percent,
                "started_unix_ms": self.index_session_started_unix_ms.load(Ordering::Acquire),
                "last_update_unix_ms": self.index_session_last_update_unix_ms.load(Ordering::Acquire),
                "server_insert_batch_profile": index_server_insert_batch_profile,
            }),
        );

        stats.insert(
            "startup".to_owned(),
            json!({
                "total_ms": self.startup_profile.total_ms,
                "startup_cleanup_removed_roots": self.startup_cleanup_removed_roots,
                "current": {
                    "total_ms": self.startup_profile.current.total_ms,
                    "opened_existing_shards": self.startup_profile.current.opened_existing_shards,
                    "initialized_new_shards": self.startup_profile.current.initialized_new_shards,
                    "doc_count": self.startup_profile.current.doc_count,
                },
                "work": {
                    "total_ms": self.startup_profile.work.total_ms,
                    "opened_existing_shards": self.startup_profile.work.opened_existing_shards,
                    "initialized_new_shards": self.startup_profile.work.initialized_new_shards,
                    "doc_count": self.startup_profile.work.doc_count,
                }
            }),
        );

        if let Some((published_root, work_root)) = self.workspace_roots()? {
            let retired_root = workspace_retired_root(&self.config.candidate_config.root);
            let (retired_published_root_count, retired_published_disk_usage_bytes) =
                workspace_retired_stats(&retired_root);
            let now_unix_ms = current_unix_ms();
            let readiness = self.publish_readiness(now_unix_ms);
            stats.insert("workspace_mode".to_owned(), json!(true));
            stats.insert(
                "published_root".to_owned(),
                Value::String(published_root.display().to_string()),
            );
            stats.insert(
                "work_root".to_owned(),
                Value::String(work_root.display().to_string()),
            );
            let mut publish = Map::new();
            publish.insert(
                "pending".to_owned(),
                json!(self.work_dirty.load(Ordering::Acquire)),
            );
            publish.insert("eligible".to_owned(), json!(readiness.eligible));
            publish.insert(
                "blocked_reason".to_owned(),
                Value::String(readiness.blocked_reason.to_owned()),
            );
            publish.insert(
                "trigger_mode".to_owned(),
                Value::String(readiness.trigger_mode.to_owned()),
            );
            publish.insert(
                "trigger_reason".to_owned(),
                Value::String(readiness.trigger_reason.to_owned()),
            );
            publish.insert(
                "idle_elapsed_ms".to_owned(),
                json!(readiness.idle_elapsed_ms),
            );
            publish.insert(
                "idle_remaining_ms".to_owned(),
                json!(readiness.idle_remaining_ms),
            );
            publish.insert(
                "work_buffer_estimated_documents".to_owned(),
                json!(readiness.work_buffer_estimated_documents),
            );
            publish.insert(
                "work_buffer_estimated_input_bytes".to_owned(),
                json!(readiness.work_buffer_estimated_input_bytes),
            );
            publish.insert(
                "work_buffer_document_threshold".to_owned(),
                json!(readiness.work_buffer_document_threshold),
            );
            publish.insert(
                "work_buffer_input_bytes_threshold".to_owned(),
                json!(readiness.work_buffer_input_bytes_threshold),
            );
            publish.insert(
                "work_buffer_rss_threshold_bytes".to_owned(),
                json!(readiness.work_buffer_rss_threshold_bytes),
            );
            publish.insert(
                "current_rss_bytes".to_owned(),
                json!(readiness.current_rss_bytes),
            );
            publish.insert(
                "pressure_publish_blocked_by_seal_backlog".to_owned(),
                json!(readiness.pressure_publish_blocked_by_seal_backlog),
            );
            publish.insert(
                "pending_tier2_snapshot_shards".to_owned(),
                json!(readiness.pending_tier2_snapshot_shards),
            );
            publish.insert(
                "index_backpressure_delay_ms".to_owned(),
                json!(readiness.index_backpressure_delay_ms),
            );
            publish.insert(
                "index_backpressure_events_total".to_owned(),
                json!(self.index_backpressure_events_total.load(Ordering::Acquire)),
            );
            publish.insert(
                "index_backpressure_sleep_ms_total".to_owned(),
                json!(
                    self.index_backpressure_sleep_ms_total
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "retired_published_root_count".to_owned(),
                json!(retired_published_root_count),
            );
            publish.insert(
                "retired_published_disk_usage_bytes".to_owned(),
                json!(retired_published_disk_usage_bytes),
            );
            publish.insert(
                "retired_published_roots_to_keep".to_owned(),
                json!(DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP as u64),
            );
            publish.insert(
                "last_publish_started_unix_ms".to_owned(),
                json!(self.last_publish_started_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_completed_unix_ms".to_owned(),
                json!(self.last_publish_completed_unix_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_duration_ms".to_owned(),
                json!(self.last_publish_duration_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_lock_wait_ms".to_owned(),
                json!(self.last_publish_lock_wait_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_swap_ms".to_owned(),
                json!(self.last_publish_swap_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_ms".to_owned(),
                json!(self.last_publish_promote_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_promote_work_export_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_export_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_resolve_doc_state_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_resolve_doc_state_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_build_payloads_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_build_payloads_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_append_sidecars_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_append_sidecars_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_install_docs_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_install_docs_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_tier2_update_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_tier2_update_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_persist_meta_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_persist_meta_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_import_rebalance_tier2_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_import_rebalance_tier2_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_remove_work_root_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_remove_work_root_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_other_ms".to_owned(),
                json!(
                    self.last_publish_promote_work_other_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_imported_docs".to_owned(),
                json!(
                    self.last_publish_promote_work_imported_docs
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_promote_work_imported_shards".to_owned(),
                json!(
                    self.last_publish_promote_work_imported_shards
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_init_work_ms".to_owned(),
                json!(self.last_publish_init_work_ms.load(Ordering::Acquire)),
            );
            publish.insert(
                "last_publish_persist_tier2_superblocks_ms".to_owned(),
                json!(
                    self.last_publish_persist_tier2_superblocks_ms
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_tier2_snapshot_persist_failures".to_owned(),
                json!(
                    self.last_publish_tier2_snapshot_persist_failures
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_persisted_snapshot_shards".to_owned(),
                json!(
                    self.last_publish_persisted_snapshot_shards
                        .load(Ordering::Acquire)
                ),
            );
            publish.insert(
                "last_publish_reused_work_stores".to_owned(),
                json!(self.last_publish_reused_work_stores.load(Ordering::Acquire)),
            );
            publish.insert(
                "publish_runs_total".to_owned(),
                json!(self.publish_runs_total.load(Ordering::Acquire)),
            );
            publish.insert("observed_at_unix_ms".to_owned(), json!(now_unix_ms));
            stats.insert("publish".to_owned(), Value::Object(publish));
            stats.insert(
                "published_tier2_snapshot_seal".to_owned(),
                json!({
                    "pending_shards": self.pending_published_tier2_snapshot_shard_count().unwrap_or(0),
                    "in_progress": self.published_tier2_snapshot_seal_in_progress.load(Ordering::Acquire),
                    "runs_total": self.published_tier2_snapshot_seal_runs_total.load(Ordering::Acquire),
                    "last_duration_ms": self.last_published_tier2_snapshot_seal_duration_ms.load(Ordering::Acquire),
                    "last_persisted_shards": self.last_published_tier2_snapshot_seal_persisted_shards.load(Ordering::Acquire),
                    "last_failures": self.last_published_tier2_snapshot_seal_failures.load(Ordering::Acquire),
                    "last_completed_unix_ms": self.last_published_tier2_snapshot_seal_completed_unix_ms.load(Ordering::Acquire),
                }),
            );
        } else {
            stats.insert("workspace_mode".to_owned(), json!(false));
        }
        Ok(stats)
    }

    fn candidate_shard_count(&self) -> usize {
        self.config.candidate_shards.max(1)
    }

    fn candidate_store_index_for_sha256(&self, sha256: &[u8; 32]) -> usize {
        candidate_shard_index(sha256, self.candidate_shard_count())
    }

    fn merge_candidate_tier_used(values: &[String]) -> String {
        let normalized = values
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .filter(|value| !value.is_empty())
            .collect::<std::collections::HashSet<_>>();
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

    fn invalidate_search_caches(&self) {
        if let Ok(mut cache) = self.normalized_plan_cache.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.prepared_plan_cache.lock() {
            cache.clear();
        }
        if let Ok(mut cache) = self.query_cache.lock() {
            cache.clear();
        }
    }

    fn next_compaction_candidate_shard(&self) -> usize {
        let shard_count = self.candidate_shard_count().max(1);
        self.next_compaction_shard.fetch_add(1, Ordering::Relaxed) % shard_count
    }

    fn garbage_collect_retired_generations(&self, shard_idx: usize) -> Result<usize> {
        let work = self.work_store_set()?;
        let mut store = work.stores[shard_idx]
            .lock()
            .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
        let removed = store.garbage_collect_retired_generations()?;
        if removed > 0 {
            let _ = self.invalidate_work_stats_cache();
        }
        Ok(removed)
    }

    fn find_compaction_candidate(&self) -> Result<Option<(usize, CandidateCompactionSnapshot)>> {
        let shard_count = self.candidate_shard_count().max(1);
        let start = self.next_compaction_candidate_shard();
        for offset in 0..shard_count {
            let shard_idx = (start + offset) % shard_count;
            let _ = self.garbage_collect_retired_generations(shard_idx);
            if let Some(snapshot) = self.prepare_compaction_snapshot(shard_idx)? {
                self.next_compaction_shard
                    .store((shard_idx + 1) % shard_count, Ordering::Relaxed);
                return Ok(Some((shard_idx, snapshot)));
            }
        }
        Ok(None)
    }

    fn record_compaction_error(&self, message: String) {
        if let Ok(mut runtime) = self.compaction_runtime.lock() {
            runtime.running_shard = None;
            runtime.last_error = Some(message);
        }
    }

    fn prepare_compaction_snapshot(
        &self,
        shard_idx: usize,
    ) -> Result<Option<CandidateCompactionSnapshot>> {
        let work = self.work_store_set()?;
        let store = work.stores[shard_idx]
            .lock()
            .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
        store.prepare_compaction_snapshot(false)
    }

    fn apply_compaction_snapshot(
        &self,
        shard_idx: usize,
        snapshot: &CandidateCompactionSnapshot,
        compacted_root: &Path,
    ) -> Result<Option<CandidateCompactionResult>> {
        let work = self.work_store_set()?;
        let mut store = work.stores[shard_idx]
            .lock()
            .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
        store.apply_compaction_snapshot(snapshot, compacted_root)
    }

    fn run_compaction_cycle(&self) -> Result<()> {
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let Some((shard_idx, snapshot)) = self.find_compaction_candidate()? else {
            return Ok(());
        };

        {
            let mut runtime = self
                .compaction_runtime
                .lock()
                .map_err(|_| SspryError::from("Compaction runtime lock poisoned."))?;
            runtime.running_shard = Some(shard_idx);
            runtime.last_error = None;
        }

        let work = self.work_store_set()?;
        let compacted_root = compaction_work_root(
            &candidate_shard_root(&work.root()?, self.candidate_shard_count(), shard_idx),
            "compact",
        );
        let build_result = write_compacted_snapshot(&snapshot, &compacted_root);
        let apply_result = match build_result {
            Ok(()) => self.apply_compaction_snapshot(shard_idx, &snapshot, &compacted_root),
            Err(err) => Err(err),
        };

        match apply_result {
            Ok(Some(result)) => {
                let _ = self.invalidate_work_stats_cache();
                let mut runtime = self
                    .compaction_runtime
                    .lock()
                    .map_err(|_| SspryError::from("Compaction runtime lock poisoned."))?;
                runtime.running_shard = None;
                runtime.runs_total = runtime.runs_total.saturating_add(1);
                runtime.last_reclaimed_docs = result.reclaimed_docs;
                runtime.last_reclaimed_bytes = result.reclaimed_bytes;
                runtime.last_completed_unix_ms = Some(current_unix_ms());
                runtime.last_error = None;
            }
            Ok(None) => {
                let _ = fs::remove_dir_all(&compacted_root);
                let mut runtime = self
                    .compaction_runtime
                    .lock()
                    .map_err(|_| SspryError::from("Compaction runtime lock poisoned."))?;
                runtime.running_shard = None;
                runtime.mutation_retries_total = runtime.mutation_retries_total.saturating_add(1);
            }
            Err(err) => {
                let _ = fs::remove_dir_all(&compacted_root);
                self.record_compaction_error(err.to_string());
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn run_compaction_cycle_for_tests(&self) -> Result<()> {
        self.run_compaction_cycle()
    }

    fn query_cache_key(plan: &CompiledQueryPlan) -> Result<String> {
        serde_json::to_string(&compiled_query_plan_to_wire(plan)).map_err(SspryError::from)
    }

    fn normalized_plan_from_wire(&self, value: &Value) -> Result<Arc<CompiledQueryPlan>> {
        let key = serde_json::to_string(value).map_err(SspryError::from)?;
        if let Some(entry) = self
            .normalized_plan_cache
            .lock()
            .map_err(|_| SspryError::from("Normalized plan cache lock poisoned."))?
            .get(&key)
        {
            record_counter("rpc.handle_candidate_query_plan_cache_hits_total", 1);
            return Ok(entry);
        }
        record_counter("rpc.handle_candidate_query_plan_cache_misses_total", 1);
        let entry = Arc::new(compiled_query_plan_from_wire(value)?);
        let mut cache = self
            .normalized_plan_cache
            .lock()
            .map_err(|_| SspryError::from("Normalized plan cache lock poisoned."))?;
        cache.insert(key, entry.clone());
        Ok(entry)
    }

    fn shared_prepared_query_artifacts(
        &self,
        plan: &CompiledQueryPlan,
    ) -> Result<Arc<PreparedQueryArtifacts>> {
        let key = Self::query_cache_key(plan)?;
        if let Some(entry) = self
            .prepared_plan_cache
            .lock()
            .map_err(|_| SspryError::from("Prepared plan cache lock poisoned."))?
            .get(&key)
        {
            record_counter("rpc.handle_candidate_query_prepared_cache_hits_total", 1);
            return Ok(entry);
        }
        record_counter("rpc.handle_candidate_query_prepared_cache_misses_total", 1);
        let mut filter_keys = HashSet::<(usize, usize)>::new();
        let mut tier2_doc_filter_keys = HashSet::<(usize, usize)>::new();
        let published = self.published_store_set()?;
        let mut summary_cap_bytes = None::<usize>;
        for store_lock in &published.stores {
            let store = lock_candidate_store_blocking(store_lock)?;
            let shard_summary_cap = store.config().tier2_superblock_summary_cap_bytes;
            if let Some(existing) = summary_cap_bytes {
                if existing != shard_summary_cap {
                    return Err(SspryError::from(
                        "published shards use mixed tier2 superblock summary caps",
                    ));
                }
            } else {
                summary_cap_bytes = Some(shard_summary_cap);
            }
            filter_keys.extend(store.tier1_superblock_filter_keys());
            tier2_doc_filter_keys.extend(store.tier2_doc_filter_keys());
        }
        let mut ordered_filter_keys = filter_keys.into_iter().collect::<Vec<_>>();
        ordered_filter_keys.sort_unstable();
        let mut ordered_tier2_doc_filter_keys =
            tier2_doc_filter_keys.into_iter().collect::<Vec<_>>();
        ordered_tier2_doc_filter_keys.sort_unstable();
        let entry = build_prepared_query_artifacts(
            plan,
            &ordered_filter_keys,
            &ordered_tier2_doc_filter_keys,
            summary_cap_bytes
                .unwrap_or(crate::candidate::DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES),
        )?;
        let mut cache = self
            .prepared_plan_cache
            .lock()
            .map_err(|_| SspryError::from("Prepared plan cache lock poisoned."))?;
        cache.insert(key, entry.clone());
        Ok(entry)
    }

    fn collect_query_matches_single_store(
        store: &mut CandidateStore,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
    ) -> Result<(Vec<(String, u32)>, Vec<String>, CandidateQueryProfile)> {
        let mut hits = Vec::<(String, u32)>::new();
        let mut tier_used = Vec::<String>::new();
        let mut query_profile = CandidateQueryProfile::default();
        let collect_chunk = plan.max_candidates.max(1).min(4096);
        let mut cursor = 0usize;
        loop {
            let local =
                store.query_candidates_with_prepared(plan, prepared, cursor, collect_chunk)?;
            tier_used.push(local.tier_used.clone());
            hits.extend(local.sha256.into_iter().zip(local.scores.into_iter()));
            query_profile.merge_from(&local.query_profile);
            if let Some(next) = local.next_cursor {
                cursor = next;
            } else {
                break;
            }
        }
        Ok((hits, tier_used, query_profile))
    }

    fn collect_query_matches_all_shards(
        &self,
        plan: &CompiledQueryPlan,
    ) -> Result<CachedCandidateQuery> {
        let prepared = self.shared_prepared_query_artifacts(plan)?;
        let published = self.published_store_set()?;
        if self.candidate_shard_count() == 1 {
            let mut store = lock_candidate_store_blocking(&published.stores[0])?;
            let (mut hits, tier_used, query_profile) =
                Self::collect_query_matches_single_store(&mut store, plan, &prepared)?;
            hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            let ordered_hashes = hits.into_iter().map(|(sha256, _)| sha256).collect();
            return Ok(CachedCandidateQuery {
                ordered_hashes,
                tier_used: Self::merge_candidate_tier_used(&tier_used),
                query_profile,
            });
        }

        let worker_count = self
            .config
            .search_workers
            .max(1)
            .min(self.candidate_shard_count().max(1));

        if worker_count <= 1 {
            let mut hits = Vec::<(String, u32)>::new();
            let mut tier_used = Vec::<String>::new();
            let mut query_profile = CandidateQueryProfile::default();
            for store_lock in &published.stores {
                let mut store = lock_candidate_store_blocking(store_lock)?;
                let (local_hits, local_tiers, local_profile) =
                    Self::collect_query_matches_single_store(&mut store, plan, &prepared)?;
                hits.extend(local_hits);
                tier_used.extend(local_tiers);
                query_profile.merge_from(&local_profile);
            }
            hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            let ordered_hashes = hits.into_iter().map(|(sha256, _)| sha256).collect();
            return Ok(CachedCandidateQuery {
                ordered_hashes,
                tier_used: Self::merge_candidate_tier_used(&tier_used),
                query_profile,
            });
        }

        let next_shard = AtomicUsize::new(0);
        let partials = std::thread::scope(|scope| {
            let mut handles = Vec::with_capacity(worker_count);
            for _ in 0..worker_count {
                let stores = published.clone();
                let plan = plan;
                let prepared = prepared.clone();
                let next_shard = &next_shard;
                handles.push(scope.spawn(
                    move || -> Result<(Vec<(String, u32)>, Vec<String>, CandidateQueryProfile)> {
                        let mut local_hits = Vec::<(String, u32)>::new();
                        let mut local_tiers = Vec::<String>::new();
                        let mut local_profile = CandidateQueryProfile::default();
                        loop {
                            let shard_idx = next_shard.fetch_add(1, Ordering::Relaxed);
                            if shard_idx >= stores.stores.len() {
                                break;
                            }
                            let mut store =
                                lock_candidate_store_blocking(&stores.stores[shard_idx])?;
                            let (hits, tiers, profile) = Self::collect_query_matches_single_store(
                                &mut store, plan, &prepared,
                            )?;
                            local_hits.extend(hits);
                            local_tiers.extend(tiers);
                            local_profile.merge_from(&profile);
                        }
                        Ok((local_hits, local_tiers, local_profile))
                    },
                ));
            }

            let mut merged = Vec::with_capacity(handles.len());
            for handle in handles {
                let partial = handle
                    .join()
                    .map_err(|_| SspryError::from("Candidate query worker panicked."))??;
                merged.push(partial);
            }
            Ok::<Vec<(Vec<(String, u32)>, Vec<String>, CandidateQueryProfile)>, SspryError>(merged)
        })?;

        let mut hits = Vec::<(String, u32)>::new();
        let mut tier_used = Vec::<String>::new();
        let mut query_profile = CandidateQueryProfile::default();
        for (local_hits, local_tiers, local_profile) in partials {
            hits.extend(local_hits);
            tier_used.extend(local_tiers);
            query_profile.merge_from(&local_profile);
        }
        hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        let ordered_hashes = hits.into_iter().map(|(sha256, _)| sha256).collect();
        Ok(CachedCandidateQuery {
            ordered_hashes,
            tier_used: Self::merge_candidate_tier_used(&tier_used),
            query_profile,
        })
    }

    fn dispatch(&self, action: u8, payload: &[u8]) -> Result<Vec<u8>> {
        self.dispatch_inner(action, payload)
    }

    fn dispatch_inner(&self, action: u8, payload: &[u8]) -> Result<Vec<u8>> {
        if self.is_shutting_down()
            && matches!(
                action,
                ACTION_CANDIDATE_INSERT
                    | ACTION_CANDIDATE_INSERT_BATCH
                    | ACTION_CANDIDATE_DELETE
                    | ACTION_INDEX_SESSION_BEGIN
                    | ACTION_INDEX_SESSION_PROGRESS
                    | ACTION_PUBLISH
            )
        {
            return Err(SspryError::from(
                "server is shutting down; mutating requests are disabled",
            ));
        }
        match action {
            ACTION_PING => json_bytes(&json!({ "message": "pong" })),
            ACTION_INDEX_SESSION_BEGIN => json_bytes(&self.handle_begin_index_session()?),
            ACTION_INDEX_SESSION_END => json_bytes(&self.handle_end_index_session()?),
            ACTION_INDEX_SESSION_PROGRESS => {
                let request: CandidateIndexSessionProgressRequest = json_from_bytes(payload)?;
                json_bytes(&self.handle_update_index_session_progress(&request)?)
            }
            ACTION_CANDIDATE_INSERT => {
                let document: CandidateDocumentWire = json_from_bytes(payload)?;
                json_bytes(&self.handle_candidate_insert(&document)?)
            }
            ACTION_CANDIDATE_INSERT_BATCH => {
                let request: CandidateInsertBatchRequest = json_from_bytes(payload)?;
                json_bytes(&self.handle_candidate_insert_batch(&request.documents)?)
            }
            ACTION_CANDIDATE_DELETE => {
                let request: CandidateDeleteRequest = json_from_bytes(payload)?;
                json_bytes(&self.handle_candidate_delete(&request.sha256)?)
            }
            ACTION_CANDIDATE_QUERY => {
                let request: CandidateQueryRequest = json_from_bytes(payload)?;
                let plan = self.normalized_plan_from_wire(&request.plan)?;
                json_bytes(&self.handle_candidate_query(
                    CandidateQueryRequest {
                        plan: Value::Null,
                        cursor: request.cursor,
                        chunk_size: request.chunk_size,
                        include_external_ids: request.include_external_ids,
                    },
                    &plan,
                )?)
            }
            ACTION_CANDIDATE_STATUS => json_bytes(&Value::Object(self.status_json()?)),
            ACTION_CANDIDATE_STATS => json_bytes(&Value::Object(self.current_stats_json()?)),
            ACTION_SHUTDOWN => {
                self.shutdown.store(true, Ordering::SeqCst);
                json_bytes(&json!({ "message": "shutdown requested" }))
            }
            ACTION_PUBLISH => json_bytes(&self.handle_publish()?),
            _ => Err(SspryError::from(format!(
                "Unsupported action code: {action}"
            ))),
        }
    }

    fn parse_candidate_insert_document(
        &self,
        document: &CandidateDocumentWire,
        field_prefix: &str,
    ) -> Result<ParsedCandidateInsertDocument> {
        let sha256 = decode_sha256(&document.sha256)?;
        let bloom_filter = base64::engine::general_purpose::STANDARD
            .decode(document.bloom_filter_b64.as_bytes())
            .map_err(|_| {
                SspryError::from(format!(
                    "{field_prefix}.bloom_filter_b64 must be valid base64."
                ))
            })?;
        let tier2_bloom_filter = if let Some(payload) = &document.tier2_bloom_filter_b64 {
            base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map_err(|_| {
                    SspryError::from(format!(
                        "{field_prefix}.tier2_bloom_filter_b64 must be valid base64."
                    ))
                })?
        } else {
            Vec::new()
        };
        let bloom_item_estimate = document
            .bloom_item_estimate
            .map(|value| {
                if value < 0 {
                    Err(SspryError::from(format!(
                        "{field_prefix}.bloom_item_estimate must be >= 0."
                    )))
                } else {
                    Ok(value as usize)
                }
            })
            .transpose()?;
        let metadata = if let Some(payload) = &document.metadata_b64 {
            base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map_err(|_| {
                    SspryError::from(format!("{field_prefix}.metadata_b64 must be valid base64."))
                })?
        } else {
            Vec::new()
        };
        let tier2_bloom_item_estimate = document
            .tier2_bloom_item_estimate
            .map(|value| {
                if value < 0 {
                    Err(SspryError::from(format!(
                        "{field_prefix}.tier2_bloom_item_estimate must be >= 0."
                    )))
                } else {
                    Ok(value as usize)
                }
            })
            .transpose()?;
        Ok((
            sha256,
            document.file_size,
            bloom_item_estimate,
            bloom_filter,
            tier2_bloom_item_estimate,
            tier2_bloom_filter,
            document.special_population,
            metadata,
            document.external_id.clone(),
        ))
    }

    fn candidate_insert_response(
        result: crate::candidate::CandidateInsertResult,
    ) -> CandidateInsertResponse {
        CandidateInsertResponse {
            status: result.status,
            doc_id: result.doc_id,
            sha256: result.sha256,
        }
    }

    fn handle_candidate_insert(
        &self,
        document: &CandidateDocumentWire,
    ) -> Result<CandidateInsertResponse> {
        let _scope = scope("rpc.handle_candidate_insert");
        self.maybe_apply_index_backpressure(1, document.file_size);
        let _mutation = self.begin_mutation("insert")?;
        let _op = if self.mutation_affects_published_queries()? {
            Some(
                self.operation_gate
                    .read()
                    .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?,
            )
        } else {
            None
        };
        let parsed = self.parse_candidate_insert_document(document, "request.payload")?;
        let shard_idx = self.candidate_store_index_for_sha256(&parsed.0);
        let work = self.work_store_set()?;
        let mut store =
            lock_candidate_store_with_timeout(&work.stores[shard_idx], shard_idx, "insert")?;
        let result = store.insert_document_with_metadata(
            parsed.0,
            parsed.1,
            parsed.2,
            None,
            parsed.4,
            None,
            parsed.3.len(),
            &parsed.3,
            parsed.5.len(),
            &parsed.5,
            parsed.7.as_slice(),
            parsed.6,
            parsed.8,
        )?;
        drop(store);
        self.mark_work_mutation();
        self.record_work_buffer_growth(1, document.file_size);
        if self.mutation_affects_published_queries()? {
            self.invalidate_search_caches();
        }
        self.record_index_session_insert_progress(1);
        Ok(Self::candidate_insert_response(result))
    }

    fn handle_candidate_insert_batch(
        &self,
        documents: &[CandidateDocumentWire],
    ) -> Result<CandidateInsertBatchResponse> {
        let _scope = scope("rpc.handle_candidate_insert_batch");
        let batch_input_bytes = documents
            .iter()
            .map(|document| document.file_size)
            .sum::<u64>();
        self.maybe_apply_index_backpressure(documents.len(), batch_input_bytes);
        let _mutation = self.begin_mutation("insert batch")?;
        let _op = if self.mutation_affects_published_queries()? {
            Some(
                self.operation_gate
                    .read()
                    .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?,
            )
        } else {
            None
        };
        let started_total = Instant::now();
        let started_parse = Instant::now();
        let mut parsed_documents = Vec::with_capacity(documents.len());
        for (idx, document) in documents.iter().enumerate() {
            parsed_documents.push(self.parse_candidate_insert_document(
                document,
                &format!("request.payload.documents[{idx}]"),
            )?);
        }
        let parse_elapsed = started_parse.elapsed();
        let mut group_elapsed = Duration::ZERO;
        let mut build_elapsed = Duration::ZERO;
        let mut store_elapsed = Duration::ZERO;
        let mut store_profile_total = CandidateInsertBatchProfile::default();
        let shards_touched;

        let mut results = vec![None; parsed_documents.len()];
        let work = self.work_store_set()?;
        if self.candidate_shard_count() == 1 {
            shards_touched = usize::from(!parsed_documents.is_empty());
            let mut store = lock_candidate_store_with_timeout(&work.stores[0], 0, "insert batch")?;
            let started_build = Instant::now();
            let batch = parsed_documents
                .iter()
                .map(|row| {
                    (
                        row.0,
                        row.1,
                        row.2,
                        None,
                        row.4,
                        None,
                        row.3.len(),
                        row.3.clone(),
                        row.5.len(),
                        row.5.clone(),
                        row.7.clone(),
                        row.6,
                        row.8.clone(),
                    )
                })
                .collect::<Vec<_>>();
            build_elapsed += started_build.elapsed();
            let started_store = Instant::now();
            for (idx, result) in store
                .insert_documents_batch(&batch)?
                .into_iter()
                .enumerate()
            {
                results[idx] = Some(Self::candidate_insert_response(result));
            }
            let store_profile = store.last_insert_batch_profile();
            store_profile_total.resolve_doc_state_us = store_profile_total
                .resolve_doc_state_us
                .saturating_add(store_profile.resolve_doc_state_us);
            store_profile_total.append_sidecars_us = store_profile_total
                .append_sidecars_us
                .saturating_add(store_profile.append_sidecars_us);
            store_profile_total.append_sidecar_payloads_us = store_profile_total
                .append_sidecar_payloads_us
                .saturating_add(store_profile.append_sidecar_payloads_us);
            store_profile_total.append_bloom_payload_assemble_us = store_profile_total
                .append_bloom_payload_assemble_us
                .saturating_add(store_profile.append_bloom_payload_assemble_us);
            store_profile_total.append_bloom_payload_us = store_profile_total
                .append_bloom_payload_us
                .saturating_add(store_profile.append_bloom_payload_us);
            store_profile_total.append_metadata_payload_us = store_profile_total
                .append_metadata_payload_us
                .saturating_add(store_profile.append_metadata_payload_us);
            store_profile_total.append_external_id_payload_us = store_profile_total
                .append_external_id_payload_us
                .saturating_add(store_profile.append_external_id_payload_us);
            store_profile_total.append_tier2_bloom_payload_us = store_profile_total
                .append_tier2_bloom_payload_us
                .saturating_add(store_profile.append_tier2_bloom_payload_us);
            store_profile_total.append_doc_row_build_us = store_profile_total
                .append_doc_row_build_us
                .saturating_add(store_profile.append_doc_row_build_us);
            store_profile_total.append_bloom_payload_bytes = store_profile_total
                .append_bloom_payload_bytes
                .saturating_add(store_profile.append_bloom_payload_bytes);
            store_profile_total.append_metadata_payload_bytes = store_profile_total
                .append_metadata_payload_bytes
                .saturating_add(store_profile.append_metadata_payload_bytes);
            store_profile_total.append_external_id_payload_bytes = store_profile_total
                .append_external_id_payload_bytes
                .saturating_add(store_profile.append_external_id_payload_bytes);
            store_profile_total.append_tier2_bloom_payload_bytes = store_profile_total
                .append_tier2_bloom_payload_bytes
                .saturating_add(store_profile.append_tier2_bloom_payload_bytes);
            store_profile_total.append_doc_records_us = store_profile_total
                .append_doc_records_us
                .saturating_add(store_profile.append_doc_records_us);
            store_profile_total.write_existing_us = store_profile_total
                .write_existing_us
                .saturating_add(store_profile.write_existing_us);
            store_profile_total.install_docs_us = store_profile_total
                .install_docs_us
                .saturating_add(store_profile.install_docs_us);
            store_profile_total.tier2_update_us = store_profile_total
                .tier2_update_us
                .saturating_add(store_profile.tier2_update_us);
            store_profile_total.persist_meta_us = store_profile_total
                .persist_meta_us
                .saturating_add(store_profile.persist_meta_us);
            store_profile_total.rebalance_tier2_us = store_profile_total
                .rebalance_tier2_us
                .saturating_add(store_profile.rebalance_tier2_us);
            store_elapsed += started_store.elapsed();
        } else {
            let started_group = Instant::now();
            let mut grouped = HashMap::<usize, Vec<(usize, ParsedCandidateInsertDocument)>>::new();
            for (idx, row) in parsed_documents.into_iter().enumerate() {
                let shard_idx = self.candidate_store_index_for_sha256(&row.0);
                grouped.entry(shard_idx).or_default().push((idx, row));
            }
            group_elapsed = started_group.elapsed();
            shards_touched = grouped.len();
            for (shard_idx, rows) in grouped {
                let mut store = lock_candidate_store_with_timeout(
                    &work.stores[shard_idx],
                    shard_idx,
                    "insert batch",
                )?;
                let started_build = Instant::now();
                let batch = rows
                    .iter()
                    .map(|(_, row)| {
                        (
                            row.0,
                            row.1,
                            row.2,
                            None,
                            row.4,
                            None,
                            row.3.len(),
                            row.3.clone(),
                            row.5.len(),
                            row.5.clone(),
                            row.7.clone(),
                            row.6,
                            row.8.clone(),
                        )
                    })
                    .collect::<Vec<_>>();
                build_elapsed += started_build.elapsed();
                let started_store = Instant::now();
                for ((original_idx, _), result) in rows
                    .into_iter()
                    .zip(store.insert_documents_batch(&batch)?.into_iter())
                {
                    results[original_idx] = Some(Self::candidate_insert_response(result));
                }
                let store_profile = store.last_insert_batch_profile();
                store_profile_total.resolve_doc_state_us = store_profile_total
                    .resolve_doc_state_us
                    .saturating_add(store_profile.resolve_doc_state_us);
                store_profile_total.append_sidecars_us = store_profile_total
                    .append_sidecars_us
                    .saturating_add(store_profile.append_sidecars_us);
                store_profile_total.append_sidecar_payloads_us = store_profile_total
                    .append_sidecar_payloads_us
                    .saturating_add(store_profile.append_sidecar_payloads_us);
                store_profile_total.append_bloom_payload_assemble_us = store_profile_total
                    .append_bloom_payload_assemble_us
                    .saturating_add(store_profile.append_bloom_payload_assemble_us);
                store_profile_total.append_bloom_payload_us = store_profile_total
                    .append_bloom_payload_us
                    .saturating_add(store_profile.append_bloom_payload_us);
                store_profile_total.append_metadata_payload_us = store_profile_total
                    .append_metadata_payload_us
                    .saturating_add(store_profile.append_metadata_payload_us);
                store_profile_total.append_external_id_payload_us = store_profile_total
                    .append_external_id_payload_us
                    .saturating_add(store_profile.append_external_id_payload_us);
                store_profile_total.append_tier2_bloom_payload_us = store_profile_total
                    .append_tier2_bloom_payload_us
                    .saturating_add(store_profile.append_tier2_bloom_payload_us);
                store_profile_total.append_doc_row_build_us = store_profile_total
                    .append_doc_row_build_us
                    .saturating_add(store_profile.append_doc_row_build_us);
                store_profile_total.append_bloom_payload_bytes = store_profile_total
                    .append_bloom_payload_bytes
                    .saturating_add(store_profile.append_bloom_payload_bytes);
                store_profile_total.append_metadata_payload_bytes = store_profile_total
                    .append_metadata_payload_bytes
                    .saturating_add(store_profile.append_metadata_payload_bytes);
                store_profile_total.append_external_id_payload_bytes = store_profile_total
                    .append_external_id_payload_bytes
                    .saturating_add(store_profile.append_external_id_payload_bytes);
                store_profile_total.append_tier2_bloom_payload_bytes = store_profile_total
                    .append_tier2_bloom_payload_bytes
                    .saturating_add(store_profile.append_tier2_bloom_payload_bytes);
                store_profile_total.append_doc_records_us = store_profile_total
                    .append_doc_records_us
                    .saturating_add(store_profile.append_doc_records_us);
                store_profile_total.write_existing_us = store_profile_total
                    .write_existing_us
                    .saturating_add(store_profile.write_existing_us);
                store_profile_total.install_docs_us = store_profile_total
                    .install_docs_us
                    .saturating_add(store_profile.install_docs_us);
                store_profile_total.tier2_update_us = store_profile_total
                    .tier2_update_us
                    .saturating_add(store_profile.tier2_update_us);
                store_profile_total.persist_meta_us = store_profile_total
                    .persist_meta_us
                    .saturating_add(store_profile.persist_meta_us);
                store_profile_total.rebalance_tier2_us = store_profile_total
                    .rebalance_tier2_us
                    .saturating_add(store_profile.rebalance_tier2_us);
                store_elapsed += started_store.elapsed();
            }
        }
        let started_finalize = Instant::now();
        let results = results.into_iter().flatten().collect::<Vec<_>>();
        if !results.is_empty() {
            self.mark_work_mutation();
            self.record_work_buffer_growth(results.len() as u64, batch_input_bytes);
        }
        if self.mutation_affects_published_queries()? {
            self.invalidate_search_caches();
        }
        self.record_index_session_insert_progress(results.len());
        let finalize_elapsed = started_finalize.elapsed();
        self.record_index_session_insert_batch_profile(
            documents.len(),
            shards_touched,
            started_total.elapsed(),
            parse_elapsed,
            group_elapsed,
            build_elapsed,
            store_elapsed,
            finalize_elapsed,
            &store_profile_total,
        );
        Ok(CandidateInsertBatchResponse {
            inserted_count: results.len(),
            results,
        })
    }

    fn handle_candidate_delete(&self, sha256: &str) -> Result<CandidateDeleteResponse> {
        let _scope = scope("rpc.handle_candidate_delete");
        let _mutation = self.begin_mutation("delete")?;
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let decoded = decode_sha256(sha256)?;
        let shard_idx = self.candidate_store_index_for_sha256(&decoded);
        let published = self.published_store_set()?;
        let mut published_store = lock_candidate_store_with_timeout(
            &published.stores[shard_idx],
            shard_idx,
            "delete published",
        )?;
        let published_result = published_store.delete_document(sha256)?;
        drop(published_store);
        if published_result.status == "deleted" {
            let _ = self.enqueue_published_tier2_snapshot_shards([shard_idx]);
        }

        let work = self.work_store_set()?;
        let work_result = if Arc::ptr_eq(&published, &work) {
            None
        } else {
            let mut work_store = lock_candidate_store_with_timeout(
                &work.stores[shard_idx],
                shard_idx,
                "delete work",
            )?;
            Some(work_store.delete_document(sha256)?)
        };

        let result = match work_result {
            Some(result) if published_result.status != "deleted" && result.status == "deleted" => {
                result
            }
            _ => published_result,
        };
        if result.status == "deleted" {
            let _ = self.invalidate_published_stats_cache();
            let _ = self.invalidate_work_stats_cache();
        }
        self.invalidate_search_caches();
        Ok(CandidateDeleteResponse {
            status: result.status,
            sha256: result.sha256,
            doc_id: result.doc_id,
        })
    }

    fn handle_candidate_query(
        &self,
        request: CandidateQueryRequest,
        plan: &CompiledQueryPlan,
    ) -> Result<CandidateQueryResponse> {
        let _scope = scope("rpc.handle_candidate_query");
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
        let chunk_size = request
            .chunk_size
            .unwrap_or(DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE)
            .max(1);
        let cache_key = Self::query_cache_key(&plan)?;
        let cached = {
            let mut cache = self
                .query_cache
                .lock()
                .map_err(|_| SspryError::from("Query cache lock poisoned."))?;
            cache.get(&cache_key)
        };
        let cached = if let Some(entry) = cached {
            record_counter("rpc.handle_candidate_query_cache_hits_total", 1);
            entry
        } else {
            record_counter("rpc.handle_candidate_query_cache_misses_total", 1);
            let entry = Arc::new(self.collect_query_matches_all_shards(&plan)?);
            let mut cache = self
                .query_cache
                .lock()
                .map_err(|_| SspryError::from("Query cache lock poisoned."))?;
            cache.insert(cache_key, entry.clone());
            entry
        };

        let total_candidates = cached.ordered_hashes.len();
        let start = request.cursor.min(total_candidates);
        let end = (start + chunk_size).min(total_candidates);
        let page = cached.ordered_hashes[start..end].to_vec();
        let next_cursor = if end < total_candidates {
            Some(end)
        } else {
            None
        };
        record_counter(
            "rpc.handle_candidate_query_total_candidates",
            total_candidates as u64,
        );
        let external_ids = if request.include_external_ids {
            let mut values = vec![None; page.len()];
            let mut by_shard = HashMap::<usize, Vec<(usize, String)>>::new();
            let published = self.published_store_set()?;
            for (idx, sha256_hex) in page.iter().enumerate() {
                let mut decoded = [0u8; 32];
                hex::decode_to_slice(sha256_hex, &mut decoded)?;
                let shard_idx = self.candidate_store_index_for_sha256(&decoded);
                by_shard
                    .entry(shard_idx)
                    .or_default()
                    .push((idx, sha256_hex.clone()));
            }
            for (shard_idx, items) in by_shard {
                let store = lock_candidate_store_with_timeout(
                    &published.stores[shard_idx],
                    shard_idx,
                    "query external ids",
                )?;
                let hashes = items
                    .iter()
                    .map(|(_, value)| value.clone())
                    .collect::<Vec<_>>();
                for ((idx, _), external_id) in items
                    .into_iter()
                    .zip(store.external_ids_for_sha256(&hashes))
                {
                    values[idx] = external_id;
                }
            }
            Some(values)
        } else {
            None
        };
        Ok(CandidateQueryResponse {
            returned_count: page.len(),
            sha256: page,
            total_candidates,
            cursor: start,
            next_cursor,
            tier_used: cached.tier_used.clone(),
            query_profile: cached.query_profile.clone(),
            external_ids,
        })
    }

    fn handle_publish(&self) -> Result<CandidatePublishResponse> {
        if self
            .publish_requested
            .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
            .is_err()
        {
            return Err(SspryError::from(
                "server is already publishing; retry later",
            ));
        }
        self.mutations_paused.store(true, Ordering::SeqCst);
        while self.active_mutations.load(Ordering::Acquire) > 0 {
            thread::sleep(Duration::from_millis(10));
        }
        self.publish_in_progress.store(true, Ordering::SeqCst);
        let result = (|| -> Result<CandidatePublishResponse> {
            let publish_lock_wait_started = Instant::now();
            self.last_publish_lock_wait_ms.store(0, Ordering::SeqCst);
            self.last_publish_promote_work_ms.store(0, Ordering::SeqCst);
            self.last_publish_promote_work_export_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_import_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_remove_work_root_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_other_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_imported_docs
                .store(0, Ordering::SeqCst);
            self.last_publish_promote_work_imported_shards
                .store(0, Ordering::SeqCst);
            self.last_publish_persist_tier2_superblocks_ms
                .store(0, Ordering::SeqCst);
            self.last_publish_tier2_snapshot_persist_failures
                .store(0, Ordering::SeqCst);
            self.last_publish_persisted_snapshot_shards
                .store(0, Ordering::SeqCst);
            let _op = self
                .operation_gate
                .write()
                .map_err(|_| SspryError::from("Server operation gate lock poisoned."))?;
            self.last_publish_lock_wait_ms.store(
                publish_lock_wait_started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            let publish_started_unix_ms = current_unix_ms();
            self.last_publish_started_unix_ms
                .store(publish_started_unix_ms, Ordering::SeqCst);
            let (
                workspace_root,
                current_root,
                retired_parent,
                publish_work,
                publish_work_root,
                published_store_set,
                published_is_empty,
            ) = {
                let mut store_mode = self
                    .store_mode
                    .lock()
                    .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
                let workspace_root = match &*store_mode {
                    StoreMode::Direct { .. } => {
                        return Err(SspryError::from(
                            "publish is only available for workspace stores",
                        ));
                    }
                    StoreMode::Workspace { root, .. } => root.clone(),
                };
                let current_root = workspace_current_root(&workspace_root);
                let retired_parent = workspace_retired_root(&workspace_root);
                let published_store_set = match &*store_mode {
                    StoreMode::Workspace { published, .. } => published.clone(),
                    StoreMode::Direct { .. } => unreachable!("workspace already checked"),
                };
                let published_is_empty = published_store_set.stores.iter().all(|store_lock| {
                    store_lock
                        .lock()
                        .map(|store| store.stats().doc_count == 0)
                        .unwrap_or(false)
                });
                let (publish_work, publish_work_root) = match &mut *store_mode {
                    StoreMode::Workspace {
                        work_active,
                        work_idle,
                        ..
                    } => {
                        let next_active = work_idle.take().ok_or_else(|| {
                            SspryError::from(
                                "idle work buffer is unavailable during publish; retry later",
                            )
                        })?;
                        let publish_work = std::mem::replace(work_active, next_active);
                        let publish_work_root = publish_work.root()?;
                        (publish_work, publish_work_root)
                    }
                    StoreMode::Direct { .. } => unreachable!("workspace already checked"),
                };
                (
                    workspace_root,
                    current_root,
                    retired_parent,
                    publish_work,
                    publish_work_root,
                    published_store_set,
                    published_is_empty,
                )
            };
            self.work_dirty.store(false, Ordering::SeqCst);
            self.reset_work_buffer_estimates();
            self.last_work_mutation_unix_ms.store(0, Ordering::SeqCst);
            self.mutations_paused.store(false, Ordering::SeqCst);
            let publish_shard_count = self.candidate_shard_count();
            let removed_current = 0usize;
            let mut reuse_work_stores = false;
            let mut changed_shards = vec![false; publish_shard_count];
            let published_store_set = if published_is_empty {
                let swap_started = Instant::now();
                if current_root.exists() {
                    fs::create_dir_all(&retired_parent)?;
                    let retired_root = next_workspace_retired_root_path(&retired_parent);
                    fs::rename(&current_root, &retired_root)?;
                }
                fs::rename(&publish_work_root, &current_root)?;
                self.last_publish_swap_ms.store(
                    swap_started
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                    Ordering::SeqCst,
                );
                let promote_started = Instant::now();
                self.last_publish_promote_work_export_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_resolve_doc_state_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_build_payloads_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_append_sidecars_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_install_docs_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_tier2_update_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_persist_meta_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_import_rebalance_tier2_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_remove_work_root_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_other_ms
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_imported_docs
                    .store(0, Ordering::SeqCst);
                self.last_publish_promote_work_imported_shards
                    .store(0, Ordering::SeqCst);
                publish_work.retarget_root(&current_root, publish_shard_count)?;
                reuse_work_stores = true;
                let published_store_set = publish_work;
                self.last_publish_promote_work_ms.store(
                    promote_started
                        .elapsed()
                        .as_millis()
                        .try_into()
                        .unwrap_or(u64::MAX),
                    Ordering::SeqCst,
                );
                for (shard_idx, store_lock) in published_store_set.stores.iter().enumerate() {
                    let store = store_lock
                        .lock()
                        .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
                    if store.stats().doc_count > 0 {
                        changed_shards[shard_idx] = true;
                    }
                }
                published_store_set
            } else {
                self.last_publish_swap_ms.store(0, Ordering::SeqCst);
                let promote_started = Instant::now();
                let mut export_ms_total = 0u128;
                let mut import_ms_total = 0u128;
                let mut import_profile_total = CandidateImportBatchProfile::default();
                let mut imported_docs_total = 0u64;
                let mut imported_shards_total = 0u64;
                for (shard_idx, store_lock) in publish_work.stores.iter().enumerate() {
                    let mut work_store = lock_candidate_store_with_timeout(
                        store_lock,
                        shard_idx,
                        "publish export work",
                    )?;
                    let export_started = Instant::now();
                    let imported = work_store.export_live_documents()?;
                    export_ms_total =
                        export_ms_total.saturating_add(export_started.elapsed().as_millis());
                    if imported.is_empty() {
                        continue;
                    }
                    changed_shards[shard_idx] = true;
                    imported_docs_total = imported_docs_total.saturating_add(imported.len() as u64);
                    imported_shards_total = imported_shards_total.saturating_add(1);
                    let import_started = Instant::now();
                    let mut published_store = published_store_set.stores[shard_idx]
                        .lock()
                        .map_err(|_| SspryError::from("Candidate store lock poisoned."))?;
                    let all_known_new = imported.iter().all(|document| {
                        !published_store.contains_live_document_sha256(&document.sha256)
                    });
                    if all_known_new {
                        published_store.import_documents_batch_known_new_quiet(&imported)?
                    } else {
                        published_store.import_documents_batch_quiet(&imported)?
                    }
                    let import_profile = published_store.last_import_batch_profile();
                    import_profile_total.resolve_doc_state_ms = import_profile_total
                        .resolve_doc_state_ms
                        .saturating_add(import_profile.resolve_doc_state_ms);
                    import_profile_total.build_payloads_ms = import_profile_total
                        .build_payloads_ms
                        .saturating_add(import_profile.build_payloads_ms);
                    import_profile_total.append_sidecars_ms = import_profile_total
                        .append_sidecars_ms
                        .saturating_add(import_profile.append_sidecars_ms);
                    import_profile_total.install_docs_ms = import_profile_total
                        .install_docs_ms
                        .saturating_add(import_profile.install_docs_ms);
                    import_profile_total.tier2_update_ms = import_profile_total
                        .tier2_update_ms
                        .saturating_add(import_profile.tier2_update_ms);
                    import_profile_total.persist_meta_ms = import_profile_total
                        .persist_meta_ms
                        .saturating_add(import_profile.persist_meta_ms);
                    import_profile_total.rebalance_tier2_ms = import_profile_total
                        .rebalance_tier2_ms
                        .saturating_add(import_profile.rebalance_tier2_ms);
                    import_ms_total =
                        import_ms_total.saturating_add(import_started.elapsed().as_millis());
                }
                let remove_started = Instant::now();
                if publish_work_root.exists() {
                    fs::remove_dir_all(&publish_work_root)?;
                }
                let remove_ms = remove_started.elapsed().as_millis();
                let promote_ms = promote_started.elapsed().as_millis();
                self.last_publish_promote_work_ms
                    .store(promote_ms.try_into().unwrap_or(u64::MAX), Ordering::SeqCst);
                self.last_publish_promote_work_export_ms.store(
                    export_ms_total.try_into().unwrap_or(u64::MAX),
                    Ordering::SeqCst,
                );
                self.last_publish_promote_work_import_ms.store(
                    import_ms_total.try_into().unwrap_or(u64::MAX),
                    Ordering::SeqCst,
                );
                self.last_publish_promote_work_import_resolve_doc_state_ms
                    .store(import_profile_total.resolve_doc_state_ms, Ordering::SeqCst);
                self.last_publish_promote_work_import_build_payloads_ms
                    .store(import_profile_total.build_payloads_ms, Ordering::SeqCst);
                self.last_publish_promote_work_import_append_sidecars_ms
                    .store(import_profile_total.append_sidecars_ms, Ordering::SeqCst);
                self.last_publish_promote_work_import_install_docs_ms
                    .store(import_profile_total.install_docs_ms, Ordering::SeqCst);
                self.last_publish_promote_work_import_tier2_update_ms
                    .store(import_profile_total.tier2_update_ms, Ordering::SeqCst);
                self.last_publish_promote_work_import_persist_meta_ms
                    .store(import_profile_total.persist_meta_ms, Ordering::SeqCst);
                self.last_publish_promote_work_import_rebalance_tier2_ms
                    .store(import_profile_total.rebalance_tier2_ms, Ordering::SeqCst);
                self.last_publish_promote_work_remove_work_root_ms
                    .store(remove_ms.try_into().unwrap_or(u64::MAX), Ordering::SeqCst);
                self.last_publish_promote_work_other_ms.store(
                    promote_ms
                        .saturating_sub(export_ms_total)
                        .saturating_sub(import_ms_total)
                        .saturating_sub(remove_ms)
                        .try_into()
                        .unwrap_or(0),
                    Ordering::SeqCst,
                );
                self.last_publish_promote_work_imported_docs
                    .store(imported_docs_total, Ordering::SeqCst);
                self.last_publish_promote_work_imported_shards
                    .store(imported_shards_total, Ordering::SeqCst);
                published_store_set
            };
            let persisted_snapshot_shards =
                changed_shards.iter().filter(|changed| **changed).count();
            self.last_publish_persisted_snapshot_shards.store(
                persisted_snapshot_shards.try_into().unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );

            let persist_tier2_started = Instant::now();
            self.enqueue_published_tier2_snapshot_shards(
                changed_shards
                    .iter()
                    .enumerate()
                    .filter_map(|(shard_idx, changed)| changed.then_some(shard_idx)),
            )?;
            self.last_publish_persist_tier2_superblocks_ms.store(
                persist_tier2_started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            self.last_publish_tier2_snapshot_persist_failures
                .store(0, Ordering::SeqCst);

            let removed_retired_roots = 0usize;
            self.last_publish_reused_work_stores
                .store(reuse_work_stores, Ordering::SeqCst);

            let init_work_started = Instant::now();
            let (idle_work_stores, removed_work, _) =
                ensure_candidate_stores_at_root(&self.config, &publish_work_root)?;
            self.last_publish_init_work_ms.store(
                init_work_started
                    .elapsed()
                    .as_millis()
                    .try_into()
                    .unwrap_or(u64::MAX),
                Ordering::SeqCst,
            );
            {
                let mut store_mode = self
                    .store_mode
                    .lock()
                    .map_err(|_| SspryError::from("Server store mode lock poisoned."))?;
                match &mut *store_mode {
                    StoreMode::Workspace {
                        root,
                        published,
                        work_idle,
                        ..
                    } => {
                        *root = workspace_root.clone();
                        *published = published_store_set;
                        *work_idle = Some(Arc::new(StoreSet::new(
                            publish_work_root.clone(),
                            idle_work_stores,
                        )));
                    }
                    StoreMode::Direct { .. } => unreachable!("workspace already checked"),
                }
            }
            if self.active_index_sessions.load(Ordering::Acquire) == 0 {
                self.index_session_total_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_submitted_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_processed_documents
                    .store(0, Ordering::SeqCst);
                self.index_session_started_unix_ms
                    .store(0, Ordering::SeqCst);
                self.index_session_last_update_unix_ms
                    .store(0, Ordering::SeqCst);
            }
            let publish_completed_unix_ms = current_unix_ms();
            self.last_publish_completed_unix_ms
                .store(publish_completed_unix_ms, Ordering::SeqCst);
            self.last_publish_duration_ms.store(
                publish_completed_unix_ms.saturating_sub(publish_started_unix_ms),
                Ordering::SeqCst,
            );
            self.publish_runs_total.fetch_add(1, Ordering::SeqCst);
            let _ = self.update_adaptive_publish_from_publish(publish_completed_unix_ms);
            self.invalidate_search_caches();
            Ok(CandidatePublishResponse {
                message: format!(
                    "published work root to {} (startup cleanup removed {}, retired cleanup removed {})",
                    current_root.display(),
                    removed_current.saturating_add(removed_work),
                    removed_retired_roots,
                ),
            })
        })();
        self.publish_in_progress.store(false, Ordering::SeqCst);
        self.mutations_paused.store(false, Ordering::SeqCst);
        self.publish_requested.store(false, Ordering::SeqCst);
        result
    }
}

#[cfg(unix)]
fn accept_unix(
    listener: UnixListener,
    state: Arc<ServerState>,
    max_request_bytes: usize,
) -> Result<()> {
    listener.set_nonblocking(true)?;
    loop {
        if state.is_shutting_down() {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let state = state.clone();
                state.active_connections.fetch_add(1, Ordering::AcqRel);
                thread::spawn(move || {
                    let _guard = ActiveConnectionGuard::new(state.clone());
                    let _ = serve_connection(stream, state, max_request_bytes);
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(SspryError::from(err.to_string())),
        }
    }
}

fn accept_tcp(
    listener: TcpListener,
    state: Arc<ServerState>,
    max_request_bytes: usize,
) -> Result<()> {
    listener.set_nonblocking(true)?;
    loop {
        if state.is_shutting_down() {
            return Ok(());
        }
        match listener.accept() {
            Ok((stream, _)) => {
                let _ = stream.set_nodelay(true);
                let state = state.clone();
                state.active_connections.fetch_add(1, Ordering::AcqRel);
                thread::spawn(move || {
                    let _guard = ActiveConnectionGuard::new(state.clone());
                    let _ = serve_connection(stream, state, max_request_bytes);
                });
            }
            Err(err) if err.kind() == ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(25));
            }
            Err(err) => return Err(SspryError::from(err.to_string())),
        }
    }
}

struct ActiveConnectionGuard {
    state: Arc<ServerState>,
}

impl ActiveConnectionGuard {
    fn new(state: Arc<ServerState>) -> Self {
        Self { state }
    }
}

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.state.active_connections.fetch_sub(1, Ordering::AcqRel);
    }
}

fn serve_connection<S>(
    mut stream: S,
    state: Arc<ServerState>,
    max_request_bytes: usize,
) -> Result<()>
where
    S: Read + Write,
{
    loop {
        let Some((version, action, payload)) = read_frame_optional(&mut stream)? else {
            return Ok(());
        };
        if version != PROTOCOL_VERSION {
            write_error_frame(
                &mut stream,
                &format!("Unsupported protocol version: {version}"),
            )?;
            return Ok(());
        }
        if payload.len() > max_request_bytes {
            write_error_frame(&mut stream, "Request is too large.")?;
            return Ok(());
        }
        match state.dispatch(action, &payload) {
            Ok(response_payload) => {
                write_frame(&mut stream, PROTOCOL_VERSION, STATUS_OK, &response_payload)?
            }
            Err(err) => write_error_frame(&mut stream, &err.to_string())?,
        }
    }
}

fn write_frame<W: Write>(
    writer: &mut W,
    version: u8,
    status_or_action: u8,
    payload: &[u8],
) -> Result<()> {
    let len =
        u32::try_from(payload.len()).map_err(|_| SspryError::from("Payload is too large."))?;
    let mut header = [0u8; HEADER_LEN];
    header[0] = version;
    header[1] = status_or_action;
    header[2..].copy_from_slice(&len.to_be_bytes());
    writer.write_all(&header)?;
    if !payload.is_empty() {
        writer.write_all(payload)?;
    }
    writer.flush()?;
    Ok(())
}

fn write_error_frame<W: Write>(writer: &mut W, message: &str) -> Result<()> {
    let payload = json!({ "type": "Error", "message": message });
    write_frame(
        writer,
        PROTOCOL_VERSION,
        STATUS_ERROR,
        &serde_json::to_vec(&payload)?,
    )
}

fn read_frame<R: Read>(reader: &mut R) -> Result<(u8, u8, Vec<u8>)> {
    let mut header = [0u8; HEADER_LEN];
    read_exact(reader, &mut header)?;
    let version = header[0];
    let status_or_action = header[1];
    let payload_len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact(reader, &mut payload)?;
    }
    Ok((version, status_or_action, payload))
}

fn read_frame_optional<R: Read>(reader: &mut R) -> Result<Option<(u8, u8, Vec<u8>)>> {
    let mut header = [0u8; HEADER_LEN];
    let first = match reader.read(&mut header[..1])? {
        0 => return Ok(None),
        n => n,
    };
    if first < 1 {
        return Ok(None);
    }
    if HEADER_LEN > 1 {
        read_exact(reader, &mut header[1..])?;
    }
    let version = header[0];
    let status_or_action = header[1];
    let payload_len = u32::from_be_bytes([header[2], header[3], header[4], header[5]]) as usize;
    let mut payload = vec![0u8; payload_len];
    if payload_len > 0 {
        read_exact(reader, &mut payload)?;
    }
    Ok(Some((version, status_or_action, payload)))
}

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0usize;
    while offset < buf.len() {
        match reader.read(&mut buf[offset..]) {
            Ok(0) => {
                return Err(SspryError::from("Connection closed while reading frame."));
            }
            Ok(n) => {
                offset += n;
            }
            Err(err) if err.kind() == ErrorKind::Interrupted => continue,
            Err(err) if matches!(err.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                return Err(SspryError::from(
                    "RPC read timed out while waiting for a server response. Increase --timeout for long-running requests.",
                ));
            }
            Err(err) => return Err(SspryError::from(err)),
        }
    }
    Ok(())
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(SspryError::from)
}

pub(crate) fn serialized_candidate_insert_batch_payload(rows: &[Vec<u8>]) -> Vec<u8> {
    let payload_len = rows.iter().map(Vec::len).sum::<usize>()
        + rows.len().saturating_sub(1)
        + br#"{"documents":["#.len()
        + b"]}".len();
    let mut payload = Vec::with_capacity(payload_len);
    payload.extend_from_slice(br#"{"documents":["#);
    for (idx, row) in rows.iter().enumerate() {
        if idx > 0 {
            payload.push(b',');
        }
        payload.extend_from_slice(row);
    }
    payload.extend_from_slice(b"]}");
    payload
}

fn json_from_bytes<T: DeserializeOwned>(payload: &[u8]) -> Result<T> {
    if payload.is_empty() {
        return serde_json::from_slice(b"{}").map_err(SspryError::from);
    }
    serde_json::from_slice(payload).map_err(SspryError::from)
}

fn compiled_query_plan_to_wire(plan: &CompiledQueryPlan) -> Value {
    json!({
        "version": 1,
        "tier2_gram_size": plan.tier2_gram_size,
        "tier1_gram_size": plan.tier1_gram_size,
        "patterns": plan.patterns.iter().map(|pattern| {
            json!({
                "id": pattern.pattern_id,
                "alternatives": pattern.alternatives,
                "tier2_alternatives": pattern.tier2_alternatives,
                "fixed_literals": pattern.fixed_literals,
                "fixed_literal_wide": pattern.fixed_literal_wide,
                "fixed_literal_fullword": pattern.fixed_literal_fullword,
            })
        }).collect::<Vec<_>>(),
        "ast": query_node_to_wire(&plan.root),
        "flags": {
            "force_tier1_only": plan.force_tier1_only,
            "allow_tier2_fallback": plan.allow_tier2_fallback,
            "max_candidates": plan.max_candidates,
        },
    })
}

fn compiled_query_plan_from_wire(value: &Value) -> Result<CompiledQueryPlan> {
    if !value.is_object() {
        return Err(SspryError::from("query plan payload must be an object"));
    }

    let patterns_raw = value
        .get("patterns")
        .and_then(Value::as_array)
        .ok_or_else(|| SspryError::from("query plan must contain a patterns list"))?;
    let mut patterns = Vec::with_capacity(patterns_raw.len());
    for item in patterns_raw {
        let object = item
            .as_object()
            .ok_or_else(|| SspryError::from("query plan patterns entries must be objects"))?;
        let pattern_id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| SspryError::from("invalid pattern id"))?
            .to_owned();
        let alternatives_raw = object
            .get("alternatives")
            .and_then(Value::as_array)
            .ok_or_else(|| SspryError::from("pattern alternatives must be a list"))?;
        let tier2_alternatives_raw = object
            .get("tier2_alternatives")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![Value::Array(Vec::new()); alternatives_raw.len()]);
        let fixed_literals_raw = object
            .get("fixed_literals")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![Value::Array(Vec::new()); alternatives_raw.len()]);
        let fixed_literal_wide_raw = object
            .get("fixed_literal_wide")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![Value::Bool(false); alternatives_raw.len()]);
        let fixed_literal_fullword_raw = object
            .get("fixed_literal_fullword")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![Value::Bool(false); alternatives_raw.len()]);
        let alt_count = alternatives_raw.len();
        let mut alternatives = Vec::with_capacity(alt_count);
        let mut tier2_alternatives = Vec::with_capacity(alt_count);
        let mut fixed_literals = Vec::with_capacity(alt_count);
        let mut fixed_literal_wide = Vec::with_capacity(alt_count);
        let mut fixed_literal_fullword = Vec::with_capacity(alt_count);
        for alt in alternatives_raw {
            let grams = alt
                .as_array()
                .ok_or_else(|| SspryError::from("pattern alternatives entries must be lists"))?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| SspryError::from("pattern contains out-of-range gram"))
                })
                .collect::<Result<Vec<_>>>()?;
            alternatives.push(grams);
        }
        for alt in tier2_alternatives_raw.into_iter().take(alt_count) {
            let grams = alt
                .as_array()
                .ok_or_else(|| {
                    SspryError::from("pattern tier2_alternatives entries must be lists")
                })?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| SspryError::from("pattern contains out-of-range tier2 gram"))
                })
                .collect::<Result<Vec<_>>>()?;
            tier2_alternatives.push(grams);
        }
        while tier2_alternatives.len() < alternatives.len() {
            tier2_alternatives.push(Vec::new());
        }
        for literal in fixed_literals_raw.into_iter().take(alt_count) {
            let bytes = literal
                .as_array()
                .ok_or_else(|| {
                    SspryError::from("pattern fixed_literals entries must be byte lists")
                })?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| SspryError::from("pattern fixed literal byte out of range"))
                        .and_then(|byte| {
                            u8::try_from(byte).map_err(|_| {
                                SspryError::from("pattern fixed literal byte out of range")
                            })
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            fixed_literals.push(bytes);
        }
        while fixed_literals.len() < alternatives.len() {
            fixed_literals.push(Vec::new());
        }
        for value in fixed_literal_wide_raw.into_iter().take(alt_count) {
            fixed_literal_wide.push(value.as_bool().ok_or_else(|| {
                SspryError::from("pattern fixed_literal_wide entries must be bools")
            })?);
        }
        while fixed_literal_wide.len() < alternatives.len() {
            fixed_literal_wide.push(false);
        }
        for value in fixed_literal_fullword_raw.into_iter().take(alt_count) {
            fixed_literal_fullword.push(value.as_bool().ok_or_else(|| {
                SspryError::from("pattern fixed_literal_fullword entries must be bools")
            })?);
        }
        while fixed_literal_fullword.len() < alternatives.len() {
            fixed_literal_fullword.push(false);
        }
        patterns.push(PatternPlan {
            pattern_id,
            alternatives,
            tier2_alternatives,
            fixed_literals,
            fixed_literal_wide,
            fixed_literal_fullword,
        });
    }

    let root = query_node_from_wire(
        value
            .get("ast")
            .ok_or_else(|| SspryError::from("query plan missing ast"))?,
    )?;
    let flags = value
        .get("flags")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let max_candidates = flags
        .get("max_candidates")
        .and_then(Value::as_u64)
        .unwrap_or(100_000) as usize;
    let max_candidates = normalize_max_candidates(max_candidates);
    Ok(CompiledQueryPlan {
        patterns,
        root,
        tier2_gram_size: value
            .get("tier2_gram_size")
            .and_then(Value::as_u64)
            .unwrap_or(3) as usize,
        tier1_gram_size: value
            .get("tier1_gram_size")
            .and_then(Value::as_u64)
            .unwrap_or(4) as usize,
        force_tier1_only: flags
            .get("force_tier1_only")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        allow_tier2_fallback: flags
            .get("allow_tier2_fallback")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        max_candidates,
    })
}

fn query_node_to_wire(node: &QueryNode) -> Value {
    let mut out = Map::new();
    out.insert("kind".to_owned(), Value::String(node.kind.clone()));
    if let Some(pattern_id) = &node.pattern_id {
        out.insert("pattern_id".to_owned(), Value::String(pattern_id.clone()));
    }
    if let Some(threshold) = node.threshold {
        out.insert("threshold".to_owned(), Value::from(threshold));
    }
    if !node.children.is_empty() {
        out.insert(
            "children".to_owned(),
            Value::Array(node.children.iter().map(query_node_to_wire).collect()),
        );
    }
    Value::Object(out)
}

fn query_node_from_wire(value: &Value) -> Result<QueryNode> {
    let object = value
        .as_object()
        .ok_or_else(|| SspryError::from("query ast node must be an object"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| SspryError::from("query ast node missing kind"))?
        .to_owned();
    let pattern_id = object
        .get("pattern_id")
        .and_then(Value::as_str)
        .map(ToOwned::to_owned);
    let threshold = object
        .get("threshold")
        .and_then(Value::as_u64)
        .map(|value| value as usize);
    let children = object
        .get("children")
        .and_then(Value::as_array)
        .map(|items| {
            items
                .iter()
                .map(query_node_from_wire)
                .collect::<Result<Vec<_>>>()
        })
        .transpose()?
        .unwrap_or_default();

    match kind.as_str() {
        "pattern" => {
            if pattern_id.is_none() {
                return Err(SspryError::from("pattern node requires a pattern_id"));
            }
        }
        "and" | "or" => {
            if children.is_empty() {
                return Err(SspryError::from(format!(
                    "{kind} node requires at least one child"
                )));
            }
        }
        "not" => {
            if children.len() != 1 {
                return Err(SspryError::from("not node requires exactly one child"));
            }
            if pattern_id.is_some() || threshold.is_some() {
                return Err(SspryError::from(
                    "not node must not use pattern_id or threshold",
                ));
            }
        }
        "n_of" => {
            if threshold.unwrap_or(0) == 0 {
                return Err(SspryError::from("n_of threshold must be > 0"));
            }
            if children.is_empty() {
                return Err(SspryError::from("n_of node requires children"));
            }
        }
        "filesize_eq" => {
            if pattern_id.as_deref() != Some("filesize") {
                return Err(SspryError::from(
                    "filesize_eq node requires pattern_id=filesize",
                ));
            }
            if threshold.is_none() {
                return Err(SspryError::from("filesize_eq node requires a threshold"));
            }
            if !children.is_empty() {
                return Err(SspryError::from("filesize_eq node must not have children"));
            }
        }
        "filesize_lt" | "filesize_le" | "filesize_gt" | "filesize_ge" => {
            if pattern_id.as_deref() != Some("filesize") {
                return Err(SspryError::from(format!(
                    "{kind} node requires pattern_id=filesize"
                )));
            }
            if threshold.is_none() {
                return Err(SspryError::from(format!(
                    "{kind} node requires a threshold"
                )));
            }
            if !children.is_empty() {
                return Err(SspryError::from(format!(
                    "{kind} node must not have children"
                )));
            }
        }
        "metadata_eq" => {
            let field = pattern_id
                .as_deref()
                .ok_or_else(|| SspryError::from("metadata_eq node requires a pattern_id"))?;
            let normalized = normalize_query_metadata_field(field).ok_or_else(|| {
                SspryError::from(format!("Unsupported metadata_eq field: {field}"))
            })?;
            if threshold.is_none() {
                return Err(SspryError::from("metadata_eq node requires a threshold"));
            }
            if !children.is_empty() {
                return Err(SspryError::from("metadata_eq node must not have children"));
            }
            if normalized == "time.now" {
                return Err(SspryError::from(
                    "time.now must use a time_now_eq node, not metadata_eq",
                ));
            }
            let expected = threshold.expect("threshold");
            if metadata_field_is_boolean(normalized) && expected > 1 {
                return Err(SspryError::from(
                    "metadata_eq boolean fields require threshold 0 or 1",
                ));
            }
            if !metadata_field_is_boolean(normalized) && !metadata_field_is_integer(normalized) {
                return Err(SspryError::from(format!(
                    "Unsupported metadata_eq field: {field}"
                )));
            }
        }
        "time_now_eq" => {
            if pattern_id.as_deref() != Some("time.now") {
                return Err(SspryError::from(
                    "time_now_eq node requires pattern_id=time.now",
                ));
            }
            if threshold.is_none() {
                return Err(SspryError::from("time_now_eq node requires a threshold"));
            }
            if !children.is_empty() {
                return Err(SspryError::from("time_now_eq node must not have children"));
            }
        }
        "identity_eq" => {
            if pattern_id.as_deref().unwrap_or_default().is_empty() {
                return Err(SspryError::from(
                    "identity_eq node requires a non-empty pattern_id",
                ));
            }
            if threshold.is_some() {
                return Err(SspryError::from("identity_eq node must not use threshold"));
            }
            if !children.is_empty() {
                return Err(SspryError::from("identity_eq node must not have children"));
            }
        }
        "verifier_only_eq"
        | "verifier_only_at"
        | "verifier_only_count"
        | "verifier_only_in_range" => {
            if pattern_id.as_deref().unwrap_or_default().is_empty() {
                return Err(SspryError::from(format!(
                    "{kind} node requires a non-empty pattern_id"
                )));
            }
            if threshold.is_some() {
                return Err(SspryError::from(format!(
                    "{kind} node must not use threshold"
                )));
            }
            if !children.is_empty() {
                return Err(SspryError::from(format!(
                    "{kind} node must not have children"
                )));
            }
        }
        _ => {
            return Err(SspryError::from(format!(
                "Unsupported ast node kind: {kind:?}"
            )));
        }
    }

    let pattern_id = match kind.as_str() {
        "metadata_eq" => pattern_id
            .as_deref()
            .and_then(normalize_query_metadata_field)
            .map(str::to_owned),
        "time_now_eq" => Some("time.now".to_owned()),
        _ => pattern_id,
    };

    Ok(QueryNode {
        kind,
        pattern_id,
        threshold,
        children,
    })
}

fn apply_store_open_profile(
    aggregate: &mut StoreRootStartupProfile,
    profile: &CandidateStoreOpenProfile,
) {
    aggregate.doc_count = aggregate.doc_count.saturating_add(profile.doc_count as u64);
    aggregate.store_open_total_ms = aggregate
        .store_open_total_ms
        .saturating_add(profile.total_ms);
    aggregate.store_open_manifest_ms = aggregate
        .store_open_manifest_ms
        .saturating_add(profile.manifest_ms);
    aggregate.store_open_meta_ms = aggregate.store_open_meta_ms.saturating_add(profile.meta_ms);
    aggregate.store_open_load_state_ms = aggregate
        .store_open_load_state_ms
        .saturating_add(profile.load_state_ms);
    aggregate.store_open_sidecars_ms = aggregate
        .store_open_sidecars_ms
        .saturating_add(profile.sidecars_ms);
    aggregate.store_open_rebuild_indexes_ms = aggregate
        .store_open_rebuild_indexes_ms
        .saturating_add(profile.rebuild_indexes_ms);
    aggregate.store_open_rebuild_sha_index_ms = aggregate
        .store_open_rebuild_sha_index_ms
        .saturating_add(profile.rebuild_sha_index_ms);
    aggregate.store_open_load_tier2_superblocks_ms = aggregate
        .store_open_load_tier2_superblocks_ms
        .saturating_add(profile.load_tier2_superblocks_ms);
    if profile.loaded_tier2_superblocks_from_snapshot {
        aggregate.store_open_loaded_tier2_superblocks_from_snapshot_shards = aggregate
            .store_open_loaded_tier2_superblocks_from_snapshot_shards
            .saturating_add(1);
    }
    aggregate.store_open_rebuild_tier2_superblocks_ms = aggregate
        .store_open_rebuild_tier2_superblocks_ms
        .saturating_add(profile.rebuild_tier2_superblocks_ms);
}

fn ensure_candidate_store_profiled(
    config: CandidateConfig,
) -> Result<(CandidateStore, bool, CandidateStoreOpenProfile)> {
    let meta_path = config.root.join("meta.json");
    if !meta_path.exists() {
        let started = Instant::now();
        let store = CandidateStore::init(config, false)?;
        return Ok((
            store,
            true,
            CandidateStoreOpenProfile {
                total_ms: started.elapsed().as_millis().try_into().unwrap_or(u64::MAX),
                ..CandidateStoreOpenProfile::default()
            },
        ));
    }
    let (store, profile) = CandidateStore::open_profiled(&config.root)?;
    Ok((store, false, profile))
}

fn workspace_current_root(root: &Path) -> PathBuf {
    root.join("current")
}

fn workspace_work_root_a(root: &Path) -> PathBuf {
    root.join("work_a")
}

fn workspace_work_root_b(root: &Path) -> PathBuf {
    root.join("work_b")
}

fn workspace_retired_root(root: &Path) -> PathBuf {
    root.join("retired")
}

fn workspace_retired_roots(root: &Path) -> Vec<PathBuf> {
    let mut retired = Vec::new();
    let entries = match fs::read_dir(root) {
        Ok(entries) => entries,
        Err(_) => return retired,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|value| value.to_str()) else {
            continue;
        };
        if name.starts_with("published_") {
            retired.push(path);
        }
    }
    retired.sort_unstable();
    retired
}

fn workspace_retired_stats(root: &Path) -> (u64, u64) {
    let retired = workspace_retired_roots(root);
    let bytes = retired.iter().map(|path| disk_usage_under(path)).sum();
    (retired.len() as u64, bytes)
}

fn next_workspace_retired_root_path(root: &Path) -> PathBuf {
    let base = current_unix_ms();
    for offset in 0..1024u64 {
        let candidate = root.join(format!("published_{}", base.saturating_add(offset)));
        if !candidate.exists() {
            return candidate;
        }
    }
    root.join(format!("published_{}_{}", base, std::process::id()))
}

fn prune_workspace_retired_roots(root: &Path, keep: usize) -> Result<usize> {
    let retired = workspace_retired_roots(root);
    let prune_count = retired.len().saturating_sub(keep);
    let mut removed = 0usize;
    for path in retired.into_iter().take(prune_count) {
        match fs::remove_dir_all(&path) {
            Ok(()) => removed = removed.saturating_add(1),
            Err(err) if err.kind() == ErrorKind::NotFound => {
                removed = removed.saturating_add(1);
            }
            Err(err) => {
                return Err(SspryError::from(format!(
                    "Failed to remove retired workspace root {}: {err}",
                    path.display()
                )));
            }
        }
    }
    Ok(removed)
}

fn ensure_candidate_stores_at_root(
    config: &ServerConfig,
    root: &Path,
) -> Result<(Vec<CandidateStore>, usize, StoreRootStartupProfile)> {
    let started_total = Instant::now();
    let shard_count = config.candidate_shards.max(1);
    let single_meta = root.join("meta.json");
    let sharded_meta = root.join("shard_000").join("meta.json");
    if let Some(existing) = read_candidate_shard_count(root)? {
        if existing != shard_count {
            return Err(SspryError::from(format!(
                "{} contains a candidate shard manifest for {existing} shard(s); start with matching --candidate-shards.",
                root.display()
            )));
        }
    } else {
        if shard_count > 1 && single_meta.exists() {
            return Err(SspryError::from(format!(
                "{} contains a single-shard store; start with --candidate-shards 1 or re-init.",
                root.display()
            )));
        }
        if shard_count == 1 && sharded_meta.exists() {
            return Err(SspryError::from(format!(
                "{} contains a sharded store; start with matching --candidate-shards.",
                root.display()
            )));
        }
    }

    let mut stores = Vec::with_capacity(shard_count);
    let mut cleanup_removed_roots = 0usize;
    let mut startup_profile = StoreRootStartupProfile::default();
    fs::create_dir_all(root)?;
    for shard_idx in 0..shard_count {
        let mut shard_config = config.candidate_config.clone();
        shard_config.root = candidate_shard_root(root, shard_count, shard_idx);
        cleanup_removed_roots = cleanup_removed_roots
            .saturating_add(cleanup_abandoned_compaction_roots(&shard_config.root)?);
        let (mut store, created_new, open_profile) = ensure_candidate_store_profiled(shard_config)?;
        if created_new {
            startup_profile.initialized_new_shards =
                startup_profile.initialized_new_shards.saturating_add(1);
        } else {
            startup_profile.opened_existing_shards =
                startup_profile.opened_existing_shards.saturating_add(1);
        }
        apply_store_open_profile(&mut startup_profile, &open_profile);
        store.apply_runtime_limits(
            config.memory_budget_bytes,
            shard_count,
            config.tier2_superblock_budget_divisor,
        )?;
        stores.push(store);
    }
    write_candidate_shard_count(root, shard_count)?;
    startup_profile.total_ms = started_total
        .elapsed()
        .as_millis()
        .try_into()
        .unwrap_or(u64::MAX);
    Ok((stores, cleanup_removed_roots, startup_profile))
}

fn ensure_candidate_stores(config: &ServerConfig) -> Result<(StoreMode, usize, StartupProfile)> {
    let root = &config.candidate_config.root;
    if !config.workspace_mode {
        let (stores, removed_roots, current_profile) =
            ensure_candidate_stores_at_root(config, root)?;
        return Ok((
            StoreMode::Direct {
                stores: Arc::new(StoreSet::new(root.clone(), stores)),
            },
            removed_roots,
            StartupProfile {
                current: current_profile,
                ..StartupProfile::default()
            },
        ));
    }

    if root.join("meta.json").exists() || root.join("shard_000").join("meta.json").exists() {
        return Err(SspryError::from(format!(
            "{} contains a direct store; move it under {}/current or use a fresh workspace root.",
            root.display(),
            root.display()
        )));
    }

    let current_root = workspace_current_root(root);
    let work_root_a = workspace_work_root_a(root);
    let work_root_b = workspace_work_root_b(root);
    if root.join("work").exists() {
        return Err(SspryError::from(format!(
            "{} contains the retired workspace work/ root; move or remove it before restarting.",
            root.display()
        )));
    }
    let retired_root = workspace_retired_root(root);
    let removed_retired =
        prune_workspace_retired_roots(&retired_root, DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP)?;
    let (published, removed_current, current_profile) =
        ensure_candidate_stores_at_root(config, &current_root)?;
    let (work_active, removed_work_active, work_profile) =
        ensure_candidate_stores_at_root(config, &work_root_a)?;
    let (work_idle, removed_work_idle, _) = ensure_candidate_stores_at_root(config, &work_root_b)?;
    Ok((
        StoreMode::Workspace {
            root: root.clone(),
            published: Arc::new(StoreSet::new(current_root, published)),
            work_active: Arc::new(StoreSet::new(work_root_a, work_active)),
            work_idle: Some(Arc::new(StoreSet::new(work_root_b, work_idle))),
        },
        removed_current
            .saturating_add(removed_work_active)
            .saturating_add(removed_work_idle)
            .saturating_add(removed_retired),
        StartupProfile {
            current: current_profile,
            work: work_profile,
            ..StartupProfile::default()
        },
    ))
}

fn decode_sha256(value: &str) -> Result<[u8; 32]> {
    let normalized = normalize_sha256_hex(value)?;
    let mut out = [0u8; 32];
    hex::decode_to_slice(normalized, &mut out)?;
    Ok(out)
}

fn normalize_sha256_hex(value: &str) -> Result<String> {
    let text = value.trim().to_ascii_lowercase();
    if text.len() != 64 || !text.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return Err(SspryError::from(
            "sha256 must be exactly 64 hexadecimal characters.",
        ));
    }
    Ok(text)
}

fn disk_usage_under(root: &Path) -> u64 {
    let mut total = 0u64;
    let mut stack = vec![root.to_path_buf()];
    while let Some(path) = stack.pop() {
        let Ok(metadata) = fs::metadata(&path) else {
            continue;
        };
        if metadata.is_file() {
            total += metadata.len();
            continue;
        }
        if !metadata.is_dir() {
            continue;
        }
        let Ok(entries) = fs::read_dir(&path) else {
            continue;
        };
        for entry in entries.flatten() {
            stack.push(entry.path());
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::fs;
    use std::io::Cursor;
    use std::net::TcpListener;

    use crate::candidate::BloomFilter;
    use crate::candidate::bloom::DEFAULT_BLOOM_POSITION_LANES;
    use crate::candidate::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE};
    use base64::Engine;
    use tempfile::tempdir;

    fn lane_bloom_bytes(filter_bytes: usize, bloom_hashes: usize, grams: &[u64]) -> Vec<u8> {
        let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
        for (idx, gram) in grams.iter().enumerate() {
            bloom
                .add_in_lane(
                    *gram,
                    idx % DEFAULT_BLOOM_POSITION_LANES,
                    DEFAULT_BLOOM_POSITION_LANES,
                )
                .expect("add gram");
        }
        bloom.into_bytes()
    }

    fn sample_server_state(base: &Path) -> Arc<ServerState> {
        Arc::new(
            ServerState::new(
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root: base.join("candidate_db"),
                        ..CandidateConfig::default()
                    },
                    candidate_shards: 1,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        )
    }

    fn sample_server_state_with_shards(base: &Path, candidate_shards: usize) -> Arc<ServerState> {
        Arc::new(
            ServerState::new(
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root: base.join(format!("candidate_db_{candidate_shards}")),
                        ..CandidateConfig::default()
                    },
                    candidate_shards,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        )
    }

    fn sample_workspace_server_state(base: &Path, candidate_shards: usize) -> Arc<ServerState> {
        sample_workspace_server_state_with_budget(
            base,
            candidate_shards,
            crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
        )
    }

    fn sample_workspace_server_state_with_budget(
        base: &Path,
        candidate_shards: usize,
        memory_budget_bytes: u64,
    ) -> Arc<ServerState> {
        Arc::new(
            ServerState::new(
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root: base.join(format!("candidate_workspace_{candidate_shards}")),
                        ..CandidateConfig::default()
                    },
                    candidate_shards,
                    search_workers: 1,
                    memory_budget_bytes,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: true,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("workspace server state"),
        )
    }

    fn candidate_document_wire_from_bytes(path: &Path, bytes: &[u8]) -> CandidateDocumentWire {
        fs::write(path, bytes).expect("write sample");
        let features = scan_features_default_grams(path).expect("features");
        CandidateDocumentWire {
            sha256: hex::encode(features.sha256),
            file_size: features.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: None,
        }
    }

    fn scan_features_default_grams(
        path: impl AsRef<Path>,
    ) -> Result<crate::candidate::DocumentFeatures> {
        crate::candidate::scan_file_features_bloom_only_with_gram_sizes(
            path,
            crate::candidate::GramSizes::new(
                crate::candidate::DEFAULT_TIER2_GRAM_SIZE,
                crate::candidate::DEFAULT_TIER1_GRAM_SIZE,
            )
            .expect("default gram sizes"),
            1024,
            7,
            0,
            0,
            1024,
        )
    }

    fn compile_query_plan_from_file_default(
        rule_path: impl AsRef<Path>,
        max_anchors_per_alt: usize,
        force_tier1_only: bool,
        allow_tier2_fallback: bool,
        max_candidates: usize,
    ) -> Result<crate::candidate::CompiledQueryPlan> {
        crate::candidate::compile_query_plan_from_file_with_gram_sizes(
            rule_path,
            crate::candidate::GramSizes::new(
                crate::candidate::DEFAULT_TIER2_GRAM_SIZE,
                crate::candidate::DEFAULT_TIER1_GRAM_SIZE,
            )
            .expect("default gram sizes"),
            max_anchors_per_alt,
            force_tier1_only,
            allow_tier2_fallback,
            max_candidates,
        )
    }

    #[test]
    fn current_stats_json_returns_busy_error_when_shard_locked() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state(tmp.path());
        let work = state.work_store_set().expect("work stores");
        let _guard = work.stores[0].lock().expect("lock store");
        let err = state
            .current_stats_json()
            .expect_err("stats should time out");
        assert!(
            err.to_string().contains("busy during stats"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn published_query_waits_for_locked_shard() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 =
            base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };

        state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: "11".repeat(32),
                file_size: 16,
                bloom_filter_b64,
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            })
            .expect("insert");
        state.handle_publish().expect("publish");

        let published = state.published_store_set().expect("published stores");
        let waited = thread::scope(|scope| {
            let store_lock = &published.stores[0];
            let holder = scope.spawn(move || {
                let _guard = store_lock.lock().expect("lock published shard");
                thread::sleep(Duration::from_millis(150));
            });
            thread::sleep(Duration::from_millis(25));

            let started = Instant::now();
            let query = state
                .handle_candidate_query(
                    CandidateQueryRequest {
                        plan: Value::Null,
                        cursor: 0,
                        chunk_size: Some(8),
                        include_external_ids: false,
                    },
                    &plan,
                )
                .expect("query after wait");
            let waited = started.elapsed();
            holder.join().expect("join holder");
            assert_eq!(query.total_candidates, 1);
            waited
        });

        assert!(
            waited >= Duration::from_millis(100),
            "expected query to wait for shard lock, waited {waited:?}"
        );
    }

    #[test]
    fn store_set_cache_helpers_work() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init store");
        let store_set = StoreSet::new(root, vec![store]);
        assert!(store_set.cached_stats().expect("empty cache").is_none());
        store_set
            .set_cached_stats(Map::from_iter([("docs".to_owned(), Value::from(1u64))]), 42)
            .expect("set cache");
        let cached = store_set
            .cached_stats()
            .expect("cached stats")
            .expect("cache entry");
        assert_eq!(cached.0.get("docs").and_then(Value::as_u64), Some(1));
        assert_eq!(cached.1, 42);
        store_set
            .invalidate_stats_cache()
            .expect("invalidate cache");
        assert!(store_set.cached_stats().expect("cache cleared").is_none());
        let stores = store_set.into_stores().expect("into stores");
        assert_eq!(stores.len(), 1);
    }

    #[test]
    fn status_json_does_not_require_shard_locks() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state(tmp.path());
        let work = state.work_store_set().expect("work stores");
        let _guard = work.stores[0].lock().expect("lock store");
        let status = state.status_json().expect("light status");
        assert_eq!(
            status.get("workspace_mode").and_then(Value::as_bool),
            Some(false)
        );
        assert!(
            status
                .get("index_session")
                .and_then(Value::as_object)
                .is_some()
        );
    }

    #[test]
    fn insert_is_rejected_while_publish_pauses_mutations() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state(tmp.path());
        state.mutations_paused.store(true, Ordering::SeqCst);
        let err = state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: "11".repeat(32),
                file_size: 1,
                bloom_filter_b64: String::new(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            })
            .expect_err("insert should be rejected");
        assert!(
            err.to_string().contains("server is publishing"),
            "unexpected error: {err}"
        );
    }

    #[test]
    fn index_session_is_exclusive() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        let started = state.handle_begin_index_session().expect("start session");
        assert_eq!(started.message, "index session started");
        let err = state
            .handle_begin_index_session()
            .expect_err("second session should fail");
        assert!(
            err.to_string()
                .contains("another index session is already active"),
            "unexpected error: {err}"
        );
        let finished = state.handle_end_index_session().expect("finish session");
        assert_eq!(finished.message, "index session finished");
    }

    #[test]
    fn index_session_progress_is_reported_in_stats() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.handle_begin_index_session().expect("start session");
        state
            .handle_update_index_session_progress(&CandidateIndexSessionProgressRequest {
                total_documents: Some(1000),
                submitted_documents: 320,
                processed_documents: 250,
            })
            .expect("update progress");
        state.mark_work_mutation();

        let stats = state.current_stats_json().expect("stats");
        let index_session = stats
            .get("index_session")
            .and_then(Value::as_object)
            .expect("index session object");
        assert_eq!(
            index_session.get("total_documents").and_then(Value::as_u64),
            Some(1000)
        );
        assert_eq!(
            index_session
                .get("submitted_documents")
                .and_then(Value::as_u64),
            Some(320)
        );
        assert_eq!(
            index_session
                .get("processed_documents")
                .and_then(Value::as_u64),
            Some(250)
        );
        assert_eq!(
            index_session
                .get("remaining_documents")
                .and_then(Value::as_u64),
            Some(750)
        );
        let publish = stats
            .get("publish")
            .and_then(Value::as_object)
            .expect("publish object");
        assert_eq!(
            publish.get("blocked_reason").and_then(Value::as_str),
            Some("active_index_sessions")
        );
        assert_eq!(publish.get("pending").and_then(Value::as_bool), Some(true));
    }

    #[test]
    fn insert_batch_advances_active_index_session_progress() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.handle_begin_index_session().expect("start session");
        state
            .handle_update_index_session_progress(&CandidateIndexSessionProgressRequest {
                total_documents: Some(10),
                submitted_documents: 0,
                processed_documents: 0,
            })
            .expect("set total");
        let sample_a = tmp.path().join("session-a.bin");
        let sample_b = tmp.path().join("session-b.bin");
        fs::write(&sample_a, b"xxABCDyy").expect("sample a");
        fs::write(&sample_b, b"zzWXYZqq").expect("sample b");
        let features_a = scan_features_default_grams(&sample_a).expect("features a");
        let features_b = scan_features_default_grams(&sample_b).expect("features b");
        let docs = vec![
            CandidateDocumentWire {
                sha256: hex::encode(features_a.sha256),
                file_size: features_a.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features_a.bloom_filter),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            },
            CandidateDocumentWire {
                sha256: hex::encode(features_b.sha256),
                file_size: features_b.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features_b.bloom_filter),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            },
        ];
        let inserted = state
            .handle_candidate_insert_batch(&docs)
            .expect("insert batch");
        assert_eq!(inserted.inserted_count, 2);
        let stats = state.current_stats_json().expect("stats");
        let index_session = stats
            .get("index_session")
            .and_then(Value::as_object)
            .expect("index session object");
        assert_eq!(
            index_session
                .get("submitted_documents")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            index_session
                .get("processed_documents")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            index_session
                .get("remaining_documents")
                .and_then(Value::as_u64),
            Some(8)
        );
        let server_insert_batch_profile = index_session
            .get("server_insert_batch_profile")
            .and_then(Value::as_object)
            .expect("server insert batch profile");
        assert_eq!(
            server_insert_batch_profile
                .get("batches")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            server_insert_batch_profile
                .get("documents")
                .and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            server_insert_batch_profile
                .get("shards_touched_total")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert!(
            server_insert_batch_profile
                .get("store_append_sidecars_us")
                .and_then(Value::as_u64)
                .is_some()
        );
    }

    #[test]
    fn current_stats_json_uses_cached_store_set_snapshot() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.mark_work_mutation();
        let _ = state.current_stats_json().expect("prime stats cache");
        let published = state.published_store_set().expect("published");
        let work = state.work_store_set().expect("work");
        let _published_guard = published.stores[0].lock().expect("lock published");
        let _work_guard = work.stores[0].lock().expect("lock work");
        let stats = state.current_stats_json().expect("cached stats");
        assert_eq!(
            stats.get("workspace_mode").and_then(Value::as_bool),
            Some(true)
        );
    }

    #[test]
    fn publish_stats_show_idle_readiness_and_last_publish_metadata() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.mark_work_mutation();
        state.last_work_mutation_unix_ms.store(
            current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
            Ordering::SeqCst,
        );

        let stats_before = state.current_stats_json().expect("stats before");
        let publish_before = stats_before
            .get("publish")
            .and_then(Value::as_object)
            .expect("publish before");
        assert_eq!(
            publish_before.get("eligible").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            publish_before.get("blocked_reason").and_then(Value::as_str),
            Some("ready")
        );

        let response = state.handle_publish().expect("publish");
        assert!(response.message.contains("published work root"));

        let stats_after = state.current_stats_json().expect("stats after");
        let publish_after = stats_after
            .get("publish")
            .and_then(Value::as_object)
            .expect("publish after");
        assert_eq!(
            publish_after.get("pending").and_then(Value::as_bool),
            Some(false)
        );
        assert_eq!(
            publish_after
                .get("publish_runs_total")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert!(
            publish_after
                .get("last_publish_completed_unix_ms")
                .and_then(Value::as_u64)
                .unwrap_or(0)
                > 0
        );
        assert!(
            publish_after
                .get("last_publish_duration_ms")
                .and_then(Value::as_u64)
                .is_some()
        );
        assert_eq!(
            publish_after
                .get("last_publish_reused_work_stores")
                .and_then(Value::as_bool),
            Some(true)
        );
        assert!(
            publish_after
                .get("last_publish_swap_ms")
                .and_then(Value::as_u64)
                .is_some()
        );
        assert!(
            publish_after
                .get("last_publish_promote_work_ms")
                .and_then(Value::as_u64)
                .is_some()
        );
        assert!(
            publish_after
                .get("last_publish_init_work_ms")
                .and_then(Value::as_u64)
                .is_some()
        );
    }

    #[test]
    fn publish_readiness_respects_adaptive_initial_idle() {
        let tmp = tempdir().expect("tmp");
        let mut config = ServerConfig {
            candidate_config: CandidateConfig {
                root: tmp.path().join("candidate_workspace_zero_idle"),
                ..CandidateConfig::default()
            },
            candidate_shards: 1,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            tier2_superblock_budget_divisor: crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
            auto_publish_initial_idle_ms: 0,
            auto_publish_storage_class: "solid-state".to_owned(),
            workspace_mode: true,
        };
        let state = Arc::new(
            ServerState::new(config.clone(), Arc::new(AtomicBool::new(false))).expect("state"),
        );
        state.mark_work_mutation();
        let readiness = state.publish_readiness(current_unix_ms());
        assert!(readiness.eligible);
        assert_eq!(readiness.idle_remaining_ms, 0);

        config.auto_publish_initial_idle_ms = 500;
        config.auto_publish_storage_class = "unknown".to_owned();
        let state =
            Arc::new(ServerState::new(config, Arc::new(AtomicBool::new(false))).expect("state"));
        state.mark_work_mutation();
        let readiness = state.publish_readiness(current_unix_ms());
        assert!(!readiness.eligible);
        assert_eq!(readiness.idle_threshold_ms, 500);
    }

    #[test]
    fn adaptive_publish_backs_off_when_seal_backlog_starts_rising() {
        let mut adaptive = AdaptivePublishState::new("solid-state".to_owned(), 0, 4);
        adaptive.update_seal_backlog(1_000, 1);

        let snapshot = adaptive.snapshot(1_000, 1);
        assert_eq!(snapshot.mode, "backoff");
        assert_eq!(snapshot.reason, "seal_backlog_rising");
        assert_eq!(snapshot.current_idle_ms, 2_000);
        assert_eq!(snapshot.tier2_pending_shards, 1);
    }

    #[test]
    fn adaptive_publish_drops_back_to_fast_when_backlog_drains() {
        let mut adaptive = AdaptivePublishState::new("solid-state".to_owned(), 2_000, 4);
        adaptive.update_seal_backlog(1_000, 1);
        adaptive.update_seal_backlog(2_000, 0);

        let snapshot = adaptive.snapshot(2_000, 0);
        assert_eq!(snapshot.mode, "fast");
        assert_eq!(snapshot.reason, "healthy");
        assert_eq!(snapshot.current_idle_ms, 0);
        assert_eq!(snapshot.healthy_cycles, 1);
    }

    #[test]
    fn adaptive_publish_backs_off_on_submit_pressure() {
        let mut adaptive = AdaptivePublishState::new("unknown".to_owned(), 0, 8);
        adaptive.update_completed_index_session(ADAPTIVE_PUBLISH_BACKOFF_SUBMIT_MS + 1, 0);
        adaptive.update_seal_backlog(5_000, 0);

        let snapshot = adaptive.snapshot(5_000, 0);
        assert_eq!(snapshot.mode, "backoff");
        assert_eq!(snapshot.reason, "submit_pressure_high");
        assert_eq!(snapshot.current_idle_ms, 2_500);
        assert_eq!(
            snapshot.recent_submit_p95_ms,
            ADAPTIVE_PUBLISH_BACKOFF_SUBMIT_MS + 1
        );
    }

    #[test]
    fn publish_waits_for_active_mutations_to_drain() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.active_mutations.store(1, Ordering::SeqCst);
        let release = state.clone();
        thread::spawn(move || {
            thread::sleep(Duration::from_millis(120));
            release.active_mutations.fetch_sub(1, Ordering::AcqRel);
        });
        let started = Instant::now();
        let publish = state.handle_publish().expect("publish");
        assert!(publish.message.contains("published work root"));
        assert!(
            started.elapsed() >= Duration::from_millis(100),
            "publish did not wait for active mutations"
        );
    }

    #[test]
    fn publish_does_not_wait_for_active_index_sessions_once_mutations_are_quiescent() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.active_index_sessions.store(1, Ordering::SeqCst);
        let started = Instant::now();
        let publish = state.handle_publish().expect("publish");
        assert!(publish.message.contains("published work root"));
        assert!(
            started.elapsed() < Duration::from_millis(100),
            "publish should not wait for the index session to end once mutations are drained"
        );
    }

    #[test]
    fn publish_requested_blocks_new_index_sessions_while_waiting_for_active_session() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.active_index_sessions.store(1, Ordering::SeqCst);
        state.active_mutations.store(1, Ordering::SeqCst);
        let publish_state = state.clone();
        let publish_thread = thread::spawn(move || publish_state.handle_publish());

        let started = Instant::now();
        while !state.publish_requested.load(Ordering::Acquire) {
            assert!(
                started.elapsed() < Duration::from_secs(2),
                "publish request did not become visible"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let err = state
            .handle_begin_index_session()
            .expect_err("new session should be blocked while publish is pending");
        assert!(
            err.to_string()
                .contains("server is publishing; index session unavailable; retry later")
        );

        state.active_mutations.store(0, Ordering::SeqCst);
        let publish = publish_thread
            .join()
            .expect("join publish thread")
            .expect("publish result");
        assert!(publish.message.contains("published work root"));
    }

    #[test]
    fn publish_prunes_workspace_retired_roots_to_keep_last_one() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        let workspace_root = tmp.path().join("candidate_workspace_1");
        let retired_root = workspace_retired_root(&workspace_root);

        state.mark_work_mutation();
        state.last_work_mutation_unix_ms.store(
            current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
            Ordering::SeqCst,
        );
        state.handle_publish().expect("first publish");

        let first_retired = retired_root.join("published_0000000000001");
        fs::create_dir_all(&first_retired).expect("create first retained root");
        let second_retired = retired_root.join("published_9999999999999");
        fs::create_dir_all(&second_retired).expect("create second retained root");

        state.mark_work_mutation();
        state.last_work_mutation_unix_ms.store(
            current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
            Ordering::SeqCst,
        );
        state.handle_publish().expect("second publish");
        state
            .run_retired_root_prune_cycle()
            .expect("retired prune cycle");

        let retained = workspace_retired_roots(&retired_root);
        assert_eq!(retained.len(), DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP);
        assert_eq!(retained[0], second_retired);
        assert!(!first_retired.exists());
    }

    #[test]
    fn workspace_startup_prunes_old_retired_roots() {
        let tmp = tempdir().expect("tmp");
        let workspace_root = tmp.path().join("candidate_workspace_1");
        let retired_root = workspace_retired_root(&workspace_root);
        fs::create_dir_all(&retired_root).expect("create retired parent");
        let older = retired_root.join("published_0000000000001");
        let newer = retired_root.join("published_0000000000002");
        fs::create_dir_all(&older).expect("create older retired root");
        fs::create_dir_all(&newer).expect("create newer retired root");

        let state = sample_workspace_server_state(tmp.path(), 1);
        let retained = workspace_retired_roots(&retired_root);
        assert_eq!(retained.len(), DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP);
        assert_eq!(retained[0], newer);
        assert!(!older.exists());
        assert!(state.startup_cleanup_removed_roots >= 1);
    }

    #[test]
    fn workspace_startup_rejects_retired_single_work_root() {
        let tmp = tempdir().expect("tmp");
        let workspace_root = tmp.path().join("candidate_workspace_1");
        let legacy_work_root = workspace_root.join("work");
        let (legacy_stores, _, _) = ensure_candidate_stores_at_root(
            &ServerConfig {
                candidate_config: CandidateConfig {
                    root: workspace_root.clone(),
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                tier2_superblock_budget_divisor:
                    crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: true,
            },
            &legacy_work_root,
        )
        .expect("init legacy work root");
        assert_eq!(legacy_stores.len(), 1);
        assert!(legacy_work_root.exists());
        assert!(!workspace_work_root_a(&workspace_root).exists());
        assert!(!workspace_work_root_b(&workspace_root).exists());

        let err = ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: workspace_root.clone(),
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                tier2_superblock_budget_divisor:
                    crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: true,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect_err("workspace startup must fail");
        assert!(err.to_string().contains("retired workspace work/ root"));
    }

    #[test]
    fn workspace_mode_keeps_queries_on_published_root_until_publish() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        let sample = tmp.path().join("workspace-doc.bin");
        fs::write(&sample, b"xxABCDyy").expect("sample");
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let features = scan_features_default_grams(&sample).expect("features");
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: hex::encode(features.sha256),
                file_size: features.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features.bloom_filter),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("work-doc".to_owned()),
            })
            .expect("insert doc");

        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let request = CandidateQueryRequest {
            plan: Value::Null,
            cursor: 0,
            chunk_size: None,
            include_external_ids: false,
        };
        let before = state
            .handle_candidate_query(request.clone(), &plan)
            .expect("query before publish");
        assert_eq!(before.total_candidates, 0);

        let stats_before = state.current_stats_json().expect("stats before");
        assert_eq!(
            stats_before.get("workspace_mode").and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            stats_before.get("doc_count").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            stats_before
                .get("work")
                .and_then(Value::as_object)
                .and_then(|work| work.get("doc_count"))
                .and_then(Value::as_u64),
            Some(1)
        );

        let publish = state.handle_publish().expect("publish");
        assert!(publish.message.contains("published work root"));

        let after = state
            .handle_candidate_query(request, &plan)
            .expect("query after publish");
        assert_eq!(after.total_candidates, 1);

        let stats_after = state.current_stats_json().expect("stats after");
        assert_eq!(
            stats_after.get("doc_count").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            stats_after
                .get("work")
                .and_then(Value::as_object)
                .and_then(|work| work.get("doc_count"))
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            stats_after
                .get("publish")
                .and_then(Value::as_object)
                .and_then(|publish| publish.get("last_publish_reused_work_stores"))
                .and_then(Value::as_bool),
            Some(true)
        );
        assert_eq!(
            stats_after
                .get("publish")
                .and_then(Value::as_object)
                .and_then(|publish| publish.get("publish_runs_total"))
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn auto_publish_promotes_work_after_index_session_finishes() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        let sample = tmp.path().join("auto-publish.bin");
        fs::write(&sample, b"xxABCDyy").expect("sample");
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let features = scan_features_default_grams(&sample).expect("features");
        state
            .handle_begin_index_session()
            .expect("begin index session");
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: hex::encode(features.sha256),
                file_size: features.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features.bloom_filter),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("auto-publish-doc".to_owned()),
            })
            .expect("insert doc");
        state.handle_end_index_session().expect("end index session");
        state.last_work_mutation_unix_ms.store(
            current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
            Ordering::SeqCst,
        );
        state.run_auto_publish_cycle().expect("auto publish");

        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let result = state
            .handle_candidate_query(
                CandidateQueryRequest {
                    plan: Value::Null,
                    cursor: 0,
                    chunk_size: None,
                    include_external_ids: false,
                },
                &plan,
            )
            .expect("query");
        assert_eq!(result.total_candidates, 1);
        assert!(!state.work_dirty.load(Ordering::Acquire));
    }

    #[test]
    fn publish_readiness_stays_blocked_with_active_index_session_under_pressure() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.work_dirty.store(true, Ordering::SeqCst);
        state.active_index_sessions.store(1, Ordering::SeqCst);
        state
            .work_active_estimated_documents
            .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
        state
            .last_work_mutation_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);

        let readiness = state.publish_readiness(current_unix_ms());
        assert!(!readiness.eligible);
        assert_eq!(readiness.blocked_reason, "active_index_sessions");
        assert_eq!(readiness.trigger_mode, "blocked");
    }

    #[test]
    fn auto_publish_does_not_rotate_work_while_index_session_is_active_under_pressure() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        let sample = tmp.path().join("pressure-publish.bin");
        fs::write(&sample, b"xxABCDyy").expect("sample");
        let features = scan_features_default_grams(&sample).expect("features");
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: hex::encode(features.sha256),
                file_size: features.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features.bloom_filter),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("pressure-doc".to_owned()),
            })
            .expect("insert doc");
        state.active_index_sessions.store(1, Ordering::SeqCst);
        state
            .work_active_estimated_documents
            .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
        state.run_auto_publish_cycle().expect("auto publish cycle");

        let stats = state.current_stats_json().expect("stats");
        assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(0),);
        assert_eq!(
            stats
                .get("publish")
                .and_then(Value::as_object)
                .and_then(|publish| publish.get("publish_runs_total"))
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            stats
                .get("work")
                .and_then(Value::as_object)
                .and_then(|work| work.get("doc_count"))
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn publish_in_progress_enables_insert_backpressure() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state_with_budget(tmp.path(), 1, 32 * 1024 * 1024);
        state.active_index_sessions.store(1, Ordering::SeqCst);
        state.publish_in_progress.store(true, Ordering::SeqCst);
        state
            .work_active_estimated_documents
            .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
        let pressure = state.work_buffer_pressure_snapshot(0, 0);
        assert_eq!(
            pressure.index_backpressure_delay_ms,
            INDEX_BACKPRESSURE_HEAVY_DELAY_MS
        );
    }

    #[test]
    fn publish_readiness_reports_seal_backlog_without_enabling_pressure_publish() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.work_dirty.store(true, Ordering::SeqCst);
        state.active_index_sessions.store(1, Ordering::SeqCst);
        state
            .work_active_estimated_documents
            .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
        state
            .last_work_mutation_unix_ms
            .store(current_unix_ms(), Ordering::SeqCst);
        state
            .enqueue_published_tier2_snapshot_shards([0usize])
            .expect("enqueue tier2 shard");

        let readiness = state.publish_readiness(current_unix_ms());
        assert!(!readiness.eligible);
        assert_eq!(readiness.blocked_reason, "active_index_sessions");
        assert!(readiness.pressure_publish_blocked_by_seal_backlog);
        assert_eq!(readiness.pending_tier2_snapshot_shards, 1);
    }

    #[test]
    fn seal_backlog_pressure_does_not_add_backpressure_when_pressure_publish_is_disabled() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state_with_budget(tmp.path(), 1, 32 * 1024 * 1024);
        state.active_index_sessions.store(1, Ordering::SeqCst);
        state
            .work_active_estimated_documents
            .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
        state
            .enqueue_published_tier2_snapshot_shards([0usize])
            .expect("enqueue tier2 shard");

        let pressure = state.work_buffer_pressure_snapshot(0, 1);
        assert!(pressure.pressure_publish_blocked_by_seal_backlog);
        assert_eq!(pressure.index_backpressure_delay_ms, 0);
    }

    #[test]
    fn pressure_thresholds_shrink_after_first_publish_during_active_index() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        state.active_index_sessions.store(1, Ordering::SeqCst);
        state.publish_runs_total.store(1, Ordering::SeqCst);

        let pressure = state.work_buffer_pressure_snapshot(0, 0);
        assert_eq!(
            pressure.document_threshold,
            WORK_BUFFER_REPUBLISH_MAX_DOCUMENT_THRESHOLD
        );
        assert_eq!(
            pressure.input_bytes_threshold,
            WORK_BUFFER_REPUBLISH_MIN_INPUT_BYTES_THRESHOLD
        );
    }

    #[test]
    fn workspace_publish_merges_incremental_work_into_published_root() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);

        let sample_a = tmp.path().join("inc-a.bin");
        fs::write(&sample_a, b"xxABCDyy").expect("sample a");
        let features_a = scan_features_default_grams(&sample_a).expect("features a");
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: hex::encode(features_a.sha256),
                file_size: features_a.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features_a.bloom_filter),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("inc-a".to_owned()),
            })
            .expect("insert a");
        state.handle_publish().expect("publish a");

        let sample_b = tmp.path().join("inc-b.bin");
        fs::write(&sample_b, b"xxWXYZyy").expect("sample b");
        let features_b = scan_features_default_grams(&sample_b).expect("features b");
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: hex::encode(features_b.sha256),
                file_size: features_b.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features_b.bloom_filter),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("inc-b".to_owned()),
            })
            .expect("insert b");
        state.handle_publish().expect("publish b");

        let stats = state.current_stats_json().expect("stats");
        assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(2));
        assert_eq!(
            stats
                .get("publish")
                .and_then(Value::as_object)
                .and_then(|publish| publish.get("retired_published_root_count"))
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            stats
                .get("work")
                .and_then(Value::as_object)
                .and_then(|work| work.get("doc_count"))
                .and_then(Value::as_u64),
            Some(0)
        );
    }

    #[cfg(unix)]
    fn start_unix_server(base: &Path, candidate_shards: usize) -> ClientConfig {
        let socket_parent = base.join("nested").join("rpc");
        fs::create_dir_all(&socket_parent).expect("socket parent");
        let socket_path = socket_parent.join(format!("rpc-{candidate_shards}.sock"));
        fs::write(&socket_path, b"stale").expect("stale socket placeholder");
        let root = base.join(format!("rpc_db_{candidate_shards}"));
        let socket_for_thread = socket_path.clone();
        thread::spawn(move || {
            let _ = serve(
                DEFAULT_RPC_HOST,
                DEFAULT_RPC_PORT,
                Some(socket_for_thread.as_path()),
                DEFAULT_MAX_REQUEST_BYTES,
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root,
                        ..CandidateConfig::default()
                    },
                    candidate_shards,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
            );
        });
        let config = ClientConfig::new(
            DEFAULT_RPC_HOST.to_owned(),
            DEFAULT_RPC_PORT,
            Duration::from_millis(250),
            Some(socket_path),
        );
        let client = SspryClient::new(config.clone());
        for _ in 0..100 {
            if client.ping().is_ok() {
                return config;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("test rpc server did not become ready");
    }

    fn one_shot_tcp_config<F>(handler: F) -> ClientConfig
    where
        F: FnOnce(TcpStream) + Send + 'static,
    {
        let listener = TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind listener");
        let port = listener.local_addr().expect("local addr").port();
        thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            handler(stream);
        });
        ClientConfig::new(
            DEFAULT_RPC_HOST.to_owned(),
            port,
            Duration::from_millis(500),
            None,
        )
    }

    fn start_tcp_server(base: &Path, candidate_shards: usize) -> ClientConfig {
        let probe = TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let root = base.join(format!("tcp_db_{candidate_shards}"));
        thread::spawn(move || {
            let _ = serve(
                DEFAULT_RPC_HOST,
                port,
                None,
                DEFAULT_MAX_REQUEST_BYTES,
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root,
                        ..CandidateConfig::default()
                    },
                    candidate_shards,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
            );
        });
        let config = ClientConfig::new(
            DEFAULT_RPC_HOST.to_owned(),
            port,
            Duration::from_millis(250),
            None,
        );
        let client = SspryClient::new(config.clone());
        for _ in 0..100 {
            if client.ping().is_ok() {
                return config;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("test tcp rpc server did not become ready");
    }

    fn start_tcp_workspace_server(base: &Path, candidate_shards: usize) -> ClientConfig {
        start_tcp_workspace_server_with_budget(
            base,
            candidate_shards,
            crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
        )
    }

    fn start_tcp_workspace_server_with_budget(
        base: &Path,
        candidate_shards: usize,
        memory_budget_bytes: u64,
    ) -> ClientConfig {
        let probe = TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);
        let root = base.join(format!("tcp_workspace_{candidate_shards}"));
        thread::spawn(move || {
            let _ = serve(
                DEFAULT_RPC_HOST,
                port,
                None,
                DEFAULT_MAX_REQUEST_BYTES,
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root,
                        ..CandidateConfig::default()
                    },
                    candidate_shards,
                    search_workers: 1,
                    memory_budget_bytes,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: true,
                },
            );
        });
        let config = ClientConfig::new(
            DEFAULT_RPC_HOST.to_owned(),
            port,
            Duration::from_millis(250),
            None,
        );
        let client = SspryClient::new(config.clone());
        for _ in 0..100 {
            if client.ping().is_ok() {
                return config;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("test tcp workspace rpc server did not become ready");
    }

    #[test]
    fn serve_with_shutdown_flag_drains_and_exits() {
        let tmp = tempdir().expect("tmp");
        let probe = TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind probe");
        let port = probe.local_addr().expect("probe addr").port();
        drop(probe);

        let shutdown = Arc::new(AtomicBool::new(false));
        let root = tmp.path().join("shutdown_db");
        let server_shutdown = shutdown.clone();
        let handle = thread::spawn(move || {
            serve_with_shutdown(
                DEFAULT_RPC_HOST,
                port,
                None,
                DEFAULT_MAX_REQUEST_BYTES,
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root,
                        ..CandidateConfig::default()
                    },
                    candidate_shards: 1,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
                server_shutdown,
            )
        });

        let config = ClientConfig::new(
            DEFAULT_RPC_HOST.to_owned(),
            port,
            Duration::from_millis(250),
            None,
        );
        let client = SspryClient::new(config);
        for _ in 0..100 {
            if client.ping().is_ok() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(client.ping().expect("server ping"), "pong");
        shutdown.store(true, Ordering::SeqCst);
        assert!(handle.join().expect("join server").is_ok());
    }

    struct MockStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MockStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }

        fn written_frame(&self) -> (u8, u8, Vec<u8>) {
            let mut cursor = Cursor::new(self.output.clone());
            read_frame(&mut cursor).expect("decode frame")
        }

        fn written_frames(&self) -> Vec<(u8, u8, Vec<u8>)> {
            let mut cursor = Cursor::new(self.output.clone());
            let mut frames = Vec::new();
            while let Some(frame) = read_frame_optional(&mut cursor).expect("decode frame") {
                frames.push(frame);
            }
            frames
        }
    }

    impl Read for MockStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for MockStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    struct WouldBlockReader {
        emitted: bool,
    }

    impl Read for WouldBlockReader {
        fn read(&mut self, _buf: &mut [u8]) -> std::io::Result<usize> {
            if !self.emitted {
                self.emitted = true;
                return Err(std::io::Error::from(ErrorKind::WouldBlock));
            }
            Ok(0)
        }
    }

    #[test]
    fn candidate_stats_json_contains_current_scan_policy_fields() {
        let tmp = tempdir().expect("tmp");
        let config = CandidateConfig {
            root: tmp.path().join("candidate_db"),
            ..CandidateConfig::default()
        };
        let store = CandidateStore::init(config.clone(), true).expect("init");
        let stats = candidate_stats_json(&config.root, &store);
        assert!(stats.contains_key("disk_usage_bytes"));
        assert_eq!(
            stats.get("tier2_gram_size").and_then(Value::as_u64),
            Some(3)
        );
        assert_eq!(
            stats.get("tier1_gram_size").and_then(Value::as_u64),
            Some(4)
        );
        assert_eq!(
            stats.get("tier1_filter_target_fp").and_then(Value::as_f64),
            Some(0.35)
        );
        assert_eq!(
            stats.get("tier2_filter_target_fp").and_then(Value::as_f64),
            Some(0.35)
        );
        assert_eq!(
            stats.get("filter_target_fp").and_then(Value::as_f64),
            Some(0.35)
        );
    }

    #[test]
    fn candidate_stats_json_reports_compaction_generation_fields() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let mut store = CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                filter_target_fp: None,
                compaction_idle_cooldown_s: 0.0,
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init");
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter = lane_bloom_bytes(32, 7, &[gram]);

        for byte in [0x11u8, 0x22u8] {
            store
                .insert_document(
                    [byte; 32],
                    32,
                    None,
                    Some(2),
                    None,
                    None,
                    32,
                    &bloom_filter,
                    0,
                    &[],
                    Some(format!("doc-{byte:02x}")),
                )
                .expect("insert");
        }
        store
            .delete_document(&hex::encode([0x22; 32]))
            .expect("delete");
        let snapshot = store
            .prepare_compaction_snapshot(true)
            .expect("snapshot")
            .expect("snapshot available");
        let compacted_root = compaction_work_root(&root, "stats-compact");
        write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");
        store
            .apply_compaction_snapshot(&snapshot, &compacted_root)
            .expect("apply compaction")
            .expect("compaction applied");

        let stats = candidate_stats_json(&root, &store);
        assert_eq!(
            stats.get("compaction_generation").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            stats
                .get("retired_generation_count")
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn candidate_query_wire_roundtrip_deserializes_plan() {
        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![0x01020304]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 123,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let request = CandidateQueryRequest {
            plan: compiled_query_plan_to_wire(&plan),
            cursor: 5,
            chunk_size: Some(17),
            include_external_ids: true,
        };
        let encoded = serde_json::to_vec(&request).expect("json");
        let decoded: CandidateQueryRequest = json_from_bytes(&encoded).expect("decode");
        let decoded_plan = compiled_query_plan_from_wire(&decoded.plan).expect("plan");
        assert_eq!(decoded_plan.max_candidates, plan.max_candidates);
        assert_eq!(decoded_plan.patterns, plan.patterns);
        assert_eq!(decoded.cursor, 5);
        assert_eq!(decoded.chunk_size, Some(17));
        assert!(decoded.include_external_ids);
    }

    #[test]
    fn frame_helpers_report_truncated_inputs() {
        let err = read_frame(&mut Cursor::new(vec![PROTOCOL_VERSION, ACTION_PING, 0]))
            .expect_err("truncated header must fail");
        assert!(
            err.to_string()
                .contains("Connection closed while reading frame.")
        );

        let payload = vec![PROTOCOL_VERSION, ACTION_PING, 0, 0, 0, 3, b'a', b'b'];
        let err = read_frame(&mut Cursor::new(payload)).expect_err("truncated payload must fail");
        assert!(
            err.to_string()
                .contains("Connection closed while reading frame.")
        );

        let parsed: Map<String, Value> = json_from_bytes(&[]).expect("empty object payload");
        assert!(parsed.is_empty());
    }

    #[test]
    fn frame_helpers_report_timeout_inputs() {
        let err = read_frame(&mut WouldBlockReader { emitted: false })
            .expect_err("would-block header must fail");
        assert!(
            err.to_string()
                .contains("RPC read timed out while waiting for a server response.")
        );
    }

    #[test]
    fn bounded_cache_updates_recency_and_evicts_oldest() {
        let mut cache = BoundedCache::new(2);
        cache.insert("a", 1);
        cache.insert("b", 2);
        assert_eq!(cache.get(&"a"), Some(1));
        cache.insert("c", 3);
        assert_eq!(cache.get(&"a"), Some(1));
        assert_eq!(cache.get(&"b"), None);
        assert_eq!(cache.get(&"c"), Some(3));
        cache.insert("a", 4);
        assert_eq!(cache.get(&"a"), Some(4));
        cache.clear();
        assert_eq!(cache.get(&"a"), None);
        assert_eq!(cache.get(&"c"), None);
    }

    #[test]
    fn candidate_insert_batch_short_circuits_empty_requests() {
        let client = SspryClient::new(one_shot_tcp_config(|_| {
            panic!("empty insert batch should not connect");
        }));
        let empty = client
            .candidate_insert_batch(&[])
            .expect("empty insert batch");
        assert_eq!(empty.inserted_count, 0);
        assert!(empty.results.is_empty());
    }

    #[test]
    fn candidate_insert_batch_splits_oversized_payloads_and_reports_single_doc_failures() {
        let listener = TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind listener");
        let port = listener.local_addr().expect("listener addr").port();
        thread::spawn(move || {
            for request_idx in 0..3 {
                let (mut stream, _) = listener.accept().expect("accept");
                let _ = read_frame(&mut stream).expect("read request");
                if request_idx == 0 {
                    write_error_frame(&mut stream, "Request payload is too large")
                        .expect("write too large");
                } else {
                    write_frame(
                        &mut stream,
                        PROTOCOL_VERSION,
                        STATUS_OK,
                        &json_bytes(&CandidateInsertBatchResponse {
                            inserted_count: 1,
                            results: vec![CandidateInsertResponse {
                                status: "inserted".to_owned(),
                                doc_id: request_idx as u64,
                                sha256: format!("{:064x}", request_idx),
                            }],
                        })
                        .expect("batch bytes"),
                    )
                    .expect("write success");
                }
            }
        });
        let client = SspryClient::new(ClientConfig::new(
            DEFAULT_RPC_HOST.to_owned(),
            port,
            Duration::from_millis(500),
            None,
        ));
        let docs = vec![
            CandidateDocumentWire {
                sha256: "11".repeat(32),
                file_size: 1,
                bloom_filter_b64: String::new(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            },
            CandidateDocumentWire {
                sha256: "22".repeat(32),
                file_size: 1,
                bloom_filter_b64: String::new(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            },
        ];
        let response = client
            .candidate_insert_batch(&docs)
            .expect("split insert succeeds");
        assert_eq!(response.inserted_count, 2);
        assert_eq!(response.results.len(), 2);

        let config = one_shot_tcp_config(|mut stream| {
            let _ = read_frame(&mut stream).expect("read request");
            write_error_frame(&mut stream, "Payload is too large").expect("write too large");
        });
        let client = SspryClient::new(config);
        let err = client
            .candidate_insert_batch(&docs[..1])
            .expect_err("single oversized doc");
        assert!(
            err.to_string()
                .contains("Single document insert request is too large")
        );
    }

    #[test]
    fn persistent_client_retries_temporary_publish_errors() {
        let listener = TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind listener");
        let port = listener.local_addr().expect("listener addr").port();
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept");

            let (_, action, _) = read_frame(&mut stream).expect("read begin request");
            assert_eq!(action, ACTION_INDEX_SESSION_BEGIN);
            write_error_frame(
                &mut stream,
                "server is publishing; index session unavailable; retry later",
            )
            .expect("write begin retry error");

            let (_, action, _) = read_frame(&mut stream).expect("read begin retry");
            assert_eq!(action, ACTION_INDEX_SESSION_BEGIN);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &json_bytes(&CandidateIndexSessionResponse {
                    message: "index session started".to_owned(),
                })
                .expect("begin payload"),
            )
            .expect("write begin success");

            let (_, action, _) = read_frame(&mut stream).expect("read batch request");
            assert_eq!(action, ACTION_CANDIDATE_INSERT_BATCH);
            write_error_frame(
                &mut stream,
                "server is publishing; insert batch temporarily disabled; retry later",
            )
            .expect("write batch retry error");

            let (_, action, _) = read_frame(&mut stream).expect("read batch retry");
            assert_eq!(action, ACTION_CANDIDATE_INSERT_BATCH);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &json_bytes(&CandidateInsertBatchResponse {
                    inserted_count: 1,
                    results: vec![CandidateInsertResponse {
                        status: "inserted".to_owned(),
                        doc_id: 1,
                        sha256: "aa".repeat(32),
                    }],
                })
                .expect("batch payload"),
            )
            .expect("write batch success");
        });

        let client = SspryClient::new(ClientConfig::new(
            DEFAULT_RPC_HOST.to_owned(),
            port,
            Duration::from_secs(2),
            None,
        ));
        let mut persistent = client.connect_persistent().expect("connect persistent");
        assert_eq!(
            persistent.begin_index_session().expect("begin session"),
            "index session started"
        );

        let row = serde_json::to_vec(&CandidateDocumentWire {
            sha256: "aa".repeat(32),
            file_size: 1,
            bloom_filter_b64: String::new(),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: None,
        })
        .expect("serialize row");
        let response = persistent
            .candidate_insert_batch_serialized_rows(&[row])
            .expect("batch retry succeeds");
        assert_eq!(response.inserted_count, 1);
        assert_eq!(response.results.len(), 1);
    }

    #[test]
    fn workspace_publish_rotates_work_buffers_while_remote_index_session_stays_active() {
        let tmp = tempdir().expect("tmp");
        let config = start_tcp_workspace_server(tmp.path(), 1);
        let client = SspryClient::new(config.clone());
        let mut persistent = client.connect_persistent().expect("connect persistent");
        assert_eq!(
            persistent
                .begin_index_session()
                .expect("begin index session"),
            "index session started"
        );

        let doc_a =
            candidate_document_wire_from_bytes(&tmp.path().join("overlap-a.bin"), b"xxABCDyy");
        let doc_b =
            candidate_document_wire_from_bytes(&tmp.path().join("overlap-b.bin"), b"zzWXYZqq");
        let doc_c =
            candidate_document_wire_from_bytes(&tmp.path().join("overlap-c.bin"), b"aaLMNObb");
        let row_a = serde_json::to_vec(&doc_a).expect("serialize doc a");
        let row_b = serde_json::to_vec(&doc_b).expect("serialize doc b");
        let row_c = serde_json::to_vec(&doc_c).expect("serialize doc c");

        let inserted_a = persistent
            .candidate_insert_batch_serialized_rows(&[row_a])
            .expect("insert first batch");
        assert_eq!(inserted_a.inserted_count, 1);

        let publish_config = config.clone();
        let publish_thread =
            thread::spawn(move || SspryClient::new(publish_config).publish().expect("publish"));

        let status_client = SspryClient::new(config.clone());
        let expected_active_root = workspace_work_root_b(&tmp.path().join("tcp_workspace_1"))
            .display()
            .to_string();
        let wait_started = Instant::now();
        loop {
            let status = status_client.candidate_status().expect("candidate status");
            if status
                .get("work_root")
                .and_then(Value::as_str)
                .map(|value| value == expected_active_root)
                .unwrap_or(false)
            {
                break;
            }
            assert!(
                wait_started.elapsed() < Duration::from_secs(5),
                "active work root did not rotate"
            );
            thread::sleep(Duration::from_millis(10));
        }

        let inserted_b = persistent
            .candidate_insert_batch_serialized_rows(&[row_b])
            .expect("insert second batch during pending publish");
        assert_eq!(inserted_b.inserted_count, 1);
        let publish_message = publish_thread.join().expect("join publish thread");
        assert!(publish_message.contains("published work root"));

        let plan_for = |gram: u64| CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let query_a = client
            .candidate_query_plan(&plan_for(u64::from(u32::from_le_bytes(*b"ABCD"))), 0, None)
            .expect("query published doc a");
        assert_eq!(query_a.total_candidates, 1);
        let query_b_before = client
            .candidate_query_plan(&plan_for(u64::from(u32::from_le_bytes(*b"WXYZ"))), 0, None)
            .expect("query unpublished doc b");
        assert_eq!(query_b_before.total_candidates, 0);

        let inserted_c = persistent
            .candidate_insert_batch_serialized_rows(&[row_c])
            .expect("insert third batch after publish");
        assert_eq!(inserted_c.inserted_count, 1);
        assert_eq!(
            persistent.end_index_session().expect("end index session"),
            "index session finished"
        );

        let second_publish = client.publish().expect("publish second buffer");
        assert!(second_publish.contains("published work root to"));

        let query_b_after = client
            .candidate_query_plan(&plan_for(u64::from(u32::from_le_bytes(*b"WXYZ"))), 0, None)
            .expect("query published doc b");
        assert_eq!(query_b_after.total_candidates, 1);
        let query_c_after = client
            .candidate_query_plan(&plan_for(u64::from(u32::from_le_bytes(*b"LMNO"))), 0, None)
            .expect("query published doc c");
        assert_eq!(query_c_after.total_candidates, 1);

        assert_eq!(client.shutdown().expect("shutdown"), "shutdown requested");
    }

    #[test]
    fn workspace_does_not_auto_publish_under_pressure_while_index_active() {
        let tmp = tempdir().expect("tmp");
        let config = start_tcp_workspace_server_with_budget(tmp.path(), 1, 32 * 1024 * 1024);
        let client = SspryClient::new(config.clone());
        let mut persistent = client.connect_persistent().expect("connect persistent");
        assert_eq!(
            persistent
                .begin_index_session()
                .expect("begin index session"),
            "index session started"
        );

        let mut rows = Vec::new();
        for idx in 0..80u32 {
            let path = tmp.path().join(format!("pressure-{idx:04}.bin"));
            let bytes = format!("doc-{idx:04}-ABCD-{idx:04}").into_bytes();
            let wire = candidate_document_wire_from_bytes(&path, &bytes);
            rows.push(serde_json::to_vec(&wire).expect("serialize row"));
        }

        let inserted = persistent
            .candidate_insert_batch_serialized_rows(&rows[..40])
            .expect("insert first pressure batch");
        assert_eq!(inserted.inserted_count, 40);
        let inserted = persistent
            .candidate_insert_batch_serialized_rows(&rows[40..])
            .expect("insert second pressure batch");
        assert_eq!(inserted.inserted_count, 40);

        let status_client = SspryClient::new(config.clone());
        thread::sleep(Duration::from_millis(250));
        let status = status_client.candidate_status().expect("candidate status");
        assert_eq!(
            status
                .get("publish")
                .and_then(Value::as_object)
                .and_then(|publish| publish.get("publish_runs_total"))
                .and_then(Value::as_u64),
            Some(0)
        );

        let extra = candidate_document_wire_from_bytes(
            &tmp.path().join("pressure-extra.bin"),
            b"doc-extra-LMNO",
        );
        let extra_row = serde_json::to_vec(&extra).expect("serialize extra row");
        let inserted = persistent
            .candidate_insert_batch_serialized_rows(&[extra_row])
            .expect("insert after pressure publish");
        assert_eq!(inserted.inserted_count, 1);
        assert_eq!(
            persistent.end_index_session().expect("end index session"),
            "index session finished"
        );
        assert_eq!(client.shutdown().expect("shutdown"), "shutdown requested");
    }

    #[test]
    fn query_plan_wire_validation_rejects_invalid_shapes() {
        assert!(
            compiled_query_plan_from_wire(&Value::Null)
                .expect_err("null plan")
                .to_string()
                .contains("query plan payload must be an object")
        );

        assert!(
            compiled_query_plan_from_wire(&serde_json::json!({ "ast": {} }))
                .expect_err("missing patterns")
                .to_string()
                .contains("patterns list")
        );

        assert!(
            compiled_query_plan_from_wire(&serde_json::json!({
                "patterns": [17],
                "ast": { "kind": "pattern", "pattern_id": "$a" }
            }))
            .expect_err("bad pattern entry")
            .to_string()
            .contains("patterns entries must be objects")
        );

        assert!(
            compiled_query_plan_from_wire(&serde_json::json!({
                "patterns": [{ "id": "$a", "alternatives": [["bad-gram"]] }],
                "ast": { "kind": "pattern", "pattern_id": "$a" }
            }))
            .expect_err("out of range gram")
            .to_string()
            .contains("out-of-range gram")
        );

        assert_eq!(
            compiled_query_plan_from_wire(&serde_json::json!({
                "patterns": [{ "id": "$a", "alternatives": [[1, 2, 3]] }],
                "ast": { "kind": "pattern", "pattern_id": "$a" },
                "flags": { "max_candidates": 0 }
            }))
            .expect("zero means unlimited")
            .max_candidates,
            usize::MAX
        );
    }

    #[test]
    fn query_node_wire_validation_rejects_invalid_nodes() {
        assert!(
            query_node_from_wire(&Value::Null)
                .expect_err("node object")
                .to_string()
                .contains("must be an object")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({}))
                .expect_err("missing kind")
                .to_string()
                .contains("missing kind")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({ "kind": "pattern" }))
                .expect_err("pattern id")
                .to_string()
                .contains("requires a pattern_id")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({ "kind": "and", "children": [] }))
                .expect_err("and child")
                .to_string()
                .contains("requires at least one child")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "n_of",
                "threshold": 0,
                "children": [{ "kind": "pattern", "pattern_id": "$a" }]
            }))
            .expect_err("n_of threshold")
            .to_string()
            .contains("threshold must be > 0")
        );

        let filesize_eq = query_node_from_wire(&serde_json::json!({
            "kind": "filesize_eq",
            "pattern_id": "filesize",
            "threshold": 8,
            "children": []
        }))
        .expect("filesize_eq");
        assert_eq!(filesize_eq.kind, "filesize_eq");
        assert_eq!(filesize_eq.pattern_id.as_deref(), Some("filesize"));
        assert_eq!(filesize_eq.threshold, Some(8));

        let filesize_lt = query_node_from_wire(&serde_json::json!({
            "kind": "filesize_lt",
            "pattern_id": "filesize",
            "threshold": 1024,
            "children": []
        }))
        .expect("filesize_lt");
        assert_eq!(filesize_lt.kind, "filesize_lt");
        assert_eq!(filesize_lt.pattern_id.as_deref(), Some("filesize"));
        assert_eq!(filesize_lt.threshold, Some(1024));

        let metadata_eq = query_node_from_wire(&serde_json::json!({
            "kind": "metadata_eq",
            "pattern_id": "PE.Machine",
            "threshold": 0x14c,
            "children": []
        }))
        .expect("metadata_eq");
        assert_eq!(metadata_eq.kind, "metadata_eq");
        assert_eq!(metadata_eq.pattern_id.as_deref(), Some("pe.machine"));
        assert_eq!(metadata_eq.threshold, Some(0x14c));

        let time_now_eq = query_node_from_wire(&serde_json::json!({
            "kind": "time_now_eq",
            "pattern_id": "time.now",
            "threshold": 42,
            "children": []
        }))
        .expect("time_now_eq");
        assert_eq!(time_now_eq.kind, "time_now_eq");
        assert_eq!(time_now_eq.pattern_id.as_deref(), Some("time.now"));
        assert_eq!(time_now_eq.threshold, Some(42));

        let expected_identity = "aa".repeat(32);
        let identity_eq = query_node_from_wire(&serde_json::json!({
            "kind": "identity_eq",
            "pattern_id": expected_identity,
            "children": []
        }))
        .expect("identity_eq");
        assert_eq!(identity_eq.kind, "identity_eq");
        assert_eq!(
            identity_eq.pattern_id.as_deref(),
            Some(expected_identity.as_str())
        );
        assert_eq!(identity_eq.threshold, None);

        let verifier_only_eq = query_node_from_wire(&serde_json::json!({
            "kind": "verifier_only_eq",
            "pattern_id": "uint32(0)==332",
            "children": []
        }))
        .expect("verifier_only_eq");
        assert_eq!(verifier_only_eq.kind, "verifier_only_eq");
        assert_eq!(
            verifier_only_eq.pattern_id.as_deref(),
            Some("uint32(0)==332")
        );
        assert_eq!(verifier_only_eq.threshold, None);

        let not_node = query_node_from_wire(&serde_json::json!({
            "kind": "not",
            "children": [
                { "kind": "pattern", "pattern_id": "$a", "children": [] }
            ]
        }))
        .expect("not");
        assert_eq!(not_node.kind, "not");
        assert_eq!(not_node.children.len(), 1);

        let verifier_only_at = query_node_from_wire(&serde_json::json!({
            "kind": "verifier_only_at",
            "pattern_id": "$a@0",
            "children": []
        }))
        .expect("verifier_only_at");
        assert_eq!(verifier_only_at.kind, "verifier_only_at");
        assert_eq!(verifier_only_at.pattern_id.as_deref(), Some("$a@0"));
        assert_eq!(verifier_only_at.threshold, None);

        let verifier_only_count = query_node_from_wire(&serde_json::json!({
            "kind": "verifier_only_count",
            "pattern_id": "count:$a:gt:2",
            "children": []
        }))
        .expect("verifier_only_count");
        assert_eq!(verifier_only_count.kind, "verifier_only_count");
        assert_eq!(
            verifier_only_count.pattern_id.as_deref(),
            Some("count:$a:gt:2")
        );
        assert_eq!(verifier_only_count.threshold, None);

        let verifier_only_in_range = query_node_from_wire(&serde_json::json!({
            "kind": "verifier_only_in_range",
            "pattern_id": "range:$a:filesize-256:filesize",
            "children": []
        }))
        .expect("verifier_only_in_range");
        assert_eq!(verifier_only_in_range.kind, "verifier_only_in_range");
        assert_eq!(
            verifier_only_in_range.pattern_id.as_deref(),
            Some("range:$a:filesize-256:filesize")
        );
        assert_eq!(verifier_only_in_range.threshold, None);

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "filesize_eq",
                "pattern_id": "size",
                "threshold": 8,
                "children": []
            }))
            .expect_err("bad filesize_eq id")
            .to_string()
            .contains("pattern_id=filesize")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "filesize_lt",
                "pattern_id": "size",
                "threshold": 8,
                "children": []
            }))
            .expect_err("bad filesize_lt id")
            .to_string()
            .contains("pattern_id=filesize")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "metadata_eq",
                "pattern_id": "bogus.field",
                "threshold": 1,
                "children": []
            }))
            .expect_err("bad metadata_eq field")
            .to_string()
            .contains("Unsupported metadata_eq field")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "time_now_eq",
                "pattern_id": "clock.now",
                "threshold": 1,
                "children": []
            }))
            .expect_err("bad time_now_eq id")
            .to_string()
            .contains("pattern_id=time.now")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "verifier_only_eq",
                "pattern_id": "",
                "children": []
            }))
            .expect_err("empty verifier-only pattern id")
            .to_string()
            .contains("requires a non-empty pattern_id")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "verifier_only_at",
                "pattern_id": "",
                "children": []
            }))
            .expect_err("empty verifier-only-at pattern id")
            .to_string()
            .contains("verifier_only_at node requires a non-empty pattern_id")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({
                "kind": "identity_eq",
                "pattern_id": "",
                "children": []
            }))
            .expect_err("empty identity_eq pattern id")
            .to_string()
            .contains("identity_eq node requires a non-empty pattern_id")
        );

        assert!(
            query_node_from_wire(&serde_json::json!({ "kind": "wat" }))
                .expect_err("unsupported kind")
                .to_string()
                .contains("Unsupported ast node kind")
        );
    }

    #[test]
    fn sha256_helpers_validate_input() {
        let upper = "AA".repeat(32);
        assert_eq!(
            normalize_sha256_hex(&upper).expect("normalize"),
            upper.to_ascii_lowercase()
        );
        assert!(decode_sha256(&upper).is_ok());

        assert!(
            normalize_sha256_hex("abc")
                .expect_err("short hex")
                .to_string()
                .contains("64 hexadecimal characters")
        );
        assert!(
            decode_sha256(&"zz".repeat(32))
                .expect_err("bad hex")
                .to_string()
                .contains("64 hexadecimal characters")
        );
    }

    #[test]
    fn serve_connection_returns_protocol_and_dispatch_errors() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state(tmp.path());

        let mut bad_version = MockStream::new({
            let mut payload = Vec::new();
            write_frame(&mut payload, PROTOCOL_VERSION + 1, ACTION_PING, b"{}").expect("frame");
            payload
        });
        serve_connection(&mut bad_version, state.clone(), DEFAULT_MAX_REQUEST_BYTES)
            .expect("serve bad version");
        let (_, status, payload) = bad_version.written_frame();
        assert_eq!(status, STATUS_ERROR);
        assert!(
            String::from_utf8(payload)
                .expect("utf8")
                .contains("Unsupported protocol version")
        );

        let mut oversized = MockStream::new({
            let mut payload = Vec::new();
            write_frame(&mut payload, PROTOCOL_VERSION, ACTION_PING, b"12345").expect("frame");
            payload
        });
        serve_connection(&mut oversized, state.clone(), 4).expect("serve oversized");
        let (_, status, payload) = oversized.written_frame();
        assert_eq!(status, STATUS_ERROR);
        assert!(
            String::from_utf8(payload)
                .expect("utf8")
                .contains("Request is too large.")
        );

        let mut unsupported = MockStream::new({
            let mut payload = Vec::new();
            write_frame(&mut payload, PROTOCOL_VERSION, 250, b"{}").expect("frame");
            payload
        });
        serve_connection(&mut unsupported, state.clone(), DEFAULT_MAX_REQUEST_BYTES)
            .expect("serve unsupported");
        let (_, status, payload) = unsupported.written_frame();
        assert_eq!(status, STATUS_ERROR);
        assert!(
            String::from_utf8(payload)
                .expect("utf8")
                .contains("Unsupported action code: 250")
        );

        let mut invalid_query = MockStream::new({
            let mut payload = Vec::new();
            write_frame(&mut payload, PROTOCOL_VERSION, ACTION_CANDIDATE_QUERY, b"{")
                .expect("frame");
            payload
        });
        serve_connection(&mut invalid_query, state, DEFAULT_MAX_REQUEST_BYTES)
            .expect("serve invalid payload");
        let (_, status, payload) = invalid_query.written_frame();
        assert_eq!(status, STATUS_ERROR);
        assert!(
            String::from_utf8(payload)
                .expect("utf8")
                .contains("EOF while parsing")
        );
    }

    #[test]
    fn serve_connection_handles_multiple_frames_per_connection() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state(tmp.path());

        let mut payload = Vec::new();
        write_frame(&mut payload, PROTOCOL_VERSION, ACTION_PING, b"{}").expect("ping frame");
        write_frame(&mut payload, PROTOCOL_VERSION, 250, b"{}").expect("bad frame");
        write_frame(&mut payload, PROTOCOL_VERSION, ACTION_PING, b"{}").expect("ping frame");

        let mut stream = MockStream::new(payload);
        serve_connection(&mut stream, state, DEFAULT_MAX_REQUEST_BYTES)
            .expect("serve multi-frame stream");

        let frames = stream.written_frames();
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].1, STATUS_OK);
        assert!(
            String::from_utf8(frames[0].2.clone())
                .expect("utf8")
                .contains("pong")
        );
        assert_eq!(frames[1].1, STATUS_ERROR);
        assert!(
            String::from_utf8(frames[1].2.clone())
                .expect("utf8")
                .contains("Unsupported action code: 250")
        );
        assert_eq!(frames[2].1, STATUS_OK);
        assert!(
            String::from_utf8(frames[2].2.clone())
                .expect("utf8")
                .contains("pong")
        );
    }

    #[test]
    fn dispatch_covers_core_candidate_actions() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state(tmp.path());

        let cand_a = tmp.path().join("cand-a.bin");
        let cand_b = tmp.path().join("cand-b.bin");
        let rule = tmp.path().join("rule.yar");
        fs::write(&cand_a, b"xxABCDyy").expect("cand a");
        fs::write(&cand_b, b"zzABCDqq").expect("cand b");
        fs::write(
            &rule,
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

        let features_a = scan_features_default_grams(&cand_a).expect("features a");
        let features_b = scan_features_default_grams(&cand_b).expect("features b");
        let doc_a = CandidateDocumentWire {
            sha256: hex::encode(features_a.sha256),
            file_size: features_a.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_a.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some(cand_a.display().to_string()),
        };
        let doc_b = CandidateDocumentWire {
            sha256: hex::encode(features_b.sha256),
            file_size: features_b.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_b.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some(cand_b.display().to_string()),
        };

        let inserted_doc: CandidateInsertResponse = json_from_bytes(
            &state
                .dispatch(
                    ACTION_CANDIDATE_INSERT,
                    &json_bytes(&doc_a).expect("candidate insert payload"),
                )
                .expect("candidate insert"),
        )
        .expect("decode candidate insert");
        assert_eq!(inserted_doc.status, "inserted");

        let inserted_docs: CandidateInsertBatchResponse = json_from_bytes(
            &state
                .dispatch(
                    ACTION_CANDIDATE_INSERT_BATCH,
                    &json_bytes(&CandidateInsertBatchRequest {
                        documents: vec![doc_b.clone()],
                    })
                    .expect("candidate batch payload"),
                )
                .expect("candidate batch"),
        )
        .expect("decode candidate batch");
        assert_eq!(inserted_docs.inserted_count, 1);

        let plan =
            compile_query_plan_from_file_default(&rule, 8, false, true, 100_000).expect("plan");
        let query_with_ids: CandidateQueryResponse = json_from_bytes(
            &state
                .dispatch(
                    ACTION_CANDIDATE_QUERY,
                    &json_bytes(&CandidateQueryRequest {
                        plan: compiled_query_plan_to_wire(&plan),
                        cursor: 0,
                        chunk_size: Some(1),
                        include_external_ids: true,
                    })
                    .expect("candidate query payload"),
                )
                .expect("candidate query"),
        )
        .expect("decode query");
        assert_eq!(query_with_ids.total_candidates, 2);
        assert_eq!(query_with_ids.returned_count, 1);
        assert!(query_with_ids.next_cursor.is_some());
        assert!(query_with_ids.external_ids.is_some());

        let stats: Map<String, Value> = json_from_bytes(
            &state
                .dispatch(ACTION_CANDIDATE_STATS, b"{}")
                .expect("candidate stats"),
        )
        .expect("decode stats");
        assert_eq!(
            stats.get("active_doc_count").and_then(Value::as_u64),
            Some(2)
        );

        let deleted: CandidateDeleteResponse = json_from_bytes(
            &state
                .dispatch(
                    ACTION_CANDIDATE_DELETE,
                    &json_bytes(&CandidateDeleteRequest {
                        sha256: doc_a.sha256.clone(),
                    })
                    .expect("delete payload"),
                )
                .expect("candidate delete"),
        )
        .expect("decode delete");
        assert_eq!(deleted.status, "deleted");
        assert!(disk_usage_under(tmp.path()) > 0);
    }

    #[test]
    fn client_request_helpers_cover_error_and_validation_paths() {
        let client = SspryClient::new(ClientConfig::new(
            "not an address".to_owned(),
            DEFAULT_RPC_PORT,
            Duration::from_millis(50),
            None,
        ));
        assert!(
            client
                .request_bytes(ACTION_PING, b"{}")
                .expect_err("invalid tcp address")
                .to_string()
                .contains("Invalid TCP address")
        );

        let bad_version_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let _ = read_frame(&mut stream);
            write_frame(&mut stream, PROTOCOL_VERSION + 1, STATUS_OK, b"{}")
                .expect("write version mismatch");
        }));
        assert!(
            bad_version_client
                .request_bytes(ACTION_PING, b"{}")
                .expect_err("version mismatch")
                .to_string()
                .contains("Unsupported protocol version")
        );

        let error_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let _ = read_frame(&mut stream);
            write_error_frame(&mut stream, "server boom").expect("write error frame");
        }));
        assert!(
            error_client
                .request_bytes(ACTION_PING, b"{}")
                .expect_err("server error")
                .to_string()
                .contains("server boom")
        );

        let object_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let _ = read_frame(&mut stream);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&serde_json::json!(["not", "an", "object"]))
                    .expect("array payload"),
            )
            .expect("write array frame");
        }));
        assert!(
            object_client
                .request_json_value(ACTION_CANDIDATE_STATS, &json!({}))
                .expect_err("non-object stats")
                .to_string()
                .contains("invalid JSON object")
        );

        let default_error_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let _ = read_frame(&mut stream);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_ERROR,
                &serde_json::to_vec(&serde_json::json!({ "type": "SspryError" }))
                    .expect("error payload"),
            )
            .expect("write error payload");
        }));
        assert!(
            default_error_client
                .request_bytes(ACTION_PING, b"{}")
                .expect_err("default server error")
                .to_string()
                .contains("Server returned an error")
        );
    }

    #[test]
    fn client_control_methods_cover_remaining_public_calls() {
        let status_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let (_, action, _) = read_frame(&mut stream).expect("read status frame");
            assert_eq!(action, ACTION_CANDIDATE_STATUS);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&json!({
                    "workspace_mode": true,
                    "publish": {"mode": "fast"},
                }))
                .expect("status payload"),
            )
            .expect("write status frame");
        }));
        let status = status_client.candidate_status().expect("candidate status");
        assert_eq!(
            status.get("workspace_mode").and_then(Value::as_bool),
            Some(true)
        );

        let publish_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let (_, action, _) = read_frame(&mut stream).expect("read publish frame");
            assert_eq!(action, ACTION_PUBLISH);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&CandidatePublishResponse {
                    message: "published work root".to_owned(),
                })
                .expect("publish payload"),
            )
            .expect("write publish frame");
        }));
        assert_eq!(
            publish_client.publish().expect("publish"),
            "published work root"
        );

        let begin_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let (_, action, _) = read_frame(&mut stream).expect("read begin frame");
            assert_eq!(action, ACTION_INDEX_SESSION_BEGIN);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&CandidateIndexSessionResponse {
                    message: "index session started".to_owned(),
                })
                .expect("begin payload"),
            )
            .expect("write begin frame");
        }));
        assert_eq!(
            begin_client.begin_index_session().expect("begin session"),
            "index session started"
        );

        let progress_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let (_, action, payload) = read_frame(&mut stream).expect("read progress frame");
            assert_eq!(action, ACTION_INDEX_SESSION_PROGRESS);
            let parsed: CandidateIndexSessionProgressRequest =
                serde_json::from_slice(&payload).expect("progress payload");
            assert_eq!(parsed.total_documents, Some(12));
            assert_eq!(parsed.submitted_documents, 7);
            assert_eq!(parsed.processed_documents, 5);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&CandidateIndexSessionResponse {
                    message: "progress updated".to_owned(),
                })
                .expect("progress response"),
            )
            .expect("write progress frame");
        }));
        progress_client
            .update_index_session_progress(Some(12), 7, 5)
            .expect("update progress");

        let end_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let (_, action, _) = read_frame(&mut stream).expect("read end frame");
            assert_eq!(action, ACTION_INDEX_SESSION_END);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&CandidateIndexSessionResponse {
                    message: "index session finished".to_owned(),
                })
                .expect("end payload"),
            )
            .expect("write end frame");
        }));
        assert_eq!(
            end_client.end_index_session().expect("end session"),
            "index session finished"
        );

        let shutdown_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let (_, action, _) = read_frame(&mut stream).expect("read shutdown frame");
            assert_eq!(action, ACTION_SHUTDOWN);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&json!({ "message": "shutdown requested" }))
                    .expect("shutdown payload"),
            )
            .expect("write shutdown frame");
        }));
        assert_eq!(
            shutdown_client.shutdown().expect("shutdown"),
            "shutdown requested"
        );

        assert!(
            SspryClient::candidate_insert_batch_payload_size(&[CandidateDocumentWire {
                sha256: "33".repeat(32),
                file_size: 4,
                bloom_filter_b64: "AQID".to_owned(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("doc".to_owned()),
            }])
            .expect("payload size")
                > 0
        );
    }

    #[cfg(unix)]
    #[test]
    fn unix_client_server_roundtrip_covers_public_client_methods() {
        let tmp = tempdir().expect("tmp");
        let config = start_unix_server(tmp.path(), 2);
        let client = SspryClient::new(config.clone());
        assert_eq!(client.ping().expect("ping"), "pong");

        let cand_a = tmp.path().join("cand-a.bin");
        let cand_b = tmp.path().join("cand-b.bin");
        let rule = tmp.path().join("rule.yar");
        fs::write(&cand_a, b"xxABCDyy").expect("cand a");
        fs::write(&cand_b, b"zzABCDqq").expect("cand b");
        fs::write(
            &rule,
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
        let features_a = scan_features_default_grams(&cand_a).expect("features a");
        let features_b = scan_features_default_grams(&cand_b).expect("features b");
        let doc_a = CandidateDocumentWire {
            sha256: hex::encode(features_a.sha256),
            file_size: features_a.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_a.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some(cand_a.display().to_string()),
        };
        let doc_b = CandidateDocumentWire {
            sha256: hex::encode(features_b.sha256),
            file_size: features_b.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_b.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some(cand_b.display().to_string()),
        };

        let inserted = client
            .candidate_insert_document(&doc_a)
            .expect("candidate insert");
        assert_eq!(inserted.status, "inserted");
        let batch = client
            .candidate_insert_batch(std::slice::from_ref(&doc_b))
            .expect("candidate batch");
        assert_eq!(batch.inserted_count, 1);
        assert_eq!(batch.results.len(), 1);

        let plan =
            compile_query_plan_from_file_default(&rule, 8, false, true, 100_000).expect("plan");
        let query = client
            .candidate_query_plan_with_options(&plan, 0, Some(1), true)
            .expect("query");
        assert_eq!(query.total_candidates, 2);
        assert!(query.next_cursor.is_some());
        assert!(query.external_ids.is_some());
        let query_without_ids = client
            .candidate_query_plan(&plan, 0, None)
            .expect("query without ids");
        assert_eq!(query_without_ids.returned_count, 2);
        assert!(query_without_ids.external_ids.is_none());

        let stats = client.candidate_stats().expect("stats");
        assert_eq!(
            stats.get("candidate_shards").and_then(Value::as_u64),
            Some(2)
        );
        let deleted = client
            .candidate_delete_sha256(&inserted.sha256)
            .expect("delete");
        assert_eq!(deleted.status, "deleted");
    }

    #[test]
    fn tcp_server_roundtrip_covers_tcp_serve_branch() {
        let tmp = tempdir().expect("tmp");
        let client = SspryClient::new(start_tcp_server(tmp.path(), 1));
        assert_eq!(client.ping().expect("tcp ping"), "pong");
        let stats = client.candidate_stats().expect("tcp stats");
        assert_eq!(
            stats.get("candidate_shards").and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn draining_server_rejects_mutations_but_keeps_non_mutating_requests() {
        let tmp = tempdir().expect("tmp");
        let state = ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: tmp.path().join("candidate_db"),
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                tier2_superblock_budget_divisor:
                    crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(true)),
        )
        .expect("server state");
        let insert_payload = serde_json::to_vec(&CandidateDocumentWire {
            sha256: "aa".repeat(32),
            file_size: 4,
            bloom_filter_b64: String::new(),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: None,
        })
        .expect("insert payload");
        let batch_payload = serde_json::to_vec(&CandidateInsertBatchRequest {
            documents: vec![CandidateDocumentWire {
                sha256: "bb".repeat(32),
                file_size: 4,
                bloom_filter_b64: String::new(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            }],
        })
        .expect("batch payload");
        let delete_payload = serde_json::to_vec(&CandidateDeleteRequest {
            sha256: "aa".repeat(32),
        })
        .expect("delete payload");

        for (action, payload) in [
            (ACTION_CANDIDATE_INSERT, insert_payload.as_slice()),
            (ACTION_CANDIDATE_INSERT_BATCH, batch_payload.as_slice()),
            (ACTION_CANDIDATE_DELETE, delete_payload.as_slice()),
        ] {
            let err = state
                .dispatch(action, payload)
                .expect_err("mutation rejected");
            assert!(
                err.to_string()
                    .contains("server is shutting down; mutating requests are disabled")
            );
        }

        let ping: Value =
            serde_json::from_slice(&state.dispatch(ACTION_PING, b"{}").expect("ping works"))
                .expect("decode ping");
        assert_eq!(ping.get("message").and_then(Value::as_str), Some("pong"));
        let stats: Value = serde_json::from_slice(
            &state
                .dispatch(ACTION_CANDIDATE_STATS, b"{}")
                .expect("stats works"),
        )
        .expect("decode stats");
        assert_eq!(
            stats.get("active_doc_count").and_then(Value::as_u64),
            Some(0)
        );
    }

    #[test]
    fn multishard_state_and_insert_parsing_cover_remaining_rpc_branches() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state_with_shards(tmp.path(), 2);
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 =
            base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let docs = vec![
            CandidateDocumentWire {
                sha256: "00".repeat(32),
                file_size: 16,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("shard-a".to_owned()),
            },
            CandidateDocumentWire {
                sha256: "01".repeat(32),
                file_size: 16,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("shard-b".to_owned()),
            },
        ];
        let batch = state
            .handle_candidate_insert_batch(&docs)
            .expect("insert multishard batch");
        assert_eq!(batch.inserted_count, 2);
        let query = state
            .handle_candidate_query(
                CandidateQueryRequest {
                    plan: Value::Null,
                    cursor: 0,
                    chunk_size: Some(1),
                    include_external_ids: true,
                },
                &plan,
            )
            .expect("query multishard");
        assert_eq!(query.total_candidates, 2);
        assert_eq!(query.returned_count, 1);
        assert!(query.next_cursor.is_some());
        assert!(query.external_ids.is_some());
        let page_two = state
            .handle_candidate_query(
                CandidateQueryRequest {
                    plan: Value::Null,
                    cursor: 1,
                    chunk_size: Some(2),
                    include_external_ids: false,
                },
                &plan,
            )
            .expect("query page two");
        assert_eq!(page_two.cursor, 1);
        assert_eq!(page_two.returned_count, 1);
        assert_eq!(page_two.next_cursor, None);
        assert!(page_two.external_ids.is_none());
        let deleted = state
            .handle_candidate_delete(&docs[0].sha256)
            .expect("delete first multishard doc");
        assert_eq!(deleted.status, "deleted");
        let query_after_delete = state
            .handle_candidate_query(
                CandidateQueryRequest {
                    plan: Value::Null,
                    cursor: 0,
                    chunk_size: Some(8),
                    include_external_ids: false,
                },
                &plan,
            )
            .expect("query after delete");
        assert_eq!(query_after_delete.total_candidates, 1);
        assert!(
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: "ab".repeat(32),
                    file_size: 1,
                    bloom_filter_b64: "**".to_owned(),
                    bloom_item_estimate: None,
                    tier2_bloom_filter_b64: None,
                    tier2_bloom_item_estimate: None,
                    special_population: false,
                    metadata_b64: None,
                    external_id: None,
                })
                .expect_err("invalid bloom base64")
                .to_string()
                .contains("bloom_filter_b64 must be valid base64")
        );
        assert!(
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: "ab".repeat(32),
                    file_size: 1,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    bloom_item_estimate: None,
                    tier2_bloom_filter_b64: None,
                    tier2_bloom_item_estimate: None,
                    special_population: false,
                    metadata_b64: None,
                    external_id: None,
                })
                .is_ok()
        );
        assert!(
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: "not hex".to_owned(),
                    file_size: 1,
                    bloom_filter_b64,
                    bloom_item_estimate: None,
                    tier2_bloom_filter_b64: None,
                    tier2_bloom_item_estimate: None,
                    special_population: false,
                    metadata_b64: None,
                    external_id: None,
                })
                .expect_err("invalid sha")
                .to_string()
                .contains("64 hexadecimal characters")
        );
    }

    #[test]
    fn query_plan_wire_and_store_setup_cover_manifest_errors() {
        let tmp = tempdir().expect("tmp");
        let single_root = tmp.path().join("single");
        CandidateStore::init(
            CandidateConfig {
                root: single_root.clone(),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init single root");
        assert!(
            ensure_candidate_stores(&ServerConfig {
                candidate_config: CandidateConfig {
                    root: single_root.clone(),
                    ..CandidateConfig::default()
                },
                candidate_shards: 2,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                tier2_superblock_budget_divisor:
                    crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            })
            .expect_err("single-shard mismatch")
            .to_string()
            .contains("single-shard store")
        );

        let sharded_root = tmp.path().join("sharded");
        CandidateStore::init(
            CandidateConfig {
                root: candidate_shard_root(&sharded_root, 2, 0),
                ..CandidateConfig::default()
            },
            true,
        )
        .expect("init orphaned shard");
        assert!(
            ensure_candidate_stores(&ServerConfig {
                candidate_config: CandidateConfig {
                    root: sharded_root.clone(),
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                tier2_superblock_budget_divisor:
                    crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            })
            .expect_err("sharded mismatch")
            .to_string()
            .contains("sharded store")
        );

        let manifest_root = tmp.path().join("manifest");
        let (stores, _, _) = ensure_candidate_stores(&ServerConfig {
            candidate_config: CandidateConfig {
                root: manifest_root.clone(),
                ..CandidateConfig::default()
            },
            candidate_shards: 2,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            tier2_superblock_budget_divisor: crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: false,
        })
        .expect("create sharded stores");
        assert_eq!(
            match stores {
                StoreMode::Direct { stores } => stores.stores.len(),
                StoreMode::Workspace { .. } => 0,
            },
            2
        );
        assert!(
            ensure_candidate_stores(&ServerConfig {
                candidate_config: CandidateConfig {
                    root: manifest_root,
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                tier2_superblock_budget_divisor:
                    crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            })
            .expect_err("manifest mismatch")
            .to_string()
            .contains("candidate shard manifest")
        );
    }

    #[test]
    fn single_shard_query_with_external_ids_and_client_delete_normalization_work() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state_with_shards(tmp.path(), 1);
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 =
            base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
        let inserted = state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: "AA".repeat(32),
                file_size: 16,
                bloom_filter_b64,
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some("single-shard-id".to_owned()),
            })
            .expect("insert single-shard doc");
        assert_eq!(inserted.status, "inserted");
        let query = state
            .handle_candidate_query(
                CandidateQueryRequest {
                    plan: Value::Null,
                    cursor: 0,
                    chunk_size: None,
                    include_external_ids: true,
                },
                &CompiledQueryPlan {
                    patterns: vec![PatternPlan {
                        pattern_id: "$a".to_owned(),
                        alternatives: vec![vec![gram]],
                        tier2_alternatives: vec![Vec::new()],
                        fixed_literals: vec![Vec::new()],
                        fixed_literal_wide: vec![false],
                        fixed_literal_fullword: vec![false],
                    }],
                    root: QueryNode {
                        kind: "pattern".to_owned(),
                        pattern_id: Some("$a".to_owned()),
                        threshold: None,
                        children: Vec::new(),
                    },
                    force_tier1_only: false,
                    allow_tier2_fallback: true,
                    max_candidates: 5,
                    tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
                    tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
                },
            )
            .expect("single-shard query");
        assert_eq!(query.total_candidates, 1);
        assert_eq!(
            query.external_ids,
            Some(vec![Some("single-shard-id".to_owned())])
        );

        let delete_client = SspryClient::new(one_shot_tcp_config(|mut stream| {
            let (_, _, payload) = read_frame(&mut stream).expect("read delete request");
            let request: CandidateDeleteRequest =
                serde_json::from_slice(&payload).expect("delete request");
            assert_eq!(request.sha256, "aa".repeat(32));
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&CandidateDeleteResponse {
                    status: "deleted".to_owned(),
                    sha256: request.sha256,
                    doc_id: Some(7),
                })
                .expect("delete response"),
            )
            .expect("write delete response");
        }));
        let deleted = delete_client
            .candidate_delete_sha256(&"AA".repeat(32))
            .expect("normalized delete");
        assert_eq!(deleted.doc_id, Some(7));
    }

    #[test]
    fn multishard_query_uses_parallel_collection_and_cached_results() {
        let tmp = tempdir().expect("tmp");
        let state = ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: tmp.path().join("candidate_db_parallel"),
                    filter_target_fp: None,
                    ..CandidateConfig::default()
                },
                candidate_shards: 2,
                search_workers: 2,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                tier2_superblock_budget_divisor:
                    crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state");
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 =
            base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(16, 7, &[gram]));
        let mut docs = Vec::new();
        for byte in 1_u8..=64 {
            let sha = [byte; 32];
            if docs.iter().all(|existing: &[u8; 32]| {
                state.candidate_store_index_for_sha256(existing)
                    != state.candidate_store_index_for_sha256(&sha)
            }) {
                docs.push(sha);
            }
            if docs.len() == 2 {
                break;
            }
        }
        assert_eq!(docs.len(), 2);
        for (index, sha) in docs.into_iter().enumerate() {
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: hex::encode(sha),
                    file_size: 16,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    bloom_item_estimate: None,
                    tier2_bloom_filter_b64: None,
                    tier2_bloom_item_estimate: None,
                    special_population: false,
                    metadata_b64: None,
                    external_id: Some(format!("parallel-{index}")),
                })
                .expect("insert doc");
        }
        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: false,
            allow_tier2_fallback: true,
            max_candidates: 8,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        };
        let request = CandidateQueryRequest {
            plan: Value::Null,
            cursor: 0,
            chunk_size: None,
            include_external_ids: true,
        };
        let first = state
            .handle_candidate_query(request.clone(), &plan)
            .expect("first query");
        assert_eq!(first.total_candidates, 2);
        assert_eq!(first.returned_count, 2);
        assert_eq!(first.tier_used, "tier1");
        assert_eq!(first.external_ids.as_ref().map(Vec::len), Some(2));

        let second = state
            .handle_candidate_query(request, &plan)
            .expect("second query");
        assert_eq!(second.sha256, first.sha256);
        assert_eq!(second.external_ids, first.external_ids);
        assert_eq!(second.tier_used, first.tier_used);
    }

    #[test]
    fn ensure_candidate_stores_removes_abandoned_compaction_roots_on_startup() {
        let tmp = tempdir().expect("tmp");
        let root = tmp.path().join("candidate_db");
        let shard_root = candidate_shard_root(&root, 2, 0);
        let abandoned = compaction_work_root(&shard_root, "compact-orphan");
        fs::create_dir_all(abandoned.join("nested")).expect("create orphan root");

        let (stores, removed_roots, _) = ensure_candidate_stores(&ServerConfig {
            candidate_config: CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            candidate_shards: 2,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            tier2_superblock_budget_divisor: crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: false,
        })
        .expect("ensure stores");
        assert_eq!(
            match stores {
                StoreMode::Direct { stores } => stores.stores.len(),
                StoreMode::Workspace { .. } => 0,
            },
            2
        );
        assert_eq!(removed_roots, 1);
        assert!(!abandoned.exists());
    }

    #[test]
    fn compaction_cycle_reclaims_deleted_docs_and_updates_stats() {
        let tmp = tempdir().expect("tmp");
        let state = Arc::new(
            ServerState::new(
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root: tmp.path().join("candidate_db"),
                        filter_target_fp: None,
                        compaction_idle_cooldown_s: 0.0,
                        ..CandidateConfig::default()
                    },
                    candidate_shards: 1,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        );
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 =
            base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(32, 7, &[gram]));

        for byte in [0x11u8, 0x22u8] {
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: hex::encode([byte; 32]),
                    file_size: 32,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    bloom_item_estimate: None,
                    tier2_bloom_filter_b64: None,
                    tier2_bloom_item_estimate: None,
                    special_population: false,
                    metadata_b64: None,
                    external_id: Some(format!("doc-{byte:02x}")),
                })
                .expect("insert doc");
        }

        state
            .handle_candidate_delete(&hex::encode([0x22; 32]))
            .expect("delete doc");
        state
            .run_compaction_cycle_for_tests()
            .expect("run compaction cycle");

        let stats: Value = serde_json::from_slice(
            &state
                .dispatch(ACTION_CANDIDATE_STATS, b"{}")
                .expect("stats"),
        )
        .expect("decode stats");
        assert_eq!(
            stats.get("deleted_doc_count").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(1));
        assert_eq!(
            stats.get("deleted_storage_bytes").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            stats.get("compaction_runs_total").and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            stats
                .get("last_compaction_reclaimed_docs")
                .and_then(Value::as_u64),
            Some(1)
        );
        assert_eq!(
            stats.get("compaction_generation").and_then(Value::as_u64),
            Some(2)
        );
        assert_eq!(
            stats
                .get("retired_generation_count")
                .and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn compaction_cycle_scans_all_shards_for_pending_work() {
        let tmp = tempdir().expect("tmp");
        let state = Arc::new(
            ServerState::new(
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root: tmp.path().join("candidate_db_4"),
                        filter_target_fp: None,
                        compaction_idle_cooldown_s: 0.0,
                        ..CandidateConfig::default()
                    },
                    candidate_shards: 4,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        );
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 =
            base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(32, 7, &[gram]));

        let mut deleted_sha = None;
        for byte in 1u8..=32 {
            let sha = [byte; 32];
            let shard_idx = state.candidate_store_index_for_sha256(&sha);
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: hex::encode(sha),
                    file_size: 32,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    bloom_item_estimate: None,
                    tier2_bloom_filter_b64: None,
                    tier2_bloom_item_estimate: None,
                    special_population: false,
                    metadata_b64: None,
                    external_id: Some(format!("doc-{byte:02x}")),
                })
                .expect("insert doc");
            if shard_idx != 0 {
                deleted_sha = Some(hex::encode(sha));
                break;
            }
        }

        let deleted_sha = deleted_sha.expect("non-zero shard doc");
        state
            .handle_candidate_delete(&deleted_sha)
            .expect("delete doc");
        state
            .run_compaction_cycle_for_tests()
            .expect("run compaction cycle");

        let stats: Value = serde_json::from_slice(
            &state
                .dispatch(ACTION_CANDIDATE_STATS, b"{}")
                .expect("stats"),
        )
        .expect("decode stats");
        assert_eq!(
            stats.get("deleted_doc_count").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            stats.get("deleted_storage_bytes").and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            stats.get("compaction_runs_total").and_then(Value::as_u64),
            Some(1)
        );
    }

    #[test]
    fn compaction_cycle_garbage_collects_retired_generation_before_next_snapshot_scan() {
        let tmp = tempdir().expect("tmp");
        let state = Arc::new(
            ServerState::new(
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root: tmp.path().join("candidate_db"),
                        filter_target_fp: None,
                        compaction_idle_cooldown_s: 0.0,
                        ..CandidateConfig::default()
                    },
                    candidate_shards: 1,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    auto_publish_initial_idle_ms: 500,
                    auto_publish_storage_class: "unknown".to_owned(),
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        );
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 =
            base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(32, 7, &[gram]));

        for byte in [0x11u8, 0x22u8] {
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: hex::encode([byte; 32]),
                    file_size: 32,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    bloom_item_estimate: None,
                    tier2_bloom_filter_b64: None,
                    tier2_bloom_item_estimate: None,
                    special_population: false,
                    metadata_b64: None,
                    external_id: Some(format!("doc-{byte:02x}")),
                })
                .expect("insert doc");
        }

        state
            .handle_candidate_delete(&hex::encode([0x22; 32]))
            .expect("delete doc");
        state
            .run_compaction_cycle_for_tests()
            .expect("first compaction cycle");

        let first_stats: Value = serde_json::from_slice(
            &state
                .dispatch(ACTION_CANDIDATE_STATS, b"{}")
                .expect("stats"),
        )
        .expect("decode stats");
        assert_eq!(
            first_stats
                .get("retired_generation_count")
                .and_then(Value::as_u64),
            Some(1)
        );

        state
            .run_compaction_cycle_for_tests()
            .expect("second compaction cycle");

        let second_stats: Value = serde_json::from_slice(
            &state
                .dispatch(ACTION_CANDIDATE_STATS, b"{}")
                .expect("stats"),
        )
        .expect("decode stats");
        assert_eq!(
            second_stats
                .get("retired_generation_count")
                .and_then(Value::as_u64),
            Some(0)
        );
        assert_eq!(
            second_stats
                .get("compaction_runs_total")
                .and_then(Value::as_u64),
            Some(1)
        );
    }
}
