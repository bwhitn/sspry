use std::collections::{HashMap, HashSet, VecDeque};
use std::fs;
use std::io::ErrorKind;
use std::net::ToSocketAddrs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Condvar, Mutex, MutexGuard, RwLock, TryLockError};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

#[cfg(test)]
use base64::Engine;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};
use tokio::runtime::Builder as TokioRuntimeBuilder;
use tokio_stream::StreamExt;
use tonic::{Request as GrpcRequest, Response as GrpcResponse, Status as GrpcStatus};

#[cfg(test)]
use crate::candidate::query_plan::compiled_query_plan_memory_bytes;
#[cfg(test)]
use crate::candidate::store::read_forest_source_dedup_manifest;
use crate::candidate::store::{
    CandidateCompactionSnapshot, CandidateImportBatchProfile, CandidateInsertBatchProfile,
    CandidateStoreOpenProfile, ForestSourceDedupResult, RuntimeQueryArtifacts,
    build_runtime_query_artifacts, build_tree_source_ref, cleanup_abandoned_compaction_roots,
    compaction_work_root, for_each_forest_source_ref_duplicate_victim, forest_source_dedup_due,
    record_forest_source_dedup_pass, runtime_query_artifacts_memory_bytes,
    tree_source_ref_build_due, write_compacted_snapshot,
};
use crate::candidate::{
    BoundedCache, CandidateConfig, CandidateQueryProfile, CandidateStore, CompiledQueryPlan,
    GramSizes, candidate_shard_index, candidate_shard_root,
    compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source,
    read_candidate_shard_count, resolve_max_candidates, search_target_rule_names,
    write_candidate_shard_count,
};
#[cfg(test)]
use crate::candidate::{PatternPlan, QueryNode};
use crate::grpc::v1::{
    AdaptivePublishSummary, DeleteRequest as GrpcDeleteRequest,
    DeleteResponse as GrpcDeleteResponse, ForestSourceDedupSummary, IndexClientBeginRequest,
    IndexClientBeginResponse, IndexClientHeartbeatRequest, IndexSessionBeginRequest,
    IndexSessionEndRequest, IndexSessionProgressRequest, IndexSessionResponse, IndexSessionSummary,
    InsertBatchProfileSummary, InsertFrame, InsertResult, InsertSummary, OptionalString,
    PingRequest, PingResponse, PublishRequest, PublishResponse as GrpcPublishResponse,
    PublishSummary, PublishedTier2SnapshotSealSummary, QueryProfileSummary, SearchFrame,
    SearchRequest, ShutdownRequest, ShutdownResponse as GrpcShutdownResponse, StartupStoreSummary,
    StartupSummary, StatsRequest, StatsResponse, StatusRequest, StatusResponse, StoreSummary,
    sspry_server::{Sspry as GrpcSspry, SspryServer},
};
use crate::perf::{record_counter, scope};
use crate::{Result, SspryError};

pub const DEFAULT_RPC_HOST: &str = "127.0.0.1";
pub const DEFAULT_RPC_PORT: u16 = 17653;
pub const DEFAULT_RPC_TIMEOUT: f64 = 30.0;
pub const DEFAULT_MAX_REQUEST_BYTES: usize = 64 * 1024 * 1024;
const INDEX_CLIENT_LEASE_MULTIPLIER: u64 = 3;
const GRPC_STREAM_INSERT_BATCH_MAX_ROWS: usize = 32;
const GRPC_STREAM_INSERT_BATCH_MAX_BYTES: usize = 8 * 1024 * 1024;

const DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE: usize = 128;
#[cfg(test)]
const NORMALIZED_PLAN_CACHE_CAPACITY: usize = 64;
const QUERY_ARTIFACT_CACHE_CAPACITY: usize = 4;
const QUERY_ARTIFACT_CACHE_MAX_ENTRY_BYTES: u64 = 512 * 1024 * 1024;
#[cfg(test)]
const QUERY_CACHE_CAPACITY: usize = 64;
const DEFAULT_CANDIDATE_SHARD_LOCK_TIMEOUT_MS: u64 = 1000;
const CANDIDATE_SHARD_LOCK_POLL_INTERVAL_MS: u64 = 10;
pub const DEFAULT_AUTO_PUBLISH_IDLE_MS: u64 = 5_000;
const DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP: usize = 0;

/// Returns whether verbose search-stream tracing is enabled for this process.
fn search_trace_enabled() -> bool {
    std::env::var_os("SSPRY_TRACE_SEARCH_STREAM").is_some()
}

/// Emits a search-stream trace line when tracing is enabled.
fn search_trace_log(message: impl AsRef<str>) {
    if search_trace_enabled() {
        eprintln!("trace.search_stream {}", message.as_ref());
    }
}

/// Clamps the effective search worker count to the number of shard/tree work
/// units available for one query.
fn resolve_search_workers(configured_workers: usize, work_unit_count: usize) -> usize {
    configured_workers.max(1).min(work_unit_count.max(1))
}

/// Attempts to lock one candidate shard within a bounded timeout so searches
/// can fail fast instead of blocking indefinitely behind mutations.
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

/// Acquires a blocking lock on one candidate shard, converting poisoning into a
/// project error.
fn lock_candidate_store_blocking<'a>(
    store_lock: &'a Mutex<CandidateStore>,
) -> Result<MutexGuard<'a, CandidateStore>> {
    store_lock
        .lock()
        .map_err(|_| SspryError::from("Candidate store lock poisoned."))
}

/// Reads current and peak resident memory usage for the running process from
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

#[derive(Clone, Debug)]
pub struct ServerConfig {
    pub candidate_config: CandidateConfig,
    pub candidate_shards: usize,
    pub search_workers: usize,
    pub memory_budget_bytes: u64,
    pub auto_publish_initial_idle_ms: u64,
    pub auto_publish_storage_class: String,
    pub workspace_mode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateInsertResponse {
    pub status: String,
    pub doc_id: u64,
    pub identity: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateInsertBatchResponse {
    pub inserted_count: usize,
    pub results: Vec<CandidateInsertResponse>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateDeleteResponse {
    pub status: String,
    pub identity: String,
    pub doc_id: Option<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateQueryResponse {
    pub identities: Vec<String>,
    pub total_candidates: usize,
    pub returned_count: usize,
    pub cursor: usize,
    pub next_cursor: Option<usize>,
    #[serde(default)]
    pub truncated: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub truncated_limit: Option<usize>,
    pub tier_used: String,
    #[serde(default)]
    pub query_profile: CandidateQueryProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ids: Option<Vec<Option<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub(crate) struct CandidateQueryStreamFrame {
    #[serde(default)]
    pub identities: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ids: Option<Vec<Option<String>>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub candidate_limit: Option<usize>,
    #[serde(default)]
    pub stream_complete: bool,
    #[serde(default)]
    pub rule_complete: bool,
    #[serde(default)]
    pub target_rule_name: String,
    #[serde(default)]
    pub tier_used: String,
    #[serde(default)]
    pub query_profile: CandidateQueryProfile,
    #[serde(default)]
    pub query_eval_nanos: u128,
}

#[cfg(test)]
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateDocumentWire {
    pub identity: String,
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
struct CandidateIndexClientBeginRequest {
    heartbeat_interval_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateIndexClientBeginResponse {
    message: String,
    client_id: u64,
    heartbeat_interval_ms: u64,
    lease_timeout_ms: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateIndexClientHeartbeatRequest {
    client_id: u64,
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
    Vec<u8>,
    u64,
    Option<usize>,
    Vec<u8>,
    Option<usize>,
    Vec<u8>,
    bool,
    Vec<u8>,
    Option<String>,
);

#[derive(Clone, Debug)]
struct IndexClientLease {
    lease_timeout_ms: u64,
    last_heartbeat_unix_ms: u64,
}

#[derive(Debug)]
struct StoreSet {
    root: Mutex<PathBuf>,
    stores: Vec<Mutex<CandidateStore>>,
    #[cfg(test)]
    stats_cache: Mutex<Option<CachedStoreSetStats>>,
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct CachedStoreSetStats {
    stats: Map<String, Value>,
    deleted_storage_bytes: u64,
}

impl StoreSet {
    /// Wraps one logical root and its per-shard stores into the mutex-backed
    /// structure shared by direct, forest, and workspace modes.
    fn new(root: PathBuf, stores: Vec<CandidateStore>) -> Self {
        Self {
            root: Mutex::new(root),
            stores: stores.into_iter().map(Mutex::new).collect(),
            #[cfg(test)]
            stats_cache: Mutex::new(None),
        }
    }

    #[cfg(test)]
    /// Consumes the store set and unwraps the owned stores for tests that need
    /// direct access to shard contents.
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

    /// Returns a cloned copy of the current logical root path for this store
    /// set.
    fn root(&self) -> Result<PathBuf> {
        self.root
            .lock()
            .map(|root| root.clone())
            .map_err(|_| SspryError::from("Store set root lock poisoned."))
    }

    /// Retargets every shard to a new root after publish/workspace swaps and
    /// clears any cached stats derived from the old location.
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
        self.invalidate_stats_cache()
    }

    #[cfg(test)]
    /// Returns the cached stats snapshot for tests when one has already been
    /// materialized for this store set.
    fn cached_stats(&self) -> Result<Option<(Map<String, Value>, u64)>> {
        let cache = self
            .stats_cache
            .lock()
            .map_err(|_| SspryError::from("Store set stats cache lock poisoned."))?;
        Ok(cache
            .as_ref()
            .map(|entry| (entry.stats.clone(), entry.deleted_storage_bytes)))
    }

    #[cfg(test)]
    /// Stores one JSON stats snapshot plus deleted-byte totals for later test
    /// reuse.
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

    #[cfg(test)]
    /// Clears the test-only stats cache after any mutation that invalidates the
    /// previously aggregated view.
    fn invalidate_stats_cache(&self) -> Result<()> {
        let mut cache = self
            .stats_cache
            .lock()
            .map_err(|_| SspryError::from("Store set stats cache lock poisoned."))?;
        *cache = None;
        Ok(())
    }

    #[cfg(not(test))]
    /// No-ops in non-test builds where store-set stats caching is not
    /// compiled in.
    fn invalidate_stats_cache(&self) -> Result<()> {
        Ok(())
    }
}

#[derive(Debug)]
enum StoreMode {
    Direct {
        stores: Arc<StoreSet>,
    },
    Forest {
        _root: PathBuf,
        trees: Vec<Arc<StoreSet>>,
    },
    Workspace {
        root: PathBuf,
        published: Arc<StoreSet>,
        work_active: Option<Arc<StoreSet>>,
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
    active_index_clients: AtomicUsize,
    next_index_client_id: AtomicU64,
    index_client_leases: Mutex<HashMap<u64, IndexClientLease>>,
    publish_after_index_clients: AtomicBool,
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
    #[cfg(test)]
    normalized_plan_cache: Mutex<BoundedCache<String, Arc<CompiledQueryPlan>>>,
    query_artifact_cache: Mutex<BoundedCache<String, Arc<RuntimeQueryArtifacts>>>,
    #[cfg(test)]
    query_cache: Mutex<BoundedCache<String, Arc<CachedCandidateQuery>>>,
    search_admission: Mutex<SearchAdmissionState>,
    search_admission_cv: Condvar,
    compaction_runtime: Mutex<CompactionRuntime>,
    next_compaction_shard: AtomicUsize,
    active_connections: AtomicUsize,
    maintenance_epoch: Mutex<u64>,
    maintenance_cv: Condvar,
    startup_cleanup_removed_roots: usize,
    startup_profile: StartupProfile,
}

#[derive(Clone, Debug, Default)]
struct SearchAdmissionState {
    active: bool,
    next_ticket: u64,
    serving_ticket: u64,
    waiting: usize,
}

struct ActiveSearchRequestGuard<'a> {
    state: &'a ServerState,
}

impl Drop for ActiveSearchRequestGuard<'_> {
    /// Releases the single-flight search admission slot and wakes any waiting
    /// search requests.
    fn drop(&mut self) {
        if let Ok(mut admission) = self.state.search_admission.lock() {
            if admission.active {
                admission.active = false;
                admission.serving_ticket = admission.serving_ticket.wrapping_add(1);
            }
            self.state.search_admission_cv.notify_all();
        }
        self.state.notify_maintenance_workers();
    }
}

#[cfg(test)]
#[derive(Clone, Debug)]
struct CachedCandidateQuery {
    ordered_hashes: Vec<String>,
    truncated: bool,
    truncated_limit: Option<usize>,
    tier_used: String,
    query_profile: CandidateQueryProfile,
}

#[cfg(test)]
/// Estimates heap usage for a cached query entry used by search-cache tests.
fn cached_candidate_query_memory_bytes(query: &CachedCandidateQuery) -> u64 {
    (std::mem::size_of::<CachedCandidateQuery>() as u64)
        .saturating_add(query.tier_used.capacity() as u64)
        .saturating_add(
            (query.ordered_hashes.capacity() as u64)
                .saturating_mul(std::mem::size_of::<String>() as u64),
        )
        .saturating_add(
            query
                .ordered_hashes
                .iter()
                .map(|hash| hash.capacity() as u64)
                .sum::<u64>(),
        )
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CompactionCycleOutcome {
    Idle,
    Progress,
    RetryLater,
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
    store_open_rebuild_identity_index_ms: u64,
}

#[derive(Clone, Debug, Default)]
struct StartupProfile {
    total_ms: u64,
    current: StoreRootStartupProfile,
    work: StoreRootStartupProfile,
}

struct ServerWorkers {
    compaction_worker: thread::JoinHandle<()>,
    auto_publish_worker: thread::JoinHandle<()>,
    published_tier2_snapshot_seal_worker: thread::JoinHandle<()>,
    status_worker: Option<thread::JoinHandle<()>>,
}

#[derive(Clone)]
struct GrpcServerService {
    state: Arc<ServerState>,
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
    /// Creates the adaptive publish controller with the storage-class baseline
    /// and recent-history buffers sized for the configured shard count.
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

    /// Pushes one observation into a bounded rolling window.
    fn push_recent(window: &mut VecDeque<u64>, value: u64, limit: usize) {
        if window.len() >= limit {
            window.pop_front();
        }
        window.push_back(value);
    }

    /// Returns the p95 value of the rolling window, or zero when it is empty.
    fn p95(window: &VecDeque<u64>) -> u64 {
        if window.is_empty() {
            return 0;
        }
        let mut values = window.iter().copied().collect::<Vec<_>>();
        values.sort_unstable();
        let idx = ((values.len() - 1) * 95) / 100;
        values[idx]
    }

    /// Counts publishes that completed within the current adaptive-rate window.
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

    /// Records the submit and store latency observed for one completed index
    /// session.
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

    /// Records one completed publish and recomputes the current publish-idle
    /// target.
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

    /// Recomputes adaptive state when only the tier-2 sealing backlog changed.
    fn update_seal_backlog(&mut self, now_unix_ms: u64, tier2_pending_shards: usize) {
        self.recompute(now_unix_ms, tier2_pending_shards);
    }

    /// Re-evaluates recent latency, publish rate, and backlog pressure to pick
    /// a new publish idle interval and operating mode.
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

    /// Returns a snapshot of the current adaptive-publish state for status
    /// reporting.
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
    /// Releases the active-mutation counter when a mutation scope finishes.
    fn drop(&mut self) {
        self.state.active_mutations.fetch_sub(1, Ordering::AcqRel);
    }
}

/// Starts the gRPC server with the default request-size limit and background
/// maintenance workers.
pub fn serve_grpc(host: &str, port: u16, config: ServerConfig) -> Result<()> {
    serve_grpc_with_signal_flags(
        host,
        port,
        DEFAULT_MAX_REQUEST_BYTES,
        config,
        Arc::new(AtomicBool::new(false)),
        None,
    )
}

/// Starts the full gRPC runtime, serves requests until shutdown, and then
/// drains all maintenance workers before returning.
pub fn serve_grpc_with_signal_flags(
    host: &str,
    port: u16,
    max_request_bytes: usize,
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    status_dump: Option<Arc<AtomicBool>>,
) -> Result<()> {
    let (state, workers) = start_server_runtime(config, shutdown, status_dump)?;
    let addr = (host, port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| SspryError::from("Invalid TCP address."))?;
    println!(
        "sspry grpc server listening on {}:{}",
        addr.ip(),
        addr.port()
    );
    let service = GrpcServerService {
        state: state.clone(),
    };
    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()?;
    let shutdown_state = state.clone();
    let (shutdown_tx, shutdown_rx) = tokio::sync::oneshot::channel::<()>();
    let shutdown_waiter = thread::spawn(move || {
        let mut maintenance_epoch = shutdown_state.current_maintenance_epoch();
        while !shutdown_state.is_shutting_down() {
            shutdown_state
                .wait_for_maintenance_event(&mut maintenance_epoch, Some(Duration::from_secs(1)));
        }
        let _ = shutdown_tx.send(());
    });
    let serve_result = runtime.block_on(async move {
        tonic::transport::Server::builder()
            .add_service(
                SspryServer::new(service)
                    .max_decoding_message_size(max_request_bytes)
                    .max_encoding_message_size(max_request_bytes),
            )
            .serve_with_shutdown(addr, async move {
                let _ = shutdown_rx.await;
            })
            .await
    });
    state.shutdown.store(true, Ordering::Relaxed);
    state.notify_maintenance_workers();
    let _ = shutdown_waiter.join();
    drain_server_runtime(state, workers);
    serve_result.map_err(|err| SspryError::from(err.to_string()))
}

// Runtime orchestration, status shaping, and gRPC response helpers live in a
// sibling file so the transport entrypoints stay readable.
include!("rpc/runtime.rs");

#[tonic::async_trait]
impl GrpcSspry for GrpcServerService {
    /// Responds to health checks with a fixed `pong` payload.
    async fn ping(
        &self,
        _request: GrpcRequest<PingRequest>,
    ) -> std::result::Result<GrpcResponse<PingResponse>, GrpcStatus> {
        Ok(GrpcResponse::new(PingResponse {
            message: "pong".to_owned(),
        }))
    }

    /// Builds the lightweight gRPC stats summary on a blocking worker thread.
    async fn stats(
        &self,
        _request: GrpcRequest<StatsRequest>,
    ) -> std::result::Result<GrpcResponse<StatsResponse>, GrpcStatus> {
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || state.grpc_stats_response())
            .await
            .map_err(grpc_join_error_status)?
            .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(response))
    }

    /// Builds the full gRPC status payload on a blocking worker thread.
    async fn status(
        &self,
        _request: GrpcRequest<StatusRequest>,
    ) -> std::result::Result<GrpcResponse<StatusResponse>, GrpcStatus> {
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || state.grpc_status_response())
            .await
            .map_err(grpc_join_error_status)?
            .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(response))
    }

    /// Starts the exclusive index session used by remote ingest clients.
    async fn begin_index_session(
        &self,
        _request: GrpcRequest<IndexSessionBeginRequest>,
    ) -> std::result::Result<GrpcResponse<IndexSessionResponse>, GrpcStatus> {
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || state.handle_begin_index_session())
            .await
            .map_err(grpc_join_error_status)?
            .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(IndexSessionResponse {
            message: response.message,
        }))
    }

    /// Registers one index client lease and returns the negotiated heartbeat
    /// timing parameters.
    async fn begin_index_client(
        &self,
        request: GrpcRequest<IndexClientBeginRequest>,
    ) -> std::result::Result<GrpcResponse<IndexClientBeginResponse>, GrpcStatus> {
        let request = request.into_inner();
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || {
            state.handle_begin_index_client(&CandidateIndexClientBeginRequest {
                heartbeat_interval_ms: request.heartbeat_interval_ms,
            })
        })
        .await
        .map_err(grpc_join_error_status)?
        .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(IndexClientBeginResponse {
            message: response.message,
            client_id: response.client_id,
            heartbeat_interval_ms: response.heartbeat_interval_ms,
            lease_timeout_ms: response.lease_timeout_ms,
        }))
    }

    /// Refreshes the lease for one active index client.
    async fn heartbeat_index_client(
        &self,
        request: GrpcRequest<IndexClientHeartbeatRequest>,
    ) -> std::result::Result<GrpcResponse<IndexSessionResponse>, GrpcStatus> {
        let request = request.into_inner();
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || {
            state.handle_heartbeat_index_client(&CandidateIndexClientHeartbeatRequest {
                client_id: request.client_id,
            })
        })
        .await
        .map_err(grpc_join_error_status)?
        .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(IndexSessionResponse {
            message: response.message,
        }))
    }

    /// Updates submitted and processed document counters for the active remote
    /// index session.
    async fn update_index_session_progress(
        &self,
        request: GrpcRequest<IndexSessionProgressRequest>,
    ) -> std::result::Result<GrpcResponse<IndexSessionResponse>, GrpcStatus> {
        let request = request.into_inner();
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || {
            state.handle_update_index_session_progress(&CandidateIndexSessionProgressRequest {
                total_documents: request
                    .has_total_documents
                    .then_some(request.total_documents),
                submitted_documents: request.submitted_documents,
                processed_documents: request.processed_documents,
            })
        })
        .await
        .map_err(grpc_join_error_status)?
        .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(IndexSessionResponse {
            message: response.message,
        }))
    }

    /// Marks the current index session complete.
    async fn end_index_session(
        &self,
        _request: GrpcRequest<IndexSessionEndRequest>,
    ) -> std::result::Result<GrpcResponse<IndexSessionResponse>, GrpcStatus> {
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || state.handle_end_index_session())
            .await
            .map_err(grpc_join_error_status)?
            .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(IndexSessionResponse {
            message: response.message,
        }))
    }

    /// Releases one index client lease and lets publish scheduling observe the
    /// new client count.
    async fn end_index_client(
        &self,
        request: GrpcRequest<IndexClientHeartbeatRequest>,
    ) -> std::result::Result<GrpcResponse<IndexSessionResponse>, GrpcStatus> {
        let request = request.into_inner();
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || {
            state.handle_end_index_client(&CandidateIndexClientHeartbeatRequest {
                client_id: request.client_id,
            })
        })
        .await
        .map_err(grpc_join_error_status)?
        .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(IndexSessionResponse {
            message: response.message,
        }))
    }

    /// Requests an immediate publish through the blocking server-state path.
    async fn publish(
        &self,
        _request: GrpcRequest<PublishRequest>,
    ) -> std::result::Result<GrpcResponse<GrpcPublishResponse>, GrpcStatus> {
        let state = self.state.clone();
        let response = tokio::task::spawn_blocking(move || state.handle_publish())
            .await
            .map_err(grpc_join_error_status)?
            .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(GrpcPublishResponse {
            message: response.message,
        }))
    }

    /// Marks the server as shutting down and acknowledges the RPC caller.
    async fn shutdown(
        &self,
        _request: GrpcRequest<ShutdownRequest>,
    ) -> std::result::Result<GrpcResponse<GrpcShutdownResponse>, GrpcStatus> {
        self.state.shutdown.store(true, Ordering::SeqCst);
        Ok(GrpcResponse::new(GrpcShutdownResponse {
            message: "shutdown requested".to_owned(),
        }))
    }

    /// Deletes one document by configured identity and translates the internal
    /// response into the gRPC wire shape.
    async fn delete(
        &self,
        request: GrpcRequest<GrpcDeleteRequest>,
    ) -> std::result::Result<GrpcResponse<GrpcDeleteResponse>, GrpcStatus> {
        let request = request.into_inner();
        if request.identity.trim().is_empty() {
            return Err(GrpcStatus::invalid_argument(
                "Delete request is missing identity.",
            ));
        }
        let state = self.state.clone();
        let response =
            tokio::task::spawn_blocking(move || state.handle_candidate_delete(&request.identity))
                .await
                .map_err(grpc_join_error_status)?
                .map_err(grpc_internal_status)?;
        Ok(GrpcResponse::new(GrpcDeleteResponse {
            status: response.status,
            identity: response.identity,
            doc_id: response.doc_id.unwrap_or(0),
            has_doc_id: response.doc_id.is_some(),
        }))
    }

    type SearchStreamStream =
        tokio_stream::wrappers::ReceiverStream<std::result::Result<SearchFrame, GrpcStatus>>;

    /// Compiles one search request, streams candidate frames over gRPC, and
    /// emits per-stream tracing around plan and frame timing.
    async fn search_stream(
        &self,
        request: GrpcRequest<SearchRequest>,
    ) -> std::result::Result<GrpcResponse<Self::SearchStreamStream>, GrpcStatus> {
        let request = request.into_inner();
        let state = self.state.clone();
        let (tx, rx) = tokio::sync::mpsc::channel(8);
        tokio::task::spawn_blocking(move || {
            let grpc_started = Instant::now();
            search_trace_log(format!(
                "grpc.start chunk_size={} include_external_ids={} max_candidates_percent={} max_anchors_per_pattern={} force_tier1_only={} allow_tier2_fallback={} target_rule_name={}",
                request.chunk_size,
                request.include_external_ids,
                request.max_candidates_percent,
                request.max_anchors_per_pattern,
                request.force_tier1_only,
                request.allow_tier2_fallback,
                request.target_rule_name
            ));
            let named_plans = match state.compile_search_plans_from_yara_source(&request) {
                Ok(plans) => plans,
                Err(err) => {
                    let _ = tx.blocking_send(Err(grpc_internal_status(err)));
                    return;
                }
            };
            let internal_request = CandidateQueryRequest {
                plan: Value::Null,
                cursor: 0,
                chunk_size: Some(
                    usize::try_from(request.chunk_size)
                        .unwrap_or(DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE)
                        .max(1),
                ),
                include_external_ids: request.include_external_ids,
            };
            let first_frame_started = Instant::now();
            let mut frame_count = 0usize;
            let mut candidate_count = 0usize;
            let result = if named_plans.len() == 1 {
                let (_, plan) = &named_plans[0];
                let plan_key = match ServerState::query_cache_key(plan) {
                    Ok(value) => value,
                    Err(err) => {
                        let _ = tx.blocking_send(Err(grpc_internal_status(err)));
                        return;
                    }
                };
                search_trace_log(format!(
                    "grpc.plan plan_key={} compile_ms={} patterns={} max_candidates={} root={:?}",
                    plan_key,
                    grpc_started.elapsed().as_millis(),
                    plan.patterns.len(),
                    plan.max_candidates,
                    plan.root
                ));
                state.stream_candidate_query_frames(internal_request, plan, |frame| {
                    let frame_candidates = frame.identities.len();
                    frame_count += 1;
                    candidate_count += frame_candidates;
                    search_trace_log(format!(
                        "grpc.frame plan_key={} idx={} candidates={} stream_complete={} elapsed_ms={}",
                        plan_key,
                        frame_count,
                        frame_candidates,
                        frame.stream_complete,
                        first_frame_started.elapsed().as_millis()
                    ));
                    let grpc_frame = grpc_search_frame_from_internal(frame)?;
                    tx.blocking_send(Ok(grpc_frame))
                        .map_err(|_| SspryError::from("gRPC search stream receiver dropped"))?;
                    Ok(())
                })
            } else {
                search_trace_log(format!(
                    "grpc.bundle plan_count={} compile_ms={}",
                    named_plans.len(),
                    grpc_started.elapsed().as_millis()
                ));
                state.stream_candidate_query_frames_batch(internal_request, &named_plans, |frame| {
                    let frame_candidates = frame.identities.len();
                    frame_count += 1;
                    candidate_count += frame_candidates;
                    search_trace_log(format!(
                        "grpc.bundle.frame idx={} rule={} candidates={} stream_complete={} rule_complete={} elapsed_ms={}",
                        frame_count,
                        frame.target_rule_name,
                        frame_candidates,
                        frame.stream_complete,
                        frame.rule_complete,
                        first_frame_started.elapsed().as_millis()
                    ));
                    let grpc_frame = grpc_search_frame_from_internal(frame)?;
                    tx.blocking_send(Ok(grpc_frame))
                        .map_err(|_| SspryError::from("gRPC search stream receiver dropped"))?;
                    Ok(())
                })
            };
            if let Err(err) = result {
                let _ = tx.blocking_send(Err(grpc_internal_status(err)));
            } else {
                search_trace_log(format!(
                    "grpc.done plans={} frames={} candidates={} total_ms={}",
                    named_plans.len(),
                    frame_count,
                    candidate_count,
                    grpc_started.elapsed().as_millis()
                ));
            }
        });
        Ok(GrpcResponse::new(
            tokio_stream::wrappers::ReceiverStream::new(rx),
        ))
    }

    /// Reassembles framed insert rows from the client stream and flushes them
    /// through the shared batch-insert path.
    async fn insert_stream(
        &self,
        request: GrpcRequest<tonic::Streaming<InsertFrame>>,
    ) -> std::result::Result<GrpcResponse<InsertSummary>, GrpcStatus> {
        let mut stream = request.into_inner();
        let mut current_row = Vec::<u8>::new();
        let mut parsed_documents = Vec::<ParsedCandidateInsertDocument>::new();
        let mut batch_input_bytes = 0u64;
        let mut batch_row_bytes = 0usize;
        let mut batch_parse_elapsed = Duration::ZERO;
        let mut summary = CandidateInsertBatchResponse {
            inserted_count: 0,
            results: Vec::new(),
        };
        let mut saw_stream_complete = false;

        while let Some(frame) = stream.next().await {
            let frame = frame.map_err(tonic_error_to_status)?;
            if saw_stream_complete {
                return Err(GrpcStatus::invalid_argument(
                    "received insert frames after stream_complete=true",
                ));
            }
            if frame.stream_complete {
                if frame.row_complete || !frame.payload.is_empty() {
                    return Err(GrpcStatus::invalid_argument(
                        "stream_complete frame must not include payload or row_complete=true",
                    ));
                }
                if !current_row.is_empty() {
                    return Err(GrpcStatus::invalid_argument(
                        "gRPC insert stream ended with an incomplete row",
                    ));
                }
                if !parsed_documents.is_empty() {
                    let flush_documents = std::mem::take(&mut parsed_documents);
                    let flush_input_bytes = batch_input_bytes;
                    let flush_parse_elapsed = batch_parse_elapsed;
                    batch_input_bytes = 0;
                    batch_row_bytes = 0;
                    batch_parse_elapsed = Duration::ZERO;
                    let state = self.state.clone();
                    let response = tokio::task::spawn_blocking(move || {
                        state.handle_candidate_insert_batch_parsed(
                            flush_documents,
                            flush_input_bytes,
                            flush_parse_elapsed,
                        )
                    })
                    .await
                    .map_err(grpc_join_error_status)?
                    .map_err(grpc_internal_status)?;
                    summary.inserted_count = summary
                        .inserted_count
                        .saturating_add(response.inserted_count);
                    summary.results.extend(response.results);
                }
                saw_stream_complete = true;
                continue;
            }

            current_row.extend_from_slice(&frame.payload);
            if !frame.row_complete {
                continue;
            }

            let row_len = current_row.len();
            let started_parse = Instant::now();
            let identity_bytes = self.state.candidate_identity_bytes_len();
            let parsed = parse_candidate_insert_binary_row(
                &current_row,
                identity_bytes,
                "grpc.insert_stream.row",
            )
            .map_err(|err| GrpcStatus::invalid_argument(err.to_string()))?;
            batch_parse_elapsed += started_parse.elapsed();
            batch_input_bytes = batch_input_bytes.saturating_add(parsed.1);
            batch_row_bytes = batch_row_bytes.saturating_add(row_len);
            parsed_documents.push(parsed);
            current_row = Vec::new();

            if parsed_documents.len() < GRPC_STREAM_INSERT_BATCH_MAX_ROWS
                && batch_row_bytes < GRPC_STREAM_INSERT_BATCH_MAX_BYTES
            {
                continue;
            }

            let flush_documents = std::mem::take(&mut parsed_documents);
            let flush_input_bytes = batch_input_bytes;
            let flush_parse_elapsed = batch_parse_elapsed;
            batch_input_bytes = 0;
            batch_row_bytes = 0;
            batch_parse_elapsed = Duration::ZERO;
            let state = self.state.clone();
            let response = tokio::task::spawn_blocking(move || {
                state.handle_candidate_insert_batch_parsed(
                    flush_documents,
                    flush_input_bytes,
                    flush_parse_elapsed,
                )
            })
            .await
            .map_err(grpc_join_error_status)?
            .map_err(grpc_internal_status)?;
            summary.inserted_count = summary
                .inserted_count
                .saturating_add(response.inserted_count);
            summary.results.extend(response.results);
        }
        if !saw_stream_complete {
            return Err(GrpcStatus::invalid_argument(
                "gRPC insert stream ended without stream_complete=true",
            ));
        }
        Ok(GrpcResponse::new(InsertSummary {
            inserted_count: summary.inserted_count.try_into().unwrap_or(u64::MAX),
            results: summary
                .results
                .into_iter()
                .map(|item| InsertResult {
                    status: item.status,
                    doc_id: item.doc_id,
                    identity: item.identity,
                })
                .collect(),
        }))
    }
}

#[cfg(test)]
/// Returns the signed difference between two monotonic counters for test
/// assertions and status summaries.
fn signed_delta_i64(current: u64, baseline: u64) -> i64 {
    if current >= baseline {
        let delta = current.saturating_sub(baseline);
        delta.min(i64::MAX as u64) as i64
    } else {
        let delta = baseline.saturating_sub(current);
        -(delta.min(i64::MAX as u64) as i64)
    }
}

// The server-state implementation is split out so the type and transport layer
// are easier to navigate independently.
include!("rpc/server_state.rs");

// Binary candidate insert payload encoding lives in a sibling file to keep
// the server core focused on transport and lifecycle logic.
include!("rpc/codec.rs");

// Store-root, workspace, forest, and disk-usage helpers live in a sibling file
// so storage layout code stays separate from RPC request handling.
include!("rpc/store_roots.rs");

#[cfg(test)]
mod tests;
