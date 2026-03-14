use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::io::ErrorKind;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
#[cfg(unix)]
use std::os::unix::net::{UnixListener, UnixStream};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, TryLockError};
use std::thread;
use std::time::{Duration, Instant};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::Engine;
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value, json};

use crate::candidate::store::{
    CandidateCompactionResult, CandidateCompactionSnapshot, PreparedQueryArtifacts,
    build_prepared_query_artifacts, cleanup_abandoned_compaction_roots, compaction_work_root,
    write_compacted_snapshot,
};
use crate::candidate::{
    BoundedCache, CandidateConfig, CandidateStore, CompiledQueryPlan, PatternPlan, QueryNode,
    candidate_shard_index, candidate_shard_root, decode_grams_delta_u64, normalize_max_candidates,
    read_candidate_shard_count, write_candidate_shard_count,
};
use crate::perf::{record_counter, scope};
use crate::{Result, TgsError};

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
const ACTION_CANDIDATE_DF: u8 = 7;
const ACTION_SHUTDOWN: u8 = 8;
const ACTION_PUBLISH: u8 = 9;

const DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE: usize = 128;
const DF_CACHE_CAPACITY: usize = 128;
const QUERY_CACHE_CAPACITY: usize = 64;
const DEFAULT_CANDIDATE_SHARD_LOCK_TIMEOUT_MS: u64 = 1000;
const CANDIDATE_SHARD_LOCK_POLL_INTERVAL_MS: u64 = 10;

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
                return Err(TgsError::from("Candidate store lock poisoned."));
            }
            Err(TryLockError::WouldBlock) => {
                if Instant::now() >= deadline {
                    return Err(TgsError::from(format!(
                        "candidate shard {shard_idx} busy during {operation}; retry later"
                    )));
                }
                thread::sleep(Duration::from_millis(CANDIDATE_SHARD_LOCK_POLL_INTERVAL_MS));
            }
        }
    }
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
    pub workspace_mode: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateInsertResponse {
    pub status: String,
    pub doc_id: u64,
    pub sha256: String,
    pub grams_received: usize,
    pub grams_indexed: usize,
    pub grams_complete: bool,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_ids: Option<Vec<Option<String>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CandidateDocumentWire {
    pub sha256: String,
    pub file_size: u64,
    pub bloom_filter_b64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gram_count_estimate: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bloom_hashes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier2_bloom_filter_b64: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier2_gram_count_estimate: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tier2_bloom_hashes: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub grams_delta_b64: Option<String>,
    #[serde(default)]
    pub grams: Vec<u64>,
    #[serde(default = "default_true")]
    pub grams_complete: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub effective_diversity: Option<f64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidateDfWireResponse {
    df: BTreeMap<String, usize>,
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
struct CandidateDfRequest {
    grams: Vec<u64>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct CandidatePublishResponse {
    message: String,
}

type ParsedCandidateInsertDocument = (
    [u8; 32],
    u64,
    Option<usize>,
    Option<usize>,
    Vec<u8>,
    Option<usize>,
    Option<usize>,
    Vec<u8>,
    Vec<u64>,
    bool,
    Option<f64>,
    Option<String>,
    bool,
);

#[derive(Debug)]
struct StoreSet {
    root: PathBuf,
    stores: Vec<Mutex<CandidateStore>>,
}

impl StoreSet {
    fn new(root: PathBuf, stores: Vec<CandidateStore>) -> Self {
        Self {
            root,
            stores: stores.into_iter().map(Mutex::new).collect(),
        }
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
        work: Arc<StoreSet>,
    },
}

#[derive(Debug)]
struct ServerState {
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    operation_gate: RwLock<()>,
    store_mode: Mutex<StoreMode>,
    mutations_paused: AtomicBool,
    publish_in_progress: AtomicBool,
    active_mutations: AtomicUsize,
    df_cache: Mutex<BoundedCache<Vec<u64>, Arc<HashMap<u64, usize>>>>,
    normalized_plan_cache: Mutex<BoundedCache<String, Arc<CompiledQueryPlan>>>,
    prepared_plan_cache: Mutex<BoundedCache<String, Arc<PreparedQueryArtifacts>>>,
    query_cache: Mutex<BoundedCache<String, Arc<CachedCandidateQuery>>>,
    compaction_runtime: Mutex<CompactionRuntime>,
    next_compaction_shard: AtomicUsize,
    active_connections: AtomicUsize,
    startup_cleanup_removed_roots: usize,
}

#[derive(Clone, Debug)]
struct CachedCandidateQuery {
    ordered_hashes: Vec<String>,
    tier_used: String,
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

struct ActiveMutationGuard<'a> {
    state: &'a ServerState,
}

impl Drop for ActiveMutationGuard<'_> {
    fn drop(&mut self) {
        self.state.active_mutations.fetch_sub(1, Ordering::AcqRel);
    }
}

#[derive(Debug)]
pub struct TgsdbClient {
    config: ClientConfig,
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

impl TgsdbClient {
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
                TgsError::from("Single document insert request is too large to send."),
            ),
            Err(err) => Err(err),
        }
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

    pub fn candidate_df(&self, grams: &[u64]) -> Result<HashMap<u64, usize>> {
        let response: CandidateDfWireResponse = self.request_typed_json(
            ACTION_CANDIDATE_DF,
            &CandidateDfRequest {
                grams: grams.to_vec(),
            },
        )?;
        let mut out = HashMap::new();
        for (gram, count) in response.df {
            if let Ok(value) = gram.parse::<u64>() {
                out.insert(value, count);
            }
        }
        Ok(out)
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
            .ok_or_else(|| TgsError::from("Server returned invalid JSON object."))
    }

    fn request_typed_bytes<T>(&self, action: u8, payload: &[u8]) -> Result<T>
    where
        T: DeserializeOwned,
    {
        let bytes = self.request_bytes(action, payload)?;
        serde_json::from_slice(&bytes).map_err(TgsError::from)
    }

    fn request_bytes(&self, action: u8, payload: &[u8]) -> Result<Vec<u8>> {
        let mut stream = self.connect()?;
        write_frame(&mut stream, PROTOCOL_VERSION, action, payload)?;
        let (version, status, response_payload) = read_frame(&mut stream)?;
        if version != PROTOCOL_VERSION {
            return Err(TgsError::from(format!(
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
        Err(TgsError::from(message.to_owned()))
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
                return Err(TgsError::from(
                    "Unix sockets are not supported on this platform.",
                ));
            }
        }

        let stream = TcpStream::connect_timeout(
            &format!("{}:{}", self.config.host, self.config.port)
                .parse()
                .map_err(|_| TgsError::from("Invalid TCP address."))?,
            self.config.timeout,
        )?;
        stream.set_read_timeout(Some(self.config.timeout))?;
        stream.set_write_timeout(Some(self.config.timeout))?;
        Ok(ClientStream::Tcp(stream))
    }
}

fn is_payload_too_large_error(err: &TgsError) -> bool {
    let text = err.to_string();
    text.contains("Request payload is too large") || text.contains("Payload is too large")
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
            println!("yaya server listening on unix://{}", path.display());
            accept_unix(listener, state.clone(), max_request_bytes)
        }
        #[cfg(not(unix))]
        {
            let _ = (path, state, max_request_bytes);
            return Err(TgsError::from(
                "Unix sockets are not supported on this platform.",
            ));
        }
    } else {
        let listener = TcpListener::bind((host, port))?;
        let local = listener.local_addr()?;
        println!("yaya server listening on {}:{}", local.ip(), local.port());
        accept_tcp(listener, state.clone(), max_request_bytes)
    };

    if state.is_shutting_down() {
        eprintln!("yaya: shutdown requested, draining");
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
    let mut last_reported_connections = usize::MAX;
    while state.active_connections.load(Ordering::Acquire) > 0 {
        let active_connections = state.active_connections.load(Ordering::Acquire);
        if active_connections != last_reported_connections {
            eprintln!("yaya: waiting for {active_connections} active connection(s) to drain");
            last_reported_connections = active_connections;
        }
        thread::sleep(Duration::from_millis(25));
    }
    eprintln!("yaya: shutdown complete");
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

fn candidate_stats_json_from_parts(
    root: &Path,
    stats_rows: &[crate::candidate::CandidateStats],
    filter_bucket_rows: &[BTreeMap<String, usize>],
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
    let tier1_incomplete_doc_count = stats_rows
        .iter()
        .map(|item| item.tier1_incomplete_doc_count)
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
    let df_counts_delta_bytes = stats_rows
        .iter()
        .map(|item| item.df_counts_delta_bytes)
        .sum::<u64>();
    let df_counts_delta_entries = stats_rows
        .iter()
        .map(|item| item.df_counts_delta_entries)
        .sum::<usize>();
    let df_counts_delta_compact_threshold_bytes = stats_rows
        .iter()
        .map(|item| item.df_counts_delta_compact_threshold_bytes)
        .sum::<u64>();
    let tier2_superblock_summary_bytes = stats_rows
        .iter()
        .map(|item| item.tier2_superblock_summary_bytes)
        .sum::<u64>();
    let tier2_superblock_memory_budget_bytes = stats_rows
        .iter()
        .map(|item| item.tier2_superblock_memory_budget_bytes)
        .sum::<u64>();
    let mut merged_filter_bucket_counts = BTreeMap::<String, usize>::new();
    for row in filter_bucket_rows {
        for (key, count) in row {
            *merged_filter_bucket_counts.entry(key.clone()).or_insert(0) += *count;
        }
    }
    let filter_bucket_counts = merged_filter_bucket_counts
        .into_iter()
        .map(|(key, count)| (key, json!(count)))
        .collect::<Map<String, Value>>();

    let mut out = Map::<String, Value>::new();
    out.insert("active_doc_count".to_owned(), json!(active_doc_count));
    out.insert(
        "candidate_shards".to_owned(),
        json!(stats_rows.len().max(1)),
    );
    out.insert("id_source".to_owned(), json!(stats.id_source));
    out.insert("store_path".to_owned(), json!(stats.store_path));
    out.insert("deleted_doc_count".to_owned(), json!(deleted_doc_count));
    out.insert("df_max".to_owned(), json!(stats.df_max));
    out.insert("df_min".to_owned(), json!(stats.df_min));
    out.insert(
        "df_counts_delta_bytes".to_owned(),
        json!(df_counts_delta_bytes),
    );
    out.insert(
        "df_counts_delta_entries".to_owned(),
        json!(df_counts_delta_entries),
    );
    out.insert(
        "df_counts_delta_compact_threshold_bytes".to_owned(),
        json!(df_counts_delta_compact_threshold_bytes),
    );
    out.insert(
        "tier2_superblock_summary_bytes".to_owned(),
        json!(tier2_superblock_summary_bytes),
    );
    out.insert(
        "tier2_superblock_memory_budget_bytes".to_owned(),
        json!(tier2_superblock_memory_budget_bytes),
    );
    out.insert("disk_usage_bytes".to_owned(), json!(disk_usage_under(root)));
    out.insert(
        "doc_count".to_owned(),
        json!(active_doc_count + deleted_doc_count),
    );
    out.insert(
        "compaction_generation".to_owned(),
        json!(compaction_generation),
    );
    out.insert(
        "filter_bucket_counts".to_owned(),
        Value::Object(filter_bucket_counts),
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
    out.insert(
        "gram_sizes".to_owned(),
        Value::String(format!(
            "{},{}",
            stats.tier2_gram_size, stats.tier1_gram_size
        )),
    );
    out.insert("query_count".to_owned(), json!(stats.query_count));
    out.insert(
        "retired_generation_count".to_owned(),
        json!(retired_generation_count),
    );
    out.insert(
        "tier1_complete".to_owned(),
        json!(tier1_incomplete_doc_count == 0),
    );
    out.insert(
        "tier1_incomplete_doc_count".to_owned(),
        json!(tier1_incomplete_doc_count),
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

pub fn candidate_stats_json(root: &Path, store: &CandidateStore) -> Map<String, Value> {
    candidate_stats_json_from_parts(root, &[store.stats()], &[store.filter_bucket_counts()])
}

pub fn candidate_stats_json_for_stores(
    root: &Path,
    stores: &[CandidateStore],
) -> Map<String, Value> {
    let stats_rows = stores.iter().map(CandidateStore::stats).collect::<Vec<_>>();
    let filter_bucket_rows = stores
        .iter()
        .map(CandidateStore::filter_bucket_counts)
        .collect::<Vec<_>>();
    candidate_stats_json_from_parts(root, &stats_rows, &filter_bucket_rows)
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
        let (store_mode, startup_cleanup_removed_roots) = ensure_candidate_stores(&config)?;
        Ok(Self {
            config,
            shutdown,
            operation_gate: RwLock::new(()),
            store_mode: Mutex::new(store_mode),
            mutations_paused: AtomicBool::new(false),
            publish_in_progress: AtomicBool::new(false),
            active_mutations: AtomicUsize::new(0),
            df_cache: Mutex::new(BoundedCache::new(DF_CACHE_CAPACITY)),
            normalized_plan_cache: Mutex::new(BoundedCache::new(QUERY_CACHE_CAPACITY)),
            prepared_plan_cache: Mutex::new(BoundedCache::new(QUERY_CACHE_CAPACITY)),
            query_cache: Mutex::new(BoundedCache::new(QUERY_CACHE_CAPACITY)),
            compaction_runtime: Mutex::new(CompactionRuntime::default()),
            next_compaction_shard: AtomicUsize::new(0),
            active_connections: AtomicUsize::new(0),
            startup_cleanup_removed_roots,
        })
    }

    fn is_shutting_down(&self) -> bool {
        self.shutdown.load(Ordering::Relaxed)
    }

    fn published_store_set(&self) -> Result<Arc<StoreSet>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| TgsError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { stores } => stores.clone(),
            StoreMode::Workspace { published, .. } => published.clone(),
        })
    }

    fn work_store_set(&self) -> Result<Arc<StoreSet>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| TgsError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { stores } => stores.clone(),
            StoreMode::Workspace { work, .. } => work.clone(),
        })
    }

    fn workspace_roots(&self) -> Result<Option<(PathBuf, PathBuf)>> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| TgsError::from("Server store mode lock poisoned."))?;
        Ok(match &*mode {
            StoreMode::Direct { .. } => None,
            StoreMode::Workspace {
                published, work, ..
            } => Some((published.root.clone(), work.root.clone())),
        })
    }

    fn mutation_affects_published_queries(&self) -> Result<bool> {
        let mode = self
            .store_mode
            .lock()
            .map_err(|_| TgsError::from("Server store mode lock poisoned."))?;
        Ok(matches!(*mode, StoreMode::Direct { .. }))
    }

    fn begin_mutation(&self, operation: &str) -> Result<ActiveMutationGuard<'_>> {
        self.active_mutations.fetch_add(1, Ordering::AcqRel);
        if self.mutations_paused.load(Ordering::Acquire) {
            self.active_mutations.fetch_sub(1, Ordering::AcqRel);
            return Err(TgsError::from(format!(
                "server is publishing; {operation} temporarily disabled; retry later"
            )));
        }
        Ok(ActiveMutationGuard { state: self })
    }

    fn candidate_stats_json_for_store_set(
        &self,
        store_set: &StoreSet,
        operation: &str,
    ) -> Result<(Map<String, Value>, u64)> {
        let mut stats_rows = Vec::with_capacity(store_set.stores.len());
        let mut filter_bucket_rows = Vec::with_capacity(store_set.stores.len());
        let mut deleted_storage_bytes = 0u64;
        for (shard_idx, store_lock) in store_set.stores.iter().enumerate() {
            let store = lock_candidate_store_with_timeout(store_lock, shard_idx, operation)?;
            stats_rows.push(store.stats());
            filter_bucket_rows.push(store.filter_bucket_counts());
            deleted_storage_bytes =
                deleted_storage_bytes.saturating_add(store.deleted_storage_bytes());
        }
        Ok((
            candidate_stats_json_from_parts(&store_set.root, &stats_rows, &filter_bucket_rows),
            deleted_storage_bytes,
        ))
    }

    fn current_stats_json(&self) -> Result<Map<String, Value>> {
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
        let published = self.published_store_set()?;
        let (mut stats, deleted_storage_bytes) =
            self.candidate_stats_json_for_store_set(&published, "stats")?;
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
            "mutations_paused".to_owned(),
            json!(self.mutations_paused.load(Ordering::Acquire)),
        );
        stats.insert(
            "publish_in_progress".to_owned(),
            json!(self.publish_in_progress.load(Ordering::Acquire)),
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
        stats.insert(
            "deleted_storage_bytes".to_owned(),
            json!(deleted_storage_bytes),
        );
        if let Some((published_root, work_root)) = self.workspace_roots()? {
            let work = self.work_store_set()?;
            let (work_stats, work_deleted_storage_bytes) =
                self.candidate_stats_json_for_store_set(&work, "work stats")?;
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
            stats.insert("work".to_owned(), Value::Object(work_stats));
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
        if let Ok(mut cache) = self.df_cache.lock() {
            cache.clear();
        }
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
            .map_err(|_| TgsError::from("Candidate store lock poisoned."))?;
        store.garbage_collect_retired_generations()
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
            .map_err(|_| TgsError::from("Candidate store lock poisoned."))?;
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
            .map_err(|_| TgsError::from("Candidate store lock poisoned."))?;
        store.apply_compaction_snapshot(snapshot, compacted_root)
    }

    fn run_compaction_cycle(&self) -> Result<()> {
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
        let Some((shard_idx, snapshot)) = self.find_compaction_candidate()? else {
            return Ok(());
        };

        {
            let mut runtime = self
                .compaction_runtime
                .lock()
                .map_err(|_| TgsError::from("Compaction runtime lock poisoned."))?;
            runtime.running_shard = Some(shard_idx);
            runtime.last_error = None;
        }

        let work = self.work_store_set()?;
        let compacted_root = compaction_work_root(
            &candidate_shard_root(&work.root, self.candidate_shard_count(), shard_idx),
            "compact",
        );
        let build_result = write_compacted_snapshot(&snapshot, &compacted_root);
        let apply_result = match build_result {
            Ok(()) => self.apply_compaction_snapshot(shard_idx, &snapshot, &compacted_root),
            Err(err) => Err(err),
        };

        match apply_result {
            Ok(Some(result)) => {
                let mut runtime = self
                    .compaction_runtime
                    .lock()
                    .map_err(|_| TgsError::from("Compaction runtime lock poisoned."))?;
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
                    .map_err(|_| TgsError::from("Compaction runtime lock poisoned."))?;
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

    fn normalized_df_cache_key(grams: &[u64]) -> Vec<u64> {
        let mut key = grams.to_vec();
        key.sort_unstable();
        key.dedup();
        key
    }

    fn query_cache_key(plan: &CompiledQueryPlan) -> Result<String> {
        serde_json::to_string(&compiled_query_plan_to_wire(plan)).map_err(TgsError::from)
    }

    fn normalized_plan_from_wire(&self, value: &Value) -> Result<Arc<CompiledQueryPlan>> {
        let key = serde_json::to_string(value).map_err(TgsError::from)?;
        if let Some(entry) = self
            .normalized_plan_cache
            .lock()
            .map_err(|_| TgsError::from("Normalized plan cache lock poisoned."))?
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
            .map_err(|_| TgsError::from("Normalized plan cache lock poisoned."))?;
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
            .map_err(|_| TgsError::from("Prepared plan cache lock poisoned."))?
            .get(&key)
        {
            record_counter("rpc.handle_candidate_query_prepared_cache_hits_total", 1);
            return Ok(entry);
        }
        record_counter("rpc.handle_candidate_query_prepared_cache_misses_total", 1);
        let mut filter_keys = HashSet::<(usize, usize)>::new();
        let mut secondary_filter_keys = HashSet::<(usize, usize)>::new();
        let published = self.published_store_set()?;
        for (shard_idx, store_lock) in published.stores.iter().enumerate() {
            let store = lock_candidate_store_with_timeout(store_lock, shard_idx, "query prepare")?;
            filter_keys.extend(store.tier2_filter_keys());
            secondary_filter_keys.extend(store.secondary_filter_keys());
        }
        let mut ordered_filter_keys = filter_keys.into_iter().collect::<Vec<_>>();
        ordered_filter_keys.sort_unstable();
        let mut ordered_secondary_filter_keys =
            secondary_filter_keys.into_iter().collect::<Vec<_>>();
        ordered_secondary_filter_keys.sort_unstable();
        let entry = build_prepared_query_artifacts(
            plan,
            &ordered_filter_keys,
            &ordered_secondary_filter_keys,
        )?;
        let mut cache = self
            .prepared_plan_cache
            .lock()
            .map_err(|_| TgsError::from("Prepared plan cache lock poisoned."))?;
        cache.insert(key, entry.clone());
        Ok(entry)
    }

    fn collect_query_matches_single_store(
        store: &mut CandidateStore,
        plan: &CompiledQueryPlan,
        prepared: &PreparedQueryArtifacts,
    ) -> Result<(Vec<(String, u32)>, Vec<String>)> {
        let mut hits = Vec::<(String, u32)>::new();
        let mut tier_used = Vec::<String>::new();
        let collect_chunk = plan.max_candidates.max(1).min(4096);
        let mut cursor = 0usize;
        loop {
            let local =
                store.query_candidates_with_prepared(plan, prepared, cursor, collect_chunk)?;
            tier_used.push(local.tier_used.clone());
            hits.extend(local.sha256.into_iter().zip(local.scores.into_iter()));
            if let Some(next) = local.next_cursor {
                cursor = next;
            } else {
                break;
            }
        }
        Ok((hits, tier_used))
    }

    fn collect_query_matches_all_shards(
        &self,
        plan: &CompiledQueryPlan,
    ) -> Result<CachedCandidateQuery> {
        let prepared = self.shared_prepared_query_artifacts(plan)?;
        let published = self.published_store_set()?;
        if self.candidate_shard_count() == 1 {
            let mut store =
                lock_candidate_store_with_timeout(&published.stores[0], 0, "query scan")?;
            let (mut hits, tier_used) =
                Self::collect_query_matches_single_store(&mut store, plan, &prepared)?;
            hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            let ordered_hashes = hits.into_iter().map(|(sha256, _)| sha256).collect();
            return Ok(CachedCandidateQuery {
                ordered_hashes,
                tier_used: Self::merge_candidate_tier_used(&tier_used),
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
            for (shard_idx, store_lock) in published.stores.iter().enumerate() {
                let mut store =
                    lock_candidate_store_with_timeout(store_lock, shard_idx, "query scan")?;
                let (local_hits, local_tiers) =
                    Self::collect_query_matches_single_store(&mut store, plan, &prepared)?;
                hits.extend(local_hits);
                tier_used.extend(local_tiers);
            }
            hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
            let ordered_hashes = hits.into_iter().map(|(sha256, _)| sha256).collect();
            return Ok(CachedCandidateQuery {
                ordered_hashes,
                tier_used: Self::merge_candidate_tier_used(&tier_used),
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
                handles.push(
                    scope.spawn(move || -> Result<(Vec<(String, u32)>, Vec<String>)> {
                        let mut local_hits = Vec::<(String, u32)>::new();
                        let mut local_tiers = Vec::<String>::new();
                        loop {
                            let shard_idx = next_shard.fetch_add(1, Ordering::Relaxed);
                            if shard_idx >= stores.stores.len() {
                                break;
                            }
                            let mut store = lock_candidate_store_with_timeout(
                                &stores.stores[shard_idx],
                                shard_idx,
                                "query scan",
                            )?;
                            let (hits, tiers) = Self::collect_query_matches_single_store(
                                &mut store, plan, &prepared,
                            )?;
                            local_hits.extend(hits);
                            local_tiers.extend(tiers);
                        }
                        Ok((local_hits, local_tiers))
                    }),
                );
            }

            let mut merged = Vec::with_capacity(handles.len());
            for handle in handles {
                let partial = handle
                    .join()
                    .map_err(|_| TgsError::from("Candidate query worker panicked."))??;
                merged.push(partial);
            }
            Ok::<Vec<(Vec<(String, u32)>, Vec<String>)>, TgsError>(merged)
        })?;

        let mut hits = Vec::<(String, u32)>::new();
        let mut tier_used = Vec::<String>::new();
        for (local_hits, local_tiers) in partials {
            hits.extend(local_hits);
            tier_used.extend(local_tiers);
        }
        hits.sort_by(|left, right| right.1.cmp(&left.1).then_with(|| left.0.cmp(&right.0)));
        let ordered_hashes = hits.into_iter().map(|(sha256, _)| sha256).collect();
        Ok(CachedCandidateQuery {
            ordered_hashes,
            tier_used: Self::merge_candidate_tier_used(&tier_used),
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
                    | ACTION_PUBLISH
            )
        {
            return Err(TgsError::from(
                "server is shutting down; mutating requests are disabled",
            ));
        }
        match action {
            ACTION_PING => json_bytes(&json!({ "message": "pong" })),
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
            ACTION_CANDIDATE_STATS => json_bytes(&Value::Object(self.current_stats_json()?)),
            ACTION_CANDIDATE_DF => {
                let request: CandidateDfRequest = json_from_bytes(payload)?;
                json_bytes(&self.handle_candidate_df(&request.grams)?)
            }
            ACTION_SHUTDOWN => {
                self.shutdown.store(true, Ordering::SeqCst);
                json_bytes(&json!({ "message": "shutdown requested" }))
            }
            ACTION_PUBLISH => json_bytes(&self.handle_publish()?),
            _ => Err(TgsError::from(format!("Unsupported action code: {action}"))),
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
                TgsError::from(format!(
                    "{field_prefix}.bloom_filter_b64 must be valid base64."
                ))
            })?;
        let tier2_bloom_filter = if let Some(payload) = &document.tier2_bloom_filter_b64 {
            base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map_err(|_| {
                    TgsError::from(format!(
                        "{field_prefix}.tier2_bloom_filter_b64 must be valid base64."
                    ))
                })?
        } else {
            Vec::new()
        };
        let (grams, grams_sorted_unique) = if let Some(payload) = &document.grams_delta_b64 {
            let packed = base64::engine::general_purpose::STANDARD
                .decode(payload.as_bytes())
                .map_err(|_| {
                    TgsError::from(format!(
                        "{field_prefix}.grams_delta_b64 must be valid base64."
                    ))
                })?;
            (
                decode_grams_delta_u64(&packed).map_err(|err| {
                    TgsError::from(format!("{field_prefix}.grams_delta_b64 is invalid: {err}"))
                })?,
                true,
            )
        } else {
            (document.grams.clone(), false)
        };
        let gram_count_estimate = document
            .gram_count_estimate
            .map(|value| {
                if value < 0 {
                    Err(TgsError::from(format!(
                        "{field_prefix}.gram_count_estimate must be >= 0."
                    )))
                } else {
                    Ok(value as usize)
                }
            })
            .transpose()?;
        let selected_grams = if grams_sorted_unique {
            grams
        } else {
            let mut dedup: Vec<u64> = grams
                .into_iter()
                .collect::<HashSet<_>>()
                .into_iter()
                .collect();
            dedup.sort_unstable();
            dedup
        };
        let bloom_hashes = document.bloom_hashes.filter(|value| *value > 0);
        let tier2_gram_count_estimate = document
            .tier2_gram_count_estimate
            .map(|value| {
                if value < 0 {
                    Err(TgsError::from(format!(
                        "{field_prefix}.tier2_gram_count_estimate must be >= 0."
                    )))
                } else {
                    Ok(value as usize)
                }
            })
            .transpose()?;
        let tier2_bloom_hashes = document.tier2_bloom_hashes.filter(|value| *value > 0);
        Ok((
            sha256,
            document.file_size,
            gram_count_estimate,
            bloom_hashes,
            bloom_filter,
            tier2_gram_count_estimate,
            tier2_bloom_hashes,
            tier2_bloom_filter,
            selected_grams,
            document.grams_complete,
            document
                .effective_diversity
                .map(|value| value.clamp(0.0, 1.0)),
            document.external_id.clone(),
            true,
        ))
    }

    fn candidate_insert_response(
        result: crate::candidate::CandidateInsertResult,
    ) -> CandidateInsertResponse {
        CandidateInsertResponse {
            status: result.status,
            doc_id: result.doc_id,
            sha256: result.sha256,
            grams_received: result.grams_received,
            grams_indexed: result.grams_indexed,
            grams_complete: result.grams_complete,
        }
    }

    fn handle_candidate_insert(
        &self,
        document: &CandidateDocumentWire,
    ) -> Result<CandidateInsertResponse> {
        let _scope = scope("rpc.handle_candidate_insert");
        let _mutation = self.begin_mutation("insert")?;
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
        let parsed = self.parse_candidate_insert_document(document, "request.payload")?;
        let shard_idx = self.candidate_store_index_for_sha256(&parsed.0);
        let work = self.work_store_set()?;
        let mut store =
            lock_candidate_store_with_timeout(&work.stores[shard_idx], shard_idx, "insert")?;
        let result = store.insert_document(
            parsed.0,
            parsed.1,
            parsed.2,
            parsed.3,
            parsed.5,
            parsed.6,
            parsed.4.len(),
            &parsed.4,
            parsed.7.len(),
            &parsed.7,
            &parsed.8,
            parsed.9,
            parsed.10,
            parsed.11,
            parsed.12,
        )?;
        drop(store);
        if self.mutation_affects_published_queries()? {
            self.invalidate_search_caches();
        }
        Ok(Self::candidate_insert_response(result))
    }

    fn handle_candidate_insert_batch(
        &self,
        documents: &[CandidateDocumentWire],
    ) -> Result<CandidateInsertBatchResponse> {
        let _scope = scope("rpc.handle_candidate_insert_batch");
        let _mutation = self.begin_mutation("insert batch")?;
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
        let mut parsed_documents = Vec::with_capacity(documents.len());
        for (idx, document) in documents.iter().enumerate() {
            parsed_documents.push(self.parse_candidate_insert_document(
                document,
                &format!("request.payload.documents[{idx}]"),
            )?);
        }

        let mut results = vec![None; parsed_documents.len()];
        let work = self.work_store_set()?;
        if self.candidate_shard_count() == 1 {
            let mut store = lock_candidate_store_with_timeout(&work.stores[0], 0, "insert batch")?;
            let batch = parsed_documents
                .iter()
                .map(|row| {
                    (
                        row.0,
                        row.1,
                        row.2,
                        row.3,
                        row.5,
                        row.6,
                        row.4.len(),
                        row.4.clone(),
                        row.7.len(),
                        row.7.clone(),
                        row.8.clone(),
                        row.9,
                        row.10,
                        row.11.clone(),
                        row.12,
                    )
                })
                .collect::<Vec<_>>();
            for (idx, result) in store
                .insert_documents_batch(&batch)?
                .into_iter()
                .enumerate()
            {
                results[idx] = Some(Self::candidate_insert_response(result));
            }
        } else {
            let mut grouped = HashMap::<usize, Vec<(usize, ParsedCandidateInsertDocument)>>::new();
            for (idx, row) in parsed_documents.into_iter().enumerate() {
                let shard_idx = self.candidate_store_index_for_sha256(&row.0);
                grouped.entry(shard_idx).or_default().push((idx, row));
            }
            for (shard_idx, rows) in grouped {
                let mut store = lock_candidate_store_with_timeout(
                    &work.stores[shard_idx],
                    shard_idx,
                    "insert batch",
                )?;
                let batch = rows
                    .iter()
                    .map(|(_, row)| {
                        (
                            row.0,
                            row.1,
                            row.2,
                            row.3,
                            row.5,
                            row.6,
                            row.4.len(),
                            row.4.clone(),
                            row.7.len(),
                            row.7.clone(),
                            row.8.clone(),
                            row.9,
                            row.10,
                            row.11.clone(),
                            row.12,
                        )
                    })
                    .collect::<Vec<_>>();
                for ((original_idx, _), result) in rows
                    .into_iter()
                    .zip(store.insert_documents_batch(&batch)?.into_iter())
                {
                    results[original_idx] = Some(Self::candidate_insert_response(result));
                }
            }
        }
        let results = results.into_iter().flatten().collect::<Vec<_>>();
        if self.mutation_affects_published_queries()? {
            self.invalidate_search_caches();
        }
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
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
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
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
        let chunk_size = request
            .chunk_size
            .unwrap_or(DEFAULT_CANDIDATE_QUERY_CHUNK_SIZE)
            .max(1);
        let cache_key = Self::query_cache_key(&plan)?;
        let cached = {
            let mut cache = self
                .query_cache
                .lock()
                .map_err(|_| TgsError::from("Query cache lock poisoned."))?;
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
                .map_err(|_| TgsError::from("Query cache lock poisoned."))?;
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
            external_ids,
        })
    }

    fn handle_candidate_df(&self, grams: &[u64]) -> Result<CandidateDfWireResponse> {
        let _op = self
            .operation_gate
            .read()
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
        let key = Self::normalized_df_cache_key(grams);
        let cached = {
            let mut cache = self
                .df_cache
                .lock()
                .map_err(|_| TgsError::from("DF cache lock poisoned."))?;
            cache.get(&key)
        };
        let counts = if let Some(entry) = cached {
            record_counter("rpc.handle_candidate_df_cache_hits_total", 1);
            entry
        } else {
            record_counter("rpc.handle_candidate_df_cache_misses_total", 1);
            let mut merged = HashMap::<u64, usize>::with_capacity(key.len());
            let published = self.published_store_set()?;
            for gram in &key {
                merged.insert(*gram, 0);
            }
            for (shard_idx, store_lock) in published.stores.iter().enumerate() {
                let store = lock_candidate_store_with_timeout(
                    store_lock,
                    shard_idx,
                    "document frequency lookup",
                )?;
                for (gram, count) in store.df_counts_for(&key) {
                    *merged.entry(gram).or_insert(0) += count;
                }
            }
            let entry = Arc::new(merged);
            let mut cache = self
                .df_cache
                .lock()
                .map_err(|_| TgsError::from("DF cache lock poisoned."))?;
            cache.insert(key.clone(), entry.clone());
            entry
        };
        let mut out = BTreeMap::new();
        for gram in grams {
            out.insert(gram.to_string(), counts.get(gram).copied().unwrap_or(0));
        }
        Ok(CandidateDfWireResponse { df: out })
    }

    fn handle_publish(&self) -> Result<CandidatePublishResponse> {
        self.mutations_paused.store(true, Ordering::SeqCst);
        while self.active_mutations.load(Ordering::Acquire) > 0 {
            thread::sleep(Duration::from_millis(10));
        }
        self.publish_in_progress.store(true, Ordering::SeqCst);
        let _op = self
            .operation_gate
            .write()
            .map_err(|_| TgsError::from("Server operation gate lock poisoned."))?;
        let result = (|| -> Result<CandidatePublishResponse> {
            let mut store_mode = self
                .store_mode
                .lock()
                .map_err(|_| TgsError::from("Server store mode lock poisoned."))?;
            let workspace_root = match &*store_mode {
                StoreMode::Direct { .. } => {
                    return Err(TgsError::from(
                        "publish is only available when the server is started with --workspace-mode",
                    ));
                }
                StoreMode::Workspace { root, .. } => root.clone(),
            };

            let current_root = workspace_current_root(&workspace_root);
            let work_root = workspace_work_root(&workspace_root);
            let retired_parent = workspace_retired_root(&workspace_root);
            if current_root.exists() {
                fs::create_dir_all(&retired_parent)?;
                let retired_root = retired_parent.join(format!("published_{}", current_unix_ms()));
                fs::rename(&current_root, &retired_root)?;
            }
            fs::rename(&work_root, &current_root)?;

            let (published_stores, removed_current) =
                ensure_candidate_stores_at_root(&self.config, &current_root)?;
            let (work_stores, removed_work) =
                ensure_candidate_stores_at_root(&self.config, &work_root)?;
            *store_mode = StoreMode::Workspace {
                root: workspace_root.clone(),
                published: Arc::new(StoreSet::new(current_root.clone(), published_stores)),
                work: Arc::new(StoreSet::new(work_root.clone(), work_stores)),
            };
            self.invalidate_search_caches();
            Ok(CandidatePublishResponse {
                message: format!(
                    "published work root to {} (startup cleanup removed {})",
                    current_root.display(),
                    removed_current.saturating_add(removed_work)
                ),
            })
        })();
        self.publish_in_progress.store(false, Ordering::SeqCst);
        self.mutations_paused.store(false, Ordering::SeqCst);
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
            Err(err) => return Err(TgsError::from(err.to_string())),
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
            Err(err) => return Err(TgsError::from(err.to_string())),
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
    let (version, action, payload) = match read_frame(&mut stream) {
        Ok(frame) => frame,
        Err(err) => {
            let _ = write_error_frame(&mut stream, &err.to_string());
            return Ok(());
        }
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
    Ok(())
}

fn write_frame<W: Write>(
    writer: &mut W,
    version: u8,
    status_or_action: u8,
    payload: &[u8],
) -> Result<()> {
    let len = u32::try_from(payload.len()).map_err(|_| TgsError::from("Payload is too large."))?;
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
    let payload = json!({ "type": "TgsError", "message": message });
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

fn read_exact<R: Read>(reader: &mut R, buf: &mut [u8]) -> Result<()> {
    let mut offset = 0usize;
    while offset < buf.len() {
        let n = reader.read(&mut buf[offset..])?;
        if n == 0 {
            return Err(TgsError::from("Connection closed while reading frame."));
        }
        offset += n;
    }
    Ok(())
}

fn json_bytes<T: Serialize>(value: &T) -> Result<Vec<u8>> {
    serde_json::to_vec(value).map_err(TgsError::from)
}

fn json_from_bytes<T: DeserializeOwned>(payload: &[u8]) -> Result<T> {
    if payload.is_empty() {
        return serde_json::from_slice(b"{}").map_err(TgsError::from);
    }
    serde_json::from_slice(payload).map_err(TgsError::from)
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
        return Err(TgsError::from("query plan payload must be an object"));
    }
    if value.get("ast").is_none() {
        return serde_json::from_value(value.clone()).map_err(TgsError::from);
    }

    let patterns_raw = value
        .get("patterns")
        .and_then(Value::as_array)
        .ok_or_else(|| TgsError::from("query plan must contain a patterns list"))?;
    let mut patterns = Vec::with_capacity(patterns_raw.len());
    for item in patterns_raw {
        let object = item
            .as_object()
            .ok_or_else(|| TgsError::from("query plan patterns entries must be objects"))?;
        let pattern_id = object
            .get("id")
            .and_then(Value::as_str)
            .ok_or_else(|| TgsError::from("invalid pattern id"))?
            .to_owned();
        let alternatives_raw = object
            .get("alternatives")
            .and_then(Value::as_array)
            .ok_or_else(|| TgsError::from("pattern alternatives must be a list"))?;
        let tier2_alternatives_raw = object
            .get("tier2_alternatives")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_else(|| vec![Value::Array(Vec::new()); alternatives_raw.len()]);
        let alt_count = alternatives_raw.len();
        let mut alternatives = Vec::with_capacity(alt_count);
        let mut tier2_alternatives = Vec::with_capacity(alt_count);
        for alt in alternatives_raw {
            let grams = alt
                .as_array()
                .ok_or_else(|| TgsError::from("pattern alternatives entries must be lists"))?
                .iter()
                .map(|value| {
                    value
                        .as_u64()
                        .ok_or_else(|| TgsError::from("pattern contains out-of-range gram"))
                })
                .collect::<Result<Vec<_>>>()?;
            alternatives.push(grams);
        }
        for alt in tier2_alternatives_raw.into_iter().take(alt_count) {
            let grams = alt
                .as_array()
                .ok_or_else(|| TgsError::from("pattern tier2_alternatives entries must be lists"))?
                .iter()
                .map(|value| {
                    value.as_u64().ok_or_else(|| {
                        TgsError::from("pattern contains out-of-range secondary gram")
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            tier2_alternatives.push(grams);
        }
        while tier2_alternatives.len() < alternatives.len() {
            tier2_alternatives.push(Vec::new());
        }
        let alt_count = tier2_alternatives.len();
        patterns.push(PatternPlan {
            pattern_id,
            alternatives,
            tier2_alternatives,
            fixed_literals: vec![Vec::new(); alt_count],
        });
    }

    let root = query_node_from_wire(
        value
            .get("ast")
            .ok_or_else(|| TgsError::from("query plan missing ast"))?,
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
        .ok_or_else(|| TgsError::from("query ast node must be an object"))?;
    let kind = object
        .get("kind")
        .and_then(Value::as_str)
        .ok_or_else(|| TgsError::from("query ast node missing kind"))?
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
                return Err(TgsError::from("pattern node requires a pattern_id"));
            }
        }
        "and" | "or" => {
            if children.is_empty() {
                return Err(TgsError::from(format!(
                    "{kind} node requires at least one child"
                )));
            }
        }
        "n_of" => {
            if threshold.unwrap_or(0) == 0 {
                return Err(TgsError::from("n_of threshold must be > 0"));
            }
            if children.is_empty() {
                return Err(TgsError::from("n_of node requires children"));
            }
        }
        _ => {
            return Err(TgsError::from(format!(
                "Unsupported ast node kind: {kind:?}"
            )));
        }
    }

    Ok(QueryNode {
        kind,
        pattern_id,
        threshold,
        children,
    })
}

fn ensure_candidate_store(config: CandidateConfig) -> Result<CandidateStore> {
    let meta_path = config.root.join("meta.json");
    if !meta_path.exists() {
        return CandidateStore::init(config, false);
    }
    CandidateStore::open(&config.root)
}

fn workspace_current_root(root: &Path) -> PathBuf {
    root.join("current")
}

fn workspace_work_root(root: &Path) -> PathBuf {
    root.join("work")
}

fn workspace_retired_root(root: &Path) -> PathBuf {
    root.join("retired")
}

fn ensure_candidate_stores_at_root(
    config: &ServerConfig,
    root: &Path,
) -> Result<(Vec<CandidateStore>, usize)> {
    let shard_count = config.candidate_shards.max(1);
    let single_meta = root.join("meta.json");
    let sharded_meta = root.join("shard_000").join("meta.json");
    if let Some(existing) = read_candidate_shard_count(root)? {
        if existing != shard_count {
            return Err(TgsError::from(format!(
                "{} contains a candidate shard manifest for {existing} shard(s); start with matching --candidate-shards.",
                root.display()
            )));
        }
    } else {
        if shard_count > 1 && single_meta.exists() {
            return Err(TgsError::from(format!(
                "{} contains a single-shard store; start with --candidate-shards 1 or re-init.",
                root.display()
            )));
        }
        if shard_count == 1 && sharded_meta.exists() {
            return Err(TgsError::from(format!(
                "{} contains a sharded store; start with matching --candidate-shards.",
                root.display()
            )));
        }
    }

    let mut stores = Vec::with_capacity(shard_count);
    let mut cleanup_removed_roots = 0usize;
    fs::create_dir_all(root)?;
    for shard_idx in 0..shard_count {
        let mut shard_config = config.candidate_config.clone();
        shard_config.root = candidate_shard_root(root, shard_count, shard_idx);
        cleanup_removed_roots = cleanup_removed_roots
            .saturating_add(cleanup_abandoned_compaction_roots(&shard_config.root)?);
        let mut store = ensure_candidate_store(shard_config)?;
        store.apply_runtime_limits(
            config.memory_budget_bytes,
            shard_count,
            config.tier2_superblock_budget_divisor,
        )?;
        stores.push(store);
    }
    write_candidate_shard_count(root, shard_count)?;
    Ok((stores, cleanup_removed_roots))
}

fn ensure_candidate_stores(config: &ServerConfig) -> Result<(StoreMode, usize)> {
    let root = &config.candidate_config.root;
    if !config.workspace_mode {
        let (stores, removed_roots) = ensure_candidate_stores_at_root(config, root)?;
        return Ok((
            StoreMode::Direct {
                stores: Arc::new(StoreSet::new(root.clone(), stores)),
            },
            removed_roots,
        ));
    }

    if root.join("meta.json").exists() || root.join("shard_000").join("meta.json").exists() {
        return Err(TgsError::from(format!(
            "{} contains a direct store; move it under {}/current or start without --workspace-mode.",
            root.display(),
            root.display()
        )));
    }

    let current_root = workspace_current_root(root);
    let work_root = workspace_work_root(root);
    let (published, removed_current) = ensure_candidate_stores_at_root(config, &current_root)?;
    let (work, removed_work) = ensure_candidate_stores_at_root(config, &work_root)?;
    Ok((
        StoreMode::Workspace {
            root: root.clone(),
            published: Arc::new(StoreSet::new(current_root, published)),
            work: Arc::new(StoreSet::new(work_root, work)),
        },
        removed_current.saturating_add(removed_work),
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
        return Err(TgsError::from(
            "sha256 must be exactly 64 hexadecimal characters.",
        ));
    }
    Ok(text)
}

fn default_true() -> bool {
    true
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

    use crate::candidate::{
        DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, encode_grams_delta_u64,
    };
    use base64::Engine;
    use tempfile::tempdir;

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
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        )
    }

    fn sample_workspace_server_state(base: &Path, candidate_shards: usize) -> Arc<ServerState> {
        Arc::new(
            ServerState::new(
                ServerConfig {
                    candidate_config: CandidateConfig {
                        root: base.join(format!("candidate_workspace_{candidate_shards}")),
                        ..CandidateConfig::default()
                    },
                    candidate_shards,
                    search_workers: 1,
                    memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                    tier2_superblock_budget_divisor:
                        crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
                    workspace_mode: true,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("workspace server state"),
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
    fn insert_is_rejected_while_publish_pauses_mutations() {
        let tmp = tempdir().expect("tmp");
        let state = sample_server_state(tmp.path());
        state.mutations_paused.store(true, Ordering::SeqCst);
        let err = state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: "11".repeat(32),
                file_size: 1,
                bloom_filter_b64: String::new(),
                gram_count_estimate: None,
                bloom_hashes: None,
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: None,
                grams: Vec::new(),
                grams_complete: false,
                effective_diversity: None,
                external_id: None,
            })
            .expect_err("insert should be rejected");
        assert!(
            err.to_string().contains("server is publishing"),
            "unexpected error: {err}"
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
    fn workspace_mode_keeps_queries_on_published_root_until_publish() {
        let tmp = tempdir().expect("tmp");
        let state = sample_workspace_server_state(tmp.path(), 1);
        let sample = tmp.path().join("workspace-doc.bin");
        fs::write(&sample, b"xxABCDyy").expect("sample");
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let features = crate::candidate::scan_file_features(
            &sample, 1024, 7, 0, 0, 1024, true, None, None, 2048, 1, 1337,
        )
        .expect("features");
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: hex::encode(features.sha256),
                file_size: features.file_size,
                bloom_filter_b64: base64::engine::general_purpose::STANDARD
                    .encode(features.bloom_filter),
                gram_count_estimate: None,
                bloom_hashes: Some(7),
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: None,
                grams: features.unique_grams,
                grams_complete: !features.unique_grams_truncated,
                effective_diversity: None,
                external_id: Some("work-doc".to_owned()),
            })
            .expect("insert doc");

        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
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
        let client = TgsdbClient::new(config.clone());
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
        let client = TgsdbClient::new(config.clone());
        for _ in 0..100 {
            if client.ping().is_ok() {
                return config;
            }
            thread::sleep(Duration::from_millis(20));
        }
        panic!("test tcp rpc server did not become ready");
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
        let client = TgsdbClient::new(config);
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

    #[test]
    fn candidate_stats_json_contains_python_compat_fields() {
        let tmp = tempdir().expect("tmp");
        let config = CandidateConfig {
            root: tmp.path().join("candidate_db"),
            ..CandidateConfig::default()
        };
        let store = CandidateStore::init(config.clone(), true).expect("init");
        let stats = candidate_stats_json(&config.root, &store);
        assert!(stats.contains_key("filter_bucket_counts"));
        assert!(stats.contains_key("disk_usage_bytes"));
        assert_eq!(stats.get("gram_sizes").and_then(Value::as_str), Some("3,4"));
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
        let bloom_filter = {
            let mut bloom = crate::candidate::BloomFilter::new(32, 2).expect("bloom");
            bloom.add(gram).expect("add gram");
            bloom.into_bytes()
        };

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
                    &[gram],
                    true,
                    None,
                    Some(format!("doc-{byte:02x}")),
                    true,
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
    fn candidate_df_ignores_unparsable_keys_and_empty_insert_batch_short_circuits() {
        let config = one_shot_tcp_config(|mut stream| {
            let (_, action, _) = read_frame(&mut stream).expect("read request");
            assert_eq!(action, ACTION_CANDIDATE_DF);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &json_bytes(&CandidateDfWireResponse {
                    df: BTreeMap::from([
                        ("123".to_owned(), 7usize),
                        ("not-a-u64".to_owned(), 9usize),
                    ]),
                })
                .expect("df bytes"),
            )
            .expect("write response");
        });
        let client = TgsdbClient::new(config);
        let df = client.candidate_df(&[1, 2, 3]).expect("candidate df");
        assert_eq!(df, HashMap::from([(123u64, 7usize)]));

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
                                grams_received: 0,
                                grams_indexed: 0,
                                grams_complete: true,
                            }],
                        })
                        .expect("batch bytes"),
                    )
                    .expect("write success");
                }
            }
        });
        let client = TgsdbClient::new(ClientConfig::new(
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
                gram_count_estimate: None,
                bloom_hashes: None,
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: None,
                grams: Vec::new(),
                grams_complete: true,
                effective_diversity: None,
                external_id: None,
            },
            CandidateDocumentWire {
                sha256: "22".repeat(32),
                file_size: 1,
                bloom_filter_b64: String::new(),
                gram_count_estimate: None,
                bloom_hashes: None,
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: None,
                grams: Vec::new(),
                grams_complete: true,
                effective_diversity: None,
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
        let client = TgsdbClient::new(config);
        let err = client
            .candidate_insert_batch(&docs[..1])
            .expect_err("single oversized doc");
        assert!(
            err.to_string()
                .contains("Single document insert request is too large")
        );
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

        let bloom_hashes = 7;
        let features_a = crate::candidate::scan_file_features(
            &cand_a,
            1024,
            bloom_hashes,
            0,
            0,
            1024,
            true,
            None,
            None,
            2048,
            1,
            1337,
        )
        .expect("features a");
        let features_b = crate::candidate::scan_file_features(
            &cand_b,
            1024,
            bloom_hashes,
            0,
            0,
            1024,
            true,
            None,
            None,
            2048,
            1,
            1337,
        )
        .expect("features b");
        let doc_a = CandidateDocumentWire {
            sha256: hex::encode(features_a.sha256),
            file_size: features_a.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_a.bloom_filter),
            gram_count_estimate: None,
            bloom_hashes: None,
            tier2_bloom_filter_b64: None,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: None,
            grams_delta_b64: None,
            grams: features_a.unique_grams,
            grams_complete: !features_a.unique_grams_truncated,
            effective_diversity: None,
            external_id: Some(cand_a.display().to_string()),
        };
        let doc_b = CandidateDocumentWire {
            sha256: hex::encode(features_b.sha256),
            file_size: features_b.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_b.bloom_filter),
            gram_count_estimate: None,
            bloom_hashes: None,
            tier2_bloom_filter_b64: None,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: None,
            grams_delta_b64: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(encode_grams_delta_u64(features_b.unique_grams.clone())),
            ),
            grams: Vec::new(),
            grams_complete: !features_b.unique_grams_truncated,
            effective_diversity: None,
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
            crate::candidate::compile_query_plan_from_file(&rule, None, 8, false, true, 100_000)
                .expect("plan");
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

        let mut grams = Vec::new();
        for pattern in &plan.patterns {
            for alt in &pattern.alternatives {
                grams.extend(alt.iter().copied());
            }
        }
        let df: CandidateDfWireResponse = json_from_bytes(
            &state
                .dispatch(
                    ACTION_CANDIDATE_DF,
                    &json_bytes(&CandidateDfRequest {
                        grams: grams.clone(),
                    })
                    .expect("df payload"),
                )
                .expect("df"),
        )
        .expect("decode df");
        assert!(!df.df.is_empty());

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
        let client = TgsdbClient::new(ClientConfig::new(
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

        let bad_version_client = TgsdbClient::new(one_shot_tcp_config(|mut stream| {
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

        let error_client = TgsdbClient::new(one_shot_tcp_config(|mut stream| {
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

        let object_client = TgsdbClient::new(one_shot_tcp_config(|mut stream| {
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

        let df_client = TgsdbClient::new(one_shot_tcp_config(|mut stream| {
            let _ = read_frame(&mut stream);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_OK,
                &serde_json::to_vec(&serde_json::json!({
                    "df": {"42": 7, "invalid": 11}
                }))
                .expect("df payload"),
            )
            .expect("write df payload");
        }));
        let df = df_client.candidate_df(&[42]).expect("candidate df");
        assert_eq!(df.get(&42).copied(), Some(7));
        assert_eq!(df.len(), 1);

        let default_error_client = TgsdbClient::new(one_shot_tcp_config(|mut stream| {
            let _ = read_frame(&mut stream);
            write_frame(
                &mut stream,
                PROTOCOL_VERSION,
                STATUS_ERROR,
                &serde_json::to_vec(&serde_json::json!({ "type": "TgsError" }))
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

    #[cfg(unix)]
    #[test]
    fn unix_client_server_roundtrip_covers_public_client_methods() {
        let tmp = tempdir().expect("tmp");
        let config = start_unix_server(tmp.path(), 2);
        let client = TgsdbClient::new(config.clone());
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
        let bloom_hashes = 7;
        let features_a = crate::candidate::scan_file_features(
            &cand_a,
            1024,
            bloom_hashes,
            0,
            0,
            1024,
            true,
            None,
            None,
            256,
            1,
            1337,
        )
        .expect("features a");
        let features_b = crate::candidate::scan_file_features(
            &cand_b,
            1024,
            bloom_hashes,
            0,
            0,
            1024,
            true,
            None,
            None,
            256,
            1,
            1337,
        )
        .expect("features b");
        let doc_a = CandidateDocumentWire {
            sha256: hex::encode(features_a.sha256),
            file_size: features_a.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_a.bloom_filter),
            gram_count_estimate: None,
            bloom_hashes: None,
            tier2_bloom_filter_b64: None,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: None,
            grams_delta_b64: None,
            grams: features_a.unique_grams.clone(),
            grams_complete: !features_a.unique_grams_truncated,
            effective_diversity: None,
            external_id: Some(cand_a.display().to_string()),
        };
        let doc_b = CandidateDocumentWire {
            sha256: hex::encode(features_b.sha256),
            file_size: features_b.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_b.bloom_filter),
            gram_count_estimate: None,
            bloom_hashes: None,
            tier2_bloom_filter_b64: None,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: None,
            grams_delta_b64: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(encode_grams_delta_u64(features_b.unique_grams.clone())),
            ),
            grams: Vec::new(),
            grams_complete: !features_b.unique_grams_truncated,
            effective_diversity: None,
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
            crate::candidate::compile_query_plan_from_file(&rule, None, 8, false, true, 100_000)
                .expect("plan");
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
        let df = client
            .candidate_df(&plan.patterns[0].alternatives[0])
            .expect("df");
        assert!(!df.is_empty());
        let deleted = client
            .candidate_delete_sha256(&inserted.sha256)
            .expect("delete");
        assert_eq!(deleted.status, "deleted");
    }

    #[test]
    fn tcp_server_roundtrip_covers_tcp_serve_branch() {
        let tmp = tempdir().expect("tmp");
        let client = TgsdbClient::new(start_tcp_server(tmp.path(), 1));
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
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(true)),
        )
        .expect("server state");
        let insert_payload = serde_json::to_vec(&CandidateDocumentWire {
            sha256: "aa".repeat(32),
            file_size: 4,
            bloom_filter_b64: String::new(),
            gram_count_estimate: None,
            bloom_hashes: None,
            tier2_bloom_filter_b64: None,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: None,
            grams_delta_b64: None,
            grams: Vec::new(),
            grams_complete: false,
            effective_diversity: None,
            external_id: None,
        })
        .expect("insert payload");
        let batch_payload = serde_json::to_vec(&CandidateInsertBatchRequest {
            documents: vec![CandidateDocumentWire {
                sha256: "bb".repeat(32),
                file_size: 4,
                bloom_filter_b64: String::new(),
                gram_count_estimate: None,
                bloom_hashes: None,
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: None,
                grams: Vec::new(),
                grams_complete: false,
                effective_diversity: None,
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
        let bloom_filter_b64 = {
            let mut bloom = crate::candidate::BloomFilter::new(1024, 7).expect("bloom");
            bloom.add(gram).expect("add gram");
            base64::engine::general_purpose::STANDARD.encode(bloom.into_bytes())
        };
        let plan = CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![gram]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
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
                gram_count_estimate: None,
                bloom_hashes: None,
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: None,
                grams: vec![gram],
                grams_complete: true,
                effective_diversity: None,
                external_id: Some("shard-a".to_owned()),
            },
            CandidateDocumentWire {
                sha256: "01".repeat(32),
                file_size: 16,
                bloom_filter_b64: bloom_filter_b64.clone(),
                gram_count_estimate: None,
                bloom_hashes: None,
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: Some(
                    base64::engine::general_purpose::STANDARD
                        .encode(encode_grams_delta_u64(vec![gram])),
                ),
                grams: Vec::new(),
                grams_complete: true,
                effective_diversity: None,
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
        let df = state.handle_candidate_df(&[gram]).expect("df");
        assert_eq!(df.df.get(&gram.to_string()).copied(), Some(2));
        let empty_df = state.handle_candidate_df(&[]).expect("empty df");
        assert!(empty_df.df.is_empty());
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
        let df_after_delete = state.handle_candidate_df(&[gram]).expect("df after delete");
        assert_eq!(df_after_delete.df.get(&gram.to_string()).copied(), Some(1));

        assert!(
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: "ab".repeat(32),
                    file_size: 1,
                    bloom_filter_b64: "**".to_owned(),
                    gram_count_estimate: None,
                    bloom_hashes: None,
                    tier2_bloom_filter_b64: None,
                    tier2_gram_count_estimate: None,
                    tier2_bloom_hashes: None,
                    grams_delta_b64: None,
                    grams: vec![gram],
                    grams_complete: true,
                    effective_diversity: None,
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
                    gram_count_estimate: None,
                    bloom_hashes: None,
                    tier2_bloom_filter_b64: None,
                    tier2_gram_count_estimate: None,
                    tier2_bloom_hashes: None,
                    grams_delta_b64: Some("**".to_owned()),
                    grams: Vec::new(),
                    grams_complete: true,
                    effective_diversity: None,
                    external_id: None,
                })
                .expect_err("invalid grams_delta base64")
                .to_string()
                .contains("grams_delta_b64 must be valid base64")
        );
        assert!(
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: "not hex".to_owned(),
                    file_size: 1,
                    bloom_filter_b64,
                    gram_count_estimate: None,
                    bloom_hashes: None,
                    tier2_bloom_filter_b64: None,
                    tier2_gram_count_estimate: None,
                    tier2_bloom_hashes: None,
                    grams_delta_b64: None,
                    grams: vec![gram],
                    grams_complete: true,
                    effective_diversity: None,
                    external_id: None,
                })
                .expect_err("invalid sha")
                .to_string()
                .contains("64 hexadecimal characters")
        );
    }

    #[test]
    fn query_plan_wire_and_store_setup_cover_fallback_and_manifest_errors() {
        let legacy_wire = serde_json::to_value(CompiledQueryPlan {
            patterns: vec![PatternPlan {
                pattern_id: "$a".to_owned(),
                alternatives: vec![vec![1, 2, 3, 4]],
                tier2_alternatives: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
            }],
            root: QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("$a".to_owned()),
                threshold: None,
                children: Vec::new(),
            },
            force_tier1_only: true,
            allow_tier2_fallback: false,
            max_candidates: 7,
            tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
            tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
        })
        .expect("legacy wire");
        let decoded = compiled_query_plan_from_wire(&legacy_wire).expect("decode legacy plan");
        assert_eq!(decoded.max_candidates, 7);
        assert!(decoded.force_tier1_only);
        assert!(!decoded.allow_tier2_fallback);

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
                workspace_mode: false,
            })
            .expect_err("sharded mismatch")
            .to_string()
            .contains("sharded store")
        );

        let manifest_root = tmp.path().join("manifest");
        let (stores, _) = ensure_candidate_stores(&ServerConfig {
            candidate_config: CandidateConfig {
                root: manifest_root.clone(),
                ..CandidateConfig::default()
            },
            candidate_shards: 2,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            tier2_superblock_budget_divisor: crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
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
        let bloom_filter_b64 = {
            let mut bloom = crate::candidate::BloomFilter::new(1024, 7).expect("bloom");
            bloom.add(gram).expect("add gram");
            base64::engine::general_purpose::STANDARD.encode(bloom.into_bytes())
        };
        let inserted = state
            .handle_candidate_insert(&CandidateDocumentWire {
                sha256: "AA".repeat(32),
                file_size: 16,
                bloom_filter_b64,
                gram_count_estimate: None,
                bloom_hashes: None,
                tier2_bloom_filter_b64: None,
                tier2_gram_count_estimate: None,
                tier2_bloom_hashes: None,
                grams_delta_b64: None,
                grams: vec![gram],
                grams_complete: true,
                effective_diversity: None,
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

        let delete_client = TgsdbClient::new(one_shot_tcp_config(|mut stream| {
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
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state");
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 = {
            let mut bloom = crate::candidate::BloomFilter::new(16, 2).expect("bloom");
            bloom.add(gram).expect("add gram");
            base64::engine::general_purpose::STANDARD.encode(bloom.into_bytes())
        };
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
                    gram_count_estimate: None,
                    bloom_hashes: Some(2),
                    tier2_bloom_filter_b64: None,
                    tier2_gram_count_estimate: None,
                    tier2_bloom_hashes: None,
                    grams_delta_b64: None,
                    grams: vec![gram],
                    grams_complete: true,
                    effective_diversity: None,
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

        let (stores, removed_roots) = ensure_candidate_stores(&ServerConfig {
            candidate_config: CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            candidate_shards: 2,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            tier2_superblock_budget_divisor: crate::app::DEFAULT_TIER2_SUPERBLOCK_BUDGET_DIVISOR,
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
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        );
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 = {
            let mut bloom = crate::candidate::BloomFilter::new(32, 2).expect("bloom");
            bloom.add(gram).expect("add gram");
            base64::engine::general_purpose::STANDARD.encode(bloom.into_bytes())
        };

        for byte in [0x11u8, 0x22u8] {
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: hex::encode([byte; 32]),
                    file_size: 32,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    gram_count_estimate: None,
                    bloom_hashes: Some(2),
                    tier2_bloom_filter_b64: None,
                    tier2_gram_count_estimate: None,
                    tier2_bloom_hashes: None,
                    grams_delta_b64: None,
                    grams: vec![gram],
                    grams_complete: true,
                    effective_diversity: None,
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
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        );
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 = {
            let mut bloom = crate::candidate::BloomFilter::new(32, 2).expect("bloom");
            bloom.add(gram).expect("add gram");
            base64::engine::general_purpose::STANDARD.encode(bloom.into_bytes())
        };

        let mut deleted_sha = None;
        for byte in 1u8..=32 {
            let sha = [byte; 32];
            let shard_idx = state.candidate_store_index_for_sha256(&sha);
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: hex::encode(sha),
                    file_size: 32,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    gram_count_estimate: None,
                    bloom_hashes: Some(2),
                    tier2_bloom_filter_b64: None,
                    tier2_gram_count_estimate: None,
                    tier2_bloom_hashes: None,
                    grams_delta_b64: None,
                    grams: vec![gram],
                    grams_complete: true,
                    effective_diversity: None,
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
                    workspace_mode: false,
                },
                Arc::new(AtomicBool::new(false)),
            )
            .expect("server state"),
        );
        let gram = u64::from(u32::from_le_bytes(*b"ABCD"));
        let bloom_filter_b64 = {
            let mut bloom = crate::candidate::BloomFilter::new(32, 2).expect("bloom");
            bloom.add(gram).expect("add gram");
            base64::engine::general_purpose::STANDARD.encode(bloom.into_bytes())
        };

        for byte in [0x11u8, 0x22u8] {
            state
                .handle_candidate_insert(&CandidateDocumentWire {
                    sha256: hex::encode([byte; 32]),
                    file_size: 32,
                    bloom_filter_b64: bloom_filter_b64.clone(),
                    gram_count_estimate: None,
                    bloom_hashes: Some(2),
                    tier2_bloom_filter_b64: None,
                    tier2_gram_count_estimate: None,
                    tier2_bloom_hashes: None,
                    grams_delta_b64: None,
                    grams: vec![gram],
                    grams_complete: true,
                    effective_diversity: None,
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
