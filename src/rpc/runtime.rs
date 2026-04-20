/// Builds the JSON stats object used by local status paths from one or more
/// candidate-store stats rows plus a precomputed disk-usage figure.
///
/// Inputs:
/// - `stats_rows`: Per-shard stats snapshots that should be aggregated.
/// - `disk_usage_bytes`: Total on-disk bytes already computed for the root.
///
/// Returns:
/// - A flattened JSON map that mirrors the CLI `info` schema.
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
    let docs_vector_bytes = stats_rows
        .iter()
        .map(|item| item.docs_vector_bytes)
        .sum::<u64>();
    let doc_rows_bytes = stats_rows
        .iter()
        .map(|item| item.doc_rows_bytes)
        .sum::<u64>();
    let tier2_doc_rows_bytes = stats_rows
        .iter()
        .map(|item| item.tier2_doc_rows_bytes)
        .sum::<u64>();
    let identity_index_bytes = stats_rows
        .iter()
        .map(|item| item.identity_index_bytes)
        .sum::<u64>();
    let special_doc_positions_bytes = stats_rows
        .iter()
        .map(|item| item.special_doc_positions_bytes)
        .sum::<u64>();
    let query_artifact_cache_entries = stats_rows
        .iter()
        .map(|item| item.query_artifact_cache_entries)
        .sum::<usize>();
    let query_artifact_cache_bytes = stats_rows
        .iter()
        .map(|item| item.query_artifact_cache_bytes)
        .sum::<u64>();
    let compaction_idle_cooldown_s = stats_rows
        .iter()
        .map(|item| item.compaction_idle_cooldown_s)
        .fold(0.0_f64, f64::max);
    let compaction_cooldown_remaining_s = if stats_rows
        .iter()
        .any(|item| item.deleted_doc_count > 0 && item.compaction_cooldown_remaining_s <= 0.0)
    {
        0.0
    } else {
        stats_rows
            .iter()
            .filter(|item| item.deleted_doc_count > 0)
            .map(|item| item.compaction_cooldown_remaining_s)
            .reduce(f64::min)
            .unwrap_or(0.0)
    };
    let compaction_waiting_for_cooldown = compaction_cooldown_remaining_s > 0.0;
    let mut out = Map::<String, Value>::new();
    out.insert("active_doc_count".to_owned(), json!(active_doc_count));
    out.insert(
        "candidate_shards".to_owned(),
        json!(stats_rows.len().max(1)),
    );
    out.insert("id_source".to_owned(), json!(stats.id_source));
    out.insert("store_path".to_owned(), json!(stats.store_path));
    out.insert("deleted_doc_count".to_owned(), json!(deleted_doc_count));
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
    out.insert("docs_vector_bytes".to_owned(), json!(docs_vector_bytes));
    out.insert("doc_rows_bytes".to_owned(), json!(doc_rows_bytes));
    out.insert(
        "tier2_doc_rows_bytes".to_owned(),
        json!(tier2_doc_rows_bytes),
    );
    out.insert(
        "identity_index_bytes".to_owned(),
        json!(identity_index_bytes),
    );
    out.insert(
        "special_doc_positions_bytes".to_owned(),
        json!(special_doc_positions_bytes),
    );
    out.insert(
        "query_artifact_cache_entries".to_owned(),
        json!(query_artifact_cache_entries),
    );
    out.insert(
        "query_artifact_cache_bytes".to_owned(),
        json!(query_artifact_cache_bytes),
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
        "compaction_idle_cooldown_s".to_owned(),
        json!(compaction_idle_cooldown_s),
    );
    out.insert(
        "source_dedup_min_new_docs".to_owned(),
        json!(stats.source_dedup_min_new_docs),
    );
    out.insert(
        "compaction_cooldown_remaining_s".to_owned(),
        json!(compaction_cooldown_remaining_s),
    );
    out.insert(
        "compaction_waiting_for_cooldown".to_owned(),
        json!(compaction_waiting_for_cooldown),
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
    out.insert("version".to_owned(), json!(1));
    out
}

/// Builds the JSON stats object for a root by first measuring disk usage and
/// then delegating to the generic aggregation helper.
///
/// Inputs:
/// - `root`: Store root whose disk usage should be reported.
/// - `stats_rows`: Per-shard stats snapshots for that root.
///
/// Returns:
/// - The aggregated JSON stats map used by local `info`.
fn candidate_stats_json_from_parts(
    root: &Path,
    stats_rows: &[crate::candidate::CandidateStats],
) -> Map<String, Value> {
    let mut out =
        candidate_stats_json_from_parts_with_disk_usage(stats_rows, disk_usage_under(root));
    if let Some(summary) = forest_source_dedup_summary_json_map(root) {
        out.insert("forest_source_dedup".to_owned(), Value::Object(summary));
    }
    out
}

/// Constructs an empty stats payload for tests that need the CLI JSON shape
/// before any documents exist on disk.
///
/// Inputs:
/// - `config`: Server configuration that supplies store defaults.
/// - `root`: Root whose disk usage should be reflected if it already exists.
/// - `shard_count`: Effective shard count to report in the empty payload.
///
/// Returns:
/// - A zero-document stats map with the configured policy fields filled in.
#[cfg(test)]
fn empty_candidate_stats_json_for_config(
    config: &ServerConfig,
    root: &Path,
    shard_count: usize,
) -> Map<String, Value> {
    let stats = crate::candidate::CandidateStats {
        doc_count: 0,
        deleted_doc_count: 0,
        id_source: config.candidate_config.id_source.clone(),
        store_path: config.candidate_config.store_path,
        tier1_filter_target_fp: config.candidate_config.tier1_filter_target_fp,
        tier2_filter_target_fp: config.candidate_config.tier2_filter_target_fp,
        tier2_gram_size: config.candidate_config.tier2_gram_size,
        tier1_gram_size: config.candidate_config.tier1_gram_size,
        compaction_idle_cooldown_s: config.candidate_config.compaction_idle_cooldown_s,
        source_dedup_min_new_docs: config.candidate_config.source_dedup_min_new_docs,
        compaction_cooldown_remaining_s: 0.0,
        compaction_waiting_for_cooldown: false,
        compaction_generation: 1,
        retired_generation_count: 0,
        query_count: 0,
        tier2_scanned_docs_total: 0,
        tier2_docs_matched_total: 0,
        tier2_match_ratio: 0.0,
        docs_vector_bytes: 0,
        doc_rows_bytes: 0,
        tier2_doc_rows_bytes: 0,
        identity_index_bytes: 0,
        special_doc_positions_bytes: 0,
        query_artifact_cache_entries: 0,
        query_artifact_cache_bytes: 0,
        mapped_bloom_bytes: 0,
        mapped_tier2_bloom_bytes: 0,
        mapped_metadata_bytes: 0,
        mapped_external_id_bytes: 0,
    };
    let mut out = candidate_stats_json_from_parts_with_disk_usage(
        &[stats],
        if root.exists() {
            disk_usage_under(root)
        } else {
            0
        },
    );
    out.insert("candidate_shards".to_owned(), json!(shard_count.max(1)));
    out
}

#[derive(Clone, Copy, Debug, Default)]
#[cfg(test)]
struct CandidateStatsBuildProfile {
    collect_store_stats_ms: u64,
    disk_usage_ms: u64,
    build_json_ms: u64,
}

/// Builds the local JSON stats object for one already-open candidate store.
///
/// Inputs:
/// - `root`: Root path used for disk-usage reporting.
/// - `store`: Open candidate store whose in-memory stats should be serialized.
///
/// Returns:
/// - The CLI-facing stats JSON map for that store.
pub fn candidate_stats_json(root: &Path, store: &CandidateStore) -> Map<String, Value> {
    candidate_stats_json_from_parts(root, &[store.stats()])
}

/// Builds the local JSON stats object for a group of already-open candidate
/// stores.
///
/// Inputs:
/// - `root`: Root path used for disk-usage reporting.
/// - `stores`: Open stores that should be aggregated as one logical root.
///
/// Returns:
/// - The CLI-facing stats JSON map for the aggregated stores.
pub fn candidate_stats_json_for_stores(
    root: &Path,
    stores: &[CandidateStore],
) -> Map<String, Value> {
    let stats_rows = stores.iter().map(CandidateStore::stats).collect::<Vec<_>>();
    candidate_stats_json_from_parts(root, &stats_rows)
}

/// Loads the persisted forest-wide source-id deduplication summary and formats
/// it for JSON status output. Returns `None` when the root does not carry valid
/// forest policy metadata.
fn forest_source_dedup_summary_json_map(root: &Path) -> Option<Map<String, Value>> {
    let summary = crate::candidate::store::forest_source_dedup_summary_state(root).ok()?;
    let mut map = Map::new();
    map.insert("min_new_docs".to_owned(), json!(summary.min_new_docs));
    map.insert(
        "last_completed_unix_ms".to_owned(),
        json!(summary.last_completed_unix_ms.unwrap_or(0)),
    );
    map.insert(
        "last_duplicate_groups".to_owned(),
        json!(summary.last_duplicate_groups),
    );
    map.insert(
        "last_deleted_docs".to_owned(),
        json!(summary.last_deleted_docs),
    );
    map.insert(
        "last_affected_trees".to_owned(),
        json!(summary.last_affected_trees),
    );
    map.insert(
        "last_total_inserted_docs".to_owned(),
        json!(summary.last_total_inserted_docs),
    );
    Some(map)
}

/// Starts the background worker that drains compaction work whenever the server
/// signals a maintenance epoch change.
///
/// Inputs:
/// - `state`: Shared server state used to poll compaction readiness and execute cycles.
///
/// Returns:
/// - The spawned maintenance thread handle.
fn start_compaction_worker(state: Arc<ServerState>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut maintenance_epoch = state.current_maintenance_epoch();
        loop {
            if state.is_shutting_down() {
                break;
            }
            let timeout = state.next_compaction_wait_timeout();
            state.wait_for_maintenance_event(&mut maintenance_epoch, Some(timeout));
            if state.is_shutting_down() {
                break;
            }
            loop {
                match state.run_compaction_cycle_once() {
                    Ok(CompactionCycleOutcome::Progress) => continue,
                    Ok(CompactionCycleOutcome::Idle) => {
                        let source_dedup_min_new_docs = state
                            .config
                            .candidate_config
                            .source_dedup_min_new_docs
                            .max(1);
                        match state.run_tree_source_ref_cycle_once(source_dedup_min_new_docs) {
                            Ok(CompactionCycleOutcome::Progress) => continue,
                            Ok(
                                CompactionCycleOutcome::Idle | CompactionCycleOutcome::RetryLater,
                            ) => {
                                match state
                                    .run_forest_source_dedup_cycle_once(source_dedup_min_new_docs)
                                {
                                    Ok(CompactionCycleOutcome::Progress) => continue,
                                    Ok(
                                        CompactionCycleOutcome::Idle
                                        | CompactionCycleOutcome::RetryLater,
                                    ) => break,
                                    Err(_) => break,
                                }
                            }
                            Err(_) => break,
                        }
                    }
                    Ok(CompactionCycleOutcome::RetryLater) => break,
                    Err(_) => break,
                }
            }
        }
    })
}

/// Starts the background worker that evaluates auto-publish readiness and
/// retired-root cleanup.
///
/// Inputs:
/// - `state`: Shared server state used to compute readiness and run publish cycles.
///
/// Returns:
/// - The spawned maintenance thread handle.
fn start_auto_publish_worker(state: Arc<ServerState>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut maintenance_epoch = state.current_maintenance_epoch();
        loop {
            if state.is_shutting_down() {
                break;
            }
            let readiness = state.publish_readiness(current_unix_ms());
            let timeout = if readiness.eligible {
                Duration::from_millis(1)
            } else if state.config.workspace_mode
                && state.work_dirty.load(Ordering::Acquire)
                && readiness.idle_remaining_ms > 0
            {
                Duration::from_millis(readiness.idle_remaining_ms.min(30_000))
            } else {
                Duration::from_secs(30)
            };
            state.wait_for_maintenance_event(&mut maintenance_epoch, Some(timeout));
            if state.is_shutting_down() {
                break;
            }
            let _ = state.run_auto_publish_cycle();
            let _ = state.run_retired_root_prune_cycle();
        }
    })
}

/// Starts the background worker that seals published tier2 snapshot shards once
/// they are ready.
///
/// Inputs:
/// - `state`: Shared server state used to poll pending seal work.
///
/// Returns:
/// - The spawned maintenance thread handle.
fn start_published_tier2_snapshot_seal_worker(state: Arc<ServerState>) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut maintenance_epoch = state.current_maintenance_epoch();
        loop {
            if state.is_shutting_down()
                && state
                    .pending_published_tier2_snapshot_shard_count()
                    .unwrap_or(0)
                    == 0
            {
                break;
            }
            state.wait_for_maintenance_event(&mut maintenance_epoch, Some(Duration::from_secs(30)));
            loop {
                match state.run_published_tier2_snapshot_seal_cycle() {
                    Ok(true) => continue,
                    Ok(false) => break,
                    Err(_) => break,
                }
            }
        }
    })
}

/// Starts the optional worker that prints a full status snapshot when the
/// external status-dump signal is toggled.
///
/// Inputs:
/// - `state`: Shared server state used to collect the current snapshot.
/// - `status_dump`: Optional trigger flag set by the signal handler.
///
/// Returns:
/// - `Some(handle)` when status dumps are enabled, otherwise `None`.
fn start_status_dump_worker(
    state: Arc<ServerState>,
    status_dump: Option<Arc<AtomicBool>>,
) -> Option<thread::JoinHandle<()>> {
    let status_dump = status_dump?;
    Some(thread::spawn(move || {
        let mut maintenance_epoch = state.current_maintenance_epoch();
        while !state.is_shutting_down() {
            if status_dump.swap(false, Ordering::SeqCst) {
                match state.grpc_stats_response() {
                    Ok(stats) => match serde_json::to_string_pretty(&stats) {
                        Ok(text) => eprintln!("{text}"),
                        Err(err) => eprintln!("failed to serialize status snapshot: {err}"),
                    },
                    Err(err) => eprintln!("failed to collect status snapshot: {err}"),
                }
            }
            state.wait_for_maintenance_event(&mut maintenance_epoch, Some(Duration::from_secs(1)));
        }
    }))
}

/// Creates the shared server state and launches the background maintenance
/// workers that keep publish/compaction activity moving.
///
/// Inputs:
/// - `config`: Full server configuration.
/// - `shutdown`: Shared shutdown flag used by all long-lived workers.
/// - `status_dump`: Optional trigger for printing runtime status snapshots.
///
/// Returns:
/// - The initialized shared server state.
/// - The worker handles that must be drained at shutdown.
fn start_server_runtime(
    config: ServerConfig,
    shutdown: Arc<AtomicBool>,
    status_dump: Option<Arc<AtomicBool>>,
) -> Result<(Arc<ServerState>, ServerWorkers)> {
    let state = Arc::new(ServerState::new(config, shutdown)?);
    let workers = ServerWorkers {
        compaction_worker: start_compaction_worker(state.clone()),
        auto_publish_worker: start_auto_publish_worker(state.clone()),
        published_tier2_snapshot_seal_worker: start_published_tier2_snapshot_seal_worker(
            state.clone(),
        ),
        status_worker: start_status_dump_worker(state.clone(), status_dump),
    };
    Ok((state, workers))
}

/// Shuts down the server runtime in a deterministic order.
///
/// How it works:
/// - Signals all maintenance workers to stop.
/// - Joins worker threads.
/// - Waits for active connections to drain.
/// - Flushes any dirty store metadata before exiting.
///
/// Inputs:
/// - `state`: Shared server state to shut down.
/// - `workers`: Worker handles returned by `start_server_runtime`.
///
/// Output:
/// - Performs shutdown side effects and emits progress to stderr.
fn drain_server_runtime(state: Arc<ServerState>, workers: ServerWorkers) {
    if state.is_shutting_down() {
        eprintln!("sspry: shutdown requested, draining");
        if let Ok(stats) = state.grpc_stats_response() {
            if let Ok(text) = serde_json::to_string_pretty(&stats) {
                eprintln!("{text}");
            }
        }
    }
    state.shutdown.store(true, Ordering::Relaxed);
    state.notify_maintenance_workers();
    if let Some(worker) = workers.status_worker {
        let _ = worker.join();
    }
    let _ = workers.compaction_worker.join();
    let _ = workers.auto_publish_worker.join();
    let _ = workers.published_tier2_snapshot_seal_worker.join();
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
}

/// Returns the current wall-clock time in milliseconds since the Unix epoch.
fn current_unix_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

/// Converts a Tokio join failure into a gRPC internal error.
fn grpc_join_error_status(err: tokio::task::JoinError) -> GrpcStatus {
    GrpcStatus::internal(format!("gRPC background task failed: {err}"))
}

/// Converts an internal `SspryError` into a gRPC internal error.
fn grpc_internal_status(err: SspryError) -> GrpcStatus {
    GrpcStatus::internal(err.to_string())
}

/// Normalizes a `tonic::Status` into the project-local gRPC status type.
fn tonic_error_to_status(err: tonic::Status) -> GrpcStatus {
    err
}

/// Encodes an optional string into the protobuf wrapper type used by the gRPC
/// API.
///
/// Inputs:
/// - `value`: Optional string value from internal state.
///
/// Returns:
/// - The protobuf wrapper with both the presence bit and string payload set.
fn grpc_optional_string(value: Option<String>) -> OptionalString {
    OptionalString {
        has_value: value.is_some(),
        value: value.unwrap_or_default(),
    }
}

/// Loads the persisted forest-wide source-id deduplication summary and adapts
/// it into the protobuf payload returned by gRPC status endpoints.
fn grpc_forest_source_dedup_summary_from_root(root: &Path) -> Option<ForestSourceDedupSummary> {
    let summary = crate::candidate::store::forest_source_dedup_summary_state(root).ok()?;
    Some(ForestSourceDedupSummary {
        min_new_docs: summary.min_new_docs,
        last_completed_unix_ms: summary.last_completed_unix_ms.unwrap_or(0),
        last_duplicate_groups: summary.last_duplicate_groups,
        last_deleted_docs: summary.last_deleted_docs,
        last_affected_trees: summary.last_affected_trees as u64,
        last_total_inserted_docs: summary.last_total_inserted_docs,
    })
}

/// Aggregates per-shard candidate stats into the protobuf store summary used by
/// the gRPC status API.
///
/// Inputs:
/// - `stats_rows`: Per-shard stats snapshots.
/// - `disk_usage_bytes`: Total on-disk usage for the logical root.
/// - `deleted_storage_bytes`: Bytes still retained by deleted data.
/// - `candidate_shards`: Effective shard count to report.
///
/// Returns:
/// - The protobuf store summary merged across all shards.
fn grpc_store_summary_from_candidate_stats(
    stats_rows: &[crate::candidate::CandidateStats],
    disk_usage_bytes: u64,
    deleted_storage_bytes: u64,
    candidate_shards: usize,
) -> StoreSummary {
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
    let compaction_idle_cooldown_s = stats_rows
        .iter()
        .map(|item| item.compaction_idle_cooldown_s)
        .fold(0.0_f64, f64::max);
    let compaction_cooldown_remaining_s = if stats_rows
        .iter()
        .any(|item| item.deleted_doc_count > 0 && item.compaction_cooldown_remaining_s <= 0.0)
    {
        0.0
    } else {
        stats_rows
            .iter()
            .filter(|item| item.deleted_doc_count > 0)
            .map(|item| item.compaction_cooldown_remaining_s)
            .reduce(f64::min)
            .unwrap_or(0.0)
    };
    let compaction_waiting_for_cooldown = compaction_cooldown_remaining_s > 0.0;
    StoreSummary {
        active_doc_count: active_doc_count as u64,
        candidate_shards: candidate_shards.max(1) as u64,
        id_source: stats.id_source,
        store_path: stats.store_path,
        source_dedup_min_new_docs: stats.source_dedup_min_new_docs,
        deleted_doc_count: deleted_doc_count as u64,
        disk_usage_bytes,
        doc_count: active_doc_count.saturating_add(deleted_doc_count) as u64,
        compaction_generation,
        tier1_filter_target_fp: stats.tier1_filter_target_fp.unwrap_or(0.0),
        tier2_filter_target_fp: stats.tier2_filter_target_fp.unwrap_or(0.0),
        tier2_gram_size: stats.tier2_gram_size as u64,
        tier1_gram_size: stats.tier1_gram_size as u64,
        query_count: stats.query_count,
        retired_generation_count: retired_generation_count as u64,
        tier2_docs_matched_total: stats.tier2_docs_matched_total,
        tier2_match_ratio: stats.tier2_match_ratio,
        tier2_scanned_docs_total: stats.tier2_scanned_docs_total,
        version: 1,
        deleted_storage_bytes,
        compaction_idle_cooldown_s,
        compaction_cooldown_remaining_s,
        compaction_waiting_for_cooldown,
    }
}

/// Builds an empty protobuf store summary when a root exists logically but does
/// not yet contain document data.
///
/// Inputs:
/// - `config`: Server configuration that supplies policy defaults.
/// - `root`: Root used for disk-usage reporting.
/// - `shard_count`: Effective shard count to report.
///
/// Returns:
/// - A zero-document store summary with configuration fields populated.
fn grpc_empty_store_summary_for_config(
    config: &ServerConfig,
    root: &Path,
    shard_count: usize,
) -> StoreSummary {
    let stats = crate::candidate::CandidateStats {
        doc_count: 0,
        deleted_doc_count: 0,
        id_source: config.candidate_config.id_source.clone(),
        store_path: config.candidate_config.store_path,
        tier1_filter_target_fp: config.candidate_config.tier1_filter_target_fp,
        tier2_filter_target_fp: config.candidate_config.tier2_filter_target_fp,
        tier2_gram_size: config.candidate_config.tier2_gram_size,
        tier1_gram_size: config.candidate_config.tier1_gram_size,
        compaction_idle_cooldown_s: config.candidate_config.compaction_idle_cooldown_s,
        source_dedup_min_new_docs: config.candidate_config.source_dedup_min_new_docs,
        compaction_cooldown_remaining_s: 0.0,
        compaction_waiting_for_cooldown: false,
        compaction_generation: 1,
        retired_generation_count: 0,
        query_count: 0,
        tier2_scanned_docs_total: 0,
        tier2_docs_matched_total: 0,
        tier2_match_ratio: 0.0,
        docs_vector_bytes: 0,
        doc_rows_bytes: 0,
        tier2_doc_rows_bytes: 0,
        identity_index_bytes: 0,
        special_doc_positions_bytes: 0,
        query_artifact_cache_entries: 0,
        query_artifact_cache_bytes: 0,
        mapped_bloom_bytes: 0,
        mapped_tier2_bloom_bytes: 0,
        mapped_metadata_bytes: 0,
        mapped_external_id_bytes: 0,
    };
    let disk_usage_bytes = if root.exists() {
        disk_usage_under(root)
    } else {
        0
    };
    grpc_store_summary_from_candidate_stats(&[stats], disk_usage_bytes, 0, shard_count)
}

/// Converts the adaptive publish controller snapshot into the protobuf summary
/// returned by `stats`.
fn grpc_adaptive_publish_summary_from_snapshot(
    adaptive: &AdaptivePublishSnapshot,
) -> AdaptivePublishSummary {
    AdaptivePublishSummary {
        storage_class: adaptive.storage_class.clone(),
        current_idle_ms: adaptive.current_idle_ms,
        mode: adaptive.mode.to_owned(),
        reason: adaptive.reason.to_owned(),
        recent_publish_p95_ms: adaptive.recent_publish_p95_ms,
        recent_submit_p95_ms: adaptive.recent_submit_p95_ms,
        recent_store_p95_ms: adaptive.recent_store_p95_ms,
        recent_publishes_in_window: adaptive.recent_publishes_in_window,
        tier2_pending_shards: adaptive.tier2_pending_shards,
        healthy_cycles: adaptive.healthy_cycles,
    }
}

/// Reads the current server-side insert-batch counters into the protobuf summary
/// returned by `stats`.
///
/// Inputs:
/// - `state`: Shared server state holding the accumulated atomic counters.
///
/// Returns:
/// - The current insert-batch telemetry snapshot.
fn grpc_insert_batch_profile_summary_from_state(state: &ServerState) -> InsertBatchProfileSummary {
    InsertBatchProfileSummary {
        batches: state
            .index_session_server_insert_batch_count
            .load(Ordering::Acquire),
        documents: state
            .index_session_server_insert_batch_documents
            .load(Ordering::Acquire),
        shards_touched_total: state
            .index_session_server_insert_batch_shards_touched
            .load(Ordering::Acquire),
        total_us: state
            .index_session_server_insert_batch_total_us
            .load(Ordering::Acquire),
        parse_us: state
            .index_session_server_insert_batch_parse_us
            .load(Ordering::Acquire),
        group_us: state
            .index_session_server_insert_batch_group_us
            .load(Ordering::Acquire),
        build_us: state
            .index_session_server_insert_batch_build_us
            .load(Ordering::Acquire),
        store_us: state
            .index_session_server_insert_batch_store_us
            .load(Ordering::Acquire),
        finalize_us: state
            .index_session_server_insert_batch_finalize_us
            .load(Ordering::Acquire),
        store_resolve_doc_state_us: state
            .index_session_server_insert_batch_store_resolve_doc_state_us
            .load(Ordering::Acquire),
        store_append_sidecars_us: state
            .index_session_server_insert_batch_store_append_sidecars_us
            .load(Ordering::Acquire),
        store_append_sidecar_payloads_us: state
            .index_session_server_insert_batch_store_append_sidecar_payloads_us
            .load(Ordering::Acquire),
        store_append_bloom_payload_assemble_us: state
            .index_session_server_insert_batch_store_append_bloom_payload_assemble_us
            .load(Ordering::Acquire),
        store_append_bloom_payload_us: state
            .index_session_server_insert_batch_store_append_bloom_payload_us
            .load(Ordering::Acquire),
        store_append_metadata_payload_us: state
            .index_session_server_insert_batch_store_append_metadata_payload_us
            .load(Ordering::Acquire),
        store_append_external_id_payload_us: state
            .index_session_server_insert_batch_store_append_external_id_payload_us
            .load(Ordering::Acquire),
        store_append_tier2_bloom_payload_us: state
            .index_session_server_insert_batch_store_append_tier2_bloom_payload_us
            .load(Ordering::Acquire),
        store_append_doc_row_build_us: state
            .index_session_server_insert_batch_store_append_doc_row_build_us
            .load(Ordering::Acquire),
        store_append_bloom_payload_bytes: state
            .index_session_server_insert_batch_store_append_bloom_payload_bytes
            .load(Ordering::Acquire),
        store_append_metadata_payload_bytes: state
            .index_session_server_insert_batch_store_append_metadata_payload_bytes
            .load(Ordering::Acquire),
        store_append_external_id_payload_bytes: state
            .index_session_server_insert_batch_store_append_external_id_payload_bytes
            .load(Ordering::Acquire),
        store_append_tier2_bloom_payload_bytes: state
            .index_session_server_insert_batch_store_append_tier2_bloom_payload_bytes
            .load(Ordering::Acquire),
        store_append_doc_records_us: state
            .index_session_server_insert_batch_store_append_doc_records_us
            .load(Ordering::Acquire),
        store_write_existing_us: state
            .index_session_server_insert_batch_store_write_existing_us
            .load(Ordering::Acquire),
        store_install_docs_us: state
            .index_session_server_insert_batch_store_install_docs_us
            .load(Ordering::Acquire),
        store_tier2_update_us: state
            .index_session_server_insert_batch_store_tier2_update_us
            .load(Ordering::Acquire),
        store_persist_meta_us: state
            .index_session_server_insert_batch_store_persist_meta_us
            .load(Ordering::Acquire),
        store_rebalance_tier2_us: state
            .index_session_server_insert_batch_store_rebalance_tier2_us
            .load(Ordering::Acquire),
    }
}

/// Builds the protobuf summary for the current index session.
///
/// Inputs:
/// - `state`: Shared server state containing session progress counters.
///
/// Returns:
/// - An `IndexSessionSummary` with progress and batch telemetry.
fn grpc_index_session_summary_from_state(state: &ServerState) -> IndexSessionSummary {
    let total_documents = state.index_session_total_documents.load(Ordering::Acquire);
    let processed_documents = state
        .index_session_processed_documents
        .load(Ordering::Acquire);
    let submitted_documents = state
        .index_session_submitted_documents
        .load(Ordering::Acquire);
    let remaining_documents = total_documents.saturating_sub(processed_documents);
    let progress_percent = if total_documents == 0 {
        0.0
    } else {
        (processed_documents as f64 / total_documents as f64) * 100.0
    };
    IndexSessionSummary {
        active: state.active_index_sessions.load(Ordering::Acquire) > 0,
        client_active: state.active_index_clients.load(Ordering::Acquire) > 0,
        total_documents,
        submitted_documents,
        processed_documents,
        remaining_documents,
        progress_percent,
        started_unix_ms: state.index_session_started_unix_ms.load(Ordering::Acquire),
        last_update_unix_ms: state
            .index_session_last_update_unix_ms
            .load(Ordering::Acquire),
        server_insert_batch_profile: Some(grpc_insert_batch_profile_summary_from_state(state)),
    }
}

/// Converts one root's startup timing profile into the protobuf form used by
/// gRPC status responses.
fn grpc_startup_store_summary_from_profile(
    profile: &StoreRootStartupProfile,
) -> StartupStoreSummary {
    StartupStoreSummary {
        total_ms: profile.total_ms,
        opened_existing_shards: profile.opened_existing_shards,
        initialized_new_shards: profile.initialized_new_shards,
        doc_count: profile.doc_count,
    }
}

/// Converts the overall startup profile into the protobuf status summary.
///
/// Inputs:
/// - `startup`: Aggregated startup timing data.
/// - `startup_cleanup_removed_roots`: Count of abandoned roots cleaned during startup.
///
/// Returns:
/// - The protobuf startup summary returned by `stats`.
fn grpc_startup_summary_from_profile(
    startup: &StartupProfile,
    startup_cleanup_removed_roots: u64,
) -> StartupSummary {
    StartupSummary {
        total_ms: startup.total_ms,
        startup_cleanup_removed_roots,
        current: Some(grpc_startup_store_summary_from_profile(&startup.current)),
        work: Some(grpc_startup_store_summary_from_profile(&startup.work)),
    }
}

/// Builds the protobuf publish summary from the current readiness snapshot plus
/// accumulated runtime counters.
///
/// Inputs:
/// - `state`: Shared server state with atomic publish counters.
/// - `readiness`: Point-in-time publish readiness computed for the current tick.
///
/// Returns:
/// - The protobuf publish summary returned by `stats`.
fn grpc_publish_summary_from_state(
    state: &ServerState,
    readiness: PublishReadiness,
) -> PublishSummary {
    PublishSummary {
        pending: state.work_dirty.load(Ordering::Acquire),
        eligible: readiness.eligible,
        blocked_reason: readiness.blocked_reason.to_owned(),
        trigger_mode: readiness.trigger_mode.to_owned(),
        trigger_reason: readiness.trigger_reason.to_owned(),
        idle_elapsed_ms: readiness.idle_elapsed_ms,
        idle_remaining_ms: readiness.idle_remaining_ms,
        work_buffer_estimated_documents: readiness.work_buffer_estimated_documents,
        work_buffer_estimated_input_bytes: readiness.work_buffer_estimated_input_bytes,
        work_buffer_document_threshold: readiness.work_buffer_document_threshold,
        work_buffer_input_bytes_threshold: readiness.work_buffer_input_bytes_threshold,
        work_buffer_rss_threshold_bytes: readiness.work_buffer_rss_threshold_bytes,
        current_rss_bytes: readiness.current_rss_bytes,
        pending_tier2_snapshot_shards: readiness.pending_tier2_snapshot_shards,
        index_backpressure_delay_ms: readiness.index_backpressure_delay_ms,
        index_backpressure_events_total: state
            .index_backpressure_events_total
            .load(Ordering::Acquire),
        index_backpressure_sleep_ms_total: state
            .index_backpressure_sleep_ms_total
            .load(Ordering::Acquire),
        last_publish_started_unix_ms: state.last_publish_started_unix_ms.load(Ordering::Acquire),
        last_publish_completed_unix_ms: state
            .last_publish_completed_unix_ms
            .load(Ordering::Acquire),
        last_publish_duration_ms: state.last_publish_duration_ms.load(Ordering::Acquire),
        last_publish_lock_wait_ms: state.last_publish_lock_wait_ms.load(Ordering::Acquire),
        last_publish_promote_work_ms: state.last_publish_promote_work_ms.load(Ordering::Acquire),
        last_publish_init_work_ms: state.last_publish_init_work_ms.load(Ordering::Acquire),
        last_publish_persisted_snapshot_shards: state
            .last_publish_persisted_snapshot_shards
            .load(Ordering::Acquire),
        last_publish_reused_work_stores: state
            .last_publish_reused_work_stores
            .load(Ordering::Acquire),
        publish_runs_total: state.publish_runs_total.load(Ordering::Acquire),
        adaptive_idle_ms: readiness.idle_threshold_ms,
    }
}

/// Builds the protobuf summary for published tier2 snapshot sealing work.
///
/// Inputs:
/// - `state`: Shared server state that tracks seal progress and failures.
///
/// Returns:
/// - The protobuf snapshot-seal summary returned by `stats`.
fn grpc_published_tier2_snapshot_seal_summary_from_state(
    state: &ServerState,
) -> PublishedTier2SnapshotSealSummary {
    PublishedTier2SnapshotSealSummary {
        pending_shards: state
            .pending_published_tier2_snapshot_shard_count()
            .unwrap_or(0) as u64,
        in_progress: state
            .published_tier2_snapshot_seal_in_progress
            .load(Ordering::Acquire),
        runs_total: state
            .published_tier2_snapshot_seal_runs_total
            .load(Ordering::Acquire),
        last_duration_ms: state
            .last_published_tier2_snapshot_seal_duration_ms
            .load(Ordering::Acquire),
        last_persisted_shards: state
            .last_published_tier2_snapshot_seal_persisted_shards
            .load(Ordering::Acquire),
        last_failures: state
            .last_published_tier2_snapshot_seal_failures
            .load(Ordering::Acquire),
        last_completed_unix_ms: state
            .last_published_tier2_snapshot_seal_completed_unix_ms
            .load(Ordering::Acquire),
    }
}

/// Converts the internal query profile into the protobuf summary attached to a
/// completed search stream.
fn grpc_query_profile_summary_from_internal(
    profile: &CandidateQueryProfile,
) -> QueryProfileSummary {
    QueryProfileSummary {
        docs_scanned: profile.docs_scanned,
        metadata_loads: profile.metadata_loads,
        metadata_bytes: profile.metadata_bytes,
        tier1_bloom_loads: profile.tier1_bloom_loads,
        tier1_bloom_bytes: profile.tier1_bloom_bytes,
        tier2_bloom_loads: profile.tier2_bloom_loads,
        tier2_bloom_bytes: profile.tier2_bloom_bytes,
    }
}

/// Converts one internal streamed search frame into the protobuf frame sent to
/// gRPC clients.
///
/// Inputs:
/// - `frame`: Internal search frame produced by the candidate query layer.
///
/// Returns:
/// - The protobuf frame with optional profiles only on the terminal frame.
fn grpc_search_frame_from_internal(frame: CandidateQueryStreamFrame) -> Result<SearchFrame> {
    Ok(SearchFrame {
        identities: frame.identities,
        external_ids: frame
            .external_ids
            .unwrap_or_default()
            .into_iter()
            .map(grpc_optional_string)
            .collect(),
        candidate_limit: frame
            .candidate_limit
            .unwrap_or(0)
            .try_into()
            .unwrap_or(u64::MAX),
        has_candidate_limit: frame.candidate_limit.is_some(),
        stream_complete: frame.stream_complete,
        truncated: false,
        rule_complete: frame.rule_complete,
        target_rule_name: frame.target_rule_name,
        tier_used: frame.tier_used,
        query_profile: if frame.stream_complete || frame.rule_complete {
            Some(grpc_query_profile_summary_from_internal(
                &frame.query_profile,
            ))
        } else {
            None
        },
    })
}
