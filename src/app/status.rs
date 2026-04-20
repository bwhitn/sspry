/// Converts the published-store section of a gRPC status response into the
/// flattened JSON object exposed by the CLI `info` commands.
///
/// Inputs:
/// - `store`: The store summary returned by the server.
///
/// Returns:
/// - A JSON map containing only store-level metrics and configuration fields.
fn grpc_store_summary_json_map(
    store: &grpc::v1::StoreSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "active_doc_count".to_owned(),
        serde_json::json!(store.active_doc_count),
    );
    map.insert(
        "candidate_shards".to_owned(),
        serde_json::json!(store.candidate_shards),
    );
    map.insert("id_source".to_owned(), serde_json::json!(store.id_source));
    map.insert("store_path".to_owned(), serde_json::json!(store.store_path));
    map.insert(
        "source_dedup_min_new_docs".to_owned(),
        serde_json::json!(store.source_dedup_min_new_docs),
    );
    map.insert(
        "deleted_doc_count".to_owned(),
        serde_json::json!(store.deleted_doc_count),
    );
    map.insert(
        "disk_usage_bytes".to_owned(),
        serde_json::json!(store.disk_usage_bytes),
    );
    map.insert("doc_count".to_owned(), serde_json::json!(store.doc_count));
    map.insert(
        "compaction_generation".to_owned(),
        serde_json::json!(store.compaction_generation),
    );
    map.insert(
        "compaction_idle_cooldown_s".to_owned(),
        serde_json::json!(store.compaction_idle_cooldown_s),
    );
    map.insert(
        "compaction_cooldown_remaining_s".to_owned(),
        serde_json::json!(store.compaction_cooldown_remaining_s),
    );
    map.insert(
        "compaction_waiting_for_cooldown".to_owned(),
        serde_json::json!(store.compaction_waiting_for_cooldown),
    );
    map.insert(
        "tier1_filter_target_fp".to_owned(),
        serde_json::json!(store.tier1_filter_target_fp),
    );
    map.insert(
        "tier2_filter_target_fp".to_owned(),
        serde_json::json!(store.tier2_filter_target_fp),
    );
    map.insert(
        "tier2_gram_size".to_owned(),
        serde_json::json!(store.tier2_gram_size),
    );
    map.insert(
        "tier1_gram_size".to_owned(),
        serde_json::json!(store.tier1_gram_size),
    );
    map.insert(
        "query_count".to_owned(),
        serde_json::json!(store.query_count),
    );
    map.insert(
        "retired_generation_count".to_owned(),
        serde_json::json!(store.retired_generation_count),
    );
    map.insert(
        "tier2_docs_matched_total".to_owned(),
        serde_json::json!(store.tier2_docs_matched_total),
    );
    map.insert(
        "tier2_match_ratio".to_owned(),
        serde_json::json!(store.tier2_match_ratio),
    );
    map.insert(
        "tier2_scanned_docs_total".to_owned(),
        serde_json::json!(store.tier2_scanned_docs_total),
    );
    map.insert("version".to_owned(), serde_json::json!(store.version));
    map.insert(
        "deleted_storage_bytes".to_owned(),
        serde_json::json!(store.deleted_storage_bytes),
    );
    map
}

/// Converts forest-wide source-id deduplication maintenance state into the
/// JSON object exposed by status and info commands.
///
/// Inputs:
/// - `summary`: Forest deduplication checkpoint state returned by the server.
///
/// Returns:
/// - A JSON map containing threshold and last-pass outcome counters.
fn grpc_forest_source_dedup_json_map(
    summary: &grpc::v1::ForestSourceDedupSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "min_new_docs".to_owned(),
        serde_json::json!(summary.min_new_docs),
    );
    map.insert(
        "last_completed_unix_ms".to_owned(),
        serde_json::json!(summary.last_completed_unix_ms),
    );
    map.insert(
        "last_duplicate_groups".to_owned(),
        serde_json::json!(summary.last_duplicate_groups),
    );
    map.insert(
        "last_deleted_docs".to_owned(),
        serde_json::json!(summary.last_deleted_docs),
    );
    map.insert(
        "last_affected_trees".to_owned(),
        serde_json::json!(summary.last_affected_trees),
    );
    map.insert(
        "last_total_inserted_docs".to_owned(),
        serde_json::json!(summary.last_total_inserted_docs),
    );
    map
}

/// Converts adaptive auto-publish telemetry into the JSON shape used by the
/// CLI status output.
///
/// Inputs:
/// - `adaptive`: The server's current adaptive publish summary.
///
/// Returns:
/// - A JSON map with publish pacing, recent latency, and pending tier2 data.
fn grpc_adaptive_publish_json_map(
    adaptive: &grpc::v1::AdaptivePublishSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "storage_class".to_owned(),
        serde_json::json!(adaptive.storage_class),
    );
    map.insert(
        "current_idle_ms".to_owned(),
        serde_json::json!(adaptive.current_idle_ms),
    );
    map.insert("mode".to_owned(), serde_json::json!(adaptive.mode));
    map.insert("reason".to_owned(), serde_json::json!(adaptive.reason));
    map.insert(
        "recent_publish_p95_ms".to_owned(),
        serde_json::json!(adaptive.recent_publish_p95_ms),
    );
    map.insert(
        "recent_submit_p95_ms".to_owned(),
        serde_json::json!(adaptive.recent_submit_p95_ms),
    );
    map.insert(
        "recent_store_p95_ms".to_owned(),
        serde_json::json!(adaptive.recent_store_p95_ms),
    );
    map.insert(
        "recent_publishes_in_window".to_owned(),
        serde_json::json!(adaptive.recent_publishes_in_window),
    );
    map.insert(
        "tier2_pending_shards".to_owned(),
        serde_json::json!(adaptive.tier2_pending_shards),
    );
    map.insert(
        "healthy_cycles".to_owned(),
        serde_json::json!(adaptive.healthy_cycles),
    );
    map
}

/// Serializes the server-side insert-batch performance counters into the JSON
/// object printed by verbose status commands.
///
/// Inputs:
/// - `profile`: The per-batch telemetry snapshot accumulated on the server.
///
/// Returns:
/// - A JSON map containing timing and byte counters for each insert stage.
fn grpc_insert_batch_profile_json_map(
    profile: &grpc::v1::InsertBatchProfileSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert("batches".to_owned(), serde_json::json!(profile.batches));
    map.insert("documents".to_owned(), serde_json::json!(profile.documents));
    map.insert(
        "shards_touched_total".to_owned(),
        serde_json::json!(profile.shards_touched_total),
    );
    map.insert("total_us".to_owned(), serde_json::json!(profile.total_us));
    map.insert("parse_us".to_owned(), serde_json::json!(profile.parse_us));
    map.insert("group_us".to_owned(), serde_json::json!(profile.group_us));
    map.insert("build_us".to_owned(), serde_json::json!(profile.build_us));
    map.insert("store_us".to_owned(), serde_json::json!(profile.store_us));
    map.insert(
        "finalize_us".to_owned(),
        serde_json::json!(profile.finalize_us),
    );
    map.insert(
        "store_resolve_doc_state_us".to_owned(),
        serde_json::json!(profile.store_resolve_doc_state_us),
    );
    map.insert(
        "store_append_sidecars_us".to_owned(),
        serde_json::json!(profile.store_append_sidecars_us),
    );
    map.insert(
        "store_append_sidecar_payloads_us".to_owned(),
        serde_json::json!(profile.store_append_sidecar_payloads_us),
    );
    map.insert(
        "store_append_bloom_payload_assemble_us".to_owned(),
        serde_json::json!(profile.store_append_bloom_payload_assemble_us),
    );
    map.insert(
        "store_append_bloom_payload_us".to_owned(),
        serde_json::json!(profile.store_append_bloom_payload_us),
    );
    map.insert(
        "store_append_metadata_payload_us".to_owned(),
        serde_json::json!(profile.store_append_metadata_payload_us),
    );
    map.insert(
        "store_append_external_id_payload_us".to_owned(),
        serde_json::json!(profile.store_append_external_id_payload_us),
    );
    map.insert(
        "store_append_tier2_bloom_payload_us".to_owned(),
        serde_json::json!(profile.store_append_tier2_bloom_payload_us),
    );
    map.insert(
        "store_append_doc_row_build_us".to_owned(),
        serde_json::json!(profile.store_append_doc_row_build_us),
    );
    map.insert(
        "store_append_bloom_payload_bytes".to_owned(),
        serde_json::json!(profile.store_append_bloom_payload_bytes),
    );
    map.insert(
        "store_append_metadata_payload_bytes".to_owned(),
        serde_json::json!(profile.store_append_metadata_payload_bytes),
    );
    map.insert(
        "store_append_external_id_payload_bytes".to_owned(),
        serde_json::json!(profile.store_append_external_id_payload_bytes),
    );
    map.insert(
        "store_append_tier2_bloom_payload_bytes".to_owned(),
        serde_json::json!(profile.store_append_tier2_bloom_payload_bytes),
    );
    map.insert(
        "store_append_doc_records_us".to_owned(),
        serde_json::json!(profile.store_append_doc_records_us),
    );
    map.insert(
        "store_write_existing_us".to_owned(),
        serde_json::json!(profile.store_write_existing_us),
    );
    map.insert(
        "store_install_docs_us".to_owned(),
        serde_json::json!(profile.store_install_docs_us),
    );
    map.insert(
        "store_tier2_update_us".to_owned(),
        serde_json::json!(profile.store_tier2_update_us),
    );
    map.insert(
        "store_persist_meta_us".to_owned(),
        serde_json::json!(profile.store_persist_meta_us),
    );
    map.insert(
        "store_rebalance_tier2_us".to_owned(),
        serde_json::json!(profile.store_rebalance_tier2_us),
    );
    map
}

/// Converts the active index-session summary into the JSON object used by
/// `info` output.
///
/// Inputs:
/// - `session`: The current server-side indexing session snapshot.
///
/// Returns:
/// - A JSON map with progress counters plus optional server batch telemetry.
fn grpc_index_session_json_map(
    session: &grpc::v1::IndexSessionSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert("active".to_owned(), serde_json::json!(session.active));
    map.insert(
        "client_active".to_owned(),
        serde_json::json!(session.client_active),
    );
    map.insert(
        "total_documents".to_owned(),
        serde_json::json!(session.total_documents),
    );
    map.insert(
        "submitted_documents".to_owned(),
        serde_json::json!(session.submitted_documents),
    );
    map.insert(
        "processed_documents".to_owned(),
        serde_json::json!(session.processed_documents),
    );
    map.insert(
        "remaining_documents".to_owned(),
        serde_json::json!(session.remaining_documents),
    );
    map.insert(
        "progress_percent".to_owned(),
        serde_json::json!(session.progress_percent),
    );
    map.insert(
        "started_unix_ms".to_owned(),
        serde_json::json!(session.started_unix_ms),
    );
    map.insert(
        "last_update_unix_ms".to_owned(),
        serde_json::json!(session.last_update_unix_ms),
    );
    if let Some(profile) = &session.server_insert_batch_profile {
        map.insert(
            "server_insert_batch_profile".to_owned(),
            serde_json::Value::Object(grpc_insert_batch_profile_json_map(profile)),
        );
    }
    map
}

/// Converts a startup profile for a single store root into the nested JSON
/// object used by status reporting.
///
/// Inputs:
/// - `startup`: Startup timings and open/init counters for one root.
///
/// Returns:
/// - A JSON map containing shard-open timings and document counts.
fn grpc_startup_store_json_map(
    startup: &grpc::v1::StartupStoreSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert("total_ms".to_owned(), serde_json::json!(startup.total_ms));
    map.insert(
        "opened_existing_shards".to_owned(),
        serde_json::json!(startup.opened_existing_shards),
    );
    map.insert(
        "initialized_new_shards".to_owned(),
        serde_json::json!(startup.initialized_new_shards),
    );
    map.insert("doc_count".to_owned(), serde_json::json!(startup.doc_count));
    map
}

/// Converts the full startup summary into the nested JSON object printed by
/// CLI status commands.
///
/// Inputs:
/// - `startup`: The top-level startup profile returned by the server.
///
/// Returns:
/// - A JSON map with overall startup timings plus optional current/work roots.
fn grpc_startup_json_map(
    startup: &grpc::v1::StartupSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert("total_ms".to_owned(), serde_json::json!(startup.total_ms));
    map.insert(
        "startup_cleanup_removed_roots".to_owned(),
        serde_json::json!(startup.startup_cleanup_removed_roots),
    );
    if let Some(current) = &startup.current {
        map.insert(
            "current".to_owned(),
            serde_json::Value::Object(grpc_startup_store_json_map(current)),
        );
    }
    if let Some(work) = &startup.work {
        map.insert(
            "work".to_owned(),
            serde_json::Value::Object(grpc_startup_store_json_map(work)),
        );
    }
    map
}

/// Converts publish-state telemetry into the JSON object merged into CLI
/// status output.
///
/// Inputs:
/// - `publish`: The server's current publish readiness and last-run snapshot.
///
/// Returns:
/// - A JSON map containing publish gating, buffer pressure, and recent run data.
fn grpc_publish_json_map(
    publish: &grpc::v1::PublishSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert("pending".to_owned(), serde_json::json!(publish.pending));
    map.insert("eligible".to_owned(), serde_json::json!(publish.eligible));
    map.insert(
        "blocked_reason".to_owned(),
        serde_json::json!(publish.blocked_reason),
    );
    map.insert(
        "trigger_mode".to_owned(),
        serde_json::json!(publish.trigger_mode),
    );
    map.insert(
        "trigger_reason".to_owned(),
        serde_json::json!(publish.trigger_reason),
    );
    map.insert(
        "idle_elapsed_ms".to_owned(),
        serde_json::json!(publish.idle_elapsed_ms),
    );
    map.insert(
        "idle_remaining_ms".to_owned(),
        serde_json::json!(publish.idle_remaining_ms),
    );
    map.insert(
        "adaptive_idle_ms".to_owned(),
        serde_json::json!(publish.adaptive_idle_ms),
    );
    map.insert(
        "work_buffer_estimated_documents".to_owned(),
        serde_json::json!(publish.work_buffer_estimated_documents),
    );
    map.insert(
        "work_buffer_estimated_input_bytes".to_owned(),
        serde_json::json!(publish.work_buffer_estimated_input_bytes),
    );
    map.insert(
        "work_buffer_document_threshold".to_owned(),
        serde_json::json!(publish.work_buffer_document_threshold),
    );
    map.insert(
        "work_buffer_input_bytes_threshold".to_owned(),
        serde_json::json!(publish.work_buffer_input_bytes_threshold),
    );
    map.insert(
        "work_buffer_rss_threshold_bytes".to_owned(),
        serde_json::json!(publish.work_buffer_rss_threshold_bytes),
    );
    map.insert(
        "current_rss_bytes".to_owned(),
        serde_json::json!(publish.current_rss_bytes),
    );
    map.insert(
        "pending_tier2_snapshot_shards".to_owned(),
        serde_json::json!(publish.pending_tier2_snapshot_shards),
    );
    map.insert(
        "index_backpressure_delay_ms".to_owned(),
        serde_json::json!(publish.index_backpressure_delay_ms),
    );
    map.insert(
        "index_backpressure_events_total".to_owned(),
        serde_json::json!(publish.index_backpressure_events_total),
    );
    map.insert(
        "index_backpressure_sleep_ms_total".to_owned(),
        serde_json::json!(publish.index_backpressure_sleep_ms_total),
    );
    map.insert(
        "last_publish_started_unix_ms".to_owned(),
        serde_json::json!(publish.last_publish_started_unix_ms),
    );
    map.insert(
        "last_publish_completed_unix_ms".to_owned(),
        serde_json::json!(publish.last_publish_completed_unix_ms),
    );
    map.insert(
        "last_publish_duration_ms".to_owned(),
        serde_json::json!(publish.last_publish_duration_ms),
    );
    map.insert(
        "last_publish_lock_wait_ms".to_owned(),
        serde_json::json!(publish.last_publish_lock_wait_ms),
    );
    map.insert(
        "last_publish_promote_work_ms".to_owned(),
        serde_json::json!(publish.last_publish_promote_work_ms),
    );
    map.insert(
        "last_publish_init_work_ms".to_owned(),
        serde_json::json!(publish.last_publish_init_work_ms),
    );
    map.insert(
        "last_publish_persisted_snapshot_shards".to_owned(),
        serde_json::json!(publish.last_publish_persisted_snapshot_shards),
    );
    map.insert(
        "last_publish_reused_work_stores".to_owned(),
        serde_json::json!(publish.last_publish_reused_work_stores),
    );
    map.insert(
        "publish_runs_total".to_owned(),
        serde_json::json!(publish.publish_runs_total),
    );
    map
}

/// Converts tier2 snapshot seal telemetry into the JSON object shown by status
/// commands.
///
/// Inputs:
/// - `seal`: The server's pending seal-work summary.
///
/// Returns:
/// - A JSON map with pending shard counts and last seal-run timing.
fn grpc_published_tier2_snapshot_seal_json_map(
    seal: &grpc::v1::PublishedTier2SnapshotSealSummary,
) -> serde_json::Map<String, serde_json::Value> {
    let mut map = serde_json::Map::new();
    map.insert(
        "pending_shards".to_owned(),
        serde_json::json!(seal.pending_shards),
    );
    map.insert(
        "in_progress".to_owned(),
        serde_json::json!(seal.in_progress),
    );
    map.insert("runs_total".to_owned(), serde_json::json!(seal.runs_total));
    map.insert(
        "last_duration_ms".to_owned(),
        serde_json::json!(seal.last_duration_ms),
    );
    map.insert(
        "last_persisted_shards".to_owned(),
        serde_json::json!(seal.last_persisted_shards),
    );
    map.insert(
        "last_failures".to_owned(),
        serde_json::json!(seal.last_failures),
    );
    map.insert(
        "last_completed_unix_ms".to_owned(),
        serde_json::json!(seal.last_completed_unix_ms),
    );
    map
}

/// Builds the complete JSON value emitted by `info` and `info --light`.
///
/// How it works:
/// - Always includes connection, runtime, publish, and worker state.
/// - Optionally merges the published/work store summaries when the caller wants
///   full store detail instead of the light status view.
///
/// Inputs:
/// - `status`: The raw gRPC status response from the server.
/// - `include_store_details`: Whether to merge the nested store summaries.
///
/// Returns:
/// - A top-level JSON value ready to print to stdout.
fn grpc_status_output_json(
    status: &grpc::v1::StatusResponse,
    include_store_details: bool,
) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    map.insert("draining".to_owned(), serde_json::json!(status.draining));
    map.insert(
        "active_connections".to_owned(),
        serde_json::json!(status.active_connections),
    );
    map.insert(
        "active_mutations".to_owned(),
        serde_json::json!(status.active_mutations),
    );
    map.insert(
        "publish_requested".to_owned(),
        serde_json::json!(status.publish_requested),
    );
    map.insert(
        "mutations_paused".to_owned(),
        serde_json::json!(status.mutations_paused),
    );
    map.insert(
        "publish_in_progress".to_owned(),
        serde_json::json!(status.publish_in_progress),
    );
    map.insert(
        "active_index_clients".to_owned(),
        serde_json::json!(status.active_index_clients),
    );
    map.insert(
        "active_index_sessions".to_owned(),
        serde_json::json!(status.active_index_sessions),
    );
    map.insert(
        "search_workers".to_owned(),
        serde_json::json!(status.search_workers),
    );
    map.insert(
        "memory_budget_bytes".to_owned(),
        serde_json::json!(status.memory_budget_bytes),
    );
    map.insert(
        "current_rss_kb".to_owned(),
        serde_json::json!(status.current_rss_kb),
    );
    map.insert(
        "peak_rss_kb".to_owned(),
        serde_json::json!(status.peak_rss_kb),
    );
    map.insert(
        "workspace_mode".to_owned(),
        serde_json::json!(status.workspace_mode),
    );
    if !status.published_root.is_empty() {
        map.insert(
            "published_root".to_owned(),
            serde_json::json!(status.published_root),
        );
    }
    if !status.work_root.is_empty() {
        map.insert("work_root".to_owned(), serde_json::json!(status.work_root));
    }
    if let Some(adaptive) = &status.adaptive_publish {
        map.insert(
            "adaptive_publish".to_owned(),
            serde_json::Value::Object(grpc_adaptive_publish_json_map(adaptive)),
        );
    }
    if let Some(session) = &status.index_session {
        map.insert(
            "index_session".to_owned(),
            serde_json::Value::Object(grpc_index_session_json_map(session)),
        );
    }
    if let Some(startup) = &status.startup {
        map.insert(
            "startup".to_owned(),
            serde_json::Value::Object(grpc_startup_json_map(startup)),
        );
    }
    if let Some(publish) = &status.publish {
        map.insert("work_dirty".to_owned(), serde_json::json!(publish.pending));
        map.insert(
            "publish".to_owned(),
            serde_json::Value::Object(grpc_publish_json_map(publish)),
        );
    }
    if let Some(seal) = &status.published_tier2_snapshot_seal {
        map.insert(
            "published_tier2_snapshot_seal".to_owned(),
            serde_json::Value::Object(grpc_published_tier2_snapshot_seal_json_map(seal)),
        );
    }
    if let Some(summary) = &status.forest_source_dedup {
        map.insert(
            "forest_source_dedup".to_owned(),
            serde_json::Value::Object(grpc_forest_source_dedup_json_map(summary)),
        );
    }
    if include_store_details {
        if status.has_published {
            if let Some(published) = &status.published {
                for (key, value) in grpc_store_summary_json_map(published) {
                    map.insert(key, value);
                }
            }
        }
        if status.has_work {
            if let Some(work) = &status.work {
                map.insert(
                    "work".to_owned(),
                    serde_json::Value::Object(grpc_store_summary_json_map(work)),
                );
            }
        }
    }
    serde_json::Value::Object(map)
}
