use std::time::Duration;

use serde_json::{Map, Value, json};
use tokio::runtime::{Builder as TokioRuntimeBuilder, Runtime};
use tokio_stream::StreamExt;
use tonic::transport::{Channel, Endpoint};

use crate::candidate::{CandidatePreparedQueryProfile, CandidateQueryProfile};
use crate::rpc::CandidateDeleteResponse;
use crate::rpc::DEFAULT_MAX_REQUEST_BYTES;
use crate::{Result, SspryError};

pub mod v1 {
    tonic::include_proto!("sspry.v1");
}

pub const PROTOTYPE_BRANCH_NOTE: &str =
    "Parallel gRPC prototype surface. The custom RPC transport remains authoritative.";

pub const DEFAULT_GRPC_INSERT_CHUNK_BYTES: usize = 8 * 1024 * 1024;

struct GrpcInsertFrameIter {
    rows: Vec<Vec<u8>>,
    chunk_bytes: usize,
    row_idx: usize,
    row_offset: usize,
    sent_stream_complete: bool,
}

impl GrpcInsertFrameIter {
    fn new(rows: Vec<Vec<u8>>, chunk_bytes: usize) -> Self {
        Self {
            rows,
            chunk_bytes: chunk_bytes.max(1),
            row_idx: 0,
            row_offset: 0,
            sent_stream_complete: false,
        }
    }
}

impl Iterator for GrpcInsertFrameIter {
    type Item = v1::InsertFrame;

    fn next(&mut self) -> Option<Self::Item> {
        if self.row_idx >= self.rows.len() {
            if self.sent_stream_complete {
                return None;
            }
            self.sent_stream_complete = true;
            return Some(v1::InsertFrame {
                payload: Vec::new(),
                row_complete: false,
                stream_complete: true,
            });
        }

        let row = &self.rows[self.row_idx];
        let end = self
            .row_offset
            .saturating_add(self.chunk_bytes)
            .min(row.len());
        let payload = row[self.row_offset..end].to_vec();
        let row_complete = end >= row.len();
        if row_complete {
            self.row_idx = self.row_idx.saturating_add(1);
            self.row_offset = 0;
        } else {
            self.row_offset = end;
        }
        Some(v1::InsertFrame {
            payload,
            row_complete,
            stream_complete: false,
        })
    }
}

fn grpc_endpoint(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_owned()
    } else {
        format!("http://{addr}")
    }
}

fn tonic_error(err: impl ToString) -> SspryError {
    SspryError::from(err.to_string())
}

#[derive(Debug)]
pub struct BlockingGrpcClient {
    runtime: Runtime,
    inner: v1::sspry_client::SspryClient<Channel>,
    max_message_bytes: usize,
    insert_chunk_bytes: usize,
}

#[derive(Clone, Debug)]
pub struct GrpcSearchFrame {
    pub sha256: Vec<String>,
    pub external_ids: Vec<Option<String>>,
    pub candidate_limit: Option<usize>,
    pub stream_complete: bool,
    pub truncated: bool,
    pub tier_used: String,
    pub query_profile: CandidateQueryProfile,
    pub prepared_query_profile: CandidatePreparedQueryProfile,
}

impl BlockingGrpcClient {
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self> {
        Self::connect_with_limits(addr, timeout, DEFAULT_MAX_REQUEST_BYTES)
    }

    pub fn connect_with_limits(
        addr: &str,
        timeout: Duration,
        max_message_bytes: usize,
    ) -> Result<Self> {
        let runtime = TokioRuntimeBuilder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(tonic_error)?;
        let endpoint = Endpoint::from_shared(grpc_endpoint(addr))
            .map_err(tonic_error)?
            .connect_timeout(timeout)
            .timeout(timeout);
        let inner = runtime
            .block_on(async { v1::sspry_client::SspryClient::connect(endpoint).await })
            .map_err(tonic_error)?;
        let inner = inner
            .max_decoding_message_size(max_message_bytes)
            .max_encoding_message_size(max_message_bytes);
        Ok(Self {
            runtime,
            inner,
            max_message_bytes,
            insert_chunk_bytes: DEFAULT_GRPC_INSERT_CHUNK_BYTES.min(max_message_bytes.max(1)),
        })
    }

    pub fn set_insert_chunk_bytes(&mut self, chunk_bytes: usize) {
        self.insert_chunk_bytes = chunk_bytes.max(1).min(self.max_message_bytes.max(1));
    }

    pub fn ping(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async { self.inner.ping(v1::PingRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    pub fn stats(&mut self) -> Result<v1::StatsResponse> {
        let response = self
            .runtime
            .block_on(async { self.inner.stats(v1::StatsRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner())
    }

    pub fn stats_json(&mut self) -> Result<Map<String, Value>> {
        Ok(stats_response_to_json_map(&self.stats()?))
    }

    pub fn status(&mut self) -> Result<v1::StatusResponse> {
        let response = self
            .runtime
            .block_on(async { self.inner.status(v1::StatusRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner())
    }

    pub fn status_json(&mut self) -> Result<Map<String, Value>> {
        Ok(status_response_to_json_map(&self.status()?))
    }

    pub fn shutdown(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async { self.inner.shutdown(v1::ShutdownRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    pub fn publish(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async { self.inner.publish(v1::PublishRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    pub fn begin_index_session(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async {
                self.inner
                    .begin_index_session(v1::IndexSessionBeginRequest {})
                    .await
            })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    pub fn begin_index_client(&mut self, heartbeat_interval_ms: u64) -> Result<(u64, u64)> {
        let response = self
            .runtime
            .block_on(async {
                self.inner
                    .begin_index_client(v1::IndexClientBeginRequest {
                        heartbeat_interval_ms,
                    })
                    .await
            })
            .map_err(tonic_error)?;
        let response = response.into_inner();
        Ok((response.client_id, response.lease_timeout_ms))
    }

    pub fn heartbeat_index_client(&mut self, client_id: u64) -> Result<()> {
        let _response = self
            .runtime
            .block_on(async {
                self.inner
                    .heartbeat_index_client(v1::IndexClientHeartbeatRequest { client_id })
                    .await
            })
            .map_err(tonic_error)?;
        Ok(())
    }

    pub fn update_index_session_progress(
        &mut self,
        total_documents: Option<usize>,
        submitted_documents: usize,
        processed_documents: usize,
    ) -> Result<()> {
        let _response = self
            .runtime
            .block_on(async {
                self.inner
                    .update_index_session_progress(v1::IndexSessionProgressRequest {
                        total_documents: total_documents.map(|value| value as u64).unwrap_or(0),
                        has_total_documents: total_documents.is_some(),
                        submitted_documents: submitted_documents as u64,
                        processed_documents: processed_documents as u64,
                    })
                    .await
            })
            .map_err(tonic_error)?;
        Ok(())
    }

    pub fn end_index_session(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async {
                self.inner
                    .end_index_session(v1::IndexSessionEndRequest {})
                    .await
            })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    pub fn end_index_client(&mut self, client_id: u64) -> Result<String> {
        let response = self
            .runtime
            .block_on(async {
                self.inner
                    .end_index_client(v1::IndexClientHeartbeatRequest { client_id })
                    .await
            })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    pub fn candidate_delete_sha256(&mut self, sha256: &str) -> Result<CandidateDeleteResponse> {
        let response = self
            .runtime
            .block_on(async {
                self.inner
                    .delete(v1::DeleteRequest {
                        sha256: sha256.to_owned(),
                    })
                    .await
            })
            .map_err(tonic_error)?;
        let response = response.into_inner();
        Ok(CandidateDeleteResponse {
            status: response.status,
            sha256: response.sha256,
            doc_id: response.has_doc_id.then_some(response.doc_id),
        })
    }

    pub fn search_stream<F>(&mut self, request: v1::SearchRequest, mut on_frame: F) -> Result<()>
    where
        F: FnMut(GrpcSearchFrame) -> Result<()>,
    {
        let response = self
            .runtime
            .block_on(async { self.inner.search_stream(request).await })
            .map_err(tonic_error)?;
        let mut stream = response.into_inner();
        self.runtime.block_on(async {
            while let Some(frame) = stream.next().await {
                let frame = frame.map_err(tonic_error)?;
                let query_profile = query_profile_from_proto(frame.query_profile.as_ref());
                let prepared_query_profile =
                    prepared_query_profile_from_proto(frame.prepared_query_profile.as_ref());
                let mapped = GrpcSearchFrame {
                    sha256: frame.sha256,
                    external_ids: frame
                        .external_ids
                        .into_iter()
                        .map(|value| value.has_value.then_some(value.value))
                        .collect(),
                    candidate_limit: frame
                        .has_candidate_limit
                        .then_some(frame.candidate_limit as usize),
                    stream_complete: frame.stream_complete,
                    truncated: frame.truncated,
                    tier_used: frame.tier_used,
                    query_profile,
                    prepared_query_profile,
                };
                on_frame(mapped)?;
            }
            Ok::<(), SspryError>(())
        })
    }

    pub fn insert_binary_rows(&mut self, rows: Vec<Vec<u8>>) -> Result<v1::InsertSummary> {
        self.insert_binary_rows_with_chunk(rows, self.insert_chunk_bytes)
    }

    pub fn insert_binary_rows_with_chunk(
        &mut self,
        rows: Vec<Vec<u8>>,
        chunk_bytes: usize,
    ) -> Result<v1::InsertSummary> {
        let request_stream = tokio_stream::iter(GrpcInsertFrameIter::new(rows, chunk_bytes));
        let response = self
            .runtime
            .block_on(async { self.inner.insert_stream(request_stream).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner())
    }
}

fn optional_string_to_option(value: &v1::OptionalString) -> Option<String> {
    value.has_value.then(|| value.value.clone())
}

fn store_summary_to_json_map(summary: &v1::StoreSummary) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert(
        "active_doc_count".to_owned(),
        json!(summary.active_doc_count),
    );
    out.insert(
        "candidate_shards".to_owned(),
        json!(summary.candidate_shards),
    );
    out.insert("id_source".to_owned(), json!(summary.id_source));
    out.insert("store_path".to_owned(), json!(summary.store_path));
    out.insert(
        "deleted_doc_count".to_owned(),
        json!(summary.deleted_doc_count),
    );
    out.insert(
        "disk_usage_bytes".to_owned(),
        json!(summary.disk_usage_bytes),
    );
    out.insert("doc_count".to_owned(), json!(summary.doc_count));
    out.insert(
        "compaction_generation".to_owned(),
        json!(summary.compaction_generation),
    );
    out.insert(
        "tier1_filter_target_fp".to_owned(),
        Value::from(summary.tier1_filter_target_fp),
    );
    out.insert(
        "tier2_filter_target_fp".to_owned(),
        Value::from(summary.tier2_filter_target_fp),
    );
    out.insert("tier2_gram_size".to_owned(), json!(summary.tier2_gram_size));
    out.insert("tier1_gram_size".to_owned(), json!(summary.tier1_gram_size));
    out.insert("query_count".to_owned(), json!(summary.query_count));
    out.insert(
        "retired_generation_count".to_owned(),
        json!(summary.retired_generation_count),
    );
    out.insert(
        "tier2_docs_matched_total".to_owned(),
        json!(summary.tier2_docs_matched_total),
    );
    out.insert(
        "tier2_match_ratio".to_owned(),
        Value::from(summary.tier2_match_ratio),
    );
    out.insert(
        "tier2_scanned_docs_total".to_owned(),
        json!(summary.tier2_scanned_docs_total),
    );
    out.insert("version".to_owned(), json!(summary.version));
    out.insert(
        "deleted_storage_bytes".to_owned(),
        json!(summary.deleted_storage_bytes),
    );
    out
}

fn insert_batch_profile_to_json_map(summary: &v1::InsertBatchProfileSummary) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("batches".to_owned(), json!(summary.batches));
    out.insert("documents".to_owned(), json!(summary.documents));
    out.insert(
        "shards_touched_total".to_owned(),
        json!(summary.shards_touched_total),
    );
    out.insert("total_us".to_owned(), json!(summary.total_us));
    out.insert("parse_us".to_owned(), json!(summary.parse_us));
    out.insert("group_us".to_owned(), json!(summary.group_us));
    out.insert("build_us".to_owned(), json!(summary.build_us));
    out.insert("store_us".to_owned(), json!(summary.store_us));
    out.insert("finalize_us".to_owned(), json!(summary.finalize_us));
    out.insert(
        "store_resolve_doc_state_us".to_owned(),
        json!(summary.store_resolve_doc_state_us),
    );
    out.insert(
        "store_append_sidecars_us".to_owned(),
        json!(summary.store_append_sidecars_us),
    );
    out.insert(
        "store_append_sidecar_payloads_us".to_owned(),
        json!(summary.store_append_sidecar_payloads_us),
    );
    out.insert(
        "store_append_bloom_payload_assemble_us".to_owned(),
        json!(summary.store_append_bloom_payload_assemble_us),
    );
    out.insert(
        "store_append_bloom_payload_us".to_owned(),
        json!(summary.store_append_bloom_payload_us),
    );
    out.insert(
        "store_append_metadata_payload_us".to_owned(),
        json!(summary.store_append_metadata_payload_us),
    );
    out.insert(
        "store_append_external_id_payload_us".to_owned(),
        json!(summary.store_append_external_id_payload_us),
    );
    out.insert(
        "store_append_tier2_bloom_payload_us".to_owned(),
        json!(summary.store_append_tier2_bloom_payload_us),
    );
    out.insert(
        "store_append_doc_row_build_us".to_owned(),
        json!(summary.store_append_doc_row_build_us),
    );
    out.insert(
        "store_append_bloom_payload_bytes".to_owned(),
        json!(summary.store_append_bloom_payload_bytes),
    );
    out.insert(
        "store_append_metadata_payload_bytes".to_owned(),
        json!(summary.store_append_metadata_payload_bytes),
    );
    out.insert(
        "store_append_external_id_payload_bytes".to_owned(),
        json!(summary.store_append_external_id_payload_bytes),
    );
    out.insert(
        "store_append_tier2_bloom_payload_bytes".to_owned(),
        json!(summary.store_append_tier2_bloom_payload_bytes),
    );
    out.insert(
        "store_append_doc_records_us".to_owned(),
        json!(summary.store_append_doc_records_us),
    );
    out.insert(
        "store_write_existing_us".to_owned(),
        json!(summary.store_write_existing_us),
    );
    out.insert(
        "store_install_docs_us".to_owned(),
        json!(summary.store_install_docs_us),
    );
    out.insert(
        "store_tier2_update_us".to_owned(),
        json!(summary.store_tier2_update_us),
    );
    out.insert(
        "store_persist_meta_us".to_owned(),
        json!(summary.store_persist_meta_us),
    );
    out.insert(
        "store_rebalance_tier2_us".to_owned(),
        json!(summary.store_rebalance_tier2_us),
    );
    out
}

fn stats_response_to_json_map(response: &v1::StatsResponse) -> Map<String, Value> {
    let mut out = response
        .stats
        .as_ref()
        .map(store_summary_to_json_map)
        .unwrap_or_default();
    out.insert(
        "memory_budget_bytes".to_owned(),
        json!(response.memory_budget_bytes),
    );
    out.insert("workspace_mode".to_owned(), json!(response.workspace_mode));
    out.insert("search_workers".to_owned(), json!(response.search_workers));
    out.insert("current_rss_kb".to_owned(), json!(response.current_rss_kb));
    out.insert("peak_rss_kb".to_owned(), json!(response.peak_rss_kb));
    out
}

fn status_response_to_json_map(response: &v1::StatusResponse) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("draining".to_owned(), json!(response.draining));
    out.insert(
        "active_connections".to_owned(),
        json!(response.active_connections),
    );
    out.insert(
        "active_mutations".to_owned(),
        json!(response.active_mutations),
    );
    out.insert(
        "publish_requested".to_owned(),
        json!(response.publish_requested),
    );
    out.insert(
        "mutations_paused".to_owned(),
        json!(response.mutations_paused),
    );
    out.insert(
        "publish_in_progress".to_owned(),
        json!(response.publish_in_progress),
    );
    out.insert(
        "active_index_clients".to_owned(),
        json!(response.active_index_clients),
    );
    out.insert(
        "active_index_sessions".to_owned(),
        json!(response.active_index_sessions),
    );
    out.insert("search_workers".to_owned(), json!(response.search_workers));
    out.insert(
        "memory_budget_bytes".to_owned(),
        json!(response.memory_budget_bytes),
    );
    out.insert("current_rss_kb".to_owned(), json!(response.current_rss_kb));
    out.insert("peak_rss_kb".to_owned(), json!(response.peak_rss_kb));
    out.insert("workspace_mode".to_owned(), json!(response.workspace_mode));
    if !response.published_root.is_empty() {
        out.insert(
            "published_root".to_owned(),
            Value::String(response.published_root.clone()),
        );
    }
    if !response.work_root.is_empty() {
        out.insert(
            "work_root".to_owned(),
            Value::String(response.work_root.clone()),
        );
    }
    if let Some(adaptive) = response.adaptive_publish.as_ref() {
        out.insert(
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
    }
    if let Some(index_session) = response.index_session.as_ref() {
        let mut index_map = Map::new();
        index_map.insert("active".to_owned(), json!(index_session.active));
        index_map.insert(
            "client_active".to_owned(),
            json!(index_session.client_active),
        );
        index_map.insert(
            "total_documents".to_owned(),
            json!(index_session.total_documents),
        );
        index_map.insert(
            "submitted_documents".to_owned(),
            json!(index_session.submitted_documents),
        );
        index_map.insert(
            "processed_documents".to_owned(),
            json!(index_session.processed_documents),
        );
        index_map.insert(
            "remaining_documents".to_owned(),
            json!(index_session.remaining_documents),
        );
        index_map.insert(
            "progress_percent".to_owned(),
            Value::from(index_session.progress_percent),
        );
        index_map.insert(
            "started_unix_ms".to_owned(),
            json!(index_session.started_unix_ms),
        );
        index_map.insert(
            "last_update_unix_ms".to_owned(),
            json!(index_session.last_update_unix_ms),
        );
        if let Some(profile) = index_session.server_insert_batch_profile.as_ref() {
            index_map.insert(
                "server_insert_batch_profile".to_owned(),
                Value::Object(insert_batch_profile_to_json_map(profile)),
            );
        }
        out.insert("index_session".to_owned(), Value::Object(index_map));
    }
    if let Some(startup) = response.startup.as_ref() {
        let startup_store = |value: &v1::StartupStoreSummary| {
            json!({
                "total_ms": value.total_ms,
                "opened_existing_shards": value.opened_existing_shards,
                "initialized_new_shards": value.initialized_new_shards,
                "doc_count": value.doc_count,
            })
        };
        out.insert(
            "startup".to_owned(),
            json!({
                "total_ms": startup.total_ms,
                "startup_cleanup_removed_roots": startup.startup_cleanup_removed_roots,
                "current": startup.current.as_ref().map(startup_store).unwrap_or(Value::Null),
                "work": startup.work.as_ref().map(startup_store).unwrap_or(Value::Null),
            }),
        );
    }
    if response.has_work {
        if let Some(work) = response.work.as_ref() {
            out.insert(
                "work".to_owned(),
                Value::Object(store_summary_to_json_map(work)),
            );
        }
    }
    if response.has_published {
        if let Some(published) = response.published.as_ref() {
            out.extend(store_summary_to_json_map(published));
        }
    }
    if let Some(publish) = response.publish.as_ref() {
        out.insert(
            "publish".to_owned(),
            json!({
                "pending": publish.pending,
                "eligible": publish.eligible,
                "blocked_reason": publish.blocked_reason,
                "trigger_mode": publish.trigger_mode,
                "trigger_reason": publish.trigger_reason,
                "idle_elapsed_ms": publish.idle_elapsed_ms,
                "idle_remaining_ms": publish.idle_remaining_ms,
                "work_buffer_estimated_documents": publish.work_buffer_estimated_documents,
                "work_buffer_estimated_input_bytes": publish.work_buffer_estimated_input_bytes,
                "work_buffer_document_threshold": publish.work_buffer_document_threshold,
                "work_buffer_input_bytes_threshold": publish.work_buffer_input_bytes_threshold,
                "work_buffer_rss_threshold_bytes": publish.work_buffer_rss_threshold_bytes,
                "current_rss_bytes": publish.current_rss_bytes,
                "pending_tier2_snapshot_shards": publish.pending_tier2_snapshot_shards,
                "index_backpressure_delay_ms": publish.index_backpressure_delay_ms,
                "index_backpressure_events_total": publish.index_backpressure_events_total,
                "index_backpressure_sleep_ms_total": publish.index_backpressure_sleep_ms_total,
                "last_publish_started_unix_ms": publish.last_publish_started_unix_ms,
                "last_publish_completed_unix_ms": publish.last_publish_completed_unix_ms,
                "last_publish_duration_ms": publish.last_publish_duration_ms,
                "last_publish_lock_wait_ms": publish.last_publish_lock_wait_ms,
                "last_publish_promote_work_ms": publish.last_publish_promote_work_ms,
                "last_publish_init_work_ms": publish.last_publish_init_work_ms,
                "last_publish_persisted_snapshot_shards": publish.last_publish_persisted_snapshot_shards,
                "last_publish_reused_work_stores": publish.last_publish_reused_work_stores,
                "publish_runs_total": publish.publish_runs_total,
            }),
        );
    }
    out
}

fn query_profile_from_proto(summary: Option<&v1::QueryProfileSummary>) -> CandidateQueryProfile {
    let Some(summary) = summary else {
        return CandidateQueryProfile::default();
    };
    CandidateQueryProfile {
        docs_scanned: summary.docs_scanned,
        metadata_loads: summary.metadata_loads,
        metadata_bytes: summary.metadata_bytes,
        tier1_bloom_loads: summary.tier1_bloom_loads,
        tier1_bloom_bytes: summary.tier1_bloom_bytes,
        tier2_bloom_loads: summary.tier2_bloom_loads,
        tier2_bloom_bytes: summary.tier2_bloom_bytes,
    }
}

fn prepared_query_profile_from_proto(
    summary: Option<&v1::PreparedQueryProfileSummary>,
) -> CandidatePreparedQueryProfile {
    let Some(summary) = summary else {
        return CandidatePreparedQueryProfile::default();
    };
    CandidatePreparedQueryProfile {
        impossible_query: summary.impossible_query,
        prepared_query_bytes: summary.prepared_query_bytes,
        prepared_pattern_plan_bytes: summary.prepared_pattern_plan_bytes,
        prepared_mask_cache_bytes: summary.prepared_mask_cache_bytes,
        pattern_count: summary.pattern_count,
        mask_cache_entries: summary.mask_cache_entries,
        fixed_literal_count: summary.fixed_literal_count,
        tier1_alternatives: summary.tier1_alternatives,
        tier2_alternatives: summary.tier2_alternatives,
        tier1_shift_variants: summary.tier1_shift_variants,
        tier2_shift_variants: summary.tier2_shift_variants,
        tier1_any_lane_alternatives: summary.tier1_any_lane_alternatives,
        tier2_any_lane_alternatives: summary.tier2_any_lane_alternatives,
        tier1_compacted_any_lane_alternatives: summary.tier1_compacted_any_lane_alternatives,
        tier2_compacted_any_lane_alternatives: summary.tier2_compacted_any_lane_alternatives,
        any_lane_variant_sets: summary.any_lane_variant_sets,
        compacted_any_lane_grams: summary.compacted_any_lane_grams,
        max_pattern_bytes: summary.max_pattern_bytes,
        max_pattern_id: summary
            .max_pattern_id
            .as_ref()
            .and_then(optional_string_to_option),
    }
}

#[cfg(test)]
mod tests {
    use super::{
        GrpcInsertFrameIter,
        v1::{PingRequest, SearchRequest},
    };

    #[test]
    fn generated_grpc_types_are_available() {
        let _ping = PingRequest {};
        let request = SearchRequest {
            yara_rule_source: "rule test { condition: true }".to_owned(),
            chunk_size: 128,
            include_external_ids: false,
            max_candidates_percent: 7.5,
            max_anchors_per_pattern: 16,
            force_tier1_only: false,
            allow_tier2_fallback: true,
        };
        assert!(request.yara_rule_source.contains("condition"));
    }

    #[test]
    fn grpc_insert_frame_iter_preserves_row_boundaries() {
        let rows = vec![b"abcdef".to_vec(), b"gh".to_vec()];
        let frames = GrpcInsertFrameIter::new(rows, 3).collect::<Vec<_>>();
        let payloads = frames
            .iter()
            .map(|frame| String::from_utf8_lossy(&frame.payload).into_owned())
            .collect::<Vec<_>>();
        assert_eq!(payloads, vec!["abc", "def", "gh", ""]);
        assert!(!frames[0].row_complete);
        assert!(frames[1].row_complete);
        assert!(frames[2].row_complete);
        assert!(frames[3].stream_complete);
    }

    #[test]
    fn grpc_insert_frame_iter_sends_stream_complete_for_empty_input() {
        let frames = GrpcInsertFrameIter::new(Vec::new(), 1024).collect::<Vec<_>>();
        assert_eq!(frames.len(), 1);
        assert!(frames[0].stream_complete);
        assert!(frames[0].payload.is_empty());
    }
}
