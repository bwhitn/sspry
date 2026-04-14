use std::time::Duration;

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

pub const DEFAULT_GRPC_INSERT_CHUNK_BYTES: usize = 8 * 1024 * 1024;

struct GrpcInsertFrameIter {
    rows: Vec<Vec<u8>>,
    chunk_bytes: usize,
    row_idx: usize,
    row_offset: usize,
    sent_stream_complete: bool,
}

impl GrpcInsertFrameIter {
    /// Creates a streaming frame iterator that chunks encoded insert rows into
    /// bounded gRPC payloads.
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

    /// Emits the next insert frame, preserving row boundaries and sending a
    /// final empty `stream_complete` frame once all rows are exhausted.
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

/// Normalizes a user-supplied gRPC address into an `http://` or `https://`
/// endpoint string accepted by `tonic`.
fn grpc_endpoint(addr: &str) -> String {
    if addr.starts_with("http://") || addr.starts_with("https://") {
        addr.to_owned()
    } else {
        format!("http://{addr}")
    }
}

/// Converts transport or runtime errors into the project's generic error type.
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
    pub rule_complete: bool,
    pub target_rule_name: String,
    pub truncated: bool,
    pub tier_used: String,
    pub query_profile: CandidateQueryProfile,
    pub prepared_query_profile: CandidatePreparedQueryProfile,
}

impl BlockingGrpcClient {
    /// Connects to the server with the default message-size limit.
    pub fn connect(addr: &str, timeout: Duration) -> Result<Self> {
        Self::connect_with_limits(addr, timeout, DEFAULT_MAX_REQUEST_BYTES)
    }

    /// Connects to the server, building a private Tokio runtime and applying
    /// explicit gRPC message-size limits.
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

    /// Updates the maximum payload size used when client-side insert rows are
    /// chunked into streaming frames.
    pub fn set_insert_chunk_bytes(&mut self, chunk_bytes: usize) {
        self.insert_chunk_bytes = chunk_bytes.max(1).min(self.max_message_bytes.max(1));
    }

    /// Calls the server `Ping` RPC and returns the response message.
    pub fn ping(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async { self.inner.ping(v1::PingRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    /// Calls the server `Stats` RPC and returns the raw protobuf response.
    pub fn stats(&mut self) -> Result<v1::StatsResponse> {
        let response = self
            .runtime
            .block_on(async { self.inner.stats(v1::StatsRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner())
    }

    /// Calls the server `Status` RPC and returns the raw protobuf response.
    pub fn status(&mut self) -> Result<v1::StatusResponse> {
        let response = self
            .runtime
            .block_on(async { self.inner.status(v1::StatusRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner())
    }

    /// Requests graceful server shutdown and returns the server's message.
    pub fn shutdown(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async { self.inner.shutdown(v1::ShutdownRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    /// Triggers a publish cycle on the server and returns the resulting status
    /// message.
    pub fn publish(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async { self.inner.publish(v1::PublishRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    /// Starts an index session and returns the server-provided status message.
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

    /// Registers an indexing client and returns its server-assigned client ID
    /// together with the lease timeout in milliseconds.
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

    /// Renews the lease for an active indexing client.
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

    /// Reports current index-session progress counters to the server.
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

    /// Ends the active index session and returns the server's completion
    /// message.
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

    /// Ends a previously registered indexing client lease.
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

    /// Deletes one candidate document by SHA-256 and maps the protobuf reply
    /// into the local response type.
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

    /// Streams search frames from the server and invokes the supplied callback
    /// for each mapped local frame.
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
                    rule_complete: frame.rule_complete,
                    target_rule_name: frame.target_rule_name,
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

    /// Inserts binary rows with the client's currently configured chunk size.
    pub fn insert_binary_rows(&mut self, rows: Vec<Vec<u8>>) -> Result<v1::InsertSummary> {
        self.insert_binary_rows_with_chunk(rows, self.insert_chunk_bytes)
    }

    /// Streams encoded insert rows to the server using an explicit per-frame
    /// chunk size.
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

/// Converts an optional protobuf query-profile summary into the local struct
/// used by the CLI and tests.
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

/// Converts an optional protobuf prepared-query profile into the local summary
/// type used by higher layers.
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
            .and_then(|value| value.has_value.then(|| value.value.clone())),
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
            target_rule_name: "test".to_owned(),
            chunk_size: 128,
            include_external_ids: false,
            max_candidates_percent: 10.0,
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
