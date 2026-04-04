use std::time::Duration;

use serde_json::{Map, Value};
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
            .max_decoding_message_size(DEFAULT_MAX_REQUEST_BYTES)
            .max_encoding_message_size(DEFAULT_MAX_REQUEST_BYTES);
        Ok(Self { runtime, inner })
    }

    pub fn ping(&mut self) -> Result<String> {
        let response = self
            .runtime
            .block_on(async { self.inner.ping(v1::PingRequest {}).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner().message)
    }

    pub fn stats_json(&mut self) -> Result<Map<String, Value>> {
        let response = self
            .runtime
            .block_on(async { self.inner.stats(v1::StatsRequest {}).await })
            .map_err(tonic_error)?;
        serde_json::from_str(&response.into_inner().json).map_err(SspryError::from)
    }

    pub fn status_json(&mut self) -> Result<Map<String, Value>> {
        let response = self
            .runtime
            .block_on(async { self.inner.status(v1::StatusRequest {}).await })
            .map_err(tonic_error)?;
        serde_json::from_str(&response.into_inner().json).map_err(SspryError::from)
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
                let query_profile = if frame.query_profile_json.is_empty() {
                    CandidateQueryProfile::default()
                } else {
                    serde_json::from_str(&frame.query_profile_json)?
                };
                let prepared_query_profile = if frame.prepared_query_profile_json.is_empty() {
                    CandidatePreparedQueryProfile::default()
                } else {
                    serde_json::from_str(&frame.prepared_query_profile_json)?
                };
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

    pub fn insert_binary_payload(
        &mut self,
        payload: &[u8],
        chunk_bytes: usize,
    ) -> Result<v1::InsertSummary> {
        let chunk_bytes = chunk_bytes.max(1);
        let chunks = if payload.is_empty() {
            vec![v1::InsertChunk {
                payload: Vec::new(),
                final_chunk: true,
            }]
        } else {
            payload
                .chunks(chunk_bytes)
                .enumerate()
                .map(|(idx, chunk)| v1::InsertChunk {
                    payload: chunk.to_vec(),
                    final_chunk: idx == (payload.len() - 1) / chunk_bytes,
                })
                .collect::<Vec<_>>()
        };
        let request_stream = tokio_stream::iter(chunks);
        let response = self
            .runtime
            .block_on(async { self.inner.insert_stream(request_stream).await })
            .map_err(tonic_error)?;
        Ok(response.into_inner())
    }
}

#[cfg(test)]
mod tests {
    use super::v1::{PingRequest, SearchRequest};

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
}
