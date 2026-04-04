pub mod v1 {
    tonic::include_proto!("sspry.v1");
}

pub const PROTOTYPE_BRANCH_NOTE: &str =
    "Parallel gRPC prototype surface. The custom RPC transport remains authoritative.";

#[cfg(test)]
mod tests {
    use super::v1::{PingRequest, SearchRequest, search_request::Query};

    #[test]
    fn generated_grpc_types_are_available() {
        let _ping = PingRequest {};
        let request = SearchRequest {
            query: Some(Query::YaraRuleSource(
                "rule test { condition: true }".to_owned(),
            )),
            chunk_size: 128,
            include_external_ids: false,
            max_candidates_percent: 7.5,
        };
        assert!(matches!(request.query, Some(Query::YaraRuleSource(_))));
    }
}
