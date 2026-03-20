pub mod bloom;
pub mod cache;
pub mod features;
pub mod filter_policy;
pub mod grams;
pub mod metadata;
pub mod query_plan;
pub mod store;

pub use bloom::{BloomFilter, bloom_positions};
pub use cache::BoundedCache;
pub use features::{
    DocumentFeatures, HLL_DEFAULT_PRECISION, estimate_unique_grams_for_size_hll,
    estimate_unique_grams_pair_hll, scan_file_features_bloom_only_with_gram_sizes,
};
pub use filter_policy::{
    choose_filter_bytes_for_file_size, derive_bloom_hash_count, derive_document_bloom_hash_count,
    normalize_tier1_filter_class_bytes,
};
pub use grams::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, pack_exact_gram};
pub use metadata::{
    extract_compact_document_metadata, metadata_field_is_boolean, metadata_field_is_integer,
    metadata_field_matches_eq, normalize_query_metadata_field,
};
pub use query_plan::{
    CompiledQueryPlan, PatternPlan, QueryNode, compile_query_plan_from_file_with_gram_sizes,
    compile_query_plan_with_gram_sizes, normalize_max_candidates,
};
pub use store::{
    CandidateConfig, CandidateDeleteResult, CandidateInsertResult, CandidateQueryProfile,
    CandidateQueryResult, CandidateStats, CandidateStore,
    DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES, candidate_shard_index,
    candidate_shard_manifest_path, candidate_shard_root, read_candidate_shard_count,
    write_candidate_shard_count,
};
