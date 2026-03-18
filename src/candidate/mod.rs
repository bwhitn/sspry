pub mod bloom;
pub mod cache;
pub mod features;
pub mod filter_policy;
pub mod gram_wire;
pub mod grams;
pub mod metadata;
pub mod query_plan;
pub mod store;

pub use bloom::{BloomFilter, bloom_positions};
pub use cache::BoundedCache;
pub use features::{
    DocumentFeatures, HLL_DEFAULT_PRECISION, estimate_unique_grams_for_size_hll,
    estimate_unique_grams_pair_hll, scan_file_features, scan_file_features_with_gram_sizes,
};
pub use filter_policy::{
    choose_filter_bytes_for_file_size, derive_bloom_hash_count, derive_document_bloom_hash_count,
    normalize_filter_policy,
};
pub use gram_wire::{
    decode_grams_delta_u32, decode_grams_delta_u64, encode_grams_delta_u32, encode_grams_delta_u64,
};
pub use grams::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, exact_gram_to_le_bytes,
    pack_exact_gram,
};
pub use metadata::{
    extract_compact_document_metadata, metadata_field_is_boolean, metadata_field_is_integer,
    metadata_field_matches_eq, normalize_query_metadata_field,
};
pub use query_plan::{
    CompiledQueryPlan, PatternPlan, QueryNode, compile_query_plan, compile_query_plan_from_file,
    compile_query_plan_from_file_with_gram_sizes,
    compile_query_plan_from_file_with_tier2_gram_size, compile_query_plan_with_gram_sizes,
    compile_query_plan_with_tier2_gram_size, normalize_max_candidates,
};
pub use store::{
    CandidateConfig, CandidateDeleteResult, CandidateInsertResult, CandidateQueryResult,
    CandidateStats, CandidateStore, DEFAULT_TIER2_SUPERBLOCK_SUMMARY_CAP_BYTES,
    candidate_shard_index, candidate_shard_manifest_path, candidate_shard_root,
    read_candidate_shard_count, write_candidate_shard_count,
};
