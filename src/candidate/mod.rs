pub mod bloom;
pub mod cache;
pub mod features;
pub mod filter_policy;
pub mod gram_wire;
pub mod grams;
pub mod query_plan;
pub mod store;

pub use bloom::{BloomFilter, bloom_positions};
pub use cache::BoundedCache;
pub use features::{
    DocumentFeatures, HLL_DEFAULT_PRECISION, estimate_unique_grams_for_size_hll,
    estimate_unique_grams4_hll, estimate_unique_grams5_hll, estimate_unique_tier2_grams_hll,
    iter_grams_from_bytes_exact_u64, iter_grams4_from_bytes, iter_grams5_from_bytes,
    iter_tier2_grams_from_bytes, scan_file_features, scan_file_features_with_gram_sizes,
    scan_file_features_with_tier2_gram_size, select_tier1_grams,
};
pub use grams::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, exact_gram_to_le_bytes,
    pack_exact_gram,
};
pub const DEFAULT_SECONDARY_GRAM_SIZE: usize = DEFAULT_TIER2_GRAM_SIZE;
pub use filter_policy::{
    choose_filter_bytes_for_file_size, derive_bloom_hash_count, derive_document_bloom_hash_count,
    normalize_filter_policy,
};
pub use gram_wire::{
    decode_grams_delta_u32, decode_grams_delta_u64, encode_grams_delta_u32, encode_grams_delta_u64,
};
pub use query_plan::{
    CompiledQueryPlan, PatternPlan, QueryNode, compile_query_plan, compile_query_plan_from_file,
    compile_query_plan_from_file_with_gram_sizes,
    compile_query_plan_from_file_with_tier2_gram_size, compile_query_plan_with_gram_sizes,
    compile_query_plan_with_tier2_gram_size, normalize_max_candidates,
};
pub use store::{
    CandidateConfig, CandidateDeleteResult, CandidateInsertResult, CandidateQueryResult,
    CandidateStats, CandidateStore, candidate_shard_index, candidate_shard_manifest_path,
    candidate_shard_root, read_candidate_shard_count, write_candidate_shard_count,
};
