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
};
pub use grams::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, pack_exact_gram};
pub use metadata::{
    MetadataCompareOp, PE_ENTRY_POINT_PREFIX_BYTES, extract_compact_document_metadata,
    extract_compact_document_metadata_with_entropy, metadata_field_is_boolean,
    metadata_field_is_float, metadata_field_is_integer, metadata_field_matches_compare,
    metadata_field_matches_compare_f32, metadata_field_matches_eq, metadata_fields_compare,
    metadata_file_prefix_8, metadata_pe_entry_point_prefix, normalize_query_metadata_field,
};
pub use query_plan::{
    CompiledQueryPlan, PatternPlan, QueryNode, RuleCheckFileReport, RuleCheckIssue,
    RuleCheckReport, RuleCheckRuleReport, RuleCheckSeverity, RuleCheckStatus,
    compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source,
    compile_query_plan_from_file_with_gram_sizes,
    compile_query_plan_from_file_with_gram_sizes_and_identity_source,
    compile_query_plan_with_gram_sizes, compile_query_plan_with_gram_sizes_and_identity_source,
    load_rule_file_with_includes, normalize_max_candidates, resolve_max_candidates,
    rule_check_all_from_file_with_gram_sizes,
    rule_check_all_from_file_with_gram_sizes_and_identity_source, rule_check_all_with_gram_sizes,
    rule_check_all_with_gram_sizes_and_identity_source, rule_check_from_file_with_gram_sizes,
    rule_check_from_file_with_gram_sizes_and_identity_source, rule_check_with_gram_sizes,
    rule_check_with_gram_sizes_and_identity_source, search_target_rule_names,
};
pub use store::{
    CandidateConfig, CandidateDeleteResult, CandidateInsertResult, CandidateQueryProfile,
    CandidateQueryResult, CandidateStats, CandidateStore, DEFAULT_TIER1_FILTER_TARGET_FP,
    DEFAULT_TIER2_FILTER_TARGET_FP, candidate_shard_index, candidate_shard_manifest_path,
    candidate_shard_root, read_candidate_shard_count, write_candidate_shard_count,
};
