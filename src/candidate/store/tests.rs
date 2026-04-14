use tempfile::tempdir;
use yara_x::{Compiler as YaraCompiler, Scanner as YaraScanner};

use crate::candidate::BloomFilter;
use crate::candidate::bloom::DEFAULT_BLOOM_POSITION_LANES;
use crate::candidate::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes, extract_compact_document_metadata,
    features::scan_file_features_bloom_only_with_gram_sizes,
    pack_exact_gram,
    query_plan::{
        compile_query_plan_with_gram_sizes, compile_query_plan_with_gram_sizes_and_identity_source,
    },
};

use super::*;

fn borrowed_bytes<'a>(bytes: &'a [u8]) -> Result<Cow<'a, [u8]>> {
    Ok(Cow::Borrowed(bytes))
}

fn yara_rule_matches_bytes(source: &str, bytes: &[u8]) -> bool {
    let mut compiler = YaraCompiler::new();
    compiler.add_source(source).expect("compile yara-x probe");
    let rules = compiler.build();
    let mut scanner = YaraScanner::new(&rules);
    scanner
        .scan(bytes)
        .expect("scan yara-x probe")
        .matching_rules()
        .next()
        .is_some()
}

struct Tier2AndMetadataOnlyOverrideGuard {
    previous: u8,
}

impl Drop for Tier2AndMetadataOnlyOverrideGuard {
    fn drop(&mut self) {
        EXPERIMENT_TIER2_AND_METADATA_ONLY_OVERRIDE.with(|value| value.set(self.previous));
    }
}

fn tier2_and_metadata_only_override(enabled: bool) -> Tier2AndMetadataOnlyOverrideGuard {
    let previous = EXPERIMENT_TIER2_AND_METADATA_ONLY_OVERRIDE.with(|value| {
        let previous = value.get();
        value.set(if enabled { 2 } else { 1 });
        previous
    });
    Tier2AndMetadataOnlyOverrideGuard { previous }
}

fn lane_bloom_bytes(filter_bytes: usize, bloom_hashes: usize, grams: &[u64]) -> Vec<u8> {
    let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
    for (idx, gram) in grams.iter().enumerate() {
        bloom
            .add_in_lane(
                *gram,
                idx % DEFAULT_BLOOM_POSITION_LANES,
                DEFAULT_BLOOM_POSITION_LANES,
            )
            .expect("add gram");
    }
    bloom.into_bytes()
}

#[test]
fn non_exact_patterns_use_any_lane_masks() {
    let grams = vec![
        pack_exact_gram(&[0x03, 0xf8, 0x0f, 0xb6]),
        pack_exact_gram(&[0x4f, 0x81, 0xcf, 0x00]),
    ];
    let filter_bytes = 64;
    let bloom_hashes = 3;
    let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
    bloom
        .add_in_lane(grams[0], 2, DEFAULT_BLOOM_POSITION_LANES)
        .expect("lane add first");
    bloom
        .add_in_lane(grams[1], 0, DEFAULT_BLOOM_POSITION_LANES)
        .expect("lane add second");
    let bytes = bloom.into_bytes();

    let pattern = PatternPlan {
        pattern_id: "$a".to_owned(),
        alternatives: vec![grams.clone()],
        tier2_alternatives: vec![Vec::new()],
        anchor_literals: vec![Vec::new()],
        fixed_literals: vec![Vec::new()],
        fixed_literal_wide: vec![false],
        fixed_literal_fullword: vec![false],
    };
    let plan = CompiledQueryPlan {
        patterns: vec![pattern.clone()],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$a".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 10.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let cache = build_pattern_mask_cache(
        &[pattern],
        &[(filter_bytes, bloom_hashes)],
        &[],
        DEFAULT_TIER1_GRAM_SIZE,
        DEFAULT_TIER2_GRAM_SIZE,
    )
    .expect("mask cache");
    let pattern_masks = cache.get("$a").expect("pattern masks");
    assert!(pattern_masks.tier1[0].shifts.is_empty());
    assert_eq!(pattern_masks.tier1[0].any_lane_values.len(), grams.len());

    let doc = CandidateDoc {
        doc_id: 0,
        sha256: String::new(),
        file_size: 0,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes: 0,
        tier2_bloom_hashes: 0,
        special_population: false,
        deleted: false,
    };
    let (mut inputs, load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &bytes, &[]);
    let outcome = evaluate_pattern(
        &plan.patterns[0],
        pattern_masks,
        &mut inputs,
        &mut load_tier1,
        &mut load_tier2,
        &plan,
    )
    .expect("evaluate pattern");
    drop(load_metadata);
    assert!(outcome.matched);
}

#[test]
fn ambiguous_exact_patterns_fall_back_to_any_lane_masks() {
    let gram = pack_exact_gram(b"abcd");
    let pattern = PatternPlan {
        pattern_id: "$a".to_owned(),
        alternatives: vec![vec![gram]],
        tier2_alternatives: vec![Vec::new()],
        anchor_literals: vec![b"abcdzzzzabcd".to_vec()],
        fixed_literals: vec![b"abcdzzzzabcd".to_vec()],
        fixed_literal_wide: vec![false],
        fixed_literal_fullword: vec![false],
    };
    let cache = build_pattern_mask_cache(
        &[pattern],
        &[(64, 3)],
        &[],
        DEFAULT_TIER1_GRAM_SIZE,
        DEFAULT_TIER2_GRAM_SIZE,
    )
    .expect("mask cache");
    let pattern_masks = cache.get("$a").expect("pattern masks");
    assert!(!pattern_masks.tier1[0].shifts.is_empty());
    assert!(pattern_masks.tier1[0].any_lane_values.is_empty());
}

#[test]
fn tier2_only_patterns_do_not_match_without_tier2_bloom_hit() {
    let pattern = PatternPlan {
        pattern_id: "$a".to_owned(),
        alternatives: vec![Vec::new()],
        tier2_alternatives: vec![vec![pack_exact_gram(b"To:!")]],
        anchor_literals: vec![b"To:!".to_vec()],
        fixed_literals: vec![b"To:!".to_vec()],
        fixed_literal_wide: vec![false],
        fixed_literal_fullword: vec![false],
    };
    let plan = CompiledQueryPlan {
        patterns: vec![pattern.clone()],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$a".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 10.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let cache = build_pattern_mask_cache(
        &[pattern],
        &[(64, 3)],
        &[(64, 3)],
        DEFAULT_TIER1_GRAM_SIZE,
        DEFAULT_TIER2_GRAM_SIZE,
    )
    .expect("mask cache");
    let pattern_masks = cache.get("$a").expect("pattern masks");
    let doc = CandidateDoc {
        doc_id: 0,
        sha256: String::new(),
        file_size: 0,
        filter_bytes: 64,
        bloom_hashes: 3,
        tier2_filter_bytes: 64,
        tier2_bloom_hashes: 3,
        special_population: false,
        deleted: false,
    };

    let (mut miss_inputs, _load_metadata, mut miss_tier1, mut miss_tier2) =
        prefetched_query_inputs(&doc, &[], &[], &[]);
    let miss = evaluate_pattern(
        &plan.patterns[0],
        pattern_masks,
        &mut miss_inputs,
        &mut miss_tier1,
        &mut miss_tier2,
        &plan,
    )
    .expect("evaluate miss");
    assert!(!miss.matched);

    let tier2_bloom = lane_bloom_bytes(64, 3, &[pack_exact_gram(b"To:!")]);
    let (mut hit_inputs, _load_metadata, mut hit_tier1, mut hit_tier2) =
        prefetched_query_inputs(&doc, &[], &[], &tier2_bloom);
    let hit = evaluate_pattern(
        &plan.patterns[0],
        pattern_masks,
        &mut hit_inputs,
        &mut hit_tier1,
        &mut hit_tier2,
        &plan,
    )
    .expect("evaluate hit");
    assert!(hit.matched);
    assert_eq!(hit.tiers.as_label(), "tier2");
}

fn prefetched_query_inputs<'a>(
    doc: &'a CandidateDoc,
    metadata_bytes: &'a [u8],
    tier1_bloom_bytes: &'a [u8],
    tier2_bloom_bytes: &'a [u8],
) -> (
    LazyDocQueryInputs<'a>,
    impl FnMut() -> Result<Cow<'a, [u8]>>,
    impl FnMut() -> Result<Cow<'a, [u8]>>,
    impl FnMut() -> Result<Cow<'a, [u8]>>,
) {
    (
        LazyDocQueryInputs::from_prefetched(
            doc,
            metadata_bytes,
            tier1_bloom_bytes,
            tier2_bloom_bytes,
        ),
        move || borrowed_bytes(metadata_bytes),
        move || borrowed_bytes(tier1_bloom_bytes),
        move || borrowed_bytes(tier2_bloom_bytes),
    )
}

#[cfg(test)]
fn evaluate_rule_against_file_blooms(
    rule_text: &str,
    file_path: &str,
    filter_bytes: usize,
    bloom_hashes: usize,
    tier2_filter_bytes: usize,
    tier2_bloom_hashes: usize,
    allow_tier2_fallback: bool,
) -> Result<MatchOutcome> {
    let plan = compile_query_plan_with_gram_sizes_and_identity_source(
        rule_text,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)?,
        Some("sha256"),
        16,
        false,
        allow_tier2_fallback,
        10_000,
    )?;
    let features = scan_file_features_bloom_only_with_gram_sizes(
        file_path,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)?,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes,
        tier2_bloom_hashes,
        64 * 1024,
        None,
    )?;
    let patterns = plan
        .patterns
        .iter()
        .map(|pattern| (pattern.pattern_id.clone(), pattern.clone()))
        .collect::<HashMap<_, _>>();
    let mask_cache = build_pattern_mask_cache(
        &plan.patterns,
        &[(filter_bytes, bloom_hashes)],
        &[(tier2_filter_bytes, tier2_bloom_hashes)],
        plan.tier1_gram_size,
        plan.tier2_gram_size,
    )?;
    let doc = CandidateDoc {
        doc_id: 0,
        sha256: hex::encode(features.sha256),
        file_size: features.file_size,
        filter_bytes,
        bloom_hashes,
        tier2_filter_bytes,
        tier2_bloom_hashes,
        special_population: features.special_population,
        deleted: false,
    };
    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(
            &doc,
            &[],
            &features.bloom_filter,
            &features.tier2_bloom_filter,
        );
    evaluate_node(
        &plan.root,
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &plan,
        0,
        &mut QueryEvalCache::default(),
    )
}

fn insert_primary(
    store: &mut CandidateStore,
    sha256: [u8; 32],
    file_size: u64,
    bloom_item_estimate: Option<usize>,
    bloom_hashes: Option<usize>,
    filter_bytes: usize,
    bloom_filter: &[u8],
    external_id: Option<String>,
) -> Result<CandidateInsertResult> {
    store.insert_document(
        sha256,
        file_size,
        bloom_item_estimate,
        bloom_hashes,
        None,
        None,
        filter_bytes,
        bloom_filter,
        0,
        &[],
        external_id,
    )
}

#[test]
fn legacy_store_meta_conversion_preserves_filter_targets() {
    let legacy = LegacyStoreMeta {
        version: 7,
        next_doc_id: 11,
        id_source: "md5".to_owned(),
        store_path: true,
        tier2_gram_size: 5,
        tier1_gram_size: 4,
        tier1_filter_target_fp: None,
        tier2_filter_target_fp: Some(0.18),
        filter_target_fp: Some(0.39),
        compaction_idle_cooldown_s: 12.5,
    };

    let forest = ForestMeta::from(&legacy);
    assert_eq!(forest.version, 7);
    assert_eq!(forest.id_source, "md5");
    assert!(forest.store_path);
    assert_eq!(forest.tier1_gram_size, 4);
    assert_eq!(forest.tier2_gram_size, 5);
    assert_eq!(forest.tier1_filter_target_fp, Some(0.39));
    assert_eq!(forest.tier2_filter_target_fp, Some(0.18));

    let local = StoreLocalMeta::from(&legacy);
    assert_eq!(local.version, 7);
    assert_eq!(local.next_doc_id, 11);
}

#[test]
#[ignore = "diagnostic on local corpus only"]
fn diagnostic_scanstrings_string_matches_bloom_path() {
    let rule = r#"
rule r {
  strings:
    $a = "$*@@@*$@@@$ *@@* $@@($*)@-$*@@$-*@@$*-@@(*$)@-*$@@*-$@@*$-@@-* $@-$ *@* $-@$ *-@$ -*@*- $@($ *)(* $)U"
  condition:
    $a
}
"#;
    let outcome = evaluate_rule_against_file_blooms(
            rule,
            "/root/pertest/data/extracted/2026-03-06/2c2caad15e5af13e6290b84f03b10f43b21ffc3dfdda0581fa24caa3450484f3.exe",
            4096,
            3,
            2048,
            3,
            true,
        )
        .expect("evaluate");
    assert!(outcome.matched);
}

#[test]
fn borrowed_bytes_returns_borrowed_slice() {
    let bytes = b"borrowed";
    let borrowed = borrowed_bytes(bytes).expect("borrowed bytes");
    assert!(matches!(borrowed, Cow::Borrowed(_)));
    assert_eq!(borrowed.as_ref(), bytes);
}

#[test]
fn evaluate_rule_against_file_blooms_matches_simple_literal_rule() {
    let tmp = tempdir().expect("tmp");
    let sample = tmp.path().join("sample.bin");
    fs::write(&sample, b"xxABCDyy").expect("sample");
    let outcome = evaluate_rule_against_file_blooms(
        r#"
rule r {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
        sample.to_str().expect("sample path"),
        1024,
        7,
        1024,
        7,
        true,
    )
    .expect("evaluate");
    assert!(outcome.matched);
}

#[test]
#[ignore = "diagnostic on local corpus only"]
fn diagnostic_asyncrat_msg_pack_matches_bloom_path() {
    let rule = r#"
rule r {
  strings:
    $a = "(ext8,ext16,ex32) type $c7,$c8,$c9" wide
  condition:
    $a
}
"#;
    let tier1_only = evaluate_rule_against_file_blooms(
            rule,
            "/root/pertest/data/extracted/2026-02-28/5d3d41bb883bc29040f1ac52731dcdd287ca069caa720493a956d7ed635b2383.exe",
            4096,
            3,
            2048,
            3,
            false,
        )
        .expect("evaluate");
    let tier1_and_tier2 = evaluate_rule_against_file_blooms(
            rule,
            "/root/pertest/data/extracted/2026-02-28/5d3d41bb883bc29040f1ac52731dcdd287ca069caa720493a956d7ed635b2383.exe",
            4096,
            3,
            2048,
            3,
            true,
        )
        .expect("evaluate");
    assert!(
        tier1_only.matched,
        "tier1-only path should match: {:?}",
        tier1_only
    );
    assert!(
        tier1_and_tier2.matched,
        "tier1+tier2 path should now match: {:?}",
        tier1_and_tier2
    );
}

#[test]
fn insert_query_delete_roundtrip() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let bloom_hashes = DEFAULT_BLOOM_HASHES;
    let result = insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        None,
        filter_bytes,
        &lane_bloom_bytes(
            filter_bytes,
            bloom_hashes,
            &[pack_exact_gram(b"ABC"), pack_exact_gram(b"BCD")],
        ),
        Some("doc-1".to_owned()),
    )
    .expect("insert");
    assert_eq!(result.status, "inserted");

    let plan = compile_query_plan_with_gram_sizes(
        r#"
rule q {
  strings:
    $a = "ABC"
  condition:
    $a
}
"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
        8,
        true,
        true,
        100_000,
    )
    .expect("plan");
    let query = store.query_candidates(&plan, 0, 128).expect("query");
    assert_eq!(query.sha256, vec![hex::encode([0x11; 32])]);

    let deleted = store
        .delete_document(&hex::encode([0x11; 32]))
        .expect("delete");
    assert_eq!(deleted.status, "deleted");

    let query_after = store.query_candidates(&plan, 0, 128).expect("query");
    assert!(query_after.sha256.is_empty());

    let reopened = CandidateStore::open(root).expect("open");
    assert_eq!(reopened.stats().deleted_doc_count, 1);
}

#[test]
fn whole_file_identity_queries_use_direct_lookup() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let bloom_hashes = DEFAULT_BLOOM_HASHES;
    insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        None,
        filter_bytes,
        &lane_bloom_bytes(filter_bytes, bloom_hashes, &[0x4443_4241]),
        Some("doc-1".to_owned()),
    )
    .expect("insert first");
    insert_primary(
        &mut store,
        [0x22; 32],
        8,
        None,
        None,
        filter_bytes,
        &lane_bloom_bytes(filter_bytes, bloom_hashes, &[0x4443_4241]),
        Some("doc-2".to_owned()),
    )
    .expect("insert second");

    let plan = compile_query_plan_with_gram_sizes_and_identity_source(
        r#"
rule q {
  condition:
    hash.sha256(0, filesize) == "1111111111111111111111111111111111111111111111111111111111111111"
}
"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
        Some("sha256"),
        8,
        false,
        true,
        100_000,
    )
    .expect("plan");
    let query = store.query_candidates(&plan, 0, 128).expect("query");
    assert_eq!(query.sha256, vec![hex::encode([0x11; 32])]);
    assert_eq!(query.query_profile.docs_scanned, 1);
    assert_eq!(query.query_profile.tier1_bloom_loads, 0);
    assert_eq!(query.query_profile.tier2_bloom_loads, 0);
}

#[test]
fn compaction_reclaims_deleted_docs_and_storage() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            compaction_idle_cooldown_s: 0.0,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
    bloom.add(0x4443_4241).expect("add gram");
    let bloom_bytes = bloom.into_bytes();

    insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        Some("live".to_owned()),
    )
    .expect("insert live");
    insert_primary(
        &mut store,
        [0x22; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        Some("deleted".to_owned()),
    )
    .expect("insert deleted");
    store
        .delete_document(&hex::encode([0x22; 32]))
        .expect("delete");

    let size_before = dir_size(&root);
    let deleted_bytes_before = store.deleted_storage_bytes();
    assert!(deleted_bytes_before > 0);

    let snapshot = store
        .prepare_compaction_snapshot(true)
        .expect("snapshot")
        .expect("snapshot available");
    let compacted_root = compaction_work_root(&root, "test-compact");
    write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");
    let result = store
        .apply_compaction_snapshot(&snapshot, &compacted_root)
        .expect("apply compaction")
        .expect("compaction applied");

    assert_eq!(result.reclaimed_docs, 1);
    assert_eq!(store.stats().compaction_generation, 2);
    assert_eq!(store.stats().retired_generation_count, 1);
    assert_eq!(store.stats().doc_count, 1);
    assert_eq!(store.stats().deleted_doc_count, 0);
    assert_eq!(store.deleted_storage_bytes(), 0);
    assert!(dir_size(&root) < size_before);
    let retired_root = retired_generation_root(&root, 1);
    assert!(retired_root.exists());

    let reopened = CandidateStore::open(&root).expect("reopen");
    assert_eq!(reopened.stats().compaction_generation, 2);
    assert_eq!(reopened.stats().retired_generation_count, 1);
    assert_eq!(reopened.stats().doc_count, 1);
    assert_eq!(reopened.stats().deleted_doc_count, 0);
}

#[test]
fn reopen_normalizes_next_doc_id_after_deferred_meta_persist() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            compaction_idle_cooldown_s: 0.0,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let mut bloom_a = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom a");
    bloom_a.add(0x4443_4241).expect("add gram a");
    let inserted_a = store
        .insert_document(
            [0x11; 32],
            8,
            Some(1),
            Some(DEFAULT_BLOOM_HASHES),
            Some(0),
            Some(0),
            filter_bytes,
            &bloom_a.into_bytes(),
            filter_bytes,
            &[],
            None,
        )
        .expect("insert a");
    assert_eq!(inserted_a.doc_id, 1);

    let mut reopened = CandidateStore::open(&root).expect("reopen");
    let mut bloom_b = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom b");
    bloom_b.add(0x5A59_5857).expect("add gram b");
    let inserted_b = reopened
        .insert_document(
            [0x22; 32],
            8,
            Some(1),
            Some(DEFAULT_BLOOM_HASHES),
            Some(0),
            Some(0),
            filter_bytes,
            &bloom_b.into_bytes(),
            filter_bytes,
            &[],
            None,
        )
        .expect("insert b");
    assert_eq!(inserted_b.doc_id, 2);
}

#[test]
fn retired_generation_gc_removes_retired_root_and_updates_manifest() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            compaction_idle_cooldown_s: 0.0,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
    bloom.add(0x4443_4241).expect("add gram");
    let bloom_bytes = bloom.into_bytes();

    insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        Some("live".to_owned()),
    )
    .expect("insert live");
    insert_primary(
        &mut store,
        [0x22; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        Some("deleted".to_owned()),
    )
    .expect("insert deleted");
    store
        .delete_document(&hex::encode([0x22; 32]))
        .expect("delete");

    let snapshot = store
        .prepare_compaction_snapshot(true)
        .expect("snapshot")
        .expect("snapshot available");
    let compacted_root = compaction_work_root(&root, "test-compact");
    write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");
    store
        .apply_compaction_snapshot(&snapshot, &compacted_root)
        .expect("apply compaction")
        .expect("compaction applied");

    let retired_root = retired_generation_root(&root, 1);
    assert!(retired_root.exists());
    assert_eq!(store.stats().retired_generation_count, 1);

    let removed = store
        .garbage_collect_retired_generations()
        .expect("garbage collect retired generations");
    assert_eq!(removed, 1);
    assert!(!retired_root.exists());
    assert_eq!(store.stats().retired_generation_count, 0);

    let reopened = CandidateStore::open(&root).expect("reopen");
    assert_eq!(reopened.stats().retired_generation_count, 0);
    assert_eq!(reopened.stats().compaction_generation, 2);
}

#[test]
fn compaction_manifest_helpers_roundtrip_and_force_init_cleans_retired_roots() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let manifest_path = shard_compaction_manifest_path(&root);
    let retired_root = retired_generation_root(&root, 7);

    let default_manifest = ensure_shard_compaction_manifest(&root).expect("ensure manifest");
    assert_eq!(default_manifest.current_generation, 1);
    assert!(manifest_path.exists());

    let manifest = ShardCompactionManifest {
        current_generation: 7,
        retired_roots: vec![
            retired_root
                .file_name()
                .expect("retired file name")
                .to_string_lossy()
                .into_owned(),
        ],
    };
    fs::create_dir_all(&retired_root).expect("create retired root");
    write_shard_compaction_manifest(&root, &manifest).expect("write manifest");
    let roundtrip = read_shard_compaction_manifest(&root).expect("read manifest");
    assert_eq!(roundtrip.current_generation, 7);
    assert_eq!(roundtrip.retired_roots, manifest.retired_roots);

    let reopened = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("force init");
    assert_eq!(reopened.stats().compaction_generation, 1);
    assert_eq!(reopened.stats().retired_generation_count, 0);
    assert!(!retired_root.exists());
    let reset_manifest = read_shard_compaction_manifest(&root).expect("read reset manifest");
    assert_eq!(reset_manifest.current_generation, 1);
    assert!(reset_manifest.retired_roots.is_empty());
}

#[test]
fn invalid_compaction_manifest_is_rejected() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let manifest_path = shard_compaction_manifest_path(&root);
    fs::write(&manifest_path, b"{not-json").expect("write invalid manifest");
    let err = read_shard_compaction_manifest(&root).expect_err("invalid manifest should fail");
    assert!(
        err.to_string()
            .contains("Invalid candidate compaction manifest"),
        "unexpected error: {err}"
    );
}

#[test]
fn compaction_swap_aborts_when_store_mutates() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            compaction_idle_cooldown_s: 0.0,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
    bloom.add(0x4443_4241).expect("add gram");
    let bloom_bytes = bloom.into_bytes();

    insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        None,
    )
    .expect("insert one");
    insert_primary(
        &mut store,
        [0x22; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        None,
    )
    .expect("insert two");
    store
        .delete_document(&hex::encode([0x22; 32]))
        .expect("delete two");

    let snapshot = store
        .prepare_compaction_snapshot(true)
        .expect("snapshot")
        .expect("snapshot available");
    let compacted_root = compaction_work_root(&root, "test-compact");
    write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");

    insert_primary(
        &mut store,
        [0x33; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        None,
    )
    .expect("insert third");

    assert!(
        store
            .apply_compaction_snapshot(&snapshot, &compacted_root)
            .expect("apply compaction")
            .is_none()
    );
    assert_eq!(store.stats().doc_count, 2);
    assert_eq!(store.stats().deleted_doc_count, 1);
    let _ = fs::remove_dir_all(compacted_root);
}

#[test]
fn compaction_snapshot_requires_deleted_docs_and_respects_cooldown() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            compaction_idle_cooldown_s: 60.0,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let mut bloom = BloomFilter::new(filter_bytes, DEFAULT_BLOOM_HASHES).expect("bloom");
    bloom.add(0x4443_4241).expect("add gram");
    let bloom_bytes = bloom.into_bytes();

    assert!(
        store
            .prepare_compaction_snapshot(false)
            .expect("snapshot without deletes")
            .is_none()
    );

    insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom_bytes,
        None,
    )
    .expect("insert");
    store
        .delete_document(&hex::encode([0x11; 32]))
        .expect("delete");

    assert!(
        store
            .prepare_compaction_snapshot(false)
            .expect("cooldown snapshot")
            .is_none()
    );
    assert!(
        store
            .prepare_compaction_snapshot(true)
            .expect("forced snapshot")
            .is_some()
    );
}

#[test]
fn target_fp_derives_effective_bloom_hash_count() {
    let tmp = tempdir().expect("tmp");
    let store = CandidateStore::init(
        CandidateConfig {
            root: tmp.path().join("candidate_db"),
            filter_target_fp: Some(0.25),
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");
    let bloom_hashes = store.resolve_bloom_hashes_for_document(512 * 1024, Some(100_000), Some(7));
    assert_eq!(bloom_hashes, 16);
    assert_eq!(store.stats().tier1_filter_target_fp, Some(0.25));
    assert_eq!(store.stats().tier2_filter_target_fp, Some(0.25));
}

#[test]
fn external_ids_follow_active_docs() {
    let tmp = tempdir().expect("tmp");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: tmp.path().join("candidate_db"),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let small_filter_bytes = 64 * 1024;
    let large_filter_bytes = 256 * 1024;
    let mut small = BloomFilter::new(small_filter_bytes, 1).expect("small bloom");
    small
        .add(u64::from(u32::from_le_bytes(*b"ABCD")))
        .expect("add small");
    let large = BloomFilter::new(large_filter_bytes, 1).expect("large bloom");

    let sha1 = [0x11; 32];
    let sha2 = [0x22; 32];
    let sha3 = [0x33; 32];

    insert_primary(
        &mut store,
        sha1,
        64 * 1024,
        None,
        None,
        small_filter_bytes,
        &small.clone().into_bytes(),
        Some("doc-small".to_owned()),
    )
    .expect("insert one");
    insert_primary(
        &mut store,
        sha2,
        256 * 1024,
        None,
        None,
        large_filter_bytes,
        &large.clone().into_bytes(),
        Some("doc-large".to_owned()),
    )
    .expect("insert two");
    insert_primary(
        &mut store,
        sha3,
        256 * 1024,
        None,
        None,
        large_filter_bytes,
        &large.into_bytes(),
        Some("doc-deleted".to_owned()),
    )
    .expect("insert three");
    store
        .delete_document(&hex::encode(sha3))
        .expect("delete third");

    let external_ids = store.external_ids_for_sha256(&[
        hex::encode(sha1),
        hex::encode(sha2),
        hex::encode(sha3),
        "ff".repeat(32),
    ]);
    assert_eq!(
        external_ids,
        vec![
            Some("doc-small".to_owned()),
            Some("doc-large".to_owned()),
            None,
            None,
        ]
    );
    let doc_ids = store.doc_ids_for_sha256(&[
        hex::encode(sha1),
        hex::encode(sha2),
        hex::encode(sha3),
        "ff".repeat(32),
    ]);
    assert_eq!(doc_ids, vec![Some(1), Some(2), None, None]);
}

#[test]
fn validation_and_open_error_paths_work() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");

    CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");
    assert!(
        CandidateStore::init(
            CandidateConfig {
                root: root.clone(),
                ..CandidateConfig::default()
            },
            false
        )
        .expect_err("existing store")
        .to_string()
        .contains("already exists")
    );

    assert!(
        validate_config(&CandidateConfig {
            root: root.clone(),
            id_source: "filepath".to_owned(),
            ..CandidateConfig::default()
        })
        .expect_err("id source")
        .to_string()
        .contains("id_source")
    );
    assert!(
        validate_config(&CandidateConfig {
            root: root.clone(),
            filter_target_fp: Some(1.0),
            ..CandidateConfig::default()
        })
        .expect_err("target fp")
        .to_string()
        .contains("filter_target_fp")
    );
    assert_eq!(
        normalize_sha256_hex(&format!("  {}  ", "AB".repeat(32))).expect("normalize"),
        "ab".repeat(32)
    );
    assert!(
        normalize_sha256_hex("not-a-sha")
            .expect_err("invalid sha")
            .to_string()
            .contains("64 hexadecimal")
    );

    let open_root = tmp.path().join("open_checks");
    fs::create_dir_all(&open_root).expect("open root");
    fs::write(meta_path(&open_root), b"{").expect("bad meta");
    assert!(
        CandidateStore::open(&open_root)
            .expect_err("invalid meta")
            .to_string()
            .contains("Invalid candidate metadata")
    );

    let bad_version = LegacyStoreMeta {
        version: STORE_VERSION + 1,
        ..LegacyStoreMeta::default()
    };
    fs::write(
        meta_path(&open_root),
        serde_json::to_vec_pretty(&bad_version).expect("version json"),
    )
    .expect("write version");
    assert!(
        CandidateStore::open(&open_root)
            .expect_err("unsupported version")
            .to_string()
            .contains("Unsupported candidate store version")
    );

    fs::write(
        meta_path(&open_root),
        serde_json::to_vec_pretty(&LegacyStoreMeta::default()).expect("meta json"),
    )
    .expect("write good meta");
    let opened = CandidateStore::open(&open_root).expect("open without docs");
    assert_eq!(opened.stats().doc_count, 0);
}

#[test]
fn binary_sidecars_roundtrip_and_reopen() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let file_size = 1234;
    let gram_count = 2;
    let filter_bytes = store
        .resolve_filter_bytes_for_file_size(file_size, Some(gram_count))
        .expect("filter bytes");
    let bloom_hashes =
        store.resolve_bloom_hashes_for_document(filter_bytes, Some(gram_count), None);
    let mut bloom_one = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom one");
    bloom_one.add(u64::from(0x0201_u32)).expect("add bloom one");
    let mut bloom_two = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom two");
    bloom_two.add(u64::from(0x0403_u32)).expect("add bloom two");

    insert_primary(
        &mut store,
        [0x11; 32],
        file_size,
        Some(gram_count),
        Some(bloom_hashes),
        filter_bytes,
        &bloom_one.into_bytes(),
        Some("doc-one".to_owned()),
    )
    .expect("insert one");
    insert_primary(
        &mut store,
        [0x22; 32],
        file_size,
        Some(gram_count),
        Some(bloom_hashes),
        filter_bytes,
        &bloom_two.into_bytes(),
        None,
    )
    .expect("insert two");
    store
        .delete_document(&hex::encode([0x22; 32]))
        .expect("delete two");

    let (loaded_docs, loaded_rows, loaded_tier2_rows) =
        load_candidate_binary_store(&root).expect("load binary");
    assert_eq!(loaded_docs.len(), 2);
    assert_eq!(loaded_rows.len(), 2);
    assert_eq!(loaded_tier2_rows.len(), 2);
    assert_eq!(loaded_docs[0].doc_id, 1);
    assert!(loaded_docs[1].deleted);

    let reopened = CandidateStore::open(&root).expect("reopen");
    assert_eq!(
        reopened.external_ids_for_sha256(&[hex::encode([0x11; 32])]),
        vec![Some("doc-one".to_owned())]
    );
}

#[test]
fn binary_sidecars_reject_corrupt_lengths_and_offsets() {
    let tmp = tempdir().expect("tmp");
    let invalid_len_root = tmp.path().join("invalid_len_root");
    let mut invalid_len_store = CandidateStore::init(
        CandidateConfig {
            root: invalid_len_root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init invalid len root");
    let file_size = 1234;
    let gram_count = 2;
    let filter_bytes = invalid_len_store
        .resolve_filter_bytes_for_file_size(file_size, Some(gram_count))
        .expect("filter bytes");
    let bloom_hashes =
        invalid_len_store.resolve_bloom_hashes_for_document(filter_bytes, Some(gram_count), None);
    let mut bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("bloom");
    bloom.add(u64::from(10_u32)).expect("add gram");
    insert_primary(
        &mut invalid_len_store,
        [0x11; 32],
        file_size,
        Some(gram_count),
        Some(bloom_hashes),
        filter_bytes,
        &bloom.into_bytes(),
        Some("ok".to_owned()),
    )
    .expect("insert invalid len root");
    fs::write(sha_by_docid_path(&invalid_len_root), [0u8; 31]).expect("truncate sha");
    assert!(
        load_candidate_binary_store(&invalid_len_root)
            .expect_err("invalid binary len")
            .to_string()
            .contains("Invalid candidate binary document state")
    );

    let mismatch_root = tmp.path().join("mismatch_root");
    let mut mismatch_store = CandidateStore::init(
        CandidateConfig {
            root: mismatch_root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init mismatch root");
    let mut mismatch_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("mismatch");
    mismatch_bloom
        .add(u64::from(20_u32))
        .expect("add mismatch gram");
    insert_primary(
        &mut mismatch_store,
        [0x11; 32],
        file_size,
        Some(gram_count),
        Some(bloom_hashes),
        filter_bytes,
        &mismatch_bloom.into_bytes(),
        Some("ok".to_owned()),
    )
    .expect("insert mismatch root");
    fs::write(sha_by_docid_path(&mismatch_root), vec![0u8; 64]).expect("mismatch sha bytes");
    assert!(
        load_candidate_binary_store(&mismatch_root)
            .expect_err("mismatch state")
            .to_string()
            .contains("Mismatched candidate binary document state")
    );

    let invalid_bloom_root = tmp.path().join("invalid_bloom_root");
    let mut invalid_bloom_store = CandidateStore::init(
        CandidateConfig {
            root: invalid_bloom_root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init invalid bloom root");
    let mut invalid_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("invalid");
    invalid_bloom
        .add(u64::from(30_u32))
        .expect("add invalid gram");
    insert_primary(
        &mut invalid_bloom_store,
        [0x11; 32],
        file_size,
        Some(gram_count),
        Some(bloom_hashes),
        filter_bytes,
        &invalid_bloom.into_bytes(),
        Some("ok".to_owned()),
    )
    .expect("insert invalid bloom root");
    let mut row = DocMetaRow::decode(&fs::read(doc_meta_path(&invalid_bloom_root)).expect("row"))
        .expect("decode row");
    row.bloom_offset = 1_000_000;
    fs::write(doc_meta_path(&invalid_bloom_root), row.encode()).expect("write bad row");
    fs::write(
        meta_path(&invalid_bloom_root),
        serde_json::to_vec_pretty(&LegacyStoreMeta::default()).expect("bad bloom meta"),
    )
    .expect("write bad bloom meta");
    let mut reopened_invalid_bloom =
        CandidateStore::open(&invalid_bloom_root).expect("open invalid bloom root");
    let invalid_bloom_plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "bad".to_owned(),
            alternatives: vec![vec![30_u64]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("bad".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: true,
        allow_tier2_fallback: false,
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    assert!(
        reopened_invalid_bloom
            .query_candidates(&invalid_bloom_plan, 0, 8)
            .expect_err("invalid bloom offset on direct scan")
            .to_string()
            .contains("Invalid bloom payload stored")
    );

    let invalid_utf8_root = tmp.path().join("invalid_utf8_root");
    let mut invalid_utf8_store = CandidateStore::init(
        CandidateConfig {
            root: invalid_utf8_root.clone(),
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init invalid utf8 root");
    let mut invalid_utf8_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("utf8");
    invalid_utf8_bloom
        .add(u64::from(40_u32))
        .expect("add utf8 gram");
    insert_primary(
        &mut invalid_utf8_store,
        [0x11; 32],
        file_size,
        Some(gram_count),
        Some(bloom_hashes),
        filter_bytes,
        &invalid_utf8_bloom.into_bytes(),
        Some("ok".to_owned()),
    )
    .expect("insert invalid utf8 root");
    fs::write(external_ids_path(&invalid_utf8_root), [0xFF, 0xFE]).expect("write bad utf8");
    fs::write(
        meta_path(&invalid_utf8_root),
        serde_json::to_vec_pretty(&LegacyStoreMeta::default()).expect("bad utf8 meta"),
    )
    .expect("write bad utf8 meta");
    assert!(
        CandidateStore::open(&invalid_utf8_root)
            .expect("open utf8 root")
            .doc_external_id(0)
            .expect_err("invalid external id utf8")
            .to_string()
            .contains("Invalid external_id payload stored")
    );
}

#[test]
fn doc_meta_codec_and_binary_write_helpers_cover_remaining_paths() {
    let row = DocMetaRow {
        file_size: 123,
        filter_bytes: 64,
        flags: DOC_FLAG_DELETED,
        bloom_hashes: 7,
        bloom_offset: 7,
        bloom_len: 8,
        external_id_offset: 21,
        external_id_len: 4,
        metadata_offset: 25,
        metadata_len: 3,
    };
    let encoded = row.encode();
    let decoded = DocMetaRow::decode(&encoded).expect("decode row");
    assert_eq!(decoded.file_size, row.file_size);
    assert_eq!(decoded.filter_bytes, row.filter_bytes);
    assert_eq!(decoded.flags, row.flags);
    assert_eq!(decoded.bloom_offset, row.bloom_offset);
    assert_eq!(decoded.bloom_len, row.bloom_len);
    assert_eq!(decoded.external_id_offset, row.external_id_offset);
    assert_eq!(decoded.external_id_len, row.external_id_len);
    assert!(
        DocMetaRow::decode(&encoded[..encoded.len() - 1])
            .expect_err("short row")
            .to_string()
            .contains("Invalid candidate doc meta row size")
    );

    let tmp = tempdir().expect("tmp");
    let blob_path = tmp.path().join("blob.bin");
    let first = append_blob(blob_path.clone(), b"abc").expect("append blob 1");
    let second = append_blob(blob_path.clone(), b"de").expect("append blob 2");
    assert_eq!(first, 0);
    assert_eq!(second, 3);
    let mut bytes = fs::read(&blob_path).expect("read blob file");
    assert_eq!(
        read_blob(&bytes, 0, 5, "blob", 1).expect("read blob"),
        b"abcde"
    );
    write_at(blob_path.clone(), 1, b"Z").expect("write at");
    bytes = fs::read(&blob_path).expect("re-read blob file");
    assert_eq!(&bytes, b"aZcde");
    assert!(
        read_blob(&bytes, 99, 1, "blob", 1)
            .expect_err("invalid blob range")
            .to_string()
            .contains("Invalid blob payload stored")
    );

    let u32_path = tmp.path().join("u32.bin");
    let offset = append_u32_slice(u32_path.clone(), &[7, 8, 9]).expect("append u32");
    let u32_bytes = fs::read(&u32_path).expect("read u32 file");
    assert_eq!(
        read_u32_vec(&u32_bytes, offset, 3, "grams", 9).expect("read u32 vec"),
        vec![7, 8, 9]
    );
    assert!(
        read_u32_vec(&u32_bytes, 0, 99, "grams", 9)
            .expect_err("invalid u32 range")
            .to_string()
            .contains("Invalid grams payload stored")
    );
}

#[test]
fn sidecar_and_append_helper_paths_work() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("root");
    fs::create_dir_all(&root).expect("create root");

    let first_blob_path = tmp.path().join("blob_first.bin");
    fs::write(&first_blob_path, b"abcdef").expect("write first blob");
    fs::write(doc_metadata_path(&root), b"meta").expect("write metadata");

    let mut sidecar = BlobSidecar::with_access_mode(
        first_blob_path.clone(),
        BlobSidecarAccessMode::MmapWholeFile,
    );
    sidecar.map_if_exists().expect("map sidecar");
    assert_eq!(
        sidecar
            .read_bytes(1, 3, "blob", 7)
            .expect("mmap read")
            .as_ref(),
        b"bcd"
    );
    assert!(
        sidecar
            .read_bytes(99, 1, "blob", 7)
            .expect_err("invalid range")
            .to_string()
            .contains("Invalid blob payload stored")
    );
    sidecar.invalidate();
    assert_eq!(
        sidecar
            .read_bytes(0, 2, "blob", 7)
            .expect("file read")
            .as_ref(),
        b"ab"
    );

    let other_root = tmp.path().join("other");
    fs::create_dir_all(&other_root).expect("create other root");
    fs::write(doc_metadata_path(&other_root), b"xyz").expect("write other metadata");
    let second_blob_path = tmp.path().join("blob_second.bin");
    fs::write(&second_blob_path, b"xyz").expect("write second blob");
    sidecar.retarget(second_blob_path.clone());
    sidecar.map_if_exists().expect("remap sidecar");
    assert_eq!(
        sidecar
            .read_bytes(0, 3, "blob", 8)
            .expect("retarget read")
            .as_ref(),
        b"xyz"
    );

    let positioned_path = tmp.path().join("blob_positioned.bin");
    fs::write(&positioned_path, b"positioned").expect("write positioned blob");
    let positioned =
        BlobSidecar::with_access_mode(positioned_path, BlobSidecarAccessMode::PositionedRead);
    positioned.map_if_exists().expect("open positioned sidecar");
    assert_eq!(
        positioned
            .read_bytes(1, 4, "blob", 11)
            .expect("positioned read")
            .as_ref(),
        b"osit"
    );
    assert_eq!(
        positioned
            .mmap_slice(0, 4, "blob")
            .expect("positioned mmap slice"),
        None
    );
    assert_eq!(positioned.mapped_bytes(), 0);

    let mut sidecars = StoreSidecars::map_existing(&root).expect("map store sidecars");
    assert_eq!(
        sidecars
            .metadata
            .read_bytes(0, 4, "metadata", 9)
            .expect("metadata read")
            .as_ref(),
        b"meta"
    );
    assert_eq!(sidecars.metadata.mapped_bytes(), 0);
    sidecars.invalidate_all();
    sidecars.retarget_root(&other_root);
    sidecars.refresh_maps().expect("refresh retargeted maps");
    assert_eq!(
        sidecars
            .metadata
            .read_bytes(0, 3, "metadata", 10)
            .expect("retargeted store metadata sidecar")
            .as_ref(),
        b"xyz"
    );

    let append_path = tmp.path().join("append").join("payload.bin");
    let mut append = AppendFile::new(append_path.clone()).expect("new append file");
    assert_eq!(append.append(b"abc").expect("append first"), 0);
    assert_eq!(append.append(b"").expect("append empty"), 3);
    assert_eq!(append.append(b"de").expect("append second"), 3);
    assert_eq!(
        fs::read(&append_path).expect("read append payload"),
        b"abcde"
    );

    let retarget_path = tmp.path().join("retarget").join("payload.bin");
    fs::create_dir_all(retarget_path.parent().expect("retarget parent"))
        .expect("create retarget dir");
    fs::write(&retarget_path, b"pre").expect("seed retarget payload");
    append.retarget(retarget_path.clone());
    assert_eq!(append.append(b"zz").expect("append retarget"), 3);
    assert_eq!(
        fs::read(&retarget_path).expect("read retarget payload"),
        b"prezz"
    );

    let mut writers = StoreAppendWriters::new(&root).expect("append writers");
    writers.retarget_root(&other_root);
    assert_eq!(writers.metadata.path, doc_metadata_path(&other_root));
    assert_eq!(writers.external_ids.path, external_ids_path(&other_root));
}

#[test]
fn insert_restore_delete_and_stats_edge_paths_work() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: Some(0.25),
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    assert!(
        store
            .insert_document([0x10; 32], 8, None, None, None, None, 0, &[], 0, &[], None,)
            .expect_err("zero filter bytes")
            .to_string()
            .contains("filter_bytes must be > 0")
    );
    assert!(
        store
            .insert_document(
                [0x10; 32],
                8,
                None,
                None,
                None,
                None,
                1024,
                &vec![0u8; 32],
                0,
                &[],
                None,
            )
            .expect_err("length mismatch")
            .to_string()
            .contains("bloom_filter length")
    );

    let inserted = insert_primary(
        &mut store,
        [0x10; 32],
        8,
        None,
        None,
        1024,
        &vec![0u8; 1024],
        Some("first".to_owned()),
    )
    .expect("insert");
    assert_eq!(inserted.status, "inserted");

    let duplicate = insert_primary(
        &mut store,
        [0x10; 32],
        999,
        None,
        None,
        1024,
        &vec![0u8; 1024],
        Some("ignored".to_owned()),
    )
    .expect("duplicate");
    assert_eq!(duplicate.status, "already_exists");
    assert_eq!(duplicate.doc_id, inserted.doc_id);

    let missing = store
        .delete_document(&hex::encode([0x33; 32]))
        .expect("missing delete");
    assert_eq!(missing.status, "missing");
    assert_eq!(missing.doc_id, None);

    let deleted = store
        .delete_document(&hex::encode([0x10; 32]))
        .expect("delete");
    assert_eq!(deleted.status, "deleted");

    let restored = insert_primary(
        &mut store,
        [0x10; 32],
        16,
        None,
        None,
        1024,
        &vec![0xFF; 1024],
        Some("restored".to_owned()),
    )
    .expect("restore");
    assert_eq!(restored.status, "restored");
    assert_eq!(restored.doc_id, inserted.doc_id);

    let stats = store.stats();
    assert_eq!(stats.doc_count, 1);
    assert_eq!(stats.deleted_doc_count, 0);
    assert_eq!(
        store.external_ids_for_sha256(&[hex::encode([0x10; 32])]),
        vec![Some("restored".to_owned())]
    );
}

#[test]
fn query_and_ast_edge_paths_work() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let bloom_one = lane_bloom_bytes(filter_bytes, 2, &[1]);
    let bloom_two = lane_bloom_bytes(filter_bytes, 2, &[2]);
    let bloom_one_two = lane_bloom_bytes(filter_bytes, 2, &[1, 2]);

    insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        Some(2),
        filter_bytes,
        &bloom_one,
        None,
    )
    .expect("insert doc one");
    insert_primary(
        &mut store,
        [0x22; 32],
        8,
        None,
        Some(2),
        filter_bytes,
        &bloom_two,
        None,
    )
    .expect("insert doc two");
    insert_primary(
        &mut store,
        [0x33; 32],
        8,
        None,
        Some(2),
        filter_bytes,
        &bloom_one_two,
        None,
    )
    .expect("insert doc three");

    let plan = CompiledQueryPlan {
        patterns: vec![
            PatternPlan {
                pattern_id: "tier1".to_owned(),
                alternatives: vec![vec![1]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
            PatternPlan {
                pattern_id: "tier2".to_owned(),
                alternatives: vec![vec![2]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
        ],
        root: QueryNode {
            kind: "or".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier1".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier2".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
            ],
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 3.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let result = store.query_candidates(&plan, 0, 1).expect("query");
    assert_eq!(result.total_candidates, 3);
    assert_eq!(result.returned_count, 1);
    assert_eq!(result.next_cursor, Some(1));
    assert_eq!(result.tier_used, "tier1");

    let bloom_bytes = lane_bloom_bytes(64, 2, &[1, 2]);
    let doc = CandidateDoc {
        doc_id: 99,
        sha256: hex::encode([0x44; 32]),
        file_size: 42,
        filter_bytes: 64,
        bloom_hashes: 2,
        tier2_filter_bytes: 0,
        tier2_bloom_hashes: 0,
        special_population: false,
        deleted: false,
    };
    let patterns_vec = vec![
        PatternPlan {
            pattern_id: "empty".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
        PatternPlan {
            pattern_id: "tier1".to_owned(),
            alternatives: vec![vec![1]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
        PatternPlan {
            pattern_id: "tier2".to_owned(),
            alternatives: vec![vec![1, 2]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
        PatternPlan {
            pattern_id: "missing".to_owned(),
            alternatives: vec![vec![99]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
    ];
    let patterns = patterns_vec
        .iter()
        .cloned()
        .map(|pattern| (pattern.pattern_id.clone(), pattern))
        .collect::<HashMap<_, _>>();
    let eval_plan = CompiledQueryPlan {
        patterns: patterns_vec.clone(),
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("tier1".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 32.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let tier2_bloom_bytes = &[][..];
    let mask_cache = build_pattern_mask_cache(
        &patterns_vec,
        &[(64, 2)],
        &[(64, 2)],
        DEFAULT_TIER1_GRAM_SIZE,
        DEFAULT_TIER2_GRAM_SIZE,
    )
    .expect("pattern mask cache");

    let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_pattern(
        patterns.get("empty").expect("empty"),
        mask_cache.get("empty").expect("empty masks"),
        &mut doc_inputs,
        &mut load_tier1,
        &mut load_tier2,
        &eval_plan,
    )
    .expect("empty pattern");
    assert!(outcome.matched);
    assert_eq!(outcome.tiers.as_label(), "tier1");

    let no_fallback_plan = CompiledQueryPlan {
        force_tier1_only: false,
        allow_tier2_fallback: false,
        ..eval_plan.clone()
    };
    let complete_doc = doc.clone();
    let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&complete_doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_pattern(
        patterns.get("missing").expect("missing"),
        mask_cache.get("missing").expect("missing masks"),
        &mut doc_inputs,
        &mut load_tier1,
        &mut load_tier2,
        &no_fallback_plan,
    )
    .expect("no match");
    assert!(!outcome.matched);
    assert_eq!(outcome.tiers.as_label(), "none");

    let allow_fallback_plan = CompiledQueryPlan {
        force_tier1_only: false,
        allow_tier2_fallback: true,
        ..eval_plan.clone()
    };
    let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&complete_doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_pattern(
        patterns.get("tier2").expect("tier2"),
        mask_cache.get("tier2").expect("tier2 masks"),
        &mut doc_inputs,
        &mut load_tier1,
        &mut load_tier2,
        &allow_fallback_plan,
    )
    .expect("complete doc should match via bloom path");
    assert!(outcome.matched);
    assert_eq!(outcome.tiers.as_label(), "tier1");

    let no_overlap_doc = doc.clone();
    let (mut doc_inputs, _load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&no_overlap_doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_pattern(
        patterns.get("tier2").expect("tier2"),
        mask_cache.get("tier2").expect("tier2 masks"),
        &mut doc_inputs,
        &mut load_tier1,
        &mut load_tier2,
        &allow_fallback_plan,
    )
    .expect("bloom-only path should match from bloom anchors");
    assert!(outcome.matched);
    assert_eq!(outcome.tiers.as_label(), "tier1");

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_node(
        &QueryNode {
            kind: "and".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier1".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("missing".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
            ],
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("and");
    assert!(!outcome.matched);
    assert_eq!(outcome.tiers.as_label(), "none");

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_node(
        &QueryNode {
            kind: "or".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("missing".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier2".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
            ],
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("or");
    assert!(outcome.matched);
    assert_eq!(outcome.tiers.as_label(), "tier1");

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_node(
        &QueryNode {
            kind: "n_of".to_owned(),
            pattern_id: None,
            threshold: Some(2),
            children: vec![
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier1".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier2".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
            ],
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("n_of");
    assert!(outcome.matched);
    assert_eq!(outcome.tiers.as_label(), "tier1");

    assert!(
        {
            let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
                prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
            evaluate_node(
                &QueryNode {
                    kind: "n_of".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children: Vec::new(),
                },
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                &patterns,
                &mask_cache,
                &eval_plan,
                0,
                &mut QueryEvalCache::default(),
            )
        }
        .expect_err("missing threshold")
        .to_string()
        .contains("requires threshold")
    );
    assert!(
        {
            let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
                prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
            evaluate_node(
                &QueryNode {
                    kind: "bogus".to_owned(),
                    pattern_id: None,
                    threshold: None,
                    children: Vec::new(),
                },
                &mut doc_inputs,
                &mut load_metadata,
                &mut load_tier1,
                &mut load_tier2,
                &patterns,
                &mask_cache,
                &eval_plan,
                0,
                &mut QueryEvalCache::default(),
            )
        }
        .expect_err("unsupported kind")
        .to_string()
        .contains("Unsupported ast node kind")
    );

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_node(
        &QueryNode {
            kind: "not".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![QueryNode {
                kind: "pattern".to_owned(),
                pattern_id: Some("tier1".to_owned()),
                threshold: None,
                children: Vec::new(),
            }],
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("not pattern");
    assert!(outcome.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &bloom_bytes, tier2_bloom_bytes);
    let outcome = evaluate_node(
        &QueryNode {
            kind: "not".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![QueryNode {
                kind: "filesize_eq".to_owned(),
                pattern_id: Some("filesize".to_owned()),
                threshold: Some(doc.file_size as usize),
                children: Vec::new(),
            }],
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("not filesize");
    assert!(!outcome.matched);
}

#[test]
fn query_candidates_truncates_when_match_count_exceeds_max_candidates() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let filter_bytes = 8;
    let bloom_one = lane_bloom_bytes(filter_bytes, 2, &[1]);
    let bloom_two = lane_bloom_bytes(filter_bytes, 2, &[2]);
    let bloom_one_two = lane_bloom_bytes(filter_bytes, 2, &[1, 2]);

    insert_primary(
        &mut store,
        [0x11; 32],
        8,
        None,
        Some(2),
        filter_bytes,
        &bloom_one,
        None,
    )
    .expect("insert doc one");
    insert_primary(
        &mut store,
        [0x22; 32],
        8,
        None,
        Some(2),
        filter_bytes,
        &bloom_two,
        None,
    )
    .expect("insert doc two");
    insert_primary(
        &mut store,
        [0x33; 32],
        8,
        None,
        Some(2),
        filter_bytes,
        &bloom_one_two,
        None,
    )
    .expect("insert doc three");

    let plan = CompiledQueryPlan {
        patterns: vec![
            PatternPlan {
                pattern_id: "tier1".to_owned(),
                alternatives: vec![vec![1]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
            PatternPlan {
                pattern_id: "tier2".to_owned(),
                alternatives: vec![vec![2]],
                tier2_alternatives: vec![Vec::new()],
                anchor_literals: vec![Vec::new()],
                fixed_literals: vec![Vec::new()],
                fixed_literal_wide: vec![false],
                fixed_literal_fullword: vec![false],
            },
        ],
        root: QueryNode {
            kind: "or".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier1".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("tier2".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
            ],
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 2.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let result = store
        .query_candidates(&plan, 0, 8)
        .expect("overflow should truncate");
    assert!(result.truncated);
    assert_eq!(result.truncated_limit, Some(2));
    assert_eq!(result.total_candidates, 2);
    assert_eq!(result.returned_count, 2);
    assert_eq!(result.sha256.len(), 2);
}

#[test]
fn evaluate_node_supports_metadata_and_time_conditions() {
    let tmp = tempdir().expect("tmp");
    let pe_path = tmp.path().join("sample.exe");
    let mut pe = vec![0u8; 0x240];
    pe[0..2].copy_from_slice(b"MZ");
    pe[0x3c..0x40].copy_from_slice(&(0x80u32).to_le_bytes());
    pe[0x80..0x84].copy_from_slice(b"PE\0\0");
    pe[0x84..0x86].copy_from_slice(&0x14cu16.to_le_bytes());
    pe[0x86..0x88].copy_from_slice(&1u16.to_le_bytes());
    pe[0x88..0x8c].copy_from_slice(&0x1234_5678u32.to_le_bytes());
    pe[0x94..0x96].copy_from_slice(&0xf0u16.to_le_bytes());
    pe[0x96..0x98].copy_from_slice(&0x2000u16.to_le_bytes());
    pe[0x98..0x9a].copy_from_slice(&0x20bu16.to_le_bytes());
    pe[0x98 + 16..0x98 + 20].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[0x98 + 60..0x98 + 64].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x98 + 68..0x98 + 70].copy_from_slice(&3u16.to_le_bytes());
    let text_section = 0x80 + 24 + 0xf0;
    pe[text_section..text_section + 8].copy_from_slice(b".text\0\0\0");
    pe[text_section + 8..text_section + 12].copy_from_slice(&0x20u32.to_le_bytes());
    pe[text_section + 12..text_section + 16].copy_from_slice(&0x1000u32.to_le_bytes());
    pe[text_section + 16..text_section + 20].copy_from_slice(&0x20u32.to_le_bytes());
    pe[text_section + 20..text_section + 24].copy_from_slice(&0x200u32.to_le_bytes());
    pe[0x200..0x210].copy_from_slice(b"ENTRYPOINT-PE!!!");
    fs::write(&pe_path, &pe).expect("write pe");
    let metadata_bytes = extract_compact_document_metadata(&pe_path).expect("metadata");

    let doc = CandidateDoc {
        doc_id: 1,
        sha256: hex::encode([0x11; 32]),
        file_size: pe.len() as u64,
        filter_bytes: 8,
        bloom_hashes: 2,
        tier2_filter_bytes: 8,
        tier2_bloom_hashes: 2,
        special_population: false,
        deleted: false,
    };
    let patterns = HashMap::<String, PatternPlan>::new();
    let mask_cache = PatternMaskCache::new();
    let eval_plan = CompiledQueryPlan {
        patterns: Vec::new(),
        root: QueryNode {
            kind: "metadata_eq".to_owned(),
            pattern_id: Some("pe.machine".to_owned()),
            threshold: Some(0x14c),
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 32.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let metadata_outcome = evaluate_node(
        &eval_plan.root,
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("metadata eq");
    assert!(metadata_outcome.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &[], &[]);
    let unknown_outcome = evaluate_node(
        &QueryNode {
            kind: "metadata_eq".to_owned(),
            pattern_id: Some("elf.machine".to_owned()),
            threshold: Some(62),
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("unknown metadata eq");
    assert!(unknown_outcome.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let time_outcome = evaluate_node(
        &QueryNode {
            kind: "time_now_eq".to_owned(),
            pattern_id: Some("time.now".to_owned()),
            threshold: Some(1234),
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        1234,
        &mut QueryEvalCache::default(),
    )
    .expect("time now eq");
    assert!(time_outcome.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let time_gt_outcome = evaluate_node(
        &QueryNode {
            kind: "time_now_gt".to_owned(),
            pattern_id: Some("time.now".to_owned()),
            threshold: Some(1000),
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        1234,
        &mut QueryEvalCache::default(),
    )
    .expect("time now gt");
    assert!(time_gt_outcome.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let verifier_outcome = evaluate_node(
        &QueryNode {
            kind: "verifier_only_eq".to_owned(),
            pattern_id: Some("uint16(0)==23117".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("verifier only eq");
    assert!(verifier_outcome.matched);

    let numeric_path = tmp.path().join("numeric.bin");
    let numeric_bytes = 0x1122_3344_5566_7788u64.to_le_bytes();
    fs::write(&numeric_path, numeric_bytes).expect("write numeric");
    let numeric_metadata = extract_compact_document_metadata(&numeric_path).expect("metadata");
    let numeric_doc = CandidateDoc {
        file_size: 8,
        ..doc.clone()
    };
    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&numeric_doc, &numeric_metadata, &[], &[]);
    let numeric_true = evaluate_node(
        &QueryNode {
            kind: "verifier_only_eq".to_owned(),
            pattern_id: Some("uint64(0)==1234605616436508552".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("uint64 prefix eq");
    assert!(numeric_true.matched);
    assert_eq!(
        true, numeric_true.matched,
        "uint64(0) prefix shortcut should match the expected decoded value"
    );

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&numeric_doc, &numeric_metadata, &[], &[]);
    let numeric_u32 = evaluate_node(
        &QueryNode {
            kind: "verifier_only_eq".to_owned(),
            pattern_id: Some("uint32(0)==1432778632".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("uint32 prefix eq");
    assert_eq!(
        numeric_u32.matched,
        yara_rule_matches_bytes(
            "rule test { condition: uint32(0) == 1432778632 }",
            &numeric_bytes,
        ),
        "uint32(0) prefix shortcut must match YARA-X semantics"
    );

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&numeric_doc, &numeric_metadata, &[], &[]);
    let numeric_u32_offset = evaluate_node(
        &QueryNode {
            kind: "verifier_only_eq".to_owned(),
            pattern_id: Some("uint32(4)==287454020".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("uint32 prefix eq at offset 4");
    assert_eq!(
        numeric_u32_offset.matched,
        yara_rule_matches_bytes(
            "rule test { condition: uint32(4) == 287454020 }",
            &numeric_bytes,
        ),
        "uint32(4) prefix shortcut must match YARA-X semantics"
    );

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&numeric_doc, &numeric_metadata, &[], &[]);
    let numeric_false = evaluate_node(
        &QueryNode {
            kind: "verifier_only_eq".to_owned(),
            pattern_id: Some("int16be(0)==-2".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("int16be prefix eq");
    assert!(!numeric_false.matched);
    assert_eq!(
        numeric_false.matched,
        yara_rule_matches_bytes("rule test { condition: int16be(0) == -2 }", &numeric_bytes,),
        "int16be(0) prefix shortcut must match YARA-X semantics"
    );

    let short_path = tmp.path().join("short.bin");
    let short_bytes = *b"AB";
    fs::write(&short_path, short_bytes).expect("write short");
    let short_metadata = extract_compact_document_metadata(&short_path).expect("metadata");
    let short_doc = CandidateDoc {
        file_size: 2,
        ..doc.clone()
    };
    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&short_doc, &short_metadata, &[], &[]);
    let short_numeric = evaluate_node(
        &QueryNode {
            kind: "verifier_only_eq".to_owned(),
            pattern_id: Some("uint32(0)==0".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("short uint64 prefix eq");
    assert_eq!(
        short_numeric.matched,
        yara_rule_matches_bytes("rule test { condition: uint32(0) == 0 }", &short_bytes),
        "short-file integer prefix shortcut must match YARA-X semantics"
    );

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let metadata_ne = evaluate_node(
        &QueryNode {
            kind: "metadata_ne".to_owned(),
            pattern_id: Some("pe.machine".to_owned()),
            threshold: Some(0x8664),
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        200_000_000,
        &mut QueryEvalCache::default(),
    )
    .expect("metadata ne");
    assert!(metadata_ne.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let metadata_time = evaluate_node(
        &QueryNode {
            kind: "metadata_time_lt".to_owned(),
            pattern_id: Some("pe.timestamp".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        400_000_000,
        &mut QueryEvalCache::default(),
    )
    .expect("metadata time lt");
    assert!(metadata_time.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let metadata_field = evaluate_node(
        &QueryNode {
            kind: "metadata_field_lt".to_owned(),
            pattern_id: Some("pe.subsystem|pe.machine".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("metadata field lt");
    assert!(metadata_field.matched);

    let at_zero_patterns = HashMap::from([(
        "$mz".to_owned(),
        PatternPlan {
            pattern_id: "$mz".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![b"MZ".to_vec()],
            fixed_literals: vec![b"MZ".to_vec()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
    )]);
    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let at_zero_true = evaluate_node(
        &QueryNode {
            kind: "verifier_only_at".to_owned(),
            pattern_id: Some("$mz@0".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &at_zero_patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("at zero prefix true");
    assert!(at_zero_true.matched);
    assert_eq!(
        at_zero_true.matched,
        yara_rule_matches_bytes(
            "rule test { strings: $mz = \"MZ\" condition: $mz at 0 }",
            &pe,
        ),
        "$str at 0 prefix shortcut must match YARA-X semantics"
    );

    let at_zero_patterns = HashMap::from([(
        "$pk".to_owned(),
        PatternPlan {
            pattern_id: "$pk".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![b"PK".to_vec()],
            fixed_literals: vec![b"PK".to_vec()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
    )]);
    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let at_zero_false = evaluate_node(
        &QueryNode {
            kind: "verifier_only_at".to_owned(),
            pattern_id: Some("$pk@0".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &at_zero_patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("at zero prefix false");
    assert!(!at_zero_false.matched);
    assert_eq!(
        at_zero_false.matched,
        yara_rule_matches_bytes(
            "rule test { strings: $pk = \"PK\" condition: $pk at 0 }",
            &pe,
        ),
        "negative $str at 0 prefix shortcut must match YARA-X semantics"
    );

    let entrypoint_patterns = HashMap::from([(
        "$ep".to_owned(),
        PatternPlan {
            pattern_id: "$ep".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![b"ENTRY".to_vec()],
            fixed_literals: vec![b"ENTRY".to_vec()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
    )]);
    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let at_entrypoint_true = evaluate_node(
        &QueryNode {
            kind: "verifier_only_at".to_owned(),
            pattern_id: Some("$ep@pe.entry_point".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &entrypoint_patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("entrypoint prefix true");
    assert!(at_entrypoint_true.matched);

    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &[], &[], &[]);
    let at_entrypoint_without_metadata = evaluate_node(
        &QueryNode {
            kind: "verifier_only_at".to_owned(),
            pattern_id: Some("$ep@pe.entry_point".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &entrypoint_patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("entrypoint prefix missing metadata");
    assert!(
        !at_entrypoint_without_metadata.matched,
        "missing PE entry-point metadata should fail exact entry-point matches"
    );

    let shifted_entrypoint_patterns = HashMap::from([(
        "$ep_plus".to_owned(),
        PatternPlan {
            pattern_id: "$ep_plus".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![b"POINT".to_vec()],
            fixed_literals: vec![b"POINT".to_vec()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        },
    )]);
    let (mut doc_inputs, mut load_metadata, mut load_tier1, mut load_tier2) =
        prefetched_query_inputs(&doc, &metadata_bytes, &[], &[]);
    let at_entrypoint_plus_true = evaluate_node(
        &QueryNode {
            kind: "verifier_only_at".to_owned(),
            pattern_id: Some("$ep_plus@pe.entry_point+5".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        &mut doc_inputs,
        &mut load_metadata,
        &mut load_tier1,
        &mut load_tier2,
        &shifted_entrypoint_patterns,
        &mask_cache,
        &eval_plan,
        0,
        &mut QueryEvalCache::default(),
    )
    .expect("entrypoint prefix plus offset");
    assert!(at_entrypoint_plus_true.matched);
}

#[test]
fn prepared_query_cache_reuses_entries_and_invalidates_on_mutation() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("store");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");
    let sha256 = [0xaa; 32];
    let filter_bytes = store
        .resolve_filter_bytes_for_file_size(4, Some(1))
        .expect("primary filter bytes");
    let bloom_hashes = store.resolve_bloom_hashes_for_document(filter_bytes, Some(1), None);
    let mut primary_bloom = BloomFilter::new(filter_bytes, bloom_hashes).expect("tier1 bloom");
    primary_bloom
        .add(pack_exact_gram(&[1, 2, 3]))
        .expect("add primary gram");
    primary_bloom
        .add(pack_exact_gram(&[2, 3, 4]))
        .expect("add primary gram");
    let tier2_filter_bytes = store
        .resolve_filter_bytes_for_file_size(4, Some(2))
        .expect("tier2 filter bytes");
    let tier2_bloom_hashes =
        store.resolve_bloom_hashes_for_document(tier2_filter_bytes, Some(2), None);
    let mut tier2_bloom =
        BloomFilter::new(tier2_filter_bytes, tier2_bloom_hashes).expect("tier2 bloom");
    tier2_bloom
        .add(pack_exact_gram(&[1, 2, 3, 4]))
        .expect("add tier2 gram");
    store
        .insert_document(
            sha256,
            4,
            Some(1),
            Some(bloom_hashes),
            Some(2),
            Some(tier2_bloom_hashes),
            filter_bytes,
            &primary_bloom.into_bytes(),
            tier2_filter_bytes,
            &tier2_bloom.into_bytes(),
            None,
        )
        .expect("write tier2 sidecars");

    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![pack_exact_gram(&[1, 2, 3, 4])]],
            tier2_alternatives: vec![vec![
                pack_exact_gram(&[1, 2, 3]),
                pack_exact_gram(&[2, 3, 4]),
            ]],
            anchor_literals: vec![vec![1, 2, 3, 4]],
            fixed_literals: vec![vec![1, 2, 3, 4]],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$a".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 64.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let first = store.query_candidates(&plan, 0, 64).expect("first query");
    assert_eq!(store.prepared_query_cache.len(), 1);

    let second = store.query_candidates(&plan, 0, 64).expect("second query");
    assert_eq!(first.total_candidates, second.total_candidates);
    assert_eq!(store.prepared_query_cache.len(), 1);

    let delete = store.delete_document(&hex::encode(sha256)).expect("delete");
    assert_eq!(delete.status, "deleted");
    assert_eq!(store.prepared_query_cache.len(), 0);

    let _third = store.query_candidates(&plan, 0, 64).expect("third query");
    assert_eq!(store.prepared_query_cache.len(), 1);
}

#[test]
fn clear_search_caches_empties_prepared_query_cache() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("store");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");
    let filter_bytes = store
        .resolve_filter_bytes_for_file_size(8, None)
        .expect("filter bytes");
    insert_primary(
        &mut store,
        [0x44; 32],
        8,
        None,
        None,
        filter_bytes,
        &lane_bloom_bytes(
            filter_bytes,
            DEFAULT_BLOOM_HASHES,
            &[pack_exact_gram(b"ABC")],
        ),
        None,
    )
    .expect("insert");
    let plan = compile_query_plan_with_gram_sizes_and_identity_source(
        r#"
rule q {
  strings:
    $a = "ABC"
  condition:
    $a
}
"#,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
        Some("sha256"),
        8,
        false,
        true,
        100_000,
    )
    .expect("plan");

    let _ = store.query_candidates(&plan, 0, 64).expect("query");
    assert_eq!(store.prepared_query_cache.len(), 1);
    store.clear_search_caches();
    assert_eq!(store.prepared_query_cache.len(), 0);
}

#[test]
fn import_document_batch_wrappers_roundtrip_live_documents() {
    let tmp = tempdir().expect("tmp");
    let src_root = tmp.path().join("src");
    let mut src = CandidateStore::init(
        CandidateConfig {
            root: src_root,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init src");
    let filter_bytes = src
        .resolve_filter_bytes_for_file_size(8, None)
        .expect("filter bytes");
    let bloom = lane_bloom_bytes(
        filter_bytes,
        DEFAULT_BLOOM_HASHES,
        &[pack_exact_gram(b"ABC")],
    );
    insert_primary(
        &mut src,
        [0x61; 32],
        8,
        None,
        None,
        filter_bytes,
        &bloom,
        Some("src-doc".to_owned()),
    )
    .expect("insert source");
    let documents = src.export_live_documents().expect("export");
    assert_eq!(documents.len(), 1);

    let mut dst = CandidateStore::init(
        CandidateConfig {
            root: tmp.path().join("dst"),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init dst");
    let inserted = dst.import_documents_batch(&documents).expect("import");
    assert_eq!(inserted.len(), 1);
    assert_eq!(inserted[0].status, "inserted");
    assert_eq!(dst.stats().doc_count, 1);

    let mut dst_known_new = CandidateStore::init(
        CandidateConfig {
            root: tmp.path().join("dst-known-new"),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init dst known new");
    let inserted_known_new = dst_known_new
        .import_documents_batch_known_new(&documents)
        .expect("import known new");
    assert_eq!(inserted_known_new.len(), 1);
    assert_eq!(inserted_known_new[0].status, "inserted");

    let mut dst_quiet = CandidateStore::init(
        CandidateConfig {
            root: tmp.path().join("dst-quiet"),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init dst quiet");
    dst_quiet
        .import_documents_batch_quiet(&documents)
        .expect("import quiet");
    assert_eq!(dst_quiet.stats().doc_count, 1);

    let mut dst_known_new_quiet = CandidateStore::init(
        CandidateConfig {
            root: tmp.path().join("dst-known-new-quiet"),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init dst known new quiet");
    dst_known_new_quiet
        .import_documents_batch_known_new_quiet(&documents)
        .expect("import known new quiet");
    assert_eq!(dst_known_new_quiet.stats().doc_count, 1);
}

#[test]
fn query_candidates_scans_special_population_when_no_regular_docs_exist() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("store");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");
    let sha256 = [0x5a; 32];
    let filter_bytes = store
        .resolve_filter_bytes_for_file_size(123, None)
        .expect("filter bytes");
    let bloom_hashes = store.resolve_bloom_hashes_for_document(filter_bytes, None, None);
    let gram = pack_exact_gram(&[1, 2, 3, 4]);
    let bloom_bytes = lane_bloom_bytes(filter_bytes, bloom_hashes, &[gram]);
    store
        .insert_document_with_metadata(
            sha256,
            123,
            None,
            None,
            None,
            None,
            filter_bytes,
            &bloom_bytes,
            0,
            &[],
            &[],
            true,
            None,
        )
        .expect("insert special doc");

    assert_eq!(store.special_doc_positions, vec![0]);

    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "tier1".to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![vec![1, 2, 3, 4]],
            fixed_literals: vec![vec![1, 2, 3, 4]],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("tier1".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let result = store.query_candidates(&plan, 0, 8).expect("query");
    assert_eq!(result.total_candidates, 1);
    assert_eq!(result.returned_count, 1);
    assert_eq!(result.sha256, vec![hex::encode(sha256)]);
    assert_eq!(result.query_profile.docs_scanned, 1);
    assert_eq!(result.query_profile.tier1_bloom_loads, 1);
}

#[test]
fn query_candidates_tier2_and_metadata_only_scans_docs_without_tier1_loads() {
    let _guard = tier2_and_metadata_only_override(true);
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("store");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");
    let gram = pack_exact_gram(&[1, 2, 3, 4]);
    for idx in 0..2u8 {
        let sha256 = [idx + 1; 32];
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(123, None)
            .expect("filter bytes");
        let tier2_filter_bytes = filter_bytes;
        let tier2_bloom_hashes =
            store.resolve_bloom_hashes_for_document(tier2_filter_bytes, None, None);
        let tier2_bloom_bytes = if idx == 0 {
            lane_bloom_bytes(tier2_filter_bytes, tier2_bloom_hashes, &[gram])
        } else {
            vec![0u8; tier2_filter_bytes]
        };
        store
            .insert_document_with_metadata(
                sha256,
                123,
                None,
                None,
                None,
                None,
                filter_bytes,
                &vec![0u8; filter_bytes],
                tier2_filter_bytes,
                &tier2_bloom_bytes,
                &[],
                false,
                None,
            )
            .expect("insert doc");
    }

    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "tier1".to_owned(),
            alternatives: vec![Vec::new()],
            tier2_alternatives: vec![vec![gram]],
            anchor_literals: vec![vec![1, 2, 3, 4]],
            fixed_literals: vec![vec![1, 2, 3, 4]],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("tier1".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let result = store.query_candidates(&plan, 0, 8).expect("query");
    assert_eq!(result.total_candidates, 1);
    assert_eq!(result.returned_count, 1);
    assert_eq!(result.query_profile.docs_scanned, 2);
    assert_eq!(result.query_profile.tier1_bloom_loads, 0);
    assert_eq!(result.query_profile.tier2_bloom_loads, 2);
    assert_eq!(result.tier_used, "tier2");
}

#[test]
fn collect_query_hits_with_prepared_batch_reuses_doc_sidecar_loads_across_rules() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("store");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let gram = pack_exact_gram(b"ABC");
    for idx in 0..2u8 {
        let sha256 = [idx + 1; 32];
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(123, None)
            .expect("filter bytes");
        let bloom_hashes = store.resolve_bloom_hashes_for_document(filter_bytes, None, None);
        let bloom_bytes = lane_bloom_bytes(filter_bytes, bloom_hashes, &[gram]);
        store
            .insert_document_with_metadata(
                sha256,
                123,
                None,
                None,
                None,
                None,
                filter_bytes,
                &bloom_bytes,
                0,
                &[],
                &[],
                false,
                None,
            )
            .expect("insert doc");
    }

    let make_plan = |pattern_id: &str| CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: pattern_id.to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![vec![b'A', b'B', b'C']],
            fixed_literals: vec![vec![b'A', b'B', b'C']],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some(pattern_id.to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let plan_a = make_plan("$a");
    let plan_b = make_plan("$b");
    let prepared_a = store.prepare_query_artifacts(&plan_a).expect("prepared a");
    let prepared_b = store.prepare_query_artifacts(&plan_b).expect("prepared b");

    let single_a = store
        .collect_query_hits_with_prepared(&plan_a, prepared_a.as_ref())
        .expect("single query a");
    let single_b = store
        .collect_query_hits_with_prepared(&plan_b, prepared_b.as_ref())
        .expect("single query b");
    let singles_tier1_loads = single_a
        .2
        .tier1_bloom_loads
        .saturating_add(single_b.2.tier1_bloom_loads);
    assert_eq!(singles_tier1_loads, 4);

    let batched = store
        .collect_query_hits_with_prepared_batch(&[plan_a, plan_b], &[prepared_a, prepared_b])
        .expect("batched query");
    assert_eq!(batched.len(), 2);
    assert_eq!(batched[0].0, single_a.0);
    assert_eq!(batched[1].0, single_b.0);
    assert_eq!(batched[0].1, "tier1");
    assert_eq!(batched[1].1, "tier1");
    assert_eq!(batched[0].2.docs_scanned, 2);
    assert_eq!(batched[1].2.docs_scanned, 2);
    let batched_tier1_loads = batched[0]
        .2
        .tier1_bloom_loads
        .saturating_add(batched[1].2.tier1_bloom_loads);
    assert_eq!(batched_tier1_loads, 2);
}

#[test]
fn collect_query_hits_with_runtime_hash_batch_reuses_doc_sidecar_loads_across_rules() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("store");
    let mut store = CandidateStore::init(
        CandidateConfig {
            root,
            filter_target_fp: None,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init");

    let gram = pack_exact_gram(b"ABC");
    for idx in 0..2u8 {
        let sha256 = [idx + 1; 32];
        let filter_bytes = store
            .resolve_filter_bytes_for_file_size(123, None)
            .expect("filter bytes");
        let bloom_hashes = store.resolve_bloom_hashes_for_document(filter_bytes, None, None);
        let bloom_bytes = lane_bloom_bytes(filter_bytes, bloom_hashes, &[gram]);
        store
            .insert_document_with_metadata(
                sha256,
                123,
                None,
                None,
                None,
                None,
                filter_bytes,
                &bloom_bytes,
                0,
                &[],
                &[],
                false,
                None,
            )
            .expect("insert doc");
    }

    let make_plan = |pattern_id: &str| CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: pattern_id.to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![vec![b'A', b'B', b'C']],
            fixed_literals: vec![vec![b'A', b'B', b'C']],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some(pattern_id.to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: false,
        allow_tier2_fallback: true,
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    let plan_a = make_plan("$a");
    let plan_b = make_plan("$b");
    let runtime_a = build_runtime_query_artifacts(&plan_a).expect("runtime a");
    let runtime_b = build_runtime_query_artifacts(&plan_b).expect("runtime b");

    let single_a = store
        .collect_query_hits_with_runtime_hash(&plan_a, runtime_a.as_ref())
        .expect("single query a");
    let single_b = store
        .collect_query_hits_with_runtime_hash(&plan_b, runtime_b.as_ref())
        .expect("single query b");
    let singles_tier1_loads = single_a
        .2
        .tier1_bloom_loads
        .saturating_add(single_b.2.tier1_bloom_loads);
    assert_eq!(singles_tier1_loads, 4);

    let batched = store
        .collect_query_hits_with_runtime_hash_batch(&[plan_a, plan_b], &[runtime_a, runtime_b])
        .expect("batched query");
    assert_eq!(batched.len(), 2);
    assert_eq!(batched[0].0, single_a.0);
    assert_eq!(batched[1].0, single_b.0);
    assert_eq!(batched[0].1, "tier1");
    assert_eq!(batched[1].1, "tier1");
    assert_eq!(batched[0].2.docs_scanned, 2);
    assert_eq!(batched[1].2.docs_scanned, 2);
    let batched_tier1_loads = batched[0]
        .2
        .tier1_bloom_loads
        .saturating_add(batched[1].2.tier1_bloom_loads);
    assert_eq!(batched_tier1_loads, 2);
}
