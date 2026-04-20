use super::*;

use std::fs;
use std::time::Duration;

use crate::candidate::BloomFilter;
use crate::candidate::bloom::DEFAULT_BLOOM_POSITION_LANES;
use crate::candidate::{DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, pack_exact_gram};
use base64::Engine;
use tempfile::tempdir;

#[test]
fn resolve_search_workers_caps_to_work_units() {
    assert_eq!(resolve_search_workers(0, 0), 1);
    assert_eq!(resolve_search_workers(1, 0), 1);
    assert_eq!(resolve_search_workers(1, 1), 1);
    assert_eq!(resolve_search_workers(5, 3), 3);
    assert_eq!(resolve_search_workers(3, 5), 3);
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

fn sample_server_state(base: &Path) -> Arc<ServerState> {
    Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: base.join("candidate_db"),
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state"),
    )
}

fn sample_server_state_with_shards(base: &Path, candidate_shards: usize) -> Arc<ServerState> {
    Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: base.join(format!("candidate_db_{candidate_shards}")),
                    ..CandidateConfig::default()
                },
                candidate_shards,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state"),
    )
}

fn sample_forest_server_state(base: &Path, candidate_shards: usize) -> Arc<ServerState> {
    let forest_root = base.join(format!("candidate_forest_{candidate_shards}"));
    let config = ServerConfig {
        candidate_config: CandidateConfig {
            root: forest_root.clone(),
            ..CandidateConfig::default()
        },
        candidate_shards,
        search_workers: 2,
        memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
        auto_publish_initial_idle_ms: 500,
        auto_publish_storage_class: "unknown".to_owned(),
        workspace_mode: false,
    };
    for tree_idx in [0usize, 1usize] {
        let tree_root = forest_root
            .join(format!("tree_{tree_idx:02}"))
            .join("current");
        let _ = ensure_candidate_stores_at_root(&config, &tree_root).expect("tree stores");
    }
    let state =
        Arc::new(ServerState::new(config, Arc::new(AtomicBool::new(false))).expect("forest state"));
    for (tree_idx, stores) in state
        .published_query_store_sets()
        .expect("forest query stores")
        .into_iter()
        .enumerate()
    {
        let store_lock = stores.stores.first().expect("single shard");
        let mut store = store_lock.lock().expect("lock tree store");
        let doc_path = base.join(format!("forest_doc_{tree_idx:02}.bin"));
        let features = scan_features_default_grams(&doc_path).unwrap_or_else(|_| {
            let payload = format!("xxABCyy{tree_idx}");
            fs::write(&doc_path, payload.as_bytes()).expect("write forest sample");
            scan_features_default_grams(&doc_path).expect("forest features")
        });
        store
            .insert_document(
                features.sha256,
                features.file_size,
                None,
                None,
                None,
                None,
                features.bloom_filter.len(),
                &features.bloom_filter,
                features.tier2_bloom_filter.len(),
                &features.tier2_bloom_filter,
                Some(format!("tree_{tree_idx:02}.bin")),
            )
            .expect("insert tree doc");
        let _ = store.persist_meta_if_dirty().expect("persist tree meta");
    }
    state
}

fn exact_abc_plan(pattern_id: &str, max_candidates: f64) -> CompiledQueryPlan {
    let gram = pack_exact_gram(b"ABC");
    CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: pattern_id.to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
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
        max_candidates,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    }
}

fn sample_workspace_server_state(base: &Path, candidate_shards: usize) -> Arc<ServerState> {
    sample_workspace_server_state_with_budget(
        base,
        candidate_shards,
        crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
    )
}

fn sample_workspace_server_state_with_budget(
    base: &Path,
    candidate_shards: usize,
    memory_budget_bytes: u64,
) -> Arc<ServerState> {
    Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: base.join(format!("candidate_workspace_{candidate_shards}")),
                    ..CandidateConfig::default()
                },
                candidate_shards,
                search_workers: 1,
                memory_budget_bytes,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: true,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("workspace server state"),
    )
}

fn candidate_document_wire_from_bytes(path: &Path, bytes: &[u8]) -> CandidateDocumentWire {
    fs::write(path, bytes).expect("write sample");
    let features = scan_features_default_grams(path).expect("features");
    CandidateDocumentWire {
        identity: hex::encode(features.sha256),
        file_size: features.file_size,
        bloom_filter_b64: base64::engine::general_purpose::STANDARD.encode(features.bloom_filter),
        bloom_item_estimate: None,
        tier2_bloom_filter_b64: None,
        tier2_bloom_item_estimate: None,
        special_population: false,
        metadata_b64: None,
        external_id: None,
    }
}

fn scan_features_default_grams(
    path: impl AsRef<Path>,
) -> Result<crate::candidate::DocumentFeatures> {
    crate::candidate::scan_file_features_bloom_only_with_gram_sizes(
        path,
        crate::candidate::GramSizes::new(
            crate::candidate::DEFAULT_TIER1_GRAM_SIZE,
            crate::candidate::DEFAULT_TIER2_GRAM_SIZE,
        )
        .expect("default gram sizes"),
        1024,
        7,
        0,
        0,
        1024,
        None,
    )
}

fn compile_query_plan_from_file_default(
    rule_path: impl AsRef<Path>,
    max_anchors_per_alt: usize,
    force_tier1_only: bool,
    allow_tier2_fallback: bool,
    max_candidates: impl Into<f64>,
) -> Result<crate::candidate::CompiledQueryPlan> {
    crate::candidate::compile_query_plan_from_file_with_gram_sizes(
        rule_path,
        crate::candidate::GramSizes::new(
            crate::candidate::DEFAULT_TIER1_GRAM_SIZE,
            crate::candidate::DEFAULT_TIER2_GRAM_SIZE,
        )
        .expect("default gram sizes"),
        max_anchors_per_alt,
        force_tier1_only,
        allow_tier2_fallback,
        max_candidates.into(),
    )
}

#[test]
fn current_stats_json_returns_busy_error_when_shard_locked() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state(tmp.path());
    let work = state.work_store_set().expect("work stores");
    let _guard = work.stores[0].lock().expect("lock store");
    let err = state
        .current_stats_json()
        .expect_err("stats should time out");
    assert!(
        err.to_string().contains("busy during stats"),
        "unexpected error: {err}"
    );
}

#[test]
fn lock_candidate_store_blocking_reports_poison_and_success() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state(tmp.path());
    let work = state.work_store_set().expect("work stores");
    let guard = lock_candidate_store_blocking(&work.stores[0]).expect("lock succeeds");
    drop(guard);

    let poison_result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let _guard = work.stores[0].lock().expect("poison lock");
        panic!("poison candidate store mutex");
    }));
    assert!(poison_result.is_err(), "poison block should panic");

    let err = lock_candidate_store_blocking(&work.stores[0]).expect_err("poisoned lock");
    assert!(
        err.to_string().contains("Candidate store lock poisoned"),
        "unexpected error: {err}"
    );
}

#[test]
fn forest_root_server_queries_across_all_trees() {
    let tmp = tempdir().expect("tmp");
    let state = sample_forest_server_state(tmp.path(), 1);
    let stores = state
        .published_query_store_sets()
        .expect("forest query stores");
    assert_eq!(stores.len(), 2);
    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![pack_exact_gram(b"ABC")]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$a".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: true,
        allow_tier2_fallback: false,
        max_candidates: 100.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let runtime = state
        .shared_runtime_query_artifacts(&plan)
        .expect("runtime query");
    for stores in &stores {
        let mut store = lock_candidate_store_blocking(&stores.stores[0]).expect("lock store");
        assert_eq!(store.stats().doc_count, 1);
        let (hits, _, _) =
            ServerState::collect_query_matches_single_store(&mut store, &plan, &runtime)
                .expect("single-store query");
        assert_eq!(hits.len(), 1);
    }
    let result = state
        .handle_candidate_query(
            CandidateQueryRequest {
                plan: Value::Null,
                cursor: 0,
                chunk_size: None,
                include_external_ids: true,
            },
            &plan,
        )
        .expect("forest query");
    assert_eq!(result.total_candidates, 2);
    assert_eq!(result.returned_count, 2);
    assert_eq!(result.external_ids.as_ref().map(Vec::len), Some(2));
    assert!(
        result
            .external_ids
            .expect("external ids")
            .iter()
            .all(|value| value.is_some())
    );
}

#[test]
fn collect_query_matches_single_store_scans_once_when_hits_span_multiple_pages() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state(tmp.path());
    let stores = state.published_query_store_sets().expect("query stores");
    let store_lock = &stores[0].stores[0];
    {
        let mut store = lock_candidate_store_blocking(store_lock).expect("lock store");
        for idx in 0..129usize {
            let doc_path = tmp.path().join(format!("single_store_{idx:03}.bin"));
            let payload = format!("xxABCyy{idx:03}");
            fs::write(&doc_path, payload.as_bytes()).expect("write sample");
            let features = scan_features_default_grams(&doc_path).expect("features");
            store
                .insert_document(
                    features.sha256,
                    features.file_size,
                    None,
                    None,
                    None,
                    None,
                    features.bloom_filter.len(),
                    &features.bloom_filter,
                    features.tier2_bloom_filter.len(),
                    &features.tier2_bloom_filter,
                    Some(format!("single_store_{idx:03}.bin")),
                )
                .expect("insert doc");
        }
        let _ = store.persist_meta_if_dirty().expect("persist meta");
        assert_eq!(store.stats().doc_count, 129);
    }

    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![pack_exact_gram(b"ABC")]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$a".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: true,
        allow_tier2_fallback: false,
        max_candidates: 100.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let runtime = state
        .shared_runtime_query_artifacts(&plan)
        .expect("runtime query");
    let mut store = lock_candidate_store_blocking(store_lock).expect("lock store");
    let (hits, _, profile) =
        ServerState::collect_query_matches_single_store(&mut store, &plan, &runtime)
            .expect("single-store query");
    assert_eq!(hits.len(), 129);
    assert_eq!(profile.docs_scanned, 129);
}

#[test]
fn forest_root_server_reports_forest_mode_and_stays_read_only() {
    let tmp = tempdir().expect("tmp");
    let state = sample_forest_server_state(tmp.path(), 1);

    state
        .flush_store_meta_if_dirty()
        .expect("flush forest meta");

    let status = state.status_json().expect("status");
    assert_eq!(
        status.get("workspace_mode").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        status.get("forest_mode").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        status.get("forest_tree_count").and_then(Value::as_u64),
        Some(2)
    );
    assert!(
        status
            .get("forest_root")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .contains("candidate_forest_1")
    );

    let stats = state.current_stats_json().expect("stats");
    assert_eq!(
        stats.get("workspace_mode").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        stats.get("forest_mode").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        stats.get("forest_tree_count").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(2));
    assert_eq!(
        stats.get("candidate_shards").and_then(Value::as_u64),
        Some(1)
    );
    assert!(stats.get("work").is_none());

    let err = state
        .published_store_set()
        .expect_err("forest root should reject single published store access");
    assert!(
        err.to_string()
            .contains("forest-root server has no single published store set"),
        "unexpected published_store_set error: {err}"
    );

    let err = state
        .work_store_set()
        .expect_err("forest root should reject work store access");
    assert!(
        err.to_string()
            .contains("forest-root server is read-only; work store is unavailable"),
        "unexpected work_store_set error: {err}"
    );

    let err = state
        .handle_publish()
        .expect_err("forest root should reject publish");
    assert!(
        err.to_string()
            .contains("publish is not available for forest-root servers"),
        "unexpected publish error: {err}"
    );
}

#[test]
fn direct_server_query_caches_results_and_external_ids() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state(tmp.path());
    let sample = tmp.path().join("direct-cache.bin");
    fs::write(&sample, b"xxABCyy").expect("sample");
    let features = scan_features_default_grams(&sample).expect("features");
    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: hex::encode(features.sha256),
            file_size: features.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("direct-cache.bin".to_owned()),
        })
        .expect("insert doc");

    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![pack_exact_gram(b"ABC")]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
            fixed_literal_wide: vec![false],
            fixed_literal_fullword: vec![false],
        }],
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$a".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
        force_tier1_only: true,
        allow_tier2_fallback: false,
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let request = CandidateQueryRequest {
        plan: Value::Null,
        cursor: 0,
        chunk_size: Some(8),
        include_external_ids: true,
    };

    let first = state
        .handle_candidate_query(request.clone(), &plan)
        .expect("first query");
    let second = state
        .handle_candidate_query(request, &plan)
        .expect("second query");

    for result in [first, second] {
        assert_eq!(result.total_candidates, 1);
        assert_eq!(result.returned_count, 1);
        assert_eq!(
            result.external_ids,
            Some(vec![Some("direct-cache.bin".to_owned())])
        );
    }

    assert_eq!(
        state.query_cache.lock().expect("query cache").len(),
        1,
        "query cache should hold the single compiled-plan result"
    );
    assert_eq!(
        state
            .query_artifact_cache
            .lock()
            .expect("prepared plan cache")
            .len(),
        1,
        "prepared plan cache should hold the single compiled-plan artifacts"
    );
}

#[test]
fn published_query_waits_for_locked_shard() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
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
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };

    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: "11".repeat(32),
            file_size: 16,
            bloom_filter_b64,
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: None,
        })
        .expect("insert");
    state.handle_publish().expect("publish");

    let published = state.published_store_set().expect("published stores");
    let waited = thread::scope(|scope| {
        let store_lock = &published.stores[0];
        let holder = scope.spawn(move || {
            let _guard = store_lock.lock().expect("lock published shard");
            thread::sleep(Duration::from_millis(150));
        });
        thread::sleep(Duration::from_millis(25));

        let started = Instant::now();
        let query = state
            .handle_candidate_query(
                CandidateQueryRequest {
                    plan: Value::Null,
                    cursor: 0,
                    chunk_size: Some(8),
                    include_external_ids: false,
                },
                &plan,
            )
            .expect("query after wait");
        let waited = started.elapsed();
        holder.join().expect("join holder");
        assert_eq!(query.total_candidates, 1);
        waited
    });

    assert!(
        waited >= Duration::from_millis(100),
        "expected query to wait for shard lock, waited {waited:?}"
    );
}

#[test]
fn candidate_query_truncates_when_matches_exceed_max_candidates() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let rule = tmp.path().join("overflow_rule.yar");
    fs::write(
        &rule,
        r#"
rule overflow_rule {
    strings:
        $a = "ABCD"
    condition:
        $a
}
"#,
    )
    .expect("write rule");
    let doc_a = candidate_document_wire_from_bytes(&tmp.path().join("a.bin"), b"xxABCDyy");
    let doc_b = candidate_document_wire_from_bytes(&tmp.path().join("b.bin"), b"ABCDzzzz");
    state
        .handle_candidate_insert_batch(&[doc_a, doc_b])
        .expect("insert docs");
    state.handle_publish().expect("publish");

    let plan = compile_query_plan_from_file_default(&rule, 8, false, true, 1).expect("plan");
    let result = state
        .handle_candidate_query(
            CandidateQueryRequest {
                plan: Value::Null,
                cursor: 0,
                chunk_size: Some(8),
                include_external_ids: false,
            },
            &plan,
        )
        .expect("overflow should truncate");
    assert!(result.truncated);
    assert_eq!(result.truncated_limit, Some(1));
    assert_eq!(result.total_candidates, 1);
    assert_eq!(result.returned_count, 1);
    assert_eq!(result.identities.len(), 1);
}

#[test]
fn store_set_cache_helpers_work() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let store = CandidateStore::init(
        CandidateConfig {
            root: root.clone(),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init store");
    let store_set = StoreSet::new(root, vec![store]);
    assert!(store_set.cached_stats().expect("empty cache").is_none());
    store_set
        .set_cached_stats(Map::from_iter([("docs".to_owned(), Value::from(1u64))]), 42)
        .expect("set cache");
    let cached = store_set
        .cached_stats()
        .expect("cached stats")
        .expect("cache entry");
    assert_eq!(cached.0.get("docs").and_then(Value::as_u64), Some(1));
    assert_eq!(cached.1, 42);
    store_set
        .invalidate_stats_cache()
        .expect("invalidate cache");
    assert!(store_set.cached_stats().expect("cache cleared").is_none());
    let stores = store_set.into_stores().expect("into stores");
    assert_eq!(stores.len(), 1);
}

#[test]
fn store_set_root_and_retarget_root_clear_cache() {
    let tmp = tempdir().expect("tmp");
    let root_a = tmp.path().join("candidate_db_a");
    let root_b = tmp.path().join("candidate_db_b");
    let store = CandidateStore::init(
        CandidateConfig {
            root: root_a.clone(),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init store");
    let store_set = StoreSet::new(root_a.clone(), vec![store]);
    assert_eq!(store_set.root().expect("root"), root_a);
    store_set
        .set_cached_stats(Map::from_iter([("docs".to_owned(), Value::from(9u64))]), 99)
        .expect("set cache");
    assert!(store_set.cached_stats().expect("cached").is_some());

    store_set.retarget_root(&root_b, 1).expect("retarget root");

    assert_eq!(store_set.root().expect("retargeted root"), root_b);
    assert!(
        store_set
            .cached_stats()
            .expect("cache after retarget")
            .is_none(),
        "retargeting should invalidate cached stats"
    );
}

#[test]
fn status_json_does_not_require_shard_locks() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state(tmp.path());
    let work = state.work_store_set().expect("work stores");
    let _guard = work.stores[0].lock().expect("lock store");
    let status = state.status_json().expect("light status");
    assert_eq!(
        status.get("workspace_mode").and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        status
            .get("index_session")
            .and_then(Value::as_object)
            .is_some()
    );
}

#[test]
fn insert_is_rejected_while_publish_pauses_mutations() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state(tmp.path());
    state.mutations_paused.store(true, Ordering::SeqCst);
    let err = state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: "11".repeat(32),
            file_size: 1,
            bloom_filter_b64: String::new(),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: None,
        })
        .expect_err("insert should be rejected");
    assert!(
        err.to_string().contains("server is publishing"),
        "unexpected error: {err}"
    );
}

#[test]
fn index_session_is_exclusive() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let started = state.handle_begin_index_session().expect("start session");
    assert_eq!(started.message, "index session started");
    let err = state
        .handle_begin_index_session()
        .expect_err("second session should fail");
    assert!(
        err.to_string()
            .contains("another index session is already active"),
        "unexpected error: {err}"
    );
    let finished = state.handle_end_index_session().expect("finish session");
    assert_eq!(finished.message, "index session finished");
}

#[test]
fn index_session_progress_is_reported_in_stats() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.handle_begin_index_session().expect("start session");
    state
        .handle_update_index_session_progress(&CandidateIndexSessionProgressRequest {
            total_documents: Some(1000),
            submitted_documents: 320,
            processed_documents: 250,
        })
        .expect("update progress");
    state.mark_work_mutation();

    let stats = state.current_stats_json().expect("stats");
    let index_session = stats
        .get("index_session")
        .and_then(Value::as_object)
        .expect("index session object");
    assert_eq!(
        index_session.get("total_documents").and_then(Value::as_u64),
        Some(1000)
    );
    assert_eq!(
        index_session
            .get("submitted_documents")
            .and_then(Value::as_u64),
        Some(320)
    );
    assert_eq!(
        index_session
            .get("processed_documents")
            .and_then(Value::as_u64),
        Some(250)
    );
    assert_eq!(
        index_session
            .get("remaining_documents")
            .and_then(Value::as_u64),
        Some(750)
    );
    let publish = stats
        .get("publish")
        .and_then(Value::as_object)
        .expect("publish object");
    assert_eq!(
        publish.get("blocked_reason").and_then(Value::as_str),
        Some("active_index_sessions")
    );
    assert_eq!(publish.get("pending").and_then(Value::as_bool), Some(true));
}

#[test]
fn index_client_heartbeat_updates_stats_and_end_client_clears_state() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let started = state
        .handle_begin_index_client(&CandidateIndexClientBeginRequest {
            heartbeat_interval_ms: 10,
        })
        .expect("start client");
    assert_eq!(started.message, "index client started");
    assert_eq!(started.heartbeat_interval_ms, 10);
    assert_eq!(
        state.active_index_clients.load(Ordering::Acquire),
        1,
        "client should be active"
    );

    let before = {
        let leases = state.index_client_leases.lock().expect("lease lock");
        leases
            .get(&started.client_id)
            .expect("client lease")
            .last_heartbeat_unix_ms
    };
    thread::sleep(Duration::from_millis(2));

    let heartbeat = state
        .handle_heartbeat_index_client(&CandidateIndexClientHeartbeatRequest {
            client_id: started.client_id,
        })
        .expect("heartbeat");
    assert_eq!(heartbeat.message, "index client heartbeat updated");

    let after = {
        let leases = state.index_client_leases.lock().expect("lease lock");
        leases
            .get(&started.client_id)
            .expect("client lease")
            .last_heartbeat_unix_ms
    };
    assert!(
        after >= before,
        "heartbeat should refresh the lease timestamp"
    );

    let stats = state.current_stats_json().expect("stats");
    assert_eq!(
        stats.get("active_index_clients").and_then(Value::as_u64),
        Some(1)
    );
    let index_session = stats
        .get("index_session")
        .and_then(Value::as_object)
        .expect("index session object");
    assert_eq!(
        index_session.get("client_active").and_then(Value::as_bool),
        Some(true)
    );

    let finished = state
        .handle_end_index_client(&CandidateIndexClientHeartbeatRequest {
            client_id: started.client_id,
        })
        .expect("finish client");
    assert_eq!(finished.message, "index client finished");
    assert_eq!(state.active_index_clients.load(Ordering::Acquire), 0);
    assert!(
        state.publish_after_index_clients.load(Ordering::Acquire),
        "ending the final client should request publish"
    );

    let err = state
        .handle_heartbeat_index_client(&CandidateIndexClientHeartbeatRequest {
            client_id: started.client_id,
        })
        .expect_err("stale heartbeat should fail");
    assert!(
        err.to_string()
            .contains("no active index client; heartbeat rejected"),
        "unexpected error: {err}"
    );
}

#[test]
fn expiring_last_index_client_clears_orphaned_index_session() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let started = state
        .handle_begin_index_client(&CandidateIndexClientBeginRequest {
            heartbeat_interval_ms: 1,
        })
        .expect("start client");
    state.handle_begin_index_session().expect("start session");
    assert_eq!(state.active_index_sessions.load(Ordering::Acquire), 1);
    thread::sleep(Duration::from_millis(
        started.lease_timeout_ms.saturating_add(2),
    ));
    let remaining = state
        .prune_expired_index_clients(current_unix_ms())
        .expect("prune expired clients");
    assert_eq!(remaining, 0);
    assert_eq!(state.active_index_clients.load(Ordering::Acquire), 0);
    assert_eq!(state.active_index_sessions.load(Ordering::Acquire), 0);
    assert!(
        state.publish_after_index_clients.load(Ordering::Acquire),
        "expiring the final client should request publish"
    );
}

#[test]
fn search_requests_are_serialized() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let first = state.begin_search_request().expect("first search");
    let second_acquired = Arc::new(AtomicBool::new(false));
    let second_state = state.clone();
    let second_acquired_flag = second_acquired.clone();
    let second = thread::spawn(move || {
        let _guard = second_state.begin_search_request().expect("second search");
        second_acquired_flag.store(true, Ordering::SeqCst);
    });
    thread::sleep(Duration::from_millis(20));
    assert!(
        !second_acquired.load(Ordering::SeqCst),
        "second search should wait while the first is active"
    );
    drop(first);
    second.join().expect("second join");
    assert!(
        second_acquired.load(Ordering::SeqCst),
        "second search should acquire after the first completes"
    );
}

#[test]
fn insert_batch_advances_active_index_session_progress() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.handle_begin_index_session().expect("start session");
    state
        .handle_update_index_session_progress(&CandidateIndexSessionProgressRequest {
            total_documents: Some(10),
            submitted_documents: 0,
            processed_documents: 0,
        })
        .expect("set total");
    let sample_a = tmp.path().join("session-a.bin");
    let sample_b = tmp.path().join("session-b.bin");
    fs::write(&sample_a, b"xxABCDyy").expect("sample a");
    fs::write(&sample_b, b"zzWXYZqq").expect("sample b");
    let features_a = scan_features_default_grams(&sample_a).expect("features a");
    let features_b = scan_features_default_grams(&sample_b).expect("features b");
    let docs = vec![
        CandidateDocumentWire {
            identity: hex::encode(features_a.sha256),
            file_size: features_a.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_a.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: None,
        },
        CandidateDocumentWire {
            identity: hex::encode(features_b.sha256),
            file_size: features_b.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_b.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: None,
        },
    ];
    let inserted = state
        .handle_candidate_insert_batch(&docs)
        .expect("insert batch");
    assert_eq!(inserted.inserted_count, 2);
    let stats = state.current_stats_json().expect("stats");
    let index_session = stats
        .get("index_session")
        .and_then(Value::as_object)
        .expect("index session object");
    assert_eq!(
        index_session
            .get("submitted_documents")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        index_session
            .get("processed_documents")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        index_session
            .get("remaining_documents")
            .and_then(Value::as_u64),
        Some(8)
    );
    let server_insert_batch_profile = index_session
        .get("server_insert_batch_profile")
        .and_then(Value::as_object)
        .expect("server insert batch profile");
    assert_eq!(
        server_insert_batch_profile
            .get("batches")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        server_insert_batch_profile
            .get("documents")
            .and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        server_insert_batch_profile
            .get("shards_touched_total")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        server_insert_batch_profile
            .get("store_append_sidecars_us")
            .and_then(Value::as_u64)
            .is_some()
    );
}

#[test]
fn current_stats_json_uses_cached_store_set_snapshot() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.mark_work_mutation();
    let work = state.work_store_set().expect("work");
    let _ = state.current_stats_json().expect("prime stats cache");
    let published = state.published_store_set().expect("published");
    let _published_guard = published.stores[0].lock().expect("lock published");
    let _work_guard = work.stores[0].lock().expect("lock work");
    let stats = state.current_stats_json().expect("cached stats");
    assert_eq!(
        stats.get("workspace_mode").and_then(Value::as_bool),
        Some(true)
    );
}

#[test]
fn publish_stats_show_idle_readiness_and_last_publish_metadata() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.mark_work_mutation();
    state.last_work_mutation_unix_ms.store(
        current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
        Ordering::SeqCst,
    );

    let stats_before = state.current_stats_json().expect("stats before");
    let publish_before = stats_before
        .get("publish")
        .and_then(Value::as_object)
        .expect("publish before");
    assert_eq!(
        publish_before.get("eligible").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        publish_before.get("blocked_reason").and_then(Value::as_str),
        Some("ready")
    );

    let response = state.handle_publish().expect("publish");
    assert!(response.message.contains("published work root"));

    let stats_after = state.current_stats_json().expect("stats after");
    let publish_after = stats_after
        .get("publish")
        .and_then(Value::as_object)
        .expect("publish after");
    assert_eq!(
        publish_after.get("pending").and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        publish_after
            .get("publish_runs_total")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(
        publish_after
            .get("last_publish_completed_unix_ms")
            .and_then(Value::as_u64)
            .unwrap_or(0)
            > 0
    );
    assert!(
        publish_after
            .get("last_publish_duration_ms")
            .and_then(Value::as_u64)
            .is_some()
    );
    assert_eq!(
        publish_after
            .get("last_publish_reused_work_stores")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert!(
        publish_after
            .get("last_publish_swap_ms")
            .and_then(Value::as_u64)
            .is_some()
    );
    assert!(
        publish_after
            .get("last_publish_promote_work_ms")
            .and_then(Value::as_u64)
            .is_some()
    );
    assert!(
        publish_after
            .get("last_publish_init_work_ms")
            .and_then(Value::as_u64)
            .is_some()
    );
}

#[test]
fn workspace_delete_only_targets_current_store() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let doc = candidate_document_wire_from_bytes(&tmp.path().join("queued.bin"), b"queued-current");
    let sha256 = doc.identity.clone();

    state
        .handle_candidate_insert(&doc)
        .expect("insert unpublished doc");

    let deleted = state
        .handle_candidate_delete(&sha256)
        .expect("delete unpublished doc");
    assert_eq!(deleted.status, "missing");

    let work = state.work_store_set().expect("work stores");
    let work_stats = work.stores[0].lock().expect("lock work store").stats();
    assert_eq!(work_stats.doc_count, 1);
    assert_eq!(work_stats.deleted_doc_count, 0);

    let published = state.published_store_set().expect("published stores");
    let published_stats = published.stores[0]
        .lock()
        .expect("lock published store")
        .stats();
    assert_eq!(published_stats.doc_count, 0);
    assert_eq!(published_stats.deleted_doc_count, 0);

    state.handle_publish().expect("publish queued doc");

    let stats = state.current_stats_json().expect("published stats");
    assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        stats.get("active_doc_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        stats.get("deleted_doc_count").and_then(Value::as_u64),
        Some(0)
    );
}

#[test]
fn workspace_compaction_reclaims_deleted_docs_from_current_store() {
    let tmp = tempdir().expect("tmp");
    let state = Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: tmp.path().join("candidate_workspace_compact"),
                    compaction_idle_cooldown_s: 0.0,
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: true,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("workspace server state"),
    );

    let mut sha256s = Vec::new();
    for (name, bytes) in [
        ("compact-first.bin", b"first-current".as_slice()),
        ("compact-second.bin", b"second-current".as_slice()),
    ] {
        let doc = candidate_document_wire_from_bytes(&tmp.path().join(name), bytes);
        sha256s.push(doc.identity.clone());
        state.handle_candidate_insert(&doc).expect("insert doc");
    }

    state.handle_publish().expect("publish docs");

    let deleted = state
        .handle_candidate_delete(&sha256s[1])
        .expect("delete published doc");
    assert_eq!(deleted.status, "deleted");

    let stats_after_delete = state.current_stats_json().expect("stats after delete");
    assert_eq!(
        stats_after_delete
            .get("active_doc_count")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        stats_after_delete
            .get("deleted_doc_count")
            .and_then(Value::as_u64),
        Some(1)
    );

    state
        .run_compaction_cycle_for_tests()
        .expect("run compaction cycle");

    let stats = state.current_stats_json().expect("stats after compaction");
    assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(1));
    assert_eq!(
        stats.get("active_doc_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        stats.get("deleted_doc_count").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        stats.get("deleted_storage_bytes").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        stats.get("compaction_runs_total").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        stats
            .get("last_compaction_reclaimed_docs")
            .and_then(Value::as_u64),
        Some(1)
    );

    let work = stats
        .get("work")
        .and_then(Value::as_object)
        .expect("workspace work stats");
    assert_eq!(work.get("doc_count").and_then(Value::as_u64), Some(0));
}

#[test]
fn publish_readiness_respects_adaptive_initial_idle() {
    let tmp = tempdir().expect("tmp");
    let mut config = ServerConfig {
        candidate_config: CandidateConfig {
            root: tmp.path().join("candidate_workspace_zero_idle"),
            ..CandidateConfig::default()
        },
        candidate_shards: 1,
        search_workers: 1,
        memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
        auto_publish_initial_idle_ms: 0,
        auto_publish_storage_class: "solid-state".to_owned(),
        workspace_mode: true,
    };
    let state = Arc::new(
        ServerState::new(config.clone(), Arc::new(AtomicBool::new(false))).expect("state"),
    );
    state.mark_work_mutation();
    let readiness = state.publish_readiness(current_unix_ms());
    assert!(readiness.eligible);
    assert_eq!(readiness.idle_remaining_ms, 0);

    config.auto_publish_initial_idle_ms = 500;
    config.auto_publish_storage_class = "unknown".to_owned();
    let state =
        Arc::new(ServerState::new(config, Arc::new(AtomicBool::new(false))).expect("state"));
    state.mark_work_mutation();
    let readiness = state.publish_readiness(current_unix_ms());
    assert!(!readiness.eligible);
    assert_eq!(readiness.idle_threshold_ms, 500);
}

#[test]
fn adaptive_publish_backs_off_when_seal_backlog_starts_rising() {
    let mut adaptive = AdaptivePublishState::new("solid-state".to_owned(), 0, 4);
    adaptive.update_seal_backlog(1_000, 1);

    let snapshot = adaptive.snapshot(1_000, 1);
    assert_eq!(snapshot.mode, "backoff");
    assert_eq!(snapshot.reason, "seal_backlog_rising");
    assert_eq!(snapshot.current_idle_ms, 2_000);
    assert_eq!(snapshot.tier2_pending_shards, 1);
}

#[test]
fn adaptive_publish_drops_back_to_fast_when_backlog_drains() {
    let mut adaptive = AdaptivePublishState::new("solid-state".to_owned(), 2_000, 4);
    adaptive.update_seal_backlog(1_000, 1);
    adaptive.update_seal_backlog(2_000, 0);

    let snapshot = adaptive.snapshot(2_000, 0);
    assert_eq!(snapshot.mode, "fast");
    assert_eq!(snapshot.reason, "healthy");
    assert_eq!(snapshot.current_idle_ms, 0);
    assert_eq!(snapshot.healthy_cycles, 1);
}

#[test]
fn adaptive_publish_backs_off_on_submit_pressure() {
    let mut adaptive = AdaptivePublishState::new("unknown".to_owned(), 0, 8);
    adaptive.update_completed_index_session(ADAPTIVE_PUBLISH_BACKOFF_SUBMIT_MS + 1, 0);
    adaptive.update_seal_backlog(5_000, 0);

    let snapshot = adaptive.snapshot(5_000, 0);
    assert_eq!(snapshot.mode, "backoff");
    assert_eq!(snapshot.reason, "submit_pressure_high");
    assert_eq!(snapshot.current_idle_ms, 2_500);
    assert_eq!(
        snapshot.recent_submit_p95_ms,
        ADAPTIVE_PUBLISH_BACKOFF_SUBMIT_MS + 1
    );
}

#[test]
fn publish_waits_for_active_mutations_to_drain() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.active_mutations.store(1, Ordering::SeqCst);
    let release = state.clone();
    thread::spawn(move || {
        thread::sleep(Duration::from_millis(120));
        release.active_mutations.fetch_sub(1, Ordering::AcqRel);
    });
    let started = Instant::now();
    let publish = state.handle_publish().expect("publish");
    assert!(publish.message.contains("published work root"));
    assert!(
        started.elapsed() >= Duration::from_millis(100),
        "publish did not wait for active mutations"
    );
}

#[test]
fn publish_does_not_wait_for_active_index_sessions_once_mutations_are_quiescent() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.active_index_sessions.store(1, Ordering::SeqCst);
    let started = Instant::now();
    let publish = state.handle_publish().expect("publish");
    assert!(publish.message.contains("published work root"));
    assert!(
        started.elapsed() < Duration::from_millis(100),
        "publish should not wait for the index session to end once mutations are drained"
    );
}

#[test]
fn publish_requested_blocks_new_index_sessions_while_waiting_for_active_session() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.active_index_sessions.store(1, Ordering::SeqCst);
    state.active_mutations.store(1, Ordering::SeqCst);
    let publish_state = state.clone();
    let publish_thread = thread::spawn(move || publish_state.handle_publish());

    let started = Instant::now();
    while !state.publish_requested.load(Ordering::Acquire) {
        assert!(
            started.elapsed() < Duration::from_secs(2),
            "publish request did not become visible"
        );
        thread::sleep(Duration::from_millis(10));
    }

    let err = state
        .handle_begin_index_session()
        .expect_err("new session should be blocked while publish is pending");
    assert!(
        err.to_string()
            .contains("server is publishing; index session unavailable; retry later")
    );

    state.active_mutations.store(0, Ordering::SeqCst);
    let publish = publish_thread
        .join()
        .expect("join publish thread")
        .expect("publish result");
    assert!(publish.message.contains("published work root"));
}

#[test]
fn publish_prunes_workspace_retired_roots_immediately_when_keep_is_zero() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let workspace_root = tmp.path().join("candidate_workspace_1");
    let retired_root = workspace_retired_root(&workspace_root);

    state.mark_work_mutation();
    state.last_work_mutation_unix_ms.store(
        current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
        Ordering::SeqCst,
    );
    state.handle_publish().expect("first publish");

    let first_retired = retired_root.join("published_0000000000001");
    fs::create_dir_all(&first_retired).expect("create first retained root");
    let second_retired = retired_root.join("published_9999999999999");
    fs::create_dir_all(&second_retired).expect("create second retained root");

    state.mark_work_mutation();
    state.last_work_mutation_unix_ms.store(
        current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
        Ordering::SeqCst,
    );
    state.handle_publish().expect("second publish");
    state
        .run_retired_root_prune_cycle()
        .expect("retired prune cycle");

    let retained = workspace_retired_roots(&retired_root);
    assert_eq!(retained.len(), DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP);
    assert!(!first_retired.exists());
    assert!(!second_retired.exists());
}

#[test]
fn workspace_startup_prunes_old_retired_roots() {
    let tmp = tempdir().expect("tmp");
    let workspace_root = tmp.path().join("candidate_workspace_1");
    let retired_root = workspace_retired_root(&workspace_root);
    fs::create_dir_all(&retired_root).expect("create retired parent");
    let older = retired_root.join("published_0000000000001");
    let newer = retired_root.join("published_0000000000002");
    fs::create_dir_all(&older).expect("create older retired root");
    fs::create_dir_all(&newer).expect("create newer retired root");

    let state = sample_workspace_server_state(tmp.path(), 1);
    let retained = workspace_retired_roots(&retired_root);
    assert_eq!(retained.len(), DEFAULT_WORKSPACE_RETIRED_ROOTS_TO_KEEP);
    assert!(!older.exists());
    assert!(!newer.exists());
    assert!(state.startup_cleanup_removed_roots >= 1);
}

#[test]
fn workspace_startup_rejects_retired_single_work_root() {
    let tmp = tempdir().expect("tmp");
    let workspace_root = tmp.path().join("candidate_workspace_1");
    let legacy_work_root = workspace_root.join("work");
    let (legacy_stores, _, _) = ensure_candidate_stores_at_root(
        &ServerConfig {
            candidate_config: CandidateConfig {
                root: workspace_root.clone(),
                ..CandidateConfig::default()
            },
            candidate_shards: 1,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: true,
        },
        &legacy_work_root,
    )
    .expect("init legacy work root");
    assert_eq!(legacy_stores.len(), 1);
    assert!(legacy_work_root.exists());
    assert!(!workspace_work_root_a(&workspace_root).exists());
    assert!(!workspace_work_root_b(&workspace_root).exists());

    let err = ServerState::new(
        ServerConfig {
            candidate_config: CandidateConfig {
                root: workspace_root.clone(),
                ..CandidateConfig::default()
            },
            candidate_shards: 1,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: true,
        },
        Arc::new(AtomicBool::new(false)),
    )
    .expect_err("workspace startup must fail");
    assert!(err.to_string().contains("retired workspace work/ root"));
}

#[test]
fn workspace_work_roots_are_lazy_and_removed_when_idle() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let workspace_root = tmp.path().join("candidate_workspace_1");
    let work_root_a = workspace_work_root_a(&workspace_root);
    let work_root_b = workspace_work_root_b(&workspace_root);

    assert!(!work_root_a.exists());
    assert!(!work_root_b.exists());

    let sample = tmp.path().join("lazy-work-doc.bin");
    fs::write(&sample, b"xxABCDyy").expect("sample");
    let features = scan_features_default_grams(&sample).expect("features");
    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: hex::encode(features.sha256),
            file_size: features.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("lazy-work-doc".to_owned()),
        })
        .expect("insert doc");

    assert!(work_root_a.exists());
    assert!(!work_root_b.exists());

    state.handle_publish().expect("publish");

    assert!(!work_root_a.exists());
    assert!(!work_root_b.exists());
}

#[test]
fn workspace_mode_keeps_queries_on_published_root_until_publish() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let workspace_root = tmp.path().join("candidate_workspace_1");
    let sample = tmp.path().join("workspace-doc.bin");
    fs::write(&sample, b"xxABCDyy").expect("sample");
    let gram = pack_exact_gram(b"ABC");
    let features = scan_features_default_grams(&sample).expect("features");
    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: hex::encode(features.sha256),
            file_size: features.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("work-doc".to_owned()),
        })
        .expect("insert doc");

    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
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
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let request = CandidateQueryRequest {
        plan: Value::Null,
        cursor: 0,
        chunk_size: None,
        include_external_ids: false,
    };
    let before = state
        .handle_candidate_query(request.clone(), &plan)
        .expect("query before publish");
    assert_eq!(before.total_candidates, 0);

    let stats_before = state.current_stats_json().expect("stats before");
    assert_eq!(
        stats_before.get("workspace_mode").and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        stats_before.get("doc_count").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        stats_before
            .get("work")
            .and_then(Value::as_object)
            .and_then(|work| work.get("doc_count"))
            .and_then(Value::as_u64),
        Some(1)
    );

    let publish = state.handle_publish().expect("publish");
    assert!(publish.message.contains("published work root"));

    let after = state
        .handle_candidate_query(request, &plan)
        .expect("query after publish");
    assert_eq!(after.total_candidates, 1);

    let stats_after = state.current_stats_json().expect("stats after");
    assert_eq!(
        stats_after.get("doc_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        stats_after
            .get("work")
            .and_then(Value::as_object)
            .and_then(|work| work.get("doc_count"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        stats_after
            .get("publish")
            .and_then(Value::as_object)
            .and_then(|publish| publish.get("last_publish_reused_work_stores"))
            .and_then(Value::as_bool),
        Some(true)
    );
    assert_eq!(
        stats_after
            .get("publish")
            .and_then(Value::as_object)
            .and_then(|publish| publish.get("publish_runs_total"))
            .and_then(Value::as_u64),
        Some(1)
    );
    assert!(!workspace_work_root_a(&workspace_root).exists());
    assert!(!workspace_work_root_b(&workspace_root).exists());
}

#[test]
fn auto_publish_promotes_work_after_index_session_finishes() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let sample = tmp.path().join("auto-publish.bin");
    fs::write(&sample, b"xxABCDyy").expect("sample");
    let gram = pack_exact_gram(b"ABC");
    let features = scan_features_default_grams(&sample).expect("features");
    state
        .handle_begin_index_session()
        .expect("begin index session");
    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: hex::encode(features.sha256),
            file_size: features.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("auto-publish-doc".to_owned()),
        })
        .expect("insert doc");
    state.handle_end_index_session().expect("end index session");
    state.last_work_mutation_unix_ms.store(
        current_unix_ms().saturating_sub(DEFAULT_AUTO_PUBLISH_IDLE_MS + 1),
        Ordering::SeqCst,
    );
    state.run_auto_publish_cycle().expect("auto publish");

    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
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
        max_candidates: 8.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let result = state
        .handle_candidate_query(
            CandidateQueryRequest {
                plan: Value::Null,
                cursor: 0,
                chunk_size: None,
                include_external_ids: false,
            },
            &plan,
        )
        .expect("query");
    assert_eq!(result.total_candidates, 1);
    assert!(!state.work_dirty.load(Ordering::Acquire));
}

#[test]
fn publish_readiness_stays_blocked_with_active_index_session_under_pressure() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.work_dirty.store(true, Ordering::SeqCst);
    state.active_index_sessions.store(1, Ordering::SeqCst);
    state
        .work_active_estimated_documents
        .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
    state
        .last_work_mutation_unix_ms
        .store(current_unix_ms(), Ordering::SeqCst);

    let readiness = state.publish_readiness(current_unix_ms());
    assert!(!readiness.eligible);
    assert_eq!(readiness.blocked_reason, "active_index_sessions");
    assert_eq!(readiness.trigger_mode, "blocked");
}

#[test]
fn auto_publish_does_not_rotate_work_while_index_session_is_active_under_pressure() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    let sample = tmp.path().join("pressure-publish.bin");
    fs::write(&sample, b"xxABCDyy").expect("sample");
    let features = scan_features_default_grams(&sample).expect("features");
    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: hex::encode(features.sha256),
            file_size: features.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("pressure-doc".to_owned()),
        })
        .expect("insert doc");
    state.active_index_sessions.store(1, Ordering::SeqCst);
    state
        .work_active_estimated_documents
        .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
    state.run_auto_publish_cycle().expect("auto publish cycle");

    let stats = state.current_stats_json().expect("stats");
    assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(0),);
    assert_eq!(
        stats
            .get("publish")
            .and_then(Value::as_object)
            .and_then(|publish| publish.get("publish_runs_total"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        stats
            .get("work")
            .and_then(Value::as_object)
            .and_then(|work| work.get("doc_count"))
            .and_then(Value::as_u64),
        Some(1)
    );
}

#[test]
fn publish_in_progress_enables_insert_backpressure() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state_with_budget(tmp.path(), 1, 32 * 1024 * 1024);
    state.active_index_sessions.store(1, Ordering::SeqCst);
    state.publish_in_progress.store(true, Ordering::SeqCst);
    state
        .work_active_estimated_documents
        .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
    let pressure = state.work_buffer_pressure_snapshot(0, 0);
    assert_eq!(
        pressure.index_backpressure_delay_ms,
        INDEX_BACKPRESSURE_HEAVY_DELAY_MS
    );
}

#[test]
fn publish_readiness_reports_seal_backlog_without_enabling_pressure_publish() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.work_dirty.store(true, Ordering::SeqCst);
    state.active_index_sessions.store(1, Ordering::SeqCst);
    state
        .work_active_estimated_documents
        .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
    state
        .last_work_mutation_unix_ms
        .store(current_unix_ms(), Ordering::SeqCst);
    state
        .enqueue_published_tier2_snapshot_shards([0usize])
        .expect("enqueue tier2 shard");

    let readiness = state.publish_readiness(current_unix_ms());
    assert!(!readiness.eligible);
    assert_eq!(readiness.blocked_reason, "active_index_sessions");
    assert!(readiness.pending_tier2_snapshot_shards > 0);
    assert_eq!(readiness.pending_tier2_snapshot_shards, 1);
}

#[test]
fn seal_backlog_pressure_does_not_add_backpressure_when_pressure_publish_is_disabled() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state_with_budget(tmp.path(), 1, 32 * 1024 * 1024);
    state.active_index_sessions.store(1, Ordering::SeqCst);
    state
        .work_active_estimated_documents
        .store(state.work_buffer_document_threshold(), Ordering::SeqCst);
    state
        .enqueue_published_tier2_snapshot_shards([0usize])
        .expect("enqueue tier2 shard");

    let pressure = state.work_buffer_pressure_snapshot(0, 1);
    assert!(pressure.pending_tier2_snapshot_shards > 0);
    assert_eq!(pressure.index_backpressure_delay_ms, 0);
}

#[test]
fn pressure_thresholds_shrink_after_first_publish_during_active_index() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);
    state.active_index_sessions.store(1, Ordering::SeqCst);
    state.publish_runs_total.store(1, Ordering::SeqCst);

    let pressure = state.work_buffer_pressure_snapshot(0, 0);
    assert_eq!(
        pressure.document_threshold,
        WORK_BUFFER_REPUBLISH_MAX_DOCUMENT_THRESHOLD
    );
    assert_eq!(
        pressure.input_bytes_threshold,
        WORK_BUFFER_REPUBLISH_MIN_INPUT_BYTES_THRESHOLD
    );
}

#[test]
fn workspace_publish_merges_incremental_work_into_published_root() {
    let tmp = tempdir().expect("tmp");
    let state = sample_workspace_server_state(tmp.path(), 1);

    let sample_a = tmp.path().join("inc-a.bin");
    fs::write(&sample_a, b"xxABCDyy").expect("sample a");
    let features_a = scan_features_default_grams(&sample_a).expect("features a");
    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: hex::encode(features_a.sha256),
            file_size: features_a.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_a.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("inc-a".to_owned()),
        })
        .expect("insert a");
    state.handle_publish().expect("publish a");

    let sample_b = tmp.path().join("inc-b.bin");
    fs::write(&sample_b, b"xxWXYZyy").expect("sample b");
    let features_b = scan_features_default_grams(&sample_b).expect("features b");
    state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: hex::encode(features_b.sha256),
            file_size: features_b.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_b.bloom_filter),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("inc-b".to_owned()),
        })
        .expect("insert b");
    state.handle_publish().expect("publish b");

    let stats = state.current_stats_json().expect("stats");
    assert_eq!(stats.get("doc_count").and_then(Value::as_u64), Some(2));
    assert_eq!(
        stats
            .get("publish")
            .and_then(Value::as_object)
            .and_then(|publish| publish.get("retired_published_root_count"))
            .and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        stats
            .get("work")
            .and_then(Value::as_object)
            .and_then(|work| work.get("doc_count"))
            .and_then(Value::as_u64),
        Some(0)
    );
}

#[test]
fn candidate_stats_json_contains_current_scan_policy_fields() {
    let tmp = tempdir().expect("tmp");
    let config = CandidateConfig {
        root: tmp.path().join("candidate_db"),
        ..CandidateConfig::default()
    };
    let store = CandidateStore::init(config.clone(), true).expect("init");
    let stats = candidate_stats_json(&config.root, &store);
    assert!(stats.contains_key("disk_usage_bytes"));
    assert_eq!(
        stats.get("tier2_gram_size").and_then(Value::as_u64),
        Some(4)
    );
    assert_eq!(
        stats.get("tier1_gram_size").and_then(Value::as_u64),
        Some(3)
    );
    assert_eq!(
        stats.get("tier1_filter_target_fp").and_then(Value::as_f64),
        Some(0.38)
    );
    assert_eq!(
        stats.get("tier2_filter_target_fp").and_then(Value::as_f64),
        Some(0.18)
    );
    assert_eq!(stats.get("filter_target_fp"), None);
}

#[test]
fn candidate_stats_json_reports_compaction_generation_fields() {
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
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter = lane_bloom_bytes(32, 7, &[gram]);

    for byte in [0x11u8, 0x22u8] {
        store
            .insert_document(
                [byte; 32],
                32,
                None,
                Some(2),
                None,
                None,
                32,
                &bloom_filter,
                0,
                &[],
                Some(format!("doc-{byte:02x}")),
            )
            .expect("insert");
    }
    store
        .delete_document(&hex::encode([0x22; 32]))
        .expect("delete");
    let snapshot = store
        .prepare_compaction_snapshot(true)
        .expect("snapshot")
        .expect("snapshot available");
    let compacted_root = compaction_work_root(&root, "stats-compact");
    write_compacted_snapshot(&snapshot, &compacted_root).expect("write compacted");
    store
        .apply_compaction_snapshot(&snapshot, &compacted_root)
        .expect("apply compaction")
        .expect("compaction applied");

    let stats = candidate_stats_json(&root, &store);
    assert_eq!(
        stats.get("compaction_generation").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        stats
            .get("compaction_idle_cooldown_s")
            .and_then(Value::as_f64),
        Some(0.0)
    );
    assert_eq!(
        stats
            .get("compaction_cooldown_remaining_s")
            .and_then(Value::as_f64),
        Some(0.0)
    );
    assert_eq!(
        stats
            .get("compaction_waiting_for_cooldown")
            .and_then(Value::as_bool),
        Some(false)
    );
    assert_eq!(
        stats
            .get("retired_generation_count")
            .and_then(Value::as_u64),
        Some(1)
    );
}

#[test]
fn workspace_and_forest_root_helpers_filter_expected_directories() {
    let tmp = tempdir().expect("tmp");
    let workspace_root = tmp.path().join("workspace");
    let forest_root = tmp.path().join("forest");
    fs::create_dir_all(workspace_root.join("published_002")).expect("published 2");
    fs::create_dir_all(workspace_root.join("published_001")).expect("published 1");
    fs::create_dir_all(workspace_root.join("ignored_dir")).expect("ignored dir");
    fs::write(workspace_root.join("published_003.txt"), b"ignore").expect("ignored file");

    let retired = workspace_retired_roots(&workspace_root);
    assert_eq!(retired.len(), 2);
    assert!(retired[0].ends_with("published_001"));
    assert!(retired[1].ends_with("published_002"));
    let (retired_count, retired_bytes) = workspace_retired_stats(&workspace_root);
    assert_eq!(retired_count, 2);
    assert_eq!(retired_bytes, 0);

    fs::create_dir_all(forest_root.join("tree_00/current")).expect("tree 00 current");
    fs::create_dir_all(forest_root.join("tree_01/current")).expect("tree 01 current");
    fs::create_dir_all(forest_root.join("noise/current")).expect("noise current");
    fs::write(forest_root.join("tree_02.txt"), b"ignore").expect("tree file");

    let trees = forest_tree_roots(&forest_root).expect("forest roots");
    assert_eq!(trees.len(), 2);
    assert!(trees[0].ends_with("tree_00/current"));
    assert!(trees[1].ends_with("tree_01/current"));
}

#[test]
fn bounded_cache_updates_recency_and_evicts_oldest() {
    let mut cache = BoundedCache::new(2);
    cache.insert("a", 1);
    cache.insert("b", 2);
    assert_eq!(cache.get(&"a"), Some(1));
    cache.insert("c", 3);
    assert_eq!(cache.get(&"a"), Some(1));
    assert_eq!(cache.get(&"b"), None);
    assert_eq!(cache.get(&"c"), Some(3));
    cache.insert("a", 4);
    assert_eq!(cache.get(&"a"), Some(4));
    cache.clear();
    assert_eq!(cache.get(&"a"), None);
    assert_eq!(cache.get(&"c"), None);
}

#[test]
fn draining_server_keeps_typed_status_and_stats_available() {
    let tmp = tempdir().expect("tmp");
    let state = ServerState::new(
        ServerConfig {
            candidate_config: CandidateConfig {
                root: tmp.path().join("candidate_db"),
                ..CandidateConfig::default()
            },
            candidate_shards: 1,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: false,
        },
        Arc::new(AtomicBool::new(true)),
    )
    .expect("server state");
    let status = state.grpc_status_response().expect("status works");
    assert!(status.draining);
    let stats = state.grpc_stats_response().expect("stats works");
    assert_eq!(stats.stats.expect("store summary").active_doc_count, 0);
}

#[test]
fn multishard_state_and_insert_parsing_cover_remaining_rpc_branches() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state_with_shards(tmp.path(), 2);
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
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
        max_candidates: 100.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let docs = vec![
        CandidateDocumentWire {
            identity: "00".repeat(32),
            file_size: 16,
            bloom_filter_b64: bloom_filter_b64.clone(),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("shard-a".to_owned()),
        },
        CandidateDocumentWire {
            identity: "01".repeat(32),
            file_size: 16,
            bloom_filter_b64: bloom_filter_b64.clone(),
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("shard-b".to_owned()),
        },
    ];
    let batch = state
        .handle_candidate_insert_batch(&docs)
        .expect("insert multishard batch");
    assert_eq!(batch.inserted_count, 2);
    let query = state
        .handle_candidate_query(
            CandidateQueryRequest {
                plan: Value::Null,
                cursor: 0,
                chunk_size: Some(1),
                include_external_ids: true,
            },
            &plan,
        )
        .expect("query multishard");
    assert_eq!(query.total_candidates, 2);
    assert_eq!(query.returned_count, 1);
    assert!(query.next_cursor.is_some());
    assert!(query.external_ids.is_some());
    let page_two = state
        .handle_candidate_query(
            CandidateQueryRequest {
                plan: Value::Null,
                cursor: 1,
                chunk_size: Some(2),
                include_external_ids: false,
            },
            &plan,
        )
        .expect("query page two");
    assert_eq!(page_two.cursor, 1);
    assert_eq!(page_two.returned_count, 1);
    assert_eq!(page_two.next_cursor, None);
    assert!(page_two.external_ids.is_none());
    let deleted = state
        .handle_candidate_delete(&docs[0].identity)
        .expect("delete first multishard doc");
    assert_eq!(deleted.status, "deleted");
    let query_after_delete = state
        .handle_candidate_query(
            CandidateQueryRequest {
                plan: Value::Null,
                cursor: 0,
                chunk_size: Some(8),
                include_external_ids: false,
            },
            &plan,
        )
        .expect("query after delete");
    assert_eq!(query_after_delete.total_candidates, 1);
    assert!(
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: "ab".repeat(32),
                file_size: 1,
                bloom_filter_b64: "**".to_owned(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            })
            .expect_err("invalid bloom base64")
            .to_string()
            .contains("bloom_filter_b64 must be valid base64")
    );
    assert!(
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: "ab".repeat(32),
                file_size: 1,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            })
            .is_ok()
    );
    assert!(
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: "not hex".to_owned(),
                file_size: 1,
                bloom_filter_b64,
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: None,
            })
            .expect_err("invalid sha")
            .to_string()
            .contains("64 hexadecimal characters")
    );
}

#[test]
fn query_plan_wire_and_store_setup_cover_manifest_errors() {
    let tmp = tempdir().expect("tmp");
    let single_root = tmp.path().join("single");
    CandidateStore::init(
        CandidateConfig {
            root: single_root.clone(),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init single root");
    assert!(
        ensure_candidate_stores(&ServerConfig {
            candidate_config: CandidateConfig {
                root: single_root.clone(),
                ..CandidateConfig::default()
            },
            candidate_shards: 2,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: false,
        })
        .expect_err("single-shard mismatch")
        .to_string()
        .contains("single-shard store")
    );

    let sharded_root = tmp.path().join("sharded");
    CandidateStore::init(
        CandidateConfig {
            root: candidate_shard_root(&sharded_root, 2, 0),
            ..CandidateConfig::default()
        },
        true,
    )
    .expect("init orphaned shard");
    let (stores, _, _) = ensure_candidate_stores(&ServerConfig {
        candidate_config: CandidateConfig {
            root: sharded_root.clone(),
            ..CandidateConfig::default()
        },
        candidate_shards: 1,
        search_workers: 1,
        memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
        auto_publish_initial_idle_ms: 500,
        auto_publish_storage_class: "unknown".to_owned(),
        workspace_mode: false,
    })
    .expect("direct root should normalize to single-store layout");
    assert_eq!(
        match stores {
            StoreMode::Direct { stores } => stores.stores.len(),
            StoreMode::Forest { .. } => 0,
            StoreMode::Workspace { .. } => 0,
        },
        1
    );

    let manifest_root = tmp.path().join("manifest");
    let (stores, _, _) = ensure_candidate_stores(&ServerConfig {
        candidate_config: CandidateConfig {
            root: manifest_root.clone(),
            ..CandidateConfig::default()
        },
        candidate_shards: 2,
        search_workers: 1,
        memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
        auto_publish_initial_idle_ms: 500,
        auto_publish_storage_class: "unknown".to_owned(),
        workspace_mode: false,
    })
    .expect("create sharded stores");
    assert_eq!(
        match stores {
            StoreMode::Direct { stores } => stores.stores.len(),
            StoreMode::Forest { .. } => 0,
            StoreMode::Workspace { .. } => 0,
        },
        2
    );
    assert!(
        ensure_candidate_stores(&ServerConfig {
            candidate_config: CandidateConfig {
                root: manifest_root,
                ..CandidateConfig::default()
            },
            candidate_shards: 1,
            search_workers: 1,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: false,
        })
        .expect_err("manifest mismatch")
        .to_string()
        .contains("candidate shard manifest")
    );
}

#[test]
fn single_shard_query_with_external_ids_and_sha_normalization_work() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state_with_shards(tmp.path(), 1);
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
    let inserted = state
        .handle_candidate_insert(&CandidateDocumentWire {
            identity: "AA".repeat(32),
            file_size: 16,
            bloom_filter_b64,
            bloom_item_estimate: None,
            tier2_bloom_filter_b64: None,
            tier2_bloom_item_estimate: None,
            special_population: false,
            metadata_b64: None,
            external_id: Some("single-shard-id".to_owned()),
        })
        .expect("insert single-shard doc");
    assert_eq!(inserted.status, "inserted");
    let query = state
        .handle_candidate_query(
            CandidateQueryRequest {
                plan: Value::Null,
                cursor: 0,
                chunk_size: None,
                include_external_ids: true,
            },
            &CompiledQueryPlan {
                patterns: vec![PatternPlan {
                    pattern_id: "$a".to_owned(),
                    alternatives: vec![vec![gram]],
                    tier2_alternatives: vec![Vec::new()],
                    anchor_literals: vec![Vec::new()],
                    fixed_literals: vec![Vec::new()],
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
                max_candidates: 5.0,
                tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
                tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
            },
        )
        .expect("single-shard query");
    assert_eq!(query.total_candidates, 1);
    assert_eq!(
        query.external_ids,
        Some(vec![Some("single-shard-id".to_owned())])
    );
    assert_eq!(
        normalize_sha256_hex(&"AA".repeat(32)).expect("normalize"),
        "aa".repeat(32)
    );
    assert_eq!(
        hex::encode(decode_sha256(&"AA".repeat(32)).expect("decode")),
        "aa".repeat(32)
    );
}

#[test]
fn multishard_query_uses_parallel_collection_and_cached_results() {
    let tmp = tempdir().expect("tmp");
    let state = ServerState::new(
        ServerConfig {
            candidate_config: CandidateConfig {
                root: tmp.path().join("candidate_db_parallel"),
                filter_target_fp: None,
                tier1_filter_target_fp: None,
                tier2_filter_target_fp: None,
                ..CandidateConfig::default()
            },
            candidate_shards: 2,
            search_workers: 2,
            memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
            auto_publish_initial_idle_ms: 500,
            auto_publish_storage_class: "unknown".to_owned(),
            workspace_mode: false,
        },
        Arc::new(AtomicBool::new(false)),
    )
    .expect("server state");
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(16, 7, &[gram]));
    let mut docs = Vec::new();
    for byte in 1_u8..=64 {
        let sha = [byte; 32];
        if docs.iter().all(|existing: &[u8; 32]| {
            state.candidate_store_index_for_identity(existing)
                != state.candidate_store_index_for_identity(&sha)
        }) {
            docs.push(sha);
        }
        if docs.len() == 2 {
            break;
        }
    }
    assert_eq!(docs.len(), 2);
    for (index, sha) in docs.into_iter().enumerate() {
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: hex::encode(sha),
                file_size: 16,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some(format!("parallel-{index}")),
            })
            .expect("insert doc");
    }
    let plan = CompiledQueryPlan {
        patterns: vec![PatternPlan {
            pattern_id: "$a".to_owned(),
            alternatives: vec![vec![gram]],
            tier2_alternatives: vec![Vec::new()],
            anchor_literals: vec![Vec::new()],
            fixed_literals: vec![Vec::new()],
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
        max_candidates: 100.0,
        tier2_gram_size: DEFAULT_TIER2_GRAM_SIZE,
        tier1_gram_size: DEFAULT_TIER1_GRAM_SIZE,
    };
    let request = CandidateQueryRequest {
        plan: Value::Null,
        cursor: 0,
        chunk_size: None,
        include_external_ids: true,
    };
    let first = state
        .handle_candidate_query(request.clone(), &plan)
        .expect("first query");
    assert_eq!(first.total_candidates, 2);
    assert_eq!(first.returned_count, 2);
    assert_eq!(first.tier_used, "tier1");
    assert_eq!(first.external_ids.as_ref().map(Vec::len), Some(2));

    let second = state
        .handle_candidate_query(request, &plan)
        .expect("second query");
    assert_eq!(second.identities, first.identities);
    assert_eq!(second.external_ids, first.external_ids);
    assert_eq!(second.tier_used, first.tier_used);
}

#[test]
fn search_work_units_count_direct_shards_and_forest_tree_shards() {
    let tmp = tempdir().expect("tmp");
    let direct_state = sample_server_state_with_shards(tmp.path(), 2);
    let direct_store_sets = direct_state
        .published_query_store_sets()
        .expect("direct query stores");
    assert_eq!(direct_store_sets.len(), 1);
    assert_eq!(ServerState::search_work_units(&direct_store_sets).len(), 2);

    let forest_state = sample_forest_server_state(tmp.path(), 2);
    let forest_store_sets = forest_state
        .published_query_store_sets()
        .expect("forest query stores");
    assert_eq!(forest_store_sets.len(), 2);
    assert_eq!(ServerState::search_work_units(&forest_store_sets).len(), 4);
}

#[test]
fn direct_multishard_stream_candidate_query_frames_returns_hits_from_all_shards() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state_with_shards(tmp.path(), 2);
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
    let mut docs = Vec::new();
    for byte in 1_u8..=64 {
        let sha = [byte; 32];
        if docs.iter().all(|existing: &[u8; 32]| {
            state.candidate_store_index_for_identity(existing)
                != state.candidate_store_index_for_identity(&sha)
        }) {
            docs.push(sha);
        }
        if docs.len() == 2 {
            break;
        }
    }
    assert_eq!(docs.len(), 2);
    for (index, sha) in docs.into_iter().enumerate() {
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: hex::encode(sha),
                file_size: 16,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some(format!("stream-parallel-{index}")),
            })
            .expect("insert doc");
    }

    let request = CandidateQueryRequest {
        plan: Value::Null,
        cursor: 0,
        chunk_size: Some(1),
        include_external_ids: true,
    };
    let plan = exact_abc_plan("$a", 8.0);
    let mut frames = Vec::<CandidateQueryStreamFrame>::new();
    state
        .stream_candidate_query_frames(request, &plan, |frame| {
            frames.push(frame);
            Ok(())
        })
        .expect("stream single rule");

    let stream_complete = frames
        .iter()
        .filter(|frame| frame.stream_complete)
        .collect::<Vec<_>>();
    assert_eq!(stream_complete.len(), 1);
    assert_eq!(stream_complete[0].tier_used, "tier1");
    assert!(stream_complete[0].query_profile.docs_scanned >= 2);

    let mut hashes = Vec::new();
    let mut external_ids = Vec::new();
    for frame in &frames {
        if frame.stream_complete || frame.rule_complete {
            continue;
        }
        hashes.extend(frame.identities.iter().cloned());
        external_ids.extend(frame.external_ids.clone().unwrap_or_default());
    }
    hashes.sort();
    hashes.dedup();
    external_ids.sort();
    external_ids.dedup();
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        external_ids,
        vec![
            Some("stream-parallel-0".to_owned()),
            Some("stream-parallel-1".to_owned())
        ]
    );
}

#[test]
fn direct_multishard_stream_candidate_query_frames_batch_returns_hits_for_each_rule() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state_with_shards(tmp.path(), 2);
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(1024, 7, &[gram]));
    let mut docs = Vec::new();
    for byte in 65_u8..=128 {
        let sha = [byte; 32];
        if docs.iter().all(|existing: &[u8; 32]| {
            state.candidate_store_index_for_identity(existing)
                != state.candidate_store_index_for_identity(&sha)
        }) {
            docs.push(sha);
        }
        if docs.len() == 2 {
            break;
        }
    }
    assert_eq!(docs.len(), 2);
    for (index, sha) in docs.into_iter().enumerate() {
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: hex::encode(sha),
                file_size: 16,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some(format!("batch-parallel-{index}")),
            })
            .expect("insert doc");
    }

    let request = CandidateQueryRequest {
        plan: Value::Null,
        cursor: 0,
        chunk_size: Some(1),
        include_external_ids: true,
    };
    let named_plans = vec![
        ("rule_one".to_owned(), exact_abc_plan("$a", 0.0)),
        ("rule_two".to_owned(), exact_abc_plan("$b", 0.0)),
    ];
    let mut frames = Vec::<CandidateQueryStreamFrame>::new();
    state
        .stream_candidate_query_frames_batch(request, &named_plans, |frame| {
            frames.push(frame);
            Ok(())
        })
        .expect("stream bundled rules");

    let stream_complete = frames
        .iter()
        .filter(|frame| frame.stream_complete)
        .collect::<Vec<_>>();
    assert_eq!(stream_complete.len(), 1);

    let rule_complete = frames
        .iter()
        .filter(|frame| frame.rule_complete)
        .map(|frame| frame.target_rule_name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        rule_complete,
        vec!["rule_one".to_owned(), "rule_two".to_owned()]
    );

    let mut hits_by_rule = HashMap::<String, Vec<String>>::new();
    let mut external_ids_by_rule = HashMap::<String, Vec<Option<String>>>::new();
    for frame in &frames {
        if frame.stream_complete || frame.rule_complete {
            continue;
        }
        hits_by_rule
            .entry(frame.target_rule_name.clone())
            .or_default()
            .extend(frame.identities.iter().cloned());
        external_ids_by_rule
            .entry(frame.target_rule_name.clone())
            .or_default()
            .extend(frame.external_ids.clone().unwrap_or_default());
    }

    for rule_name in ["rule_one", "rule_two"] {
        let Some(hashes) = hits_by_rule.get_mut(rule_name) else {
            panic!("missing hits for {rule_name}");
        };
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 2);

        let Some(external_ids) = external_ids_by_rule.get_mut(rule_name) else {
            panic!("missing external ids for {rule_name}");
        };
        external_ids.sort();
        external_ids.dedup();
        assert_eq!(
            external_ids,
            &vec![
                Some("batch-parallel-0".to_owned()),
                Some("batch-parallel-1".to_owned())
            ]
        );
    }
}

#[test]
fn forest_stream_candidate_query_frames_returns_hits_from_all_trees() {
    let tmp = tempdir().expect("tmp");
    let state = sample_forest_server_state(tmp.path(), 1);
    let request = CandidateQueryRequest {
        plan: Value::Null,
        cursor: 0,
        chunk_size: Some(1),
        include_external_ids: true,
    };
    let plan = exact_abc_plan("$a", 8.0);
    let mut frames = Vec::<CandidateQueryStreamFrame>::new();
    state
        .stream_candidate_query_frames(request, &plan, |frame| {
            frames.push(frame);
            Ok(())
        })
        .expect("stream single rule");

    let stream_complete = frames
        .iter()
        .filter(|frame| frame.stream_complete)
        .collect::<Vec<_>>();
    assert_eq!(stream_complete.len(), 1);
    assert_eq!(stream_complete[0].tier_used, "tier1");
    assert!(stream_complete[0].query_profile.docs_scanned >= 2);

    let mut hashes = Vec::new();
    let mut external_ids = Vec::new();
    for frame in &frames {
        if frame.stream_complete || frame.rule_complete {
            continue;
        }
        hashes.extend(frame.identities.iter().cloned());
        external_ids.extend(frame.external_ids.clone().unwrap_or_default());
    }
    hashes.sort();
    hashes.dedup();
    external_ids.sort();
    external_ids.dedup();
    assert_eq!(hashes.len(), 2);
    assert_eq!(
        external_ids,
        vec![
            Some("tree_00.bin".to_owned()),
            Some("tree_01.bin".to_owned())
        ]
    );
}

#[test]
fn forest_stream_candidate_query_frames_batch_returns_hits_for_each_rule() {
    let tmp = tempdir().expect("tmp");
    let state = sample_forest_server_state(tmp.path(), 1);
    let request = CandidateQueryRequest {
        plan: Value::Null,
        cursor: 0,
        chunk_size: Some(1),
        include_external_ids: true,
    };
    let named_plans = vec![
        ("rule_one".to_owned(), exact_abc_plan("$a", 8.0)),
        ("rule_two".to_owned(), exact_abc_plan("$b", 8.0)),
    ];
    let mut frames = Vec::<CandidateQueryStreamFrame>::new();
    state
        .stream_candidate_query_frames_batch(request, &named_plans, |frame| {
            frames.push(frame);
            Ok(())
        })
        .expect("stream bundled rules");

    let stream_complete = frames
        .iter()
        .filter(|frame| frame.stream_complete)
        .collect::<Vec<_>>();
    assert_eq!(stream_complete.len(), 1);

    let rule_complete = frames
        .iter()
        .filter(|frame| frame.rule_complete)
        .map(|frame| frame.target_rule_name.clone())
        .collect::<Vec<_>>();
    assert_eq!(
        rule_complete,
        vec!["rule_one".to_owned(), "rule_two".to_owned()]
    );

    let mut hits_by_rule = HashMap::<String, Vec<String>>::new();
    let mut external_ids_by_rule = HashMap::<String, Vec<Option<String>>>::new();
    for frame in &frames {
        if frame.stream_complete || frame.rule_complete {
            continue;
        }
        hits_by_rule
            .entry(frame.target_rule_name.clone())
            .or_default()
            .extend(frame.identities.iter().cloned());
        external_ids_by_rule
            .entry(frame.target_rule_name.clone())
            .or_default()
            .extend(frame.external_ids.clone().unwrap_or_default());
    }

    for rule_name in ["rule_one", "rule_two"] {
        let Some(hashes) = hits_by_rule.get_mut(rule_name) else {
            panic!("missing hits for {rule_name}");
        };
        hashes.sort();
        hashes.dedup();
        assert_eq!(hashes.len(), 2);

        let Some(external_ids) = external_ids_by_rule.get_mut(rule_name) else {
            panic!("missing external ids for {rule_name}");
        };
        external_ids.sort();
        external_ids.dedup();
        assert_eq!(
            external_ids,
            &vec![
                Some("tree_00.bin".to_owned()),
                Some("tree_01.bin".to_owned())
            ]
        );
    }
}

#[test]
fn emit_stream_candidate_query_frames_batch_partial_streams_hits_immediately() {
    let named_plans = vec![
        ("rule_one".to_owned(), exact_abc_plan("$a", 8.0)),
        ("rule_two".to_owned(), exact_abc_plan("$b", 8.0)),
    ];
    let candidate_limits = vec![Some(10), Some(20)];
    let mut accumulators = vec![
        BundledQueryAccumulator::default(),
        BundledQueryAccumulator::default(),
    ];
    let mut frames = Vec::<CandidateQueryStreamFrame>::new();

    let mut profile_one = CandidateQueryProfile::default();
    profile_one.docs_scanned = 3;
    let mut profile_two = CandidateQueryProfile::default();
    profile_two.docs_scanned = 4;
    ServerState::emit_stream_candidate_query_frames_batch_partial(
        (
            SearchWorkUnit {
                store_set_idx: 0,
                store_idx: 0,
            },
            vec![
                BundledQueryPartial {
                    hashes: vec!["hash-a".to_owned()],
                    external_ids: Some(vec![Some("ext-a".to_owned())]),
                    tier_used: "tier1".to_owned(),
                    query_profile: profile_one.clone(),
                    eval_nanos: 11,
                },
                BundledQueryPartial {
                    hashes: vec!["hash-b".to_owned(), "hash-c".to_owned()],
                    external_ids: Some(vec![Some("ext-b".to_owned()), None]),
                    tier_used: "tier2".to_owned(),
                    query_profile: profile_two.clone(),
                    eval_nanos: 22,
                },
            ],
        ),
        &named_plans,
        1,
        &candidate_limits,
        &mut accumulators,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    )
    .expect("emit first bundled partial");

    assert_eq!(frames.len(), 3);
    assert!(
        frames
            .iter()
            .all(|frame| !frame.stream_complete && !frame.rule_complete)
    );
    assert_eq!(frames[0].target_rule_name, "rule_one");
    assert_eq!(frames[0].identities, vec!["hash-a".to_owned()]);
    assert_eq!(frames[1].target_rule_name, "rule_two");
    assert_eq!(frames[1].identities, vec!["hash-b".to_owned()]);
    assert_eq!(frames[2].identities, vec!["hash-c".to_owned()]);
    assert_eq!(accumulators[0].tier_used, vec!["tier1".to_owned()]);
    assert_eq!(accumulators[0].query_profile.docs_scanned, 3);
    assert_eq!(accumulators[0].eval_nanos, 11);
    assert_eq!(accumulators[1].tier_used, vec!["tier2".to_owned()]);
    assert_eq!(accumulators[1].query_profile.docs_scanned, 4);
    assert_eq!(accumulators[1].eval_nanos, 22);

    let mut profile_three = CandidateQueryProfile::default();
    profile_three.docs_scanned = 5;
    let prior_frame_count = frames.len();
    ServerState::emit_stream_candidate_query_frames_batch_partial(
        (
            SearchWorkUnit {
                store_set_idx: 1,
                store_idx: 0,
            },
            vec![
                BundledQueryPartial {
                    hashes: vec!["hash-d".to_owned()],
                    external_ids: None,
                    tier_used: "tier1".to_owned(),
                    query_profile: profile_three,
                    eval_nanos: 33,
                },
                BundledQueryPartial {
                    hashes: Vec::new(),
                    external_ids: None,
                    tier_used: String::new(),
                    query_profile: CandidateQueryProfile::default(),
                    eval_nanos: 0,
                },
            ],
        ),
        &named_plans,
        2,
        &candidate_limits,
        &mut accumulators,
        |frame| {
            frames.push(frame);
            Ok(())
        },
    )
    .expect("emit second bundled partial");

    assert_eq!(frames.len(), prior_frame_count + 1);
    assert_eq!(
        frames.last().expect("second partial frame").identities,
        vec!["hash-d"]
    );
    assert_eq!(
        accumulators[0].tier_used,
        vec!["tier1".to_owned(), "tier1".to_owned()]
    );
    assert_eq!(accumulators[0].query_profile.docs_scanned, 8);
    assert_eq!(accumulators[0].eval_nanos, 44);
}

#[test]
fn ensure_candidate_stores_removes_abandoned_compaction_roots_on_startup() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let shard_root = candidate_shard_root(&root, 2, 0);
    let abandoned = compaction_work_root(&shard_root, "compact-orphan");
    fs::create_dir_all(abandoned.join("nested")).expect("create orphan root");

    let (stores, removed_roots, _) = ensure_candidate_stores(&ServerConfig {
        candidate_config: CandidateConfig {
            root: root.clone(),
            ..CandidateConfig::default()
        },
        candidate_shards: 2,
        search_workers: 1,
        memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
        auto_publish_initial_idle_ms: 500,
        auto_publish_storage_class: "unknown".to_owned(),
        workspace_mode: false,
    })
    .expect("ensure stores");
    assert_eq!(
        match stores {
            StoreMode::Direct { stores } => stores.stores.len(),
            StoreMode::Forest { .. } => 0,
            StoreMode::Workspace { .. } => 0,
        },
        2
    );
    assert_eq!(removed_roots, 1);
    assert!(!abandoned.exists());
}

#[test]
fn compaction_cycle_reclaims_deleted_docs_and_updates_stats() {
    let tmp = tempdir().expect("tmp");
    let state = Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: tmp.path().join("candidate_db"),
                    filter_target_fp: None,
                    tier1_filter_target_fp: None,
                    tier2_filter_target_fp: None,
                    compaction_idle_cooldown_s: 0.0,
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state"),
    );
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(32, 7, &[gram]));

    for byte in [0x11u8, 0x22u8] {
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: hex::encode([byte; 32]),
                file_size: 32,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some(format!("doc-{byte:02x}")),
            })
            .expect("insert doc");
    }

    state
        .handle_candidate_delete(&hex::encode([0x22; 32]))
        .expect("delete doc");
    state
        .run_compaction_cycle_for_tests()
        .expect("run compaction cycle");

    let stats = state.grpc_stats_response().expect("stats");
    let summary = stats.stats.expect("store summary");
    assert_eq!(summary.deleted_doc_count, 0);
    assert_eq!(summary.doc_count, 1);
    assert_eq!(summary.deleted_storage_bytes, 0);
    let runtime = state.current_stats_json().expect("runtime stats");
    assert_eq!(
        runtime.get("compaction_runs_total").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        runtime
            .get("last_compaction_reclaimed_docs")
            .and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(summary.compaction_generation, 2);
    assert_eq!(summary.retired_generation_count, 1);
}

#[test]
fn record_compaction_error_updates_runtime_and_stats() {
    let tmp = tempdir().expect("tmp");
    let state = sample_server_state(tmp.path());
    {
        let mut runtime = state.compaction_runtime.lock().expect("runtime lock");
        runtime.running_shard = Some(3);
    }

    state.record_compaction_error("compaction boom".to_owned());

    {
        let runtime = state.compaction_runtime.lock().expect("runtime lock");
        assert_eq!(runtime.running_shard, None);
        assert_eq!(runtime.last_error.as_deref(), Some("compaction boom"));
    }

    let stats = state.current_stats_json().expect("stats");
    assert_eq!(
        stats.get("last_compaction_error").and_then(Value::as_str),
        Some("compaction boom")
    );
    assert!(
        !stats
            .get("compaction_running")
            .and_then(Value::as_bool)
            .unwrap_or(true),
        "compaction should no longer be marked running"
    );
}

#[test]
fn compaction_cycle_scans_all_shards_for_pending_work() {
    let tmp = tempdir().expect("tmp");
    let state = Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: tmp.path().join("candidate_db_4"),
                    filter_target_fp: None,
                    tier1_filter_target_fp: None,
                    tier2_filter_target_fp: None,
                    compaction_idle_cooldown_s: 0.0,
                    ..CandidateConfig::default()
                },
                candidate_shards: 4,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state"),
    );
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(32, 7, &[gram]));

    let mut deleted_sha = None;
    for byte in 1u8..=32 {
        let sha = [byte; 32];
        let shard_idx = state.candidate_store_index_for_identity(&sha);
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: hex::encode(sha),
                file_size: 32,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some(format!("doc-{byte:02x}")),
            })
            .expect("insert doc");
        if shard_idx != 0 {
            deleted_sha = Some(hex::encode(sha));
            break;
        }
    }

    let deleted_sha = deleted_sha.expect("non-zero shard doc");
    state
        .handle_candidate_delete(&deleted_sha)
        .expect("delete doc");
    state
        .run_compaction_cycle_for_tests()
        .expect("run compaction cycle");

    let stats = state.grpc_stats_response().expect("stats");
    let summary = stats.stats.expect("store summary");
    assert_eq!(summary.deleted_doc_count, 0);
    assert_eq!(summary.deleted_storage_bytes, 0);
    let runtime = state.current_stats_json().expect("runtime stats");
    assert_eq!(
        runtime.get("compaction_runs_total").and_then(Value::as_u64),
        Some(1)
    );
}

#[test]
fn next_compaction_wait_timeout_tracks_pending_delete_cooldown() {
    let tmp = tempdir().expect("tmp");
    let state = Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: tmp.path().join("candidate_db"),
                    filter_target_fp: None,
                    tier1_filter_target_fp: None,
                    tier2_filter_target_fp: None,
                    compaction_idle_cooldown_s: 5.0,
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state"),
    );
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(32, 7, &[gram]));

    for byte in [0x11u8, 0x22u8] {
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: hex::encode([byte; 32]),
                file_size: 32,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some(format!("doc-{byte:02x}")),
            })
            .expect("insert doc");
    }

    assert_eq!(
        state.next_compaction_wait_timeout(),
        Duration::from_secs(30)
    );

    state
        .handle_candidate_delete(&hex::encode([0x22; 32]))
        .expect("delete doc");

    let stats = state.current_stats_json().expect("stats after delete");
    assert_eq!(
        stats
            .get("compaction_idle_cooldown_s")
            .and_then(Value::as_f64),
        Some(5.0)
    );
    let remaining = stats
        .get("compaction_cooldown_remaining_s")
        .and_then(Value::as_f64)
        .expect("remaining cooldown");
    assert!(
        remaining <= 5.0 && remaining > 4.0,
        "expected cooldown remaining near 5s after delete, got {remaining}"
    );
    assert_eq!(
        stats
            .get("compaction_waiting_for_cooldown")
            .and_then(Value::as_bool),
        Some(true)
    );

    let timeout = state.next_compaction_wait_timeout();
    assert!(
        timeout <= Duration::from_secs(5),
        "expected timeout <= cooldown after delete, got {timeout:?}"
    );
    assert!(
        timeout > Duration::from_secs(4),
        "expected timeout to reflect remaining cooldown, got {timeout:?}"
    );
}

#[test]
fn compaction_cycle_garbage_collects_retired_generation_before_next_snapshot_scan() {
    let tmp = tempdir().expect("tmp");
    let state = Arc::new(
        ServerState::new(
            ServerConfig {
                candidate_config: CandidateConfig {
                    root: tmp.path().join("candidate_db"),
                    filter_target_fp: None,
                    tier1_filter_target_fp: None,
                    tier2_filter_target_fp: None,
                    compaction_idle_cooldown_s: 0.0,
                    ..CandidateConfig::default()
                },
                candidate_shards: 1,
                search_workers: 1,
                memory_budget_bytes: crate::app::DEFAULT_MEMORY_BUDGET_BYTES,
                auto_publish_initial_idle_ms: 500,
                auto_publish_storage_class: "unknown".to_owned(),
                workspace_mode: false,
            },
            Arc::new(AtomicBool::new(false)),
        )
        .expect("server state"),
    );
    let gram = pack_exact_gram(b"ABC");
    let bloom_filter_b64 =
        base64::engine::general_purpose::STANDARD.encode(lane_bloom_bytes(32, 7, &[gram]));

    for byte in [0x11u8, 0x22u8] {
        state
            .handle_candidate_insert(&CandidateDocumentWire {
                identity: hex::encode([byte; 32]),
                file_size: 32,
                bloom_filter_b64: bloom_filter_b64.clone(),
                bloom_item_estimate: None,
                tier2_bloom_filter_b64: None,
                tier2_bloom_item_estimate: None,
                special_population: false,
                metadata_b64: None,
                external_id: Some(format!("doc-{byte:02x}")),
            })
            .expect("insert doc");
    }

    state
        .handle_candidate_delete(&hex::encode([0x22; 32]))
        .expect("delete doc");
    state
        .run_compaction_cycle_for_tests()
        .expect("first compaction cycle");

    let first_stats = state.grpc_stats_response().expect("stats");
    assert_eq!(
        first_stats
            .stats
            .expect("store summary")
            .retired_generation_count,
        1
    );

    state
        .run_compaction_cycle_for_tests()
        .expect("second compaction cycle");

    let second_stats = state.grpc_stats_response().expect("stats");
    assert_eq!(
        second_stats
            .stats
            .expect("store summary")
            .retired_generation_count,
        0
    );
    let runtime = state.current_stats_json().expect("runtime stats");
    assert_eq!(
        runtime.get("compaction_runs_total").and_then(Value::as_u64),
        Some(1)
    );
}
