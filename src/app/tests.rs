use super::*;
use tempfile::tempdir;

use crate::candidate::{CandidateConfig, QueryNode};
use crate::grpc::GrpcSearchFrame;

fn default_connection() -> ClientConnectionArgs {
    ClientConnectionArgs {
        addr: DEFAULT_RPC_ADDR.to_owned(),
        timeout: DEFAULT_RPC_TIMEOUT,
        max_message_bytes: DEFAULT_MAX_REQUEST_BYTES,
    }
}

fn default_internal_init_args(root: &Path, candidate_shards: usize, force: bool) -> InitArgs {
    InitArgs {
        root: root.display().to_string(),
        candidate_shards,
        force,
        tier1_filter_target_fp: None,
        tier2_filter_target_fp: None,
        gram_sizes: "3,4".to_owned(),
        compaction_idle_cooldown_s: 5.0,
    }
}

fn start_grpc_test_server(base: &Path, shard_count: usize) -> ClientConnectionArgs {
    start_grpc_test_server_with_config(RpcServerConfig {
        candidate_config: CandidateConfig {
            root: base.join("server_candidate_db"),
            ..CandidateConfig::default()
        },
        candidate_shards: shard_count,
        search_workers: default_search_workers_for(4),
        memory_budget_bytes: DEFAULT_MEMORY_BUDGET_BYTES,
        auto_publish_initial_idle_ms: 500,
        auto_publish_storage_class: "unknown".to_owned(),
        workspace_mode: true,
    })
}

fn start_grpc_test_server_with_config(config: RpcServerConfig) -> ClientConnectionArgs {
    let listener = std::net::TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind test listener");
    let port = listener.local_addr().expect("listener addr").port();
    drop(listener);
    thread::spawn(move || {
        let _ = rpc::serve_grpc(DEFAULT_RPC_HOST, port, config);
    });
    let connection = ClientConnectionArgs {
        addr: format!("{DEFAULT_RPC_HOST}:{port}"),
        timeout: 0.5,
        max_message_bytes: DEFAULT_MAX_REQUEST_BYTES,
    };
    for _ in 0..100 {
        if grpc_client(&connection)
            .and_then(|mut client| client.ping())
            .is_ok()
        {
            return connection;
        }
        thread::sleep(Duration::from_millis(20));
    }
    panic!("test grpc server did not become ready");
}

#[test]
fn incremental_remote_batch_size_matches_full_payload_size() {
    let empty = empty_remote_batch_payload_size().expect("empty payload size");
    let rows = vec![
        crate::rpc::serialize_candidate_insert_binary_row_parts(
            &[0x11; 32],
            123,
            Some(3),
            &[1, 2, 3],
            Some(2),
            &[4, 5, 6],
            false,
            &[],
            Some("doc-1"),
        )
        .expect("row a"),
        crate::rpc::serialize_candidate_insert_binary_row_parts(
            &[0x22; 32],
            456,
            None,
            &[10, 11, 12],
            None,
            &[13, 14, 15],
            false,
            &[],
            None,
        )
        .expect("row b"),
    ];
    let mut running = empty;
    let mut pending_rows = Vec::new();
    for row in rows {
        running += 4 + row.len();
        pending_rows.push(row);
        let exact =
            crate::rpc::serialized_candidate_insert_binary_batch_payload(&pending_rows).len();
        assert_eq!(running, exact);
    }
}

fn default_serve_common_args() -> ServeCommonArgs {
    ServeCommonArgs {
        addr: DEFAULT_RPC_ADDR.to_owned(),
        search_workers: default_search_workers_for(4),
        root: DEFAULT_CANDIDATE_ROOT.to_owned(),
        layout_profile: ServeLayoutProfile::Standard,
        shards: None,
        tier1_filter_target_fp: None,
        tier2_filter_target_fp: None,
        id_source: CandidateIdSource::Sha256,
        store_path: false,
        gram_sizes: "3,4".to_owned(),
    }
}

fn default_serve_args() -> ServeArgs {
    ServeArgs {
        common: default_serve_common_args(),
        max_message_bytes: DEFAULT_MAX_REQUEST_BYTES,
    }
}

#[test]
fn serve_candidate_shard_count_uses_profile_default() {
    let mut args = default_serve_common_args();
    args.layout_profile = ServeLayoutProfile::Incremental;
    assert_eq!(
        serve_candidate_shard_count(&args),
        DEFAULT_INCREMENTAL_SHARDS
    );
}

#[test]
fn serve_candidate_shard_count_explicit_override_wins() {
    let mut args = default_serve_common_args();
    args.layout_profile = ServeLayoutProfile::Incremental;
    args.shards = Some(17);
    assert_eq!(serve_candidate_shard_count(&args), 17);
}

#[test]
fn resolve_serve_runtime_settings_prefers_existing_forest_tree_roots() {
    let tmp = tempdir().expect("tmp");
    let forest_root = tmp.path().join("forest");
    let tree_root = forest_root.join("tree_00").join("current");
    fs::create_dir_all(tree_root.parent().expect("tree parent")).expect("tree parent");

    assert_eq!(
        cmd_init(&default_internal_init_args(&tree_root, 2, true)),
        0
    );
    assert!(forest_root.join("meta.json").exists());
    assert!(!serve_uses_workspace_mode(&forest_root));

    let existing_root =
        existing_serve_store_root(&forest_root, false).expect("existing forest root");
    assert_eq!(existing_root, Some(tree_root.clone()));

    let mut args = default_serve_common_args();
    args.root = forest_root.display().to_string();
    let resolved = resolve_serve_runtime_settings(&args, ServeInitOptionSources::default())
        .expect("resolved serve settings");
    assert_eq!(resolved.candidate_shards, 2);
    assert!(!resolved.workspace_mode);
    assert_eq!(resolved.candidate_config.root, forest_root);
}

#[test]
fn search_related_commands_default_max_candidates_to_ten_percent() {
    let cli = Cli::try_parse_from(["sspry", "search", "--rule", "rule.yar"]).expect("parse search");
    match cli.command {
        Commands::Search(args) => {
            assert_eq!(args.rule, "rule.yar".to_owned());
            assert_eq!(args.max_candidates, 10.0);
        }
        other => panic!("unexpected command: {other:?}"),
    }

    let cli = Cli::try_parse_from([
        "sspry",
        "local",
        "search",
        "--root",
        "db",
        "--rule",
        "rule.yar",
    ])
    .expect("parse local search");
    match cli.command {
        Commands::Local(args) => match args.command {
            LocalCommands::Search(args) => {
                assert_eq!(args.rule, "rule.yar".to_owned());
                assert_eq!(args.max_candidates, 10.0);
            }
            other => panic!("unexpected local command: {other:?}"),
        }
        other => panic!("unexpected command: {other:?}"),
    }
}

#[test]
fn load_search_rule_bundle_expands_includes_and_returns_searchable_rules() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let root = base.join("root.yar");
    let first = base.join("first.yar");
    let second = base.join("second.yar");
    fs::write(
        &first,
        r#"
private rule helper_one {
  condition:
    false
}

rule first_rule {
  condition:
    true
}
"#,
    )
    .expect("first");
    fs::write(
        &second,
        r#"
rule second_rule {
  condition:
    true
}
"#,
    )
    .expect("second");
    fs::write(
        &root,
        r#"
include "first.yar"
include "second.yar"
"#,
    )
    .expect("root");

    let (expanded, rules) = load_search_rule_bundle(&root).expect("bundle");
    assert!(expanded.contains("rule first_rule"));
    assert!(expanded.contains("rule second_rule"));
    assert_eq!(
        rules,
        vec!["first_rule".to_owned(), "second_rule".to_owned()]
    );
}

#[test]
fn grpc_search_frame_to_internal_preserves_bundled_rule_metadata() {
    let frame = GrpcSearchFrame {
        sha256: vec!["aa".to_owned()],
        external_ids: vec![Some("doc-a".to_owned())],
        candidate_limit: Some(10),
        stream_complete: false,
        rule_complete: true,
        target_rule_name: "bundle_rule".to_owned(),
        truncated: false,
        tier_used: "tier1".to_owned(),
        query_profile: CandidateQueryProfile::default(),
    };

    let internal = grpc_search_frame_to_internal(frame);
    assert!(internal.rule_complete);
    assert_eq!(internal.target_rule_name, "bundle_rule".to_owned());
    assert_eq!(internal.candidate_limit, Some(10));
}

#[test]
fn collect_streamed_search_executions_batch_builds_one_execution_per_rule() {
    let args = SearchCommandArgs {
        connection: default_connection(),
        rule: "bundle.yar".to_owned(),
        verify_yara_files: false,
        max_candidates: 100.0,
        max_anchors_per_pattern: 16,
        verbose: false,
    };
    let rule_text = r#"
rule rule_one {
  strings:
    $a = "alpha"
  condition:
    $a
}

rule rule_two {
  strings:
    $b = "beta"
  condition:
    $b
}
"#;
    let planned_rules = ["rule_one", "rule_two"]
        .into_iter()
        .map(|rule_name| {
            let started_plan = Instant::now();
            let plan = compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source(
                rule_text,
                rule_name,
                GramSizes::new(3, 4).expect("gram sizes"),
                None,
                args.max_anchors_per_pattern,
                false,
                true,
                args.max_candidates,
            )
            .expect("compile plan");
            (rule_name.to_owned(), plan, started_plan.elapsed())
        })
        .collect::<Vec<_>>();

    let executions = collect_streamed_search_executions_batch(
        &args,
        planned_rules,
        None,
        &mut |on_frame: &mut dyn FnMut(rpc::CandidateQueryStreamFrame) -> Result<()>| {
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: vec!["hash-a".to_owned()],
                external_ids: Some(vec![None]),
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: false,
                target_rule_name: "rule_one".to_owned(),
                tier_used: String::new(),
                query_profile: CandidateQueryProfile::default(),
                query_eval_nanos: 0,
            })?;
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: Vec::new(),
                external_ids: None,
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: true,
                target_rule_name: "rule_one".to_owned(),
                tier_used: "tier1".to_owned(),
                query_profile: CandidateQueryProfile {
                    docs_scanned: 11,
                    ..CandidateQueryProfile::default()
                },
                query_eval_nanos: 0,
            })?;
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: vec!["hash-b".to_owned()],
                external_ids: Some(vec![None]),
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: false,
                target_rule_name: "rule_two".to_owned(),
                tier_used: String::new(),
                query_profile: CandidateQueryProfile::default(),
                query_eval_nanos: 0,
            })?;
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: Vec::new(),
                external_ids: None,
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: true,
                target_rule_name: "rule_two".to_owned(),
                tier_used: "tier2".to_owned(),
                query_profile: CandidateQueryProfile {
                    docs_scanned: 22,
                    ..CandidateQueryProfile::default()
                },
                query_eval_nanos: 0,
            })?;
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: Vec::new(),
                external_ids: None,
                candidate_limit: None,
                stream_complete: true,
                rule_complete: false,
                target_rule_name: String::new(),
                tier_used: String::new(),
                query_profile: CandidateQueryProfile::default(),
                query_eval_nanos: 0,
            })?;
            Ok(())
        },
    )
    .expect("collect bundled executions");

    assert_eq!(executions.len(), 2);
    assert_eq!(executions[0].0, "rule_one".to_owned());
    assert_eq!(executions[0].1.rows, vec!["hash-a".to_owned()]);
    assert_eq!(executions[0].1.tier_used, "tier1".to_owned());
    assert_eq!(executions[0].1.query_profile.docs_scanned, 11);
    assert_eq!(executions[1].0, "rule_two".to_owned());
    assert_eq!(executions[1].1.rows, vec!["hash-b".to_owned()]);
    assert_eq!(executions[1].1.tier_used, "tier2".to_owned());
    assert_eq!(executions[1].1.query_profile.docs_scanned, 22);
}

#[test]
fn stream_search_executions_batch_flushes_rules_before_stream_complete() {
    let args = SearchCommandArgs {
        connection: default_connection(),
        rule: "bundle.yar".to_owned(),
        verify_yara_files: false,
        max_candidates: 100.0,
        max_anchors_per_pattern: 16,
        verbose: false,
    };
    let rule_text = r#"
rule rule_one {
  strings:
    $a = "alpha"
  condition:
    $a
}

rule rule_two {
  strings:
    $b = "beta"
  condition:
    $b
}
"#;
    let planned_rules = ["rule_one", "rule_two"]
        .into_iter()
        .map(|rule_name| {
            let started_plan = Instant::now();
            let plan = compile_query_plan_for_rule_name_with_gram_sizes_and_identity_source(
                rule_text,
                rule_name,
                GramSizes::new(3, 4).expect("gram sizes"),
                None,
                args.max_anchors_per_pattern,
                false,
                true,
                args.max_candidates,
            )
            .expect("compile plan");
            (rule_name.to_owned(), plan, started_plan.elapsed())
        })
        .collect::<Vec<_>>();
    let callback_order = std::rc::Rc::new(std::cell::RefCell::new(Vec::<String>::new()));
    let callback_order_for_cb = callback_order.clone();
    let saw_stream_complete = std::rc::Rc::new(std::cell::Cell::new(false));
    let saw_stream_complete_for_cb = saw_stream_complete.clone();

    stream_search_executions_batch(
        &args,
        planned_rules,
        None,
        &mut |on_frame: &mut dyn FnMut(rpc::CandidateQueryStreamFrame) -> Result<()>| {
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: vec!["hash-a".to_owned()],
                external_ids: Some(vec![None]),
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: false,
                target_rule_name: "rule_one".to_owned(),
                tier_used: String::new(),
                query_profile: CandidateQueryProfile::default(),
                query_eval_nanos: 0,
            })?;
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: Vec::new(),
                external_ids: None,
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: true,
                target_rule_name: "rule_one".to_owned(),
                tier_used: "tier1".to_owned(),
                query_profile: CandidateQueryProfile {
                    docs_scanned: 11,
                    ..CandidateQueryProfile::default()
                },
                query_eval_nanos: 0,
            })?;
            assert_eq!(
                callback_order.borrow().as_slice(),
                &[String::from("rule_one")]
            );
            assert!(!saw_stream_complete.get());

            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: vec!["hash-b".to_owned()],
                external_ids: Some(vec![None]),
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: false,
                target_rule_name: "rule_two".to_owned(),
                tier_used: String::new(),
                query_profile: CandidateQueryProfile::default(),
                query_eval_nanos: 0,
            })?;
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: Vec::new(),
                external_ids: None,
                candidate_limit: Some(100),
                stream_complete: false,
                rule_complete: true,
                target_rule_name: "rule_two".to_owned(),
                tier_used: "tier2".to_owned(),
                query_profile: CandidateQueryProfile {
                    docs_scanned: 22,
                    ..CandidateQueryProfile::default()
                },
                query_eval_nanos: 0,
            })?;
            assert_eq!(
                callback_order.borrow().as_slice(),
                &[String::from("rule_one"), String::from("rule_two")]
            );
            assert!(!saw_stream_complete.get());

            saw_stream_complete.set(true);
            on_frame(rpc::CandidateQueryStreamFrame {
                sha256: Vec::new(),
                external_ids: None,
                candidate_limit: None,
                stream_complete: true,
                rule_complete: false,
                target_rule_name: String::new(),
                tier_used: String::new(),
                query_profile: CandidateQueryProfile::default(),
                query_eval_nanos: 0,
            })?;
            Ok(())
        },
        |rule_name, execution, index| {
            assert!(!saw_stream_complete_for_cb.get());
            callback_order_for_cb.borrow_mut().push(rule_name.clone());
            match index {
                0 => {
                    assert_eq!(rule_name, "rule_one");
                    assert_eq!(execution.rows, vec!["hash-a".to_owned()]);
                    assert_eq!(execution.tier_used, "tier1".to_owned());
                    assert_eq!(execution.query_profile.docs_scanned, 11);
                }
                1 => {
                    assert_eq!(rule_name, "rule_two");
                    assert_eq!(execution.rows, vec!["hash-b".to_owned()]);
                    assert_eq!(execution.tier_used, "tier2".to_owned());
                    assert_eq!(execution.query_profile.docs_scanned, 22);
                }
                other => panic!("unexpected callback index: {other}"),
            }
            Ok(())
        },
    )
    .expect("stream bundled executions");

    assert!(saw_stream_complete.get());
    assert_eq!(
        callback_order.borrow().as_slice(),
        &[String::from("rule_one"), String::from("rule_two")]
    );
}

#[test]
fn parse_host_port_accepts_common_forms() {
    assert_eq!(
        parse_host_port("127.0.0.1:17653").expect("ipv4"),
        ("127.0.0.1".to_owned(), 17653)
    );
    assert_eq!(
        parse_host_port("example.com:443").expect("hostname"),
        ("example.com".to_owned(), 443)
    );
    assert_eq!(
        parse_host_port("[::1]:17653").expect("ipv6"),
        ("::1".to_owned(), 17653)
    );
}

#[test]
fn parse_host_port_rejects_invalid_values() {
    assert!(parse_host_port("").is_err());
    assert!(parse_host_port("127.0.0.1").is_err());
    assert!(parse_host_port(":17653").is_err());
    assert!(parse_host_port("127.0.0.1:notaport").is_err());
    assert!(parse_host_port("[::1]").is_err());
}

#[test]
fn file_path_collection_and_hash_helpers_work() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let nested = tmp.path().join("nested");
    let child = nested.join("child");
    fs::create_dir_all(&child).expect("mkdir");
    let sample = child.join("sample.bin");
    fs::write(&sample, b"abcdef").expect("write sample");

    let resolved = resolved_file_path(&sample).expect("resolve");
    assert_eq!(resolved, fs::canonicalize(&sample).expect("canonicalize"));
    assert_eq!(
        path_identity_sha256(&sample).expect("path hash"),
        path_identity_sha256(&resolved).expect("path hash again")
    );
    let file_digest = sha256_file(&sample, 2).expect("sha256 file");
    assert_ne!(
        file_digest,
        path_identity_sha256(&sample).expect("path digest")
    );
    assert!(sha256_file(&sample, 0)
        .expect_err("zero chunk size")
        .to_string()
        .contains("positive integer"));

    let mut files = Vec::new();
    collect_files_recursive(tmp.path(), &mut files).expect("collect files");
    files.sort();
    assert!(files.contains(&sample));
    let mut singleton = Vec::new();
    collect_files_recursive(&sample, &mut singleton).expect("collect single file");
    assert_eq!(singleton, vec![sample.clone()]);
    let mut missing = Vec::new();
    collect_files_recursive(&tmp.path().join("missing.bin"), &mut missing)
        .expect("missing path should be ignored");
    assert!(missing.is_empty());
    assert!(resolved_file_path(&tmp.path().join("missing.bin")).is_err());
    assert!(path_identity_sha256(&tmp.path().join("missing.bin")).is_err());
    assert!(decode_sha256_hex("abcd").is_err());
}

#[test]
fn json_config_and_binary_row_helpers_work() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let mut stats = serde_json::Map::new();
    stats.insert("count".to_owned(), serde_json::json!(7));
    stats.insert("ratio".to_owned(), serde_json::json!(0.25));
    assert_eq!(json_usize(&stats, "count", 0), 7);
    assert_eq!(json_usize(&stats, "missing", 5), 5);
    assert_eq!(json_f64_opt(&stats, "ratio"), Some(0.25));
    assert_eq!(json_f64_opt(&stats, "missing"), None);

    let fixed = store_config_from_parts(
        PathBuf::from("root"),
        CandidateIdSource::Sha256,
        true,
        0.001,
        0.002,
        3,
        4,
        33.5,
    );
    assert_eq!(fixed.root, PathBuf::from("root"));
    assert_eq!(fixed.id_source, "sha256");
    assert!(fixed.store_path);
    assert_eq!(fixed.tier2_gram_size, 3);
    assert_eq!(fixed.tier1_gram_size, 4);
    assert_eq!(fixed.tier1_filter_target_fp, Some(0.001));
    assert_eq!(fixed.tier2_filter_target_fp, Some(0.002));
    assert_eq!(fixed.filter_target_fp, None);
    assert_eq!(fixed.compaction_idle_cooldown_s, 33.5);

    let variable = store_config_from_parts(
        PathBuf::from("root"),
        CandidateIdSource::Sha256,
        false,
        0.01,
        0.01,
        5,
        4,
        9.25,
    );
    assert_eq!(variable.root, PathBuf::from("root"));
    assert_eq!(variable.id_source, "sha256");
    assert!(!variable.store_path);
    assert_eq!(variable.tier1_filter_target_fp, Some(0.01));
    assert_eq!(variable.tier2_filter_target_fp, Some(0.01));
    assert_eq!(variable.filter_target_fp, Some(0.01));
    assert_eq!(variable.tier2_gram_size, 5);
    assert_eq!(variable.tier1_gram_size, 4);
    assert_eq!(variable.compaction_idle_cooldown_s, 9.25);

    let row = IndexBatchRow {
        sha256: [0xAA; 32],
        file_size: 123,
        filter_bytes: 2048,
        bloom_item_estimate: Some(77),
        bloom_filter: vec![1, 2, 3, 4],
        tier2_filter_bytes: 0,
        tier2_bloom_item_estimate: None,
        tier2_bloom_filter: Vec::new(),
        special_population: false,
        metadata: vec![9, 8, 7],
        external_id: Some("x".to_owned()),
    };
    let wire = serialize_candidate_document_binary_row(&row).expect("binary row");
    let parsed = crate::rpc::parse_candidate_insert_binary_row_for_test(&wire).expect("parse row");
    assert_eq!(parsed.0, [0xAA; 32]);
    assert_eq!(parsed.1, 123);
    assert_eq!(parsed.2, Some(77));
    assert_eq!(parsed.3, vec![1, 2, 3, 4]);
    assert_eq!(parsed.7, vec![9, 8, 7]);
    assert_eq!(parsed.8.as_deref(), Some("x"));

    let tmp = tempdir().expect("tmp");
    let config = CandidateConfig {
        root: tmp.path().join("candidate_db"),
        ..CandidateConfig::default()
    };
    let store = ensure_store(config.clone(), true).expect("init store");
    assert_eq!(store.stats().doc_count, 0);
    let reopened = ensure_store(config, false).expect("reopen store");
    assert_eq!(reopened.stats().doc_count, 0);
}

#[test]
fn default_ingest_workers_matches_python_formula() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    assert_eq!(default_ingest_workers_for(1), 1);
    assert_eq!(default_ingest_workers_for(2), 1);
    assert_eq!(default_ingest_workers_for(3), 1);
    assert_eq!(default_ingest_workers_for(4), 2);
    assert_eq!(default_ingest_workers_for(7), 3);
    assert_eq!(default_ingest_workers_for(8), 6);
    assert_eq!(default_ingest_workers_for(9), 6);
    assert_eq!(default_ingest_workers_for(16), 12);
}

#[test]
fn auto_ingest_workers_caps_rotational_and_small_workloads() {
    assert_eq!(
        auto_ingest_workers_for(
            16,
            500,
            IngestStorageClass::SolidState,
            IngestStorageClass::Unknown
        ),
        12
    );
    assert_eq!(
        auto_ingest_workers_for(
            16,
            500,
            IngestStorageClass::Rotational,
            IngestStorageClass::Unknown
        ),
        4
    );
    assert_eq!(
        auto_ingest_workers_for(
            16,
            3,
            IngestStorageClass::SolidState,
            IngestStorageClass::Unknown
        ),
        3
    );
    assert_eq!(
        auto_ingest_workers_for(
            16,
            2,
            IngestStorageClass::Rotational,
            IngestStorageClass::Unknown
        ),
        2
    );
}

#[test]
fn resolve_ingest_workers_respects_explicit_override() {
    let resolved = resolve_ingest_workers(7, 500, &[], None);
    assert_eq!(resolved.workers, 7);
    assert!(!resolved.auto);
    assert_eq!(resolved.input_storage, IngestStorageClass::Unknown);
    assert_eq!(resolved.output_storage, IngestStorageClass::Unknown);
}

#[test]
fn default_search_workers_is_quarter_cpu_floor() {
    assert_eq!(default_search_workers_for(1), 1);
    assert_eq!(default_search_workers_for(2), 1);
    assert_eq!(default_search_workers_for(3), 1);
    assert_eq!(default_search_workers_for(4), 1);
    assert_eq!(default_search_workers_for(7), 1);
    assert_eq!(default_search_workers_for(8), 2);
    assert_eq!(default_search_workers_for(16), 4);
    assert_eq!(default_search_workers_for(20), 5);
}

#[test]
fn scan_candidate_batch_helpers_work() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let sample = tmp.path().join("sample.bin");
    fs::write(&sample, b"well hello there").expect("sample");

    let row = scan_index_batch_row(
        &sample,
        ScanPolicy {
            fixed_filter_bytes: Some(2048),
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
            chunk_size: 4,
            store_path: true,
            id_source: CandidateIdSource::Sha256,
        },
    )
    .expect("scan row");
    assert_eq!(
        row.external_id.as_deref(),
        Some(
            sample
                .canonicalize()
                .expect("canon")
                .to_string_lossy()
                .as_ref()
        )
    );

    let md5_row = scan_index_batch_row(
        &sample,
        ScanPolicy {
            fixed_filter_bytes: Some(2048),
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
            chunk_size: 4,
            store_path: false,
            id_source: CandidateIdSource::Md5,
        },
    )
    .expect("scan md5 row");
    assert_eq!(row.filter_bytes % 8, 0);
    assert_eq!(row.tier2_filter_bytes % 8, 0);
    assert_eq!(
        md5_row.sha256,
        identity_from_file(&sample, 4, CandidateIdSource::Md5).expect("md5 id")
    );
    assert!(md5_row.external_id.is_none());

    let aligned_row = scan_index_batch_row(
        &sample,
        ScanPolicy {
            fixed_filter_bytes: Some(2051),
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
            chunk_size: 4,
            store_path: false,
            id_source: CandidateIdSource::Sha256,
        },
    )
    .expect("scan aligned row");
    assert_eq!(aligned_row.filter_bytes, 2056);
    assert_eq!(aligned_row.tier2_filter_bytes, 2056);

    assert_eq!(merge_tier_used(Vec::<String>::new()), "unknown");
    assert_eq!(merge_tier_used(vec![" tier1 ".to_owned()]), "tier1");
    assert_eq!(
        merge_tier_used(vec!["tier1".to_owned(), "tier2".to_owned()]),
        "tier1+tier2"
    );

    let rule_path = tmp.path().join("rule.yar");
    fs::write(
        &rule_path,
        "rule test { strings: $a = \"hello\" condition: $a }\n",
    )
    .expect("rule");
    assert!(compile_yara_verifier(&rule_path).is_ok());
    let bad_rule_path = tmp.path().join("bad_rule.yar");
    fs::write(&bad_rule_path, "rule {").expect("bad rule");
    assert!(compile_yara_verifier(&bad_rule_path).is_err());

    let multi_rule_verify_path = tmp.path().join("multi_verify.yar");
    fs::write(
        &multi_rule_verify_path,
        concat!(
            "rule first_rule { strings: $a = \"ABCD\" condition: $a }\n",
            "rule second_rule { strings: $a = \"WXYZ\" condition: $a }\n",
        ),
    )
    .expect("multi verify rule");
    let second_match_path = tmp.path().join("second_match.bin");
    fs::write(&second_match_path, b"--WXYZ--").expect("second match");
    let multi_rules = compile_yara_verifier(&multi_rule_verify_path).expect("multi rules");
    assert!(
        !scan_candidate_matches_rule(&multi_rules, &second_match_path, Some("first_rule"))
            .expect("first verify")
    );
    assert!(
        scan_candidate_matches_rule(&multi_rules, &second_match_path, Some("second_rule"))
            .expect("second verify")
    );
    assert!(
        scan_candidate_matches_rule(&multi_rules, &second_match_path, None).expect("any verify")
    );

    let single_rule_path = tmp.path().join("single_rule.yar");
    fs::write(
        &single_rule_path,
        "rule single_rule { strings: $a = { 41 42 43 44 } condition: $a }\n",
    )
    .expect("single rule");
    assert_eq!(rule_file_has_single_rule(&single_rule_path), Some(true));

    let multi_rule_path = tmp.path().join("multi_rule.yar");
    fs::write(
        &multi_rule_path,
        concat!(
            "rule first { strings: $a = { 41 42 43 44 } condition: $a }\n",
            "rule second { strings: $a = { 45 46 47 48 } condition: $a }\n",
        ),
    )
    .expect("multi rule");
    assert_eq!(rule_file_has_single_rule(&multi_rule_path), Some(false));
    assert!(fixed_literal_plan_from_rule(&multi_rule_path).is_none());

    let fixed_match_path = tmp.path().join("fixed.bin");
    fs::write(&fixed_match_path, b"--ABCDEFGH--").expect("fixed match");
    let fixed_plan = FixedLiteralMatchPlan {
        literals: HashMap::from([
            ("$a".to_owned(), vec![b"ABCD".to_vec()]),
            ("$b".to_owned(), vec![b"EFGH".to_vec()]),
        ]),
        literal_wide: HashMap::from([
            ("$a".to_owned(), vec![false]),
            ("$b".to_owned(), vec![false]),
        ]),
        literal_fullword: HashMap::from([
            ("$a".to_owned(), vec![false]),
            ("$b".to_owned(), vec![false]),
        ]),
        root: QueryNode {
            kind: "and".to_owned(),
            pattern_id: None,
            threshold: None,
            children: vec![
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("$a".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
                QueryNode {
                    kind: "pattern".to_owned(),
                    pattern_id: Some("$b".to_owned()),
                    threshold: None,
                    children: Vec::new(),
                },
            ],
        },
    };
    assert!(verify_fixed_literal_plan_on_file(&fixed_match_path, &fixed_plan).expect("match"));
    fs::write(&fixed_match_path, b"--ABCD----").expect("fixed miss");
    assert!(!verify_fixed_literal_plan_on_file(&fixed_match_path, &fixed_plan).expect("miss"));

    let fullword_path = tmp.path().join("fullword.bin");
    fs::write(&fullword_path, b".WORD! xWORDx").expect("fullword bytes");
    let fullword_plan = FixedLiteralMatchPlan {
        literals: HashMap::from([("$a".to_owned(), vec![b"WORD".to_vec()])]),
        literal_wide: HashMap::from([("$a".to_owned(), vec![false])]),
        literal_fullword: HashMap::from([("$a".to_owned(), vec![true])]),
        root: QueryNode {
            kind: "pattern".to_owned(),
            pattern_id: Some("$a".to_owned()),
            threshold: None,
            children: Vec::new(),
        },
    };
    assert!(verify_fixed_literal_plan_on_file(&fullword_path, &fullword_plan).expect("fullword"));
    fs::write(&fullword_path, b"xWORDx").expect("fullword miss bytes");
    assert!(
        !verify_fixed_literal_plan_on_file(&fullword_path, &fullword_plan).expect("fullword miss")
    );
}

#[test]
fn scan_index_batch_row_perf_report_includes_stage_breakdown() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    let tmp = tempdir().expect("tmp");
    let sample = tmp.path().join("sample.bin");
    let perf_path = tmp.path().join("perf.json");
    fs::write(
        &sample,
        b"MZthis file is long enough to exercise hll and metadata extraction",
    )
    .expect("sample");
    crate::perf::configure(Some(perf_path), false);

    let _row = scan_index_batch_row(
        &sample,
        ScanPolicy {
            fixed_filter_bytes: None,
            tier1_filter_target_fp: Some(DEFAULT_TIER1_FILTER_TARGET_FP),
            tier2_filter_target_fp: Some(DEFAULT_TIER2_FILTER_TARGET_FP),
            gram_sizes: GramSizes::new(3, 4).expect("gram sizes"),
            chunk_size: 8,
            store_path: false,
            id_source: CandidateIdSource::Sha256,
        },
    )
    .expect("scan row");

    let report = crate::perf::report_value(0).expect("perf report");
    let stages = report
        .get("stages")
        .and_then(serde_json::Value::as_object)
        .expect("stages");
    for stage in [
        "candidate.scan_index_batch_row",
        "candidate.scan_index_batch_row.estimate_unique_grams",
        "candidate.scan_index_batch_row.filter_sizing",
        "candidate.scan_index_batch_row.metadata",
        "candidate.scan_index_batch_row.row_build",
        "candidate.scan_file_features",
    ] {
        let stats = stages
            .get(stage)
            .unwrap_or_else(|| panic!("missing stage {stage}"));
        assert_eq!(
            stats.get("calls").and_then(serde_json::Value::as_u64),
            Some(1),
            "stage {stage}"
        );
    }
    crate::perf::configure(None, false);
}

#[test]
fn candidate_helper_commands_work() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let sample_dir = base.join("samples");
    let candidate_root = base.join("candidate_db");
    let rule_path = base.join("rule.yar");
    fs::create_dir_all(&sample_dir).expect("sample dir");
    let sample_a = sample_dir.join("a.bin");
    let sample_b = sample_dir.join("b.bin");
    fs::write(&sample_a, b"xxABCDyy").expect("sample a");
    fs::write(&sample_b, b"zzABCDqq").expect("sample b");
    fs::write(
        &rule_path,
        r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("rule");

    let candidate_init_args = default_internal_init_args(&candidate_root, 1, true);
    assert_eq!(cmd_init(&candidate_init_args), 0);

    let ingest_one = InternalIndexArgs {
        connection: default_connection(),
        file_path: sample_a.display().to_string(),
        root: Some(candidate_root.display().to_string()),
        external_id: Some("manual-a".to_owned()),
        chunk_size: 1024,
    };
    assert_eq!(cmd_internal_index(&ingest_one), 0);

    let ingest_batch = InternalIndexBatchArgs {
        paths: vec![sample_dir.display().to_string()],
        path_list: false,
        root: Some(candidate_root.display().to_string()),
        batch_size: 1,
        workers: 2,
        chunk_size: 1024,
        verbose: false,
    };
    assert_eq!(cmd_internal_index_batch(&ingest_batch), 0);

    let query_args = InternalQueryArgs {
        connection: default_connection(),
        root: Some(candidate_root.display().to_string()),
        rule: rule_path.display().to_string(),
        cursor: 0,
        chunk_size: 10,
        max_anchors_per_pattern: 8,
        force_tier1_only: false,
        no_tier2_fallback: false,
        max_candidates: 100.0,
    };
    assert_eq!(cmd_internal_query(&query_args), 0);

    let stats_args = InternalStatsArgs {
        connection: default_connection(),
        root: Some(candidate_root.display().to_string()),
    };
    assert_eq!(cmd_internal_stats(&stats_args), 0);

    let delete_args = InternalDeleteArgs {
        connection: default_connection(),
        root: Some(candidate_root.display().to_string()),
        values: vec![sample_a.display().to_string()],
    };
    assert_eq!(cmd_internal_delete(&delete_args), 0);
    assert_eq!(
        cmd_internal_delete(&InternalDeleteArgs {
            connection: default_connection(),
            root: Some(candidate_root.display().to_string()),
            values: Vec::new(),
        }),
        1
    );
}

#[test]
fn expand_input_paths_supports_path_lists() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let rel_dir = base.join("rel");
    fs::create_dir_all(&rel_dir).expect("rel dir");
    let rel_file = rel_dir.join("a.bin");
    let abs_file = base.join("b.bin");
    fs::write(&rel_file, b"a").expect("rel");
    fs::write(&abs_file, b"b").expect("abs");
    let list_path = base.join("dataset.txt");
    fs::write(&list_path, format!("rel/a.bin\n{}\n\n", abs_file.display())).expect("list");

    let expanded = expand_input_paths(&[list_path.display().to_string()], true).expect("list");
    assert_eq!(expanded, vec![abs_file, rel_file]);
}

#[test]
fn yara_check_and_main_dispatch_work() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    let hit_path = tmp.path().join("hit.bin");
    fs::write(
        &rule_path,
        "rule TestLiteral : tag_a { strings: $a = \"hello\" condition: $a }\n",
    )
    .expect("rule");
    fs::write(&hit_path, b"well hello there").expect("hit");

    assert_eq!(
        cmd_yara(&YaraArgs {
            rule: rule_path.display().to_string(),
            file_path: hit_path.display().to_string(),
            scan_timeout: 1,
            show_tags: true,
        }),
        0
    );
    assert_eq!(
        cmd_yara(&YaraArgs {
            rule: tmp.path().join("missing.yar").display().to_string(),
            file_path: hit_path.display().to_string(),
            scan_timeout: 1,
            show_tags: false,
        }),
        1
    );
    assert_eq!(
        main(Some(vec![
            "sspry".to_owned(),
            "--rule".to_owned(),
            rule_path.display().to_string(),
            hit_path.display().to_string(),
        ])),
        0
    );
}

#[test]
fn local_multishard_candidate_commands_cover_root_branches() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let sample_dir = base.join("samples");
    let candidate_root = base.join("candidate_db");
    let rule_path = base.join("rule.yar");
    fs::create_dir_all(&sample_dir).expect("sample dir");
    let sample_a = sample_dir.join("a.bin");
    let sample_b = sample_dir.join("b.bin");
    let sample_c = sample_dir.join("c.bin");
    fs::write(&sample_a, b"ABCD tail").expect("sample a");
    fs::write(&sample_b, b"prefix ABCD").expect("sample b");
    fs::write(&sample_c, b"ABCD extra").expect("sample c");
    fs::write(
        &rule_path,
        r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("rule");

    assert_eq!(
        cmd_init(&default_internal_init_args(&candidate_root, 2, true)),
        0
    );
    assert_eq!(
        cmd_init(&default_internal_init_args(&candidate_root, 2, false)),
        0
    );
    assert_eq!(
        cmd_init(&default_internal_init_args(&candidate_root, 1, false)),
        1
    );

    assert_eq!(
        cmd_local_index(&LocalIndexArgs {
            root: candidate_root.display().to_string(),
            candidate_shards: 2,
            force: false,
            tier1_filter_target_fp: None,
            tier2_filter_target_fp: None,
            gram_sizes: "3,4".to_owned(),
            compaction_idle_cooldown_s: 5.0,
            paths: vec![
                sample_dir.display().to_string(),
                base.join("missing").display().to_string(),
            ],
            path_list: false,
            batch_size: 1,
            workers: Some(1),
            verbose: false,
        }),
        0
    );
    assert_eq!(
        cmd_internal_index_batch(&InternalIndexBatchArgs {
            paths: vec![base.join("missing_only").display().to_string()],
            path_list: false,
            root: Some(candidate_root.display().to_string()),
            batch_size: 1,
            workers: 1,
            chunk_size: 1024,
            verbose: false,
        }),
        1
    );
    assert_eq!(
        cmd_internal_index(&InternalIndexArgs {
            connection: default_connection(),
            file_path: sample_a.display().to_string(),
            root: Some(candidate_root.display().to_string()),
            external_id: Some("manual-root-id".to_owned()),
            chunk_size: 1024,
        }),
        0
    );
    assert_eq!(
        cmd_internal_query(&InternalQueryArgs {
            connection: default_connection(),
            root: Some(candidate_root.display().to_string()),
            rule: rule_path.display().to_string(),
            cursor: 0,
            chunk_size: 1,
            max_anchors_per_pattern: 2,
            force_tier1_only: false,
            no_tier2_fallback: false,
            max_candidates: 2.0,
        }),
        0
    );
    assert_eq!(
        cmd_internal_query(&InternalQueryArgs {
            connection: default_connection(),
            root: Some(candidate_root.display().to_string()),
            rule: rule_path.display().to_string(),
            cursor: 0,
            chunk_size: 4,
            max_anchors_per_pattern: 4,
            force_tier1_only: true,
            no_tier2_fallback: true,
            max_candidates: 8.0,
        }),
        0
    );
    assert_eq!(
        cmd_local_search(&LocalSearchArgs {
            root: candidate_root.display().to_string(),
            rule: rule_path.display().to_string(),
            tree_search_workers: 2,
            max_anchors_per_pattern: 4,
            max_candidates: 8.0,
            verify_yara_files: false,
            verbose: false,
        }),
        0
    );
    let path_sha = hex::encode(sha256_file(&sample_b, 1024).expect("sha256"));
    assert_eq!(
        cmd_local_info(&LocalInfoArgs {
            root: candidate_root.display().to_string(),
        }),
        0
    );
    assert_eq!(
        cmd_local_delete(&LocalDeleteArgs {
            root: candidate_root.display().to_string(),
            values: vec![path_sha],
        }),
        0
    );
}

#[cfg(unix)]
#[test]
fn public_remote_commands_cover_grpc_path() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let sample_dir = base.join("remote_samples");
    fs::create_dir_all(&sample_dir).expect("sample dir");
    let sample_a = sample_dir.join("a.bin");
    let sample_b = sample_dir.join("b.bin");
    let sample_c = sample_dir.join("c.bin");
    fs::write(&sample_a, b"ABCD remote one").expect("sample a");
    fs::write(&sample_b, b"prefix ABCD remote two").expect("sample b");
    fs::write(&sample_c, b"ABCD remote three").expect("sample c");
    let rule_path = base.join("remote_rule.yar");
    fs::write(
        &rule_path,
        r#"
rule remote_q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("rule");
    let connection = start_grpc_test_server(base, 2);
    let policy = server_scan_policy(&connection).expect("scan policy from server");
    assert_eq!(policy.id_source, CandidateIdSource::Sha256);
    assert!(!policy.store_path);
    assert_eq!(policy.tier1_filter_target_fp, Some(0.38));
    assert_eq!(policy.tier2_filter_target_fp, Some(0.18));
    assert_eq!(policy.gram_sizes, GramSizes::new(3, 4).expect("gram sizes"));

    assert_eq!(
        cmd_index(&IndexArgs {
            connection: connection.clone(),
            paths: vec![
                sample_a.display().to_string(),
                sample_b.display().to_string(),
                sample_c.display().to_string()
            ],
            path_list: false,
            batch_size: 1,
            remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
            grpc_insert_chunk_bytes: grpc::DEFAULT_GRPC_INSERT_CHUNK_BYTES,
            workers: Some(2),
            verbose: false,
        }),
        0
    );
    assert_eq!(
        cmd_search(&SearchCommandArgs {
            connection: connection.clone(),
            rule: rule_path.display().to_string(),
            max_anchors_per_pattern: 2,
            max_candidates: 8.0,
            verify_yara_files: false,
            verbose: false,
        }),
        0
    );
    assert_eq!(
        cmd_search(&SearchCommandArgs {
            connection: connection.clone(),
            rule: rule_path.display().to_string(),
            max_anchors_per_pattern: 2,
            max_candidates: 8.0,
            verify_yara_files: true,
            verbose: false,
        }),
        0
    );
    assert_eq!(
        cmd_info(&InfoCommandArgs {
            connection: connection.clone(),
            light: false,
        }),
        0
    );
    assert_eq!(
        cmd_delete(&DeleteArgs {
            connection: connection.clone(),
            values: vec![sample_a.display().to_string()],
        }),
        0
    );
    assert_eq!(
        main(Some(vec![
            "sspry".to_owned(),
            "--perf-report".to_owned(),
            base.join("perf").join("stats.json").display().to_string(),
            "info".to_owned(),
            "--addr".to_owned(),
            connection.addr.clone(),
        ])),
        0
    );
}

#[test]
fn main_returns_error_when_perf_report_path_is_unwritable() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let perf_dir = tmp.path().join("perf-as-dir");
    let rule_path = tmp.path().join("rule.yar");
    let hit_path = tmp.path().join("hit.bin");
    fs::create_dir_all(&perf_dir).expect("perf dir");
    fs::write(
        &rule_path,
        "rule TestLiteral { strings: $a = \"hello\" condition: $a }\n",
    )
    .expect("rule");
    fs::write(&hit_path, b"hello").expect("hit");
    assert_eq!(
        main(Some(vec![
            "sspry".to_owned(),
            "--perf-report".to_owned(),
            perf_dir.display().to_string(),
            "--rule".to_owned(),
            rule_path.display().to_string(),
            hit_path.display().to_string(),
        ])),
        1
    );
    crate::perf::configure(None, false);
}

#[test]
fn cmd_serve_reports_tcp_bind_errors() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let listener = std::net::TcpListener::bind((DEFAULT_RPC_HOST, 0)).expect("bind occupied port");
    let port = listener.local_addr().expect("listener addr").port();
    let mut args = default_serve_args();
    args.common.addr = format!("{DEFAULT_RPC_HOST}:{port}");
    assert_eq!(cmd_serve(&args), 1);
}

#[test]
fn local_command_error_paths_report_failures() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let sample = tmp.path().join("sample.bin");
    let missing_root = tmp.path().join("missing_root");
    let missing_rule = tmp.path().join("missing_rule.yar");
    fs::write(&sample, b"ABCD").expect("sample");

    assert_eq!(
        cmd_internal_index(&InternalIndexArgs {
            connection: default_connection(),
            file_path: sample.display().to_string(),
            root: Some(missing_root.display().to_string()),
            external_id: None,
            chunk_size: 1024,
        }),
        1
    );
    assert_eq!(
        cmd_local_info(&LocalInfoArgs {
            root: missing_root.display().to_string(),
        }),
        1
    );
    assert_eq!(
        cmd_local_search(&LocalSearchArgs {
            root: missing_root.display().to_string(),
            rule: missing_rule.display().to_string(),
            tree_search_workers: 0,
            max_anchors_per_pattern: 1,
            max_candidates: 1.0,
            verify_yara_files: false,
            verbose: false,
        }),
        1
    );
    assert_eq!(
        cmd_local_delete(&LocalDeleteArgs {
            root: missing_root.display().to_string(),
            values: vec![sample.display().to_string()],
        }),
        1
    );
    assert_eq!(
        cmd_delete(&DeleteArgs {
            connection: default_connection(),
            values: vec!["not-a-valid-digest".to_owned()],
        }),
        1
    );
}

#[cfg(unix)]
#[test]
fn public_ingest_and_delete_follow_server_identity_source() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let sample = base.join("identity.bin");
    fs::write(&sample, b"ABCD identity").expect("sample");

    let connection = start_grpc_test_server_with_config(RpcServerConfig {
        candidate_config: CandidateConfig {
            root: base.join("candidate_db"),
            id_source: "md5".to_owned(),
            ..CandidateConfig::default()
        },
        candidate_shards: 1,
        search_workers: default_search_workers_for(4),
        memory_budget_bytes: DEFAULT_MEMORY_BUDGET_BYTES,
        auto_publish_initial_idle_ms: 500,
        auto_publish_storage_class: "unknown".to_owned(),
        workspace_mode: true,
    });

    assert_eq!(
        cmd_index(&IndexArgs {
            connection: connection.clone(),
            paths: vec![sample.display().to_string()],
            path_list: false,
            batch_size: 1,
            remote_batch_soft_limit_bytes: REMOTE_INSERT_BATCH_SOFT_LIMIT_BYTES,
            grpc_insert_chunk_bytes: grpc::DEFAULT_GRPC_INSERT_CHUNK_BYTES,
            workers: Some(1),
            verbose: false,
        }),
        0
    );

    assert_eq!(
        cmd_delete(&DeleteArgs {
            connection: connection.clone(),
            values: vec![hex::encode(sha256_file(&sample, 1024).expect("sha256"))],
        }),
        1
    );

    assert_eq!(
        cmd_delete(&DeleteArgs {
            connection,
            values: vec![hex::encode(md5_file(&sample, 1024).expect("md5"))],
        }),
        0
    );
}

#[test]
fn non_sha256_identity_sources_normalize_consistently() {
    let tmp = tempdir().expect("tmp");
    let sample = tmp.path().join("sample.bin");
    fs::write(&sample, b"identity-check-bytes").expect("sample");

    let md5_bytes = md5_file(&sample, 1024).expect("md5");
    let sha1_bytes = sha1_file(&sample, 1024).expect("sha1");
    let sha512_bytes = sha512_file(&sample, 1024).expect("sha512");

    assert_eq!(
        identity_from_file(&sample, 1024, CandidateIdSource::Md5).expect("md5 file"),
        identity_from_hex(&hex::encode(md5_bytes), CandidateIdSource::Md5).expect("md5 hex")
    );
    assert_eq!(
        identity_from_file(&sample, 1024, CandidateIdSource::Sha1).expect("sha1 file"),
        identity_from_hex(&hex::encode(sha1_bytes), CandidateIdSource::Sha1).expect("sha1 hex")
    );
    assert_eq!(
        identity_from_file(&sample, 1024, CandidateIdSource::Sha512).expect("sha512 file"),
        identity_from_hex(&hex::encode(sha512_bytes), CandidateIdSource::Sha512)
            .expect("sha512 hex")
    );

    assert_ne!(
        identity_from_file(&sample, 1024, CandidateIdSource::Md5).expect("md5 file"),
        sha256_file(&sample, 1024).expect("sha256 file")
    );
}

#[test]
fn digest_helpers_and_delete_resolution_cover_remaining_branches() {
    let tmp = tempdir().expect("tmp");
    let sample = tmp.path().join("sample.bin");
    fs::write(&sample, b"identity-check-bytes").expect("sample");

    assert!(md5_file(&sample, 0)
        .expect_err("md5 zero chunk")
        .to_string()
        .contains("positive integer"));
    assert!(sha1_file(&sample, 0)
        .expect_err("sha1 zero chunk")
        .to_string()
        .contains("positive integer"));
    assert!(sha512_file(&sample, 0)
        .expect_err("sha512 zero chunk")
        .to_string()
        .contains("positive integer"));

    assert_eq!(
        detect_digest_identity_source(&"aa".repeat(16)),
        Some(CandidateIdSource::Md5)
    );
    assert_eq!(
        detect_digest_identity_source(&"bb".repeat(20)),
        Some(CandidateIdSource::Sha1)
    );
    assert_eq!(
        detect_digest_identity_source(&"cc".repeat(32)),
        Some(CandidateIdSource::Sha256)
    );
    assert_eq!(
        detect_digest_identity_source(&"dd".repeat(64)),
        Some(CandidateIdSource::Sha512)
    );
    assert_eq!(detect_digest_identity_source("not-hex"), None);
    assert_eq!(detect_digest_identity_source(&"ee".repeat(12)), None);

    let sha256_hex = hex::encode(sha256_file(&sample, 1024).expect("sha256"));
    let md5_hex = hex::encode(md5_file(&sample, 1024).expect("md5"));
    let sha1_hex = hex::encode(sha1_file(&sample, 1024).expect("sha1"));
    let sha512_hex = hex::encode(sha512_file(&sample, 1024).expect("sha512"));

    assert_eq!(
        resolve_delete_value(
            sample.to_str().expect("sample"),
            CandidateIdSource::Sha256,
            1024,
        )
        .expect("path delete resolution"),
        hex::encode(
            identity_from_file(&sample, 1024, CandidateIdSource::Sha256).expect("path identity")
        )
    );
    assert_eq!(
        resolve_delete_value(&md5_hex, CandidateIdSource::Md5, 1024)
            .expect("md5 delete resolution"),
        hex::encode(identity_from_hex(&md5_hex, CandidateIdSource::Md5).expect("normalized md5"))
    );
    assert_eq!(
        resolve_delete_value(&sha1_hex, CandidateIdSource::Sha1, 1024)
            .expect("sha1 delete resolution"),
        hex::encode(
            identity_from_hex(&sha1_hex, CandidateIdSource::Sha1).expect("normalized sha1")
        )
    );
    assert_eq!(
        resolve_delete_value(&sha512_hex, CandidateIdSource::Sha512, 1024)
            .expect("sha512 delete resolution"),
        hex::encode(
            identity_from_hex(&sha512_hex, CandidateIdSource::Sha512).expect("normalized sha512")
        )
    );
    assert!(
        resolve_delete_value(&md5_hex, CandidateIdSource::Sha256, 1024)
            .expect_err("mismatched digest type")
            .to_string()
            .contains("server identity source is")
    );
    assert!(
        resolve_delete_value("not-a-path-or-digest", CandidateIdSource::Sha256, 1024)
            .expect_err("invalid delete value")
            .to_string()
            .contains("is neither an existing file path nor a valid")
    );

    assert_eq!(
        resolve_delete_identity(
            Some(&sha256_hex),
            None,
            None,
            None,
            None,
            CandidateIdSource::Sha256,
            1024,
        )
        .expect("resolved identity"),
        hex::encode(
            identity_from_hex(&sha256_hex, CandidateIdSource::Sha256).expect("normalized sha256")
        )
    );
}

#[test]
fn batch_search_helper_functions_cover_local_forest_paths() {
    let _guard = crate::perf::test_lock().lock().expect("perf lock");
    crate::perf::configure(None, false);
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();

    assert!(default_ingest_workers() >= 1);
    assert_eq!(
        remote_index_session_document_limit(0, 64),
        REMOTE_INDEX_SESSION_MAX_DOCUMENTS
    );
    assert_eq!(
        remote_index_session_document_limit(640 * 1024 * 4 * 8, 64),
        64
    );
    assert_eq!(
        remote_index_session_document_limit(640 * 1024 * 4 * 4096, 1),
        REMOTE_INDEX_SESSION_MAX_DOCUMENTS
    );
    assert_eq!(
        remote_index_session_input_bytes_limit(0),
        REMOTE_INDEX_SESSION_MAX_INPUT_BYTES
    );
    assert_eq!(
        remote_index_session_input_bytes_limit(4 << 30),
        REMOTE_INDEX_SESSION_MIN_INPUT_BYTES
    );
    assert_eq!(
        remote_index_session_input_bytes_limit(40 << 30),
        REMOTE_INDEX_SESSION_MAX_INPUT_BYTES
    );
    assert!(is_retryable_remote_index_rotation_error(&SspryError::from(
        "server is publishing; retry later"
    )));
    assert!(is_retryable_remote_index_rotation_error(&SspryError::from(
        "another index session is already active; retry later"
    )));
    assert!(is_retryable_remote_index_rotation_error(&SspryError::from(
        "no active index session; cannot update progress"
    )));
    assert!(!is_retryable_remote_index_rotation_error(
        &SspryError::from("fatal publish failure")
    ));
    assert!(is_wide_word_unit(b"A\0"));
    assert!(!is_wide_word_unit(b"A"));
    assert!(!is_wide_word_unit(&[0xff, 0x00]));

    let direct_root = base.join("direct");
    fs::create_dir_all(direct_root.join("current")).expect("direct current");
    assert_eq!(
        forest_tree_roots(&direct_root).expect("direct tree roots"),
        vec![direct_root.join("current")]
    );

    let empty_root = base.join("empty");
    fs::create_dir_all(&empty_root).expect("empty root");
    assert_eq!(
        forest_tree_roots(&empty_root).expect("fallback tree roots"),
        vec![empty_root.clone()]
    );
}

#[test]
fn grpc_batch_helper_functions_cover_limits_and_oversize_rows() {
    let empty_payload_size = empty_remote_batch_payload_size().expect("empty payload size");
    let minimum_soft_limit = empty_payload_size.saturating_add(1);

    assert_eq!(grpc_remote_batch_size(0), 1);
    assert_eq!(grpc_remote_batch_size(3), 3);
    assert_eq!(
        grpc_remote_batch_size(GRPC_REMOTE_BATCH_MAX_ROWS + 5),
        GRPC_REMOTE_BATCH_MAX_ROWS
    );

    assert_eq!(
        grpc_remote_batch_soft_limit_bytes(1, empty_payload_size),
        minimum_soft_limit
    );
    assert_eq!(
        grpc_remote_batch_soft_limit_bytes(usize::MAX, empty_payload_size),
        GRPC_REMOTE_BATCH_SOFT_LIMIT_BYTES.max(minimum_soft_limit)
    );

    assert_eq!(
        remote_upload_queue_byte_limit(0, 1024),
        2048.min(REMOTE_UPLOAD_QUEUE_MAX_BYTES)
    );
    assert_eq!(
        remote_upload_queue_byte_limit(u64::MAX, 1024),
        REMOTE_UPLOAD_QUEUE_MAX_BYTES
    );

    let pending_empty = RemotePendingBatch {
        rows: Vec::new(),
        payload_size: empty_payload_size,
    };
    let pending_non_empty = RemotePendingBatch {
        rows: vec![vec![1, 2, 3]],
        payload_size: empty_payload_size + 3,
    };

    assert!(!prepare_serialized_remote_batch_row(
        &pending_empty,
        16,
        empty_payload_size,
        empty_payload_size + 32,
        false,
    )
    .expect("fits empty batch"));
    assert!(prepare_serialized_remote_batch_row(
        &pending_non_empty,
        4,
        empty_payload_size,
        empty_payload_size + 7,
        false,
    )
    .expect("flush before oversize append"));
    assert!(prepare_serialized_remote_batch_row(
        &pending_non_empty,
        64,
        empty_payload_size,
        empty_payload_size + 32,
        true,
    )
    .expect("flush before oversize single row"));
    assert!(prepare_serialized_remote_batch_row(
        &pending_empty,
        64,
        empty_payload_size,
        empty_payload_size + 32,
        false,
    )
    .is_err());
}

#[test]
fn internal_local_only_commands_reject_removed_remote_paths() {
    assert_eq!(
        cmd_internal_index_batch(&InternalIndexBatchArgs {
            paths: Vec::new(),
            path_list: false,
            root: None,
            batch_size: 1,
            workers: 1,
            chunk_size: 1024,
            verbose: false,
        }),
        1
    );
    assert_eq!(
        cmd_internal_query(&InternalQueryArgs {
            connection: default_connection(),
            root: None,
            rule: "/tmp/missing.yar".to_owned(),
            cursor: 0,
            chunk_size: 1,
            max_anchors_per_pattern: 4,
            force_tier1_only: false,
            no_tier2_fallback: false,
            max_candidates: 1.0,
        }),
        1
    );
}
