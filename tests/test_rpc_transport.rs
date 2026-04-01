use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;

use sspry::candidate::{
    DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE, GramSizes,
    compile_query_plan_from_file_with_gram_sizes, scan_file_features_bloom_only_with_gram_sizes,
};
use sspry::rpc::{ClientConfig, SspryClient, serialize_candidate_insert_binary_row_parts};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sspry"))
}

struct ChildGuard {
    child: Child,
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

fn reserve_port() -> u16 {
    let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn tcp_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn spawn_tcp_serve(port: u16, candidate_root: &Path) -> ChildGuard {
    let addr = tcp_addr(port);
    let child = Command::new(bin_path())
        .arg("serve")
        .arg("--addr")
        .arg(&addr)
        .arg("--root")
        .arg(candidate_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn serve");
    ChildGuard { child }
}

fn wait_for_server(port: u16) -> SspryClient {
    let client = SspryClient::new(ClientConfig::new(
        "127.0.0.1".to_owned(),
        port,
        Duration::from_secs(1),
        None,
    ));
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        if client.ping().is_ok() {
            return client;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not start on port {port}");
}

#[test]
fn tcp_rpc_transport_covers_candidate_actions() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let port = reserve_port();

    let cand_a = base.join("cand-a.bin");
    let cand_b = base.join("cand-b.bin");
    let rule = base.join("rule.yar");

    fs::write(&cand_a, b"xxABCDyy").expect("write cand a");
    fs::write(&cand_b, b"zzABCDqq").expect("write cand b");
    fs::write(
        &rule,
        r#"
rule q {
  strings:
    $a = "ABCD"
  condition:
    $a
}
"#,
    )
    .expect("write rule");

    let _server = spawn_tcp_serve(port, &candidate_root);
    let client = wait_for_server(port);

    let features_a = scan_file_features_bloom_only_with_gram_sizes(
        &cand_a,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
        1024,
        7,
        0,
        0,
        4096,
    )
    .expect("features a");
    let features_b = scan_file_features_bloom_only_with_gram_sizes(
        &cand_b,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
        1024,
        7,
        0,
        0,
        4096,
    )
    .expect("features b");
    let rows = vec![
        serialize_candidate_insert_binary_row_parts(
            &features_a.sha256,
            features_a.file_size,
            None,
            &features_a.bloom_filter,
            None,
            &[],
            false,
            &[],
            Some("cand-a"),
        )
        .expect("row a"),
        serialize_candidate_insert_binary_row_parts(
            &features_b.sha256,
            features_b.file_size,
            None,
            &features_b.bloom_filter,
            None,
            &[],
            false,
            &[],
            Some("cand-b"),
        )
        .expect("row b"),
    ];
    let inserted_docs = client
        .candidate_insert_binary_rows(&rows)
        .expect("candidate insert batch");
    assert_eq!(inserted_docs.inserted_count, 2);
    let publish = client.publish().expect("publish");
    assert!(publish.contains("published work root"));

    let plan = compile_query_plan_from_file_with_gram_sizes(
        &rule,
        GramSizes::new(DEFAULT_TIER1_GRAM_SIZE, DEFAULT_TIER2_GRAM_SIZE)
            .expect("default gram sizes"),
        8,
        false,
        true,
        100_000,
    )
    .expect("plan");
    let result = client
        .candidate_query_plan_with_options(&plan, 0, Some(32), true)
        .expect("candidate query");
    assert_eq!(result.total_candidates, 2);
    assert_eq!(result.sha256.len(), 2);
    let mut external_ids = result.external_ids.expect("external ids");
    external_ids.sort();
    assert_eq!(
        external_ids,
        vec![Some("cand-a".to_owned()), Some("cand-b".to_owned())]
    );

    let delete_result = client
        .candidate_delete_sha256(&hex::encode(features_a.sha256))
        .expect("candidate delete");
    assert_eq!(delete_result.status, "deleted");

    let stats = client.candidate_stats().expect("candidate stats");
    assert_eq!(
        stats.get("active_doc_count").and_then(|v| v.as_u64()),
        Some(1)
    );
    assert_eq!(
        stats.get("deleted_doc_count").and_then(|v| v.as_u64()),
        Some(1)
    );
}
