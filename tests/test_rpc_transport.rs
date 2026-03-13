use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use base64::Engine;
use tempfile::tempdir;

use yaya::candidate::{compile_query_plan_from_file, encode_grams_delta_u64, scan_file_features};
use yaya::rpc::{CandidateDocumentWire, ClientConfig, TgsdbClient};

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_yaya"))
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

fn wait_for_server(port: u16) -> TgsdbClient {
    let client = TgsdbClient::new(ClientConfig::new(
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

    let bloom_hashes = 7;
    let features_a = scan_file_features(
        &cand_a,
        1024,
        bloom_hashes,
        0,
        0,
        4096,
        true,
        None,
        None,
        2048,
        1,
        1337,
    )
    .expect("features a");
    let features_b = scan_file_features(
        &cand_b,
        1024,
        bloom_hashes,
        0,
        0,
        4096,
        true,
        None,
        None,
        2048,
        1,
        1337,
    )
    .expect("features b");
    let docs = vec![
        CandidateDocumentWire {
            sha256: hex::encode(features_a.sha256),
            file_size: features_a.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_a.bloom_filter),
            gram_count_estimate: None,
            bloom_hashes: None,
            tier2_bloom_filter_b64: None,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: None,
            grams_delta_b64: Some(
                base64::engine::general_purpose::STANDARD
                    .encode(encode_grams_delta_u64(features_a.unique_grams.clone())),
            ),
            grams: Vec::new(),
            grams_complete: !features_a.unique_grams_truncated,
            effective_diversity: None,
            external_id: Some("cand-a".to_owned()),
        },
        CandidateDocumentWire {
            sha256: hex::encode(features_b.sha256),
            file_size: features_b.file_size,
            bloom_filter_b64: base64::engine::general_purpose::STANDARD
                .encode(features_b.bloom_filter),
            gram_count_estimate: None,
            bloom_hashes: None,
            tier2_bloom_filter_b64: None,
            tier2_gram_count_estimate: None,
            tier2_bloom_hashes: None,
            grams_delta_b64: None,
            grams: features_b.unique_grams,
            grams_complete: !features_b.unique_grams_truncated,
            effective_diversity: None,
            external_id: Some("cand-b".to_owned()),
        },
    ];
    let inserted_docs = client
        .candidate_insert_batch(&docs)
        .expect("candidate insert batch");
    assert_eq!(inserted_docs.inserted_count, 2);

    let plan = compile_query_plan_from_file(&rule, None, 8, false, true, 100_000).expect("plan");
    let mut grams = Vec::new();
    for pattern in &plan.patterns {
        for alt in &pattern.alternatives {
            grams.extend(alt.iter().copied());
        }
    }
    let df = client.candidate_df(&grams).expect("candidate df");
    assert!(!df.is_empty());

    let result = client
        .candidate_query_plan_with_options(&plan, 0, Some(32), true)
        .expect("candidate query");
    assert_eq!(result.total_candidates, 2);
    assert_eq!(result.sha256.len(), 2);
    assert_eq!(
        result.external_ids,
        Some(vec![Some("cand-a".to_owned()), Some("cand-b".to_owned())])
    );

    let delete_result = client
        .candidate_delete_sha256(&docs[0].sha256)
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
