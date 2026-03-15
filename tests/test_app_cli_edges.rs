use std::fs;
use std::net::TcpListener;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::tempdir;

fn bin_path() -> String {
    env!("CARGO_BIN_EXE_sspry").to_owned()
}

fn run_ok(args: &[&str]) -> String {
    let output = Command::new(bin_path())
        .args(args)
        .output()
        .expect("run command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

fn run_fail(args: &[&str]) -> String {
    let output = Command::new(bin_path())
        .args(args)
        .output()
        .expect("run command");
    assert!(
        !output.status.success(),
        "command unexpectedly succeeded: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    )
}

fn reserve_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

fn tcp_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn wait_for_info(addr: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    while Instant::now() < deadline {
        let output = Command::new(bin_path())
            .args(["info", "--addr", addr])
            .output()
            .expect("run info");
        if output.status.success() {
            return;
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!("server did not become ready on {addr}");
}

fn spawn_serve_tcp(port: u16, candidate_root: &Path, extra_args: &[&str]) -> Child {
    let addr = tcp_addr(port);
    let mut command = Command::new(bin_path());
    command
        .arg("serve")
        .arg("--addr")
        .arg(&addr)
        .arg("--root")
        .arg(candidate_root)
        .args(extra_args)
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    command.spawn().expect("spawn serve")
}

#[test]
fn serve_validation_errors_are_reported() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("candidate_db");

    let err = run_fail(&[
        "serve",
        "--addr",
        &tcp_addr(reserve_tcp_port()),
        "--root",
        candidate_root.to_str().expect("root"),
        "--set-fp",
        "1.0",
    ]);
    assert!(err.contains("filter_target_fp"));
}

#[test]
fn info_over_tcp_returns_json_after_auto_init() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();

    let mut child = spawn_serve_tcp(port, &root, &[]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let stats = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&stats).expect("stats json");
    assert_eq!(
        parsed.get("active_doc_count").and_then(Value::as_u64),
        Some(0)
    );
    assert_eq!(
        parsed.get("deleted_doc_count").and_then(Value::as_u64),
        Some(0)
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn serve_persists_candidate_shards() {
    let tmp = tempdir().expect("tmp");
    let root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();

    let mut child = spawn_serve_tcp(port, &root, &["--shards", "2"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let stats = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&stats).expect("stats json");
    assert_eq!(
        parsed.get("candidate_shards").and_then(Value::as_u64),
        Some(2)
    );
    assert_eq!(
        parsed.get("workspace_mode").and_then(Value::as_bool),
        Some(true)
    );
    assert!(
        root.join("current")
            .join("shard_000")
            .join("meta.json")
            .exists()
    );
    assert!(
        root.join("current")
            .join("shard_001")
            .join("meta.json")
            .exists()
    );
    assert!(
        root.join("work")
            .join("shard_000")
            .join("meta.json")
            .exists()
    );
    assert!(
        root.join("work")
            .join("shard_001")
            .join("meta.json")
            .exists()
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn yara_reports_match_and_tags() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    let hit_path = tmp.path().join("hit.bin");
    fs::write(
        &rule_path,
        "rule TestLiteral : tag_a { strings: $a = \"hello\" condition: $a }\n",
    )
    .expect("rule");
    fs::write(&hit_path, b"well hello there").expect("hit");

    let out = run_ok(&[
        "yara",
        "--rule",
        rule_path.to_str().expect("rule"),
        "--show-tags",
        hit_path.to_str().expect("hit"),
    ]);
    assert!(out.contains("matched: yes"));
    assert!(out.contains("match_rule: TestLiteral"));
    assert!(out.contains("match_tags: tag_a"));
}

#[test]
fn removed_yara_check_name_is_rejected() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("rule.yar");
    let miss_path = tmp.path().join("miss.bin");
    fs::write(
        &rule_path,
        "rule TestLiteral { strings: $a = \"hello\" condition: $a }\n",
    )
    .expect("rule");
    fs::write(&miss_path, b"goodbye").expect("miss");

    let out = run_fail(&[
        "yara-check",
        "--rule",
        rule_path.to_str().expect("rule"),
        miss_path.to_str().expect("miss"),
    ]);
    assert!(out.contains("unrecognized subcommand 'yara-check'"));
}

#[test]
fn yara_reports_missing_inputs() {
    let tmp = tempdir().expect("tmp");
    let hit_path = tmp.path().join("hit.bin");
    fs::write(&hit_path, b"hello").expect("hit");

    let rule_err = run_fail(&[
        "yara",
        "--rule",
        tmp.path().join("missing.yar").to_str().expect("rule"),
        hit_path.to_str().expect("hit"),
    ]);
    assert!(rule_err.contains("Rule file not found"));

    let file_err = run_fail(&[
        "yara",
        "--rule",
        hit_path.to_str().expect("rule"),
        tmp.path().join("missing.bin").to_str().expect("file"),
    ]);
    assert!(file_err.contains("Target file not found"));
}

#[test]
fn yara_supports_numeric_reads_and_filesize_conditions() {
    let tmp = tempdir().expect("tmp");
    let rule_path = tmp.path().join("numeric.yar");
    let hit_path = tmp.path().join("numeric.bin");

    let mut payload = Vec::new();
    payload.extend_from_slice(&0x0102_0304u32.to_le_bytes());
    payload.extend_from_slice(&0x0102_0304u32.to_be_bytes());
    payload.extend_from_slice(&1.5f32.to_le_bytes());
    payload.extend_from_slice(&2.5f32.to_be_bytes());
    payload.extend_from_slice(&3.5f64.to_le_bytes());
    payload.extend_from_slice(&4.5f64.to_be_bytes());
    assert_eq!(payload.len(), 32);
    fs::write(&hit_path, payload).expect("write payload");

    fs::write(
        &rule_path,
        r#"
rule NumericReads {
  condition:
    filesize == 32 and
    uint32(0) == 16909060 and
    int32(0) == 16909060 and
    uint32be(4) == 16909060 and
    int32be(4) == 16909060 and
    float32(8) == 1.5 and
    float32be(12) == 2.5 and
    float64(16) == 3.5 and
    float64be(24) == 4.5
}
"#,
    )
    .expect("write rule");

    let out = run_ok(&[
        "yara",
        "--rule",
        rule_path.to_str().expect("rule"),
        hit_path.to_str().expect("hit"),
    ]);
    assert!(out.contains("matched: yes"));
    assert!(out.contains("match_rule: NumericReads"));
}
