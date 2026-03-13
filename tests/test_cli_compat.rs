use std::fs;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;
use tempfile::tempdir;

fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_yaya"))
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

fn run_ok_env(args: &[&str], envs: &[(&str, &str)]) -> String {
    let mut command = Command::new(bin_path());
    command.args(args);
    for (key, value) in envs {
        command.env(key, value);
    }
    let output = command.output().expect("run command");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
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
fn public_cli_roundtrip_over_tcp() {
    let tmp = tempdir().expect("tmp");
    let base = tmp.path();
    let candidate_root = base.join("candidate_db");
    let sample_dir = base.join("samples");
    let rule = base.join("rule.yar");
    let port = reserve_tcp_port();
    fs::create_dir_all(&sample_dir).expect("mkdir samples");

    let sample_a = sample_dir.join("a.bin");
    let sample_b = sample_dir.join("b.bin");
    fs::write(&sample_a, b"xxABCDyy").expect("write a");
    fs::write(&sample_b, b"zzABCDqq").expect("write b");
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

    let mut child = spawn_serve_tcp(port, &candidate_root, &["--store-path"]);
    let addr = tcp_addr(port);
    wait_for_info(&addr);

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-size",
        "1",
    ]);
    assert!(ingest.contains("submitted_documents: 2"));
    assert!(ingest.contains("processed_documents: 2"));

    let search = run_ok(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        rule.to_str().expect("rule"),
    ]);
    assert!(search.contains("legacy_query:"));
    assert!(search.contains("tier_used:"));
    assert!(search.contains("candidates: 2"));

    let deleted = run_ok(&[
        "delete",
        "--addr",
        &addr,
        sample_a.to_str().expect("sample a"),
    ]);
    assert!(deleted.contains("status: deleted"));

    let info = run_ok(&["info", "--addr", &addr]);
    let parsed: Value = serde_json::from_str(&info).expect("info json");
    assert_eq!(parsed.get("doc_count").and_then(Value::as_u64), Some(2));
    assert_eq!(
        parsed.get("active_doc_count").and_then(Value::as_u64),
        Some(1)
    );
    assert_eq!(
        parsed.get("deleted_doc_count").and_then(Value::as_u64),
        Some(1)
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn help_surface_has_only_public_commands() {
    let out = run_ok(&["--help"]);
    assert!(out.contains("serve"));
    assert!(out.contains("index"));
    assert!(out.contains("delete"));
    assert!(out.contains("search"));
    assert!(out.contains("info"));
    assert!(out.contains("shutdown"));
    assert!(out.contains("yara"));
    assert!(!out.contains("candidate-init"));
    assert!(!out.contains("candidate-ingest"));
    assert!(!out.contains("candidate-query"));
    assert!(!out.contains("candidate-stats"));
    assert!(!out.contains("init\n"));
}

#[test]
fn info_uses_tgsdb_addr_env() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();
    let addr = tcp_addr(port);

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    wait_for_info(&addr);

    let info = run_ok_env(&["info"], &[("YAYA_ADDR", &addr)]);
    let parsed: Value = serde_json::from_str(&info).expect("info json");
    assert_eq!(
        parsed.get("candidate_shards").and_then(Value::as_u64),
        Some(256)
    );

    let _ = child.kill();
    let _ = child.wait();
}

#[test]
fn shutdown_command_drains_server() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("candidate_db");
    let port = reserve_tcp_port();
    let addr = tcp_addr(port);

    let mut child = spawn_serve_tcp(port, &candidate_root, &[]);
    wait_for_info(&addr);

    let out = run_ok(&["shutdown", "--addr", &addr]);
    assert!(out.contains("shutdown requested"));

    for _ in 0..80 {
        if child.try_wait().expect("wait").is_some() {
            return;
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    let _ = child.kill();
    panic!("server did not exit after shutdown");
}

#[test]
fn removed_internal_commands_are_rejected() {
    for command in [
        "init",
        "candidate-init",
        "candidate-ingest",
        "candidate-ingest-batch",
        "candidate-delete",
        "candidate-query",
        "candidate-stats",
    ] {
        let err = run_fail(&[command]);
        assert!(err.contains("unrecognized subcommand"), "{command}: {err}");
    }
}

#[test]
fn removed_public_aliases_and_flags_are_rejected() {
    for alias in ["remove", "query", "ingest", "yara-check"] {
        let err = run_fail(&[alias]);
        assert!(err.contains("unrecognized subcommand"));
    }

    for flag in [
        "--max-unique-grams",
        "--filter-bytes",
        "--bloom-hashes",
        "--tier1-gram-budget",
        "--tier1-gram-sample-mod",
        "--tier1-gram-hash-seed",
        "--chunk-size",
        "--external-id-from-path",
        "--socket-path",
        "--store-path",
        "--host",
        "--port",
    ] {
        let err = run_fail(&["index", "/tmp/sample.bin", flag, "1"]);
        assert!(err.contains("unexpected argument"));
    }

    for flag in [
        "--chunk-size",
        "--socket-path",
        "--force-tier1-only",
        "--no-tier2-fallback",
        "--no-df-lookup",
        "--no-verify-yara-files",
        "--host",
        "--port",
    ] {
        let err = run_fail(&["search", "--rule", "rule.yar", flag]);
        assert!(err.contains("unexpected argument"));
    }

    for flag in [
        "--candidate-filter-bytes",
        "--candidate-bloom-hashes",
        "--candidate-filter-min-bytes",
        "--candidate-filter-max-bytes",
        "--candidate-filter-size-divisor",
        "--lock-timeout",
        "--socket-path",
        "--wal-group-commit-ms",
        "--wal-max-pending-bytes",
        "--candidate-memtable-max-postings",
        "--candidate-tier1-gram-budget",
        "--candidate-tier1-gram-sample-mod",
        "--candidate-tier1-gram-hash-seed",
        "--candidate-df-min",
        "--candidate-df-max",
        "--candidate-segment-bloom-bits",
        "--candidate-segment-bloom-hashes",
        "--candidate-compaction-trigger-segments",
        "--candidate-compaction-max-segments",
        "--candidate-compaction-merge-count",
        "--candidate-compaction-io-budget-bytes-per-wake",
        "--candidate-compaction-idle-cooldown-s",
        "--candidate-compaction-level-size-base",
        "--candidate-segment-data-alignment",
        "--candidate-segment-write-buffer-bytes",
        "--wal-path",
        "--host",
        "--port",
    ] {
        let err = run_fail(&["serve", flag, "x"]);
        assert!(err.contains("unexpected argument"));
    }

    for flag in ["--socket-path", "--chunk-size", "--host", "--port"] {
        let err = run_fail(&["delete", flag, "x"]);
        assert!(err.contains("unexpected argument"));
    }

    for flag in ["--socket-path", "--host", "--port"] {
        let err = run_fail(&["info", flag, "x"]);
        assert!(err.contains("unexpected argument"));
    }
}
