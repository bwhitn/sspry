#![allow(dead_code)]

use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use serde_json::Value;

pub fn bin_path() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_sspry"))
}

fn run_output(args: &[&str]) -> Output {
    Command::new(bin_path())
        .args(args)
        .output()
        .expect("run command")
}

fn run_output_owned(args: &[String]) -> Output {
    Command::new(bin_path())
        .args(args)
        .output()
        .expect("run command")
}

pub fn run_ok(args: &[&str]) -> String {
    let output = run_output(args);
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

pub fn run_ok_owned(args: &[String]) -> String {
    let output = run_output_owned(args);
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("utf8 stdout")
}

pub fn run_ok_capture(args: &[&str]) -> (String, String) {
    let output = run_output(args);
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout={}\nstderr={}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (
        String::from_utf8(output.stdout).expect("utf8 stdout"),
        String::from_utf8(output.stderr).expect("utf8 stderr"),
    )
}

pub fn run_fail(args: &[&str]) -> String {
    let output = run_output(args);
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

pub fn run_ok_env(args: &[&str], envs: &[(&str, &str)]) -> String {
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

pub fn reserve_tcp_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind ephemeral");
    let port = listener.local_addr().expect("local addr").port();
    drop(listener);
    port
}

pub fn tcp_addr(port: u16) -> String {
    format!("127.0.0.1:{port}")
}

fn wait_for_info_with_timeout(addr: &str, timeout: Duration) {
    let deadline = Instant::now() + timeout;
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

pub fn wait_for_info(addr: &str) {
    wait_for_info_with_timeout(addr, Duration::from_secs(15));
}

pub fn wait_for_info_quick(addr: &str) {
    wait_for_info_with_timeout(addr, Duration::from_secs(5));
}

fn wait_for_published_doc_count_with_timeout(
    addr: &str,
    expected_docs: u64,
    min_publish_runs: u64,
    timeout: Duration,
) {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        let output = Command::new(bin_path())
            .args(["info", "--addr", addr])
            .output()
            .expect("run info");
        if output.status.success() {
            let parsed: Value =
                serde_json::from_slice(&output.stdout).expect("stats json from info");
            let publish_runs_total = parsed
                .get("publish")
                .and_then(|value| value.get("publish_runs_total"))
                .and_then(Value::as_u64)
                .unwrap_or(0);
            let doc_count = parsed.get("doc_count").and_then(Value::as_u64).unwrap_or(0);
            let work_dirty = parsed
                .get("work_dirty")
                .and_then(Value::as_bool)
                .unwrap_or(true);
            if publish_runs_total >= min_publish_runs && doc_count == expected_docs && !work_dirty {
                return;
            }
        }
        thread::sleep(Duration::from_millis(50));
    }
    panic!(
        "server did not publish {expected_docs} docs with at least {min_publish_runs} publish runs on {addr}"
    );
}

pub fn wait_for_published_doc_count(addr: &str, expected_docs: u64, min_publish_runs: u64) {
    wait_for_published_doc_count_with_timeout(
        addr,
        expected_docs,
        min_publish_runs,
        Duration::from_secs(30),
    );
}

pub fn wait_for_published_doc_count_quick(addr: &str, expected_docs: u64, min_publish_runs: u64) {
    wait_for_published_doc_count_with_timeout(
        addr,
        expected_docs,
        min_publish_runs,
        Duration::from_secs(10),
    );
}

pub fn wait_for_search_candidates(addr: &str, rule: &Path, expected: usize) {
    let deadline = Instant::now() + Duration::from_secs(20);
    let mut last_output = String::new();
    while Instant::now() < deadline {
        let output = Command::new(bin_path())
            .args([
                "search",
                "--addr",
                addr,
                "--rule",
                rule.to_str().expect("rule path"),
                "--max-candidates",
                "100",
            ])
            .output()
            .expect("run search");
        last_output = format!(
            "stdout={}\nstderr={}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        if output.status.success()
            && String::from_utf8_lossy(&output.stdout).contains(&format!("candidates: {expected}"))
        {
            return;
        }
        thread::sleep(Duration::from_millis(100));
    }
    panic!("search did not reach {expected} candidates on {addr}; last_output={last_output}");
}

pub fn spawn_serve_tcp(port: u16, candidate_root: &Path, extra_args: &[&str]) -> Child {
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

pub fn spawn_serve_tcp_capture_stderr(
    port: u16,
    candidate_root: &Path,
    extra_args: &[&str],
) -> Child {
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
        .stderr(Stdio::piped());
    command.spawn().expect("spawn serve")
}

pub fn init_root(root: &Path, mode: &str, extra_args: &[&str]) -> String {
    let mut args = vec![
        "init".to_owned(),
        "--root".to_owned(),
        root.to_string_lossy().into_owned(),
        "--mode".to_owned(),
        mode.to_owned(),
    ];
    args.extend(extra_args.iter().map(|value| (*value).to_owned()));
    run_ok_owned(&args)
}
