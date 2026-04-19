use std::fs;
use std::fs::File;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use tempfile::tempdir;
use tokio::runtime::Builder as TokioRuntimeBuilder;

use sspry::grpc::v1::{
    PingRequest, ShutdownRequest, StatsRequest, StatusRequest, sspry_client::SspryClient,
};

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

fn spawn_grpc_serve(port: u16, candidate_root: &Path) -> ChildGuard {
    spawn_grpc_serve_with_stderr(port, candidate_root, Stdio::null(), &[])
}

fn spawn_grpc_serve_with_stderr(
    port: u16,
    candidate_root: &Path,
    stderr: Stdio,
    envs: &[(&str, &str)],
) -> ChildGuard {
    let addr = format!("127.0.0.1:{port}");
    let mut command = Command::new(bin_path());
    command
        .arg("serve")
        .arg("--addr")
        .arg(&addr)
        .arg("--root")
        .arg(candidate_root)
        .stdout(Stdio::null())
        .stderr(stderr);
    for (key, value) in envs {
        command.env(key, value);
    }
    let child = command.spawn().expect("spawn grpc serve");
    ChildGuard { child }
}

fn run_ok(args: &[&str]) -> String {
    let output = Command::new(bin_path())
        .args(args)
        .output()
        .expect("run sspry");
    assert!(
        output.status.success(),
        "command failed: {:?}\nstdout:\n{}\nstderr:\n{}",
        args,
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn grpc_transport_covers_ping_stats_status_and_shutdown() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("grpc_candidate_db");
    let port = reserve_port();
    let mut server = spawn_grpc_serve(port, &candidate_root);
    let endpoint = format!("http://127.0.0.1:{port}");

    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(10);
        let mut client = loop {
            match SspryClient::connect(endpoint.clone()).await {
                Ok(mut client) => {
                    if client.ping(PingRequest {}).await.is_ok() {
                        break client;
                    }
                }
                Err(_) => {}
            }
            assert!(
                Instant::now() < deadline,
                "gRPC server did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        };

        let ping = client.ping(PingRequest {}).await.expect("ping");
        assert_eq!(ping.into_inner().message, "pong");

        let status = client.status(StatusRequest {}).await.expect("status");
        let status = status.into_inner();
        assert!(!status.draining);
        assert!(status.adaptive_publish.is_some());

        let stats = client.stats(StatsRequest {}).await.expect("stats");
        let stats = stats.into_inner();
        let store = stats.stats.expect("store summary");
        assert_eq!(store.active_doc_count, 0);
        assert!(store.candidate_shards >= 1);
        assert_eq!(store.compaction_idle_cooldown_s, 5.0);
        assert_eq!(store.compaction_cooldown_remaining_s, 0.0);
        assert!(!store.compaction_waiting_for_cooldown);

        let shutdown = client.shutdown(ShutdownRequest {}).await.expect("shutdown");
        assert_eq!(shutdown.into_inner().message, "shutdown requested");
    });

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_status)) = server.child.try_wait() {
            break;
        }
        assert!(Instant::now() < deadline, "gRPC server did not exit");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn grpc_cli_covers_index_search_info_and_shutdown() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("grpc_candidate_db");
    let sample_dir = tmp.path().join("samples");
    fs::create_dir_all(&sample_dir).expect("create samples");
    let sample_a = sample_dir.join("alpha.bin");
    let sample_b = sample_dir.join("beta.bin");
    fs::write(&sample_a, b"alpha hello over grpc\n").expect("write sample a");
    fs::write(&sample_b, b"beta hello over grpc\n").expect("write sample b");
    let rule = tmp.path().join("hello.yar");
    fs::write(
        &rule,
        "rule hello_over_grpc {\n  strings:\n    $a = \"hello over grpc\"\n  condition:\n    $a\n}\n",
    )
    .expect("write rule");

    let port = reserve_port();
    let addr = format!("127.0.0.1:{port}");
    let mut server = spawn_grpc_serve(port, &candidate_root);
    let endpoint = format!("http://{addr}");

    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match SspryClient::connect(endpoint.clone()).await {
                Ok(mut client) => {
                    if client.ping(PingRequest {}).await.is_ok() {
                        break;
                    }
                }
                Err(_) => {}
            }
            assert!(
                Instant::now() < deadline,
                "gRPC server did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-bytes",
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
        "--max-candidates",
        "100",
    ]);
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
    assert!(info.contains("\"doc_count\": 2"));
    assert!(info.contains("\"active_doc_count\": 1"));
    assert!(info.contains("\"deleted_doc_count\": 1"));

    let shutdown = run_ok(&["shutdown", "--addr", &addr]);
    assert!(shutdown.contains("shutdown requested"));

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_status)) = server.child.try_wait() {
            break;
        }
        assert!(Instant::now() < deadline, "gRPC server did not exit");
        thread::sleep(Duration::from_millis(50));
    }
}

#[test]
fn grpc_cli_bundle_search_uses_one_rpc_request_for_multiple_rules() {
    let tmp = tempdir().expect("tmp");
    let candidate_root = tmp.path().join("grpc_candidate_db");
    let sample_dir = tmp.path().join("samples");
    fs::create_dir_all(&sample_dir).expect("create samples");
    let sample_a = sample_dir.join("alpha.bin");
    let sample_b = sample_dir.join("beta.bin");
    fs::write(&sample_a, b"alpha hello over grpc\n").expect("write sample a");
    fs::write(&sample_b, b"beta hello over grpc\n").expect("write sample b");

    let rule_a = tmp.path().join("rule_a.yar");
    let rule_b = tmp.path().join("rule_b.yar");
    let bundle = tmp.path().join("bundle.yar");
    fs::write(
        &rule_a,
        "rule hello_one {\n  strings:\n    $a = \"hello over grpc\"\n  condition:\n    $a\n}\n",
    )
    .expect("write rule a");
    fs::write(
        &rule_b,
        "rule hello_two {\n  strings:\n    $a = \"hello over grpc\"\n  condition:\n    $a\n}\n",
    )
    .expect("write rule b");
    fs::write(&bundle, "include \"rule_a.yar\"\ninclude \"rule_b.yar\"\n").expect("write bundle");

    let stderr_log = tmp.path().join("server.stderr.log");
    let port = reserve_port();
    let addr = format!("127.0.0.1:{port}");
    let mut server = spawn_grpc_serve_with_stderr(
        port,
        &candidate_root,
        Stdio::from(File::create(&stderr_log).expect("create stderr log")),
        &[("SSPRY_TRACE_SEARCH_STREAM", "1")],
    );
    let endpoint = format!("http://{addr}");

    let runtime = TokioRuntimeBuilder::new_multi_thread()
        .enable_all()
        .build()
        .expect("tokio runtime");
    runtime.block_on(async {
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            match SspryClient::connect(endpoint.clone()).await {
                Ok(mut client) => {
                    if client.ping(PingRequest {}).await.is_ok() {
                        break;
                    }
                }
                Err(_) => {}
            }
            assert!(
                Instant::now() < deadline,
                "gRPC server did not become ready"
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    let ingest = run_ok(&[
        "index",
        "--addr",
        &addr,
        sample_dir.to_str().expect("sample dir"),
        "--batch-bytes",
        "1",
    ]);
    assert!(ingest.contains("processed_documents: 2"));

    let search = run_ok(&[
        "search",
        "--addr",
        &addr,
        "--rule",
        bundle.to_str().expect("bundle"),
        "--max-candidates",
        "100",
    ]);
    assert!(search.contains("rule: hello_one"));
    assert!(search.contains("rule: hello_two"));
    assert_eq!(search.matches("candidates: 2").count(), 2);

    let shutdown = run_ok(&["shutdown", "--addr", &addr]);
    assert!(shutdown.contains("shutdown requested"));

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Ok(Some(_status)) = server.child.try_wait() {
            break;
        }
        assert!(Instant::now() < deadline, "gRPC server did not exit");
        thread::sleep(Duration::from_millis(50));
    }

    let stderr = fs::read_to_string(&stderr_log).expect("read stderr log");
    assert_eq!(stderr.matches("trace.search_stream grpc.start").count(), 1);
    assert!(stderr.contains("trace.search_stream grpc.bundle plan_count=2"));
}
