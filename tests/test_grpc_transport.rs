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
    let addr = format!("127.0.0.1:{port}");
    let child = Command::new(bin_path())
        .arg("grpc-serve")
        .arg("--addr")
        .arg(&addr)
        .arg("--root")
        .arg(candidate_root)
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn grpc serve");
    ChildGuard { child }
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
        assert!(status.into_inner().json.contains("draining"));

        let stats = client.stats(StatsRequest {}).await.expect("stats");
        let stats_json = stats.into_inner().json;
        assert!(stats_json.contains("active_doc_count"));
        assert!(stats_json.contains("candidate_shards"));

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
