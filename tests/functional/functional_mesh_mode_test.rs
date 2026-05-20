//! Functional runtime coverage for `FERRUM_MODE=mesh`.
//!
//! This test spawns the real `ferrum-edge` binary and a lightweight native
//! `MeshSubscribe` control-plane stub. It verifies the binary can authenticate
//! to a CP URL, consume an initial mesh slice, build the mesh runtime, and bind
//! its sidecar listeners. Unit/integration tests cover the detailed projection
//! and request-path behavior; this locks in the process-level startup contract.
//!
//! Run with:
//!   cargo test --test functional_tests functional_mesh_mode -- --ignored --nocapture

use std::path::PathBuf;
use std::pin::Pin;
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use chrono::Utc;
use futures_util::{Stream, StreamExt, stream};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{oneshot, watch};
use tokio_stream::wrappers::{IntervalStream, TcpListenerStream};
use tonic::transport::Server;
use tonic::{Request, Response, Status};

use ferrum_edge::grpc::proto::mesh_config_sync_server::{MeshConfigSync, MeshConfigSyncServer};
use ferrum_edge::grpc::proto::{MeshConfigUpdate, MeshSubscribeRequest};
use ferrum_edge::modes::mesh::slice::MeshSlice;

use crate::common::ensure_gateway_built;
use crate::scaffolding::ports::reserve_port;

const GRPC_SECRET: &str = "ferrum-edge-functional-mesh-grpc-secret00";
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);
const RETRY_ATTEMPTS: u32 = 3;

fn binary_path() -> PathBuf {
    let debug = PathBuf::from("./target/debug/ferrum-edge");
    if debug.exists() {
        return debug;
    }
    PathBuf::from("./target/release/ferrum-edge")
}

#[derive(Clone)]
struct StaticMeshControlPlane {
    slice: Arc<MeshSlice>,
    request_tx: watch::Sender<Option<MeshSubscribeRequest>>,
    subscribe_count: Arc<AtomicUsize>,
}

#[tonic::async_trait]
impl MeshConfigSync for StaticMeshControlPlane {
    type MeshSubscribeStream = Pin<Box<dyn Stream<Item = Result<MeshConfigUpdate, Status>> + Send>>;

    async fn mesh_subscribe(
        &self,
        request: Request<MeshSubscribeRequest>,
    ) -> Result<Response<Self::MeshSubscribeStream>, Status> {
        let request = request.into_inner();
        self.subscribe_count.fetch_add(1, Ordering::Relaxed);
        let _ = self.request_tx.send(Some(request));

        let update = MeshConfigUpdate {
            version: self.slice.version.clone(),
            timestamp: Utc::now().timestamp(),
            mesh_slice_json: serde_json::to_string(self.slice.as_ref())
                .map_err(|e| Status::internal(format!("serialize mesh slice: {e}")))?,
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            heartbeat: false,
        };
        let heartbeat = MeshConfigUpdate {
            version: self.slice.version.clone(),
            timestamp: Utc::now().timestamp(),
            mesh_slice_json: String::new(),
            ferrum_version: ferrum_edge::FERRUM_VERSION.to_string(),
            heartbeat: true,
        };
        let heartbeats = IntervalStream::new(tokio::time::interval(Duration::from_secs(60)))
            .map(move |_| Ok(heartbeat.clone()));
        let stream = stream::once(async move { Ok(update) }).chain(heartbeats);
        Ok(Response::new(Box::pin(stream)))
    }
}

struct MeshCpHandle {
    addr: std::net::SocketAddr,
    request_rx: watch::Receiver<Option<MeshSubscribeRequest>>,
    subscribe_count: Arc<AtomicUsize>,
    shutdown_tx: Option<oneshot::Sender<()>>,
    task: tokio::task::JoinHandle<Result<(), tonic::transport::Error>>,
}

impl MeshCpHandle {
    async fn shutdown(mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
        match tokio::time::timeout(Duration::from_secs(2), &mut self.task).await {
            Ok(_) => {}
            Err(_) => {
                self.task.abort();
                let _ = self.task.await;
            }
        }
    }
}

async fn start_static_mesh_cp(slice: MeshSlice) -> MeshCpHandle {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind mesh CP");
    let addr = listener.local_addr().expect("mesh CP local addr");
    let (request_tx, request_rx) = watch::channel(None);
    let subscribe_count = Arc::new(AtomicUsize::new(0));
    let cp = StaticMeshControlPlane {
        slice: Arc::new(slice),
        request_tx,
        subscribe_count: subscribe_count.clone(),
    };
    let (shutdown_tx, shutdown_rx) = oneshot::channel();
    let incoming = TcpListenerStream::new(listener);
    let task = tokio::spawn(async move {
        Server::builder()
            .add_service(MeshConfigSyncServer::new(cp))
            .serve_with_incoming_shutdown(incoming, async {
                let _ = shutdown_rx.await;
            })
            .await
    });
    MeshCpHandle {
        addr,
        request_rx,
        subscribe_count,
        shutdown_tx: Some(shutdown_tx),
        task,
    }
}

fn initial_mesh_slice(node_id: &str) -> MeshSlice {
    MeshSlice {
        node_id: node_id.to_string(),
        namespace: "ferrum".to_string(),
        version: Utc::now().to_rfc3339(),
        ..MeshSlice::default()
    }
}

fn scrub_ferrum_env(cmd: &mut Command) {
    for (key, _) in std::env::vars() {
        if key.starts_with("FERRUM_") {
            cmd.env_remove(key);
        }
    }
}

fn spawn_mesh_gateway(
    temp: &TempDir,
    cp_addr: std::net::SocketAddr,
    inbound_port: u16,
    outbound_port: u16,
    node_id: &str,
) -> Child {
    let stdout =
        std::fs::File::create(temp.path().join("mesh.stdout.log")).expect("create stdout capture");
    let stderr =
        std::fs::File::create(temp.path().join("mesh.stderr.log")).expect("create stderr capture");
    let mut cmd = Command::new(binary_path());
    scrub_ferrum_env(&mut cmd);
    cmd.args(["run"])
        .stdin(Stdio::null())
        .stdout(Stdio::from(stdout))
        .stderr(Stdio::from(stderr))
        .env("FERRUM_MODE", "mesh")
        .env("FERRUM_LOG_LEVEL", "info")
        .env("FERRUM_NAMESPACE", "ferrum")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_SHUTDOWN_DRAIN_SECONDS", "0")
        .env("FERRUM_PROXY_HTTP_PORT", "0")
        .env("FERRUM_ADMIN_HTTP_PORT", "0")
        .env("FERRUM_CP_DP_GRPC_JWT_SECRET", GRPC_SECRET)
        .env("FERRUM_DP_CP_GRPC_URLS", format!("http://{cp_addr}"))
        .env("FERRUM_MESH_CONFIG_PROTOCOL", "native")
        .env("FERRUM_MESH_TOPOLOGY", "sidecar")
        .env("FERRUM_MESH_NODE_ID", node_id)
        .env(
            "FERRUM_MESH_INBOUND_LISTEN_ADDR",
            format!("127.0.0.1:{inbound_port}"),
        )
        .env(
            "FERRUM_MESH_OUTBOUND_LISTEN_ADDR",
            format!("127.0.0.1:{outbound_port}"),
        )
        .env("FERRUM_MESH_HBONE_LISTEN_ADDR", "127.0.0.1:0")
        .env("FERRUM_MESH_DNS_PROXY_ENABLED", "false")
        .env("FERRUM_MESH_FEDERATION_POLL_INTERVAL_SECONDS", "0");
    cmd.spawn().expect("spawn mesh gateway")
}

fn kill_child(child: &mut Child) {
    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

fn captured_output(temp: &TempDir) -> String {
    let stderr = std::fs::read_to_string(temp.path().join("mesh.stderr.log")).unwrap_or_default();
    let stdout = std::fs::read_to_string(temp.path().join("mesh.stdout.log")).unwrap_or_default();
    format!("{stderr}\n{stdout}")
}

async fn wait_for_mesh_subscribe(
    request_rx: &mut watch::Receiver<Option<MeshSubscribeRequest>>,
    timeout: Duration,
) -> Option<MeshSubscribeRequest> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(request) = request_rx.borrow().clone() {
            return Some(request);
        }
        let now = Instant::now();
        if now >= deadline {
            return None;
        }
        let remaining = deadline.saturating_duration_since(now);
        if tokio::time::timeout(remaining, request_rx.changed())
            .await
            .is_err()
        {
            return None;
        }
    }
}

async fn wait_for_tcp_port(port: u16, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if TcpStream::connect(("127.0.0.1", port)).await.is_ok() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

#[ignore]
#[tokio::test]
async fn functional_mesh_mode_starts_after_native_mesh_subscribe() {
    ensure_gateway_built().expect("gateway binary built");

    let mut last_failure = String::new();
    for attempt in 1..=RETRY_ATTEMPTS {
        let node_id = format!("functional-mesh-node-{attempt}");
        let cp = start_static_mesh_cp(initial_mesh_slice(&node_id)).await;
        let mut request_rx = cp.request_rx.clone();
        let inbound_port = reserve_port()
            .await
            .expect("reserve mesh inbound port")
            .drop_and_take_port();
        let outbound_port = reserve_port()
            .await
            .expect("reserve mesh outbound port")
            .drop_and_take_port();
        let temp = TempDir::new().expect("temp dir");
        let mut child = spawn_mesh_gateway(&temp, cp.addr, inbound_port, outbound_port, &node_id);

        let subscribe = wait_for_mesh_subscribe(&mut request_rx, STARTUP_TIMEOUT).await;
        let inbound_listening = wait_for_tcp_port(inbound_port, STARTUP_TIMEOUT).await;
        let outbound_listening = wait_for_tcp_port(outbound_port, Duration::from_secs(5)).await;

        kill_child(&mut child);
        let subscribe_count = cp.subscribe_count.load(Ordering::Relaxed);
        cp.shutdown().await;

        match (subscribe, inbound_listening, outbound_listening) {
            (Some(request), true, true) => {
                assert_eq!(request.node_id, node_id);
                assert_eq!(request.namespace, "ferrum");
                assert!(
                    subscribe_count >= 1,
                    "expected at least one MeshSubscribe request"
                );
                return;
            }
            (subscribe, inbound_listening, outbound_listening) => {
                last_failure = format!(
                    "attempt {attempt}: subscribe={:?}, inbound_listening={inbound_listening}, \
                     outbound_listening={outbound_listening}\n{}",
                    subscribe.as_ref().map(|r| (&r.node_id, &r.namespace)),
                    captured_output(&temp)
                );
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        }
    }

    panic!("mesh mode did not start after {RETRY_ATTEMPTS} attempts\n{last_failure}");
}
