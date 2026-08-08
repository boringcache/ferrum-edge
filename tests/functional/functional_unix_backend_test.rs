//! Live data-path coverage for Unix-domain-socket backends (issue #3261).
//!
//! An Istio `Sidecar` ingress `defaultEndpoint: unix:///path.sock` materializes
//! into a route whose upstream target carries the reserved `mesh.unix_socket`
//! tag; the HTTP dispatch path recognizes that tag and dials a
//! `tokio::net::UnixStream` instead of TCP. These tests drive the REAL gateway
//! binary over that path with real sockets on disk, so they fail if the
//! transport regresses to a TCP dial, if the fail-closed gate is dropped, or if
//! reload/update/delete stops re-materializing the backend.
//!
//! The tag is the entire transport gate (exactly like `mesh.hbone` /
//! `mesh.mtls`), so a plain file-mode config expresses the same runtime shape
//! the mesh materializer emits — without needing a full mesh control plane in a
//! functional test.
//!
//! Unix-only: there is no Unix-domain socket transport (nor file-mode SIGHUP
//! reload) on Windows.

use crate::common::TestGateway;

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UnixListener;
use tokio::time::{Instant, sleep};

/// A minimal HTTP/1.1 server on a Unix-domain stream socket. Answers every
/// request with `name` so a test can prove WHICH socket served it.
struct UnixBackend {
    path: PathBuf,
    hits: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl UnixBackend {
    async fn start(dir: &Path, file_name: &str, name: &'static str) -> Self {
        let path = dir.join(file_name);
        let listener = UnixListener::bind(&path).expect("bind unix backend socket");
        let hits = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(serve_unix_backend(listener, name, Arc::clone(&hits)));
        Self { path, hits, task }
    }

    fn hits(&self) -> usize {
        self.hits.load(Ordering::SeqCst)
    }
}

impl Drop for UnixBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn serve_unix_backend(listener: UnixListener, name: &'static str, hits: Arc<AtomicUsize>) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let hits = Arc::clone(&hits);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 8192];
            let n = match tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await
            {
                Ok(Ok(n)) if n > 0 => n,
                _ => return,
            };
            let request = String::from_utf8_lossy(&buf[..n]).into_owned();
            hits.fetch_add(1, Ordering::SeqCst);
            // Echo back the request line plus the Host the gateway forwarded, so
            // the test can assert the request target and header regeneration
            // survived the transport swap.
            let request_line = request.lines().next().unwrap_or("").to_string();
            let host = request
                .lines()
                .find(|line| line.to_ascii_lowercase().starts_with("host:"))
                .map(|line| line["host:".len()..].trim().to_string())
                .unwrap_or_default();
            let body = format!("{name}|{request_line}|{host}");
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\n\r\n{}",
                body.len(),
                body
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.flush().await;
        });
    }
}

/// File-mode config: one HTTP route per named upstream, each upstream's single
/// target carrying the `mesh.unix_socket` tag for `socket_path`.
///
/// `backend_host`/`backend_port` are the same never-dialed placeholder the mesh
/// materializer stamps: a bound-but-unused loopback port. If the Unix transport
/// gate ever regressed to a TCP fallback, the request would hit that port
/// instead — which is exactly why the tests below assert on the socket's own
/// response body rather than merely on a 200.
fn build_config(entries: &[(&str, &str, &str)], placeholder_port: u16) -> String {
    let mut proxies = String::new();
    let mut upstreams = String::new();
    for (id, listen_path, socket_path) in entries {
        proxies.push_str(&format!(
            r#"  - id: "{id}"
    listen_path: "{listen_path}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {placeholder_port}
    upstream_id: "{id}-upstream"
    strip_listen_path: false
    preserve_host_header: true
    pool_enable_http2: false
"#
        ));
        upstreams.push_str(&format!(
            r#"  - id: "{id}-upstream"
    name: "{id}-upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {placeholder_port}
        weight: 1
        tags:
          mesh.unix_socket: "{socket_path}"
"#
        ));
    }
    format!(
        r#"version: "1"
proxies:
{proxies}
upstreams:
{upstreams}
consumers: []
plugin_configs: []
"#
    )
}

/// Poll the live data path until `ready` accepts a response body, or fail with
/// the last observation. Waits on the behavior under test rather than guessing
/// how long a reload needs on a loaded runner.
async fn wait_for_body(
    client: &reqwest::Client,
    url: &str,
    context: &str,
    mut ready: impl FnMut(u16, &str) -> bool,
) -> String {
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut last = String::from("no request issued yet");
    loop {
        match client.get(url).send().await {
            Ok(response) => {
                let status = response.status().as_u16();
                let body = response.text().await.unwrap_or_default();
                if ready(status, &body) {
                    return body;
                }
                last = format!("status={status} body={body:?}");
            }
            Err(err) => last = format!("request error: {err}"),
        }
        if Instant::now() >= deadline {
            panic!("{context}: behavior did not appear; last observation: {last}");
        }
        sleep(Duration::from_millis(150)).await;
    }
}

/// A loopback TCP port that is bound for the lifetime of the test but never
/// served. Any request that reached it instead of the Unix socket would hang and
/// then fail, making a silent TCP fallback impossible to mistake for success.
async fn reserve_placeholder_port() -> (u16, tokio::net::TcpListener) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind placeholder port");
    let port = listener.local_addr().expect("placeholder addr").port();
    (port, listener)
}

#[tokio::test]
#[ignore]
async fn unix_socket_backend_serves_requests_over_a_real_socket() {
    let temp = TempDir::new().expect("temp dir");
    let backend = UnixBackend::start(temp.path(), "app.sock", "alpha").await;
    let (placeholder_port, _placeholder) = reserve_placeholder_port().await;

    let config = build_config(
        &[(
            "unix-route",
            "/unix",
            backend.path.to_str().expect("utf-8 socket path"),
        )],
        placeholder_port,
    );
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        // Keep startup deterministic: the placeholder loopback port is bound but
        // never served, so a warmup dial against it would only add noise.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");
    let body = wait_for_body(
        &client,
        &gateway.proxy_url("/unix?q=1"),
        "unix backend first response",
        |status, _| status == 200,
    )
    .await;

    let parts: Vec<&str> = body.split('|').collect();
    assert_eq!(parts[0], "alpha", "the unix socket served the request");
    assert_eq!(
        parts[1], "GET /unix?q=1 HTTP/1.1",
        "the request target (path + query) is preserved byte-for-byte over the unix transport"
    );
    assert!(
        !parts[2].is_empty(),
        "the gateway forwards a Host header to the unix backend, got {body:?}"
    );
    assert!(backend.hits() >= 1, "the unix socket observed the request");
}

#[tokio::test]
#[ignore]
async fn unix_socket_backend_fails_closed_when_the_socket_is_absent() {
    let temp = TempDir::new().expect("temp dir");
    // Deliberately never bound: `connect(2)` yields ENOENT, which must surface
    // as a pre-wire backend failure and NEVER as a fallback TCP dial to the
    // placeholder port.
    let missing = temp.path().join("absent.sock");
    let (placeholder_port, _placeholder) = reserve_placeholder_port().await;

    let config = build_config(
        &[(
            "unix-route",
            "/unix",
            missing.to_str().expect("utf-8 socket path"),
        )],
        placeholder_port,
    );
    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        // Keep startup deterministic: the placeholder loopback port is bound but
        // never served, so a warmup dial against it would only add noise.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");
    let response = client
        .get(gateway.proxy_url("/unix"))
        .send()
        .await
        .expect("gateway answers");
    assert_eq!(
        response.status().as_u16(),
        502,
        "a missing unix socket is a pre-wire backend failure, not a TCP fallback"
    );
}

/// Reload/update/delete, not just first-start construction: the same running
/// gateway must re-point a Unix backend at a different socket and then stop
/// routing it entirely, both driven from the live data path.
#[cfg(unix)]
#[tokio::test]
#[ignore]
async fn unix_socket_backend_survives_reload_update_and_delete() {
    let temp = TempDir::new().expect("temp dir");
    let alpha = UnixBackend::start(temp.path(), "alpha.sock", "alpha").await;
    let beta = UnixBackend::start(temp.path(), "beta.sock", "beta").await;
    let (placeholder_port, _placeholder) = reserve_placeholder_port().await;

    let alpha_path = alpha.path.to_str().expect("utf-8 socket path").to_string();
    let beta_path = beta.path.to_str().expect("utf-8 socket path").to_string();

    let gateway = TestGateway::builder()
        .mode_file(build_config(
            &[("unix-route", "/unix", &alpha_path)],
            placeholder_port,
        ))
        .log_level("warn")
        // Keep startup deterministic: the placeholder loopback port is bound but
        // never served, so a warmup dial against it would only add noise.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");

    let config_path = gateway
        .config_path
        .clone()
        .expect("file mode writes a config path");
    let pid = gateway.pid().expect("running gateway has a pid");
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("build client");

    wait_for_body(
        &client,
        &gateway.proxy_url("/unix"),
        "initial alpha socket",
        |status, body| status == 200 && body.starts_with("alpha|"),
    )
    .await;

    // UPDATE: re-point the same route at a different socket and SIGHUP.
    std::fs::write(
        &config_path,
        build_config(&[("unix-route", "/unix", &beta_path)], placeholder_port),
    )
    .expect("rewrite config");
    sighup(pid);
    wait_for_body(
        &client,
        &gateway.proxy_url("/unix"),
        "reloaded beta socket",
        |status, body| status == 200 && body.starts_with("beta|"),
    )
    .await;
    assert!(beta.hits() >= 1, "the re-pointed socket served traffic");

    // DELETE: remove the route entirely; the path must stop resolving rather
    // than keep dialing a stale socket.
    std::fs::write(
        &config_path,
        build_config(&[("other-route", "/other", &alpha_path)], placeholder_port),
    )
    .expect("rewrite config without the unix route");
    sighup(pid);
    wait_for_body(
        &client,
        &gateway.proxy_url("/unix"),
        "deleted unix route",
        |status, _| status == 404,
    )
    .await;

    // The surviving route still works, proving the delete was surgical.
    wait_for_body(
        &client,
        &gateway.proxy_url("/other"),
        "surviving unix route",
        |status, body| status == 200 && body.starts_with("alpha|"),
    )
    .await;
}

#[cfg(unix)]
fn sighup(pid: u32) {
    let output = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .output()
        .expect("send SIGHUP to gateway");
    assert!(
        output.status.success(),
        "sending SIGHUP to gateway failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
}
