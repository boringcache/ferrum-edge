//! Live RFC 9298 CONNECT-UDP over HTTP/3 against a real `ferrum-edge` binary.
//!
//! Covers the datapath, not construction:
//!
//! - a real UDP echo target reached through a real QUIC/H3 Extended CONNECT
//!   tunnel, with payloads framed as RFC 9297 DATAGRAM capsules
//! - `Capsule-Protocol: ?1` on the 200
//! - unregistered Context IDs and unknown capsule types dropped, not proxied
//! - a spoofed destination that the matched proxy is not configured to reach
//! - a mixed upstream where the client-requested member requires HBONE while a
//!   sibling is directly dialable: the requested member is still refused
//! - an open backend circuit breaker not governing a tunnel that dials no
//!   HTTP backend
//! - malformed URI-template expansions
//! - a registered-but-unimplemented `:protocol` (`webtransport`)
//! - the profile disabled by default
//! - an oversized capsule RESETTING the tunnel (never a clean FIN), and a
//!   client FIN in the middle of a capsule doing the same
//! - the RFC 9298 §3 pseudo-header shape (a non-HTTPS `:scheme` never tunnels)
//! - the RFC 9297 §3.2 forbidden fields refused on the request and absent from
//!   the successful response
//! - the concurrent-session limit
//! - a live tunnel torn down by a SIGHUP reload that withdraws the destination
//!
//! The client-side capsule codec in `tests/scaffolding/clients/http3.rs` is
//! written independently of the gateway's, so these assert wire
//! interoperability rather than agreement between two copies of one encoder.

use std::time::Duration;

use tokio::net::{TcpListener, UdpSocket};

use crate::common::TestGateway;
use crate::scaffolding::clients::{Http3Client, Http3ConnectUdp};

const MASQUE_PREFIX: &str = "/.well-known/masque";

/// UDP echo target: reflects every datagram back to its sender.
struct UdpEcho {
    port: u16,
    task: tokio::task::JoinHandle<()>,
}

impl UdpEcho {
    async fn spawn() -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.expect("bind udp echo");
        let port = socket.local_addr().expect("udp echo addr").port();
        let task = tokio::spawn(async move {
            let mut buf = vec![0u8; 70_000];
            loop {
                match socket.recv_from(&mut buf).await {
                    Ok((len, peer)) => {
                        let _ = socket.send_to(&buf[..len], peer).await;
                    }
                    Err(_) => return,
                }
            }
        });
        Self { port, task }
    }
}

impl Drop for UdpEcho {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn masque_config(target_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "masque"
    listen_path: "{MASQUE_PREFIX}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {target_port}
    strip_listen_path: false
consumers: []
plugin_configs: []
"#
    )
}

/// The MASQUE route with a hair-trigger circuit breaker on its HTTP backend.
///
/// The backend address is a UDP socket, so any ordinary HTTP request to this
/// route is a connection failure and opens the breaker immediately.
fn masque_config_with_circuit_breaker(target_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "masque"
    listen_path: "{MASQUE_PREFIX}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {target_port}
    strip_listen_path: false
    circuit_breaker:
      failure_threshold: 1
      timeout_seconds: 300
      trip_on_connection_errors: true
consumers: []
plugin_configs: []
"#
    )
}

/// The same MASQUE route, but its destinations come from a MIXED upstream: one
/// ordinary direct target and one that is tagged as requiring HBONE dispatch.
///
/// `backend_host`/`backend_port` are deliberately a third address that the
/// upstream does not contain, so nothing here can be admitted by the route
/// backend rule.
fn masque_mixed_upstream_config(direct_port: u16, hbone_port: u16, unused_port: u16) -> String {
    format!(
        r#"version: "1"
upstreams:
  - id: "masque-pool"
    targets:
      - host: "127.0.0.1"
        port: {direct_port}
      - host: "127.0.0.1"
        port: {hbone_port}
        tags:
          mesh.hbone: "true"
proxies:
  - id: "masque"
    listen_path: "{MASQUE_PREFIX}"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {unused_port}
    upstream_id: "masque-pool"
    strip_listen_path: false
consumers: []
plugin_configs: []
"#
    )
}

async fn start_masque_gateway(config: String, extra_env: &[(&str, &str)]) -> (TestGateway, u16) {
    // Own the retry loop here: the HTTPS/QUIC port is chosen outside the
    // harness's own port retry, so every attempt needs a fresh one.
    let mut last_error = None;
    for attempt in 1..=3 {
        let reservation = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve port");
        let https_port = reservation.local_addr().expect("reserved addr").port();
        drop(reservation);

        let mut builder = TestGateway::builder()
            .mode_file(config.clone())
            .log_level("warn")
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            // The backend is a UDP socket, so an HTTP warmup probe against it
            // would never answer.
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
            .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key");
        for (key, value) in extra_env {
            builder = builder.env(*key, *value);
        }
        match builder.spawn().await {
            Ok(gateway) => return (gateway, https_port),
            Err(error) => {
                eprintln!("CONNECT-UDP gateway attempt {attempt}/3 failed: {error}");
                last_error = Some(error.to_string());
            }
        }
    }
    panic!(
        "failed to start CONNECT-UDP gateway after 3 attempts: {}",
        last_error.unwrap_or_else(|| "no error recorded".to_string())
    );
}

fn tunnel_url(https_port: u16, target_host: &str, target_port: u16) -> String {
    format!("https://localhost:{https_port}{MASQUE_PREFIX}/udp/{target_host}/{target_port}/")
}

/// Open a tunnel, tolerating the QUIC listener not being up yet.
async fn open_tunnel(client: &Http3Client, url: &str) -> Http3ConnectUdp {
    let mut last_error = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    loop {
        match client.connect_udp(url).await {
            Ok(tunnel) => return tunnel,
            Err(error) if std::time::Instant::now() < deadline => {
                last_error = Some(error.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!(
                "CONNECT-UDP request never completed; last startup error={last_error:?}; final error={error}"
            ),
        }
    }
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_relays_datagrams_end_to_end() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;

    assert_eq!(tunnel.status.as_u16(), 200, "RFC 9298 tunnel must be 200");
    assert_eq!(
        tunnel
            .headers
            .get("capsule-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("?1"),
        "RFC 9297 §3.4 requires Capsule-Protocol on the successful response"
    );

    for probe in ["first", "second", "third"] {
        tunnel
            .send_datagram(probe.as_bytes())
            .await
            .expect("send datagram");
        let echoed = tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive echoed datagram");
        assert_eq!(echoed, probe.as_bytes(), "UDP payload must round-trip");
    }

    // A datagram naming an unregistered context and an unknown capsule type
    // must both be dropped, and must not desynchronize the capsule stream.
    tunnel
        .send_datagram_with_context(2, b"must-not-be-proxied")
        .await
        .expect("send unregistered-context datagram");
    tunnel
        .send_capsule(0x17, b"unknown-capsule-value")
        .await
        .expect("send unknown capsule");
    tunnel
        .send_datagram(b"after-drops")
        .await
        .expect("send datagram");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(
        echoed, b"after-drops",
        "only the Context ID 0 payload may reach the target"
    );

    tunnel.close().await;
    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_an_unconfigured_target() {
    let echo = UdpEcho::spawn().await;
    // A second live UDP socket the route was never configured to reach.
    let spoof = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", spoof.port);
    let mut tunnel = open_tunnel(&client, &url).await;

    assert_eq!(
        tunnel.status.as_u16(),
        403,
        "a destination the proxy is not configured to reach must be refused"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain refusal body");
    assert!(
        body.contains("not an allowed destination"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains(&echo.port.to_string()),
        "the refusal must not disclose the configured destination: {body}"
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_is_not_governed_by_backend_circuit_breaker_state() {
    // A CONNECT-UDP tunnel dials no HTTP backend, so an HTTP backend's failure
    // history must not decide it. Ordinary requests to the same route open the
    // breaker (the "backend" is a UDP socket, so every HTTP dial is refused);
    // the tunnel to the destination the client named and the route admits must
    // still be established and relay.
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config_with_circuit_breaker(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let probe_url = format!("https://localhost:{https_port}{MASQUE_PREFIX}/health-probe");

    // Drive the breaker open, and prove it with the gateway's own 503 rather
    // than assuming the threshold was reached.
    let mut breaker_open = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    while std::time::Instant::now() < deadline {
        match client.get(&probe_url).await {
            Ok(response) if response.status.as_u16() == 503 => {
                breaker_open = true;
                break;
            }
            Ok(_) | Err(_) => tokio::time::sleep(Duration::from_millis(100)).await,
        }
    }
    assert!(
        breaker_open,
        "the route's circuit breaker never reported open; the exemption below would be vacuous"
    );

    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", echo.port)).await;
    assert_eq!(
        tunnel.status.as_u16(),
        200,
        "an open backend circuit breaker must not refuse a CONNECT-UDP tunnel"
    );
    tunnel
        .send_datagram(b"breaker-open")
        .await
        .expect("send datagram");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(echoed, b"breaker-open");
    tunnel.close().await;

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_a_transport_constrained_target_in_a_mixed_upstream() {
    // Both members of one upstream are live UDP echo sockets, so the only thing
    // separating them is the transport the operator configured. The direct
    // member proves the route works end to end; the HBONE-tagged member must
    // still be refused, because a direct UDP dial would bypass exactly the
    // transport its tag requires. Whichever member load balancing would have
    // selected is irrelevant — no member is selected for a CONNECT-UDP request.
    let direct = UdpEcho::spawn().await;
    let hbone = UdpEcho::spawn().await;
    let unused = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_mixed_upstream_config(direct.port, hbone.port, unused.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");

    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", direct.port)).await;
    assert_eq!(
        tunnel.status.as_u16(),
        200,
        "the directly dialable member of the upstream must tunnel"
    );
    tunnel
        .send_datagram(b"direct-member")
        .await
        .expect("send datagram");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(echoed, b"direct-member");
    tunnel.close().await;

    let mut refused = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", hbone.port)).await;
    assert_eq!(
        refused.status.as_u16(),
        403,
        "a target requiring HBONE dispatch must never be tunnelled over a direct UDP socket"
    );
    let body = refused
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain refusal body");
    assert!(
        body.contains("not an allowed destination"),
        "unexpected refusal body: {body}"
    );
    assert!(
        !body.contains(&direct.port.to_string()),
        "the refusal must not disclose the directly dialable member: {body}"
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_malformed_template_expansions() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");

    // Malformed target_host.
    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "under_score", 53)).await;
    assert_eq!(tunnel.status.as_u16(), 400);
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("target_host"), "unexpected body: {body}");

    // Out-of-range target_port.
    let mut tunnel = open_tunnel(&client, &tunnel_url(https_port, "127.0.0.1", 0)).await;
    assert_eq!(tunnel.status.as_u16(), 400);
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("target_port"), "unexpected body: {body}");

    // A path that is not a template expansion at all.
    let no_anchor = format!("https://localhost:{https_port}{MASQUE_PREFIX}/tcp/127.0.0.1/53/");
    let mut tunnel = open_tunnel(&client, &no_anchor).await;
    assert_eq!(tunnel.status.as_u16(), 400);
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("URI template"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_is_disabled_by_default() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(masque_config(echo.port), &[]).await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;

    assert_eq!(
        tunnel.status.as_u16(),
        501,
        "the CONNECT-UDP profile must be off unless the operator enables it"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("disabled"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_an_unimplemented_extended_connect_protocol() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);

    let mut last_error = None;
    let deadline = std::time::Instant::now() + Duration::from_secs(40);
    let mut tunnel = loop {
        match client
            .connect_udp_with_protocol(&url, h3::ext::Protocol::WEB_TRANSPORT)
            .await
        {
            Ok(tunnel) => break tunnel,
            Err(error) if std::time::Instant::now() < deadline => {
                last_error = Some(error.to_string());
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("request never completed; last={last_error:?}; final={error}"),
        }
    };

    assert_eq!(
        tunnel.status.as_u16(),
        405,
        "webtransport must not open a tunnel"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("CONNECT"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_terminates_on_an_oversized_capsule() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[
            ("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true"),
            ("FERRUM_HTTP3_CONNECT_UDP_MAX_DATAGRAM_BYTES", "64"),
        ],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);

    // Inside the ceiling: still relayed.
    tunnel.send_datagram(b"small").await.expect("send small");
    let echoed = tunnel
        .recv_datagram(Duration::from_secs(10))
        .await
        .expect("receive echoed datagram");
    assert_eq!(echoed, b"small");

    // Above the ceiling: the capsule stream is unrecoverable, so the tunnel
    // must fail closed rather than truncate or resynchronize.
    let mut value = vec![0u8];
    value.extend_from_slice(&vec![0x41u8; 4096]);
    tunnel
        .send_capsule(0x00, &value)
        .await
        .expect("send oversized capsule");
    // RFC 9297 §3.5 / RFC 9114 §4.1.2: a capsule over the ceiling is a
    // MALFORMED message. A clean FIN here would be indistinguishable from a
    // successful end of response, so the assertion is a reset specifically —
    // never "either is fine".
    tunnel
        .expect_stream_reset(Duration::from_secs(10))
        .await
        .expect("an oversized capsule must RESET the tunnel, not FIN it");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_enforces_the_session_limit() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[
            ("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true"),
            ("FERRUM_HTTP3_CONNECT_UDP_MAX_SESSIONS", "1"),
        ],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);

    let mut first = open_tunnel(&client, &url).await;
    assert_eq!(first.status.as_u16(), 200);
    // Prove the first tunnel is live and therefore holding the only permit.
    first.send_datagram(b"hold").await.expect("send");
    assert_eq!(
        first
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"hold"
    );

    let mut second = client.connect_udp(&url).await.expect("second request");
    assert_eq!(
        second.status.as_u16(),
        503,
        "the concurrent-session limit must refuse the second tunnel"
    );
    let body = second
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains("session limit"), "unexpected body: {body}");

    // Releasing the first permit must let a new tunnel in.
    first.close().await;
    let mut third = None;
    for _ in 0..40 {
        let candidate = client.connect_udp(&url).await.expect("third request");
        if candidate.status.as_u16() == 200 {
            third = Some(candidate);
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    let third = third.expect("the permit must be released when a tunnel closes");
    assert_eq!(third.status.as_u16(), 200);
    third.close().await;

    gateway.shutdown();
}

#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_closes_live_tunnels_on_route_withdrawal() {
    let echo = UdpEcho::spawn().await;
    let replacement = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);
    tunnel.send_datagram(b"live").await.expect("send");
    assert_eq!(
        tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"live"
    );

    // Reload with the destination withdrawn: the proxy still exists, but it is
    // no longer configured to reach the port this tunnel is relaying to.
    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");
    std::fs::write(config_path, masque_config(replacement.port)).expect("rewrite config");
    let pid = gateway.pid().expect("gateway still running");
    let _ = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .output();

    // Route withdrawal is an ordinary end of tunnel, not a protocol fault, so
    // the client must observe a clean FIN — the counterpart assertion to the
    // malformed-capsule reset above.
    tunnel
        .expect_clean_stream_end(Duration::from_secs(20))
        .await
        .expect("a withdrawn destination must tear the live tunnel down");

    // The replacement destination is now the admitted one.
    let new_url = tunnel_url(https_port, "127.0.0.1", replacement.port);
    let mut reopened = None;
    for _ in 0..40 {
        let candidate = client.connect_udp(&new_url).await.expect("reopen");
        if candidate.status.as_u16() == 200 {
            reopened = Some(candidate);
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    let mut reopened = reopened.expect("the reloaded destination must be reachable");
    reopened.send_datagram(b"reloaded").await.expect("send");
    assert_eq!(
        reopened
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"reloaded"
    );
    reopened.close().await;

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_resets_on_a_client_fin_inside_a_capsule() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);
    let mut tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);

    // Prove the tunnel is live first, so the reset below cannot be confused
    // with a failure to establish.
    tunnel.send_datagram(b"live").await.expect("send");
    assert_eq!(
        tunnel
            .recv_datagram(Duration::from_secs(10))
            .await
            .expect("receive"),
        b"live"
    );

    // A DATAGRAM capsule header declaring 32 bytes of value, followed by 4.
    // Then a clean FIN. RFC 9297 §3.3: "If the stream is closed in the middle
    // of a capsule, this MUST be treated as a malformed message." A tidy FIN
    // from the client does not make a truncated capsule stream an EOF.
    tunnel
        .send_raw(&[0x00, 0x20, 0x00, 0xde, 0xad, 0xbe])
        .await
        .expect("send a truncated capsule");
    tunnel.half_close().await.expect("client FIN");

    tunnel
        .expect_stream_reset(Duration::from_secs(15))
        .await
        .expect("a FIN in the middle of a capsule must RESET, never FIN cleanly");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_a_non_https_scheme() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    // Same QUIC listener, same expansion — only `:scheme` differs. RFC 9298 §3
    // bootstraps over HTTPS; the handler must not assume it.
    let http_scheme = format!(
        "http://localhost:{https_port}{MASQUE_PREFIX}/udp/127.0.0.1/{}/",
        echo.port
    );
    let mut tunnel = open_tunnel(&client, &http_scheme).await;

    assert_eq!(
        tunnel.status.as_u16(),
        400,
        "a connect-udp request whose :scheme is not https must never tunnel"
    );
    let body = tunnel
        .recv_body_text(Duration::from_secs(5))
        .await
        .expect("drain body");
    assert!(body.contains(":scheme"), "unexpected body: {body}");

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_h3_connect_udp_refuses_capsule_protocol_forbidden_fields() {
    let echo = UdpEcho::spawn().await;
    let (mut gateway, https_port) = start_masque_gateway(
        masque_config(echo.port),
        &[("FERRUM_HTTP3_CONNECT_UDP_ENABLED", "true")],
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = tunnel_url(https_port, "127.0.0.1", echo.port);

    // RFC 9297 §3.2: none of these may appear on a message that uses the
    // Capsule Protocol. Each must be refused before a UDP socket exists.
    for (name, value, marker) in [
        ("content-length", "0", "Content-Length"),
        ("content-type", "application/octet-stream", "Content-Type"),
    ] {
        let mut last_error = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(40);
        let mut tunnel = loop {
            match client
                .connect_udp_with_headers(&url, &[(name, value)])
                .await
            {
                Ok(tunnel) => break tunnel,
                Err(error) if std::time::Instant::now() < deadline => {
                    last_error = Some(error.to_string());
                    tokio::time::sleep(Duration::from_millis(100)).await;
                }
                Err(error) => panic!("request never completed; last={last_error:?}; final={error}"),
            }
        };
        assert_eq!(
            tunnel.status.as_u16(),
            400,
            "{name} must be refused on a Capsule Protocol message"
        );
        let body = tunnel
            .recv_body_text(Duration::from_secs(5))
            .await
            .expect("drain body");
        assert!(body.contains(marker), "unexpected body for {name}: {body}");
    }

    // And the successful response must not carry them either.
    let tunnel = open_tunnel(&client, &url).await;
    assert_eq!(tunnel.status.as_u16(), 200);
    for forbidden in ["content-length", "content-type", "transfer-encoding"] {
        assert!(
            tunnel.headers.get(forbidden).is_none(),
            "RFC 9297 §3.2 forbids {forbidden} on the CONNECT-UDP response"
        );
    }
    assert_eq!(
        tunnel
            .headers
            .get("capsule-protocol")
            .and_then(|v| v.to_str().ok()),
        Some("?1")
    );
    tunnel.close().await;

    gateway.shutdown();
}
