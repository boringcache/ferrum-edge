//! Live RFC 9298 CONNECT-UDP over HTTP/3 against a real `ferrum-edge` binary.
//!
//! Covers the datapath, not construction:
//!
//! - a real UDP echo target reached through a real QUIC/H3 Extended CONNECT
//!   tunnel, with payloads framed as RFC 9297 DATAGRAM capsules
//! - `Capsule-Protocol: ?1` on the 200
//! - unregistered Context IDs and unknown capsule types dropped, not proxied
//! - a spoofed destination that the matched proxy is not configured to reach
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
    let http_scheme =
        format!("http://localhost:{https_port}{MASQUE_PREFIX}/udp/127.0.0.1/{}/", echo.port);
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
            match client.connect_udp_with_headers(&url, &[(name, value)]).await {
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
    let mut tunnel = open_tunnel(&client, &url).await;
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
