//! Unit tests for the WebSocket tunnel-mode disconnect-hook path.
//!
//! Codex P2: tunnel mode (enabled via `FERRUM_WEBSOCKET_TUNNEL_MODE=true` when
//! no frame-level plugins are configured) bypasses WebSocket frame parsing
//! and does raw `copy_bidirectional`. Before this fix, that path returned
//! immediately after the copy without firing `on_ws_disconnect` — any plugin
//! that opted into disconnect hooks would silently miss every tunnel-mode
//! session teardown, breaking the disconnect-observability contract used by
//! `ws_frame_logging` and `prometheus_metrics`.
//!
//! These tests exercise the helper the tunnel-mode path now calls:
//! `fire_ws_tunnel_disconnect_hooks`. They verify that:
//!
//! 1. The hook fires for every plugin in the slice.
//! 2. Frame counters are reported as 0 (tunnel mode doesn't parse frames).
//! 3. Failure info is preserved into `WsDisconnectContext.direction`,
//!    `.io_side`, and `.error_class`.
//! 4. Empty plugin slices skip the hook entirely (zero overhead when no
//!    plugin opts in).
//!
//! The final section (issue #1619) pins the decision behind the
//! `FERRUM_WEBSOCKET_TUNNEL_MODE` startup frame-loss-risk warning.

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;

use async_trait::async_trait;

use ferrum_edge::_test_support::{
    StreamIoSide, fire_ws_tunnel_disconnect_hooks, make_ws_session_meta,
    warn_if_websocket_tunnel_mode_frame_loss_risk_for_test,
};
use ferrum_edge::config::types::{BackendScheme, DispatchKind, GatewayConfig, PluginConfig, Proxy};
use ferrum_edge::plugins::{Direction, Plugin, WsDisconnectContext};
use ferrum_edge::retry::ErrorClass;

/// Plugin that captures every `on_ws_disconnect` invocation.
struct CapturingDisconnectPlugin {
    captured: Arc<Mutex<Vec<CapturedDisconnect>>>,
}

#[derive(Clone)]
struct CapturedDisconnect {
    proxy_id: String,
    client_ip: String,
    frames_c2b: u64,
    frames_b2c: u64,
    direction: Option<Direction>,
    io_side: Option<StreamIoSide>,
    error_class: Option<ErrorClass>,
}

impl CapturingDisconnectPlugin {
    fn new() -> (Self, Arc<Mutex<Vec<CapturedDisconnect>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                captured: Arc::clone(&captured),
            },
            captured,
        )
    }
}

#[async_trait]
impl Plugin for CapturingDisconnectPlugin {
    fn name(&self) -> &str {
        "capturing_ws_disconnect"
    }

    fn priority(&self) -> u16 {
        9175
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, ctx: &WsDisconnectContext) {
        self.captured.lock().unwrap().push(CapturedDisconnect {
            proxy_id: ctx.proxy_id.clone(),
            client_ip: ctx.client_ip.clone(),
            frames_c2b: ctx.frames_client_to_backend,
            frames_b2c: ctx.frames_backend_to_client,
            direction: ctx.direction,
            io_side: ctx.io_side,
            error_class: ctx.error_class,
        });
    }
}

fn session_meta() -> ferrum_edge::proxy::WsSessionMeta {
    make_ws_session_meta(
        "ferrum".to_string(),
        Some("ws-echo".to_string()),
        "10.0.0.7".to_string(),
        "backend:9000".to_string(),
        8000,
        Some("user-42".to_string()),
        HashMap::new(),
        chrono::Utc::now() - chrono::Duration::milliseconds(250),
    )
}

#[tokio::test]
async fn test_tunnel_disconnect_fires_for_every_plugin() {
    let (plugin_a, captured_a) = CapturingDisconnectPlugin::new();
    let (plugin_b, captured_b) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin_a), Arc::new(plugin_b)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, None).await;

    let a = captured_a.lock().unwrap();
    let b = captured_b.lock().unwrap();
    assert_eq!(a.len(), 1, "plugin A must receive exactly one disconnect");
    assert_eq!(b.len(), 1, "plugin B must receive exactly one disconnect");
    assert_eq!(a[0].proxy_id, "proxy-abc");
    assert_eq!(a[0].client_ip, "10.0.0.7");
}

#[tokio::test]
async fn test_tunnel_disconnect_reports_zero_frame_counts() {
    // Tunnel mode does raw TCP bidirectional copy — it never parses WebSocket
    // frames, so c2b / b2c frame counters are always 0. Operators who need
    // frame-level accounting must disable tunnel mode.
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, None).await;

    let captured = captured.lock().unwrap();
    assert_eq!(captured.len(), 1);
    assert_eq!(captured[0].frames_c2b, 0);
    assert_eq!(captured[0].frames_b2c, 0);
}

#[tokio::test]
async fn test_tunnel_disconnect_graceful_close_has_no_failure() {
    // When the raw copy finishes cleanly (both halves EOF), the helper is
    // called with `failure: None`. The disconnect context surfaces both
    // direction and error_class as None — dashboards read that as "graceful".
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(&plugins, "proxy-abc", &meta, None).await;

    let captured = captured.lock().unwrap();
    assert!(captured[0].direction.is_none());
    assert!(captured[0].error_class.is_none());
}

#[tokio::test]
async fn test_tunnel_disconnect_propagates_direction_and_error_class() {
    // The drain-phase write-failure path attributes to `BackendToClient`
    // (client socket errored while we were pushing a buffered frame). The
    // copy_bidirectional error path attributes to `Direction::Unknown`
    // because the std::io::copy_bidirectional API doesn't report side.
    let (plugin, captured) = CapturingDisconnectPlugin::new();
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(plugin)];
    let meta = session_meta();

    fire_ws_tunnel_disconnect_hooks(
        &plugins,
        "proxy-abc",
        &meta,
        Some((
            Direction::BackendToClient,
            ErrorClass::ConnectionReset,
            Some(StreamIoSide::Write),
        )),
    )
    .await;

    let captured = captured.lock().unwrap();
    assert_eq!(captured[0].direction, Some(Direction::BackendToClient));
    assert_eq!(captured[0].io_side, Some(StreamIoSide::Write));
    assert_eq!(captured[0].error_class, Some(ErrorClass::ConnectionReset),);
}

#[tokio::test]
async fn test_tunnel_disconnect_skips_when_no_plugins_opted_in() {
    // Empty slice → zero overhead: no allocation, no await, no hook fired.
    // This test mostly documents the contract — if it regresses to
    // `for plugin in &[] { plugin.on_ws_disconnect(...).await }` that's
    // semantically fine, but the branch must still be reached.
    let plugins: Vec<Arc<dyn Plugin>> = Vec::new();
    let meta = session_meta();

    // Should complete without panicking or awaiting on anything meaningful.
    fire_ws_tunnel_disconnect_hooks(
        &plugins,
        "proxy-abc",
        &meta,
        Some((Direction::Unknown, ErrorClass::RequestError, None)),
    )
    .await;
}

// ── Startup frame-loss-risk warning decision (issue #1619) ───────────────────
//
// `FERRUM_WEBSOCKET_TUNNEL_MODE` cannot recover backend WebSocket frame bytes
// that tokio-tungstenite buffered while parsing the backend 101 response
// (`into_inner()` discards the codec's read buffer and the dependency exposes
// no accessor for it), so the first backend push frame can be dropped. The
// gateway surfaces that caveat as a one-time startup `warn!`. These tests pin
// the decision behind that warning: it fires only when tunnel mode is enabled
// AND at least one HTTP-family proxy (the only kind that can carry a WebSocket
// upgrade) is configured. The helper returns the count of affected proxies so
// the decision is assertable without capturing logs.

/// Build a minimal `Proxy` with the requested dispatch kind. `dispatch_kind`
/// is `#[serde(skip)]` (resolved post-deserialize), so it is set explicitly
/// here rather than via JSON.
fn proxy_with_dispatch_kind(id: &str, scheme: BackendScheme, kind: DispatchKind) -> Proxy {
    let json = format!(
        r#"{{
            "id": "{id}",
            "backend_scheme": "{}",
            "backend_host": "backend.example.com",
            "backend_port": 9000
        }}"#,
        match scheme {
            BackendScheme::Http => "http",
            BackendScheme::Https => "https",
            BackendScheme::Tcp => "tcp",
            BackendScheme::Tcps => "tcps",
            BackendScheme::Udp => "udp",
            BackendScheme::Dtls => "dtls",
        }
    );
    let mut proxy: Proxy = serde_json::from_str(&json).expect("proxy json deserializes");
    proxy.dispatch_kind = kind;
    proxy
}

/// Build a proxy-scoped `ws_frame_logging` plugin config bound to `proxy_id`.
/// `ws_frame_logging` returns `requires_ws_frame_hooks() == true`, so any proxy
/// carrying it parses every frame and never takes the lossy raw-tunnel path —
/// the warning must therefore exclude it. A proxy-scoped plugin config resolves
/// purely by `proxy_id`; no `PluginAssociation` entry is needed.
fn ws_frame_logging_for(proxy_id: &str) -> PluginConfig {
    let json = format!(
        r#"{{
            "id": "wsfl-{proxy_id}",
            "plugin_name": "ws_frame_logging",
            "scope": "proxy",
            "proxy_id": "{proxy_id}",
            "config": {{}}
        }}"#
    );
    serde_json::from_str(&json).expect("ws_frame_logging plugin config deserializes")
}

#[test]
fn test_tunnel_warning_skipped_when_tunnel_mode_disabled() {
    let config = GatewayConfig {
        proxies: vec![proxy_with_dispatch_kind(
            "p-https",
            BackendScheme::Https,
            DispatchKind::HttpsPool,
        )],
        ..GatewayConfig::default()
    };

    // Tunnel mode off → no warning regardless of proxy mix.
    assert_eq!(
        warn_if_websocket_tunnel_mode_frame_loss_risk_for_test(&config, false)
            .expect("plugin cache builds"),
        0,
    );
}

#[test]
fn test_tunnel_warning_skipped_when_only_stream_proxies() {
    let config = GatewayConfig {
        proxies: vec![
            proxy_with_dispatch_kind("p-tcp", BackendScheme::Tcp, DispatchKind::TcpRaw),
            proxy_with_dispatch_kind("p-udp", BackendScheme::Udp, DispatchKind::UdpRaw),
            proxy_with_dispatch_kind("p-dtls", BackendScheme::Dtls, DispatchKind::UdpDtls),
        ],
        ..GatewayConfig::default()
    };

    // Stream-family proxies never reach the tunnel-mode raw-copy branch, so
    // even with tunnel mode enabled there is no WebSocket frame-loss exposure.
    assert_eq!(
        warn_if_websocket_tunnel_mode_frame_loss_risk_for_test(&config, true)
            .expect("plugin cache builds"),
        0,
    );
}

#[test]
fn test_tunnel_warning_counts_only_http_family_proxies() {
    let config = GatewayConfig {
        proxies: vec![
            proxy_with_dispatch_kind("p-http", BackendScheme::Http, DispatchKind::HttpPool),
            proxy_with_dispatch_kind("p-https", BackendScheme::Https, DispatchKind::HttpsPool),
            proxy_with_dispatch_kind("p-tcp", BackendScheme::Tcp, DispatchKind::TcpRaw),
            proxy_with_dispatch_kind("p-tcptls", BackendScheme::Tcps, DispatchKind::TcpTls),
        ],
        ..GatewayConfig::default()
    };

    // Tunnel mode on + 2 HTTP-family proxies (http + https) → warning fires and
    // reports exactly the 2 affected proxies; the TCP / TCP+TLS proxies are
    // excluded.
    assert_eq!(
        warn_if_websocket_tunnel_mode_frame_loss_risk_for_test(&config, true)
            .expect("plugin cache builds"),
        2,
    );
}

#[test]
fn test_tunnel_warning_skipped_when_no_proxies() {
    let config = GatewayConfig::default();
    assert_eq!(
        warn_if_websocket_tunnel_mode_frame_loss_risk_for_test(&config, true)
            .expect("plugin cache builds"),
        0,
    );
}

#[test]
fn test_tunnel_warning_excludes_proxy_with_ws_frame_plugin() {
    // The lone HTTP-family proxy carries a frame-level WebSocket plugin
    // (`ws_frame_logging`), so `run_websocket_proxy` parses frames instead of
    // taking the raw-copy fast path — there is no first-frame-loss exposure.
    // The warning must report 0 even with tunnel mode enabled.
    let proxy = proxy_with_dispatch_kind("p-https", BackendScheme::Https, DispatchKind::HttpsPool);
    let config = GatewayConfig {
        plugin_configs: vec![ws_frame_logging_for(&proxy.id)],
        proxies: vec![proxy],
        ..GatewayConfig::default()
    };

    assert_eq!(
        warn_if_websocket_tunnel_mode_frame_loss_risk_for_test(&config, true)
            .expect("plugin cache builds"),
        0,
    );
}

#[test]
fn test_tunnel_warning_counts_only_frame_pluginless_http_proxies() {
    // Two HTTP-family proxies: one with a frame-level WS plugin (parses frames,
    // safe) and one without (takes the raw-copy fast path, lossy). The warning
    // must count only the second — the count and the actual fast-path condition
    // share `requires_ws_frame_hooks(proxy_id)` as their single source of truth.
    let p_framed =
        proxy_with_dispatch_kind("p-framed", BackendScheme::Https, DispatchKind::HttpsPool);
    let p_raw = proxy_with_dispatch_kind("p-raw", BackendScheme::Http, DispatchKind::HttpPool);
    let config = GatewayConfig {
        plugin_configs: vec![ws_frame_logging_for(&p_framed.id)],
        proxies: vec![p_framed, p_raw],
        ..GatewayConfig::default()
    };

    assert_eq!(
        warn_if_websocket_tunnel_mode_frame_loss_risk_for_test(&config, true)
            .expect("plugin cache builds"),
        1,
    );
}
