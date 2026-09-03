//! Request → target mapping for the mesh application-probe server (#4533).
//!
//! The server exists so kubelet can probe the sidecar instead of the
//! application port, which is what lets the injector stop punching
//! destination-port-wide `RETURN` holes in inbound capture. Its whole
//! admissible surface is the injector-supplied target list, so these tests pin
//! that NOTHING in a request can name a host, port, path, or scheme.

use ferrum_edge::modes::mesh::app_probe::{
    APP_PROBE_PATH_PREFIX, AppProbeGrpc, AppProbeHttpGet, AppProbeScheme, AppProbeServer,
    AppProbeSpec, AppProbeTcpSocket, DEFAULT_APP_PROBE_PORT, DEFAULT_PROBE_TIMEOUT_SECONDS,
    MAX_PROBE_TIMEOUT_SECONDS, app_probe_key, app_probe_path, parse_app_probes,
    validate_probe_container_name,
};
use hyper::{Method, StatusCode};

fn http_spec(port: u16) -> AppProbeSpec {
    AppProbeSpec::from_http_get(
        AppProbeHttpGet {
            path: "/livez".to_string(),
            port,
            scheme: AppProbeScheme::Http,
            host: None,
            http_headers: Vec::new(),
        },
        DEFAULT_PROBE_TIMEOUT_SECONDS,
    )
}

fn server_with_one_target() -> AppProbeServer {
    let mut targets = std::collections::BTreeMap::new();
    targets.insert(app_probe_key("app", "livenessProbe"), http_spec(8080));
    AppProbeServer::new(targets)
}

#[test]
fn rewritten_path_round_trips_to_its_registered_target() {
    let server = server_with_one_target();
    let path = app_probe_path("app", "livenessProbe");
    assert_eq!(path, format!("{APP_PROBE_PATH_PREFIX}app/livenessProbe"));
    let (container, probe, spec) = server.resolve_target(&path).expect("registered target");
    assert_eq!(container, "app");
    assert_eq!(probe, "livenessProbe");
    assert_eq!(spec.http_get.as_ref().map(|h| h.port), Some(8080));
}

#[test]
fn unknown_container_or_probe_field_resolves_to_nothing() {
    let server = server_with_one_target();
    for path in [
        "/app-probe/other/livenessProbe",
        "/app-probe/app/readinessProbe",
        "/app-probe/app",
        "/app-probe/",
        "/app-probe/app/livenessProbe/extra",
        "/healthz",
        "/",
    ] {
        assert!(
            server.resolve_target(path).is_none(),
            "{path} must not resolve to a probe target"
        );
    }
}

/// The server takes no target from the request: there is no host, port, or
/// path parameter to supply, and a path that merely *looks* like one is an
/// unregistered key.
#[test]
fn request_supplied_targets_are_never_honored() {
    let server = server_with_one_target();
    for path in [
        "/app-probe/127.0.0.1:9999/livenessProbe",
        "/app-probe/app/livenessProbe?port=9999",
        "/app-probe/../app/livenessProbe",
        "/app-probe/%2e%2e/app/livenessProbe",
        "/app-probe/http://example.com/livenessProbe",
    ] {
        assert!(
            server.resolve_target(path).is_none(),
            "{path} must not resolve to a probe target"
        );
    }
}

#[tokio::test]
async fn unregistered_target_is_404_and_runs_no_probe() {
    let server = server_with_one_target();
    assert_eq!(
        server
            .handle_request(&Method::GET, "/app-probe/app/readinessProbe")
            .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        server.handle_request(&Method::GET, "/metrics").await,
        StatusCode::NOT_FOUND
    );
}

#[tokio::test]
async fn non_probe_methods_are_rejected() {
    let server = server_with_one_target();
    for method in [Method::POST, Method::PUT, Method::DELETE, Method::CONNECT] {
        assert_eq!(
            server
                .handle_request(&method, &app_probe_path("app", "livenessProbe"))
                .await,
            StatusCode::METHOD_NOT_ALLOWED,
            "{method} must not drive a probe"
        );
    }
}

#[test]
fn recorded_probes_round_trip_through_the_env_encoding() {
    let mut targets = std::collections::BTreeMap::new();
    targets.insert(app_probe_key("app", "livenessProbe"), http_spec(8080));
    targets.insert(
        app_probe_key("metrics", "readinessProbe"),
        AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: 9090 }, 2),
    );
    targets.insert(
        app_probe_key("grpcsvc", "startupProbe"),
        AppProbeSpec::from_grpc(
            AppProbeGrpc {
                port: 50051,
                service: Some("readiness".to_string()),
            },
            5,
        ),
    );
    let encoded = serde_json::to_string(&targets).expect("encode");
    assert_eq!(parse_app_probes(&encoded).expect("decode"), targets);
}

#[test]
fn empty_probe_env_is_an_empty_target_set() {
    assert!(parse_app_probes("").expect("empty").is_empty());
    assert!(parse_app_probes("   ").expect("blank").is_empty());
    assert!(parse_app_probes("{}").expect("empty object").is_empty());
}

#[test]
fn malformed_probe_env_fails_closed() {
    for raw in [
        // Not an object.
        "[]",
        // Two handlers on one probe.
        r#"{"app/livenessProbe":{"httpGet":{"port":8080},"tcpSocket":{"port":9090}}}"#,
        // No handler at all.
        r#"{"app/livenessProbe":{"timeoutSeconds":1}}"#,
        // Unknown probe field.
        r#"{"app/warmupProbe":{"tcpSocket":{"port":9090}}}"#,
        // Key is not `<container>/<probeField>`.
        r#"{"livenessProbe":{"tcpSocket":{"port":9090}}}"#,
        // Container name that could not have come from a real pod spec.
        r#"{"a b/livenessProbe":{"tcpSocket":{"port":9090}}}"#,
        // Unknown field (deny_unknown_fields).
        r#"{"app/livenessProbe":{"tcpSocket":{"port":9090},"exec":{"command":["x"]}}}"#,
    ] {
        assert!(
            parse_app_probes(raw).is_err(),
            "{raw} must be refused rather than partially honored"
        );
    }
}

#[test]
fn recorded_timeout_is_bounded() {
    let spec = AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: 9090 }, 0);
    assert_eq!(
        spec.timeout_seconds, 1,
        "a zero timeout would never succeed"
    );
    let spec = AppProbeSpec::from_tcp_socket(AppProbeTcpSocket { port: 9090 }, u64::MAX);
    assert_eq!(spec.timeout_seconds, MAX_PROBE_TIMEOUT_SECONDS);
}

#[test]
fn container_names_that_cannot_address_a_probe_are_refused() {
    for name in ["", "App", "a/b", "a b", "a?b", "a%2fb", "../etc"] {
        assert!(
            validate_probe_container_name(name).is_err(),
            "'{name}' must not become part of a rewritten probe path"
        );
    }
    for name in ["app", "my-app-1", "a"] {
        assert!(validate_probe_container_name(name).is_ok(), "'{name}'");
    }
}

#[test]
fn default_probe_port_matches_the_istio_status_port() {
    assert_eq!(DEFAULT_APP_PROBE_PORT, 15020);
}
