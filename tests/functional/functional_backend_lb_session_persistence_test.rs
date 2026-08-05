//! Live request-path coverage for Gateway API BackendLBPolicy /
//! XBackendTrafficPolicy session persistence (issue #3278 / PR #3585).
//!
//! There is no Kubernetes CRD / live-translator functional harness for these
//! policies yet, so this test starts the real `ferrum-edge` binary in file
//! mode with the **translator-equivalent** Upstream shape that
//! `translate_k8s_objects` emits for supported Cookie `sessionPersistence`:
//!
//! - Cookie → `algorithm: consistent_hashing`, `hash_on: cookie:<sessionName>`,
//!   `hash_on_cookie_config.session_cookie: true` (Session lifetimeType)
//!
//! Proves through actual gateway traffic (not `translate_k8s_objects`,
//! `LoadBalancerCache::select`, or the test-only sticky-cookie helper) the
//! property Gateway API actually requires — a client returns to the backend
//! that served its INITIAL response:
//!
//! - the first request's backend identity is retained, and every subsequent
//!   request carrying the returned cookie reaches THAT SAME backend;
//! - a bound request is not re-issued a cookie (the binding is honored, not
//!   re-minted per response);
//! - a hostile/foreign cookie value does not steer traffic and does not fail
//!   the request: it falls back to ordinary selection and is re-issued a fresh
//!   binding, which then pins to the backend that produced *that* response.
//!   This pair of assertions — "an honored binding is never re-issued" and "an
//!   unrecognized well-formed value always is" — is the deterministic
//!   discriminator against the previous hash-the-opaque-token behavior, which
//!   accepted ANY cookie value as an established session;
//! - the three backends really are distinguishable and live, proven by a
//!   sibling round-robin route over the same targets, so the pinning assertion
//!   above cannot pass vacuously on a one-backend deployment.
//!
//! Gateway API Header persistence is intentionally rejected because Ferrum
//! cannot synthesize the required response session token. Translation and
//! status regressions cover that fail-closed decision; a hand-written runtime
//! `hash_on: header:...` upstream is not evidence that the Gateway API policy
//! shape is implemented.
//!
//! Token scope validation, malformed/oversized/foreign/stale tokens, backend
//! removal, health ejection, and subset/port isolation are covered
//! deterministically in `tests/unit/gateway_core/sticky_session_binding_tests.rs`.
//!
//! Policy reload/update/delete stays covered by the focused translation
//! lifecycle tests (`backend_lb_policy_update_changes_session_name`,
//! `backend_lb_policy_delete_withdraws_session_persistence`). This harness
//! exercises the atomic file-mode reload seam for route addition elsewhere
//! (`functional_file_mode_test`); rewriting sticky Upstream hash_on under
//! SIGHUP here would race readiness without adding stronger evidence than
//! those translation lifecycle cells already provide for the CRD surface.
//!
//! Ignored by default. Hosted CI runs it via the `Functional Tests
//! (application)` shard (`test-functional` / `application` in
//! `.github/workflows/ci.yml`). Locally:
//!   cargo test --test functional_tests functional_backend_lb_session_persistence -- --ignored --nocapture

use crate::common::{TestGateway, spawn_http_identifying};
use std::collections::HashSet;
use std::time::Duration;

const COOKIE_NAME: &str = "lb-affinity";

fn parse_server_name(body: &str) -> String {
    serde_json::from_str::<serde_json::Value>(body)
        .ok()
        .and_then(|v| v.get("server").and_then(|s| s.as_str()).map(String::from))
        .unwrap_or_default()
}

/// The `name=value` pair of the gateway's affinity `Set-Cookie`, ready to send
/// back on a `Cookie` request header.
fn cookie_pair_from_set_cookie(set_cookie: &str, name: &str) -> String {
    let prefix = format!("{name}=");
    let pair = set_cookie
        .split(';')
        .next()
        .map(str::trim)
        .expect("Set-Cookie must carry a name=value pair");
    assert!(
        pair.starts_with(&prefix) && pair.len() > prefix.len(),
        "expected sticky cookie named {name}, got {set_cookie}"
    );
    pair.to_string()
}

fn affinity_set_cookie(response: &reqwest::Response) -> Option<String> {
    response
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{COOKIE_NAME}=")))
        .map(str::to_string)
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_lb_session_persistence_cookie_pins_live_backends() {
    let backend_a = spawn_http_identifying("sticky-a")
        .await
        .expect("spawn sticky-a");
    let backend_b = spawn_http_identifying("sticky-b")
        .await
        .expect("spawn sticky-b");
    let backend_c = spawn_http_identifying("sticky-c")
        .await
        .expect("spawn sticky-c");

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "cookie-sticky-proxy"
    listen_path: "/cookie-sticky"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {a}
    strip_listen_path: true
    upstream_id: "cookie-sticky-upstream"
  - id: "spread-proxy"
    listen_path: "/spread"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {a}
    strip_listen_path: true
    upstream_id: "spread-upstream"
upstreams:
  - id: "cookie-sticky-upstream"
    name: "BackendLBPolicy Cookie sessionPersistence"
    algorithm: consistent_hashing
    hash_on: "cookie:{cookie_name}"
    hash_on_cookie_config:
      path: "/"
      session_cookie: true
      http_only: true
    targets:
      - host: "127.0.0.1"
        port: {a}
        weight: 1
      - host: "127.0.0.1"
        port: {b}
        weight: 1
      - host: "127.0.0.1"
        port: {c}
        weight: 1
  - id: "spread-upstream"
    name: "Non-vacuity control: same targets, no session persistence"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {a}
        weight: 1
      - host: "127.0.0.1"
        port: {b}
        weight: 1
      - host: "127.0.0.1"
        port: {c}
        weight: 1
consumers: []
plugin_configs: []
"#,
        a = backend_a.port,
        b = backend_b.port,
        c = backend_c.port,
        cookie_name = COOKIE_NAME,
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .reserve_listener_port(backend_a.port)
        .reserve_listener_port(backend_b.port)
        .reserve_listener_port(backend_c.port)
        .spawn()
        .await
        .expect("start sticky session gateway");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");

    // --- Non-vacuity control -------------------------------------------------
    // The same three targets behind a round-robin route must be individually
    // reachable and distinguishable, so "every pinned request hit one backend"
    // below cannot be an artifact of a single live backend.
    let mut reachable = HashSet::new();
    for i in 0..12 {
        let resp = client
            .get(gateway.proxy_url(&format!("/spread/rr-{i}")))
            .send()
            .await
            .unwrap_or_else(|e| panic!("round-robin control request {i} failed: {e}"));
        assert!(resp.status().is_success(), "control status {}", i);
        let server = parse_server_name(&resp.text().await.expect("control body"));
        assert!(
            !server.is_empty(),
            "control request {i} must identify a backend"
        );
        reachable.insert(server);
    }
    assert!(
        reachable.len() >= 2,
        "control route must reach ≥2 distinguishable live backends, got {reachable:?}"
    );

    // --- Initial response mints a binding to the backend that SERVED it ------
    let first = client
        .get(gateway.proxy_url("/cookie-sticky/probe"))
        .send()
        .await
        .expect("cookie probe request");
    assert!(
        first.status().is_success(),
        "cookie probe must succeed, got {}",
        first.status()
    );
    let set_cookie = affinity_set_cookie(&first)
        .expect("gateway must inject sticky Set-Cookie for a new session");
    assert!(
        !set_cookie.to_ascii_lowercase().contains("max-age="),
        "Session lifetimeType must omit Max-Age: {set_cookie}"
    );
    assert!(
        set_cookie.contains("HttpOnly"),
        "sticky cookie should keep HttpOnly: {set_cookie}"
    );
    let cookie_pair = cookie_pair_from_set_cookie(&set_cookie, COOKIE_NAME);
    // The whole point of the fix: RETAIN the first response's backend identity.
    let selected = parse_server_name(&first.text().await.expect("cookie probe body"));
    assert!(
        !selected.is_empty(),
        "initial response must identify the backend that served it"
    );
    assert!(
        !cookie_pair.contains(&selected),
        "affinity token must not disclose the backend it binds: {cookie_pair}"
    );

    // --- Every subsequent cookie-bearing request returns to THAT backend -----
    for i in 0..12 {
        let resp = client
            .get(gateway.proxy_url(&format!("/cookie-sticky/pinned-{i}")))
            .header(reqwest::header::COOKIE, &cookie_pair)
            .send()
            .await
            .unwrap_or_else(|e| panic!("pinned cookie request {i} failed: {e}"));
        assert!(resp.status().is_success(), "pinned cookie status {}", i);
        assert!(
            affinity_set_cookie(&resp).is_none(),
            "an honored binding must not be re-issued on request {i}"
        );
        let server = parse_server_name(&resp.text().await.expect("pinned cookie body"));
        assert_eq!(
            server, selected,
            "session persistence must return the client to the backend that served \
             the initial response (request {i})"
        );
    }

    // --- Hostile / foreign cookie values: safe fallback, then re-bind --------
    // These are not valid bindings for this route, so the gateway must select
    // normally, succeed, and issue a fresh cookie bound to the backend that
    // actually served the response.
    let hostile = [
        "not-a-token".to_string(),
        "0".repeat(64),
        "z".repeat(64),
        // Oversized, but comfortably inside the gateway's header limits so the
        // assertion below is about token validation, not header rejection.
        "a".repeat(1024),
        format!("{}deadbeef", &cookie_pair[COOKIE_NAME.len() + 1..]),
    ];
    for (i, value) in hostile.iter().enumerate() {
        let resp = client
            .get(gateway.proxy_url(&format!("/cookie-sticky/hostile-{i}")))
            .header(reqwest::header::COOKIE, format!("{COOKIE_NAME}={value}"))
            .send()
            .await
            .unwrap_or_else(|e| panic!("hostile cookie request {i} failed: {e}"));
        assert!(
            resp.status().is_success(),
            "hostile cookie must fall back, not fail: status {} on {i}",
            resp.status()
        );
        let reissued = affinity_set_cookie(&resp)
            .unwrap_or_else(|| panic!("hostile cookie {i} must be re-issued a fresh binding"));
        let rebound = cookie_pair_from_set_cookie(&reissued, COOKIE_NAME);
        assert_ne!(
            rebound,
            format!("{COOKIE_NAME}={value}"),
            "the re-issued binding must not echo the presented value"
        );
        let served = parse_server_name(&resp.text().await.expect("hostile cookie body"));
        assert!(
            !served.is_empty(),
            "hostile fallback {i} must identify a backend"
        );

        // The re-issued cookie must bind to the backend that served THAT response.
        let confirm = client
            .get(gateway.proxy_url(&format!("/cookie-sticky/rebound-{i}")))
            .header(reqwest::header::COOKIE, &rebound)
            .send()
            .await
            .unwrap_or_else(|e| panic!("rebound request {i} failed: {e}"));
        assert!(confirm.status().is_success(), "rebound status {}", i);
        let confirmed = parse_server_name(&confirm.text().await.expect("rebound body"));
        assert_eq!(
            confirmed, served,
            "a re-issued cookie must bind the backend that produced its response ({i})"
        );
    }
}
