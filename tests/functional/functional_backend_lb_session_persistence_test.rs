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
//! `LoadBalancerCache::select`, or the test-only sticky-cookie helper) that:
//! - a first cookie request receives the configured sticky `Set-Cookie`
//!   (session cookie: no `Max-Age`) and subsequent requests carrying that
//!   cookie pin to one live backend;
//! - distinct cookie affinity keys spread across at least two distinguishable
//!   live backends.
//!
//! Gateway API Header persistence is intentionally rejected because Ferrum
//! cannot synthesize the required response session token. Translation and
//! status regressions cover that fail-closed decision; a hand-written runtime
//! `hash_on: header:...` upstream is not evidence that the Gateway API policy
//! shape is implemented.
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

    // --- Cookie affinity (BackendLBPolicy / Session lifetimeType shape) ---
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
    let set_cookie = first
        .headers()
        .get_all(reqwest::header::SET_COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .find(|v| v.starts_with(&format!("{COOKIE_NAME}=")))
        .expect("gateway must inject sticky Set-Cookie for missing affinity cookie")
        .to_string();
    assert!(
        !set_cookie.to_ascii_lowercase().contains("max-age="),
        "Session lifetimeType must omit Max-Age: {set_cookie}"
    );
    assert!(
        set_cookie.contains("HttpOnly"),
        "sticky cookie should keep HttpOnly: {set_cookie}"
    );
    let cookie_pair = cookie_pair_from_set_cookie(&set_cookie, COOKIE_NAME);
    // Drop the first-response body: the no-cookie probe hashes by client IP,
    // while later requests hash the injected cookie value. Affinity is proven
    // by repeated traffic carrying that cookie agreeing on one backend.
    let _ = first.text().await.expect("cookie probe body");

    let mut pinned: Option<String> = None;
    for i in 0..12 {
        let resp = client
            .get(gateway.proxy_url(&format!("/cookie-sticky/pinned-{i}")))
            .header(reqwest::header::COOKIE, &cookie_pair)
            .send()
            .await
            .unwrap_or_else(|e| panic!("pinned cookie request {i} failed: {e}"));
        assert!(resp.status().is_success(), "pinned cookie status {}", i);
        let server = parse_server_name(&resp.text().await.expect("pinned cookie body"));
        assert!(
            !server.is_empty(),
            "pinned cookie request {i} must identify a backend"
        );
        match &pinned {
            None => pinned = Some(server),
            Some(expected) => assert_eq!(
                &server, expected,
                "cookie {cookie_pair} must pin to {expected}, got {server} on request {i}"
            ),
        }
    }
    let pinned = pinned.expect("at least one pinned cookie response");

    let mut cookie_hosts = HashSet::new();
    cookie_hosts.insert(pinned);
    for i in 0..40 {
        let synthetic = format!("{COOKIE_NAME}=synthetic-affinity-key-{i}");
        let resp = client
            .get(gateway.proxy_url(&format!("/cookie-sticky/spread-{i}")))
            .header(reqwest::header::COOKIE, &synthetic)
            .send()
            .await
            .unwrap_or_else(|e| panic!("spread cookie request {i} failed: {e}"));
        assert!(resp.status().is_success());
        let server = parse_server_name(&resp.text().await.expect("spread cookie body"));
        if !server.is_empty() {
            cookie_hosts.insert(server);
        }
    }
    assert!(
        cookie_hosts.len() >= 2,
        "distinct sticky cookie keys must reach ≥2 live backends, got {cookie_hosts:?}"
    );
}
