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

/// Live proof for the retry-rotation reissue contract (root review finding 1).
///
/// Selection resolves a presented, VALID binding and returns
/// `sticky_cookie_needed: false` before any backend is dialed. If that flag is
/// carried unchanged into response-cookie injection, a retry that rotates onto
/// a different backend serves the response from one endpoint while leaving the
/// client pinned to another — the one that just failed, and which retry
/// rotation did not necessarily eject. The next request then goes straight back
/// to the dead endpoint.
///
/// This drives the real binary over the real load-balancer + retry path:
///
/// 1. a cookie bound to a LIVE backend is honored and NOT re-issued (no
///    rotation happened) — the control that keeps step 2 from passing simply
///    because the gateway re-mints on every response;
/// 2. a cookie bound to a backend that refuses connections is honored,
///    dialed, fails pre-wire, rotates to the live backend, and the response
///    carries a FRESH cookie for the backend that actually served it;
/// 3. that fresh cookie returns the client to the live backend.
///
/// Deterministic: the refusing target is a socket this test OWNS for its whole
/// lifetime — bound, never listening — so every dial is an immediate
/// `ECONNREFUSED` with no bind/reuse window another process could win, and no
/// sleeps, polling, or retry-until-pass anywhere.
#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backend_lb_session_persistence_reissues_after_retry_rotation() {
    use ferrum_edge::config::types::UpstreamTarget;

    let backend_live = spawn_http_identifying("sticky-rotation-live")
        .await
        .expect("spawn sticky-rotation-live");

    // A backend that deterministically REFUSES, with no bind/reuse window: a TCP
    // socket bound to an ephemeral port and deliberately never moved into the
    // listening state. Two properties make it exact:
    //
    // - the bind is held for the whole test (RAII — the socket lives to the end
    //   of this body and closes with it), so no parallel test or unrelated
    //   process can claim the port and start answering on it. Taking a port by
    //   binding and immediately dropping the listener would be a TOCTOU race:
    //   between the release and the request, anything may bind it, and the
    //   "refusing" backend would accept instead;
    // - a bound socket that never called `listen(2)` has no accept queue, so the
    //   kernel answers every SYN with RST. The gateway's real connect attempt
    //   fails ECONNREFUSED before any request byte reaches a backend — the
    //   pre-wire, `connection_error` class that `retry_on_connect_failure`
    //   replays (`retry::should_retry`), and the only class that lets the retry
    //   loop rotate onto the live target.
    //
    // No sleeps, no retry-until-pass: the refusal is a property of the socket
    // state, observed identically on every attempt.
    let refusing_backend = tokio::net::TcpSocket::new_v4().expect("refusing-backend socket");
    refusing_backend
        .bind("127.0.0.1:0".parse().expect("refusing-backend bind addr"))
        .expect("reserve the refusing-backend port");
    let refusing_port = refusing_backend
        .local_addr()
        .expect("refusing-backend addr")
        .port();

    let upstream_id = "rotation-sticky-upstream";
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "rotation-sticky-proxy"
    listen_path: "/rotation"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {live}
    strip_listen_path: true
    upstream_id: "{upstream_id}"
    retry:
      max_retries: 1
      retry_on_connect_failure: true
      backoff: !fixed
        delay_ms: 1
upstreams:
  - id: "{upstream_id}"
    name: "BackendLBPolicy Cookie sessionPersistence with retry"
    algorithm: consistent_hashing
    hash_on: "cookie:{cookie_name}"
    hash_on_cookie_config:
      path: "/"
      session_cookie: true
      http_only: true
    targets:
      - host: "127.0.0.1"
        port: {live}
        weight: 1
      - host: "127.0.0.1"
        port: {refusing}
        weight: 1
consumers: []
plugin_configs: []
"#,
        live = backend_live.port,
        refusing = refusing_port,
        upstream_id = upstream_id,
        cookie_name = COOKIE_NAME,
    );

    let gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .reserve_listener_port(backend_live.port)
        .reserve_listener_port(refusing_port)
        .spawn()
        .await
        .expect("start sticky rotation gateway");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("http client");

    // The gateway's own binding derivation, so the test presents exactly the
    // token a prior response would have minted for each target.
    let scope = format!("ferrum|{upstream_id}");
    let token_for_port = |port: u16| {
        ferrum_edge::load_balancer::sticky_session_token(
            &scope,
            &UpstreamTarget {
                host: "127.0.0.1".to_string(),
                port,
                service_port_policy_key: None,
                weight: 1,
                tags: std::collections::HashMap::new(),
                locality: None,
                path: None,
            },
        )
    };
    let live_cookie = format!("{COOKIE_NAME}={}", token_for_port(backend_live.port));
    let refusing_cookie = format!("{COOKIE_NAME}={}", token_for_port(refusing_port));

    // --- Control: an honored binding that needed no rotation is NOT re-issued
    let honored = client
        .get(gateway.proxy_url("/rotation/honored"))
        .header(reqwest::header::COOKIE, &live_cookie)
        .send()
        .await
        .expect("honored binding request");
    assert!(
        honored.status().is_success(),
        "honored binding status {}",
        honored.status()
    );
    assert!(
        affinity_set_cookie(&honored).is_none(),
        "a binding honored without rotation must not be re-issued"
    );
    assert_eq!(
        parse_server_name(&honored.text().await.expect("honored body")),
        "sticky-rotation-live",
        "the live binding must be honored, proving the token derivation matches"
    );

    // --- A valid binding whose backend refuses: rotate, then RE-ISSUE --------
    let rotated = client
        .get(gateway.proxy_url("/rotation/rotated"))
        .header(reqwest::header::COOKIE, &refusing_cookie)
        .send()
        .await
        .expect("rotated binding request");
    assert!(
        rotated.status().is_success(),
        "a retry must rescue the request off the refusing backend, got {}",
        rotated.status()
    );
    let reissued = affinity_set_cookie(&rotated).expect(
        "a retry that rotated off the bound backend must re-issue the cookie \
         for the backend that actually served the response",
    );
    let rebound = cookie_pair_from_set_cookie(&reissued, COOKIE_NAME);
    assert_ne!(
        rebound, refusing_cookie,
        "the re-issued binding must not point back at the refusing backend"
    );
    assert_eq!(
        rebound, live_cookie,
        "the re-issued binding must name the backend that served the response"
    );
    assert_eq!(
        parse_server_name(&rotated.text().await.expect("rotated body")),
        "sticky-rotation-live"
    );

    // --- The re-issued cookie returns the client to that same backend -------
    let confirm = client
        .get(gateway.proxy_url("/rotation/confirm"))
        .header(reqwest::header::COOKIE, &rebound)
        .send()
        .await
        .expect("rebound request");
    assert!(confirm.status().is_success(), "rebound status");
    assert!(
        affinity_set_cookie(&confirm).is_none(),
        "the re-issued binding is now honored end-to-end and must not re-mint"
    );
    assert_eq!(
        parse_server_name(&confirm.text().await.expect("rebound body")),
        "sticky-rotation-live"
    );

    // Release the refusing backend's port only now that every request that had
    // to be refused has been made. Explicit rather than implicit so a future
    // edit cannot reorder the drop above the traffic and quietly reintroduce the
    // bind/reuse race; `EchoServer` and `TestGateway` clean up through their own
    // `Drop` after this.
    drop(refusing_backend);
}
