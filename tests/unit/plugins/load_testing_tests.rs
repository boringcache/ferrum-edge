use bytes::Bytes;
use ferrum_edge::plugins::load_testing::{
    LOAD_TESTING_CONFIG_KEYS, LoadTesting, MIN_TRIGGER_KEY_LEN, RunOutcome,
};
use ferrum_edge::plugins::{
    HTTP_ONLY_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    RequestContext, plugin_failure_policy, priority, validate_plugin_config,
};
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

const VALID_KEY: &str = "test-secret-key!!"; // 16 chars

fn make_valid_config() -> serde_json::Value {
    json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10
    })
}

fn make_plugin() -> LoadTesting {
    LoadTesting::new(&make_valid_config(), PluginHttpClient::default()).unwrap()
}

fn matched_proxy() -> Arc<ferrum_edge::config::types::Proxy> {
    Arc::new(
        serde_json::from_value(json!({
            "id": "proxy-1",
            "name": "test-proxy",
            "listen_path": "/api",
            "backend_host": "backend.local",
            "backend_port": 8080,
            "backend_scheme": "http"
        }))
        .unwrap(),
    )
}

async fn wait_until_idle(plugin: &LoadTesting) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    while plugin.is_running() && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[test]
fn validate_plugin_config_with_policy_screens_denied_gateway_address() {
    use ferrum_edge::config::{BackendAllowIps, BackendEgressPolicy};
    use ferrum_edge::plugins::validate_plugin_config_with_policy;

    let default_policy =
        BackendEgressPolicy::from_env(BackendAllowIps::Both, "", "", true).expect("valid");

    let denied = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_addresses": ["http://169.254.169.254:8000"]
    });
    assert!(
        validate_plugin_config_with_policy("load_testing", &denied, &default_policy).is_err(),
        "metadata gateway address must be rejected under the default policy"
    );

    let loopback = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_addresses": ["http://10.0.0.2:8000"]
    });
    assert!(
        validate_plugin_config_with_policy("load_testing", &loopback, &default_policy).is_ok(),
        "private gateway address must remain valid by default"
    );
}

#[test]
fn test_plugin_name() {
    assert_eq!(make_plugin().name(), "load_testing");
}

#[test]
fn test_plugin_priority() {
    assert_eq!(make_plugin().priority(), priority::LOAD_TESTING);
}

#[test]
fn test_supported_protocols() {
    assert_eq!(make_plugin().supported_protocols(), HTTP_ONLY_PROTOCOLS);
}

#[test]
fn test_valid_minimal_config() {
    assert!(LoadTesting::new(&make_valid_config(), PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_ramp() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "ramp": true
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_port() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_port": 9090
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_tls() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_tls": true
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_gateway_addresses() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 10,
        "duration_seconds": 30,
        "gateway_addresses": ["https://node1:8443", "https://node2:8443"]
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_boundary_values() {
    let config = json!({
        "key": "sixteen-char-key",
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());

    let config = json!({
        "key": "sixteen-char-key",
        "concurrent_clients": 10000,
        "duration_seconds": 3600
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_valid_config_with_every_supported_field() {
    let config = json!({
        "key": "full-surface-key!",
        "concurrent_clients": 25,
        "duration_seconds": 45,
        "ramp": true,
        "request_timeout_ms": 5000,
        "max_response_body_bytes": 2048,
        "gateway_port": 8443,
        "gateway_tls": true,
        "gateway_tls_no_verify": true,
        "gateway_addresses": ["https://10.0.0.2:8443", "https://10.0.0.3:8443"]
    });
    assert_eq!(
        config.as_object().unwrap().len(),
        LOAD_TESTING_CONFIG_KEYS.len(),
        "fixture must exercise every accepted top-level key"
    );
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
    assert!(validate_plugin_config("load_testing", &config).is_ok());
}

#[test]
fn test_optional_null_fields_still_select_defaults() {
    let config = json!({
        "key": "null-defaults-key",
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "ramp": null,
        "request_timeout_ms": null,
        "max_response_body_bytes": null,
        "gateway_port": null,
        "gateway_tls": null,
        "gateway_tls_no_verify": null,
        "gateway_addresses": null
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
}

#[test]
fn test_rejects_short_trigger_key() {
    let short = "x".repeat(MIN_TRIGGER_KEY_LEN - 1);
    let config = json!({
        "key": short,
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("at least 16 characters"), "got: {err}");
}

#[test]
fn test_rejects_one_typo_with_path_qualified_suggestion() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 50,
        "duration_seconds": 30,
        "request_timeot_ms": 5000
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .expect("typo must be rejected");
    assert!(err.contains("'config.request_timeot_ms'"), "got: {err}");
    assert!(
        err.contains("did you mean 'request_timeout_ms'"),
        "got: {err}"
    );
}

#[test]
fn shared_file_admin_database_cp_dp_admission_rejects_unknown_keys() {
    assert_eq!(
        plugin_failure_policy("load_testing"),
        Some(PluginFailurePolicy::KeepLastKnownGood)
    );

    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "request_timeot_ms": 5000
    });
    let err = validate_plugin_config("load_testing", &config).expect_err("must reject typo");
    assert!(err.contains("'config.request_timeot_ms'"), "got: {err}");
}

#[test]
fn test_non_object_config_is_error() {
    let err = LoadTesting::new(&json!("bad"), PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("config must be an object"), "got: {err}");
}

#[test]
fn test_missing_key_is_error() {
    let config = json!({
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("'key' is required"), "got: {err}");
}

#[test]
fn test_empty_key_is_error() {
    let config = json!({
        "key": "",
        "concurrent_clients": 5,
        "duration_seconds": 10
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("'key' is required"), "got: {err}");
}

#[test]
fn test_zero_gateway_port_is_error() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 5,
        "duration_seconds": 10,
        "gateway_port": 0
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("1–65535"), "got: {err}");
}

#[test]
fn test_request_timeout_above_max_is_error() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "request_timeout_ms": 60_001
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("60000"), "got: {err}");
}

#[test]
fn test_gateway_address_userinfo_is_rejected() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_addresses": ["https://user:password@node2:8443"]
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("userinfo"), "got: {err}");
}

#[test]
fn test_duplicate_gateway_addresses_are_rejected() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_addresses": ["https://node2:8443/", "https://node2:8443"]
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("duplicate"), "got: {err}");
}

#[test]
fn test_self_loopback_gateway_address_is_rejected() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 8000,
        "gateway_addresses": ["http://127.0.0.1:8000"]
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .unwrap();
    assert!(err.contains("local loopback"), "got: {err}");
}

#[test]
#[serial_test::serial(load_testing_listener_env)]
fn test_env_derived_disabled_http_port_is_rejected() {
    // SAFETY: serialized against other load_testing listener env tests.
    unsafe {
        std::env::set_var("FERRUM_PROXY_HTTP_PORT", "0");
    }
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .expect("disabled HTTP listener must fail closed");
    assert!(err.contains("resolved gateway port is 0"), "got: {err}");
    assert!(err.contains("HTTP (FERRUM_PROXY_HTTP_PORT)"), "got: {err}");
    unsafe {
        std::env::remove_var("FERRUM_PROXY_HTTP_PORT");
    }
}

#[test]
#[serial_test::serial(load_testing_listener_env)]
fn test_env_derived_disabled_https_port_is_rejected() {
    unsafe {
        std::env::set_var("FERRUM_PROXY_HTTPS_PORT", "0");
    }
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_tls": true
    });
    let err = LoadTesting::new(&config, PluginHttpClient::default())
        .err()
        .expect("disabled HTTPS listener must fail closed");
    assert!(err.contains("resolved gateway port is 0"), "got: {err}");
    assert!(
        err.contains("HTTPS (FERRUM_PROXY_HTTPS_PORT)"),
        "got: {err}"
    );
    unsafe {
        std::env::remove_var("FERRUM_PROXY_HTTPS_PORT");
    }
}

#[test]
#[serial_test::serial(load_testing_listener_env)]
fn test_explicit_port_overrides_disabled_env_default() {
    unsafe {
        std::env::set_var("FERRUM_PROXY_HTTP_PORT", "0");
    }
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1,
        "gateway_port": 18080
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
    unsafe {
        std::env::remove_var("FERRUM_PROXY_HTTP_PORT");
    }
}

#[test]
#[serial_test::serial(load_testing_listener_env)]
fn test_env_derived_enabled_http_port_is_accepted() {
    unsafe {
        std::env::set_var("FERRUM_PROXY_HTTP_PORT", "18081");
    }
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 1
    });
    assert!(LoadTesting::new(&config, PluginHttpClient::default()).is_ok());
    unsafe {
        std::env::remove_var("FERRUM_PROXY_HTTP_PORT");
    }
}

#[test]
fn test_should_buffer_only_when_trigger_header_present() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    assert!(!plugin.should_buffer_request_body(&ctx));
    ctx.headers
        .insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    assert!(plugin.should_buffer_request_body(&ctx));
    assert!(plugin.requires_request_body_before_before_proxy());
    assert!(plugin.needs_request_body_bytes());
    assert!(!plugin.needs_request_body_text());
}

#[tokio::test]
async fn test_skips_when_no_key_header() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert("content-type".to_string(), "application/json".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_skips_when_key_does_not_match() {
    let plugin = make_plugin();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    let mut headers = HashMap::new();
    headers.insert(
        "x-loadtesting-key".to_string(),
        "wrong-key-value!!".to_string(),
    );

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_strips_trigger_key_from_original_request() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("x-forwarded-for".to_string(), "203.0.113.9".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("x-loadtesting-key"));
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_fanout_control_request_terminates_before_backend() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": 9
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("x-loadtesting-fanout".to_string(), "1".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    match result {
        PluginResult::Reject { status_code, .. } => assert_eq!(status_code, 204),
        other => panic!("expected fanout ack reject, got {other:?}"),
    }
    assert!(!headers.contains_key("x-loadtesting-key"));
    assert!(!headers.contains_key("x-loadtesting-fanout"));
    wait_until_idle(&plugin).await;
}

#[tokio::test]
async fn test_connection_refusal_is_not_reported_as_completed_throughput() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 2,
            "duration_seconds": 1,
            "gateway_port": 9,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());

    let _ = plugin.before_proxy(&mut ctx, &mut headers).await;
    wait_until_idle(&plugin).await;

    let result = plugin
        .last_run_result()
        .expect("completed run must publish counters");
    assert!(result.attempted_requests > 0);
    assert_eq!(result.responses_completed, 0);
    assert!(result.transport_errors > 0);
    assert_eq!(result.completed_requests_per_second(), 0.0);
    assert!(matches!(
        result.outcome,
        RunOutcome::Failed | RunOutcome::Degraded | RunOutcome::Cancelled
    ));
}

#[tokio::test]
async fn test_successful_local_run_records_completed_responses() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = listener.accept().await else {
                break;
            };
            tokio::spawn(async move {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut buf = [0u8; 4096];
                let _ = socket.read(&mut buf).await;
                let body = b"ok";
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.write_all(body).await;
            });
        }
    });

    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_port": port,
            "request_timeout_ms": 1000
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "POST".to_string(),
        "/orders".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    ctx.set_raw_query_string("tag=red&tag=blue&q=a+b".to_string());
    ctx.request_body_bytes = Some(Bytes::from_static(b"{\"sku\":\"A-123\"}"));
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert("content-length".to_string(), "15".to_string());
    headers.insert("x-forwarded-for".to_string(), "198.51.100.7".to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(!headers.contains_key("x-loadtesting-key"));
    wait_until_idle(&plugin).await;

    let run = plugin.last_run_result().expect("run result");
    assert!(run.responses_completed > 0, "expected completed responses");
    assert!(run.status_2xx > 0);
    assert_eq!(run.responses_completed, run.status_2xx);
    assert!(matches!(
        run.outcome,
        RunOutcome::Success | RunOutcome::Degraded
    ));
}

#[tokio::test]
async fn test_shared_state_prevents_second_instance_while_running() {
    let config = json!({
        "key": VALID_KEY,
        "concurrent_clients": 1,
        "duration_seconds": 2,
        "gateway_port": 9,
        "request_timeout_ms": 200
    });
    let plugin_a = LoadTesting::new(&config, PluginHttpClient::default()).unwrap();
    let plugin_b = plugin_a
        .share_with(&config, PluginHttpClient::default())
        .unwrap();

    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let _ = plugin_a.before_proxy(&mut ctx, &mut headers).await;
    assert!(plugin_a.is_running());

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx2.matched_proxy = Some(matched_proxy());
    let mut headers2 = HashMap::new();
    headers2.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let _ = plugin_b.before_proxy(&mut ctx2, &mut headers2).await;

    // Second instance must observe the shared admission guard.
    assert!(plugin_b.is_running());
    wait_until_idle(&plugin_a).await;
}

#[tokio::test]
async fn test_triggers_when_key_matches_and_blocks_concurrent_trigger() {
    let plugin = LoadTesting::new(
        &json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 2,
            "gateway_port": 9,
            "request_timeout_ms": 200
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx.matched_proxy = Some(matched_proxy());
    let mut headers = HashMap::new();
    headers.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());

    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
    assert!(plugin.is_running());

    let mut ctx2 = RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/api/test".to_string(),
    );
    ctx2.matched_proxy = Some(matched_proxy());
    let mut headers2 = HashMap::new();
    headers2.insert("x-loadtesting-key".to_string(), VALID_KEY.to_string());
    let result2 = plugin.before_proxy(&mut ctx2, &mut headers2).await;
    assert!(matches!(result2, PluginResult::Continue));
    wait_until_idle(&plugin).await;
}

#[test]
fn test_gateway_address_query_fragment_still_rejected() {
    for address in [
        "https://node2:8443?x=1",
        "https://node2:8443#frag",
        "ftp://node2:8443",
    ] {
        let config = json!({
            "key": VALID_KEY,
            "concurrent_clients": 1,
            "duration_seconds": 1,
            "gateway_addresses": [address]
        });
        assert!(
            LoadTesting::new(&config, PluginHttpClient::default()).is_err(),
            "address {address} should fail"
        );
    }
}
