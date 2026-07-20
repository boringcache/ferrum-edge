//! Tests for statsd_logging plugin

use chrono::Utc;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::{
    ALL_PROTOCOLS, Plugin, PluginFailurePolicy, PluginHttpClient, PluginResult,
    StreamTransactionSummary, plugin_failure_policy,
    statsd_logging::{STATSD_LOGGING_CONFIG_KEYS, StatsdLogging},
    validate_plugin_config,
};
use serde_json::json;
use std::collections::HashMap;

use super::plugin_utils::{create_test_context, create_test_transaction_summary};

fn default_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn make_stream_summary() -> StreamTransactionSummary {
    StreamTransactionSummary {
        namespace: "ferrum".to_string(),
        proxy_id: "tcp-proxy-1".to_string(),
        proxy_name: Some("TCP Test".to_string()),
        client_ip: "127.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        backend_target: "127.0.0.1:9000".to_string(),
        backend_resolved_ip: None,
        protocol: "tcp".to_string(),
        listen_port: 8080,
        duration_ms: 15.0,
        bytes_sent: 128,
        bytes_received: 256,
        connection_error: None,
        error_class: None,
        disconnect_direction: None,
        disconnect_cause: None,
        timestamp_connected: "2025-01-01T00:00:00Z".to_string(),
        timestamp_disconnected: "2025-01-01T00:00:01Z".to_string(),
        sni_hostname: None,
        metadata: HashMap::new(),
    }
}

#[tokio::test]
async fn test_statsd_logging_plugin_creation() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 8125
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
    assert_eq!(plugin.priority(), 9075);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_statsd_logging_missing_host() {
    let result = StatsdLogging::new(&json!({}), default_client());
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {e}"),
        Ok(_) => panic!("Expected Err when creating statsd_logging without host"),
    }
}

#[tokio::test]
async fn test_statsd_logging_empty_host() {
    let result = StatsdLogging::new(&json!({"host": ""}), default_client());
    match result {
        Err(e) => assert!(e.contains("host")),
        Ok(_) => panic!("Expected Err for empty host"),
    }
}

#[tokio::test]
async fn test_statsd_logging_rejects_host_with_url_or_port_material() {
    for host in [
        "udp://statsd.example.com",
        "user@statsd.example.com",
        "statsd.example.com/path",
        "statsd.example.com?token=secret",
        "statsd.example.com#fragment",
        "statsd.example.com:8125",
        "bad host",
    ] {
        let result = StatsdLogging::new(&json!({"host": host}), default_client());
        assert!(result.is_err(), "host should fail validation: {host}");
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_port_zero() {
    let result = StatsdLogging::new(&json!({"host": "127.0.0.1", "port": 0}), default_client());
    match result {
        Err(e) => assert!(e.contains("port")),
        Ok(_) => panic!("Expected Err for port 0"),
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_port_too_high() {
    let result = StatsdLogging::new(
        &json!({"host": "127.0.0.1", "port": 99999}),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port")),
        Ok(_) => panic!("Expected Err for port > 65535"),
    }
}

#[tokio::test]
async fn test_statsd_logging_invalid_scalar_types() {
    let cases = [
        json!(null),
        json!({"host": 127}),
        json!({"host": "127.0.0.1", "port": "8125"}),
        json!({"host": "127.0.0.1", "prefix": 42}),
        json!({"host": "127.0.0.1", "global_tags": []}),
        json!({"host": "127.0.0.1", "global_tags": {"env": true}}),
    ];

    for config in cases {
        assert!(
            StatsdLogging::new(&config, default_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_statsd_logging_empty_prefix_rejected() {
    let result = StatsdLogging::new(
        &json!({"host": "127.0.0.1", "prefix": "   "}),
        default_client(),
    );
    match result {
        Err(e) => assert!(e.contains("prefix")),
        Ok(_) => panic!("Expected Err for empty prefix"),
    }
}

#[tokio::test]
async fn test_statsd_logging_default_port() {
    // port defaults to 8125 when not specified
    let plugin = StatsdLogging::new(&json!({"host": "127.0.0.1"}), default_client()).unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_custom_prefix() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "prefix": "myapp.gateway"
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_with_global_tags() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "global_tags": {
                "env": "prod",
                "region": "us-east-1"
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_log_does_not_panic() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1
        }),
        default_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued and background task handles UDP send
    plugin.log(&summary).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_statsd_logging_stream_disconnect_does_not_panic() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1
        }),
        default_client(),
    )
    .unwrap();
    let summary = make_stream_summary();

    // Should not panic
    plugin.on_stream_disconnect(&summary).await;

    tokio::time::sleep(tokio::time::Duration::from_millis(200)).await;
}

#[tokio::test]
async fn test_statsd_logging_default_lifecycle_phases() {
    let plugin = StatsdLogging::new(&json!({"host": "127.0.0.1"}), default_client()).unwrap();

    let mut ctx = create_test_context();
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(result, PluginResult::Continue));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(result, PluginResult::Continue));
}

#[tokio::test]
async fn test_statsd_logging_buffer_full_drops_gracefully() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "buffer_capacity": 5,
            "max_batch_lines": 1000,
            "flush_interval_ms": 60000
        }),
        default_client(),
    )
    .unwrap();

    let summary = create_test_transaction_summary();
    // Send more entries than buffer_capacity — excess should be dropped
    for _ in 0..20 {
        plugin.log(&summary).await;
    }
    // Should not panic — overflow entries are dropped with a warning
}

#[tokio::test]
async fn test_statsd_logging_accepts_all_config_options() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9125,
            "prefix": "gateway.edge",
            "global_tags": {"env": "staging", "dc": "us-west-2"},
            "flush_interval_ms": 1000,
            "buffer_capacity": 50000,
            "max_batch_lines": 100,
            "max_retries": 2,
            "retry_delay_ms": 25,
            "schema": {
                "summary_type": "both",
                "rename": { "proxy_id": "route_id" }
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_warmup_hostnames() {
    let plugin = StatsdLogging::new(
        &json!({
            "host": "statsd.internal.example.com"
        }),
        default_client(),
    )
    .unwrap();
    let hosts = plugin.warmup_hostnames();
    assert_eq!(hosts, vec!["statsd.internal.example.com".to_string()]);
}

#[tokio::test]
async fn test_statsd_logging_warmup_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin = StatsdLogging::new(&json!({"host": host}), default_client()).unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

#[tokio::test]
async fn test_statsd_logging_accepts_rename_and_omit_schema() {
    // rename + omit are supported; construction succeeds without warnings.
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "schema": {
                "summary_type": "http",
                "rename": { "proxy_id": "route_id" },
                "omit": ["response_status_code"]
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_accepts_unsupported_schema_keys_with_warning() {
    // static_fields / metadata / timestamp_format / order / derived_fields
    // are no-ops for statsd, but construction still succeeds — the plugin
    // just emits a `warn!` for visibility. Verify here that they do not
    // hard-error.
    let plugin = StatsdLogging::new(
        &json!({
            "host": "127.0.0.1",
            "schema": {
                "summary_type": "http",
                "static_fields": { "env": "prod" },
                "derived_fields": [{ "name": "outcome", "kind": "outcome" }],
                "order": ["*"],
                "timestamp_format": "epoch_ms",
                "metadata": { "mode": "omit" }
            }
        }),
        default_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "statsd_logging");
}

#[tokio::test]
async fn test_statsd_logging_rejects_one_character_misspellings_of_every_key() {
    assert_eq!(
        plugin_failure_policy("statsd_logging"),
        Some(PluginFailurePolicy::OptionalFailOpen)
    );

    let typos = [
        ("host", "hos"),
        ("port", "prot"),
        ("prefix", "prefx"),
        ("global_tags", "global_tgas"),
        ("flush_interval_ms", "flush_interval_m"),
        ("buffer_capacity", "buffer_capacit"),
        ("max_batch_lines", "max_batch_line"),
        ("max_retries", "max_retrie"),
        ("retry_delay_ms", "retry_delay_m"),
        ("schema", "schemaa"),
        ("schema_ref", "schema_reff"),
    ];
    assert_eq!(
        typos.len(),
        STATSD_LOGGING_CONFIG_KEYS.len(),
        "every recognized key needs a one-character misspelling case"
    );

    for (canonical, typo) in typos {
        assert!(
            STATSD_LOGGING_CONFIG_KEYS.contains(&canonical),
            "typo fixture must target a recognized key: {canonical}"
        );
        let mut config = json!({"host": "statsd.example.test"});
        config
            .as_object_mut()
            .unwrap()
            .insert(typo.to_string(), json!(1));
        let err = StatsdLogging::new(&config, default_client())
            .err()
            .unwrap_or_else(|| panic!("expected unknown-key rejection for {typo}"));
        assert!(err.contains("unknown configuration key"), "got: {err}");
        assert!(err.contains(typo), "error must name the typo key: {err}");
        assert!(
            err.contains("allowed keys"),
            "error must list the allowed-key contract: {err}"
        );
        for key in STATSD_LOGGING_CONFIG_KEYS {
            assert!(err.contains(key), "missing allowed key {key} in: {err}");
        }

        let shared = validate_plugin_config("statsd_logging", &config)
            .expect_err("shared admission must reject the same typo");
        assert!(shared.contains(typo), "got: {shared}");
    }
}

#[tokio::test]
async fn test_statsd_logging_rejects_multiple_unknown_keys_with_sorted_names() {
    let err = StatsdLogging::new(
        &json!({
            "host": "statsd.example.test",
            "zzz_extra": true,
            "aaa_extra": false
        }),
        default_client(),
    )
    .err()
    .expect("multiple unknown keys must be rejected");
    assert!(err.contains("aaa_extra"), "got: {err}");
    assert!(err.contains("zzz_extra"), "got: {err}");
    let aaa = err.find("aaa_extra").expect("aaa_extra present");
    let zzz = err.find("zzz_extra").expect("zzz_extra present");
    assert!(
        aaa < zzz,
        "unknown keys should be sorted in the error: {err}"
    );
}

#[tokio::test]
async fn test_statsd_logging_valid_complete_config_and_open_global_tags_map() {
    let config = json!({
        "host": "statsd.example.test",
        "port": 9125,
        "prefix": "edge.prod",
        "global_tags": {
            "env": "prod",
            "region": "us-east-1",
            "custom_dimension": "ok"
        },
        "flush_interval_ms": 250,
        "buffer_capacity": 2048,
        "max_batch_lines": 10,
        "max_retries": 1,
        "retry_delay_ms": 5,
        "schema": {
            "summary_type": "stream",
            "omit": ["disconnect_cause"]
        }
    });
    assert!(StatsdLogging::new(&config, default_client()).is_ok());
    assert!(validate_plugin_config("statsd_logging", &config).is_ok());
}

#[test]
fn test_statsd_logging_disabled_config_skips_construction_validation() {
    let mut gateway = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "statsd-disabled".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "statsd_logging".to_string(),
            config: json!({"prot": 9125}),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: false,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        ..GatewayConfig::default()
    };
    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();
    ferrum_edge::_test_support::validate_plugin_configs_fatal_for_test(&mut gateway, &policy)
        .expect("disabled statsd_logging must skip unknown-key validation");
}

#[test]
fn test_statsd_logging_optional_fail_open_on_file_mode_load_and_cache_rebuild() {
    use ferrum_edge::config::types::Proxy;

    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "http"
    }))
    .expect("minimal proxy deserializes");

    let bad_plugin = PluginConfig {
        id: "statsd-typo".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "statsd_logging".to_string(),
        config: json!({"host": "statsd.example.test", "prot": 9125}),
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    let mut bad_gateway = GatewayConfig {
        proxies: vec![proxy.clone()],
        plugin_configs: vec![bad_plugin.clone()],
        ..GatewayConfig::default()
    };
    ferrum_edge::_test_support::validate_plugin_configs_fatal_for_test(&mut bad_gateway, &policy)
        .expect("OptionalFailOpen statsd typos warn but do not abort file-mode load");

    let omitted = PluginCache::new(&bad_gateway)
        .expect("cache construction must omit the failed optional statsd plugin");
    assert!(
        omitted.get_plugins("p1").is_empty(),
        "unknown-key statsd_logging must be omitted, not silently defaulted"
    );

    let valid_gateway = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![PluginConfig {
            config: json!({"host": "statsd.example.test", "port": 9125}),
            ..bad_plugin
        }],
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&valid_gateway).expect("valid statsd config constructs");
    assert_eq!(cache.get_plugins("p1").len(), 1);
    assert_eq!(cache.get_plugins("p1")[0].name(), "statsd_logging");

    cache
        .rebuild(&bad_gateway)
        .expect("OptionalFailOpen reload omits bad statsd rather than rejecting the generation");
    assert!(
        cache.get_plugins("p1").is_empty(),
        "reload with unknown keys must drop the previously published statsd instance"
    );
}

#[test]
fn test_statsd_metric_docs_inventory_and_byte_directions() {
    let docs = include_str!("../../../docs/plugins.md");
    let statsd_section = docs
        .split("### `statsd_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("statsd_logging section present in docs/plugins.md");

    for needle in [
        "request.client_disconnect",
        "stream.disconnect",
        "client→backend",
        "backend→client",
        "last-observation",
        "idle_timeout",
        "recv_error",
        "backend_error",
        "graceful_shutdown",
        "client_to_backend",
        "backend_to_client",
        "max_retries",
        "retry_delay_ms",
        "OptionalFailOpen",
        "#2555",
    ] {
        assert!(
            statsd_section.contains(needle),
            "statsd docs missing `{needle}`"
        );
    }
    assert!(
        !statsd_section.contains("Bytes sent to client"),
        "reversed byte direction must not remain in the StatsD reference"
    );
    assert!(
        !statsd_section.contains("Bytes received from client"),
        "reversed byte direction must not remain in the StatsD reference"
    );
}
