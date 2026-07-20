//! Tests for udp_logging plugin

use std::io::Write;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::plugin_cache::PluginCache;
use ferrum_edge::plugins::udp_logging::{UDP_LOGGING_CONFIG_KEYS, UdpLogging};
use ferrum_edge::plugins::{ALL_PROTOCOLS, Plugin, PluginHttpClient, validate_plugin_config};
use rcgen::{
    CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
};
use serde_json::json;
use tokio::net::UdpSocket;

use super::plugin_utils::{
    create_test_stream_transaction_summary, create_test_transaction_summary,
};

fn test_client() -> PluginHttpClient {
    PluginHttpClient::default()
}

fn ensure_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn mint_cert_key_pair(
    alg: &'static rcgen::SignatureAlgorithm,
) -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    let key_pair = KeyPair::generate_for(alg).expect("key");
    let mut params = CertificateParams::new(vec!["udp-logging-test".to_string()]).expect("params");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "udp-logging-test");
    params.distinguished_name = dn;
    let cert = params.self_signed(&key_pair).expect("self-sign");

    let mut cert_file = tempfile::NamedTempFile::with_suffix(".pem").expect("cert file");
    cert_file
        .write_all(cert.pem().as_bytes())
        .expect("write cert");
    cert_file.flush().expect("flush cert");

    let mut key_file = tempfile::NamedTempFile::with_suffix(".pem").expect("key file");
    key_file
        .write_all(key_pair.serialize_pem().as_bytes())
        .expect("write key");
    key_file.flush().expect("flush key");
    (cert_file, key_file)
}

fn mint_ecdsa_p256_pair() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    mint_cert_key_pair(&PKCS_ECDSA_P256_SHA256)
}

fn mint_rsa_pair() -> (tempfile::NamedTempFile, tempfile::NamedTempFile) {
    mint_cert_key_pair(&PKCS_RSA_SHA256)
}

fn write_temp_pem(contents: &str) -> tempfile::NamedTempFile {
    let mut file = tempfile::NamedTempFile::with_suffix(".pem").expect("temp pem");
    file.write_all(contents.as_bytes()).expect("write pem");
    file.flush().expect("flush pem");
    file
}

#[tokio::test]
async fn test_udp_logging_plugin_creation() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
    assert_eq!(plugin.priority(), 9160);
    assert_eq!(plugin.supported_protocols(), ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_udp_logging_missing_host() {
    let result = UdpLogging::new(
        &json!({
            "port": 9514
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(e.contains("host"), "Expected error about host, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without host"),
    }
}

#[tokio::test]
async fn test_udp_logging_missing_port() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(e.contains("port"), "Expected error about port, got: {}", e),
        Ok(_) => panic!("Expected Err when creating udp_logging without port"),
    }
}

#[tokio::test]
async fn test_udp_logging_empty_host() {
    let result = UdpLogging::new(
        &json!({
            "host": "",
            "port": 9514
        }),
        test_client(),
    );
    assert!(result.is_err());
}

#[tokio::test]
async fn test_udp_logging_rejects_host_with_url_or_port_material() {
    for host in [
        "udp://logs.example.com",
        "user@logs.example.com",
        "logs.example.com/path",
        "logs.example.com?token=secret",
        "logs.example.com#fragment",
        "logs.example.com:9514",
        "bad host",
    ] {
        let result = UdpLogging::new(&json!({"host": host, "port": 9514}), test_client());
        assert!(result.is_err(), "host should fail validation: {host}");
    }
}

#[tokio::test]
async fn test_udp_logging_invalid_port_zero() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 0
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("between 1 and 65535"),
            "Expected port range error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err for port 0"),
    }
}

#[tokio::test]
async fn test_udp_logging_invalid_port_too_large() {
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 70000
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("between 1 and 65535"),
            "Expected port range error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err for port 70000"),
    }
}

#[tokio::test]
async fn test_udp_logging_rejects_invalid_config_shapes() {
    let cases = [
        json!(null),
        json!({"host": 123, "port": 9514}),
        json!({"host": "127.0.0.1", "port": "9514"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls": "true"}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_no_verify": 1}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_cert_path": ""}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_key_path": false}),
        json!({"host": "127.0.0.1", "port": 9514, "dtls_ca_cert_path": []}),
        json!({"host": "127.0.0.1", "port": 9514, "batch_size": {}}),
        json!({"host": "127.0.0.1", "port": 9514, "retry_delay_ms": "500"}),
    ];

    for config in cases {
        assert!(
            UdpLogging::new(&config, test_client()).is_err(),
            "expected invalid config to be rejected: {config}"
        );
    }
}

#[tokio::test]
async fn test_udp_logging_log_does_not_panic() {
    // When the endpoint is unreachable, log() should still accept entries
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "max_retries": 0
        }),
        test_client(),
    )
    .unwrap();
    let summary = create_test_transaction_summary();

    // Should not panic — entry is queued in the channel
    plugin.log(&summary).await;
}

#[tokio::test]
async fn test_udp_logging_stream_disconnect_does_not_panic() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1,
            "flush_interval_ms": 100,
            "max_retries": 0
        }),
        test_client(),
    )
    .unwrap();
    let summary = create_test_stream_transaction_summary();

    plugin.on_stream_disconnect(&summary).await;
    tokio::time::sleep(tokio::time::Duration::from_millis(300)).await;
}

#[tokio::test]
async fn test_udp_logging_buffer_accepts_multiple_entries() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 50,
            "flush_interval_ms": 10000,
            "max_retries": 0,
            "buffer_capacity": 1000
        }),
        test_client(),
    )
    .unwrap();

    let summary = create_test_transaction_summary();
    for _ in 0..100 {
        plugin.log(&summary).await;
    }
    // Should not panic or block — entries are queued in the channel
}

#[tokio::test]
async fn test_udp_logging_buffer_full_drops_gracefully() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 1,
            "batch_size": 1000,
            "flush_interval_ms": 60000,
            "max_retries": 0,
            "buffer_capacity": 5
        }),
        test_client(),
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
async fn test_udp_logging_default_lifecycle_phases() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();

    let mut ctx = ferrum_edge::plugins::RequestContext::new(
        "127.0.0.1".to_string(),
        "GET".to_string(),
        "/test".to_string(),
    );
    let consumer_index = ferrum_edge::ConsumerIndex::new(&[]);

    let result = plugin.on_request_received(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authenticate(&mut ctx, &consumer_index).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.authorize(&mut ctx).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let mut headers = std::collections::HashMap::new();
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));

    let result = plugin.after_proxy(&mut ctx, 200, &mut headers).await;
    assert!(matches!(
        result,
        ferrum_edge::plugins::PluginResult::Continue
    ));
}

#[tokio::test]
async fn test_udp_logging_batch_config_defaults() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_custom_batch_config() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "batch_size": 5,
            "flush_interval_ms": 2000,
            "max_retries": 3,
            "retry_delay_ms": 1000,
            "buffer_capacity": 50000
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_dtls_cert_key_pairing_required() {
    // cert without key should fail
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": "/some/cert.pem"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("together"),
            "Expected cert/key pairing error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when cert is provided without key"),
    }

    // key without cert should fail
    let result = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_key_path": "/some/key.pem"
        }),
        test_client(),
    );
    match result {
        Err(e) => assert!(
            e.contains("together"),
            "Expected cert/key pairing error, got: {}",
            e
        ),
        Ok(_) => panic!("Expected Err when key is provided without cert"),
    }
}

#[tokio::test]
async fn test_udp_logging_dtls_config_accepted() {
    // DTLS config without certs (ephemeral cert will be used) should be accepted
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .unwrap();
    assert_eq!(plugin.name(), "udp_logging");
}

#[tokio::test]
async fn test_udp_logging_warmup_hostnames() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "syslog.example.com",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    let hostnames = plugin.warmup_hostnames();
    assert_eq!(hostnames, vec!["syslog.example.com".to_string()]);
}

#[tokio::test]
async fn test_udp_logging_warmup_skips_ip_literals() {
    for host in ["127.0.0.1", "2001:db8::10", "[2001:db8::10]"] {
        let plugin = UdpLogging::new(&json!({"host": host, "port": 9514}), test_client()).unwrap();
        assert!(
            plugin.warmup_hostnames().is_empty(),
            "IP literal {host} should not be DNS-warmed"
        );
    }
}

#[tokio::test]
async fn test_udp_logging_supported_protocols() {
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514
        }),
        test_client(),
    )
    .unwrap();
    let protocols = plugin.supported_protocols();
    assert_eq!(protocols, ALL_PROTOCOLS);
}

#[tokio::test]
async fn test_udp_logging_rejects_unknown_keys_including_dtls_typos() {
    for (canonical, typo) in [("dtls", "dtsl"), ("port", "prot"), ("host", "hst")] {
        assert!(
            UDP_LOGGING_CONFIG_KEYS.contains(&canonical),
            "fixture must target a recognized key: {canonical}"
        );
        let mut config = json!({"host": "127.0.0.1", "port": 9514});
        config
            .as_object_mut()
            .expect("object")
            .insert(typo.to_string(), json!(true));
        let err = UdpLogging::new(&config, test_client())
            .err()
            .unwrap_or_else(|| panic!("expected unknown-key rejection for {typo}"));
        assert!(err.contains("unknown configuration key"), "got: {err}");
        assert!(err.contains(typo), "error must name the typo: {err}");
        let shared = validate_plugin_config("udp_logging", &config)
            .expect_err("shared validation must reject the same typo");
        assert!(shared.contains(typo), "got: {shared}");
    }
}

#[tokio::test]
async fn test_udp_logging_rejects_multiple_unknown_keys_sorted() {
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "zzz_extra": true,
            "aaa_extra": false
        }),
        test_client(),
    )
    .err()
    .expect("multiple unknown keys must be rejected");
    let aaa = err.find("aaa_extra").expect("aaa_extra");
    let zzz = err.find("zzz_extra").expect("zzz_extra");
    assert!(aaa < zzz, "unknown keys should be sorted: {err}");
}

#[test]
fn test_udp_logging_disabled_skips_construction_validation() {
    let mut gateway = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "udp-disabled".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "udp_logging".to_string(),
            config: json!({"dtsl": true}),
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
        .expect("disabled udp_logging must skip unknown-key validation");
}

#[tokio::test]
async fn test_udp_logging_optional_fail_open_omits_unknown_key_instance() {
    use ferrum_edge::config::types::Proxy;

    let policy = ferrum_edge::config::BackendEgressPolicy::unrestricted();
    let proxy: Proxy = serde_json::from_value(json!({
        "id": "p1",
        "listen_path": "/api",
        "backend_host": "localhost",
        "backend_port": 3000,
        "backend_scheme": "http"
    }))
    .expect("proxy");

    let bad_plugin = PluginConfig {
        id: "udp-typo".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: "udp_logging".to_string(),
        config: json!({"host": "127.0.0.1", "port": 9514, "dtsl": true}),
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
        .expect("OptionalFailOpen udp typos warn but do not abort file-mode load");

    let omitted = PluginCache::new(&bad_gateway).expect("cache omits failed optional plugin");
    assert!(
        omitted.get_plugins("p1").is_empty(),
        "unknown-key udp_logging must be omitted, not silently defaulted to plaintext"
    );

    let valid_gateway = GatewayConfig {
        proxies: vec![proxy],
        plugin_configs: vec![PluginConfig {
            config: json!({"host": "127.0.0.1", "port": 9514, "dtls": true, "dtls_no_verify": true}),
            ..bad_plugin
        }],
        ..GatewayConfig::default()
    };
    let cache = PluginCache::new(&valid_gateway).expect("valid dtls config constructs");
    assert_eq!(cache.get_plugins("p1").len(), 1);

    cache
        .rebuild(&bad_gateway)
        .expect("OptionalFailOpen reload omits bad udp rather than rejecting the generation");
    assert!(
        cache.get_plugins("p1").is_empty(),
        "reload with unknown keys must drop the previously published udp instance"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_missing_cert_source_at_admission() {
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": "/definitely/missing/udp-logging-cert.pem",
            "dtls_key_path": "/definitely/missing/udp-logging-key.pem",
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("missing DTLS sources must fail admission");
    assert!(
        err.contains("DTLS cert/key materialization failed") || err.contains("failed to load"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_malformed_pem_at_admission() {
    let cert = write_temp_pem("not-a-certificate");
    let key = write_temp_pem("not-a-key");
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("malformed PEM must fail admission");
    assert!(
        err.contains("DTLS cert/key materialization failed")
            || err.contains("No certificate")
            || err.contains("parse"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_rsa_key_at_admission() {
    let (cert, key) = mint_rsa_pair();
    let err = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_no_verify": true
        }),
        test_client(),
    )
    .err()
    .expect("RSA keys are unsupported for DTLS");
    assert!(
        err.contains("Unsupported DTLS private key") || err.contains("ECDSA"),
        "got: {err}"
    );
}

#[tokio::test]
async fn test_udp_logging_dtls_accepts_valid_ecdsa_material_and_caches() {
    ensure_crypto_provider();
    let (cert, key) = mint_ecdsa_p256_pair();
    let ca = write_temp_pem(&std::fs::read_to_string(cert.path()).expect("read cert as ca"));
    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_ca_cert_path": ca.path().to_str().unwrap(),
            "dtls_no_verify": false
        }),
        test_client(),
    )
    .expect("valid ECDSA DTLS material must construct");
    assert_eq!(plugin.name(), "udp_logging");
    validate_plugin_config(
        "udp_logging",
        &json!({
            "host": "127.0.0.1",
            "port": 9514,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_ca_cert_path": ca.path().to_str().unwrap()
        }),
    )
    .expect("validate_config must accept the same material without spawning issues");
}

#[tokio::test]
async fn test_udp_logging_dtls_rejects_malformed_ca_at_admission() {
    let (cert, key) = mint_ecdsa_p256_pair();
    let ca = write_temp_pem("not-a-ca");
    let err = UdpLogging::new(
        &json!({
            "host": "logs.example.com",
            "port": 9515,
            "dtls": true,
            "dtls_cert_path": cert.path().to_str().unwrap(),
            "dtls_key_path": key.path().to_str().unwrap(),
            "dtls_ca_cert_path": ca.path().to_str().unwrap()
        }),
        test_client(),
    )
    .err()
    .expect("malformed CA must fail admission");
    assert!(
        err.contains("DTLS CA materialization failed") || err.contains("No valid certificates"),
        "got: {err}"
    );
}

#[test]
fn test_udp_logging_file_dependency_phase_reports_bad_dtls_material() {
    let config = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "udp-deps".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            plugin_name: "udp_logging".to_string(),
            config: json!({
                "host": "127.0.0.1",
                "port": 9514,
                "dtls": true,
                "dtls_cert_path": "/missing/udp-cert.pem",
                "dtls_key_path": "/missing/udp-key.pem",
                "dtls_no_verify": true
            }),
            scope: PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        }],
        ..GatewayConfig::default()
    };
    let errors = config.validate_plugin_file_dependencies();
    assert!(
        errors
            .iter()
            .any(|e| e.contains("udp-deps") && e.contains("DTLS")),
        "file-dependency phase must surface DTLS material errors: {errors:?}"
    );

    let disabled = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            enabled: false,
            ..config.plugin_configs[0].clone()
        }],
        ..GatewayConfig::default()
    };
    assert!(
        disabled.validate_plugin_file_dependencies().is_empty(),
        "disabled udp_logging must skip DTLS file dependencies"
    );

    let plaintext = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            config: json!({"host": "127.0.0.1", "port": 9514, "dtls": false}),
            ..config.plugin_configs[0].clone()
        }],
        ..GatewayConfig::default()
    };
    assert!(
        plaintext.validate_plugin_file_dependencies().is_empty(),
        "plaintext udp_logging must not require DTLS sources"
    );
}

#[test]
fn test_udp_logging_dns_lifecycle_predicate() {
    let addr_a: SocketAddr = "127.0.0.1:9514".parse().unwrap();
    let addr_b: SocketAddr = "127.0.0.1:9515".parse().unwrap();
    let interval = Duration::from_secs(60);

    assert!(
        !ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            Duration::from_secs(30),
            Some(addr_a),
            addr_b,
            interval,
        ),
        "interval not elapsed"
    );
    assert!(
        !ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            interval,
            Some(addr_a),
            addr_a,
            interval,
        ),
        "unchanged address keeps association"
    );
    assert!(
        ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            interval,
            Some(addr_a),
            addr_b,
            interval,
        ),
        "changed address after interval replaces sender"
    );
}

#[tokio::test]
async fn test_udp_logging_plain_udp_dns_address_change_rebuilds_sender() {
    let listener_a = UdpSocket::bind("127.0.0.1:0").await.expect("bind a");
    let listener_b = UdpSocket::bind("127.0.0.1:0").await.expect("bind b");
    let addr_a = listener_a.local_addr().expect("addr a");
    let addr_b = listener_b.local_addr().expect("addr b");

    let plugin = UdpLogging::new(
        &json!({
            "host": "127.0.0.1",
            "port": addr_a.port(),
            "batch_size": 1,
            "flush_interval_ms": 50,
            "max_retries": 0,
            "buffer_capacity": 16
        }),
        test_client(),
    )
    .expect("construct");

    let summary = create_test_transaction_summary();
    plugin.log(&summary).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(plugin.current_addr_for_test(), Some(addr_a));

    plugin.set_next_resolve_addr_for_test(addr_b);
    plugin.age_last_resolve_for_test(Duration::from_secs(61));
    plugin.log(&summary).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        plugin.current_addr_for_test(),
        Some(addr_b),
        "plain UDP must rebuild the connected sender when DNS moves"
    );
}

#[test]
fn test_udp_logging_dtls_docs_retain_association_when_rebuild_fails() {
    // Runtime retain-on-failed-rebuild is covered by the warn path in
    // `send_batch` plus the docs contract below; the pure predicate pins the
    // unchanged-address half of the lifecycle.
    let addr: SocketAddr = "127.0.0.1:9514".parse().unwrap();
    assert!(
        !ferrum_edge::_test_support::udp_logging_should_replace_sender_on_resolve_for_test(
            Duration::from_secs(60),
            Some(addr),
            addr,
            Duration::from_secs(60),
        )
    );
    let docs = include_str!("../../../docs/plugins.md");
    assert!(docs.contains(
        "If re-resolution or the replacement handshake fails, the current sender is retained"
    ));
}

#[test]
fn test_udp_logging_dtls_batch_size_gate_classifies_send_reject_and_split() {
    let max = 16_384usize;
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            false,
            max + 1,
            8,
            max
        ),
        "send_as_is",
        "plain UDP must not apply the DTLS plaintext ceiling"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            true, max, 8, max
        ),
        "send_as_is",
        "in-limit DTLS batches send as one datagram"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            true,
            max + 1,
            1,
            max
        ),
        "reject_oversized_single",
        "oversized singles fail closed into retry/final-loss"
    );
    assert_eq!(
        ferrum_edge::_test_support::udp_logging_classify_dtls_batch_size_for_test(
            true,
            max + 1,
            2,
            max
        ),
        "split_per_entry",
        "oversized multi-entry batches fan out per entry without async recursion"
    );
}

#[tokio::test]
async fn test_dtls_connection_send_rejects_oversized_plaintext() {
    ensure_crypto_provider();
    let server_cert = dimpl::certificate::generate_self_signed_certificate().expect("server cert");
    let server_config = dimpl::Config::builder()
        .build()
        .expect("build server config");
    let frontend = ferrum_edge::dtls::FrontendDtlsConfig {
        dimpl_config: Arc::new(server_config),
        certificate: server_cert,
        client_cert_verifier: None,
    };
    let server = Arc::new(
        ferrum_edge::dtls::DtlsServer::bind("127.0.0.1:0".parse().unwrap(), frontend)
            .await
            .expect("dtls server"),
    );
    let server_addr = server.local_addr();
    let runner = server.clone();
    tokio::spawn(async move {
        let _ = runner.run().await;
    });
    let acceptor = server.clone();
    let accept = tokio::spawn(async move {
        let (conn, _) = acceptor.accept().await.expect("accept");
        conn
    });

    let client_socket = UdpSocket::bind("127.0.0.1:0").await.expect("client bind");
    client_socket.connect(server_addr).await.expect("connect");
    let client_cert = dimpl::certificate::generate_self_signed_certificate().expect("client cert");
    let params = ferrum_edge::dtls::BackendDtlsParams {
        config: Arc::new(dimpl::Config::default()),
        certificate: client_cert,
        server_name: None,
        server_cert_verifier: None,
        connect_timeout_ms: 10_000,
    };
    let client = ferrum_edge::dtls::DtlsConnection::connect(client_socket, params)
        .await
        .expect("handshake");
    let _server_conn = accept.await.expect("join accept");

    let max = ferrum_edge::dtls::max_plaintext_bytes();
    let oversized = vec![b'x'; max.saturating_add(1)];
    let err = client
        .send(&oversized)
        .await
        .err()
        .expect("oversized plaintext must fail");
    assert!(err.to_string().contains("max_plaintext"), "got: {err}");

    client
        .send(b"ok")
        .await
        .expect("in-limit send must succeed");
}

#[test]
fn test_udp_logging_docs_dns_and_delivery_contract() {
    let docs = include_str!("../../../docs/plugins.md");
    let section = docs
        .split("### `udp_logging`")
        .nth(1)
        .and_then(|rest| rest.split("\n### `").next())
        .expect("udp_logging section present");

    for needle in [
        "Both plain UDP and DTLS re-resolve",
        "fresh handshake",
        "retains the current sender",
        "local UDP socket",
        "FERRUM_DTLS_MAX_PLAINTEXT_BYTES",
        "split per entry",
        "co-batched siblings",
        "OptionalFailOpen",
        "materialized at admission",
        "File mode",
        "Database mode",
        "DP mode",
    ] {
        assert!(
            section.contains(needle),
            "docs/plugins.md udp_logging section missing `{needle}`"
        );
    }
    assert!(
        !section.contains("DTLS sessions are not re-handshaken mid-session"),
        "stale DTLS non-rehandshake wording must be removed"
    );
}
