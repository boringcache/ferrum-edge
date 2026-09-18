use ferrum_edge::plugins::validate_plugin_config;
use ferrum_edge::startup::render_startup_error;
use serde_json::json;

#[test]
fn cors_unknown_keys_are_supplied_values_not_schema_labels() {
    for key in ["UNREGISTERED_CORS_KEY", "'\"`UNREGISTERED_CORS_KEY"] {
        let mut config = json!({"allowed_origins": ["https://example.com"]});
        config.as_object_mut().unwrap().insert(key.into(), json!(true));
        let error = validate_plugin_config("cors", &config).unwrap_err();
        let rendered = render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains("unknown configuration key"), "{rendered}");
        assert!(rendered.contains("<redacted scalar>"), "{rendered}");
        assert!(!rendered.contains("UNREGISTERED_CORS_KEY"), "{rendered}");
    }
}

#[test]
fn waf_custom_pattern_sets_do_not_retain_regex_library_errors() {
    for (target, set) in [("url_path", "url_path"), ("body_text", "body_bytes")] {
        let config = json!({"include_default_rules": false, "custom_rules": [{
            "id": "fixture", "category": "test", "target": target,
            "pattern": "UNREGISTERED_PATTERN_5591["
        }]});
        let error = validate_plugin_config("waf", &config).unwrap_err();
        assert!(!error.contains("UNREGISTERED_PATTERN_5591"), "{error}");
        let rendered = render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains("`pattern`"), "{rendered}");
        assert!(rendered.contains(&format!("`{set}`")), "{rendered}");
        assert!(rendered.contains("rule indexes [0]"), "{rendered}");
        assert!(rendered.contains("invalid or too complex"), "{rendered}");
    }
}

#[test]
fn constructor_object_guards_withhold_complete_json_values() {
    for plugin in [
        "access_control",
        "adaptive_concurrency",
        "geo_restriction",
        "grpc_method_router",
        "hmac_auth",
        "jwks_auth",
        "jwt_auth",
        "key_auth",
        "oauth2_introspection",
        "oidc_relying_party",
        "rate_limiting",
        "tcp_connection_throttle",
    ] {
        for value in [
            json!(918273641),
            json!(["'UNREGISTERED_DIAGNOSTIC_TOKEN", 918273641]),
        ] {
            let error = validate_plugin_config(plugin, &value).unwrap_err();
            let rendered = render_startup_error(anyhow::anyhow!(error), &[]);
            assert!(
                rendered.contains("must be an object"),
                "{plugin}: {rendered}"
            );
            assert!(
                rendered.contains("<redacted scalar>"),
                "{plugin}: {rendered}"
            );
            assert!(!rendered.contains("918273641"), "{plugin}: {rendered}");
            assert!(
                !rendered.contains("UNREGISTERED_DIAGNOSTIC_TOKEN"),
                "{rendered}"
            );
        }
    }
}

#[test]
fn constructor_numeric_bounds_withhold_supplied_values() {
    let cases = [
        (
            "bot_detection",
            json!({"custom_response_code": 918273641}),
            "custom_response_code",
        ),
        (
            "grpc_web",
            json!({"expose_headers": [918273641]}),
            "expose_headers[0]",
        ),
        (
            "fault_injection",
            json!({"abort": {"status_code": 918273641}}),
            "status_code",
        ),
        (
            "ai_token_metrics",
            json!({"cost_per_prompt_token": -918273641}),
            "cost_per_prompt_token",
        ),
        (
            "response_mock",
            json!({"rules": [{"path": "/", "delay_ms": 918273641}]}),
            "delay_ms",
        ),
    ];
    for (plugin, config, field) in cases {
        let error = validate_plugin_config(plugin, &config).unwrap_err();
        let rendered = render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(field), "{plugin}: {rendered}");
        assert!(!rendered.contains("918273641"), "{plugin}: {rendered}");
    }
}

#[test]
fn waf_rule_and_exemption_diagnostics_withhold_quote_bearing_values() {
    let token = "'UNREGISTERED_DIAGNOSTIC_TOKEN";
    for (config, reason) in [
        (
            json!({"disabled_default_rules": [token]}),
            "unknown default rule",
        ),
        (
            json!({"global_exemptions": {"ips": [token]}}),
            "invalid IP/CIDR",
        ),
        (
            json!({"custom_rules": [{"id": token, "category": "test"}]}),
            "requires",
        ),
        (
            json!({"custom_rules": [{
                "id": token, "category": "test", "target": "body_text", "pattern": "ok",
                "fp_filters": [format!("{token}[")]
            }]}),
            "`fp_filters`",
        ),
    ] {
        let error = validate_plugin_config("waf", &config).unwrap_err();
        let rendered = render_startup_error(anyhow::anyhow!(error), &[]);
        assert!(rendered.contains(reason), "{rendered}");
        assert!(
            !rendered.contains("UNREGISTERED_DIAGNOSTIC_TOKEN"),
            "{rendered}"
        );
    }
}
