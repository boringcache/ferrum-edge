//! Schema-aware plugin-configuration sensitivity contract
//! (GHSA-4988-2wph-67g2).
//!
//! These cover the projection itself. The role/audit/backup surfaces that
//! consume it are covered end to end in
//! `tests/integration/admin_audit_rbac_tests.rs`.

use ferrum_edge::admin::plugin_config_projection::{
    KAFKA_SAFE_PRODUCER_PROPERTIES, PLUGIN_SENSITIVITY_SCHEMAS, is_safe_kafka_producer_property,
    project_plugin_config, redact_endpoint_url, sensitivity_rules_for,
};
use ferrum_edge::plugins::builtin_parity::BUILTIN_PLUGIN_PARITY_META;
use serde_json::{Value, json};

const REDACTED: &str = "[REDACTED]";

fn project(plugin: &str, config: Value) -> Value {
    let mut projected = config;
    project_plugin_config(plugin, &mut projected);
    projected
}

/// Assert none of `canaries` survives anywhere in the projected document.
fn assert_no_canaries(projected: &Value, canaries: &[&str]) {
    let serialized = projected.to_string();
    for canary in canaries {
        assert!(
            !serialized.contains(canary),
            "projection leaked {canary}: {serialized}"
        );
    }
}

// ---------------------------------------------------------------------------
// Future built-in parity
// ---------------------------------------------------------------------------

/// A new built-in plugin must not be able to ship without an explicit
/// sensitivity decision. This is the gate that keeps the contract exhaustive
/// instead of drifting back into name guessing.
#[test]
fn every_builtin_plugin_has_a_sensitivity_schema_entry() {
    let missing: Vec<&str> = BUILTIN_PLUGIN_PARITY_META
        .iter()
        .map(|meta| meta.name)
        .filter(|name| {
            !PLUGIN_SENSITIVITY_SCHEMAS
                .iter()
                .any(|(schema_name, _)| schema_name == name)
        })
        .collect();
    assert!(
        missing.is_empty(),
        "built-in plugins without a sensitivity schema entry (add one to \
         PLUGIN_SENSITIVITY_SCHEMAS, using the empty rule set if nothing in the \
         plugin's config is credential-bearing): {missing:?}"
    );
}

/// The reverse direction: a schema entry for a plugin that no longer exists is
/// dead weight that hides a real gap behind a passing parity test.
#[test]
fn sensitivity_schema_has_no_entries_for_unknown_plugins() {
    let unknown: Vec<&str> = PLUGIN_SENSITIVITY_SCHEMAS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| {
            !BUILTIN_PLUGIN_PARITY_META
                .iter()
                .any(|meta| meta.name == *name)
        })
        .collect();
    assert!(
        unknown.is_empty(),
        "sensitivity schema entries for unknown plugins: {unknown:?}"
    );
}

#[test]
fn sensitivity_schema_has_no_duplicate_plugin_entries() {
    let mut names: Vec<&str> = PLUGIN_SENSITIVITY_SCHEMAS.iter().map(|(n, _)| *n).collect();
    names.sort_unstable();
    let before = names.len();
    names.dedup();
    assert_eq!(before, names.len(), "duplicate plugin entries in schema");
}

#[test]
fn unknown_custom_plugins_get_no_schema_rules_but_still_project() {
    assert!(sensitivity_rules_for("some_custom_plugin").is_empty());

    let projected = project(
        "some_custom_plugin",
        json!({
            "api_key": "custom-plugin-api-key-canary",
            "sink_url": "https://user:custom-plugin-userinfo-canary@sink.example.com/ingest",
            "batch_size": 50
        }),
    );
    // Heuristic layer still fires for custom plugins.
    assert_eq!(projected["api_key"], REDACTED);
    // Structural URL sweep still strips userinfo on a path no rule names.
    assert_eq!(
        projected["sink_url"],
        "https://redacted@sink.example.com/ingest"
    );
    // Safe-value control: ordinary tuning survives.
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(
        &projected,
        &[
            "custom-plugin-api-key-canary",
            "custom-plugin-userinfo-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Structural URL projection
// ---------------------------------------------------------------------------

#[test]
fn endpoint_url_projection_keeps_only_origin_and_structural_markers() {
    assert_eq!(
        redact_endpoint_url("https://user:pw@collector.example.com:4318/v1/traces?k=v#frag"),
        "https://collector.example.com:4318/[REDACTED_PATH]?[REDACTED_QUERY]#[REDACTED_FRAGMENT]"
    );
    // No path/query/fragment means no markers — the origin alone is emitted.
    assert_eq!(
        redact_endpoint_url("https://collector.example.com"),
        "https://collector.example.com"
    );
    assert_eq!(
        redact_endpoint_url("https://collector.example.com/"),
        "https://collector.example.com"
    );
    // IPv6 literals keep their brackets so the value stays a parseable origin.
    assert_eq!(
        redact_endpoint_url("https://[2001:db8::1]:8443/ingest"),
        "https://[2001:db8::1]:8443/[REDACTED_PATH]"
    );
    // Non-HTTP schemes are projected the same way.
    assert_eq!(
        redact_endpoint_url("ldaps://ldap.example.com:636/dc=example"),
        "ldaps://ldap.example.com:636/[REDACTED_PATH]"
    );
}

#[test]
fn endpoint_url_projection_fails_closed_for_unparseable_and_hostless_values() {
    assert_eq!(redact_endpoint_url("not a url at all"), REDACTED);
    assert_eq!(redact_endpoint_url(""), REDACTED);
    // No host to anchor the diagnostic on.
    assert_eq!(redact_endpoint_url("mailto:ops@example.com"), REDACTED);
}

// ---------------------------------------------------------------------------
// Advisory-named surfaces
// ---------------------------------------------------------------------------

#[test]
fn serverless_function_keys_and_trigger_urls_are_projected() {
    let projected = project(
        "serverless_function",
        json!({
            "provider": "azure_functions",
            "function_url": "https://fn.example.net/api/serverless-path-canary?code=serverless-query-canary",
            "azure_function_key": "serverless-function-key-canary",
            "timeout_ms": 3000
        }),
    );
    assert_eq!(
        projected["function_url"],
        "https://fn.example.net/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(projected["azure_function_key"], REDACTED);
    assert_eq!(projected["timeout_ms"], 3000);
    assert_eq!(projected["provider"], "azure_functions");
    assert_no_canaries(
        &projected,
        &[
            "serverless-path-canary",
            "serverless-query-canary",
            "serverless-function-key-canary",
        ],
    );
}

#[test]
fn http_logging_endpoint_and_every_custom_header_value_are_projected() {
    let projected = project(
        "http_logging",
        json!({
            "endpoint_url": "https://collector.example.com/ingest/http-path-canary?key=http-query-canary",
            "custom_headers": {
                // No substring pattern matches this vendor header name.
                "x-honeycomb-team": "http-header-canary",
                "X-Tenant": "http-tenant-canary"
            },
            "batch_size": 50
        }),
    );
    assert_eq!(
        projected["endpoint_url"],
        "https://collector.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(projected["custom_headers"]["x-honeycomb-team"], REDACTED);
    assert_eq!(projected["custom_headers"]["X-Tenant"], REDACTED);
    // Header NAMES stay visible; only values are secret.
    assert!(
        projected["custom_headers"]
            .as_object()
            .expect("headers object")
            .contains_key("x-honeycomb-team")
    );
    assert_eq!(projected["batch_size"], 50);
    assert_no_canaries(
        &projected,
        &[
            "http-path-canary",
            "http-query-canary",
            "http-header-canary",
            "http-tenant-canary",
        ],
    );
}

#[test]
fn otel_header_values_are_secret_by_default_regardless_of_name() {
    let projected = project(
        "otel_tracing",
        json!({
            "endpoint": "https://api.honeycomb.io/v1/traces",
            "headers": {
                "x-honeycomb-team": "otel-honeycomb-canary",
                "dd-api-key": "otel-datadog-canary",
                "lightstep-access-token": "otel-lightstep-canary",
                "x-tenant": "otel-tenant-canary"
            },
            "batch_size": 50,
            "include_url_path": true
        }),
    );
    for name in [
        "x-honeycomb-team",
        "dd-api-key",
        "lightstep-access-token",
        "x-tenant",
    ] {
        assert_eq!(projected["headers"][name], REDACTED, "header {name}");
    }
    assert_eq!(projected["batch_size"], 50);
    assert_eq!(projected["include_url_path"], true);
    assert_no_canaries(
        &projected,
        &[
            "otel-honeycomb-canary",
            "otel-datadog-canary",
            "otel-lightstep-canary",
            "otel-tenant-canary",
        ],
    );
}

#[test]
fn proxy_alerts_generic_webhook_url_headers_and_body_template_are_projected() {
    let projected = project(
        "proxy_alerts",
        json!({
            "channels": {
                "generic": {
                    "type": "webhook",
                    // Generic key `url`, not `webhook_url`: no substring match.
                    "url": "https://hooks.example.com/services/alerts-path-canary?t=alerts-query-canary",
                    "headers": {
                        "x-routing-key": "alerts-header-canary"
                    },
                    "body_template": "{\"routing_key\":\"alerts-template-canary\",\"msg\":\"${message}\"}",
                    "method": "POST"
                },
                "ops-slack": {
                    "type": "slack",
                    "webhook_url": "https://hooks.slack.com/services/T0/B0/alerts-slack-canary"
                }
            },
            "rules": [{"name": "5xx", "type": "error_rate", "threshold": 5}]
        }),
    );
    let generic = &projected["channels"]["generic"];
    assert_eq!(
        generic["url"],
        "https://hooks.example.com/[REDACTED_PATH]?[REDACTED_QUERY]"
    );
    assert_eq!(generic["headers"]["x-routing-key"], REDACTED);
    assert_eq!(generic["body_template"], REDACTED);
    // Safe-value controls: channel type/method and rules stay readable.
    assert_eq!(generic["type"], "webhook");
    assert_eq!(generic["method"], "POST");
    assert_eq!(projected["rules"][0]["name"], "5xx");
    assert_eq!(projected["rules"][0]["threshold"], 5);
    // The name-heuristic layer already fully redacts `webhook_url`; the schema
    // must not weaken that to a structural projection.
    assert_eq!(projected["channels"]["ops-slack"]["webhook_url"], REDACTED);
    assert_no_canaries(
        &projected,
        &[
            "alerts-path-canary",
            "alerts-query-canary",
            "alerts-header-canary",
            "alerts-template-canary",
            "alerts-slack-canary",
        ],
    );
}

#[test]
fn proxy_alerts_array_shaped_channels_are_projected_too() {
    let projected = project(
        "proxy_alerts",
        json!({
            "channels": [
                {
                    "type": "webhook",
                    "url": "https://hooks.example.com/array-path-canary",
                    "headers": {"x-routing-key": "array-header-canary"},
                    "body_template": "array-template-canary"
                }
            ]
        }),
    );
    assert_eq!(
        projected["channels"][0]["url"],
        "https://hooks.example.com/[REDACTED_PATH]"
    );
    assert_eq!(projected["channels"][0]["headers"]["x-routing-key"], REDACTED);
    assert_eq!(projected["channels"][0]["body_template"], REDACTED);
    assert_no_canaries(
        &projected,
        &[
            "array-path-canary",
            "array-header-canary",
            "array-template-canary",
        ],
    );
}

// ---------------------------------------------------------------------------
// Kafka producer properties
// ---------------------------------------------------------------------------

#[test]
fn kafka_producer_properties_redact_everything_outside_the_safe_allow_list() {
    let projected = project(
        "kafka_logging",
        json!({
            "broker_list": "broker.example.com:9093",
            "topic": "ferrum-logs",
            "security_protocol": "sasl_ssl",
            "producer_config": {
                // librdkafka marks each of these sensitive.
                "ssl.key.pem": "-----BEGIN PRIVATE KEY-----kafka-pem-canary-----END PRIVATE KEY-----",
                "ssl.key.password": "kafka-keypw-canary",
                "ssl.keystore.password": "kafka-keystorepw-canary",
                "sasl.password": "kafka-saslpw-canary",
                "sasl.oauthbearer.config": "kafka-oauth-canary",
                // Matches no name heuristic at all: only the allow-list saves it.
                "sasl.kerberos.keytab": "kafka-keytab-canary",
                // Safe tuning knobs survive as operator diagnostics.
                "linger.ms": "20",
                "compression.type": "lz4",
                "queue.buffering.max.messages": "100000"
            }
        }),
    );
    let props = &projected["producer_config"];
    for sensitive in [
        "ssl.key.pem",
        "ssl.key.password",
        "ssl.keystore.password",
        "sasl.password",
        "sasl.oauthbearer.config",
        "sasl.kerberos.keytab",
    ] {
        assert_eq!(props[sensitive], REDACTED, "property {sensitive}");
    }
    assert_eq!(props["linger.ms"], "20");
    assert_eq!(props["compression.type"], "lz4");
    assert_eq!(props["queue.buffering.max.messages"], "100000");
    assert_eq!(projected["topic"], "ferrum-logs");
    assert_eq!(projected["broker_list"], "broker.example.com:9093");
    assert_no_canaries(
        &projected,
        &[
            "kafka-pem-canary",
            "kafka-keypw-canary",
            "kafka-keystorepw-canary",
            "kafka-saslpw-canary",
            "kafka-oauth-canary",
            "kafka-keytab-canary",
        ],
    );
}

/// The allow-list is the load-bearing half of the Kafka rule: a stray entry
/// silently un-redacts a property forever.
#[test]
fn kafka_safe_property_allow_list_holds_no_credential_shaped_names() {
    for safe in KAFKA_SAFE_PRODUCER_PROPERTIES {
        for marker in [
            "password", "secret", "key", "pem", "token", "cert", "auth", "sasl", "ssl",
        ] {
            assert!(
                !safe.contains(marker),
                "allow-listed producer property {safe} contains credential marker {marker}"
            );
        }
    }
    assert!(is_safe_kafka_producer_property("LINGER.MS"));
    assert!(is_safe_kafka_producer_property(" linger.ms "));
    assert!(!is_safe_kafka_producer_property("ssl.key.pem"));
    assert!(!is_safe_kafka_producer_property("sasl.oauthbearer.config"));
    assert!(!is_safe_kafka_producer_property("sasl.kerberos.keytab"));
}

#[test]
fn kafka_non_object_producer_config_fails_closed() {
    let projected = project(
        "kafka_logging",
        json!({"producer_config": "kafka-scalar-canary"}),
    );
    assert_eq!(projected["producer_config"], REDACTED);
    assert_no_canaries(&projected, &["kafka-scalar-canary"]);
}

// ---------------------------------------------------------------------------
// Shape handling: nesting, arrays, case/delimiter variants, fail-closed
// ---------------------------------------------------------------------------

#[test]
fn schema_paths_match_case_and_delimiter_variants() {
    for spelling in [
        "custom_headers",
        "custom-headers",
        "customHeaders",
        "CUSTOM_HEADERS",
        "custom.headers",
    ] {
        let mut config = serde_json::Map::new();
        config.insert(
            spelling.to_string(),
            json!({"x-scope-orgid": "loki-variant-canary"}),
        );
        let projected = project("loki_logging", Value::Object(config));
        assert_eq!(
            projected[spelling]["x-scope-orgid"], REDACTED,
            "spelling {spelling} bypassed the schema"
        );
        assert_no_canaries(&projected, &["loki-variant-canary"]);
    }
}

#[test]
fn nested_and_array_wrapped_endpoint_values_fail_closed() {
    // A header map that is not a map cannot be classified per-entry.
    let projected = project(
        "otel_tracing",
        json!({"headers": "otel-scalar-headers-canary"}),
    );
    assert_eq!(projected["headers"], REDACTED);
    assert_no_canaries(&projected, &["otel-scalar-headers-canary"]);

    // An endpoint that is an array of nested objects is replaced wholesale
    // rather than walked, so a credential at any depth cannot survive.
    let projected = project(
        "otel_tracing",
        json!({"endpoint": [null, {"nested": "https://c.example/x?code=otel-nested-canary"}]}),
    );
    assert_eq!(projected["endpoint"], REDACTED);
    assert_no_canaries(&projected, &["otel-nested-canary"]);
}

#[test]
fn null_values_are_preserved_and_null_config_is_untouched() {
    let projected = project(
        "otel_tracing",
        json!({"endpoint": null, "authorization": null, "headers": null}),
    );
    assert!(projected["endpoint"].is_null());
    assert!(projected["authorization"].is_null());
    assert!(projected["headers"].is_null());

    let mut null_config = Value::Null;
    project_plugin_config("otel_tracing", &mut null_config);
    assert!(null_config.is_null());
}

#[test]
fn non_object_configs_are_replaced_wholesale() {
    for shape in [
        json!("scalar-config-canary"),
        json!(["array-config-canary", {"nested": "nested-config-canary"}]),
        json!(42),
        json!(true),
    ] {
        let projected = project("loki_logging", shape);
        assert_eq!(projected, json!(REDACTED));
    }
}

#[test]
fn url_userinfo_is_stripped_on_paths_no_rule_names() {
    let projected = project(
        "mcp_gateway",
        json!({
            // Not in any rule for this plugin.
            "discovery": {
                "peers": [
                    "https://svc:userinfo-array-canary@peer.example.com/mcp",
                    "https://plain.example.com/mcp"
                ]
            },
            "upstream_url": "https://svc:upstream-userinfo-canary@up.example.com/mcp"
        }),
    );
    assert_eq!(
        projected["discovery"]["peers"][0],
        "https://redacted@peer.example.com/mcp"
    );
    // Safe-value control: a URL without userinfo is untouched by the sweep.
    assert_eq!(
        projected["discovery"]["peers"][1],
        "https://plain.example.com/mcp"
    );
    // The schema rule wins on the named path: no userinfo and no path.
    assert_eq!(projected["upstream_url"], "https://up.example.com/[REDACTED_PATH]");
    assert_no_canaries(
        &projected,
        &["userinfo-array-canary", "upstream-userinfo-canary"],
    );
}

/// Header *name* lists are not credentials. Redacting them would break routing
/// configuration readability and is exactly the mistake a substring-only rule
/// makes.
#[test]
fn header_name_lists_are_not_redacted() {
    let projected = project(
        "cors",
        json!({
            "allowed_headers": ["authorization", "content-type"],
            "exposed_headers": ["x-request-id"]
        }),
    );
    assert_eq!(
        projected["allowed_headers"],
        json!(["authorization", "content-type"])
    );
    assert_eq!(projected["exposed_headers"], json!(["x-request-id"]));

    let projected = project(
        "rate_limiting",
        json!({"expose_headers": true, "limit_by": "ip"}),
    );
    assert_eq!(projected["expose_headers"], true);
    assert_eq!(projected["limit_by"], "ip");
}

/// The documented Redis projection shape must survive the refactor: it is
/// pinned by `docs/admin_api.md` and matches the Redis client's log fields.
#[test]
fn redis_url_keeps_its_documented_projection_shape() {
    let projected = project(
        "rate_limiting",
        json!({
            "redis_url": "redis://cacheuser:redis-userinfo-canary@cache.internal:6379/3?token=redis-query-canary#redis-frag-canary",
            "redis_username": "cacheuser",
            "sync_mode": "redis"
        }),
    );
    assert_eq!(
        projected["redis_url"],
        "redis://redacted@cache.internal:6379/3"
    );
    // `redis_username` is not secret material and stays visible.
    assert_eq!(projected["redis_username"], "cacheuser");
    assert_eq!(projected["sync_mode"], "redis");
    assert_no_canaries(
        &projected,
        &[
            "redis-userinfo-canary",
            "redis-query-canary",
            "redis-frag-canary",
        ],
    );
}
