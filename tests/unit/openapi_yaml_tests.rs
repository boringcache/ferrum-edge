use serde_json::json;
use serde_yaml::Value;
use std::collections::{BTreeMap, BTreeSet};

fn get_path<'a>(value: &'a Value, path: &[&str]) -> &'a Value {
    let mut current = value;
    for key in path {
        current = current
            .get(Value::String((*key).to_string()))
            .unwrap_or_else(|| panic!("missing OpenAPI path component: {key}"));
    }
    current
}

#[test]
fn waf_scoring_weights_reject_unknown_severities() {
    let spec: Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let weights = get_path(
        &spec,
        &[
            "components",
            "schemas",
            "WafPluginConfig",
            "properties",
            "scoring",
            "properties",
            "weights",
        ],
    );

    assert_eq!(
        weights
            .get(Value::String("additionalProperties".to_string()))
            .and_then(Value::as_bool),
        Some(false)
    );
}

#[test]
fn access_control_schema_matches_runtime_validation() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let schema = spec
        .pointer("/components/schemas/AccessControlConfig")
        .expect("missing AccessControlConfig schema");
    let validator = jsonschema::draft202012::options()
        .build(schema)
        .expect("AccessControlConfig schema compiles");

    for config in [
        json!({"allowed_consumers": ["alice"]}),
        json!({"disallowed_consumers": ["bad"], "allow_authenticated_identity": true}),
        json!({"allow_authenticated_identity": true}),
        json!({"allow_authenticated_identity": true, "allowed_consumers": []}),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    for config in [
        json!({}),
        json!({"allowed_consumer": ["alice"]}),
        json!({"allowed_consumers": [], "allowed_groups": []}),
        json!({"allowed_consumers": ["alice"], "allow_authenticated_identity": true}),
        json!({"allowed_groups": ["engineering"], "allow_authenticated_identity": true}),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
    }
}

#[test]
fn ai_tool_governor_schema_matches_runtime_invariants() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/AiToolGovernorConfig"
    });
    schema
        .as_object_mut()
        .expect("schema should be object")
        .insert("components".to_string(), spec["components"].clone());
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("AiToolGovernorConfig schema compiles");

    for config in [
        json!({
            "enabled": false,
            "mode": "ignored-invalid-mode",
            "default_action": "ignored-invalid-action",
            "tools": {"": {"action": "ignored-invalid-action"}},
            "inspect": "ignored-invalid-inspection",
            "approval": "ignored-invalid-approval"
        }),
        json!({"default_action": "deny", "tools": {}}),
        json!({"tools": {"search": {"action": "allow"}}}),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "required_args": ["query"],
                    "blocked_arg_patterns": [{"name": "secret", "regex": "secret"}]
                }
            }
        }),
        json!({
            "default_action": "allow",
            "tools": {"deploy": {"action": "require_approval"}},
            "inspect": {"request_tool_definitions": true, "response_tool_calls": false}
        }),
        json!({
            "mode": "dry_run",
            "tools": {"deploy": {"action": "require_approval"}}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "https://approval.example/decide"}
        }),
    ] {
        assert!(
            validator.validate(&config).is_ok(),
            "config should be valid: {config}"
        );
    }

    for config in [
        json!({
            "tools": {"search": {"action": "allow"}},
            "inspect": {
                "request_tool_definitions": false,
                "response_tool_calls": false,
                "streaming_response_tool_calls": false,
                "mcp_tool_calls": false,
                "a2a_methods": false
            }
        }),
        json!({"default_action": "allow"}),
        json!({"default_action": "allow", "tools": {}}),
        json!({"tools": {"": {"action": "deny"}}}),
        json!({"tools": {"search": {"action": "redact_args"}}}),
        json!({
            "tools": {"search": {"action": "redact_args", "blocked_arg_patterns": []}}
        }),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{"name": "", "regex": "secret"}]
                }
            }
        }),
        json!({
            "tools": {
                "search": {
                    "action": "redact_args",
                    "blocked_arg_patterns": [{"name": "secret", "regex": ""}]
                }
            }
        }),
        json!({"tools": {"deploy": {"action": "require_approval"}}}),
        json!({"default_action": "require_approval", "tools": {}}),
        json!({"tools": {"search": {"action": "allow", "required_args": [""]}}}),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": ""}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "ftp://approval.example/decide"}
        }),
        json!({
            "tools": {"deploy": {"action": "require_approval"}},
            "approval": {"endpoint_url": "https:///decide"}
        }),
    ] {
        assert!(
            validator.validate(&config).is_err(),
            "config should be invalid: {config}"
        );
    }
}

fn plugin_config_schema_mapping(spec: &serde_json::Value) -> BTreeMap<String, String> {
    let all_of = spec
        .pointer("/components/schemas/PluginConfig/allOf")
        .and_then(serde_json::Value::as_array)
        .expect("PluginConfig allOf should be an array");

    let mut mapping = BTreeMap::new();
    for entry in all_of {
        let plugin_name = entry
            .pointer("/if/properties/plugin_name/const")
            .and_then(serde_json::Value::as_str)
            .expect("PluginConfig conditional should name a plugin");
        let schema_ref = entry
            .pointer("/then/properties/config/$ref")
            .and_then(serde_json::Value::as_str)
            .expect("PluginConfig conditional should constrain config");

        assert!(
            mapping
                .insert(plugin_name.to_string(), schema_ref.to_string())
                .is_none(),
            "duplicate PluginConfig schema conditional for {plugin_name}"
        );
    }

    mapping
}

#[test]
fn plugin_config_schema_maps_every_builtin_plugin() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let custom_plugins: BTreeSet<_> = ferrum_edge::custom_plugins::custom_plugin_names()
        .into_iter()
        .collect();
    let builtins: BTreeSet<_> = ferrum_edge::plugins::available_plugins()
        .into_iter()
        .filter(|name| !custom_plugins.contains(name))
        .collect();

    let mapping = plugin_config_schema_mapping(&spec);
    let documented: BTreeSet<_> = mapping.keys().map(String::as_str).collect();

    assert_eq!(
        documented, builtins,
        "PluginConfig schema conditionals should cover every built-in plugin"
    );
    assert!(
        !mapping.contains_key("semantic_ai_firewall"),
        "undocumented ai_semantic_firewall alias must not re-enter OpenAPI"
    );

    for (plugin_name, schema_ref) in mapping {
        let schema_name = schema_ref
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("PluginConfig ref for {plugin_name} is not local"));
        let pointer = format!("/components/schemas/{schema_name}");
        assert!(
            spec.pointer(&pointer).is_some(),
            "PluginConfig ref for {plugin_name} points to missing schema {schema_name}"
        );
    }
}

#[test]
fn plugin_config_schema_applies_plugin_specific_config() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mut schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": "#/components/schemas/PluginConfig"
    });
    schema
        .as_object_mut()
        .expect("schema should be object")
        .insert("components".to_string(), spec["components"].clone());

    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .expect("PluginConfig schema compiles");
    let plugin_config =
        |plugin_name: &str, config: Option<serde_json::Value>| -> serde_json::Value {
            let mut value = json!({
                "plugin_name": plugin_name,
                "scope": "global",
                "enabled": true
            });
            if let Some(config) = config {
                value
                    .as_object_mut()
                    .expect("plugin config should be object")
                    .insert("config".to_string(), config);
            }
            value
        };

    let valid = json!({
        "plugin_name": "ws_message_size_limiting",
        "scope": "global",
        "enabled": true,
        "config": {"max_frame_bytes": 1024}
    });
    assert!(validator.validate(&valid).is_ok(), "config should be valid");

    let invalid = json!({
        "plugin_name": "ws_message_size_limiting",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    assert!(
        validator.validate(&invalid).is_err(),
        "ws_message_size_limiting should require max_frame_bytes through PluginConfig"
    );

    for (plugin_name, config) in [
        ("udp_rate_limiting", json!({"datagrams_per_second": 100})),
        (
            "fault_injection",
            json!({"abort": {"status_code": 503, "percentage": 5.0}}),
        ),
        ("ai_rate_limiter", json!({"token_limit": 100000})),
        ("ai_request_guard", json!({"max_tokens_limit": 2048})),
        ("ai_response_guard", json!({"require_json": true})),
        ("ai_semantic_firewall", json!({"enabled": false})),
        (
            "ai_semantic_firewall",
            json!({
                "provider": {
                    "type": "openai_compatible_embeddings",
                    "endpoint": "https://embeddings.example/v1"
                }
            }),
        ),
    ] {
        let value = plugin_config(plugin_name, Some(config));
        assert!(
            validator.validate(&value).is_ok(),
            "{plugin_name} config should be valid: {value}"
        );
    }

    for (plugin_name, config) in [
        ("udp_rate_limiting", None),
        ("udp_rate_limiting", Some(json!({}))),
        ("fault_injection", None),
        ("fault_injection", Some(json!({}))),
        ("ai_rate_limiter", None),
        ("ai_rate_limiter", Some(json!({}))),
        ("ai_rate_limiter", Some(json!({"token_limit": 0}))),
        ("ai_request_guard", None),
        ("ai_request_guard", Some(json!({}))),
        ("ai_request_guard", Some(json!({"allowed_models": []}))),
        (
            "ai_request_guard",
            Some(json!({"require_user_field": false})),
        ),
        ("ai_response_guard", None),
        ("ai_response_guard", Some(json!({}))),
        ("ai_response_guard", Some(json!({"require_json": false}))),
        ("ai_response_guard", Some(json!({"blocked_phrases": []}))),
        ("ai_semantic_firewall", None),
        ("ai_semantic_firewall", Some(json!({}))),
    ] {
        let value = plugin_config(plugin_name, config);
        assert!(
            validator.validate(&value).is_err(),
            "{plugin_name} config should be invalid: {value}"
        );
    }

    let custom = json!({
        "plugin_name": "custom_observer",
        "scope": "global",
        "enabled": true,
        "config": {}
    });
    assert!(
        validator.validate(&custom).is_ok(),
        "custom plugins should keep generic PluginConfig config shape"
    );
}

#[tokio::test]
async fn runtime_valid_builtin_plugin_fixtures_match_their_openapi_schemas() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mapping = plugin_config_schema_mapping(&spec);
    let mut exercised = 0usize;

    for (plugin_name, schema_ref) in mapping {
        let config = super::plugins::minimal_plugin_config(&plugin_name);
        let Ok(Some(_plugin)) = ferrum_edge::plugins::create_plugin(&plugin_name, &config) else {
            continue;
        };
        let component = schema_ref
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("PluginConfig ref for {plugin_name} is not local"));
        assert_component_validity(&spec, component, &config, true);
        exercised += 1;
    }

    assert!(
        exercised >= 50,
        "expected broad plugin-schema coverage, exercised only {exercised} built-ins"
    );
}

#[tokio::test]
async fn optional_builtin_plugin_fields_match_runtime_and_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let mapping = plugin_config_schema_mapping(&spec);
    let fixtures = [
        (
            "body_validator",
            json!({"grpc_max_decompressed_size_bytes": 0}),
        ),
        (
            "load_testing",
            json!({
                "key": "test-key",
                "concurrent_clients": 1,
                "duration_seconds": 1,
                "max_response_body_bytes": 1024
            }),
        ),
        (
            "request_mirror",
            json!({"mirror_host": "mirror.example", "max_in_flight": 8}),
        ),
        (
            "request_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "x-audit",
                    "value": "enabled"
                }],
                "runtime_overlay_scope": "ferrum.transform.request",
                "default_enabled": false
            }),
        ),
        (
            "response_transformer",
            json!({
                "rules": [{
                    "operation": "add",
                    "target": "header",
                    "key": "x-audit",
                    "value": "enabled"
                }],
                "runtime_overlay_scope": "ferrum.transform.response",
                "default_enabled": false
            }),
        ),
        (
            "serverless_function",
            json!({
                "provider": "aws_lambda",
                "aws_region": "us-east-1",
                "aws_access_key_id": "test-access-key",
                "aws_secret_access_key": "test-secret-key",
                "aws_function_name": "test-function",
                "aws_endpoint_url": "http://127.0.0.1:4566"
            }),
        ),
        (
            "mesh_authz",
            json!({
                "mesh_policies": [],
                "per_pod_policy_scoping": true,
                "ambient_udp_source_scoping": true,
                "cluster_domain": "cluster.local",
                "cluster_domains": ["cluster.local", "cluster.internal"],
                "node_waypoint_route_upstreams": [{
                    "id": "istio-vs-upstream-reviews",
                    "namespace": "ferrum",
                    "targets": [{
                        "host": "10.0.0.10",
                        "port": 8080,
                        "service_namespace": "ferrum",
                        "service_name": "reviews",
                        "service_port": 80
                    }]
                }]
            }),
        ),
    ];

    for (plugin_name, optional_fields) in fixtures {
        let mut config = super::plugins::minimal_plugin_config(plugin_name);
        let config_object = config
            .as_object_mut()
            .unwrap_or_else(|| panic!("minimal {plugin_name} config is not an object"));
        config_object.extend(
            optional_fields
                .as_object()
                .unwrap_or_else(|| panic!("optional {plugin_name} fields are not an object"))
                .clone(),
        );
        let created = ferrum_edge::plugins::create_plugin(plugin_name, &config)
            .unwrap_or_else(|error| panic!("runtime rejected {plugin_name} fixture: {error}"));
        assert!(created.is_some(), "missing built-in plugin {plugin_name}");
        let schema_ref = mapping
            .get(plugin_name)
            .unwrap_or_else(|| panic!("missing OpenAPI mapping for {plugin_name}"));
        let component = schema_ref
            .strip_prefix("#/components/schemas/")
            .unwrap_or_else(|| panic!("PluginConfig ref for {plugin_name} is not local"));
        assert_component_validity(&spec, component, &config, true);
    }

    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({"provider": "azure_functions"}),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({"provider": "gcp_cloud_functions", "function_url": "ftp://functions.example"}),
        false,
    );
    assert_component_validity(
        &spec,
        "ServerlessFunctionConfig",
        &json!({
            "provider": "aws_lambda",
            "aws_endpoint_url": "ftp://lambda.example"
        }),
        false,
    );
}

fn assert_component_validity(
    spec: &serde_json::Value,
    component: &str,
    instance: &serde_json::Value,
    expected_valid: bool,
) {
    let schema = json!({
        "$schema": "https://json-schema.org/draft/2020-12/schema",
        "$ref": format!("#/components/schemas/{component}"),
        "components": spec["components"].clone()
    });
    let validator = jsonschema::draft202012::options()
        .build(&schema)
        .unwrap_or_else(|error| panic!("{component} schema compiles: {error}"));
    let actual_valid = validator.validate(instance).is_ok();
    assert_eq!(
        actual_valid, expected_valid,
        "unexpected {component} validation result for {instance}"
    );
}

#[test]
fn upstream_runtime_serialization_is_covered_by_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let upstream: ferrum_edge::config::types::Upstream = serde_json::from_value(json!({
        "targets": [{
            "host": "backend.example",
            "port": 8443,
            "weight": 2,
            "tags": {"version": "v1"},
            "locality": "us-east/us-east-1/a",
            "path": "/api"
        }],
        "service_discovery": {
            "provider": "dns_sd",
            "dns_sd": {"service_name": "_https._tcp.backend.example"}
        },
        "subsets": [{
            "name": "v1",
            "labels": {"version": "v1"},
            "traffic_policy": {
                "load_balancer_algorithm": "consistent_hashing",
                "hash_on": "header:x-tenant",
                "tls": {
                    "mode": "simple",
                    "sni": "backend.example",
                    "subject_alt_names": ["backend.example"]
                },
                "connect_timeout_ms": 750,
                "passive_health_check": {}
            }
        }],
        "port_overrides": {
            "8443": {
                "connect_timeout_ms": 500,
                "algorithm": "least_connections",
                "hash_on": "ip",
                "passive_health_check": {},
                "locality_lb_setting": {
                    "enabled": true,
                    "distribute": [{
                        "from": "us-east/us-east-1/a",
                        "to": {"us-east": 90, "us-west": 10}
                    }]
                },
                "max_connections": 100,
                "tcp_keepalive": {"time_seconds": 30, "interval_seconds": 10, "probes": 3},
                "http_max_requests_per_connection": 1000,
                "http_idle_timeout_ms": 30000,
                "h2_max_concurrent_streams": 128,
                "tls": {},
                "h2_upgrade_policy": "UPGRADE",
                "max_retries": 2,
                "http1_max_pending_requests": 64
            }
        },
        "source_locality": "us-east/us-east-1/a",
        "locality_lb_strict": true,
        "locality_lb_setting": {
            "enabled": true,
            "failover": [{"from": "us-east", "to": "us-west"}]
        }
    }))
    .expect("representative upstream deserializes");
    let serialized = serde_json::to_value(upstream).expect("upstream serializes");

    assert_component_validity(&spec, "Upstream", &serialized, true);
}

#[test]
fn config_schemas_reject_nulls_that_rust_does_not_accept() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    for (component, instance) in [
        (
            "Proxy",
            json!({"id": null, "backend_host": "backend", "backend_port": 443}),
        ),
        ("Consumer", json!({"username": null})),
        (
            "PluginConfig",
            json!({"plugin_name": null, "scope": "global", "enabled": true}),
        ),
        ("PluginAssociation", json!({"plugin_config_id": null})),
        ("UpstreamTarget", json!({"host": null, "port": 443})),
        ("ActiveHealthCheck", json!({"http_path": null})),
    ] {
        assert_component_validity(&spec, component, &instance, false);
    }

    assert_component_validity(
        &spec,
        "Proxy",
        &json!({"id": "", "backend_host": "", "backend_port": 0}),
        true,
    );
}

#[test]
fn service_discovery_schema_matches_provider_validation_and_serialization() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");

    assert_component_validity(
        &spec,
        "ServiceDiscoveryConfig",
        &json!({
            "provider": "dns_sd",
            "dns_sd": {"service_name": "_http._tcp.backend.example"},
            "kubernetes": null,
            "consul": null,
            "mesh": null,
            "default_weight": 1
        }),
        true,
    );
    assert_component_validity(
        &spec,
        "ServiceDiscoveryConfig",
        &json!({"provider": "dns_sd", "dns_sd": null}),
        false,
    );
    assert_component_validity(
        &spec,
        "ServiceDiscoveryConfig",
        &json!({"provider": "consul", "consul": {"address": "http://consul:8500"}}),
        false,
    );
}

#[test]
fn mesh_and_overload_runtime_snapshots_are_covered_by_openapi() {
    use ferrum_edge::modes::mesh::runtime::MeshEgressScopeHealth;
    use ferrum_edge::modes::mesh::slice::{MeshEgressScopeResource, MeshEgressScopeSnapshot};
    use ferrum_edge::overload::{
        ActionSnapshot, ConnPressure, FdPressure, NodeWaypointDropSnapshot, OverloadLevel,
        OverloadSnapshot, PressureSnapshot, ReqPressure,
    };

    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let resource = MeshEgressScopeResource {
        namespace: "ferrum".to_string(),
        name: "reviews".to_string(),
        hosts: vec!["reviews.ferrum.svc.cluster.local".to_string()],
        ports: vec![8080],
    };
    let scope = MeshEgressScopeSnapshot {
        sidecar_enforced: true,
        dry_run: false,
        sidecar_applied: true,
        sidecar_admitted_services: 1,
        sidecar_denied_services: 0,
        destination_rules: vec![resource.clone()],
        sidecar_admitted_destination_rules: 1,
        sidecar_denied_destination_rules: 0,
        services: vec![resource],
        service_entries: Vec::new(),
        known_destinations: vec!["reviews.ferrum.svc.cluster.local:8080".to_string()],
    };
    let health = MeshEgressScopeHealth {
        sidecar_admitted_services: 1,
        sidecar_denied_services: 0,
    };
    let egress_response = json!({
        "namespace": "ferrum",
        "scope": scope,
        "health": health
    });
    assert_component_validity(&spec, "MeshEgressScopeResponse", &egress_response, true);
    assert_component_validity(
        &spec,
        "HealthResponse",
        &json!({
            "status": "ok",
            "ready": true,
            "mesh": {"egress_scope": health}
        }),
        true,
    );

    let mut overload = serde_json::to_value(OverloadSnapshot {
        level: OverloadLevel::Normal,
        draining: false,
        active_connections: 2,
        active_requests: 1,
        red_drop_probability_pct: 0.0,
        port_exhaustion_events: 0,
        node_waypoint_drops: NodeWaypointDropSnapshot {
            cookie_unavailable: 1,
            unknown_cookie: 2,
            missing_pod_uid: 3,
            missing_workload_hash: 4,
            unknown_pod: 5,
            hash_mismatch: 6,
        },
        pressure: PressureSnapshot {
            file_descriptors: FdPressure {
                current: 10,
                max: 100,
                ratio: 0.1,
            },
            connections: ConnPressure {
                current: 2,
                max: 100,
                ratio: 0.02,
            },
            requests: ReqPressure {
                current: 1,
                max: 100,
                ratio: 0.01,
            },
            event_loop_latency_us: 50,
        },
        actions: ActionSnapshot {
            disable_keepalive: false,
            reject_new_connections: false,
            reject_new_requests: false,
        },
    })
    .expect("overload snapshot serializes");
    overload
        .as_object_mut()
        .expect("overload snapshot is an object")
        .insert(
            "stream_listeners".to_string(),
            json!({
                "dtls_demux_sessions_total": 0,
                "dtls_demux_sessions": [],
                "bind_failures_total": 0,
                "bind_failures": []
            }),
        );
    assert_component_validity(&spec, "OverloadSnapshot", &overload, true);
}

#[test]
fn no_proxy_runtime_metrics_snapshot_is_covered_by_openapi() {
    let spec: serde_json::Value =
        serde_yaml::from_str(include_str!("../../openapi.yaml")).expect("openapi.yaml parses");
    let snapshot = ferrum_edge::runtime_metrics::build_snapshot("node_agent", None);
    let serialized = serde_json::to_value(snapshot).expect("runtime metrics snapshot serializes");

    assert_component_validity(&spec, "RuntimeMetricsSnapshot", &serialized, true);
}
