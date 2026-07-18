//! Tests for admin API validation improvements.
//!
//! Tests credential type whitelist, credential redaction coverage,
//! and validation constants.

use serde_json::json;

#[test]
fn test_proxy_and_plugin_writes_run_plugin_graph_candidate_validation() {
    let source = include_str!("../../../src/admin/crud.rs");
    assert!(
        source.contains("validate_candidate_plugin_graph("),
        "cross-resource plugin checks must share one candidate graph"
    );
    assert!(
        source.contains("validate_plugin_composition_candidate(candidate, http_client)"),
        "admin candidates must enforce HMAC and correlation-ID composition"
    );
    assert!(
        source.contains("validate_tcp_connection_throttle_attachments(candidate)"),
        "admin candidates must reject unsupported TCP-throttle attachments"
    );
    assert!(
        source.matches("validate_plugin_graph_candidates(").count() >= 3,
        "the helper definition plus Proxy and PluginConfig admission calls must exist"
    );
    assert!(
        source.matches("std::slice::from_ref(resource)").count() >= 2,
        "both resource write paths must overlay their candidate"
    );
    let validation = source
        .rfind("validate_plugin_graph_candidates(")
        .expect("candidate validation call must exist");
    let persistence = source
        .rfind("resource.prepare_for_write()")
        .expect("CRUD persistence boundary must exist");
    assert!(
        validation < persistence,
        "candidate composition must be rejected before persistence"
    );
}

#[test]
fn proxy_and_api_spec_deletes_validate_the_post_cascade_plugin_graph() {
    let crud = include_str!("../../../src/admin/crud.rs");
    assert!(
        crud.contains("validate_plugin_graph_proxy_deletion_candidate("),
        "direct Proxy deletion must build the post-cascade graph"
    );
    assert!(
        crud.contains(
            "validate_plugin_graph_proxy_deletion_candidate(db, state, namespace, &existing.id)"
        ),
        "Proxy::before_delete must reject the candidate before persistence"
    );
    assert!(
        crud.contains("plugin.proxy_id.as_deref() != Some(removed_proxy_id)"),
        "the candidate must mirror proxy-scoped plugin cascade deletion"
    );
    assert!(
        crud.contains("plugin.scope != PluginScope::ProxyGroup"),
        "the candidate must mirror orphaned proxy-group cleanup"
    );

    let api_specs = include_str!("../../../src/admin/api_specs/handlers.rs");
    let validation = api_specs
        .rfind("validate_plugin_graph_proxy_deletion_candidate(")
        .expect("API-spec DELETE must validate its proxy cascade");
    let persistence = api_specs
        .rfind("persistence_db.delete_api_spec(&settlement_namespace, &persistence_id)")
        .expect("settled API-spec DELETE persistence call");
    assert!(validation < persistence);
}

#[test]
fn test_batch_writes_run_plugin_graph_candidate_validation() {
    let source = include_str!("../../../src/admin/mod.rs");
    assert!(
        source.contains("crud::validate_plugin_graph_candidates("),
        "batch Proxy and PluginConfig admission must validate the candidate chain"
    );
    assert!(source.contains("&batch.proxies,"));
    assert!(source.contains("&batch.plugin_configs,"));
}

#[test]
fn test_plugin_graph_mutations_run_prospective_validation_before_persistence() {
    let crud_source = include_str!("../../../src/admin/crud.rs");
    assert!(crud_source.contains("validate_transaction_log_schema_candidates("));
    assert!(crud_source.contains("std::slice::from_ref(resource)"));
    assert!(crud_source.contains("Some(&existing.id)"));
    assert!(crud_source.contains(".chain(replaced_plugins.iter())"));
    assert!(crud_source.contains("is_enabled_config_graph_participant(resource)"));
    assert!(crud_source.contains("const SERIALIZE_NAMESPACE_CONFIG_ADMISSION: bool = true;"));
    assert!(crud_source.contains("tokio::task::spawn_blocking(move ||"));
    assert!(crud_source.contains("try_acquire_namespace_config_admission_lease("));
    assert!(crud_source.contains("renew_namespace_config_admission_lease("));
    assert!(crud_source.contains("release_namespace_config_admission_lease("));
    assert!(crud_source.contains("guard.ensure_held()"));
    assert!(crud_source.contains("run_to_completion_while_held"));
    assert!(crud_source.contains("NamespaceConfigAdmissionCompletion::Lost"));
    assert!(crud_source.contains("immediately_succeeds_generation"));
    assert!(crud_source.contains("InterveningWriteRecovery::KeepCurrent"));
    assert!(crud_source.contains("persist_delete_to_settlement("));
    assert!(crud_source.contains("tokio::spawn(persist_delete_to_settlement("));
    assert!(crud_source.contains("lease was lost before persistence started"));
    assert!(crud_source.contains("mark_mtls_dns_admission_unavailable(anyhow::anyhow!("));
    assert!(crud_source.contains("late_create_compensation_safe("));
    assert!(crud_source.contains("late plugin delete compensation could not restore proxy"));
    assert!(crud_source.contains("late_delete_api_spec_snapshot("));
    assert!(crud_source.contains("db.get_api_spec_by_proxy(namespace, &previous.id)"));
    assert!(crud_source.contains(
        "restore_api_spec_bundle(&bundle, spec, &additional_upstreams, &additional_plugins)"
    ));
    assert!(crud_source.contains("affected_upstreams"));
    assert!(crud_source.contains("task.abort();"));
    assert!(crud_source.contains("tokio::time::timeout("));
    assert!(crud_source.contains("drop(local);"));

    let graph_validation = crud_source
        .rfind("validate_transaction_log_schema_candidates(")
        .expect("delete candidate validation call must exist");
    let persistence = crud_source
        .rfind("resource.prepare_for_write()")
        .expect("CRUD persistence boundary must exist");
    assert!(
        graph_validation < persistence,
        "prospective graph validation must run before CRUD persistence"
    );

    let batch_source = include_str!("../../../src/admin/mod.rs");
    assert!(batch_source.contains("crud::validate_transaction_log_schema_candidates("));
    assert!(batch_source.contains("&batch.plugin_configs,"));
    assert!(batch_source.contains("is_enabled_config_graph_participant"));
    let restore_validator = batch_source
        .find("async fn validate_restore_candidate_on_blocking_pool(")
        .expect("restore candidate validator must exist");
    let restore_handler = batch_source
        .find("async fn handle_restore(")
        .expect("restore handler must exist");
    assert!(
        batch_source[restore_validator..restore_handler]
            .contains("tokio::task::spawn_blocking(move ||"),
        "restore graph construction must run off the Tokio worker"
    );
    assert!(
        batch_source[restore_handler..].contains("validate_restore_candidate_on_blocking_pool("),
        "restore must use the blocking candidate validator"
    );
    assert!(
        batch_source
            .matches("crud::lock_namespace_config_admission(")
            .count()
            >= 5,
        "batch and restore mutations and their recovery paths must share namespace admission"
    );
    assert!(
        batch_source
            .matches(".run_to_completion_while_held(")
            .count()
            >= 5,
        "batch and restore persistence must preserve concrete outcomes across lease loss"
    );
    assert!(batch_source.contains("rollback_failed_batch_create("));
    assert!(batch_source.contains("batch_plugin_configs_with_intervening_proxy_dependencies("));
    assert!(batch_source.contains("protected_plugin_config_ids.contains(&plugin_config.id)"));
    assert!(batch_source.contains("immediately_succeeds_generation(lost_generation)"));
    assert_eq!(
        batch_source
            .matches("acquire_credential_namespace_admission(db.clone(), namespace)")
            .count(),
        4,
        "every credential read/modify/write endpoint must take namespace admission"
    );
    assert!(batch_source.contains("async fn recover_late_credential_update("));
    assert!(batch_source.contains("async fn release_guard(&self)"));
    assert!(batch_source.contains("participates_in_config_graph(plugin_config)"));
    assert!(batch_source.contains("admission.run_mutation(db.update_consumer(&consumer, mode))"));
    assert!(
        batch_source.contains("late credential update compensation found no matching consumer")
    );
    let sql_store_source = include_str!("../../../src/config/db_loader.rs");
    assert!(sql_store_source.contains("config_admission_locks"));
    assert!(sql_store_source.contains("config_admission_lease_now_sql"));
    assert!(sql_store_source.contains("SELECT generation FROM config_admission_locks"));
    assert!(sql_store_source.contains("additionally failed to release the claimed lease"));
    assert!(sql_store_source.contains("batch_create_plugin_configs_chunk(&graph_configs, mode)"));
    assert!(sql_store_source.contains("partition(crate::plugins::transaction_log_schema::"));
    assert!(sql_store_source.contains("unrelated_configs.chunks(Self::BATCH_CHUNK_SIZE)"));
    assert!(sql_store_source.contains(".bind(proxy.updated_at.to_rfc3339())"));
    assert!(sql_store_source.contains(".bind(consumer.updated_at.to_rfc3339())"));
    assert!(sql_store_source.contains(".bind(pc.updated_at.to_rfc3339())"));
    assert!(sql_store_source.contains(".bind(upstream.updated_at.to_rfc3339())"));
    let mongo_store_source = include_str!("../../../src/config/mongo_store.rs");
    assert!(mongo_store_source.contains("config_admission_locks"));
    assert!(mongo_store_source.contains("server_time_lease_acquire_pipeline"));
    assert!(mongo_store_source.contains("\"generation\""));

    let pipeline_source = include_str!("../../../src/config/validation_pipeline.rs");
    assert!(pipeline_source.contains("transaction_log_schema::validate_config_graph("));

    let api_spec_source = include_str!("../../../src/admin/api_specs/handlers.rs");
    assert!(api_spec_source.contains("validate_transaction_log_schema_candidates("));
    assert!(
        api_spec_source.contains("validate_transaction_log_schema_api_spec_replacement_candidate(")
    );
    assert_eq!(
        api_spec_source
            .matches(
                "crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await",
            )
            .count(),
        3,
        "API-spec POST, PUT, and DELETE must serialize through persistence"
    );
    assert!(api_spec_source.contains("run_api_spec_persistence_while_held("));
    assert_eq!(
        api_spec_source
            .matches("return Ok(error_response(ApiSpecError::AdmissionUnavailable(")
            .count(),
        3,
        "API-spec POST, PUT, and DELETE lease failures must report admission outages"
    );
    assert!(api_spec_source.contains("enum ApiSpecLateWriteRecovery"));
    assert!(api_spec_source.contains("ApiSpecLateWriteRecovery::Retained"));
    let post_lock = api_spec_source
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .expect("POST admission guard");
    let post_persist = api_spec_source
        .find("persistence_db.submit_api_spec_bundle(&persistence_bundle, &persistence_spec)")
        .expect("POST persistence");
    assert!(post_lock < post_persist);
    let put_lock = api_spec_source[post_lock + 1..]
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .map(|position| position + post_lock + 1)
        .expect("PUT admission guard");
    let put_persist = api_spec_source
        .find("persistence_db.replace_api_spec_bundle(&persistence_bundle, &persistence_spec)")
        .expect("PUT persistence");
    assert!(put_lock < put_persist);
    let delete_lock = api_spec_source[put_lock + 1..]
        .find("crate::admin::crud::lock_namespace_config_admission(db.clone(), namespace).await")
        .map(|position| position + put_lock + 1)
        .expect("DELETE admission guard");
    let delete_persist = api_spec_source
        .find("persistence_db.delete_api_spec(&settlement_namespace, &persistence_id)")
        .expect("DELETE persistence");
    let delete_validation = api_spec_source[delete_lock..]
        .find("validate_transaction_log_schema_api_spec_deletion_candidate(")
        .map(|position| position + delete_lock)
        .expect("DELETE prospective graph validation");
    assert!(delete_lock < delete_validation);
    assert!(delete_validation < delete_persist);
}

#[test]
fn direct_api_spec_proxy_delete_uses_atomic_restore_contract() {
    let source = include_str!("../../../src/admin/crud.rs");
    let proxy_impl = source
        .find("impl AdminResource for Proxy")
        .expect("Proxy admin implementation must exist");
    let compensation = source[proxy_impl..]
        .find("async fn compensate_late_delete(")
        .map(|offset| proxy_impl + offset)
        .expect("Proxy DELETE must define late compensation");
    let snapshot = source[compensation..]
        .find("async fn late_delete_api_spec_snapshot(")
        .map(|offset| compensation + offset)
        .expect("Proxy compensation must have a bounded source region");
    let recovery = &source[compensation..snapshot];

    assert!(recovery.contains("proxy: previous.clone()"));
    assert!(recovery.contains("!spec_plugin_ids.contains(plugin.id.as_str())"));
    assert!(recovery.contains(".position(|affected| affected.id == upstream.id)"));
    assert!(recovery.contains("affected_upstreams[existing_index] = upstream.clone()"));
    assert!(recovery.contains(
        "restore_api_spec_bundle(&bundle, spec, &additional_upstreams, &additional_plugins)"
    ));
    assert!(!recovery.contains("db.submit_api_spec_bundle("));
}

#[test]
fn api_spec_delete_snapshots_current_hand_upstream_for_atomic_restore() {
    let source = include_str!("../../../src/admin/api_specs/handlers.rs");
    let delete_start = source
        .find("pub async fn handle_delete_api_spec(")
        .expect("API-spec DELETE handler");
    let delete = &source[delete_start..];

    assert!(delete.contains("existing_proxy.upstream_id.as_deref()"));
    assert!(delete.contains("db.get_upstream(namespace, upstream_id)"));
    assert!(delete.contains("upstream.api_spec_id.is_none()"));
    let validation = delete
        .find("validate_api_spec_restore_inputs(")
        .expect("API-spec DELETE must validate its restore snapshot");
    let compensation = delete
        .find("compensate_late_api_spec_delete(")
        .expect("API-spec DELETE must compensate a late persistence failure");
    assert!(validation < compensation);
    assert!(delete[validation..compensation].contains("&additional_upstreams,"));
    assert!(delete[compensation..].contains("additional_upstreams,"));
}

#[test]
fn test_batch_hmac_uniqueness_is_gated_on_submitted_hmac_consumers() {
    let source = include_str!("../../../src/admin/mod.rs");
    let gate = r#".any(|consumer| !consumer.credential_entries("hmac_auth").is_empty())"#;
    let validation = "candidate_config.validate_unique_hmac_credentials()";
    let gate_position = source
        .find(gate)
        .expect("batch admission must detect submitted HMAC consumers");
    let validation_position = source
        .find(validation)
        .expect("batch admission must validate the authoritative HMAC candidate");
    assert!(
        gate_position < validation_position,
        "legacy HMAC duplicates must not block unrelated batch writes"
    );
}

// --- Credential type whitelist tests ---

#[test]
fn test_allowed_credential_types_contains_expected() {
    let expected = &["basicauth", "keyauth", "jwt", "hmac_auth", "mtls_auth"];
    for cred_type in expected {
        assert!(
            ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.contains(cred_type),
            "Expected '{}' to be in ALLOWED_CREDENTIAL_TYPES",
            cred_type
        );
    }
}

#[test]
fn test_disallowed_credential_types_rejected() {
    let disallowed = &[
        "admin_flag",
        "custom",
        "unknown",
        "",
        "BASICAUTH",
        "basic_auth",
    ];
    for cred_type in disallowed {
        assert!(
            !ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.contains(cred_type),
            "Expected '{}' to NOT be in ALLOWED_CREDENTIAL_TYPES",
            cred_type
        );
    }
}

#[test]
fn test_credential_types_count() {
    // Ensure we have exactly the 5 known credential types
    assert_eq!(
        ferrum_edge::admin::ALLOWED_CREDENTIAL_TYPES.len(),
        5,
        "Expected exactly 5 allowed credential types"
    );
}

// --- Credential redaction tests ---

fn make_consumer(
    credentials: std::collections::HashMap<String, serde_json::Value>,
) -> ferrum_edge::config::types::Consumer {
    ferrum_edge::config::types::Consumer {
        id: "test-consumer".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        username: "test-user".to_string(),
        custom_id: None,
        credentials,
        acl_groups: Vec::new(),
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn test_redact_basicauth_password_hash_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"username": "alice", "password_hash": "$2b$12$realhashabcdef"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_basicauth_plaintext_password_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"password": "must-not-escape"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_basic_credential_user_shape_failure_is_bad_request() {
    let mut credential = json!({
        "password": "x".repeat(ferrum_edge::config::types::MAX_CREDENTIAL_VALUE_LENGTH + 1)
    });

    let status =
        ferrum_edge::_test_support::prepare_basic_auth_credential_for_test(&mut credential)
            .expect_err("oversized Basic password must be rejected");

    assert_eq!(status, hyper::StatusCode::BAD_REQUEST);
    assert!(credential.get("password").is_some());
    assert!(credential.get("password_hash").is_none());
}

#[test]
fn test_basic_credential_server_configuration_failures_are_internal_errors() {
    assert_eq!(
        ferrum_edge::_test_support::basic_auth_server_configuration_status_for_test(None),
        Some(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    );
    assert_eq!(
        ferrum_edge::_test_support::basic_auth_server_configuration_status_for_test(Some("weak")),
        Some(hyper::StatusCode::INTERNAL_SERVER_ERROR)
    );
}

#[test]
fn test_disabled_basic_auth_config_skips_plugin_construction() {
    let now = chrono::Utc::now();
    let mut plugin_config = ferrum_edge::config::types::PluginConfig {
        id: "disabled-basic-auth".to_string(),
        plugin_name: "basic_auth".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        // An unsupported field makes constructor invocation fail regardless of
        // process environment, so this deterministically proves the disabled
        // admin path does not construct the plugin.
        config: json!({"realm": "staged-but-unused"}),
        scope: ferrum_edge::config::types::PluginScope::Global,
        proxy_id: None,
        enabled: false,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_ok()
    );

    plugin_config.enabled = true;
    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_err()
    );
}

#[test]
fn test_disabled_unknown_plugin_name_remains_invalid() {
    let now = chrono::Utc::now();
    let plugin_config = ferrum_edge::config::types::PluginConfig {
        id: "disabled-unknown-plugin".to_string(),
        plugin_name: "not_a_registered_plugin".to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        config: json!({"staged": true}),
        scope: ferrum_edge::config::types::PluginScope::Global,
        proxy_id: None,
        enabled: false,
        priority_override: None,
        api_spec_id: None,
        created_at: now,
        updated_at: now,
    };

    assert!(
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config).is_err()
    );
}

#[test]
fn test_admin_stdout_logging_validation_rejects_unknown_paths() {
    let now = chrono::Utc::now();
    for (config, path) in [
        (
            json!({"filters": {"errors_only": true}}),
            "stdout_logging.filters",
        ),
        (
            json!({"filter": {"error_only": true}}),
            "stdout_logging.filter.error_only",
        ),
    ] {
        let plugin_config = ferrum_edge::config::types::PluginConfig {
            id: format!("invalid-{path}"),
            plugin_name: "stdout_logging".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            config,
            scope: ferrum_edge::config::types::PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
        let error =
            ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config)
                .expect_err("admin validation must reject unknown keys");
        assert!(error.contains(path), "expected {path} in {error}");
    }
}

#[test]
fn test_admin_stdout_logging_validation_preserves_null_defaults() {
    for (index, config) in [serde_json::Value::Null, json!({"filter": null})]
        .into_iter()
        .enumerate()
    {
        let plugin_config = ferrum_edge::config::types::PluginConfig {
            id: format!("stdout-null-default-{index}"),
            plugin_name: "stdout_logging".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            config,
            scope: ferrum_edge::config::types::PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
        ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config)
            .expect("admin validation must preserve null defaults");
    }
}

#[test]
fn test_admin_transaction_log_schema_rejects_unknown_closed_object_keys() {
    let now = chrono::Utc::now();
    for (id, config, expected_path) in [
        (
            "outer-key",
            json!({"schemas": {"audit": {}}, "strict": true}),
            "config.strict",
        ),
        (
            "derived-key",
            json!({
                "schemas": {
                    "audit": {
                        "derived_fields": [
                            {"name": "outcome", "kind": "outcome", "from": "status"}
                        ]
                    }
                }
            }),
            "derived_fields[0].from",
        ),
        (
            "metadata-key",
            json!({
                "schemas": {
                    "audit": {
                        "metadata": {"mode": "flatten", "on_collison": "overwrite"}
                    }
                }
            }),
            "metadata.on_collison",
        ),
    ] {
        let plugin_config = ferrum_edge::config::types::PluginConfig {
            id: id.to_string(),
            plugin_name: "transaction_log_schema".to_string(),
            namespace: ferrum_edge::config::types::default_namespace(),
            config,
            scope: ferrum_edge::config::types::PluginScope::Global,
            proxy_id: None,
            enabled: true,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        };
        let error =
            ferrum_edge::_test_support::validate_admin_plugin_config_for_test(&plugin_config)
                .expect_err("admin constructor validation must reject unknown keys");
        assert!(error.contains(expected_path), "unexpected error: {error}");
    }
}

#[test]
fn test_basic_auth_audit_redaction_uses_one_shape_independent_marker() {
    let password_hash = format!("hmac_sha256:{}", "a".repeat(64));
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!([{
            "password_hash": password_hash.clone(),
            "credential_label": "must-not-escape"
        }]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::config::types::redact_consumer_credentials_for_audit(&consumer);
    assert_eq!(redacted.credentials["basicauth"], "[REDACTED]");

    let serialized = serde_json::to_string(&redacted).expect("redacted consumer serializes");
    assert!(!serialized.contains("password_hash"));
    assert!(!serialized.contains("credential_label"));
    assert!(!serialized.contains("must-not-escape"));
    assert!(!serialized.contains(&password_hash));
}

#[test]
fn test_redact_hmac_auth_secret() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "hmac_auth".to_string(),
        json!({"username": "bob", "secret": "supersecret123"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let hmac = redacted.credentials.get("hmac_auth").unwrap();
    assert_eq!(hmac["secret"], "[REDACTED]");
    assert_eq!(hmac["username"], "bob");
}

#[test]
fn test_redact_jwt_secret() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "jwt".to_string(),
        json!({"secret": "my-jwt-secret", "algorithm": "HS256"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    assert_eq!(jwt["secret"], "[REDACTED]");
    assert_eq!(jwt["algorithm"], "HS256");
}

#[test]
fn test_redact_keyauth_key() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert("keyauth".to_string(), json!({"key": "api-key-value"}));
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let keyauth = redacted.credentials.get("keyauth").unwrap();
    assert_eq!(keyauth["key"], "[REDACTED]");
}

#[test]
fn test_redact_multiple_credential_types() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!({"username": "alice", "password_hash": "hash123"}),
    );
    credentials.insert(
        "hmac_auth".to_string(),
        json!({"username": "alice", "secret": "secret123"}),
    );
    credentials.insert("keyauth".to_string(), json!({"key": "api-key-value"}));
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);

    assert!(!redacted.credentials.contains_key("basicauth"));
    assert_eq!(redacted.credentials["hmac_auth"]["secret"], "[REDACTED]");
    assert_eq!(redacted.credentials["keyauth"]["key"], "[REDACTED]");
}

#[test]
fn test_redact_mtls_identity_unchanged() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "mtls_auth".to_string(),
        json!({"identity": "CN=client.example.com"}),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert_eq!(
        redacted.credentials["mtls_auth"]["identity"],
        "CN=client.example.com"
    );
}

#[test]
fn test_redact_empty_credentials() {
    let consumer = make_consumer(std::collections::HashMap::new());
    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(redacted.credentials.is_empty());
}

// ---- Multi-credential array redaction tests ----

#[test]
fn test_redact_array_jwt_secrets() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "jwt".to_string(),
        json!([
            {"secret": "old-secret", "algorithm": "HS256"},
            {"secret": "new-secret", "algorithm": "HS256"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let jwt = redacted.credentials.get("jwt").unwrap();
    let arr = jwt.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["secret"], "[REDACTED]");
    assert_eq!(arr[0]["algorithm"], "HS256");
    assert_eq!(arr[1]["secret"], "[REDACTED]");
    assert_eq!(arr[1]["algorithm"], "HS256");
}

#[test]
fn test_redact_array_basicauth_passwords_by_omission() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "basicauth".to_string(),
        json!([
            {"password_hash": "hash-old"},
            {"password_hash": "hash-new"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    assert!(!redacted.credentials.contains_key("basicauth"));
}

#[test]
fn test_redact_array_hmac_secrets() {
    let mut credentials = std::collections::HashMap::new();
    credentials.insert(
        "hmac_auth".to_string(),
        json!([
            {"secret": "secret-1"},
            {"secret": "secret-2"}
        ]),
    );
    let consumer = make_consumer(credentials);

    let redacted = ferrum_edge::admin::redact_consumer_credentials(&consumer);
    let hmac = redacted.credentials.get("hmac_auth").unwrap();
    let arr = hmac.as_array().unwrap();
    assert_eq!(arr.len(), 2);
    assert_eq!(arr[0]["secret"], "[REDACTED]");
    assert_eq!(arr[1]["secret"], "[REDACTED]");
}

fn recovery_plugin(
    id: &str,
    plugin_name: &str,
    config: serde_json::Value,
) -> ferrum_edge::config::types::PluginConfig {
    ferrum_edge::config::types::PluginConfig {
        id: id.to_string(),
        namespace: ferrum_edge::config::types::default_namespace(),
        plugin_name: plugin_name.to_string(),
        config,
        scope: ferrum_edge::config::types::PluginScope::Global,
        enabled: true,
        proxy_id: None,
        priority_override: None,
        api_spec_id: None,
        created_at: chrono::Utc::now(),
        updated_at: chrono::Utc::now(),
    }
}

#[test]
fn intervening_clear_recovery_preserves_both_valid_schema_graphs() {
    let snapshot = ferrum_edge::config::types::GatewayConfig {
        plugin_configs: vec![
            recovery_plugin(
                "snapshot-schema",
                "transaction_log_schema",
                json!({"schemas": {"snapshot": {"summary_type": "both"}}}),
            ),
            recovery_plugin(
                "snapshot-logger",
                "stdout_logging",
                json!({"schema_ref": "snapshot"}),
            ),
        ],
        ..Default::default()
    };
    let current = ferrum_edge::config::types::GatewayConfig {
        plugin_configs: vec![
            recovery_plugin(
                "intervening-schema",
                "transaction_log_schema",
                json!({"schemas": {"intervening": {"summary_type": "both"}}}),
            ),
            recovery_plugin(
                "intervening-logger",
                "stdout_logging",
                json!({"schema_ref": "intervening"}),
            ),
        ],
        ..Default::default()
    };

    let candidate = ferrum_edge::_test_support::intervening_clear_recovery_candidate_for_test(
        snapshot, current,
    );
    let ids = candidate
        .plugin_configs
        .iter()
        .map(|plugin| plugin.id.as_str())
        .collect::<std::collections::HashSet<_>>();
    assert_eq!(ids.len(), 4);
    assert!(ids.contains("snapshot-schema"));
    assert!(ids.contains("snapshot-logger"));
    assert!(ids.contains("intervening-schema"));
    assert!(ids.contains("intervening-logger"));
    ferrum_edge::_test_support::validate_transaction_log_schema_graph_for_test(&candidate)
        .expect("the additive recovery union must retain a valid schema graph");
}

#[test]
fn intervening_clear_recovery_keeps_current_ids_and_rejects_invalid_union() {
    let snapshot = ferrum_edge::config::types::GatewayConfig {
        plugin_configs: vec![
            recovery_plugin(
                "same-id",
                "transaction_log_schema",
                json!({"schemas": {"snapshot-only": {"summary_type": "both"}}}),
            ),
            recovery_plugin(
                "snapshot-schema",
                "transaction_log_schema",
                json!({"schemas": {"duplicate": {"summary_type": "both"}}}),
            ),
        ],
        ..Default::default()
    };
    let current = ferrum_edge::config::types::GatewayConfig {
        plugin_configs: vec![
            recovery_plugin(
                "same-id",
                "transaction_log_schema",
                json!({"schemas": {"current-wins": {"summary_type": "both"}}}),
            ),
            recovery_plugin(
                "intervening-schema",
                "transaction_log_schema",
                json!({"schemas": {"duplicate": {"summary_type": "both"}}}),
            ),
        ],
        ..Default::default()
    };

    let candidate = ferrum_edge::_test_support::intervening_clear_recovery_candidate_for_test(
        snapshot, current,
    );
    let same_id = candidate
        .plugin_configs
        .iter()
        .find(|plugin| plugin.id == "same-id")
        .expect("the current same-id resource must survive");
    assert!(same_id.config["schemas"].get("current-wins").is_some());
    assert!(same_id.config["schemas"].get("snapshot-only").is_none());

    let errors =
        ferrum_edge::_test_support::validate_transaction_log_schema_graph_for_test(&candidate)
            .expect_err("duplicate names across the recovery union must fail closed");
    assert!(errors.iter().any(|error| error.contains("duplicate")));
}

#[test]
fn late_api_spec_post_compensation_preserves_intervening_proxy_plugins() {
    let api_spec_source = include_str!("../../../src/admin/api_specs/handlers.rs");
    assert!(api_spec_source.contains("late_api_spec_create_compensation_safe("));
    assert!(api_spec_source.contains("current_proxy.plugins.len() != expected_associations.len()"));
    assert!(
        api_spec_source.contains("plugin.proxy_id.as_deref() == Some(bundle.proxy.id.as_str())")
    );
}

#[test]
fn late_api_spec_put_reconciles_the_current_schema_graph() {
    let api_spec_source = include_str!("../../../src/admin/api_specs/handlers.rs");
    assert!(api_spec_source.contains("current_transaction_log_schema_graph_is_valid("));
    assert!(
        api_spec_source.contains("validate_transaction_log_schema_api_spec_replacement_candidate(")
    );
    let put_compensation = api_spec_source
        .rfind("compensate_late_api_spec_replace(")
        .expect("PUT must provide late-write graph reconciliation");
    assert!(api_spec_source[put_compensation..].contains("true,"));
}

#[test]
fn ambiguous_namespace_admission_acquisition_has_owned_cleanup() {
    let crud_source = include_str!("../../../src/admin/crud.rs");
    assert!(crud_source.contains("struct PendingNamespaceConfigAdmissionClaim"));
    assert!(crud_source.contains("let (result_tx, result_rx) = tokio::sync::oneshot::channel()"));
    assert!(crud_source.contains("an ambiguous namespace config admission acquisition"));
    assert!(crud_source.contains("a cancelled namespace config admission acquisition"));
}

#[test]
fn mongo_namespace_admission_uses_the_dedicated_lease_client() {
    let mongo_source = include_str!("../../../src/config/mongo_store.rs");
    assert!(mongo_source.contains("fn lease_db(&self) -> MongoDatabaseHandle"));
    assert!(mongo_source.contains("self.lease_db().run_command(doc! { \"hello\": 1 })"));
    assert!(mongo_source.contains("let lease_db = self.lease_db();"));
}

#[test]
fn late_restore_clear_validates_the_union_before_additive_replay() {
    let restore_source = include_str!("../../../src/admin/mod.rs");
    let recovery_start = restore_source
        .find("async fn restore_snapshot_after_intervening_clear(")
        .expect("restore must have an additive late-clear recovery path");
    let recovery_end = restore_source[recovery_start..]
        .find("/// Finalize a failed restore")
        .map(|offset| recovery_start + offset)
        .expect("additive recovery helper must have a bounded source region");
    let recovery = &restore_source[recovery_start..recovery_end];
    let graph_validation = recovery
        .find("validate_transaction_log_schema_graph_on_blocking_pool(")
        .expect("the merged durable graph must be validated");
    let persistence = recovery
        .find("persist_payload_resources(")
        .expect("missing snapshot resources must be replayed");
    assert!(graph_validation < persistence);
    assert!(restore_source.contains("finish_failed_restore_after_intervening_clear("));
}
