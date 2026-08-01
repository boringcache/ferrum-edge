//! FIPS deployment-mode surface and fail-closed admission policy (issue #3510).
//!
//! These target the `_enforced` policy entry points rather than the gated
//! wrappers. `crate::fips::BUILD_CAPABLE` is `false` in this build, so
//! enforcement can never be established at runtime and the gated wrappers would
//! short-circuit to `Ok(())` — testing through them would assert nothing. The
//! wrappers' own gate is covered by
//! `fips_policy_is_inert_when_mode_is_off`.

use chrono::Utc;
use ferrum_edge::config::env_config::EnvConfig;
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use ferrum_edge::fips;
use ferrum_edge::fips::policy;
use serde_json::json;

fn plugin(name: &str, config: serde_json::Value) -> PluginConfig {
    PluginConfig {
        id: format!("{name}-1"),
        plugin_name: name.to_string(),
        namespace: "ferrum".to_string(),
        config,
        scope: PluginScope::Global,
        proxy_id: None,
        enabled: true,
        priority_override: None,
        api_spec_id: None,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    }
}

fn config_with(plugins: Vec<PluginConfig>) -> GatewayConfig {
    GatewayConfig {
        plugin_configs: plugins,
        ..GatewayConfig::default()
    }
}

// ── Mode parsing ────────────────────────────────────────────────────────────

#[test]
fn mode_parses_documented_spellings() {
    for raw in ["", "off", "OFF", " off ", "false", "0", "disabled", "disable"] {
        assert_eq!(
            fips::FipsMode::parse(raw).expect("parses"),
            fips::FipsMode::Off,
            "expected {raw:?} to parse as off"
        );
    }
    for raw in ["enforce", "ENFORCE", " enforce ", "true", "1", "on", "enabled"] {
        assert_eq!(
            fips::FipsMode::parse(raw).expect("parses"),
            fips::FipsMode::Enforce,
            "expected {raw:?} to parse as enforce"
        );
    }
}

#[test]
fn mode_rejects_unknown_value_rather_than_downgrading() {
    // A typo must not quietly run non-FIPS. This is the whole reason the
    // setting is not a plain bool parse.
    let err = fips::FipsMode::parse("enfroce").expect_err("unknown value is an error");
    assert!(err.contains("FERRUM_FIPS_MODE"), "names the setting: {err}");
    assert!(
        !err.contains("enfroce"),
        "the supplied value must not be echoed: {err}"
    );
}

#[test]
fn mode_default_is_off() {
    assert_eq!(fips::FipsMode::default(), fips::FipsMode::Off);
    assert!(!fips::FipsMode::default().is_enforcing());
    assert_eq!(fips::FipsMode::Off.as_str(), "off");
    assert_eq!(fips::FipsMode::Enforce.as_str(), "enforce");
}

// ── Fail-closed bootstrap ───────────────────────────────────────────────────

#[test]
fn enforce_request_fails_closed_on_a_build_without_the_module() {
    // The load-bearing assertion of this whole feature: an enforce request on a
    // build that cannot provide a validated module must be refused, never
    // downgraded to `ring`.
    assert!(
        !fips::BUILD_CAPABLE,
        "this build is expected to lack the validated-module integration; \
         if that changed, this test and docs/fips.md must both be updated"
    );

    let err = fips::verify_resolved_mode(fips::FipsMode::Enforce)
        .expect_err("enforce must fail closed without build capability");
    assert!(err.contains("aws-lc-fips"), "names the integration: {err}");
    assert!(err.contains("docs/fips.md"), "points at the boundary doc");

    // And the mode-off path stays inert.
    assert!(fips::verify_resolved_mode(fips::FipsMode::Off).is_ok());
}

#[test]
fn bootstrap_error_text_is_bounded_and_makes_no_certification_claim() {
    let rendered = fips::BootstrapError::BuildNotCapable.to_string();
    assert!(rendered.len() < 1024, "diagnostic stays bounded");
    assert!(
        !rendered.to_lowercase().contains("certified"),
        "must not imply certification: {rendered}"
    );
    assert!(rendered.contains("will not fall back"), "states fail-closed");
}

// ── Status metadata ─────────────────────────────────────────────────────────

#[test]
fn status_metadata_is_non_sensitive_and_denies_certification() {
    let value = fips::status_metadata();
    let object = value.as_object().expect("object");

    // `certified` must be present and false on every build. A status scraper
    // must never be able to read `enforcing` as `certified`.
    assert_eq!(object.get("certified"), Some(&json!(false)));
    assert_eq!(object.get("mode"), Some(&json!("off")));
    assert_eq!(object.get("build_capable"), Some(&json!(false)));
    assert_eq!(object.get("provider"), Some(&json!("ring")));
    assert_eq!(object.get("module_self_test_passed"), Some(&json!(false)));
    assert_eq!(
        object.get("boundary_documentation"),
        Some(&json!("docs/fips.md"))
    );

    // Every value is a boolean or a fixed-set string: no paths, no key
    // material, no operator-supplied text.
    for (key, field) in object {
        assert!(
            field.is_boolean() || field.is_string(),
            "field {key} must be a boolean or fixed-set string, got {field}"
        );
    }
}

// ── Process configuration policy ────────────────────────────────────────────

#[test]
fn env_policy_accepts_an_approved_default_configuration() {
    let env_config = EnvConfig::default();
    policy::check_env_config_enforced(&env_config).expect("defaults are FIPS-approved");
}

#[test]
fn env_policy_rejects_a_provider_pin_this_build_does_not_provide() {
    let mut env_config = EnvConfig::default();
    env_config.fips_required_provider = "some-other-module".to_string();
    let err = policy::check_env_config_enforced(&env_config).expect_err("pin is rejected");
    assert!(err.contains("FERRUM_FIPS_REQUIRED_PROVIDER"));
    assert!(err.contains(fips::SUPPORTED_PROVIDER_ID));
    assert!(
        !err.contains("some-other-module"),
        "operator-supplied value must not be echoed: {err}"
    );
}

#[test]
fn env_policy_rejects_disabled_backend_certificate_verification() {
    let mut env_config = EnvConfig::default();
    env_config.tls_no_verify = true;
    let err = policy::check_env_config_enforced(&env_config).expect_err("no-verify is rejected");
    assert!(err.contains("FERRUM_TLS_NO_VERIFY"));
}

#[test]
fn env_policy_rejects_encrypted_mongodb_config_store() {
    // The MongoDB driver pins its own non-validated rustls provider, so its
    // transport can never be routed onto Ferrum's module.
    let mut env_config = EnvConfig::default();
    env_config.db_type = Some("mongodb".to_string());
    env_config.db_tls_mode = Some(ferrum_edge::config::env_config::DbTlsMode::Require);
    let err = policy::check_env_config_enforced(&env_config).expect_err("mongo TLS is rejected");
    assert!(err.contains("mongodb"), "{err}");
    assert!(err.contains("docs/fips.md"), "{err}");

    // `disable` is admitted: there is no TLS stack to attest to.
    env_config.db_tls_mode = Some(ferrum_edge::config::env_config::DbTlsMode::Disable);
    policy::check_env_config_enforced(&env_config).expect("plaintext mongo is admitted");
}

#[test]
fn env_policy_floors_hmac_key_length() {
    let mut env_config = EnvConfig::default();
    env_config.admin_jwt_secret = Some("short".to_string());
    let err = policy::check_env_config_enforced(&env_config).expect_err("short key is rejected");
    assert!(err.contains("FERRUM_ADMIN_JWT_SECRET"));
    assert!(
        !err.contains("short"),
        "the secret must never appear in the diagnostic: {err}"
    );

    env_config.admin_jwt_secret = Some("x".repeat(policy::MIN_HMAC_KEY_BYTES));
    policy::check_env_config_enforced(&env_config).expect("32-byte key is admitted");
}

// ── Gateway configuration policy ────────────────────────────────────────────

#[test]
fn gateway_policy_rejects_plugins_outside_the_module_boundary() {
    let config = config_with(vec![plugin("kafka_logging", json!({}))]);
    let err = policy::check_gateway_config_enforced(&config).expect_err("kafka is rejected");
    assert!(err.contains("kafka_logging"), "{err}");
    assert!(err.contains("docs/fips.md"), "{err}");
}

#[test]
fn gateway_policy_ignores_a_disabled_non_approved_plugin() {
    // A disabled plugin performs no cryptography, so refusing it would be a
    // false rejection that blocks an otherwise compliant startup.
    let mut disabled = plugin("kafka_logging", json!({}));
    disabled.enabled = false;
    policy::check_gateway_config_enforced(&config_with(vec![disabled]))
        .expect("disabled plugin is not a violation");
}

#[test]
fn gateway_policy_rejects_non_approved_jwt_algorithms() {
    for alg in ["none", "EdDSA", "HS999"] {
        let config = config_with(vec![plugin("jwt_auth", json!({ "algorithm": alg }))]);
        let err = match policy::check_gateway_config_enforced(&config) {
            Err(err) => err,
            Ok(()) => panic!("{alg} must be rejected"),
        };
        assert!(err.contains(&alg.to_ascii_uppercase()), "{err}");
    }
}

#[test]
fn gateway_policy_accepts_approved_jwt_algorithms_in_both_config_shapes() {
    let scalar = config_with(vec![plugin("jwt_auth", json!({ "algorithm": "RS256" }))]);
    policy::check_gateway_config_enforced(&scalar).expect("RS256 scalar is approved");

    let array = config_with(vec![plugin(
        "jwks_auth",
        json!({ "algorithms": ["RS256", "ES384", "PS512"] }),
    )]);
    policy::check_gateway_config_enforced(&array).expect("approved array is admitted");
}

#[test]
fn gateway_policy_does_not_misread_non_jws_algorithm_vocabularies() {
    // `hmac_auth` reuses the `algorithm` key for its own vocabulary. Screening
    // it against the JWS registry would be a false rejection of an algorithm
    // that is itself approved.
    let config = config_with(vec![plugin(
        "hmac_auth",
        json!({ "algorithm": "hmac-sha256" }),
    )]);
    policy::check_gateway_config_enforced(&config).expect("hmac-sha256 is not a JWS alg");
}

#[test]
fn gateway_policy_diagnostics_stay_bounded_under_a_large_configuration() {
    // A hostile or merely large configuration must not turn a startup failure
    // into an unbounded log record.
    let plugins: Vec<PluginConfig> = (0..200)
        .map(|i| plugin("jwt_auth", json!({ "algorithm": format!("HS{i:03}") })))
        .collect();
    let err = policy::check_gateway_config_enforced(&config_with(plugins))
        .expect_err("non-approved algorithms are rejected");
    assert!(err.contains("and "), "reports a residual count: {err}");
    assert!(err.len() < 2048, "diagnostic stays bounded: {} bytes", err.len());
}

// ── The gate itself ─────────────────────────────────────────────────────────

#[test]
fn fips_policy_is_inert_when_mode_is_off() {
    // Ordinary deployments must be behaviourally unchanged. The gated wrappers
    // admit configurations the enforced policy refuses.
    assert!(!fips::is_enforcing());

    let mut env_config = EnvConfig::default();
    env_config.tls_no_verify = true;
    policy::check_env_config(&env_config).expect("gated wrapper is inert when mode is off");

    let config = config_with(vec![plugin("kafka_logging", json!({}))]);
    policy::check_gateway_config(&config).expect("gated wrapper is inert when mode is off");
}


// ── Crypto inventory ────────────────────────────────────────────────────────

#[test]
fn inventory_entries_are_all_classified_and_documented() {
    use ferrum_edge::fips::inventory::{self, Disposition};

    assert!(
        inventory::INVENTORY.len() >= 20,
        "the inventory must cover the full acceptance-criteria surface"
    );
    for entry in inventory::INVENTORY {
        assert!(!entry.operation.is_empty(), "every row names an operation");
        assert!(!entry.location.is_empty(), "every row names a source location");
        assert!(
            !entry.implementation.is_empty(),
            "every row names an implementing library"
        );
        assert!(
            !entry.rationale.is_empty(),
            "every row states how its disposition is achieved or enforced: {}",
            entry.operation
        );
        // Exhaustive so a new variant cannot be added without deciding what it
        // means for the honesty invariants below.
        match entry.disposition {
            Disposition::ModuleRoutable
            | Disposition::PendingClassification
            | Disposition::Rejected
            | Disposition::OutsideBoundary => {}
        }
    }
}

#[test]
fn inventory_rejected_plugins_agree_with_the_admission_policy() {
    use ferrum_edge::fips::inventory;

    // The inventory is documentation; the policy is enforcement. If they drift,
    // the document is lying about what the gateway does.
    let rejected_kafka = inventory::rejected()
        .any(|entry| entry.location.contains("kafka_logging"));
    assert_eq!(
        rejected_kafka,
        policy::NON_APPROVED_PLUGINS.contains(&"kafka_logging"),
        "inventory and NON_APPROVED_PLUGINS disagree about kafka_logging"
    );
}

#[test]
fn inventory_records_the_outstanding_module_integration_work() {
    use ferrum_edge::fips::inventory;

    // This build does not link the validated module, so the inventory must
    // still be carrying a non-empty work register. When the integration lands,
    // this assertion is the thing that forces the register to be revisited
    // rather than silently left stale.
    assert!(!fips::BUILD_CAPABLE);
    assert!(
        inventory::pending_classification().count() > 0,
        "a build without the module must not claim a fully routed crypto surface"
    );
}
