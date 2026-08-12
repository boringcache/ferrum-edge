//! Database-mode gateway trust records must reach the LIVE gateway SVID
//! verifier, not just `GatewayConfig.gateway_trust_bundles` (issue #3727).
//!
//! A persisted, validated, polled record that is only loaded into the config
//! projection leaves a database-mode proxy validating gateway-to-mesh peers
//! with the old source-loaded bundle while status reports the persisted
//! generation as published. These tests exercise the production helpers
//! (`ProxyState::install_database_gateway_trust` /
//! `ProxyState::publish_gateway_trust_generation`) and the production reload
//! path (`ProxyState::update_config`) — never a duplicate of either.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use ferrum_edge::config::env_config::{EnvConfig, OperatingMode};
use ferrum_edge::config::gateway_trust::GatewayTrustBundleRecord;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::identity::{
    SvidBundle, TrustBundle as RuntimeTrustBundle, TrustBundleSet as RuntimeTrustBundleSet,
    spiffe::{SpiffeId, TrustDomain},
};
use ferrum_edge::modes::mesh::config::{TrustBundle, TrustBundleSet};
use ferrum_edge::proxy::{ConfigApplyOutcome, DatabaseGatewayTrustInstall, ProxyState};

const TEST_NAMESPACE: &str = "ferrum";

/// Serializable trust material as an admitted database record would carry it.
fn stored_bundle(trust_domain: &str, authority: &[u8]) -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new(trust_domain).expect("test trust domain"),
            x509_authorities: vec![BASE64.encode(authority)],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }
}

fn record(trust_domain: &str, authority: &[u8]) -> GatewayTrustBundleRecord {
    GatewayTrustBundleRecord::new(
        TEST_NAMESPACE,
        &GatewayTrustBundleRecord::default_singleton_id(TEST_NAMESPACE),
        stored_bundle(trust_domain, authority),
    )
}

fn config_with(records: Vec<GatewayTrustBundleRecord>) -> GatewayConfig {
    let mut config = GatewayConfig {
        gateway_trust_bundles: records,
        ..GatewayConfig::default()
    };
    config.normalize_fields();
    config
}

fn source_loaded_svid(trust_domain: &str, authority: &[u8]) -> SvidBundle {
    SvidBundle {
        spiffe_id: SpiffeId::new("spiffe://file.local/ns/ferrum/sa/gateway")
            .expect("test SPIFFE ID should be valid"),
        cert_chain_der: vec![vec![9, 9, 9]],
        private_key_pkcs8_der: Vec::new().into(),
        trust_bundles: RuntimeTrustBundleSet {
            local: RuntimeTrustBundle {
                trust_domain: TrustDomain::new(trust_domain).expect("test trust domain"),
                x509_authorities: vec![authority.to_vec()],
                jwt_authorities: Vec::new(),
                refresh_hint_seconds: None,
            },
            federated: Default::default(),
        },
    }
}

async fn database_mode_state(config: GatewayConfig) -> ProxyState {
    state_in_mode(config, OperatingMode::Database).await
}

async fn state_in_mode(config: GatewayConfig, mode: OperatingMode) -> ProxyState {
    let dns_cache = ferrum_edge::dns::DnsCache::new(ferrum_edge::dns::DnsConfig::default());
    let env_config = EnvConfig {
        mode,
        namespace: TEST_NAMESPACE.to_string(),
        ..EnvConfig::default()
    };
    let (state, _) = ProxyState::new(config, dns_cache, env_config, None, None)
        .expect("test proxy state should build");
    state
}

/// Trust domain of the live gateway trust override, if one is installed.
fn live_override_domain(state: &ProxyState) -> Option<String> {
    state
        .gateway_trust_bundles
        .load_full()
        .as_ref()
        .as_ref()
        .map(|bundles| bundles.local.trust_domain.as_str().to_string())
}

/// Trust domain the active gateway SVID actually validates peers with.
fn active_svid_domain(state: &ProxyState) -> Option<String> {
    state
        .gateway_svid_bundle
        .load_full()
        .as_ref()
        .as_ref()
        .map(|svid| svid.trust_bundles.local.trust_domain.as_str().to_string())
}

fn seed_source_loaded_svid(state: &ProxyState) {
    let file_svid = source_loaded_svid("file.local", &[1, 2, 3]);
    state
        .gateway_file_svid_bundle
        .store(std::sync::Arc::new(Some(file_svid.clone())));
    state
        .gateway_svid_bundle
        .store(std::sync::Arc::new(Some(file_svid)));
}

#[tokio::test]
async fn database_startup_installs_persisted_trust_into_live_verifier() {
    let config = config_with(vec![record("db.local", &[10, 20, 30])]);
    let state = database_mode_state(config.clone()).await;
    seed_source_loaded_svid(&state);

    // Before publication the runtime override is empty — this is exactly the
    // gap: the record is in the config projection but not in the verifier.
    assert_eq!(live_override_domain(&state), None);
    assert_eq!(active_svid_domain(&state).as_deref(), Some("file.local"));

    let outcome = state.publish_gateway_trust_generation(&config);

    assert_eq!(outcome, DatabaseGatewayTrustInstall::Installed);
    assert_eq!(live_override_domain(&state).as_deref(), Some("db.local"));
    assert_eq!(
        active_svid_domain(&state).as_deref(),
        Some("db.local"),
        "the active gateway SVID must validate peers with the persisted database trust"
    );
}

#[tokio::test]
async fn accepted_trust_only_reload_rotates_the_live_verifier() {
    let initial = config_with(vec![record("db-v1.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    assert_eq!(live_override_domain(&state).as_deref(), Some("db-v1.local"));

    // Nothing but the trust record changes: no proxies, consumers, upstreams,
    // or plugin configs exist to produce a resource delta.
    let rotated = config_with(vec![record("db-v2.local", &[2])]);
    let outcome = state.update_config(rotated);

    assert_eq!(
        outcome,
        ConfigApplyOutcome::Applied,
        "a trust-only rotation must publish a fresh generation"
    );
    assert_eq!(live_override_domain(&state).as_deref(), Some("db-v2.local"));
    assert_eq!(active_svid_domain(&state).as_deref(), Some("db-v2.local"));
}

#[tokio::test]
async fn accepted_revocation_withdraws_the_override_and_restores_source_trust() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    assert_eq!(live_override_domain(&state).as_deref(), Some("db.local"));

    // Explicit record deletion.
    let revoked = config_with(Vec::new());
    state.update_config(revoked);

    assert_eq!(
        live_override_domain(&state),
        None,
        "an explicit database revocation must withdraw the runtime override"
    );
    assert_eq!(
        active_svid_domain(&state).as_deref(),
        Some("file.local"),
        "withdrawing the override must restore the source-loaded fallback"
    );
}

#[tokio::test]
async fn unconvertible_stored_material_retains_last_known_good_and_fails_closed() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);

    // Admission guarantees convertibility; this is the broken-invariant case.
    // It must fail closed without panicking and without disturbing the live
    // verifier.
    let mut broken = record("db-broken.local", &[1]);
    broken.bundle.local.x509_authorities = vec!["not-valid-base64!!!".to_string()];
    let candidate = config_with(vec![broken]);

    let outcome = state.publish_gateway_trust_generation(&candidate);

    assert_eq!(outcome, DatabaseGatewayTrustInstall::Failed);
    assert_eq!(
        live_override_domain(&state).as_deref(),
        Some("db.local"),
        "a failed candidate must retain the last known good trust generation"
    );
    assert_eq!(active_svid_domain(&state).as_deref(), Some("db.local"));
}

#[tokio::test]
async fn ambiguous_authority_keeps_the_previous_live_generation() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);

    // A database record AND an unpartitioned file/overlay value: two
    // authorities, so the runtime keeps what it already validates with.
    let mut ambiguous = config_with(vec![record("db-v2.local", &[2])]);
    ambiguous.trust_bundles = Some(Box::new(stored_bundle("overlay.local", &[3])));

    let outcome = state.install_database_gateway_trust(&ambiguous);

    assert_eq!(outcome, DatabaseGatewayTrustInstall::KeptPrevious);
    assert_eq!(live_override_domain(&state).as_deref(), Some("db.local"));
}

#[tokio::test]
async fn non_database_modes_do_not_touch_the_gateway_trust_override() {
    // The CP→DP side channel and the mesh apply loop own this slot in their
    // own modes; database publication must not become a second writer there.
    let config = config_with(vec![record("db.local", &[1])]);
    let state = state_in_mode(config.clone(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);

    let outcome = state.publish_gateway_trust_generation(&config);

    assert_eq!(outcome, DatabaseGatewayTrustInstall::NotApplicable);
    assert_eq!(live_override_domain(&state), None);
    assert_eq!(active_svid_domain(&state).as_deref(), Some("file.local"));
}
