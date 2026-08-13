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
//!
//! The second half of the file pins the **publication boundary** itself: an
//! accepted configuration generation and the gateway trust it accepts must be
//! ONE request-facing generation, so no request can pair new configuration with
//! old trust roots or old configuration with new ones. Those cases drive the
//! production seam step by step (`stage_database_gateway_trust` →
//! `fence_gateway_trust_generation` → `commit_gateway_trust_generation`) and
//! assert at the barrier, rather than racing a window.

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
use ferrum_edge::proxy::{
    ConfigApplyOutcome, DatabaseGatewayTrustInstall, GatewayTrustCommit, ProxyState,
};

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
    source_loaded_svid_generation(trust_domain, authority, &[9, 9, 9], &[8, 8, 8])
}

fn source_loaded_svid_generation(
    trust_domain: &str,
    authority: &[u8],
    leaf: &[u8],
    key: &[u8],
) -> SvidBundle {
    SvidBundle {
        spiffe_id: SpiffeId::new("spiffe://file.local/ns/ferrum/sa/gateway")
            .expect("test SPIFFE ID should be valid"),
        cert_chain_der: vec![leaf.to_vec()],
        private_key_pkcs8_der: key.to_vec().into(),
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

/// Install a source-loaded gateway SVID exactly the way the SVID source
/// watcher does, so the live slots AND the published request epoch agree about
/// which identity this process has.
fn seed_source_loaded_svid(state: &ProxyState) {
    state.install_gateway_runtime_svid_bundle(source_loaded_svid("file.local", &[1, 2, 3]));
}

/// Whether request paths may authenticate gateway-to-mesh peers right now,
/// read exactly the way the dispatch/egress admission gates read it.
fn mesh_admission_open(state: &ProxyState) -> bool {
    state.admits_gateway_mesh_identity()
}

/// `(config generation, gateway trust generation, trust is live)` for the
/// currently published request epoch — the one snapshot a request path loads.
fn published_generations(state: &ProxyState) -> (u64, u64, bool) {
    let epoch = state.request_epoch.load();
    let trust = epoch.gateway_trust();
    (
        epoch.config_generation(),
        trust.generation(),
        trust.is_live(),
    )
}

fn runtime_bundles(trust_domain: &str, authority: &[u8]) -> RuntimeTrustBundleSet {
    stored_bundle(trust_domain, authority)
        .to_runtime()
        .expect("test bundle should convert to runtime trust material")
}

#[tokio::test]
async fn source_rotation_cannot_lift_another_publishers_fence_and_keeps_newest_identity() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    state.install_gateway_runtime_svid_bundle(source_loaded_svid_generation(
        "file.local",
        &[1],
        &[10],
        &[20],
    ));
    state.update_gateway_trust_bundles(runtime_bundles("cp.local", &[7]));

    // Model the exact forbidden interval: another publisher owns the complete
    // publication boundary and has fenced admission but has not committed yet.
    let publication = state
        .gateway_trust_publication_lock
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    state.fence_gateway_trust_generation();
    assert!(!mesh_admission_open(&state));

    let entered = std::sync::Arc::new(std::sync::Barrier::new(2));
    let worker_state = state.clone();
    let worker_entered = entered.clone();
    let worker = std::thread::spawn(move || {
        worker_entered.wait();
        worker_state.install_gateway_runtime_svid_bundle(source_loaded_svid_generation(
            "file.local",
            &[2],
            &[11],
            &[21],
        ));
    });
    entered.wait();

    // Publication is the outer lock. While it is held the source writer cannot
    // have reached the nested material lock or the live-admission republish.
    let material = state
        .gateway_svid_update_lock
        .try_lock()
        .expect("a blocked source writer cannot invert the publication/material lock order");
    assert!(!mesh_admission_open(&state));
    drop(material);
    drop(publication);
    worker.join().expect("source rotation joins");

    let active = state.gateway_svid_bundle.load_full();
    let active = active.as_ref().as_ref().expect("active gateway SVID");
    assert_eq!(active.cert_chain_der, vec![vec![11]]);
    assert_eq!(active.private_key_pkcs8_der.as_slice(), &[21]);
    assert_eq!(
        active.trust_bundles.local.trust_domain.as_str(),
        "cp.local",
        "the newest source leaf/key must retain the authoritative override"
    );
    assert!(mesh_admission_open(&state));
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

// ─── Coherent config/trust publication boundary (issue #3727) ───────────────
//
// A bundle update and the configuration that depends on it are two writes. The
// tests below pin the property that makes them ONE request-facing generation:
// for the whole interval between publishing an accepted configuration and
// installing the trust it accepted, `ProxyState::admits_gateway_mesh_identity`
// — the predicate every gateway-to-mesh admission gate reads — is CLOSED.
//
// They drive the production publication seam step by step
// (`stage_database_gateway_trust` → `fence_gateway_trust_generation` →
// `commit_gateway_trust_generation`), which is the same sequence
// `ProxyState::update_config` runs internally, so the barrier is the test's own
// control flow rather than a timing window. No sleeps, no spin loops, no
// eventual assertions.

#[tokio::test]
async fn rotation_closes_mesh_admission_for_the_whole_publication_boundary() {
    let initial = config_with(vec![record("db-v1.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    assert!(
        mesh_admission_open(&state),
        "the steady state must admit gateway-to-mesh authentication"
    );
    let (_, trust_before, _) = published_generations(&state);

    let rotated = config_with(vec![record("db-v2.local", &[2])]);
    let commit = state
        .stage_database_gateway_trust(&rotated)
        .expect("a convertible candidate must stage");
    assert!(
        commit.changes_live_trust(),
        "a rotation to different material must be staged as a live-trust change"
    );

    // Step 1 of the publication: the accepted generation is published FENCED.
    state.fence_gateway_trust_generation();

    // ── BARRIER ──────────────────────────────────────────────────────────
    // This is the exact instant the old ordering exposed: the accepted
    // generation is live but the verifier still holds the material it
    // replaced. Admission must be refused here, not served from the previous
    // generation's roots.
    assert!(
        !mesh_admission_open(&state),
        "a published generation whose trust is not installed must refuse \
         gateway-to-mesh authentication"
    );
    assert_eq!(
        active_svid_domain(&state).as_deref(),
        Some("db-v1.local"),
        "the fence must not have swapped material yet — that is what makes this \
         interval observable"
    );
    let (_, trust_at_barrier, live_at_barrier) = published_generations(&state);
    assert!(!live_at_barrier);
    assert_eq!(
        trust_at_barrier, trust_before,
        "a fence marks the generation pending; it does not advance it"
    );

    // Step 2: install the material and republish the admission live.
    state.commit_gateway_trust_generation(commit);

    assert!(mesh_admission_open(&state));
    assert_eq!(live_override_domain(&state).as_deref(), Some("db-v2.local"));
    assert_eq!(active_svid_domain(&state).as_deref(), Some("db-v2.local"));
    let (_, trust_after, live_after) = published_generations(&state);
    assert!(live_after);
    assert!(
        trust_after > trust_at_barrier,
        "committing the material must advance the gateway trust generation"
    );
}

#[tokio::test]
async fn revocation_closes_mesh_admission_until_the_root_is_withdrawn() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    assert!(mesh_admission_open(&state));

    // Explicit record deletion: the direction where an un-fenced boundary keeps
    // authenticating a peer the accepted generation withdrew.
    let revoked = config_with(Vec::new());
    let commit = state
        .stage_database_gateway_trust(&revoked)
        .expect("a revocation stages without conversion work");
    assert!(commit.changes_live_trust());

    state.fence_gateway_trust_generation();
    assert!(
        !mesh_admission_open(&state),
        "a revocation must refuse gateway-to-mesh authentication rather than keep \
         validating against the withdrawn root"
    );
    assert_eq!(
        active_svid_domain(&state).as_deref(),
        Some("db.local"),
        "the withdrawn root is still installed at the barrier, which is exactly \
         why admission must be closed"
    );

    state.commit_gateway_trust_generation(commit);
    assert!(mesh_admission_open(&state));
    assert_eq!(live_override_domain(&state), None);
    assert_eq!(active_svid_domain(&state).as_deref(), Some("file.local"));
}

#[tokio::test]
async fn accepted_rotation_through_update_config_publishes_one_coherent_generation() {
    let initial = config_with(vec![record("db-v1.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let (config_before, trust_before, _) = published_generations(&state);

    let rotated = config_with(vec![record("db-v2.local", &[2])]);
    assert_eq!(state.update_config(rotated), ConfigApplyOutcome::Applied);

    let (config_after, trust_after, live_after) = published_generations(&state);
    assert!(config_after > config_before);
    assert!(
        trust_after > trust_before,
        "the accepted configuration generation must carry its own trust generation"
    );
    assert!(
        live_after,
        "the production reload must leave the accepted generation authenticating, \
         never parked behind its own fence"
    );
    assert!(mesh_admission_open(&state));
    assert_eq!(active_svid_domain(&state).as_deref(), Some("db-v2.local"));
    assert_eq!(
        state
            .request_epoch
            .load()
            .config()
            .gateway_trust_bundle_for(TEST_NAMESPACE)
            .map(|record| record.bundle.local.trust_domain.as_str().to_string())
            .as_deref(),
        Some("db-v2.local"),
        "the published configuration and the live verifier must name the same \
         trust domain"
    );
}

#[tokio::test]
async fn unconvertible_candidate_rejects_the_apply_and_retains_the_whole_generation() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let before = published_generations(&state);

    // Admission guarantees convertibility, so this is the broken-invariant
    // case. It must reject the whole apply: publishing the candidate
    // configuration beside the previous trust and calling it live is exactly
    // the half-updated pair issue #3727 forbids.
    let mut broken = record("db-broken.local", &[1]);
    broken.bundle.local.x509_authorities = vec!["not-valid-base64!!!".to_string()];
    let candidate = config_with(vec![broken]);

    assert!(state.stage_database_gateway_trust(&candidate).is_err());
    let outcome = state.update_config(candidate);

    assert!(
        matches!(outcome, ConfigApplyOutcome::Rejected { .. }),
        "a failed trust stage must reject the configuration apply, not publish it"
    );
    assert_eq!(
        published_generations(&state),
        before,
        "the complete previous generation — configuration AND trust — must stay live"
    );
    assert!(mesh_admission_open(&state));
    assert_eq!(live_override_domain(&state).as_deref(), Some("db.local"));
    assert_eq!(active_svid_domain(&state).as_deref(), Some("db.local"));
}

#[tokio::test]
async fn a_reload_that_changes_no_trust_never_closes_mesh_admission() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let (_, trust_before, _) = published_generations(&state);

    // Byte-identical trust inputs: an ordinary reload on a gateway that HAS a
    // trust record must cost nothing and must not fence the admission gate,
    // otherwise every poll tick would briefly refuse mesh traffic. The live
    // config is the candidate a re-poll of the same unchanged row produces —
    // record equality includes the stored `created_at`/`updated_at`, so
    // reconstructing the record here would compare unequal for reasons a real
    // poll never sees.
    let same_trust = state.config.load_full().as_ref().clone();
    let commit = state
        .stage_database_gateway_trust(&same_trust)
        .expect("an unchanged candidate stages");
    assert!(
        !commit.changes_live_trust(),
        "unchanged trust inputs must stage as Unchanged"
    );

    state.commit_gateway_trust_generation(commit);
    let (_, trust_after, live_after) = published_generations(&state);
    assert!(live_after);
    assert_eq!(
        trust_after, trust_before,
        "an unchanged commit must not advance the gateway trust generation"
    );
    assert!(mesh_admission_open(&state));
}

#[tokio::test]
async fn ambiguous_authority_stages_unchanged_and_keeps_the_complete_generation() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let before = published_generations(&state);

    let mut ambiguous = config_with(vec![record("db-v2.local", &[2])]);
    ambiguous.trust_bundles = Some(Box::new(stored_bundle("overlay.local", &[3])));

    let commit = state
        .stage_database_gateway_trust(&ambiguous)
        .expect("ambiguity is a refusal, not a staging error");
    assert!(
        !commit.changes_live_trust(),
        "two authorities must keep the last known good generation rather than \
         publishing either one"
    );

    state.commit_gateway_trust_generation(commit);
    assert_eq!(published_generations(&state), before);
    assert!(mesh_admission_open(&state));
    assert_eq!(live_override_domain(&state).as_deref(), Some("db.local"));
}

// ─── DP FULL_SNAPSHOT: CP trust rides WITH the snapshot ─────────────────────

#[tokio::test]
async fn dp_snapshot_publishes_cp_trust_with_its_own_configuration_generation() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    let (config_before, trust_before, _) = published_generations(&state);
    assert!(mesh_admission_open(&state));

    // A CP snapshot carrying a namespace-projected trust Replace. The DP's
    // configuration never carries `gateway_trust_bundles` (the CP strips it),
    // so the decision must be handed to the publication rather than applied
    // after it.
    let snapshot = GatewayConfig {
        version: "dp-1".to_string(),
        ..GatewayConfig::default()
    };
    let outcome = state.update_config_with_gateway_trust(
        snapshot,
        GatewayTrustCommit::Replace(runtime_bundles("cp.local", &[7, 7, 7])),
    );
    assert!(matches!(
        outcome,
        ConfigApplyOutcome::Applied | ConfigApplyOutcome::Unchanged
    ));

    let (config_after, trust_after, live_after) = published_generations(&state);
    assert!(
        live_after,
        "the accepted snapshot must end up authenticating"
    );
    assert!(mesh_admission_open(&state));
    assert!(
        trust_after > trust_before,
        "CP-delivered trust must advance the published trust generation"
    );
    assert!(config_after >= config_before);
    assert_eq!(live_override_domain(&state).as_deref(), Some("cp.local"));
    assert_eq!(active_svid_domain(&state).as_deref(), Some("cp.local"));
}

#[tokio::test]
async fn dp_unchanged_side_channel_leaves_the_live_trust_generation_untouched() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    state.update_config_with_gateway_trust(
        GatewayConfig::default(),
        GatewayTrustCommit::Replace(runtime_bundles("cp.local", &[7])),
    );
    let before = published_generations(&state);

    // An ordinary delta with an empty side channel means "no trust change".
    let next = GatewayConfig {
        version: "dp-2".to_string(),
        ..GatewayConfig::default()
    };
    state.update_config_with_gateway_trust(next, GatewayTrustCommit::Unchanged);

    assert_eq!(
        published_generations(&state),
        before,
        "an Unchanged side channel must not rotate, withdraw, or re-publish trust"
    );
    assert_eq!(live_override_domain(&state).as_deref(), Some("cp.local"));
    assert!(mesh_admission_open(&state));
}

#[tokio::test]
async fn dp_snapshot_clear_withdraws_cp_trust_with_the_accepted_generation() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    state.update_config_with_gateway_trust(
        GatewayConfig::default(),
        GatewayTrustCommit::Replace(runtime_bundles("cp.local", &[7])),
    );
    assert_eq!(active_svid_domain(&state).as_deref(), Some("cp.local"));

    let cleared = GatewayConfig {
        version: "dp-3".to_string(),
        ..GatewayConfig::default()
    };
    state.update_config_with_gateway_trust(cleared, GatewayTrustCommit::Clear);

    assert!(mesh_admission_open(&state));
    assert_eq!(live_override_domain(&state), None);
    assert_eq!(
        active_svid_domain(&state).as_deref(),
        Some("file.local"),
        "an explicit CP clear must restore the source-loaded gateway trust"
    );
}

// ─── Backend security generation: withdrawn trust must not stay poolable ────
//
// Installing the accepted verifier is only half of a rotation/revocation. Every
// backend and mesh transport already in a pool was authenticated under the
// OUTGOING roots, so a generation that replaces or withdraws gateway trust must
// also advance the shared backend security (SVID) generation — the counter that
// partitions `|svidg=` pool keys and backend TLS config caches, invalidates the
// outgoing generation's cached TLS configs, restarts health checks, and
// schedules the bounded force-drain of HTTP/2, gRPC, H3, HBONE, and
// mesh-mTLS/connection-pool entries. Without it an HBONE or mesh-mTLS
// connection authenticated under a root the accepted generation withdrew stays
// reusable until idle pruning, which is unbounded.
//
// The advance must also be SYNCHRONOUS: publishing only on the rotation watch
// and leaving the counter to the consumer task would let the fence lift before
// the consumer was scheduled, and every request admitted in that window would
// key its pool lookups on the withdrawn generation.
//
// These tests run on the default `#[tokio::test]` current-thread runtime, so
// the rotation consumer task cannot be polled between two synchronous
// statements. Every assertion below is therefore about the publishing call's
// OWN writes, not about eventual observation by another task.

/// The counter backend pools stamp into their keys and the TLS config caches
/// partition on — read exactly the way a dispatching request reads it.
fn backend_security_generation(state: &ProxyState) -> u64 {
    state
        .backend_svid_generation
        .load(std::sync::atomic::Ordering::Acquire)
}

/// The rotation revision the drain consumer keys off. Equal to the live
/// generation means the outgoing generation's cache invalidation, health-check
/// restart, and bounded force-drain are scheduled for exactly the generation
/// that just retired.
fn scheduled_rotation_revision(state: &ProxyState) -> u64 {
    *state.backend_svid_rotation_tx.borrow()
}

fn empty_delta() -> ferrum_edge::config::db_loader::IncrementalResult {
    ferrum_edge::config::db_loader::IncrementalResult {
        added_or_modified_proxies: Vec::new(),
        removed_proxy_ids: Vec::new(),
        added_or_modified_consumers: Vec::new(),
        removed_consumer_ids: Vec::new(),
        added_or_modified_plugin_configs: Vec::new(),
        removed_plugin_config_ids: Vec::new(),
        added_or_modified_upstreams: Vec::new(),
        removed_upstream_ids: Vec::new(),
        sequence_cursor: 0,
        poll_timestamp: chrono::DateTime::from_timestamp(1_700_000_000, 0)
            .expect("valid test timestamp"),
    }
}

#[tokio::test]
async fn a_committed_rotation_advances_the_backend_security_generation_inside_the_fence() {
    let initial = config_with(vec![record("db-v1.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let before = backend_security_generation(&state);

    let rotated = config_with(vec![record("db-v2.local", &[2])]);
    let commit = state
        .stage_database_gateway_trust(&rotated)
        .expect("a convertible candidate must stage");
    assert!(commit.changes_live_trust());

    state.fence_gateway_trust_generation();

    // ── BARRIER ──────────────────────────────────────────────────────────
    // Admission is closed, so nothing can dispatch to the mesh here. Staging
    // and fencing are not a rotation: the counter must not move until the
    // material is actually installed.
    assert!(!mesh_admission_open(&state));
    assert_eq!(
        backend_security_generation(&state),
        before,
        "fencing a pending generation must not rotate the backend pools"
    );

    state.commit_gateway_trust_generation(commit);

    // One synchronous call installed the material, advanced the generation, and
    // only then re-opened admission. Nothing can observe an intermediate state,
    // so no request is ever admitted under the accepted trust while still
    // keying its pool lookups on the withdrawn generation.
    assert!(mesh_admission_open(&state));
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "committing replaced gateway trust must advance the backend security \
         generation exactly once"
    );
    assert_eq!(
        scheduled_rotation_revision(&state),
        before + 1,
        "the rotation consumer must be told to invalidate caches, restart health \
         checks, and force-drain exactly the generation that just retired"
    );
}

#[tokio::test]
async fn a_committed_revocation_retires_the_withdrawn_generation_exactly_once() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let before = backend_security_generation(&state);

    // Explicit record deletion: the direction where a pooled transport
    // authenticated under the withdrawn root must not survive unbounded.
    let revoked = config_with(Vec::new());
    let commit = state
        .stage_database_gateway_trust(&revoked)
        .expect("a revocation stages without conversion work");
    assert!(commit.changes_live_trust());

    state.commit_gateway_trust_generation(commit);

    assert_eq!(live_override_domain(&state), None);
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "an explicit clear must retire the transports the withdrawn root \
         authenticated"
    );
    assert_eq!(scheduled_rotation_revision(&state), before + 1);
}

#[tokio::test]
async fn an_unchanged_commit_never_churns_the_backend_pools() {
    let initial = config_with(vec![record("db.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let before = backend_security_generation(&state);
    let revision_before = scheduled_rotation_revision(&state);

    // The live config is the candidate a re-poll of the same unchanged row
    // produces (see `a_reload_that_changes_no_trust_never_closes_mesh_admission`
    // for why it is read back rather than reconstructed).
    let same_trust = state.config.load_full().as_ref().clone();
    let commit = state
        .stage_database_gateway_trust(&same_trust)
        .expect("an unchanged candidate stages");
    assert!(!commit.changes_live_trust());

    state.commit_gateway_trust_generation(commit);

    assert_eq!(
        backend_security_generation(&state),
        before,
        "an Unchanged commit changes no material, so rotating every pooled \
         transport would be a self-inflicted reconnect storm on every poll tick"
    );
    assert_eq!(scheduled_rotation_revision(&state), revision_before);
    assert!(mesh_admission_open(&state));
}

#[tokio::test]
async fn the_database_full_apply_advances_the_backend_security_generation_once() {
    let initial = config_with(vec![record("db-v1.local", &[1])]);
    let state = database_mode_state(initial.clone()).await;
    seed_source_loaded_svid(&state);
    state.publish_gateway_trust_generation(&initial);
    let before = backend_security_generation(&state);

    // The production reload path, not the step-by-step seam: it stages, fences,
    // publishes, installs, and re-opens admission internally. Exactly one of
    // those steps may rotate the pools — a helper that fences and commits twice
    // would double-rotate here.
    let rotated = config_with(vec![record("db-v2.local", &[2])]);
    assert_eq!(state.update_config(rotated), ConfigApplyOutcome::Applied);

    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "a database full apply that replaces gateway trust must rotate the \
         backend pools exactly once"
    );
    assert_eq!(scheduled_rotation_revision(&state), before + 1);
    assert_eq!(active_svid_domain(&state).as_deref(), Some("db-v2.local"));

    // An ordinary reload behind it must be free.
    let steady = state.config.load_full().as_ref().clone();
    state.update_config(steady);
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "a reload that changes no trust must not rotate the pools again"
    );
}

#[tokio::test]
async fn dp_snapshot_replace_then_clear_each_rotate_the_backend_pools_once() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    let before = backend_security_generation(&state);

    let replaced = GatewayConfig {
        version: "dp-1".to_string(),
        ..GatewayConfig::default()
    };
    state.update_config_with_gateway_trust(
        replaced,
        GatewayTrustCommit::Replace(runtime_bundles("cp.local", &[7, 7, 7])),
    );
    assert_eq!(active_svid_domain(&state).as_deref(), Some("cp.local"));
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "a CP-delivered Replace riding a full snapshot must rotate the pools once"
    );

    let steady = GatewayConfig {
        version: "dp-2".to_string(),
        ..GatewayConfig::default()
    };
    state.update_config_with_gateway_trust(steady, GatewayTrustCommit::Unchanged);
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "an Unchanged side channel must not rotate the pools"
    );

    let cleared = GatewayConfig {
        version: "dp-3".to_string(),
        ..GatewayConfig::default()
    };
    state.update_config_with_gateway_trust(cleared, GatewayTrustCommit::Clear);
    assert_eq!(active_svid_domain(&state).as_deref(), Some("file.local"));
    assert_eq!(
        backend_security_generation(&state),
        before + 2,
        "a CP-delivered Clear must retire the transports the withdrawn CP root \
         authenticated"
    );
    assert_eq!(scheduled_rotation_revision(&state), before + 2);
}

#[tokio::test]
async fn a_cp_trust_only_delta_rotates_the_backend_pools_once() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    let before = backend_security_generation(&state);

    // A CP trust-only update carries no resources at all, so the incremental
    // apply short-circuits before any configuration publication. That path has
    // no fenced publication to inherit, so it must fence, install, rotate, and
    // re-open admission on its own.
    let replace = GatewayTrustCommit::Replace(runtime_bundles("cp-delta.local", &[4, 2]));
    let outcome = state
        .apply_incremental_with_gateway_trust(empty_delta(), Some(replace))
        .await;

    assert_eq!(outcome, ConfigApplyOutcome::Unchanged);
    assert_eq!(
        active_svid_domain(&state).as_deref(),
        Some("cp-delta.local")
    );
    assert!(mesh_admission_open(&state));
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "a trust-only delta must rotate the backend pools exactly once"
    );
    assert_eq!(scheduled_rotation_revision(&state), before + 1);

    let unchanged = state
        .apply_incremental_with_gateway_trust(empty_delta(), Some(GatewayTrustCommit::Unchanged))
        .await;
    assert_eq!(unchanged, ConfigApplyOutcome::Unchanged);
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "an empty delta with an Unchanged side channel must change nothing"
    );
}

#[tokio::test]
async fn the_new_generation_is_visible_without_the_rotation_consumer_running() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    let before = backend_security_generation(&state);

    let snapshot = GatewayConfig {
        version: "dp-sync".to_string(),
        ..GatewayConfig::default()
    };

    // No `.await` between the publishing call and the assertions, on a
    // current-thread runtime: the rotation consumer task cannot have been
    // polled. Anything observed here was written by the publishing call itself.
    // This is the property that closes the post-unfence reuse window — a watch
    // send alone would leave the counter at `before` right here, and every
    // request admitted after the fence lifted would select pool entries and
    // cached backend TLS configs belonging to the withdrawn generation.
    state.update_config_with_gateway_trust(
        snapshot,
        GatewayTrustCommit::Replace(runtime_bundles("cp-sync.local", &[5])),
    );

    assert!(
        mesh_admission_open(&state),
        "the accepted generation must be authenticating once the call returns"
    );
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "the publishing call must make the new backend security generation \
         visible itself, not leave it to an asynchronous watch consumer"
    );
    assert_eq!(
        scheduled_rotation_revision(&state),
        backend_security_generation(&state),
        "the live generation and the drain consumer's target must not diverge"
    );
}

// ─── Retirement is scoped to an actual WITHDRAWAL ───────────────────────────
//
// Advancing the backend security generation re-partitions every generation-keyed
// pool, and (issue #3727) a committed withdrawal now also retires the two
// fingerprint-keyed mesh pools WHOLE, synchronously, regardless of
// `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS`. That is the right price for a
// revocation and the wrong price for anything else, so the predicate that gates
// it is "does this decision remove a root the live verifier currently honours",
// not "does this decision touch trust material".
//
// The distinction is load-bearing, not cosmetic: the CP encodes "this gateway
// has no trust bundles" as an explicit `Clear` on EVERY full snapshot, and a DP
// reconnect re-delivers an unchanged `Replace` verbatim. Treating either as a
// withdrawal would drop every pooled mesh transport on the node each time a DP
// reconnects — for deployments that never revoked anything, and in the common
// case for deployments that use no CP trust bundles at all.

/// Runtime trust material with an explicit authority list, so a test can express
/// "the same roots", "one more root", and "a root removed".
fn runtime_bundles_with(trust_domain: &str, authorities: &[&[u8]]) -> RuntimeTrustBundleSet {
    RuntimeTrustBundleSet {
        local: RuntimeTrustBundle {
            trust_domain: TrustDomain::new(trust_domain).expect("test trust domain"),
            x509_authorities: authorities.iter().map(|root| root.to_vec()).collect(),
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Default::default(),
    }
}

/// How many roots the live gateway verifier actually anchors SVID chains to —
/// the proof that a decision was INSTALLED even when it retired nothing.
fn active_svid_authority_count(state: &ProxyState) -> usize {
    state
        .gateway_svid_bundle
        .load_full()
        .as_ref()
        .as_ref()
        .map(|svid| svid.trust_bundles.local.x509_authorities.len())
        .unwrap_or(0)
}

fn dp_snapshot(version: &str) -> GatewayConfig {
    GatewayConfig {
        version: version.to_string(),
        ..GatewayConfig::default()
    }
}

#[tokio::test]
async fn an_identical_replace_redelivered_by_a_reconnect_never_rotates_the_backend_pools() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    state.update_config_with_gateway_trust(
        dp_snapshot("dp-1"),
        GatewayTrustCommit::Replace(runtime_bundles_with("cp.local", &[&[7]])),
    );
    let before = backend_security_generation(&state);
    let revision_before = scheduled_rotation_revision(&state);

    // A DP reconnect re-delivers the same bundles verbatim on its FULL_SNAPSHOT.
    state.update_config_with_gateway_trust(
        dp_snapshot("dp-reconnect"),
        GatewayTrustCommit::Replace(runtime_bundles_with("cp.local", &[&[7]])),
    );

    assert_eq!(
        backend_security_generation(&state),
        before,
        "re-delivering the same trust material removes no root, so it must not \
         rotate the backend pools — a reconnect is not a revocation"
    );
    assert_eq!(scheduled_rotation_revision(&state), revision_before);
    assert!(mesh_admission_open(&state));
    assert_eq!(live_override_domain(&state).as_deref(), Some("cp.local"));
}

#[tokio::test]
async fn a_purely_additive_replace_installs_the_root_without_rotating_the_backend_pools() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    state.update_config_with_gateway_trust(
        dp_snapshot("dp-1"),
        GatewayTrustCommit::Replace(runtime_bundles_with("cp.local", &[&[7]])),
    );
    let before = backend_security_generation(&state);
    assert_eq!(active_svid_authority_count(&state), 1);

    // Cross-sign overlap: the incoming root is published ALONGSIDE the one it
    // will eventually replace. Every transport the live verifier already
    // admitted was admitted by a root that is still a root.
    state.update_config_with_gateway_trust(
        dp_snapshot("dp-overlap"),
        GatewayTrustCommit::Replace(runtime_bundles_with("cp.local", &[&[7], &[8]])),
    );

    assert_eq!(
        active_svid_authority_count(&state),
        2,
        "the added root must be live — the decision is still installed, it just \
         retires nothing"
    );
    assert_eq!(
        backend_security_generation(&state),
        before,
        "adding a root is overlap, not withdrawal, so no pooled transport becomes \
         unusable and none may be retired"
    );
    assert!(mesh_admission_open(&state));
}

#[tokio::test]
async fn a_replace_that_drops_a_root_retires_the_transports_it_authenticated() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    state.update_config_with_gateway_trust(
        dp_snapshot("dp-overlap"),
        GatewayTrustCommit::Replace(runtime_bundles_with("cp.local", &[&[7], &[8]])),
    );
    let before = backend_security_generation(&state);

    // The second half of the cross-sign rotation: the outgoing root is dropped.
    // A transport admitted by it must not survive.
    state.update_config_with_gateway_trust(
        dp_snapshot("dp-drop"),
        GatewayTrustCommit::Replace(runtime_bundles_with("cp.local", &[&[8]])),
    );

    assert_eq!(active_svid_authority_count(&state), 1);
    assert_eq!(
        backend_security_generation(&state),
        before + 1,
        "dropping a root the live verifier honoured is a withdrawal and must \
         retire the transports it authenticated"
    );
    assert_eq!(scheduled_rotation_revision(&state), before + 1);
    assert!(mesh_admission_open(&state));
}

#[tokio::test]
async fn a_clear_with_no_installed_override_never_rotates_the_backend_pools() {
    let state = state_in_mode(GatewayConfig::default(), OperatingMode::DataPlane).await;
    seed_source_loaded_svid(&state);
    let before = backend_security_generation(&state);
    let revision_before = scheduled_rotation_revision(&state);
    assert_eq!(live_override_domain(&state), None);

    // Every CP full snapshot of a gateway with no trust bundles carries an
    // explicit `Clear`. There is no override to withdraw.
    state.update_config_with_gateway_trust(dp_snapshot("dp-1"), GatewayTrustCommit::Clear);

    assert_eq!(
        backend_security_generation(&state),
        before,
        "a Clear that withdraws nothing must not rotate the backend pools; a DP \
         reconnect would otherwise retire every pooled mesh transport on the node"
    );
    assert_eq!(scheduled_rotation_revision(&state), revision_before);
    assert!(mesh_admission_open(&state));
    assert_eq!(
        active_svid_domain(&state).as_deref(),
        Some("file.local"),
        "the source-loaded gateway trust stays live"
    );
}
