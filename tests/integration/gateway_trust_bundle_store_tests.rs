//! Integration coverage for the authoritative gateway trust-bundle store and
//! its control-plane propagation (issue #3727).
//!
//! The SQL half exercises the SQLite path because every SQL backend
//! (PostgreSQL, MySQL, SQLite) shares one `DatabaseStore` implementation behind
//! dialect-specific rendering — the same reasoning `db_incremental_poll_tests`
//! documents. Backend-specific rendering is covered by the shared v001 baseline
//! (`sql_dialect.rs`), and the MongoDB implementation is exercised by the
//! MongoDB functional suite; what is unique to this resource — transactional
//! change recording, namespace predication, optimistic concurrency, validate-
//! before-swap, and the ConfigSync projection — is backend-independent and is
//! asserted here.

use base64::Engine;
use chrono::Utc;
use ferrum_edge::config::db_backend::{
    FullConfigLoadPurpose, IncrementalFullReloadReason, gateway_trust_bundle_revision_conflict,
    is_incremental_full_reload_required,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::gateway_trust::GatewayTrustBundleRecord;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::grpc::cp_server::{CpGrpcServer, CpScope};
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{TrustBundle, TrustBundleSet};
use tempfile::TempDir;

async fn sqlite_store() -> (DatabaseStore, TempDir) {
    let temp_dir = TempDir::new().expect("temp dir");
    let db_path = temp_dir.path().join("gateway_trust_bundle_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    let store = DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store creation must succeed");
    (store, temp_dir)
}

/// Reopen the same on-disk database with a fresh store, standing in for a
/// control-plane restart: nothing survives in process memory, so whatever the
/// reopened store returns came solely from the authoritative database.
async fn reopen(temp_dir: &TempDir) -> DatabaseStore {
    let db_path = temp_dir.path().join("gateway_trust_bundle_test.db");
    let db_url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &db_url, DbPoolConfig::default())
        .await
        .expect("SQLite store reopen must succeed")
}

fn root_ca_der_base64(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("test CA key generates");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("test CA params build");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("test CA self-signs");
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

fn record(
    namespace: &str,
    trust_domain: &str,
    authorities: Vec<String>,
) -> GatewayTrustBundleRecord {
    let bundle = TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new(trust_domain).expect("fixture trust domain"),
            x509_authorities: authorities,
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    };
    GatewayTrustBundleRecord::new(namespace, namespace, bundle)
}

// ── CRUD lifecycle ──────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn create_rotate_revoke_round_trips_through_the_authoritative_store() {
    let (store, temp_dir) = sqlite_store().await;
    let root_a = root_ca_der_base64("root-a");
    let created = record("ferrum", "cluster.local", vec![root_a.clone()]);

    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create must succeed");

    let loaded = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read must succeed")
        .expect("the record must exist");
    assert_eq!(loaded.trust_domain, "cluster.local");
    assert_eq!(loaded.bundle.local.x509_authorities, vec![root_a.clone()]);
    assert_eq!(loaded.revision, 1);

    // Rotation with overlap: the new root is added alongside the old one so
    // in-flight workloads keep validating during rollout.
    let root_b = root_ca_der_base64("root-b");
    let mut rotated = loaded.clone();
    rotated.bundle.local.x509_authorities = vec![root_a.clone(), root_b.clone()];
    assert!(
        store
            .update_gateway_trust_bundle(&rotated, Some(loaded.revision))
            .await
            .expect("rotation must succeed")
    );

    let after_rotation = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read must succeed")
        .expect("record still exists");
    assert_eq!(
        after_rotation.bundle.local.x509_authorities,
        vec![root_a.clone(), root_b.clone()]
    );
    assert_eq!(
        after_rotation.revision, 2,
        "the store assigns the next revision itself"
    );

    // A restart must reconstruct exactly this state from the database alone.
    drop(store);
    let reopened = reopen(&temp_dir).await;
    let after_restart = reopened
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read after restart must succeed")
        .expect("record survives restart");
    assert_eq!(after_restart, after_rotation);

    // Explicit revocation.
    assert!(
        reopened
            .delete_gateway_trust_bundle("ferrum", &after_restart.id)
            .await
            .expect("delete must succeed")
    );
    assert!(
        reopened
            .get_namespace_gateway_trust_bundle("ferrum")
            .await
            .expect("read must succeed")
            .is_none()
    );
    assert!(
        !reopened
            .delete_gateway_trust_bundle("ferrum", &after_restart.id)
            .await
            .expect("second delete must not error"),
        "a repeat delete reports 'nothing matched', not a phantom success"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn an_update_that_matches_no_row_reports_not_found_instead_of_a_phantom_success() {
    let (store, _temp_dir) = sqlite_store().await;
    let ghost = record("ferrum", "cluster.local", vec![root_ca_der_base64("ghost")]);
    assert!(
        !store
            .update_gateway_trust_bundle(&ghost, None)
            .await
            .expect("update of an absent record must not error")
    );
    // A phantom update must not leave a change-log record behind either.
    let sequence = store
        .latest_change_sequence("ferrum")
        .await
        .expect("sequence read");
    assert_eq!(sequence, 0, "a phantom update must record no config change");
}

// ── Optimistic concurrency ──────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_stale_revision_loses_the_race_without_overwriting() {
    let (store, _temp_dir) = sqlite_store().await;
    let root_a = root_ca_der_base64("root-a");
    let created = record("ferrum", "cluster.local", vec![root_a.clone()]);
    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create must succeed");

    let read_by_both = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");

    // Writer A commits.
    let mut writer_a = read_by_both.clone();
    writer_a.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-a")];
    assert!(
        store
            .update_gateway_trust_bundle(&writer_a, Some(read_by_both.revision))
            .await
            .expect("first writer wins")
    );

    // Writer B still holds the revision it read before A committed.
    let mut writer_b = read_by_both.clone();
    writer_b.bundle.local.x509_authorities = vec![root_ca_der_base64("writer-b")];
    let error = store
        .update_gateway_trust_bundle(&writer_b, Some(read_by_both.revision))
        .await
        .expect_err("the stale writer must be refused");
    let conflict =
        gateway_trust_bundle_revision_conflict(&error).expect("a typed revision conflict");
    assert_eq!(conflict.expected, read_by_both.revision);
    assert_eq!(conflict.current, read_by_both.revision + 1);

    // Writer A's material is still the one stored.
    let stored = store
        .get_namespace_gateway_trust_bundle("ferrum")
        .await
        .expect("read")
        .expect("exists");
    assert_eq!(
        stored.bundle.local.x509_authorities,
        writer_a.bundle.local.x509_authorities,
        "the lost race must not overwrite the winner's roots"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_second_record_in_one_namespace_is_refused_by_the_store() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("first")],
        ))
        .await
        .expect("first create must succeed");

    let mut second = record("ferrum", "other.local", vec![root_ca_der_base64("second")]);
    second.id = "second".to_string();
    store
        .create_gateway_trust_bundle(&second)
        .await
        .expect_err("the namespace primary key must refuse a second record");
}

// ── Namespace isolation ─────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn one_namespace_can_neither_read_nor_delete_another_namespaces_record() {
    let (store, _temp_dir) = sqlite_store().await;
    let tenant_a = record("tenant-a", "a.local", vec![root_ca_der_base64("a-root")]);
    let tenant_b = record("tenant-b", "b.local", vec![root_ca_der_base64("b-root")]);
    store
        .create_gateway_trust_bundle(&tenant_a)
        .await
        .expect("tenant-a create");
    store
        .create_gateway_trust_bundle(&tenant_b)
        .await
        .expect("tenant-b create");

    // Addressing tenant B's id from tenant A's namespace resolves to nothing —
    // the namespace is in the WHERE clause, not applied after the read.
    assert!(
        store
            .get_gateway_trust_bundle("tenant-a", &tenant_b.id)
            .await
            .expect("read must succeed")
            .is_none()
    );
    assert!(
        !store
            .delete_gateway_trust_bundle("tenant-a", &tenant_b.id)
            .await
            .expect("delete must succeed")
    );
    assert!(
        store
            .get_namespace_gateway_trust_bundle("tenant-b")
            .await
            .expect("read must succeed")
            .is_some(),
        "tenant-b's record must survive tenant-a's delete attempt"
    );

    // Listing is namespace-scoped too.
    let page = store
        .list_gateway_trust_bundles_paginated("tenant-a", 50, 0)
        .await
        .expect("list must succeed");
    assert_eq!(page.total, 1);
    assert_eq!(page.items.len(), 1);
    assert_eq!(page.items[0].namespace, "tenant-a");
}

// ── Change detection ────────────────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn every_trust_mutation_escalates_the_incremental_poll_to_a_full_reload() {
    let (store, _temp_dir) = sqlite_store().await;
    let start = store
        .latest_change_sequence("ferrum")
        .await
        .expect("sequence read");

    let created = record("ferrum", "cluster.local", vec![root_ca_der_base64("root")]);
    store
        .create_gateway_trust_bundle(&created)
        .await
        .expect("create");

    let error = store
        .load_incremental_config("ferrum", start)
        .await
        .expect_err("a trust change must escalate");
    assert!(
        is_incremental_full_reload_required(&error),
        "the escalation must be the typed full-reload marker, not a generic failure"
    );
    let typed = error
        .chain()
        .find_map(|cause| {
            cause.downcast_ref::<ferrum_edge::config::db_backend::IncrementalFullReloadRequired>()
        })
        .expect("typed marker present");
    assert_eq!(
        typed.reason(),
        IncrementalFullReloadReason::GatewayTrustBundleChanges
    );

    // The same holds for a revocation, so a subscribed data plane learns about
    // a withdrawn root without a restart.
    let after_create = store
        .latest_change_sequence("ferrum")
        .await
        .expect("sequence read");
    store
        .delete_gateway_trust_bundle("ferrum", &created.id)
        .await
        .expect("delete");
    let revocation_error = store
        .load_incremental_config("ferrum", after_create)
        .await
        .expect_err("a revocation must escalate too");
    assert!(is_incremental_full_reload_required(&revocation_error));
}

// ── Full loads and validate-before-swap ─────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_full_load_carries_only_the_requested_namespaces_record() {
    let (store, _temp_dir) = sqlite_store().await;
    store
        .create_gateway_trust_bundle(&record(
            "tenant-a",
            "a.local",
            vec![root_ca_der_base64("a-root")],
        ))
        .await
        .expect("tenant-a create");
    store
        .create_gateway_trust_bundle(&record(
            "tenant-b",
            "b.local",
            vec![root_ca_der_base64("b-root")],
        ))
        .await
        .expect("tenant-b create");

    let config = store
        .load_full_config_for_purpose("tenant-a", FullConfigLoadPurpose::ControlPlane)
        .await
        .expect("full load must succeed");
    assert_eq!(config.gateway_trust_bundles.len(), 1);
    assert_eq!(config.gateway_trust_bundles[0].namespace, "tenant-a");
    assert_eq!(config.gateway_trust_bundles[0].trust_domain, "a.local");
}

#[tokio::test(flavor = "multi_thread")]
async fn a_corrupted_stored_bundle_rejects_the_load_without_leaking_material() {
    let (store, _temp_dir) = sqlite_store().await;
    let secret_marker = "SUPER-SECRET-TRUST-MATERIAL";
    store
        .create_gateway_trust_bundle(&record(
            "ferrum",
            "cluster.local",
            vec![root_ca_der_base64("root")],
        ))
        .await
        .expect("create");

    // Corrupt the stored material out-of-band, as a bad migration or a direct
    // database edit would. The load must fail closed rather than publishing an
    // unverifiable generation.
    let bad_bundle = serde_json::json!({
        "local": {
            "trust_domain": "cluster.local",
            "x509_authorities": [secret_marker],
        }
    })
    .to_string();
    sqlx::query("UPDATE gateway_trust_bundles SET bundle = ? WHERE namespace = ?")
        .bind(&bad_bundle)
        .bind("ferrum")
        .execute(&store.pool())
        .await
        .expect("out-of-band corruption applies");

    let error = store
        .load_full_config_for_purpose("ferrum", FullConfigLoadPurpose::ControlPlane)
        .await
        .expect_err("an invalid stored bundle must reject the load");
    let rendered = format!("{error:#}");
    assert!(
        !rendered.contains(secret_marker),
        "a rejection must never echo stored trust material: {rendered}"
    );
}

// ── ConfigSync projection ───────────────────────────────────────────────────

fn config_with_records(records: Vec<GatewayTrustBundleRecord>) -> GatewayConfig {
    GatewayConfig {
        version: "1".to_string(),
        loaded_at: Utc::now(),
        gateway_trust_bundles: records,
        ..Default::default()
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn the_control_plane_projects_only_the_subscribers_namespace() {
    let tenant_a = record("tenant-a", "a.local", vec![root_ca_der_base64("a-root")]);
    let tenant_b = record("tenant-b", "b.local", vec![root_ca_der_base64("b-root")]);
    let config = config_with_records(vec![tenant_a.clone(), tenant_b.clone()]);

    let scope = CpScope::Set(
        ["tenant-a".to_string(), "tenant-b".to_string()]
            .into_iter()
            .collect(),
    );
    let filtered = CpGrpcServer::filter_config_to_namespace_for_scope(&config, "tenant-a", &scope);

    let projected = filtered
        .trust_bundles
        .as_deref()
        .expect("tenant-a receives its own record");
    assert_eq!(projected.local.trust_domain.as_str(), "a.local");
    assert_eq!(
        filtered.gateway_trust_bundles.len(),
        1,
        "the record vector must be pruned to the subscriber's namespace"
    );
    assert_eq!(filtered.gateway_trust_bundles[0].namespace, "tenant-a");

    // Nothing anywhere in the filtered snapshot mentions tenant B's identity.
    let rendered = serde_json::to_string(&filtered).expect("filtered config serializes");
    assert!(
        !rendered.contains("b.local"),
        "tenant-a's slice must not carry tenant-b's trust domain"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_namespace_without_a_record_receives_no_trust_material() {
    let tenant_a = record("tenant-a", "a.local", vec![root_ca_der_base64("a-root")]);
    let config = config_with_records(vec![tenant_a]);

    let scope = CpScope::Set(
        ["tenant-a".to_string(), "tenant-b".to_string()]
            .into_iter()
            .collect(),
    );
    let filtered = CpGrpcServer::filter_config_to_namespace_for_scope(&config, "tenant-b", &scope);
    assert!(
        filtered.trust_bundles.is_none(),
        "a namespace with no record must receive nothing, not another tenant's roots"
    );
    assert!(filtered.gateway_trust_bundles.is_empty());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_single_namespace_control_plane_still_publishes_its_database_record() {
    let ferrum = record("ferrum", "cluster.local", vec![root_ca_der_base64("root")]);
    let config = config_with_records(vec![ferrum]);

    let filtered = CpGrpcServer::filter_config_to_namespace_for_scope(
        &config,
        "ferrum",
        &CpScope::Single("ferrum".to_string()),
    );
    let projected = filtered
        .trust_bundles
        .as_deref()
        .expect("a single-namespace CP publishes its record");
    assert_eq!(projected.local.trust_domain.as_str(), "cluster.local");
}

#[tokio::test(flavor = "multi_thread")]
async fn two_simultaneous_authorities_withdraw_trust_rather_than_ranking_them() {
    let ferrum = record("ferrum", "cluster.local", vec![root_ca_der_base64("db-root")]);
    let mut config = config_with_records(vec![ferrum]);
    config.trust_bundles = Some(Box::new(TrustBundleSet {
        local: TrustBundle {
            trust_domain: TrustDomain::new("file.local").expect("fixture trust domain"),
            x509_authorities: vec![root_ca_der_base64("file-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }));

    let filtered = CpGrpcServer::filter_config_to_namespace_for_scope(
        &config,
        "ferrum",
        &CpScope::Single("ferrum".to_string()),
    );
    assert!(
        filtered.trust_bundles.is_none(),
        "an ambiguous deployment must fail closed identically on every replica"
    );
}
