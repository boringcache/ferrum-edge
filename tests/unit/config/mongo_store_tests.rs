//! Unit coverage for the MongoDB config store's pure builders.
//!
//! The migration lease normally acquires/renews via an aggregation-pipeline
//! update that stamps expiry/renewal from MongoDB SERVER time (`$$NOW`), which
//! is immune to client clock skew. AWS DocumentDB is documented as
//! MongoDB-compatible but does NOT support pipeline-form updates, so the lease
//! falls back to classic operator updates stamped from the CLIENT clock. These
//! tests pin the classic builder shapes and the command-error capability
//! detection without requiring a live DocumentDB backend.

use ferrum_edge::_test_support::{
    mongo_migration_lease_acquire_filter_classic, mongo_migration_lease_acquire_update_classic,
    mongo_migration_lease_duration_millis, mongo_migration_lease_renew_update_classic,
    mongo_mtls_dns_admission_drop_must_retain, mongo_mtls_dns_admission_lock_filter,
    mongo_mtls_dns_admission_lock_update, mongo_pipeline_update_unsupported,
    mtls_dns_policy_requires_consumer_load,
};
use ferrum_edge::config::types::{GatewayConfig, PluginConfig, PluginScope};
use serde_json::json;

const OWNER: &str = "test-owner-uuid";
const MONGO_STORE_SOURCE: &str = include_str!("../../../src/config/mongo_store.rs");
// Fixed client-clock instant so the builders are deterministic (no DateTime::now).
const NOW_MILLIS: i64 = 1_700_000_000_000;

fn mongo_method(name: &str) -> &str {
    let marker = format!("        async fn {name}");
    let start = MONGO_STORE_SOURCE.find(&marker).unwrap();
    let tail = &MONGO_STORE_SOURCE[start + marker.len()..];
    let end = tail.find("\n        async fn ").unwrap_or(tail.len());
    &MONGO_STORE_SOURCE[start..start + marker.len() + end]
}

fn expiry_millis() -> i64 {
    NOW_MILLIS + mongo_migration_lease_duration_millis()
}

fn mongo_command_error(code: i32, message: &str) -> mongodb::error::Error {
    let command_error: mongodb::error::CommandError = mongodb::bson::from_document(
        mongodb::bson::doc! { "code": code, "codeName": "TestCommandError", "errmsg": message },
    )
    .unwrap();
    mongodb::error::ErrorKind::Command(command_error).into()
}

#[test]
fn pipeline_update_rejection_matches_unsupported_and_type_error_shapes() {
    for error in [
        mongo_command_error(303, "Aggregation pipeline updates are not supported"),
        mongo_command_error(
            14,
            "The update value must be an object, but received an array",
        ),
    ] {
        assert!(
            mongo_pipeline_update_unsupported(&error),
            "DocumentDB pipeline rejection must select the classic lease: {error}"
        );
    }
}

#[test]
fn pipeline_update_rejection_excludes_contention_connectivity_and_auth() {
    let duplicate_key = mongo_command_error(11_000, "duplicate key during update");
    assert!(!mongo_pipeline_update_unsupported(&duplicate_key));

    let network_error: mongodb::error::Error = std::io::Error::new(
        std::io::ErrorKind::ConnectionReset,
        "connection reset during update",
    )
    .into();
    assert!(!mongo_pipeline_update_unsupported(&network_error));

    let unauthorized = mongo_command_error(13, "not authorized to execute update command");
    assert!(!mongo_pipeline_update_unsupported(&unauthorized));
}

#[test]
fn migration_lease_duration_is_120_seconds() {
    // The classic fallback must keep the same 120s lease window as the pipeline.
    assert_eq!(mongo_migration_lease_duration_millis(), 120_000);
}

#[test]
fn mtls_dns_admission_lock_has_no_expiry_takeover_path() {
    let filter = mongo_mtls_dns_admission_lock_filter("default", OWNER);
    assert_eq!(filter.get_str("_id").unwrap(), "default");
    assert!(
        !filter.contains_key("expires_at") && !format!("{filter:?}").contains("expires_at"),
        "admission lock filter must never admit an expired-owner takeover: {filter:?}"
    );
    let clauses = filter.get_array("$or").unwrap();
    assert_eq!(clauses.len(), 2);
    assert_eq!(
        clauses[1].as_document().unwrap().get_str("owner").unwrap(),
        OWNER
    );

    let update = mongo_mtls_dns_admission_lock_update(OWNER, NOW_MILLIS);
    let set = update.get_document("$set").unwrap();
    assert_eq!(set.get_str("owner").unwrap(), OWNER);
    assert!(set.get("expires_at").is_none());
    assert!(
        update
            .get_document("$unset")
            .unwrap()
            .contains_key("expires_at"),
        "admission lock must erase any expiry field: {update:?}"
    );
}

#[test]
fn mtls_dns_admission_drop_retains_only_uncertain_mutations() {
    assert!(
        mongo_mtls_dns_admission_drop_must_retain(true, false),
        "a dispatched mutation without a settled outcome must keep the durable fence"
    );
    assert!(
        !mongo_mtls_dns_admission_drop_must_retain(false, false),
        "pre-mutation validation cancellation may clean up its unused fence"
    );
    assert!(
        !mongo_mtls_dns_admission_drop_must_retain(true, true),
        "an explicit settled release may retry owner-qualified cleanup"
    );
}

#[test]
fn mongo_plugin_graph_validation_runs_under_the_durable_namespace_fence() {
    let validator = mongo_method("validate_mtls_dns_candidate_with_mode");
    let graph_validation = validator
        .find("validate_tcp_connection_throttle_attachments")
        .expect("shared Mongo candidate validation must enforce TCP throttle attachments");
    let mtls_fast_path = validator
        .find("has_effective_mtls_dns_identity_policy")
        .expect("mTLS consumer-load fast path");
    assert!(
        graph_validation < mtls_fast_path,
        "TCP graph validation must run even when no effective mTLS DNS policy loads Consumers"
    );

    for method_name in [
        "create_proxy(&self, proxy: &Proxy)",
        "update_proxy(&self, proxy: &Proxy)",
        "delete_proxy(&self, namespace: &str, id: &str)",
        "create_plugin_config(&self, pc: &PluginConfig)",
        "update_plugin_config(&self, pc: &PluginConfig)",
        "delete_plugin_config(",
        "batch_create_proxies(",
        "batch_create_plugin_configs(",
        "submit_api_spec_bundle(",
        "delete_api_spec(&self, namespace: &str, id: &str)",
    ] {
        let method = mongo_method(method_name);
        let acquire = method
            .find("acquire_mtls_dns_admission")
            .unwrap_or_else(|| panic!("{method_name} must acquire the durable namespace fence"));
        let validate = method
            .find("validate_plugin_graph")
            .unwrap_or_else(|| panic!("{method_name} must validate the guarded graph candidate"));
        let mutate = method[validate..]
            .find("run_mutation")
            .map(|offset| validate + offset)
            .or_else(|| {
                method[validate..]
                    .find("run_mtls_dns_mutations")
                    .map(|offset| validate + offset)
            })
            .unwrap_or_else(|| panic!("{method_name} must mutate only after validation"));
        assert!(
            acquire < validate && validate < mutate,
            "{method_name} must acquire, re-read/validate, then mutate in that order"
        );
    }

    let replace = mongo_method("replace_api_spec_bundle(");
    let acquire = replace.find("acquire_mtls_dns_admission").unwrap();
    let validate = replace.find("validate_plugin_graph").unwrap();
    let graph_mutation = replace[validate..].find("run_mtls_dns_mutations").unwrap() + validate;
    assert!(acquire < validate && validate < graph_mutation);
}

#[test]
fn mtls_dns_policy_gate_skips_consumers_until_san_dns_is_effective() {
    let now = chrono::Utc::now();
    let mut config = GatewayConfig {
        plugin_configs: vec![PluginConfig {
            id: "dns-mtls".to_string(),
            namespace: "ferrum".to_string(),
            plugin_name: "mtls_auth".to_string(),
            enabled: false,
            config: json!({"cert_field": "san_dns"}),
            scope: PluginScope::Global,
            proxy_id: None,
            priority_override: None,
            api_spec_id: None,
            created_at: now,
            updated_at: now,
        }],
        ..Default::default()
    };
    assert!(!mtls_dns_policy_requires_consumer_load(&config));
    config.plugin_configs[0].enabled = true;
    assert!(mtls_dns_policy_requires_consumer_load(&config));
}

#[test]
fn classic_acquire_filter_matches_missing_expired_or_owned_lease() {
    let filter = mongo_migration_lease_acquire_filter_classic(OWNER, NOW_MILLIS);
    assert_eq!(filter.get_str("_id").unwrap(), "global");

    let clauses = filter.get_array("$or").unwrap();
    assert_eq!(
        clauses.len(),
        3,
        "classic acquire filter must offer exactly the three claimable cases: {filter:?}"
    );

    // 1) lock document has no expires_at (never held / freshly upserted).
    let missing = clauses[0].as_document().unwrap();
    assert!(
        !missing
            .get_document("expires_at")
            .unwrap()
            .get_bool("$exists")
            .unwrap(),
        "first clause must match a missing expires_at: {missing:?}"
    );

    // 2) lock expired by the CLIENT clock (client-time comparison).
    let expired = clauses[1].as_document().unwrap();
    assert_eq!(
        expired
            .get_document("expires_at")
            .unwrap()
            .get_datetime("$lte")
            .unwrap()
            .timestamp_millis(),
        NOW_MILLIS,
        "second clause must expire against the client clock: {expired:?}"
    );

    // 3) lock already owned by us (re-entrant renewal via acquire).
    let owned = clauses[2].as_document().unwrap();
    assert_eq!(owned.get_str("owner").unwrap(), OWNER);
}

#[test]
fn classic_acquire_update_stamps_client_time_expiry_and_created_on_insert() {
    let update = mongo_migration_lease_acquire_update_classic(OWNER, NOW_MILLIS);

    let set = update.get_document("$set").unwrap();
    assert_eq!(set.get_str("owner").unwrap(), OWNER);
    assert_eq!(
        set.get_datetime("expires_at").unwrap().timestamp_millis(),
        expiry_millis(),
        "acquire must stamp expires_at at client now + lease duration: {set:?}"
    );
    assert_eq!(
        set.get_datetime("updated_at").unwrap().timestamp_millis(),
        NOW_MILLIS
    );
    // created_at is written ONLY on insert, never on a takeover of an expired
    // lease, so the original creation time survives.
    assert!(
        set.get("created_at").is_none(),
        "$set must not rewrite created_at: {set:?}"
    );
    let set_on_insert = update.get_document("$setOnInsert").unwrap();
    assert_eq!(
        set_on_insert
            .get_datetime("created_at")
            .unwrap()
            .timestamp_millis(),
        NOW_MILLIS
    );
}

#[test]
fn classic_renew_update_refreshes_expiry_without_touching_ownership() {
    let update = mongo_migration_lease_renew_update_classic(NOW_MILLIS);

    let set = update.get_document("$set").unwrap();
    assert_eq!(
        set.get_datetime("expires_at").unwrap().timestamp_millis(),
        expiry_millis(),
        "renew must extend expires_at to client now + lease duration: {set:?}"
    );
    assert_eq!(
        set.get_datetime("updated_at").unwrap().timestamp_millis(),
        NOW_MILLIS
    );
    // Renew relies on the owner match in the query filter, so the update must
    // not rewrite owner or created_at.
    assert!(
        set.get("owner").is_none(),
        "renew $set must not rewrite owner: {set:?}"
    );
    assert!(
        update.get("$setOnInsert").is_none(),
        "renew must not upsert a new lock document: {update:?}"
    );
}

#[test]
fn same_owner_orphan_reservation_is_adoptable_cross_owner_is_conflict() {
    use ferrum_edge::_test_support::{
        ConsumerIdentityReservationDisposition, classify_consumer_identity_reservation,
        consumer_identity_reservation_is_same_owner,
    };

    assert_eq!(
        classify_consumer_identity_reservation(None, "alice"),
        ConsumerIdentityReservationDisposition::Vacant
    );
    assert_eq!(
        classify_consumer_identity_reservation(Some("alice"), "alice"),
        ConsumerIdentityReservationDisposition::Adopted,
        "orphaned same-owner reservation must be adoptable on retry"
    );
    assert_eq!(
        classify_consumer_identity_reservation(Some("bob"), "alice"),
        ConsumerIdentityReservationDisposition::Conflict,
        "a different owner must never steal a live reservation"
    );
    assert!(consumer_identity_reservation_is_same_owner("alice", "alice"));
    assert!(!consumer_identity_reservation_is_same_owner("bob", "alice"));
}

#[test]
fn live_reservation_cannot_be_reclaimed_from_point_read_absence() {
    use ferrum_edge::_test_support::{
        ConsumerIdentityReconcileObservation, automatic_consumer_identity_orphan_reclaim_permitted,
        consumer_identity_values_safe_to_rollback_release, ordered_insert_newly_inserted_prefix,
    };

    // Dangerous interleaving: node A reserved identity, consumer insert still
    // in flight; node B sees consumer absent. Reclaim must be refused — proving
    // absence is not `!consumer_exists` alone.
    assert!(
        !automatic_consumer_identity_orphan_reclaim_permitted(
            ConsumerIdentityReconcileObservation::ConsumerAbsentSameOwnerCreateInFlight
        ),
        "in-flight same-owner reserve-first create must keep its reservation"
    );
    assert!(
        !automatic_consumer_identity_orphan_reclaim_permitted(
            ConsumerIdentityReconcileObservation::ConsumerAbsentNoKnownWriter
        ),
        "point-read consumer absence without a known writer is still not reclaim-safe \
         across serving nodes (migration lease does not serialize CRUD)"
    );
    assert!(
        !automatic_consumer_identity_orphan_reclaim_permitted(
            ConsumerIdentityReconcileObservation::ConsumerPresent
        ),
        "present consumer means the reservation is live"
    );

    // Rollback may release only this attempt's newly inserted prefix; adopted
    // same-owner docs (provenance unknown) stay out of the release set.
    let values = ["alice".to_string(), "alice@example.com".to_string()];
    assert_eq!(
        ordered_insert_newly_inserted_prefix(&values, Some(1)),
        &values[..1],
        "ordered E11000 at index 1 means only the leading value was inserted here"
    );
    assert!(
        ordered_insert_newly_inserted_prefix(&values, None).is_empty(),
        "unknown write-error index ⇒ retain all (empty rollback-safe set)"
    );
    let adopted_only: [String; 0] = [];
    assert_eq!(
        consumer_identity_values_safe_to_rollback_release(&adopted_only),
        &[] as &[String],
        "pure same-owner adoption must not roll back pre-existing reservations"
    );
}

#[test]
fn adoption_failure_preserves_vacant_insert_provenance_for_rollback() {
    use ferrum_edge::_test_support::{
        ConsumerIdentityEnsureFold, ConsumerIdentityEnsureObservation,
        consumer_identity_adoption_failure_release_values,
        consumer_identity_ensure_owned_error_for_test, fold_consumer_identity_ensure_observations,
    };

    // Single-consumer ensure: vacant insert, then different-owner conflict.
    // Failure provenance must retain the vacant insert for rollback.
    let fold = fold_consumer_identity_ensure_observations(&[
        ConsumerIdentityEnsureObservation::InsertedVacant("alice".to_string()),
        ConsumerIdentityEnsureObservation::Conflict,
    ]);
    assert_eq!(
        fold,
        ConsumerIdentityEnsureFold::Failed {
            newly_inserted_before_failure: vec!["alice".to_string()],
        },
        "vacant insert before conflict must remain in failure provenance"
    );

    let err = consumer_identity_ensure_owned_error_for_test(
        vec!["alice".to_string()],
        "E11000 duplicate key error: identity value 'bob' reserved by other",
    );
    assert_eq!(
        err.newly_inserted,
        vec!["alice".to_string()],
        "ensure-owned error must carry exact vacant inserts committed before failure"
    );

    let ordered = [
        "alice".to_string(),
        "alice@example.com".to_string(),
        "bob".to_string(),
    ];
    // Ordered insert failed at index 1 (only "alice" from ordered path); adoption
    // then inserted alice@example.com before conflicting on bob.
    let release = consumer_identity_adoption_failure_release_values(
        &ordered,
        Some(1),
        &["alice@example.com".to_string()],
    );
    assert_eq!(
        release,
        vec!["alice".to_string(), "alice@example.com".to_string()],
        "failure release must include ordered prefix plus adoption vacant inserts"
    );
}

#[test]
fn batch_adoption_failure_identifies_earlier_vacant_inserts_for_rollback() {
    use ferrum_edge::_test_support::{
        ConsumerIdentityEnsureFold, ConsumerIdentityEnsureObservation,
        consumer_identity_adoption_failure_release_values, fold_consumer_identity_ensure_observations,
    };

    // Batch-style per-doc adoption: earlier vacant docs succeed, later conflict.
    let fold = fold_consumer_identity_ensure_observations(&[
        ConsumerIdentityEnsureObservation::InsertedVacant("ns:alice".to_string()),
        ConsumerIdentityEnsureObservation::InsertedVacant("ns:alice@example.com".to_string()),
        ConsumerIdentityEnsureObservation::Conflict,
    ]);
    let ConsumerIdentityEnsureFold::Failed {
        newly_inserted_before_failure,
    } = fold
    else {
        panic!("expected failure provenance after later conflict");
    };
    assert_eq!(
        newly_inserted_before_failure,
        vec!["ns:alice".to_string(), "ns:alice@example.com".to_string()],
        "earlier vacant batch adoption inserts must be identified for rollback"
    );

    let ordered_batch = [
        "ns:alice".to_string(),
        "ns:alice@example.com".to_string(),
        "ns:stolen".to_string(),
    ];
    // No verifiable ordered prefix (conflict on first ordered doc) — still release
    // adoption inserts from earlier successful ensure steps.
    let release = consumer_identity_adoption_failure_release_values(
        &ordered_batch,
        Some(0),
        &newly_inserted_before_failure,
    );
    assert_eq!(
        release,
        newly_inserted_before_failure,
        "with empty ordered prefix, release set is exactly earlier adoption inserts"
    );
}

#[test]
fn pre_existing_same_owner_docs_never_enter_rollback_safe_set() {
    use ferrum_edge::_test_support::{
        ConsumerIdentityEnsureFold, ConsumerIdentityEnsureObservation,
        consumer_identity_adoption_failure_release_values,
        consumer_identity_values_safe_to_rollback_release, fold_consumer_identity_ensure_observations,
    };

    let fold = fold_consumer_identity_ensure_observations(&[
        ConsumerIdentityEnsureObservation::AdoptedExisting,
        ConsumerIdentityEnsureObservation::AdoptedExisting,
    ]);
    assert_eq!(
        fold,
        ConsumerIdentityEnsureFold::Complete {
            newly_inserted: vec![],
        },
        "pure same-owner adoption must yield an empty newly-inserted set"
    );

    let fold_then_conflict = fold_consumer_identity_ensure_observations(&[
        ConsumerIdentityEnsureObservation::AdoptedExisting,
        ConsumerIdentityEnsureObservation::InsertedVacant("new-value".to_string()),
        ConsumerIdentityEnsureObservation::Conflict,
    ]);
    assert_eq!(
        fold_then_conflict,
        ConsumerIdentityEnsureFold::Failed {
            newly_inserted_before_failure: vec!["new-value".to_string()],
        },
        "adopted pre-existing docs must not appear in failure provenance"
    );

    let ordered = ["pre-existing".to_string(), "new-value".to_string(), "conflict".to_string()];
    let release = consumer_identity_adoption_failure_release_values(
        &ordered,
        Some(0), // ordered inserted nothing verifiable
        &["new-value".to_string()],
    );
    assert_eq!(release, vec!["new-value".to_string()]);
    assert!(
        !release.contains(&"pre-existing".to_string()),
        "pre-existing same-owner reservation must stay out of the release set"
    );
    assert_eq!(
        consumer_identity_values_safe_to_rollback_release(&[]),
        &[] as &[String]
    );
}

#[test]
fn unknown_ordered_insert_provenance_remains_retained_on_adoption_failure() {
    use ferrum_edge::_test_support::consumer_identity_adoption_failure_release_values;

    let ordered = [
        "maybe-inserted-a".to_string(),
        "maybe-inserted-b".to_string(),
        "conflict".to_string(),
    ];
    // None ⇒ cannot attribute any ordered-insert docs to this attempt; retain
    // them. Still release exact vacant inserts from the adoption attempt.
    let release = consumer_identity_adoption_failure_release_values(
        &ordered,
        None,
        &["adoption-vacant".to_string()],
    );
    assert_eq!(
        release,
        vec!["adoption-vacant".to_string()],
        "unknown ordered-insert provenance must remain retained; only adoption \
         vacant inserts are release-safe"
    );
    assert!(
        !release.iter().any(|v| v.starts_with("maybe-inserted")),
        "unattributed ordered-insert values must not be released"
    );
}

#[test]
fn mongo_timeout_overrides_preserve_uri_unless_env_explicit() {
    use ferrum_edge::_test_support::apply_mongo_timeout_overrides;
    use mongodb::options::ClientOptions;
    use std::time::Duration;

    let mut options = ClientOptions::default();
    options.server_selection_timeout = Some(Duration::from_millis(5_000));
    options.connect_timeout = Some(Duration::from_millis(3_000));

    apply_mongo_timeout_overrides(&mut options, None, None);
    assert_eq!(
        options.server_selection_timeout,
        Some(Duration::from_millis(5_000)),
        "URI-only serverSelectionTimeoutMS must survive when env is unset"
    );
    assert_eq!(
        options.connect_timeout,
        Some(Duration::from_millis(3_000)),
        "URI-only connectTimeoutMS must survive when env is unset"
    );

    apply_mongo_timeout_overrides(&mut options, Some(30), Some(10));
    assert_eq!(
        options.server_selection_timeout,
        Some(Duration::from_secs(30)),
        "explicit FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS must override URI"
    );
    assert_eq!(
        options.connect_timeout,
        Some(Duration::from_secs(10)),
        "explicit FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS must override URI"
    );

    // Driver/default path: unset options stay unset when env is also unset.
    let mut bare = ClientOptions::default();
    apply_mongo_timeout_overrides(&mut bare, None, None);
    assert!(
        bare.server_selection_timeout.is_none() && bare.connect_timeout.is_none(),
        "defaults must not clobber absent URI timeout options"
    );
}

#[test]
fn metadata_replace_one_requires_exactly_one_match() {
    use ferrum_edge::_test_support::mongo_replace_one_matched_exactly_one;

    assert!(mongo_replace_one_matched_exactly_one(1));
    assert!(
        !mongo_replace_one_matched_exactly_one(0),
        "zero-match replace must not be reported as a successful metadata update"
    );
    assert!(!mongo_replace_one_matched_exactly_one(2));
}

#[test]
fn replace_api_spec_metadata_shortcut_checks_matched_count() {
    let replace = mongo_method("replace_api_spec_bundle(");
    let shortcut = replace
        .find("Only update metadata fields on the spec doc")
        .expect("metadata-only shortcut marker");
    let matched = replace[shortcut..]
        .find("mongo_replace_one_matched_exactly_one")
        .or_else(|| replace[shortcut..].find("matched_count"))
        .expect("metadata shortcut must verify matched_count");
    let release = replace[shortcut..]
        .find("release_mtls_dns_admission_leases")
        .expect("shortcut lease release");
    assert!(
        matched < release,
        "matched_count must be checked before the metadata shortcut returns success"
    );
}

#[test]
fn consumer_identity_reserve_paths_adopt_same_owner_on_duplicate_key() {
    let standalone = mongo_method("reserve_consumer_identity_docs_standalone(");
    assert!(
        standalone.contains("ensure_consumer_identity_docs_owned"),
        "standalone reserve must same-owner-adopt on E11000"
    );
    assert!(
        standalone.contains("is_duplicate_key"),
        "standalone reserve must classify duplicate-key before adopting"
    );
    assert!(
        standalone.contains("newly_inserted")
            || standalone.contains("consumer_identity_values_safe_to_rollback_release"),
        "standalone reserve must expose newly-inserted values for safe rollback"
    );
    assert!(
        standalone.contains("consumer_identity_adoption_failure_release_values"),
        "standalone reserve failure must release ordered prefix plus adoption vacant inserts"
    );

    let ensure = mongo_method("ensure_consumer_identity_docs_owned(");
    assert!(
        ensure.contains("ConsumerIdentityEnsureOwnedError"),
        "ensure must return an error type that preserves failure provenance"
    );

    let session = mongo_method("insert_consumer_identity_docs_in_session(");
    assert!(
        session.contains("ensure_consumer_identity_docs_owned_in_session"),
        "replica-set reserve must same-owner-adopt on E11000"
    );

    let create = mongo_method("create_consumer(");
    assert!(
        create.contains("consumer_identity_values_safe_to_rollback_release")
            || create.contains("newly_inserted_identity_values"),
        "create_consumer rollback must release only newly-inserted reservations"
    );

    // Batch standalone adoption failure must release ensured_new_docs, not only
    // the ordered-insert prefix.
    let batch = mongo_method("batch_create_consumers(");
    let adopt_fail = batch
        .find("still releasing vacant reservations inserted during this adoption")
        .or_else(|| batch.find("ensured_new_docs"))
        .expect("batch adoption failure must track ensured_new_docs for release");
    let release_call = batch[adopt_fail..]
        .find("release_consumer_identity_docs_best_effort")
        .expect("batch adoption failure must best-effort release tracked docs");
    assert!(
        release_call < 2500,
        "batch failure release must run on the adoption-conflict path"
    );

    let migrations = mongo_method("run_migrations(");
    assert!(
        !migrations.contains("reconcile_orphaned_consumer_identity_reservations"),
        "startup migrations must not reclaim reservations from point-read consumer absence"
    );
    assert!(
        migrations.contains("automatic_consumer_identity_orphan_reclaim_permitted")
            || migrations.contains("Intentionally no automatic orphan reconcile"),
        "migrations must document why automatic orphan reclaim is omitted"
    );
}
