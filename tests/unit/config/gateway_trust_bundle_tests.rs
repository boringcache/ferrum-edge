//! Unit coverage for the namespace-keyed gateway trust-bundle resource
//! (issue #3727).
//!
//! Three things are load-bearing here and are asserted directly:
//!
//! 1. **Admission validation.** Oversized, malformed, mis-identified, and
//!    duplicate trust material must be refused *before* persistence or
//!    publication, and the resulting messages must never echo the material.
//! 2. **Publication semantics.** `Unchanged` / `Clear` / `Replace` must be three
//!    distinguishable states on the wire. Collapsing "nothing changed" into
//!    "revoke" is precisely the defect this resource had to fix.
//! 3. **Authority precedence.** Two simultaneous authorities must fail closed
//!    identically on every replica rather than each replica picking one.

use ferrum_edge::config::gateway_trust::{
    AMBIGUOUS_TRUST_AUTHORITY_MESSAGE, GatewayTrustBundleRecord, GatewayTrustFailureReason,
    GatewayTrustPublication, MAX_FEDERATED_BUNDLES, MAX_JWT_AUTHORITIES_PER_BUNDLE,
    MAX_TRUST_BUNDLE_JSON_BYTES, MAX_X509_AUTHORITIES_PER_BUNDLE, TrustAuthorityResolution,
    observability_snapshot, record_ambiguous_authority, record_trust_load_rejection,
    record_trust_load_success, reset_observability_for_tests, resolve_trust_authority,
};
use ferrum_edge::identity::TrustDomain;
use ferrum_edge::modes::mesh::config::{JwtAuthority, TrustBundle, TrustBundleSet};

use base64::Engine;

/// A real self-signed X.509 root, base64-encoded DER. Admission parses the DER,
/// so a fixture of arbitrary bytes would be rejected for the wrong reason and
/// would make the "invalid certificate" test vacuous.
fn root_ca_der_base64(common_name: &str) -> String {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256)
        .expect("test CA key generates");
    let mut params = rcgen::CertificateParams::new(Vec::<String>::new())
        .expect("test CA params build");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("test CA self-signs");
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

fn trust_domain(value: &str) -> TrustDomain {
    TrustDomain::new(value).expect("fixture trust domain is valid")
}

fn bundle_with(authorities: Vec<String>) -> TrustBundleSet {
    TrustBundleSet {
        local: TrustBundle {
            trust_domain: trust_domain("cluster.local"),
            x509_authorities: authorities,
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        },
        federated: Vec::new(),
    }
}

fn valid_record() -> GatewayTrustBundleRecord {
    GatewayTrustBundleRecord::new(
        "production",
        "production",
        bundle_with(vec![root_ca_der_base64("ferrum-test-root")]),
    )
}

// ── Admission validation ────────────────────────────────────────────────────

#[test]
fn valid_record_passes_admission() {
    let mut record = valid_record();
    record.normalize_fields();
    record
        .validate_fields()
        .expect("a well-formed record must be admitted");
}

#[test]
fn normalize_defaults_the_id_to_the_namespace() {
    let mut record = valid_record();
    record.id = "   ".to_string();
    record.normalize_fields();
    assert_eq!(
        record.id, "production",
        "an omitted id must default to the namespace so the singleton stays addressable"
    );
}

#[test]
fn trust_domain_must_match_the_bundle_identity() {
    let mut record = valid_record();
    // The stored identity column must never be authorable into disagreement
    // with the material it names.
    record.trust_domain = "other.local".to_string();
    let errors = record
        .validate_fields()
        .expect_err("a mismatched identity must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("does not match bundle.local.trust_domain")),
        "expected an identity-mismatch error, got {errors:?}"
    );
}

#[test]
fn base64_that_is_not_a_certificate_is_rejected() {
    let mut record = valid_record();
    record.bundle.local.x509_authorities =
        vec![base64::engine::general_purpose::STANDARD.encode([0_u8; 64])];
    let errors = record
        .validate_fields()
        .expect_err("valid base64 that is not a certificate must still be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("not a parseable X.509 certificate")),
        "expected a certificate-parse error, got {errors:?}"
    );
}

#[test]
fn a_bundle_with_no_authorities_is_rejected() {
    let mut record = valid_record();
    record.bundle.local.x509_authorities.clear();
    let errors = record
        .validate_fields()
        .expect_err("a bundle that authorizes nothing must be rejected");
    assert!(
        errors.iter().any(|error| error.contains("no authorities")),
        "expected an empty-authorities error, got {errors:?}"
    );
}

#[test]
fn too_many_x509_authorities_are_rejected() {
    let der = root_ca_der_base64("ferrum-test-root");
    let mut record = valid_record();
    record.bundle.local.x509_authorities = vec![der; MAX_X509_AUTHORITIES_PER_BUNDLE + 1];
    let errors = record
        .validate_fields()
        .expect_err("an unbounded authority list must be rejected");
    assert!(
        errors.iter().any(|error| error.contains("x509 authorities")),
        "expected an authority-count error, got {errors:?}"
    );
}

#[test]
fn too_many_federated_bundles_are_rejected() {
    let mut record = valid_record();
    record.bundle.federated = (0..=MAX_FEDERATED_BUNDLES)
        .map(|index| TrustBundle {
            trust_domain: trust_domain(&format!("federated-{index}.local")),
            x509_authorities: vec![root_ca_der_base64("ferrum-test-root")],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        })
        .collect();
    let errors = record
        .validate_fields()
        .expect_err("an unbounded federated list must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("federated bundles")),
        "expected a federated-count error, got {errors:?}"
    );
}

#[test]
fn a_federated_entry_repeating_the_local_trust_domain_is_rejected() {
    let mut record = valid_record();
    record.bundle.federated = vec![TrustBundle {
        trust_domain: trust_domain("cluster.local"),
        x509_authorities: vec![root_ca_der_base64("ferrum-test-root")],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }];
    let errors = record
        .validate_fields()
        .expect_err("a duplicate trust domain must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("repeats the local trust domain")),
        "expected a duplicate trust-domain error, got {errors:?}"
    );
}

#[test]
fn a_private_key_pasted_into_a_jwt_authority_is_rejected() {
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = vec![JwtAuthority {
        key_id: "rotation-1".to_string(),
        public_key_pem: "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----".to_string(),
    }];
    let errors = record
        .validate_fields()
        .expect_err("a non-public-key PEM must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("not a PEM public key block")),
        "expected a PEM shape error, got {errors:?}"
    );
}

#[test]
fn duplicate_jwt_key_ids_within_one_bundle_are_rejected() {
    let pem = "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----".to_string();
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = vec![
        JwtAuthority {
            key_id: "same".to_string(),
            public_key_pem: pem.clone(),
        },
        JwtAuthority {
            key_id: "same".to_string(),
            public_key_pem: pem,
        },
    ];
    let errors = record
        .validate_fields()
        .expect_err("a repeated key_id must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("repeats a key_id")),
        "expected a duplicate key_id error, got {errors:?}"
    );
}

#[test]
fn too_many_jwt_authorities_are_rejected() {
    let mut record = valid_record();
    record.bundle.local.jwt_authorities = (0..=MAX_JWT_AUTHORITIES_PER_BUNDLE)
        .map(|index| JwtAuthority {
            key_id: format!("key-{index}"),
            public_key_pem: "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----"
                .to_string(),
        })
        .collect();
    let errors = record
        .validate_fields()
        .expect_err("an unbounded JWT authority list must be rejected");
    assert!(
        errors.iter().any(|error| error.contains("jwt authorities")),
        "expected a JWT authority-count error, got {errors:?}"
    );
}

#[test]
fn an_oversized_bundle_is_rejected_and_the_error_carries_no_material() {
    // One valid root repeated is under the per-authority cap but blows the
    // whole-bundle cap once the federated set is large enough.
    let der = root_ca_der_base64("ferrum-test-root");
    let mut record = valid_record();
    record.bundle.local.x509_authorities = vec![der.clone(); MAX_X509_AUTHORITIES_PER_BUNDLE];
    record.bundle.federated = (0..MAX_FEDERATED_BUNDLES)
        .map(|index| TrustBundle {
            trust_domain: trust_domain(&format!("federated-{index}.local")),
            x509_authorities: vec![der.clone(); MAX_X509_AUTHORITIES_PER_BUNDLE],
            jwt_authorities: Vec::new(),
            refresh_hint_seconds: None,
        })
        .collect();

    let encoded = serde_json::to_string(&record.bundle).expect("fixture serializes");
    assert!(
        encoded.len() > MAX_TRUST_BUNDLE_JSON_BYTES,
        "fixture must actually exceed the encoded-size cap"
    );

    let errors = record
        .validate_fields()
        .expect_err("an oversized bundle must be rejected");
    assert!(
        errors
            .iter()
            .any(|error| error.contains("the maximum is") && error.contains("bytes")),
        "expected a size error, got {errors:?}"
    );
    for error in &errors {
        assert!(
            !error.contains(&der),
            "a validation error must never echo trust material"
        );
        assert!(
            !error.contains("BEGIN"),
            "a validation error must never echo PEM content"
        );
    }
}

// ── Redacted summary ────────────────────────────────────────────────────────

#[test]
fn the_summary_carries_counts_and_never_material() {
    let der = root_ca_der_base64("ferrum-test-root");
    let mut record = valid_record();
    record.bundle.local.x509_authorities = vec![der.clone(), root_ca_der_base64("second-root")];
    record.bundle.federated = vec![TrustBundle {
        trust_domain: trust_domain("remote.local"),
        x509_authorities: vec![root_ca_der_base64("remote-root")],
        jwt_authorities: Vec::new(),
        refresh_hint_seconds: None,
    }];

    let summary = record.summary();
    assert_eq!(summary.namespace, "production");
    assert_eq!(summary.trust_domain, "cluster.local");
    assert_eq!(summary.x509_authority_count, 2);
    assert_eq!(summary.jwt_authority_count, 0);
    assert_eq!(summary.federated_count, 1);

    let rendered = serde_json::to_string(&summary).expect("summary serializes");
    assert!(
        !rendered.contains(&der),
        "the status summary must never carry trust material"
    );
}

// ── Publication semantics ───────────────────────────────────────────────────

#[test]
fn a_snapshot_always_states_the_complete_current_state() {
    let record = valid_record();

    // Present → Replace, so a reconnecting data plane reconstructs trust from
    // the snapshot alone.
    let replace = GatewayTrustPublication::for_snapshot(Some(&record));
    assert!(matches!(replace, GatewayTrustPublication::Replace(_)));
    let json = replace
        .to_side_channel_json()
        .expect("a valid bundle serializes");
    assert!(json.contains("cluster.local"));

    // Absent → Clear, NOT Unchanged: a namespace with no record must actively
    // withdraw anything a subscriber applied earlier.
    let clear = GatewayTrustPublication::for_snapshot(None);
    assert_eq!(clear, GatewayTrustPublication::Clear);
    assert_eq!(
        clear
            .to_side_channel_json()
            .expect("clear serializes"),
        "null"
    );
}

#[test]
fn unchanged_and_clear_are_distinguishable_on_the_wire() {
    // This is the regression the resource exists to prevent: before issue
    // #3727 the delta path encoded "no trust to say" as JSON `null`, which the
    // data plane reads as an explicit revocation.
    assert_eq!(
        GatewayTrustPublication::Unchanged
            .to_side_channel_json()
            .expect("unchanged serializes"),
        "",
        "'nothing to say' must be an EMPTY side channel"
    );
    assert_eq!(
        GatewayTrustPublication::Clear
            .to_side_channel_json()
            .expect("clear serializes"),
        "null",
        "'revoke' must be JSON null"
    );
}

#[test]
fn a_delta_publication_distinguishes_no_change_rotation_and_revocation() {
    let previous = valid_record();

    // Untouched namespace: say nothing.
    assert_eq!(
        GatewayTrustPublication::for_delta(Some(&previous), Some(&previous)),
        GatewayTrustPublication::Unchanged
    );

    // Never had one, still does not: say nothing (NOT a clear — an absent
    // record must not repeatedly revoke).
    assert_eq!(
        GatewayTrustPublication::for_delta(None, None),
        GatewayTrustPublication::Unchanged
    );

    // Rotation: same identity, new revision and material.
    let mut rotated = previous.clone();
    rotated.revision = previous.revision + 1;
    rotated.bundle.local.x509_authorities = vec![
        previous.bundle.local.x509_authorities[0].clone(),
        root_ca_der_base64("rotated-root"),
    ];
    assert!(matches!(
        GatewayTrustPublication::for_delta(Some(&previous), Some(&rotated)),
        GatewayTrustPublication::Replace(_)
    ));

    // Revocation: the record went away.
    assert_eq!(
        GatewayTrustPublication::for_delta(Some(&previous), None),
        GatewayTrustPublication::Clear
    );

    // First publication for a namespace that had none.
    assert!(matches!(
        GatewayTrustPublication::for_delta(None, Some(&previous)),
        GatewayTrustPublication::Replace(_)
    ));
}

// ── Authority precedence ────────────────────────────────────────────────────

#[test]
fn the_database_record_is_authoritative_when_it_is_the_only_authority() {
    let record = valid_record();
    assert_eq!(
        resolve_trust_authority(Some(&record), None),
        TrustAuthorityResolution::Database
    );
}

#[test]
fn a_file_sourced_value_stands_when_there_is_no_database_record() {
    let file_value = bundle_with(vec![root_ca_der_base64("file-root")]);
    assert_eq!(
        resolve_trust_authority(None, Some(&file_value)),
        TrustAuthorityResolution::File
    );
}

#[test]
fn two_simultaneous_authorities_are_ambiguous_rather_than_ranked() {
    // Ranking them silently would let one replica publish the database value
    // and another the file value — the divergence this resource removes.
    let record = valid_record();
    let file_value = bundle_with(vec![root_ca_der_base64("file-root")]);
    assert_eq!(
        resolve_trust_authority(Some(&record), Some(&file_value)),
        TrustAuthorityResolution::Ambiguous
    );
    assert!(
        !AMBIGUOUS_TRUST_AUTHORITY_MESSAGE.contains("path"),
        "the operator message must not name filesystem paths"
    );
}

#[test]
fn no_authority_at_all_resolves_to_the_database_with_nothing_to_publish() {
    assert_eq!(
        resolve_trust_authority(None, None),
        TrustAuthorityResolution::Database
    );
}

// ── Observability ───────────────────────────────────────────────────────────

/// Counters are process-global, so the observability assertions run in one test
/// rather than racing each other across cargo's parallel test threads.
#[test]
fn observability_counters_are_bounded_and_material_free() {
    reset_observability_for_tests();

    let baseline = observability_snapshot();
    assert_eq!(baseline.loads_total, 0);
    assert_eq!(baseline.published_revision, 0);
    assert_eq!(baseline.last_failure_reason, "none");

    record_trust_load_success(7, 1_700_000_000);
    let after_success = observability_snapshot();
    assert_eq!(after_success.loads_total, 1);
    assert_eq!(after_success.published_revision, 7);
    assert_eq!(after_success.last_successful_load_unix_seconds, 1_700_000_000);
    assert_eq!(after_success.last_failure_reason, "none");

    // A rejected candidate must NOT advance the published revision: the
    // previous valid generation is still the one serving.
    record_trust_load_rejection(GatewayTrustFailureReason::InvalidMaterial);
    let after_rejection = observability_snapshot();
    assert_eq!(after_rejection.load_rejections_total, 1);
    assert_eq!(
        after_rejection.published_revision, 7,
        "a refused candidate must not replace the live generation's revision"
    );
    assert_eq!(after_rejection.last_failure_reason, "invalid_material");

    record_ambiguous_authority();
    let after_ambiguous = observability_snapshot();
    assert_eq!(after_ambiguous.ambiguous_authority_total, 1);
    assert_eq!(after_ambiguous.last_failure_reason, "ambiguous_authority");

    // The whole snapshot is a fixed set of integers plus a bounded enum, so it
    // cannot carry a trust domain, a namespace, or an unbounded identifier.
    let rendered = serde_json::to_string(&after_ambiguous).expect("snapshot serializes");
    for forbidden in ["cluster.local", "production", "BEGIN"] {
        assert!(
            !rendered.contains(forbidden),
            "process metrics must not carry {forbidden}"
        );
    }

    reset_observability_for_tests();
}

// ── Serde contract ──────────────────────────────────────────────────────────

#[test]
fn the_record_round_trips_through_json_for_backup_and_restore() {
    let mut record = valid_record();
    record.revision = 4;
    record.updated_by = Some("admin@example.test".to_string());

    let encoded = serde_json::to_string(&record).expect("record serializes");
    let decoded: GatewayTrustBundleRecord =
        serde_json::from_str(&encoded).expect("record round-trips");
    assert_eq!(decoded, record);
}

#[test]
fn an_unknown_field_is_rejected_rather_than_silently_dropped() {
    let body = serde_json::json!({
        "id": "production",
        "namespace": "production",
        "trust_domain": "cluster.local",
        "bundle": {"local": {"trust_domain": "cluster.local", "x509_authorities": []}},
        "surprise": true,
    });
    serde_json::from_value::<GatewayTrustBundleRecord>(body)
        .expect_err("deny_unknown_fields must reject an unexpected key");
}

#[test]
fn revision_defaults_to_zero_meaning_no_concurrency_expectation() {
    let body = serde_json::json!({
        "trust_domain": "cluster.local",
        "bundle": {"local": {"trust_domain": "cluster.local", "x509_authorities": []}},
    });
    let decoded: GatewayTrustBundleRecord =
        serde_json::from_value(body).expect("optional fields default");
    assert_eq!(
        decoded.revision, 0,
        "an omitted revision must mean 'no expectation', not revision 1"
    );
}
