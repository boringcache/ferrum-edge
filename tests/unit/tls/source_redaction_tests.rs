//! A direct provider URI's identifier must not reach operator-facing output.
//!
//! `secrets::registry::redact_source_reference` scrubs the *backend detail* of a
//! failed fetch, but `MaterialError`'s own variants interpolate a `source_id`
//! alongside that detail, and their `Display` reaches `validate` output and
//! startup logs. For a `vault://`/`aws://`/`azure://`/`gcp://` source that
//! `source_id` was the full secret path, ARN, or Key Vault URL — so the
//! reference leaked through the wrapper instead of through the detail.

use ferrum_edge::tls::source::subscription::{WatchedMaterialSource, material_set_fingerprint};
use ferrum_edge::tls::source::{
    CertSource, MaterialError, MaterialKind, MaterializedMaterial, SourceScheme,
};

/// The four schemes whose identifier is a secret source reference, with an
/// identifier shaped like the real thing for each.
const PROVIDER_URIS: [&str; 4] = [
    "vault://secret/data/gateway/tls#server-key",
    "aws://arn:aws:secretsmanager:us-east-1:123456789012:secret:prod/tls-AbCdEf",
    "azure://https://gw-prod-kv.vault.azure.net/secrets/tls-key/9f2c",
    "gcp://projects/prod-1234/secrets/tls-key/versions/7",
];

/// Everything after the scheme — the part that names the secret and must never
/// be echoed. Derived rather than hand-listed so the assertion covers the whole
/// identifier instead of a chosen fragment of it.
fn identifier_of(raw: &str) -> &str {
    raw.split_once("://").expect("fixture must be a URI").1
}

fn scheme_of(raw: &str) -> &str {
    raw.split_once("://").expect("fixture must be a URI").0
}

fn uri_source(raw: &str) -> CertSource {
    CertSource::parse(raw, MaterialKind::Key)
}

#[test]
fn provider_schemes_are_classified_as_secret_sources() {
    let providers = [
        SourceScheme::Vault,
        SourceScheme::Aws,
        SourceScheme::Azure,
        SourceScheme::Gcp,
    ];
    for scheme in providers {
        assert!(
            scheme.is_secret_provider(),
            "{} addresses an external secret provider",
            scheme.as_str()
        );
    }

    // Local configuration, not a secret reference: an operator needs these
    // verbatim to act on a diagnostic, and they are already in the settings
    // file.
    let local = [
        SourceScheme::File,
        SourceScheme::K8sSecret,
        SourceScheme::Acme,
        SourceScheme::Managed,
        SourceScheme::Pkcs11,
    ];
    for scheme in local {
        assert!(
            !scheme.is_secret_provider(),
            "{} is local configuration",
            scheme.as_str()
        );
    }
}

#[test]
fn redacted_source_id_withholds_the_provider_identifier() {
    for raw in PROVIDER_URIS {
        let redacted = uri_source(raw).redacted_source_id();
        assert!(
            !redacted.contains(identifier_of(raw)),
            "the identifier must not survive: {redacted}"
        );
        // The provider label is retained: it is a bounded, fixed-set value that
        // tells an operator which backend to go look at.
        let label = format!("{}://", scheme_of(raw));
        assert!(
            redacted.starts_with(&label),
            "the provider label must be kept for operators: {redacted}"
        );
    }
}

/// The cited path. `load_secret_material` wraps a failed fetch as
/// `MaterialError::Secret { source_id, details }`, and `Display` prints both.
#[test]
fn material_error_display_withholds_the_provider_identifier() {
    for raw in PROVIDER_URIS {
        let error = MaterialError::Secret {
            source_id: uri_source(raw).redacted_source_id(),
            details: "permission denied".to_string(),
        };
        let rendered = error.to_string();
        assert!(
            !rendered.contains(identifier_of(raw)),
            "the wrapper must not re-disclose what the detail scrubbed: {rendered}"
        );
        // The failure class stays actionable.
        assert!(rendered.contains("permission denied"));
    }
}

/// `source_id` is an *identity* — it keys TLS inventory entries and event
/// filters — so it is deliberately not redacted in place, and distinct provider
/// sources must stay distinguishable from each other.
#[test]
fn identity_source_id_is_unchanged_and_still_distinguishing() {
    let first = uri_source("vault://secret/data/gateway/tls#cert");
    let second = uri_source("vault://secret/data/gateway/tls#key");
    assert_ne!(
        first.source_id(),
        second.source_id(),
        "inventory and event filtering depend on these staying distinct"
    );
    assert!(first.source_id().contains("secret/data/gateway/tls"));
    // ...but both collapse to the same non-secret label for operator output.
    assert_eq!(first.redacted_source_id(), second.redacted_source_id());
}

/// Non-provider sources are unaffected: a filesystem path is operator-authored
/// local configuration and is needed verbatim to act on the diagnostic.
#[test]
fn non_provider_sources_are_reported_verbatim() {
    let path = uri_source("file:///etc/ferrum/tls/server.pem");
    assert_eq!(path.redacted_source_id(), path.source_id());

    let bare = CertSource::parse("/etc/ferrum/tls/server.pem", MaterialKind::Cert);
    assert_eq!(bare.redacted_source_id(), bare.source_id());
    assert!(bare.redacted_source_id().contains("server.pem"));

    let local = [
        "k8s://ferrum/tls-secret#tls.crt",
        "acme://certificates/edge-cert#cert",
        "managed://edge-cert#cert",
    ];
    for raw in local {
        let source = uri_source(raw);
        assert_eq!(
            source.redacted_source_id(),
            source.source_id(),
            "{raw} is local configuration, not a secret reference"
        );
    }
}

/// Inline PEM keeps its existing constant, which already discloses nothing.
#[test]
fn inline_pem_stays_redacted() {
    let pem = "-----BEGIN CERTIFICATE-----\nAAA\n";
    let inline = CertSource::parse(pem, MaterialKind::Cert);
    assert_eq!(inline.redacted_source_id(), inline.source_id());
    assert!(!inline.redacted_source_id().contains("BEGIN CERTIFICATE"));
}

// ── identity vs. display: the two must not be the same string ───────────────
//
// `MaterializedMaterial` carries only the *display* rendering, and it is
// redacted at the producer. That is safe precisely because nothing keys off it:
// every consumer that needs to tell two sources apart reads the configured
// `CertSource`. The tests below pin both halves of that split — the field is
// non-disclosing, and the identity consumers stayed distinguishing.

/// The materialized value carries the redacted label and nothing else, on the
/// struct's `Debug` as well as its field.
///
/// `MaterializedMaterial` is `Debug`-formatted into diagnostics, so a raw
/// identifier stored here would leak through `{:?}` even at call sites that
/// never touch the field by name.
#[test]
fn materialized_material_debug_withholds_the_provider_identifier() {
    for raw in PROVIDER_URIS {
        let material = MaterializedMaterial::from_bytes(
            b"-----BEGIN CERTIFICATE-----\nAAA\n".to_vec(),
            SourceScheme::Vault,
            uri_source(raw).redacted_source_id(),
            MaterialKind::Cert,
            None,
        );
        assert!(
            !material.display_source_id.contains(identifier_of(raw)),
            "the display label must not carry the identifier: {}",
            material.display_source_id
        );
        let rendered = format!("{material:?}");
        assert!(
            !rendered.contains(identifier_of(raw)),
            "Debug must not re-disclose the identifier: {rendered}"
        );
        // The bytes are redacted by `SecretBytes` as before.
        assert!(!rendered.contains("BEGIN CERTIFICATE"), "{rendered}");
    }
}

/// The rotation predicate keeps seeing a source change.
///
/// `MaterialSetFingerprint` equality is what decides whether TLS material is
/// rebuilt, and `tls::events` derives `cert_id`, `source_id`, and its
/// source-id filter from these same entries. The entry's `source_id` therefore
/// comes from the **configured** `CertSource`, never from
/// `MaterializedMaterial::display_source_id` — which is redacted, so every
/// provider reference under one scheme renders identically and two distinct
/// references with equal bytes and version would compare equal.
///
/// Driven with `file://` sources because a provider fetch needs a live backend,
/// but the property under test is the same one and is visible here: the two
/// files hold **identical bytes**, so `fingerprint` and `version` match exactly
/// and only the source identity can tell the entries apart. It also pins the
/// specific regression shape, since a `file://` source's configured id
/// (`file:///path`) and its materialized display id (the bare `/path`) are
/// different strings.
#[test]
fn identical_material_under_different_references_stays_distinguishable() {
    let dir = tempfile::tempdir().expect("temp dir");
    let pem = b"-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----\n";
    let first_path = dir.path().join("first.pem");
    let second_path = dir.path().join("second.pem");
    std::fs::write(&first_path, pem).expect("write first");
    std::fs::write(&second_path, pem).expect("write second");

    let watched = |path: &std::path::Path| {
        WatchedMaterialSource::new(
            "test-cert",
            CertSource::parse(format!("file://{}", path.display()), MaterialKind::Cert),
            MaterialKind::Cert,
        )
    };

    let first = material_set_fingerprint(&[watched(&first_path)]).expect("first fingerprint");
    let second = material_set_fingerprint(&[watched(&second_path)]).expect("second fingerprint");

    assert_eq!(
        first.entries[0].fingerprint, second.entries[0].fingerprint,
        "the fixture is only meaningful if the bytes really are identical"
    );
    assert_ne!(
        first, second,
        "a changed source reference must remain visible to the rotation predicate \
         even when the material behind it is byte-identical"
    );

    // The identity recorded is the configured source id, which is also what
    // `events::event_material_from_source` reports for a not-yet-loaded source,
    // so both event paths agree on one identity for the same source.
    assert_eq!(
        first.entries[0].source_id,
        CertSource::parse(
            format!("file://{}", first_path.display()),
            MaterialKind::Cert
        )
        .source_id(),
    );
}
