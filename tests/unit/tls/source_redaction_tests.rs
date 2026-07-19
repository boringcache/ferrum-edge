//! A direct provider URI's identifier must not reach operator-facing output.
//!
//! `secrets::registry::redact_source_reference` scrubs the *backend detail* of a
//! failed fetch, but `MaterialError`'s own variants interpolate a `source_id`
//! alongside that detail, and their `Display` reaches `validate` output and
//! startup logs. For a `vault://`/`aws://`/`azure://`/`gcp://` source that
//! `source_id` was the full secret path, ARN, or Key Vault URL — so the
//! reference leaked through the wrapper instead of through the detail.

use ferrum_edge::tls::source::{CertSource, MaterialError, MaterialKind, SourceScheme};

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
