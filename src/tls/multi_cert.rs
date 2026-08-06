//! SNI-aware frontend certificate selection for Gateway-delivered TLS.
//!
//! A Kubernetes Gateway may terminate TLS for several hostnames from one data
//! plane: one listener may carry several `certificateRefs`, and several
//! Gateways in one namespace may each own their own certificate (issues #3267
//! and #3268). rustls selects a credential per ClientHello through a
//! [`rustls::server::ResolvesServerCert`], so that is where the choice belongs.
//!
//! Selection is exact-match first, then one-label wildcard, then the
//! deterministic fallback certificate. The index is built once per config
//! snapshot from data the control plane already authorized — no per-handshake
//! parsing, allocation, or locking, and no growth with request volume.
//!
//! Nothing here logs or formats key material: an entry is identified by its
//! owning `namespace/gateway/listener`, which is public Kubernetes metadata.

use std::collections::HashMap;
use std::sync::Arc;

use rustls::pki_types::{CertificateDer, CertificateRevocationListDer};
use rustls::server::{ClientHello, ResolvesServerCert};
use rustls::sign::CertifiedKey;
use tracing::{debug, info, warn};
use x509_parser::extensions::{GeneralName, ParsedExtension};
use x509_parser::prelude::*;

use crate::tls::TlsPolicy;
use crate::tls::source::{CertSource, MaterialKind, SourceScheme, load_material_blocking};

/// Upper bound on SNI names indexed across the whole snapshot.
///
/// The certificate set is already capped at admission
/// (`MAX_FRONTEND_TLS_CERTIFICATE_SOURCES`), but a single certificate may carry
/// an arbitrary number of SANs, so the derived index needs its own ceiling.
/// Names beyond it are dropped with a warning; the affected certificate is
/// still reachable through its listener hostname or the fallback slot, so this
/// degrades selection rather than failing a handshake open.
pub const MAX_SNI_INDEX_ENTRIES: usize = 4096;

/// One Gateway-owned certificate to install in the resolver.
#[derive(Debug, Clone)]
pub struct GatewayCertificateInput {
    pub cert_source: String,
    pub key_source: String,
    /// The owning listener's `hostname`, ASCII-lowercased. `None` is a
    /// catch-all listener: it contributes only the certificate's own SANs.
    pub hostname: Option<String>,
    /// `namespace/gateway/listener` — public metadata, used for diagnostics.
    /// Never contains certificate or key bytes.
    pub identity: String,
    /// Whether this is the snapshot's fallback certificate.
    pub is_default: bool,
}

/// SNI → certificate index built once per config snapshot.
///
/// `Debug` deliberately reports only counts: a `CertifiedKey` holds a live
/// signing key, and a resolver is reachable from broad runtime state dumps.
pub struct SniCertResolver {
    exact: HashMap<String, Arc<CertifiedKey>>,
    /// Keyed by the suffix AFTER `*.`, so `*.example.com` is stored as
    /// `example.com` and matched against a client name's parent domain.
    wildcard: HashMap<String, Arc<CertifiedKey>>,
    fallback: Arc<CertifiedKey>,
}

impl std::fmt::Debug for SniCertResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SniCertResolver")
            .field("exact_names", &self.exact.len())
            .field("wildcard_names", &self.wildcard.len())
            .finish_non_exhaustive()
    }
}

impl SniCertResolver {
    /// The certificate a server name selects, or `None` to use the fallback.
    ///
    /// Exact beats wildcard: `a.example.com` prefers a certificate that names
    /// it outright over one that only names `*.example.com`. Wildcards match a
    /// single label, per RFC 6125 — `*.example.com` covers `a.example.com` but
    /// not `a.b.example.com` and not bare `example.com`.
    fn select(&self, server_name: &str) -> Option<Arc<CertifiedKey>> {
        if let Some(certified_key) = self.exact.get(server_name) {
            return Some(certified_key.clone());
        }
        let (label, parent) = server_name.split_once('.')?;
        if label.is_empty() || parent.is_empty() {
            return None;
        }
        self.wildcard.get(parent).cloned()
    }
}

impl ResolvesServerCert for SniCertResolver {
    fn resolve(&self, client_hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        // rustls already lowercases and validates the SNI host_name, and a
        // ClientHello without SNI (or with an unknown one) is answered with the
        // fallback rather than a handshake failure — the same credential a
        // single-certificate listener would have presented.
        let selected = client_hello
            .server_name()
            .and_then(|server_name| self.select(server_name));
        Some(selected.unwrap_or_else(|| self.fallback.clone()))
    }
}

/// Build the frontend `ServerConfig` that serves a Gateway's whole certificate
/// set, selecting per ClientHello by SNI.
///
/// Fails closed: if ANY certificate in the set cannot be loaded, parsed,
/// paired, or is expired, the whole config fails and the caller keeps its
/// previous one. Serving a partial set would silently answer some hostnames
/// with the fallback certificate — a name mismatch the operator never asked
/// for — so a broken certificate is a rejected snapshot, not a degraded one.
pub fn load_gateway_multi_cert_tls_config(
    certificates: &[GatewayCertificateInput],
    client_ca_bundle_path: Option<&str>,
    ocsp_response_source: Option<&str>,
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
    crls: &[CertificateRevocationListDer<'static>],
) -> Result<Arc<rustls::ServerConfig>, anyhow::Error> {
    if certificates.is_empty() {
        anyhow::bail!("Gateway frontend TLS was requested with no certificate sources");
    }

    // A single stapled OCSP response is bound to ONE certificate, so it is
    // only correct to attach while there is exactly one. With several, it is
    // deliberately not attached to any: stapling a response for the wrong
    // certificate breaks handshakes with clients that check staple validity,
    // and guessing which certificate it belongs to is not something the
    // operator asked for.
    let ocsp_response = match (ocsp_response_source, certificates.len()) {
        (Some(source), 1) => {
            let material = load_material_blocking(
                &CertSource::parse(source, MaterialKind::Ocsp),
                MaterialKind::Ocsp,
            )?;
            let bytes = material.bytes.expose_secret().to_vec();
            if bytes.is_empty() {
                anyhow::bail!(
                    "OCSP response source '{}' was empty",
                    material.display_source_id
                );
            }
            bytes
        }
        (Some(_), _) => {
            warn!(
                certificate_count = certificates.len(),
                "A stapled OCSP response is configured but this data plane serves several Gateway \
                 certificates; the response is bound to one certificate and is not stapled to any \
                 of them"
            );
            Vec::new()
        }
        (None, _) => Vec::new(),
    };

    let mut exact: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut wildcard: HashMap<String, Arc<CertifiedKey>> = HashMap::new();
    let mut fallback: Option<Arc<CertifiedKey>> = None;
    let mut indexed_names = 0usize;
    let mut dropped_names = 0usize;
    let mut cert_display = String::new();
    let mut key_display = String::new();
    let mut first_key: Option<Arc<CertifiedKey>> = None;

    for input in certificates {
        let (certified_key, leaf, cert_source_id, key_source_id) =
            load_certified_key(input, &ocsp_response, tls_policy, cert_expiry_warning_days)?;
        if cert_display.is_empty() {
            cert_display = cert_source_id;
            key_display = key_source_id;
        }

        for name in sni_names_for(input, &leaf) {
            if indexed_names >= MAX_SNI_INDEX_ENTRIES {
                dropped_names += 1;
                continue;
            }
            // Own the derived key before choosing a map: taking `&mut` to one
            // of two maps while a borrow of `name` is still live would not
            // borrow-check.
            let wildcard_parent = name
                .strip_prefix("*.")
                .filter(|parent| !parent.is_empty())
                .map(str::to_string);
            let (map, key) = match wildcard_parent {
                Some(parent) => (&mut wildcard, parent),
                None => (&mut exact, name),
            };
            match map.entry(key) {
                std::collections::hash_map::Entry::Occupied(entry) => {
                    // First writer wins, and the order is the control plane's
                    // deterministic one, so the same snapshot always resolves
                    // the same way. Overlapping SANs are ordinary, so this is
                    // a debug line rather than a warning.
                    debug!(
                        server_name = %entry.key(),
                        certificate = %input.identity,
                        "Gateway certificate does not take this SNI name; an earlier certificate \
                         already serves it"
                    );
                }
                std::collections::hash_map::Entry::Vacant(entry) => {
                    entry.insert(certified_key.clone());
                    indexed_names += 1;
                }
            }
        }

        if input.is_default && fallback.is_none() {
            fallback = Some(certified_key.clone());
        }
        if first_key.is_none() {
            first_key = Some(certified_key);
        }
    }

    if dropped_names > 0 {
        warn!(
            dropped_names,
            limit = MAX_SNI_INDEX_ENTRIES,
            "Gateway frontend TLS SNI index reached its limit; the remaining names are served by \
             their listener hostname or the fallback certificate"
        );
    }

    // No entry carried the marker (a snapshot from a control plane that
    // predates it, or a hand-written config): the first certificate in the
    // control plane's deterministic order takes the slot rather than leaving
    // the listener with no credential for an unmatched ClientHello.
    let fallback = fallback.or(first_key).ok_or_else(|| {
        anyhow::anyhow!("Gateway frontend TLS produced no usable fallback certificate")
    })?;

    info!(
        certificate_count = certificates.len(),
        exact_names = exact.len(),
        wildcard_names = wildcard.len(),
        "Built SNI-aware Gateway frontend TLS certificate resolver"
    );

    let sni_resolver = Arc::new(SniCertResolver {
        exact,
        wildcard,
        fallback,
    });
    // ACME TLS-ALPN-01 validation still wins over SNI selection, exactly as it
    // does on a single-certificate listener.
    let resolver = Arc::new(crate::tls::acme::AcmeTlsAlpnResolver::with_resolver(
        sni_resolver,
    ));
    let client_ca_source =
        client_ca_bundle_path.map(|source| CertSource::parse(source, MaterialKind::CaBundle));

    crate::tls::finish_frontend_server_config(
        resolver,
        client_ca_source.as_ref(),
        false,
        tls_policy,
        cert_expiry_warning_days,
        crls,
        &cert_display,
        &key_display,
    )
}

/// Load and pair one certificate, returning it plus its parsed leaf DER.
fn load_certified_key(
    input: &GatewayCertificateInput,
    ocsp_response: &[u8],
    tls_policy: &TlsPolicy,
    cert_expiry_warning_days: u64,
) -> Result<(Arc<CertifiedKey>, CertificateDer<'static>, String, String), anyhow::Error> {
    let cert_source = CertSource::parse(input.cert_source.as_str(), MaterialKind::Cert);
    let key_source = CertSource::parse(input.key_source.as_str(), MaterialKind::Key);
    if matches!(&key_source, CertSource::Uri(uri) if uri.scheme == SourceScheme::Pkcs11) {
        anyhow::bail!(
            "Gateway certificate {} uses a PKCS#11 key source, which the multi-certificate \
             frontend does not support",
            input.identity
        );
    }

    let cert_material = load_material_blocking(&cert_source, MaterialKind::Cert)?;
    crate::tls::check_cert_expiry_from_pem_bytes(
        cert_material.bytes.expose_secret(),
        "Gateway server TLS cert",
        &cert_material.display_source_id,
        cert_expiry_warning_days,
    )?;
    let cert_chain = crate::tls::parse_pem_certificate_bundle(
        cert_material.bytes.expose_secret(),
        "Gateway server TLS cert",
        &cert_material.display_source_id,
    )?;
    let leaf = cert_chain.first().cloned().ok_or_else(|| {
        anyhow::anyhow!("Gateway certificate {} has an empty chain", input.identity)
    })?;

    let key_material = load_material_blocking(&key_source, MaterialKind::Key)?;
    let key = crate::tls::parse_pem_private_key(
        key_material.bytes.expose_secret(),
        "Gateway server TLS private key",
        &key_material.display_source_id,
    )?;

    let mut certified_key =
        CertifiedKey::from_der(cert_chain, key, tls_policy.crypto_provider.as_ref()).map_err(
            |error| {
                anyhow::anyhow!(
                    "Gateway certificate {} cert and key do not form a valid pair: {error}",
                    input.identity
                )
            },
        )?;
    if !ocsp_response.is_empty() {
        certified_key.ocsp = Some(ocsp_response.to_vec());
    }

    Ok((
        Arc::new(certified_key),
        leaf,
        cert_material.display_source_id,
        key_material.display_source_id,
    ))
}

/// The SNI names one certificate answers to.
///
/// The listener `hostname` comes first because it is what the operator
/// *declared* this listener serves; the leaf's own DNS SANs follow so a
/// catch-all listener (no hostname) is still reachable by name, and so a
/// multi-SAN certificate covers every name it was actually issued for.
fn sni_names_for(input: &GatewayCertificateInput, leaf: &CertificateDer<'_>) -> Vec<String> {
    let mut names = Vec::new();
    if let Some(hostname) = input.hostname.as_deref()
        && is_indexable_sni_name(hostname)
    {
        names.push(hostname.to_string());
    }
    for san in leaf_dns_sans(leaf) {
        if is_indexable_sni_name(&san) && !names.contains(&san) {
            names.push(san);
        }
    }
    names
}

/// DNS SANs of a leaf certificate, ASCII-lowercased.
///
/// A certificate that cannot be parsed here is not an error: it already passed
/// `CertifiedKey::from_der`, so it is usable — it simply contributes no
/// SAN-derived names and stays reachable by listener hostname or fallback.
fn leaf_dns_sans(leaf: &CertificateDer<'_>) -> Vec<String> {
    let Ok((_, certificate)) = X509Certificate::from_der(leaf.as_ref()) else {
        return Vec::new();
    };
    let mut names = Vec::new();
    for extension in certificate.extensions() {
        if let ParsedExtension::SubjectAlternativeName(san) = extension.parsed_extension() {
            for general_name in &san.general_names {
                if let GeneralName::DNSName(value) = general_name {
                    names.push(value.to_ascii_lowercase());
                }
            }
        }
    }
    names
}

/// Whether a name is safe to put in the SNI index.
///
/// Rejects the bare `*` catch-all (that is the fallback slot's job, not a
/// wildcard entry), empty labels, over-long names, and anything outside the
/// LDH + `*.` shape a ClientHello `server_name` can carry — a name rustls would
/// never present cannot be matched and would only take up index space.
fn is_indexable_sni_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 253 || name == "*" {
        return false;
    }
    let candidate = name.strip_prefix("*.").unwrap_or(name);
    if candidate.is_empty() {
        return false;
    }
    candidate.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn indexable_sni_names_reject_unusable_shapes() {
        assert!(is_indexable_sni_name("api.example.com"));
        assert!(is_indexable_sni_name("*.example.com"));
        assert!(!is_indexable_sni_name("*"));
        assert!(!is_indexable_sni_name(""));
        assert!(!is_indexable_sni_name("a..b"));
        assert!(!is_indexable_sni_name("a_b.example.com"));
        assert!(!is_indexable_sni_name(&"a".repeat(254)));
    }
}
