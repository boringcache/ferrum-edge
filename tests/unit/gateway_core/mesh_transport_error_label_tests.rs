//! Topology-specific public error wording for mesh transport dispatch
//! failures (issue #3927).
//!
//! Two different datapaths share [`HbonePoolError`] because they share every
//! failure shape:
//!
//! * **Ambient / waypoint** dials HTTP/2 CONNECT over `:15008` — a real HBONE
//!   tunnel, so its client-visible wording must keep saying HBONE.
//! * **Sidecar** dials plain HTTP/2 over mutual TLS to a peer sidecar's
//!   `:15006` inbound listener. No CONNECT tunnel is ever opened, so calling
//!   its handshake failure "HBONE backend unavailable" sent operators to debug
//!   a tunnel that does not exist (the reported symptom in #3927).
//!
//! These tests also pin the redaction contract: the public reason is chosen
//! from the error VARIANT and is always a fixed `&'static str`, so no peer
//! address, CONNECT authority, SPIFFE ID, certificate subject, trust root, or
//! raw rustls/SPIFFE verifier text can ride the client body. The full
//! `Display` — which does carry those details — stays on the operator log.

use ferrum_edge::proxy::hbone_pool::{HbonePoolError, MeshTransportLabel};
use ferrum_edge::tls::spiffe::SpiffeTlsError;
use std::io;

/// Values a client must never be able to read back out of an error body.
const SECRET_HOST: &str = "10.4.7.9:15006";
const SECRET_VERIFIER_TEXT: &str =
    "invalid peer certificate: BadSignature; subject CN=orders, spiffe://cluster.local/ns/x/sa/y";

fn tls_handshake_error() -> HbonePoolError {
    HbonePoolError::TlsHandshake {
        host: SECRET_HOST.to_string(),
        source: io::Error::other(SECRET_VERIFIER_TEXT),
    }
}

// ── Public noun is topology-specific ──────────────────────────────────────

#[test]
fn ambient_transport_keeps_hbone_wording() {
    assert_eq!(
        MeshTransportLabel::Hbone.unavailable_noun(),
        "HBONE backend unavailable"
    );
    assert_eq!(
        MeshTransportLabel::Hbone.unavailable_body(),
        r#"{"error":"HBONE backend unavailable"}"#
    );
    assert_eq!(
        MeshTransportLabel::Hbone.dns_failure_body(),
        r#"{"error":"DNS resolution for HBONE backend failed"}"#
    );
    assert_eq!(MeshTransportLabel::Hbone.log_noun(), "HBONE");
}

#[test]
fn sidecar_mtls_transport_never_claims_hbone() {
    let label = MeshTransportLabel::SidecarMtls;
    assert_eq!(label.unavailable_noun(), "Sidecar mTLS backend unavailable");
    assert_eq!(
        label.unavailable_body(),
        r#"{"error":"Sidecar mTLS backend unavailable"}"#
    );
    assert_eq!(
        label.dns_failure_body(),
        r#"{"error":"DNS resolution for sidecar mTLS backend failed"}"#
    );
    assert_eq!(label.log_noun(), "Sidecar mTLS");

    for text in [
        label.unavailable_noun(),
        label.unavailable_body(),
        label.dns_failure_body(),
        label.log_noun(),
    ] {
        assert!(
            !text.to_ascii_lowercase().contains("hbone"),
            "sidecar SVID-mTLS surfaces must never mention HBONE: {text}"
        );
    }
}

#[test]
fn sidecar_handshake_failure_body_is_the_reported_regression() {
    // The exact shape reported in #3927 — a sidecar-to-sidecar `:15006`
    // SVID-mTLS handshake failure — must no longer be labeled HBONE, and must
    // still say which phase failed.
    let reason = tls_handshake_error().public_reason();
    let body = MeshTransportLabel::SidecarMtls.unavailable_body_with_reason(reason);
    assert_eq!(
        body,
        r#"{"error":"Sidecar mTLS backend unavailable: TLS handshake failed"}"#
    );
}

#[test]
fn ambient_handshake_failure_body_still_says_hbone() {
    let reason = tls_handshake_error().public_reason();
    let body = MeshTransportLabel::Hbone.unavailable_body_with_reason(reason);
    assert_eq!(
        body,
        r#"{"error":"HBONE backend unavailable: TLS handshake failed"}"#
    );
}

// ── Redaction contract ────────────────────────────────────────────────────

#[test]
fn public_reason_never_echoes_peer_or_verifier_detail() {
    let leaky = [
        tls_handshake_error(),
        HbonePoolError::Connect {
            addr: SECRET_HOST.to_string(),
            source: io::Error::new(io::ErrorKind::ConnectionRefused, SECRET_VERIFIER_TEXT),
        },
        HbonePoolError::ConnectTimeout {
            addr: SECRET_HOST.to_string(),
            timeout_ms: 250,
        },
        HbonePoolError::DnsLookup {
            host: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::InvalidServerName {
            host: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::InvalidPeerSpiffeTag {
            value: "spiffe://cluster.local/ns/default/sa/orders".to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::H2Handshake {
            host: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::ConnectStream {
            authority: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::ConnectRejected {
            authority: SECRET_HOST.to_string(),
            status: 403,
        },
        HbonePoolError::MaxConnectionsExceeded {
            host: "orders.default.svc.cluster.local".to_string(),
            port: 8080,
            current: 12,
            cap: 12,
        },
        HbonePoolError::TlsConfig(SpiffeTlsError::BadKeyMaterial(
            SECRET_VERIFIER_TEXT.to_string(),
        )),
    ];

    for err in &leaky {
        let reason = err.public_reason();
        for secret in [
            SECRET_HOST,
            SECRET_VERIFIER_TEXT,
            "spiffe://",
            "BadSignature",
            "orders",
        ] {
            assert!(
                !reason.contains(secret),
                "public reason '{reason}' leaked '{secret}'"
            );
        }
        for label in [MeshTransportLabel::Hbone, MeshTransportLabel::SidecarMtls] {
            let body = label.unavailable_body_with_reason(reason);
            assert!(
                !body.contains(SECRET_HOST) && !body.contains("BadSignature"),
                "client body '{body}' leaked peer/verifier detail"
            );
        }
    }
}

#[test]
fn display_keeps_the_detail_the_operator_log_needs() {
    // The redaction is client-side only: the operator-facing `Display` (what
    // the `error!` line carries) must still name the peer and the cause, or
    // the fix would have traded a mislabel for an undiagnosable failure.
    let rendered = tls_handshake_error().to_string();
    assert!(rendered.contains(SECRET_HOST), "{rendered}");
    assert!(rendered.contains("BadSignature"), "{rendered}");
}

#[test]
fn every_reason_is_a_short_fixed_phrase() {
    // A reason is a phase name, never a sentence assembled from peer input.
    for err in [
        HbonePoolError::NoSvid,
        HbonePoolError::NoLeafCert,
        HbonePoolError::TrustWithdrawn,
        HbonePoolError::MissingCrossClusterSni,
        HbonePoolError::MissingCrossClusterTrustDomain,
        HbonePoolError::MissingCrossClusterAuthorityHost,
        HbonePoolError::ExtendedConnectUnsupported {
            authority: SECRET_HOST.to_string(),
        },
        HbonePoolError::InvalidConnectRequest {
            authority: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::InvalidDialHostTag {
            value: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::InvalidAuthorityHostTag {
            value: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
    ] {
        let reason = err.public_reason();
        assert!(!reason.is_empty(), "empty public reason");
        assert!(reason.len() <= 64, "public reason too chatty: {reason}");
        assert!(
            !reason.contains('"') && !reason.contains('\\'),
            "public reason must be JSON-body safe without escaping: {reason}"
        );
        assert!(!reason.contains(SECRET_HOST), "{reason}");
        assert!(!reason.contains(SECRET_VERIFIER_TEXT), "{reason}");
    }
}
