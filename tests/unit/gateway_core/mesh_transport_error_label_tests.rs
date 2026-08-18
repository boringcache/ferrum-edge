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
//! raw rustls/SPIFFE verifier text can ride the client body. The operator
//! `error!` record on the pool-error path is the same closed set (`error_kind`,
//! `error_phase`, and `peer_status` only for `ConnectRejected`) and never
//! interpolates `Display`. `Display` may still carry those details as an
//! error value.

use ferrum_edge::proxy::hbone_pool::{HbonePoolError, MeshTransportLabel};
use ferrum_edge::retry::error_class_log_kind;
use ferrum_edge::tls::spiffe::SpiffeTlsError;
use std::io;
use std::sync::{Arc, Mutex};
use tracing_subscriber::fmt::MakeWriter;

/// Values a client and the operator log must never echo from `Display`.
const SECRET_HOST: &str = "10.4.7.9:15006";
const SECRET_VERIFIER_TEXT: &str = concat!(
    "invalid peer certificate: BadSignature; ",
    "subject CN=hostile-leaf, ",
    "spiffe://cluster.local/ns/x/sa/y",
);
const SECRET_SPIFFE: &str = "spiffe://cluster.local/ns/default/sa/orders";
const SECRET_TRUST_ROOT: &str = "CN=cluster.local-hostile-root";
const SECRET_FINGERPRINT: &str = "sha256:deadbeefcafebabe00112233";
const SECRET_KEY_PATH: &str = "/var/run/secrets/svid/hostile-key.pem";
const SECRET_SAN: &str = "URI:spiffe://cluster.local/ns/x/sa/y";
const HOSTILE_SENTINELS: &[&str] = &[
    SECRET_HOST,
    SECRET_VERIFIER_TEXT,
    SECRET_SPIFFE,
    SECRET_TRUST_ROOT,
    SECRET_FINGERPRINT,
    SECRET_KEY_PATH,
    SECRET_SAN,
    "BadSignature",
    "spiffe://",
    "hostile-leaf",
    "hostile-root",
    "hostile-key.pem",
];

fn tls_handshake_error() -> HbonePoolError {
    HbonePoolError::TlsHandshake {
        host: SECRET_HOST.to_string(),
        source: io::Error::other(SECRET_VERIFIER_TEXT),
    }
}

#[derive(Clone, Default)]
struct SharedLogWriter(Arc<Mutex<Vec<u8>>>);

impl io::Write for SharedLogWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<'a> MakeWriter<'a> for SharedLogWriter {
    type Writer = Self;

    fn make_writer(&'a self) -> Self::Writer {
        self.clone()
    }
}

fn capture_pool_error_log(label: MeshTransportLabel, err: &HbonePoolError) -> String {
    let writer = SharedLogWriter::default();
    let subscriber = tracing_subscriber::fmt()
        .with_ansi(false)
        .with_target(false)
        .without_time()
        .with_writer(writer.clone())
        .finish();
    tracing::subscriber::with_default(subscriber, || {
        label.log_pool_error("mesh-outbound", err);
    });
    String::from_utf8(writer.0.lock().unwrap().clone()).expect("operator log must be utf-8")
}

fn sensitive_pool_errors() -> Vec<HbonePoolError> {
    vec![
        tls_handshake_error(),
        HbonePoolError::DnsLookup {
            host: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::ConnectTimeout {
            addr: SECRET_HOST.to_string(),
            timeout_ms: 250,
        },
        HbonePoolError::Connect {
            addr: SECRET_HOST.to_string(),
            source: io::Error::new(io::ErrorKind::ConnectionRefused, SECRET_VERIFIER_TEXT),
        },
        HbonePoolError::InvalidServerName {
            host: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::InvalidDialHostTag {
            value: SECRET_HOST.to_string(),
            message: SECRET_KEY_PATH.to_string(),
        },
        HbonePoolError::InvalidAuthorityHostTag {
            value: SECRET_HOST.to_string(),
            message: SECRET_SAN.to_string(),
        },
        HbonePoolError::InvalidPeerSpiffeTag {
            value: SECRET_SPIFFE.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::TlsConfig(SpiffeTlsError::BadKeyMaterial(format!(
            "{SECRET_VERIFIER_TEXT}; trust={SECRET_TRUST_ROOT}; \
             fp={SECRET_FINGERPRINT}; path={SECRET_KEY_PATH}"
        ))),
        HbonePoolError::TlsConfig(SpiffeTlsError::Rustls(format!(
            "{SECRET_VERIFIER_TEXT}; {SECRET_SAN}"
        ))),
        HbonePoolError::H2Handshake {
            host: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::InvalidConnectRequest {
            authority: SECRET_HOST.to_string(),
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
            host: SECRET_HOST.to_string(),
            port: 8080,
            current: 12,
            cap: 12,
        },
        HbonePoolError::ExtendedConnectUnsupported {
            authority: SECRET_HOST.to_string(),
        },
        HbonePoolError::TrustWithdrawn,
        HbonePoolError::MissingCrossClusterSni,
        HbonePoolError::MissingCrossClusterTrustDomain,
        HbonePoolError::MissingCrossClusterAuthorityHost,
        HbonePoolError::NoSvid,
        HbonePoolError::NoLeafCert,
    ]
}

fn assert_operator_log_redacted(logs: &str, err: &HbonePoolError, label: MeshTransportLabel) {
    for secret in HOSTILE_SENTINELS {
        assert!(
            !logs.contains(secret),
            "operator log leaked {secret:?}: {logs}"
        );
    }
    assert!(
        logs.contains(err.public_reason()),
        "operator log missing error_phase '{}': {logs}",
        err.public_reason()
    );
    assert!(
        logs.contains(error_class_log_kind(err.error_class())),
        "operator log missing error_kind: {logs}"
    );
    assert!(
        logs.contains(label.dispatch_failure_log_message()),
        "operator log missing transport message: {logs}"
    );
    match err.public_status() {
        Some(status) => {
            let status_text = status.to_string();
            assert!(
                logs.contains("peer_status=") && logs.contains(&status_text),
                "operator log missing numeric CONNECT peer_status {status}: {logs}"
            );
        }
        None => {
            assert!(
                !logs.contains("peer_status"),
                "operator log grew an unexpected peer_status field: {logs}"
            );
        }
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
    let error = tls_handshake_error();
    let body = MeshTransportLabel::SidecarMtls.unavailable_body_for_error(&error);
    assert_eq!(
        body,
        r#"{"error":"Sidecar mTLS backend unavailable: TLS handshake failed"}"#
    );
}

#[test]
fn ambient_handshake_failure_body_still_says_hbone() {
    let error = tls_handshake_error();
    let body = MeshTransportLabel::Hbone.unavailable_body_for_error(&error);
    assert_eq!(
        body,
        r#"{"error":"HBONE backend unavailable: TLS handshake failed"}"#
    );
}

#[test]
fn connect_rejection_keeps_the_peer_admission_status_and_nothing_else() {
    // Issue #3927 redacts the CONNECT authority, but NOT the peer's own
    // admission status: a destination HBONE policy denial (403) has to stay
    // distinguishable from any other tunnel refusal, and the NodeWaypoint
    // eBPF live gate matches this exact body to prove a forged baggage
    // assertion was refused by POLICY. A `u16` cannot carry peer-controlled
    // text, so the suffix is not a redaction hole.
    let error = HbonePoolError::ConnectRejected {
        authority: SECRET_HOST.to_string(),
        status: 403,
    };
    assert_eq!(error.public_status(), Some(403));
    assert_eq!(
        MeshTransportLabel::Hbone.unavailable_body_for_error(&error),
        r#"{"error":"HBONE backend unavailable: tunnel rejected by peer with status 403"}"#
    );
    assert_eq!(
        MeshTransportLabel::SidecarMtls.unavailable_body_for_error(&error),
        r#"{"error":"Sidecar mTLS backend unavailable: tunnel rejected by peer with status 403"}"#
    );
}

#[test]
fn no_other_variant_grows_a_status_suffix() {
    // The numeric suffix is variant-scoped. If another variant ever reported a
    // status, its public body would start carrying a peer-influenced value
    // that no test pins.
    for err in [
        tls_handshake_error(),
        HbonePoolError::ConnectTimeout {
            addr: SECRET_HOST.to_string(),
            timeout_ms: 250,
        },
        HbonePoolError::ConnectStream {
            authority: SECRET_HOST.to_string(),
            message: SECRET_VERIFIER_TEXT.to_string(),
        },
        HbonePoolError::TrustWithdrawn,
    ] {
        assert_eq!(err.public_status(), None, "{err}");
        let body = MeshTransportLabel::Hbone.unavailable_body_for_error(&err);
        assert!(!body.contains("with status"), "{body}");
    }
}

// ── Redaction contract ────────────────────────────────────────────────────

#[test]
fn public_reason_never_echoes_peer_or_verifier_detail() {
    for err in sensitive_pool_errors() {
        let reason = err.public_reason();
        for secret in HOSTILE_SENTINELS {
            assert!(
                !reason.contains(secret),
                "public reason '{reason}' leaked '{secret}'"
            );
        }
        for label in [MeshTransportLabel::Hbone, MeshTransportLabel::SidecarMtls] {
            let body = label.unavailable_body_for_error(&err);
            for secret in HOSTILE_SENTINELS {
                assert!(
                    !body.contains(secret),
                    "client body '{body}' leaked '{secret}'"
                );
            }
        }
    }
}

#[test]
fn display_still_carries_internal_diagnostic_detail() {
    // `Display` remains useful as the error value. Production operator logs
    // must not interpolate it; they are pinned separately by capturing the
    // `error!` record.
    let rendered = tls_handshake_error().to_string();
    assert!(rendered.contains(SECRET_HOST), "{rendered}");
    assert!(rendered.contains("BadSignature"), "{rendered}");
}

#[test]
fn shared_server_name_error_is_transport_neutral_in_operator_logs() {
    let rendered = HbonePoolError::InvalidServerName {
        host: SECRET_HOST.to_string(),
        message: SECRET_VERIFIER_TEXT.to_string(),
    }
    .to_string();
    assert!(
        rendered.contains("invalid mesh TLS server name"),
        "{rendered}"
    );
    assert!(
        !rendered.contains("HBONE"),
        "the shared error may be logged by the sidecar transport: {rendered}"
    );
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

#[test]
fn operator_pool_error_log_omits_hostile_display_detail() {
    for err in sensitive_pool_errors() {
        for label in [MeshTransportLabel::Hbone, MeshTransportLabel::SidecarMtls] {
            let logs = capture_pool_error_log(label, &err);
            assert!(
                !logs.trim().is_empty(),
                "pool-error path must emit an operator log"
            );
            assert_operator_log_redacted(&logs, &err, label);
        }
    }
}

#[test]
fn connect_rejected_operator_log_keeps_numeric_peer_status() {
    let err = HbonePoolError::ConnectRejected {
        authority: SECRET_HOST.to_string(),
        status: 403,
    };
    let logs = capture_pool_error_log(MeshTransportLabel::Hbone, &err);
    assert_operator_log_redacted(&logs, &err, MeshTransportLabel::Hbone);
    assert!(
        logs.contains("peer_status=403"),
        "CONNECT admission status must remain a closed numeric field: {logs}"
    );
    assert_eq!(
        MeshTransportLabel::Hbone.unavailable_body_for_error(&err),
        r#"{"error":"HBONE backend unavailable: tunnel rejected by peer with status 403"}"#
    );
}
