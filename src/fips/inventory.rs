//! Source-level cryptographic inventory.
//!
//! Every security-relevant cryptographic operation Ferrum performs is listed
//! here with the source location that performs it, the library that implements
//! it, and its disposition under FIPS mode. The table is the machine-readable
//! half of `docs/fips.md`; the prose half explains the module boundary and the
//! operator obligations.
//!
//! This exists because "uses a FIPS-capable library" is not evidence of
//! coverage — so note the precise meaning of [`Disposition::ModuleRoutable`]:
//! the operation resolves its implementation through Ferrum's provider seam
//! ([`crate::fips::base_crypto_provider`], [`crate::fips::backend`],
//! [`crate::fips::approved`]), through a dependency crypto backend the
//! mutually exclusive `crypto-ring` / `fips` cargo-feature pair selects, or
//! through the process-default rustls provider that
//! [`crate::fips::install_crypto_provider`] installed. On a build where
//! [`crate::fips::BUILD_CAPABLE`] is `true` it therefore reaches the validated
//! module; on an ordinary build it reaches `ring`, and the mode refuses to
//! enforce.
//!
//! The other dispositions are the honest remainder:
//! [`Disposition::PendingClassification`] (security-relevant, not yet routed —
//! the variant is retained so a newly discovered surface has somewhere honest
//! to land, and `pending_classification()` must be **empty** on a build that
//! claims a complete surface), [`Disposition::Rejected`] (refused by
//! [`crate::fips::policy`] before serving), and
//! [`Disposition::OutsideBoundary`] (not cryptography Ferrum is claiming, and
//! documented as such — either not a security service, or performed by a
//! separately validated component the operator supplies).
//!
//! `tests/unit/tls/fips_policy_tests.rs` asserts the invariants that keep this
//! table honest: every entry carries a non-empty rationale, the set of rejected
//! plugins agrees with [`crate::fips::policy::NON_APPROVED_PLUGINS`], and the
//! work register is empty.

/// How one cryptographic operation behaves under FIPS mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Disposition {
    /// Resolves through Ferrum's provider seam or a build-time-selected
    /// dependency backend, and so reaches the validated module on a build that
    /// links one. See the module docs for why this is "routable", not "backed".
    ModuleRoutable,
    /// Security-relevant, and *not* yet routed through the seam. Each of these
    /// must be moved onto the module or explicitly rejected before a FIPS
    /// deployment claim is possible. See `docs/fips.md` §"Residual work".
    PendingClassification,
    /// Cannot reach the module, and FIPS mode refuses the configuration that
    /// would perform it.
    Rejected,
    /// Not a security claim Ferrum makes: either the operation is not
    /// security-relevant (a protocol handshake token, a scheduling jitter
    /// source), or the cryptography is performed by a separately validated
    /// component the operator supplies (an HSM behind PKCS#11).
    OutsideBoundary,
}

impl Disposition {
    /// Stable identifier for status/documentation rendering.
    pub fn as_str(self) -> &'static str {
        match self {
            Self::ModuleRoutable => "module-routable",
            Self::PendingClassification => "pending-classification",
            Self::Rejected => "rejected",
            Self::OutsideBoundary => "outside-boundary",
        }
    }
}

/// One inventory row.
#[derive(Debug, Clone, Copy)]
pub struct CryptoOperation {
    /// Operation, in the vocabulary of issue #3510's acceptance criteria.
    pub operation: &'static str,
    /// Primary source location that performs it.
    pub location: &'static str,
    /// Implementing library, as it appears in `Cargo.toml`.
    pub implementation: &'static str,
    /// Disposition under FIPS mode.
    pub disposition: Disposition,
    /// The mechanism that achieves or enforces the disposition. For a
    /// [`Disposition::Rejected`] row this names the check that rejects it; for a
    /// [`Disposition::PendingClassification`] row it names the outstanding work.
    pub rationale: &'static str,
}

/// The complete inventory.
pub const INVENTORY: &[CryptoOperation] = &[
    // ── Frontend TLS: HTTP/1.1, HTTP/2, WebSocket ───────────────────────
    CryptoOperation {
        operation: "Frontend TLS 1.2/1.3 termination (H1, H2, WebSocket)",
        location: "src/tls/mod.rs::TlsPolicy::from_env_config",
        implementation: "rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "provider comes from fips::base_crypto_provider(); suites and groups are \
                    screened by fips::policy::check_tls_policy",
    },
    CryptoOperation {
        operation: "Frontend mTLS client certificate verification + CRL",
        location: "src/tls/mod.rs::load_tls_config_with_client_auth",
        implementation: "rustls, rustls-webpki",
        disposition: Disposition::ModuleRoutable,
        rationale: "verifier is built from the same TlsPolicy provider",
    },
    CryptoOperation {
        operation: "Frontend TLS live reload (cert/key rotation)",
        location: "src/tls/frontend_reload.rs, src/modes/tls_reload.rs",
        implementation: "rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "rebuilds through TlsPolicy, so reload re-applies the same policy",
    },
    // ── Admin TLS ───────────────────────────────────────────────────────
    CryptoOperation {
        operation: "Admin API HTTPS listener",
        location: "src/admin/tls_management.rs",
        implementation: "rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "ServerConfig::builder_with_provider(fips::base_crypto_provider())",
    },
    // ── HTTP/3 and QUIC ─────────────────────────────────────────────────
    CryptoOperation {
        operation: "HTTP/3 server QUIC handshake, packet protection, initial keys",
        location: "src/http3/server.rs",
        implementation: "quinn, quinn-proto, rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "quinn is declared with default-features = false so its default `rustls-ring` \
                    arm is never compiled; the `fips` feature selects quinn/rustls-aws-lc-rs-fips. \
                    Initial keys come from the supplied rustls config's own provider \
                    (fips::base_crypto_provider()), and the TLS 1.3 suite fallback resolves \
                    against that same provider",
    },
    CryptoOperation {
        operation: "HTTP/3 backend (client) QUIC handshake",
        location: "src/http3/client.rs",
        implementation: "quinn, rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "client config is built from fips::base_crypto_provider()",
    },
    // ── Backend TLS ─────────────────────────────────────────────────────
    CryptoOperation {
        operation: "Backend TLS/mTLS for H1, H2, gRPC, wss, TCP-TLS",
        location: "src/tls/backend.rs",
        implementation: "rustls, passed to reqwest via use_preconfigured_tls",
        disposition: Disposition::ModuleRoutable,
        rationale: "Ferrum builds the ClientConfig from the seam; reqwest 0.13's rustls feature \
                    is already aws-lc-rs backed and receives the preconfigured config",
    },
    CryptoOperation {
        operation: "SPIFFE/SVID backend identity and trust-bundle verification",
        location: "src/tls/spiffe.rs, src/identity/",
        implementation: "rustls, rustls-webpki",
        disposition: Disposition::ModuleRoutable,
        rationale: "verifier and signing key built through the seam",
    },
    // ── CP/DP control plane ─────────────────────────────────────────────
    CryptoOperation {
        operation: "CP/DP gRPC transport TLS and mTLS",
        location: "src/grpc/cp_server.rs, src/grpc/dp_client.rs",
        implementation: "tonic, tokio-rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "the `fips` feature selects tonic/tls-aws-lc and excludes tonic/tls-ring, so no \
                    ring arm is compiled; tonic also resolves CryptoProvider::get_default() first, \
                    which fips::install_crypto_provider() sets",
    },
    CryptoOperation {
        operation: "CP/DP gRPC bearer-token HS256 signing and verification",
        location: "src/grpc/auth.rs",
        implementation: "jsonwebtoken (aws_lc_rs backend on a fips build)",
        disposition: Disposition::ModuleRoutable,
        rationale: "the `fips` cargo feature selects jsonwebtoken/aws_lc_rs and excludes \
                    jsonwebtoken/rust_crypto, so HS256 runs in the module. Key length is floored \
                    by fips::policy::check_env_config",
    },
    // ── DTLS ────────────────────────────────────────────────────────────
    CryptoOperation {
        operation: "DTLS 1.2/1.3 frontend termination (UDP proxy)",
        location: "src/dtls/mod.rs",
        implementation: "dimpl (vendored), aws-lc-rs",
        disposition: Disposition::ModuleRoutable,
        rationale: "dimpl already selects the aws-lc-rs backend, so cargo feature unification \
                    turns that same crate into the FIPS module build once aws-lc-rs/fips is on",
    },
    CryptoOperation {
        operation: "DTLS private-key parsing / signing key selection",
        location: "src/dtls/mod.rs",
        implementation: "rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "fips::any_supported_signing_key() selects the active key provider without a \
                    second owned DER allocation",
    },
    // ── Config store ────────────────────────────────────────────────────
    CryptoOperation {
        operation: "SQL config-database TLS (postgres, mysql, sqlite)",
        location: "src/config/db_backend.rs",
        implementation: "sqlx, rustls",
        disposition: Disposition::ModuleRoutable,
        rationale: "the `fips` feature selects sqlx/tls-rustls-aws-lc-rs and the `crypto-ring` \
                    feature that would otherwise keep sqlx-core on ring is mutually exclusive \
                    with it",
    },
    CryptoOperation {
        operation: "MongoDB config-database TLS",
        location: "src/config/mongo_store.rs",
        implementation: "mongodb driver (pins rustls/ring in its own manifest)",
        disposition: Disposition::Rejected,
        rationale: "fips::policy refuses FERRUM_DB_TYPE=mongodb with FERRUM_DB_TLS_MODE other \
                    than `disable`",
    },
    // ── JWT / JWK ───────────────────────────────────────────────────────
    CryptoOperation {
        operation: "Admin API JWT verification",
        location: "src/admin/jwt_auth.rs",
        implementation: "jsonwebtoken (aws_lc_rs backend on a fips build)",
        disposition: Disposition::ModuleRoutable,
        rationale: "the `fips` cargo feature selects jsonwebtoken/aws_lc_rs",
    },
    CryptoOperation {
        operation: "Request-path JWT and JWKS verification (plugins)",
        location: "src/plugins/jwt_auth.rs, src/plugins/jwks_auth.rs",
        implementation: "jsonwebtoken (aws_lc_rs backend on a fips build)",
        disposition: Disposition::ModuleRoutable,
        rationale: "algorithms are screened against fips::policy::APPROVED_JWT_ALGORITHMS at \
                    config admission and the implementation is selected by the `fips` feature",
    },
    // ── Hash / MAC / randomness ─────────────────────────────────────────
    CryptoOperation {
        operation: "HMAC-SHA256/512 request authentication",
        location: "src/plugins/hmac_auth.rs",
        implementation: "crate::fips::approved (module-backed HMAC-SHA-256/512)",
        disposition: Disposition::ModuleRoutable,
        rationale: "migrated off RustCrypto hmac/sha2 onto fips::approved; the request body digest \
                    (`Digest`/`Content-Digest`) uses the same module-backed SHA-2",
    },
    CryptoOperation {
        operation: "Password verification (basic auth) and LDAP bind-cache keying",
        location: "src/plugins/basic_auth.rs, src/plugins/ldap_auth.rs",
        implementation: "crate::fips::approved (module-backed HMAC-SHA-256)",
        disposition: Disposition::ModuleRoutable,
        rationale: "Ferrum's only stored-password representation is `hmac_sha256:<hex>`, an \
                    approved keyed MAC, now computed by the module. The unreferenced `argon2` \
                    dependency was removed rather than policy-gated, so no non-approved KDF is \
                    linked; fips::policy additionally refuses any unclassified stored-hash form",
    },
    CryptoOperation {
        operation: "DPoP proof and client-certificate thumbprints",
        location: "src/plugins/utils/dpop.rs, src/plugins/utils/cert_hash.rs, \
                   src/plugins/mtls_auth.rs",
        implementation: "crate::fips::approved (module-backed SHA-256)",
        disposition: Disposition::ModuleRoutable,
        rationale: "migrated off RustCrypto sha2 onto fips::approved",
    },
    CryptoOperation {
        operation: "HMAC-SHA256 frame-log redaction keying",
        location: "src/plugins/ws_frame_logging.rs",
        implementation: "ring / aws-lc-rs via crate::fips::backend",
        disposition: Disposition::ModuleRoutable,
        rationale: "routed through the backend alias",
    },
    CryptoOperation {
        operation: "Security-relevant random values (nonces, state, salts, IDs)",
        location: "src/plugins/oidc_relying_party.rs, src/plugins/utils/ai_pii.rs, \
                   src/plugins/ldap_auth.rs, src/identity/ca/, src/modes/node_agent_cni_server.rs",
        implementation: "ring / aws-lc-rs via crate::fips::backend",
        disposition: Disposition::ModuleRoutable,
        rationale: "routed through the backend alias; the module supplies an approved DRBG",
    },
    CryptoOperation {
        operation: "Retry/backoff jitter",
        location: "src/util/backoff.rs",
        implementation: "ring / aws-lc-rs via crate::fips::backend",
        disposition: Disposition::OutsideBoundary,
        rationale: "scheduling jitter is not a security service; routed through the backend alias \
                    anyway so no second RNG is linked",
    },
    // ── Certificates ────────────────────────────────────────────────────
    CryptoOperation {
        operation: "X.509 parsing, expiry, SAN and trust-chain checks",
        location: "src/tls/mod.rs, src/identity/",
        implementation: "x509-parser, rustls-webpki",
        disposition: Disposition::ModuleRoutable,
        rationale: "chain-building signature verification runs in the rustls provider; structural \
                    DER parsing performs no cryptography",
    },
    CryptoOperation {
        operation: "Certificate and CSR generation (internal CA, dev bootstrap)",
        location: "src/identity/ca/internal.rs, src/identity/ca/bootstrap.rs",
        implementation: "rcgen",
        disposition: Disposition::ModuleRoutable,
        rationale: "the `fips` feature selects rcgen/fips and excludes rcgen/ring",
    },
    CryptoOperation {
        operation: "ACME (RFC 8555) account keys, CSR signing, directory TLS",
        location: "src/tls/acme.rs",
        implementation: "instant-acme, hyper-rustls, rcgen, crate::fips::approved",
        disposition: Disposition::ModuleRoutable,
        rationale: "the `fips` feature selects instant-acme/fips and hyper-rustls/fips; the \
                    key-authorization digest is module-backed SHA-256",
    },
    // ── PKCS#11 ─────────────────────────────────────────────────────────
    CryptoOperation {
        operation: "PKCS#11 private-key operations (HSM-held keys)",
        location: "src/tls/pkcs11.rs",
        implementation: "cryptoki + operator-supplied PKCS#11 module",
        disposition: Disposition::OutsideBoundary,
        rationale: "signing happens inside the operator's token, which must carry its own \
                    validation; Ferrum's local randomness and RSA verification on this path use \
                    crate::fips::backend",
    },
    // ── Secrets ─────────────────────────────────────────────────────────
    CryptoOperation {
        operation: "External secret provider transport (Vault, AWS, Azure, GCP)",
        location: "src/secrets/",
        implementation: "provider SDKs over their own TLS stacks",
        disposition: Disposition::OutsideBoundary,
        rationale: "the SDK TLS stacks are not routed through Ferrum's provider; secrets resolve \
                    once at startup, before the gateway serves, and the remote KMS/HSM carries \
                    its own validation. Documented in docs/fips.md as an operator control, not a \
                    Ferrum claim",
    },
    // ── Non-approved sinks ──────────────────────────────────────────────
    CryptoOperation {
        operation: "Kafka log sink TLS",
        location: "src/plugins/kafka_logging.rs",
        implementation: "rdkafka / librdkafka / OpenSSL",
        disposition: Disposition::Rejected,
        rationale: "fips::policy::NON_APPROVED_PLUGINS refuses the plugin at config admission",
    },
    // ── Not a security service ──────────────────────────────────────────
    CryptoOperation {
        operation: "Non-security SHA-256 digests (cache keys, deduplication \
                    keys, ETags, config/policy drift digests, xDS nonces, spec \
                    codec identities, statsd/chargeback row identities)",
        location: "src/plugins/response_caching.rs, src/plugins/request_deduplication.rs, \
                   src/plugins/utils/policy_digest.rs, src/xds/, src/admin/spec_codec.rs, \
                   src/tls/inventory.rs, src/tls/events.rs (33 modules)",
        implementation: "RustCrypto sha2",
        disposition: Disposition::OutsideBoundary,
        rationale: "these digests carry no key, protect no secret, and authenticate nothing: they \
                    are content-addressing and change-detection identities over data that was \
                    already admitted and, where applicable, already cryptographically verified. \
                    Forging one causes a cache or rebuild decision, not an authentication or \
                    confidentiality failure, so relabelling them approved would be the exact \
                    'uses a FIPS-capable library' claim this table exists to refuse. The \
                    security-relevant digests and MACs were migrated to crate::fips::approved \
                    instead",
    },
    CryptoOperation {
        operation: "X.509 / PKCS#10 signature verification helper (proof-of-possession)",
        location: "src/identity/ca/",
        implementation: "x509-parser",
        disposition: Disposition::ModuleRoutable,
        rationale: "the `fips` feature selects x509-parser/verify-aws (aws-lc-rs) and excludes \
                    x509-parser/verify (ring); both gate the same public API",
    },
    CryptoOperation {
        operation: "SOAP WS-Security XML-DSig with rsa-sha1 / sha1 selections",
        location: "src/plugins/soap_ws_security.rs",
        implementation: "crate::fips::backend signature + digest",
        disposition: Disposition::Rejected,
        rationale: "SHA-1 is disallowed for signature generation and verification (SP 800-131A \
                    Rev. 2); fips::policy::NON_APPROVED_ALGORITHM_SELECTIONS refuses the \
                    configuration at admission. The rsa-sha256 / sha256 selections on the same \
                    plugin are module-routed through crate::fips::backend",
    },
    CryptoOperation {
        operation: "WebSocket Sec-WebSocket-Accept SHA-1 digest",
        location: "vendor/tungstenite (RFC 6455 handshake)",
        implementation: "sha1",
        disposition: Disposition::OutsideBoundary,
        rationale: "RFC 6455 defines this as a cache-poisoning guard over a fixed public GUID, \
                    not a security mechanism; it protects nothing and carries no key",
    },
];

/// Rows whose disposition is [`Disposition::Rejected`].
pub fn rejected() -> impl Iterator<Item = &'static CryptoOperation> {
    INVENTORY
        .iter()
        .filter(|entry| entry.disposition == Disposition::Rejected)
}

/// Rows that are security-relevant but not yet routed through the seam.
///
/// This must be **empty**. It is queryable precisely so a test can assert that:
/// a non-empty register means Ferrum is claiming a crypto surface it has not
/// actually routed, which is the failure mode this whole module exists to
/// prevent. The variant is retained so a newly discovered surface has an honest
/// place to land while it is being routed or rejected.
pub fn pending_classification() -> impl Iterator<Item = &'static CryptoOperation> {
    INVENTORY
        .iter()
        .filter(|entry| entry.disposition == Disposition::PendingClassification)
}
