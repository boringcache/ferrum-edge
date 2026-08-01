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
//! the operation resolves its implementation through Ferrum's single provider
//! seam ([`crate::fips::base_crypto_provider`] / [`crate::fips::backend`]),
//! through a dependency crypto backend selected at build time, or through the
//! process-default rustls provider that
//! [`crate::fips::install_crypto_provider`] installed. It therefore *will*
//! reach the validated module on a build that links one. It does **not** assert
//! that it reaches one today: [`crate::fips::BUILD_CAPABLE`] is `false` in this
//! build, so every routable entry currently resolves to `ring`.
//!
//! The other dispositions are the honest remainder:
//! [`Disposition::PendingClassification`] (security-relevant, not yet routed
//! through the seam — the work register), [`Disposition::Rejected`] (refused by
//! [`crate::fips::policy`]), and [`Disposition::OutsideBoundary`] (not
//! cryptography Ferrum is claiming, and documented as such).
//!
//! `tests/unit/tls/fips_inventory_tests.rs` asserts the invariants that keep
//! this table honest: every entry carries a non-empty rationale, and the set of
//! rejected plugins agrees with [`crate::fips::policy::NON_APPROVED_PLUGINS`].

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
        rationale: "quinn derives initial keys from the supplied rustls config's own provider, \
                    which is fips::base_crypto_provider(); the TLS 1.3 suite fallback now also \
                    resolves against that provider. Selecting quinn's rustls-aws-lc-rs-fips \
                    backend is docs/fips.md residual item 1",
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
        rationale: "tonic resolves CryptoProvider::get_default() first, which \
                    fips::install_crypto_provider() sets. Selecting tonic/tls-aws-lc so no ring \
                    fallback arm is compiled is docs/fips.md residual item 1",
    },
    CryptoOperation {
        operation: "CP/DP gRPC bearer-token HS256 signing and verification",
        location: "src/grpc/auth.rs",
        implementation: "jsonwebtoken (rust_crypto backend)",
        disposition: Disposition::PendingClassification,
        rationale: "requires jsonwebtoken/aws_lc_rs; docs/fips.md residual item 1. Key length is \
                    already floored by fips::policy::check_env_config",
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
        disposition: Disposition::PendingClassification,
        rationale: "sqlx-core prefers ring whenever its ring feature is compiled, so this needs \
                    the mutually exclusive crypto-ring/fips split; docs/fips.md residual item 1",
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
        implementation: "jsonwebtoken (rust_crypto backend)",
        disposition: Disposition::PendingClassification,
        rationale: "requires jsonwebtoken/aws_lc_rs; docs/fips.md residual item 1",
    },
    CryptoOperation {
        operation: "Request-path JWT and JWKS verification (plugins)",
        location: "src/plugins/jwt_auth.rs, src/plugins/jwks_auth.rs",
        implementation: "jsonwebtoken (rust_crypto backend)",
        disposition: Disposition::PendingClassification,
        rationale: "algorithms are already screened against \
                    fips::policy::APPROVED_JWT_ALGORITHMS at config admission; the implementation \
                    still needs jsonwebtoken/aws_lc_rs (docs/fips.md residual item 1)",
    },
    // ── Hash / MAC / randomness ─────────────────────────────────────────
    CryptoOperation {
        operation: "HMAC-SHA256/512 request authentication",
        location: "src/plugins/hmac_auth.rs",
        implementation: "RustCrypto hmac + sha2 (not routed through the seam)",
        disposition: Disposition::PendingClassification,
        rationale: "must move onto the module or be rejected; docs/fips.md residual item 2",
    },
    CryptoOperation {
        operation: "Password verification (basic auth, LDAP bind caching)",
        location: "src/plugins/basic_auth.rs, src/plugins/ldap_auth.rs",
        implementation: "argon2, RustCrypto sha2",
        disposition: Disposition::PendingClassification,
        rationale: "Argon2 is not an SP 800-132 approved KDF; must be classified and either \
                    rejected or replaced with PBKDF2 in FIPS mode; docs/fips.md residual item 2",
    },
    CryptoOperation {
        operation: "DPoP proof and client-certificate thumbprints",
        location: "src/plugins/utils/dpop.rs, src/plugins/utils/cert_hash.rs, \
                   src/plugins/mtls_auth.rs",
        implementation: "RustCrypto sha2",
        disposition: Disposition::PendingClassification,
        rationale: "security-relevant digests; docs/fips.md residual item 2",
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
                    DER parsing performs no cryptography. x509-parser's own `verify` feature \
                    needs the `verify-aws` counterpart (docs/fips.md residual item 1)",
    },
    CryptoOperation {
        operation: "Certificate and CSR generation (internal CA, dev bootstrap)",
        location: "src/identity/ca/internal.rs, src/identity/ca/bootstrap.rs",
        implementation: "rcgen",
        disposition: Disposition::PendingClassification,
        rationale: "requires rcgen/fips; docs/fips.md residual item 1",
    },
    CryptoOperation {
        operation: "ACME (RFC 8555) account keys, CSR signing, directory TLS",
        location: "src/tls/acme.rs",
        implementation: "instant-acme, hyper-rustls, rcgen",
        disposition: Disposition::PendingClassification,
        rationale: "requires instant-acme/fips and hyper-rustls/fips; docs/fips.md residual item 1",
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
/// This is the work register for `docs/fips.md` §"Residual work"; it is
/// deliberately queryable so a test can assert the list has not silently grown.
pub fn pending_classification() -> impl Iterator<Item = &'static CryptoOperation> {
    INVENTORY
        .iter()
        .filter(|entry| entry.disposition == Disposition::PendingClassification)
}
