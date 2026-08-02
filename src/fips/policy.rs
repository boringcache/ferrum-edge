//! Fail-closed FIPS admission policy.
//!
//! One policy, evaluated identically at every admission point:
//!
//! | Surface | Entry point |
//! |---|---|
//! | `ferrum-edge validate` | [`check_env_config`] + [`check_gateway_config`] |
//! | bootstrap / startup | [`check_env_config`] + [`check_gateway_config`] |
//! | file-mode SIGHUP reload | [`check_gateway_config`] |
//! | database poll apply | [`check_gateway_config`] |
//! | CP publication / DP apply | [`check_gateway_config`] |
//! | CP/DP namespace trust-bundle load | [`is_approved_jwt_algorithm`] |
//! | rustls policy construction | [`check_tls_policy`] |
//!
//! Every diagnostic is bounded: it names the setting, states the rule, and — for
//! collection-valued settings — reports at most [`MAX_REPORTED_VIOLATIONS`]
//! offending entries followed by a count. Operator-supplied values are echoed
//! only where they are already a fixed, non-secret vocabulary (algorithm names,
//! cipher-suite names, plugin names); secrets, key material, paths, and free-form
//! configuration are never interpolated.
//!
//! When FIPS mode is off every function here returns `Ok(())` without inspecting
//! anything, so ordinary deployments are behaviourally unchanged.

use std::fmt::Write as _;

use crate::config::env_config::EnvConfig;
use crate::config::types::{GatewayConfig, PluginConfig};

/// Maximum number of individual offending entries named in one diagnostic.
///
/// A hostile or merely large configuration must not be able to turn a startup
/// failure into an unbounded log record.
pub const MAX_REPORTED_VIOLATIONS: usize = 8;

/// JWT/JWS algorithms Ferrum admits while FIPS mode is enforced.
///
/// HMAC-SHA2 (FIPS 198-1), RSASSA-PKCS1-v1_5 and RSASSA-PSS with SHA-2, and
/// ECDSA over P-256/P-384/P-521 (FIPS 186-5). `none` is always rejected.
/// `EdDSA` is deliberately absent: Ed25519 is approved by FIPS 186-5, but it is
/// not part of the algorithm set Ferrum routes through the selected validated
/// module, so admitting it would be a claim this build cannot back.
pub const APPROVED_JWT_ALGORITHMS: &[&str] = &[
    "HS256", "HS384", "HS512", "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256",
    "ES384", "ES512",
];

/// Whether a configured JWS algorithm is in Ferrum's FIPS-approved set.
///
/// This helper is public because not every JWT admission surface lives inside
/// [`GatewayConfig`]. In particular, the CP/DP namespace trust bundle is an
/// environment-selected JSON document loaded directly by the control-plane
/// runtime and must apply the identical algorithm policy at its own parser.
pub fn is_approved_jwt_algorithm(algorithm: &str) -> bool {
    APPROVED_JWT_ALGORITHMS
        .iter()
        .any(|approved| approved.eq_ignore_ascii_case(algorithm.trim()))
}

/// Minimum HMAC key length, in bytes, for an approved JWT/JWS MAC key.
///
/// SP 800-107 requires an HMAC key at least as long as the security strength
/// being claimed. Ferrum already enforces 32 characters on admin and CP/DP JWT
/// secrets; FIPS mode applies that same floor to the operator-owned JWT and
/// stored-password MAC keys it admits at the environment boundary.
pub const MIN_HMAC_KEY_BYTES: usize = 32;

/// Plugins whose cryptography is provided by a library outside the selected
/// validated module's boundary, and which are therefore refused while FIPS mode
/// is enforced.
///
/// `kafka_logging` binds librdkafka, which performs its TLS through OpenSSL
/// rather than through the module Ferrum selected. Ferrum cannot attest to that
/// stack, so it refuses the plugin instead of implying coverage it does not
/// have. See `docs/fips.md` for the supported alternatives
/// (`tcp_logging`/`ws_logging`/`http_logging`, all of which are rustls-based
/// and therefore module-backed).
pub const NON_APPROVED_PLUGINS: &[&str] = &["kafka_logging"];

/// Algorithm selections a plugin may expose that name a non-approved primitive.
///
/// SHA-1 is not an approved hash for a digital signature or a signature-bearing
/// digest (SP 800-131A Rev. 2 disallowed it for signature generation and
/// verification). `soap_ws_security` lets an operator admit `rsa-sha1`
/// signatures and `sha1` reference digests for XML-DSig interoperability; both
/// are refused while FIPS mode is enforced rather than silently computed
/// outside the approved set. The values are Ferrum's own fixed configuration
/// vocabulary, so echoing them in a diagnostic discloses nothing.
const NON_APPROVED_ALGORITHM_SELECTIONS: &[(&str, &[&str], &[&str])] = &[(
    "soap_ws_security",
    &[
        "x509_signature.allowed_algorithms",
        "x509_signature.allowed_digest_algorithms",
        "saml.allowed_signature_algorithms",
        "saml.allowed_digest_algorithms",
    ],
    &["rsa-sha1", "sha1"],
)];

/// Approved stored-password representation.
///
/// Ferrum stores consumer Basic credentials as `hmac_sha256:<64 hex>` — an
/// HMAC-SHA-256 under an operator secret, which is an approved keyed MAC and,
/// since this change, computed by the selected module
/// ([`crate::fips::approved`]). Any other prefix would be a password KDF Ferrum
/// has not classified, so FIPS mode refuses it rather than assuming.
pub const APPROVED_PASSWORD_HASH_PREFIX: &str = "hmac_sha256:";

/// Render a bounded list of offending entries.
fn bounded_list(entries: &[String]) -> String {
    let mut out = String::new();
    for (index, entry) in entries.iter().take(MAX_REPORTED_VIOLATIONS).enumerate() {
        if index > 0 {
            out.push_str(", ");
        }
        out.push_str(entry);
    }
    if entries.len() > MAX_REPORTED_VIOLATIONS {
        let _ = write!(
            out,
            " (and {} more)",
            entries.len() - MAX_REPORTED_VIOLATIONS
        );
    }
    out
}

/// Validate process-level configuration against FIPS policy.
///
/// Returns the first violation. Callers surface it verbatim; it is already
/// bounded and secret-free.
pub fn check_env_config(env_config: &EnvConfig) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_env_config_enforced(env_config)
}

/// The enforced half of [`check_env_config`], with the mode gate removed.
///
/// Split out so the policy itself is directly testable on a build where
/// [`super::BUILD_CAPABLE`] is `false` and enforcement can therefore never be
/// established at runtime. Production callers use the gated wrapper.
pub fn check_env_config_enforced(env_config: &EnvConfig) -> Result<(), String> {
    // ── Provider pin ────────────────────────────────────────────────────
    // The operator names the integration they audited. Today exactly one is
    // supported; pinning it means a future build that changed integrations
    // cannot silently satisfy an existing FIPS deployment contract.
    let required = env_config.fips_required_provider.trim();
    if required != super::SUPPORTED_PROVIDER_ID {
        return Err(format!(
            "FERRUM_FIPS_REQUIRED_PROVIDER names a validated-module integration this build does \
             not provide. This build supports `{}` only.",
            super::SUPPORTED_PROVIDER_ID
        ));
    }

    // ── TLS versions ────────────────────────────────────────────────────
    // Ferrum already restricts both bounds to 1.2/1.3, and SP 800-52r2 permits
    // both. Re-assert here so a future widening of the ordinary vocabulary
    // cannot silently widen the FIPS one.
    for (name, value) in [
        (
            "FERRUM_TLS_MIN_VERSION",
            env_config.tls_min_version.as_str(),
        ),
        (
            "FERRUM_TLS_MAX_VERSION",
            env_config.tls_max_version.as_str(),
        ),
    ] {
        if !matches!(value, "1.2" | "1.3") {
            return Err(format!(
                "{name} must be `1.2` or `1.3` while FIPS mode is enforced; earlier TLS versions \
                 are outside the approved boundary."
            ));
        }
    }

    // ── Peer verification ───────────────────────────────────────────────
    // An unauthenticated peer defeats the point of an approved key exchange.
    if env_config.tls_no_verify {
        return Err(
            "FERRUM_TLS_NO_VERIFY=true disables backend server certificate verification and is \
             refused while FIPS mode is enforced."
                .to_string(),
        );
    }

    // ── Config-database TLS ─────────────────────────────────────────────
    // The SQL config store rides sqlx, whose rustls provider is selectable at
    // build time. The MongoDB driver instead pins `rustls/ring` in its own
    // manifest and can enable TLS from the connection URI independently of
    // FERRUM_DB_TLS_MODE (including implicitly for mongodb+srv). Ferrum cannot
    // exhaustively prove that every effective Mongo transport is plaintext, so
    // refuse the Mongo config store outright rather than admit a URI-controlled
    // non-validated TLS path. See docs/fips.md for supported config stores.
    if env_config
        .db_type
        .as_deref()
        .is_some_and(|db_type| db_type.eq_ignore_ascii_case("mongodb"))
    {
        return Err(
            "FERRUM_DB_TYPE=mongodb is refused while FIPS mode is enforced: the MongoDB driver \
             builds its TLS stack on its own bundled non-validated provider and connection-URI \
             options can enable that TLS path independently of FERRUM_DB_TLS_MODE. Ferrum cannot \
             route or exhaustively exclude that transport. Use a SQL config store \
             (postgres/mysql/sqlite), file mode, or CP/DP distribution. See docs/fips.md."
                .to_string(),
        );
    }

    // ── Admin and CP/DP JWT MAC keys ────────────────────────────────────
    for (name, secret) in [
        (
            "FERRUM_ADMIN_JWT_SECRET",
            env_config.admin_jwt_secret.as_deref(),
        ),
        (
            "FERRUM_CP_DP_GRPC_JWT_SECRET",
            env_config.cp_dp_grpc_jwt_secret.as_deref(),
        ),
        (
            "FERRUM_BASIC_AUTH_HMAC_SECRET",
            env_config.basic_auth_hmac_secret.as_deref(),
        ),
    ] {
        if let Some(secret) = secret.filter(|s| !s.is_empty())
            && secret.len() < MIN_HMAC_KEY_BYTES
        {
            // The length is a property of the secret, not the secret; it is the
            // only actionable fact and is already reported by the ordinary
            // (non-FIPS) validator for these same keys.
            return Err(format!(
                "{name} must be at least {MIN_HMAC_KEY_BYTES} bytes while FIPS mode is enforced \
                 (SP 800-107 HMAC key strength)."
            ));
        }
    }

    Ok(())
}

/// Validate a gateway configuration document against FIPS policy.
///
/// This is the shared admission gate for `validate`, startup, file-mode SIGHUP
/// reload, database poll application, CP publication, and DP snapshot/delta
/// application, so a configuration that could not start also cannot be
/// hot-loaded or distributed.
pub fn check_gateway_config(config: &GatewayConfig) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_gateway_config_enforced(config)
}

/// The enforced half of [`check_gateway_config`]. See
/// [`check_env_config_enforced`] for why the gate is split out.
pub fn check_gateway_config_enforced(config: &GatewayConfig) -> Result<(), String> {
    let mut non_approved_plugins: Vec<String> = Vec::new();
    let mut jwt_violations: Vec<String> = Vec::new();
    let mut algorithm_violations: Vec<String> = Vec::new();

    for plugin in &config.plugin_configs {
        if !plugin.enabled {
            continue;
        }
        if NON_APPROVED_PLUGINS.contains(&plugin.plugin_name.as_str()) {
            // The plugin name is a fixed Ferrum vocabulary entry, not operator
            // free text, so echoing it discloses nothing the operator did not
            // already write and is what makes the diagnostic actionable.
            non_approved_plugins.push(plugin.plugin_name.clone());
        }
        collect_jwt_algorithm_violations(plugin, &mut jwt_violations);
        collect_non_approved_algorithm_selections(plugin, &mut algorithm_violations);
    }

    // ── Stored password representation ──────────────────────────────────
    // Ordinary validation already pins the `hmac_sha256:` form, so this is a
    // fail-closed backstop rather than the primary gate: it is what refuses a
    // future stored-credential format that has not been classified against the
    // approved KDF/MAC set. No credential material is interpolated — only the
    // consumer count, which the operator already knows.
    let unclassified_hashes = config
        .consumers
        .iter()
        .filter(|consumer| {
            consumer.credentials.get("basic_auth").is_some_and(|value| {
                stored_password_hash_representations(value).any(|hash| match hash {
                    Some(hash) => !is_approved_password_hash(hash),
                    None => true,
                })
            })
        })
        .count();
    if unclassified_hashes > 0 {
        return Err(format!(
            "{unclassified_hashes} consumer(s) carry a stored password hash in a representation \
             Ferrum has not classified against the approved MAC/KDF set. FIPS mode admits only \
             `{APPROVED_PASSWORD_HASH_PREFIX}<64 lowercase hex>`. See docs/fips.md."
        ));
    }

    if !non_approved_plugins.is_empty() {
        non_approved_plugins.sort();
        non_approved_plugins.dedup();
        return Err(format!(
            "plugin(s) [{}] perform cryptography outside the selected validated module's boundary \
             and are refused while FIPS mode is enforced. See docs/fips.md for module-backed \
             alternatives.",
            bounded_list(&non_approved_plugins)
        ));
    }

    if !jwt_violations.is_empty() {
        jwt_violations.sort();
        jwt_violations.dedup();
        return Err(format!(
            "JWT/JWS algorithm(s) [{}] are not in the approved set while FIPS mode is enforced. \
             Approved: {}.",
            bounded_list(&jwt_violations),
            APPROVED_JWT_ALGORITHMS.join(", ")
        ));
    }

    if !algorithm_violations.is_empty() {
        algorithm_violations.sort();
        algorithm_violations.dedup();
        return Err(format!(
            "plugin algorithm selection(s) [{}] name a primitive that is not approved for \
             signature generation or verification and are refused while FIPS mode is enforced. \
             See docs/fips.md.",
            bounded_list(&algorithm_violations)
        ));
    }

    Ok(())
}

/// Stored password hashes carried by one credential value.
///
/// A credential is either a single object or an array of objects (multi-
/// credential rotation), so both shapes are walked. Only the `password_hash`
/// member is read and its representation is checked in place — the value
/// itself never leaves this function.
fn stored_password_hash_representations(
    value: &serde_json::Value,
) -> impl Iterator<Item = Option<&str>> {
    let entries: Vec<&serde_json::Value> = match value {
        serde_json::Value::Array(entries) => entries.iter().collect(),
        other => vec![other],
    };
    entries
        .into_iter()
        .map(|entry| {
            entry
                .get("password_hash")
                .and_then(serde_json::Value::as_str)
        })
        .collect::<Vec<_>>()
        .into_iter()
}

fn is_approved_password_hash(value: &str) -> bool {
    value
        .strip_prefix(APPROVED_PASSWORD_HASH_PREFIX)
        .is_some_and(|hex_hash| {
            hex_hash.len() == 64
                && hex_hash
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        })
}

/// Collect non-approved algorithm names a plugin's configuration selects.
///
/// The keys are dotted paths into the plugin's config object, matching the
/// spelling the plugin's own validator uses, so the diagnostic names the field
/// the operator must edit.
fn collect_non_approved_algorithm_selections(plugin: &PluginConfig, out: &mut Vec<String>) {
    for (plugin_name, keys, non_approved) in NON_APPROVED_ALGORITHM_SELECTIONS {
        if plugin.plugin_name != *plugin_name {
            continue;
        }
        for key in *keys {
            let Some(value) = lookup_dotted(&plugin.config, key) else {
                continue;
            };
            let serde_json::Value::Array(entries) = value else {
                continue;
            };
            for entry in entries {
                let Some(selected) = entry.as_str() else {
                    continue;
                };
                if non_approved
                    .iter()
                    .any(|name| name.eq_ignore_ascii_case(selected.trim()))
                {
                    out.push(format!("{plugin_name}.{key}={}", selected.trim()));
                }
            }
        }
    }
}

/// Resolve a dotted path through nested JSON objects.
fn lookup_dotted<'a>(root: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut current = root;
    for segment in path.split('.') {
        current = current.get(segment)?;
    }
    Some(current)
}

/// Collect non-approved JWT algorithm names from one plugin's configuration.
///
/// Ferrum's JWT-bearing plugins spell their accepted algorithms as either a
/// scalar `algorithm`/`alg` string or an `algorithms` array, depending on the
/// plugin. Both shapes are inspected; anything that is not a string is left to
/// the plugin's own schema validation rather than reported twice.
fn collect_jwt_algorithm_violations(plugin: &PluginConfig, out: &mut Vec<String>) {
    const ALGORITHM_KEYS: &[&str] = &["algorithm", "alg", "algorithms", "allowed_algorithms"];

    for key in ALGORITHM_KEYS {
        let Some(value) = plugin.config.get(*key) else {
            continue;
        };
        match value {
            serde_json::Value::String(alg) => push_if_not_approved(alg, out),
            serde_json::Value::Array(entries) => {
                for entry in entries {
                    if let serde_json::Value::String(alg) = entry {
                        push_if_not_approved(alg, out);
                    }
                }
            }
            _ => {}
        }
    }

    // OIDC RP and OAuth2 introspection can sign private_key_jwt client
    // assertions. Their algorithm selector is nested per provider rather than
    // at the plugin root, so inspect that production shape explicitly. EdDSA
    // is valid ordinary configuration but is outside the algorithm set routed
    // through the selected module and must fail FIPS admission.
    if matches!(
        plugin.plugin_name.as_str(),
        "oidc_relying_party" | "oauth2_introspection"
    ) && let Some(providers) = plugin
        .config
        .get("providers")
        .and_then(serde_json::Value::as_array)
    {
        for provider in providers {
            if let Some(algorithm) = provider
                .get("client_auth")
                .and_then(|value| value.get("private_key_jwt_alg"))
                .and_then(serde_json::Value::as_str)
            {
                push_if_not_approved(algorithm, out);
            }
        }
    }
}

fn push_if_not_approved(alg: &str, out: &mut Vec<String>) {
    let candidate = alg.trim();
    if candidate.is_empty() {
        return;
    }
    // Only JWS algorithm names are screened here. Plugins that reuse the
    // `algorithm` key for a non-JWS vocabulary (for example `hmac_auth`'s
    // `hmac-sha256`) name algorithms that are themselves approved and are
    // covered by their own admission checks; screening them against the JWS set
    // would produce a false rejection.
    if !looks_like_jws_algorithm(candidate) {
        return;
    }
    if !is_approved_jwt_algorithm(candidate) {
        out.push(candidate.to_ascii_uppercase());
    }
}

/// `true` when a value is spelled like an RFC 7518 `alg` header parameter.
///
/// Matches the registered families (`HS`/`RS`/`PS`/`ES`/`Ed`) and the
/// unauthenticated `none` sentinel, which must always be rejected.
fn looks_like_jws_algorithm(candidate: &str) -> bool {
    if candidate.eq_ignore_ascii_case("none") {
        return true;
    }
    let upper = candidate.to_ascii_uppercase();
    matches!(upper.as_str(), "EDDSA")
        || (upper.len() == 5
            && matches!(&upper[..2], "HS" | "RS" | "PS" | "ES")
            && upper[2..].chars().all(|c| c.is_ascii_digit()))
}

/// Validate a constructed rustls policy against FIPS policy.
///
/// This is the last gate before any listener or backend client is built. It
/// delegates the algorithm classification to rustls/AWS-LC rather than
/// re-deriving an allow-list, so Ferrum's notion of "approved" cannot drift from
/// the module's: `SupportedCipherSuite::fips()` and `SupportedKxGroup::fips()`
/// are `false` for every suite and group the module does not treat as approved,
/// including everything provided by a non-validated backend.
pub fn check_tls_policy(policy: &crate::tls::TlsPolicy) -> Result<(), String> {
    if !super::is_enforcing() {
        return Ok(());
    }
    check_tls_policy_enforced(policy)
}

/// The enforced half of [`check_tls_policy`]. See
/// [`check_env_config_enforced`] for why the gate is split out.
pub fn check_tls_policy_enforced(policy: &crate::tls::TlsPolicy) -> Result<(), String> {
    let provider = policy.crypto_provider.as_ref();

    let rejected_suites: Vec<String> = provider
        .cipher_suites
        .iter()
        .filter(|suite| !suite.fips())
        .map(|suite| format!("{:?}", suite.suite()))
        .collect();
    if !rejected_suites.is_empty() {
        return Err(format!(
            "cipher suite(s) [{}] are not FIPS-approved and are refused while FIPS mode is \
             enforced. Remove them from FERRUM_TLS_CIPHER_SUITES, or unset it to take the \
             approved defaults.",
            bounded_list(&rejected_suites)
        ));
    }

    let rejected_groups: Vec<String> = provider
        .kx_groups
        .iter()
        .filter(|group| !group.fips())
        .map(|group| format!("{:?}", group.name()))
        .collect();
    if !rejected_groups.is_empty() {
        return Err(format!(
            "key-exchange group(s) [{}] are not FIPS-approved and are refused while FIPS mode is \
             enforced. Remove them from FERRUM_TLS_KEY_EXCHANGE_GROUPS, or unset it to take the \
             approved defaults.",
            bounded_list(&rejected_groups)
        ));
    }

    // Belt-and-braces over the whole provider: this also covers the signature
    // verification algorithms, the secure random source, and the key provider,
    // none of which Ferrum lets the operator select but all of which would be
    // non-approved on a build whose crypto features drifted.
    if !provider.fips() {
        return Err(
            "the constructed rustls provider is not FIPS-approved. This indicates a build whose \
             crypto features do not match the FIPS profile documented in docs/fips.md."
                .to_string(),
        );
    }

    Ok(())
}

/// Approved-default cipher suites, expressed as protocol identifiers.
///
/// Used by `crate::tls` to seed the default suite list from whichever provider
/// this build links. ChaCha20-Poly1305 is absent: it is not an approved AEAD, so
/// including it in the FIPS defaults would make every FIPS startup fail on a
/// default configuration.
pub const FIPS_DEFAULT_CIPHER_SUITES: &[rustls::CipherSuite] = &[
    rustls::CipherSuite::TLS13_AES_128_GCM_SHA256,
    rustls::CipherSuite::TLS13_AES_256_GCM_SHA384,
    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
    rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
    rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
];

/// Approved-default key-exchange groups.
///
/// X25519 is absent: ECDH over Curve25519 is not an approved SP 800-56A scheme,
/// so it cannot be a FIPS default even though it is Ferrum's ordinary first
/// preference.
pub const FIPS_DEFAULT_KX_GROUPS: &[rustls::NamedGroup] =
    &[rustls::NamedGroup::secp256r1, rustls::NamedGroup::secp384r1];
