//! One fail-closed replay-partition contract for every plugin that can return a
//! retained result before the backend evaluates the current request.
//!
//! `response_caching`, `request_deduplication`, and `ai_semantic_cache` all
//! short-circuit a request with bytes produced for an *earlier* request. That is
//! only sound while the two requests provably share every backend-visible
//! dimension the origin could have used to decide what to return:
//!
//! * **Caller authorization** — not a display subject. Two credentials can carry
//!   the same `sub` with different scopes, audiences, or tenancy claims, so the
//!   partition binds a digest of the actual credential material presented on
//!   this request together with the mechanism that accepted it.
//! * **Canonical caller context** — an anonymous caller is bound to the
//!   gateway-resolved peer address, because Ferrum regenerates
//!   `X-Forwarded-For` on every outbound HTTP request and the origin therefore
//!   observes it. Operators whose origins provably ignore caller address may
//!   opt one plugin instance out with [`AnonymousCallerScope::Shared`].
//! * **Effective destination** — the post-routing upstream / host / port /
//!   scheme / authority and rewritten path, not the originally matched proxy.
//!
//! Every component is serialized with typed, length-framed fields
//! ([`PartitionHasher`]) so no attacker-controlled byte can impersonate a field
//! boundary. Raw delimiter concatenation (`a:b|c=d`) is structurally unsafe:
//! distinct requests can serialize to identical preimages without breaking
//! SHA-256.
//!
//! Nothing here is ever logged. The returned values are opaque digests; the
//! inputs are credentials, identities, and addresses.

use std::collections::HashMap;
use std::net::IpAddr;

use sha2::{Digest, Sha256};

use crate::plugins::RequestContext;

/// Request headers that carry caller authorization context.
///
/// Two requests whose credential material differs are *different callers* even
/// when the gateway resolves them to the same display subject. Only SHA-256
/// digests of these values ever enter a partition.
pub const CREDENTIAL_CONTEXT_HEADERS: &[&str] = &[
    "api-key",
    "apikey",
    "authorization",
    "cookie",
    "proxy-authorization",
    "x-access-token",
    "x-amz-security-token",
    "x-api-key",
    "x-auth-token",
    "x-forwarded-authorization",
    "x-goog-api-key",
];

/// Case-insensitive membership test for [`CREDENTIAL_CONTEXT_HEADERS`].
pub fn is_credential_context_header(name: &str) -> bool {
    CREDENTIAL_CONTEXT_HEADERS
        .iter()
        .any(|candidate| name.eq_ignore_ascii_case(candidate))
}

/// How an *anonymous* caller (no gateway identity, no credential header, no
/// peer SPIFFE identity) is partitioned.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AnonymousCallerScope {
    /// Default. Bind the retained result to the gateway-resolved canonical peer
    /// address, which the origin observes through Ferrum's regenerated
    /// `X-Forwarded-For`. A request whose canonical address cannot be derived
    /// is refused rather than partitioned incompletely.
    CallerAddress,
    /// Operator attestation that the origin does not vary its response by
    /// caller address for this route, so anonymous callers may share one
    /// retained result. This deliberately re-opens cross-caller replay for
    /// address-sensitive origins and must only be set when that is known-safe.
    Shared,
}

impl AnonymousCallerScope {
    /// Parse the shared `anonymous_caller_scope` configuration value.
    pub fn parse(plugin: &str, value: &str) -> Result<Self, String> {
        match value.trim().to_ascii_lowercase().as_str() {
            "caller_address" | "caller-address" => Ok(Self::CallerAddress),
            "shared" => Ok(Self::Shared),
            other => Err(format!(
                "{plugin}: unknown 'anonymous_caller_scope' value '{other}' \
                 (expected caller_address or shared)"
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::CallerAddress => "caller_address",
            Self::Shared => "shared",
        }
    }
}

impl Default for AnonymousCallerScope {
    fn default() -> Self {
        Self::CallerAddress
    }
}

/// Why a complete, stable replay partition could not be derived.
///
/// Every variant is terminal for the request: the plugin must fall through to
/// the origin without looking up, storing, or deduplicating. The strings are
/// static and content-free so they are safe to emit in a debug line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PartitionRefusal {
    /// The caller is anonymous and the canonical peer address could not be
    /// parsed, so the caller dimension the origin observes cannot be bound.
    AnonymousCallerAddressUnavailable,
}

impl PartitionRefusal {
    /// Content-free operator-facing reason. Never includes key, caller, or
    /// credential material.
    pub fn reason(self) -> &'static str {
        match self {
            Self::AnonymousCallerAddressUnavailable => {
                "anonymous caller has no canonical peer address to bind"
            }
        }
    }
}

/// Domain-separated, length-framed hasher for replay-partition keys.
///
/// Every write is `len(label) || label || len(value) || value` with 64-bit
/// big-endian lengths, so no field content can forge a field boundary, an empty
/// field is distinct from an absent one, and a sequence is bound to its own
/// element count.
pub struct PartitionHasher {
    hasher: Sha256,
}

impl PartitionHasher {
    /// Start a partition under an explicit domain-separation tag. Two plugins
    /// (or two key roles inside one plugin) must never share a tag.
    pub fn new(domain: &str) -> Self {
        let mut hasher = Sha256::new();
        hasher.update((domain.len() as u64).to_be_bytes());
        hasher.update(domain.as_bytes());
        Self { hasher }
    }

    /// Append one length-framed labeled field.
    pub fn field(&mut self, label: &str, value: &[u8]) {
        self.hasher.update((label.len() as u64).to_be_bytes());
        self.hasher.update(label.as_bytes());
        self.hasher.update((value.len() as u64).to_be_bytes());
        self.hasher.update(value);
    }

    pub fn text(&mut self, label: &str, value: &str) {
        self.field(label, value.as_bytes());
    }

    /// Append an optional field. Presence is framed separately from the value,
    /// so an absent field can never be confused with a present empty one.
    pub fn optional_text(&mut self, label: &str, value: Option<&str>) {
        match value {
            Some(value) => {
                self.field(label, &[1u8]);
                self.field(label, value.as_bytes());
            }
            None => self.field(label, &[0u8]),
        }
    }

    pub fn bool_value(&mut self, label: &str, value: bool) {
        self.field(label, &[u8::from(value)]);
    }

    pub fn u64_value(&mut self, label: &str, value: u64) {
        self.field(label, &value.to_be_bytes());
    }

    /// Bind the element count of a sequence before its members are appended.
    pub fn count(&mut self, label: &str, count: usize) {
        self.u64_value(label, count as u64);
    }

    /// Append a nested partition digest as one opaque field.
    pub fn nested(&mut self, label: &str, digest: &[u8; 32]) {
        self.field(label, digest);
    }

    pub fn digest(self) -> [u8; 32] {
        self.hasher.finalize().into()
    }

    pub fn hex(self) -> String {
        hex::encode(self.digest())
    }
}

/// SHA-256 of one value, used for credential material that must never appear in
/// a key, a log line, or `RequestContext::metadata`.
pub fn value_digest(value: &str) -> [u8; 32] {
    Sha256::digest(value.as_bytes()).into()
}

/// Append the caller-authorization dimension of the replay partition.
///
/// Authenticated callers are bound to a *context* fingerprint — mechanism,
/// resolved identity, consumer, peer SPIFFE identity, and a digest of every
/// credential header actually presented — rather than to a display subject, so
/// two tokens with the same `sub` and different scopes never share a retained
/// result. Anonymous callers are bound per [`AnonymousCallerScope`].
///
/// `request_headers` must be the same header view the plugin will use for the
/// rest of the key (the `before_proxy` `headers` parameter, or a restored
/// snapshot of it), never a stale `ctx.headers` alone.
pub fn append_caller_partition(
    hasher: &mut PartitionHasher,
    ctx: &RequestContext,
    request_headers: &HashMap<String, String>,
    anonymous_scope: AnonymousCallerScope,
) -> Result<(), PartitionRefusal> {
    // Credential material present on this request, canonicalized to a lowercase
    // name and reduced to a digest. `Vec` with a small capacity rather than a
    // map: the candidate set is a fixed 11 names and most requests carry none.
    //
    // Hot path: one hash lookup per candidate. Protocol header maps are already
    // lowercase, so the case-insensitive sweep below is gated on a name
    // actually carrying an uppercase byte (only plugin-synthesised keys do) and
    // never scans the map for an ordinary request.
    let mut credentials: Vec<(&'static str, [u8; 32])> = Vec::new();
    for candidate in CREDENTIAL_CONTEXT_HEADERS {
        if let Some(value) = request_headers.get(*candidate) {
            credentials.push((*candidate, value_digest(value)));
        }
    }
    if request_headers
        .keys()
        .any(|name| name.bytes().any(|byte| byte.is_ascii_uppercase()))
    {
        for (name, value) in request_headers {
            if !name.bytes().any(|byte| byte.is_ascii_uppercase()) {
                continue;
            }
            let Some(canonical) = CREDENTIAL_CONTEXT_HEADERS
                .iter()
                .copied()
                .find(|candidate| name.eq_ignore_ascii_case(candidate))
            else {
                continue;
            };
            if !credentials.iter().any(|(known, _)| *known == canonical) {
                credentials.push((canonical, value_digest(value)));
            }
        }
        // `CREDENTIAL_CONTEXT_HEADERS` is sorted, so the loop above is the only
        // thing that can disturb order. Restore it so the digest is stable.
        credentials.sort_by(|left, right| left.0.cmp(right.0).then(left.1.cmp(&right.1)));
    }

    let identity = ctx.effective_identity();
    let peer_spiffe_id = ctx.peer_spiffe_id.as_ref().map(|id| id.as_str());
    let authenticated =
        identity.is_some() || peer_spiffe_id.is_some() || !credentials.is_empty();

    hasher.text(
        "caller.class",
        if authenticated {
            "authenticated"
        } else {
            "anonymous"
        },
    );
    hasher.optional_text("caller.auth_method", ctx.auth_method);
    hasher.optional_text("caller.identity", identity);
    hasher.optional_text(
        "caller.consumer_id",
        ctx.identified_consumer.as_ref().map(|c| c.id.as_str()),
    );
    hasher.optional_text(
        "caller.identity_header",
        ctx.authenticated_identity_header.as_deref(),
    );
    hasher.optional_text("caller.peer_spiffe_id", peer_spiffe_id);
    hasher.count("caller.credentials", credentials.len());
    for (name, digest) in &credentials {
        hasher.text("caller.credential_name", name);
        hasher.nested("caller.credential_digest", digest);
    }

    if authenticated {
        // An authenticated caller's partition is its authorization context; the
        // peer address adds nothing the origin can key on beyond it.
        hasher.text("caller.address_scope", "authenticated");
        return Ok(());
    }

    match anonymous_scope {
        AnonymousCallerScope::Shared => {
            hasher.text("caller.address_scope", "shared");
            Ok(())
        }
        AnonymousCallerScope::CallerAddress => {
            let address = ctx
                .canonical_client_ip()
                .ok_or(PartitionRefusal::AnonymousCallerAddressUnavailable)?;
            hasher.text("caller.address_scope", "caller_address");
            // Hash the raw octets: no `format!` on the request path, and the
            // family tag keeps a v4-mapped v6 address distinct from its v4 form.
            match address {
                IpAddr::V4(v4) => hasher.field("caller.address_v4", &v4.octets()),
                IpAddr::V6(v6) => hasher.field("caller.address_v6", &v6.octets()),
            }
            Ok(())
        }
    }
}

/// Append the effective destination dimension: the route/provider the *current*
/// request would reach, after every route-dispatch plugin has run.
///
/// Callers must invoke this only once route selection is final for the request
/// (or once they have refused composition with anything that could still change
/// it). Proxy *absence* is framed explicitly rather than defaulted to a sentinel,
/// so an unmatched request can never share a partition with a matched one.
pub fn append_destination_partition(hasher: &mut PartitionHasher, ctx: &RequestContext) {
    let Some(proxy) = ctx.matched_proxy.as_ref() else {
        hasher.bool_value("dst.matched_proxy", false);
        return;
    };
    hasher.bool_value("dst.matched_proxy", true);

    hasher.text("dst.proxy_id", &proxy.id);
    hasher.text("dst.proxy_namespace", &proxy.namespace);
    hasher.optional_text("dst.listen_path", proxy.listen_path.as_deref());

    match ctx.effective_upstream_id(proxy) {
        Some(upstream_id) => {
            hasher.text("dst.kind", "upstream");
            hasher.text("dst.upstream_id", upstream_id);
        }
        None => {
            hasher.text("dst.kind", "direct");
            hasher.text("dst.backend_host", ctx.effective_backend_host(proxy));
            hasher.u64_value("dst.backend_port", u64::from(ctx.effective_backend_port(proxy)));
            let scheme = ctx
                .route_override_backend_scheme
                .or(proxy.backend_scheme)
                .map(|scheme| scheme.to_scheme_str());
            hasher.optional_text("dst.backend_scheme", scheme);
        }
    }

    hasher.optional_text("dst.authority", ctx.route_override_authority.as_deref());
    hasher.optional_text("dst.rewrite_path", ctx.route_override_path.as_deref());
    hasher.bool_value(
        "dst.rewrite_path_is_absolute",
        ctx.route_override_path_is_absolute,
    );
}
