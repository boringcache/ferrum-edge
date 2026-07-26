//! Content-derived digests for response-side *presentation* policy provenance.
//!
//! A plugin that persists a finalized client representation for later replay
//! (`request_deduplication` writing to Redis) must be able to prove, in a
//! different process and after arbitrary config reloads, that the retained
//! bytes are still compatible with every response-side presentation policy the
//! replay path deliberately skips. Pointer identities and generation counters
//! cannot answer that question across a process boundary, so the answer has to
//! be a digest of the policy's *content*.
//!
//! Two properties make these digests usable as security provenance:
//!
//! - **Stable.** Equivalent configuration digests identically in every process.
//!   JSON object keys are hashed in sorted order and every variable-length
//!   field is length-framed, so neither `HashMap`/`Map` iteration order nor an
//!   ambiguous concatenation can change the result.
//! - **Opaque.** Only the fixed-size SHA-256 output ever leaves this module.
//!   Configuration values — which may include operator-authored header values —
//!   are never serialized, logged, or persisted.
//!
//! Both helpers run on cold paths only (plugin construction and plugin-cache
//! rebuild), never per request.

use serde_json::Value;
use sha2::{Digest, Sha256};

/// Type tags keeping distinct JSON shapes from digesting to the same bytes
/// (for example the string `"1"` and the number `1`).
const TAG_NULL: u8 = 0;
const TAG_BOOL: u8 = 1;
const TAG_NUMBER: u8 = 2;
const TAG_STRING: u8 = 3;
const TAG_ARRAY: u8 = 4;
const TAG_OBJECT: u8 = 5;
const TAG_OBJECT_KEY: u8 = 6;

/// Domain separator for the per-proxy fold below.
const PRESENTATION_POLICY_DOMAIN: &[u8] = b"ferrum.response-presentation-policy.v1";

/// Digest one plugin's static configuration under a caller-supplied domain
/// separator.
///
/// `domain` must uniquely identify the plugin and the digest's schema version,
/// so two plugins that happen to accept the same configuration shape never
/// produce interchangeable provenance, and a future change to what a plugin
/// digests invalidates prior persisted representations instead of silently
/// matching them.
pub fn static_config_digest(domain: &str, config: &Value) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update((domain.len() as u64).to_be_bytes());
    hasher.update(domain.as_bytes());
    hash_canonical_value(&mut hasher, config);
    hasher.finalize().into()
}

/// Fold every enrolled plugin instance's static digest, **in configured
/// execution order**, into one per-proxy presentation-policy digest.
///
/// Order is part of the identity: response header/body rules are not
/// commutative, so the same instances reordered produce a different
/// client-visible representation and must not share provenance. The plugin
/// name is hashed alongside each digest so two different plugin types can
/// never swap contributions unnoticed. An empty iterator yields the
/// well-defined "no presentation policy" digest rather than a sentinel, so the
/// absence of transformers is itself a policy that a stored representation is
/// bound to.
pub fn presentation_policy_digest<'a>(
    contributions: impl IntoIterator<Item = (&'a str, [u8; 32])>,
) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(PRESENTATION_POLICY_DOMAIN);
    let mut count: u64 = 0;
    for (plugin_name, digest) in contributions {
        count = count.saturating_add(1);
        hasher.update((plugin_name.len() as u64).to_be_bytes());
        hasher.update(plugin_name.as_bytes());
        hasher.update(digest);
    }
    hasher.update(count.to_be_bytes());
    hasher.finalize().into()
}

/// Hash a JSON value canonically.
///
/// Recursion depth is bounded by `serde_json`'s own parser recursion limit
/// (configuration only ever reaches this function after `serde_json` accepted
/// it), so this cannot be driven to a stack overflow by hostile config.
fn hash_canonical_value(hasher: &mut Sha256, value: &Value) {
    match value {
        Value::Null => hasher.update([TAG_NULL]),
        Value::Bool(flag) => {
            hasher.update([TAG_BOOL]);
            hasher.update([u8::from(*flag)]);
        }
        Value::Number(number) => {
            // `to_string` is the canonical textual form serde_json would emit,
            // so an integer/float distinction survives the digest.
            let rendered = number.to_string();
            hasher.update([TAG_NUMBER]);
            hasher.update((rendered.len() as u64).to_be_bytes());
            hasher.update(rendered.as_bytes());
        }
        Value::String(text) => {
            hasher.update([TAG_STRING]);
            hasher.update((text.len() as u64).to_be_bytes());
            hasher.update(text.as_bytes());
        }
        Value::Array(items) => {
            hasher.update([TAG_ARRAY]);
            hasher.update((items.len() as u64).to_be_bytes());
            for item in items {
                hash_canonical_value(hasher, item);
            }
        }
        Value::Object(map) => {
            hasher.update([TAG_OBJECT]);
            hasher.update((map.len() as u64).to_be_bytes());
            // Sorted so the digest does not depend on `serde_json`'s map
            // representation (BTreeMap today, insertion-ordered under the
            // `preserve_order` feature) or on the order an operator happened to
            // write the keys in.
            let mut keys: Vec<&str> = map.keys().map(String::as_str).collect();
            keys.sort_unstable();
            for key in keys {
                hasher.update([TAG_OBJECT_KEY]);
                hasher.update((key.len() as u64).to_be_bytes());
                hasher.update(key.as_bytes());
                match map.get(key) {
                    Some(child) => hash_canonical_value(hasher, child),
                    // Unreachable: `keys` comes from `map`. Hashing an explicit
                    // null keeps the framing well defined without a panic on
                    // the cold construction path.
                    None => hasher.update([TAG_NULL]),
                }
            }
        }
    }
}
