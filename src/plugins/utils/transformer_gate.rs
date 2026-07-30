//! Shared RTDS gate parsing for transformer plugins.
//!
//! `request_transformer` and `response_transformer` each maintain their
//! own gate map (different key prefix, independent state) but share the
//! same scan-and-collect logic over the [`MeshRuntimeOverlay`]. Keeping
//! the parser in one place avoids forking the
//! "strip prefix, strip suffix, accept bools only" recipe.
//!
//! Out-of-spec values (`Number`, `String`, `FractionalPercent`) are
//! silently skipped — gate semantics are strictly boolean.
//!
//! ## Generation binding (GHSA-83rc-23c9-3g9x)
//!
//! A transformer must never evaluate its gate against process-global state at
//! request time. Doing so made the gate and the rules two independently
//! published values: a plugin built from slice B could read slice A's gate
//! during the publication gap, an in-flight plugin from slice A could read
//! slice B's gate for the whole lifetime of a slow request, and one request
//! could observe *different* gate values at its buffering-preflight, header,
//! and body phases. Scope, rules, defaults, and gate then combined into states
//! that existed in neither accepted slice.
//!
//! The binding is therefore done on the cold path, exactly as
//! [`crate::plugins::fault_injection::runtime_overlay`] binds fault
//! percentages: [`materialize_resolved_gate`] folds the accepted overlay's gate
//! for a candidate instance's scope into that instance's own configuration
//! under [`RESOLVED_ENABLED_KEY`], and the resulting effective config is
//! validated, built into the candidate plugin cache, and published in the same
//! [`crate::request_epoch::RequestEpoch`] as the rules it gates. The plugin
//! then resolves one immutable decision at construction and every phase reads
//! that same field, so there is no request-time lookup to race and nothing for
//! a mid-request publication to move.

use std::collections::HashMap;

use serde_json::Value;

use crate::modes::mesh::config::{MeshRuntimeOverlay, RuntimeValue};

/// Reserved config key carrying the accepted overlay's gate for this instance's
/// scope, written by mesh preparation and consumed at plugin construction.
///
/// Absent means "the accepted overlay named no boolean for this scope", which
/// is what makes the plugin's `default_enabled` fallback apply. The key is
/// meaningless without `runtime_overlay_scope` and is removed when no scope is
/// configured, so it can never pin a gate on an instance that opted out.
pub const RESOLVED_ENABLED_KEY: &str = "runtime_overlay_resolved_enabled";

/// Walk every `<prefix><scope><suffix>` key in `overlay` and insert the
/// bool value into `dest`. Keys with empty scope or non-bool values are
/// dropped so the resulting map is always safe to consult directly.
pub fn collect_gates(
    overlay: &MeshRuntimeOverlay,
    prefix: &str,
    suffix: &str,
    dest: &mut HashMap<String, bool>,
) {
    for (raw_key, value) in &overlay.fields {
        let Some(rest) = raw_key.strip_prefix(prefix) else {
            continue;
        };
        let Some(scope) = rest.strip_suffix(suffix) else {
            continue;
        };
        if scope.is_empty() {
            continue;
        }
        let RuntimeValue::Bool(enabled) = value else {
            continue;
        };
        dest.insert(scope.to_string(), *enabled);
    }
}

/// Collect one transformer namespace's gates from `overlay` into a fresh map.
///
/// Shares [`collect_gates`] with the process-global stores so a materialized
/// effective gate and the published provenance map can never parse the same
/// overlay differently.
pub fn scope_gates(
    overlay: &MeshRuntimeOverlay,
    prefix: &str,
    suffix: &str,
) -> HashMap<String, bool> {
    let mut gates = HashMap::new();
    collect_gates(overlay, prefix, suffix, &mut gates);
    gates
}

/// Bind one candidate transformer config's effective gate to `gates`.
///
/// Idempotent and authoritative: the reserved key is always rewritten from
/// `gates` (or removed) rather than merged, so a value left over from an
/// earlier generation — or authored by a hostile/confused config source — can
/// never survive into this one. Returns whether this call changed the config;
/// the rebuild decision itself is made later by
/// `reconcile_runtime_overlay_plugin_generations`, which compares the whole
/// serialized candidate against the previously accepted one.
///
/// Scope resolution matches the plugin's own parser: trimmed, and empty means
/// "no scope".
pub fn materialize_resolved_gate(config: &mut Value, gates: &HashMap<String, bool>) -> bool {
    let Some(config_object) = config.as_object_mut() else {
        return false;
    };
    let scope = config_object
        .get("runtime_overlay_scope")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|scope| !scope.is_empty())
        .map(str::to_string);

    // No scope means the instance never consults the overlay. Strip the
    // reserved key so an inherited value cannot pin an opted-out instance.
    let Some(scope) = scope else {
        return config_object.remove(RESOLVED_ENABLED_KEY).is_some();
    };

    match gates.get(&scope) {
        // A named gate replaces whatever was there before.
        Some(enabled) => {
            let next = Value::Bool(*enabled);
            if config_object.get(RESOLVED_ENABLED_KEY) == Some(&next) {
                return false;
            }
            config_object.insert(RESOLVED_ENABLED_KEY.to_string(), next);
            true
        }
        // The accepted overlay names no gate for this scope, so the instance's
        // own `default_enabled` governs this generation.
        None => config_object.remove(RESOLVED_ENABLED_KEY).is_some(),
    }
}
