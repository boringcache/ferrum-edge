//! Request transformer plugin — modifies headers, query params, and body
//! before proxying.
//!
//! Header/query rules execute in `before_proxy` before the backend request is
//! built. Body rules execute in `transform_request_body` which forces the
//! request body to be buffered.
//!
//! Rules are validated and partitioned at construction time:
//!
//! - Unknown top-level and per-rule properties are rejected (no silent typos).
//! - Unknown `operation` / `target` values are rejected (no silent no-ops).
//! - Header/query operation fields are exact: only `add`/`update` accept
//!   `value`; only `rename` accepts `new_key`; `remove` accepts neither.
//! - Every configured header `value` must parse as an HTTP `HeaderValue`
//!   (same complete syntax accepted at H1/H2/H3 emission). CR/LF keep a
//!   dedicated diagnostic; other forbidden control bytes fail the same gate.
//! - Rules are split into `header_rules` and `query_rules` so the hot path
//!   does not dispatch on target strings per request, and so
//!   [`modifies_request_headers`] returns an accurate answer (which lets the
//!   handler skip cloning `ctx.headers` for query-only or body-only configs).
//!
//! ## Per-rule overrides from `mesh_route_dispatch`
//!
//! When `mesh_route_dispatch` matches a rule that carries
//! `request_transform`, it publishes a pre-compiled `Arc` onto
//! [`RequestContext::route_override_request_transform`]. This plugin always
//! consults that field at the end of `before_proxy` — i.e. **static rules
//! run first, then per-rule overrides**. The ordering is deterministic so
//! operators can predict the final header state when both surfaces are in
//! use simultaneously (e.g. a proxy-wide `set X-Trace: gateway` plus a
//! route-level `set X-Trace: canary`: the route-level write wins because it
//! runs last).
//!
//! ## `apply_route_overrides` opt-in
//!
//! Setting `apply_route_overrides: true` on the plugin config lets the
//! instance carry zero static `rules`. The K8s VirtualService translator
//! uses this to auto-emit a `request_transformer` on proxies that do not
//! already have one, so per-rule route-level transforms still find a
//! consumer. Direct operator configs without static rules and without this
//! flag continue to be rejected.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the plugin reads
//! `ferrum.request_transformer.<scope>.enabled` from the mesh runtime
//! overlay at request time. A `false` value short-circuits the plugin
//! (static rules AND route-overlay overrides become no-ops). A missing
//! entry falls back to `default_enabled` (defaults to `true` so the gate
//! is fail-open).

use async_trait::async_trait;
use http::header::{HeaderName, HeaderValue};
use serde_json::{Map, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tracing::debug;

use super::utils::body_transform::{self, BodyRule};
use super::utils::route_header_transform::{
    RouteHeaderTransformRule, apply_route_header_transforms,
};
use super::{Plugin, PluginResult, RequestContext};

pub mod runtime_overlay;

/// Top-level config keys accepted by [`RequestTransformer::new`].
const CONFIG_KEYS: &[&str] = &[
    "rules",
    "apply_route_overrides",
    "runtime_overlay_scope",
    "default_enabled",
];

/// Per-rule keys accepted for header, query, and body rules.
const RULE_KEYS: &[&str] = &["operation", "target", "key", "value", "new_key"];

#[derive(Debug, Clone, Copy, PartialEq)]
enum HeaderOp {
    Add,
    Update,
    Remove,
    Rename,
}

#[derive(Debug, Clone)]
struct HeaderRule {
    operation: HeaderOp,
    /// Pre-lowercased header key.
    key: String,
    /// Required for add/update.
    value: Option<String>,
    /// Pre-lowercased new key, required for rename.
    new_key: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq)]
enum QueryOp {
    Add,
    Update,
    Remove,
    Rename,
}

#[derive(Debug, Clone)]
struct QueryRule {
    operation: QueryOp,
    key: String,
    /// Required for add/update.
    value: Option<String>,
    /// Required for rename.
    new_key: Option<String>,
}

pub struct RequestTransformer {
    header_rules: Vec<HeaderRule>,
    query_rules: Vec<QueryRule>,
    body_rules: Vec<BodyRule>,
    /// Set by config field `apply_route_overrides`. When `true` the plugin
    /// instance accepts a zero-rule config and declares
    /// `modifies_request_headers() == true` so the dispatcher clones request
    /// headers for it. The K8s VirtualService translator uses this opt-in
    /// when auto-emitting a `request_transformer` whose sole purpose is to
    /// apply per-rule `mesh_route_dispatch` route-level transforms.
    apply_route_overrides: bool,
    /// When `Some`, the plugin reads
    /// `ferrum.request_transformer.<scope>.enabled` from the mesh runtime
    /// overlay on every request before applying rules.
    runtime_overlay_scope: Option<String>,
    /// Fallback when [`runtime_overlay_scope`] is set but the overlay does
    /// not carry the matching key. Defaults to `true` (fail-open).
    default_enabled: bool,
}

impl RequestTransformer {
    fn rules_enabled(&self) -> bool {
        let Some(scope) = self.runtime_overlay_scope.as_deref() else {
            return true;
        };
        runtime_overlay::current_gates()
            .gate(scope)
            .unwrap_or(self.default_enabled)
    }
}

fn parse_op(op: &str) -> Option<(HeaderOp, QueryOp)> {
    match op {
        "add" => Some((HeaderOp::Add, QueryOp::Add)),
        "update" => Some((HeaderOp::Update, QueryOp::Update)),
        "remove" => Some((HeaderOp::Remove, QueryOp::Remove)),
        "rename" => Some((HeaderOp::Rename, QueryOp::Rename)),
        _ => None,
    }
}

fn contains_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

fn reject_unknown_keys(
    object: &Map<String, Value>,
    path: &str,
    allowed: &[&str],
) -> Result<(), String> {
    let mut unknown: Vec<&str> = object
        .keys()
        .map(String::as_str)
        .filter(|key| !allowed.contains(key))
        .collect();
    if unknown.is_empty() {
        return Ok(());
    }
    unknown.sort_unstable();
    Err(format!(
        "request_transformer: unknown config key(s) under '{path}': {}; allowed keys: {}",
        unknown.join(", "),
        allowed.join(", ")
    ))
}

/// Validate a configured header value the same way outbound Hyper / H3 /
/// reqwest adapters do (`HeaderValue::from_str`), while keeping the
/// historical CR/LF-specific diagnostic for injection typos.
fn validate_configured_header_value(value: &str, idx: usize) -> Result<(), String> {
    if contains_crlf(value) {
        return Err(format!(
            "request_transformer: rule[{idx}]: header 'value' must not contain CR or LF"
        ));
    }
    HeaderValue::from_str(value).map_err(|_| {
        format!(
            "request_transformer: rule[{idx}]: header 'value' must be a valid HTTP HeaderValue"
        )
    })?;
    Ok(())
}

impl RequestTransformer {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config_obj = config.as_object().ok_or_else(|| {
            format!(
                "request_transformer: config must be an object; allowed keys: {}",
                CONFIG_KEYS.join(", ")
            )
        })?;
        reject_unknown_keys(config_obj, "config", CONFIG_KEYS)?;

        let mut header_rules: Vec<HeaderRule> = Vec::new();
        let mut query_rules: Vec<QueryRule> = Vec::new();

        if let Some(rules) = config.get("rules") {
            let arr = rules
                .as_array()
                .ok_or("request_transformer: 'rules' must be an array")?;
            for (idx, r) in arr.iter().enumerate() {
                let rule_obj = r.as_object().ok_or_else(|| {
                    format!("request_transformer: rule[{idx}]: rule must be an object")
                })?;
                let rule_path = format!("config.rules[{idx}]");
                reject_unknown_keys(rule_obj, &rule_path, RULE_KEYS)?;

                let target = match r.get("target") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'target' is required (expected header/query/body)"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'target' must be a string (expected header/query/body)"
                        ));
                    }
                };

                // Body rules are validated and collected by `parse_body_rules`
                // (required / incompatible fields). Unknown keys are already
                // rejected above.
                if target == "body" {
                    continue;
                }

                if target != "header" && target != "query" {
                    return Err(format!(
                        "request_transformer: rule[{idx}]: unknown target '{target}' (expected header/query/body)"
                    ));
                }

                let op_str = match r.get("operation") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'operation' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'operation' must be a string"
                        ));
                    }
                };
                let (hop, qop) = parse_op(op_str).ok_or_else(|| {
                    format!(
                        "request_transformer: rule[{idx}]: unknown operation '{op_str}' (expected add/update/remove/rename)"
                    )
                })?;

                let raw_key = match r.get("key") {
                    Some(Value::String(s)) => s.clone(),
                    None => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'key' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'key' must be a string"
                        ));
                    }
                };
                let value = match r.get("value") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'value' must be a string for header/query rules"
                        ));
                    }
                };
                let raw_new_key = match r.get("new_key") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "request_transformer: rule[{idx}]: 'new_key' must be a string"
                        ));
                    }
                };

                // Per-operation required- and forbidden-field validation.
                // Incompatible extras are rejected rather than silently ignored
                // so typos cannot produce a different transform than intended.
                // Matches body-rule constraints in `body_transform`.
                match op_str {
                    "add" | "update" => {
                        if value.is_none() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: '{op_str}' operation requires a 'value'"
                            ));
                        }
                        if raw_new_key.is_some() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'new_key' must not be set for {target} '{op_str}' operation"
                            ));
                        }
                    }
                    "rename" => {
                        if value.is_some() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'value' must not be set for {target} 'rename' operation"
                            ));
                        }
                        if raw_new_key.is_none() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'rename' operation requires a 'new_key'"
                            ));
                        }
                    }
                    "remove" => {
                        if value.is_some() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'value' must not be set for {target} 'remove' operation"
                            ));
                        }
                        if raw_new_key.is_some() {
                            return Err(format!(
                                "request_transformer: rule[{idx}]: 'new_key' must not be set for {target} 'remove' operation"
                            ));
                        }
                    }
                    _ => {}
                }

                if target == "header" {
                    let key = HeaderName::from_bytes(raw_key.as_bytes())
                        .map_err(|_| {
                            format!(
                                "request_transformer: rule[{idx}]: 'key' must be a valid HTTP header name"
                            )
                        })?
                        .to_string();
                    let new_key = raw_new_key
                        .as_deref()
                        .map(|key| {
                            HeaderName::from_bytes(key.as_bytes())
                                .map_err(|_| {
                                    format!(
                                        "request_transformer: rule[{idx}]: 'new_key' must be a valid HTTP header name"
                                    )
                                })
                                .map(|name| name.to_string())
                        })
                        .transpose()?;

                    if let Some(ref v) = value {
                        validate_configured_header_value(v, idx)?;
                    }
                    header_rules.push(HeaderRule {
                        operation: hop,
                        key,
                        value,
                        new_key,
                    });
                } else {
                    query_rules.push(QueryRule {
                        operation: qop,
                        key: raw_key,
                        value,
                        new_key: raw_new_key,
                    });
                }
            }
        }

        let body_rules = body_transform::parse_body_rules(config)
            .map_err(|e| format!("request_transformer: {e}"))?;

        let apply_route_overrides = match config.get("apply_route_overrides") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            Some(_) => {
                return Err(
                    "request_transformer: 'apply_route_overrides' must be a boolean".to_string(),
                );
            }
        };

        if header_rules.is_empty()
            && query_rules.is_empty()
            && body_rules.is_empty()
            && !apply_route_overrides
        {
            return Err(
                "request_transformer: no 'rules' configured — plugin will have no effect"
                    .to_string(),
            );
        }

        let runtime_overlay_scope = match config.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "request_transformer: runtime_overlay_scope must be a non-empty string"
                            .to_string(),
                    );
                }
                Some(trimmed.to_string())
            }
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(
                    "request_transformer: runtime_overlay_scope must be a string".to_string(),
                );
            }
        };

        let default_enabled = match config.get("default_enabled") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => true,
            Some(_) => {
                return Err("request_transformer: default_enabled must be a boolean".to_string());
            }
        };

        Ok(Self {
            header_rules,
            query_rules,
            body_rules,
            apply_route_overrides,
            runtime_overlay_scope,
            default_enabled,
        })
    }
}

#[async_trait]
impl Plugin for RequestTransformer {
    fn name(&self) -> &str {
        "request_transformer"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_TRANSFORMER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn modifies_request_headers(&self) -> bool {
        // Per-rule overrides (`apply_route_overrides=true`) can mutate
        // headers even when this instance has no static `header_rules`, so
        // the dispatcher must clone request headers for it. Returning
        // `false` here would let the dispatcher hand `ctx.headers` itself
        // to plugins via `mem::take`, which both breaks the gateway-wide
        // "ctx.headers is the original inbound headers" invariant and (on
        // some paths) silently drops route-level header writes.
        !self.header_rules.is_empty() || self.apply_route_overrides
    }

    fn modifies_request_body(&self) -> bool {
        !self.body_rules.is_empty()
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.rules_enabled() {
            return PluginResult::Continue;
        }
        for rule in &self.header_rules {
            match rule.operation {
                HeaderOp::Add => {
                    if let Some(ref val) = rule.value {
                        headers.entry(rule.key.clone()).or_insert_with(|| {
                            debug!("request_transformer: added header {}={}", rule.key, val);
                            val.clone()
                        });
                    }
                }
                HeaderOp::Update => {
                    if let Some(ref val) = rule.value {
                        headers.insert(rule.key.clone(), val.clone());
                        debug!("request_transformer: set header {}={}", rule.key, val);
                    }
                }
                HeaderOp::Remove => {
                    headers.remove(&rule.key);
                    debug!("request_transformer: removed header {}", rule.key);
                }
                HeaderOp::Rename => {
                    if let Some(ref new_key) = rule.new_key
                        && let Some(val) = headers.remove(&rule.key)
                    {
                        debug!(
                            "request_transformer: renamed header {} -> {}",
                            rule.key, new_key
                        );
                        headers.insert(new_key.clone(), val);
                    }
                }
            }
        }
        let mut query_mutated = false;
        for rule in &self.query_rules {
            match rule.operation {
                QueryOp::Add => {
                    if let Some(ref val) = rule.value {
                        let before = ctx.query_params.len();
                        ctx.query_params
                            .entry(rule.key.clone())
                            .or_insert_with(|| val.clone());
                        query_mutated |= ctx.query_params.len() != before;
                    }
                }
                QueryOp::Update => {
                    if let Some(ref val) = rule.value {
                        ctx.query_params.insert(rule.key.clone(), val.clone());
                        query_mutated = true;
                    }
                }
                QueryOp::Remove => {
                    query_mutated |= ctx.query_params.remove(&rule.key).is_some();
                }
                QueryOp::Rename => {
                    if let Some(ref new_key) = rule.new_key
                        && let Some(val) = ctx.query_params.remove(&rule.key)
                    {
                        ctx.query_params.insert(new_key.clone(), val);
                        query_mutated = true;
                    }
                }
            }
        }
        if query_mutated {
            // Signal the decoded-query transform so a downstream raw-query
            // consumer (`serverless_function`) can fail closed rather than emit a
            // payload rebuilt from the untransformed raw query string. The
            // transform lands on `ctx.query_params`, which the backend request
            // URL does not re-serialize, so this marker is the only faithful
            // record that operator query intent diverged from the raw wire query.
            ctx.metadata.insert(
                crate::proxy::QUERY_PARAMS_TRANSFORMED_METADATA_KEY.to_string(),
                "true".to_string(),
            );
        }
        // Per-rule header transforms published by `mesh_route_dispatch`
        // run AFTER this plugin's static rules so route-level writes win on
        // conflict — see the module docstring for the precedence rationale.
        // Take the Arc out of ctx so a future plugin instance in the chain
        // does not re-apply the same list.
        let route_rules: Option<Arc<Vec<RouteHeaderTransformRule>>> =
            ctx.route_override_request_transform.take();
        if let Some(route_rules) = route_rules {
            apply_route_header_transforms(route_rules.as_ref(), headers);
        }
        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.rules_enabled() {
            return None;
        }
        // Only transform JSON bodies. When Content-Type is absent, attempt
        // JSON parse anyway — the body_transform helper short-circuits on
        // parse failure, so the cost is one failed parse per non-JSON request.
        if let Some(ct) = content_type
            && !body_transform::is_json_content_type(ct)
        {
            return None;
        }
        body_transform::apply_body_rules(body, &self.body_rules)
    }
}
