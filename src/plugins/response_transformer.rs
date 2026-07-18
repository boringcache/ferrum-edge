//! Response transformer plugin — modifies response headers and body after
//! proxying.
//!
//! Header rules (add/remove/update/rename) execute in `after_proxy`. Body
//! rules require `requires_response_body_buffering()` = true so the response
//! body is collected before being forwarded to the client.
//!
//! Rules are validated at construction time:
//!
//! - Unknown `operation` / `target` values are rejected (no silent no-ops).
//! - `add` / `update` require a `value`; `rename` requires a `new_key`.
//! - Header values with CR/LF characters are rejected (defence against
//!   header injection via config).
//! - Header keys are pre-lowercased.
//!
//! ## Per-rule overrides from `mesh_route_dispatch`
//!
//! `mesh_route_dispatch` publishes per-rule
//! `route_override_response_transform` Arcs onto `RequestContext`. This
//! plugin applies them at the end of `after_proxy` — i.e. **static rules
//! run first, then per-rule overrides** — so route-level writes win on
//! conflict. The `apply_route_overrides: true` opt-in mirrors the
//! `request_transformer` counterpart: it lets the K8s VirtualService
//! translator auto-emit a `response_transformer` with zero static rules
//! whose only job is to act as a consumer for per-rule overrides.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the plugin reads
//! `ferrum.response_transformer.<scope>.enabled` from the mesh runtime
//! overlay at request time. A `false` value short-circuits rule
//! application (static rules AND route-overlay overrides). A missing
//! entry falls back to `default_enabled` (defaults to `true` —
//! fail-open).

use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::HashMap;
use std::collections::hash_map::Entry;
use std::sync::Arc;
use tracing::debug;

use super::utils::body_transform::{self, BodyRule};
use super::utils::route_header_transform::{
    RouteHeaderTransformOp, RouteHeaderTransformRule, apply_route_header_transforms,
    apply_route_header_transforms_tracked,
};
use super::{Plugin, PluginResult, RequestContext};
use crate::util::http_headers::{cache_control_has_directive, etag_value_is_strong};

pub mod runtime_overlay;

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

pub struct ResponseTransformer {
    header_rules: Vec<HeaderRule>,
    /// Pre-lowercased keys of static `update` rules. These are unconditional
    /// gateway overwrites, so a completed `after_proxy` owns them on a gRPC
    /// deadline rebuild even when the backend pre-populated the identical value
    /// (mutation tracking alone cannot see an exact-value write). Precomputed
    /// once so the deadline-provenance path allocates nothing per request.
    static_update_keys: Vec<String>,
    body_rules: Vec<BodyRule>,
    /// When `Some`, the plugin reads
    /// `ferrum.response_transformer.<scope>.enabled` from the mesh
    /// runtime overlay on every request before applying rules.
    runtime_overlay_scope: Option<String>,
    /// Fallback when [`runtime_overlay_scope`] is set but the overlay
    /// does not carry the matching key. Defaults to `true` (fail-open).
    default_enabled: bool,
}

impl ResponseTransformer {
    fn rules_enabled(&self) -> bool {
        let Some(scope) = self.runtime_overlay_scope.as_deref() else {
            return true;
        };
        runtime_overlay::current_gates()
            .gate(scope)
            .unwrap_or(self.default_enabled)
    }

    fn static_rules_may_modify_content_type(&self) -> bool {
        self.header_rules.iter().any(|rule| match rule.operation {
            HeaderOp::Add | HeaderOp::Update | HeaderOp::Remove => rule.key == "content-type",
            HeaderOp::Rename => {
                rule.key == "content-type" || rule.new_key.as_deref() == Some("content-type")
            }
        })
    }

    fn route_rules_may_modify_content_type(ctx: &RequestContext) -> bool {
        ctx.route_override_response_transform
            .as_ref()
            .is_some_and(|rules| rules.iter().any(|rule| rule.key == "content-type"))
    }

    fn static_rules_may_add_cache_control_no_transform(&self) -> bool {
        self.header_rules.iter().any(|rule| match rule.operation {
            HeaderOp::Add | HeaderOp::Update => {
                rule.key == "cache-control"
                    && rule
                        .value
                        .as_deref()
                        .is_some_and(|value| cache_control_has_directive(value, "no-transform"))
            }
            HeaderOp::Remove => false,
            HeaderOp::Rename => rule.new_key.as_deref() == Some("cache-control"),
        })
    }

    fn route_rules_may_add_cache_control_no_transform(ctx: &RequestContext) -> bool {
        ctx.route_override_response_transform
            .as_ref()
            .is_some_and(|rules| {
                rules.iter().any(|rule| match rule.operation {
                    RouteHeaderTransformOp::Add | RouteHeaderTransformOp::Update => {
                        rule.key == "cache-control"
                            && rule.value.as_deref().is_some_and(|value| {
                                cache_control_has_directive(value, "no-transform")
                            })
                    }
                    RouteHeaderTransformOp::Remove => false,
                })
            })
    }

    fn static_rules_may_add_strong_etag(&self) -> bool {
        self.header_rules.iter().any(|rule| match rule.operation {
            HeaderOp::Add | HeaderOp::Update => {
                rule.key == "etag" && rule.value.as_deref().is_some_and(etag_value_is_strong)
            }
            HeaderOp::Remove => false,
            HeaderOp::Rename => rule.new_key.as_deref() == Some("etag"),
        })
    }

    fn route_rules_may_add_strong_etag(ctx: &RequestContext) -> bool {
        ctx.route_override_response_transform
            .as_ref()
            .is_some_and(|rules| {
                rules.iter().any(|rule| match rule.operation {
                    RouteHeaderTransformOp::Add | RouteHeaderTransformOp::Update => {
                        rule.key == "etag"
                            && rule.value.as_deref().is_some_and(etag_value_is_strong)
                    }
                    RouteHeaderTransformOp::Remove => false,
                })
            })
    }

    /// `fired_write_keys`, when `Some`, collects every key this rule set wrote
    /// WHOLE — that is, wrote a complete value that net-diff mutation tracking
    /// cannot be relied on to notice:
    ///
    /// * the destination key of every `rename` that actually fired. A rename can
    ///   land a value on the destination that is byte-identical to something a
    ///   backend could have sent (the backend may even have sent that exact
    ///   destination header itself), and mutation tracking sees only the source
    ///   removal.
    /// * the key of every `add` that actually INSERTED (a static `add` fires only
    ///   into an absent slot). An `add` following a `remove` of the same key can
    ///   leave the final map byte-identical to the backend's, so the net diff is
    ///   empty even though the gateway authored the surviving value.
    ///
    /// Callers that track gRPC-deadline provenance pass a sink and declare these
    /// keys owned; everyone else passes `None` and stays allocation-free.
    fn apply_static_header_rules(
        &self,
        response_headers: &mut HashMap<String, String>,
        emit_debug: bool,
        mut fired_write_keys: Option<&mut Vec<String>>,
    ) {
        for rule in &self.header_rules {
            match rule.operation {
                HeaderOp::Add => {
                    if let Some(value) = rule.value.as_ref()
                        && let Entry::Vacant(slot) = response_headers.entry(rule.key.clone())
                    {
                        // A static `add` only ever fires into an ABSENT slot, so
                        // the whole inserted value is gateway-authored. Record it
                        // for the same reason as a fired `rename` destination: an
                        // `add` that follows a `remove` of the same key can leave
                        // the map byte-identical to the backend's, and net-diff
                        // mutation tracking would then never credit the
                        // reintroduced header — silently dropping it from a
                        // synthesized DEADLINE_EXCEEDED response.
                        if emit_debug {
                            debug!("response_transformer: added header {}={}", rule.key, value);
                        }
                        slot.insert(value.clone());
                        if let Some(sink) = fired_write_keys.as_mut() {
                            sink.push(rule.key.clone());
                        }
                    }
                }
                HeaderOp::Update => {
                    if let Some(value) = rule.value.as_ref() {
                        response_headers.insert(rule.key.clone(), value.clone());
                        if emit_debug {
                            debug!("response_transformer: set header {}={}", rule.key, value);
                        }
                    }
                }
                HeaderOp::Remove => {
                    response_headers.remove(&rule.key);
                    if emit_debug {
                        debug!("response_transformer: removed header {}", rule.key);
                    }
                }
                HeaderOp::Rename => {
                    if let Some(new_key) = rule.new_key.as_ref()
                        && let Some(value) = response_headers.remove(&rule.key)
                    {
                        if emit_debug {
                            debug!(
                                "response_transformer: renamed header {} -> {}",
                                rule.key, new_key
                            );
                        }
                        response_headers.insert(new_key.clone(), value);
                        if let Some(sink) = fired_write_keys.as_mut() {
                            sink.push(new_key.clone());
                        }
                    }
                }
            }
        }
    }
}

fn parse_op(op: &str) -> Option<HeaderOp> {
    match op {
        "add" => Some(HeaderOp::Add),
        "update" => Some(HeaderOp::Update),
        "remove" => Some(HeaderOp::Remove),
        "rename" => Some(HeaderOp::Rename),
        _ => None,
    }
}

fn contains_crlf(s: &str) -> bool {
    s.bytes().any(|b| b == b'\r' || b == b'\n')
}

impl ResponseTransformer {
    pub fn new(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("response_transformer: config must be an object".to_string());
        }

        let mut header_rules: Vec<HeaderRule> = Vec::new();

        if let Some(rules) = config.get("rules") {
            let arr = rules
                .as_array()
                .ok_or("response_transformer: 'rules' must be an array")?;
            for (idx, r) in arr.iter().enumerate() {
                if !r.is_object() {
                    return Err(format!(
                        "response_transformer: rule[{idx}]: rule must be an object"
                    ));
                }
                let target = match r.get("target") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'target' is required (expected header/body)"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'target' must be a string (expected header/body)"
                        ));
                    }
                };

                if target == "body" {
                    // Body rules are validated by `parse_body_rules`.
                    continue;
                }

                if target != "header" {
                    return Err(format!(
                        "response_transformer: rule[{idx}]: unknown target '{target}' (expected header/body)"
                    ));
                }

                let op_str = match r.get("operation") {
                    Some(Value::String(s)) => s.as_str(),
                    None => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'operation' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'operation' must be a string"
                        ));
                    }
                };
                let operation = parse_op(op_str).ok_or_else(|| {
                    format!(
                        "response_transformer: rule[{idx}]: unknown operation '{op_str}' (expected add/update/remove/rename)"
                    )
                })?;

                let raw_key = match r.get("key") {
                    Some(Value::String(s)) => s.clone(),
                    None => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'key' is required"
                        ));
                    }
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'key' must be a string"
                        ));
                    }
                };
                let key = HeaderName::from_bytes(raw_key.as_bytes())
                    .map_err(|_| {
                        format!(
                            "response_transformer: rule[{idx}]: 'key' must be a valid HTTP header name"
                        )
                    })?
                    .to_string();
                let value = match r.get("value") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'value' must be a string for header rules"
                        ));
                    }
                };
                let raw_new_key = match r.get("new_key") {
                    Some(Value::String(s)) => Some(s.clone()),
                    Some(Value::Null) | None => None,
                    Some(_) => {
                        return Err(format!(
                            "response_transformer: rule[{idx}]: 'new_key' must be a string"
                        ));
                    }
                };
                let new_key = raw_new_key
                    .as_deref()
                    .map(|key| {
                        HeaderName::from_bytes(key.as_bytes())
                            .map_err(|_| {
                                format!(
                                    "response_transformer: rule[{idx}]: 'new_key' must be a valid HTTP header name"
                                )
                            })
                            .map(|name| name.to_string())
                    })
                    .transpose()?;

                // Per-operation required-field validation.
                match operation {
                    HeaderOp::Add | HeaderOp::Update => {
                        if value.is_none() {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: '{op_str}' operation requires a 'value'"
                            ));
                        }
                    }
                    HeaderOp::Rename => {
                        if raw_new_key.is_none() {
                            return Err(format!(
                                "response_transformer: rule[{idx}]: 'rename' operation requires a 'new_key'"
                            ));
                        }
                    }
                    HeaderOp::Remove => {}
                }

                if let Some(ref v) = value
                    && contains_crlf(v)
                {
                    return Err(format!(
                        "response_transformer: rule[{idx}]: header 'value' must not contain CR or LF"
                    ));
                }

                header_rules.push(HeaderRule {
                    operation,
                    key,
                    value,
                    new_key,
                });
            }
        }

        let body_rules = body_transform::parse_body_rules(config)
            .map_err(|e| format!("response_transformer: {e}"))?;

        let apply_route_overrides = match config.get("apply_route_overrides") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => false,
            Some(_) => {
                return Err(
                    "response_transformer: 'apply_route_overrides' must be a boolean".to_string(),
                );
            }
        };

        if header_rules.is_empty() && body_rules.is_empty() && !apply_route_overrides {
            return Err(
                "response_transformer: no 'rules' configured — plugin will have no effect"
                    .to_string(),
            );
        }

        // `apply_route_overrides` is parsed and validated above so the
        // K8s VirtualService translator can auto-emit a `response_transformer`
        // with zero static rules whose only purpose is to consume
        // `ctx.route_override_response_transform` Arcs in `after_proxy`.
        // The flag is config-time only — the runtime path consults `ctx`
        // unconditionally — so we drop it after construction.
        let _ = apply_route_overrides;

        let runtime_overlay_scope = match config.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "response_transformer: runtime_overlay_scope must be a non-empty string"
                            .to_string(),
                    );
                }
                Some(trimmed.to_string())
            }
            Some(Value::Null) | None => None,
            Some(_) => {
                return Err(
                    "response_transformer: runtime_overlay_scope must be a string".to_string(),
                );
            }
        };

        let default_enabled = match config.get("default_enabled") {
            Some(Value::Bool(b)) => *b,
            Some(Value::Null) | None => true,
            Some(_) => {
                return Err("response_transformer: default_enabled must be a boolean".to_string());
            }
        };

        let static_update_keys = header_rules
            .iter()
            .filter(|rule| rule.operation == HeaderOp::Update)
            .map(|rule| rule.key.clone())
            .collect::<Vec<_>>();

        Ok(Self {
            header_rules,
            static_update_keys,
            body_rules,
            runtime_overlay_scope,
            default_enabled,
        })
    }
}

#[async_trait]
impl Plugin for ResponseTransformer {
    fn name(&self) -> &str {
        "response_transformer"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_TRANSFORMER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_GRPC_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        !self.body_rules.is_empty()
    }

    fn may_modify_response_content_type(
        &self,
        ctx: &RequestContext,
        _response_content_type: Option<&str>,
    ) -> bool {
        // Whether a rule fires is decided by config/route state, not the
        // backend response type, so the backend `Content-Type` is not consulted.
        self.rules_enabled()
            && (self.static_rules_may_modify_content_type()
                || Self::route_rules_may_modify_content_type(ctx))
    }

    fn may_add_response_cache_control_no_transform(
        &self,
        ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.rules_enabled()
            && (self.static_rules_may_add_cache_control_no_transform()
                || Self::route_rules_may_add_cache_control_no_transform(ctx))
    }

    fn may_add_response_strong_etag(
        &self,
        ctx: &RequestContext,
        _response_headers: &HashMap<String, String>,
    ) -> bool {
        self.rules_enabled()
            && (self.static_rules_may_add_strong_etag()
                || Self::route_rules_may_add_strong_etag(ctx))
    }

    fn simulate_after_proxy_response_headers(
        &self,
        ctx: &mut RequestContext,
        response_headers: &mut HashMap<String, String>,
    ) {
        if !self.rules_enabled() {
            return;
        }
        self.apply_static_header_rules(response_headers, false, None);
        if let Some(route_rules) = ctx.route_override_response_transform.take() {
            apply_route_header_transforms(route_rules.as_ref(), response_headers);
        }
    }

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Honor the RTDS runtime kill-switch here, mirroring the early
        // `return None` in `transform_response_body`. When the overlay disables
        // this scope the transform is a no-op, so we must not pin the response
        // into the buffered path — otherwise a disabled transform still buffers
        // a large/streaming non-SSE response until the max-response-body limit
        // and then 502s, defeating the very buffering relief the kill-switch is
        // meant to provide. `rules_enabled()` reads request-time overlay state,
        // so it belongs in this per-request gate (not the cache-level
        // `requires_response_body_buffering` upper bound). (Finding #64.)
        //
        // Skip body buffering for SSE requests (`Accept: text/event-stream`).
        // Body transforms operate on the assembled response body — applying
        // them to an unbounded event stream would buffer until the
        // max-response-body limit is hit and then 502. SSE transforms are
        // out of scope; operators should configure body transforms only for
        // non-SSE proxies, or layer a frame-level plugin on top.
        !self.body_rules.is_empty()
            && self.rules_enabled()
            && !super::utils::sse::is_sse_request(ctx)
    }

    fn enforces_response_body_policy(
        &self,
        ctx: &RequestContext,
        response_content_type: Option<&str>,
    ) -> bool {
        // Claim exactly the responses `transform_response_body` would actually
        // rewrite, so the shared representation gate fails closed on those and
        // leaves every other response alone. The three declines below are the
        // plugin's own documented no-ops, not inspection failures:
        //   * no configured `body_rules` — there is no body policy at all;
        //   * the RTDS kill-switch disabled this scope, mirroring the early
        //     `return None` in `transform_response_body`;
        //   * SSE, which `should_buffer_response_body` keeps out of the buffered
        //     path entirely, so no transform ever runs over it.
        // The media-type condition requires a *positive* JSON `Content-Type`.
        // A non-JSON type is a documented decline (the configured rules address
        // JSON fields). An ABSENT type is treated the same way, deliberately: the
        // gate would otherwise have to parse every untyped body as JSON and
        // reject the ones that are not, which turns ordinary untyped responses —
        // minimal error pages, redirect bodies, plain-text health output — into
        // 502s without protecting anything, since no JSON field rule can be
        // proven to target an untyped document in the first place. This shares
        // the (pre-existing) property that a backend which mislabels or omits
        // `Content-Type` is outside what this policy can enforce.
        !self.body_rules.is_empty()
            && self.rules_enabled()
            && !super::utils::sse::is_sse_request(ctx)
            && response_content_type.is_some_and(body_transform::is_json_content_type)
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.rules_enabled() {
            return PluginResult::Continue;
        }
        // Collect fired whole-value writes only when a deadline rebuild could
        // consult them, keeping the common path allocation-free.
        let track_owned = ctx.has_buffered_deadline_response_header_provenance();
        let mut fired_write_keys: Vec<String> = Vec::new();
        self.apply_static_header_rules(
            response_headers,
            true,
            track_owned.then_some(&mut fired_write_keys),
        );
        // Per-rule overrides published by `mesh_route_dispatch` run AFTER
        // static rules so route-level writes win on conflict — see module
        // docstring. Take the Arc out so a later response_transformer
        // instance in the chain does not re-apply the same list.
        let route_rules: Option<Arc<Vec<RouteHeaderTransformRule>>> =
            ctx.route_override_response_transform.take();
        if let Some(route_rules) = route_rules.as_ref() {
            apply_route_header_transforms_tracked(
                route_rules.as_ref(),
                response_headers,
                track_owned.then_some(&mut fired_write_keys),
            );
        }
        // Declare every WHOLE-VALUE gateway write (static and route-override) as
        // gateway-owned for a gRPC deadline rebuild, because net-diff mutation
        // tracking cannot see such a write when the backend already carried the
        // identical bytes:
        //
        // * `update` overwrites with the configured value, so a backend that
        //   pre-populated the identical key/value must not be able to suppress
        //   the decoration on a synthesized DEADLINE_EXCEEDED response.
        // * a fired `rename` destination: mutation tracking observes only the
        //   source removal, so a backend that also sent the destination key with
        //   the same value it is being renamed to would suppress the write.
        // * an `add` that actually INSERTED into an absent slot — including the
        //   `remove`-then-`add` sequence whose final map is byte-identical to the
        //   backend's, where the net diff is empty. `fired_write_keys` carries
        //   these from both rule sets.
        //
        // An `add` that APPENDED onto an existing value is deliberately absent:
        // it must stay on mutation tracking's append-partition branch so the
        // backend portion of the value never crosses onto the deadline response.
        //
        // The provenance state exists only for deadline-bound buffered responses,
        // so this is gated to avoid per-request allocation otherwise. Owned names
        // are borrowed, not cloned.
        if track_owned {
            let mut owned: Vec<&str> = Vec::new();
            owned.extend(self.static_update_keys.iter().map(String::as_str));
            owned.extend(fired_write_keys.iter().map(String::as_str));
            if let Some(route_rules) = route_rules.as_ref() {
                for rule in route_rules.iter() {
                    if rule.operation == RouteHeaderTransformOp::Update {
                        owned.push(rule.key.as_str());
                    }
                }
            }
            if !owned.is_empty() {
                ctx.record_deadline_owned_response_headers(&owned, response_headers);
            }
        }
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        _response_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        if !self.rules_enabled() {
            return None;
        }
        if let Some(ct) = content_type
            && !body_transform::is_json_content_type(ct)
        {
            return None;
        }
        body_transform::apply_body_rules(body, &self.body_rules)
    }
}
