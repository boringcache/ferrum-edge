//! Fault Injection Plugin
//!
//! Injects controlled failures (delays and aborts) into request processing
//! for chaos engineering workflows. Both fault types are probabilistic —
//! each has a `percentage` field (0.0–100.0) checked per-request.
//!
//! Runs in the `before_proxy` phase for HTTP-family requests so it fires after
//! authentication, authorization, and consumer rate limiting but before backend
//! dispatch. When backend-effective path policy is active, the HTTP hook waits
//! until the resolved backend path has been authorized, so a delay or abort
//! cannot precede the route-sensitive denial. Raw TCP proxies run the same fault
//! decision in `on_stream_connect`; stream rejects close the connection and do
//! not deliver HTTP status bodies to clients. UDP and DTLS are not supported
//! because delaying their shared listener/session loops would head-of-line block
//! unrelated datagrams.
//!
//! ## Config
//!
//! ```json
//! {
//!   "abort": {
//!     "status_code": 503,
//!     "percentage": 50.0,
//!     "grpc_status": 14,
//!     "body": "service unavailable"
//!   },
//!   "delay": {
//!     "duration_ms": 2000,
//!     "percentage": 25.0
//!   },
//!   "runtime_overlay_scope": "checkout"
//! }
//! ```
//!
//! At least one of `abort` or `delay` must be present. When both are
//! configured and both trigger on the same request, the delay executes
//! first, then the abort fires.
//! `runtime_overlay_scope` may be omitted or null to disable RTDS scoping.
//!
//! ## RTDS overlay
//!
//! When `runtime_overlay_scope: "<scope>"` is set, the plugin reads its
//! `abort.percentage` and `delay.percentage` from the RTDS-driven
//! [`MeshRuntimeOverlay`](crate::modes::mesh::config::MeshRuntimeOverlay)
//! from the same plugin-cache/request-epoch generation. Reserved keys:
//!
//! - `ferrum.fault_injection.<scope>.abort_percent`
//! - `ferrum.fault_injection.<scope>.delay_percent`
//!
//! Each accepts either a `Number(0..=100)` or a `FractionalPercent` value.
//! Missing / malformed entries fall back to the static config so a partial
//! overlay never silently disables the plugin. A valid zero temporarily
//! disables that fault side for the accepted generation.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;

use super::utils::fault_roll::{FaultRoller, MAX_FAULT_DELAY_MS};
use super::{Plugin, PluginResult, ProxyProtocol, RequestContext, StreamConnectionContext};

pub mod runtime_overlay;

const NON_UDP_PROTOCOLS: &[ProxyProtocol] = &[
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
];

struct AbortFault {
    status_code: u16,
    percentage: f64,
    grpc_status: Option<u32>,
    body: String,
}

struct DelayFault {
    duration_ms: u64,
    percentage: f64,
}

pub struct FaultInjectionPlugin {
    abort: Option<AbortFault>,
    delay: Option<DelayFault>,
    roller: FaultRoller,
}

impl FaultInjectionPlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let obj = config
            .as_object()
            .ok_or("fault_injection: config must be an object")?;
        reject_unknown_keys(
            obj.keys(),
            &["abort", "delay", "runtime_overlay_scope"],
            "config",
        )?;

        let abort = match obj.get("abort") {
            Some(Value::Object(abort_obj)) => {
                reject_unknown_keys(
                    abort_obj.keys(),
                    &["status_code", "percentage", "grpc_status", "body"],
                    "abort",
                )?;
                let status_code = abort_obj
                    .get("status_code")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: abort.status_code is required and must be an integer",
                    )?;

                if !(200..=599).contains(&status_code) {
                    return Err(format!(
                        "fault_injection: abort.status_code must be 200-599, got {status_code}"
                    ));
                }

                let percentage = parse_percentage(abort_obj.get("percentage"), "abort.percentage")?;

                let grpc_status = if let Some(grpc_val) = abort_obj.get("grpc_status") {
                    let code = grpc_val
                        .as_u64()
                        .ok_or("fault_injection: abort.grpc_status must be an integer")?;
                    if code > 16 {
                        return Err(format!(
                            "fault_injection: abort.grpc_status must be 0-16, got {code}"
                        ));
                    }
                    Some(code as u32)
                } else {
                    None
                };

                let body = match abort_obj.get("body") {
                    Some(Value::String(s)) => s.clone(),
                    Some(Value::Null) | None => String::new(),
                    Some(_) => {
                        return Err("fault_injection: abort.body must be a string".to_string());
                    }
                };

                Some(AbortFault {
                    status_code: status_code as u16,
                    percentage,
                    grpc_status,
                    body,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'abort' must be an object".to_string()),
        };

        let delay = match obj.get("delay") {
            Some(Value::Object(delay_obj)) => {
                reject_unknown_keys(delay_obj.keys(), &["duration_ms", "percentage"], "delay")?;
                let duration_ms = delay_obj
                    .get("duration_ms")
                    .and_then(|v| v.as_u64())
                    .ok_or(
                        "fault_injection: delay.duration_ms is required and must be a positive integer",
                    )?;

                if duration_ms == 0 {
                    return Err(
                        "fault_injection: delay.duration_ms must be greater than 0".to_string()
                    );
                }
                if duration_ms > MAX_FAULT_DELAY_MS {
                    return Err(format!(
                        "fault_injection: delay.duration_ms must be <= {MAX_FAULT_DELAY_MS}, got {duration_ms}"
                    ));
                }

                let percentage = parse_percentage(delay_obj.get("percentage"), "delay.percentage")?;

                Some(DelayFault {
                    duration_ms,
                    percentage,
                })
            }
            Some(Value::Null) | None => None,
            Some(_) => return Err("fault_injection: 'delay' must be an object".to_string()),
        };

        if abort.is_none() && delay.is_none() {
            return Err(
                "fault_injection: at least one of 'abort' or 'delay' must be configured"
                    .to_string(),
            );
        }

        match obj.get("runtime_overlay_scope") {
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "fault_injection: runtime_overlay_scope must be a non-empty string"
                            .to_string(),
                    );
                }
            }
            Some(Value::Null) | None => {}
            Some(_) => {
                return Err("fault_injection: runtime_overlay_scope must be a string".to_string());
            }
        }

        Ok(Self {
            abort,
            delay,
            roller: FaultRoller::new(),
        })
    }
}

fn reject_unknown_keys<'a>(
    keys: impl Iterator<Item = &'a String>,
    allowed: &[&str],
    scope: &str,
) -> Result<(), String> {
    for key in keys {
        if !allowed.contains(&key.as_str()) {
            return Err(format!("fault_injection: unknown {scope} field '{key}'"));
        }
    }
    Ok(())
}

fn parse_percentage(val: Option<&Value>, field_name: &str) -> Result<f64, String> {
    let pct = match val {
        Some(Value::Number(n)) => n
            .as_f64()
            .ok_or_else(|| format!("fault_injection: {field_name} must be a number"))?,
        Some(_) => {
            return Err(format!("fault_injection: {field_name} must be a number"));
        }
        None => {
            return Err(format!("fault_injection: {field_name} is required"));
        }
    };

    if !(0.0..=100.0).contains(&pct) {
        return Err(format!(
            "fault_injection: {field_name} must be 0.0-100.0, got {pct}"
        ));
    }
    if pct == 0.0 {
        return Err(format!(
            "fault_injection: {field_name} must be greater than 0.0"
        ));
    }

    Ok(pct)
}

impl FaultInjectionPlugin {
    fn decide_faults(&self) -> (bool, bool) {
        let outcome = self.roller.roll_pair(
            self.delay.as_ref().map(|delay| delay.percentage),
            self.abort.as_ref().map(|abort| abort.percentage),
        );
        (outcome.delay_triggered, outcome.abort_triggered)
    }

    fn reject_for_abort(&self, abort: &AbortFault, is_grpc_request: bool) -> PluginResult {
        let mut headers = HashMap::new();
        if is_grpc_request && let Some(grpc_status) = abort.grpc_status {
            headers.insert("grpc-status".to_string(), grpc_status.to_string());
        }
        PluginResult::Reject {
            status_code: abort.status_code,
            body: abort.body.clone(),
            headers,
        }
    }

    fn reject_for_stream_abort(&self, abort: &AbortFault) -> PluginResult {
        PluginResult::Reject {
            status_code: abort.status_code,
            body: String::new(),
            headers: HashMap::new(),
        }
    }
}

/// Private source marker written by a route-local fault. A normal
/// `fault_injected=true` marker intentionally does not suppress sibling
/// `fault_injection` instances; only a route-local action causes a later,
/// priority-overridden proxy-scoped instance to no-op.
pub(crate) const ROUTE_FAULT_INJECTED_METADATA_KEY: &str = "fault_injection.route_applied";

/// Classify only client-visible native gRPC requests from the immutable flavor
/// fixed before plugin hooks run. Earlier plugins may add, remove, or rewrite
/// `content-type`; none of those mutations may change rejection semantics.
pub(crate) fn is_native_grpc_request(ctx: &RequestContext) -> bool {
    ctx.is_native_grpc_request()
}

#[async_trait]
impl Plugin for FaultInjectionPlugin {
    fn name(&self) -> &str {
        "fault_injection"
    }

    fn priority(&self) -> u16 {
        super::priority::FAULT_INJECTION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        NON_UDP_PROTOCOLS
    }

    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.metadata.contains_key(ROUTE_FAULT_INJECTED_METADATA_KEY) {
            return PluginResult::Continue;
        }

        let (delay_triggered, abort_triggered) = self.decide_faults();

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.metadata
            .insert("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            tokio::time::sleep(std::time::Duration::from_millis(d.duration_ms)).await;
            ctx.metadata
                .insert("fault_delay_ms".to_string(), d.duration_ms.to_string());
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.metadata
                .insert("fault_type".to_string(), fault_type.to_string());
            ctx.metadata
                .insert("fault_abort_status".to_string(), a.status_code.to_string());

            return self.reject_for_abort(a, is_native_grpc_request(ctx));
        }

        ctx.metadata
            .insert("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }

    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        let (delay_triggered, abort_triggered) = self.decide_faults();

        if !delay_triggered && !abort_triggered {
            return PluginResult::Continue;
        }

        ctx.insert_metadata("fault_injected".to_string(), "true".to_string());

        if delay_triggered && let Some(d) = self.delay.as_ref() {
            tokio::time::sleep(std::time::Duration::from_millis(d.duration_ms)).await;
            ctx.insert_metadata("fault_delay_ms".to_string(), d.duration_ms.to_string());
        }

        if abort_triggered && let Some(a) = self.abort.as_ref() {
            let fault_type = if delay_triggered {
                "delay_and_abort"
            } else {
                "abort"
            };
            ctx.insert_metadata("fault_type".to_string(), fault_type.to_string());
            ctx.insert_metadata("fault_abort_status".to_string(), a.status_code.to_string());

            return self.reject_for_stream_abort(a);
        }

        ctx.insert_metadata("fault_type".to_string(), "delay".to_string());

        PluginResult::Continue
    }
}
