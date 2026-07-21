//! Transaction debugger plugin — detailed per-request diagnostics.
//!
//! Emits debug output via `tracing::debug!` on the `transaction_debug` target,
//! showing the request/response lifecycle: matched proxy, consumer identity,
//! plugin execution timing, backend connection details, and authoritative
//! terminal state. Request and response payloads are never captured. Sensitive
//! headers (Authorization, Cookie, API keys) are automatically redacted.
//! Intended for development and troubleshooting — should not be enabled in
//! production due to information disclosure risk.

use async_trait::async_trait;
use http::header::HeaderName;
use serde_json::Value;
use std::collections::HashMap;

use super::{
    Direction, DisconnectCause, Plugin, PluginResult, RequestContext, StreamTransactionSummary,
    TransactionSummary, WsDisconnectContext,
};
use crate::plugins::utils::metadata_redaction::{REDACTED_PLACEHOLDER, is_sensitive_metadata_key};
use crate::proxy::tcp_proxy::StreamIoSide;

/// Headers that contain sensitive credentials and must be redacted in debug output.
const SENSITIVE_HEADERS: &[&str] = &[
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "api-key",
    "x-api-key",
    "x-goog-api-key",
    "x-auth-token",
    "x-csrf-token",
    "x-xsrf-token",
    "www-authenticate",
    "x-forwarded-authorization",
    "last-event-id",
];

/// Redaction placeholder for sensitive header values.
const REDACTED: &str = "***REDACTED***";

pub struct TransactionDebugger {
    /// Additional header names (lowercase) to redact beyond the built-in list.
    extra_redacted_headers: Vec<String>,
}

impl TransactionDebugger {
    pub fn new(config: &Value) -> Result<Self, String> {
        let object = config
            .as_object()
            .ok_or_else(|| "transaction_debugger: config must be an object".to_string())?;
        if config.get("schema").is_some() || config.get("schema_ref").is_some() {
            return Err(
                "transaction_debugger: 'schema' / 'schema_ref' is not supported \
                 (transaction-log schema customization applies only to log-shipping plugins; \
                 see docs/plugins.md)"
                    .to_string(),
            );
        }
        if config.get("log_request_body").is_some() || config.get("log_response_body").is_some() {
            return Err(
                "transaction_debugger: 'log_request_body' / 'log_response_body' is not supported \
                 because request and response payloads are not captured"
                    .to_string(),
            );
        }

        let mut unknown_keys: Vec<&str> = object
            .keys()
            .map(String::as_str)
            .filter(|key| *key != "redacted_headers")
            .collect();
        if !unknown_keys.is_empty() {
            unknown_keys.sort_unstable();
            return Err(format!(
                "transaction_debugger: unknown configuration keys: {}",
                unknown_keys.join(", ")
            ));
        }

        let extra_redacted_headers =
            optional_header_names(config, "redacted_headers")?.unwrap_or_default();

        Ok(Self {
            extra_redacted_headers,
        })
    }

    /// Stable terminal classification derived from the final HTTP/gRPC summary.
    pub fn classify_http_outcome(summary: &TransactionSummary) -> &'static str {
        if summary.error_class.is_some() {
            "dispatch_error"
        } else if summary.client_disconnected {
            "client_disconnected"
        } else if summary.body_error_class.is_some() {
            "body_error"
        } else if summary.response_streamed && !summary.body_completed {
            "body_incomplete"
        } else if summary.metadata.contains_key("rejection_phase") {
            "rejected"
        } else if summary.metadata.contains_key("mirror_error") {
            "mirror_error"
        } else if summary.grpc_status().is_some_and(|status| status != 0) {
            "grpc_error"
        } else {
            "completed"
        }
    }

    /// Stable terminal classification derived from typed stream teardown state.
    pub fn classify_stream_outcome(summary: &StreamTransactionSummary) -> &'static str {
        if matches!(summary.disconnect_cause, Some(DisconnectCause::IdleTimeout)) {
            "idle_timeout"
        } else if summary.connection_error.is_some()
            || summary.error_class.is_some()
            || summary.disconnect_direction.is_some()
            || matches!(
                summary.disconnect_cause,
                Some(DisconnectCause::RecvError | DisconnectCause::BackendError)
            )
        {
            "stream_error"
        } else if matches!(
            summary.disconnect_cause,
            Some(DisconnectCause::GracefulShutdown)
        ) {
            "graceful_shutdown"
        } else {
            "completed"
        }
    }

    /// Stable terminal classification derived from WebSocket teardown state.
    pub fn classify_ws_outcome(summary: &WsDisconnectContext) -> &'static str {
        // Core relay paths derive all three fields from one failure tuple, but keep each
        // public typed signal authoritative so a partial context cannot look completed.
        if summary.error_class.is_some() || summary.direction.is_some() || summary.io_side.is_some()
        {
            "websocket_error"
        } else {
            "completed"
        }
    }

    /// Returns true if the given header name should be redacted.
    /// Header names are normally lowercased by hyper, but tests/custom callers
    /// may provide different ASCII casing; compare case-insensitively without
    /// allocating.
    fn is_sensitive(&self, ctx: &RequestContext, header_name: &str) -> bool {
        SENSITIVE_HEADERS
            .iter()
            .any(|h| header_name.eq_ignore_ascii_case(h))
            || self
                .extra_redacted_headers
                .iter()
                .any(|h| header_name.eq_ignore_ascii_case(h))
            || ctx.request_header_requires_redaction(header_name)
    }

    /// Create a redacted copy of headers for safe logging.
    fn redact_headers(
        &self,
        ctx: &RequestContext,
        headers: &HashMap<String, String>,
    ) -> HashMap<String, String> {
        headers
            .iter()
            .map(|(k, v)| {
                if self.is_sensitive(ctx, k) {
                    (k.clone(), REDACTED.to_string())
                } else {
                    (k.clone(), v.clone())
                }
            })
            .collect()
    }
}

#[async_trait]
impl Plugin for TransactionDebugger {
    fn name(&self) -> &str {
        "transaction_debugger"
    }

    fn priority(&self) -> u16 {
        super::priority::TRANSACTION_DEBUGGER
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::ALL_PROTOCOLS
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        if tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            let safe_headers = self.redact_headers(ctx, &ctx.headers);
            tracing::debug!(target: "transaction_debug", method = %ctx.method, path = %ctx.path, client_ip = %ctx.client_ip, headers = ?safe_headers, "Incoming request");
        }
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            let safe_headers = self.redact_headers(ctx, response_headers);
            tracing::debug!(target: "transaction_debug", status = response_status, method = %ctx.method, path = %ctx.path, headers = ?safe_headers, "Backend response");
        }
        PluginResult::Continue
    }

    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        if !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            return;
        }
        let outcome = Self::classify_stream_outcome(summary);
        let error_class = summary.error_class.map(|class| class.as_str());
        let disconnect_direction = summary.disconnect_direction.map(direction_label);
        let disconnect_cause = summary.disconnect_cause.map(disconnect_cause_label);
        let request_id = selected_metadata_value(&summary.metadata, "request_id");
        let trace_id = selected_metadata_value(&summary.metadata, "trace_id");
        tracing::debug!(
            target: "transaction_debug",
            outcome = %outcome,
            namespace = %summary.namespace,
            protocol = %summary.protocol,
            proxy_id = %summary.proxy_id,
            proxy_name = %summary.proxy_name.as_deref().unwrap_or("-"),
            client_ip = %summary.client_ip,
            listen_port = summary.listen_port,
            backend_target = %summary.backend_target,
            backend_resolved_ip = %summary.backend_resolved_ip.as_deref().unwrap_or("-"),
            consumer_username = %summary.consumer_username.as_deref().unwrap_or("-"),
            auth_method = %summary.auth_method.unwrap_or("-"),
            connection_error = %summary.connection_error.as_deref().unwrap_or("-"),
            error_class = %error_class.unwrap_or("-"),
            disconnect_direction = %disconnect_direction.unwrap_or("-"),
            disconnect_cause = %disconnect_cause.unwrap_or("-"),
            duration_ms = summary.duration_ms,
            bytes_sent = summary.bytes_sent,
            bytes_received = summary.bytes_received,
            timestamp_connected = %summary.timestamp_connected,
            timestamp_disconnected = %summary.timestamp_disconnected,
            sni_hostname = %summary.sni_hostname.as_deref().unwrap_or("-"),
            request_id = %request_id.unwrap_or("-"),
            trace_id = %trace_id.unwrap_or("-"),
            "Stream terminal diagnostic",
        );
    }

    async fn log(&self, summary: &TransactionSummary) {
        if !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            return;
        }
        let outcome = Self::classify_http_outcome(summary);
        let error_class = summary.error_class.map(|class| class.as_str());
        let body_error_class = summary.body_error_class.map(|class| class.as_str());
        let rejection_phase = selected_metadata_value(&summary.metadata, "rejection_phase");
        let grpc_status = selected_metadata_value(&summary.metadata, "grpc_status");
        let request_id = selected_metadata_value(&summary.metadata, "request_id");
        let trace_id = selected_metadata_value(&summary.metadata, "trace_id");
        tracing::debug!(
            target: "transaction_debug",
            outcome = %outcome,
            namespace = %summary.namespace,
            timestamp_received = %summary.timestamp_received,
            client_ip = %summary.client_ip,
            method = %summary.http_method,
            path = %summary.request_path,
            status = summary.response_status_code,
            proxy_id = %summary.proxy_id.as_deref().unwrap_or("-"),
            proxy_name = %summary.proxy_name.as_deref().unwrap_or("-"),
            backend_target = %summary.backend_target.as_deref().unwrap_or("-"),
            backend_resolved_ip = %summary.backend_resolved_ip.as_deref().unwrap_or("-"),
            consumer_username = %summary.consumer_username.as_deref().unwrap_or("-"),
            auth_method = %summary.auth_method.unwrap_or("-"),
            error_class = %error_class.unwrap_or("-"),
            body_error_class = %body_error_class.unwrap_or("-"),
            response_streamed = summary.response_streamed,
            body_completed = summary.body_completed,
            client_disconnected = summary.client_disconnected,
            bytes_sent = summary.bytes_sent,
            bytes_received = summary.bytes_received,
            rejection_phase = %rejection_phase.unwrap_or("-"),
            grpc_status = %grpc_status.unwrap_or("-"),
            request_id = %request_id.unwrap_or("-"),
            trace_id = %trace_id.unwrap_or("-"),
            latency_total_ms = summary.latency_total_ms,
            latency_backend_ttfb_ms = summary.latency_backend_ttfb_ms,
            latency_backend_total_ms = summary.latency_backend_total_ms,
            latency_plugin_ms = summary.latency_plugin_execution_ms,
            latency_gw_overhead_ms = summary.latency_gateway_overhead_ms,
            "Transaction terminal diagnostic",
        );
    }

    fn requires_ws_disconnect_hooks(&self) -> bool {
        true
    }

    async fn on_ws_disconnect(&self, summary: &WsDisconnectContext) {
        if !tracing::enabled!(target: "transaction_debug", tracing::Level::DEBUG) {
            return;
        }
        let outcome = Self::classify_ws_outcome(summary);
        let direction = summary.direction.map(direction_label);
        let io_side = summary.io_side.map(stream_io_side_label);
        let error_class = summary.error_class.map(|class| class.as_str());
        let request_id = selected_metadata_value(&summary.metadata, "request_id");
        let trace_id = selected_metadata_value(&summary.metadata, "trace_id");
        tracing::debug!(
            target: "transaction_debug",
            outcome = %outcome,
            namespace = %summary.namespace,
            proxy_id = %summary.proxy_id,
            proxy_name = %summary.proxy_name.as_deref().unwrap_or("-"),
            client_ip = %summary.client_ip,
            listen_port = summary.listen_port,
            backend_target = %summary.backend_target,
            consumer_username = %summary.consumer_username.as_deref().unwrap_or("-"),
            auth_method = %summary.auth_method.unwrap_or("-"),
            duration_ms = summary.duration_ms,
            frames_client_to_backend = summary.frames_client_to_backend,
            frames_backend_to_client = summary.frames_backend_to_client,
            bytes_client_to_backend = summary.bytes_client_to_backend,
            bytes_backend_to_client = summary.bytes_backend_to_client,
            disconnect_direction = %direction.unwrap_or("-"),
            io_side = %io_side.unwrap_or("-"),
            error_class = %error_class.unwrap_or("-"),
            request_id = %request_id.unwrap_or("-"),
            trace_id = %trace_id.unwrap_or("-"),
            "WebSocket terminal diagnostic",
        );
    }
}

fn selected_metadata_value<'a>(
    metadata: &'a HashMap<String, String>,
    key: &str,
) -> Option<&'a str> {
    metadata.get(key).map(|value| {
        if is_sensitive_metadata_key(key) {
            REDACTED_PLACEHOLDER
        } else {
            value.as_str()
        }
    })
}

const fn direction_label(direction: Direction) -> &'static str {
    match direction {
        Direction::ClientToBackend => "client_to_backend",
        Direction::BackendToClient => "backend_to_client",
        Direction::Unknown => "unknown",
    }
}

const fn disconnect_cause_label(cause: DisconnectCause) -> &'static str {
    match cause {
        DisconnectCause::IdleTimeout => "idle_timeout",
        DisconnectCause::RecvError => "recv_error",
        DisconnectCause::BackendError => "backend_error",
        DisconnectCause::GracefulShutdown => "graceful_shutdown",
    }
}

const fn stream_io_side_label(side: StreamIoSide) -> &'static str {
    match side {
        StreamIoSide::Read => "read",
        StreamIoSide::Write => "write",
    }
}

fn optional_header_names(
    config: &Value,
    field: &'static str,
) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("transaction_debugger: '{field}' must be an array"));
    };
    let mut headers = Vec::with_capacity(values.len());
    for (idx, value) in values.iter().enumerate() {
        let Some(raw) = value.as_str() else {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must be a string"
            ));
        };
        if raw.is_empty() {
            return Err(format!(
                "transaction_debugger: '{field}[{idx}]' must not be empty"
            ));
        }
        let raw = raw.to_ascii_lowercase();
        let name = HeaderName::from_bytes(raw.as_bytes()).map_err(|_| {
            format!("transaction_debugger: '{field}[{idx}]' is not a valid HTTP header name")
        })?;
        headers.push(name.as_str().to_string());
    }
    Ok(Some(headers))
}
