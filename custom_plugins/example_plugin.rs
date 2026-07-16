//! Example Custom Plugin
//!
//! This is a complete, working example of a custom Ferrum Edge plugin.
//! Copy this file as a starting point for your own plugins.
//!
//! This plugin adds a custom `X-Custom-Gateway` header to every request
//! before it is proxied to the backend, and echoes it back in the response.
//! An optional `request_body_prefix` demonstrates request-body transformation
//! capability metadata used by core composition validation.
//!
//! The `create_plugin` function at the bottom is the only required entry
//! point — the build script discovers this file automatically.

use async_trait::async_trait;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;

use crate::plugins::{Plugin, PluginHttpClient, PluginResult, RequestContext, TransactionSummary};

pub struct ExamplePlugin {
    header_value: String,
    request_body_prefix: Option<Vec<u8>>,
}

impl ExamplePlugin {
    pub fn new(config: &Value) -> Result<Self, String> {
        let request_body_prefix = match config.get("request_body_prefix") {
            None | Some(Value::Null) => None,
            Some(Value::String(prefix)) if prefix.is_empty() => {
                return Err("request_body_prefix must not be empty".to_string());
            }
            Some(Value::String(prefix)) => Some(prefix.as_bytes().to_vec()),
            Some(_) => return Err("request_body_prefix must be a string".to_string()),
        };
        Ok(Self {
            // Read configuration from the plugin's JSON config.
            // In the gateway config, this would look like:
            //   { "plugin_name": "example_plugin", "config": { "header_value": "my-gateway" } }
            header_value: config["header_value"]
                .as_str()
                .unwrap_or("ferrum-custom")
                .to_string(),
            request_body_prefix,
        })
    }
}

#[async_trait]
impl Plugin for ExamplePlugin {
    /// Unique name for this plugin. Must match the file name (without .rs).
    fn name(&self) -> &str {
        "example_plugin"
    }

    /// Execution priority. See `src/plugins/mod.rs` for the priority band guide:
    ///   - 0–999:    Preflight (CORS, IP filtering, correlation IDs)
    ///   - 1000–1999: Authentication (identity verification)
    ///   - 2000–2999: Authorization (access control, rate limiting)
    ///   - 3000–3999: Request transformation
    ///   - 4000–4999: Response transformation
    ///   - 5000:      Default (custom plugins land here if not overridden)
    ///   - 9000–9999: Logging & observability
    fn priority(&self) -> u16 {
        // Default band — runs after transforms, before logging.
        // Override this to control when your plugin executes relative to others.
        super::super::plugins::priority::DEFAULT
    }

    /// Return `true` if your plugin modifies outgoing request headers in
    /// `before_proxy`. This allows the gateway to skip cloning the header
    /// map when no plugin needs to modify it.
    fn modifies_request_headers(&self) -> bool {
        true
    }

    fn modifies_request_body(&self) -> bool {
        self.request_body_prefix.is_some()
    }

    /// Called when a request is first received (before routing).
    /// Return `PluginResult::Reject` to short-circuit with an error response.
    async fn on_request_received(&self, _ctx: &mut RequestContext) -> PluginResult {
        // Example: you could reject requests here based on custom logic.
        PluginResult::Continue
    }

    /// Called just before the request is forwarded to the backend.
    /// Use this to add/modify headers sent to the backend.
    async fn before_proxy(
        &self,
        _ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        headers.insert("x-custom-gateway".to_string(), self.header_value.clone());
        PluginResult::Continue
    }

    async fn transform_request_body(
        &self,
        body: &[u8],
        _content_type: Option<&str>,
        _request_headers: &HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        let prefix = self.request_body_prefix.as_ref()?;
        let mut transformed = Vec::with_capacity(prefix.len() + body.len());
        transformed.extend_from_slice(prefix);
        transformed.extend_from_slice(body);
        Some(transformed)
    }

    /// Called after the backend response is received.
    /// Use this to add/modify response headers sent to the client.
    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        response_headers.insert("x-custom-gateway".to_string(), self.header_value.clone());
        PluginResult::Continue
    }

    /// Called for transaction logging (fire-and-forget, after response is sent).
    async fn log(&self, _summary: &TransactionSummary) {
        // Example: send to a custom logging endpoint, write to a file, etc.
    }

    // ── Optional overrides ──────────────────────────────────────────────────
    //
    // fn is_auth_plugin(&self) -> bool {
    //     // Return `true` if this plugin participates in the authentication phase.
    //     // This lets the gateway include it in auth mode (Single/Multi) logic.
    //     false
    // }
    //
    // fn requires_response_body_buffering(&self) -> bool {
    //     // Return `true` if your plugin needs to inspect or transform the
    //     // response body. This disables streaming for proxies using this plugin.
    //     false
    // }
    //
    // fn warmup_hostnames(&self) -> Vec<String> {
    //     // Return hostnames your plugin will connect to, so the gateway can
    //     // pre-resolve DNS at startup.
    //     vec![]
    // }
}

/// Factory function — called automatically by the build-script-generated registry.
/// The function name `create_plugin` and signature are the convention that every
/// custom plugin file must follow. Must return `Result` so invalid configs are
/// rejected at admission time (admin API, file mode startup, DB mode warnings).
pub fn create_plugin(
    config: &Value,
    _http_client: PluginHttpClient,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    Ok(Some(Arc::new(ExamplePlugin::new(config)?)))
}

pub fn failure_policy() -> crate::plugins::PluginFailurePolicy {
    crate::plugins::PluginFailurePolicy::KeepLastKnownGood
}
