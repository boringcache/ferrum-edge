//! Pre-resolved plugin cache for O(1) per-request plugin lookup.
//!
//! Plugins are created once at config load time — not per-request. This is
//! critical for stateful plugins (e.g., `rate_limiting`) whose internal DashMap
//! counters must persist across requests. Without caching, a fresh rate limiter
//! would be created per request and limits would never be enforced.
//!
//! Each proxy gets a merged plugin list: global plugins + proxy-scoped plugins,
//! sorted by priority. Pre-computed flags (`requires_response_body_buffering`,
//! `requires_request_body_buffering`, `requires_ws_frame_hooks`, and
//! protocol-scoped response-stream hooks) enable O(1)
//! upper-bound decisions on the hot path instead of per-request plugin
//! iteration.
//!
//! Incremental updates via `apply_delta()` preserve unchanged proxy plugin
//! lists (including their stateful instances) and only rebuild affected proxies.

use arc_swap::ArcSwap;
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use crate::config::types::{
    CountryMmdbLoadSession, GatewayConfig, MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES, PluginScope,
};
use tracing::{error, warn};

use crate::adaptive_concurrency::{
    AdaptiveConcurrencyConfig, AdaptiveConcurrencyKeyBy, AdaptiveConcurrencyLimiter,
    adaptive_concurrency_scope,
};
use crate::config::types::PluginConfig;
use crate::plugins::utils::jwks_cache::retain_active_requirements;
use crate::plugins::{
    Plugin, PluginFailurePolicy, PluginHttpClient, ProxyProtocol, create_plugin_with_http_client,
};

// ---------------------------------------------------------------------------
// PriorityOverridePlugin — wraps any plugin with a user-specified priority
// ---------------------------------------------------------------------------

use crate::plugins::{
    BackendPathPolicyPhase, PluginResult, RequestContext, ResponseStreamInspector,
    StreamConnectionContext, StreamTransactionSummary, TransactionSummary, UdpDatagramContext,
    UdpDatagramVerdict, WebSocketFrameDirection,
};
use async_trait::async_trait;

/// Thin wrapper that overrides a plugin's built-in priority with a
/// user-configured value from `PluginConfig.priority_override`.
struct PriorityOverridePlugin {
    inner: Arc<dyn Plugin>,
    priority: u16,
}

/// Per-chain CORS wrapper. It avoids mutating a shared plugin instance when a
/// proxy-group or global CORS policy participates in a multiple-instance chain
/// for only some proxies.
struct DeferredCorsPlugin {
    inner: Arc<dyn Plugin>,
}

#[async_trait]
impl Plugin for DeferredCorsPlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }

    fn priority(&self) -> u16 {
        self.inner.priority()
    }

    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        self.inner.supported_protocols()
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        ctx.cors_state.defer_finalization = true;
        self.inner.on_request_received(ctx).await
    }

    fn is_deferred_cors_wrapper(&self) -> bool {
        true
    }

    async fn after_proxy(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &mut std::collections::HashMap<String, String>,
    ) -> PluginResult {
        PluginResult::Continue
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        false
    }
}

const MESH_ROUTE_DISPATCH_NAME: &str = "mesh_route_dispatch";
const MESH_ROUTE_DISPATCH_FINALIZER_NAME: &str = "__mesh_route_dispatch_finalizer";
const CORS_NAME: &str = "cors";

/// Cache-internal sentinel placed immediately after the last route-dispatch
/// instance. Individual instances stage fail-closed misses on `RequestContext`;
/// this sentinel rejects only when the aggregate chain produced neither a
/// match nor an override from an earlier routing plugin.
struct MeshRouteDispatchFinalizer {
    priority: u16,
}

#[async_trait]
impl Plugin for MeshRouteDispatchFinalizer {
    fn name(&self) -> &str {
        MESH_ROUTE_DISPATCH_FINALIZER_NAME
    }

    fn priority(&self) -> u16 {
        self.priority
    }

    fn supported_protocols(&self) -> &'static [crate::plugins::ProxyProtocol] {
        crate::plugins::HTTP_FAMILY_PROTOCOLS
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        _headers: &mut std::collections::HashMap<String, String>,
    ) -> PluginResult {
        if !std::mem::take(&mut ctx.mesh_route_dispatch_reject_unmatched)
            || ctx.mesh_route_dispatch_matched
            || ctx.has_route_overrides()
        {
            return PluginResult::Continue;
        }
        crate::plugins::mesh_route_dispatch::reject_unmatched_result()
    }
}

/// Enable aggregate unmatched handling and install exactly one finalizer at
/// the execution boundary after the final `mesh_route_dispatch` instance.
/// Existing finalizers may be present when a global list is cloned during an
/// incremental rebuild, so remove them before recomputing the boundary.
fn install_mesh_route_dispatch_finalizer(plugins: &mut Vec<Arc<dyn Plugin>>) -> Result<(), String> {
    plugins.retain(|plugin| plugin.name() != MESH_ROUTE_DISPATCH_FINALIZER_NAME);
    let first_index = plugins
        .iter()
        .position(|plugin| plugin.name() == MESH_ROUTE_DISPATCH_NAME);
    let Some(last_index) = plugins
        .iter()
        .rposition(|plugin| plugin.name() == MESH_ROUTE_DISPATCH_NAME)
    else {
        return Ok(());
    };
    let first_index = first_index.unwrap_or(last_index);

    if plugins[first_index..=last_index].iter().any(|plugin| {
        plugin.name() != MESH_ROUTE_DISPATCH_NAME
            && plugin
                .supported_protocols()
                .iter()
                .any(|protocol| crate::plugins::HTTP_FAMILY_PROTOCOLS.contains(protocol))
    }) {
        return Err(
            "mesh_route_dispatch instances must remain contiguous in HTTP-family chains so reject_unmatched is finalized before later short-circuit plugins; remove priority overrides that interleave another HTTP-family plugin"
                .to_string(),
        );
    }

    for plugin in plugins
        .iter()
        .filter(|plugin| plugin.name() == MESH_ROUTE_DISPATCH_NAME)
    {
        plugin.enable_deferred_unmatched_rejection();
    }
    let priority = plugins[last_index].priority();
    plugins.insert(
        last_index + 1,
        Arc::new(MeshRouteDispatchFinalizer { priority }),
    );
    Ok(())
}

/// Install one aggregate CORS boundary after every attached CORS instance has
/// evaluated the request. The chain must remain contiguous so an intervening
/// short-circuit plugin cannot bypass a later CORS policy.
fn install_cors_finalizer(plugins: &mut Vec<Arc<dyn Plugin>>) -> Result<(), String> {
    plugins.retain(|plugin| plugin.name() != crate::plugins::cors::CORS_FINALIZER_NAME);
    let Some(first_index) = plugins.iter().position(|plugin| plugin.name() == CORS_NAME) else {
        return Ok(());
    };
    let Some(last_index) = plugins
        .iter()
        .rposition(|plugin| plugin.name() == CORS_NAME)
    else {
        return Err("cors cache invariant lost its first instance".to_string());
    };
    if first_index == last_index {
        return Ok(());
    }
    if plugins[first_index..=last_index].iter().any(|plugin| {
        plugin.name() != CORS_NAME
            && plugin
                .supported_protocols()
                .iter()
                .any(|protocol| crate::plugins::HTTP_GRPC_PROTOCOLS.contains(protocol))
    }) {
        return Err(
            "cors instances must remain contiguous in HTTP/gRPC chains so their origin and preflight method/header policies can be intersected before any request short-circuits; remove priority overrides that interleave another HTTP/gRPC plugin"
                .to_string(),
        );
    }
    for plugin in &mut plugins[first_index..=last_index] {
        if plugin.name() == CORS_NAME && !plugin.is_deferred_cors_wrapper() {
            *plugin = Arc::new(DeferredCorsPlugin {
                inner: Arc::clone(plugin),
            });
        }
    }
    let priority = plugins[last_index].priority();
    plugins.insert(
        last_index + 1,
        Arc::new(crate::plugins::cors::CorsFinalizer::new(priority)),
    );
    Ok(())
}

/// HMAC authenticates the exact client-visible request body and digest. A later
/// body transform would make the backend-visible bytes disagree with the
/// signed `Digest`/`Content-Digest` and `Authorization` fields. Reject that
/// composition at cache build time instead of forwarding stale integrity
/// metadata or silently weakening authentication.
fn validate_hmac_request_transform_composition(plugins: &[Arc<dyn Plugin>]) -> Result<(), String> {
    for protocol in ALL_PROXY_PROTOCOLS {
        if !plugins
            .iter()
            .filter(|plugin| plugin.supported_protocols().contains(&protocol))
            .any(|plugin| plugin.name() == "hmac_auth")
        {
            continue;
        }
        if let Some(transformer) = plugins
            .iter()
            .filter(|plugin| plugin.supported_protocols().contains(&protocol))
            .find(|plugin| plugin.modifies_request_body())
        {
            return Err(format!(
                "hmac_auth cannot be combined with request-body transformer '{}' for protocol {:?} on the same proxy; HMAC authenticates the client-to-gateway representation and Ferrum will not forward stale signed digest metadata",
                transformer.name(),
                protocol
            ));
        }
    }
    Ok(())
}

#[async_trait]
impl Plugin for PriorityOverridePlugin {
    fn name(&self) -> &str {
        self.inner.name()
    }
    fn country_mmdb_snapshot(&self) -> Option<&crate::config::types::CountryMmdbSnapshot> {
        self.inner.country_mmdb_snapshot()
    }
    fn priority(&self) -> u16 {
        self.priority
    }
    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        self.inner.on_request_received(ctx).await
    }
    async fn authenticate(
        &self,
        ctx: &mut RequestContext,
        consumer_index: &crate::consumer_index::ConsumerIndex,
    ) -> PluginResult {
        self.inner.authenticate(ctx, consumer_index).await
    }
    fn mark_query_credentials_for_redaction(&self, ctx: &mut RequestContext) {
        self.inner.mark_query_credentials_for_redaction(ctx);
    }
    fn request_headers_to_redact(&self) -> &[String] {
        self.inner.request_headers_to_redact()
    }
    async fn authorize(&self, ctx: &mut RequestContext) -> PluginResult {
        self.inner.authorize(ctx).await
    }
    fn is_authorize_plugin(&self) -> bool {
        self.inner.is_authorize_plugin()
    }
    fn modifies_request_headers(&self) -> bool {
        self.inner.modifies_request_headers()
    }
    fn modifies_request_body(&self) -> bool {
        self.inner.modifies_request_body()
    }
    fn requires_request_body_before_before_proxy(&self) -> bool {
        self.inner.requires_request_body_before_before_proxy()
    }
    fn requires_request_body_before_authenticate(&self) -> bool {
        self.inner.requires_request_body_before_authenticate()
    }
    fn should_buffer_request_body_before_authenticate(
        &self,
        ctx: &RequestContext,
        consumer_index: &crate::consumer_index::ConsumerIndex,
    ) -> bool {
        self.inner
            .should_buffer_request_body_before_authenticate(ctx, consumer_index)
    }
    fn requires_request_body_before_authorize(&self) -> bool {
        self.inner.requires_request_body_before_authorize()
    }
    fn requires_request_body_buffering(&self) -> bool {
        self.inner.requires_request_body_buffering()
    }
    fn needs_request_body_bytes(&self) -> bool {
        self.inner.needs_request_body_bytes()
    }
    fn needs_request_body_digests(&self) -> bool {
        self.inner.needs_request_body_digests()
    }
    fn needs_request_body_text(&self) -> bool {
        self.inner.needs_request_body_text()
    }
    fn request_body_buffer_limit(&self) -> Option<usize> {
        self.inner.request_body_buffer_limit()
    }
    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut std::collections::HashMap<String, String>,
    ) -> PluginResult {
        self.inner.before_proxy(ctx, headers).await
    }
    fn defer_before_proxy_until_backend_path_resolved(&self) -> bool {
        self.inner.defer_before_proxy_until_backend_path_resolved()
    }
    fn deferred_before_proxy_may_change_routing_headers(&self) -> bool {
        self.inner
            .deferred_before_proxy_may_change_routing_headers()
    }
    fn requires_backend_path_resolution(&self) -> bool {
        self.inner.requires_backend_path_resolution()
    }
    async fn on_backend_path_resolved(
        &self,
        ctx: &mut RequestContext,
        backend_path: &str,
        phase: BackendPathPolicyPhase,
    ) -> PluginResult {
        self.inner
            .on_backend_path_resolved(ctx, backend_path, phase)
            .await
    }
    fn enable_deferred_unmatched_rejection(&self) {
        self.inner.enable_deferred_unmatched_rejection();
    }
    fn is_backend_admission_plugin(&self) -> bool {
        self.inner.is_backend_admission_plugin()
    }
    fn try_backend_admission(
        &self,
        ctx: &RequestContext,
        admission: &crate::plugins::BackendAdmissionContext<'_>,
    ) -> crate::plugins::BackendAdmissionDecision {
        self.inner.try_backend_admission(ctx, admission)
    }
    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        self.inner.should_buffer_request_body(ctx)
    }
    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut std::collections::HashMap<String, String>,
    ) -> PluginResult {
        self.inner
            .after_proxy(ctx, response_status, response_headers)
            .await
    }
    fn is_initial_response_header_policy(&self) -> bool {
        self.inner.is_initial_response_header_policy()
    }
    fn apply_initial_response_header_policy(
        &self,
        response_headers: &mut std::collections::HashMap<String, String>,
    ) {
        self.inner
            .apply_initial_response_header_policy(response_headers);
    }
    fn initial_response_header_policy_names(&self) -> &[String] {
        self.inner.initial_response_header_policy_names()
    }
    fn may_modify_response_content_type(
        &self,
        ctx: &RequestContext,
        response_content_type: Option<&str>,
    ) -> bool {
        self.inner
            .may_modify_response_content_type(ctx, response_content_type)
    }
    fn may_add_response_cache_control_no_transform(
        &self,
        ctx: &RequestContext,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .may_add_response_cache_control_no_transform(ctx, response_headers)
    }
    fn may_add_response_strong_etag(
        &self,
        ctx: &RequestContext,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .may_add_response_strong_etag(ctx, response_headers)
    }
    fn simulate_after_proxy_response_headers(
        &self,
        ctx: &mut RequestContext,
        response_headers: &mut std::collections::HashMap<String, String>,
    ) {
        self.inner
            .simulate_after_proxy_response_headers(ctx, response_headers);
    }
    fn needs_later_response_cache_control_no_transform(&self) -> bool {
        self.inner.needs_later_response_cache_control_no_transform()
    }
    fn needs_later_response_strong_etag(&self) -> bool {
        self.inner.needs_later_response_strong_etag()
    }
    fn applies_after_proxy_on_reject(&self) -> bool {
        self.inner.applies_after_proxy_on_reject()
    }
    fn may_replace_rejection_response(&self) -> bool {
        self.inner.may_replace_rejection_response()
    }
    fn warn_on_rejection_response_replacement(&self) -> bool {
        self.inner.warn_on_rejection_response_replacement()
    }
    fn requires_response_body_buffering(&self) -> bool {
        self.inner.requires_response_body_buffering()
    }
    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        self.inner.should_buffer_response_body(ctx)
    }
    fn may_release_response_body_under_retries(&self, ctx: &RequestContext) -> bool {
        self.inner.may_release_response_body_under_retries(ctx)
    }
    fn should_release_response_body_under_retries(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner.should_release_response_body_under_retries(
            ctx,
            response_status,
            response_headers,
        )
    }
    fn should_release_response_body_before_content_type_rewrite(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .should_release_response_body_before_content_type_rewrite(
                ctx,
                response_status,
                response_headers,
            )
    }
    fn should_release_response_body_for_later_no_transform(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .should_release_response_body_for_later_no_transform(
                ctx,
                response_status,
                response_headers,
            )
    }
    fn should_release_response_body_for_later_strong_etag(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        self.inner
            .should_release_response_body_for_later_strong_etag(
                ctx,
                response_status,
                response_headers,
            )
    }
    fn should_buffer_response_body_for_content_type(
        &self,
        ctx: &RequestContext,
        content_type: Option<&str>,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> bool {
        // Must forward, not fall back to the trait default (which ignores
        // content-type): a priority-overridden inspect-mode policy needs the
        // buffer->stream downgrade for SSE, else it buffers an unbounded stream.
        self.inner.should_buffer_response_body_for_content_type(
            ctx,
            content_type,
            response_status,
            response_headers,
        )
    }
    async fn on_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner
            .on_response_body(ctx, response_status, response_headers, body)
            .await
    }
    async fn normalize_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .normalize_response_body_with_context(
                ctx,
                response_status,
                body,
                content_type,
                response_headers,
            )
            .await
    }
    async fn transform_request_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_request_body(body, content_type, request_headers)
            .await
    }
    async fn transform_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        request_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_request_body_with_context(ctx, body, content_type, request_headers)
            .await
    }
    async fn on_final_request_body(
        &self,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner.on_final_request_body(headers, body).await
    }
    async fn on_final_request_body_with_context(
        &self,
        ctx: &mut RequestContext,
        headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner
            .on_final_request_body_with_context(ctx, headers, body)
            .await
    }
    fn needs_final_request_body_context(&self) -> bool {
        self.inner.needs_final_request_body_context()
    }
    async fn transform_response_body(
        &self,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_response_body(body, content_type, response_headers)
            .await
    }
    async fn transform_response_body_with_context(
        &self,
        ctx: &mut RequestContext,
        body: &[u8],
        content_type: Option<&str>,
        response_headers: &std::collections::HashMap<String, String>,
    ) -> Option<Vec<u8>> {
        self.inner
            .transform_response_body_with_context(ctx, body, content_type, response_headers)
            .await
    }
    fn on_response_body_transformed(
        &self,
        ctx: &mut RequestContext,
        response_headers: &mut std::collections::HashMap<String, String>,
    ) {
        self.inner
            .on_response_body_transformed(ctx, response_headers);
    }
    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        self.inner
            .on_final_response_body(ctx, response_status, response_headers, body)
            .await
    }
    fn requires_response_committed_hook(&self) -> bool {
        self.inner.requires_response_committed_hook()
    }
    async fn on_response_committed(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &std::collections::HashMap<String, String>,
        body: &[u8],
    ) {
        self.inner
            .on_response_committed(ctx, response_status, response_headers, body)
            .await;
    }
    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        outcome: &crate::proxy::deferred_log::BodyOutcome,
    ) {
        self.inner
            .on_response_stream_terminated(ctx, response_status, outcome)
            .await;
    }
    async fn log(&self, summary: &TransactionSummary) {
        self.inner.log(summary).await;
    }
    fn is_auth_plugin(&self) -> bool {
        self.inner.is_auth_plugin()
    }
    fn authentication_challenge(&self) -> Option<&'static str> {
        self.inner.authentication_challenge()
    }
    fn start_background_tasks(&self) -> Result<(), String> {
        self.inner.start_background_tasks()
    }
    fn warmup_hostnames(&self) -> Vec<String> {
        self.inner.warmup_hostnames()
    }
    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        self.inner.supported_protocols()
    }
    fn tracked_keys_count(&self) -> Option<usize> {
        self.inner.tracked_keys_count()
    }
    async fn on_stream_connect(&self, ctx: &mut StreamConnectionContext) -> PluginResult {
        self.inner.on_stream_connect(ctx).await
    }
    async fn on_stream_disconnect(&self, summary: &StreamTransactionSummary) {
        self.inner.on_stream_disconnect(summary).await;
    }
    fn requires_ws_frame_hooks(&self) -> bool {
        self.inner.requires_ws_frame_hooks()
    }
    async fn on_ws_frame(
        &self,
        proxy_id: &str,
        connection_id: u64,
        direction: WebSocketFrameDirection,
        message: &tokio_tungstenite::tungstenite::Message,
    ) -> Option<tokio_tungstenite::tungstenite::Message> {
        self.inner
            .on_ws_frame(proxy_id, connection_id, direction, message)
            .await
    }
    fn requires_response_stream_hooks(&self) -> bool {
        self.inner.requires_response_stream_hooks()
    }
    fn on_response_stream_selected(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) {
        self.inner
            .on_response_stream_selected(ctx, response_status, content_type);
    }
    fn forces_reqwest_dispatch(&self, ctx: &RequestContext) -> bool {
        self.inner.forces_reqwest_dispatch(ctx)
    }
    fn response_stream_inspector(
        &self,
        ctx: &RequestContext,
        response_status: u16,
        content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        self.inner
            .response_stream_inspector(ctx, response_status, content_type)
    }
    fn requires_udp_datagram_hooks(&self) -> bool {
        self.inner.requires_udp_datagram_hooks()
    }
    fn requires_stream_first_bytes(&self) -> bool {
        self.inner.requires_stream_first_bytes()
    }
    fn requires_stream_first_bytes_decrypted(&self) -> bool {
        self.inner.requires_stream_first_bytes_decrypted()
    }
    fn stream_first_bytes_min_len(&self) -> usize {
        self.inner.stream_first_bytes_min_len()
    }
    async fn on_udp_datagram(&self, ctx: &UdpDatagramContext<'_>) -> UdpDatagramVerdict {
        self.inner.on_udp_datagram(ctx).await
    }
    fn requires_ws_disconnect_hooks(&self) -> bool {
        self.inner.requires_ws_disconnect_hooks()
    }
    async fn on_ws_disconnect(&self, ctx: &crate::plugins::WsDisconnectContext) {
        self.inner.on_ws_disconnect(ctx).await;
    }
    fn requires_decoded_query_params(&self) -> bool {
        self.inner.requires_decoded_query_params()
    }
    fn active_jwks_uris(&self) -> Vec<String> {
        self.inner.active_jwks_uris()
    }
    fn active_jwks_refresh_requirements(&self) -> Vec<(String, Duration)> {
        self.inner.active_jwks_refresh_requirements()
    }
}

/// Try to create a plugin and apply `priority_override` from the plugin config.
///
/// Enabled plugin configs are load-bearing configuration: unknown plugin names
/// and required-plugin validation failures reject the whole cache generation.
/// Optional plugins may be omitted only when their registration metadata allows
/// fail-open behavior.
fn try_create_plugin(
    pc: &PluginConfig,
    gateway_config: &GatewayConfig,
    http_client: &PluginHttpClient,
    country_mmdb_load_session: &CountryMmdbLoadSession,
    current_adaptive_states: &AdaptiveConcurrencyInstanceMap,
    staged_adaptive_states: &mut AdaptiveConcurrencyInstanceMap,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    let created = if pc.plugin_name == "adaptive_concurrency" {
        create_adaptive_concurrency_plugin(
            pc,
            gateway_config,
            http_client,
            current_adaptive_states,
            staged_adaptive_states,
        )
    } else if pc.plugin_name == "geo_restriction" {
        crate::plugins::geo_restriction::GeoRestriction::new_with_load_session(
            &pc.config,
            country_mmdb_load_session,
        )
        .map(|plugin| Some(Arc::new(plugin) as Arc<dyn Plugin>))
    } else {
        create_plugin_with_http_client(&pc.plugin_name, &pc.config, http_client.clone())
    };

    match created {
        Ok(Some(plugin)) => {
            let plugin: Arc<dyn Plugin> = if let Some(priority) = pc.priority_override {
                Arc::new(PriorityOverridePlugin {
                    inner: plugin,
                    priority,
                })
            } else {
                plugin
            };
            Ok(Some(plugin))
        }
        Ok(None) => {
            if crate::plugins::removed_plugin_registration(&pc.plugin_name).is_some() {
                let msg = format!(
                    "Removed security plugin '{}' (plugin_config_id={}) is not supported; migrate to a supported auth plugin before startup/reload",
                    pc.plugin_name, pc.id
                );
                error!("FATAL: {}", msg);
                Err(msg)
            } else {
                let msg = format!(
                    "Unknown enabled plugin '{}' (plugin_config_id={}, scope={:?}, proxy_id={})",
                    pc.plugin_name,
                    pc.id,
                    pc.scope,
                    pc.proxy_id.as_deref().unwrap_or("<none>")
                );
                error!("Config rejected: {}", msg);
                Err(msg)
            }
        }
        Err(e) => {
            let failure_policy = crate::plugins::plugin_failure_policy(&pc.plugin_name)
                .unwrap_or(PluginFailurePolicy::FailClosed);
            let msg = format!(
                "Plugin '{}' (plugin_config_id={}, scope={:?}, proxy_id={}) config validation failed: {}",
                pc.plugin_name,
                pc.id,
                pc.scope,
                pc.proxy_id.as_deref().unwrap_or("<none>"),
                e
            );
            if failure_policy == PluginFailurePolicy::OptionalFailOpen {
                warn!("Optional plugin omitted after validation failure: {}", msg);
                Ok(None)
            } else {
                error!("Config rejected: {}", msg);
                Err(msg)
            }
        }
    }
}

/// A list of plugins shared across requests via Arc.
type PluginList = Arc<Vec<Arc<dyn Plugin>>>;
/// Map from proxy_id to its pre-resolved plugin list.
type ProxyPluginMap = HashMap<String, PluginList>;
/// Map from proxy_id to whether any plugin requires response body buffering.
type BufferingMap = HashMap<String, bool>;
/// Map from proxy_id to whether any plugin may require request body buffering
/// for at least some requests.
type RequestBufferingMap = HashMap<String, bool>;
/// Map from proxy_id to whether any plugin requires per-frame WebSocket hooks.
type WsFrameMap = HashMap<String, bool>;
/// Map from proxy_group plugin_config_id to its shared plugin instance.
type ProxyGroupInstanceMap = HashMap<String, ProxyGroupPluginInstance>;
type HmacCompositionPluginMap<'a> =
    HashMap<(&'a str, &'a str), (&'a PluginConfig, Arc<dyn Plugin>)>;

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct CountryMmdbPluginId {
    namespace: String,
    plugin_config_id: String,
}

type CountryMmdbPluginInstanceMap = HashMap<CountryMmdbPluginId, Arc<dyn Plugin>>;

fn country_mmdb_plugin_id(plugin_config: &PluginConfig) -> CountryMmdbPluginId {
    CountryMmdbPluginId {
        namespace: plugin_config.namespace.clone(),
        plugin_config_id: plugin_config.id.clone(),
    }
}

fn country_mmdb_plugin_is_active(config: &GatewayConfig, plugin_config: &PluginConfig) -> bool {
    if !plugin_config.enabled || plugin_config.plugin_name != "geo_restriction" {
        return false;
    }
    match &plugin_config.scope {
        PluginScope::Global => true,
        PluginScope::Proxy => plugin_config.proxy_id.as_ref().is_some_and(|proxy_id| {
            config.proxies.iter().any(|proxy| {
                &proxy.id == proxy_id
                    && proxy
                        .plugins
                        .iter()
                        .any(|association| association.plugin_config_id == plugin_config.id)
            })
        }),
        PluginScope::ProxyGroup => config.proxies.iter().any(|proxy| {
            proxy
                .plugins
                .iter()
                .any(|association| association.plugin_config_id == plugin_config.id)
        }),
    }
}

/// Whether an incremental cache stage would construct at least one active geo
/// plugin and therefore needs an off-thread MMDB validation handoff first.
pub(crate) fn country_mmdb_preload_required(
    config: &GatewayConfig,
    proxy_ids_to_rebuild: &HashSet<String>,
    rebuild_globals: bool,
) -> bool {
    config.plugin_configs.iter().any(|plugin_config| {
        if !country_mmdb_plugin_is_active(config, plugin_config) {
            return false;
        }
        match &plugin_config.scope {
            PluginScope::Global => rebuild_globals,
            PluginScope::Proxy => plugin_config
                .proxy_id
                .as_ref()
                .is_some_and(|proxy_id| proxy_ids_to_rebuild.contains(proxy_id)),
            PluginScope::ProxyGroup => config.proxies.iter().any(|proxy| {
                proxy_ids_to_rebuild.contains(&proxy.id)
                    && proxy
                        .plugins
                        .iter()
                        .any(|association| association.plugin_config_id == plugin_config.id)
            }),
        }
    })
}

#[allow(clippy::too_many_arguments)]
fn try_create_plugin_for_cache(
    plugin_config: &PluginConfig,
    gateway_config: &GatewayConfig,
    http_client: &PluginHttpClient,
    country_mmdb_load_session: &CountryMmdbLoadSession,
    forced_country_mmdb_instances: Option<&CountryMmdbPluginInstanceMap>,
    country_mmdb_instances: &mut CountryMmdbPluginInstanceMap,
    current_adaptive_states: &AdaptiveConcurrencyInstanceMap,
    staged_adaptive_states: &mut AdaptiveConcurrencyInstanceMap,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    let country_mmdb_id = (plugin_config.plugin_name == "geo_restriction")
        .then(|| country_mmdb_plugin_id(plugin_config));
    let plugin = if let Some(forced) = forced_country_mmdb_instances
        && let Some(country_mmdb_id) = &country_mmdb_id
        && let Some(plugin) = forced.get(country_mmdb_id)
    {
        Some(Arc::clone(plugin))
    } else {
        try_create_plugin(
            plugin_config,
            gateway_config,
            http_client,
            country_mmdb_load_session,
            current_adaptive_states,
            staged_adaptive_states,
        )?
    };
    if let (Some(country_mmdb_id), Some(plugin)) = (country_mmdb_id, &plugin) {
        country_mmdb_instances.insert(country_mmdb_id, Arc::clone(plugin));
    }
    Ok(plugin)
}

fn replace_country_mmdb_instances(
    plugins: &PluginList,
    replacements: &HashMap<usize, Arc<dyn Plugin>>,
) -> (PluginList, bool) {
    let mut changed = false;
    let plugins = plugins
        .iter()
        .map(|plugin| {
            let pointer = Arc::as_ptr(plugin) as *const () as usize;
            if let Some(replacement) = replacements.get(&pointer) {
                changed = true;
                Arc::clone(replacement)
            } else {
                Arc::clone(plugin)
            }
        })
        .collect();
    (Arc::new(plugins), changed)
}

fn country_mmdb_snapshot_bytes(
    proxy_plugins: &ProxyPluginMap,
    global_plugins: &[Arc<dyn Plugin>],
) -> Result<u64, String> {
    let mut snapshots = HashSet::new();
    let mut bytes = 0u64;
    for plugin in global_plugins
        .iter()
        .chain(proxy_plugins.values().flat_map(|plugins| plugins.iter()))
    {
        let Some(snapshot) = plugin.country_mmdb_snapshot() else {
            continue;
        };
        let pointer = snapshot as *const _ as usize;
        if !snapshots.insert(pointer) {
            continue;
        }
        bytes = bytes.checked_add(snapshot.size_bytes()).ok_or_else(|| {
            "MaxMind database resulting-generation snapshot size overflow".to_string()
        })?;
        if bytes > MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES {
            return Err(format!(
                "MaxMind database aggregate snapshot budget exceeded: the resulting plugin-cache generation retains {bytes} bytes across distinct snapshots; maximum aggregate size is {MAX_COUNTRY_MMDB_AGGREGATE_SIZE_BYTES} bytes"
            ));
        }
    }
    Ok(bytes)
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct AdaptiveConcurrencyPolicyId {
    namespace: String,
    plugin_config_id: String,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AdaptiveConcurrencyRouteKey {
    scope: String,
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq)]
struct AdaptiveConcurrencyRouteOverride {
    proxy_id: String,
    plugin_name: String,
    effective_priority: u16,
    destination_fingerprint: serde_json::Value,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct AdaptiveConcurrencyUpstreamRoute {
    scope: String,
    upstream_id: String,
    subset: Option<String>,
    backend_port: u16,
    port_override_keys: Vec<u16>,
    resolved_port_override_keys: Vec<u16>,
}

#[derive(Clone, Debug, PartialEq)]
struct AdaptiveConcurrencyRouteDefinition {
    protected_proxy_ids: Vec<String>,
    keys: Vec<AdaptiveConcurrencyRouteKey>,
    overrides: Vec<AdaptiveConcurrencyRouteOverride>,
    upstream_routes: Vec<AdaptiveConcurrencyUpstreamRoute>,
}

#[derive(Clone)]
struct AdaptiveConcurrencyInstance {
    limiter: Arc<AdaptiveConcurrencyLimiter>,
    config: Arc<AdaptiveConcurrencyConfig>,
    config_value: serde_json::Value,
    scope: PluginScope,
    proxy_id: Option<String>,
    route_definition: AdaptiveConcurrencyRouteDefinition,
    generation: u64,
    reset_tracking_space: bool,
}

type AdaptiveConcurrencyInstanceMap =
    HashMap<AdaptiveConcurrencyPolicyId, AdaptiveConcurrencyInstance>;

fn adaptive_concurrency_policy_id(pc: &PluginConfig) -> AdaptiveConcurrencyPolicyId {
    AdaptiveConcurrencyPolicyId {
        namespace: pc.namespace.clone(),
        plugin_config_id: pc.id.clone(),
    }
}

fn adaptive_definition_matches(
    state: &AdaptiveConcurrencyInstance,
    pc: &PluginConfig,
    route_definition: &AdaptiveConcurrencyRouteDefinition,
) -> bool {
    state.config_value == pc.config
        && state.scope == pc.scope
        && state.proxy_id == pc.proxy_id
        && state.route_definition.eq(route_definition)
}

fn scoped_plugin_config_applies_to_proxy(
    pc: &PluginConfig,
    proxy: &crate::config::types::Proxy,
) -> bool {
    match &pc.scope {
        PluginScope::Global => false,
        PluginScope::Proxy => {
            pc.proxy_id.as_deref() == Some(proxy.id.as_str())
                && proxy
                    .plugins
                    .iter()
                    .any(|association| association.plugin_config_id == pc.id)
        }
        PluginScope::ProxyGroup => proxy
            .plugins
            .iter()
            .any(|association| association.plugin_config_id == pc.id),
    }
}

fn plugin_config_effectively_applies_to_proxy(
    pc: &PluginConfig,
    proxy: &crate::config::types::Proxy,
    config: &GatewayConfig,
) -> bool {
    if !pc.enabled {
        return false;
    }
    match &pc.scope {
        PluginScope::Global => !config.plugin_configs.iter().any(|candidate| {
            candidate.enabled
                && candidate.plugin_name == pc.plugin_name
                && scoped_plugin_config_applies_to_proxy(candidate, proxy)
        }),
        PluginScope::Proxy | PluginScope::ProxyGroup => {
            scoped_plugin_config_applies_to_proxy(pc, proxy)
        }
    }
}

fn target_matches_subset(
    upstream: &crate::config::types::Upstream,
    target: &crate::config::types::UpstreamTarget,
    subset_name: Option<&str>,
) -> bool {
    let Some(subset_name) = subset_name else {
        return true;
    };
    upstream
        .subsets
        .as_ref()
        .and_then(|subsets| subsets.iter().find(|subset| subset.name == subset_name))
        .is_some_and(|subset| {
            subset
                .labels
                .iter()
                .all(|(key, value)| target.tags.get(key) == Some(value))
        })
}

fn push_upstream_route(
    keys: &mut Vec<AdaptiveConcurrencyRouteKey>,
    upstream_routes: &mut Vec<AdaptiveConcurrencyUpstreamRoute>,
    scope: String,
    upstream_id: &str,
    subset: Option<&str>,
    backend_port: u16,
    upstream: Option<&crate::config::types::Upstream>,
) {
    let port_override_keys = upstream
        .map(adaptive_concurrency_port_override_keys)
        .unwrap_or_default();
    let resolved_port_override_keys = upstream
        .map(adaptive_concurrency_resolved_port_override_keys)
        .unwrap_or_default();
    let port_scope = upstream.and_then(|upstream| {
        adaptive_concurrency_upstream_port_scope(
            backend_port,
            &port_override_keys,
            &resolved_port_override_keys,
            &upstream.targets,
        )
    });
    upstream_routes.push(AdaptiveConcurrencyUpstreamRoute {
        scope: scope.clone(),
        upstream_id: upstream_id.to_string(),
        subset: subset.map(ToOwned::to_owned),
        backend_port,
        port_override_keys,
        resolved_port_override_keys,
    });
    let key_count = keys.len();
    if let Some(upstream) = upstream {
        keys.extend(
            upstream
                .targets
                .iter()
                .filter(|target| target_matches_subset(upstream, target, subset))
                .filter(|target| {
                    port_scope.is_none_or(|port| target.dispatch_policy_port() == port)
                })
                .map(|target| AdaptiveConcurrencyRouteKey {
                    scope: scope.clone(),
                    host: Some(target.host.clone()),
                    port: Some(target.port),
                }),
        );
    }
    if keys.len() == key_count {
        // Preserve the route source while service discovery has no effective
        // target for this upstream/subset.
        keys.push(AdaptiveConcurrencyRouteKey {
            scope,
            host: None,
            port: None,
        });
    }
}

fn adaptive_concurrency_port_override_keys(upstream: &crate::config::types::Upstream) -> Vec<u16> {
    let mut keys = upstream.port_overrides.keys().copied().collect::<Vec<_>>();
    keys.sort_unstable();
    keys
}

fn adaptive_concurrency_resolved_port_override_keys(
    upstream: &crate::config::types::Upstream,
) -> Vec<u16> {
    let mut keys = upstream
        .port_overrides
        .iter()
        .filter_map(|(port, value)| {
            crate::config::types::ResolvedPortOverride::from_upstream_override(value).map(|_| *port)
        })
        .collect::<Vec<_>>();
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn adaptive_concurrency_upstream_port_scope(
    backend_port: u16,
    port_override_keys: &[u16],
    resolved_port_override_keys: &[u16],
    targets: &[crate::config::types::UpstreamTarget],
) -> Option<u16> {
    if port_override_keys.is_empty() || targets.is_empty() {
        return None;
    }

    let mut full_coverage_port = None;
    let mut full_coverage_count = 0usize;
    for port in port_override_keys {
        if targets
            .iter()
            .all(|target| target.dispatch_policy_port() == *port)
        {
            full_coverage_count += 1;
            full_coverage_port = Some(*port);
        }
    }
    let dispatch_port = if full_coverage_count == 1 {
        full_coverage_port.unwrap_or(backend_port)
    } else {
        backend_port
    };
    (resolved_port_override_keys
        .binary_search(&dispatch_port)
        .is_ok()
        && targets
            .iter()
            .any(|target| target.dispatch_policy_port() == dispatch_port))
    .then_some(dispatch_port)
}

fn push_direct_route_key(
    keys: &mut Vec<AdaptiveConcurrencyRouteKey>,
    key_by: AdaptiveConcurrencyKeyBy,
    proxy: &crate::config::types::Proxy,
    host: &str,
    port: u16,
) {
    keys.push(AdaptiveConcurrencyRouteKey {
        scope: adaptive_concurrency_scope(key_by, proxy, None),
        host: Some(normalize_adaptive_concurrency_direct_host(host)),
        port: Some(port),
    });
}

fn normalize_adaptive_concurrency_direct_host(host: &str) -> String {
    // GatewayConfig::normalize_fields delegates configured destinations to
    // Proxy::normalize_fields and Upstream::normalize_fields. Route overrides
    // bypass those host fields, so mirror their lowercase contract here.
    host.trim().to_ascii_lowercase()
}

fn route_override_priority(pc: &PluginConfig) -> u16 {
    pc.priority_override
        .unwrap_or(match pc.plugin_name.as_str() {
            "ai_stream_router" => crate::plugins::priority::AI_STREAM_ROUTER,
            "mcp_gateway" => crate::plugins::priority::MCP_GATEWAY,
            "mesh_route_dispatch" => crate::plugins::priority::MESH_ROUTE_DISPATCH,
            _ => crate::plugins::priority::DEFAULT,
        })
}

fn effective_route_override_configs_for_proxy<'a>(
    proxy: &crate::config::types::Proxy,
    config: &'a GatewayConfig,
) -> Vec<&'a PluginConfig> {
    const ROUTE_OVERRIDE_PLUGINS: &[&str] =
        &["ai_stream_router", "mcp_gateway", "mesh_route_dispatch"];
    let mut route_configs = Vec::new();

    // Match PluginCache construction order before its stable priority sort:
    // globals, proxy-scoped configs in config order, then proxy-group configs
    // in association order.
    route_configs.extend(config.plugin_configs.iter().filter(|pc| {
        pc.scope == PluginScope::Global
            && ROUTE_OVERRIDE_PLUGINS.contains(&pc.plugin_name.as_str())
            && plugin_config_effectively_applies_to_proxy(pc, proxy, config)
    }));
    route_configs.extend(config.plugin_configs.iter().filter(|pc| {
        pc.scope == PluginScope::Proxy
            && ROUTE_OVERRIDE_PLUGINS.contains(&pc.plugin_name.as_str())
            && plugin_config_effectively_applies_to_proxy(pc, proxy, config)
    }));
    for association in &proxy.plugins {
        if let Some(pc) = config.plugin_configs.iter().find(|pc| {
            pc.id == association.plugin_config_id
                && pc.scope == PluginScope::ProxyGroup
                && ROUTE_OVERRIDE_PLUGINS.contains(&pc.plugin_name.as_str())
                && plugin_config_effectively_applies_to_proxy(pc, proxy, config)
        }) {
            route_configs.push(pc);
        }
    }
    route_configs.sort_by_key(|pc| route_override_priority(pc));
    route_configs
}

fn url_destination_fingerprint(url: &str) -> serde_json::Value {
    let parse_source = url.replace("{model}", "__FERRUM_MODEL__");
    if let Ok(parsed) = url::Url::parse(&parse_source)
        && let (Some(host), Some(port)) = (parsed.host_str(), parsed.port_or_known_default())
    {
        return serde_json::json!({
            "host": host.to_ascii_lowercase(),
            "port": port
        });
    }
    // Invalid route configs fail their own constructor validation. Retaining
    // the raw value here keeps staged fingerprinting deterministic until that
    // validation rejects the generation.
    serde_json::Value::String(url.to_string())
}

fn route_override_destination_fingerprint(pc: &PluginConfig) -> serde_json::Value {
    match pc.plugin_name.as_str() {
        "mesh_route_dispatch" => {
            let normalized_config =
                crate::plugins::mesh_route_dispatch::MeshRouteDispatchConfig::from_value_normalized(
                    &pc.config,
                )
                .ok()
                .and_then(|config| serde_json::to_value(config).ok());
            let fingerprint_config = normalized_config.as_ref().unwrap_or(&pc.config);
            let rules = fingerprint_config
                .get("rules")
                .and_then(serde_json::Value::as_array)
                .map(|rules| {
                    rules
                        .iter()
                        .map(|rule| {
                            let redirects = rule
                                .get("redirect")
                                .is_some_and(|redirect| !redirect.is_null());
                            let destination = if redirects {
                                None
                            } else {
                                rule.get("destination")
                                    .and_then(serde_json::Value::as_object)
                            };
                            let upstream_id = destination
                                .and_then(|value| value.get("upstream_id"))
                                .cloned();
                            let backend_host = destination
                                .and_then(|value| value.get("backend_host"))
                                .map(|value| {
                                    value.as_str().map_or_else(
                                        || value.clone(),
                                        |host| {
                                            serde_json::Value::String(
                                                normalize_adaptive_concurrency_direct_host(host),
                                            )
                                        },
                                    )
                                });
                            let backend_port = destination
                                .and_then(|value| value.get("backend_port"))
                                .cloned();
                            let backend_tls = destination
                                .and_then(|value| value.get("backend_tls"))
                                .cloned();
                            let requires_node_waypoint_authz = destination
                                .and_then(|value| value.get("requires_node_waypoint_authz"))
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(false);
                            serde_json::json!({
                                "match": rule
                                    .get("match")
                                    .cloned()
                                    .unwrap_or_else(|| serde_json::json!({})),
                                "destination": {
                                    "upstream_id": upstream_id,
                                    "backend_host": backend_host,
                                    "backend_port": backend_port,
                                    "backend_tls": backend_tls,
                                    "requires_node_waypoint_authz": requires_node_waypoint_authz
                                },
                                // Redirect presence suppresses backend dispatch; its
                                // response-only fields do not affect limiter keys.
                                "redirects": redirects
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            serde_json::json!({
                "reject_unmatched": fingerprint_config
                    .get("reject_unmatched")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                "rules": rules
            })
        }
        "ai_stream_router" => {
            let enabled = pc
                .config
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            if !enabled {
                return serde_json::json!({"enabled": false});
            }
            let mut providers = pc
                .config
                .get("providers")
                .and_then(serde_json::Value::as_array)
                .map(|providers| {
                    providers
                        .iter()
                        .enumerate()
                        .map(|(index, provider)| {
                            let priority = provider
                                .get("priority")
                                .and_then(serde_json::Value::as_u64)
                                .unwrap_or((index as u64).saturating_add(1));
                            serde_json::json!({
                                "priority": priority,
                                "model_patterns": provider
                                    .get("model_patterns")
                                    .cloned()
                                    .unwrap_or_else(|| serde_json::json!([])),
                                "destination": provider
                                    .get("endpoint")
                                    .and_then(serde_json::Value::as_str)
                                    .map(url_destination_fingerprint)
                                    .unwrap_or(serde_json::Value::Null)
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            providers.sort_by_key(|provider| {
                provider
                    .get("priority")
                    .and_then(serde_json::Value::as_u64)
                    .unwrap_or(u64::MAX)
            });
            serde_json::json!({
                "enabled": true,
                "fail_on_missing_model": pc
                    .config
                    .get("fail_on_missing_model")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                "fail_on_no_matching_provider": pc
                    .config
                    .get("fail_on_no_matching_provider")
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(true),
                "providers": providers
            })
        }
        "mcp_gateway" => {
            let enabled = pc
                .config
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                .unwrap_or(true);
            if !enabled {
                return serde_json::json!({"enabled": false});
            }
            let mut servers = pc
                .config
                .get("servers")
                .and_then(serde_json::Value::as_object)
                .map(|servers| {
                    servers
                        .iter()
                        .map(|(server_id, server)| {
                            let enabled = server
                                .get("enabled")
                                .and_then(serde_json::Value::as_bool)
                                .unwrap_or(true);
                            if !enabled {
                                return serde_json::json!({
                                    "server_id": server_id,
                                    "enabled": false
                                });
                            }
                            serde_json::json!({
                                "server_id": server_id,
                                "namespace": server.get("namespace").cloned(),
                                "enabled": true,
                                "expose_tools": server
                                    .get("expose_tools")
                                    .and_then(serde_json::Value::as_bool)
                                    .unwrap_or(true),
                                "expose_resources": server
                                    .get("expose_resources")
                                    .and_then(serde_json::Value::as_bool)
                                    .unwrap_or(false),
                                "expose_prompts": server
                                    .get("expose_prompts")
                                    .and_then(serde_json::Value::as_bool)
                                    .unwrap_or(false),
                                "destination": server
                                    .get("upstream_url")
                                    .and_then(serde_json::Value::as_str)
                                    .map(url_destination_fingerprint)
                                    .unwrap_or(serde_json::Value::Null)
                            })
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            servers.sort_by(|left, right| {
                left.get("server_id")
                    .and_then(serde_json::Value::as_str)
                    .cmp(&right.get("server_id").and_then(serde_json::Value::as_str))
            });
            serde_json::json!({
                "enabled": true,
                "mode": pc.config.get("mode").cloned(),
                "endpoint_path": pc
                    .config
                    .get("endpoint")
                    .and_then(|value| value.get("path"))
                    .cloned(),
                "namespace_separator": pc
                    .config
                    .get("discovery")
                    .and_then(|value| value.get("namespace_separator"))
                    .and_then(serde_json::Value::as_str)
                    .unwrap_or("."),
                "passthrough_unknown_methods": pc
                    .config
                    .get("capabilities")
                    .and_then(|value| value.get("passthrough_unknown_methods"))
                    .and_then(serde_json::Value::as_bool)
                    .unwrap_or(false),
                "servers": servers
            })
        }
        _ => serde_json::Value::Null,
    }
}

fn collect_route_override_destinations(
    route_pc: &PluginConfig,
    proxy: &crate::config::types::Proxy,
    key_by: AdaptiveConcurrencyKeyBy,
    config: &GatewayConfig,
    keys: &mut Vec<AdaptiveConcurrencyRouteKey>,
    upstream_routes: &mut Vec<AdaptiveConcurrencyUpstreamRoute>,
) {
    match route_pc.plugin_name.as_str() {
        "mesh_route_dispatch" => {
            let Some(rules) = route_pc
                .config
                .get("rules")
                .and_then(serde_json::Value::as_array)
            else {
                return;
            };
            for destination in rules
                .iter()
                .filter(|rule| {
                    !rule
                        .get("redirect")
                        .is_some_and(|redirect| !redirect.is_null())
                })
                .filter_map(|rule| {
                    rule.get("destination")
                        .and_then(serde_json::Value::as_object)
                })
            {
                if let Some(upstream_id) = destination
                    .get("upstream_id")
                    .and_then(serde_json::Value::as_str)
                {
                    let subset = if proxy.upstream_id.as_deref() == Some(upstream_id) {
                        proxy.upstream_subset.as_deref()
                    } else {
                        None
                    };
                    let upstream = config
                        .upstreams
                        .iter()
                        .find(|upstream| upstream.id == upstream_id);
                    push_upstream_route(
                        keys,
                        upstream_routes,
                        adaptive_concurrency_scope(key_by, proxy, Some(upstream_id)),
                        upstream_id,
                        subset,
                        proxy.backend_port,
                        upstream,
                    );
                } else if let (Some(host), Some(port)) = (
                    destination
                        .get("backend_host")
                        .and_then(serde_json::Value::as_str),
                    destination
                        .get("backend_port")
                        .and_then(serde_json::Value::as_u64)
                        .and_then(|port| u16::try_from(port).ok()),
                ) {
                    push_direct_route_key(keys, key_by, proxy, host, port);
                }
            }
        }
        "ai_stream_router" => {
            if route_pc
                .config
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            {
                return;
            }
            if let Some(providers) = route_pc
                .config
                .get("providers")
                .and_then(serde_json::Value::as_array)
            {
                for endpoint in providers.iter().filter_map(|provider| {
                    provider.get("endpoint").and_then(serde_json::Value::as_str)
                }) {
                    let parse_source = endpoint.replace("{model}", "__FERRUM_MODEL__");
                    if let Ok(parsed) = url::Url::parse(&parse_source)
                        && let (Some(host), Some(port)) =
                            (parsed.host_str(), parsed.port_or_known_default())
                    {
                        push_direct_route_key(keys, key_by, proxy, host, port);
                    }
                }
            }
        }
        "mcp_gateway" => {
            if route_pc
                .config
                .get("enabled")
                .and_then(serde_json::Value::as_bool)
                == Some(false)
            {
                return;
            }
            if let Some(servers) = route_pc
                .config
                .get("servers")
                .and_then(serde_json::Value::as_object)
            {
                for upstream_url in servers
                    .values()
                    .filter(|server| {
                        server
                            .get("enabled")
                            .and_then(serde_json::Value::as_bool)
                            .unwrap_or(true)
                    })
                    .filter_map(|server| {
                        server
                            .get("upstream_url")
                            .and_then(serde_json::Value::as_str)
                    })
                {
                    if let Ok(parsed) = url::Url::parse(upstream_url)
                        && let (Some(host), Some(port)) =
                            (parsed.host_str(), parsed.port_or_known_default())
                    {
                        push_direct_route_key(keys, key_by, proxy, host, port);
                    }
                }
            }
        }
        _ => {}
    }
}

fn adaptive_concurrency_route_definition(
    pc: &PluginConfig,
    key_by: AdaptiveConcurrencyKeyBy,
    config: &GatewayConfig,
) -> AdaptiveConcurrencyRouteDefinition {
    let mut protected_proxy_ids = Vec::new();
    let mut keys = Vec::new();
    let mut overrides = Vec::new();
    let mut upstream_routes = Vec::new();
    for proxy in &config.proxies {
        if !plugin_config_effectively_applies_to_proxy(pc, proxy, config) {
            continue;
        }
        protected_proxy_ids.push(proxy.id.clone());

        for route_pc in effective_route_override_configs_for_proxy(proxy, config) {
            collect_route_override_destinations(
                route_pc,
                proxy,
                key_by,
                config,
                &mut keys,
                &mut upstream_routes,
            );
            overrides.push(AdaptiveConcurrencyRouteOverride {
                proxy_id: proxy.id.clone(),
                plugin_name: route_pc.plugin_name.clone(),
                effective_priority: route_override_priority(route_pc),
                destination_fingerprint: route_override_destination_fingerprint(route_pc),
            });
        }

        if let Some(upstream_id) = proxy.upstream_id.as_deref() {
            let upstream = config
                .upstreams
                .iter()
                .find(|upstream| upstream.id == upstream_id);
            push_upstream_route(
                &mut keys,
                &mut upstream_routes,
                adaptive_concurrency_scope(key_by, proxy, Some(upstream_id)),
                upstream_id,
                proxy.upstream_subset.as_deref(),
                proxy.backend_port,
                upstream,
            );
        } else {
            push_direct_route_key(
                &mut keys,
                key_by,
                proxy,
                &proxy.backend_host,
                proxy.backend_port,
            );
        }
    }
    keys.sort_unstable();
    keys.dedup();
    // Proxy ordering in GatewayConfig is not execution ordering. Stable-sort
    // only by proxy ID so the effective route-plugin order within each proxy
    // remains visible to compatibility checks.
    overrides.sort_by(|left, right| left.proxy_id.cmp(&right.proxy_id));
    protected_proxy_ids.sort_unstable();
    protected_proxy_ids.dedup();
    upstream_routes.sort_unstable();
    upstream_routes.dedup();
    AdaptiveConcurrencyRouteDefinition {
        protected_proxy_ids,
        keys,
        overrides,
        upstream_routes,
    }
}

fn adaptive_concurrency_effective_lb_keys(
    route_definition: &AdaptiveConcurrencyRouteDefinition,
    load_balancer: &crate::load_balancer::LoadBalancerCacheInner,
) -> Vec<AdaptiveConcurrencyRouteKey> {
    let mut keys = Vec::new();
    for route in &route_definition.upstream_routes {
        let key_count = keys.len();
        if let Some(upstream) = load_balancer.upstreams().get(&route.upstream_id) {
            let port_scope = adaptive_concurrency_upstream_port_scope(
                route.backend_port,
                &route.port_override_keys,
                &route.resolved_port_override_keys,
                &upstream.targets,
            );
            keys.extend(
                upstream
                    .targets
                    .iter()
                    .filter(|target| {
                        target_matches_subset(upstream, target, route.subset.as_deref())
                    })
                    .filter(|target| {
                        port_scope.is_none_or(|port| target.dispatch_policy_port() == port)
                    })
                    .map(|target| AdaptiveConcurrencyRouteKey {
                        scope: route.scope.clone(),
                        host: Some(target.host.clone()),
                        port: Some(target.port),
                    }),
            );
        }
        if keys.len() == key_count {
            keys.push(AdaptiveConcurrencyRouteKey {
                scope: route.scope.clone(),
                host: None,
                port: None,
            });
        }
    }
    keys.sort_unstable();
    keys.dedup();
    keys
}

fn adaptive_concurrency_has_zero_target_sentinel(keys: &[AdaptiveConcurrencyRouteKey]) -> bool {
    keys.iter()
        .any(|key| key.host.is_none() && key.port.is_none())
}

/// Existing target keys keep their counters during strict scale-out. Any
/// retirement/replacement requires an independent tracking space, as do
/// expansions involving the zero-target sentinel because it identifies a route
/// source rather than a concrete limiter key and can collide across sources
/// sharing one scope.
fn adaptive_concurrency_key_space_requires_reset(
    current: &[AdaptiveConcurrencyRouteKey],
    replacement: &[AdaptiveConcurrencyRouteKey],
) -> bool {
    if current == replacement {
        return false;
    }
    if adaptive_concurrency_has_zero_target_sentinel(current)
        || adaptive_concurrency_has_zero_target_sentinel(replacement)
    {
        return true;
    }
    !current
        .iter()
        .all(|key| replacement.binary_search(key).is_ok())
}

fn adaptive_concurrency_route_definition_requires_reset(
    current: &AdaptiveConcurrencyRouteDefinition,
    replacement: &AdaptiveConcurrencyRouteDefinition,
) -> bool {
    if current == replacement {
        return false;
    }
    let existing_proxy_scopes_preserved = current.protected_proxy_ids.iter().all(|proxy_id| {
        replacement
            .protected_proxy_ids
            .binary_search(proxy_id)
            .is_ok()
    });
    let existing_override_semantics_preserved =
        current.protected_proxy_ids.iter().all(|proxy_id| {
            current
                .overrides
                .iter()
                .filter(|route| route.proxy_id.as_str() == proxy_id.as_str())
                .eq(replacement
                    .overrides
                    .iter()
                    .filter(|route| route.proxy_id.as_str() == proxy_id.as_str()))
        });
    if !existing_proxy_scopes_preserved
        || !existing_override_semantics_preserved
        || adaptive_concurrency_has_zero_target_sentinel(&current.keys)
        || adaptive_concurrency_has_zero_target_sentinel(&replacement.keys)
        || !current
            .upstream_routes
            .iter()
            .all(|route| replacement.upstream_routes.binary_search(route).is_ok())
    {
        return true;
    }
    adaptive_concurrency_key_space_requires_reset(&current.keys, &replacement.keys)
}

fn adaptive_concurrency_lb_key_space_changed(
    instance: &AdaptiveConcurrencyInstance,
    current: &crate::load_balancer::LoadBalancerCacheInner,
    replacement: &crate::load_balancer::LoadBalancerCacheInner,
) -> bool {
    let current_keys = adaptive_concurrency_effective_lb_keys(&instance.route_definition, current);
    let replacement_keys =
        adaptive_concurrency_effective_lb_keys(&instance.route_definition, replacement);
    adaptive_concurrency_key_space_requires_reset(&current_keys, &replacement_keys)
}

fn retained_adaptive_concurrency_states(
    current: &AdaptiveConcurrencyInstanceMap,
    config: &GatewayConfig,
) -> AdaptiveConcurrencyInstanceMap {
    let mut retained = HashMap::new();
    for pc in &config.plugin_configs {
        if !pc.enabled
            || pc.plugin_name != "adaptive_concurrency"
            || !adaptive_concurrency_policy_is_active(pc, config)
        {
            continue;
        }
        let identity = adaptive_concurrency_policy_id(pc);
        if let Some(existing) = current.get(&identity) {
            let route_definition =
                adaptive_concurrency_route_definition(pc, existing.config.key_by, config);
            if adaptive_definition_matches(existing, pc, &route_definition) {
                retained.insert(identity, existing.clone());
            }
        }
    }
    retained
}

fn adaptive_concurrency_policy_is_active(pc: &PluginConfig, config: &GatewayConfig) -> bool {
    match &pc.scope {
        PluginScope::Global => true,
        PluginScope::Proxy => pc.proxy_id.as_deref().is_some_and(|proxy_id| {
            config.proxies.iter().any(|proxy| {
                proxy.id == proxy_id
                    && proxy
                        .plugins
                        .iter()
                        .any(|association| association.plugin_config_id == pc.id)
            })
        }),
        PluginScope::ProxyGroup => config.proxies.iter().any(|proxy| {
            proxy
                .plugins
                .iter()
                .any(|association| association.plugin_config_id == pc.id)
        }),
    }
}

fn include_adaptive_concurrency_route_rebuilds(
    current: &AdaptiveConcurrencyInstanceMap,
    config: &GatewayConfig,
    proxy_ids_to_rebuild: &mut HashSet<String>,
    rebuild_adaptive_globals: &mut bool,
) {
    for (identity, existing) in current {
        let Some(pc) = config.plugin_configs.iter().find(|pc| {
            pc.enabled
                && pc.plugin_name == "adaptive_concurrency"
                && pc.namespace == identity.namespace
                && pc.id == identity.plugin_config_id
        }) else {
            continue;
        };
        let route_definition =
            adaptive_concurrency_route_definition(pc, existing.config.key_by, config);
        if route_definition == existing.route_definition {
            continue;
        }

        match &pc.scope {
            PluginScope::Global => {
                *rebuild_adaptive_globals = true;
                proxy_ids_to_rebuild.extend(config.proxies.iter().map(|proxy| proxy.id.clone()));
            }
            PluginScope::Proxy => {
                if let Some(proxy_id) = pc.proxy_id.as_ref() {
                    proxy_ids_to_rebuild.insert(proxy_id.clone());
                }
            }
            PluginScope::ProxyGroup => {
                proxy_ids_to_rebuild.extend(
                    config
                        .proxies
                        .iter()
                        .filter(|proxy| {
                            proxy
                                .plugins
                                .iter()
                                .any(|association| association.plugin_config_id == pc.id)
                        })
                        .map(|proxy| proxy.id.clone()),
                );
            }
        }
    }
}

fn create_adaptive_concurrency_plugin(
    pc: &PluginConfig,
    gateway_config: &GatewayConfig,
    http_client: &PluginHttpClient,
    current: &AdaptiveConcurrencyInstanceMap,
    staged: &mut AdaptiveConcurrencyInstanceMap,
) -> Result<Option<Arc<dyn Plugin>>, String> {
    let identity = adaptive_concurrency_policy_id(pc);
    let parsed = Arc::new(crate::plugins::adaptive_concurrency::parse_config_value(
        &pc.config,
    )?);
    let route_definition = adaptive_concurrency_route_definition(pc, parsed.key_by, gateway_config);
    if let Some(existing) = staged.get(&identity) {
        if !adaptive_definition_matches(existing, pc, &route_definition) {
            return Err(format!(
                "adaptive_concurrency: plugin config identity '{}:{}' resolves to conflicting policy definitions",
                pc.namespace, pc.id
            ));
        }
        return Ok(Some(Arc::new(
            crate::plugins::adaptive_concurrency::AdaptiveConcurrency::with_shared_limiter(
                Arc::clone(&existing.config),
                Arc::clone(&existing.limiter),
                existing.generation,
            ),
        )));
    }

    let (limiter, generation, reset_tracking_space) = if let Some(existing) = current.get(&identity)
    {
        let generation = existing.generation.checked_add(1).ok_or_else(|| {
            format!(
                "adaptive_concurrency: plugin config '{}:{}' exhausted its reload generation counter",
                pc.namespace, pc.id
            )
        })?;
        let structural_change = existing.config.key_by != parsed.key_by
            || parsed.max_tracked_keys < existing.config.max_tracked_keys
            || existing.scope != pc.scope
            || existing.proxy_id != pc.proxy_id
            || adaptive_concurrency_route_definition_requires_reset(
                &existing.route_definition,
                &route_definition,
            );
        // Keep the generation lifecycle shared so pinned retired cache views
        // are rejected after a structural cutover. The limiter rotates its
        // target-tracking space at commit, allowing permits from the detached
        // space to finish without blocking or training the replacement.
        (Arc::clone(&existing.limiter), generation, structural_change)
    } else {
        (
            Arc::new(AdaptiveConcurrencyLimiter::new(
                http_client.pool_shard_amount(),
            )),
            1,
            false,
        )
    };

    let plugin = crate::plugins::adaptive_concurrency::AdaptiveConcurrency::with_shared_limiter(
        Arc::clone(&parsed),
        Arc::clone(&limiter),
        generation,
    );
    staged.insert(
        identity,
        AdaptiveConcurrencyInstance {
            limiter,
            config: parsed,
            config_value: pc.config.clone(),
            scope: pc.scope.clone(),
            proxy_id: pc.proxy_id.clone(),
            route_definition,
            generation,
            reset_tracking_space,
        },
    );
    Ok(Some(Arc::new(plugin)))
}

#[derive(Clone)]
struct ProxyGroupPluginInstance {
    plugin: Arc<dyn Plugin>,
    config: PluginConfig,
}

/// Built-in plugin types whose constructed instance can participate in the
/// HMAC request-body composition invariant. Keep this list aligned with
/// `Plugin::modifies_request_body()` implementations. Registered custom
/// plugins are also constructed because their capability is defined by their
/// `Plugin` implementation rather than a core allowlist.
const HMAC_COMPOSITION_PLUGIN_NAMES: &[&str] = &[
    "hmac_auth",
    "request_transformer",
    "compression",
    "grpc_web",
    "ai_prompt_shield",
    "ai_stream_router",
    "mcp_gateway",
    "ai_prompt_compressor",
    "ai_request_guard",
];

/// Validate the HMAC/request-body-transform invariant against a candidate
/// config before an admin Proxy or PluginConfig write is persisted. Runtime
/// cache construction repeats the same check as a fail-closed backstop.
pub(crate) fn validate_hmac_request_transform_candidate(
    config: &GatewayConfig,
    http_client: &PluginHttpClient,
) -> Result<(), String> {
    if !config
        .plugin_configs
        .iter()
        .any(|plugin| plugin.enabled && plugin.plugin_name == "hmac_auth")
    {
        return Ok(());
    }
    let mut errors = Vec::new();
    let mut global_plugins = Vec::new();
    let mut scoped_plugins: HmacCompositionPluginMap<'_> = HashMap::new();
    let custom_plugin_names = crate::custom_plugins::custom_plugin_names();
    let current_adaptive_states = AdaptiveConcurrencyInstanceMap::new();
    let mut staged_adaptive_states = AdaptiveConcurrencyInstanceMap::new();
    let country_mmdb_load_session = CountryMmdbLoadSession::default();

    for plugin_config in &config.plugin_configs {
        if !plugin_config.enabled
            || (!HMAC_COMPOSITION_PLUGIN_NAMES.contains(&plugin_config.plugin_name.as_str())
                && !custom_plugin_names.contains(&plugin_config.plugin_name.as_str()))
        {
            continue;
        }
        match try_create_plugin(
            plugin_config,
            config,
            http_client,
            &country_mmdb_load_session,
            &current_adaptive_states,
            &mut staged_adaptive_states,
        ) {
            Ok(Some(plugin)) if plugin_config.scope == PluginScope::Global => {
                global_plugins.push(plugin);
            }
            Ok(Some(plugin)) => {
                scoped_plugins.insert(
                    (plugin_config.namespace.as_str(), plugin_config.id.as_str()),
                    (plugin_config, plugin),
                );
            }
            Ok(None) => {}
            Err(error) => errors.push(error),
        }
    }

    for proxy in &config.proxies {
        let mut merged = global_plugins.clone();
        let global_ptrs: HashSet<usize> = merged
            .iter()
            .map(|plugin| Arc::as_ptr(plugin) as *const () as usize)
            .collect();
        for association in &proxy.plugins {
            let Some((plugin_config, plugin)) = scoped_plugins.get(&(
                proxy.namespace.as_str(),
                association.plugin_config_id.as_str(),
            )) else {
                continue;
            };
            let applies = match plugin_config.scope {
                PluginScope::Proxy => plugin_config.proxy_id.as_deref() == Some(proxy.id.as_str()),
                PluginScope::ProxyGroup => plugin_config.proxy_id.is_none(),
                PluginScope::Global => false,
            };
            if !applies {
                continue;
            }
            remove_shadowed_global_plugin(&mut merged, &global_ptrs, plugin.name());
            merged.push(Arc::clone(plugin));
        }
        if let Err(error) = validate_hmac_request_transform_composition(&merged) {
            errors.push(format!("proxy_id={}: {error}", proxy.id));
        }
    }

    if let Err(error) = validate_hmac_request_transform_composition(&global_plugins) {
        errors.push(format!("global plugins: {error}"));
    }

    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "{} HMAC request-transform composition error(s): {}",
            errors.len(),
            errors.join("; ")
        ))
    }
}

fn remove_shadowed_global_plugin(
    plugins: &mut Vec<Arc<dyn Plugin>>,
    global_ptrs: &HashSet<usize>,
    plugin_name: &str,
) {
    plugins.retain(|plugin| {
        plugin.name() != plugin_name
            || !global_ptrs.contains(&(Arc::as_ptr(plugin) as *const () as usize))
    });
}

fn same_proxy_group_plugin_config(left: &PluginConfig, right: &PluginConfig) -> bool {
    left.id == right.id
        && left.namespace == right.namespace
        && left.plugin_name == right.plugin_name
        && left.config == right.config
        && left.scope == right.scope
        && left.proxy_id == right.proxy_id
        && left.enabled == right.enabled
        && left.priority_override == right.priority_override
}

// ---------------------------------------------------------------------------
// Per-protocol phase data — precomputed at config reload time
// ---------------------------------------------------------------------------

/// Bitflags for per-protocol plugin capability checks. Avoids per-request
/// `plugins.iter().any(|p| p.some_flag())` scans on the hot path.
#[derive(Clone, Copy, Default)]
pub struct PluginCapabilities(u16);

impl PluginCapabilities {
    pub const HAS_AUTH_PLUGINS: u16 = 1 << 0;
    pub const MODIFIES_REQUEST_HEADERS: u16 = 1 << 1;
    pub const MODIFIES_REQUEST_BODY: u16 = 1 << 2;
    pub const HAS_BODY_BEFORE_BEFORE_PROXY: u16 = 1 << 3;
    pub const NEEDS_REQUEST_BODY_BYTES: u16 = 1 << 4;
    pub const HAS_BODY_BEFORE_AUTHENTICATE: u16 = 1 << 5;
    pub const NEEDS_DECODED_QUERY_PARAMS: u16 = 1 << 6;
    pub const NEEDS_FINAL_REQUEST_BODY_CONTEXT: u16 = 1 << 7;
    pub const HAS_RESPONSE_COMMITTED_HOOK: u16 = 1 << 8;
    pub const HAS_RESPONSE_STREAM_HOOKS: u16 = 1 << 9;
    pub const HAS_BODY_BEFORE_AUTHORIZE: u16 = 1 << 10;
    pub const HAS_BACKEND_PATH_PLUGINS: u16 = 1 << 11;
    pub const HAS_DEFERRED_ROUTING_HEADER_HOOKS: u16 = 1 << 12;

    #[inline(always)]
    pub fn has(self, flag: u16) -> bool {
        self.0 & flag != 0
    }
}

/// Pre-computed per-protocol plugin phase data for a single proxy.
/// Built at config reload time so the hot path does zero filtering or allocation.
#[derive(Clone)]
pub struct PluginPhaseData {
    /// Auth plugins only (pre-filtered from the protocol plugin list).
    pub auth_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Authorization plugins only (pre-filtered from the protocol plugin list).
    pub authorize_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Backend-admission plugins only (pre-filtered from the protocol plugin list).
    pub backend_admission_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Plugins that inspect the backend-effective path after route resolution.
    pub backend_path_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Credential-bearing request header names used by safe downstream views.
    pub request_headers_to_redact: Arc<Vec<String>>,
    /// Deterministic initial-response header policy plugins, already filtered
    /// and kept in configured priority order for protocol boundary paths.
    pub initial_response_header_policy_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    /// Unique canonical field names touched by initial-response policy.
    pub initial_response_header_policy_names: Arc<Vec<String>>,
    /// Capability bitset for fast boolean checks.
    pub capabilities: PluginCapabilities,
}

/// Build `PluginPhaseData` from a protocol-filtered plugin list.
fn build_phase_data(plugins: &[Arc<dyn Plugin>]) -> PluginPhaseData {
    let mut caps = 0u16;
    let mut auth = Vec::new();
    let mut authorize = Vec::new();
    let mut backend_admission = Vec::new();
    let mut backend_path = Vec::new();
    let mut request_headers_to_redact = Vec::new();
    let mut initial_response_header_policy_plugins = Vec::new();
    let mut initial_response_header_policy_names = Vec::new();
    for p in plugins {
        if p.is_auth_plugin() {
            caps |= PluginCapabilities::HAS_AUTH_PLUGINS;
            auth.push(Arc::clone(p));
        }
        if p.is_authorize_plugin() {
            authorize.push(Arc::clone(p));
        }
        if p.is_backend_admission_plugin() {
            backend_admission.push(Arc::clone(p));
        }
        if p.requires_backend_path_resolution() {
            caps |= PluginCapabilities::HAS_BACKEND_PATH_PLUGINS;
            backend_path.push(Arc::clone(p));
        }
        if p.deferred_before_proxy_may_change_routing_headers() {
            caps |= PluginCapabilities::HAS_DEFERRED_ROUTING_HEADER_HOOKS;
        }
        if p.is_initial_response_header_policy() {
            initial_response_header_policy_plugins.push(Arc::clone(p));
            for name in p.initial_response_header_policy_names() {
                if !initial_response_header_policy_names.contains(name) {
                    initial_response_header_policy_names.push(name.clone());
                }
            }
        }
        for header in p.request_headers_to_redact() {
            if !request_headers_to_redact
                .iter()
                .any(|known: &String| known.eq_ignore_ascii_case(header))
            {
                request_headers_to_redact.push(header.clone());
            }
        }
        if p.modifies_request_headers() {
            caps |= PluginCapabilities::MODIFIES_REQUEST_HEADERS;
        }
        if p.modifies_request_body() {
            caps |= PluginCapabilities::MODIFIES_REQUEST_BODY;
        }
        if p.requires_request_body_before_before_proxy() {
            caps |= PluginCapabilities::HAS_BODY_BEFORE_BEFORE_PROXY;
        }
        if p.requires_request_body_before_authenticate() {
            caps |= PluginCapabilities::HAS_BODY_BEFORE_AUTHENTICATE;
        }
        if p.requires_request_body_before_authorize() {
            caps |= PluginCapabilities::HAS_BODY_BEFORE_AUTHORIZE;
        }
        if p.needs_request_body_bytes() {
            caps |= PluginCapabilities::NEEDS_REQUEST_BODY_BYTES;
        }
        if p.requires_decoded_query_params() {
            caps |= PluginCapabilities::NEEDS_DECODED_QUERY_PARAMS;
        }
        if p.needs_final_request_body_context() {
            caps |= PluginCapabilities::NEEDS_FINAL_REQUEST_BODY_CONTEXT;
        }
        if p.requires_response_committed_hook() {
            caps |= PluginCapabilities::HAS_RESPONSE_COMMITTED_HOOK;
        }
        if p.requires_response_stream_hooks() {
            caps |= PluginCapabilities::HAS_RESPONSE_STREAM_HOOKS;
        }
    }
    PluginPhaseData {
        auth_plugins: Arc::new(auth),
        authorize_plugins: Arc::new(authorize),
        backend_admission_plugins: Arc::new(backend_admission),
        backend_path_plugins: Arc::new(backend_path),
        request_headers_to_redact: Arc::new(request_headers_to_redact),
        initial_response_header_policy_plugins: Arc::new(initial_response_header_policy_plugins),
        initial_response_header_policy_names: Arc::new(initial_response_header_policy_names),
        capabilities: PluginCapabilities(caps),
    }
}

/// Filter a plugin list to only those supporting a given protocol.
fn filter_for_protocol(
    plugins: &[Arc<dyn Plugin>],
    protocol: ProxyProtocol,
) -> Arc<Vec<Arc<dyn Plugin>>> {
    Arc::new(
        plugins
            .iter()
            .filter(|p| p.supported_protocols().contains(&protocol))
            .cloned()
            .collect(),
    )
}

// ---------------------------------------------------------------------------
// ProtocolSnapshot — bundles protocol-filtered plugins + phase data for
// atomic swap via a single ArcSwap. Ensures a request always reads a
// consistent pair of (plugin list, phase data) for the same config generation.
// ---------------------------------------------------------------------------

/// Per-proxy, per-protocol entry: the filtered plugin list and its derived phase data.
#[derive(Clone)]
struct ProtocolEntry {
    plugins: PluginList,
    phase: PluginPhaseData,
}

/// All per-proxy protocol data, swapped atomically as one unit.
struct ProtocolSnapshot {
    /// proxy_id → (protocol → ProtocolEntry)
    proxy: HashMap<String, HashMap<ProxyProtocol, ProtocolEntry>>,
    /// Global fallback: protocol → ProtocolEntry
    global: HashMap<ProxyProtocol, ProtocolEntry>,
}

const ALL_PROXY_PROTOCOLS: [ProxyProtocol; 5] = [
    ProxyProtocol::Http,
    ProxyProtocol::Grpc,
    ProxyProtocol::WebSocket,
    ProxyProtocol::Tcp,
    ProxyProtocol::Udp,
];

fn build_protocol_entry(plugins: &[Arc<dyn Plugin>], proto: ProxyProtocol) -> ProtocolEntry {
    let filtered = filter_for_protocol(plugins, proto);
    let phase = build_phase_data(&filtered);
    ProtocolEntry {
        plugins: filtered,
        phase,
    }
}

/// Build the full protocol snapshot from the plugin map + global fallback.
fn build_protocol_snapshot(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> ProtocolSnapshot {
    let mut proxy = HashMap::with_capacity(proxy_map.len());
    for (proxy_id, plugins) in proxy_map {
        let mut inner = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
        for &proto in &ALL_PROXY_PROTOCOLS {
            inner.insert(proto, build_protocol_entry(plugins, proto));
        }
        proxy.insert(proxy_id.clone(), inner);
    }

    let mut global = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
    for &proto in &ALL_PROXY_PROTOCOLS {
        global.insert(proto, build_protocol_entry(globals, proto));
    }

    ProtocolSnapshot { proxy, global }
}

/// Collect all JWKS URIs actively referenced by `jwks_auth` plugin instances
/// across all proxies and global plugins. Used to clean up stale JWKS cache
/// entries (and abort their background refresh tasks) on config reload.
fn collect_active_jwks_requirements(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> HashMap<String, Duration> {
    let mut requirements = HashMap::new();
    for plugin in globals
        .iter()
        .chain(proxy_map.values().flat_map(|plugins| plugins.iter()))
    {
        for (uri, interval) in plugin.active_jwks_refresh_requirements() {
            requirements
                .entry(uri)
                .and_modify(|current: &mut Duration| *current = (*current).min(interval))
                .or_insert(interval);
        }
    }
    requirements
}

fn start_background_tasks(
    proxy_map: &ProxyPluginMap,
    globals: &[Arc<dyn Plugin>],
) -> Result<(), String> {
    let mut started = HashSet::new();
    for plugin in globals
        .iter()
        .chain(proxy_map.values().flat_map(|plugins| plugins.iter()))
    {
        let pointer = Arc::as_ptr(plugin) as *const () as usize;
        if started.insert(pointer) {
            plugin.start_background_tasks().map_err(|error| {
                format!(
                    "plugin '{}' background startup failed: {error}",
                    plugin.name()
                )
            })?;
        }
    }
    Ok(())
}

/// All plugin-cache state swapped as a single unit so a single load observes
/// either the old generation or the new generation, never a partial rebuild.
pub(crate) struct PluginCacheInner {
    /// proxy_id -> pre-resolved plugin list (global + proxy-scoped, merged).
    proxy_plugins: ProxyPluginMap,
    /// Fallback: global plugins only (for proxies with no scoped overrides).
    global_plugins: PluginList,
    /// Pre-computed: does any plugin for this proxy require response body buffering?
    requires_buffering: BufferingMap,
    /// Whether global-only plugins require response body buffering (fallback).
    global_requires_buffering: bool,
    /// Pre-computed: does any plugin for this proxy ever require request body
    /// buffering?
    requires_request_buffering: RequestBufferingMap,
    /// Whether global-only plugins require request body buffering (fallback).
    global_requires_request_buffering: bool,
    /// Pre-computed per-protocol plugin lists + phase data (auth plugin lists,
    /// capability bitsets).
    protocol_snapshot: ProtocolSnapshot,
    /// Pre-computed: does any plugin for this proxy require per-frame WebSocket hooks?
    requires_ws_frame: WsFrameMap,
    /// Whether global-only plugins require per-frame WebSocket hooks (fallback).
    global_requires_ws_frame: bool,
    /// Shared proxy-group plugin instances, keyed by plugin_config_id. Kept
    /// across incremental updates so rebuilt proxies can keep sharing state
    /// with unchanged proxies when the proxy-group config itself did not change.
    proxy_group_plugins: ProxyGroupInstanceMap,
    /// Stable adaptive-concurrency policies keyed by namespace + plugin config
    /// ID. Replacement plugin objects share these limiters so live permits and
    /// learned target state remain coherent across cache generations.
    adaptive_concurrency_instances: AdaptiveConcurrencyInstanceMap,
    /// Live geo plugin instances keyed by stable config identity. This lets an
    /// accepted MMDB-only validation generation replace exactly the geo
    /// snapshots while retaining every unrelated stateful plugin instance.
    country_mmdb_instances: CountryMmdbPluginInstanceMap,
    /// Deduplicated immutable MMDB bytes retained by this cache generation.
    country_mmdb_snapshot_bytes: u64,
}

impl PluginCacheInner {
    #[allow(clippy::too_many_arguments)]
    fn new(
        proxy_plugins: ProxyPluginMap,
        global_plugins: PluginList,
        requires_buffering: BufferingMap,
        global_requires_buffering: bool,
        requires_request_buffering: RequestBufferingMap,
        global_requires_request_buffering: bool,
        protocol_snapshot: ProtocolSnapshot,
        requires_ws_frame: WsFrameMap,
        global_requires_ws_frame: bool,
        proxy_group_plugins: ProxyGroupInstanceMap,
        adaptive_concurrency_instances: AdaptiveConcurrencyInstanceMap,
        country_mmdb_instances: CountryMmdbPluginInstanceMap,
        country_mmdb_snapshot_bytes: u64,
    ) -> Self {
        Self {
            proxy_plugins,
            global_plugins,
            requires_buffering,
            global_requires_buffering,
            requires_request_buffering,
            global_requires_request_buffering,
            protocol_snapshot,
            requires_ws_frame,
            global_requires_ws_frame,
            proxy_group_plugins,
            adaptive_concurrency_instances,
            country_mmdb_instances,
            country_mmdb_snapshot_bytes,
        }
    }

    pub(crate) fn prepare_adaptive_concurrency_generations(&self) {
        for instance in self.adaptive_concurrency_instances.values() {
            instance
                .limiter
                .prepare_policy_generation(instance.generation, instance.reset_tracking_space);
        }
    }

    pub(crate) fn commit_adaptive_concurrency_generations(&self) {
        for instance in self.adaptive_concurrency_instances.values() {
            instance.limiter.commit_policy_generation(
                instance.generation,
                Arc::clone(&instance.config),
                instance.reset_tracking_space,
            );
        }
    }

    pub(crate) fn prepare_adaptive_concurrency_lb_generation(
        &self,
        generation: u64,
        current: &crate::load_balancer::LoadBalancerCacheInner,
        replacement: &crate::load_balancer::LoadBalancerCacheInner,
    ) {
        for instance in self.adaptive_concurrency_instances.values() {
            let reset_tracking_space =
                adaptive_concurrency_lb_key_space_changed(instance, current, replacement);
            instance
                .limiter
                .prepare_lb_generation(generation, reset_tracking_space);
        }
    }

    pub(crate) fn commit_adaptive_concurrency_lb_generation(
        &self,
        generation: u64,
        current: &crate::load_balancer::LoadBalancerCacheInner,
        replacement: &crate::load_balancer::LoadBalancerCacheInner,
    ) {
        for instance in self.adaptive_concurrency_instances.values() {
            let reset_tracking_space =
                adaptive_concurrency_lb_key_space_changed(instance, current, replacement);
            instance
                .limiter
                .commit_lb_generation(generation, reset_tracking_space);
        }
    }

    pub(crate) fn get_plugins(&self, proxy_id: &str) -> Arc<Vec<Arc<dyn Plugin>>> {
        if let Some(plugins) = self.proxy_plugins.get(proxy_id) {
            Arc::clone(plugins)
        } else {
            Arc::clone(&self.global_plugins)
        }
    }

    fn protocol_entry(&self, proxy_id: &str, protocol: ProxyProtocol) -> Option<&ProtocolEntry> {
        self.protocol_snapshot
            .proxy
            .get(proxy_id)
            .and_then(|m| m.get(&protocol))
            .or_else(|| self.protocol_snapshot.global.get(&protocol))
    }

    pub(crate) fn get_plugins_for_protocol(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_auth_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.auth_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_authorize_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.authorize_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_backend_admission_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.backend_admission_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_backend_path_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.backend_path_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_request_headers_to_redact(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<String>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.request_headers_to_redact))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_initial_response_header_policy_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.initial_response_header_policy_plugins))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_initial_response_header_policy_names(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<String>> {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| Arc::clone(&entry.phase.initial_response_header_policy_names))
            .unwrap_or_else(|| Arc::new(Vec::new()))
    }

    pub(crate) fn get_capabilities(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> PluginCapabilities {
        self.protocol_entry(proxy_id, protocol)
            .map(|entry| entry.phase.capabilities)
            .unwrap_or_default()
    }

    pub(crate) fn requires_response_body_buffering(&self, proxy_id: &str) -> bool {
        self.requires_buffering
            .get(proxy_id)
            .copied()
            .unwrap_or(self.global_requires_buffering)
    }

    pub(crate) fn requires_request_body_buffering(&self, proxy_id: &str) -> bool {
        self.requires_request_buffering
            .get(proxy_id)
            .copied()
            .unwrap_or(self.global_requires_request_buffering)
    }

    pub(crate) fn requires_ws_frame_hooks(&self, proxy_id: &str) -> bool {
        self.requires_ws_frame
            .get(proxy_id)
            .copied()
            .unwrap_or(self.global_requires_ws_frame)
    }

    pub(crate) fn request_view(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> PluginCacheRequestView {
        let capabilities = self.get_capabilities(proxy_id, protocol);
        let backend_path_plugins = capabilities
            .has(PluginCapabilities::HAS_BACKEND_PATH_PLUGINS)
            .then(|| self.get_backend_path_plugins(proxy_id, protocol));
        PluginCacheRequestView {
            plugins: self.get_plugins_for_protocol(proxy_id, protocol),
            auth_plugins: self.get_auth_plugins(proxy_id, protocol),
            authorize_plugins: self.get_authorize_plugins(proxy_id, protocol),
            backend_admission_plugins: self.get_backend_admission_plugins(proxy_id, protocol),
            backend_path_plugins,
            request_headers_to_redact: self.get_request_headers_to_redact(proxy_id, protocol),
            initial_response_header_policy_plugins: self
                .get_initial_response_header_policy_plugins(proxy_id, protocol),
            initial_response_header_policy_names: self
                .get_initial_response_header_policy_names(proxy_id, protocol),
            capabilities,
            requires_response_body_buffering: self.requires_response_body_buffering(proxy_id),
            requires_request_body_buffering: self.requires_request_body_buffering(proxy_id),
            requires_ws_frame_hooks: self.requires_ws_frame_hooks(proxy_id),
        }
    }
}

/// Request-scoped plugin cache values for one proxy/protocol pair.
///
/// Built from one cache generation near the start of request handling. It
/// stores only the values that request paths need, so the full plugin-cache
/// snapshot does not stay pinned across plugin/backend awaits.
#[derive(Clone)]
pub struct PluginCacheRequestView {
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    auth_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    authorize_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    backend_admission_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    backend_path_plugins: Option<Arc<Vec<Arc<dyn Plugin>>>>,
    request_headers_to_redact: Arc<Vec<String>>,
    initial_response_header_policy_plugins: Arc<Vec<Arc<dyn Plugin>>>,
    initial_response_header_policy_names: Arc<Vec<String>>,
    capabilities: PluginCapabilities,
    requires_response_body_buffering: bool,
    requires_request_body_buffering: bool,
    requires_ws_frame_hooks: bool,
}

impl PluginCacheRequestView {
    /// Get pre-resolved protocol-filtered plugins from this request view.
    pub fn plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.plugins)
    }

    /// Get pre-computed auth plugins from this request view.
    pub fn auth_plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.auth_plugins)
    }

    /// Get pre-computed authorization plugins from this request view.
    pub fn authorize_plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.authorize_plugins)
    }

    /// Get pre-computed backend admission plugins from this request view.
    pub fn backend_admission_plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.backend_admission_plugins)
    }

    /// Get plugins that inspect the finalized backend path.
    pub fn backend_path_plugins(&self) -> &[Arc<dyn Plugin>] {
        self.backend_path_plugins
            .as_deref()
            .map(Vec::as_slice)
            .unwrap_or(&[])
    }

    /// Get credential-bearing request headers precomputed for safe downstream views.
    pub fn request_headers_to_redact(&self) -> Arc<Vec<String>> {
        Arc::clone(&self.request_headers_to_redact)
    }

    /// Get the pre-filtered deterministic initial-response header policy chain.
    pub fn initial_response_header_policy_plugins(&self) -> Arc<Vec<Arc<dyn Plugin>>> {
        Arc::clone(&self.initial_response_header_policy_plugins)
    }

    /// Get canonical field names touched by initial-response policy.
    pub fn initial_response_header_policy_names(&self) -> Arc<Vec<String>> {
        Arc::clone(&self.initial_response_header_policy_names)
    }

    /// Get pre-computed capability bitset from this request view.
    pub fn capabilities(&self) -> PluginCapabilities {
        self.capabilities
    }

    /// Check response-body buffering requirement from this request view.
    pub fn requires_response_body_buffering(&self) -> bool {
        self.requires_response_body_buffering
    }

    /// Check request-body buffering requirement from this request view.
    pub fn requires_request_body_buffering(&self) -> bool {
        self.requires_request_body_buffering
    }

    /// Check WebSocket frame-hook requirement from this request view.
    pub fn requires_ws_frame_hooks(&self) -> bool {
        self.requires_ws_frame_hooks
    }

    /// Check whether any protocol-compatible plugin opted into response-stream
    /// inspection or terminal hooks. Precomputed at cache-build time so the
    /// common response path does not scan plugins per request.
    pub fn requires_response_stream_hooks(&self) -> bool {
        self.capabilities
            .has(PluginCapabilities::HAS_RESPONSE_STREAM_HOOKS)
    }
}

/// Pre-resolved plugin cache that avoids per-request plugin creation.
///
/// Plugins are created once at config load time and cached per proxy_id.
/// This is critical for stateful plugins like `rate_limiting` whose internal
/// DashMap state must persist across requests. Without caching, a new
/// rate limiter is created per request and limits are never enforced.
///
/// All mutable state is bundled inside a single `ArcSwap<PluginCacheInner>`
/// so every config reload swaps all fields atomically — readers see either
/// the old generation or the new generation, never a mix.
pub struct PluginCache {
    inner: ArcSwap<PluginCacheInner>,
    /// Shared HTTP client for plugins that make outbound network calls.
    http_client: PluginHttpClient,
}

fn validate_prometheus_metrics_ownership(config: &GatewayConfig) -> Result<(), String> {
    let mut enabled = config
        .plugin_configs
        .iter()
        .filter(|plugin| plugin.enabled && plugin.plugin_name == "prometheus_metrics");
    let Some(first) = enabled.next() else {
        return Ok(());
    };
    if first.scope != PluginScope::Global {
        return Err(format!(
            "PluginConfig '{}' (prometheus_metrics) must have scope 'global'",
            first.id
        ));
    }
    if let Some(second) = enabled.next() {
        return Err(format!(
            "prometheus_metrics permits at most one enabled global instance; found '{}' and '{}'",
            first.id, second.id
        ));
    }
    Ok(())
}

impl PluginCache {
    /// Build a new plugin cache from the given config with a default HTTP client.
    #[allow(dead_code)]
    pub fn new(config: &GatewayConfig) -> Result<Self, String> {
        let http_client = PluginHttpClient::default();
        Self::with_http_client(config, http_client)
    }

    /// Build a new plugin cache with a shared HTTP client configured from
    /// the gateway's pool settings. All plugins that make outbound HTTP calls
    /// (http_logging, future OTel exporters, etc.) share this client for
    /// connection reuse and keepalive.
    pub fn with_http_client(
        config: &GatewayConfig,
        http_client: PluginHttpClient,
    ) -> Result<Self, String> {
        let inner = Self::build_inner(config, &http_client)?;
        Ok(Self {
            inner: ArcSwap::new(inner),
            http_client,
        })
    }

    /// Borrow the shared HTTP client configured at construction. Used by
    /// out-of-band runtime tasks (mesh federation poller, etc.) that need
    /// the same DNS cache, pool settings, and TLS configuration as plugins.
    pub fn http_client(&self) -> &PluginHttpClient {
        &self.http_client
    }

    pub(crate) fn build_inner(
        config: &GatewayConfig,
        http_client: &PluginHttpClient,
    ) -> Result<Arc<PluginCacheInner>, String> {
        Self::build_inner_with_prior_adaptive_states(config, http_client, &HashMap::new())
    }

    fn build_inner_with_prior_adaptive_states(
        config: &GatewayConfig,
        http_client: &PluginHttpClient,
        current_adaptive_states: &AdaptiveConcurrencyInstanceMap,
    ) -> Result<Arc<PluginCacheInner>, String> {
        validate_prometheus_metrics_ownership(config)?;
        let (
            proxy_map,
            globals,
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            ws_frame_map,
            global_needs_ws_frame,
            proxy_group_plugins,
            adaptive_concurrency_instances,
            country_mmdb_instances,
            country_mmdb_snapshot_bytes,
        ) = Self::build_cache(config, http_client, current_adaptive_states)?;
        let snapshot = build_protocol_snapshot(&proxy_map, &globals);

        Ok(Arc::new(PluginCacheInner::new(
            proxy_map,
            globals,
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            snapshot,
            ws_frame_map,
            global_needs_ws_frame,
            proxy_group_plugins,
            adaptive_concurrency_instances,
            country_mmdb_instances,
            country_mmdb_snapshot_bytes,
        )))
    }

    pub(crate) fn build_inner_with_existing_client(
        &self,
        config: &GatewayConfig,
    ) -> Result<Arc<PluginCacheInner>, String> {
        let current = self.inner.load();
        Self::build_inner_with_prior_adaptive_states(
            config,
            &self.http_client,
            &current.adaptive_concurrency_instances,
        )
    }

    pub(crate) fn store_inner(&self, inner: Arc<PluginCacheInner>) {
        inner.prepare_adaptive_concurrency_generations();
        self.inner.store(Arc::clone(&inner));
        inner.commit_adaptive_concurrency_generations();
    }

    pub(crate) fn load_inner(&self) -> Arc<PluginCacheInner> {
        self.inner.load_full()
    }

    pub(crate) fn retain_active_uris_for_inner(inner: &PluginCacheInner) {
        let requirements =
            collect_active_jwks_requirements(&inner.proxy_plugins, &inner.global_plugins);
        retain_active_requirements(&requirements);
    }

    /// Build a request-scoped view of plugin-cache values for one proxy/protocol.
    ///
    /// Use this when a request needs more than one plugin-cache-derived value.
    /// The cache is loaded once, all returned values come from that generation,
    /// and the full cache snapshot is released before request processing awaits.
    pub fn request_view(&self, proxy_id: &str, protocol: ProxyProtocol) -> PluginCacheRequestView {
        let inner = self.inner.load();
        inner.request_view(proxy_id, protocol)
    }

    /// Atomically rebuild the cache when config changes. Most old plugin
    /// instances are dropped only after in-flight requests release them;
    /// adaptive-concurrency policies additionally carry coherent admission
    /// state into compatible replacement generations.
    ///
    /// Returns `Err` if any enabled plugin config cannot be resolved or fails validation.
    pub fn rebuild(&self, config: &GatewayConfig) -> Result<(), String> {
        let inner = self.build_inner_with_existing_client(config)?;

        // Single atomic swap — readers see either the old or new generation.
        self.store_inner(Arc::clone(&inner));

        // Clean up JWKS cache entries (and their background refresh tasks)
        // after commit so a staged rebuild that fails validation cannot prune
        // the still-live cache.
        Self::retain_active_uris_for_inner(&inner);
        Ok(())
    }

    /// Incrementally update the plugin cache, only rebuilding plugins for
    /// proxies identified in `proxy_ids_to_rebuild`. All other proxy plugin
    /// lists — including their stateful plugin instances (rate limiters, etc.)
    /// — are preserved unchanged.
    ///
    /// Also rebuilds global plugins if `rebuild_globals` is true (i.e., a
    /// global-scoped plugin config was added/modified/removed).
    /// `force_node_local_refresh` additionally rebuilds every active country
    /// MMDB instance for DP full snapshots whose CP source cannot hand off
    /// node-local validation snapshots.
    /// Returns `Err` if any enabled plugin config cannot be resolved or fails
    /// validation during incremental update, matching the behavior of `rebuild()`.
    pub(crate) fn build_delta_inner(
        &self,
        current: &PluginCacheInner,
        config: &GatewayConfig,
        proxy_ids_to_rebuild: &HashSet<String>,
        removed_proxy_ids: &[String],
        rebuild_globals: bool,
        force_node_local_refresh: bool,
    ) -> Result<Arc<PluginCacheInner>, String> {
        validate_prometheus_metrics_ownership(config)?;
        let paths = config.country_mmdb_file_dependency_paths();
        let country_mmdb_load_session = if force_node_local_refresh && !paths.is_empty() {
            CountryMmdbLoadSession::for_node_local_refresh(&paths)?
        } else {
            CountryMmdbLoadSession::claim(&paths)?
        };
        self.build_delta_inner_with_country_mmdb_session(
            current,
            config,
            proxy_ids_to_rebuild,
            removed_proxy_ids,
            rebuild_globals,
            &country_mmdb_load_session,
        )
    }

    /// Refresh country MMDB plugins even when the serialized gateway config has
    /// no delta. Serving modes normally require an accepted validation handoff;
    /// DP full snapshots set `force_node_local_refresh` because CP intentionally
    /// skips node-local file validation and therefore cannot create one.
    /// Returning `None` means there was no handoff and no forced refresh, so the
    /// caller may keep the live plugin snapshot unchanged.
    pub(crate) fn build_country_mmdb_reload_inner(
        &self,
        current: &PluginCacheInner,
        config: &GatewayConfig,
        force_node_local_refresh: bool,
    ) -> Result<Option<Arc<PluginCacheInner>>, String> {
        validate_prometheus_metrics_ownership(config)?;
        let paths = config.country_mmdb_file_dependency_paths();
        if paths.is_empty() {
            return Ok(None);
        }
        let country_mmdb_load_session = if force_node_local_refresh {
            CountryMmdbLoadSession::for_node_local_refresh(&paths)?
        } else {
            CountryMmdbLoadSession::claim(&paths)?
        };
        if !country_mmdb_load_session.refresh_country_mmdb_plugins() {
            return Ok(None);
        }
        self.build_delta_inner_with_country_mmdb_session(
            current,
            config,
            &HashSet::new(),
            &[],
            false,
            &country_mmdb_load_session,
        )
        .map(Some)
    }

    fn build_delta_inner_with_country_mmdb_session(
        &self,
        current: &PluginCacheInner,
        config: &GatewayConfig,
        proxy_ids_to_rebuild: &HashSet<String>,
        removed_proxy_ids: &[String],
        rebuild_globals: bool,
        country_mmdb_load_session: &CountryMmdbLoadSession,
    ) -> Result<Arc<PluginCacheInner>, String> {
        let mut plugin_errors: Vec<String> = Vec::new();
        let mut proxy_ids_to_rebuild = proxy_ids_to_rebuild.clone();
        let mut rebuild_adaptive_globals = false;
        include_adaptive_concurrency_route_rebuilds(
            &current.adaptive_concurrency_instances,
            config,
            &mut proxy_ids_to_rebuild,
            &mut rebuild_adaptive_globals,
        );
        let mut global_plugins_changed = rebuild_globals || rebuild_adaptive_globals;
        let mut adaptive_concurrency_instances =
            retained_adaptive_concurrency_states(&current.adaptive_concurrency_instances, config);
        let force_country_mmdb_refresh = country_mmdb_load_session.refresh_country_mmdb_plugins();
        let active_country_mmdb_configs: HashMap<CountryMmdbPluginId, &PluginConfig> = config
            .plugin_configs
            .iter()
            .filter(|plugin_config| country_mmdb_plugin_is_active(config, plugin_config))
            .map(|plugin_config| (country_mmdb_plugin_id(plugin_config), plugin_config))
            .collect();
        let mut forced_country_mmdb_instances = CountryMmdbPluginInstanceMap::new();
        if force_country_mmdb_refresh {
            for (id, plugin_config) in &active_country_mmdb_configs {
                match try_create_plugin(
                    plugin_config,
                    config,
                    &self.http_client,
                    country_mmdb_load_session,
                    &current.adaptive_concurrency_instances,
                    &mut adaptive_concurrency_instances,
                ) {
                    Ok(Some(plugin)) => {
                        forced_country_mmdb_instances.insert(id.clone(), plugin);
                    }
                    Ok(None) => {}
                    Err(error) => {
                        error!("Config reload: {}", error);
                        plugin_errors.push(error);
                    }
                }
            }
        }
        let mut country_mmdb_instances = if force_country_mmdb_refresh {
            forced_country_mmdb_instances.clone()
        } else {
            current
                .country_mmdb_instances
                .iter()
                .filter(|(id, _)| active_country_mmdb_configs.contains_key(*id))
                .map(|(id, plugin)| (id.clone(), Arc::clone(plugin)))
                .collect()
        };
        let forced_country_mmdb_instances =
            force_country_mmdb_refresh.then_some(&forced_country_mmdb_instances);
        let country_mmdb_replacements: HashMap<usize, Arc<dyn Plugin>> =
            if let Some(forced) = forced_country_mmdb_instances {
                current
                    .country_mmdb_instances
                    .iter()
                    .filter_map(|(id, plugin)| {
                        forced.get(id).map(|replacement| {
                            (
                                Arc::as_ptr(plugin) as *const () as usize,
                                Arc::clone(replacement),
                            )
                        })
                    })
                    .collect()
            } else {
                HashMap::new()
            };

        // Rebuild globals if any global plugin config changed
        let mut new_globals = if rebuild_globals {
            let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();

            // Stage the named-schema registry first so subsequent global /
            // proxy plugins can resolve `schema_ref` against the new state
            // via the reload thread's staging-visibility. The bracket is
            // left OPEN here — commit/abort runs once the rest of the
            // delta build has succeeded or failed (see plugin_errors
            // handling below), so the registry stays atomically tied to
            // the PluginCache that gets swapped in.
            //
            // This runs for every global-plugin rebuild, not just when
            // `transaction_log_schema` itself changed — the bracket is
            // cheap (one Mutex acquire + empty HashMap) and guarantees
            // the registry stays in sync even if a sibling global plugin
            // was the trigger for the rebuild.
            crate::plugins::utils::log_schema::registry::begin_reload();
            for pc in &config.plugin_configs {
                if !pc.enabled || pc.scope != PluginScope::Global {
                    continue;
                }
                if pc.plugin_name != "transaction_log_schema" {
                    continue;
                }
                match try_create_plugin_for_cache(
                    pc,
                    config,
                    &self.http_client,
                    country_mmdb_load_session,
                    forced_country_mmdb_instances,
                    &mut country_mmdb_instances,
                    &current.adaptive_concurrency_instances,
                    &mut adaptive_concurrency_instances,
                ) {
                    Ok(Some(plugin)) => global_plugins.push(plugin),
                    Ok(None) => {}
                    Err(e) => {
                        error!("Config reload: {}", e);
                        plugin_errors.push(e);
                    }
                }
            }

            for pc in &config.plugin_configs {
                if !pc.enabled {
                    continue;
                }
                if pc.plugin_name == "transaction_log_schema" {
                    continue; // already constructed
                }
                if pc.scope == PluginScope::Global {
                    match try_create_plugin_for_cache(
                        pc,
                        config,
                        &self.http_client,
                        country_mmdb_load_session,
                        forced_country_mmdb_instances,
                        &mut country_mmdb_instances,
                        &current.adaptive_concurrency_instances,
                        &mut adaptive_concurrency_instances,
                    ) {
                        Ok(Some(plugin)) => global_plugins.push(plugin),
                        Ok(None) => {}
                        Err(e) => {
                            error!("Config reload: {}", e);
                            plugin_errors.push(e);
                        }
                    }
                }
            }
            global_plugins.sort_by_key(|p| p.priority());
            if let Err(e) = install_cors_finalizer(&mut global_plugins) {
                plugin_errors.push(format!("global plugins: {e}"));
            }
            if let Err(e) = install_mesh_route_dispatch_finalizer(&mut global_plugins) {
                plugin_errors.push(format!("global plugins: {e}"));
            }
            if let Err(e) = validate_hmac_request_transform_composition(&global_plugins) {
                plugin_errors.push(format!("global plugins: {e}"));
            }
            Arc::new(global_plugins)
        } else if rebuild_adaptive_globals {
            // Route compatibility can require a fresh global adaptive view
            // without any global PluginConfig changing. Replace only those
            // wrappers so unrelated stateful globals retain their Arc/state.
            let mut global_plugins = current
                .global_plugins
                .iter()
                .filter(|plugin| plugin.name() != "adaptive_concurrency")
                .cloned()
                .collect::<Vec<_>>();
            for pc in &config.plugin_configs {
                if !pc.enabled
                    || pc.scope != PluginScope::Global
                    || pc.plugin_name != "adaptive_concurrency"
                {
                    continue;
                }
                match try_create_plugin_for_cache(
                    pc,
                    config,
                    &self.http_client,
                    country_mmdb_load_session,
                    forced_country_mmdb_instances,
                    &mut country_mmdb_instances,
                    &current.adaptive_concurrency_instances,
                    &mut adaptive_concurrency_instances,
                ) {
                    Ok(Some(plugin)) => global_plugins.push(plugin),
                    Ok(None) => {}
                    Err(e) => {
                        error!("Config reload: {}", e);
                        plugin_errors.push(e);
                    }
                }
            }
            global_plugins.sort_by_key(|plugin| plugin.priority());
            if let Err(e) = install_cors_finalizer(&mut global_plugins) {
                plugin_errors.push(format!("global plugins: {e}"));
            }
            if let Err(e) = install_mesh_route_dispatch_finalizer(&mut global_plugins) {
                plugin_errors.push(format!("global plugins: {e}"));
            }
            Arc::new(global_plugins)
        } else {
            Arc::clone(&current.global_plugins)
        };
        if force_country_mmdb_refresh {
            let (replaced_globals, changed) =
                replace_country_mmdb_instances(&new_globals, &country_mmdb_replacements);
            new_globals = replaced_globals;
            global_plugins_changed |= changed;
        }

        // Build index of proxy-scoped plugin configs for efficient lookup
        let mut proxy_scoped_configs: HashMap<&str, Vec<&crate::config::types::PluginConfig>> =
            HashMap::new();
        let mut proxy_group_configs: HashMap<&str, &crate::config::types::PluginConfig> =
            HashMap::new();
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.scope == PluginScope::Proxy
                && let Some(ref proxy_id) = pc.proxy_id
            {
                proxy_scoped_configs
                    .entry(proxy_id.as_str())
                    .or_default()
                    .push(pc);
            } else if pc.scope == PluginScope::ProxyGroup {
                proxy_group_configs.insert(pc.id.as_str(), pc);
            }
        }

        let active_proxy_group_ids: HashSet<&str> = config
            .proxies
            .iter()
            .flat_map(|proxy| proxy.plugins.iter())
            .map(|assoc| assoc.plugin_config_id.as_str())
            .filter(|id| proxy_group_configs.contains_key(*id))
            .collect();

        // Shared ProxyGroup plugin instances. Start with unchanged current
        // instances that are still referenced in the post-delta config. This
        // keeps state shared with unchanged proxies but drops cascade-deleted
        // group state once the last proxy association is removed.
        let mut group_plugin_instances: ProxyGroupInstanceMap = current
            .proxy_group_plugins
            .iter()
            .filter_map(|(id, existing)| {
                if !active_proxy_group_ids.contains(id.as_str()) {
                    return None;
                }
                let pc = proxy_group_configs.get(id.as_str())?;
                if pc.plugin_name == "adaptive_concurrency"
                    && !adaptive_concurrency_instances
                        .contains_key(&adaptive_concurrency_policy_id(pc))
                {
                    return None;
                }
                if force_country_mmdb_refresh && pc.plugin_name == "geo_restriction" {
                    return None;
                }
                if same_proxy_group_plugin_config(&existing.config, pc) {
                    Some((id.clone(), existing.clone()))
                } else {
                    None
                }
            })
            .collect();
        if let Some(forced) = forced_country_mmdb_instances {
            for (id, plugin_config) in &active_country_mmdb_configs {
                if plugin_config.scope != PluginScope::ProxyGroup {
                    continue;
                }
                if let Some(plugin) = forced.get(id) {
                    group_plugin_instances.insert(
                        plugin_config.id.clone(),
                        ProxyGroupPluginInstance {
                            plugin: Arc::clone(plugin),
                            config: (*plugin_config).clone(),
                        },
                    );
                }
            }
        }

        // Clone the current map and patch it
        let mut new_map: HashMap<String, Arc<Vec<Arc<dyn Plugin>>>> = current.proxy_plugins.clone();

        // Remove deleted proxies
        for id in removed_proxy_ids {
            new_map.remove(id);
        }

        // Rebuild only the affected proxies' plugin lists
        for proxy in &config.proxies {
            if !proxy_ids_to_rebuild.contains(&proxy.id) {
                continue;
            }

            let mut merged: Vec<Arc<dyn Plugin>> = new_globals.as_ref().clone();
            let global_ptrs: HashSet<usize> = merged
                .iter()
                .map(|p| Arc::as_ptr(p) as *const () as usize)
                .collect();

            let proxy_plugin_ids: HashSet<&str> = proxy
                .plugins
                .iter()
                .map(|a| a.plugin_config_id.as_str())
                .collect();

            if let Some(scoped_configs) = proxy_scoped_configs.get(proxy.id.as_str()) {
                for pc in scoped_configs {
                    if proxy_plugin_ids.contains(pc.id.as_str()) {
                        match try_create_plugin_for_cache(
                            pc,
                            config,
                            &self.http_client,
                            country_mmdb_load_session,
                            forced_country_mmdb_instances,
                            &mut country_mmdb_instances,
                            &current.adaptive_concurrency_instances,
                            &mut adaptive_concurrency_instances,
                        ) {
                            Ok(Some(plugin)) => {
                                // Detect when an auto-emitted plugin instance
                                // (Istio VirtualService translator helpers) is
                                // about to shadow an operator-configured global
                                // of the same name. The operator's global will
                                // not apply to this proxy, which may surprise
                                // operators who expected the global's static
                                // rules to also run for VS-translated routes.
                                // Emit a warn so the silent shadowing is at
                                // least operator-visible.
                                if pc.id.starts_with("__istio_vs_") {
                                    let shadowed = merged.iter().any(|p| {
                                        p.name() == plugin.name()
                                            && global_ptrs
                                                .contains(&(Arc::as_ptr(p) as *const () as usize))
                                    });
                                    if shadowed {
                                        warn!(
                                            proxy = %proxy.id,
                                            plugin = plugin.name(),
                                            auto_emit_id = %pc.id,
                                            "Istio VirtualService translator auto-emitted a proxy-scoped {} instance to consume route-level header transforms; this shadows the operator-configured global {} on this proxy. Move the global's rules to the VirtualService or pre-create a proxy-scoped instance with the merged ruleset to retain both behaviors.",
                                            plugin.name(),
                                            plugin.name(),
                                        );
                                    }
                                }
                                // Remove only GLOBAL plugins of the same name.
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => {
                                error!(proxy_id = %proxy.id, "Config reload: {}", e);
                                plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e));
                            }
                        }
                    }
                }
            }

            // Resolve proxy_group-scoped plugins via the proxy's association list
            for assoc in &proxy.plugins {
                if let Some(pc) = proxy_group_configs.get(assoc.plugin_config_id.as_str()) {
                    if let Some(existing) = group_plugin_instances.get(pc.id.as_str()) {
                        let plugin = Arc::clone(&existing.plugin);
                        remove_shadowed_global_plugin(&mut merged, &global_ptrs, plugin.name());
                        merged.push(plugin);
                    } else {
                        match try_create_plugin_for_cache(
                            pc,
                            config,
                            &self.http_client,
                            country_mmdb_load_session,
                            forced_country_mmdb_instances,
                            &mut country_mmdb_instances,
                            &current.adaptive_concurrency_instances,
                            &mut adaptive_concurrency_instances,
                        ) {
                            Ok(Some(plugin)) => {
                                group_plugin_instances.insert(
                                    pc.id.clone(),
                                    ProxyGroupPluginInstance {
                                        plugin: Arc::clone(&plugin),
                                        config: (*pc).clone(),
                                    },
                                );
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => {
                                error!(
                                    proxy_id = %proxy.id,
                                    plugin_config_id = %pc.id,
                                    "Config reload: {}",
                                    e
                                );
                                plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e));
                            }
                        }
                    }
                }
            }

            merged.sort_by_key(|p| p.priority());
            if let Err(e) = install_cors_finalizer(&mut merged) {
                plugin_errors.push(format!("proxy_id={}: {e}", proxy.id));
            }
            if let Err(e) = install_mesh_route_dispatch_finalizer(&mut merged) {
                plugin_errors.push(format!("proxy_id={}: {e}", proxy.id));
            }
            if let Err(e) = validate_hmac_request_transform_composition(&merged) {
                plugin_errors.push(format!("proxy_id={}: {e}", proxy.id));
            }
            new_map.insert(proxy.id.clone(), Arc::new(merged));
        }

        // An accepted file-dependency generation is independent of serialized
        // ConfigDelta timestamps. Patch unchanged proxy views by old geo Arc
        // identity so only geo instances change and unrelated state survives.
        let mut proxy_ids_to_refresh = proxy_ids_to_rebuild.clone();
        if force_country_mmdb_refresh {
            for (proxy_id, plugins) in &mut new_map {
                let (replacement, changed) =
                    replace_country_mmdb_instances(plugins, &country_mmdb_replacements);
                if changed {
                    *plugins = replacement;
                    proxy_ids_to_refresh.insert(proxy_id.clone());
                }
            }
        }

        // Update buffering maps for changed proxies
        let mut new_buffering: BufferingMap = current.requires_buffering.clone();
        let mut new_req_buffering: RequestBufferingMap = current.requires_request_buffering.clone();
        let mut new_ws_frame: WsFrameMap = current.requires_ws_frame.clone();
        for id in removed_proxy_ids {
            new_buffering.remove(id);
            new_req_buffering.remove(id);
            new_ws_frame.remove(id);
        }
        for proxy in &config.proxies {
            if proxy_ids_to_refresh.contains(&proxy.id)
                && let Some(plugins) = new_map.get(&proxy.id)
            {
                new_buffering.insert(
                    proxy.id.clone(),
                    plugins.iter().any(|p| p.requires_response_body_buffering()),
                );
                new_req_buffering.insert(
                    proxy.id.clone(),
                    plugins.iter().any(|p| p.requires_request_body_buffering()),
                );
                new_ws_frame.insert(
                    proxy.id.clone(),
                    plugins.iter().any(|p| p.requires_ws_frame_hooks()),
                );
            }
        }

        // Reject the delta if any enabled plugin failed validation or could
        // not be resolved. The staged generation has not been published, so
        // callers keep serving the last known-good cache.
        // When `rebuild_globals` was true, we opened a registry reload
        // bracket above — abort it so the process-global named-schema
        // registry doesn't get mutated by a config that's being rejected.
        if !plugin_errors.is_empty() {
            if rebuild_globals {
                crate::plugins::utils::log_schema::registry::abort_reload();
            }
            return Err(format!(
                "Config reload rejected: {} plugin config(s) failed validation: {}",
                plugin_errors.len(),
                plugin_errors.join("; ")
            ));
        }

        let country_mmdb_snapshot_bytes = match country_mmdb_snapshot_bytes(&new_map, &new_globals)
        {
            Ok(bytes) => bytes,
            Err(error) => {
                if rebuild_globals {
                    crate::plugins::utils::log_schema::registry::abort_reload();
                }
                return Err(format!("Config reload rejected: {error}"));
            }
        };

        if let Err(error) = start_background_tasks(&new_map, &new_globals) {
            if rebuild_globals {
                crate::plugins::utils::log_schema::registry::abort_reload();
            }
            return Err(format!("Config reload rejected: {error}"));
        }

        // Rebuild protocol snapshot (plugins + phase data) for changed proxies.
        // Clone-and-patch from the current snapshot so unchanged proxies are preserved.
        let mut new_proxy_proto = current.protocol_snapshot.proxy.clone();
        for id in removed_proxy_ids {
            new_proxy_proto.remove(id);
        }
        for proxy in &config.proxies {
            if proxy_ids_to_refresh.contains(&proxy.id)
                && let Some(plugins) = new_map.get(&proxy.id)
            {
                let mut inner = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
                for &proto in &ALL_PROXY_PROTOCOLS {
                    inner.insert(proto, build_protocol_entry(plugins, proto));
                }
                new_proxy_proto.insert(proxy.id.clone(), inner);
            }
        }
        let new_global_proto = if global_plugins_changed {
            let mut g = HashMap::with_capacity(ALL_PROXY_PROTOCOLS.len());
            for &proto in &ALL_PROXY_PROTOCOLS {
                g.insert(proto, build_protocol_entry(&new_globals, proto));
            }
            g
        } else {
            current.protocol_snapshot.global.clone()
        };

        let new_global_requires_buffering = if global_plugins_changed {
            new_globals
                .iter()
                .any(|p| p.requires_response_body_buffering())
        } else {
            current.global_requires_buffering
        };
        let new_global_requires_request_buffering = if global_plugins_changed {
            new_globals
                .iter()
                .any(|p| p.requires_request_body_buffering())
        } else {
            current.global_requires_request_buffering
        };
        let new_global_requires_ws_frame = if global_plugins_changed {
            new_globals.iter().any(|p| p.requires_ws_frame_hooks())
        } else {
            current.global_requires_ws_frame
        };

        // Delta build succeeded. If a registry reload bracket was opened
        // above (rebuild_globals == true), promote the staged named
        // schemas now — pairs with the `begin_reload` at the top.
        if rebuild_globals {
            crate::plugins::utils::log_schema::registry::commit_reload();
        }

        Ok(Arc::new(PluginCacheInner::new(
            new_map,
            new_globals,
            new_buffering,
            new_global_requires_buffering,
            new_req_buffering,
            new_global_requires_request_buffering,
            ProtocolSnapshot {
                proxy: new_proxy_proto,
                global: new_global_proto,
            },
            new_ws_frame,
            new_global_requires_ws_frame,
            group_plugin_instances,
            adaptive_concurrency_instances,
            country_mmdb_instances,
            country_mmdb_snapshot_bytes,
        )))
    }

    pub fn apply_delta(
        &self,
        config: &GatewayConfig,
        proxy_ids_to_rebuild: &HashSet<String>,
        removed_proxy_ids: &[String],
        rebuild_globals: bool,
    ) -> Result<(), String> {
        let current = self.inner.load();
        let inner = self.build_delta_inner(
            &current,
            config,
            proxy_ids_to_rebuild,
            removed_proxy_ids,
            rebuild_globals,
            false,
        )?;

        // Single atomic swap — readers see old or new, never a partial state.
        self.store_inner(Arc::clone(&inner));

        // Clean up JWKS cache entries (and their background refresh tasks)
        // after commit so a rejected staged cache never prunes the live set.
        Self::retain_active_uris_for_inner(&inner);

        Ok(())
    }

    /// Get the pre-resolved plugins for a proxy. Lock-free O(1) lookup.
    ///
    /// Returns an Arc to the cached plugin Vec — zero allocation per request.
    /// Callers iterate by reference; no Vec clone needed.
    #[allow(dead_code)] // Used by tests for protocol-agnostic plugin inspection
    pub fn get_plugins(&self, proxy_id: &str) -> Arc<Vec<Arc<dyn Plugin>>> {
        let inner = self.inner.load();
        inner.get_plugins(proxy_id)
    }

    /// Get pre-resolved plugins for a proxy filtered by protocol. Lock-free O(1) lookup.
    ///
    /// Returns only plugins that declare support for the given protocol.
    /// Pre-computed at config reload time — zero filtering cost per request.
    pub fn get_plugins_for_protocol(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        let inner = self.inner.load();
        inner.get_plugins_for_protocol(proxy_id, protocol)
    }

    /// Get pre-computed auth plugins for a proxy+protocol. Lock-free O(1) lookup.
    /// Returns only plugins where `is_auth_plugin() == true`, pre-filtered at
    /// config reload time — eliminates the per-request `filter().collect()` Vec allocation.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn get_auth_plugins(
        &self,
        proxy_id: &str,
        protocol: ProxyProtocol,
    ) -> Arc<Vec<Arc<dyn Plugin>>> {
        let inner = self.inner.load();
        inner.get_auth_plugins(proxy_id, protocol)
    }

    /// Get pre-computed capability bitset for a proxy+protocol. Lock-free O(1) lookup.
    /// Replaces per-request `plugins.iter().any(|p| p.some_flag())` scans.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn get_capabilities(&self, proxy_id: &str, protocol: ProxyProtocol) -> PluginCapabilities {
        let inner = self.inner.load();
        inner.get_capabilities(proxy_id, protocol)
    }

    /// Check whether any plugin for this proxy requires response body buffering.
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn requires_response_body_buffering(&self, proxy_id: &str) -> bool {
        let inner = self.inner.load();
        inner.requires_response_body_buffering(proxy_id)
    }

    /// Check whether any plugin for this proxy may require request body
    /// buffering. This is a config-time upper bound used to skip per-request
    /// plugin scans entirely when body-aware plugins are absent.
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    pub fn requires_request_body_buffering(&self, proxy_id: &str) -> bool {
        let inner = self.inner.load();
        inner.requires_request_body_buffering(proxy_id)
    }

    /// Check whether any plugin for this proxy requires per-frame WebSocket hooks.
    /// When false, the WebSocket frame forwarding loop skips plugins entirely (zero overhead).
    /// Pre-computed at config load time — O(1) lookup instead of per-request iteration.
    ///
    /// Standalone accessor: each call loads the cache independently. Request
    /// paths that need multiple plugin-cache values should use
    /// `request_view()` for cross-accessor generation consistency.
    #[allow(dead_code)] // Retained standalone API; hot request paths use request_view().
    pub fn requires_ws_frame_hooks(&self, proxy_id: &str) -> bool {
        let inner = self.inner.load();
        inner.requires_ws_frame_hooks(proxy_id)
    }

    /// Collect all hostnames that plugins will send traffic to.
    ///
    /// Iterates all cached plugin instances (global + per-proxy) and calls
    /// `warmup_hostnames()` on each. Returns deduplicated hostnames suitable
    /// for feeding into `DnsCache::warmup()`.
    pub fn collect_warmup_hostnames(&self) -> Vec<String> {
        let mut seen = std::collections::HashSet::new();
        let mut result = Vec::new();
        let inner = self.inner.load();

        // Collect from global plugins
        for plugin in inner.global_plugins.iter() {
            for host in plugin.warmup_hostnames() {
                if seen.insert(host.clone()) {
                    result.push(host);
                }
            }
        }

        // Collect from per-proxy plugins
        for plugins in inner.proxy_plugins.values() {
            for plugin in plugins.iter() {
                for host in plugin.warmup_hostnames() {
                    if seen.insert(host.clone()) {
                        result.push(host);
                    }
                }
            }
        }

        result
    }

    /// Total number of tracked rate-limiter keys across all plugin instances.
    pub fn total_rate_limiter_keys(&self) -> usize {
        let mut total = 0usize;
        let mut seen = std::collections::HashSet::new();
        let inner = self.inner.load();

        // Count from global plugins
        for plugin in inner.global_plugins.iter() {
            let ptr = Arc::as_ptr(plugin) as *const () as usize;
            if seen.insert(ptr)
                && let Some(count) = plugin.tracked_keys_count()
            {
                total += count;
            }
        }

        // Count from per-proxy plugins (deduplicate by pointer identity)
        for plugins in inner.proxy_plugins.values() {
            for plugin in plugins.iter() {
                let ptr = Arc::as_ptr(plugin) as *const () as usize;
                if seen.insert(ptr)
                    && let Some(count) = plugin.tracked_keys_count()
                {
                    total += count;
                }
            }
        }

        total
    }

    /// Deduplicated immutable country-MMDB bytes retained by the live cache
    /// generation. Exposed for diagnostics and admission regression tests.
    pub fn country_mmdb_snapshot_bytes(&self) -> u64 {
        self.inner.load().country_mmdb_snapshot_bytes
    }

    /// Number of proxy entries in the cache (for testing).
    #[allow(dead_code)]
    pub fn proxy_count(&self) -> usize {
        self.inner.load().proxy_plugins.len()
    }

    #[allow(clippy::type_complexity)]
    fn build_cache(
        config: &GatewayConfig,
        http_client: &PluginHttpClient,
        current_adaptive_states: &AdaptiveConcurrencyInstanceMap,
    ) -> Result<
        (
            ProxyPluginMap,
            PluginList,
            BufferingMap,
            bool,
            RequestBufferingMap,
            bool,
            WsFrameMap,
            bool,
            ProxyGroupInstanceMap,
            AdaptiveConcurrencyInstanceMap,
            CountryMmdbPluginInstanceMap,
            u64,
        ),
        String,
    > {
        let country_mmdb_load_session =
            CountryMmdbLoadSession::claim(&config.country_mmdb_file_dependency_paths())?;
        // Step 1: Create all enabled global plugins (shared across proxies)
        let mut global_plugins: Vec<Arc<dyn Plugin>> = Vec::new();
        let mut adaptive_concurrency_instances =
            retained_adaptive_concurrency_states(current_adaptive_states, config);
        let mut country_mmdb_instances = CountryMmdbPluginInstanceMap::new();

        // Pre-index proxy-scoped plugin configs by proxy_id for O(1) lookup
        // instead of scanning all plugin_configs for every proxy (O(P×C) → O(P+C)).
        let mut proxy_scoped_configs: HashMap<&str, Vec<&crate::config::types::PluginConfig>> =
            HashMap::new();

        // Collect all enabled-plugin construction errors to report before bailing.
        let mut plugin_errors: Vec<String> = Vec::new();

        // Pre-index proxy_group-scoped plugin configs by config ID for shared
        // instance creation. A single ProxyGroup plugin instance is shared across
        // all proxies that reference it, so stateful plugins (e.g., rate_limiting)
        // share counters across the group.
        let mut proxy_group_configs: HashMap<&str, &crate::config::types::PluginConfig> =
            HashMap::new();

        // First pass: stage the named-schema registry from
        // `transaction_log_schema` global plugins so subsequent plugins
        // can resolve `schema_ref:` against the new state via the
        // reload thread's staging-visibility (see `registry::lookup_named`).
        // The bracket is left OPEN here — `commit_reload` only runs after
        // the rest of the plugin-cache build succeeds; `abort_reload`
        // runs if any plugin fails validation, so the process-global
        // registry stays atomically tied to the cache.
        crate::plugins::utils::log_schema::registry::begin_reload();
        for pc in &config.plugin_configs {
            if !pc.enabled || pc.scope != PluginScope::Global {
                continue;
            }
            if pc.plugin_name != "transaction_log_schema" {
                continue;
            }
            match try_create_plugin_for_cache(
                pc,
                config,
                http_client,
                &country_mmdb_load_session,
                None,
                &mut country_mmdb_instances,
                current_adaptive_states,
                &mut adaptive_concurrency_instances,
            ) {
                Ok(Some(plugin)) => global_plugins.push(plugin),
                Ok(None) => {}
                Err(e) => plugin_errors.push(e),
            }
        }

        // Second pass: everything else, including other globals,
        // proxy-scoped, and proxy_group-scoped configs.
        for pc in &config.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.plugin_name == "transaction_log_schema" {
                continue; // already constructed above
            }
            if pc.scope == PluginScope::Global {
                match try_create_plugin_for_cache(
                    pc,
                    config,
                    http_client,
                    &country_mmdb_load_session,
                    None,
                    &mut country_mmdb_instances,
                    current_adaptive_states,
                    &mut adaptive_concurrency_instances,
                ) {
                    Ok(Some(plugin)) => global_plugins.push(plugin),
                    Ok(None) => {}
                    Err(e) => plugin_errors.push(e),
                }
            } else if pc.scope == PluginScope::Proxy
                && let Some(ref proxy_id) = pc.proxy_id
            {
                proxy_scoped_configs
                    .entry(proxy_id.as_str())
                    .or_default()
                    .push(pc);
            } else if pc.scope == PluginScope::ProxyGroup {
                proxy_group_configs.insert(pc.id.as_str(), pc);
            }
        }

        // Lazily create shared ProxyGroup plugin instances (created on first
        // reference, then Arc-cloned for subsequent proxies in the group).
        let mut group_plugin_instances: ProxyGroupInstanceMap = HashMap::new();

        // Step 2: For each proxy, resolve its full plugin list
        // (global + proxy-scoped, with proxy overriding global of same name)
        let mut proxy_map: HashMap<String, Arc<Vec<Arc<dyn Plugin>>>> =
            HashMap::with_capacity(config.proxies.len());
        let mut buffering_map: BufferingMap = HashMap::with_capacity(config.proxies.len());
        let mut req_buffering_map: RequestBufferingMap =
            HashMap::with_capacity(config.proxies.len());
        let mut ws_frame_map: WsFrameMap = HashMap::with_capacity(config.proxies.len());

        for proxy in &config.proxies {
            // Start with global plugins
            let mut merged = global_plugins.clone(); // Clones Arcs, not instances
            // Track which Arc pointers came from the global list so we can
            // selectively remove only globals when a proxy-scoped plugin of
            // the same name is added (preserving other proxy-scoped instances).
            let global_ptrs: HashSet<usize> = merged
                .iter()
                .map(|p| Arc::as_ptr(p) as *const () as usize)
                .collect();

            // Collect which plugin config IDs this proxy explicitly references
            let proxy_plugin_ids: std::collections::HashSet<&str> = proxy
                .plugins
                .iter()
                .map(|a| a.plugin_config_id.as_str())
                .collect();

            // Resolve proxy-scoped plugins indexed by proxy_id (O(plugins_per_proxy))
            if let Some(scoped_configs) = proxy_scoped_configs.get(proxy.id.as_str()) {
                for pc in scoped_configs {
                    if proxy_plugin_ids.contains(pc.id.as_str()) {
                        match try_create_plugin_for_cache(
                            pc,
                            config,
                            http_client,
                            &country_mmdb_load_session,
                            None,
                            &mut country_mmdb_instances,
                            current_adaptive_states,
                            &mut adaptive_concurrency_instances,
                        ) {
                            Ok(Some(plugin)) => {
                                // Remove only GLOBAL plugins of the same name —
                                // other proxy-scoped instances are preserved,
                                // allowing multiple instances of the same plugin type.
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e)),
                        }
                    }
                }
            }

            // Resolve proxy_group-scoped plugins via the proxy's association list.
            // Shared Arc instances are reused across all proxies in the group.
            for assoc in &proxy.plugins {
                if let Some(pc) = proxy_group_configs.get(assoc.plugin_config_id.as_str()) {
                    if let Some(existing) = group_plugin_instances.get(pc.id.as_str()) {
                        // Reuse the shared instance (Arc::clone is ~5ns)
                        let plugin = Arc::clone(&existing.plugin);
                        remove_shadowed_global_plugin(&mut merged, &global_ptrs, plugin.name());
                        merged.push(plugin);
                    } else {
                        // First proxy to reference this group plugin — create the instance
                        match try_create_plugin_for_cache(
                            pc,
                            config,
                            http_client,
                            &country_mmdb_load_session,
                            None,
                            &mut country_mmdb_instances,
                            current_adaptive_states,
                            &mut adaptive_concurrency_instances,
                        ) {
                            Ok(Some(plugin)) => {
                                group_plugin_instances.insert(
                                    pc.id.clone(),
                                    ProxyGroupPluginInstance {
                                        plugin: Arc::clone(&plugin),
                                        config: (*pc).clone(),
                                    },
                                );
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    plugin.name(),
                                );
                                merged.push(plugin);
                            }
                            Ok(None) => {
                                remove_shadowed_global_plugin(
                                    &mut merged,
                                    &global_ptrs,
                                    &pc.plugin_name,
                                );
                            }
                            Err(e) => plugin_errors.push(format!("proxy_id={}: {}", proxy.id, e)),
                        }
                    }
                }
            }

            // Sort by priority so execution order is deterministic
            merged.sort_by_key(|p| p.priority());
            if let Err(e) = install_cors_finalizer(&mut merged) {
                plugin_errors.push(format!("proxy_id={}: {e}", proxy.id));
            }
            if let Err(e) = install_mesh_route_dispatch_finalizer(&mut merged) {
                plugin_errors.push(format!("proxy_id={}: {e}", proxy.id));
            }
            if let Err(e) = validate_hmac_request_transform_composition(&merged) {
                plugin_errors.push(format!("proxy_id={}: {e}", proxy.id));
            }

            // Pre-compute whether any plugin requires response body buffering
            let needs_buffering = merged.iter().any(|p| p.requires_response_body_buffering());
            buffering_map.insert(proxy.id.clone(), needs_buffering);

            // Pre-compute whether any plugin may require request body buffering
            let needs_req_buffering = merged.iter().any(|p| p.requires_request_body_buffering());
            req_buffering_map.insert(proxy.id.clone(), needs_req_buffering);

            // Pre-compute whether any plugin requires per-frame WebSocket hooks
            let needs_ws_frame = merged.iter().any(|p| p.requires_ws_frame_hooks());
            ws_frame_map.insert(proxy.id.clone(), needs_ws_frame);

            proxy_map.insert(proxy.id.clone(), Arc::new(merged));
        }

        // Sort and validate the global fallback list before committing the
        // staged registry so ordering errors reject the whole cache build.
        global_plugins.sort_by_key(|p| p.priority());
        if let Err(e) = install_cors_finalizer(&mut global_plugins) {
            plugin_errors.push(format!("global plugins: {e}"));
        }
        if let Err(e) = install_mesh_route_dispatch_finalizer(&mut global_plugins) {
            plugin_errors.push(format!("global plugins: {e}"));
        }
        if let Err(e) = validate_hmac_request_transform_composition(&global_plugins) {
            plugin_errors.push(format!("global plugins: {e}"));
        }

        // If any enabled plugin failed validation or could not be resolved,
        // refuse to build the cache.
        // Abort the named-schema reload bracket so the process-global registry
        // is NOT mutated by a config that's being rejected — otherwise the
        // live PluginCache stays on the old plugins while the registry
        // already reflects the rejected reload's schemas.
        if !plugin_errors.is_empty() {
            crate::plugins::utils::log_schema::registry::abort_reload();
            for err in &plugin_errors {
                error!("{}", err);
            }
            return Err(format!(
                "Gateway startup aborted: {} plugin config(s) failed validation: {}",
                plugin_errors.len(),
                plugin_errors.join("; ")
            ));
        }

        let country_mmdb_snapshot_bytes =
            match country_mmdb_snapshot_bytes(&proxy_map, &global_plugins) {
                Ok(bytes) => bytes,
                Err(error) => {
                    crate::plugins::utils::log_schema::registry::abort_reload();
                    return Err(format!("Gateway startup aborted: {error}"));
                }
            };

        if let Err(error) = start_background_tasks(&proxy_map, &global_plugins) {
            crate::plugins::utils::log_schema::registry::abort_reload();
            return Err(format!("Gateway startup aborted: {error}"));
        }

        // All plugins validated — promote the staged named schemas to live.
        // Pairs with the `begin_reload` at the start of this function.
        crate::plugins::utils::log_schema::registry::commit_reload();

        let global_needs_buffering = global_plugins
            .iter()
            .any(|p| p.requires_response_body_buffering());
        let global_needs_req_buffering = global_plugins
            .iter()
            .any(|p| p.requires_request_body_buffering());
        let global_needs_ws_frame = global_plugins.iter().any(|p| p.requires_ws_frame_hooks());

        Ok((
            proxy_map,
            Arc::new(global_plugins),
            buffering_map,
            global_needs_buffering,
            req_buffering_map,
            global_needs_req_buffering,
            ws_frame_map,
            global_needs_ws_frame,
            group_plugin_instances,
            adaptive_concurrency_instances,
            country_mmdb_instances,
            country_mmdb_snapshot_bytes,
        ))
    }
}
