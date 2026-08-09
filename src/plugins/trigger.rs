//! Runtime binding for declarative per-instance plugin execution triggers.
//!
//! The schema, bounds, compiler, and pure evaluator live in
//! [`crate::config::plugin_trigger`]. This module supplies the two things the
//! gateway runtime adds:
//!
//! 1. [`HttpTriggerFacts`] / [`StreamTriggerFacts`] — zero-copy views that bind
//!    a live `RequestContext` / `StreamConnectionContext` to the evaluator's
//!    [`TriggerFacts`] surface.
//! 2. [`PluginTriggerGate`] — the per-instance gate the plugin cache attaches to
//!    a wrapped plugin. It owns the compiled predicate, an opaque process-local
//!    token, and the precomputed bounded metadata key used to report a skip.
//!
//! # Decide-once semantics
//!
//! A trigger is evaluated **at most once per request/connection per instance**
//! and the outcome is memoized on the context. Every later phase of that
//! instance reuses it. That is what makes a skip symmetric: a `before_proxy`
//! rewrite of the path, headers, or query can never flip an instance from
//! "skipped its request hooks" to "runs its response hooks", which would leave
//! half-initialized plugin state behind.
//!
//! # Phase safety
//!
//! A trigger that reads authenticated identity (`consumer`, `auth_method`,
//! `spiffe_id`) is not authoritative before the authentication boundary. Such a
//! trigger simply **does not gate** hooks at or before `authenticate`
//! ([`TriggerPhase::PreAuth`]): the instance runs, and no decision is memoized,
//! so the first `authorize`-or-later hook makes the real decision. Failing
//! toward "run" there is the only fail-closed choice — skipping a guard because
//! its identity input has not been populated yet would widen access.
//!
//! # Redaction
//!
//! A skip records exactly one bounded metadata pair,
//! `plugin_trigger.<plugin-config-id>.skipped = "true"`. Cardinality is bounded
//! by the configured instance count, and no header, cookie, query value, claim,
//! token, or body byte is ever copied into it or logged.

use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use percent_encoding::percent_decode_str;

use crate::config::plugin_trigger::{
    CompiledPluginTrigger, FieldVisitor, PluginTrigger, PluginTriggerProtocol, TriggerFacts,
};
use crate::config::types::{BackendScheme, HttpFlavor, HttpWireTransport};
use crate::plugins::{RequestContext, StreamConnectionContext};

/// Process-local token generator. Tokens are opaque and never persisted; they
/// only have to be unique among the instances a single request can observe.
static NEXT_TRIGGER_TOKEN: AtomicU64 = AtomicU64::new(1);

/// Lifecycle position of the hook asking for a decision.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TriggerPhase {
    /// `prepare_grpc_deadline`, `on_request_received`, `authenticate` — the
    /// authentication boundary has not committed an identity yet.
    PreAuth,
    /// `authorize` and every later request/response phase.
    PostAuth,
}

/// One plugin instance's compiled execution trigger plus its runtime identity.
#[derive(Debug)]
pub struct PluginTriggerGate {
    compiled: Arc<CompiledPluginTrigger>,
    token: u64,
    /// Precomputed `plugin_trigger.<config-id>.skipped` metadata key, so a skip
    /// costs one clone rather than a `format!` on the request path.
    skip_metadata_key: String,
}

impl PluginTriggerGate {
    /// Compile a configured trigger for one plugin-config instance.
    ///
    /// Every rejection here is a config error surfaced by plugin-cache
    /// publication, file-config validation, or the admin API — never a request.
    pub fn compile(trigger: &PluginTrigger, plugin_config_id: &str) -> Result<Self, String> {
        let compiled = CompiledPluginTrigger::compile(trigger)?;
        Ok(Self {
            compiled: Arc::new(compiled),
            token: NEXT_TRIGGER_TOKEN.fetch_add(1, Ordering::Relaxed),
            skip_metadata_key: format!("plugin_trigger.{plugin_config_id}.skipped"),
        })
    }

    /// Whether the compiled predicate reads authenticated identity.
    pub fn reads_authenticated_identity(&self) -> bool {
        self.compiled.reads_authenticated_identity()
    }

    /// Decide whether this instance runs for `ctx`, memoizing the outcome.
    ///
    /// Returns `true` to run. An identity-reading trigger asked at
    /// [`TriggerPhase::PreAuth`] returns `true` without memoizing, leaving the
    /// authoritative decision to the first `authorize`-or-later hook.
    pub fn admits_request(&self, ctx: &mut RequestContext, phase: TriggerPhase) -> bool {
        if let Some(decision) = ctx.plugin_trigger_decision(self.token) {
            return decision;
        }
        if phase == TriggerPhase::PreAuth && self.compiled.reads_authenticated_identity() {
            return true;
        }
        let decision = {
            let facts = HttpTriggerFacts::new(ctx);
            self.compiled.evaluate(&facts)
        };
        let decision = ctx.record_plugin_trigger_decision(self.token, decision);
        if !decision {
            ctx.metadata
                .insert(self.skip_metadata_key.clone(), "true".to_string());
        }
        decision
    }

    /// Read-only view of an already-memoized decision.
    ///
    /// Used by the `&RequestContext` capability predicates (buffering,
    /// enforcement claims) that cannot memoize. It fails closed: an
    /// undecided instance reports "runs", so a trigger can only ever REMOVE
    /// work, never suppress a guard whose decision has not been made.
    pub fn request_decision_or_run(&self, ctx: &RequestContext) -> bool {
        ctx.plugin_trigger_decision(self.token).unwrap_or(true)
    }

    /// Decide whether this instance runs for a stream connection, memoizing the
    /// outcome so `on_stream_connect` and `on_stream_disconnect` agree.
    pub fn admits_stream(&self, ctx: &mut StreamConnectionContext) -> bool {
        if let Some(decision) = ctx.plugin_trigger_decision(self.token) {
            return decision;
        }
        let decision = {
            let facts = StreamTriggerFacts::new(ctx);
            self.compiled.evaluate(&facts)
        };
        let decision = ctx.record_plugin_trigger_decision(self.token, decision);
        if !decision {
            let key = self.skip_metadata_key.clone();
            ctx.insert_metadata(key, "true".to_string());
        }
        decision
    }
}

// ---------------------------------------------------------------------------
// HTTP-family facts
// ---------------------------------------------------------------------------

/// Zero-copy [`TriggerFacts`] view over a live HTTP request context.
pub struct HttpTriggerFacts<'a> {
    ctx: &'a RequestContext,
    host: Option<&'a str>,
    protocols: [PluginTriggerProtocol; 3],
    protocol_len: usize,
}

impl<'a> HttpTriggerFacts<'a> {
    /// Build the view. Everything here is a field read or a borrowed slice —
    /// no allocation, no locks.
    pub fn new(ctx: &'a RequestContext) -> Self {
        let mut protocols = [PluginTriggerProtocol::Http1; 3];
        let mut protocol_len = 0;
        if let Some(transport) = ctx.request_wire_transport() {
            protocols[protocol_len] = match transport {
                HttpWireTransport::Http1 => PluginTriggerProtocol::Http1,
                HttpWireTransport::Http2 => PluginTriggerProtocol::Http2,
                HttpWireTransport::Http3 => PluginTriggerProtocol::Http3,
            };
            protocol_len += 1;
        }
        match ctx.request_http_flavor() {
            HttpFlavor::Grpc => {
                protocols[protocol_len] = PluginTriggerProtocol::Grpc;
                protocol_len += 1;
            }
            HttpFlavor::WebSocket => {
                protocols[protocol_len] = PluginTriggerProtocol::Websocket;
                protocol_len += 1;
            }
            HttpFlavor::Plain => {}
        }
        if ctx.request_is_grpc_web() {
            protocols[protocol_len] = PluginTriggerProtocol::GrpcWeb;
            protocol_len += 1;
        }
        Self {
            ctx,
            host: ctx.request_authority.as_deref().map(authority_host),
            protocols,
            protocol_len,
        }
    }
}

/// Strip an optional `:port` from an already-normalized authority, keeping an
/// IPv6 literal's bracketed form intact.
fn authority_host(authority: &str) -> &str {
    if let Some(rest) = authority.strip_prefix('[') {
        return match rest.find(']') {
            // Include the brackets so `[::1]` compares as written.
            Some(end) => &authority[..end + 2],
            None => authority,
        };
    }
    match authority.rfind(':') {
        Some(index) => &authority[..index],
        None => authority,
    }
}

impl TriggerFacts for HttpTriggerFacts<'_> {
    fn is_http(&self) -> bool {
        true
    }

    fn method(&self) -> Option<&str> {
        Some(self.ctx.method.as_str())
    }

    fn path(&self) -> Option<&str> {
        Some(self.ctx.path.as_str())
    }

    fn host(&self) -> Option<&str> {
        self.host
    }

    fn sni(&self) -> Option<&str> {
        self.ctx.frontend_sni_hostname.as_deref()
    }

    fn protocols(&self) -> &[PluginTriggerProtocol] {
        &self.protocols[..self.protocol_len]
    }

    fn client_ip(&self) -> Option<IpAddr> {
        self.ctx.canonical_client_ip()
    }

    fn namespace(&self) -> Option<&str> {
        self.ctx
            .matched_proxy
            .as_ref()
            .map(|proxy| proxy.namespace.as_str())
    }

    fn proxy_id(&self) -> Option<&str> {
        self.ctx
            .matched_proxy
            .as_ref()
            .map(|proxy| proxy.id.as_str())
    }

    fn listen_port(&self) -> Option<u16> {
        self.ctx.frontend_listen_port
    }

    fn consumer_identity(&self) -> Option<&str> {
        self.ctx
            .identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str())
            .or(self.ctx.authenticated_identity.as_deref())
    }

    fn auth_method(&self) -> Option<&str> {
        self.ctx.auth_method
    }

    fn spiffe_id(&self) -> Option<&str> {
        self.ctx.peer_spiffe_id.as_ref().map(|id| id.as_str())
    }

    fn for_each_header_value(&self, lower_name: &str, visit: &mut FieldVisitor<'_>) {
        // Read the PRISTINE inbound wire view. A trigger must describe what the
        // client actually sent, not what an earlier plugin rewrote — and the
        // memoized decision is taken before any transformer runs anyway.
        // Non-UTF-8 field lines are skipped rather than lossily transcoded, so a
        // hostile byte sequence can never be coerced into matching a pattern.
        if let Some(raw) = self.ctx.raw_headers.as_ref() {
            for value in raw.get_all(lower_name) {
                let Ok(value) = value.to_str() else {
                    continue;
                };
                if !visit(value) {
                    return;
                }
            }
            return;
        }
        // Direct plugin callers and tests that never carried a wire header map
        // fall back to the folded view, which holds one value per name.
        if let Some(value) = self.ctx.headers.get(lower_name) {
            visit(value);
        }
    }

    fn for_each_query_value(&self, name: &str, visit: &mut FieldVisitor<'_>) {
        let Some(query) = self.ctx.raw_query_string() else {
            return;
        };
        for pair in query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (raw_name, raw_value) = match pair.split_once('=') {
                Some((raw_name, raw_value)) => (raw_name, raw_value),
                None => (pair, ""),
            };
            let decoded_name = percent_decode_str(raw_name).decode_utf8_lossy();
            if decoded_name != name {
                continue;
            }
            let decoded_value = percent_decode_str(raw_value).decode_utf8_lossy();
            if !visit(decoded_value.as_ref()) {
                return;
            }
        }
    }

    fn for_each_cookie_value(&self, name: &str, visit: &mut FieldVisitor<'_>) {
        self.for_each_header_value("cookie", &mut |header_value: &str| -> bool {
            for pair in header_value.split(';') {
                let pair = pair.trim();
                if pair.is_empty() {
                    continue;
                }
                let (cookie_name, cookie_value) = match pair.split_once('=') {
                    Some((cookie_name, cookie_value)) => (cookie_name.trim(), cookie_value.trim()),
                    None => (pair, ""),
                };
                if cookie_name != name {
                    continue;
                }
                // A quoted cookie-value is the same value per RFC 6265 §4.1.1.
                let cookie_value = cookie_value
                    .strip_prefix('"')
                    .and_then(|rest| rest.strip_suffix('"'))
                    .unwrap_or(cookie_value);
                if !visit(cookie_value) {
                    return false;
                }
            }
            true
        });
    }
}

// ---------------------------------------------------------------------------
// Stream facts
// ---------------------------------------------------------------------------

/// Zero-copy [`TriggerFacts`] view over a live TCP/UDP/DTLS connection context.
///
/// HTTP-only predicates (method, path, host, header, query, cookie) evaluate to
/// `false` here rather than being silently ignored: a stream connection genuinely
/// has no request line, so "only run on `/orders`" faithfully means "do not run".
pub struct StreamTriggerFacts<'a> {
    ctx: &'a StreamConnectionContext,
    protocols: [PluginTriggerProtocol; 1],
}

impl<'a> StreamTriggerFacts<'a> {
    pub fn new(ctx: &'a StreamConnectionContext) -> Self {
        let protocol = match ctx.backend_scheme {
            BackendScheme::Udp => PluginTriggerProtocol::Udp,
            BackendScheme::Dtls => PluginTriggerProtocol::Dtls,
            _ => PluginTriggerProtocol::Tcp,
        };
        Self {
            ctx,
            protocols: [protocol],
        }
    }
}

impl TriggerFacts for StreamTriggerFacts<'_> {
    fn is_http(&self) -> bool {
        false
    }

    fn method(&self) -> Option<&str> {
        None
    }

    fn path(&self) -> Option<&str> {
        None
    }

    fn host(&self) -> Option<&str> {
        None
    }

    fn sni(&self) -> Option<&str> {
        self.ctx.sni_hostname.as_deref()
    }

    fn protocols(&self) -> &[PluginTriggerProtocol] {
        &self.protocols
    }

    fn client_ip(&self) -> Option<IpAddr> {
        self.ctx.canonical_client_ip()
    }

    fn namespace(&self) -> Option<&str> {
        Some(self.ctx.proxy_namespace.as_str())
    }

    fn proxy_id(&self) -> Option<&str> {
        Some(self.ctx.proxy_id.as_str())
    }

    fn listen_port(&self) -> Option<u16> {
        Some(self.ctx.listen_port)
    }

    fn consumer_identity(&self) -> Option<&str> {
        self.ctx.effective_identity()
    }

    fn auth_method(&self) -> Option<&str> {
        self.ctx.auth_method
    }

    fn spiffe_id(&self) -> Option<&str> {
        None
    }

    fn for_each_header_value(&self, _lower_name: &str, _visit: &mut FieldVisitor<'_>) {}

    fn for_each_query_value(&self, _name: &str, _visit: &mut FieldVisitor<'_>) {}

    fn for_each_cookie_value(&self, _name: &str, _visit: &mut FieldVisitor<'_>) {}
}
