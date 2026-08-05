//! Multiplexed aggregate-router SSE session broker for `mcp_gateway`.
//!
//! Routes MCP JSON-RPC events onto one downstream `text/event-stream`
//! connection per live session, keyed by bounded request/stream identity.
//! Every queue, retained payload, identity, map cardinality, and cleanup
//! horizon is capped. Identities and payloads are never logged; diagnostics
//! are field-specific and value-redacted.

use bytes::Bytes;
use dashmap::DashMap;
use http_body::Frame;
use serde_json::Value;
use std::collections::{HashMap, VecDeque};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, mpsc};

use crate::proxy::body::BoxError;

/// Default max concurrent request streams retained per downstream session.
pub const DEFAULT_MAX_STREAMS_PER_SESSION: usize = 64;
/// Default max queued events waiting for the SSE listener (all streams).
pub const DEFAULT_MAX_QUEUE_EVENTS: usize = 128;
/// Default aggregate retained payload budget for queued + replay events.
pub const DEFAULT_MAX_QUEUE_BYTES: usize = 1024 * 1024;
/// Default max serialized bytes for one multiplexed SSE event payload.
pub const DEFAULT_MAX_EVENT_BYTES: usize = 256 * 1024;
/// Default replay ring capacity (events retained for `Last-Event-ID`).
pub const DEFAULT_MAX_REPLAY_EVENTS: usize = 64;
/// Default max accepted stream-identity UTF-8 bytes (JSON-RPC id string form).
pub const DEFAULT_MAX_STREAM_ID_BYTES: usize = 128;
/// Default max accepted `Last-Event-ID` header bytes.
pub const DEFAULT_MAX_LAST_EVENT_ID_BYTES: usize = 64;
/// Absolute ceilings for operator overrides (fail closed above these).
pub const MAX_STREAMS_PER_SESSION_CEILING: usize = 4_096;
pub const MAX_QUEUE_EVENTS_CEILING: usize = 16_384;
pub const MAX_QUEUE_BYTES_CEILING: usize = 16 * 1024 * 1024;
pub const MAX_EVENT_BYTES_CEILING: usize = 2 * 1024 * 1024;
pub const MAX_REPLAY_EVENTS_CEILING: usize = 4_096;
pub const MAX_STREAM_ID_BYTES_CEILING: usize = 512;
pub const MAX_LAST_EVENT_ID_BYTES_CEILING: usize = 1_024;

/// Channel capacity for one attached SSE listener (frames awaiting poll).
const LISTENER_CHANNEL_CAPACITY: usize = 32;

/// Operator-tunable bounds for the aggregate SSE broker.
#[derive(Debug, Clone)]
pub struct AggregateSseBounds {
    pub max_streams_per_session: usize,
    pub max_queue_events: usize,
    pub max_queue_bytes: usize,
    pub max_event_bytes: usize,
    pub max_replay_events: usize,
    pub max_stream_id_bytes: usize,
    pub max_last_event_id_bytes: usize,
}

impl Default for AggregateSseBounds {
    fn default() -> Self {
        Self {
            max_streams_per_session: DEFAULT_MAX_STREAMS_PER_SESSION,
            max_queue_events: DEFAULT_MAX_QUEUE_EVENTS,
            max_queue_bytes: DEFAULT_MAX_QUEUE_BYTES,
            max_event_bytes: DEFAULT_MAX_EVENT_BYTES,
            max_replay_events: DEFAULT_MAX_REPLAY_EVENTS,
            max_stream_id_bytes: DEFAULT_MAX_STREAM_ID_BYTES,
            max_last_event_id_bytes: DEFAULT_MAX_LAST_EVENT_ID_BYTES,
        }
    }
}

impl AggregateSseBounds {
    /// Validate operator bounds; errors name the field and never echo values.
    pub fn validate(self) -> Result<Self, String> {
        validate_bound(
            self.max_streams_per_session,
            1,
            MAX_STREAMS_PER_SESSION_CEILING,
            "sessions.sse_max_streams_per_session",
        )?;
        validate_bound(
            self.max_queue_events,
            1,
            MAX_QUEUE_EVENTS_CEILING,
            "sessions.sse_max_queue_events",
        )?;
        validate_bound(
            self.max_queue_bytes,
            1,
            MAX_QUEUE_BYTES_CEILING,
            "sessions.sse_max_queue_bytes",
        )?;
        validate_bound(
            self.max_event_bytes,
            1,
            MAX_EVENT_BYTES_CEILING,
            "sessions.sse_max_event_bytes",
        )?;
        validate_bound(
            self.max_replay_events,
            0,
            MAX_REPLAY_EVENTS_CEILING,
            "sessions.sse_max_replay_events",
        )?;
        validate_bound(
            self.max_stream_id_bytes,
            1,
            MAX_STREAM_ID_BYTES_CEILING,
            "sessions.sse_max_stream_id_bytes",
        )?;
        validate_bound(
            self.max_last_event_id_bytes,
            1,
            MAX_LAST_EVENT_ID_BYTES_CEILING,
            "sessions.sse_max_last_event_id_bytes",
        )?;
        if self.max_event_bytes > self.max_queue_bytes {
            return Err(
                "mcp_gateway: 'sessions.sse_max_event_bytes' must be <= 'sessions.sse_max_queue_bytes'"
                    .to_string(),
            );
        }
        Ok(self)
    }
}

fn validate_bound(value: usize, min: usize, max: usize, field: &str) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "mcp_gateway: '{field}' must be between {min} and {max}"
        ));
    }
    Ok(())
}

/// Fail-closed broker admission / routing errors (field-specific, value-free).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AggregateSseError {
    MissingSession,
    UnknownSession,
    StaleSession,
    DuplicateListener,
    ListenerRequired,
    InvalidAccept,
    LastEventIdTooLarge,
    LastEventIdInvalid,
    StreamIdMissing,
    StreamIdTooLarge,
    StreamIdInvalid,
    DuplicateStream,
    UnknownStream,
    StaleStream,
    EventTooLarge,
    QueueOverflow,
    StreamCardinalityOverflow,
    SessionCardinalityOverflow,
    Cancelled,
    GenerationMismatch,
}

impl AggregateSseError {
    pub fn as_static_reason(self) -> &'static str {
        match self {
            Self::MissingSession => "sessions.downstream_session_header is required for SSE",
            Self::UnknownSession => "MCP session not found",
            Self::StaleSession => "MCP session is stale for SSE multiplexing",
            Self::DuplicateListener => "SSE listener already attached for this session",
            Self::ListenerRequired => "SSE listener is required for multiplexed delivery",
            Self::InvalidAccept => "Accept must include text/event-stream for aggregate SSE",
            Self::LastEventIdTooLarge => "Last-Event-ID exceeds maximum length",
            Self::LastEventIdInvalid => "Last-Event-ID is not a valid event cursor",
            Self::StreamIdMissing => "stream identity is required",
            Self::StreamIdTooLarge => "stream identity exceeds maximum length",
            Self::StreamIdInvalid => "stream identity is not a representable JSON-RPC id",
            Self::DuplicateStream => "stream identity is already open on this session",
            Self::UnknownStream => "stream identity is unknown on this session",
            Self::StaleStream => "stream identity is stale on this session",
            Self::EventTooLarge => "SSE event payload exceeds maximum length",
            Self::QueueOverflow => "SSE session queue capacity exceeded",
            Self::StreamCardinalityOverflow => "SSE stream cardinality exceeded for session",
            Self::SessionCardinalityOverflow => "SSE session cardinality exceeded",
            Self::Cancelled => "SSE stream was cancelled",
            Self::GenerationMismatch => "SSE broker generation does not match session",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::MissingSession | Self::InvalidAccept | Self::LastEventIdTooLarge
            | Self::LastEventIdInvalid | Self::StreamIdMissing | Self::StreamIdTooLarge
            | Self::StreamIdInvalid | Self::EventTooLarge => 400,
            Self::UnknownSession | Self::StaleSession | Self::UnknownStream | Self::StaleStream => {
                404
            }
            Self::DuplicateListener | Self::DuplicateStream => 409,
            Self::QueueOverflow
            | Self::StreamCardinalityOverflow
            | Self::SessionCardinalityOverflow => 503,
            Self::ListenerRequired | Self::Cancelled | Self::GenerationMismatch => 409,
        }
    }
}

/// Canonical, bounded stream identity derived from a JSON-RPC request id.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StreamIdentity(String);

impl StreamIdentity {
    /// Admit a JSON-RPC id as a stream identity. Objects/arrays/bools/null fail
    /// closed; strings and numbers are canonicalized without retaining raw
    /// hostile forms beyond the bound.
    pub fn from_json_rpc_id(id: &Value, max_bytes: usize) -> Result<Self, AggregateSseError> {
        let canonical = match id {
            Value::String(s) => s.clone(),
            Value::Number(n) => n.to_string(),
            Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => {
                return Err(AggregateSseError::StreamIdInvalid);
            }
        };
        if canonical.is_empty() {
            return Err(AggregateSseError::StreamIdMissing);
        }
        if canonical.len() > max_bytes {
            return Err(AggregateSseError::StreamIdTooLarge);
        }
        // Reject control characters so identities stay log/header safe if ever
        // mirrored into diagnostics (we still never log the value).
        if canonical.bytes().any(|b| b < 0x20 || b == 0x7f) {
            return Err(AggregateSseError::StreamIdInvalid);
        }
        Ok(Self(canonical))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Debug, Clone)]
struct QueuedEvent {
    event_id: u64,
    #[allow(dead_code)] // Retained for per-stream drain/cancel accounting.
    stream: Option<StreamIdentity>,
    /// Pre-framed SSE bytes (`id:` / `event:` / `data:` / blank line).
    framed: Bytes,
    payload_bytes: usize,
}

struct StreamSlot {
    #[allow(dead_code)] // Retained for diagnostics/snapshots; identity is the map key.
    identity: StreamIdentity,
    cancelled: bool,
    #[allow(dead_code)] // Retained for idle/stream TTL accounting.
    opened_at: Instant,
}

struct ListenerSlot {
    tx: mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
    attached_generation: u64,
}

struct SessionSseState {
    generation: u64,
    streams: Mutex<HashMap<StreamIdentity, StreamSlot>>,
    /// Events waiting because no listener is attached yet (bounded).
    pending: Mutex<VecDeque<QueuedEvent>>,
    pending_bytes: AtomicU64,
    replay: Mutex<VecDeque<QueuedEvent>>,
    replay_bytes: AtomicU64,
    next_event_id: AtomicU64,
    listener: Mutex<Option<ListenerSlot>>,
    closed: AtomicBool,
    last_activity: Mutex<Instant>,
}

impl SessionSseState {
    fn new(generation: u64) -> Self {
        Self {
            generation,
            streams: Mutex::new(HashMap::new()),
            pending: Mutex::new(VecDeque::new()),
            pending_bytes: AtomicU64::new(0),
            replay: Mutex::new(VecDeque::new()),
            replay_bytes: AtomicU64::new(0),
            next_event_id: AtomicU64::new(1),
            listener: Mutex::new(None),
            closed: AtomicBool::new(false),
            last_activity: Mutex::new(Instant::now()),
        }
    }

    async fn touch(&self) {
        *self.last_activity.lock().await = Instant::now();
    }
}

/// Process-local multiplexed SSE broker for one `mcp_gateway` plugin generation.
pub struct AggregateSseBroker {
    generation: AtomicU64,
    bounds: AggregateSseBounds,
    /// Max sessions that may hold broker state (aligned with MCP session cap).
    max_sessions: usize,
    sessions: DashMap<String, Arc<SessionSseState>>,
}

impl AggregateSseBroker {
    pub fn new(bounds: AggregateSseBounds, max_sessions: usize, shard_amount: usize) -> Self {
        Self {
            generation: AtomicU64::new(1),
            bounds,
            max_sessions: max_sessions.max(1),
            sessions: DashMap::with_shard_amount(shard_amount.max(1)),
        }
    }

    pub fn bounds(&self) -> &AggregateSseBounds {
        &self.bounds
    }

    pub fn generation(&self) -> u64 {
        self.generation.load(Ordering::Acquire)
    }

    /// Bump the broker generation and drop every session slot. Used on
    /// reload/update semantics when the owning plugin instance is replaced;
    /// Drop of the old instance also tears listeners down.
    pub fn retire_generation(&self) {
        self.generation.fetch_add(1, Ordering::AcqRel);
        let keys: Vec<String> = self.sessions.iter().map(|e| e.key().clone()).collect();
        for key in keys {
            if let Some((_, state)) = self.sessions.remove(&key) {
                state.closed.store(true, Ordering::Release);
                // Dropping the listener sender ends the SSE body.
                let _ = state.listener.try_lock().map(|mut guard| guard.take());
            }
        }
    }

    pub fn session_count(&self) -> usize {
        self.sessions.len()
    }

    /// Ensure a broker session exists for a live downstream MCP session.
    pub fn ensure_session(&self, session_id: &str) -> Result<Arc<SessionSseState>, AggregateSseError> {
        if session_id.is_empty() {
            return Err(AggregateSseError::MissingSession);
        }
        if let Some(existing) = self.sessions.get(session_id) {
            if existing.closed.load(Ordering::Acquire) {
                return Err(AggregateSseError::StaleSession);
            }
            if existing.generation != self.generation() {
                return Err(AggregateSseError::GenerationMismatch);
            }
            return Ok(Arc::clone(existing.value()));
        }
        if self.sessions.len() >= self.max_sessions {
            return Err(AggregateSseError::SessionCardinalityOverflow);
        }
        let state = Arc::new(SessionSseState::new(self.generation()));
        // DashMap entry API avoids TOCTOU growth past the cap under concurrency.
        match self.sessions.entry(session_id.to_string()) {
            dashmap::mapref::entry::Entry::Occupied(occupied) => {
                let existing = occupied.get();
                if existing.closed.load(Ordering::Acquire) {
                    return Err(AggregateSseError::StaleSession);
                }
                if existing.generation != self.generation() {
                    return Err(AggregateSseError::GenerationMismatch);
                }
                Ok(Arc::clone(existing))
            }
            dashmap::mapref::entry::Entry::Vacant(vacant) => {
                if self.sessions.len() >= self.max_sessions {
                    return Err(AggregateSseError::SessionCardinalityOverflow);
                }
                vacant.insert(Arc::clone(&state));
                Ok(state)
            }
        }
    }

    pub fn get_session(&self, session_id: &str) -> Result<Arc<SessionSseState>, AggregateSseError> {
        let Some(existing) = self.sessions.get(session_id) else {
            return Err(AggregateSseError::UnknownSession);
        };
        if existing.closed.load(Ordering::Acquire) {
            return Err(AggregateSseError::StaleSession);
        }
        if existing.generation != self.generation() {
            return Err(AggregateSseError::GenerationMismatch);
        }
        Ok(Arc::clone(existing.value()))
    }

    /// Tear down broker state for a deleted/expired downstream session.
    pub async fn remove_session(&self, session_id: &str) {
        self.detach_session(session_id);
    }

    /// Synchronous teardown used from session-store eviction paths that cannot
    /// await. Drops the listener sender so in-flight SSE bodies end promptly.
    pub fn detach_session(&self, session_id: &str) {
        if let Some((_, state)) = self.sessions.remove(session_id) {
            state.closed.store(true, Ordering::Release);
            if let Ok(mut listener) = state.listener.try_lock() {
                listener.take();
            }
        }
    }

    /// Open a request stream identity on a session (idempotent fail on duplicate).
    pub async fn open_stream(
        &self,
        session_id: &str,
        identity: StreamIdentity,
    ) -> Result<(), AggregateSseError> {
        let state = self.get_session(session_id)?;
        state.touch().await;
        let mut streams = state.streams.lock().await;
        if let Some(existing) = streams.get(&identity) {
            if existing.cancelled {
                return Err(AggregateSseError::StaleStream);
            }
            return Err(AggregateSseError::DuplicateStream);
        }
        if streams.len() >= self.bounds.max_streams_per_session {
            return Err(AggregateSseError::StreamCardinalityOverflow);
        }
        streams.insert(
            identity.clone(),
            StreamSlot {
                identity,
                cancelled: false,
                opened_at: Instant::now(),
            },
        );
        Ok(())
    }

    /// Cancel a stream identity; subsequent publishes for it fail closed.
    pub async fn cancel_stream(
        &self,
        session_id: &str,
        identity: &StreamIdentity,
    ) -> Result<(), AggregateSseError> {
        let state = self.get_session(session_id)?;
        state.touch().await;
        let mut streams = state.streams.lock().await;
        let Some(slot) = streams.get_mut(identity) else {
            return Err(AggregateSseError::UnknownStream);
        };
        if slot.cancelled {
            return Err(AggregateSseError::StaleStream);
        }
        slot.cancelled = true;
        Ok(())
    }

    /// Attach the single SSE listener for a session. Returns the body channel
    /// receiver and any replay frames for `Last-Event-ID`.
    pub async fn attach_listener(
        &self,
        session_id: &str,
        last_event_id: Option<&str>,
    ) -> Result<mpsc::Receiver<Result<Frame<Bytes>, BoxError>>, AggregateSseError> {
        let resume_after = parse_last_event_id(last_event_id, self.bounds.max_last_event_id_bytes)?;
        let state = self.ensure_session(session_id)?;
        if state.closed.load(Ordering::Acquire) {
            return Err(AggregateSseError::StaleSession);
        }
        state.touch().await;

        let (tx, rx) = mpsc::channel(LISTENER_CHANNEL_CAPACITY);
        {
            let mut listener = state.listener.lock().await;
            if listener.is_some() {
                return Err(AggregateSseError::DuplicateListener);
            }
            *listener = Some(ListenerSlot {
                tx: tx.clone(),
                attached_generation: self.generation(),
            });
        }

        // Replay ring: events with id > resume_after.
        if self.bounds.max_replay_events > 0 {
            let replay = state.replay.lock().await;
            for event in replay.iter() {
                if resume_after.is_none_or(|cursor| event.event_id > cursor)
                    && tx
                        .try_send(Ok(Frame::data(event.framed.clone())))
                        .is_err()
                {
                    // Listener cannot accept replay under backpressure — fail
                    // closed rather than silently truncating history.
                    let mut listener = state.listener.lock().await;
                    listener.take();
                    return Err(AggregateSseError::QueueOverflow);
                }
            }
        }

        // Drain pending (pre-listener) queue into the live listener.
        {
            let mut pending = state.pending.lock().await;
            while let Some(event) = pending.pop_front() {
                state
                    .pending_bytes
                    .fetch_sub(event.payload_bytes as u64, Ordering::AcqRel);
                if resume_after.is_some_and(|cursor| event.event_id <= cursor) {
                    continue;
                }
                if tx
                    .try_send(Ok(Frame::data(event.framed.clone())))
                    .is_err()
                {
                    let mut listener = state.listener.lock().await;
                    listener.take();
                    return Err(AggregateSseError::QueueOverflow);
                }
            }
        }

        // Initial comment frame so clients see an established stream even when
        // no events are pending (MCP Streamable HTTP GET semantics).
        let _ = tx.try_send(Ok(Frame::data(Bytes::from_static(b": mcp-sse\n\n"))));

        Ok(rx)
    }

    /// Detach the SSE listener (client disconnect / explicit cleanup).
    pub async fn detach_listener(&self, session_id: &str) {
        if let Ok(state) = self.get_session(session_id) {
            let mut listener = state.listener.lock().await;
            listener.take();
            state.touch().await;
        }
    }

    pub async fn has_listener(&self, session_id: &str) -> bool {
        match self.get_session(session_id) {
            Ok(state) => state.listener.lock().await.is_some(),
            Err(_) => false,
        }
    }

    /// Publish a JSON-RPC message onto the session's multiplexed SSE stream.
    pub async fn publish(
        &self,
        session_id: &str,
        stream: Option<&StreamIdentity>,
        payload: &Value,
    ) -> Result<u64, AggregateSseError> {
        let state = self.get_session(session_id)?;
        if state.closed.load(Ordering::Acquire) {
            return Err(AggregateSseError::StaleSession);
        }
        state.touch().await;

        if let Some(identity) = stream {
            let streams = state.streams.lock().await;
            match streams.get(identity) {
                None => return Err(AggregateSseError::UnknownStream),
                Some(slot) if slot.cancelled => return Err(AggregateSseError::Cancelled),
                Some(_) => {}
            }
        }

        let raw = serde_json::to_vec(payload).map_err(|_| AggregateSseError::EventTooLarge)?;
        if raw.len() > self.bounds.max_event_bytes {
            return Err(AggregateSseError::EventTooLarge);
        }
        // SSE data lines cannot carry raw newlines without splitting; JSON
        // serialization is single-line for compact output, but defend anyway.
        if raw.iter().any(|b| *b == b'\n' || *b == b'\r') {
            return Err(AggregateSseError::EventTooLarge);
        }

        let event_id = state.next_event_id.fetch_add(1, Ordering::AcqRel);
        let framed = frame_sse_event(event_id, &raw);
        let payload_bytes = raw.len();
        let queued = QueuedEvent {
            event_id,
            stream: stream.cloned(),
            framed: framed.clone(),
            payload_bytes,
        };

        // Prefer live listener; otherwise retain in the pending queue.
        let delivered = {
            let listener = state.listener.lock().await;
            if let Some(slot) = listener.as_ref() {
                if slot.attached_generation != self.generation() {
                    return Err(AggregateSseError::GenerationMismatch);
                }
                match slot.tx.try_send(Ok(Frame::data(framed))) {
                    Ok(()) => true,
                    Err(mpsc::error::TrySendError::Full(_)) => {
                        return Err(AggregateSseError::QueueOverflow);
                    }
                    Err(mpsc::error::TrySendError::Closed(_)) => {
                        // Listener gone mid-send — fall through to pending.
                        false
                    }
                }
            } else {
                false
            }
        };

        if !delivered {
            let mut pending = state.pending.lock().await;
            let current_bytes = state.pending_bytes.load(Ordering::Acquire) as usize;
            if pending.len() >= self.bounds.max_queue_events
                || current_bytes.saturating_add(payload_bytes) > self.bounds.max_queue_bytes
            {
                return Err(AggregateSseError::QueueOverflow);
            }
            pending.push_back(queued.clone());
            state
                .pending_bytes
                .fetch_add(payload_bytes as u64, Ordering::AcqRel);
        }

        // Retain in the replay ring (independent of live delivery).
        if self.bounds.max_replay_events > 0 {
            let mut replay = state.replay.lock().await;
            while replay.len() >= self.bounds.max_replay_events {
                if let Some(old) = replay.pop_front() {
                    state
                        .replay_bytes
                        .fetch_sub(old.payload_bytes as u64, Ordering::AcqRel);
                }
            }
            while state.replay_bytes.load(Ordering::Acquire) as usize + payload_bytes
                > self.bounds.max_queue_bytes
                && !replay.is_empty()
            {
                if let Some(old) = replay.pop_front() {
                    state
                        .replay_bytes
                        .fetch_sub(old.payload_bytes as u64, Ordering::AcqRel);
                } else {
                    break;
                }
            }
            if state.replay_bytes.load(Ordering::Acquire) as usize + payload_bytes
                <= self.bounds.max_queue_bytes
            {
                replay.push_back(queued);
                state
                    .replay_bytes
                    .fetch_add(payload_bytes as u64, Ordering::AcqRel);
            }
        }

        Ok(event_id)
    }

    /// Drop idle broker sessions whose activity is older than `ttl`.
    pub async fn reap_idle(&self, ttl: Duration) {
        let now = Instant::now();
        let mut stale = Vec::new();
        for entry in self.sessions.iter() {
            let Ok(guard) = entry.value().last_activity.try_lock() else {
                continue;
            };
            if now.duration_since(*guard) >= ttl {
                stale.push(entry.key().clone());
            }
        }
        for key in stale {
            self.remove_session(&key).await;
        }
    }
}

impl Drop for AggregateSseBroker {
    fn drop(&mut self) {
        // Closing every listener sender ends in-flight SSE bodies for this
        // plugin generation so reload/delete cannot leak cross-generation
        // events onto a new instance.
        for entry in self.sessions.iter() {
            entry.value().closed.store(true, Ordering::Release);
            if let Ok(mut listener) = entry.value().listener.try_lock() {
                listener.take();
            }
        }
        self.sessions.clear();
    }
}

fn parse_last_event_id(
    raw: Option<&str>,
    max_bytes: usize,
) -> Result<Option<u64>, AggregateSseError> {
    let Some(value) = raw.map(str::trim).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    if value.len() > max_bytes {
        return Err(AggregateSseError::LastEventIdTooLarge);
    }
    if !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AggregateSseError::LastEventIdInvalid);
    }
    value
        .parse::<u64>()
        .map(Some)
        .map_err(|_| AggregateSseError::LastEventIdInvalid)
}

fn frame_sse_event(event_id: u64, data: &[u8]) -> Bytes {
    // id / event / data / blank line. event_id is gateway-authored decimal.
    let mut out = Vec::with_capacity(32 + data.len());
    out.extend_from_slice(b"id: ");
    out.extend_from_slice(event_id.to_string().as_bytes());
    out.extend_from_slice(b"\nevent: message\ndata: ");
    out.extend_from_slice(data);
    out.extend_from_slice(b"\n\n");
    Bytes::from(out)
}

/// Returns true when request headers include a usable `text/event-stream` Accept.
pub fn headers_request_aggregate_sse(headers: &std::collections::HashMap<String, String>) -> bool {
    crate::plugins::utils::sse::headers_accept_sse(headers)
}

#[cfg(test)]
mod inline_smoke {
    // Intentionally empty: coverage lives in external unit tests per policy.
}
