//! Opt-in bounded diagnostics. Never changes request accounting or transport policy.

use std::error::Error;
use std::fmt::{self, Write};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use crate::phases::{PhaseReport, TransportEvent};

pub const MAX_EVENTS: usize = 512;
pub const MAX_CHAIN_DEPTH: usize = 8;
pub const MAX_CHAIN_BYTES: usize = 2048;

struct Escaped {
    text: String,
    limit: usize,
}

impl Write for Escaped {
    fn write_str(&mut self, text: &str) -> fmt::Result {
        for ch in text.chars().flat_map(char::escape_default) {
            if self.text.len() + ch.len_utf8() > self.limit {
                return Err(fmt::Error);
            }
            self.text.push(ch);
        }
        Ok(())
    }
}

pub fn escaped_snippet(bytes: &[u8]) -> String {
    let mut output = Escaped {
        text: String::new(),
        limit: 800,
    };
    let _ = write!(
        output,
        "{}",
        String::from_utf8_lossy(&bytes[..bytes.len().min(200)])
    );
    output.text
}

pub fn error_chain(error: &(dyn Error + 'static)) -> String {
    let mut output = Escaped {
        text: String::new(),
        limit: MAX_CHAIN_BYTES - 16,
    };
    let mut current = Some(error);
    for depth in 0..MAX_CHAIN_DEPTH {
        let Some(cause) = current else {
            return output.text;
        };
        if (depth > 0 && output.write_str(" <- ").is_err()) || write!(output, "{cause}").is_err() {
            output.text.push_str(" [truncated]");
            return output.text;
        }
        current = cause.source();
    }
    if current.is_some() {
        output.text.push_str(" [depth limit]");
    }
    output.text
}

/// Type inspection only; a reason alone must never be promoted to GOAWAY/RST.
pub fn classify(error: &(dyn Error + 'static), event: &mut TransportEvent) {
    let mut current = Some(error);
    for _ in 0..MAX_CHAIN_DEPTH {
        let Some(cause) = current else { break };
        if let Some(h2) = cause.downcast_ref::<h2::Error>() {
            event.h2_reason = h2.reason().map(u32::from);
            let kind = if h2.is_go_away() {
                "goaway"
            } else if h2.is_reset() {
                "reset"
            } else if h2.is_io() {
                "io"
            } else {
                "other"
            };
            event.h2_kind = Some(kind.to_string());
            let initiator = if h2.is_remote() {
                "remote"
            } else if h2.is_library() {
                "local_library"
            } else if h2.is_go_away() || h2.is_reset() {
                "local_user"
            } else {
                "unknown"
            };
            event.h2_initiator = Some(initiator.to_string());
            break;
        }
        current = cause.source();
    }
}

#[derive(Default)]
struct State {
    total: AtomicUsize,
    errors: AtomicUsize,
    next_connection: AtomicUsize,
    events: Mutex<Vec<TransportEvent>>,
}

#[derive(Clone)]
pub struct Observer {
    state: Option<Arc<State>>,
    hop: &'static str,
    stderr: bool,
}

impl Observer {
    pub fn new(enabled: bool, hop: &'static str, stderr: bool) -> Self {
        Self {
            state: enabled.then(|| Arc::new(State::default())),
            hop,
            stderr,
        }
    }

    pub fn connection_id(&self) -> usize {
        self.state.as_ref().map_or(0, |state| {
            state.next_connection.fetch_add(1, Ordering::Relaxed) + 1
        })
    }

    pub fn record(
        &self,
        connection_id: usize,
        worker_id: Option<usize>,
        channel_id: Option<usize>,
        operation: &'static str,
        error: Option<&(dyn Error + 'static)>,
    ) {
        let Some(state) = &self.state else { return };
        let mut events = state.events.lock().unwrap();
        if error.is_some() {
            state.errors.fetch_add(1, Ordering::Relaxed);
        }
        let sequence = state.total.fetch_add(1, Ordering::Relaxed);
        if sequence >= MAX_EVENTS {
            if self.stderr && sequence == MAX_EVENTS {
                eprintln!("H2_OBSERVATION_LIMIT {MAX_EVENTS}");
            }
            return;
        }
        let mut event = TransportEvent::new(
            connection_id,
            operation,
            error.map(error_chain).unwrap_or_default(),
        );
        event.worker_id = worker_id;
        event.channel_id = channel_id;
        event.hop = Some(self.hop.to_string());
        if let Some(error) = error {
            classify(error, &mut event);
        }
        if self.stderr {
            // Backend phase must be correlated with client boundaries later.
            event.phase = "unattributed_backend".to_string();
            if let Ok(json) = serde_json::to_string(&event) {
                eprintln!("H2_TRANSPORT {json}");
            }
        }
        events.push(event);
    }

    pub fn attach(&self, phases: &mut PhaseReport) {
        if let Some(state) = &self.state {
            let events = state.events.lock().unwrap();
            phases.transport_events_total = state.total.load(Ordering::Relaxed);
            phases.transport_errors_total = state.errors.load(Ordering::Relaxed);
            phases.transport_events_suppressed = phases.transport_events_total - events.len();
            phases.set_transport_events(events.clone());
        }
    }
}
