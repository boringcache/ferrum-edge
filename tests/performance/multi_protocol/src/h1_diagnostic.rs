//! Opt-in H1 last-state capture. No payloads, arbitrary headers or error text.
//! All times belong to this client process and this diagnostic session only.

use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Buf;
use hyper::body::Body;
use serde::Serialize;
use tokio::task::JoinSet;

pub const CLOCK_DOMAIN: &str = "client_process_diagnostic_session_instant_microseconds";
pub const MAX_WORKERS: usize = 256;
pub const MAX_CONNECTIONS: usize = 512;
pub const MAX_SNAPSHOTS: usize = 4;
pub const DRIVER_BOUND: Duration = Duration::from_secs(5);
pub const WARMUP_NOTICE: Duration = Duration::from_secs(10);

#[derive(Clone, Debug, Serialize)]
pub struct Stamp {
    pub session_us: u64,
    pub phase: &'static str,
    pub phase_us: u64,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct RequestState {
    pub id: u64,
    pub offered: Option<Stamp>,
    pub body_first_poll: Option<Stamp>,
    pub body_bytes: u64,
    pub body_last_progress: Option<Stamp>,
    pub body_end: Option<Stamp>,
    pub body_end_signal: Option<&'static str>,
    pub headers: Option<Stamp>,
    pub status: Option<u16>,
    pub version: Option<&'static str>,
    pub content_length: Option<u64>,
    pub content_length_present: bool,
    pub transfer_encoding_present: bool,
    pub chunked: bool,
    pub connection_close: bool,
    pub response_bytes: u64,
    pub response_last_progress: Option<Stamp>,
    pub response_end: Option<Stamp>,
    pub response_end_signal: Option<&'static str>,
    pub error_class: Option<&'static str>,
    pub error_at: Option<Stamp>,
    pub validated: Option<bool>,
    pub completion: Option<Stamp>,
}

#[derive(Clone, Debug, Serialize)]
pub struct WorkerState {
    pub id: usize,
    pub connection_id: Option<u64>,
    pub stage: &'static str,
    pub stage_since: Stamp,
    pub lifecycle: &'static str,
    pub requests_offered: u64,
    pub bodies_admitted: u64,
    pub completions: u64,
    pub errors: u64,
    pub request: RequestState,
}

#[derive(Clone, Debug, Serialize)]
pub struct ConnectionState {
    pub id: u64,
    pub worker_id: usize,
    pub local: Option<SocketAddr>,
    pub peer: Option<SocketAddr>,
    pub socket_at: Stamp,
    pub driver: &'static str,
    pub driver_at: Option<Stamp>,
    pub error_class: Option<&'static str>,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Loss {
    pub workers: u64,
    pub connections: u64,
    pub updates: u64,
    pub snapshots: u64,
    pub poisoned_locks: u64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Snapshot {
    pub clock_domain: &'static str,
    pub pid: u32,
    pub reason: &'static str,
    pub at: Stamp,
    pub workers: Vec<WorkerState>,
    pub connections: Vec<ConnectionState>,
    pub loss: Loss,
}

#[derive(Clone, Debug, Default, Serialize)]
pub struct Retirement {
    pub started: u64,
    pub completed_ok: u64,
    pub completed_error: u64,
    pub cancelled: u64,
    pub panicked: u64,
    pub capacity_rejections: u64,
    pub pending_at_request_drain: usize,
    pub abort_requested: usize,
    pub unreaped_after_abort: usize,
    pub abort_reap_bound_secs: f64,
    pub timed_out: bool,
    pub elapsed_secs: f64,
    pub bound_secs: f64,
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub schema: u32,
    pub clock_domain: &'static str,
    pub pid: u32,
    pub worker_capacity: usize,
    pub connection_capacity: usize,
    pub snapshot_capacity: usize,
    pub loss: Loss,
    pub snapshots: Vec<Snapshot>,
    pub retirement: Option<Retirement>,
}

struct State {
    epoch: Instant,
    phase: &'static str,
    phase_start: Instant,
    measurement_end: Option<Instant>,
    next_request: u64,
    next_connection: u64,
    workers: Vec<WorkerState>,
    connections: Vec<ConnectionState>,
    snapshots: Vec<Snapshot>,
    loss: Loss,
    retirement: Option<Retirement>,
}

impl State {
    fn stamp(&self) -> Stamp {
        let now = Instant::now();
        let (phase, start) = match self.measurement_end {
            Some(end) if self.phase == "measurement" && now >= end => ("drain", end),
            _ => (self.phase, self.phase_start),
        };
        Stamp {
            session_us: now.duration_since(self.epoch).as_micros() as u64,
            phase,
            phase_us: now.saturating_duration_since(start).as_micros() as u64,
        }
    }
}

#[derive(Clone, Default)]
pub struct Diagnostic(Option<Arc<Mutex<State>>>);

impl Diagnostic {
    pub fn new(enabled: bool) -> Self {
        if !enabled {
            return Self::default();
        }
        let epoch = Instant::now();
        Self(Some(Arc::new(Mutex::new(State {
            epoch,
            phase: "setup",
            phase_start: epoch,
            measurement_end: None,
            next_request: 0,
            next_connection: 0,
            workers: Vec::new(),
            connections: Vec::new(),
            snapshots: Vec::new(),
            loss: Loss::default(),
            retirement: None,
        }))))
    }

    fn lock(&self) -> Option<MutexGuard<'_, State>> {
        self.0.as_ref().map(|state| match state.lock() {
            Ok(state) => state,
            Err(error) => {
                let mut state = error.into_inner();
                state.loss.poisoned_locks += 1;
                state
            }
        })
    }

    pub fn enabled(&self) -> bool {
        self.0.is_some()
    }

    pub fn phase(&self, name: &'static str, start: Instant, end: Option<Instant>) {
        if let Some(mut state) = self.lock() {
            let start = if name == "drain" && state.phase == "measurement" {
                state.measurement_end.unwrap_or(start)
            } else {
                start
            };
            state.phase = name;
            state.phase_start = start;
            state.measurement_end = end;
        }
    }

    pub fn worker(&self, id: usize) -> WorkerTrace {
        if let Some(mut state) = self.lock() {
            let stamp = state.stamp();
            if state.workers.len() < MAX_WORKERS {
                state.workers.push(WorkerState {
                    id,
                    connection_id: None,
                    stage: "connect",
                    stage_since: stamp,
                    lifecycle: "running",
                    requests_offered: 0,
                    bodies_admitted: 0,
                    completions: 0,
                    errors: 0,
                    request: RequestState::default(),
                });
            } else {
                state.loss.workers += 1;
            }
        }
        WorkerTrace {
            observation: Observation {
                diagnostic: self.clone(),
                worker_id: id,
                request_id: None,
            },
            returned: false,
        }
    }

    /// At most four full snapshots. Also emit immediately, so an outer process
    /// timeout can retain pre-abort state even if final JSON never gets written.
    pub fn snapshot(&self, reason: &'static str) {
        if let Some(mut state) = self.lock() {
            if state.snapshots.len() == MAX_SNAPSHOTS {
                state.loss.snapshots += 1;
                return;
            }
            let snapshot = Snapshot {
                clock_domain: CLOCK_DOMAIN,
                pid: std::process::id(),
                reason,
                at: state.stamp(),
                workers: state.workers.clone(),
                connections: state.connections.clone(),
                loss: state.loss.clone(),
            };
            match serde_json::to_string(&snapshot) {
                Ok(json) => eprintln!("H1_DIAGNOSTIC {json}"),
                Err(_) => state.loss.snapshots += 1,
            }
            state.snapshots.push(snapshot);
        }
    }

    pub fn report(&self) -> Option<Report> {
        self.lock().map(|state| Report {
            schema: 1,
            clock_domain: CLOCK_DOMAIN,
            pid: std::process::id(),
            worker_capacity: MAX_WORKERS,
            connection_capacity: MAX_CONNECTIONS,
            snapshot_capacity: MAX_SNAPSHOTS,
            loss: state.loss.clone(),
            snapshots: state.snapshots.clone(),
            retirement: state.retirement.clone(),
        })
    }

    fn driver(&self, id: u64, outcome: &'static str, error: Option<&'static str>) {
        if let Some(mut state) = self.lock() {
            let at = state.stamp();
            if let Some(connection) = state.connections.iter_mut().find(|c| c.id == id) {
                connection.driver = outcome;
                connection.driver_at = Some(at);
                connection.error_class = error;
            } else {
                state.loss.updates += 1;
            }
        }
    }
}

pub struct WorkerTrace {
    pub observation: Observation,
    returned: bool,
}

impl WorkerTrace {
    pub fn returned(&mut self, ok: bool) {
        self.returned = true;
        self.observation.update(|worker, _| {
            worker.lifecycle = if ok { "returned" } else { "returned_error" };
        });
    }
}

impl Drop for WorkerTrace {
    fn drop(&mut self) {
        if !self.returned {
            self.observation.update(|worker, _| {
                // Do not overwrite the last await or pretend to know whether
                // this was cancellation or unwinding from a panic.
                worker.lifecycle = "dropped_without_return";
            });
        }
    }
}

#[derive(Clone)]
pub struct Observation {
    diagnostic: Diagnostic,
    worker_id: usize,
    request_id: Option<u64>,
}

impl Observation {
    fn update(&self, update: impl FnOnce(&mut WorkerState, Stamp)) {
        if let Some(mut state) = self.diagnostic.lock() {
            let stamp = state.stamp();
            if let Some(worker) = state.workers.iter_mut().find(|w| w.id == self.worker_id) {
                if self.request_id.is_none_or(|id| id == worker.request.id) {
                    update(worker, stamp);
                } else {
                    state.loss.updates += 1;
                }
            } else {
                state.loss.updates += 1;
            }
        }
    }

    pub fn connecting(&self) {
        self.update(|worker, _| worker.connection_id = None);
        self.stage("connect");
    }

    pub fn stage(&self, stage: &'static str) {
        self.update(|worker, at| {
            worker.stage = stage;
            worker.stage_since = at;
        });
    }

    pub fn socket(&self, local: Option<SocketAddr>, peer: Option<SocketAddr>) -> u64 {
        let Some(mut state) = self.diagnostic.lock() else {
            return 0;
        };
        state.next_connection += 1;
        let id = state.next_connection;
        let at = state.stamp();
        if state.connections.len() < MAX_CONNECTIONS {
            state.connections.push(ConnectionState {
                id,
                worker_id: self.worker_id,
                local,
                peer,
                socket_at: at,
                driver: "not_started",
                driver_at: None,
                error_class: None,
            });
        } else {
            state.loss.connections += 1;
        }
        if let Some(worker) = state.workers.iter_mut().find(|w| w.id == self.worker_id) {
            worker.connection_id = Some(id);
        }
        id
    }

    pub fn request(&self) -> Self {
        let Some(mut state) = self.diagnostic.lock() else {
            return self.clone();
        };
        state.next_request += 1;
        let id = state.next_request;
        let at = state.stamp();
        if let Some(worker) = state.workers.iter_mut().find(|w| w.id == self.worker_id) {
            worker.requests_offered += 1;
            worker.request = RequestState {
                id,
                offered: Some(at),
                ..RequestState::default()
            };
        } else {
            state.loss.updates += 1;
        }
        Self {
            request_id: Some(id),
            ..self.clone()
        }
    }

    pub fn headers(
        &self,
        status: http::StatusCode,
        version: http::Version,
        headers: &http::HeaderMap,
    ) {
        self.update(|worker, at| {
            let request = &mut worker.request;
            request.headers = Some(at);
            request.status = Some(status.as_u16());
            request.version = Some(match version {
                http::Version::HTTP_10 => "HTTP/1.0",
                http::Version::HTTP_11 => "HTTP/1.1",
                _ => "unexpected_version",
            });
            request.content_length_present = headers.contains_key(http::header::CONTENT_LENGTH);
            request.content_length = headers
                .get(http::header::CONTENT_LENGTH)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse().ok());
            request.transfer_encoding_present =
                headers.contains_key(http::header::TRANSFER_ENCODING);
            request.chunked = header_token(headers, http::header::TRANSFER_ENCODING, "chunked");
            request.connection_close = header_token(headers, http::header::CONNECTION, "close");
        });
        self.stage("response_body");
    }

    pub fn error(&self, class: &'static str) {
        self.update(|worker, at| {
            worker.errors += 1;
            worker.request.error_class = Some(class);
            worker.request.error_at = Some(at);
        });
    }

    pub fn complete(&self, valid: bool) {
        self.update(|worker, at| {
            worker.request.validated = Some(valid);
            worker.request.completion = Some(at);
            if valid {
                worker.completions += 1;
            } else {
                worker.errors += 1;
            }
        });
    }

    fn body_poll(&self, request: bool) {
        if request {
            self.update(|worker, at| {
                if worker.request.body_first_poll.is_none() {
                    worker.request.body_first_poll = Some(at);
                    worker.bodies_admitted += 1;
                }
            });
        }
    }

    fn progress(&self, request: bool, bytes: usize) {
        self.update(|worker, at| {
            if request {
                worker.request.body_bytes += bytes as u64;
                worker.request.body_last_progress = Some(at);
            } else {
                worker.request.response_bytes += bytes as u64;
                worker.request.response_last_progress = Some(at);
            }
        });
    }

    fn end(&self, request: bool, signal: &'static str) {
        self.update(|worker, at| {
            let request_state = &mut worker.request;
            let (end, end_signal) = if request {
                (
                    &mut request_state.body_end,
                    &mut request_state.body_end_signal,
                )
            } else {
                (
                    &mut request_state.response_end,
                    &mut request_state.response_end_signal,
                )
            };
            if end.is_none() {
                *end = Some(at);
                *end_signal = Some(signal);
            }
        });
    }
}

fn header_token(headers: &http::HeaderMap, name: http::header::HeaderName, token: &str) -> bool {
    headers.get_all(name).iter().any(|value| {
        value.to_str().is_ok_and(|text| {
            text.split(',')
                .any(|v| v.trim().eq_ignore_ascii_case(token))
        })
    })
}

pub fn error_class(error: &hyper::Error) -> &'static str {
    if error.is_incomplete_message() {
        "incomplete_message"
    } else if error.is_parse() {
        "http_parse"
    } else if error.is_timeout() {
        "timeout"
    } else if error.is_canceled() {
        "cancelled"
    } else if error.is_closed() {
        "closed"
    } else if error.is_body_write_aborted() {
        "body_write_aborted"
    } else {
        "hyper_transport_or_body"
    }
}

/// Delegates the same frame poll/size hint/end-stream contract. Body completion
/// is a Hyper body signal, never a socket flush, peer receipt or driver close.
pub struct DiagnosticBody<B> {
    inner: B,
    observation: Observation,
    request: bool,
}

impl<B: Body> DiagnosticBody<B> {
    pub fn new(inner: B, observation: Observation, request: bool) -> Self {
        if inner.is_end_stream() {
            observation.end(request, "initial_end_stream");
        }
        Self {
            inner,
            observation,
            request,
        }
    }
}

impl<B: Body + Unpin> Body for DiagnosticBody<B> {
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        self.observation.body_poll(self.request);
        let result = Pin::new(&mut self.inner).poll_frame(cx);
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    self.observation.progress(self.request, data.remaining());
                }
                if self.inner.is_end_stream() {
                    self.observation.end(self.request, "end_stream_after_frame");
                }
            }
            Poll::Ready(None) => self.observation.end(self.request, "poll_none"),
            _ => {}
        }
        result
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

struct DriverDrop {
    diagnostic: Diagnostic,
    id: u64,
    completed: bool,
}

impl Drop for DriverDrop {
    fn drop(&mut self) {
        if !self.completed {
            self.diagnostic
                .driver(self.id, "dropped_without_result", None);
        }
    }
}

#[derive(Default)]
struct DriverTasks {
    tasks: JoinSet<bool>,
    totals: Retirement,
}

impl DriverTasks {
    fn joined(&mut self, result: Result<bool, tokio::task::JoinError>) {
        match result {
            Ok(true) => self.totals.completed_ok += 1,
            Ok(false) => self.totals.completed_error += 1,
            Err(error) if error.is_cancelled() => self.totals.cancelled += 1,
            Err(_) => self.totals.panicked += 1,
        }
    }
}

/// Ownership is enabled only in diagnostic mode. Capacity overflow is an
/// explicit diagnostic failure, never an untracked detached driver or success.
#[derive(Clone, Default)]
pub struct Drivers(Arc<Mutex<DriverTasks>>);

impl Drivers {
    pub fn spawn(
        &self,
        diagnostic: &Diagnostic,
        id: u64,
        driver: impl Future<Output = Result<(), hyper::Error>> + Send + 'static,
    ) -> anyhow::Result<()> {
        if !diagnostic.enabled() {
            tokio::spawn(async move {
                let _ = driver.await;
            });
            return Ok(());
        }
        let mut owned = self
            .0
            .lock()
            .map_err(|_| anyhow::anyhow!("H1 driver registry poisoned"))?;
        while let Some(result) = owned.tasks.try_join_next() {
            owned.joined(result);
        }
        if owned.tasks.len() == MAX_CONNECTIONS {
            owned.totals.capacity_rejections += 1;
            diagnostic.driver(id, "capacity_rejected", None);
            anyhow::bail!("H1 diagnostic active-driver capacity exceeded");
        }
        owned.totals.started += 1;
        diagnostic.driver(id, "running", None);
        let mut guard = DriverDrop {
            diagnostic: diagnostic.clone(),
            id,
            completed: false,
        };
        owned.tasks.spawn(async move {
            let result = driver.await;
            guard.diagnostic.driver(
                id,
                if result.is_ok() {
                    "completed_ok"
                } else {
                    "completed_error"
                },
                result.as_ref().err().map(error_class),
            );
            guard.completed = true;
            result.is_ok()
        });
        Ok(())
    }

    pub async fn retire(&self, diagnostic: &Diagnostic, bound: Duration) {
        if !diagnostic.enabled() {
            return;
        }
        diagnostic.phase("driver_retirement", Instant::now(), None);
        let start = Instant::now();
        // Workers have all joined before this call; no new registrations race it.
        let mut owned = {
            // Recovery retains the owned handles for abort/reap; never detach on poison.
            let mut registry = self.0.lock().unwrap_or_else(|e| e.into_inner());
            std::mem::take(&mut *registry)
        };
        while let Some(result) = owned.tasks.try_join_next() {
            owned.joined(result);
        }
        owned.totals.pending_at_request_drain = owned.tasks.len();
        owned.totals.bound_secs = bound.as_secs_f64();
        let drained = tokio::time::timeout(bound, async {
            while let Some(result) = owned.tasks.join_next().await {
                owned.joined(result);
            }
        })
        .await;
        if drained.is_err() {
            owned.totals.timed_out = true;
            owned.totals.abort_requested = owned.tasks.len();
            owned.tasks.abort_all();
            let reap_bound = Duration::from_secs(1);
            owned.totals.abort_reap_bound_secs = reap_bound.as_secs_f64();
            let _ = tokio::time::timeout(reap_bound, async {
                while let Some(result) = owned.tasks.join_next().await {
                    owned.joined(result);
                }
            })
            .await;
            owned.totals.unreaped_after_abort = owned.tasks.len();
        }
        owned.totals.elapsed_secs = start.elapsed().as_secs_f64();
        if let Some(mut state) = diagnostic.lock() {
            state.retirement = Some(owned.totals);
        }
        diagnostic.snapshot("driver_retirement_finished");
    }
}
