//! External unit coverage for the aggregate MCP SSE session broker (#3295).
//!
//! Covers the invariants the broker exists to hold: one listener per session
//! multiplexing many request streams, race-free session and stream
//! cardinality, a single retained-byte budget, deterministic replay-then-live
//! ordering, explicit `Last-Event-ID` semantics, reliable teardown on
//! disconnect / delete / reload, and value-free diagnostics.

use ferrum_edge::plugins::mcp_aggregate_sse::{
    AggregateSseBody, AggregateSseBounds, AggregateSseBroker, AggregateSseError as SseError,
    SseFrameResult, StreamIdentity,
};
use futures_util::StreamExt;
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::Duration;

const FRAME_TIMEOUT: Duration = Duration::from_secs(2);
const IDLE_WINDOW: Duration = Duration::from_millis(150);

fn bounds() -> AggregateSseBounds {
    AggregateSseBounds::default()
}

fn broker() -> AggregateSseBroker {
    AggregateSseBroker::new(bounds(), 16, 4)
}

fn text_id(value: &str) -> StreamIdentity {
    match StreamIdentity::from_json_rpc_id(&json!(value), 128) {
        Ok(identity) => identity,
        Err(error) => panic!("string id must be admissible: {error:?}"),
    }
}

fn number_id(value: i64) -> StreamIdentity {
    match StreamIdentity::from_json_rpc_id(&json!(value), 128) {
        Ok(identity) => identity,
        Err(error) => panic!("number id must be admissible: {error:?}"),
    }
}

fn identity_error(id: Value) -> SseError {
    match StreamIdentity::from_json_rpc_id(&id, 128) {
        Ok(_) => panic!("identity must be refused"),
        Err(error) => error,
    }
}

fn publish(broker: &AggregateSseBroker, session: &str, id: i64) -> Result<u64, SseError> {
    let payload = json!({"jsonrpc": "2.0", "id": id, "result": {"n": id}});
    broker.publish_response(session, &number_id(id), &payload)
}

fn publish_text(broker: &AggregateSseBroker, session: &str, id: &str) -> Result<u64, SseError> {
    let payload = json!({"jsonrpc": "2.0", "id": id, "result": {}});
    broker.publish_response(session, &text_id(id), &payload)
}

fn frame_text(frame: Option<SseFrameResult>) -> String {
    let frame = match frame {
        Some(Ok(frame)) => frame,
        Some(Err(error)) => panic!("broker bodies never error: {error}"),
        None => panic!("stream ended before the expected frame"),
    };
    let data = match frame.into_data() {
        Ok(data) => data,
        Err(_) => panic!("broker bodies emit data frames only"),
    };
    String::from_utf8_lossy(&data).into_owned()
}

async fn next_frame(body: &mut AggregateSseBody) -> Option<SseFrameResult> {
    match tokio::time::timeout(FRAME_TIMEOUT, body.next()).await {
        Ok(frame) => frame,
        Err(_) => panic!("expected a frame within the timeout"),
    }
}

/// True when the stream produces nothing within `IDLE_WINDOW`.
async fn stays_idle(body: &mut AggregateSseBody) -> bool {
    let polled = tokio::time::timeout(IDLE_WINDOW, body.next()).await;
    polled.is_err()
}

async fn assert_ended(body: &mut AggregateSseBody) {
    match tokio::time::timeout(FRAME_TIMEOUT, body.next()).await {
        Ok(None) => {}
        Ok(Some(_)) => panic!("stream produced a frame after it should have ended"),
        Err(_) => panic!("stream did not end promptly"),
    }
}

/// Drain frames until every needle has been seen or the stream stalls.
async fn drain_until(body: &mut AggregateSseBody, wanted: &[&str], max_frames: usize) -> String {
    let mut seen = String::new();
    for _ in 0..max_frames {
        if wanted.iter().all(|needle| seen.contains(needle)) {
            break;
        }
        let Ok(frame) = tokio::time::timeout(FRAME_TIMEOUT, body.next()).await else {
            break;
        };
        if frame.is_none() {
            break;
        }
        seen.push_str(&frame_text(frame));
    }
    seen
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_listener_multiplexes_concurrent_request_streams() {
    let broker = Arc::new(broker());
    broker.ensure_session("sess-a").unwrap();
    let listener = broker.attach_listener("sess-a", None).unwrap();
    let mut body = listener.take_body().expect("body claimed once");

    let publish_a = {
        let broker = Arc::clone(&broker);
        tokio::spawn(async move { publish_text(&broker, "sess-a", "req-a") })
    };
    let publish_b = {
        let broker = Arc::clone(&broker);
        tokio::spawn(async move { publish(&broker, "sess-a", 42) })
    };
    let first = publish_a.await.unwrap().unwrap();
    let second = publish_b.await.unwrap().unwrap();
    // Each multiplexed event carries its own monotonic SSE id.
    assert_ne!(first, second);

    let seen = drain_until(&mut body, &["req-a", "\"n\":42"], 8).await;
    // The greeting proves the stream is established before any event.
    assert!(seen.contains(": mcp-sse"));
    assert!(seen.contains("req-a"), "string identity delivered");
    assert!(seen.contains("\"n\":42"), "number identity delivered");
    assert!(seen.contains("event: message"));
}

#[test]
fn json_rpc_string_and_number_identities_never_collide() {
    let string_one = StreamIdentity::from_json_rpc_id(&json!("1"), 128);
    let number_one = StreamIdentity::from_json_rpc_id(&json!(1), 128);
    assert_ne!(string_one.unwrap(), number_one.unwrap());
}

#[test]
fn string_and_number_identities_are_separate_streams() {
    let broker = broker();
    broker.ensure_session("sess-id").unwrap();
    publish_text(&broker, "sess-id", "1").unwrap();
    // A DIFFERENT stream, so it is still admissible even though the string
    // form just completed and would otherwise be refused as a duplicate.
    publish(&broker, "sess-id", 1).unwrap();
}

#[test]
fn unrepresentable_and_oversized_identities_fail_closed() {
    let object = identity_error(json!({"x": 1}));
    assert_eq!(object, SseError::StreamIdInvalid);
    let array = identity_error(json!([1]));
    assert_eq!(array, SseError::StreamIdInvalid);
    let boolean = identity_error(json!(true));
    assert_eq!(boolean, SseError::StreamIdInvalid);
    let null = identity_error(json!(null));
    assert_eq!(null, SseError::StreamIdInvalid);
    let empty = identity_error(json!(""));
    assert_eq!(empty, SseError::StreamIdMissing);
    let long = identity_error(json!("x".repeat(200)));
    assert_eq!(long, SseError::StreamIdTooLarge);
    // Control bytes would break SSE framing if an identity were ever mirrored.
    let control = identity_error(json!("a\nb"));
    assert_eq!(control, SseError::StreamIdInvalid);
}

#[test]
fn completed_stream_releases_capacity_and_refuses_late_duplicates() {
    let tuned = AggregateSseBounds {
        max_streams_per_session: 2,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-cap").unwrap();

    broker.open_stream("sess-cap", &text_id("s1")).unwrap();
    broker.open_stream("sess-cap", &text_id("s2")).unwrap();
    // A third concurrent OPEN stream exceeds the per-session bound.
    let overflow = broker.open_stream("sess-cap", &text_id("s3"));
    assert_eq!(overflow.unwrap_err(), SseError::StreamCardinalityOverflow);

    // Completing a stream must return its capacity, or the session would be
    // permanently exhausted after `max_streams_per_session` requests.
    publish_text(&broker, "sess-cap", "s1").unwrap();
    broker.open_stream("sess-cap", &text_id("s3")).unwrap();

    // A late or duplicate response for a completed identity is refused rather
    // than misattributed onto a fresh stream.
    let late = publish_text(&broker, "sess-cap", "s1");
    assert_eq!(late.unwrap_err(), SseError::StreamCompleted);
    let reopen = broker.open_stream("sess-cap", &text_id("s1"));
    assert_eq!(reopen.unwrap_err(), SseError::StreamCompleted);
}

#[test]
fn cancelled_stream_refuses_its_own_response() {
    let broker = broker();
    broker.ensure_session("sess-cancel").unwrap();
    let identity = text_id("c1");
    let unknown = broker.cancel_stream("sess-cancel", &identity);
    assert_eq!(unknown.unwrap_err(), SseError::UnknownStream);

    broker.open_stream("sess-cancel", &identity).unwrap();
    broker.cancel_stream("sess-cancel", &identity).unwrap();
    let again = broker.cancel_stream("sess-cancel", &identity);
    assert_eq!(again.unwrap_err(), SseError::StreamCancelled);

    let refused = publish_text(&broker, "sess-cancel", "c1");
    assert_eq!(refused.unwrap_err(), SseError::StreamCancelled);
}

#[tokio::test]
async fn duplicate_listener_is_refused_and_disconnect_permits_reattach() {
    let broker = broker();
    broker.ensure_session("sess-dup").unwrap();
    let listener = broker.attach_listener("sess-dup", None).unwrap();
    let body = listener.take_body().expect("first claim wins");
    // The body is single-consumer: a second claim on the same lease fails.
    assert!(listener.take_body().is_none());
    let duplicate = broker.attach_listener("sess-dup", None);
    assert_eq!(duplicate.unwrap_err(), SseError::DuplicateListener);

    // A transport disconnect drops the body, which is the ONLY delivery-side
    // release path. Without it the session stays locked out forever.
    drop(body);
    let reattached = broker.attach_listener("sess-dup", None).unwrap();
    assert!(reattached.take_body().is_some());
}

#[tokio::test]
async fn unclaimed_listener_lease_releases_the_slot_on_drop() {
    let broker = broker();
    broker.ensure_session("sess-lease").unwrap();
    let listener = broker.attach_listener("sess-lease", None).unwrap();
    // A clone is what a `RequestContext` clone produces: it shares the lease,
    // so the slot is released only once every handle is gone.
    let clone = listener.clone();
    drop(listener);
    let still_held = broker.attach_listener("sess-lease", None);
    assert_eq!(still_held.unwrap_err(), SseError::DuplicateListener);
    drop(clone);
    assert!(broker.attach_listener("sess-lease", None).is_ok());
}

#[tokio::test]
async fn attach_delivers_staged_events_exactly_once() {
    let broker = broker();
    broker.ensure_session("sess-stage").unwrap();
    publish(&broker, "sess-stage", 1).unwrap();

    let listener = broker.attach_listener("sess-stage", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let seen = drain_until(&mut body, &["\"n\":1"], 4).await;
    // Staging and replay share one ring, so an event is never delivered twice.
    assert_eq!(seen.matches("\"n\":1").count(), 1);

    // Reattaching without a cursor resumes at the delivery watermark, so an
    // already-delivered event is not replayed.
    drop(body);
    let listener = broker.attach_listener("sess-stage", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let greeting = frame_text(next_frame(&mut body).await);
    assert!(greeting.contains(": mcp-sse"));
    assert!(stays_idle(&mut body).await);
}

#[tokio::test]
async fn last_event_id_replays_only_newer_events() {
    let broker = broker();
    broker.ensure_session("sess-replay").unwrap();
    let listener = broker.attach_listener("sess-replay", None).unwrap();
    let mut body = listener.take_body().unwrap();

    let mut ids = Vec::new();
    for index in 1..=3 {
        ids.push(publish(&broker, "sess-replay", index).unwrap());
    }
    let seen = drain_until(&mut body, &["\"n\":3"], 8).await;
    assert!(seen.contains("\"n\":1"));
    assert!(seen.contains("\"n\":3"));
    drop(body);

    let cursor = ids[0].to_string();
    let resumed = broker.attach_listener("sess-replay", Some(&cursor));
    let mut body = resumed.unwrap().take_body().unwrap();
    let seen = drain_until(&mut body, &["\"n\":3"], 8).await;
    assert!(!seen.contains("\"n\":1"), "cursor event is not replayed");
    assert!(seen.contains("\"n\":2"), "newer events are replayed");
    assert!(seen.contains("\"n\":3"));
}

#[tokio::test]
async fn last_event_id_boundaries_fail_closed() {
    let broker = broker();
    broker.ensure_session("sess-cursor").unwrap();
    let invalid = broker.attach_listener("sess-cursor", Some("not-a-number"));
    assert_eq!(invalid.unwrap_err(), SseError::LastEventIdInvalid);

    let long = "9".repeat(200);
    let too_large = broker.attach_listener("sess-cursor", Some(&long));
    assert_eq!(too_large.unwrap_err(), SseError::LastEventIdTooLarge);

    // A cursor ahead of anything the broker ever issued is not continuity the
    // gateway may fabricate.
    let ahead = broker.attach_listener("sess-cursor", Some("99"));
    assert_eq!(ahead.unwrap_err(), SseError::LastEventIdUnknown);
    assert_eq!(SseError::LastEventIdUnknown.http_status(), 400);
}

#[tokio::test]
async fn cursor_older_than_retained_history_is_gone_not_silently_resumed() {
    // Replay disabled: a consumed event is evicted immediately, so only the
    // exact delivery watermark can resume.
    let tuned = AggregateSseBounds {
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-gone").unwrap();
    let listener = broker.attach_listener("sess-gone", None).unwrap();
    let mut body = listener.take_body().unwrap();

    let mut ids = Vec::new();
    for index in 1..=3 {
        ids.push(publish(&broker, "sess-gone", index).unwrap());
    }
    let seen = drain_until(&mut body, &["\"n\":3"], 8).await;
    assert!(seen.contains("\"n\":3"));
    drop(body);

    let stale = ids[0].to_string();
    let refused = broker.attach_listener("sess-gone", Some(&stale));
    assert_eq!(refused.unwrap_err(), SseError::LastEventIdTooOld);
    // Lost history is gone for good, not a retryable 404.
    assert_eq!(SseError::LastEventIdTooOld.http_status(), 410);

    // The current watermark still resumes: nothing was missed there.
    let current = ids[2].to_string();
    assert!(broker.attach_listener("sess-gone", Some(&current)).is_ok());
}

#[tokio::test]
async fn retention_is_one_budget_and_never_drops_an_undelivered_response() {
    // Two retained events, no replay window. With no listener attached every
    // event is still owed to a consumer, so the third publish must fail closed
    // rather than evict a JSON-RPC response nobody has seen.
    let tuned = AggregateSseBounds {
        max_retained_events: 2,
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-budget").unwrap();
    publish(&broker, "sess-budget", 1).unwrap();
    publish(&broker, "sess-budget", 2).unwrap();
    let overflow = publish(&broker, "sess-budget", 3);
    assert_eq!(overflow.unwrap_err(), SseError::RetentionOverflow);

    // Draining frees the consumed prefix, so the session recovers instead of
    // being stranded by one overflow.
    let listener = broker.attach_listener("sess-budget", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let seen = drain_until(&mut body, &["\"n\":2"], 6).await;
    assert!(seen.contains("\"n\":1"));
    assert!(seen.contains("\"n\":2"));
    publish(&broker, "sess-budget", 3).unwrap();
}

#[test]
fn byte_budget_bounds_total_retained_bytes() {
    // One ~4 KiB event fits; two do not. The retired design's independent
    // pending and replay caps would have retained about twice this.
    let tuned = AggregateSseBounds {
        max_event_bytes: 4096,
        max_retained_bytes: 4096 + 128,
        max_replay_events: 0,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-bytes").unwrap();
    let filler = "x".repeat(3800);
    let payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"blob": filler}});
    let one = number_id(1);
    let two = number_id(2);
    broker
        .publish_response("sess-bytes", &one, &payload)
        .unwrap();
    let overflow = broker.publish_response("sess-bytes", &two, &payload);
    assert_eq!(overflow.unwrap_err(), SseError::RetentionOverflow);
}

#[test]
fn oversized_event_payload_fails_closed() {
    let tuned = AggregateSseBounds {
        max_event_bytes: 512,
        ..bounds()
    };
    let broker = AggregateSseBroker::new(tuned.validate().unwrap(), 4, 2);
    broker.ensure_session("sess-big").unwrap();
    let blob = "y".repeat(4096);
    let payload = json!({"jsonrpc": "2.0", "id": 1, "result": {"blob": blob}});
    let one = number_id(1);
    let refused = broker.publish_response("sess-big", &one, &payload);
    assert_eq!(refused.unwrap_err(), SseError::EventTooLarge);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn session_cardinality_is_race_free_under_concurrent_distinct_sessions() {
    let broker = Arc::new(AggregateSseBroker::new(bounds(), 4, 8));
    let mut handles = Vec::new();
    for index in 0..32 {
        let broker = Arc::clone(&broker);
        let key = format!("sess-{index}");
        let handle = tokio::spawn(async move { broker.ensure_session(&key) });
        handles.push(handle);
    }
    let mut admitted = 0usize;
    let mut refused = 0usize;
    for handle in handles {
        match handle.await.unwrap() {
            Ok(()) => admitted += 1,
            Err(SseError::SessionCardinalityOverflow) => refused += 1,
            Err(other) => panic!("unexpected admission error: {other:?}"),
        }
    }
    // Reservation precedes insertion, so admission can never exceed the cap.
    assert_eq!(admitted, 4);
    assert_eq!(refused, 28);
    assert_eq!(broker.session_count(), 4);

    // Removal returns capacity exactly once, so accounting cannot drift.
    broker.remove_session("does-not-exist");
    for index in 0..32 {
        broker.remove_session(&format!("sess-{index}"));
    }
    assert_eq!(broker.session_count(), 0);
    assert!(broker.ensure_session("sess-fresh").is_ok());
}

#[tokio::test]
async fn session_removal_ends_the_attached_body() {
    let broker = broker();
    broker.ensure_session("sess-del").unwrap();
    let listener = broker.attach_listener("sess-del", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let greeting = frame_text(next_frame(&mut body).await);
    assert!(greeting.contains(": mcp-sse"));

    broker.remove_session("sess-del");
    assert_ended(&mut body).await;
}

#[tokio::test]
async fn retiring_a_generation_ends_every_body_and_refuses_new_work() {
    let broker = broker();
    broker.ensure_session("sess-gen").unwrap();
    let listener = broker.attach_listener("sess-gen", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let _greeting = next_frame(&mut body).await;

    broker.retire_generation();
    assert!(broker.is_retired());
    assert_eq!(broker.session_count(), 0);
    assert_ended(&mut body).await;

    let readmit = broker.ensure_session("sess-gen");
    assert_eq!(readmit.unwrap_err(), SseError::BrokerRetired);
    let published = publish(&broker, "sess-gen", 1);
    assert_eq!(published.unwrap_err(), SseError::BrokerRetired);
}

#[tokio::test]
async fn dropping_the_broker_ends_in_flight_bodies() {
    let broker = broker();
    broker.ensure_session("sess-drop").unwrap();
    let listener = broker.attach_listener("sess-drop", None).unwrap();
    let mut body = listener.take_body().unwrap();
    let _greeting = next_frame(&mut body).await;

    // Reload / update / delete drops the owning plugin instance, which drops
    // the broker: no event may cross generations.
    drop(broker);
    assert_ended(&mut body).await;
}

#[test]
fn unknown_session_operations_fail_closed() {
    let broker = broker();
    let attach = broker.attach_listener("missing", None);
    assert_eq!(attach.unwrap_err(), SseError::UnknownSession);
    let open = broker.open_stream("missing", &text_id("x"));
    assert_eq!(open.unwrap_err(), SseError::UnknownSession);
    let published = publish(&broker, "missing", 1);
    assert_eq!(published.unwrap_err(), SseError::UnknownSession);
    assert!(!broker.has_listener("missing"));
    let empty = broker.ensure_session("");
    assert_eq!(empty.unwrap_err(), SseError::MissingSession);
}

#[tokio::test]
async fn idle_sessions_are_reaped_and_their_bodies_end() {
    let broker = broker();
    broker.ensure_session("sess-idle").unwrap();
    let listener = broker.attach_listener("sess-idle", None).unwrap();
    let mut body = listener.take_body().unwrap();

    assert_eq!(broker.reap_idle(Duration::from_secs(3600)), 0);
    assert_eq!(broker.reap_idle(Duration::from_millis(0)), 1);
    assert_eq!(broker.session_count(), 0);
    assert_ended(&mut body).await;
}

#[test]
fn bounds_validation_is_field_specific_and_value_free() {
    let err = AggregateSseBounds {
        max_event_bytes: 100,
        max_retained_bytes: 50,
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_max_event_bytes"));
    // Diagnostics name the field and never echo the configured value.
    assert!(!err.contains("100"));

    let err = AggregateSseBounds {
        max_replay_events: 4096,
        max_retained_events: 8,
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_max_replay_events"));

    let err = AggregateSseBounds {
        max_streams_per_session: 0,
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_max_streams_per_session"));

    let err = AggregateSseBounds {
        listener_max_lifetime: Duration::from_secs(1),
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_listener_max_lifetime_seconds"));

    let err = AggregateSseBounds {
        keepalive_interval: Duration::from_secs(3600),
        listener_max_lifetime: Duration::from_secs(60),
        ..bounds()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sessions.sse_keepalive_seconds"));

    assert!(bounds().validate().is_ok());
}

#[test]
fn every_error_reason_is_a_fixed_low_cardinality_token() {
    let errors = [
        SseError::MissingSession,
        SseError::UnknownSession,
        SseError::StaleSession,
        SseError::BrokerRetired,
        SseError::DuplicateListener,
        SseError::InvalidAccept,
        SseError::LastEventIdTooLarge,
        SseError::LastEventIdInvalid,
        SseError::LastEventIdTooOld,
        SseError::LastEventIdUnknown,
        SseError::StreamIdMissing,
        SseError::StreamIdTooLarge,
        SseError::StreamIdInvalid,
        SseError::DuplicateStream,
        SseError::UnknownStream,
        SseError::StreamCompleted,
        SseError::StreamCancelled,
        SseError::EventTooLarge,
        SseError::RetentionOverflow,
        SseError::StreamCardinalityOverflow,
        SseError::SessionCardinalityOverflow,
    ];
    for error in errors {
        let token = error.reason_token();
        assert!(!token.is_empty());
        let low_cardinality = token
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte == b'_');
        assert!(low_cardinality, "reason token stays a fixed slug: {token}");
        assert!(!error.as_static_reason().is_empty());
        assert!((400..=599).contains(&error.http_status()));
    }
}
