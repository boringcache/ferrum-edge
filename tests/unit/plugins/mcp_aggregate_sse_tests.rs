//! External unit coverage for the aggregate MCP SSE session broker (#3295).

use bytes::Bytes;
use ferrum_edge::plugins::mcp_aggregate_sse::{
    AggregateSseBounds, AggregateSseBroker, AggregateSseError, StreamIdentity,
};
use http_body::Frame;
use serde_json::json;
use std::sync::Arc;
use std::time::Duration;

fn broker() -> AggregateSseBroker {
    AggregateSseBroker::new(AggregateSseBounds::default(), 16, 4)
}

#[tokio::test]
async fn concurrent_streams_multiplex_onto_one_listener() {
    let broker = broker();
    broker.ensure_session("sess-a").unwrap();
    let mut rx = broker.attach_listener("sess-a", None).await.unwrap();

    let id_a = StreamIdentity::from_json_rpc_id(&json!("req-a"), 128).unwrap();
    let id_b = StreamIdentity::from_json_rpc_id(&json!(42), 128).unwrap();
    broker.open_stream("sess-a", id_a.clone()).await.unwrap();
    broker.open_stream("sess-a", id_b.clone()).await.unwrap();

    let broker = Arc::new(broker);
    let b1 = Arc::clone(&broker);
    let b2 = Arc::clone(&broker);
    let a = id_a.clone();
    let b = id_b.clone();
    let t1 = tokio::spawn(async move {
        b1.publish("sess-a", Some(&a), &json!({"jsonrpc":"2.0","id":"req-a","result":{}}))
            .await
    });
    let t2 = tokio::spawn(async move {
        b2.publish("sess-a", Some(&b), &json!({"jsonrpc":"2.0","id":42,"result":{}}))
            .await
    });
    let e1 = t1.await.unwrap().unwrap();
    let e2 = t2.await.unwrap().unwrap();
    assert_ne!(e1, e2);

    // Opening comment + two events.
    let mut frames = Vec::new();
    while frames.len() < 3 {
        let frame = rx.recv().await.expect("frame");
        let data = frame.expect("ok").into_data().expect("data frame");
        frames.push(data);
    }
    let joined = frames
        .iter()
        .map(|b| String::from_utf8_lossy(b).into_owned())
        .collect::<String>();
    assert!(joined.contains("req-a"));
    assert!(joined.contains("\"id\":42") || joined.contains("id: "));
}

#[tokio::test]
async fn bounded_backpressure_fails_closed_on_queue_overflow() {
    let bounds = AggregateSseBounds {
        max_queue_events: 2,
        max_replay_events: 0,
        ..AggregateSseBounds::default()
    }
    .validate()
    .unwrap();
    let broker = AggregateSseBroker::new(bounds, 4, 2);
    broker.ensure_session("sess-b").unwrap();
    // No listener: events land in the pending queue.
    let id = StreamIdentity::from_json_rpc_id(&json!("q"), 128).unwrap();
    broker.open_stream("sess-b", id.clone()).await.unwrap();
    broker
        .publish("sess-b", Some(&id), &json!({"jsonrpc":"2.0","id":"q","result":{"n":1}}))
        .await
        .unwrap();
    broker
        .publish("sess-b", Some(&id), &json!({"jsonrpc":"2.0","id":"q","result":{"n":2}}))
        .await
        .unwrap();
    let err = broker
        .publish("sess-b", Some(&id), &json!({"jsonrpc":"2.0","id":"q","result":{"n":3}}))
        .await
        .unwrap_err();
    assert_eq!(err, AggregateSseError::QueueOverflow);
}

#[tokio::test]
async fn cancel_and_disconnect_cleanup() {
    let broker = broker();
    broker.ensure_session("sess-c").unwrap();
    let rx = broker.attach_listener("sess-c", None).await.unwrap();
    let id = StreamIdentity::from_json_rpc_id(&json!("c1"), 128).unwrap();
    broker.open_stream("sess-c", id.clone()).await.unwrap();
    broker.cancel_stream("sess-c", &id).await.unwrap();
    let err = broker
        .publish("sess-c", Some(&id), &json!({"jsonrpc":"2.0","id":"c1","result":{}}))
        .await
        .unwrap_err();
    assert_eq!(err, AggregateSseError::Cancelled);

    // Dropping the receiver detaches delivery; re-attach must succeed after
    // explicit detach (disconnect cleanup).
    drop(rx);
    broker.detach_listener("sess-c").await;
    let _rx2 = broker.attach_listener("sess-c", None).await.unwrap();
}

#[tokio::test]
async fn invalid_unknown_stale_identities_fail_closed() {
    let broker = broker();
    assert_eq!(
        StreamIdentity::from_json_rpc_id(&json!({"x": 1}), 128).unwrap_err(),
        AggregateSseError::StreamIdInvalid
    );
    assert_eq!(
        StreamIdentity::from_json_rpc_id(&json!("x".repeat(200)), 128).unwrap_err(),
        AggregateSseError::StreamIdTooLarge
    );
    assert_eq!(
        broker.get_session("missing").unwrap_err(),
        AggregateSseError::UnknownSession
    );

    broker.ensure_session("sess-d").unwrap();
    let id = StreamIdentity::from_json_rpc_id(&json!("d1"), 128).unwrap();
    assert_eq!(
        broker.cancel_stream("sess-d", &id).await.unwrap_err(),
        AggregateSseError::UnknownStream
    );
    broker.open_stream("sess-d", id.clone()).await.unwrap();
    broker.cancel_stream("sess-d", &id).await.unwrap();
    assert_eq!(
        broker.cancel_stream("sess-d", &id).await.unwrap_err(),
        AggregateSseError::StaleStream
    );

    assert_eq!(
        broker.attach_listener("sess-d", Some("not-a-number")).await.unwrap_err(),
        AggregateSseError::LastEventIdInvalid
    );
    assert_eq!(
        broker
            .attach_listener("sess-d", Some(&"9".repeat(200)))
            .await
            .unwrap_err(),
        AggregateSseError::LastEventIdTooLarge
    );
}

#[tokio::test]
async fn duplicate_listener_and_reload_generation_teardown() {
    let broker = broker();
    broker.ensure_session("sess-e").unwrap();
    let rx = broker.attach_listener("sess-e", None).await.unwrap();
    assert_eq!(
        broker.attach_listener("sess-e", None).await.unwrap_err(),
        AggregateSseError::DuplicateListener
    );
    drop(rx);

    let gen = broker.generation();
    broker.retire_generation();
    assert_ne!(broker.generation(), gen);
    assert_eq!(broker.session_count(), 0);
    // New generation can attach again.
    broker.ensure_session("sess-e").unwrap();
    let _ = broker.attach_listener("sess-e", None).await.unwrap();
}

#[tokio::test]
async fn last_event_id_replay_is_bounded_and_deterministic() {
    let bounds = AggregateSseBounds {
        max_replay_events: 2,
        ..AggregateSseBounds::default()
    }
    .validate()
    .unwrap();
    let broker = AggregateSseBroker::new(bounds, 4, 2);
    broker.ensure_session("sess-f").unwrap();
    let id = StreamIdentity::from_json_rpc_id(&json!("f"), 128).unwrap();
    broker.open_stream("sess-f", id.clone()).await.unwrap();
    let e1 = broker
        .publish("sess-f", Some(&id), &json!({"jsonrpc":"2.0","id":"f","result":{"n":1}}))
        .await
        .unwrap();
    let _e2 = broker
        .publish("sess-f", Some(&id), &json!({"jsonrpc":"2.0","id":"f","result":{"n":2}}))
        .await
        .unwrap();
    let e3 = broker
        .publish("sess-f", Some(&id), &json!({"jsonrpc":"2.0","id":"f","result":{"n":3}}))
        .await
        .unwrap();
    // Ring retained only the last two; resume after e1 should still see e3.
    let mut rx = broker
        .attach_listener("sess-f", Some(&e1.to_string()))
        .await
        .unwrap();
    let mut saw_e3 = false;
    for _ in 0..4 {
        let Some(frame) = rx.recv().await else {
            break;
        };
        let data = frame.unwrap().into_data().unwrap();
        let text = String::from_utf8_lossy(&data);
        if text.contains(&format!("id: {e3}")) {
            saw_e3 = true;
        }
        // Must not replay the event at or before the cursor.
        assert!(
            !text.contains(&format!("id: {e1}\n")),
            "replay must skip events at or before Last-Event-ID"
        );
    }
    assert!(saw_e3);
}

#[tokio::test]
async fn drop_broker_ends_listener_without_cross_generation_leak() {
    let broker = broker();
    broker.ensure_session("sess-g").unwrap();
    let mut rx = broker.attach_listener("sess-g", None).await.unwrap();
    // Drain the opening comment.
    let _ = rx.recv().await;
    drop(broker);
    // Sender side is gone; recv completes with None.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(1);
    let finished = tokio::time::timeout_at(deadline, rx.recv()).await;
    assert!(matches!(finished, Ok(None)));
}

#[test]
fn bounds_validation_is_field_specific() {
    let err = AggregateSseBounds {
        max_event_bytes: 100,
        max_queue_bytes: 50,
        ..AggregateSseBounds::default()
    }
    .validate()
    .unwrap_err();
    assert!(err.contains("sse_max_event_bytes"));
    assert!(!err.contains("100"));
}

#[test]
fn frame_data_helpers_compile() {
    // Keep Frame/Bytes import surface exercised for harness parity.
    let _ = Frame::data(Bytes::from_static(b": ok\n\n"));
}
