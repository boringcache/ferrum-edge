//! Protocol-correct termination of an admitted response body when the
//! authorization lifetime elapses (issue #3815).
//!
//! Covers: `UNAUTHENTICATED` trailers before any response DATA, deterministic
//! reset after DATA (never a fabricated successful status), the bounded
//! gRPC-Web trailer frame, upstream cancellation, non-extension by activity,
//! earliest-deadline-wins against a client `grpc-timeout`, and the unbounded
//! (unauthenticated) baseline.

use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{
    GRPC_FRAME_TRAILER, parse_grpc_frames, proxy_body_into_grpc_web_streaming_for_test,
    proxy_body_streaming_for_test, proxy_body_with_authorization_deadline_for_test,
    proxy_body_with_client_grpc_deadline_for_test,
};
use ferrum_edge::proxy::auth_lifetime::{
    StreamAuthDeadline, StreamAuthProtocolFamily, StreamAuthTermination,
};
use ferrum_edge::proxy::body::ProxyBodyError;
use futures_util::stream;
use http_body::{Body, Frame};
use http_body_util::{BodyExt, StreamBody};

/// A body that yields the queued frames and then stalls forever, recording how
/// often it was polled and whether it was dropped. Stands in for a backend
/// stream that would keep producing indefinitely.
struct ProbeBody {
    frames: VecDeque<Frame<Bytes>>,
    polls: Arc<AtomicUsize>,
    dropped: Arc<AtomicBool>,
}

impl http_body::Body for ProbeBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        _cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        match self.frames.pop_front() {
            Some(frame) => std::task::Poll::Ready(Some(Ok(frame))),
            None => std::task::Poll::Pending,
        }
    }
}

impl Drop for ProbeBody {
    fn drop(&mut self) {
        self.dropped.store(true, Ordering::SeqCst);
    }
}

fn elapsed_deadline(termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .expect("one second before now is representable"),
        termination,
    }
}

fn future_deadline(after: Duration, termination: StreamAuthTermination) -> StreamAuthDeadline {
    StreamAuthDeadline {
        at: tokio::time::Instant::now() + after,
        termination,
    }
}

fn pending_body() -> ferrum_edge::proxy::ProxyBody {
    proxy_body_streaming_for_test(Box::pin(StreamBody::new(stream::pending::<
        Result<Frame<Bytes>, ProxyBodyError>,
    >())))
}

// --- Before response commitment --------------------------------------------

#[tokio::test]
async fn expiry_before_response_data_emits_unauthenticated_grpc_trailers() {
    let mut body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Grpc,
    );

    let frame = body
        .frame()
        .await
        .expect("the deadline must produce a terminal frame")
        .expect("terminal frame must be readable");
    let trailers = frame
        .trailers_ref()
        .expect("native gRPC terminates with HTTP trailers");
    assert_eq!(trailers.get("grpc-status").unwrap().to_str().unwrap(), "16");
    assert_eq!(
        trailers.get("grpc-message").unwrap().to_str().unwrap(),
        "credential expired"
    );
    assert!(Body::is_end_stream(&body));
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn the_max_lifetime_class_carries_its_own_bounded_message() {
    let mut body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::AuthenticatedStreamMaxLifetime),
        None,
        StreamAuthProtocolFamily::Http,
    );

    let frame = body.frame().await.unwrap().unwrap();
    let trailers = frame.trailers_ref().unwrap();
    assert_eq!(trailers.get("grpc-status").unwrap().to_str().unwrap(), "16");
    assert_eq!(
        trailers.get("grpc-message").unwrap().to_str().unwrap(),
        "authenticated stream lifetime reached"
    );
}

#[tokio::test]
async fn grpc_web_expiry_emits_the_equivalent_bounded_trailer_frame() {
    let body = proxy_body_with_authorization_deadline_for_test(
        pending_body(),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        Some("application/grpc-web+proto"),
        StreamAuthProtocolFamily::GrpcWeb,
    );
    let mut body =
        proxy_body_into_grpc_web_streaming_for_test(body, "application/grpc-web+proto", 200, None);

    let frame = body.frame().await.unwrap().unwrap();
    let data = frame
        .data_ref()
        .expect("gRPC-Web carries terminal metadata as DATA");
    let frames = parse_grpc_frames(data);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
    let rendered = String::from_utf8_lossy(&frames[0].1).to_ascii_lowercase();
    assert!(
        rendered.contains("grpc-status: 16"),
        "expected UNAUTHENTICATED, got {rendered:?}"
    );
    assert!(Body::is_end_stream(&body));
}

// --- After response commitment ---------------------------------------------

#[tokio::test]
async fn expiry_after_response_data_resets_instead_of_fabricating_a_status() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let inner = ProbeBody {
        frames: VecDeque::from(vec![Frame::data(Bytes::from_static(b"event: tick\n\n"))]),
        polls: Arc::clone(&polls),
        dropped: Arc::clone(&dropped),
    };
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        future_deadline(
            Duration::from_millis(60),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Http,
    );

    // One SSE event is committed downstream.
    let first = body.frame().await.unwrap().unwrap();
    assert_eq!(first.data_ref().unwrap().as_ref(), b"event: tick\n\n".as_slice());

    // The deadline then fires. A complete message boundary cannot be proven, so
    // the body ends with a transport error — never a successful terminal status.
    let message = match body.frame().await.expect("the deadline must terminate the body") {
        Ok(_) => panic!(
            "post-commitment expiry must not fabricate a successful terminal status or frame"
        ),
        Err(error) => error.to_string(),
    };
    assert!(
        message.contains("authorization") || message.contains("credential expired"),
        "unexpected terminal message: {message}"
    );
    // Bounded and redacted: no expiry value, identity, or provider detail.
    assert!(!message.chars().any(|c| c.is_ascii_digit()));

    assert!(Body::is_end_stream(&body));
    assert!(
        dropped.load(Ordering::SeqCst),
        "upstream work must be cancelled when the deadline fires"
    );
}

#[tokio::test]
async fn the_upstream_body_is_dropped_exactly_once_at_expiry() {
    let polls = Arc::new(AtomicUsize::new(0));
    let dropped = Arc::new(AtomicBool::new(false));
    let inner = ProbeBody {
        frames: VecDeque::new(),
        polls: Arc::clone(&polls),
        dropped: Arc::clone(&dropped),
    };
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Grpc,
    );

    let _terminal = body.frame().await.unwrap().unwrap();
    assert!(dropped.load(Ordering::SeqCst));
    assert_eq!(
        polls.load(Ordering::SeqCst),
        0,
        "an already-elapsed deadline is checked before the inner body is polled"
    );
    // Draining again must not produce a second completion.
    assert!(body.frame().await.is_none());
    assert!(body.frame().await.is_none());
}

// --- Non-extension and composition -----------------------------------------

#[tokio::test(start_paused = true)]
async fn continuous_activity_never_extends_the_authorization_deadline() {
    // A backend that always has another frame ready never yields a `Pending`
    // inner poll, so an idle-style timer would never fire. The absolute deadline
    // is checked on EVERY poll and must still fire.
    let frames: VecDeque<Frame<Bytes>> = (0..1_000)
        .map(|_| Frame::data(Bytes::from_static(b"data: x\n\n")))
        .collect();
    let inner = ProbeBody {
        frames,
        polls: Arc::new(AtomicUsize::new(0)),
        dropped: Arc::new(AtomicBool::new(false)),
    };
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        future_deadline(
            Duration::from_secs(30),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Http,
    );

    for _ in 0..5 {
        let frame = body.frame().await.unwrap().unwrap();
        assert!(frame.data_ref().is_some());
    }

    tokio::time::advance(Duration::from_secs(31)).await;

    let terminal = body.frame().await.unwrap();
    assert!(
        terminal.is_err(),
        "a continuously active stream must still be terminated at its deadline"
    );
}

#[tokio::test]
async fn an_unexpired_deadline_passes_frames_through_untouched() {
    let inner = StreamBody::new(stream::iter(vec![
        Ok::<_, ProxyBodyError>(Frame::data(Bytes::from_static(b"one"))),
        Ok(Frame::data(Bytes::from_static(b"two"))),
    ]));
    let mut body = proxy_body_with_authorization_deadline_for_test(
        proxy_body_streaming_for_test(Box::pin(inner)),
        future_deadline(
            Duration::from_secs(3_600),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Http,
    );

    assert_eq!(
        body.frame().await.unwrap().unwrap().data_ref().unwrap().as_ref(),
        b"one".as_slice()
    );
    assert_eq!(
        body.frame().await.unwrap().unwrap().data_ref().unwrap().as_ref(),
        b"two".as_slice()
    );
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn an_earlier_client_grpc_timeout_wins_over_a_later_credential_deadline() {
    // The client deadline is installed first (inner), the authorization deadline
    // second (outer), exactly as the response funnels stack them. The earlier of
    // the two must decide the terminal status, and only one completion may occur.
    let body = proxy_body_with_client_grpc_deadline_for_test(
        pending_body(),
        tokio::time::Instant::now()
            .checked_sub(Duration::from_secs(1))
            .unwrap(),
        None,
    );
    let mut body = proxy_body_with_authorization_deadline_for_test(
        body,
        future_deadline(
            Duration::from_secs(3_600),
            StreamAuthTermination::CredentialExpired,
        ),
        None,
        StreamAuthProtocolFamily::Grpc,
    );

    let frame = body.frame().await.unwrap().unwrap();
    let trailers = frame.trailers_ref().expect("trailers");
    assert_eq!(
        trailers.get("grpc-status").unwrap().to_str().unwrap(),
        "4",
        "the earlier client grpc-timeout must decide the terminal status"
    );
    assert!(body.frame().await.is_none(), "no second completion");
}

#[tokio::test]
async fn an_earlier_credential_deadline_wins_over_a_later_client_grpc_timeout() {
    let body = proxy_body_with_client_grpc_deadline_for_test(
        pending_body(),
        tokio::time::Instant::now() + Duration::from_secs(3_600),
        None,
    );
    let mut body = proxy_body_with_authorization_deadline_for_test(
        body,
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Grpc,
    );

    let frame = body.frame().await.unwrap().unwrap();
    let trailers = frame.trailers_ref().expect("trailers");
    assert_eq!(trailers.get("grpc-status").unwrap().to_str().unwrap(), "16");
    assert!(body.frame().await.is_none(), "no second completion");
}

// --- Buffered and unbounded baselines --------------------------------------

#[tokio::test]
async fn a_buffered_body_is_already_committed_and_is_returned_unchanged() {
    use ferrum_edge::proxy::ProxyBody;

    let mut body = proxy_body_with_authorization_deadline_for_test(
        ProxyBody::from_string("hello"),
        elapsed_deadline(StreamAuthTermination::CredentialExpired),
        None,
        StreamAuthProtocolFamily::Http,
    );

    let frame = body.frame().await.unwrap().unwrap();
    assert_eq!(frame.data_ref().unwrap().as_ref(), b"hello".as_slice());
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn a_body_with_no_authorization_deadline_streams_to_completion() {
    let inner = StreamBody::new(stream::iter(vec![Ok::<_, ProxyBodyError>(Frame::data(
        Bytes::from_static(b"public"),
    ))]));
    let mut body = proxy_body_streaming_for_test(Box::pin(inner));

    assert_eq!(
        body.frame().await.unwrap().unwrap().data_ref().unwrap().as_ref(),
        b"public".as_slice()
    );
    assert!(body.frame().await.is_none());
}
