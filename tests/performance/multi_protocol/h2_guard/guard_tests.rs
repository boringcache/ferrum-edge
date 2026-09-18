//! Injected only into the verified h2 crate's private streams test module.
//! These call upstream recv_data/poll_data/clear_recv_buffer, not a guard model.
use super::*;
use crate::proto::streams::guard_observe::{admit, Limit, TARGET};
use std::sync::atomic::Ordering;
use tracing::field::{Field, Visit};
use tracing::span::{Attributes, Id, Record};
use tracing::{Event, Metadata, Subscriber};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<String>>>);

struct Message(String);
impl Visit for Message {
    fn record_debug(&mut self, field: &Field, value: &dyn fmt::Debug) {
        if field.name() == "message" {
            self.0 = format!("{value:?}");
        }
    }
}
impl Subscriber for Capture {
    fn enabled(&self, metadata: &Metadata<'_>) -> bool {
        metadata.target() == TARGET
    }
    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }
    fn record(&self, _: &Id, _: &Record<'_>) {}
    fn record_follows_from(&self, _: &Id, _: &Id) {}
    fn event(&self, event: &Event<'_>) {
        let mut message = Message(String::new());
        event.record(&mut message);
        self.0.lock().unwrap().push(message.0);
    }
    fn enter(&self, _: &Id) {}
    fn exit(&self, _: &Id) {}
}

fn observed(f: impl FnOnce()) -> Vec<String> {
    let capture = Capture::default();
    tracing::subscriber::with_default(capture.clone(), f);
    let rows = capture.0.lock().unwrap().clone();
    assert!(rows.iter().all(|row| row.len() < 4096));
    rows
}

struct NoopWake;
impl std::task::Wake for NoopWake {
    fn wake(self: Arc<Self>) {}
}

fn noop_waker() -> Waker {
    Waker::from(Arc::new(NoopWake))
}

fn connection() -> Streams<Bytes, client::Peer> {
    Streams::new(Config {
        initial_max_send_streams: 1000,
        local_max_buffer_size: 1024 * 1024,
        local_next_stream_id: 1.into(),
        local_push_enabled: false,
        extended_connect_protocol_enabled: false,
        local_reset_duration: std::time::Duration::from_secs(30),
        local_reset_max: 1000,
        remote_reset_max: 1000,
        remote_init_window_sz: 65535,
        remote_max_initiated: Some(1000),
        local_max_error_reset_streams: Some(1000),
        data_frame_budget: 32767,
    })
}

fn response(s: &mut Streams<Bytes, client::Peer>) -> StreamRef<Bytes> {
    let (mut stream, _) = s
        .send_request(Request::builder().uri("https://fixture.invalid/").body(()).unwrap(), true, None)
        .unwrap();
    // send_request only queues opening HEADERS. Drive the real prioritizer and
    // codec before receiving a response; an unflushed stream is still idle.
    let (io, _peer) = tokio::io::duplex(4096);
    let mut codec = Codec::new(io);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    assert!(matches!(s.poll_complete(&mut cx, &mut codec), Poll::Ready(Ok(()))));
    let headers = frame::Headers::new(
        stream.stream_id(),
        frame::Pseudo::response(http::StatusCode::OK),
        HeaderMap::new(),
    );
    s.as_dyn().recv_headers(headers).unwrap();
    assert!(matches!(
        stream.opaque.poll_response(&Context::from_waker(&noop_waker())),
        Poll::Ready(Ok(_))
    ));
    stream
}

fn data(s: &Streams<Bytes, client::Peer>, stream: &StreamRef<Bytes>, len: usize, end: bool) -> Result<(), Error> {
    let mut frame = frame::Data::new(stream.stream_id(), Bytes::from(vec![b'x'; len]));
    frame.set_end_stream(end);
    s.as_dyn().recv_data(frame)
}

fn state(s: &Streams<Bytes, client::Peer>) -> [usize; 7] {
    s.inner.lock().unwrap().counts.guard_state()
}

fn guard_error(error: Error) {
    match error {
        Error::GoAway(debug, Reason::ENHANCE_YOUR_CALM, Initiator::Library) => {
            assert_eq!(debug.as_ref(), b"too_many_data_frames");
        }
        other => panic!("unexpected guard result: {other:?}"),
    }
}

#[test]
fn guard_observation_small_credit_boundary_and_failure_snapshot() {
    let rows = observed(|| {
        let mut s = connection();
        let stream = response(&mut s);
        for _ in 0..128 {
            data(&s, &stream, 1, false).unwrap();
        }
        assert_eq!(&state(&s)[..3], &[32767, 127, 0]);
        guard_error(data(&s, &stream, 1, false).unwrap_err());
        assert_eq!(&state(&s)[..3], &[32767, 127, 0]);
        let me = s.inner.lock().unwrap();
        let observation = me.counts.observation.as_ref().unwrap();
        assert_eq!(observation.branch, 1);
        assert_eq!(observation.counters[1], 129);
        assert_eq!(observation.counters[5], 129); // queued before guard, including failure
    });
    let failures: Vec<_> = rows.iter().filter(|s| s.contains(" event=1 ")).collect();
    assert_eq!(failures.len(), 1);
    assert!(failures[0].contains(" branch=1 reason=11 "));
    assert!(failures[0].contains(" max=32767 available=127 empty=0 "));
    assert!(failures[0].contains(" last_len=1 last_flow=1 last_end=0 disposition=1 "));
    assert!(rows.iter().all(|s| !s.contains("fixture.invalid")));
}

#[test]
fn guard_observation_100_101_empty_nonfinal_and_final_empty_exemption() {
    observed(|| {
        let mut s = connection();
        let stream = response(&mut s);
        for _ in 0..100 {
            data(&s, &stream, 0, false).unwrap();
        }
        assert_eq!(&state(&s)[..3], &[32767, 32767, 100]);
        guard_error(data(&s, &stream, 0, false).unwrap_err());
        assert_eq!(&state(&s)[..3], &[32767, 32767, 101]);
        assert_eq!(s.inner.lock().unwrap().counts.observation.as_ref().unwrap().branch, 2);

        let mut s = connection();
        for _ in 0..101 {
            let mut stream = response(&mut s);
            data(&s, &stream, 0, true).unwrap();
            assert!(matches!(stream.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
        }
        assert_eq!(&state(&s)[..3], &[32767, 32767, 0]);
    });
}

#[test]
fn guard_observation_poll_and_drop_return_real_queue_credit() {
    observed(|| {
        let mut s = connection();
        let mut stream = response(&mut s);
        data(&s, &stream, 1, false).unwrap();
        assert_eq!(state(&s)[1], 32512);
        assert!(matches!(stream.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
        assert_eq!(state(&s)[1], 32767);
        data(&s, &stream, 2, false).unwrap();
        assert_eq!(state(&s)[1], 32513);
        drop(stream); // real OpaqueStreamRef::drop -> release_closed_capacity
        assert_eq!(state(&s)[1], 32767);
        let me = s.inner.lock().unwrap();
        let observation = me.counts.observation.as_ref().unwrap();
        assert_eq!(&observation.counters[11..], &[1, 1, 509]);
    });
}

#[test]
fn guard_observation_released_and_reset_frames_are_charged_but_not_queued() {
    observed(|| {
        let mut s = connection();
        let mut stream = response(&mut s);
        stream.opaque.clear_recv_buffer();
        data(&s, &stream, 1, false).unwrap();
        assert_eq!(state(&s)[1], 32512);
        assert_eq!(s.inner.lock().unwrap().counts.observation.as_ref().unwrap().disposition, 3);
        stream.send_reset(Reason::CANCEL);
        data(&s, &stream, 1, false).unwrap();
        assert_eq!(state(&s)[1], 32257);
        assert_eq!(s.inner.lock().unwrap().counts.observation.as_ref().unwrap().disposition, 2);
    });
}

#[test]
fn guard_observation_window_growth_retains_guard_and_large_frames_replenish() {
    observed(|| {
        let mut s = connection();
        s.set_target_connection_window_size(65535).unwrap();
        let stream = response(&mut s);
        data(&s, &stream, 1, false).unwrap();
        data(&s, &stream, 512, false).unwrap();
        assert_eq!(state(&s)[1], 32767);
        s.set_target_connection_window_size(33554432).unwrap();
        let mut settings = frame::Settings::default();
        settings.set_initial_window_size(Some(8388608));
        s.apply_local_settings(&settings).unwrap();
        assert_eq!(&state(&s)[..3], &[32767, 32767, 0]);
        for _ in 0..128 {
            data(&s, &stream, 1, false).unwrap();
        }
        guard_error(data(&s, &stream, 1, false).unwrap_err());
        let me = s.inner.lock().unwrap();
        let observation = me.counts.observation.as_ref().unwrap();
        assert_eq!(observation.initial_target, 65535);
        assert_eq!(observation.target, 33554432);
        assert_eq!(observation.target_updates, 2);
        assert_eq!(observation.stream_window, 8388608);
        assert_eq!(observation.branch, 1);
    });
}

#[test]
fn guard_observation_opt_in_and_bounded_suppression() {
    tracing::subscriber::with_default(tracing::subscriber::NoSubscriber::default(), || {
        assert!(connection().inner.lock().unwrap().counts.observation.is_none());
    });
    let limit = Limit::new(3);
    for id in 1..=3 {
        assert_eq!(limit.take(), Ok(id));
    }
    let mut notices = 0;
    for suppressed in 1u64..=10000 {
        assert_eq!(limit.take(), Err(suppressed));
        notices += usize::from(suppressed.is_power_of_two());
    }
    assert_eq!(limit.suppressed.load(Ordering::Relaxed), 10000);
    assert_eq!(notices, 14);
    let rows = observed(|| {
        let limit = Limit::new(0);
        for _ in 0..10000 {
            assert_eq!(admit(&limit, 3), None);
        }
    });
    assert_eq!(rows.len(), 14);
    assert!(rows.last().unwrap().contains("scope=3 suppressed=8192"));
    let rows = observed(|| {
        let mut s = connection();
        let mut stream = response(&mut s);
        for _ in 0..100 {
            data(&s, &stream, 256, false).unwrap();
            assert!(matches!(stream.opaque.poll_data(&Context::from_waker(&noop_waker())), Poll::Ready(Some(Ok(_)))));
            stream.opaque.release_capacity(256).unwrap();
        }
    });
    assert_eq!(rows.len(), 2); // initial and terminal, no per-frame records
}
