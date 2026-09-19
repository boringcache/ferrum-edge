use ferrum_edge::udp_profile::{self as profile, Direction, Operation, schema};

fn index(name: &str) -> usize {
    schema::NAMES
        .iter()
        .position(|value| *value == name)
        .unwrap()
}

fn delta(before: &[u64; schema::COUNTERS], name: &str) -> u64 {
    profile::current_thread_counters()[index(name)] - before[index(name)]
}

#[test]
fn nested_synchronous_timings_execute_once_and_sample_per_operation() {
    std::thread::spawn(|| {
        let before = profile::current_thread_counters();
        let mut calls = 0;
        for _ in 0..65 {
            profile::timed(Operation::PendingLookup, || {
                profile::timed(Operation::LastClientLookup, || calls += 1);
            });
        }
        assert_eq!(calls, 65);
        assert_eq!(delta(&before, "pending_lookup_calls"), 65);
        assert_eq!(delta(&before, "pending_lookup_time_samples"), 2);
        assert_eq!(delta(&before, "last_client_lookup_time_samples"), 2);
        let histogram: u64 = schema::NAMES
            .iter()
            .filter(|name| name.starts_with("pending_lookup_ns_"))
            .map(|name| delta(&before, name))
            .sum();
        assert_eq!(histogram, 2);
    })
    .join()
    .unwrap();
}

#[test]
fn partial_error_and_zero_batch_results_are_not_successful_slots() {
    let before = profile::current_thread_counters();
    profile::sendmmsg(Direction::Reply, 4, &Ok(2), 2048);
    profile::sendmmsg(Direction::Reply, 2, &Ok(0), 0);
    profile::sendmmsg(
        Direction::Reply,
        2,
        &Err(std::io::ErrorKind::WouldBlock.into()),
        0,
    );
    assert_eq!(delta(&before, "reply_tx_requested_slots"), 8);
    assert_eq!(delta(&before, "reply_tx_sent_slots"), 2);
    assert_eq!(delta(&before, "reply_tx_partial_calls"), 2);
    assert_eq!(delta(&before, "reply_tx_remaining_slots"), 4);
    assert_eq!(delta(&before, "reply_tx_error_slots"), 2);
    assert_eq!(delta(&before, "reply_tx_sent_slots_0"), 1);
    assert_eq!(delta(&before, "reply_tx_sent_bytes"), 2048);
    assert_eq!(delta(&before, "ingress_tx_calls"), 0);
    profile::gso(Direction::Reply, 4, 4096, 1024, &Ok(1));
    assert_eq!(delta(&before, "reply_gso_accepted_segments"), 0);
    assert_eq!(delta(&before, "reply_gso_short_bytes"), 1);
}

#[test]
fn pending_poll_can_migrate_without_carrying_thread_attribution() {
    use std::future::Future;
    use std::task::{Context, Poll, Waker};

    let mut polled = false;
    let future = std::future::poll_fn(move |_| {
        if polled {
            Poll::Ready(7)
        } else {
            polled = true;
            Poll::Pending
        }
    });
    let future = Box::pin(profile::observe_polls(future, false));
    let mut future = std::thread::spawn(move || {
        let before = profile::current_thread_counters();
        let mut future = future;
        assert!(
            future
                .as_mut()
                .poll(&mut Context::from_waker(Waker::noop()))
                .is_pending()
        );
        assert_eq!(delta(&before, "egress_poll_pending"), 1);
        assert_eq!(delta(&before, "egress_poll_ready"), 0);
        future
    })
    .join()
    .unwrap();
    let before = profile::current_thread_counters();
    assert_eq!(
        future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop())),
        Poll::Ready(7)
    );
    assert_eq!(delta(&before, "egress_poll_ready"), 1);
    assert_eq!(delta(&before, "egress_poll_pending"), 0);
}

#[tokio::test]
async fn borrowed_success_and_fifo_handoff_have_distinct_counters() {
    use ferrum_edge::_test_support::{UdpEgressAdmissionForTest, UdpEgressWriterProbe};

    let probe = UdpEgressWriterProbe::new().await.unwrap();
    let before = profile::current_thread_counters();
    assert_eq!(
        probe.forward_without_blocking(b"fast"),
        UdpEgressAdmissionForTest::Sent
    );
    assert_eq!(probe.backend_peer_recv().await.unwrap(), b"fast".to_vec());
    assert_eq!(delta(&before, "borrowed_send_success"), 1);
    assert_eq!(delta(&before, "borrowed_send_bytes"), 4);
    assert_eq!(delta(&before, "egress_queued"), 0);
    probe.park_backend_sends();
    assert_eq!(
        probe.hand_off_to_writer(b"first"),
        UdpEgressAdmissionForTest::Queued
    );
    assert_eq!(
        probe.forward_without_blocking(b"second"),
        UdpEgressAdmissionForTest::Queued
    );
    assert_eq!(delta(&before, "egress_queued"), 2);
    assert_eq!(delta(&before, "borrowed_send_success"), 1);
    assert_eq!(delta(&before, "egress_sent"), 0);
    probe.release_backend_sends();
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        while probe.committed_sends().len() != 2 {
            tokio::time::sleep(std::time::Duration::from_millis(1)).await;
        }
    })
    .await
    .expect("released writer must commit both queued datagrams");
    assert_eq!(
        probe.committed_sends(),
        vec![b"first".to_vec(), b"second".to_vec()]
    );
    assert_eq!(delta(&before, "egress_sent"), 2);
}

#[cfg(target_os = "linux")]
#[test]
fn real_mmsg_occupancy_errors_and_gso_fallback_preserve_payload_order() {
    use ferrum_edge::proxy::udp_batch::{
        GsoBatchBuf, RecvMmsgBatch, SendMmsgBatch, SendMmsgPushResult,
    };
    use std::net::UdpSocket;
    use std::os::fd::AsRawFd;

    let sender = UdpSocket::bind("127.0.0.1:0").unwrap();
    let receiver = UdpSocket::bind("127.0.0.1:0").unwrap();
    receiver.set_nonblocking(true).unwrap();
    let address = receiver.local_addr().unwrap();
    let before = profile::current_thread_counters();
    let mut tx = SendMmsgBatch::new(8);
    tx.profile_direction = Direction::Reply;
    assert_eq!(
        tx.push_with_local(b"", address, None),
        SendMmsgPushResult::Queued
    );
    assert_eq!(
        tx.push_with_local(b"ab", address, None),
        SendMmsgPushResult::Queued
    );
    let sent = tx.flush(sender.as_raw_fd()).unwrap();
    assert_eq!((sent.datagrams, sent.bytes), (2, 2));
    tx.flush(sender.as_raw_fd()).unwrap(); // Empty flush is not a syscall.
    let mut rx = RecvMmsgBatch::new(8, false);
    rx.profile_direction = Direction::Ingress;
    assert_eq!(rx.recv(receiver.as_raw_fd(), 5).unwrap(), 2);
    assert_eq!(rx.datagram(0).0, b"");
    assert_eq!(rx.datagram(1).0, b"ab");
    assert_eq!(
        rx.recv(receiver.as_raw_fd(), 5).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    assert_eq!(delta(&before, "ingress_rx_requested_slots"), 10);
    assert_eq!(delta(&before, "ingress_rx_returned_slots"), 2);
    assert_eq!(delta(&before, "ingress_rx_logical_packets"), 2);
    assert_eq!(delta(&before, "reply_tx_requested_slots"), 2);
    assert_eq!(delta(&before, "reply_tx_calls"), 1);

    // An IPv6 destination on this IPv4 fd fails only after the first slot sent.
    tx.push_with_local(b"ok", address, None);
    tx.push_with_local(b"bad", "[::1]:9".parse().unwrap(), None);
    assert_eq!(tx.flush(sender.as_raw_fd()).unwrap().datagrams, 1);
    assert_eq!(tx.pending_stats().datagrams, 1);
    assert_eq!(delta(&before, "reply_tx_partial_calls"), 1);
    assert!(tx.flush(sender.as_raw_fd()).is_err());
    assert!(tx.is_empty());
    assert_eq!(rx.recv(receiver.as_raw_fd(), 8).unwrap(), 1);
    assert_eq!(rx.datagram(0).0, b"ok");

    let mut gso = GsoBatchBuf::new(4096);
    gso.profile_direction = Direction::Reply;
    assert!(gso.push(b"aa"));
    assert!(gso.push(b"bb"));
    let socket_address = socket2::SockAddr::from(address);
    let mut dest: libc::sockaddr_storage = unsafe { std::mem::zeroed() };
    let length = socket_address.len();
    // SAFETY: SockAddr contains an initialized address of this bounded length.
    unsafe {
        std::ptr::copy_nonoverlapping(
            socket_address.as_ptr().cast::<u8>(),
            std::ptr::addr_of_mut!(dest).cast::<u8>(),
            length as usize,
        );
    }
    assert!(gso.flush_to(-1, &dest, length, None).is_err());
    assert!(!gso.is_empty());
    assert_eq!(gso.drain_to_sendmmsg(&mut tx, address, None), 2);
    assert_eq!(delta(&before, "reply_gso_errors"), 1);
    assert_eq!(delta(&before, "reply_gso_accepted_segments"), 0);
    assert_eq!(delta(&before, "reply_gso_fallback_to_mmsg_segments"), 2);
    assert_eq!(tx.flush(sender.as_raw_fd()).unwrap().datagrams, 2);
    assert_eq!(rx.recv(receiver.as_raw_fd(), 8).unwrap(), 2);
    assert_eq!(rx.datagram(0).0, b"aa");
    assert_eq!(rx.datagram(1).0, b"bb");
    tx.push_with_local(b"lost1", address, None);
    tx.push_with_local(b"lost2", address, None);
    assert!(tx.flush(-1).is_err());
    assert!(
        tx.is_empty(),
        "sendmmsg preserves its existing clear-on-error semantics"
    );
    assert_eq!(delta(&before, "reply_tx_error_slots"), 3);
    assert_eq!(delta(&before, "reply_tx_sent_slots"), 5);
}
