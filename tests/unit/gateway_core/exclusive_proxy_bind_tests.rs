//! Exclusive TCP proxy-port bind (issue #3924).
//!
//! Production accept workers share one listen socket via duplicated fds and
//! never set `SO_REUSEPORT`. These tests prove a foreign/independent second
//! bind is rejected while configured workers still share that listener, and
//! that dropping every clone releases the port for reload/shutdown rebind.

use std::io::ErrorKind;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use ferrum_edge::_test_support::{
    bind_exclusive_proxy_accept_listeners_for_test, try_foreign_reuseport_tcp_bind_for_test,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const BACKLOG: i32 = 128;

fn ipv4_ephemeral() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0)
}

fn is_addr_in_use(err: &std::io::Error) -> bool {
    err.kind() == ErrorKind::AddrInUse
        || err.to_string().to_ascii_lowercase().contains("in use")
}

fn assert_foreign_bind_rejected(addr: SocketAddr, what: &str) {
    match try_foreign_reuseport_tcp_bind_for_test(addr) {
        Ok(stolen) => {
            drop(stolen);
            panic!(
                "{what}: SO_REUSEPORT foreign bind succeeded on {addr}; exclusive listen socket \
                 must not be joinable by another process"
            );
        }
        Err(err) => assert!(
            is_addr_in_use(&err),
            "{what}: expected EADDRINUSE for SO_REUSEPORT foreign bind on {addr}, got {err}"
        ),
    }

    match std::net::TcpListener::bind(addr) {
        Ok(stolen) => {
            drop(stolen);
            panic!(
                "{what}: SO_REUSEADDR-only foreign bind succeeded on {addr}; the first process \
                 must keep exclusive ownership"
            );
        }
        Err(err) => assert!(
            is_addr_in_use(&err),
            "{what}: expected EADDRINUSE for SO_REUSEADDR foreign bind on {addr}, got {err}"
        ),
    }
}

#[tokio::test]
async fn foreign_bind_is_rejected_while_exclusive_listener_holds_the_port() {
    let listeners = bind_exclusive_proxy_accept_listeners_for_test(ipv4_ephemeral(), BACKLOG, 1)
        .expect("exclusive bind");
    let addr = listeners[0].local_addr().expect("local addr");
    assert_ne!(addr.port(), 0, "ephemeral bind must assign a concrete port");

    assert_foreign_bind_rejected(addr, "single exclusive listener");

    let connect = TcpStream::connect(addr);
    let accept = listeners.into_iter().next().expect("listener").accept();
    let (client, accepted) = tokio::join!(connect, accept);
    let mut client = client.expect("first process must still accept after rejected foreign bind");
    let (mut server, _) = accepted.expect("accept");
    client.write_all(b"ok").await.expect("client write");
    let mut buf = [0u8; 2];
    server.read_exact(&mut buf).await.expect("server read");
    assert_eq!(&buf, b"ok");
}

#[tokio::test]
async fn cloned_accept_workers_share_one_listener_and_reject_a_foreign_bind() {
    let mut listeners =
        bind_exclusive_proxy_accept_listeners_for_test(ipv4_ephemeral(), BACKLOG, 3)
            .expect("exclusive bind with three accept workers");
    assert_eq!(
        listeners.len(),
        3,
        "configured accept workers must all be created"
    );

    let addr = listeners[0].local_addr().expect("local addr");
    for (index, listener) in listeners.iter().enumerate() {
        assert_eq!(
            listener.local_addr().expect("clone local addr"),
            addr,
            "accept worker {index} must share the authoritative bound address"
        );
    }

    assert_foreign_bind_rejected(addr, "three cloned accept workers");

    let worker_a = listeners.remove(0);
    let worker_b = listeners.remove(0);
    let worker_c = listeners.remove(0);

    let accept_a = tokio::spawn(async move { worker_a.accept().await });
    let accept_b = tokio::spawn(async move { worker_b.accept().await });
    let accept_c = tokio::spawn(async move { worker_c.accept().await });

    let mut clients = Vec::with_capacity(3);
    for _ in 0..3 {
        clients.push(
            TcpStream::connect(addr)
                .await
                .expect("connect through shared exclusive listener"),
        );
    }

    let accepted = tokio::time::timeout(Duration::from_secs(2), async {
        (
            accept_a.await.expect("join worker a").expect("accept a"),
            accept_b.await.expect("join worker b").expect("accept b"),
            accept_c.await.expect("join worker c").expect("accept c"),
        )
    })
    .await
    .expect("every cloned accept worker must complete");
    drop(accepted);
    drop(clients);
}

#[tokio::test]
async fn dropping_clones_releases_the_port_for_reload_and_partial_hold_stays_exclusive() {
    let listeners = bind_exclusive_proxy_accept_listeners_for_test(ipv4_ephemeral(), BACKLOG, 3)
        .expect("exclusive bind");
    let addr = listeners[0].local_addr().expect("local addr");
    assert_foreign_bind_rejected(addr, "before shutdown");

    drop(listeners);

    let mut rebound = bind_exclusive_proxy_accept_listeners_for_test(addr, BACKLOG, 2)
        .expect("rebind after dropping every accept fd must succeed (reload/shutdown)");
    assert_eq!(rebound[0].local_addr().expect("rebound addr"), addr);
    assert_foreign_bind_rejected(addr, "after reload rebind");

    let held = rebound.pop().expect("keep one clone");
    drop(rebound);
    assert_foreign_bind_rejected(
        addr,
        "dropping extra clones must not release the port while one worker still holds it",
    );
    drop(held);

    bind_exclusive_proxy_accept_listeners_for_test(addr, BACKLOG, 1)
        .expect("rebind after the last accept fd is dropped");
}

#[tokio::test]
async fn port_zero_assigns_an_ephemeral_port_held_exclusively_by_clones() {
    let listeners = bind_exclusive_proxy_accept_listeners_for_test(ipv4_ephemeral(), BACKLOG, 2)
        .expect("ephemeral exclusive bind");
    let assigned = listeners[0].local_addr().expect("assigned addr");
    assert_ne!(assigned.port(), 0);
    assert_eq!(listeners[1].local_addr().expect("clone addr"), assigned);
    assert_foreign_bind_rejected(assigned, "assigned ephemeral port");

    let other = bind_exclusive_proxy_accept_listeners_for_test(ipv4_ephemeral(), BACKLOG, 1)
        .expect("a distinct port-0 bind must receive a different ephemeral port");
    let other_addr = other[0].local_addr().expect("other addr");
    assert_ne!(other_addr.port(), assigned.port());
}

#[tokio::test]
async fn ipv6_exclusive_bind_rejects_a_foreign_listener() {
    let addr = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0);
    let listeners = match bind_exclusive_proxy_accept_listeners_for_test(addr, BACKLOG, 2) {
        Ok(listeners) => listeners,
        Err(err) => {
            let msg = err.to_string();
            if msg.contains("Cannot assign requested address")
                || msg.contains("Address family not supported")
                || msg.contains("Can't assign requested address")
            {
                return;
            }
            panic!("IPv6 exclusive bind failed unexpectedly: {err}");
        }
    };
    let bound = listeners[0].local_addr().expect("ipv6 addr");
    assert!(bound.is_ipv6());
    assert_eq!(listeners[1].local_addr().expect("ipv6 clone"), bound);
    assert_foreign_bind_rejected(bound, "IPv6 exclusive listener");
}

#[tokio::test]
async fn second_exclusive_bind_error_names_the_address() {
    let first = bind_exclusive_proxy_accept_listeners_for_test(ipv4_ephemeral(), BACKLOG, 1)
        .expect("first bind");
    let addr = first[0].local_addr().expect("local addr");
    let err = bind_exclusive_proxy_accept_listeners_for_test(addr, BACKLOG, 1)
        .expect_err("second exclusive bind must fail clearly");
    let msg = err.to_string();
    assert!(
        msg.contains(&addr.to_string())
            || msg.contains("Address already in use")
            || msg.to_lowercase().contains("in use"),
        "bind failure must identify the collision; got {msg}"
    );
}
