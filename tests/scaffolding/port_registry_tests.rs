//! Regression coverage for nextest's one-test-per-process port handoff.

use super::port_registry::{
    PortLease, PortRegistry, TestSocket, bind_tcp_listener, bind_udp_socket,
};
use std::collections::BTreeSet;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::{Arc, Barrier};
use std::time::{Duration, Instant};

// Synthetic candidates isolate the registry invariant from OS port availability.
// With the old bind/drop allocator both owners always select the first candidate.
fn lease(registry: &Arc<PortRegistry>) -> io::Result<PortLease> {
    registry
        .lease_with(41_000..=41_002, |port| Ok((port, ())))
        .map(|(lease, ())| lease)
}

#[test]
fn multi_port_allocation_is_distinct_and_exhaustion_is_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let registry = PortRegistry::new(directory.path()).unwrap();
    let leases: Vec<_> = (0..3).map(|_| lease(&registry).unwrap()).collect();
    let ports: BTreeSet<_> = leases.iter().map(|lease| lease.port).collect();
    assert_eq!(ports.len(), 3);
    assert_eq!(
        lease(&registry).err().unwrap().kind(),
        io::ErrorKind::AddrInUse
    );
}

#[test]
fn lease_is_released_on_drop() {
    let directory = tempfile::tempdir().unwrap();
    let first = PortRegistry::new(directory.path()).unwrap();
    let second = PortRegistry::new(directory.path()).unwrap();
    let held = lease(&first).unwrap();
    let port = held.port;
    let other = lease(&second).unwrap();
    assert_ne!(port, other.port);
    drop(held);
    assert_eq!(lease(&second).unwrap().port, port);
}

#[test]
fn allocator_offsets_wrap_the_filtered_range_from_distinct_starts() {
    let directory = tempfile::tempdir().unwrap();
    let first = PortRegistry::with_candidate_offset(directory.path().join("first"), 1).unwrap();
    let second = PortRegistry::with_candidate_offset(directory.path().join("second"), 2).unwrap();
    let candidates = [10_240, 32_768, 60_999, 61_000, 61_001]
        .into_iter()
        .filter(|port| !(32_768..=60_999).contains(port));
    assert_eq!(
        first.candidates(candidates.clone()).collect::<Vec<_>>(),
        [61_000, 61_001, 10_240]
    );
    assert_eq!(
        second.candidates(candidates.clone()).collect::<Vec<_>>(),
        [61_001, 10_240, 61_000]
    );
    // Separate tables ensure registry contention cannot make this pass when
    // both instances accidentally start at the lowest candidate.
    let (first_port, ()) = first
        .lease_with(first.candidates(candidates.clone()), |port| Ok((port, ())))
        .unwrap();
    let (second_port, ()) = second
        .lease_with(second.candidates(candidates), |port| Ok((port, ())))
        .unwrap();
    assert_ne!(first_port.port, second_port.port);
    assert_eq!(first.candidates(std::iter::empty()).next(), None);
}

#[test]
fn allocator_skips_a_held_exclusive_socket_without_a_registry_entry() {
    let held = super::ports::reserve_refused_tcp_port().unwrap();
    let directory = tempfile::tempdir().unwrap();
    let registry = PortRegistry::new(directory.path()).unwrap();
    let mut attempted = Vec::new();
    let (lease, listener) = registry
        .lease_with([held.port, 0], |port| {
            attempted.push(port);
            let listener = bind_tcp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
            Ok((listener.local_addr()?.port(), listener))
        })
        .unwrap();
    assert_eq!(attempted, [held.port, 0]);
    assert_ne!(lease.port, held.port);
    assert_eq!(lease.port, listener.local_addr().unwrap().port());
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn allocator_skips_time_wait_that_a_reuse_address_bind_would_accept() {
    use std::io::Read;
    use std::net::{Shutdown, TcpListener, TcpStream};

    let listener = super::ports::reserve_port()
        .await
        .unwrap()
        .into_listener()
        .into_std()
        .unwrap();
    listener.set_nonblocking(false).unwrap();
    // Model the old reservation / a reuse-enabled server. The accepted socket
    // inherits this option; an ordinary std listener can later reuse its port.
    socket2::SockRef::from(&listener)
        .set_reuse_address(true)
        .unwrap();
    let addr = listener.local_addr().unwrap();
    let mut client = TcpStream::connect(addr).unwrap();
    let (mut server, _) = listener.accept().unwrap();
    client
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    server
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    // The server actively closes and the client observes FIN before replying,
    // so TIME_WAIT belongs to the listener's port. No timing sleeps are needed.
    server.shutdown(Shutdown::Write).unwrap();
    assert_eq!(client.read(&mut [0]).unwrap(), 0);
    client.shutdown(Shutdown::Write).unwrap();
    assert_eq!(server.read(&mut [0]).unwrap(), 0);
    drop(server);
    drop(client);
    drop(listener);

    let reusable = TcpListener::bind(addr).expect("old SO_REUSEADDR probe accepts TIME_WAIT");
    drop(reusable);
    assert_eq!(
        bind_tcp_listener(addr).unwrap_err().kind(),
        io::ErrorKind::AddrInUse
    );
    // Use an independent table so the kernel, rather than the retained process
    // lease, rejects the first candidate. Port zero is only a test fallback.
    let directory = tempfile::tempdir().unwrap();
    let registry = PortRegistry::new(directory.path()).unwrap();
    let mut attempted = Vec::new();
    let (lease, _listener) = registry
        .lease_with([addr.port(), 0], |port| {
            attempted.push(port);
            let listener = bind_tcp_listener(SocketAddr::from((Ipv4Addr::LOCALHOST, port)))?;
            Ok((listener.local_addr()?.port(), listener))
        })
        .unwrap();
    assert_eq!(attempted, [addr.port(), 0]);
    assert_ne!(lease.port, addr.port());
}

#[tokio::test]
async fn tcp_reservations_and_native_listeners_disable_address_reuse() {
    use super::ports;

    let (first, second) = ports::reserve_port_pair().await.unwrap();
    let (tcp, _udp) = ports::reserve_colocated_tcp_udp().await.unwrap();
    for reservation in [
        ports::reserve_port().await.unwrap(),
        ports::reserve_port_in_range(10_240..u16::MAX).unwrap(),
        first,
        second,
        tcp,
    ] {
        let listener = reservation.into_listener().into_std().unwrap();
        assert!(!socket2::SockRef::from(&listener).reuse_address().unwrap());
    }
    let native = std::net::TcpListener::bind_test((Ipv4Addr::LOCALHOST, 0)).unwrap();
    assert!(!socket2::SockRef::from(&native).reuse_address().unwrap());
    let native = tokio::net::TcpListener::bind_test((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap()
        .into_std()
        .unwrap();
    assert!(!socket2::SockRef::from(&native).reuse_address().unwrap());
    let socket = tokio::net::TcpSocket::bind_test((Ipv4Addr::LOCALHOST, 0)).unwrap();
    assert!(!socket.reuseaddr().unwrap());
}

#[tokio::test]
async fn udp_reservations_and_native_sockets_disable_address_reuse() {
    use super::ports;

    let (_tcp, udp) = ports::reserve_colocated_tcp_udp().await.unwrap();
    for reservation in [ports::reserve_udp_port().await.unwrap(), udp] {
        let socket = reservation.into_socket().into_std().unwrap();
        assert!(!socket2::SockRef::from(&socket).reuse_address().unwrap());
        let peer = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )
        .unwrap();
        peer.set_reuse_address(true).unwrap();
        assert_eq!(
            peer.bind(&socket.local_addr().unwrap().into())
                .unwrap_err()
                .kind(),
            io::ErrorKind::AddrInUse,
            "a reuse-enabled peer must not share an exclusive UDP reservation"
        );
    }
    let native = std::net::UdpSocket::bind_test((Ipv4Addr::LOCALHOST, 0)).unwrap();
    assert!(!socket2::SockRef::from(&native).reuse_address().unwrap());
    let native = tokio::net::UdpSocket::bind_test((Ipv4Addr::LOCALHOST, 0))
        .await
        .unwrap()
        .into_std()
        .unwrap();
    assert!(!socket2::SockRef::from(&native).reuse_address().unwrap());
}

#[tokio::test]
async fn udp_handoff_excludes_racing_owners_after_socket_release() {
    // The process lease keeps unrelated tests away from this real port while
    // isolated owners race for the same candidate in their own registry.
    let port = super::ports::unbound_udp_port().await.unwrap();
    assert_eq!(
        super::port_registry::process_registry()
            .unwrap()
            .lease_with([port], |port| Ok((port, ())))
            .err()
            .expect("the public UDP handoff must retain its process lease")
            .kind(),
        io::ErrorKind::AddrInUse
    );
    let directory = tempfile::tempdir().unwrap();
    let owners = [
        PortRegistry::new(directory.path()).unwrap(),
        PortRegistry::new(directory.path()).unwrap(),
    ];
    let barrier = Arc::new(Barrier::new(2));
    let racers = owners.each_ref().map(|owner| {
        let owner = Arc::clone(owner);
        let barrier = Arc::clone(&barrier);
        std::thread::spawn(move || {
            barrier.wait();
            owner
                .lease_with([port], |port| {
                    let socket = bind_udp_socket((Ipv4Addr::LOCALHOST, port).into())?;
                    Ok((port, socket))
                })
                .map(|(lease, socket)| {
                    // Model the handoff: close the socket before returning, but
                    // keep the lease while the child has yet to bind.
                    lease.retain_for_process();
                    drop(socket);
                })
        })
    });
    let results = racers.map(|racer| racer.join().unwrap());
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    for error in results.iter().filter_map(|result| result.as_ref().err()) {
        assert_eq!(error.kind(), io::ErrorKind::AddrInUse);
    }
    let contender = PortRegistry::new(directory.path()).unwrap();
    let try_handoff = || {
        contender.lease_with([port], |port| {
            let socket = bind_udp_socket((Ipv4Addr::LOCALHOST, port).into())?;
            Ok((port, socket))
        })
    };
    // Both racing calls have returned and dropped their socket and PortLease.
    // This assertion deterministically catches releasing the lease too early,
    // even if the losing racer previously saw the winner's still-bound socket.
    assert_eq!(
        try_handoff().err().unwrap().kind(),
        io::ErrorKind::AddrInUse
    );
    let child_socket = bind_udp_socket(([0, 0, 0, 0], port).into()).unwrap();
    assert!(try_handoff().is_err());
    drop(child_socket);
    assert!(try_handoff().is_err(), "lease outlives the child socket");
    drop(owners);
    let (lease, _socket) = try_handoff().expect("reclaim only after the lease owners exit");
    assert_eq!(lease.port, port);
}

struct RegistryChild(Child);

impl Drop for RegistryChild {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn cross_process_leases_survive_handoff_and_reclaim_after_exit() {
    let directory = tempfile::tempdir().unwrap();
    let registry = PortRegistry::new(directory.path()).unwrap();
    let first = lease(&registry).unwrap();
    let second = lease(&registry).unwrap();
    assert_eq!((first.port, second.port), (41_000, 41_001));

    let mut child = RegistryChild(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scaffolding::port_registry_tests::port_registry_child",
                "--nocapture",
            ])
            .env("TEST_PORT_REGISTRY_CHILD", directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::inherit())
            .spawn()
            .expect("spawn independent test allocator"),
    );
    let deadline = Instant::now() + Duration::from_secs(15);
    let ready = directory.path().join("ready");
    while !ready.exists() {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "allocator child exited early"
        );
        assert!(
            Instant::now() < deadline,
            "allocator child did not report its lease"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(std::fs::read_to_string(ready).unwrap(), "41002");
    assert!(
        lease(&registry).is_err(),
        "child's unbound port must remain leased"
    );

    std::fs::write(directory.path().join("exit"), b"exit without destructors").unwrap();
    loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            assert!(status.success(), "allocator child failed: {status}");
            break;
        }
        assert!(Instant::now() < deadline, "allocator child did not exit");
        std::thread::sleep(Duration::from_millis(10));
    }
    assert_eq!(
        lease(&registry).unwrap().port,
        41_002,
        "reclaim dead owner's lease"
    );
}

#[test]
fn port_registry_child() {
    let Some(root) = std::env::var_os("TEST_PORT_REGISTRY_CHILD") else {
        return;
    };
    let root = std::path::PathBuf::from(root);
    let registry = PortRegistry::new(&root).unwrap();
    let held = lease(&registry).unwrap();
    assert_eq!(
        held.port, 41_002,
        "must skip both ports held by the other process"
    );
    let port = held.retain_for_process();
    drop(held);
    std::fs::write(root.join("ready.tmp"), port.to_string()).unwrap();
    std::fs::rename(root.join("ready.tmp"), root.join("ready")).unwrap();
    let deadline = Instant::now() + Duration::from_secs(15);
    while !root.join("exit").exists() {
        assert!(
            Instant::now() < deadline,
            "parent did not release allocator child"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
    // Model nextest termination: no Rust destructors, but the kernel releases
    // the owner lock. The surviving allocator must reclaim the retained lease.
    std::process::exit(0);
}

#[tokio::test]
async fn socket_handoff_and_wildcard_listener_share_the_registry() {
    let reservation = super::ports::reserve_port().await.unwrap();
    let port = reservation.drop_and_take_port();
    let wildcard = tokio::net::TcpListener::bind_test(("0.0.0.0", port))
        .await
        .unwrap();
    let udp = super::ports::reserve_udp_port().await.unwrap();
    assert_ne!(
        udp.port, port,
        "TCP and UDP allocations share the lease namespace"
    );
    drop(wildcard);
    let next = super::ports::unbound_port().await.unwrap();
    assert_ne!(
        next, port,
        "dropping a native listener must preserve the handoff lease"
    );
}

#[cfg(target_os = "linux")]
#[tokio::test]
async fn every_subprocess_handoff_avoids_the_linux_source_port_range() {
    use super::ports;
    use crate::common::gateway_harness;
    use std::collections::HashSet;

    // Read the kernel independently of the allocator so returning bind(:0)
    // ports, or hard-coding the default on a tuned runner, breaks this test.
    let raw = match std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") {
        Ok(raw) => raw,
        Err(error) if error.kind() == io::ErrorKind::NotFound => "32768 60999".to_string(),
        Err(error) => panic!("read ephemeral range: {error}"),
    };
    let bounds: Vec<u16> = raw.split_whitespace().map(|s| s.parse().unwrap()).collect();
    assert_eq!(bounds.len(), 2);
    let ephemeral = bounds[0]..=bounds[1];
    let (tcp, udp) = ports::reserve_colocated_tcp_udp().await.unwrap();
    let colocated = tcp.drop_and_take_port();
    assert_eq!(udp.drop_and_take_port(), colocated);
    let (first, second) = ports::reserve_port_pair().await.unwrap();
    let mut excluded = HashSet::new();
    let held = gateway_harness::hold_ephemeral_port_excluding(&mut excluded)
        .await
        .unwrap();
    let cases = [
        ("sync TCP", ports::unbound_tcp_port().unwrap()),
        ("async TCP", ports::unbound_port().await.unwrap()),
        ("async UDP", ports::unbound_udp_port().await.unwrap()),
        (
            "bounded TCP reservation",
            ports::reserve_port_in_range(10_240..u16::MAX)
                .unwrap()
                .drop_and_take_port(),
        ),
        (
            "mesh namespace handoff",
            super::port_registry::unbound_port_outside(ephemeral.clone()).unwrap(),
        ),
        (
            "TCP reservation",
            ports::reserve_port().await.unwrap().drop_and_take_port(),
        ),
        (
            "UDP reservation",
            ports::reserve_udp_port()
                .await
                .unwrap()
                .drop_and_take_port(),
        ),
        ("colocated TCP/UDP", colocated),
        ("pair first", first.drop_and_take_port()),
        ("pair second", second.drop_and_take_port()),
        (
            "future listener",
            ports::reserve_future_tcp_port()
                .unwrap()
                .drop_and_take_port(),
        ),
        (
            "generic spawner",
            gateway_harness::ephemeral_port().await.unwrap(),
        ),
        ("held generic spawner", held.port),
        (
            "excluding generic spawner",
            gateway_harness::ephemeral_port_excluding(&mut excluded)
                .await
                .unwrap(),
        ),
    ];
    let mut distinct = BTreeSet::new();
    for (name, port) in cases {
        assert!(port >= 10_240, "{name}: avoid well-known/service ports");
        assert!(
            !ephemeral.contains(&port),
            "{name}: {port} is in {ephemeral:?}"
        );
        assert!(distinct.insert(port), "{name}: handoff lease was lost");
    }
    if bounds[0] < bounds[1] {
        assert!(ports::reserve_port_in_range(bounds[0]..bounds[1]).is_err());
    }
}

#[test]
fn functional_and_integration_sockets_use_the_registry() {
    fn inspect(directory: &Path) {
        for entry in std::fs::read_dir(directory).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                inspect(&path);
            } else if path.extension().is_some_and(|extension| extension == "rs") {
                let source = std::fs::read_to_string(&path).unwrap();
                for constructor in ["TcpListener", "UdpSocket", "TcpSocket", "DtlsServer"] {
                    for method in ["bind", "bind_with_limits"] {
                        let bypass = format!("{constructor}::{method}(");
                        assert!(
                            !source.contains(&bypass),
                            "{} bypasses the shared port registry with {bypass}",
                            path.display()
                        );
                    }
                }
                assert!(
                    !uses_literal_socket_port(&source),
                    "{} uses a literal socket port instead of a registry lease",
                    path.display()
                );
            }
        }
    }
    let tests = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests");
    inspect(&tests.join("functional"));
    inspect(&tests.join("integration"));
}

/// Catch fixed ports even when a fixture uses the registry's socket API.
/// Config-only examples are allowed; a matching bind/connect is not.
fn uses_literal_socket_port(source: &str) -> bool {
    use regex::{Regex, RegexSet};
    use std::sync::LazyLock;

    static DIRECT: LazyLock<RegexSet> = LazyLock::new(|| {
        RegexSet::new([
            r"\bbind_test\s*\(\s*[1-9][0-9_]*",
            r#"\bbind_test\s*\(\s*(?:format!\s*\(\s*)?"[^"\n]*:[1-9][0-9_]*""#,
            r#"\bbind_test\s*\(\s*\(\s*[^,\n]+,\s*[1-9][0-9_]*\b"#,
            r#"\bbind_test\s*\(\s*format!\s*\(\s*"[^"\n]*"\s*,\s*[1-9][0-9_]*"#,
            r"\bstart_\w*server(?:_on)?\s*\(\s*[1-9][0-9_]*",
        ])
        .unwrap()
    });
    static CONFIG: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r#"(?m)^\s*"?(?:port|backend_port|listen_port)"?\s*:\s*([0-9_]+)"#).unwrap()
    });
    static CALL: LazyLock<Regex> = LazyLock::new(|| {
        Regex::new(r"(?s)\b(?:bind_test|connect|start_\w*server(?:_on)?)\s*\(([^;]*?)\)").unwrap()
    });
    static NUMBER: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"\b[1-9][0-9_]{3,}(?:u16)?\b").unwrap());

    if DIRECT.is_match(source) {
        return true;
    }
    let config_ports: BTreeSet<u16> = CONFIG
        .captures_iter(source)
        .filter_map(|capture| capture[1].replace('_', "").parse().ok())
        .filter(|port| *port >= 1000)
        .collect();
    CALL.captures_iter(source).any(|call| {
        NUMBER.find_iter(&call[1]).any(|number| {
            number
                .as_str()
                .trim_end_matches("u16")
                .replace('_', "")
                .parse::<u16>()
                .is_ok_and(|port| config_ports.contains(&port))
        })
    })
}

#[test]
fn literal_socket_port_guard_rejects_fixed_bind_and_config_handoffs() {
    for source in [
        r#"TcpListener::bind_test("127.0.0.1:30031").await;"#,
        r#"TcpListener::bind_test("[::1]:30031").await;"#,
        r#"UdpSocket::bind_test(("127.0.0.1", 30_031)).await;"#,
        "TcpSocket::bind_test(30031);",
        "start_identifying_server(\n    30031,\n    \"healthy-server\",\n);",
        "start_status_server(30032, \"unhealthy-server\", 500);",
        "start_echo_server_on(8080);",
        r#"TcpListener::bind_test(format!("127.0.0.1:{}", 30031)).await;"#,
        "backend_port: 30031\nTcpStream::connect((\"127.0.0.1\", 30031)).await;",
        "listen_port: 30_031\nTcpStream::connect(\"127.0.0.1:30031\").await;",
        "port: 30031\nTcpStream::connect(\n    format!(\"127.0.0.1:{}\", 30031),\n).await;",
    ] {
        assert!(
            uses_literal_socket_port(source),
            "missed fixed port: {source}"
        );
    }
}

#[test]
fn literal_socket_port_guard_allows_leases_and_config_only_examples() {
    for source in [
        r#"TcpListener::bind_test("127.0.0.1:0").await;"#,
        r#"TcpListener::bind_test("[::1]:0").await;"#,
        r#"UdpSocket::bind_test(("127.0.0.1", 0)).await;"#,
        r#"UdpSocket::bind_test(("::1", 0)).await;"#,
        r#"TcpListener::bind_test(format!("127.0.0.1:{port}")).await;"#,
        "start_identifying_server(listener, \"healthy-server\");",
        "start_status_server(listener, \"unhealthy-server\", 500);",
        "backend_port: 30031\nlisten_port: 40123\nport: 8080",
        "backend_port: 30031\nTcpStream::connect((\"127.0.0.1\", port)).await;",
        r#"TcpStream::connect("127.0.0.1:6379").await;"#,
    ] {
        assert!(
            !uses_literal_socket_port(source),
            "rejected safe source: {source}"
        );
    }
}
