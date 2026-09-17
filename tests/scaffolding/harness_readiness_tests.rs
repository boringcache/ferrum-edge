//! Spawned-listener readiness must wait for stream binds without sending UDP traffic.

use super::harness::{StreamListener, wait_for_spawned_gateway};
use super::port_registry::TestSocket;
use super::ports::{reserve_port, unbound_port, unbound_udp_port};
use crate::common::GatewayChildGuard;
use std::io::{self, Read, Write};
use std::process::{Command, Stdio};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::time::timeout;

fn readiness_child() -> GatewayChildGuard {
    GatewayChildGuard::spawn(
        Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "scaffolding::harness_readiness_tests::hold_readiness_child",
                "--nocapture",
            ])
            .env("TEST_GATEWAY_READINESS_CHILD", "1")
            .env("FERRUM_ADMIN_HTTP_PORT", "0")
            .env("FERRUM_ADMIN_JWT_SECRET", "readiness-fixture-secret")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::null()),
    )
    .expect("spawn readiness fixture child")
}

#[test]
fn hold_readiness_child() {
    if std::env::var_os("TEST_GATEWAY_READINESS_CHILD").is_some() {
        // The parent owns the pipe; closing it lets the child exit during a probe.
        let _ = std::io::stdin().read_exact(&mut [0]);
        // Exceed a pipe buffer and the diagnostic budget. File-backed capture
        // must let the child exit and retain the tail of BOTH output streams.
        let padding = vec![b'x'; 128 * 1024];
        for mut output in [
            Box::new(std::io::stdout()) as Box<dyn Write>,
            Box::new(std::io::stderr()) as Box<dyn Write>,
        ] {
            output.write_all(&padding).unwrap();
            writeln!(output, "\nstartup failed: Address already in use").unwrap();
            writeln!(output, "readiness-fixture-secret").unwrap();
        }
        std::process::exit(1);
    }
}

#[tokio::test]
async fn http_accept_does_not_admit_unbound_udp_and_probe_sends_no_datagrams() {
    let mut child = readiness_child();
    let http = reserve_port().await.unwrap();
    let udp_port = unbound_udp_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        &mut child,
        http.port,
        Some(StreamListener::Udp(udp_port)),
    ));
    assert!(
        timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err(),
        "HTTP acceptance must not make an unbound UDP listener ready"
    );

    // A pending probe must release its socket so the intended listener can bind.
    let udp = std::net::UdpSocket::bind_test(("127.0.0.1", udp_port)).unwrap();
    timeout(Duration::from_secs(5), ready)
        .await
        .expect("UDP bind must release readiness wait")
        .unwrap();
    udp.set_nonblocking(true).unwrap();
    assert_eq!(
        udp.recv_from(&mut [0; 1]).unwrap_err().kind(),
        io::ErrorKind::WouldBlock,
        "readiness must not send even an empty UDP datagram"
    );
}

#[tokio::test]
async fn http_accept_does_not_admit_unbound_tcp_stream() {
    let mut child = readiness_child();
    let http = reserve_port().await.unwrap();
    let tcp_port = unbound_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        &mut child,
        http.port,
        Some(StreamListener::Tcp(tcp_port)),
    ));
    assert!(
        timeout(Duration::from_millis(100), &mut ready)
            .await
            .is_err(),
        "HTTP acceptance must not make an unbound TCP stream listener ready"
    );

    let tcp = tokio::net::TcpListener::bind_test(("127.0.0.1", tcp_port))
        .await
        .unwrap();
    timeout(Duration::from_secs(5), ready)
        .await
        .expect("TCP bind must release readiness wait")
        .unwrap();
    let (mut stream, _) = tcp.accept().await.unwrap();
    assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
}

#[tokio::test]
async fn exited_child_fails_before_http_probe() {
    let mut child = readiness_child();
    child.child_mut().kill().unwrap();
    child.child_mut().wait().unwrap();
    let http_port = unbound_port().await.unwrap();
    let error = timeout(
        Duration::from_secs(1),
        wait_for_spawned_gateway(&mut child, http_port, None),
    )
    .await
    .expect("an exited child must not consume the readiness timeout")
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("exited with"), "{message}");
    assert!(message.contains("HTTP listener"), "{message}");
    assert!(message.contains(&http_port.to_string()), "{message}");
}

#[tokio::test]
async fn exited_child_reports_both_output_tails_and_all_listener_ports() {
    let mut child = readiness_child();
    drop(child.child_mut().stdin.take());
    let http_port = unbound_port().await.unwrap();
    let udp_port = unbound_udp_port().await.unwrap();
    let error = timeout(
        Duration::from_secs(5),
        wait_for_spawned_gateway(&mut child, http_port, Some(StreamListener::Udp(udp_port))),
    )
    .await
    .expect("child output must not block exit or readiness")
    .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("exited with"), "{message}");
    assert!(message.contains("gateway stderr tail"), "{message}");
    assert!(message.contains("gateway stdout tail"), "{message}");
    assert_eq!(
        message
            .matches("startup failed: Address already in use")
            .count(),
        2
    );
    assert!(message.contains(&http_port.to_string()), "{message}");
    assert!(message.contains(&udp_port.to_string()), "{message}");
    assert!(message.contains("FERRUM_ADMIN_HTTP_PORT"), "{message}");
    assert!(!message.contains("readiness-fixture-secret"));
    assert!(message.len() < 34 * 1024, "diagnostics must be bounded");
}

#[tokio::test]
async fn child_exit_during_udp_wait_reports_stream_stage() {
    let mut child = readiness_child();
    let release = child.child_mut().stdin.take().unwrap();
    let http = reserve_port().await.unwrap();
    let http_port = http.port;
    let http = http.into_listener();
    let udp_port = unbound_udp_port().await.unwrap();
    let mut ready = Box::pin(wait_for_spawned_gateway(
        &mut child,
        http_port,
        Some(StreamListener::Udp(udp_port)),
    ));
    // Wait for the helper to close its successful HTTP probe before killing the
    // child, so the stage assertion does not depend on scheduler timing.
    timeout(Duration::from_secs(5), async {
        tokio::select! {
            result = &mut ready => panic!("unbound UDP listener was admitted: {result:?}"),
            () = async {
                let (mut stream, _) = http.accept().await.unwrap();
                assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
            } => {}
        }
    })
    .await
    .expect("HTTP probe must complete before child exits");
    drop(release);
    let error = timeout(Duration::from_secs(5), ready)
        .await
        .expect("child exit must not consume the readiness timeout")
        .unwrap_err();
    let message = error.to_string();
    assert!(message.contains("exited with"), "{message}");
    assert!(message.contains("UDP stream listener"), "{message}");
    assert!(message.contains(&udp_port.to_string()), "{message}");
}
