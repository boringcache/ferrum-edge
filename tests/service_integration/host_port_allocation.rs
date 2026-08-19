//! Unit coverage for service-integration host-port allocation (#3999).
//!
//! These tests do not start Docker. They pin the allocator's range bounds,
//! exhaustion, and collision classification so a CI flake cannot be "fixed" by
//! blanket-retrying unrelated container errors.

use std::collections::HashSet;
use std::io;
use std::sync::atomic::{AtomicU32, Ordering};

use crate::common::host_ports::{
    HOST_PORT_COLLISION_ATTEMPTS, HostPortAllocError, allocate_host_port_with,
    is_host_port_collision, parse_ephemeral_port_range, retry_on_host_port_collision,
};

#[cfg(target_os = "linux")]
use crate::common::host_ports::allocate_host_port;

#[test]
fn parse_ephemeral_port_range_accepts_proc_sys_shape() {
    assert_eq!(
        parse_ephemeral_port_range("32768\t60999\n").expect("parse default Linux range"),
        (32768, 60999)
    );
}

#[test]
fn parse_ephemeral_port_range_rejects_empty_inverted_and_extra_fields() {
    assert!(parse_ephemeral_port_range("").is_err());
    assert!(parse_ephemeral_port_range("32768").is_err());
    assert!(parse_ephemeral_port_range("60999 32768").is_err());
    assert!(parse_ephemeral_port_range("32768 60999 1").is_err());
    assert!(parse_ephemeral_port_range("not-a-port 60999").is_err());
}

#[test]
fn allocate_skips_ephemeral_and_already_used_ports() {
    let mut used = HashSet::from([10, 11]);
    let mut probed = Vec::new();
    let port = allocate_host_port_with(20..=30, 10, 40, 10, &mut used, |candidate| {
        probed.push(candidate);
        Ok(())
    })
    .expect("allocate a non-ephemeral port");

    assert_eq!(port, 12);
    assert!(!(20..=30).contains(&port));
    assert!(used.contains(&12));
    assert_eq!(probed, vec![12]);
}

#[test]
fn allocate_wraps_probe_window_and_stays_outside_ephemeral_range() {
    let mut used = HashSet::new();
    let port = allocate_host_port_with(1..=15, 10, 20, 18, &mut used, |_| Ok(()))
        .expect("wrap past the end of the probe window");
    assert_eq!(port, 18);
    assert!(!(1..=15).contains(&port));

    let mut used = HashSet::from([18, 19, 20]);
    let port = allocate_host_port_with(1..=15, 10, 20, 18, &mut used, |_| Ok(()))
        .expect("wrap to first non-ephemeral candidate");
    assert_eq!(port, 16);
}

#[test]
fn allocate_exhausts_when_every_candidate_reports_in_use() {
    let mut used = HashSet::new();
    let err = allocate_host_port_with(1..=1, 10, 12, 10, &mut used, |_| {
        Err(io::Error::from(io::ErrorKind::AddrInUse))
    })
    .expect_err("in-use candidates must exhaust");
    assert!(
        matches!(
            err,
            HostPortAllocError::Exhausted {
                ephemeral_first: 1,
                ephemeral_last: 1,
                probe_first: 10,
                probe_last: 12,
            }
        ),
        "unexpected exhaustion error: {err}"
    );
}

#[test]
fn allocate_exhausts_when_probe_window_is_entirely_ephemeral() {
    let mut used = HashSet::new();
    let err = allocate_host_port_with(1..=40, 10, 20, 10, &mut used, |_| {
        panic!("bind must not run when every probe candidate is ephemeral")
    })
    .expect_err("no candidates outside the ephemeral range");
    assert!(matches!(err, HostPortAllocError::Exhausted { .. }));
}

#[test]
fn allocate_skips_permission_denied_and_addr_not_available() {
    let mut used = HashSet::new();
    let port = allocate_host_port_with(1..=1, 10, 12, 10, &mut used, |candidate| match candidate {
        10 => Err(io::Error::from(io::ErrorKind::PermissionDenied)),
        11 => Err(io::Error::from(io::ErrorKind::AddrNotAvailable)),
        12 => Ok(()),
        other => panic!("unexpected candidate {other}"),
    })
    .expect("skip transient bind failures");
    assert_eq!(port, 12);
}

#[test]
fn allocate_surfaces_unexpected_bind_failures() {
    let mut used = HashSet::new();
    let err = allocate_host_port_with(1..=1, 10, 10, 10, &mut used, |_| {
        Err(io::Error::other("nic disappeared"))
    })
    .expect_err("unexpected bind errors must not look like exhaustion");
    match err {
        HostPortAllocError::BindFailed { port, source } => {
            assert_eq!(port, 10);
            assert_eq!(source.to_string(), "nic disappeared");
        }
        other => panic!("expected BindFailed, got {other}"),
    }
}

#[test]
fn classifies_docker_and_kernel_port_collisions() {
    assert!(is_host_port_collision(
        "Hydra container start failed: failed to start a container:\n\
         Docker responded with status code 500: failed to set up container networking:\n\
         driver failed programming external connectivity on endpoint admiring_wozniak:\n\
         Bind for 0.0.0.0:42887 failed: port is already allocated"
    ));
    assert!(is_host_port_collision(
        "listen tcp 0.0.0.0:1234: bind: address already in use"
    ));
    assert!(is_host_port_collision("bind: EADDRINUSE"));
}

#[test]
fn does_not_classify_unrelated_container_start_failures() {
    assert!(!is_host_port_collision(
        "failed to start a container: error pulling image mysql:8.4"
    ));
    assert!(!is_host_port_collision(
        "Hydra container start failed: failed to start a container"
    ));
    assert!(!is_host_port_collision(
        "failed to set up container networking: iptables failed"
    ));
    assert!(!is_host_port_collision(
        "Consul did not elect a leader within 30s"
    ));
}

#[tokio::test]
async fn retry_returns_non_collision_errors_on_the_first_attempt() {
    let attempts = AtomicU32::new(0);
    let result: Result<(), _> = retry_on_host_port_collision(|| {
        attempts.fetch_add(1, Ordering::SeqCst);
        async { Err("error pulling image mysql:8.4".into()) }
    })
    .await;
    assert!(result.is_err(), "generic start failure must stay a hard error");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn retry_retries_only_collisions_then_succeeds() {
    let attempts = AtomicU32::new(0);
    let value = retry_on_host_port_collision(|| {
        let attempt = attempts.fetch_add(1, Ordering::SeqCst) + 1;
        async move {
            if attempt < 3 {
                Err("Bind for 0.0.0.0:1 failed: port is already allocated".into())
            } else {
                Ok(attempt)
            }
        }
    })
    .await
    .expect("collision retry should succeed once a free port is chosen");
    assert_eq!(value, 3);
    assert_eq!(attempts.load(Ordering::SeqCst), 3);
}

#[tokio::test]
async fn retry_exhausts_collision_budget_without_masking_the_error() {
    let attempts = AtomicU32::new(0);
    let result: Result<(), _> = retry_on_host_port_collision(|| {
        attempts.fetch_add(1, Ordering::SeqCst);
        async { Err("port is already allocated".into()) }
    })
    .await;
    let err = result.expect_err("budget exhaustion must fail loudly");
    assert!(
        err.to_string().contains("still allocated after"),
        "exhaustion must keep the collision visible: {err}"
    );
    assert_eq!(attempts.load(Ordering::SeqCst), HOST_PORT_COLLISION_ATTEMPTS);
}

#[cfg(target_os = "linux")]
#[test]
fn allocated_host_port_stays_outside_the_proc_ephemeral_range() {
    let raw = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range")
        .expect("read host ephemeral port range");
    let (first, last) = parse_ephemeral_port_range(&raw).expect("parse host ephemeral port range");
    let port = allocate_host_port().expect("allocate a service-integration host port");
    assert!(
        !(first..=last).contains(&port),
        "allocated host port {port} must stay outside the ephemeral source range {first}-{last}"
    );
}
