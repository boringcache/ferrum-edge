//! NodeWaypoint scoped DTLS listener socket options (issue #3286).
//!
//! A `DtlsServer` owns the UDP socket every encrypted record leaves from, so
//! the two socket options a NodeWaypoint scoped listener depends on cannot be
//! applied by the caller after the fact:
//!
//! - `IP_PKTINFO` / `IPV6_RECVPKTINFO`, whose kernel-reported ingress
//!   interface IS the session's source-workload attribution;
//! - `SO_MARK = NODE_WAYPOINT_INBOUND_AUTH_MARK`, without which the pod-veth tc
//!   guard drops every record heading back toward the enrolled source pod.
//!
//! Both are startup preconditions: a server that reports itself constructed
//! while missing either is a black hole that looks healthy. These tests pin
//! that construction fails instead, that ordinary DTLS listeners are untouched,
//! and that the fail-closed family decision cannot be satisfied by a success on
//! a family the socket does not actually serve.

use std::sync::Arc;

use ferrum_edge::dtls::{DtlsServer, DtlsServerLimits, FrontendDtlsConfig};
use ferrum_edge::socket_opts::{
    IngressPktinfoFamilies, ingress_pktinfo_outcome, required_ingress_pktinfo_families,
};
use tokio::net::UdpSocket;

/// Arbitrary non-zero mark. The wiring under test is value-agnostic; production
/// passes `crate::ebpf::NODE_WAYPOINT_INBOUND_AUTH_MARK`.
const TEST_MARK: u32 = 0x0539;

fn ensure_crypto_provider() {
    let _ =
        rustls::crypto::CryptoProvider::install_default(rustls::crypto::ring::default_provider());
}

fn frontend_config() -> FrontendDtlsConfig {
    ensure_crypto_provider();
    let certificate =
        dimpl::certificate::generate_self_signed_certificate().expect("generate self-signed cert");
    FrontendDtlsConfig {
        dimpl_config: Arc::new(dimpl::Config::builder().build().expect("build dtls config")),
        certificate: certificate.into(),
        client_cert_verifier: None,
    }
}

async fn bound_socket() -> UdpSocket {
    UdpSocket::bind("127.0.0.1:0")
        .await
        .expect("bind loopback UDP socket")
}

/// Whether this host actually lets an unprivileged process set `SO_MARK`
/// (Linux requires `CAP_NET_ADMIN`; the non-Linux stub is a no-op).
///
/// Probed through the same public primitive the DTLS path uses, so the
/// expectation below is exact on every runner instead of privilege-dependent.
async fn host_allows_socket_mark() -> bool {
    let probe = bound_socket().await;
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        ferrum_edge::socket_opts::set_socket_mark(probe.as_raw_fd(), TEST_MARK).is_ok()
    }
    #[cfg(not(unix))]
    {
        let _ = probe;
        true
    }
}

// ── Ordinary DTLS listeners are unchanged ──────────────────────────────────

#[test]
fn default_dtls_limits_leave_both_scoped_socket_options_off() {
    let limits = DtlsServerLimits::default();
    assert!(
        !limits.capture_ingress_ifindex,
        "ingress-interface capture is a NodeWaypoint-only opt-in"
    );
    assert!(
        limits.socket_mark.is_none(),
        "the NodeWaypoint inbound auth mark is a NodeWaypoint-only opt-in"
    );
}

#[tokio::test]
async fn an_ordinary_dtls_listener_constructs_without_touching_socket_options() {
    let server = DtlsServer::from_socket_with_limits(
        bound_socket().await,
        frontend_config(),
        DtlsServerLimits::default(),
    );
    assert!(
        server.is_ok(),
        "default limits touch no socket option and cannot fail construction"
    );
}

/// `Some(0)` is not a mark. It must take the untouched path rather than issuing
/// a `SO_MARK` syscall that could fail and refuse an ordinary listener.
#[tokio::test]
async fn a_zero_socket_mark_is_treated_as_no_mark() {
    let server = DtlsServer::from_socket_with_limits(
        bound_socket().await,
        frontend_config(),
        DtlsServerLimits {
            socket_mark: Some(0),
            ..DtlsServerLimits::default()
        },
    );
    assert!(
        server.is_ok(),
        "a zero mark must be inert, not a construction failure"
    );
}

// ── Scoped listener preconditions ──────────────────────────────────────────

/// The wiring contract: the scoped listener's construction shares the fate of
/// the underlying `SO_MARK` syscall exactly. A host that refuses the option
/// must not yield a constructed server — that is the black hole this replaces.
#[tokio::test]
async fn a_scoped_socket_mark_shares_the_fate_of_the_underlying_setsockopt() {
    let can_mark = host_allows_socket_mark().await;
    let result = DtlsServer::from_socket_with_limits(
        bound_socket().await,
        frontend_config(),
        DtlsServerLimits {
            socket_mark: Some(TEST_MARK),
            ..DtlsServerLimits::default()
        },
    );
    match (can_mark, result) {
        (true, Ok(_)) => {}
        (true, Err(error)) => {
            panic!("SO_MARK is permitted on this host, so construction must succeed: {error:#}")
        }
        (false, Ok(_)) => panic!(
            "SO_MARK was refused, so every reply to an enrolled source pod would be dropped by \
             the pod-veth guard; the listener must not be constructed"
        ),
        (false, Err(error)) => {
            let text = format!("{error:#}");
            assert!(
                text.contains("DtlsServerLimits::socket_mark"),
                "the diagnostic must name the field that could not be applied: {text}"
            );
            assert!(
                text.contains("SO_MARK"),
                "the diagnostic must name the socket option: {text}"
            );
            assert!(
                text.contains("pod-veth"),
                "the diagnostic must say why it is fatal: {text}"
            );
            assert!(
                !text.contains("BEGIN") && !text.to_ascii_lowercase().contains("private key"),
                "the diagnostic must not carry crypto material: {text}"
            );
        }
    }
}

/// Ingress capture is Linux-only. On Linux `IP_PKTINFO` on a bound IPv4 socket
/// needs no privilege and must arm the demux; everywhere else the channel does
/// not exist, so the scoped listener must refuse to be constructed rather than
/// serve sessions it could only deny.
#[tokio::test]
async fn scoped_ingress_capture_construction_matches_platform_support() {
    let result = DtlsServer::from_socket_with_limits(
        bound_socket().await,
        frontend_config(),
        DtlsServerLimits {
            capture_ingress_ifindex: true,
            ..DtlsServerLimits::default()
        },
    );
    #[cfg(target_os = "linux")]
    {
        assert!(
            result.is_ok(),
            "IP_PKTINFO on a bound IPv4 socket is unprivileged and must arm the demux"
        );
    }
    #[cfg(not(target_os = "linux"))]
    {
        match result {
            Ok(_) => panic!(
                "no IP_PKTINFO ingress-interface channel exists off Linux, so a scoped DTLS \
                 listener must fail construction instead of denying every session"
            ),
            Err(error) => {
                let text = format!("{error:#}");
                assert!(
                    text.contains("ingress interface"),
                    "the diagnostic must name the missing capability: {text}"
                );
                assert!(
                    text.contains("source-workload authorization"),
                    "the diagnostic must say why it is fatal: {text}"
                );
            }
        }
    }
}

// ── Fail-closed family decision ────────────────────────────────────────────

#[test]
fn the_required_pktinfo_families_follow_the_bound_address_and_v6only() {
    let v4 = "0.0.0.0:5353".parse().expect("v4 addr");
    let v6 = "[::]:5353".parse().expect("v6 addr");
    assert_eq!(
        required_ingress_pktinfo_families(v4, false),
        IngressPktinfoFamilies::V4
    );
    // `IPV6_V6ONLY` cannot apply to an IPv4 bind and must not change it.
    assert_eq!(
        required_ingress_pktinfo_families(v4, true),
        IngressPktinfoFamilies::V4
    );
    assert_eq!(
        required_ingress_pktinfo_families(v6, true),
        IngressPktinfoFamilies::V6
    );
    assert_eq!(
        required_ingress_pktinfo_families(v6, false),
        IngressPktinfoFamilies::Both
    );
}

/// The reason the decision is per-family: a dual-stack `[::]` listener serves
/// native IPv6 through `IPV6_PKTINFO` and IPv4-mapped clients through
/// `IP_PKTINFO`. Accepting "one of them worked" would start a listener that
/// silently loses attribution — and therefore denies every session — for one
/// whole family.
#[test]
fn success_on_one_family_does_not_satisfy_a_dual_stack_socket() {
    let refused = ingress_pktinfo_outcome(
        IngressPktinfoFamilies::Both,
        Ok(()),
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
    )
    .expect_err("a dual-stack socket missing IPV6_RECVPKTINFO must fail closed");
    assert_eq!(refused.required, IngressPktinfoFamilies::Both);
    assert!(refused.v4.is_none(), "IPv4 succeeded and must not be blamed");
    assert!(refused.v6.is_some(), "the IPv6 failure must be reported");
    let text = refused.to_string();
    assert!(
        text.contains("IPV6_RECVPKTINFO"),
        "the failing option must be named: {text}"
    );
    assert!(
        !text.contains("IP_PKTINFO:"),
        "the succeeding option must not be reported as a failure: {text}"
    );

    let mirrored = ingress_pktinfo_outcome(
        IngressPktinfoFamilies::Both,
        Err(std::io::Error::from(std::io::ErrorKind::PermissionDenied)),
        Ok(()),
    )
    .expect_err("the mirrored failure must also fail closed");
    assert!(mirrored.v4.is_some());
    assert!(mirrored.v6.is_none());
}

/// The converse: a failure on a family the socket cannot receive is irrelevant
/// and must not refuse an otherwise-attributable listener.
#[test]
fn a_failure_on_an_unserved_family_is_ignored() {
    let permission_denied = || std::io::Error::from(std::io::ErrorKind::PermissionDenied);
    assert!(
        ingress_pktinfo_outcome(IngressPktinfoFamilies::V4, Ok(()), Err(permission_denied()))
            .is_ok(),
        "an IPv4 socket receives no IPv6 datagrams, so IPV6_RECVPKTINFO is irrelevant"
    );
    assert!(
        ingress_pktinfo_outcome(IngressPktinfoFamilies::V6, Err(permission_denied()), Ok(()))
            .is_ok(),
        "a v6only socket receives no IPv4 datagrams, so IP_PKTINFO is irrelevant"
    );
    assert!(
        ingress_pktinfo_outcome(IngressPktinfoFamilies::V4, Ok(()), Ok(())).is_ok(),
        "the all-clear case must not fail closed"
    );
}

#[test]
fn the_family_shape_reports_exactly_which_options_are_required() {
    assert!(IngressPktinfoFamilies::V4.needs_v4() && !IngressPktinfoFamilies::V4.needs_v6());
    assert!(IngressPktinfoFamilies::V6.needs_v6() && !IngressPktinfoFamilies::V6.needs_v4());
    assert!(IngressPktinfoFamilies::Both.needs_v4() && IngressPktinfoFamilies::Both.needs_v6());
}
