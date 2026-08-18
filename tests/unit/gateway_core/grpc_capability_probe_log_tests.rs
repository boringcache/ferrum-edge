//! Capability-probe vs request-time gRPC establishment logging (issue #3923).
//!
//! An ordinary HTTP/1.1 origin failing the startup/reload h2c probe must stay
//! quiet at the documented default `warn` level. Live gRPC failures, timeouts,
//! TLS failures, and port exhaustion must remain WARN/ERROR.

use ferrum_edge::proxy::grpc_proxy::{
    GrpcBackendUnavailableKind, GrpcEstablishmentLogLevel, GrpcEstablishmentPurpose,
    GrpcProxyError, GrpcTimeoutKind, grpc_establishment_failure_log_level,
};
use std::io::{Error as IoError, ErrorKind};

fn h2c_handshake_miss() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::H2cHandshake,
        "h2c handshake failed: http2 error".into(),
    )
}

fn connect_refused() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable_with_source(
        GrpcBackendUnavailableKind::Connect,
        "Connection failed: connection refused".into(),
        IoError::new(ErrorKind::ConnectionRefused, "connection refused"),
    )
}

fn tls_handshake_fail() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::TlsHandshake,
        "TLS handshake failed: invalid peer certificate".into(),
    )
}

fn dns_fail() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable(
        GrpcBackendUnavailableKind::DnsResolution,
        "DNS resolution failed for backend.example: lookup failed".into(),
    )
}

fn connect_timeout() -> GrpcProxyError {
    GrpcProxyError::BackendTimeout {
        kind: GrpcTimeoutKind::Connect,
        message: "Connect timeout after 100ms establishing gRPC HTTP/2 to 127.0.0.1:18081".into(),
    }
}

fn port_exhaustion() -> GrpcProxyError {
    GrpcProxyError::backend_unavailable_with_source(
        GrpcBackendUnavailableKind::Connect,
        "Connection failed: address not available".into(),
        IoError::from_raw_os_error(99),
    )
}

#[test]
fn expected_h2c_capability_miss_is_debug_not_warn() {
    assert_eq!(
        grpc_establishment_failure_log_level(
            GrpcEstablishmentPurpose::CapabilityProbe,
            &h2c_handshake_miss(),
        ),
        GrpcEstablishmentLogLevel::Debug,
        "ordinary HTTP/1.1 classification must not WARN at default log level"
    );
}

#[test]
fn request_time_h2c_handshake_failure_stays_warn() {
    assert_eq!(
        grpc_establishment_failure_log_level(
            GrpcEstablishmentPurpose::Request,
            &h2c_handshake_miss(),
        ),
        GrpcEstablishmentLogLevel::Warn,
        "live gRPC h2c establishment failures must remain actionable"
    );
}

#[test]
fn unexpected_probe_failures_stay_warn() {
    for (label, error) in [
        ("connect", connect_refused()),
        ("tls", tls_handshake_fail()),
        ("dns", dns_fail()),
        ("timeout", connect_timeout()),
    ] {
        assert_eq!(
            grpc_establishment_failure_log_level(
                GrpcEstablishmentPurpose::CapabilityProbe,
                &error,
            ),
            GrpcEstablishmentLogLevel::Warn,
            "{label} during a capability probe must stay WARN"
        );
        assert_eq!(
            grpc_establishment_failure_log_level(GrpcEstablishmentPurpose::Request, &error),
            GrpcEstablishmentLogLevel::Warn,
            "{label} during request-time gRPC must stay WARN"
        );
    }
}

#[test]
fn port_exhaustion_is_error_for_probe_and_request() {
    let error = port_exhaustion();
    assert_eq!(
        grpc_establishment_failure_log_level(GrpcEstablishmentPurpose::CapabilityProbe, &error),
        GrpcEstablishmentLogLevel::Error,
    );
    assert_eq!(
        grpc_establishment_failure_log_level(GrpcEstablishmentPurpose::Request, &error),
        GrpcEstablishmentLogLevel::Error,
    );
}

#[test]
fn probe_h2c_threads_capability_probe_purpose_not_request_get_sender() {
    let source = include_str!("../../../src/proxy/mod.rs");
    let probe = source
        .split("async fn probe_h2c(")
        .nth(1)
        .expect("probe_h2c")
        .split("async fn probe_h2_tls(")
        .next()
        .expect("bounded probe_h2c body");
    assert!(
        probe.contains("get_sender_for_capability_probe(probe_proxy)"),
        "h2c capability probes must carry probe purpose into the gRPC pool"
    );
    assert!(
        !probe.contains("grpc_pool.get_sender(probe_proxy)"),
        "request-time get_sender would WARN on expected HTTP/1.1 misses"
    );
}

#[test]
fn request_time_get_sender_keeps_request_purpose() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let get_sender = source
        .split("pub async fn get_sender(")
        .nth(1)
        .expect("get_sender")
        .split("pub async fn get_sender_for_capability_probe(")
        .next()
        .expect("bounded get_sender");
    assert!(
        get_sender.contains("GrpcEstablishmentPurpose::Request"),
        "live gRPC dispatch must keep request-time establishment logging"
    );
    assert!(
        !get_sender.contains("CapabilityProbe"),
        "request-time get_sender must not inherit probe quieting"
    );
}

#[test]
fn establishment_logger_is_not_a_blanket_warn_downgrade() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let create = source
        .split("async fn create_connection(")
        .nth(1)
        .expect("create_connection")
        .split("fn build_h2_builder(")
        .next()
        .expect("bounded create_connection");
    assert!(
        create.contains("purpose: GrpcEstablishmentPurpose"),
        "create_connection must receive explicit probe vs request context"
    );
    assert!(
        create.contains("log_grpc_protocol_establishment_failure("),
        "Failed establishment must go through the purpose-aware logger"
    );
    assert!(
        create.contains("&source"),
        "the logger must receive the typed establishment error, not a formatted secret"
    );
    assert!(
        create.contains("protocol establishment budget exhausted"),
        "timeouts must keep their dedicated WARN diagnostic"
    );
    assert!(
        create.contains("warn!"),
        "timeouts must still emit WARN rather than being folded into debug"
    );

    let classifier = source
        .split("pub fn grpc_establishment_failure_log_level(")
        .nth(1)
        .expect("classifier")
        .split("pub fn log_grpc_protocol_establishment_failure(")
        .next()
        .expect("bounded classifier");
    assert!(
        classifier.contains("GrpcBackendUnavailableKind::H2cHandshake"),
        "only the expected h2c classification miss is quieted"
    );
    assert!(
        classifier.contains("is_port_exhaustion(error)"),
        "port exhaustion must stay ERROR even during probes"
    );
}

#[test]
fn establishment_failure_messages_name_only_host_and_address() {
    let source = include_str!("../../../src/proxy/grpc_proxy.rs");
    let logger = source
        .split("pub fn log_grpc_protocol_establishment_failure(")
        .nth(1)
        .expect("logger")
        .split("/// Which phase of a gRPC backend interaction timed out.")
        .next()
        .expect("bounded logger");
    assert!(
        logger.contains("last={}"),
        "quiet and warn lines must name the last candidate address"
    );
    assert!(
        logger.contains("for backend {}"),
        "lines must name the backend host only"
    );
    assert!(
        logger.contains("host, last_addr, error"),
        "debug/warn interpolations must be host + address + error"
    );
    assert!(
        !logger.contains("authorization"),
        "establishment logs must not interpolate credential headers"
    );
    assert!(
        !logger.contains("cookie"),
        "establishment logs must not interpolate cookies"
    );
}
