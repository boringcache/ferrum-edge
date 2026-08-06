//! External unit coverage for Sidecar `ingress[]` stream-family listeners
//! (issue #3260): resolve, protocol classification lock-step with the K8s
//! translator predicates, and bind-contract documentation (#3266 boundary).

use ferrum_edge::modes::mesh::config::{
    AppProtocol, IngressListenerUnsupported, MeshSidecarIngress, is_http_family_app_protocol,
    is_modeled_ingress_app_protocol, is_stream_family_app_protocol,
};

fn entry(port: u16, protocol: AppProtocol, endpoint: &str) -> MeshSidecarIngress {
    MeshSidecarIngress {
        port,
        protocol,
        name: None,
        bind: None,
        default_endpoint: endpoint.to_string(),
    }
}

#[test]
fn stream_family_protocols_partition_from_http_and_unknown() {
    for protocol in [
        AppProtocol::Tcp,
        AppProtocol::Tls,
        AppProtocol::Mongo,
        AppProtocol::Redis,
        AppProtocol::Mysql,
        AppProtocol::Postgres,
    ] {
        assert!(is_stream_family_app_protocol(protocol));
        assert!(!is_http_family_app_protocol(protocol));
        assert!(is_modeled_ingress_app_protocol(protocol));
    }
    for protocol in [AppProtocol::Http, AppProtocol::Http2, AppProtocol::Grpc] {
        assert!(is_http_family_app_protocol(protocol));
        assert!(!is_stream_family_app_protocol(protocol));
        assert!(is_modeled_ingress_app_protocol(protocol));
    }
    assert!(!is_modeled_ingress_app_protocol(AppProtocol::Unknown));
    assert!(!is_modeled_ingress_app_protocol(AppProtocol::Udp));
}

#[test]
fn stream_ingress_resolves_loopback_and_preserves_protocol() {
    let resolved = entry(16379, AppProtocol::Redis, "127.0.0.1:6379")
        .resolve()
        .expect("redis ingress resolves");
    assert_eq!(resolved.port, 16379);
    assert_eq!(resolved.endpoint_port, 6379);
    assert_eq!(resolved.protocol, AppProtocol::Redis);
    assert!(resolved.is_stream_family());
}

#[test]
fn stream_ingress_maps_instance_ip_wildcard_to_loopback() {
    let resolved = entry(9000, AppProtocol::Tcp, "0.0.0.0:6000")
        .resolve()
        .expect("instance-IP TCP ingress resolves");
    assert_eq!(resolved.endpoint_host, "127.0.0.1");
    assert_eq!(resolved.endpoint_port, 6000);
}

#[test]
fn stream_ingress_rejects_unix_and_off_box_endpoints() {
    assert_eq!(
        entry(9000, AppProtocol::Tcp, "unix:///var/run/app.sock").resolve(),
        Err(IngressListenerUnsupported::UnixSocketEndpoint)
    );
    assert_eq!(
        entry(9000, AppProtocol::Tcp, "10.0.0.5:6000").resolve(),
        Err(IngressListenerUnsupported::UnparseableEndpoint)
    );
}

#[test]
fn custom_bind_is_preserved_but_does_not_affect_resolve() {
    // Issue #3266 boundary: custom bind is observability-only under the
    // shared :15006 capture contract required by #3260. Resolve still keys
    // off port + protocol + defaultEndpoint.
    let mut with_bind = entry(9000, AppProtocol::Tcp, "127.0.0.1:6000");
    with_bind.bind = Some("127.0.0.1".to_string());
    let resolved = with_bind.resolve().expect("bind does not block resolve");
    assert_eq!(resolved.port, 9000);
    assert_eq!(resolved.endpoint_port, 6000);
}
