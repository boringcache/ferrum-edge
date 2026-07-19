use ferrum_edge::config::EnvConfig;

#[test]
fn admin_listener_defaults_use_distinct_http_and_https_ports() {
    let config = EnvConfig::default();

    assert_eq!(config.admin_http_port, 9000);
    assert_eq!(config.admin_https_port, 9443);
    assert_ne!(config.admin_http_port, config.admin_https_port);

    let reserved = config.reserved_gateway_ports();
    assert!(reserved.contains(&config.admin_http_port));
    assert!(reserved.contains(&config.admin_https_port));
}

#[test]
fn admin_socket_addr_uses_admin_bind_address_not_proxy_bind_address() {
    let config = EnvConfig {
        proxy_bind_address: "127.0.0.1".to_string(),
        admin_bind_address: "127.0.0.2".to_string(),
        ..Default::default()
    };

    assert_eq!(
        config.proxy_socket_addr(config.proxy_http_port).to_string(),
        "127.0.0.1:8000"
    );
    assert_eq!(
        config.admin_socket_addr(config.admin_http_port).to_string(),
        "127.0.0.2:9000"
    );
}

#[test]
fn disabled_admin_listener_ports_do_not_reserve_port_zero() {
    let config = EnvConfig {
        admin_http_port: 0,
        admin_https_port: 0,
        ..Default::default()
    };

    let reserved = config.reserved_gateway_ports();
    assert!(!reserved.contains(&0));
    assert!(!reserved.contains(&9000));
    assert!(!reserved.contains(&9443));
    assert!(reserved.contains(&config.proxy_http_port));
    assert!(reserved.contains(&config.proxy_https_port));
}

#[test]
fn cp_grpc_listener_port_is_reserved_when_configured() {
    let config = EnvConfig {
        cp_grpc_listen_addr: Some("0.0.0.0:50051".to_string()),
        ..Default::default()
    };

    let reserved = config.reserved_gateway_ports();
    assert!(reserved.contains(&50051));
}

#[test]
fn admin_https_listener_enabled_requires_port_and_tls_material() {
    // Port 0 is the disable sentinel: TLS material alone must not enable the
    // listener (CP, DP, and mesh previously bound an ephemeral port here).
    let port_zero_with_tls = EnvConfig {
        admin_https_port: 0,
        admin_tls_cert_path: Some("/tmp/tls.crt".to_string()),
        admin_tls_key_path: Some("/tmp/tls.key".to_string()),
        ..Default::default()
    };
    assert!(
        !port_zero_with_tls.admin_https_listener_enabled(),
        "FERRUM_ADMIN_HTTPS_PORT=0 must disable admin HTTPS even with cert/key configured"
    );

    let enabled = EnvConfig {
        admin_https_port: 9443,
        admin_tls_cert_path: Some("/tmp/tls.crt".to_string()),
        admin_tls_key_path: Some("/tmp/tls.key".to_string()),
        ..Default::default()
    };
    assert!(enabled.admin_https_listener_enabled());

    let no_tls = EnvConfig {
        admin_https_port: 9443,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        ..Default::default()
    };
    assert!(!no_tls.admin_https_listener_enabled());

    let cert_without_key = EnvConfig {
        admin_https_port: 9443,
        admin_tls_cert_path: Some("/tmp/tls.crt".to_string()),
        admin_tls_key_path: None,
        ..Default::default()
    };
    assert!(!cert_without_key.admin_https_listener_enabled());

    let port_zero_without_tls = EnvConfig {
        admin_https_port: 0,
        admin_tls_cert_path: None,
        admin_tls_key_path: None,
        ..Default::default()
    };
    assert!(!port_zero_without_tls.admin_https_listener_enabled());
}
