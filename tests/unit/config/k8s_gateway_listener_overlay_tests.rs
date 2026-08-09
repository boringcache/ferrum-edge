use std::collections::BTreeSet;

use ferrum_edge::_test_support::merge_k8s_translation;
use ferrum_edge::config::types::{GatewayConfig, Proxy};
use serde_json::json;

fn http_proxy(id: &str, namespace: &str, port: u16) -> Proxy {
    serde_json::from_value(json!({
        "id": id,
        "namespace": namespace,
        "hosts": ["app.example.com"],
        "listen_path": "/",
        "listen_port": port,
        "backend_scheme": "http",
        "backend_host": "backend.example.com",
        "backend_port": 8080
    }))
    .expect("proxy fixture")
}

#[test]
fn gateway_tls_withdrawal_does_not_reclassify_a_native_same_port_proxy() {
    let namespace = "default";
    let port = 8443;
    let native = http_proxy("native", namespace, port);

    // The active composition contains a native proxy plus the TLS ownership
    // bit left by a prior Kubernetes Gateway listener on the same namespace
    // and port. The replacement translation withdraws that listener.
    let mut active = GatewayConfig {
        proxies: vec![native],
        ..GatewayConfig::default()
    };
    active
        .http_tls_listen_ports
        .insert((namespace.to_string(), port));

    let replacement = GatewayConfig::default();
    let managed: BTreeSet<String> = [namespace.to_string()].into_iter().collect();
    let merged = merge_k8s_translation(&active, &replacement, &managed);

    assert_eq!(merged.proxies.len(), 1, "the native proxy must survive");
    assert!(
        merged.http_tls_listen_ports.is_empty(),
        "withdrawn Kubernetes TLS ownership must not attach to the surviving native proxy"
    );
}
