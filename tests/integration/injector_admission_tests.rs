//! Integration coverage for the Kubernetes sidecar-injector admission webhook
//! (`FERRUM_MODE=injector`).
//!
//! These tests exercise the public `admission_response` surface from outside
//! the crate to confirm the hostile-input boundary behavior:
//!   - a mis-scoped webhook delivering a non-Pod object is admitted without a
//!     patch (never inject into unknown kinds);
//!   - a `dryRun` request returns the identical patch (no implied side effects);
//!   - a real core `v1` Pod is still injected (happy path).

use base64::Engine as _;
use ferrum_edge::capture::{
    CaptureMode, DEFAULT_TPROXY_MARK, DEFAULT_UDP_OUTBOUND_PORT, Ip6TablesMode,
};
use ferrum_edge::modes::injector::{
    ContainerResourceConfig, InjectorConfig, SecretKeyRef, admission_response,
};
use serde_json::{Value, json};

fn injector_config(capture_mode: CaptureMode) -> InjectorConfig {
    InjectorConfig {
        listen_addr: "127.0.0.1:9443".parse().expect("listen addr"),
        namespace: "default".to_string(),
        sidecar_image: "ferrum-edge:test".to_string(),
        sidecar_env: vec![(
            "FERRUM_DP_CP_GRPC_URLS".to_string(),
            "http://cp:50051".to_string(),
        )],
        jwt_secret_ref: Some(SecretKeyRef {
            name: "ferrum-edge-secrets".to_string(),
            key: "cp-dp-grpc-jwt-secret".to_string(),
        }),
        sidecar_resources: ContainerResourceConfig {
            cpu_request: "25m".to_string(),
            memory_request: "64Mi".to_string(),
            cpu_limit: "250m".to_string(),
            memory_limit: "256Mi".to_string(),
        },
        init_resources: ContainerResourceConfig {
            cpu_request: "10m".to_string(),
            memory_request: "32Mi".to_string(),
            cpu_limit: "100m".to_string(),
            memory_limit: "128Mi".to_string(),
        },
        require_annotation: true,
        capture_mode,
        proxy_uid: Some(1337),
        exclude_outbound_ports: Vec::new(),
        exclude_inbound_ports: Vec::new(),
        include_outbound_cidrs: Vec::new(),
        exclude_outbound_cidrs: Vec::new(),
        ip6tables_mode: Ip6TablesMode::Auto,
        udp_capture_enabled: false,
        udp_outbound_port: DEFAULT_UDP_OUTBOUND_PORT,
        tproxy_mark: DEFAULT_TPROXY_MARK,
        trust_domain: "cluster.local".to_string(),
        tls_cert_path: None,
        tls_key_path: None,
        allow_plaintext: true,
        tls_handshake_timeout_seconds: 10,
        http_header_read_timeout_seconds: 10,
        admission_review_max_body_bytes: 4 * 1024 * 1024,
    }
}

fn pod_object() -> Value {
    json!({
        "metadata": {
            "labels": {"ferrum.io/mesh": "enabled"}
        },
        "spec": {
            "serviceAccountName": "api",
            "containers": [{"name": "app", "image": "app:test"}]
        }
    })
}

#[test]
fn admission_webhook_injects_core_v1_pod() {
    let review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "pod-1",
            "namespace": "payments",
            "kind": {"group": "", "version": "v1", "kind": "Pod"},
            "resource": {"group": "", "version": "v1", "resource": "pods"},
            "object": pod_object()
        }
    });
    let response = admission_response(
        review.to_string().as_bytes(),
        &injector_config(CaptureMode::Iptables),
    )
    .expect("admission response");

    assert_eq!(
        response.pointer("/response/allowed"),
        Some(&Value::Bool(true))
    );
    assert_eq!(response.pointer("/response/uid"), Some(&json!("pod-1")));
    assert_eq!(
        response.pointer("/response/patchType"),
        Some(&Value::String("JSONPatch".to_string()))
    );
    let patch = response
        .pointer("/response/patch")
        .and_then(Value::as_str)
        .expect("encoded patch");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(patch)
        .expect("base64 patch");
    let ops: Vec<Value> = serde_json::from_slice(&decoded).expect("json patch");
    assert!(
        ops.iter()
            .any(|op| op.get("path").and_then(Value::as_str) == Some("/spec/containers/-")),
        "sidecar container must be appended"
    );
}

#[test]
fn admission_webhook_admits_non_pod_without_injection() {
    // A mis-scoped MutatingWebhookConfiguration routes a Deployment here.
    let review = json!({
        "apiVersion": "admission.k8s.io/v1",
        "kind": "AdmissionReview",
        "request": {
            "uid": "deploy-1",
            "namespace": "payments",
            "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
            "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
            "object": {
                "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                "spec": {"template": {"spec": {"containers": []}}}
            }
        }
    });
    let response = admission_response(
        review.to_string().as_bytes(),
        &injector_config(CaptureMode::Iptables),
    )
    .expect("admission response");

    assert_eq!(
        response.pointer("/response/allowed"),
        Some(&Value::Bool(true)),
        "non-Pod objects must be admitted, never blocked"
    );
    assert_eq!(
        response.pointer("/response/patch"),
        None,
        "non-Pod objects must never be patched"
    );
    assert_eq!(response.pointer("/response/patchType"), None);
}

#[test]
fn admission_webhook_dry_run_returns_identical_patch() {
    let make_review = |dry_run: bool| {
        json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "pod-1",
                "namespace": "payments",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "dryRun": dry_run,
                "object": pod_object()
            }
        })
    };
    let config = injector_config(CaptureMode::Iptables);

    let live = admission_response(make_review(false).to_string().as_bytes(), &config)
        .expect("live response");
    let dry = admission_response(make_review(true).to_string().as_bytes(), &config)
        .expect("dry response");

    assert_eq!(live.pointer("/response/allowed"), Some(&Value::Bool(true)));
    assert_eq!(dry.pointer("/response/allowed"), Some(&Value::Bool(true)));
    assert_eq!(
        live.pointer("/response/patch"),
        dry.pointer("/response/patch"),
        "dryRun must not alter the computed patch"
    );
    assert!(dry.pointer("/response/patch").is_some());
}
