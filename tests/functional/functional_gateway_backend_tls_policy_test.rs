//! Live data-path coverage for Gateway API `BackendTLSPolicy` (issue #3276).
//!
//! The integration suite proves what the *translator* emits. This suite proves
//! the emitted configuration actually changes traffic: a real gateway process
//! serves a K8s-translated config against a real TLS backend, and every
//! assertion is made on the wire.
//!
//! Covered:
//!
//! * `caCertificateRefs` → verified backend TLS with the policy's SNI/trust.
//! * an untrusted backend CA fails closed (502), never silently plaintext.
//! * a hostname/SAN-mismatched backend fails closed (502).
//! * `subjectAltNames` is enforced: a cert that chains and matches the SNI but
//!   carries no allow-listed SAN is still refused.
//! * `wellKnownCACertificates: System` does NOT inherit
//!   `FERRUM_TLS_CA_BUNDLE_PATH` — a backend signed by the cluster-global
//!   private CA is refused, which is the whole point of the `system://` source.
//! * live withdrawal: deleting the policy and SIGHUP-reloading returns the
//!   backend to plaintext, so the TLS-only backend stops answering.
//!
//! Run with:
//!   cargo build --bin ferrum-edge && cargo test --test functional_tests -- functional_gateway_backend_tls_policy --ignored --nocapture

use crate::common::TestGateway;
use ferrum_edge::config_sources::k8s::{
    K8sMetadata, K8sObject, K8sTranslationOptions, translate_k8s_objects,
};
use ferrum_edge::identity::spiffe::TrustDomain;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair, KeyUsagePurpose};
use serde_json::{Value, json};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

const BACKEND_SNI: &str = "backend.example.com";
const ROUTE_HOST: &str = "app.example.com";

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

struct GeneratedCa {
    cert_pem: String,
    issuer: Issuer<'static, KeyPair>,
}

struct GeneratedCert {
    cert_pem: String,
    key_pem: String,
}

fn generate_ca(cn: &str) -> GeneratedCa {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen CA key");
    let mut params = CertificateParams::new(Vec::<String>::new()).expect("CA params");
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    params.key_usages.push(KeyUsagePurpose::KeyCertSign);
    params.key_usages.push(KeyUsagePurpose::CrlSign);
    let cert = params.self_signed(&key_pair).expect("self-sign CA");
    GeneratedCa {
        cert_pem: cert.pem(),
        issuer: Issuer::new(params, key_pair),
    }
}

fn generate_signed_cert(ca: &GeneratedCa, cn: &str, sans: &[&str]) -> GeneratedCert {
    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("gen leaf key");
    let san_strings: Vec<String> = sans.iter().map(|s| s.to_string()).collect();
    let mut params = CertificateParams::new(san_strings).expect("leaf params");
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, cn);
    let cert = params.signed_by(&key_pair, &ca.issuer).expect("sign leaf");
    GeneratedCert {
        cert_pem: cert.pem(),
        key_pem: key_pair.serialize_pem(),
    }
}

// ---------------------------------------------------------------------------
// TLS backend
// ---------------------------------------------------------------------------

/// TLS-only echo backend. It speaks no plaintext at all, which is what makes
/// the withdrawal assertion meaningful: once the policy is gone the gateway
/// dials plaintext and the backend cannot answer.
async fn start_https_echo_on(
    listener: TcpListener,
    cert_pem: &str,
    key_pem: &str,
) -> tokio::task::JoinHandle<()> {
    let cert = cert_pem.to_string();
    let key = key_pem.to_string();
    let handle = tokio::spawn(async move {
        let certs: Vec<_> = rustls_pemfile::certs(&mut cert.as_bytes())
            .filter_map(|r| r.ok())
            .collect();
        let pk = rustls_pemfile::private_key(&mut key.as_bytes())
            .expect("key parse")
            .expect("key present");
        let provider = rustls::crypto::ring::default_provider();
        let mut cfg = rustls::ServerConfig::builder_with_provider(Arc::new(provider))
            .with_safe_default_protocol_versions()
            .expect("protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, pk)
            .expect("server cert");
        cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(cfg));
        while let Ok((tcp, _)) = listener.accept().await {
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(tcp).await else {
                    return;
                };
                let mut buf = vec![0u8; 4096];
                let _ = stream.read(&mut buf).await;
                let body = r#"{"status":"ok","tls":true}"#;
                let resp = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(resp.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    });
    handle
}

// ---------------------------------------------------------------------------
// Kubernetes fixture → translated gateway config
// ---------------------------------------------------------------------------

fn k8s_object(api_version: &str, kind: &str, name: &str, spec: Value) -> K8sObject {
    K8sObject {
        api_version: api_version.to_string(),
        kind: kind.to_string(),
        metadata: K8sMetadata {
            name: name.to_string(),
            uid: String::new(),
            namespace: "default".to_string(),
            generation: Some(1),
            labels: Default::default(),
            creation_timestamp: None,
            deletion_timestamp: None,
            annotations: Default::default(),
        },
        spec,
        status: Value::Object(Default::default()),
    }
}

/// `validation` block variants under test.
enum PolicyValidation {
    /// ConfigMap-backed CA, optionally with a `subjectAltNames` allow-list.
    ConfigMapCa {
        sans: Vec<String>,
    },
    System,
}

/// Build the Kubernetes snapshot. `backend_port` is the *real* bound port of
/// the TLS echo backend, declared as the Service port so the translated
/// upstream target dials it directly.
fn k8s_objects(
    backend_port: u16,
    ca_pem: &str,
    policy: Option<PolicyValidation>,
) -> Vec<K8sObject> {
    let mut gateway_class = k8s_object(
        "gateway.networking.k8s.io/v1",
        "GatewayClass",
        "ferrum",
        json!({ "controllerName": "ferrum.io/gateway-controller" }),
    );
    gateway_class.metadata.namespace.clear();

    let mut objects = vec![
        gateway_class,
        k8s_object(
            "gateway.networking.k8s.io/v1",
            "Gateway",
            "edge",
            json!({
                "gatewayClassName": "ferrum",
                "listeners": [{
                    "name": "http",
                    "port": 80,
                    "protocol": "HTTP",
                    "allowedRoutes": { "namespaces": { "from": "Same" } }
                }]
            }),
        ),
        k8s_object(
            "v1",
            "Service",
            "reviews",
            json!({
                "ports": [{ "name": "https", "port": backend_port, "targetPort": backend_port }]
            }),
        ),
        k8s_object(
            "v1",
            "ConfigMap",
            "reviews-ca",
            json!({ "data": { "ca.crt": ca_pem } }),
        ),
        k8s_object(
            "gateway.networking.k8s.io/v1",
            "HTTPRoute",
            "reviews-route",
            json!({
                "parentRefs": [{ "name": "edge" }],
                "hostnames": [ROUTE_HOST],
                "rules": [{
                    "matches": [{ "path": { "type": "PathPrefix", "value": "/api" } }],
                    "backendRefs": [{ "name": "reviews", "port": backend_port }]
                }]
            }),
        ),
    ];

    if let Some(validation) = policy {
        let validation = match validation {
            PolicyValidation::ConfigMapCa { sans } => {
                let mut block = json!({
                    "hostname": BACKEND_SNI,
                    "caCertificateRefs": [{
                        "group": "",
                        "kind": "ConfigMap",
                        "name": "reviews-ca"
                    }]
                });
                if !sans.is_empty() {
                    block["subjectAltNames"] = Value::Array(
                        sans.into_iter()
                            .map(|san| json!({ "type": "Hostname", "hostname": san }))
                            .collect(),
                    );
                }
                block
            }
            PolicyValidation::System => json!({
                "hostname": BACKEND_SNI,
                "wellKnownCACertificates": "System"
            }),
        };
        objects.push(k8s_object(
            "gateway.networking.k8s.io/v1",
            "BackendTLSPolicy",
            "reviews-tls",
            json!({
                "targetRefs": [{ "group": "", "kind": "Service", "name": "reviews" }],
                "validation": validation
            }),
        ));
    }

    objects
}

/// Translate the snapshot and render the file-mode document.
///
/// The only post-processing is `dns_override`: the translated upstream targets
/// name the Service's cluster DNS record, which does not exist off-cluster.
/// Every security-relevant field (`backend_scheme`, `backend_tls_sni`,
/// `backend_tls_server_ca_cert_path`, `backend_tls_san_allow_list`,
/// `backend_tls_verify_server_cert`) is used exactly as the translator emitted
/// it — that is what makes this a test of the translated policy and not of a
/// hand-written config.
fn translated_config_yaml(objects: &[K8sObject]) -> String {
    let options = K8sTranslationOptions::new(
        "default".to_string(),
        TrustDomain::new("cluster.local").expect("trust domain"),
    );
    let mut translated = translate_k8s_objects(objects, options).expect("translate");
    for proxy in &mut translated.config.proxies {
        proxy.dns_override = Some("127.0.0.1".to_string());
        // Keep the dispatch on HTTP/1.1 so the assertion is about TLS trust and
        // not about ALPN negotiation against the single-protocol echo backend.
        proxy.pool_enable_http2 = Some(false);
    }

    let document = json!({
        "version": "1",
        "proxies": translated.config.proxies,
        "consumers": translated.config.consumers,
        "plugin_configs": translated.config.plugin_configs,
        "upstreams": translated.config.upstreams,
    });
    serde_yaml::to_string(&document).expect("serialize translated config")
}

// ---------------------------------------------------------------------------
// Gateway harness
// ---------------------------------------------------------------------------

async fn alloc_port() -> u16 {
    TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind")
        .local_addr()
        .expect("addr")
        .port()
}

/// Spawn a file-mode gateway on the rendered config, retrying with fresh ports
/// when a spawn loses an ephemeral-port race.
async fn start_gateway(config_yaml: &str, extra_env: Vec<(String, String)>) -> (TestGateway, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_error = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_http = alloc_port().await;
        let mut builder = TestGateway::builder()
            .mode_file(config_yaml.to_string())
            .max_attempts(1)
            .capture_output()
            .env("FERRUM_PROXY_HTTP_PORT", proxy_http.to_string())
            .env("FERRUM_PROXY_HTTPS_PORT", alloc_port().await.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", alloc_port().await.to_string())
            .env("FERRUM_ADMIN_HTTPS_PORT", alloc_port().await.to_string())
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_TLS_NO_VERIFY", "false");
        for (key, value) in &extra_env {
            builder = builder.env(key.clone(), value.clone());
        }
        match builder.spawn().await {
            Ok(gateway) => return (gateway, proxy_http),
            Err(error) => {
                last_error = error.to_string();
                eprintln!("gateway spawn attempt {attempt} failed: {last_error}");
            }
        }
    }
    panic!("gateway failed to start after {MAX_ATTEMPTS} attempts: {last_error}");
}

async fn get_status(proxy_http: u16, path: &str) -> u16 {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("client");
    client
        .get(format!("http://127.0.0.1:{proxy_http}{path}"))
        .header("Host", ROUTE_HOST)
        .send()
        .await
        .expect("gateway must answer, not hang")
        .status()
        .as_u16()
}

/// Poll through the bounded SIGHUP reload window instead of assuming a loaded
/// hosted runner will apply the new snapshot within a fixed sleep.
async fn wait_for_status(proxy_http: u16, path: &str, expected: u16) -> u16 {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .expect("client");
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let last = match client
            .get(format!("http://127.0.0.1:{proxy_http}{path}"))
            .header("Host", ROUTE_HOST)
            .send()
            .await
        {
            Ok(response) if response.status().as_u16() == expected => return expected,
            Ok(response) => format!("HTTP {}", response.status()),
            Err(error) => error.to_string(),
        };
        assert!(
            Instant::now() < deadline,
            "gateway did not converge to HTTP {expected} before the reload deadline; last observation: {last}"
        );
        sleep(Duration::from_millis(100)).await;
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

/// Trusted CA + matching SNI + matching SAN allow-list → verified backend TLS.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_performs_verified_backend_tls() {
    let ca = generate_ca("Reviews-CA");
    let backend = generate_signed_cert(&ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let echo = start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa {
            sans: vec![BACKEND_SNI.to_string()],
        }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        200,
        "a trusted, SNI- and SAN-matching backend must be reachable over TLS"
    );

    gateway.shutdown();
    echo.abort();
}

/// The backend chains to a CA the policy does not name → fail closed.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_untrusted_backend_ca_fails_closed() {
    let trusted_ca = generate_ca("Trusted-CA");
    let rogue_ca = generate_ca("Rogue-CA");
    let backend = generate_signed_cert(&rogue_ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let echo = start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &trusted_ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "an untrusted backend chain must fail closed, never fall back to plaintext"
    );

    gateway.shutdown();
    echo.abort();
}

/// The backend chains correctly but its SANs do not cover the policy hostname.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_hostname_mismatch_fails_closed() {
    let ca = generate_ca("Reviews-CA");
    let backend = generate_signed_cert(&ca, "reviews", &["some-other-host.example.com"]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let echo = start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "validation.hostname must be enforced as the verified certificate name"
    );

    gateway.shutdown();
    echo.abort();
}

/// The chain and the SNI both verify, but no SAN matches the allow-list.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_subject_alt_name_allow_list_is_enforced() {
    let ca = generate_ca("Reviews-CA");
    // The cert covers the policy hostname, so chain + name verification pass;
    // only the explicit `subjectAltNames` allow-list can reject it.
    let backend = generate_signed_cert(&ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let echo = start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let objects = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa {
            sans: vec!["not-presented.example.com".to_string()],
        }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&objects), Vec::new()).await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "subjectAltNames must be enforced independently of chain and name verification"
    );

    gateway.shutdown();
    echo.abort();
}

/// `wellKnownCACertificates: System` must pin the built-in roots.
///
/// This is the security boundary the `system://` source exists for. The
/// cluster-global `FERRUM_TLS_CA_BUNDLE_PATH` names the private CA that signed
/// the backend, so before `system://` the request succeeded — the private CA had
/// silently replaced the public trust anchors the policy asked for. It must now
/// fail closed.
#[ignore]
#[tokio::test]
async fn backend_tls_policy_system_roots_ignore_global_ca_bundle() {
    let cluster_ca = generate_ca("Cluster-Private-CA");
    let backend = generate_signed_cert(&cluster_ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let echo = start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let temp = TempDir::new().expect("tempdir");
    let global_ca_path = temp.path().join("cluster-ca.pem");
    std::fs::write(&global_ca_path, &cluster_ca.cert_pem).expect("write global CA");

    let objects = k8s_objects(
        backend_port,
        &cluster_ca.cert_pem,
        Some(PolicyValidation::System),
    );
    let (mut gateway, proxy_http) = start_gateway(
        &translated_config_yaml(&objects),
        vec![(
            "FERRUM_TLS_CA_BUNDLE_PATH".to_string(),
            global_ca_path.to_string_lossy().to_string(),
        )],
    )
    .await;

    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        502,
        "System trust must not inherit the cluster-global private CA bundle"
    );

    gateway.shutdown();
    echo.abort();

    // Positive control on the same backend and the same global bundle: naming
    // the CA through `caCertificateRefs` is trusted, so the 502 above is about
    // trust-anchor selection and not about the fixture being unreachable.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let echo = start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;
    let objects = k8s_objects(
        backend_port,
        &cluster_ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) = start_gateway(
        &translated_config_yaml(&objects),
        vec![(
            "FERRUM_TLS_CA_BUNDLE_PATH".to_string(),
            global_ca_path.to_string_lossy().to_string(),
        )],
    )
    .await;
    assert_eq!(get_status(proxy_http, "/api/test").await, 200);
    gateway.shutdown();
    echo.abort();
}

/// Deleting the policy and reloading withdraws backend TLS on the live config.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn backend_tls_policy_withdrawal_reaches_the_live_data_path() {
    let ca = generate_ca("Reviews-CA");
    let backend = generate_signed_cert(&ca, "reviews", &[BACKEND_SNI]);
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let backend_port = listener.local_addr().expect("addr").port();
    let echo = start_https_echo_on(listener, &backend.cert_pem, &backend.key_pem).await;

    let with_policy = k8s_objects(
        backend_port,
        &ca.cert_pem,
        Some(PolicyValidation::ConfigMapCa { sans: Vec::new() }),
    );
    let (mut gateway, proxy_http) =
        start_gateway(&translated_config_yaml(&with_policy), Vec::new()).await;
    assert_eq!(
        get_status(proxy_http, "/api/test").await,
        200,
        "baseline: the policy-backed TLS route works"
    );

    // Withdraw the policy from the Kubernetes snapshot, re-translate, and
    // SIGHUP the running gateway.
    let without_policy = k8s_objects(backend_port, &ca.cert_pem, None);
    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness must populate config_path");
    std::fs::write(config_path, translated_config_yaml(&without_policy))
        .expect("rewrite translated config");
    let pid = gateway.pid().expect("gateway still running");
    let signal = std::process::Command::new("kill")
        .args(["-HUP", &pid.to_string()])
        .output()
        .expect("invoke SIGHUP command");
    assert!(
        signal.status.success(),
        "SIGHUP command failed: {}",
        String::from_utf8_lossy(&signal.stderr)
    );

    // The backend speaks TLS only, so a withdrawn policy — which returns the
    // route to a plaintext direct backend — must stop succeeding.
    assert_eq!(
        wait_for_status(proxy_http, "/api/test", 502).await,
        502,
        "withdrawing the policy must reach the live data path, not just the config"
    );

    gateway.shutdown();
    echo.abort();
}
