//! Integration tests for opt-in frontend TLS cert/key live reload
//! (`FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED`).
//!
//! Validates that:
//! 1. The HTTPS listener reads from the shared `SharedFrontendTls` ArcSwap
//!    slot on every new accept, so swapping the slot takes effect on the
//!    next handshake without restarting the listener.
//! 2. A swap to a config bearing a different leaf certificate is observed
//!    by the next handshake (we compare the cert chain length / SAN
//!    indirectly via certificate-equality assertions on the peer-cert seen
//!    by the rustls client).
//! 3. Existing in-flight TLS sessions are NOT torn down by a swap (rustls
//!    consults the `ServerConfig` only during the handshake).

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use arc_swap::ArcSwap;
use ferrum_edge::config::EnvConfig;
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::dns::{DnsCache, DnsConfig};
use ferrum_edge::proxy::{ProxyState, start_proxy_listener_with_dynamic_tls_and_signal};
use ferrum_edge::tls::NoVerifier;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, RootCertStore, ServerConfig};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;
use tokio_rustls::TlsConnector;

use crate::scaffolding::ports::reserve_port;

fn ensure_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

fn test_env_config() -> EnvConfig {
    EnvConfig {
        pool_warmup_enabled: false,
        shutdown_drain_seconds: 0,
        accept_threads: 1,
        frontend_tls_handshake_timeout_seconds: 2,
        ..EnvConfig::default()
    }
}

fn test_proxy_state(env: EnvConfig) -> ProxyState {
    ProxyState::new(
        GatewayConfig::default(),
        DnsCache::new(DnsConfig::default()),
        env,
        None,
        None,
    )
    .expect("proxy state")
    .0
}

fn generate_server_config_with_san(san: &str) -> (Arc<ServerConfig>, Vec<u8>) {
    ensure_crypto_provider();
    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate key");
    let params = rcgen::CertificateParams::new(vec![san.to_string()]).expect("cert params");
    let cert = params.self_signed(&key_pair).expect("self-sign cert");

    let cert_pem = cert.pem();
    let mut cert_reader = cert_pem.as_bytes();
    let certs: Vec<_> = rustls_pemfile::certs(&mut cert_reader)
        .filter_map(Result::ok)
        .collect();
    let cert_der = certs[0].as_ref().to_vec();
    let key_pem = key_pair.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("read private key")
        .expect("private key present");

    let config =
        ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("default protocol versions")
            .with_no_client_auth()
            .with_single_cert(certs, private_key)
            .expect("server cert");

    (Arc::new(config), cert_der)
}

fn no_verify_client_config() -> Arc<ClientConfig> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let cfg = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("default protocol versions")
        .with_root_certificates(RootCertStore::empty())
        .with_no_client_auth();
    // Use the gateway's shared NoVerifier so peer certs are accepted
    // unconditionally. We compare cert DERs after the handshake to verify
    // the slot's current cert is being served.
    let mut cfg = cfg;
    cfg.dangerous()
        .set_certificate_verifier(Arc::new(NoVerifier));
    Arc::new(cfg)
}

async fn fetch_peer_cert_der(addr: SocketAddr) -> Vec<u8> {
    let client_config = no_verify_client_config();
    let connector = TlsConnector::from(client_config);
    let stream = TcpStream::connect(addr).await.expect("connect TCP");
    let server_name = ServerName::try_from("localhost").expect("server name");
    let mut tls = connector
        .connect(server_name, stream)
        .await
        .expect("tls handshake");
    // Write a tiny dummy request so the server processes the connection;
    // we only care about the handshake's peer cert chain.
    let _ = tls
        .write_all(b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .await;
    // Drain (best-effort) so the connection is fully exchanged.
    let mut buf = Vec::new();
    let _ = tokio::time::timeout(Duration::from_millis(500), tls.read_to_end(&mut buf)).await;

    let (_io, conn) = tls.into_inner();
    conn.peer_certificates()
        .expect("server cert presented")
        .first()
        .expect("at least one cert")
        .as_ref()
        .to_vec()
}

async fn start_dynamic_tls_listener_with_retry(
    state: &ProxyState,
    slot: ferrum_edge::tls::SharedFrontendTls,
) -> (
    SocketAddr,
    tokio::sync::watch::Sender<bool>,
    JoinHandle<Result<(), anyhow::Error>>,
) {
    let mut errors = Vec::new();
    for attempt in 1..=5 {
        let reservation = reserve_port().await.expect("reserve proxy port");
        let port = reservation.drop_and_take_port();
        let addr = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
        let listener_state = state.clone();
        let listener_slot = slot.clone();
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
        let (started_tx, started_rx) = tokio::sync::oneshot::channel();
        let listener = tokio::spawn(async move {
            start_proxy_listener_with_dynamic_tls_and_signal(
                addr,
                listener_state,
                shutdown_rx,
                listener_slot,
                Some(started_tx),
            )
            .await
        });

        let start_result = tokio::time::timeout(Duration::from_secs(2), started_rx).await;
        let mut attempt_error = match start_result {
            Ok(Ok(())) => return (addr, shutdown_tx, listener),
            Ok(Err(error)) => {
                format!("attempt {attempt}: listener start signal dropped: {error}")
            }
            Err(error) => format!("attempt {attempt}: listener start timed out: {error}"),
        };

        let _ = shutdown_tx.send(true);
        match tokio::time::timeout(Duration::from_secs(2), listener).await {
            Ok(Ok(Err(error))) => {
                attempt_error = format!("{attempt_error}; listener returned error: {error}");
            }
            Ok(Err(error)) => {
                attempt_error = format!("{attempt_error}; listener task join error: {error}");
            }
            Err(error) => {
                attempt_error = format!("{attempt_error}; listener task did not stop: {error}");
            }
            Ok(Ok(Ok(()))) => {}
        }
        errors.push(attempt_error);
    }

    panic!(
        "listener did not bind after retries: {}",
        errors.join(" | ")
    );
}

/// New TLS handshakes after an `ArcSwap` cert swap present the new
/// certificate chain. This is the load-bearing contract for opt-in frontend
/// TLS live reload — the listener reads from the slot on each accept, so a
/// successful reload flips the served cert on the very next handshake.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn dynamic_tls_listener_serves_rotated_cert_after_slot_swap() {
    ensure_crypto_provider();
    let state = test_proxy_state(test_env_config());

    let (initial_config, initial_der) = generate_server_config_with_san("localhost");
    let slot: ferrum_edge::tls::SharedFrontendTls =
        Arc::new(ArcSwap::new(Arc::new(Some(initial_config))));

    let (addr, shutdown_tx, listener) =
        start_dynamic_tls_listener_with_retry(&state, slot.clone()).await;

    let first_seen = fetch_peer_cert_der(addr).await;
    assert_eq!(
        first_seen, initial_der,
        "first handshake must present the startup-loaded cert"
    );

    // Rotate: build a fresh self-signed cert and swap the slot. The next
    // handshake should pick it up — no listener restart, no port rebind.
    let (rotated_config, rotated_der) = generate_server_config_with_san("localhost");
    assert_ne!(initial_der, rotated_der, "rotated cert must differ");
    slot.store(Arc::new(Some(rotated_config)));

    let second_seen = fetch_peer_cert_der(addr).await;
    assert_eq!(
        second_seen, rotated_der,
        "second handshake must present the rotated cert without restarting the listener"
    );

    let _ = shutdown_tx.send(true);
    tokio::time::timeout(Duration::from_secs(2), listener)
        .await
        .expect("listener should stop")
        .expect("listener task should join")
        .expect("listener should return cleanly");
}

// ---------------------------------------------------------------------------
// HTTP/3 accepted-candidate binding (issue #3857)
// ---------------------------------------------------------------------------

/// Materials for a frontend surface that terminates client certificates.
struct ClientAuthMaterials {
    _dir: tempfile::TempDir,
    cert_path: String,
    key_path: String,
    ca_path: String,
    crl_path: String,
    client_der: Vec<u8>,
}

/// Write a server identity, a client CA, one client certificate under that CA,
/// and a CRL that already revokes it. The revocation is in the STARTUP CRL on
/// purpose: it is what proves the accepted candidate's verifier is compiled
/// from the CRLs of the same load, rather than from an unrelated list.
fn write_client_auth_materials() -> ClientAuthMaterials {
    ensure_crypto_provider();
    let dir = tempfile::tempdir().expect("tempdir");

    let ca_key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("CA key");
    let mut ca_params = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "Frontend Client CA");
    ca_params.key_usages.push(rcgen::KeyUsagePurpose::KeyCertSign);
    ca_params.key_usages.push(rcgen::KeyUsagePurpose::CrlSign);
    let ca_cert = ca_params.self_signed(&ca_key).expect("self-signed CA");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let client_serial = 0x3857u64;
    let client_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("client key");
    let mut client_params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("client params");
    client_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "frontend-client");
    client_params
        .extended_key_usages
        .push(rcgen::ExtendedKeyUsagePurpose::ClientAuth);
    client_params
        .key_usages
        .push(rcgen::KeyUsagePurpose::DigitalSignature);
    client_params.serial_number = Some(rcgen::SerialNumber::from(client_serial));
    let client_cert = client_params
        .signed_by(&client_key, &issuer)
        .expect("client cert");

    let now = time::OffsetDateTime::now_utc();
    let crl_pem = rcgen::CertificateRevocationListParams {
        this_update: now,
        next_update: now + time::Duration::days(30),
        crl_number: rcgen::SerialNumber::from(1u64),
        issuing_distribution_point: None,
        revoked_certs: vec![rcgen::RevokedCertParams {
            serial_number: rcgen::SerialNumber::from(client_serial),
            revocation_time: now,
            reason_code: Some(rcgen::RevocationReason::KeyCompromise),
            invalidity_date: None,
        }],
        key_identifier_method: rcgen::KeyIdMethod::Sha256,
    }
    .signed_by(&issuer)
    .expect("sign CRL")
    .pem()
    .expect("CRL PEM");

    let server_key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("server key");
    let server_params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
    let server_cert = server_params
        .self_signed(&server_key)
        .expect("self-signed server cert");

    let cert_path = dir.path().join("server-cert.pem");
    let key_path = dir.path().join("server-key.pem");
    let ca_path = dir.path().join("client-ca.pem");
    let crl_path = dir.path().join("revocations.pem");
    std::fs::write(&cert_path, server_cert.pem()).expect("write server cert");
    std::fs::write(&key_path, server_key.serialize_pem()).expect("write server key");
    std::fs::write(&ca_path, ca_cert.pem()).expect("write client CA");
    std::fs::write(&crl_path, &crl_pem).expect("write CRL");

    ClientAuthMaterials {
        cert_path: cert_path.to_string_lossy().into_owned(),
        key_path: key_path.to_string_lossy().into_owned(),
        ca_path: ca_path.to_string_lossy().into_owned(),
        crl_path: crl_path.to_string_lossy().into_owned(),
        client_der: client_cert.der().to_vec(),
        _dir: dir,
    }
}

/// The proxy frontend reload wiring must hand the HTTP/3 listener ONE accepted
/// candidate (issue #3857), and arm the proxy client-trust baseline from that
/// same load.
///
/// The H3 endpoint applies its config asynchronously, so before this it rebuilt
/// a verifier from a re-read client-CA source plus the startup CRL clone and
/// then published the proxy scope's latest material as its own generation —
/// three different instants, one published generation. Here the config in the
/// serving slot, the verifier, and the identity are asserted to be one value:
/// the accepted candidate's `config` is the very `Arc` the listeners serve, its
/// verifier enforces the CRLs of that load, and its identity is what the proxy
/// scope was armed with.
#[tokio::test]
async fn proxy_frontend_reload_publishes_one_accepted_candidate_for_http3() {
    ensure_crypto_provider();
    let materials = write_client_auth_materials();

    let env = EnvConfig {
        frontend_tls_live_reload_enabled: true,
        frontend_tls_cert_path: Some(materials.cert_path.clone()),
        frontend_tls_key_path: Some(materials.key_path.clone()),
        frontend_tls_client_ca_bundle_path: Some(materials.ca_path.clone()),
        tls_crl_file_path: Some(materials.crl_path.clone()),
        // Long enough that no background poll can interleave with the
        // assertions below; every assertion is on the startup publication.
        frontend_tls_watch_interval_seconds: 3600,
        ..EnvConfig::default()
    };
    let tls_policy = ferrum_edge::tls::TlsPolicy::from_env_config(&env).expect("tls policy");
    let crls = ferrum_edge::tls::load_crls(env.tls_crl_file_path.as_deref()).expect("load CRLs");
    assert!(!crls.is_empty(), "the startup CRL must parse");

    let candidate = ferrum_edge::modes::startup_security::try_load_frontend_tls_candidate(
        &env,
        &tls_policy,
        &crls,
    )
    .expect("startup frontend TLS load")
    .expect("cert and key are configured");
    let startup_material = candidate.client_trust.material.clone();

    // The registry is process-global; this is the only integration test that
    // publishes into it.
    ferrum_edge::tls::client_trust::reset_for_test();

    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let mut handles = ferrum_edge::modes::tls_reload::prepare_proxy_frontend_tls(
        candidate.config.clone(),
        Some(candidate.client_trust),
        &env,
        &tls_policy,
        &crls,
        Some(shutdown_rx),
    );

    let slot = handles.slot.clone().expect("live reload publishes a slot");
    let accepted_slot = handles
        .accepted_slot
        .clone()
        .expect("live reload publishes an accepted candidate for the H3 listener");
    let accepted = accepted_slot
        .load_full()
        .as_ref()
        .clone()
        .expect("the accepted slot is pre-populated at startup");

    let served = slot.load_full().as_ref().clone().expect("slot config");
    assert!(
        Arc::ptr_eq(&accepted.config, &served),
        "the accepted candidate must carry the very ServerConfig the listeners serve, not a \
         separately loaded one"
    );

    // The verifier the H3 endpoint would install enforces the CRLs of this same
    // load: the client certificate the startup CRL revokes is refused.
    let verifier = accepted
        .client_trust
        .verifier
        .as_ref()
        .expect("a configured client CA must yield a verifier");
    assert!(
        verifier
            .verify_client_cert(
                &rustls::pki_types::CertificateDer::from(materials.client_der.clone()),
                &[],
                rustls::pki_types::UnixTime::now(),
            )
            .is_err(),
        "the accepted candidate's verifier must enforce the CRLs of its own load"
    );

    // ...and the identity published alongside it is the identity of exactly
    // that material, which is also the proxy scope's armed baseline. A baseline
    // re-read from the client-CA source could describe a different generation.
    assert_eq!(
        accepted.client_trust.material, startup_material,
        "the accepted candidate's identity must be the startup load's identity"
    );
    assert_eq!(
        ferrum_edge::tls::client_trust::current_material(
            ferrum_edge::tls::ClientTrustScope::ProxyFrontend
        ),
        Some(startup_material),
        "the proxy client-trust baseline must be armed from the served load, not a re-read"
    );

    if let Some(watcher) = handles.watcher_handle.take() {
        watcher.abort();
    }
}
