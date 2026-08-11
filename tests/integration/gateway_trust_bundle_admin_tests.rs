//! Admin-surface coverage for the namespace-keyed gateway trust-bundle
//! resource (issue #3727).
//!
//! What is proved here is what only the real HTTP path can prove:
//!
//! - the stored namespace and the default id come from the authenticated
//!   `X-Ferrum-Namespace` header, never from the request body;
//! - `updated_by` is the verified JWT subject, never a body value;
//! - a backup carries the trust section and a restore of it round-trips the
//!   material, with `revision` staying server-assigned;
//! - a PRESENT-but-empty section is an explicit revocation;
//! - a section with more than one record for the target namespace is refused
//!   BEFORE the destructive clear, so a bad payload cannot leave a partially
//!   mutated trust generation behind.

use arc_swap::ArcSwap;
use base64::Engine;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-trust-bundles-32chars!!";
const JWT_ISSUER: &str = "test-ferrum-edge";

fn jwt_manager() -> JwtManager {
    JwtManager::new(JwtConfig {
        secret: JWT_SECRET.to_string(),
        issuer: JWT_ISSUER.to_string(),
        audience: None,
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    })
}

fn admin_token(subject: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": subject,
        "role": "admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": uuid::Uuid::new_v4().to_string(),
    });
    encode(
        &Header::new(jsonwebtoken::Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(JWT_SECRET.as_bytes()),
    )
    .expect("token encodes")
}

fn test_pool_config() -> DbPoolConfig {
    DbPoolConfig {
        max_connections: 2,
        min_connections: 0,
        acquire_timeout_seconds: 5,
        idle_timeout_seconds: 60,
        max_lifetime_seconds: 300,
        connect_timeout_seconds: 5,
        statement_timeout_seconds: 0,
    }
}

async fn make_store(dir: &TempDir) -> DatabaseStore {
    let db_path = dir
        .path()
        .join(format!("trust-admin-{}.db", uuid::Uuid::new_v4()));
    let url = format!("sqlite:{}?mode=rwc", db_path.to_string_lossy());
    DatabaseStore::connect_with_pool_config("sqlite", &url, test_pool_config())
        .await
        .expect("connect sqlite store")
}

fn admin_state(db: DatabaseStore) -> AdminState {
    AdminState {
        db: Some(Arc::new(db)),
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: None,
        proxy_state: None,
        mode: "database".to_string(),
        read_only: false,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: 100,
        admin_spec_max_body_size_mib: 25,
        reserved_ports: std::collections::HashSet::new(),
        stream_proxy_bind_address: "0.0.0.0".to_string(),
        admin_allowed_cidrs: Arc::new(ferrum_edge::proxy::client_ip::TrustedProxies::none()),
        cached_db_health: Arc::new(ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: 10,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: 10,
        admin_request_limits: Default::default(),
        backend_allow_ips: ferrum_edge::config::BackendEgressPolicy::unrestricted(),
        external_ref_policy: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::ExternalRefProcessPolicy::default(),
        ),
        external_ref_loader: std::sync::Arc::new(
            ferrum_edge::admin::api_specs::DefaultExternalDocumentLoader::default(),
        ),
    }
}

async fn start_admin(state: AdminState) -> (String, tokio::sync::watch::Sender<bool>) {
    let addr: SocketAddr = "127.0.0.1:0".parse().expect("loopback addr parses");
    let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let listener = tokio::net::TcpListener::bind(addr).await.expect("bind");
    let actual = listener.local_addr().expect("local addr");
    tokio::spawn(async move {
        let _ = serve_admin_on_listener(
            listener,
            state,
            shutdown_rx,
            None,
            ferrum_edge::admin::AdminConnLimiter::unlimited(),
        )
        .await;
    });
    for _ in 0..200 {
        if tokio::net::TcpStream::connect(actual).await.is_ok() {
            return (format!("http://{actual}"), shutdown_tx);
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("admin listener at {actual} never became ready");
}

fn root_ca_der_base64(common_name: &str) -> String {
    let key =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("test CA key generates");
    let mut params =
        rcgen::CertificateParams::new(Vec::<String>::new()).expect("test CA params build");
    params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    params
        .distinguished_name
        .push(rcgen::DnType::CommonName, common_name);
    let cert = params.self_signed(&key).expect("test CA self-signs");
    base64::engine::general_purpose::STANDARD.encode(cert.der())
}

async fn post_json(base: &str, path: &str, namespace: &str, body: Value) -> (u16, Value) {
    let response = reqwest::Client::new()
        .post(format!("{base}{path}"))
        .bearer_auth(admin_token("restore-admin"))
        .header("X-Ferrum-Namespace", namespace)
        .json(&body)
        .send()
        .await
        .expect("POST succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn get_json(base: &str, path: &str, namespace: &str) -> (u16, Value) {
    let response = reqwest::Client::new()
        .get(format!("{base}{path}"))
        .bearer_auth(admin_token("restore-admin"))
        .header("X-Ferrum-Namespace", namespace)
        .send()
        .await
        .expect("GET succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

fn bundle_body(trust_domain: &str, authority: &str) -> Value {
    json!({
        "local": {
            "trust_domain": trust_domain,
            "x509_authorities": [authority],
        }
    })
}

// ── Server-owned namespace and id ───────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_hostile_body_namespace_influences_neither_the_stored_namespace_nor_the_id() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    // The body claims another tenant and omits `id`. The stored record must be
    // keyed entirely by the authenticated header value.
    let (status, created) = post_json(
        &base,
        "/gateway-trust-bundles",
        "tenant-a",
        json!({
            "namespace": "tenant-b",
            "trust_domain": "a.local",
            "updated_by": "attacker",
            "bundle": bundle_body("a.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201, "create must succeed: {created}");
    assert_eq!(created["namespace"], "tenant-a");
    assert_eq!(
        created["id"], "tenant-a",
        "an omitted id must default to the SERVER-selected namespace, not the body's"
    );
    assert_eq!(
        created["updated_by"], "restore-admin",
        "attribution must come from the verified JWT subject"
    );
    assert_eq!(created["revision"], 1);

    // tenant-b must have received nothing at all.
    let (status, listed) = get_json(&base, "/gateway-trust-bundles", "tenant-b").await;
    assert_eq!(status, 200);
    assert_eq!(
        listed["data"].as_array().map(Vec::len).unwrap_or_default(),
        0,
        "the body namespace must not have created a record in another tenant"
    );
}

// ── Backup / restore round trip ─────────────────────────────────────────────

#[tokio::test(flavor = "multi_thread")]
async fn a_backup_round_trips_the_trust_resource_with_server_assigned_revisions() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, _) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201);

    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);
    let section = backup["gateway_trust_bundles"]
        .as_array()
        .expect("a database-backed backup carries the trust section");
    assert_eq!(section.len(), 1);
    assert_eq!(section[0]["trust_domain"], "cluster.local");
    assert_eq!(backup["counts"]["gateway_trust_bundles"], 1);

    // Restore the backup verbatim.
    let (status, restored) = post_json(&base, "/restore?confirm=true", "ferrum", backup).await;
    assert_eq!(status, 200, "restore must succeed: {restored}");
    assert_eq!(restored["restored"]["gateway_trust_bundles"], 1);

    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(after["trust_domain"], "cluster.local");
    assert_eq!(
        after["bundle"]["local"]["x509_authorities"][0], authority,
        "the restored material must be byte-identical"
    );
    assert!(
        after["revision"].as_u64().unwrap_or_default() >= 2,
        "revision is server-assigned and monotonic across a restore, got {}",
        after["revision"]
    );

    // The status view reports a namespace-safe generation identity and no
    // process-wide revision.
    let (status, view) = get_json(&base, "/gateway-trust/status", "ferrum").await;
    assert_eq!(status, 200);
    assert_eq!(view["configured"], true);
    let generation = view["generation"].as_str().expect("a generation identity");
    assert!(!generation.is_empty());
    assert!(
        !generation.contains(&authority[..16]),
        "the generation identity is a digest and must not carry material"
    );
    assert!(view["process"]["published_revision"].is_null());
}

#[tokio::test(flavor = "multi_thread")]
async fn a_present_but_empty_section_revokes_and_an_absent_one_does_not() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, _) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201);

    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);

    // An ABSENT section says nothing about trust: restoring a backup taken
    // before the resource existed must not revoke a namespace's roots.
    let mut legacy = backup.clone();
    legacy
        .as_object_mut()
        .expect("backup is an object")
        .remove("gateway_trust_bundles");
    let (status, body) = post_json(&base, "/restore?confirm=true", "ferrum", legacy).await;
    assert_eq!(status, 200, "legacy restore must succeed: {body}");
    let (status, _) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(
        status, 200,
        "an absent trust section must leave the record in place"
    );

    // A PRESENT-but-empty section is an explicit revocation.
    let mut revoking = backup.clone();
    revoking["gateway_trust_bundles"] = json!([]);
    let (status, body) = post_json(&base, "/restore?confirm=true", "ferrum", revoking).await;
    assert_eq!(status, 200, "revoking restore must succeed: {body}");
    assert_eq!(body["restored"]["gateway_trust_bundles"], 0);
    let (status, _) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(
        status, 404,
        "a present-but-empty section must revoke the namespace's record"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn more_than_one_record_is_refused_before_anything_is_deleted() {
    let dir = TempDir::new().expect("temp dir");
    let (base, _shutdown) = start_admin(admin_state(make_store(&dir).await)).await;
    let authority = root_ca_der_base64("root");

    let (status, _) = post_json(
        &base,
        "/gateway-trust-bundles",
        "ferrum",
        json!({
            "trust_domain": "cluster.local",
            "bundle": bundle_body("cluster.local", &authority),
        }),
    )
    .await;
    assert_eq!(status, 201);

    let (status, backup) = get_json(&base, "/backup", "ferrum").await;
    assert_eq!(status, 200);

    // Two records for one namespace: the reconciler must not silently take the
    // first, because which one wins would then depend on payload order.
    let mut hostile = backup.clone();
    let mut second = backup["gateway_trust_bundles"][0].clone();
    second["id"] = json!("second");
    second["namespace"] = json!("tenant-b");
    hostile["gateway_trust_bundles"] = json!([backup["gateway_trust_bundles"][0], second]);

    let (status, body) = post_json(&base, "/restore?confirm=true", "ferrum", hostile).await;
    assert_eq!(status, 400, "a non-singleton section must be refused: {body}");
    assert!(
        body["error"]
            .as_str()
            .unwrap_or_default()
            .contains("NOT deleted"),
        "the refusal must happen before the destructive clear: {body}"
    );

    // Nothing was mutated: the original generation is intact.
    let (status, after) = get_json(&base, "/gateway-trust-bundles/ferrum", "ferrum").await;
    assert_eq!(status, 200, "the refused restore must not revoke trust");
    assert_eq!(after["revision"], 1, "and must not bump the revision either");
}
