//! Admin API first-class namespace CRUD (issue #3955).
//!
//! Covers create, duplicate, invalid name, get, rename (resources move),
//! delete empty, delete non-empty 409, confirmed cascade, and file-mode 403.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::admin::{
    AdminState,
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::types::GatewayConfig;
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use std::sync::Arc;
use tempfile::TempDir;

const JWT_SECRET: &str = "test-secret-key-for-namespace-crud-32ch";
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

fn token_with_role(role: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": JWT_ISSUER,
        "sub": "namespace-admin",
        "role": role,
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

fn admin_token() -> String {
    token_with_role("admin")
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
        .join(format!("ns-admin-{}.db", uuid::Uuid::new_v4()));
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
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
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

fn file_mode_state() -> AdminState {
    let mut config = GatewayConfig::default();
    config.known_namespaces = vec!["ferrum".to_string(), "file-only".to_string()];
    AdminState {
        db: None,
        jwt_manager: jwt_manager(),
        metrics_auth: Default::default(),
        cached_config: Some(Arc::new(ArcSwap::new(Arc::new(config)))),
        proxy_state: None,
        mode: "file".to_string(),
        read_only: true,
        admin_audit_enabled: false,
        admin_audit_fallback_dir: Some(crate::common::isolated_audit_fallback_dir()),
        admin_require_namespace_claim: false,
        startup_ready: None,
        serving_degraded: None,
        serving_listener_failures: None,
        gateway_listener_status: None,
        gateway_listener_failure_fails_readiness: false,
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

async fn send(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    body: Option<Value>,
) -> (u16, Value) {
    let mut request = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.expect("request succeeds");
    let status = response.status().as_u16();
    let body = response.json::<Value>().await.unwrap_or_else(|_| json!({}));
    (status, body)
}

async fn seed_upstream(store: &DatabaseStore, namespace: &str, id: &str) {
    sqlx::query("INSERT INTO upstreams (id, namespace, name, targets) VALUES (?, ?, ?, '[]')")
        .bind(id)
        .bind(namespace)
        .bind(format!("{id}-name"))
        .execute(&store.pool())
        .await
        .unwrap();
}

#[tokio::test]
async fn create_get_list_and_reject_duplicates_and_invalid_names() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "staging", "description": "pre-prod"})),
    )
    .await;
    assert_eq!(status, 201, "create empty tenant: {body:?}");
    assert_eq!(body["name"], "staging");
    assert_eq!(body["description"], "pre-prod");
    assert!(body["created_at"].as_str().is_some());
    assert!(body["updated_at"].as_str().is_some());

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/staging",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "get created tenant: {body:?}");
    assert_eq!(body["name"], "staging");
    assert_eq!(body["description"], "pre-prod");

    let (status, body) = send(reqwest::Method::GET, &base, "/namespaces", &token, None).await;
    assert_eq!(status, 200);
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert!(
        names.contains(&"ferrum") && names.contains(&"staging"),
        "list stays string[] and includes registry names: {names:?}"
    );

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "staging"})),
    )
    .await;
    assert_eq!(status, 409, "duplicate registry name: {body:?}");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "bad name"})),
    )
    .await;
    assert_eq!(status, 400, "invalid name: {body:?}");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token_with_role("operator"),
        Some(json!({"name": "ops-denied"})),
    )
    .await;
    assert_eq!(status, 403, "operator cannot create: {body:?}");
}

#[tokio::test]
async fn rename_moves_resources_and_rejects_target_collision() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "tenant-a"})),
    )
    .await;
    assert_eq!(status, 201, "create tenant-a: {body:?}");

    let response = reqwest::Client::new()
        .post(format!("{base}/upstreams"))
        .bearer_auth(&token)
        .header("X-Ferrum-Namespace", "tenant-a")
        .json(&json!({
            "id": "up-a",
            "name": "up-a-name",
            "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
        }))
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        201,
        "create upstream in tenant-a"
    );

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-a",
        &token,
        Some(json!({"name": "tenant-b", "description": "moved"})),
    )
    .await;
    assert_eq!(status, 200, "rename: {body:?}");
    assert_eq!(body["name"], "tenant-b");
    assert_eq!(body["description"], "moved");

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant-a",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "old name is gone: {body:?}");

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant-b",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "new name exists: {body:?}");

    let (status, body) = send(reqwest::Method::GET, &base, "/upstreams/up-a", &token, None).await;
    // Default X-Ferrum-Namespace is ferrum; the moved upstream lives in tenant-b.
    assert_eq!(
        status, 404,
        "upstream is not in default namespace: {body:?}"
    );

    let response = reqwest::Client::new()
        .get(format!("{base}/upstreams/up-a"))
        .bearer_auth(&token)
        .header("X-Ferrum-Namespace", "tenant-b")
        .send()
        .await
        .unwrap();
    assert_eq!(
        response.status().as_u16(),
        200,
        "upstream moved with the tenant"
    );

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "taken"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-b",
        &token,
        Some(json!({"name": "taken"})),
    )
    .await;
    assert_eq!(status, 409, "rename onto an existing name: {body:?}");
}

#[tokio::test]
async fn delete_empty_ok_non_empty_conflicts_unless_confirmed() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    seed_upstream(&store, "occupied", "up-occupied").await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "empty-tenant"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/empty-tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204);

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/empty-tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "{body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/occupied",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 409, "non-empty without confirm: {body:?}");

    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/occupied?confirm=true",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204);

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/ferrum",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 409, "process default cannot be deleted: {body:?}");
}

#[tokio::test]
async fn file_mode_writes_are_forbidden() {
    let (base, _shutdown) = start_admin(file_mode_state()).await;
    let token = admin_token();

    let (status, body) = send(reqwest::Method::GET, &base, "/namespaces", &token, None).await;
    assert_eq!(status, 200);
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    assert_eq!(names, ["ferrum", "file-only"]);

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/file-only",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body["name"], "file-only");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "new-file-ns"})),
    )
    .await;
    assert_eq!(status, 403, "file-mode create: {body:?}");

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/file-only",
        &token,
        Some(json!({"description": "nope"})),
    )
    .await;
    assert_eq!(status, 403, "file-mode update: {body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/file-only",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 403, "file-mode delete: {body:?}");
}

#[tokio::test]
async fn store_create_rename_delete_round_trip() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let now = Utc::now();
    let record = ferrum_edge::config::namespace_registry::NamespaceRecord::new(
        "direct".to_string(),
        Some("via store".to_string()),
        now,
    );
    store.create_namespace(&record).await.unwrap();
    assert!(store.namespace_name_in_use("direct").await.unwrap());
    assert!(!store.namespace_has_resources("direct").await.unwrap());

    seed_upstream(&store, "direct", "up-direct").await;
    assert!(store.namespace_has_resources("direct").await.unwrap());

    let updated = store
        .update_namespace("direct", "renamed", Some(Some("moved".into())))
        .await
        .unwrap();
    assert_eq!(updated.name, "renamed");
    assert!(!store.namespace_name_in_use("direct").await.unwrap());
    assert!(store.namespace_name_in_use("renamed").await.unwrap());

    let err = store.delete_namespace("renamed", false).await.unwrap_err();
    assert!(
        ferrum_edge::config::namespace_registry::is_namespace_registry_error(&err).is_some(),
        "unconfirmed occupied delete is a typed 409: {err}"
    );
    assert!(store.delete_namespace("renamed", true).await.unwrap());
    assert!(!store.namespace_name_in_use("renamed").await.unwrap());
}
