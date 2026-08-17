//! Admin API first-class namespace CRUD (issue #3955).
//!
//! Covers create/get/list, malformed update bodies, Unicode description
//! bounds, rename (resources move, target collision, derived-only tenants,
//! historical audit namespace retained), delete (empty, occupied, confirmed
//! cascade over every occupancy and ancillary surface), protection of the
//! effective configured namespace from both delete and rename-away, the
//! last-remaining-namespace invariant under concurrent deletes, commit-boundary
//! lease loss, late-step rollback, and file-mode 403s.

use arc_swap::ArcSwap;
use chrono::Utc;
use ferrum_edge::_test_support::lock_namespace_registry_admission_for_test;
use ferrum_edge::admin::{
    AdminState,
    audit::{AuditEvent, AuditListFilter},
    jwt_auth::{JwtConfig, JwtManager},
    serve_admin_on_listener,
};
use ferrum_edge::config::batch_atomicity::{
    NamespaceAdmissionLeaseHold, NamespaceConfigAdmissionLeaseRef,
};
use ferrum_edge::config::db_backend::DatabaseBackend;
use ferrum_edge::config::db_loader::{DatabaseStore, DbPoolConfig};
use ferrum_edge::config::namespace_registry::{
    MAX_NAMESPACE_DESCRIPTION_CHARS, NamespaceRegistryPhase, set_namespace_registry_fault,
};
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
        max_connections: 4,
        min_connections: 0,
        acquire_timeout_seconds: 10,
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

/// A store whose *effective configured namespace* is not `ferrum`, mirroring a
/// deployment that set `FERRUM_NAMESPACE`. The value is applied through the
/// same startup setter `src/modes/database.rs` uses, so the protection path is
/// exercised without touching the process environment.
async fn make_store_serving(dir: &TempDir, namespace: &str) -> DatabaseStore {
    let mut store = make_store(dir).await;
    store.set_effective_default_namespace(namespace);
    store
}

fn admin_state(db: DatabaseStore) -> AdminState {
    admin_state_from_arc(Arc::new(db))
}

fn admin_state_from_arc(db: Arc<dyn DatabaseBackend>) -> AdminState {
    AdminState {
        db: Some(db),
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
    // Struct-update form, not `let mut config = Default::default()` + field
    // assignment: the latter is `clippy::field_reassign_with_default`.
    let config = GatewayConfig {
        known_namespaces: vec!["ferrum".to_string(), "file-only".to_string()],
        ..GatewayConfig::default()
    };
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

async fn send_in_namespace(
    method: reqwest::Method,
    base: &str,
    path: &str,
    token: &str,
    namespace: &str,
    body: Option<Value>,
) -> u16 {
    let mut request = reqwest::Client::new()
        .request(method, format!("{base}{path}"))
        .bearer_auth(token)
        .header("X-Ferrum-Namespace", namespace);
    if let Some(body) = body {
        request = request.json(&body);
    }
    request
        .send()
        .await
        .expect("request succeeds")
        .status()
        .as_u16()
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

async fn count_rows(store: &DatabaseStore, sql: &str, namespace: &str) -> i64 {
    sqlx::query_scalar::<_, i64>(sql)
        .bind(namespace)
        .fetch_one(&store.pool())
        .await
        .unwrap()
}

async fn count_registry_rows(store: &DatabaseStore) -> i64 {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM namespaces")
        .fetch_one(&store.pool())
        .await
        .unwrap()
}

async fn registry_row_exists(store: &DatabaseStore, name: &str) -> bool {
    sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM namespaces WHERE name = ?")
        .bind(name)
        .fetch_one(&store.pool())
        .await
        .unwrap()
        > 0
}

/// Drop the canonical `ferrum` registry row so a test can create an exact
/// two-namespace world. The backfill always seeds `ferrum`, and with no
/// resources under it the name then genuinely no longer exists.
async fn drop_default_registry_row(store: &DatabaseStore) {
    sqlx::query("DELETE FROM namespaces WHERE name = 'ferrum'")
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

    let over_limit = "x".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "too-wordy", "description": over_limit})),
    )
    .await;
    assert_eq!(status, 400, "over-limit description on create: {body:?}");
    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/too-wordy",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "a rejected create must not persist anything");

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "typed", "description": 5})),
    )
    .await;
    assert_eq!(status, 400, "wrong-typed description on create: {body:?}");

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
async fn update_rejects_malformed_fields_without_mutating() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "tenant", "description": "keep me"})),
    )
    .await;
    assert_eq!(status, 201);

    // Every one of these is a 400 with nothing mutated. A non-string
    // `description` must NOT be read as "clear it".
    for body in [
        json!({"description": {}}),
        json!({"description": []}),
        json!({"description": 42}),
        json!({"description": true}),
        json!({"name": null}),
        json!({"name": 7}),
        json!({"name": ["other"]}),
        json!({"name": "bad name"}),
    ] {
        let (status, response) = send(
            reqwest::Method::PUT,
            &base,
            "/namespaces/tenant",
            &token,
            Some(body.clone()),
        )
        .await;
        assert_eq!(status, 400, "malformed update {body:?} -> {response:?}");
    }

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(
        body["description"], "keep me",
        "no rejected update may have touched the stored description"
    );

    // Omitted description leaves it alone; explicit null clears it.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant",
        &token,
        Some(json!({})),
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert_eq!(body["description"], "keep me");

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant",
        &token,
        Some(json!({"description": null})),
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    assert!(
        body.get("description").is_none() || body["description"].is_null(),
        "explicit null clears: {body:?}"
    );
}

#[tokio::test]
async fn update_description_respects_unicode_character_bounds() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();

    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "unicode"})),
    )
    .await;
    assert_eq!(status, 201);

    // `maxLength` is Unicode scalar values: 1024 four-byte characters is over
    // 4 KiB of UTF-8 and must still be accepted.
    let at_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS);
    assert!(at_limit.len() > MAX_NAMESPACE_DESCRIPTION_CHARS);
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/unicode",
        &token,
        Some(json!({"description": at_limit})),
    )
    .await;
    assert_eq!(status, 200, "multibyte description at the limit: {body:?}");
    assert_eq!(
        body["description"].as_str().unwrap().chars().count(),
        MAX_NAMESPACE_DESCRIPTION_CHARS
    );

    let over_limit: String = "🧪".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS + 1);
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/unicode",
        &token,
        Some(json!({"description": over_limit})),
    )
    .await;
    assert_eq!(status, 400, "one character over the limit: {body:?}");

    // Trailing whitespace is trimmed before the length rule applies, so an
    // otherwise-at-limit value padded with spaces is still accepted.
    let padded = format!("  {}  ", "é".repeat(MAX_NAMESPACE_DESCRIPTION_CHARS));
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/unicode",
        &token,
        Some(json!({"description": padded})),
    )
    .await;
    assert_eq!(
        status, 200,
        "trim happens before the length check: {body:?}"
    );
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

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/upstreams",
        &token,
        "tenant-a",
        Some(json!({
            "id": "up-a",
            "name": "up-a-name",
            "targets": [{"host": "10.0.0.1", "port": 8080, "weight": 100}]
        })),
    )
    .await;
    assert_eq!(status, 201, "create upstream in tenant-a");

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

    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-a",
        &token,
        "tenant-b",
        None,
    )
    .await;
    assert_eq!(status, 200, "upstream moved with the tenant");

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

    // The refused rename must have changed nothing on either side.
    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant-b",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "source survives a refused rename");
    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-a",
        &token,
        "tenant-b",
        None,
    )
    .await;
    assert_eq!(status, 200, "resources survive a refused rename");
}

#[tokio::test]
async fn derived_only_namespace_can_be_renamed_and_described() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    // A namespace that exists ONLY because a resource was written under it —
    // no registry row at all. This is the pre-#3955 shape every existing
    // deployment has.
    seed_upstream(&store, "implicit", "up-implicit").await;
    assert!(!registry_row_exists(&store, "implicit").await);
    let store = Arc::new(store);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    // A description-only update materializes the registry row.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/implicit",
        &token,
        Some(json!({"description": "materialized"})),
    )
    .await;
    assert_eq!(status, 200, "derived-only description update: {body:?}");
    assert_eq!(body["description"], "materialized");

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/implicit",
        &token,
        Some(json!({"name": "explicit"})),
    )
    .await;
    assert_eq!(status, 200, "derived-only rename: {body:?}");
    assert_eq!(body["name"], "explicit");
    assert_eq!(
        body["description"], "materialized",
        "an omitted description survives a rename"
    );

    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-implicit",
        &token,
        "explicit",
        None,
    )
    .await;
    assert_eq!(status, 200, "resources moved with the derived tenant");

    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/implicit",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404, "old derived name is gone");
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

    let status = send_in_namespace(
        reqwest::Method::GET,
        &base,
        "/upstreams/up-occupied",
        &token,
        "occupied",
        None,
    )
    .await;
    assert_eq!(status, 200, "a refused delete removes nothing");

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
    assert_eq!(
        status, 409,
        "the effective configured namespace cannot be deleted: {body:?}"
    );
}

#[tokio::test]
async fn confirmed_cascade_removes_every_occupancy_and_ancillary_surface() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/upstreams",
        &token,
        "doomed",
        Some(json!({
            "id": "up-doomed",
            "name": "up-doomed-name",
            "targets": [{"host": "10.0.0.2", "port": 8080, "weight": 100}]
        })),
    )
    .await;
    assert_eq!(status, 201, "seed upstream");

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/proxies",
        &token,
        "doomed",
        Some(json!({
            "id": "px-doomed",
            "listen_path": "/doomed",
            "backend_scheme": "http",
            "backend_host": "10.0.0.2",
            "backend_port": 8080,
            "strip_listen_path": true
        })),
    )
    .await;
    assert_eq!(status, 201, "seed proxy");

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/consumers",
        &token,
        "doomed",
        Some(json!({"id": "cons-doomed", "username": "doomed-user", "credentials": {}})),
    )
    .await;
    assert_eq!(status, 201, "seed consumer");

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/plugins/config",
        &token,
        "doomed",
        Some(json!({
            "id": "pl-doomed",
            "plugin_name": "correlation_id",
            "scope": "proxy",
            "proxy_id": "px-doomed",
            "config": {}
        })),
    )
    .await;
    assert_eq!(status, 201, "seed plugin config");

    // Surfaces with no admin write endpoint: seeded directly so the cascade is
    // proved against the real row shapes.
    let now = Utc::now().to_rfc3339();
    sqlx::query(
        "INSERT INTO gateway_trust_bundles \
         (namespace, id, trust_domain, bundle, revision, updated_by, created_at, updated_at) \
         VALUES ('doomed', 'tb-doomed', 'doomed.local', '[]', 1, 'test', ?, ?)",
    )
    .bind(&now)
    .bind(&now)
    .execute(&store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO api_specs \
         (id, namespace, proxy_id, spec_version, spec_format, spec_content, content_encoding, \
          uncompressed_size, content_hash, tags, server_urls, operation_count, resource_hash, \
          created_at, updated_at) \
         VALUES ('spec-doomed', 'doomed', 'px-doomed', '3.0.0', 'json', X'00', 'gzip', 1, \
                 'hash', '[]', '[]', 0, '', ?, ?)",
    )
    .bind(&now)
    .bind(&now)
    .execute(&store.pool())
    .await
    .unwrap();
    sqlx::query(
        "INSERT INTO proxy_route_locks (namespace, route_key_hash, created_at) \
         VALUES ('doomed', 'stale-bucket', ?)",
    )
    .bind(&now)
    .execute(&store.pool())
    .await
    .unwrap();

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/doomed?confirm=true",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204, "confirmed cascade: {body:?}");

    for sql in [
        "SELECT COUNT(*) FROM proxies WHERE namespace = ?",
        "SELECT COUNT(*) FROM consumers WHERE namespace = ?",
        "SELECT COUNT(*) FROM consumer_identity_index WHERE namespace = ?",
        "SELECT COUNT(*) FROM consumer_credential_index WHERE namespace = ?",
        "SELECT COUNT(*) FROM plugin_configs WHERE namespace = ?",
        "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
        "SELECT COUNT(*) FROM api_specs WHERE namespace = ?",
        "SELECT COUNT(*) FROM gateway_trust_bundles WHERE namespace = ?",
        "SELECT COUNT(*) FROM proxy_route_locks WHERE namespace = ?",
        "SELECT COUNT(*) FROM namespaces WHERE name = ?",
    ] {
        assert_eq!(
            count_rows(&store, sql, "doomed").await,
            0,
            "cascade must clear: {sql}"
        );
    }

    // Polling tombstones are deliberately RETAINED so a gateway serving the
    // deleted namespace converges instead of silently keeping stale config.
    assert!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM config_changes WHERE namespace = ? AND operation = 'delete'",
            "doomed",
        )
        .await
            > 0,
        "the cascade must leave delete tombstones for pollers"
    );

    let (status, _body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/doomed",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 404);
}

#[tokio::test]
async fn effective_configured_namespace_is_protected_from_delete_and_rename() {
    let dir = TempDir::new().unwrap();
    // This gateway serves `tenant-prod`, NOT `ferrum`. The protection must
    // follow the resolved configuration, not the hardcoded default.
    let store = Arc::new(make_store_serving(&dir, "tenant-prod").await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "tenant-prod", "description": "live"})),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/tenant-prod",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "configured namespace cannot be deleted: {body:?}"
    );

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-prod",
        &token,
        Some(json!({"name": "tenant-prod-renamed"})),
    )
    .await;
    assert_eq!(
        status, 409,
        "a rename is a removal of the old name: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "tenant-prod").await
            && !registry_row_exists(&store, "tenant-prod-renamed").await,
        "the refused rename must not have created the target"
    );

    // Description-only updates of the protected namespace stay allowed.
    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/tenant-prod",
        &token,
        Some(json!({"description": "still live"})),
    )
    .await;
    assert_eq!(status, 200, "description-only update is allowed: {body:?}");
    assert_eq!(body["description"], "still live");

    // `ferrum` is NOT this process's namespace, so it is an ordinary tenant.
    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/ferrum",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 204,
        "a non-configured `ferrum` is deletable: {body:?}"
    );
}

#[tokio::test]
async fn concurrent_deletes_cannot_remove_the_last_namespace() {
    let dir = TempDir::new().unwrap();
    // No namespace of this name exists, so neither `alpha` nor `beta` is
    // protected as the configured namespace and the last-remaining invariant
    // is the only thing standing between the two deletes and an empty world.
    let store = Arc::new(make_store_serving(&dir, "not-present").await);
    drop_default_registry_row(&store).await;
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    for name in ["alpha", "beta"] {
        let (status, body) = send(
            reqwest::Method::POST,
            &base,
            "/namespaces",
            &token,
            Some(json!({ "name": name })),
        )
        .await;
        assert_eq!(status, 201, "create {name}: {body:?}");
    }

    let (base_a, base_b) = (base.clone(), base.clone());
    let (token_a, token_b) = (token.clone(), token.clone());
    let first = tokio::spawn(async move {
        send(
            reqwest::Method::DELETE,
            &base_a,
            "/namespaces/alpha",
            &token_a,
            None,
        )
        .await
    });
    let second = tokio::spawn(async move {
        send(
            reqwest::Method::DELETE,
            &base_b,
            "/namespaces/beta",
            &token_b,
            None,
        )
        .await
    });
    let (first, second) = (first.await.unwrap(), second.await.unwrap());

    let statuses = [first.0, second.0];
    assert!(
        statuses.contains(&204),
        "exactly one delete should succeed: {statuses:?}"
    );
    assert!(
        statuses.contains(&409),
        "the other must be refused as the last remaining namespace: {statuses:?} \
         ({:?} / {:?})",
        first.1,
        second.1
    );

    assert_eq!(
        count_registry_rows(&store).await,
        1,
        "the registry must never be emptied by concurrent deletes"
    );
}

#[tokio::test]
async fn a_late_transaction_failure_rolls_the_whole_tenant_back() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let status = send_in_namespace(
        reqwest::Method::POST,
        &base,
        "/upstreams",
        &token,
        "rollback",
        Some(json!({
            "id": "up-rollback",
            "name": "up-rollback-name",
            "targets": [{"host": "10.0.0.3", "port": 8080, "weight": 100}]
        })),
    )
    .await;
    assert_eq!(status, 201);
    let (status, _body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/rollback",
        &token,
        Some(json!({"description": "registered"})),
    )
    .await;
    assert_eq!(status, 200);

    // Trip AFTER the resource rows, the guard rows, and the registry row have
    // all been written inside the transaction. A happy-path test can never
    // reach this step.
    set_namespace_registry_fault("rollback", Some(NamespaceRegistryPhase::LastNamespaceCheck));
    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/rollback?confirm=true",
        &token,
        None,
    )
    .await;
    set_namespace_registry_fault("rollback", None);
    assert_eq!(status, 500, "an injected late failure is a server error");

    assert!(
        registry_row_exists(&store, "rollback").await,
        "the registry row must be rolled back"
    );
    assert_eq!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
            "rollback"
        )
        .await,
        1,
        "cascade-deleted resources must be rolled back"
    );

    // Without the fault the same request succeeds, proving the rollback was
    // the fault and not a broken code path.
    let (status, _body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/rollback?confirm=true",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 204);
    assert!(!registry_row_exists(&store, "rollback").await);
}

#[tokio::test]
async fn a_lost_admission_lease_fails_closed_at_the_commit_boundary() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({"name": "leased"})),
    )
    .await;
    assert_eq!(status, 201);

    // Handler path: a lease reported lost at the commit gate is the retryable
    // fail-closed 503, and nothing is deleted.
    set_namespace_registry_fault("leased", Some(NamespaceRegistryPhase::LeaseLost));
    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/leased",
        &token,
        None,
    )
    .await;
    set_namespace_registry_fault("leased", None);
    assert_eq!(status, 503, "lost lease is retryable: {body:?}");
    assert_eq!(body["rollback"], "not_needed");
    assert!(registry_row_exists(&store, "leased").await);

    // Backend path with a REAL but wrong lease identity: the commit-boundary
    // re-verification must refuse it even though the caller holds the local
    // guards, and nothing may become durable.
    let db: Arc<dyn DatabaseBackend> = store.clone();
    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["leased"])
        .await
        .expect("registry admission");
    let mut holds = admission.holds();
    // Corrupt exactly the affected namespace's lease, leaving the global
    // registry lease genuinely held.
    let stolen = NamespaceAdmissionLeaseHold {
        key: "leased",
        lease: NamespaceConfigAdmissionLeaseRef {
            owner: "some-other-writer",
            generation: 1,
        },
    };
    for hold in holds.iter_mut() {
        if hold.key == "leased" {
            *hold = stolen;
        }
    }
    let error = store
        .delete_namespace("leased", true, &holds)
        .await
        .expect_err("a stolen lease must abort the commit");
    assert!(
        ferrum_edge::config::db_backend::is_batch_admission_lease_lost(&error),
        "expected a typed lease-lost error, got: {error}"
    );
    drop(admission);
    assert!(
        registry_row_exists(&store, "leased").await,
        "an unverified write must never become durable"
    );
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
    let store = Arc::new(make_store(&dir).await);
    let db: Arc<dyn DatabaseBackend> = store.clone();
    let now = Utc::now();
    let record = ferrum_edge::config::namespace_registry::NamespaceRecord::new(
        "direct".to_string(),
        Some("via store".to_string()),
        now,
    );

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["direct"])
        .await
        .expect("registry admission");
    store
        .create_namespace(&record, &admission.holds())
        .await
        .unwrap();
    drop(admission);
    assert!(store.namespace_name_in_use("direct").await.unwrap());
    assert!(!store.namespace_has_resources("direct").await.unwrap());

    seed_upstream(&store, "direct", "up-direct").await;
    assert!(store.namespace_has_resources("direct").await.unwrap());

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["direct", "renamed"])
        .await
        .expect("registry admission");
    let updated = store
        .update_namespace(
            "direct",
            "renamed",
            Some(Some("moved".into())),
            &admission.holds(),
        )
        .await
        .unwrap();
    drop(admission);
    assert_eq!(updated.name, "renamed");
    assert!(!store.namespace_name_in_use("direct").await.unwrap());
    assert!(store.namespace_name_in_use("renamed").await.unwrap());

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["renamed"])
        .await
        .expect("registry admission");
    let err = store
        .delete_namespace("renamed", false, &admission.holds())
        .await
        .unwrap_err();
    assert!(
        ferrum_edge::config::namespace_registry::is_namespace_registry_error(&err).is_some(),
        "unconfirmed occupied delete is a typed 409: {err}"
    );
    assert!(
        store
            .delete_namespace("renamed", true, &admission.holds())
            .await
            .unwrap()
    );
    drop(admission);
    assert!(!store.namespace_name_in_use("renamed").await.unwrap());
}

#[tokio::test]
async fn namespace_rename_retains_historical_audit_namespace() {
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store(&dir).await);
    let db: Arc<dyn DatabaseBackend> = store.clone();
    let now = Utc::now();
    let record = ferrum_edge::config::namespace_registry::NamespaceRecord::new(
        "hist-a".to_string(),
        None,
        now,
    );

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["hist-a"])
        .await
        .expect("registry admission");
    store
        .create_namespace(&record, &admission.holds())
        .await
        .unwrap();
    drop(admission);

    seed_upstream(&store, "hist-a", "up-hist").await;
    store
        .insert_audit_event(&AuditEvent {
            id: "hist-event-1".to_string(),
            ts: now,
            actor: "namespace-admin".to_string(),
            action: "update".to_string(),
            resource_type: "upstream".to_string(),
            resource_id: "up-hist".to_string(),
            namespace: "hist-a".to_string(),
            source_address: String::new(),
            request_id: String::new(),
            outcome: "success".to_string(),
            diff: json!({ "after": { "id": "up-hist" } }),
        })
        .await
        .unwrap();

    let admission = lock_namespace_registry_admission_for_test(db.clone(), &["hist-a", "hist-b"])
        .await
        .expect("registry admission");
    store
        .update_namespace("hist-a", "hist-b", None, &admission.holds())
        .await
        .unwrap();
    drop(admission);

    assert_eq!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
            "hist-a"
        )
        .await,
        0,
        "live resource rows must move with the tenant"
    );
    assert_eq!(
        count_rows(
            &store,
            "SELECT COUNT(*) FROM upstreams WHERE namespace = ?",
            "hist-b"
        )
        .await,
        1,
        "live resource rows must land under the new name"
    );

    let historical = store
        .list_audit_events(
            "hist-a",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(historical.total, 1, "prior audit rows stay under hist-a");
    assert_eq!(historical.items[0].id, "hist-event-1");
    assert_eq!(historical.items[0].namespace, "hist-a");

    let renamed = store
        .list_audit_events(
            "hist-b",
            &AuditListFilter {
                limit: 50,
                offset: 0,
                ..Default::default()
            },
        )
        .await
        .unwrap();
    assert_eq!(
        renamed.total, 0,
        "rename must not rewrite historical audit_events onto the new name"
    );
}

#[tokio::test]
async fn last_registry_row_cannot_disappear_behind_a_derived_only_name() {
    // Race this invariant prevents: delete registered A while derived-only B
    // still has one resource; concurrently ordinary DELETE removes B's last
    // resource. If last-remaining counted the GET union, A's delete would
    // observe B and commit, then B's resource delete would leave zero names.
    // Registry-row authority cannot race with writers outside the global lease.
    let dir = TempDir::new().unwrap();
    let store = Arc::new(make_store_serving(&dir, "not-present").await);
    drop_default_registry_row(&store).await;
    let (base, _shutdown) = start_admin(admin_state_from_arc(store.clone())).await;
    let token = admin_token();

    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "alpha" })),
    )
    .await;
    assert_eq!(status, 201, "create the sole registry row: {body:?}");
    seed_upstream(&store, "ghost", "up-ghost").await;
    assert!(
        !registry_row_exists(&store, "ghost").await,
        "ordinary resource writes must not insert a registry row"
    );

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces?limit=100",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200, "{body:?}");
    let names: Vec<&str> = body["data"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(|v| v.as_str())
        .collect();
    assert!(
        names.contains(&"alpha") && names.contains(&"ghost"),
        "GET remains registry ∪ derived names: {body:?}"
    );

    let (status, body) = send(
        reqwest::Method::DELETE,
        &base,
        "/namespaces/alpha",
        &token,
        None,
    )
    .await;
    assert_eq!(
        status, 409,
        "the last registry row must survive even while a derived-only name has \
         resources: {body:?}"
    );
    assert!(
        body["error"]
            .as_str()
            .unwrap_or("")
            .contains("last remaining"),
        "typed last-remaining refusal: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "alpha").await,
        "the last registry row must still be durable"
    );
}

#[tokio::test]
async fn namespace_rename_fails_closed_on_a_target_mtls_dns_restore_fence() {
    // `alpha` sorts before `zeta`, so a rename zeta→alpha locks the target
    // first. A restore owner on alpha must reject the rename. Locking only
    // the source would write resources into the fenced target.
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store.clone())).await;
    let token = admin_token();
    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "zeta" })),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    sqlx::query(
        "INSERT INTO mtls_dns_admission_locks (namespace, updated_at, restore_owner) \
         VALUES (?, ?, ?)",
    )
    .bind("alpha")
    .bind(Utc::now().to_rfc3339())
    .bind("restore-owner-uuid")
    .execute(&store.pool())
    .await
    .unwrap();

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/zeta",
        &token,
        Some(json!({ "name": "alpha" })),
    )
    .await;
    assert_eq!(
        status, 503,
        "target restore fence must fail closed: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "zeta").await && !registry_row_exists(&store, "alpha").await,
        "the refused rename must not have created the target"
    );
}

#[tokio::test]
async fn namespace_rename_fails_closed_on_a_source_mtls_dns_restore_fence() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store.clone())).await;
    let token = admin_token();
    let (status, body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "alpha" })),
    )
    .await;
    assert_eq!(status, 201, "{body:?}");

    sqlx::query(
        "INSERT INTO mtls_dns_admission_locks (namespace, updated_at, restore_owner) \
         VALUES (?, ?, ?)",
    )
    .bind("alpha")
    .bind(Utc::now().to_rfc3339())
    .bind("restore-owner-uuid")
    .execute(&store.pool())
    .await
    .unwrap();

    let (status, body) = send(
        reqwest::Method::PUT,
        &base,
        "/namespaces/alpha",
        &token,
        Some(json!({ "name": "zeta" })),
    )
    .await;
    assert_eq!(
        status, 503,
        "source restore fence must fail closed: {body:?}"
    );
    assert!(
        registry_row_exists(&store, "alpha").await && !registry_row_exists(&store, "zeta").await,
        "the refused rename must not have created the target"
    );
}

#[tokio::test]
async fn update_rejects_empty_or_non_object_bodies() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();
    let (status, _body) = send(
        reqwest::Method::POST,
        &base,
        "/namespaces",
        &token,
        Some(json!({ "name": "tenant", "description": "keep" })),
    )
    .await;
    assert_eq!(status, 201);

    for raw in ["", "null", "[]", "42", "\"tenant\""] {
        let response = reqwest::Client::new()
            .request(reqwest::Method::PUT, format!("{base}/namespaces/tenant"))
            .bearer_auth(&token)
            .header("Content-Type", "application/json")
            .body(raw.to_string())
            .send()
            .await
            .expect("request succeeds");
        assert_eq!(
            response.status().as_u16(),
            400,
            "non-object PUT body {raw:?} must be 400"
        );
    }

    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/tenant",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(body["description"], "keep");
}

#[tokio::test]
async fn corrupt_registry_row_is_not_served_as_plausible_detail() {
    let dir = TempDir::new().unwrap();
    let store = make_store(&dir).await;
    sqlx::query("UPDATE namespaces SET created_at = 'not-a-timestamp' WHERE name = 'ferrum'")
        .execute(&store.pool())
        .await
        .unwrap();
    let (base, _shutdown) = start_admin(admin_state(store)).await;
    let token = admin_token();
    let (status, body) = send(
        reqwest::Method::GET,
        &base,
        "/namespaces/ferrum",
        &token,
        None,
    )
    .await;
    assert_eq!(status, 500, "corrupt timestamps must fail closed: {body:?}");
    let error = body["error"].as_str().unwrap_or("");
    assert!(
        error.contains(ferrum_edge::config::namespace_registry::NamespaceRegistryCorrupt::MESSAGE),
        "client must see the static corrupt message: {body:?}"
    );
    assert!(
        !error.contains("not-a-timestamp") && !error.contains("ferrum"),
        "raw corrupt values must not be echoed: {body:?}"
    );
}
