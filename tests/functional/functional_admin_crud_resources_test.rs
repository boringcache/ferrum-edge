//! Functional admin CRUD resource coverage.
//!
//! Existing functional suites cover individual admin surfaces such as proxy
//! routing, plugin CRUD, backup/restore, Mongo connectivity, and file-mode
//! startup/reload. These tests fill the cross-resource gaps:
//! - full Proxy/Consumer/PluginConfig/Upstream CRUD on one SQL backend
//! - the same CRUD matrix on MongoDB
//! - file-mode reload updates and deletes resource-backed runtime state while
//!   admin writes remain read-only

use crate::common::{DbType, TestGateway, spawn_http_identifying};
use reqwest::{Client, StatusCode};
use serde_json::{Value, json};
use std::time::{Duration, Instant};
use tokio::time::sleep;
use uuid::Uuid;

const DEFAULT_MONGO_URL: &str = "mongodb://localhost:27017/ferrum_test";

#[tokio::test]
#[ignore]
async fn test_admin_sqlite_runtime_resource_crud_matrix() {
    let backend_a = spawn_http_identifying("sql-crud-a")
        .await
        .expect("spawn sql backend a");
    let backend_b = spawn_http_identifying("sql-crud-b")
        .await
        .expect("spawn sql backend b");

    let gateway = TestGateway::builder()
        .mode_database_sqlite()
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn sqlite gateway");

    run_admin_resource_crud_matrix(
        &gateway,
        backend_a.port,
        backend_b.port,
        "sqlite",
        "sql-crud-a",
        "sql-crud-b",
    )
    .await;
}

#[tokio::test]
#[ignore]
async fn test_admin_mongodb_runtime_resource_crud_matrix() {
    let mongo_url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    if !mongodb_is_available(&mongo_url).await {
        eprintln!("MongoDB is not available at {mongo_url}; skipping MongoDB CRUD matrix");
        return;
    }

    let backend_a = spawn_http_identifying("mongo-crud-a")
        .await
        .expect("spawn mongo backend a");
    let backend_b = spawn_http_identifying("mongo-crud-b")
        .await
        .expect("spawn mongo backend b");
    let mongo_database = format!("ferrum_crud_{}", Uuid::new_v4().simple());

    let gateway = TestGateway::builder()
        .mode_database(DbType::Mongo(mongo_url))
        .env("FERRUM_MONGO_DATABASE", mongo_database)
        .log_level("warn")
        .db_poll_interval_seconds(1)
        .spawn()
        .await
        .expect("spawn mongodb gateway");

    run_admin_resource_crud_matrix(
        &gateway,
        backend_a.port,
        backend_b.port,
        "mongodb",
        "mongo-crud-a",
        "mongo-crud-b",
    )
    .await;
}

#[tokio::test]
#[ignore]
async fn test_file_mode_reload_updates_and_deletes_runtime_resources() {
    let backend_a = spawn_http_identifying("file-crud-a")
        .await
        .expect("spawn file backend a");
    let backend_b = spawn_http_identifying("file-crud-b")
        .await
        .expect("spawn file backend b");

    let initial_config = file_mode_resource_config(backend_a.port, "old-file-key");
    let gateway = TestGateway::builder()
        .mode_file(initial_config)
        .log_level("warn")
        .spawn()
        .await
        .expect("spawn file gateway");

    let client = Client::new();
    let auth = gateway.auth_header();

    for path in [
        "/proxies/file-crud-proxy",
        "/upstreams/file-crud-upstream",
        "/consumers/file-crud-consumer",
        "/plugins/config/file-crud-key-auth",
    ] {
        let value = admin_get_json(&client, &gateway, path, &auth).await;
        assert_eq!(
            value["id"],
            path.rsplit('/').next().unwrap(),
            "file-mode admin GET should expose loaded resource at {path}"
        );
    }

    let forbidden = client
        .post(gateway.admin_url("/proxies"))
        .header("Authorization", &auth)
        .json(&json!({
            "id": "file-write-should-fail",
            "listen_path": "/forbidden",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_a.port
        }))
        .send()
        .await
        .expect("POST /proxies in file mode");
    assert_status(
        forbidden,
        StatusCode::FORBIDDEN,
        "file-mode admin writes are read-only",
    )
    .await;

    wait_for_server_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("old-file-key"),
        "file-crud-a",
    )
    .await;

    let config_path = gateway
        .config_path
        .as_ref()
        .expect("file-mode harness exposes config path");
    std::fs::write(
        config_path,
        file_mode_resource_config(backend_b.port, "new-file-key"),
    )
    .expect("rewrite file-mode config");
    send_sighup(&gateway);

    wait_for_status_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("old-file-key"),
        StatusCode::UNAUTHORIZED,
    )
    .await;
    wait_for_server_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("new-file-key"),
        "file-crud-b",
    )
    .await;

    std::fs::write(config_path, empty_file_mode_config()).expect("clear file-mode config");
    send_sighup(&gateway);

    wait_for_status_with_key(
        &client,
        &gateway.proxy_url("/file-crud/check"),
        Some("new-file-key"),
        StatusCode::NOT_FOUND,
    )
    .await;

    let deleted = client
        .get(gateway.admin_url("/proxies/file-crud-proxy"))
        .header("Authorization", &auth)
        .send()
        .await
        .expect("GET deleted file proxy");
    assert_status(
        deleted,
        StatusCode::NOT_FOUND,
        "file-mode admin cache should drop deleted proxy after reload",
    )
    .await;
}

async fn run_admin_resource_crud_matrix(
    gateway: &TestGateway,
    backend_a_port: u16,
    backend_b_port: u16,
    prefix: &str,
    backend_a_name: &str,
    backend_b_name: &str,
) {
    let client = Client::new();
    let auth = gateway.auth_header();
    let suffix = Uuid::new_v4().simple().to_string();
    let suffix = &suffix[..8];
    let base = format!("{prefix}-{suffix}");
    let upstream_id = format!("{base}-upstream");
    let proxy_id = format!("{base}-proxy");
    let consumer_id = format!("{base}-consumer");
    let plugin_id = format!("{base}-plugin");
    let listen_path = format!("/{base}");

    let upstream = json!({
        "id": upstream_id,
        "name": format!("{base} upstream"),
        "algorithm": "round_robin",
        "targets": [{"host": "127.0.0.1", "port": backend_a_port, "weight": 1}]
    });
    admin_post_json(&client, gateway, "/upstreams", &auth, upstream).await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["targets"].as_array().unwrap().len(), 1);

    let updated_upstream = json!({
        "id": upstream_id,
        "name": format!("{base} upstream updated"),
        "algorithm": "round_robin",
        "targets": [{"host": "127.0.0.1", "port": backend_b_port, "weight": 1}]
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
        updated_upstream.clone(),
    )
    .await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["targets"][0]["port"], backend_b_port);

    admin_delete(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/upstreams/{upstream_id}"),
        &auth,
    )
    .await;
    admin_post_json(&client, gateway, "/upstreams", &auth, updated_upstream).await;

    let proxy = json!({
        "id": proxy_id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_a_port,
        "strip_listen_path": true,
        "upstream_id": upstream_id
    });
    admin_post_json(&client, gateway, "/proxies", &auth, proxy).await;
    let value = admin_get_json(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert_eq!(value["upstream_id"], upstream_id);

    let consumer = json!({
        "id": consumer_id,
        "username": format!("{base}-user"),
        "custom_id": format!("{base}-custom")
    });
    admin_post_json(&client, gateway, "/consumers", &auth, consumer).await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["custom_id"], format!("{base}-custom"));

    let updated_consumer = json!({
        "id": consumer_id,
        "username": format!("{base}-user-renamed"),
        "custom_id": format!("{base}-custom-updated"),
        "acl_groups": ["crud-admins"]
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
        updated_consumer,
    )
    .await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["username"], format!("{base}-user-renamed"));
    assert_eq!(value["acl_groups"][0], "crud-admins");

    let plugin = json!({
        "id": plugin_id,
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": true,
        "config": {
            "limit_by": "ip",
            "limits": [{"scope": "default", "requests_per_minute": 100}]
        }
    });
    admin_post_json(&client, gateway, "/plugins/config", &auth, plugin).await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["enabled"], true);

    let updated_plugin = json!({
        "id": plugin_id,
        "plugin_name": "rate_limiting",
        "scope": "proxy",
        "proxy_id": proxy_id,
        "enabled": false,
        "config": {
            "limit_by": "ip",
            "limits": [{"scope": "default", "requests_per_minute": 200}]
        }
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
        updated_plugin,
    )
    .await;
    let value = admin_get_json(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;
    assert_eq!(value["enabled"], false);
    assert_eq!(value["config"]["limits"][0]["requests_per_minute"], 200);

    admin_delete(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/plugins/config/{plugin_id}"),
        &auth,
    )
    .await;

    wait_for_server(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/one")),
        backend_b_name,
    )
    .await;

    let updated_proxy = json!({
        "id": proxy_id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_a_port,
        "strip_listen_path": false,
        "upstream_id": null
    });
    admin_put_json(
        &client,
        gateway,
        &format!("/proxies/{proxy_id}"),
        &auth,
        updated_proxy,
    )
    .await;
    let value = admin_get_json(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert!(value["upstream_id"].is_null());
    assert_eq!(value["strip_listen_path"], false);

    wait_for_server(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/two")),
        backend_a_name,
    )
    .await;

    admin_delete(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;
    assert_admin_not_found(
        &client,
        gateway,
        &format!("/consumers/{consumer_id}"),
        &auth,
    )
    .await;

    admin_delete(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    assert_admin_not_found(&client, gateway, &format!("/proxies/{proxy_id}"), &auth).await;
    wait_for_status(
        &client,
        &gateway.proxy_url(&format!("{listen_path}/gone")),
        StatusCode::NOT_FOUND,
    )
    .await;
}

async fn admin_post_json(
    client: &Client,
    gateway: &TestGateway,
    path: &str,
    auth: &str,
    body: Value,
) -> Value {
    let response = client
        .post(gateway.admin_url(path))
        .header("Authorization", auth)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|err| panic!("POST {path}: {err}"));
    expect_json_success(response, &format!("POST {path}")).await
}

async fn admin_put_json(
    client: &Client,
    gateway: &TestGateway,
    path: &str,
    auth: &str,
    body: Value,
) -> Value {
    let response = client
        .put(gateway.admin_url(path))
        .header("Authorization", auth)
        .json(&body)
        .send()
        .await
        .unwrap_or_else(|err| panic!("PUT {path}: {err}"));
    expect_json_success(response, &format!("PUT {path}")).await
}

async fn admin_get_json(client: &Client, gateway: &TestGateway, path: &str, auth: &str) -> Value {
    let response = client
        .get(gateway.admin_url(path))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap_or_else(|err| panic!("GET {path}: {err}"));
    expect_json_success(response, &format!("GET {path}")).await
}

async fn admin_delete(client: &Client, gateway: &TestGateway, path: &str, auth: &str) {
    let response = client
        .delete(gateway.admin_url(path))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap_or_else(|err| panic!("DELETE {path}: {err}"));
    assert_success(response, &format!("DELETE {path}")).await;
}

async fn assert_admin_not_found(client: &Client, gateway: &TestGateway, path: &str, auth: &str) {
    let response = client
        .get(gateway.admin_url(path))
        .header("Authorization", auth)
        .send()
        .await
        .unwrap_or_else(|err| panic!("GET {path}: {err}"));
    assert_status(response, StatusCode::NOT_FOUND, &format!("GET {path}")).await;
}

async fn expect_json_success(response: reqwest::Response, context: &str) -> Value {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "{context} failed with {status}: {body}"
    );
    if body.is_empty() {
        Value::Null
    } else {
        serde_json::from_str(&body).unwrap_or_else(|err| {
            panic!("{context} returned invalid JSON ({err}): {body}");
        })
    }
}

async fn assert_success(response: reqwest::Response, context: &str) {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "{context} failed with {status}: {body}"
    );
}

async fn assert_status(response: reqwest::Response, expected: StatusCode, context: &str) {
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    assert_eq!(status, expected, "{context} returned {status}: {body}");
}

async fn wait_for_server(client: &Client, url: &str, expected_server: &str) {
    wait_for_server_with_key(client, url, None, expected_server).await;
}

async fn wait_for_server_with_key(
    client: &Client,
    url: &str,
    key: Option<&str>,
    expected_server: &str,
) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = String::from("no response yet");
    while Instant::now() < deadline {
        let mut request = client.get(url);
        if let Some(key) = key {
            request = request.header("X-Api-Key", key);
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                if status.is_success()
                    && let Some(server) = parse_server_name(&body)
                    && server == expected_server
                {
                    return;
                }
                last = format!("{status}: {body}");
            }
            Err(err) => last = err.to_string(),
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {url} to route to {expected_server}; last observation: {last}");
}

async fn wait_for_status(client: &Client, url: &str, expected: StatusCode) {
    wait_for_status_with_key(client, url, None, expected).await;
}

async fn wait_for_status_with_key(
    client: &Client,
    url: &str,
    key: Option<&str>,
    expected: StatusCode,
) {
    let deadline = Instant::now() + Duration::from_secs(8);
    let mut last = String::from("no response yet");
    while Instant::now() < deadline {
        let mut request = client.get(url);
        if let Some(key) = key {
            request = request.header("X-Api-Key", key);
        }
        match request.send().await {
            Ok(response) => {
                let status = response.status();
                let body = response.text().await.unwrap_or_default();
                if status == expected {
                    return;
                }
                last = format!("{status}: {body}");
            }
            Err(err) => last = err.to_string(),
        }
        sleep(Duration::from_millis(250)).await;
    }
    panic!("timed out waiting for {url} to return {expected}; last observation: {last}");
}

fn parse_server_name(body: &str) -> Option<String> {
    serde_json::from_str::<Value>(body).ok().and_then(|value| {
        value
            .get("server")
            .and_then(Value::as_str)
            .map(str::to_string)
    })
}

fn file_mode_resource_config(backend_port: u16, key: &str) -> String {
    format!(
        r#"
version: "1"
upstreams:
  - id: "file-crud-upstream"
    name: "file-crud-upstream"
    algorithm: round_robin
    targets:
      - host: "127.0.0.1"
        port: {backend_port}
        weight: 1

proxies:
  - id: "file-crud-proxy"
    listen_path: "/file-crud"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    upstream_id: "file-crud-upstream"
    plugins:
      - plugin_config_id: "file-crud-key-auth"

consumers:
  - id: "file-crud-consumer"
    username: "file-crud-user"
    custom_id: "file-crud-custom"
    credentials:
      keyauth:
        - key: "{key}"

plugin_configs:
  - id: "file-crud-key-auth"
    plugin_name: "key_auth"
    scope: proxy
    proxy_id: "file-crud-proxy"
    enabled: true
    config:
      key_location: "header:X-Api-Key"
"#,
    )
}

fn empty_file_mode_config() -> &'static str {
    r#"
version: "1"
proxies: []
consumers: []
upstreams: []
plugin_configs: []
"#
}

fn send_sighup(gateway: &TestGateway) {
    #[cfg(unix)]
    {
        let pid = gateway.pid().expect("gateway process is running");
        let status = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .expect("send SIGHUP");
        assert!(status.success(), "kill -HUP {pid} failed with {status}");
    }

    #[cfg(not(unix))]
    panic!("file-mode SIGHUP reload functional test requires Unix");
}

async fn mongodb_is_available(url: &str) -> bool {
    let host_port = url
        .strip_prefix("mongodb://")
        .or_else(|| url.strip_prefix("mongodb+srv://"))
        .and_then(|value| value.split('/').next())
        .and_then(|value| value.split('@').next_back())
        .unwrap_or("localhost:27017");

    tokio::net::TcpStream::connect(host_port).await.is_ok()
}
