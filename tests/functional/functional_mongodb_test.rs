//! MongoDB Functional Tests
//!
//! Verifies that ferrum-edge works correctly with MongoDB as the database backend:
//! - Plaintext MongoDB connection (no TLS)
//! - TLS-encrypted MongoDB connection
//! - TLS-encrypted MongoDB connection without server certificate verification
//! - mTLS MongoDB connection (client certificate authentication)
//! - Full Admin API CRUD lifecycle (proxies, consumers, plugins, upstreams)
//! - Proxy traffic routing through a MongoDB-backed gateway
//! - Health endpoint reports MongoDB connectivity
//!
//! Prerequisites:
//!   1. MongoDB running on localhost:27017 (plaintext test)
//!      - Docker: `docker run -d --name mongo-test -p 27017:27017 mongo:7`
//!   2. For TLS/mTLS tests: TLS-enabled MongoDB with certs
//!      - Run `tests/scripts/setup_mongo_tls.sh` (if available) or configure manually
//!   3. Build the gateway: `cargo build`
//!
//! Run with:
//!   cargo test --test functional_tests functional_mongodb -- --ignored --nocapture

use crate::common::{
    configure_coverage_gateway_command, explicit_test_binary, shutdown_gateway_child,
};
use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use mongodb::bson::{Bson, Document, doc};
use mongodb::{Client as MongoClient, Database as MongoDatabase};
use serde_json::json;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use uuid::Uuid;

/// Default MongoDB connection for local development / CI.
const DEFAULT_MONGO_URL: &str = "mongodb://localhost:27017/ferrum_test";
const DEFAULT_MONGO_DATABASE: &str = "ferrum_test";

/// Check if MongoDB is reachable at the expected address.
/// Returns false if MongoDB is down — tests will be skipped gracefully.
async fn mongodb_is_available(url: &str) -> bool {
    // Extract host:port from the MongoDB URL (mongodb://host:port/db)
    let host_port = url
        .strip_prefix("mongodb://")
        .or_else(|| url.strip_prefix("mongodb+srv://"))
        .and_then(|s| s.split('/').next())
        .and_then(|s| {
            // Strip credentials if present (user:pass@host:port)
            if s.contains('@') {
                s.split('@').next_back()
            } else {
                Some(s)
            }
        })
        .unwrap_or("localhost:27017");

    match tokio::net::TcpStream::connect(host_port).await {
        Ok(_) => true,
        Err(_) => {
            eprintln!(
                "MongoDB not available at {} — skipping MongoDB functional tests",
                host_port
            );
            false
        }
    }
}

/// Default certificate directory for TLS tests.
const DEFAULT_CERT_DIR: &str = "/tmp/ferrum-mongo-tls-certs";

/// Test harness for MongoDB functional testing.
struct MongoTestHarness {
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
    mongo_app_name: String,
    admin_port: u16,
    proxy_port: u16,
}

impl MongoTestHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let jwt_secret = "mongo-test-secret-key-1234567890ab".to_string();
        let jwt_issuer = "ferrum-edge-mongo-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        Ok(Self {
            gateway_process: None,
            proxy_base_url: format!("http://127.0.0.1:{}", proxy_port),
            admin_base_url: format!("http://127.0.0.1:{}", admin_port),
            jwt_secret,
            jwt_issuer,
            mongo_app_name: format!("ferrum-functional-{}", Uuid::new_v4()),
            admin_port,
            proxy_port,
        })
    }

    /// Start the gateway with plaintext MongoDB connection.
    /// Retries up to 3 times with fresh ports to handle ephemeral port races.
    async fn start_gateway_plaintext(
        &mut self,
        mongo_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self.try_start_gateway_plaintext(mongo_url).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "start_gateway_plaintext attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        self.reallocate_ports().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to start gateway (plaintext) after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_start_gateway_plaintext(
        &mut self,
        mongo_url: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        self.try_start_gateway_plaintext_with_replica_set(mongo_url, None)
            .await
    }

    async fn try_start_gateway_plaintext_with_replica_set(
        &mut self,
        mongo_url: &str,
        replica_set: Option<&str>,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binary_path = find_binary()?;

        let mut command = Command::new(binary_path);
        command
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "mongodb")
            .env("FERRUM_DB_URL", mongo_url)
            .env("FERRUM_MONGO_DATABASE", DEFAULT_MONGO_DATABASE)
            .env("FERRUM_MONGO_APP_NAME", &self.mongo_app_name)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        if let Some(replica_set) = replica_set {
            command.env("FERRUM_MONGO_REPLICA_SET", replica_set);
        }
        configure_coverage_gateway_command(&mut command);
        let child = command.spawn()?;

        self.gateway_process = Some(child);
        match self.wait_for_health().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(mut child) = self.gateway_process.take() {
                    shutdown_gateway_child(&mut child);
                }
                Err(e)
            }
        }
    }

    /// Start the gateway against a MongoDB replica set.
    ///
    /// `POST /batch` needs multi-document transactions, which require a replica
    /// set (or mongos); `FERRUM_MONGO_REPLICA_SET` is what makes the store
    /// advertise that capability.
    async fn start_gateway_replica_set(
        &mut self,
        mongo_url: &str,
        replica_set: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self
                .try_start_gateway_plaintext_with_replica_set(mongo_url, Some(replica_set))
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "start_gateway_replica_set attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        self.reallocate_ports().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to start gateway (replica set) after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    /// Start the gateway with TLS-encrypted MongoDB connection.
    /// Retries up to 3 times with fresh ports to handle ephemeral port races.
    async fn start_gateway_tls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
        insecure: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self
                .try_start_gateway_tls(mongo_url, cert_dir, insecure)
                .await
            {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "start_gateway_tls attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        self.reallocate_ports().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to start gateway (tls) after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_start_gateway_tls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
        insecure: bool,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binary_path = find_binary()?;
        let ca_cert_path = format!("{}/ca.crt", cert_dir);
        let tls_mode = if insecure { "require" } else { "verify-full" };
        let mut command = Command::new(binary_path);
        command
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "mongodb")
            .env("FERRUM_DB_URL", mongo_url)
            .env("FERRUM_MONGO_DATABASE", DEFAULT_MONGO_DATABASE)
            .env("FERRUM_MONGO_APP_NAME", &self.mongo_app_name)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .env("FERRUM_DB_TLS_MODE", tls_mode);
        if !insecure {
            command.env("FERRUM_DB_TLS_CA_CERT_PATH", &ca_cert_path);
        }

        configure_coverage_gateway_command(&mut command);
        let child = command
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        self.gateway_process = Some(child);
        match self.wait_for_health().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(mut child) = self.gateway_process.take() {
                    shutdown_gateway_child(&mut child);
                }
                Err(e)
            }
        }
    }

    /// Start the gateway with mTLS MongoDB connection (client certificate auth).
    /// Retries up to 3 times with fresh ports to handle ephemeral port races.
    async fn start_gateway_mtls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        const MAX_ATTEMPTS: u32 = 3;
        let mut last_err = String::new();
        for attempt in 1..=MAX_ATTEMPTS {
            match self.try_start_gateway_mtls(mongo_url, cert_dir).await {
                Ok(()) => return Ok(()),
                Err(e) => {
                    last_err = e.to_string();
                    eprintln!(
                        "start_gateway_mtls attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, last_err
                    );
                    if attempt < MAX_ATTEMPTS {
                        self.reallocate_ports().await?;
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(format!(
            "Failed to start gateway (mtls) after {} attempts: {}",
            MAX_ATTEMPTS, last_err
        )
        .into())
    }

    async fn try_start_gateway_mtls(
        &mut self,
        mongo_url: &str,
        cert_dir: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let binary_path = find_binary()?;
        let ca_cert_path = format!("{}/ca.crt", cert_dir);
        let client_cert_path = format!("{}/client.crt", cert_dir);
        let client_key_path = format!("{}/client.key", cert_dir);

        let mut command = Command::new(binary_path);
        command
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_DB_TYPE", "mongodb")
            .env("FERRUM_DB_URL", mongo_url)
            .env("FERRUM_MONGO_DATABASE", DEFAULT_MONGO_DATABASE)
            .env("FERRUM_MONGO_APP_NAME", &self.mongo_app_name)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", self.proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", self.admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "info")
            .env("FERRUM_DB_TLS_MODE", "verify-full")
            .env("FERRUM_DB_TLS_CA_CERT_PATH", &ca_cert_path)
            .env("FERRUM_DB_TLS_CLIENT_CERT_PATH", &client_cert_path)
            .env("FERRUM_DB_TLS_CLIENT_KEY_PATH", &client_key_path)
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        configure_coverage_gateway_command(&mut command);
        let child = command.spawn()?;

        self.gateway_process = Some(child);
        match self.wait_for_health().await {
            Ok(()) => Ok(()),
            Err(e) => {
                if let Some(mut child) = self.gateway_process.take() {
                    shutdown_gateway_child(&mut child);
                }
                Err(e)
            }
        }
    }

    /// Reallocate ephemeral ports after a failed startup attempt.
    async fn reallocate_ports(&mut self) -> Result<(), Box<dyn std::error::Error>> {
        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        self.admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        self.proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        self.admin_base_url = format!("http://127.0.0.1:{}", self.admin_port);
        self.proxy_base_url = format!("http://127.0.0.1:{}", self.proxy_port);
        Ok(())
    }

    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);

        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway (mongodb) did not start within 30 seconds".into());
            }

            match reqwest::get(&health_url).await {
                Ok(response) if response.status().is_success() => {
                    println!("  Gateway (mongodb) is ready!");
                    return Ok(());
                }
                _ => {
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
            }
        }
    }

    fn generate_token(&self) -> Result<String, Box<dyn std::error::Error>> {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "role": "admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string()
        });

        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        Ok(encode(&header, &claims, &key)?)
    }
}

impl Drop for MongoTestHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            shutdown_gateway_child(&mut child);
        }
    }
}

fn find_binary() -> Result<String, Box<dyn std::error::Error>> {
    if let Some(path) = explicit_test_binary() {
        return Ok(path.to_string_lossy().into_owned());
    }
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        Ok("./target/debug/ferrum-edge".to_string())
    } else if std::path::Path::new("./target/release/ferrum-edge").exists() {
        Ok("./target/release/ferrum-edge".to_string())
    } else {
        Err("ferrum-edge binary not found. Run `cargo build` first.".into())
    }
}

/// Create a simple echo HTTP server for backend testing.
async fn start_echo_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;

    let handle = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let (reader, mut writer) = socket.into_split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut line = String::new();

                if buf_reader.read_line(&mut line).await.is_err() {
                    return;
                }

                // Read headers until blank line
                loop {
                    line.clear();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                }

                let body = r#"{"status":"ok","backend":"echo","db":"mongodb"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });

    Ok(handle)
}

/// Run the full CRUD + proxy routing test suite against a running harness.
async fn run_crud_and_proxy_tests(
    harness: &MongoTestHarness,
    backend_port: u16,
    test_prefix: &str,
) {
    let client = reqwest::Client::new();
    let token = harness.generate_token().expect("Failed to generate token");
    let auth_header = format!("Bearer {}", token);

    // Use unique IDs per test run to avoid conflicts
    let run_id = Uuid::new_v4().to_string()[..8].to_string();
    let proxy_id = format!("{}-proxy-{}", test_prefix, run_id);
    let consumer_id = format!("{}-consumer-{}", test_prefix, run_id);
    let plugin_id = format!("{}-plugin-{}", test_prefix, run_id);

    // Test 1: Health check reports MongoDB
    println!("\n--- {}: Health Check ---", test_prefix);
    let resp = client
        .get(format!("{}/health", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Health check failed");
    assert!(resp.status().is_success());
    let health: serde_json::Value = resp.json().await.expect("Parse health");
    assert_eq!(health["status"], "ok");
    assert_eq!(health["database"]["status"], "connected");
    assert_eq!(health["database"]["type"], "mongodb");
    println!("  OK: Health reports mongodb connected");

    // Test 2: Create proxy
    println!("\n--- {}: Create Proxy ---", test_prefix);
    let resp = client
        .post(format!("{}/proxies", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &proxy_id,
            "name": format!("{}-test", test_prefix),
            "listen_path": format!("/mongo-test-{}", run_id),
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
        }))
        .send()
        .await
        .expect("Create proxy failed");
    assert!(
        resp.status().is_success(),
        "Create proxy: {}",
        resp.status()
    );
    println!("  OK: Proxy created");

    // Test 3: Read proxy back
    println!("\n--- {}: Get Proxy ---", test_prefix);
    let resp = client
        .get(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Get proxy failed");
    let status = resp.status();
    let body = resp.text().await.unwrap_or_default();
    assert!(
        status.is_success(),
        "Get proxy failed with {}: {}",
        status,
        body
    );
    let proxy: serde_json::Value = serde_json::from_str(&body).expect("Parse proxy");
    assert_eq!(proxy["id"], proxy_id);
    println!("  OK: Proxy retrieved from MongoDB");

    // Test 4: Create consumer
    println!("\n--- {}: Create Consumer ---", test_prefix);
    let resp = client
        .post(format!("{}/consumers", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &consumer_id,
            "username": format!("user-{}", run_id),
            "custom_id": format!("custom-{}", run_id),
        }))
        .send()
        .await
        .expect("Create consumer failed");
    assert!(
        resp.status().is_success(),
        "Create consumer: {}",
        resp.status()
    );
    println!("  OK: Consumer created");

    // Test 5: Read consumer back
    let resp = client
        .get(format!(
            "{}/consumers/{}",
            harness.admin_base_url, consumer_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Get consumer failed");
    assert!(resp.status().is_success());
    let consumer: serde_json::Value = resp.json().await.expect("Parse consumer");
    assert_eq!(consumer["id"], consumer_id);
    println!("  OK: Consumer retrieved from MongoDB");

    // Test 6: Create plugin config
    println!("\n--- {}: Create Plugin Config ---", test_prefix);
    let resp = client
        .post(format!("{}/plugins/config", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &plugin_id,
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": &proxy_id,
            "enabled": true,
            "config": {
                "limit_by": "ip",
                "limits": [{"scope": "default", "requests_per_minute": 100}]
            }
        }))
        .send()
        .await
        .expect("Create plugin config failed");
    assert!(
        resp.status().is_success(),
        "Create plugin: {}",
        resp.status()
    );
    println!("  OK: Plugin config created");

    // Test 7: Wait for DB poll and route through proxy
    println!("\n--- {}: Route Traffic Through Proxy ---", test_prefix);
    tokio::time::sleep(Duration::from_secs(3)).await;

    let resp = client
        .get(format!("{}/mongo-test-{}", harness.proxy_base_url, run_id))
        .send()
        .await
        .expect("Proxy request failed");
    assert!(
        resp.status().is_success(),
        "Proxy routing failed: {}",
        resp.status()
    );
    let body: serde_json::Value = resp.json().await.expect("Parse proxy response");
    assert_eq!(body["db"], "mongodb");
    println!("  OK: Traffic routed through MongoDB-backed proxy");

    // Test 8: Update proxy
    println!("\n--- {}: Update Proxy ---", test_prefix);
    let resp = client
        .put(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &proxy_id,
            "name": format!("{}-updated", test_prefix),
            "listen_path": format!("/mongo-test-{}", run_id),
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
        }))
        .send()
        .await
        .expect("Update proxy failed");
    assert!(
        resp.status().is_success(),
        "Update proxy: {}",
        resp.status()
    );
    println!("  OK: Proxy updated");

    // Test 9: Delete resources
    println!("\n--- {}: Delete Resources ---", test_prefix);
    let resp = client
        .delete(format!(
            "{}/plugins/config/{}",
            harness.admin_base_url, plugin_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Delete plugin failed");
    assert!(resp.status().is_success(), "Delete plugin");

    let resp = client
        .delete(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Delete proxy failed");
    assert!(resp.status().is_success(), "Delete proxy");

    let resp = client
        .delete(format!(
            "{}/consumers/{}",
            harness.admin_base_url, consumer_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Delete consumer failed");
    assert!(resp.status().is_success(), "Delete consumer");
    println!("  OK: All resources deleted");

    // Verify deletion
    tokio::time::sleep(Duration::from_secs(1)).await;
    let resp = client
        .get(format!("{}/proxies/{}", harness.admin_base_url, proxy_id))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("Get deleted proxy");
    assert_eq!(
        resp.status().as_u16(),
        404,
        "Proxy should be 404 after delete"
    );
    println!("  OK: Deletion verified");
}

// ==========================================================================
// Test: Plaintext MongoDB Connection
// ==========================================================================

#[tokio::test]
#[ignore]
async fn test_mongodb_plaintext_full_lifecycle() {
    println!("\n=== MongoDB Plaintext Functional Test ===\n");

    let mongo_url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());

    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    // Start echo backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind backend");
    let backend_port = backend_listener.local_addr().expect("Backend addr").port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.expect("Start echo");
    println!("Echo backend on port {}", backend_port);

    // Start gateway
    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_plaintext(&mongo_url)
        .await
        .expect("Start gateway with MongoDB");

    println!(
        "Gateway started (admin={}, proxy={})",
        harness.admin_port, harness.proxy_port
    );

    // Run full test suite
    run_crud_and_proxy_tests(&harness, backend_port, "plaintext").await;

    println!("\n=== MongoDB Plaintext Test PASSED ===\n");
}

// ==========================================================================
// Test: TLS MongoDB Connection
// ==========================================================================

#[tokio::test]
#[ignore]
async fn test_mongodb_tls_connection() {
    println!("\n=== MongoDB TLS Functional Test ===\n");

    let mongo_url = std::env::var("FERRUM_TEST_MONGO_TLS_URL")
        .unwrap_or_else(|_| "mongodb://localhost:27018/ferrum_test".to_string());
    let cert_dir = std::env::var("FERRUM_TEST_MONGO_CERT_DIR")
        .unwrap_or_else(|_| DEFAULT_CERT_DIR.to_string());

    if !std::path::Path::new(&format!("{}/ca.crt", cert_dir)).exists() {
        println!(
            "SKIP: TLS certs not found at {}. Run setup_mongo_tls.sh first.",
            cert_dir
        );
        return;
    }

    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind backend");
    let backend_port = backend_listener.local_addr().expect("Backend addr").port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.expect("Start echo");

    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_tls(&mongo_url, &cert_dir, false)
        .await
        .expect("Start gateway with MongoDB TLS");

    run_crud_and_proxy_tests(&harness, backend_port, "tls").await;

    println!("\n=== MongoDB TLS Test PASSED ===\n");
}

// ==========================================================================
// Test: TLS MongoDB Connection Without Server Certificate Verification
// ==========================================================================

#[tokio::test]
#[ignore]
async fn test_mongodb_tls_require_connection() {
    println!("\n=== MongoDB TLS Require Functional Test ===\n");

    let mongo_url = std::env::var("FERRUM_TEST_MONGO_TLS_REQUIRE_URL")
        .or_else(|_| std::env::var("FERRUM_TEST_MONGO_TLS_URL"))
        .unwrap_or_else(|_| "mongodb://localhost:27018/ferrum_test".to_string());
    let cert_dir = std::env::var("FERRUM_TEST_MONGO_CERT_DIR")
        .unwrap_or_else(|_| DEFAULT_CERT_DIR.to_string());

    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind backend");
    let backend_port = backend_listener.local_addr().expect("Backend addr").port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.expect("Start echo");

    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_tls(&mongo_url, &cert_dir, true)
        .await
        .expect("Start gateway with MongoDB TLS require");

    run_crud_and_proxy_tests(&harness, backend_port, "tls-require").await;

    println!("\n=== MongoDB TLS Require Test PASSED ===\n");
}

// ==========================================================================
// Test: mTLS MongoDB Connection (Client Certificate Authentication)
// ==========================================================================

#[tokio::test]
#[ignore]
async fn test_mongodb_mtls_connection() {
    println!("\n=== MongoDB mTLS Functional Test ===\n");

    let mongo_url = std::env::var("FERRUM_TEST_MONGO_MTLS_URL")
        .unwrap_or_else(|_| "mongodb://localhost:27019/ferrum_test".to_string());
    let cert_dir = std::env::var("FERRUM_TEST_MONGO_CERT_DIR")
        .unwrap_or_else(|_| DEFAULT_CERT_DIR.to_string());

    if !std::path::Path::new(&format!("{}/client.crt", cert_dir)).exists() {
        println!(
            "SKIP: mTLS client certs not found at {}. Run setup_mongo_tls.sh first.",
            cert_dir
        );
        return;
    }

    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("Bind backend");
    let backend_port = backend_listener.local_addr().expect("Backend addr").port();
    drop(backend_listener);
    let _backend = start_echo_backend(backend_port).await.expect("Start echo");

    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_mtls(&mongo_url, &cert_dir)
        .await
        .expect("Start gateway with MongoDB mTLS");

    run_crud_and_proxy_tests(&harness, backend_port, "mtls").await;

    println!("\n=== MongoDB mTLS Test PASSED ===\n");
}

// ==========================================================================
// Test: POST /batch atomicity semantics per MongoDB topology (issue #2401)
// ==========================================================================

/// One graph that spans every dependency phase: an upstream, a proxy that
/// references it, and a proxy-scoped plugin config attached to that proxy.
fn batch_graph(run_id: &str, upstream_id: &str) -> serde_json::Value {
    json!({
        "consumers": [{
            "id": format!("batch-consumer-{run_id}"),
            "username": format!("batch-user-{run_id}"),
        }],
        "upstreams": [{
            "id": upstream_id,
            "name": format!("batch-upstream-{run_id}"),
            "targets": [{"host": "10.0.0.10", "port": 8080, "weight": 100}],
            "algorithm": "round_robin",
        }],
        "proxies": [{
            "id": format!("batch-proxy-{run_id}"),
            "name": format!("batch-proxy-{run_id}"),
            "listen_path": format!("/batch-atomic-{run_id}"),
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": 8080,
            "upstream_id": upstream_id,
            "plugins": [{"plugin_config_id": format!("batch-plugin-{run_id}")}],
        }],
        "plugin_configs": [{
            "id": format!("batch-plugin-{run_id}"),
            "plugin_name": "request_size_limiting",
            "scope": "proxy",
            "proxy_id": format!("batch-proxy-{run_id}"),
            "enabled": true,
            "config": {"max_bytes": 1048576},
        }],
    })
}

async fn resource_exists(
    client: &reqwest::Client,
    harness: &MongoTestHarness,
    auth_header: &str,
    path: &str,
) -> bool {
    let resp = client
        .get(format!("{}{}", harness.admin_base_url, path))
        .header("Authorization", auth_header)
        .send()
        .await
        .expect("admin GET");
    resp.status().as_u16() != 404
}

/// Standalone MongoDB has no multi-document transactions, so `POST /batch`
/// cannot be applied all-or-nothing. It must be refused with `501` **before any
/// mutation** rather than falling back to per-family writes that can strand half
/// a graph.
#[tokio::test]
#[ignore]
async fn test_mongodb_batch_atomicity_refused_on_standalone() {
    println!("\n=== MongoDB Standalone Batch Refusal Test ===\n");

    let mongo_url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_plaintext(&mongo_url)
        .await
        .expect("Start gateway with standalone MongoDB");

    let client = reqwest::Client::new();
    let auth_header = format!("Bearer {}", harness.generate_token().expect("token"));
    let run_id = Uuid::new_v4().to_string()[..8].to_string();
    let upstream_id = format!("batch-upstream-{run_id}");
    let graph = batch_graph(&run_id, &upstream_id);

    let resp = client
        .post(format!("{}/batch", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&graph)
        .send()
        .await
        .expect("POST /batch");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status, 501,
        "standalone MongoDB must refuse POST /batch: {body:?}"
    );
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("FERRUM_MONGO_REPLICA_SET"),
        "the refusal must name the configuration that enables the guarantee: {body:?}"
    );
    println!("  OK: standalone refusal returns 501 with remediation");

    // Refused before any mutation: not one resource from the graph exists.
    for path in [
        format!("/consumers/batch-consumer-{run_id}"),
        format!("/upstreams/{upstream_id}"),
        format!("/proxies/batch-proxy-{run_id}"),
        format!("/plugins/config/batch-plugin-{run_id}"),
    ] {
        assert!(
            !resource_exists(&client, &harness, &auth_header, &path).await,
            "refused batch must not have written {path}"
        );
    }
    println!("  OK: nothing was written before the refusal");
    println!("\n=== MongoDB Standalone Batch Refusal Test PASSED ===\n");
}

/// Replica-set MongoDB persists the whole graph in one transaction. A duplicate
/// in a later dependency phase must roll back the earlier phases, and the
/// corrected retry must apply cleanly.
///
/// Requires a replica set. Set `FERRUM_TEST_MONGO_REPLICA_SET` (and optionally
/// `FERRUM_TEST_MONGO_REPLICA_SET_URL`) to run it; skipped otherwise, because a
/// plain `mongo:7` container cannot start a transaction.
#[tokio::test]
#[ignore]
async fn test_mongodb_batch_atomicity_all_or_nothing_on_replica_set() {
    println!("\n=== MongoDB Replica-Set Batch Atomicity Test ===\n");

    let Ok(replica_set) = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET") else {
        println!("SKIP: FERRUM_TEST_MONGO_REPLICA_SET not set — no replica set available");
        return;
    };
    let mongo_url = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET_URL")
        .or_else(|_| std::env::var("FERRUM_TEST_MONGO_URL"))
        .unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let mut harness = MongoTestHarness::new().await.expect("Create harness");
    harness
        .start_gateway_replica_set(&mongo_url, &replica_set)
        .await
        .expect("Start gateway with MongoDB replica set");

    let client = reqwest::Client::new();
    let auth_header = format!("Bearer {}", harness.generate_token().expect("token"));
    let run_id = Uuid::new_v4().to_string()[..8].to_string();

    // Seed the upstream the graph will collide with. Consumers are written
    // before upstreams, so the collision fails a *later* dependency phase.
    let taken_upstream = format!("batch-taken-upstream-{run_id}");
    let resp = client
        .post(format!("{}/upstreams", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&json!({
            "id": &taken_upstream,
            "name": &taken_upstream,
            "targets": [{"host": "10.0.0.10", "port": 8080, "weight": 100}],
            "algorithm": "round_robin",
        }))
        .send()
        .await
        .expect("seed upstream");
    let seed_status = resp.status();
    assert!(seed_status.is_success(), "seed upstream: {seed_status}");

    let conflicting = batch_graph(&run_id, &taken_upstream);
    let resp = client
        .post(format!("{}/batch", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&conflicting)
        .send()
        .await
        .expect("POST /batch");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status, 409,
        "a duplicate in the graph must reject the whole graph: {body:?}"
    );
    assert!(
        body.get("created").is_none(),
        "a rejected graph must not report created counts: {body:?}"
    );

    // The consumer phase ran before the collision; nothing may survive.
    for path in [
        format!("/consumers/batch-consumer-{run_id}"),
        format!("/proxies/batch-proxy-{run_id}"),
        format!("/plugins/config/batch-plugin-{run_id}"),
    ] {
        assert!(
            !resource_exists(&client, &harness, &auth_header, &path).await,
            "a rolled-back MongoDB batch must not leave {path}"
        );
    }
    println!("  OK: an earlier phase was rolled back with the failing one");

    // Corrected retry: the identical consumer/proxy/plugin IDs still apply,
    // which is only possible because the failed attempt committed nothing.
    let fixed_upstream = format!("batch-fixed-upstream-{run_id}");
    let resp = client
        .post(format!("{}/batch", harness.admin_base_url))
        .header("Authorization", &auth_header)
        .json(&batch_graph(&run_id, &fixed_upstream))
        .send()
        .await
        .expect("POST /batch retry");
    let status = resp.status().as_u16();
    let body: serde_json::Value = resp.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(status, 201, "corrected retry must succeed: {body:?}");
    assert_eq!(body["created"]["consumers"], 1);
    assert_eq!(body["created"]["upstreams"], 1);
    assert_eq!(body["created"]["proxies"], 1);
    assert_eq!(body["created"]["plugin_configs"], 1);
    println!("  OK: corrected retry applied the whole graph");
    println!("\n=== MongoDB Replica-Set Batch Atomicity Test PASSED ===\n");
}

#[derive(Debug)]
struct OwnedProxyDeleteFixture {
    proxy_id: String,
    upstream_id: String,
    plugin_id: String,
}

impl OwnedProxyDeleteFixture {
    fn new(label: &str) -> Self {
        let run_id = Uuid::new_v4().to_string()[..8].to_string();
        Self {
            proxy_id: format!("{label}-proxy-{run_id}"),
            upstream_id: format!("{label}-upstream-{run_id}"),
            plugin_id: format!("{label}-plugin-{run_id}"),
        }
    }

    fn api_spec(&self) -> serde_json::Value {
        json!({
            "openapi": "3.1.0",
            "info": {
                "title": "Mongo proxy delete atomicity fixture",
                "version": "1.0.0"
            },
            "x-ferrum-proxy": {
                "id": self.proxy_id.as_str(),
                "listen_path": format!("/{}", self.proxy_id),
                "backend_scheme": "http",
                "backend_host": "127.0.0.1",
                "backend_port": 8080
            },
            "x-ferrum-upstream": {
                "id": self.upstream_id.as_str(),
                "name": self.upstream_id.as_str(),
                "targets": [{
                    "host": "127.0.0.1",
                    "port": 8080,
                    "weight": 100
                }],
                "algorithm": "round_robin"
            },
            "x-ferrum-plugins": [{
                "id": self.plugin_id.as_str(),
                "plugin_name": "request_size_limiting",
                "config": {"max_bytes": 1048576}
            }],
            "paths": {}
        })
    }

    fn change_filter(&self) -> Document {
        doc! {
            "namespace": "ferrum",
            "resource_id": {
                "$in": [
                    self.proxy_id.as_str(),
                    self.upstream_id.as_str(),
                    self.plugin_id.as_str(),
                ]
            }
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct OwnedProxyDeleteSnapshot {
    proxies: u64,
    plugin_configs: u64,
    api_specs: u64,
    upstreams: u64,
    config_changes: u64,
}

async fn mongo_database(url: &str) -> MongoDatabase {
    MongoClient::with_uri_str(url)
        .await
        .expect("connect MongoDB test observer")
        .database(DEFAULT_MONGO_DATABASE)
}

async fn submit_owned_proxy_fixture(
    client: &reqwest::Client,
    harness: &MongoTestHarness,
    auth_header: &str,
    fixture: &OwnedProxyDeleteFixture,
) -> String {
    let response = client
        .post(format!("{}/api-specs", harness.admin_base_url))
        .header("Authorization", auth_header)
        .json(&fixture.api_spec())
        .send()
        .await
        .expect("submit API-spec-owned proxy fixture");
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status.as_u16(),
        201,
        "API-spec-owned proxy fixture must be created: {body:?}"
    );
    body["id"]
        .as_str()
        .expect("API-spec response id")
        .to_string()
}

async fn owned_proxy_delete_snapshot(
    db: &MongoDatabase,
    fixture: &OwnedProxyDeleteFixture,
    spec_id: &str,
) -> OwnedProxyDeleteSnapshot {
    OwnedProxyDeleteSnapshot {
        proxies: db
            .collection::<Document>("proxies")
            .count_documents(doc! { "_id": fixture.proxy_id.as_str(), "namespace": "ferrum" })
            .await
            .expect("count fixture proxies"),
        plugin_configs: db
            .collection::<Document>("plugin_configs")
            .count_documents(
                doc! { "_id": fixture.plugin_id.as_str(), "namespace": "ferrum" },
            )
            .await
            .expect("count fixture plugin configs"),
        api_specs: db
            .collection::<Document>("api_specs")
            .count_documents(doc! { "_id": spec_id, "namespace": "ferrum" })
            .await
            .expect("count fixture API specs"),
        upstreams: db
            .collection::<Document>("upstreams")
            .count_documents(
                doc! { "_id": fixture.upstream_id.as_str(), "namespace": "ferrum" },
            )
            .await
            .expect("count fixture upstreams"),
        config_changes: db
            .collection::<Document>("config_changes")
            .count_documents(fixture.change_filter())
            .await
            .expect("count fixture config changes"),
    }
}

fn failpoint_count(result: &Document) -> i64 {
    match result.get("count") {
        Some(Bson::Int32(value)) => i64::from(*value),
        Some(Bson::Int64(value)) => *value,
        other => panic!("configureFailPoint response missing numeric count: {other:?}"),
    }
}

async fn enable_delete_failpoint(
    mongo_url: &str,
    app_name: &str,
    collection: &str,
) -> (MongoClient, i64) {
    let client = MongoClient::with_uri_str(mongo_url)
        .await
        .expect("connect MongoDB failpoint controller");
    let result = client
        .database("admin")
        .run_command(doc! {
            "configureFailPoint": "failCommand",
            "mode": "alwaysOn",
            "data": {
                "errorCode": 1,
                "failCommands": ["delete"],
                "namespace": format!("{DEFAULT_MONGO_DATABASE}.{collection}"),
                "appName": app_name,
            }
        })
        .await
        .expect("enable namespace-scoped MongoDB delete failpoint");
    let count = failpoint_count(&result);
    (client, count)
}

async fn disable_delete_failpoint(client: &MongoClient, initial_count: i64) {
    let result = client
        .database("admin")
        .run_command(doc! {
            "configureFailPoint": "failCommand",
            "mode": "off",
        })
        .await
        .expect("disable MongoDB delete failpoint");
    assert!(
        failpoint_count(&result) > initial_count,
        "the targeted MongoDB delete command must reach the configured failpoint"
    );
}

fn assert_delete_error_is_redacted(
    body: &serde_json::Value,
    mongo_url: &str,
    fixture: &OwnedProxyDeleteFixture,
    spec_id: &str,
) {
    let rendered = body.to_string();
    for forbidden in [
        mongo_url,
        fixture.proxy_id.as_str(),
        fixture.upstream_id.as_str(),
        fixture.plugin_id.as_str(),
        spec_id,
    ] {
        assert!(
            !rendered.contains(forbidden),
            "delete error must not expose database or ownership identifiers: {body:?}"
        );
    }
}

/// A standalone deployment must refuse a direct delete of an API-spec-owned
/// proxy before touching any member of the ownership graph or its change log.
#[tokio::test]
#[ignore]
async fn test_mongodb_standalone_owned_proxy_delete_refuses_before_mutation() {
    let mongo_url =
        std::env::var("FERRUM_TEST_MONGO_URL").unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let mut harness = MongoTestHarness::new().await.expect("create harness");
    harness
        .start_gateway_plaintext(&mongo_url)
        .await
        .expect("start gateway with standalone MongoDB");
    let client = reqwest::Client::new();
    let auth_header = format!("Bearer {}", harness.generate_token().expect("token"));
    let fixture = OwnedProxyDeleteFixture::new("standalone-owned-delete");
    let spec_id =
        submit_owned_proxy_fixture(&client, &harness, &auth_header, &fixture).await;
    let db = mongo_database(&mongo_url).await;
    let before = owned_proxy_delete_snapshot(&db, &fixture, &spec_id).await;
    assert_eq!(
        before,
        OwnedProxyDeleteSnapshot {
            proxies: 1,
            plugin_configs: 1,
            api_specs: 1,
            upstreams: 1,
            config_changes: 3,
        },
        "fixture must contain the complete ownership graph before refusal"
    );

    let response = client
        .delete(format!(
            "{}/proxies/{}",
            harness.admin_base_url, fixture.proxy_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("delete API-spec-owned proxy");
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status.as_u16(),
        501,
        "standalone owned proxy deletion must fail closed: {body:?}"
    );
    assert_eq!(
        body["error"],
        "Atomic deletion of an API-spec-owned proxy is not supported by the configured database deployment"
    );
    assert!(
        body["detail"]
            .as_str()
            .unwrap_or_default()
            .contains("FERRUM_MONGO_REPLICA_SET"),
        "refusal must name the transaction-capable remediation: {body:?}"
    );
    assert_delete_error_is_redacted(&body, &mongo_url, &fixture, &spec_id);

    let after = owned_proxy_delete_snapshot(&db, &fixture, &spec_id).await;
    assert_eq!(
        after, before,
        "preflight refusal must leave proxy, plugin, owner spec, generated upstream, and config changes untouched"
    );
}

async fn assert_replica_set_delete_failure_rolls_back(collection: &str) {
    let Ok(replica_set) = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET") else {
        println!("SKIP: FERRUM_TEST_MONGO_REPLICA_SET not set");
        return;
    };
    let mongo_url = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET_URL")
        .or_else(|_| std::env::var("FERRUM_TEST_MONGO_URL"))
        .unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let mut harness = MongoTestHarness::new().await.expect("create harness");
    harness
        .start_gateway_replica_set(&mongo_url, &replica_set)
        .await
        .expect("start gateway with MongoDB replica set");
    let client = reqwest::Client::new();
    let auth_header = format!("Bearer {}", harness.generate_token().expect("token"));
    let fixture = OwnedProxyDeleteFixture::new(collection);
    let spec_id =
        submit_owned_proxy_fixture(&client, &harness, &auth_header, &fixture).await;
    let db = mongo_database(&mongo_url).await;
    let before = owned_proxy_delete_snapshot(&db, &fixture, &spec_id).await;
    assert_eq!(
        before,
        OwnedProxyDeleteSnapshot {
            proxies: 1,
            plugin_configs: 1,
            api_specs: 1,
            upstreams: 1,
            config_changes: 3,
        },
        "failpoint fixture must contain the complete ownership graph"
    );

    let (failpoint_client, initial_count) =
        enable_delete_failpoint(&mongo_url, &harness.mongo_app_name, collection).await;
    let response_result = client
        .delete(format!(
            "{}/proxies/{}",
            harness.admin_base_url, fixture.proxy_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await;
    disable_delete_failpoint(&failpoint_client, initial_count).await;
    let response = response_result.expect("delete request with MongoDB failpoint");
    let status = response.status();
    let body: serde_json::Value = response.json().await.unwrap_or_else(|_| json!({}));
    assert_eq!(
        status.as_u16(),
        503,
        "a failed {collection} cascade command must never report success: {body:?}"
    );
    assert_delete_error_is_redacted(&body, &mongo_url, &fixture, &spec_id);

    let after = owned_proxy_delete_snapshot(&db, &fixture, &spec_id).await;
    assert_eq!(
        after, before,
        "the transaction must roll back every resource and change record after {collection} deletion fails"
    );
}

/// The owner-row delete occurs after proxy/plugin mutations inside the MongoDB
/// transaction. Injecting failure there must abort the whole transaction.
#[tokio::test]
#[ignore]
async fn test_mongodb_replica_set_owner_delete_failure_rolls_back() {
    assert_replica_set_delete_failure_rolls_back("api_specs").await;
}

/// The generated-upstream delete occurs after the owner row inside the same
/// transaction. Injecting failure there must restore the full graph and require
/// no convergence tombstones because nothing committed.
#[tokio::test]
#[ignore]
async fn test_mongodb_replica_set_owned_upstream_delete_failure_rolls_back() {
    assert_replica_set_delete_failure_rolls_back("upstreams").await;
}

/// The transaction-capable path still removes the complete ownership graph and
/// commits one coherent runtime deletion record for each affected resource.
#[tokio::test]
#[ignore]
async fn test_mongodb_replica_set_owned_proxy_delete_commits_complete_graph() {
    let Ok(replica_set) = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET") else {
        println!("SKIP: FERRUM_TEST_MONGO_REPLICA_SET not set");
        return;
    };
    let mongo_url = std::env::var("FERRUM_TEST_MONGO_REPLICA_SET_URL")
        .or_else(|_| std::env::var("FERRUM_TEST_MONGO_URL"))
        .unwrap_or_else(|_| DEFAULT_MONGO_URL.to_string());
    if !mongodb_is_available(&mongo_url).await {
        return;
    }

    let mut harness = MongoTestHarness::new().await.expect("create harness");
    harness
        .start_gateway_replica_set(&mongo_url, &replica_set)
        .await
        .expect("start gateway with MongoDB replica set");
    let client = reqwest::Client::new();
    let auth_header = format!("Bearer {}", harness.generate_token().expect("token"));
    let fixture = OwnedProxyDeleteFixture::new("transactional-owned-delete");
    let spec_id =
        submit_owned_proxy_fixture(&client, &harness, &auth_header, &fixture).await;
    let db = mongo_database(&mongo_url).await;

    let response = client
        .delete(format!(
            "{}/proxies/{}",
            harness.admin_base_url, fixture.proxy_id
        ))
        .header("Authorization", &auth_header)
        .send()
        .await
        .expect("delete API-spec-owned proxy transactionally");
    assert_eq!(
        response.status().as_u16(),
        204,
        "transactional owned proxy deletion must succeed"
    );

    let after = owned_proxy_delete_snapshot(&db, &fixture, &spec_id).await;
    assert_eq!(after.proxies, 0, "proxy must be deleted");
    assert_eq!(after.plugin_configs, 0, "scoped plugin must be deleted");
    assert_eq!(after.api_specs, 0, "owning API spec must be deleted");
    assert_eq!(after.upstreams, 0, "generated upstream must be deleted");
    assert_eq!(
        after.config_changes, 6,
        "three create records plus three coherent delete records must remain"
    );

    for (resource_type, resource_id) in [
        ("proxy", fixture.proxy_id.as_str()),
        ("plugin_config", fixture.plugin_id.as_str()),
        ("upstream", fixture.upstream_id.as_str()),
    ] {
        let delete_changes = db
            .collection::<Document>("config_changes")
            .count_documents(doc! {
                "namespace": "ferrum",
                "resource_type": resource_type,
                "resource_id": resource_id,
                "operation": "delete",
            })
            .await
            .expect("count coherent delete change");
        assert_eq!(
            delete_changes, 1,
            "transaction must emit exactly one delete record for {resource_type}"
        );
    }
}
