//! CORS request/response parity across H1, H2, and H3 frontends.

use crate::common::{EchoServer, TestGateway, spawn_http_echo};
use crate::scaffolding::clients::{GetOptions, Http3Client};
use crate::scaffolding::ports::reserve_port;

use bytes::Bytes;
use http::{HeaderMap, Method, StatusCode};
use std::time::{Duration, Instant};

const ORIGIN: &str = "https://app.example";
const CANONICAL_ORIGIN: &str = "https://xn--bcher-kva.example";

#[derive(Debug)]
struct CapturedResponse {
    status: StatusCode,
    headers: HeaderMap,
    body: Bytes,
}

#[ignore]
#[tokio::test]
async fn functional_cors_forwarded_preflight_and_composition_match_h1_h2_h3() {
    let mut harness = CorsProtocolHarness::spawn().await;

    let allowed_h1 = send_h1(&harness, Method::OPTIONS, Some("PUT"), Some("X-Custom")).await;
    let allowed_h2 = send_h2(&harness, Method::OPTIONS, Some("PUT"), Some("X-Custom")).await;
    let allowed_h3 = send_h3(&harness, Method::OPTIONS, Some("PUT"), Some("X-Custom")).await;
    for response in [&allowed_h1, &allowed_h2, &allowed_h3] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            String::from_utf8_lossy(&response.body).contains("cors-protocol"),
            "forwarded preflight must retain the backend body: {response:?}"
        );
        assert_eq!(header(response, "access-control-allow-origin"), ORIGIN);
        assert_eq!(header(response, "access-control-allow-methods"), "PUT");
        assert_eq!(header(response, "access-control-allow-headers"), "X-Custom");
        assert_eq!(header(response, "access-control-max-age"), "600");
        assert_eq!(header(response, "access-control-allow-credentials"), "true");
        assert_eq!(
            header(response, "access-control-expose-headers"),
            "X-Response"
        );
        assert_vary(response, "Origin");
        assert_vary(response, "Access-Control-Request-Method");
        assert_vary(response, "Access-Control-Request-Headers");
    }

    for response in [&allowed_h2, &allowed_h3] {
        assert_eq!(response.body, allowed_h1.body);
    }

    for response in [
        send_h1(&harness, Method::OPTIONS, Some("DELETE"), None).await,
        send_h2(&harness, Method::OPTIONS, Some("DELETE"), None).await,
        send_h3(&harness, Method::OPTIONS, Some("DELETE"), None).await,
    ] {
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(
            String::from_utf8_lossy(&response.body).contains("CORS method not allowed: DELETE"),
            "later CORS policy must reject the conflicting preflight method: {response:?}"
        );
    }

    for response in [
        send_h1(&harness, Method::DELETE, None, None).await,
        send_h2(&harness, Method::DELETE, None, None).await,
        send_h3(&harness, Method::DELETE, None, None).await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(
            String::from_utf8_lossy(&response.body).contains("cors-protocol"),
            "preflight-only method policy must not reject the actual request: {response:?}"
        );
        assert_eq!(header(&response, "access-control-allow-origin"), ORIGIN);
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-methods")
        );
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-headers")
        );
    }

    for response in [
        send_h1(
            &harness,
            Method::OPTIONS,
            Some("PUT"),
            Some("Authorization"),
        )
        .await,
        send_h2(
            &harness,
            Method::OPTIONS,
            Some("PUT"),
            Some("Authorization"),
        )
        .await,
        send_h3(
            &harness,
            Method::OPTIONS,
            Some("PUT"),
            Some("Authorization"),
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(
            String::from_utf8_lossy(&response.body)
                .contains("CORS header not allowed: Authorization"),
            "later CORS policy must reject the conflicting header: {response:?}"
        );
    }

    for response in [
        send_h1_path(&harness, "/mixed-cors", Method::GET, None, None, ORIGIN).await,
        send_h2_path(&harness, "/mixed-cors", Method::GET, None, None, ORIGIN).await,
        send_h3_path(&harness, "/mixed-cors", Method::GET, None, None, ORIGIN).await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&response.body).contains("mixed-cors"));
        assert_eq!(header(&response, "access-control-allow-origin"), ORIGIN);
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-methods")
        );
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-headers")
        );
    }

    for response in [
        send_h1_path(
            &harness,
            "/mixed-cors",
            Method::OPTIONS,
            Some("GET"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h2_path(
            &harness,
            "/mixed-cors",
            Method::OPTIONS,
            Some("GET"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h3_path(
            &harness,
            "/mixed-cors",
            Method::OPTIONS,
            Some("GET"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::FORBIDDEN);
        assert!(
            String::from_utf8_lossy(&response.body).contains("CORS method not allowed: GET"),
            "the empty Istio preflight list must narrow the native approval: {response:?}"
        );
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            "https://other.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            "https://other.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            "https://other.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&response.body).contains("istio-forward"));
        assert!(!response.headers.contains_key("access-control-allow-origin"));
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-forward",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-forward",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-forward",
            Method::GET,
            None,
            None,
            "https://other.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(String::from_utf8_lossy(&response.body).contains("istio-forward"));
        assert!(!response.headers.contains_key("access-control-allow-origin"));
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-ignore",
            Method::OPTIONS,
            Some("DELETE"),
            None,
            "https://other.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-ignore",
            Method::OPTIONS,
            Some("DELETE"),
            None,
            "https://other.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-ignore",
            Method::OPTIONS,
            Some("DELETE"),
            None,
            "https://other.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert!(!response.headers.contains_key("access-control-allow-origin"));
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-forward",
            Method::OPTIONS,
            Some("DELETE"),
            Some("Authorization"),
            ORIGIN,
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert!(response.body.is_empty());
        assert_eq!(header(&response, "access-control-allow-origin"), ORIGIN);
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-methods")
        );
        assert!(
            !response
                .headers
                .contains_key("access-control-allow-headers")
        );
        assert!(!response.headers.contains_key("access-control-max-age"));
    }

    for response in [
        send_h1_path(
            &harness,
            "/istio-star",
            Method::GET,
            None,
            None,
            "https://anything.example",
        )
        .await,
        send_h2_path(
            &harness,
            "/istio-star",
            Method::GET,
            None,
            None,
            "https://anything.example",
        )
        .await,
        send_h3_path(
            &harness,
            "/istio-star",
            Method::GET,
            None,
            None,
            "https://anything.example",
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(header(&response, "access-control-allow-origin"), "*");
    }

    for response in [
        send_h1_path(
            &harness,
            "/canonical",
            Method::GET,
            None,
            None,
            CANONICAL_ORIGIN,
        )
        .await,
        send_h2_path(
            &harness,
            "/canonical",
            Method::GET,
            None,
            None,
            CANONICAL_ORIGIN,
        )
        .await,
        send_h3_path(
            &harness,
            "/canonical",
            Method::GET,
            None,
            None,
            CANONICAL_ORIGIN,
        )
        .await,
    ] {
        assert_eq!(response.status, StatusCode::OK);
        assert_eq!(
            header(&response, "access-control-allow-origin"),
            CANONICAL_ORIGIN,
            "configured Unicode host and default HTTPS port must match the browser-serialized origin"
        );
    }

    harness.shutdown();
}

struct CorsProtocolHarness {
    gateway: TestGateway,
    echo: EchoServer,
    https_port: u16,
}

impl CorsProtocolHarness {
    async fn spawn() -> Self {
        let mut echo = spawn_http_echo().await.expect("spawn CORS backend");
        let config = cors_config(echo.port);
        let mut last_error = String::new();
        for _ in 0..5 {
            let reservation = reserve_port().await.expect("reserve HTTPS port");
            let https_port = reservation.drop_and_take_port();
            let spawn = TestGateway::builder()
                .mode_file(config.clone())
                .log_level("warn")
                // The pinned HTTPS/QUIC port must change between attempts, so
                // this outer loop owns startup retries.
                .max_attempts(1)
                .env("FERRUM_ENABLE_HTTP3", "true")
                .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
                .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
                .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
                .spawn()
                .await;
            match spawn {
                Ok(mut gateway) => {
                    match gateway.wait_for_proxy_port(Duration::from_secs(5)).await {
                        Ok(()) => {
                            return Self {
                                gateway,
                                echo,
                                https_port,
                            };
                        }
                        Err(error) => {
                            last_error = error.to_string();
                            gateway.shutdown();
                        }
                    }
                }
                Err(error) => last_error = error.to_string(),
            }
        }
        echo.abort();
        panic!("start CORS protocol gateway after retries: {last_error}");
    }

    fn h1_h2_url(&self, path: &str) -> String {
        self.gateway.proxy_url(path)
    }

    fn h3_url(&self, path: &str) -> String {
        format!("https://localhost:{}{path}", self.https_port)
    }

    fn shutdown(&mut self) {
        self.gateway.shutdown();
        self.echo.abort();
    }
}

fn cors_config(backend_port: u16) -> String {
    let proxies = vec![
        cors_proxy(
            "cors-protocol",
            "/cors-protocol",
            backend_port,
            &["cors-wide", "cors-narrow"],
        ),
        cors_proxy(
            "istio-forward",
            "/istio-forward",
            backend_port,
            &["istio-forward"],
        ),
        cors_proxy(
            "istio-ignore",
            "/istio-ignore",
            backend_port,
            &["istio-ignore"],
        ),
        cors_proxy(
            "mixed-cors",
            "/mixed-cors",
            backend_port,
            &["mixed-native", "mixed-istio"],
        ),
        cors_proxy("istio-star", "/istio-star", backend_port, &["istio-star"]),
        cors_proxy("canonical", "/canonical", backend_port, &["canonical"]),
    ];
    let config = serde_json::json!({
        "version": "1",
        "proxies": proxies,
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [
            {
                "id": "cors-wide",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "cors-protocol",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": ["PUT", "DELETE"],
                    "allowed_headers": ["X-Custom", "Authorization"],
                    "exposed_headers": ["X-Response", "X-Wide"],
                    "allow_credentials": true,
                    "max_age": 900,
                    "preflight_continue": true
                }
            },
            {
                "id": "cors-narrow",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "cors-protocol",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": ["PUT"],
                    "allowed_headers": ["X-Custom"],
                    "exposed_headers": ["X-Response"],
                    "allow_credentials": true,
                    "max_age": 600,
                    "preflight_continue": true
                }
            },
            {
                "id": "mixed-native",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "mixed-cors",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": ["GET"],
                    "allowed_headers": ["Authorization"]
                }
            },
            {
                "id": "mixed-istio",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "mixed-cors",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "forward"
                }
            },
            {
                "id": "istio-forward",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "istio-forward",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "forward"
                }
            },
            {
                "id": "istio-ignore",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "istio-ignore",
                "enabled": true,
                "config": {
                    "allowed_origins": [ORIGIN],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "ignore"
                }
            },
            {
                "id": "istio-star",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "istio-star",
                "enabled": true,
                "config": {
                    "allowed_origins": [{"exact": "*"}],
                    "allowed_methods": [],
                    "allowed_headers": [],
                    "exposed_headers": [],
                    "unmatched_preflights": "forward"
                }
            },
            {
                "id": "canonical",
                "plugin_name": "cors",
                "scope": "proxy",
                "proxy_id": "canonical",
                "enabled": true,
                "config": {
                    "allowed_origins": ["HTTPS://BÜCHER.EXAMPLE:443"]
                }
            }
        ]
    });
    serde_yaml::to_string(&config).expect("serialize CORS config")
}

fn cors_proxy(
    id: &str,
    listen_path: &str,
    backend_port: u16,
    plugin_ids: &[&str],
) -> serde_json::Value {
    let plugins = plugin_ids
        .iter()
        .map(|plugin_config_id| {
            serde_json::json!({
                "plugin_config_id": plugin_config_id
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "id": id,
        "listen_path": listen_path,
        "backend_scheme": "http",
        "backend_host": "127.0.0.1",
        "backend_port": backend_port,
        "strip_listen_path": false,
        "pool_enable_http2": false,
        "plugins": plugins
    })
}

fn apply_cors_headers(
    mut request: reqwest::RequestBuilder,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> reqwest::RequestBuilder {
    request = request.header("origin", origin);
    if let Some(method) = requested_method {
        request = request.header("access-control-request-method", method);
    }
    if let Some(headers) = requested_headers {
        request = request.header("access-control-request-headers", headers);
    }
    request
}

async fn send_h1(
    harness: &CorsProtocolHarness,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
) -> CapturedResponse {
    send_h1_path(
        harness,
        "/cors-protocol",
        method,
        requested_method,
        requested_headers,
        ORIGIN,
    )
    .await
}

async fn send_h1_path(
    harness: &CorsProtocolHarness,
    path: &str,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> CapturedResponse {
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("H1 client");
    let response = apply_cors_headers(
        client.request(method, harness.h1_h2_url(path)),
        requested_method,
        requested_headers,
        origin,
    )
    .send()
    .await
    .expect("H1 CORS request");
    capture_reqwest(response).await
}

async fn send_h2(
    harness: &CorsProtocolHarness,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
) -> CapturedResponse {
    send_h2_path(
        harness,
        "/cors-protocol",
        method,
        requested_method,
        requested_headers,
        ORIGIN,
    )
    .await
}

async fn send_h2_path(
    harness: &CorsProtocolHarness,
    path: &str,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> CapturedResponse {
    let client = reqwest::Client::builder()
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("H2 client");
    let response = apply_cors_headers(
        client.request(method, harness.h1_h2_url(path)),
        requested_method,
        requested_headers,
        origin,
    )
    .send()
    .await
    .expect("H2 CORS request");
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    capture_reqwest(response).await
}

async fn capture_reqwest(response: reqwest::Response) -> CapturedResponse {
    let status = response.status();
    let headers = response.headers().clone();
    let body = response.bytes().await.expect("response body");
    CapturedResponse {
        status,
        headers,
        body,
    }
}

async fn send_h3(
    harness: &CorsProtocolHarness,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
) -> CapturedResponse {
    send_h3_path(
        harness,
        "/cors-protocol",
        method,
        requested_method,
        requested_headers,
        ORIGIN,
    )
    .await
}

async fn send_h3_path(
    harness: &CorsProtocolHarness,
    path: &str,
    method: Method,
    requested_method: Option<&str>,
    requested_headers: Option<&str>,
    origin: &str,
) -> CapturedResponse {
    let client = Http3Client::insecure().expect("H3 client");
    let mut options = GetOptions::default().method(method);
    options = options.header("origin", origin);
    if let Some(method) = requested_method {
        options = options.header("access-control-request-method", method);
    }
    if let Some(headers) = requested_headers {
        options = options.header("access-control-request-headers", headers);
    }

    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        match client
            .get_with_options(&harness.h3_url(path), options.clone())
            .await
        {
            Ok(response) => {
                return CapturedResponse {
                    status: response.status,
                    headers: response.headers,
                    body: response.body_bytes,
                };
            }
            Err(_) if Instant::now() < deadline => {
                tokio::time::sleep(Duration::from_millis(100)).await;
            }
            Err(error) => panic!("H3 CORS request did not complete: {error}"),
        }
    }
}

fn header<'a>(response: &'a CapturedResponse, name: &str) -> &'a str {
    response
        .headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("missing {name}: {response:?}"))
}

fn assert_vary(response: &CapturedResponse, expected: &str) {
    assert!(
        header(response, "vary")
            .split(',')
            .any(|value| value.trim().eq_ignore_ascii_case(expected)),
        "missing Vary token {expected}: {response:?}"
    );
}
