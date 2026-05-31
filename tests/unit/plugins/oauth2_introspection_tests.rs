use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, RequestContext, oauth2_introspection::Oauth2Introspection, priority,
};
use serde_json::json;
use std::collections::HashMap;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{assert_continue, assert_reject};

fn make_ctx(token: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.headers
        .insert("authorization".to_string(), format!("Bearer {token}"));
    ctx
}

fn config(endpoint: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "introspection_endpoint": endpoint,
            "client_auth": {"method": "none"}
        }]
    })
}

fn config_with_client_auth(endpoint: &str, method: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "introspection_endpoint": endpoint,
            "client_auth": {
                "method": method,
                "client_id": "cid",
                "client_secret": "shhh",
                "private_key_pem": "not-a-real-pem"
            }
        }]
    })
}

fn discovery_config_with_client_auth(discovery_url: &str, method: &str) -> serde_json::Value {
    json!({
        "providers": [{
            "discovery_url": discovery_url,
            "client_auth": {
                "method": method,
                "client_id": "cid",
                "client_secret": "shhh"
            }
        }]
    })
}

#[test]
fn new_rejects_empty_providers() {
    assert!(
        Oauth2Introspection::new(&json!({"providers": []}), PluginHttpClient::default()).is_err()
    );
}

#[test]
fn new_rejects_credentialed_client_auth_for_remote_http_endpoint() {
    // The invalid private-key PEM is intentional: private_key_jwt must fail on
    // the plaintext remote endpoint before any secret material is parsed.
    for method in [
        "client_secret_basic",
        "client_secret_post",
        "private_key_jwt",
    ] {
        let err = Oauth2Introspection::new(
            &config_with_client_auth("http://idp.internal/introspect", method),
            PluginHttpClient::default(),
        )
        .err()
        .expect("remote http endpoint should reject credentialed auth");
        assert!(
            err.contains("requires an https"),
            "method {method} produced unexpected error: {err}"
        );
    }
}

#[test]
fn new_accepts_credentialed_client_auth_for_remote_https_endpoint() {
    for method in ["client_secret_basic", "client_secret_post"] {
        assert!(
            Oauth2Introspection::new(
                &config_with_client_auth("https://idp.internal/introspect", method),
                PluginHttpClient::default(),
            )
            .is_ok(),
            "method {method} should accept remote https endpoint"
        );
    }
}

#[test]
fn new_accepts_credentialed_client_auth_for_loopback_http_endpoint() {
    for endpoint in [
        "http://localhost:9000/introspect",
        "http://127.0.0.1:9000/introspect",
        "http://[::1]:9000/introspect",
    ] {
        assert!(
            Oauth2Introspection::new(
                &config_with_client_auth(endpoint, "client_secret_basic"),
                PluginHttpClient::default(),
            )
            .is_ok(),
            "loopback http endpoint {endpoint} should be accepted"
        );
    }
}

#[test]
fn new_accepts_credentialed_client_auth_with_discovery_url() {
    assert!(
        Oauth2Introspection::new(
            &discovery_config_with_client_auth(
                "https://issuer.example.com/.well-known/openid-configuration",
                "client_secret_basic",
            ),
            PluginHttpClient::default(),
        )
        .is_ok()
    );
}

#[test]
fn new_rejects_none_client_auth_for_remote_endpoint() {
    let err = match Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": "https://auth.example.com/introspect",
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    ) {
        Ok(_) => panic!("remote none auth should reject"),
        Err(err) => err,
    };
    assert!(err.contains("only allowed"));
}

#[test]
fn new_accepts_none_client_auth_for_localhost_endpoint() {
    assert!(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": "http://localhost:8080/introspect",
                    "client_auth": {"method": "none"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .is_ok()
    );
}

#[test]
fn new_rejects_none_client_auth_for_local_mdns_endpoint() {
    assert!(
        Oauth2Introspection::new(
            &json!({
                "providers": [{
                    "introspection_endpoint": "http://idp.local/introspect",
                    "client_auth": {"method": "none"}
                }]
            }),
            PluginHttpClient::default(),
        )
        .is_err()
    );
}

#[tokio::test]
async fn active_token_sets_authenticated_identity_when_no_consumer_match() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "scope": "read:data"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.priority(), priority::OAUTH2_INTROSPECTION);
    // Unique token per test: the introspection cache is process-global and keyed
    // by endpoint, and wiremock reuses freed ports across tests, so a shared
    // token string could yield a cross-test cache hit.
    let mut ctx = make_ctx("active-opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("external-user"));
    assert_eq!(ctx.auth_method, Some("oauth2_introspection"));
}

#[tokio::test]
async fn inactive_token_rejects_with_401() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(&config(&endpoint), PluginHttpClient::default()).unwrap();
    let mut ctx = make_ctx("inactive-opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

#[tokio::test]
async fn cached_token_does_not_bypass_stricter_provider_policy() {
    // Regression: the positive introspection cache is process-global. Before the
    // cache key was partitioned by issuer/audience, a token validated by a
    // permissive provider (no iss/aud constraints) sharing an endpoint+client_id
    // with a stricter provider would be served from cache to the stricter provider,
    // skipping its `iss`/`aud` re-validation. Both providers point at one endpoint
    // whose response carries an issuer/audience the stricter provider rejects.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "iss": "https://issuer-a.example",
            "aud": "audience-a"
        })))
        .mount(&server)
        .await;
    let endpoint = format!("{}/introspect", server.uri());

    // Permissive provider: no issuer/audience constraints -> accepts and caches.
    let permissive = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    // Stricter provider: same endpoint + client auth, but enforces a different
    // issuer/audience than the introspection response carries.
    let strict = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "issuer": "https://issuer-b.example",
                "audiences": ["audience-b"]
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let consumers = ConsumerIndex::new(&[]);

    // Permissive provider accepts and populates its positive cache.
    let mut ctx = make_ctx("shared-token");
    assert_continue(permissive.authenticate(&mut ctx, &consumers).await);

    // Stricter provider must re-validate issuer/audience instead of reusing the
    // permissive provider's cached claims, so it rejects with 401.
    let mut ctx = make_ctx("shared-token");
    assert_reject(strict.authenticate(&mut ctx, &consumers).await, Some(401));
}

#[tokio::test]
async fn claims_to_headers_and_forward_original_false_strip_authorization() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "external-user",
            "email": "user@example.com"
        })))
        .mount(&server)
        .await;

    let endpoint = format!("{}/introspect", server.uri());
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": endpoint,
                "client_auth": {"method": "none"},
                "forward_original_token": false,
                "claim_headers": {"email": "X-User-Email"}
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = make_ctx("claims-opaque-token");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);

    let mut headers = HashMap::from([(
        "authorization".to_string(),
        "Bearer claims-opaque-token".to_string(),
    )]);
    let result = plugin.before_proxy(&mut ctx, &mut headers).await;
    assert_continue(result);
    assert!(!headers.contains_key("authorization"));
    assert_eq!(
        headers.get("x-user-email").map(String::as_str),
        Some("user@example.com")
    );
}

#[tokio::test]
async fn multi_provider_falls_through_to_provider_that_accepts_token() {
    // Two providers share the default Authorization-bearer token location (the
    // common multi-IdP setup). The first provider does not recognize the token
    // (active:false); the second does. Routing must try the second provider
    // instead of rejecting on the first provider's verdict.
    let provider_a = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({"active": false})))
        .mount(&provider_a)
        .await;
    let provider_b = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "active": true,
            "username": "user-from-b"
        })))
        .mount(&provider_b)
        .await;

    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [
                {
                    "introspection_endpoint": format!("{}/introspect", provider_a.uri()),
                    "client_auth": {"method": "none"}
                },
                {
                    "introspection_endpoint": format!("{}/introspect", provider_b.uri()),
                    "client_auth": {"method": "none"}
                }
            ]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();

    let mut ctx = make_ctx("token-owned-by-provider-b");
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_continue(result);
    assert_eq!(ctx.authenticated_identity.as_deref(), Some("user-from-b"));
    assert_eq!(ctx.auth_method, Some("oauth2_introspection"));
}

#[tokio::test]
async fn query_param_token_marks_shared_strip_prefix_for_proxy() {
    // forward_original_token=false on a query-param token must mark the param for
    // stripping with the shared `auth.strip_query_param.` prefix the proxy honors.
    // oauth2 previously used a private prefix the proxy ignored, leaking the token
    // to the backend.
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/introspect"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(json!({"active": true, "username": "u"})),
        )
        .mount(&server)
        .await;
    let plugin = Oauth2Introspection::new(
        &json!({
            "providers": [{
                "introspection_endpoint": format!("{}/introspect", server.uri()),
                "client_auth": {"method": "none"},
                "from_params": ["access_token"],
                "forward_original_token": false
            }]
        }),
        PluginHttpClient::default(),
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/test".into());
    ctx.query_params
        .insert("access_token".to_string(), "qp-opaque-token".to_string());
    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert!(
        ctx.metadata
            .contains_key("auth.strip_query_param.access_token")
    );
    assert!(!ctx.query_params.contains_key("access_token"));
}
