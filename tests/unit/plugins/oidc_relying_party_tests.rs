use ferrum_edge::_test_support::{
    oidc_sealed_due_refresh_session_cookie_for_test, oidc_sealed_session_cookie_for_test,
    oidc_session_state_from_set_cookie_for_test,
};
use ferrum_edge::ConsumerIndex;
use ferrum_edge::config::types::AuthMode;
use ferrum_edge::plugins::validate_plugin_config;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, key_auth::KeyAuth,
    oidc_relying_party::OidcRelyingParty, priority,
};
use ferrum_edge::proxy::run_authentication_phase;
use serde_json::json;
use std::collections::HashMap;
use std::sync::Arc;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::plugin_utils::{assert_continue, assert_reject, create_test_consumer};

fn base_config() -> serde_json::Value {
    json!({
        "providers": [{
            "issuer": "https://issuer.example.com",
            "authorization_endpoint": "https://issuer.example.com/authorize",
            "token_endpoint": "https://issuer.example.com/token",
            "jwks_uri": "https://issuer.example.com/jwks",
            "client_id": "ferrum-gateway",
            "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
            "scopes": ["openid", "profile"],
            "redirect_uri": "https://app.example.com/oauth/callback",
            "callback_path": "/oauth/callback",
            "logout_path": "/oauth/logout"
        }],
        "session": {
            "store": "cookie",
            "cookie_name": "ferrum_session",
            "encryption_secret": "01234567890123456789012345678901"
        },
        "behavior": {
            "trusted_redirect_hosts": ["app.example.com"],
            "post_login_redirect_param": "rd"
        }
    })
}

fn html_ctx() -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.headers
        .insert("accept".to_string(), "text/html".to_string());
    ctx.headers
        .insert("host".to_string(), "app.example.com".to_string());
    ctx.metadata
        .insert("ferrum.frontend_scheme".to_string(), "https".to_string());
    ctx
}

fn refresh_rejection_plugin(token_endpoint: &str) -> OidcRelyingParty {
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(token_endpoint);
    config["providers"][0]["required_scopes"] = json!(["admin"]);
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"role": "X-Untrusted-Role"});
    OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap()
}

fn ctx_with_session_cookie(set_cookie: &str) -> RequestContext {
    let cookie_pair = set_cookie
        .split('\n')
        .find(|cookie| cookie.trim_start().starts_with("ferrum_session="))
        .expect("OIDC session cookie")
        .split(';')
        .next()
        .expect("OIDC session cookie pair")
        .to_string();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.headers.insert("cookie".to_string(), cookie_pair);
    ctx
}

#[tokio::test]
async fn new_accepts_minimal_cookie_store_config() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.name(), "oidc_relying_party");
    assert_eq!(plugin.priority(), priority::OIDC_RELYING_PARTY);
}

#[tokio::test]
async fn oidc_success_commits_claim_headers_and_rolling_cookie_together() {
    let mut config = base_config();
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"role": "X-Trusted-Role"});
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let now = chrono::Utc::now().timestamp();
    let set_cookie = oidc_sealed_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "external@example.test",
            "role": "operator",
            "exp": now + 3600
        }),
        true,
    )
    .unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.headers.insert(
        "cookie".to_string(),
        set_cookie.split(';').next().unwrap().to_string(),
    );

    assert_continue(
        plugin
            .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(
        ctx.authenticated_identity.as_deref(),
        Some("external@example.test")
    );
    assert_eq!(ctx.auth_method, Some("oidc_relying_party"));

    let mut request_headers = HashMap::new();
    assert_continue(plugin.before_proxy(&mut ctx, &mut request_headers).await);
    assert_eq!(
        request_headers.get("x-trusted-role").map(String::as_str),
        Some("operator")
    );
    let mut response_headers = HashMap::new();
    assert_continue(
        plugin
            .after_proxy(&mut ctx, 200, &mut response_headers)
            .await,
    );
    assert!(response_headers.contains_key("set-cookie"));
}

#[tokio::test]
async fn oidc_single_auth_scope_rejection_returns_rotated_refresh_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = Arc::new(refresh_rejection_plugin(&format!("{}/token", server.uri())));
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut ctx = ctx_with_session_cookie(&cookie);

    let plugin_for_phase: Arc<dyn Plugin> = plugin.clone();
    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Single,
        &[plugin_for_phase],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("scope-rejected OIDC session must reject");
    assert_eq!(status_code, 403);
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );
    let mut set_cookies = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"));
    let set_cookie = set_cookies
        .next()
        .map(|(_, value)| value)
        .expect("rotated session must be returned on terminal rejection");
    assert!(set_cookies.next().is_none());
    assert!(!set_cookie.contains('\n'));
    let state = oidc_session_state_from_set_cookie_for_test(&plugin, set_cookie)
        .expect("rotated session cookie must open");
    assert_eq!(state.access_token, "new-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("rotated-refresh-token")
    );
    assert!(state.refresh_after_unix > now);
}

#[tokio::test]
async fn oidc_scope_rejection_persists_refresh_failure_backoff() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .expect(1)
        .mount(&server)
        .await;
    let plugin = refresh_rejection_plugin(&format!("{}/token", server.uri()));
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut first_ctx = ctx_with_session_cookie(&cookie);

    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin
        .authenticate(&mut first_ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("scope-rejected OIDC session must reject");
    };
    assert_eq!(status_code, 403);
    let set_cookie = headers
        .get("set-cookie")
        .expect("refresh backoff must be returned on terminal rejection");
    let state = oidc_session_state_from_set_cookie_for_test(&plugin, set_cookie)
        .expect("backoff session cookie must open");
    assert_eq!(state.access_token, "test-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("original-refresh-token")
    );
    assert!(state.refresh_after_unix >= now + 20);

    let mut second_ctx = ctx_with_session_cookie(set_cookie);
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin
        .authenticate(&mut second_ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("scope-rejected OIDC session must reject");
    };
    assert_eq!(status_code, 403);
    assert!(
        !headers.contains_key("set-cookie"),
        "a backed-off session must not be re-sealed again immediately"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the persisted backoff must suppress an immediate second refresh"
    );
}

#[tokio::test]
async fn oidc_multi_auth_preserves_rotated_cookie_when_later_credential_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["required_roles"] = json!(["admin"]);
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"roles": "X-Untrusted-Roles"});
    let oidc = Arc::new(OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap());
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "roles": ["viewer"],
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut ctx = ctx_with_session_cookie(&cookie);
    ctx.headers
        .insert("x-api-key".to_string(), "invalid-api-key".to_string());
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

    let (status_code, body, mut response_headers) = run_authentication_phase(
        AuthMode::Multi,
        &[oidc_plugin, key_auth],
        &mut ctx,
        &consumer_index,
    )
    .await
    .expect("later invalid API key must keep the request rejected");
    assert_eq!(status_code, 401, "the later client rejection must still win");
    assert_eq!(body.as_slice(), br#"{"error":"Invalid API key"}"#);
    assert!(ctx.identified_consumer.is_none());
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.authenticated_identity_header.is_none());
    assert!(ctx.auth_method.is_none());
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );

    let mut request_headers = HashMap::new();
    assert_continue(oidc.before_proxy(&mut ctx, &mut request_headers).await);
    assert!(
        !request_headers.contains_key("x-untrusted-roles"),
        "the rejected OIDC attempt must not publish claim headers"
    );

    let set_cookie = response_headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie")
                .then_some(value.clone())
        })
        .expect("the earlier rotated session must survive the later rejection");
    assert!(!set_cookie.contains('\n'));
    let state = oidc_session_state_from_set_cookie_for_test(&oidc, &set_cookie)
        .expect("rotated session cookie must open");
    assert_eq!(state.access_token, "new-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("rotated-refresh-token")
    );

    assert_continue(
        oidc.after_proxy(&mut ctx, status_code, &mut response_headers)
            .await,
    );
    assert_eq!(
        response_headers
            .keys()
            .filter(|name| name.eq_ignore_ascii_case("set-cookie"))
            .count(),
        1,
        "reject finalization must emit exactly one session cookie"
    );
    assert_eq!(
        response_headers.iter().find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie").then_some(value)
        }),
        Some(&set_cookie)
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_multi_auth_uses_latest_rejected_session_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/first-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "first-access-token",
            "token_type": "Bearer",
            "refresh_token": "first-rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    Mock::given(method("POST"))
        .and(path("/second-token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "second-access-token",
            "token_type": "Bearer",
            "refresh_token": "second-rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let rejection_plugin = |cookie_name: &str, token_path: &str| {
        let mut config = base_config();
        config["providers"][0]["token_endpoint"] =
            json!(format!("{}{token_path}", server.uri()));
        config["providers"][0]["required_scopes"] = json!(["admin"]);
        config["providers"][0]["consumer_identity_claim"] = json!("email");
        config["session"]["cookie_name"] = json!(cookie_name);
        OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap()
    };
    let first = Arc::new(rejection_plugin("first_session", "/first-token"));
    let second = Arc::new(rejection_plugin("second_session", "/second-token"));
    let now = chrono::Utc::now().timestamp();
    let claims = json!({
        "sub": "oidc-subject",
        "email": "rejected@example.test",
        "scope": "viewer",
        "exp": now + 3600
    });
    let first_cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &first,
        claims.clone(),
        "first-original-refresh-token",
    )
    .unwrap();
    let second_cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &second,
        claims,
        "second-original-refresh-token",
    )
    .unwrap();
    let first_pair = first_cookie.split(';').next().expect("first cookie pair");
    let second_pair = second_cookie
        .split(';')
        .next()
        .expect("second cookie pair");
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.headers.insert(
        "cookie".to_string(),
        format!("{first_pair}; {second_pair}"),
    );
    let first_plugin: Arc<dyn Plugin> = first.clone();
    let second_plugin: Arc<dyn Plugin> = second.clone();

    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("both scope-rejected sessions must reject");
    assert_eq!(status_code, 403);
    let mut set_cookies = headers
        .iter()
        .filter(|(name, _)| name.eq_ignore_ascii_case("set-cookie"));
    let set_cookie = set_cookies
        .next()
        .map(|(_, value)| value)
        .expect("latest rejected session cookie must reach the client");
    assert!(set_cookies.next().is_none());
    assert!(set_cookie.starts_with("second_session="));
    assert!(oidc_session_state_from_set_cookie_for_test(&first, set_cookie).is_none());
    let state = oidc_session_state_from_set_cookie_for_test(&second, set_cookie)
        .expect("latest rejected session cookie must open with its owner");
    assert_eq!(state.access_token, "second-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("second-rotated-refresh-token")
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 2);
}

#[tokio::test]
async fn oidc_multi_auth_preserves_selected_rejection_cookie() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;

    let mut first_config = base_config();
    first_config["providers"][0]["token_endpoint"] =
        json!(format!("{}/token", server.uri()));
    first_config["providers"][0]["required_scopes"] = json!(["admin"]);
    first_config["providers"][0]["consumer_identity_claim"] = json!("email");
    first_config["session"]["cookie_name"] = json!("first_session");
    let first = Arc::new(
        OidcRelyingParty::new(&first_config, PluginHttpClient::default()).unwrap(),
    );
    let mut second_config = base_config();
    second_config["session"]["cookie_name"] = json!("second_session");
    let second = Arc::new(
        OidcRelyingParty::new(&second_config, PluginHttpClient::default()).unwrap(),
    );
    let now = chrono::Utc::now().timestamp();
    let first_cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &first,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let first_pair = first_cookie.split(';').next().expect("session cookie pair");
    let mut ctx = html_ctx();
    ctx.headers
        .insert("cookie".to_string(), first_pair.to_string());
    let first_plugin: Arc<dyn Plugin> = first.clone();
    let second_plugin: Arc<dyn Plugin> = second.clone();

    let (status_code, _, mut headers) = run_authentication_phase(
        AuthMode::Multi,
        &[first_plugin, second_plugin],
        &mut ctx,
        &ConsumerIndex::new(&[]),
    )
    .await
    .expect("the later browser challenge must reject");
    assert_eq!(status_code, 302);
    assert!(
        headers
            .get("location")
            .is_some_and(|location| location.starts_with("https://issuer.example.com/authorize"))
    );
    let set_cookie = headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie")
                .then_some(value.clone())
        })
        .expect("both response-owned cookies must reach the client");
    let cookies: Vec<&str> = set_cookie.split('\n').collect();
    assert_eq!(cookies.len(), 2);
    assert!(cookies[0].contains("Path=/oauth/callback"));
    assert!(cookies[1].starts_with("first_session="));
    assert_eq!(
        cookies
            .iter()
            .filter(|cookie| cookie.starts_with("first_session="))
            .count(),
        1
    );
    let state = oidc_session_state_from_set_cookie_for_test(&first, &set_cookie)
        .expect("rotated requester session cookie must remain readable");
    assert_eq!(state.access_token, "new-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("rotated-refresh-token")
    );
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );

    assert_continue(first.after_proxy(&mut ctx, status_code, &mut headers).await);
    assert_continue(second.after_proxy(&mut ctx, status_code, &mut headers).await);
    assert_eq!(
        headers
            .iter()
            .find_map(|(name, value)| {
                name.eq_ignore_ascii_case("set-cookie").then_some(value)
            })
            .map(|value| value.split('\n').count()),
        Some(2),
        "reject finalization must not duplicate either cookie"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_multi_auth_preserves_refresh_backoff_when_later_credential_rejects() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({"error": "invalid_grant"})))
        .expect(1)
        .mount(&server)
        .await;
    let oidc = Arc::new(refresh_rejection_plugin(&format!("{}/token", server.uri())));
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let auth_plugins = [oidc_plugin, key_auth];
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "role": "viewer",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut first_ctx = ctx_with_session_cookie(&cookie);
    first_ctx
        .headers
        .insert("x-api-key".to_string(), "invalid-api-key".to_string());

    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &auth_plugins,
        &mut first_ctx,
        &consumer_index,
    )
    .await
    .expect("later invalid API key must keep the request rejected");
    assert_eq!(status_code, 401);
    let set_cookie = headers
        .iter()
        .find_map(|(name, value)| {
            name.eq_ignore_ascii_case("set-cookie")
                .then_some(value.as_str())
        })
        .expect("refresh backoff must survive the later rejection");
    let state = oidc_session_state_from_set_cookie_for_test(&oidc, set_cookie)
        .expect("backoff session cookie must open");
    assert_eq!(state.access_token, "test-access-token");
    assert_eq!(
        state.refresh_token.as_deref(),
        Some("original-refresh-token")
    );
    assert!(state.refresh_after_unix >= now + 20);

    let mut second_ctx = ctx_with_session_cookie(set_cookie);
    second_ctx
        .headers
        .insert("x-api-key".to_string(), "invalid-api-key".to_string());
    let (status_code, _, headers) = run_authentication_phase(
        AuthMode::Multi,
        &auth_plugins,
        &mut second_ctx,
        &consumer_index,
    )
    .await
    .expect("backed-off session and invalid API key must reject");
    assert_eq!(status_code, 401);
    assert!(
        headers
            .keys()
            .all(|name| !name.eq_ignore_ascii_case("set-cookie")),
        "a no-refresh attempt must not fabricate a response cookie"
    );
    assert_eq!(
        server.received_requests().await.unwrap().len(),
        1,
        "the persisted backoff must suppress an immediate second refresh"
    );
}

#[tokio::test]
async fn oidc_multi_auth_discards_scope_rejection_refresh_cookie_on_later_success() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "token_type": "Bearer",
            "refresh_token": "rotated-refresh-token",
            "expires_in": 3600
        })))
        .expect(1)
        .mount(&server)
        .await;
    let oidc = Arc::new(refresh_rejection_plugin(&format!("{}/token", server.uri())));
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_due_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "role": "attacker",
            "scope": "viewer",
            "exp": now + 3600
        }),
        "original-refresh-token",
    )
    .unwrap();
    let mut ctx = ctx_with_session_cookie(&cookie);
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

    let rejection = run_authentication_phase(
        AuthMode::Multi,
        &[oidc_plugin, key_auth],
        &mut ctx,
        &consumer_index,
    )
    .await;
    assert!(rejection.is_none(), "later key_auth must authenticate");
    assert_eq!(ctx.auth_method, Some("key_auth"));
    assert_eq!(
        ctx.identified_consumer
            .as_ref()
            .map(|consumer| consumer.username.as_str()),
        Some("testuser")
    );
    assert!(ctx.authenticated_identity.is_none());
    assert!(ctx.authenticated_identity_header.is_none());
    assert!(
        ctx.metadata
            .keys()
            .all(|key| !key.contains("rejection_set_cookie"))
    );

    let mut request_headers = HashMap::new();
    assert_continue(oidc.before_proxy(&mut ctx, &mut request_headers).await);
    assert!(
        !request_headers.contains_key("x-untrusted-role"),
        "the rejected OIDC attempt must not publish claim headers"
    );
    let mut response_headers = HashMap::new();
    assert_continue(oidc.after_proxy(&mut ctx, 200, &mut response_headers).await);
    assert!(
        !response_headers.contains_key("set-cookie"),
        "a successful later credential must discard the rejected OIDC cookie"
    );
    assert_eq!(server.received_requests().await.unwrap().len(), 1);
}

#[tokio::test]
async fn oidc_multi_auth_discards_uncommitted_attempt_metadata() {
    let mut config = base_config();
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config["providers"][0]["claim_headers"] = json!({"role": "X-Untrusted-Role"});
    config["providers"][0]["required_scopes"] = json!(["admin"]);
    let oidc = Arc::new(OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap());
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({"key_location": "header:X-API-Key"})).unwrap());
    let consumers = [create_test_consumer()];
    let consumer_index = ConsumerIndex::new(&consumers);
    let now = chrono::Utc::now().timestamp();
    let attempted_cookies = [
        oidc_sealed_session_cookie_for_test(
            &oidc,
            json!({
                "sub": "oidc-subject",
                "email": "   ",
                "role": "attacker",
                "scope": "admin",
                "exp": now + 3600
            }),
            true,
        )
        .unwrap(),
        oidc_sealed_session_cookie_for_test(
            &oidc,
            json!({
                "sub": "oidc-subject",
                "role": "attacker",
                "scope": "admin",
                "exp": now + 3600
            }),
            true,
        )
        .unwrap(),
        oidc_sealed_session_cookie_for_test(
            &oidc,
            json!({
                "sub": "oidc-subject",
                "email": "rejected@example.test",
                "role": "attacker",
                "scope": "viewer",
                "exp": now + 3600
            }),
            true,
        )
        .unwrap(),
        "ferrum_session=invalid-session".to_string(),
    ];

    for attempted_cookie in attempted_cookies {
        let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
        ctx.headers.insert(
            "cookie".to_string(),
            attempted_cookie.split(';').next().unwrap().to_string(),
        );
        ctx.headers
            .insert("x-api-key".to_string(), "test-api-key".to_string());
        let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

        let rejection = run_authentication_phase(
            AuthMode::Multi,
            &[oidc_plugin, Arc::clone(&key_auth)],
            &mut ctx,
            &consumer_index,
        )
        .await;
        assert!(rejection.is_none(), "later key_auth must authenticate");
        assert_eq!(ctx.auth_method, Some("key_auth"));

        let mut request_headers = HashMap::new();
        assert_continue(oidc.before_proxy(&mut ctx, &mut request_headers).await);
        assert!(!request_headers.contains_key("x-untrusted-role"));
        let mut response_headers = HashMap::new();
        assert_continue(oidc.after_proxy(&mut ctx, 200, &mut response_headers).await);
        assert!(
            !response_headers.contains_key("set-cookie"),
            "an uncommitted OIDC attempt must not publish rolling session state"
        );
    }
}

#[test]
fn new_rejects_missing_openid_scope() {
    let mut config = base_config();
    config["providers"][0]["scopes"] = json!(["profile"]);
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_same_site_none_without_secure() {
    let mut config = base_config();
    config["session"]["same_site"] = json!("none");
    config["session"]["secure"] = json!(false);
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_invalid_state_admission_limits() {
    for (field, value) in [
        ("state_ttl_secs", json!(0)),
        ("state_ttl_secs", json!(3601)),
        ("state_cache_max_entries", json!(0)),
        ("state_cache_max_entries_per_source", json!(0)),
    ] {
        let mut config = base_config();
        config["behavior"][field] = value;
        assert!(
            OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err(),
            "{field} must reject invalid value"
        );
    }

    let mut config = base_config();
    config["behavior"]["state_cache_max_entries"] = json!(4);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(5);
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_redis_session_store_until_implemented() {
    let mut config = base_config();
    config["session"]["store"] = json!("redis");
    config["session"]["redis_url"] = json!("redis://127.0.0.1:6379/0");
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_err());
}

#[test]
fn new_rejects_none_client_auth_for_remote_token_endpoint() {
    let mut config = base_config();
    config["providers"][0]["client_auth"] = json!({"method": "none"});
    let error = match OidcRelyingParty::new(&config, PluginHttpClient::default()) {
        Ok(_) => panic!("remote none client auth should be rejected"),
        Err(error) => error,
    };
    assert!(error.contains("client_auth.method='none'"));
}

#[tokio::test]
async fn new_accepts_uppercase_same_site_from_schema() {
    let mut config = base_config();
    config["session"]["same_site"] = json!("Lax");
    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_ok());
}

#[tokio::test]
async fn unauthenticated_html_get_returns_302() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let mut ctx = html_ctx();
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    match result {
        ferrum_edge::plugins::PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 302);
            assert!(headers.get("location").is_some_and(|value| {
                value.starts_with("https://issuer.example.com/authorize")
            }));
        }
        _ => panic!("expected redirect"),
    }
}

#[tokio::test]
async fn correlation_cookie_preserves_configured_session_domain() {
    let mut config = base_config();
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let mut ctx = html_ctx();

    match plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
    {
        PluginResult::Reject { headers, .. } => {
            let cookie = headers
                .get("set-cookie")
                .expect("browser challenge correlation cookie");
            assert!(cookie.contains("Domain=example.com"));
            assert!(cookie.contains("Path=/oauth/callback"));
            assert!(cookie.contains("SameSite=Lax"));
            assert!(cookie.contains("Secure"));
            assert!(cookie.contains("HttpOnly"));
        }
        other => panic!("expected browser challenge, got {other:?}"),
    }
}

#[tokio::test]
async fn unauthenticated_api_post_returns_401() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "POST".into(), "/api".into());
    let result = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await;
    assert_reject(result, Some(401));
}

#[test]
fn rejects_unknown_fields_at_every_config_boundary() {
    for (scope, config) in [
        ("config.typo", {
            let mut config = base_config();
            config["typo"] = json!(true);
            config
        }),
        ("provider[0].required_scope", {
            let mut config = base_config();
            config["providers"][0]["required_scope"] = json!(["admin"]);
            config
        }),
        ("provider[0].client_auth.client_secert", {
            let mut config = base_config();
            config["providers"][0]["client_auth"]["client_secert"] = json!("typo");
            config
        }),
        ("session.securee", {
            let mut config = base_config();
            config["session"]["securee"] = json!(true);
            config
        }),
        ("behavior.state_ttl_second", {
            let mut config = base_config();
            config["behavior"]["state_ttl_second"] = json!(600);
            config
        }),
    ] {
        let error = OidcRelyingParty::new(&config, PluginHttpClient::default())
            .err()
            .expect("unknown field must be rejected");
        assert!(
            error.contains(scope),
            "unexpected error for {scope}: {error}"
        );
    }
}

#[test]
fn shared_validation_entrypoint_rejects_authorization_policy_typo() {
    let mut config = base_config();
    config["providers"][0]["required_role"] = json!(["admin"]);

    let error = validate_plugin_config("oidc_relying_party", &config)
        .expect_err("validation must reject unknown authorization fields");
    assert!(error.contains("provider[0].required_role"));
}

#[test]
fn remote_cleartext_provider_endpoints_are_rejected() {
    for field in [
        "issuer",
        "authorization_endpoint",
        "token_endpoint",
        "userinfo_endpoint",
        "jwks_uri",
        "end_session_endpoint",
        "post_logout_redirect_uri",
    ] {
        let mut config = base_config();
        config["providers"][0][field] = json!(format!("http://idp.example.com/{field}"));
        let error = OidcRelyingParty::new(&config, PluginHttpClient::default())
            .err()
            .expect("remote HTTP endpoint must be rejected");
        assert!(
            error.contains(field),
            "unexpected error for {field}: {error}"
        );
        assert!(
            error.contains("https"),
            "unexpected error for {field}: {error}"
        );
    }
}

#[tokio::test]
async fn loopback_http_provider_endpoints_remain_available_for_development() {
    let config = json!({
        "providers": [{
            "issuer": "http://127.0.0.1:8080",
            "authorization_endpoint": "http://127.0.0.1:8080/authorize",
            "token_endpoint": "http://127.0.0.1:8080/token",
            "userinfo_endpoint": "http://127.0.0.1:8080/userinfo",
            "jwks_uri": "http://127.0.0.1:8080/jwks",
            "end_session_endpoint": "http://127.0.0.1:8080/logout",
            "post_logout_redirect_uri": "http://localhost:3000/goodbye",
            "client_id": "local-client",
            "client_auth": {"method": "client_secret_basic", "client_secret": "secret"},
            "scopes": ["openid"],
            "redirect_uri": "http://localhost:3000/oauth/callback",
            "callback_path": "/oauth/callback"
        }],
        "session": {"encryption_secret": "01234567890123456789012345678901"}
    });

    assert!(OidcRelyingParty::new(&config, PluginHttpClient::default()).is_ok());
}

#[tokio::test]
async fn callback_hook_materializes_decoded_query_before_processing() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    ctx.set_raw_query_string("state=encoded%2Bstate&code=example".to_string());

    let reject = plugin.on_request_received(&mut ctx).await;
    assert_eq!(
        ctx.query_params.get("state").map(String::as_str),
        Some("encoded+state")
    );
    match reject {
        PluginResult::Reject {
            status_code,
            body,
            headers,
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Invalid state"}"#);
            assert!(headers["set-cookie"].contains("Max-Age=0"));
        }
        other => panic!("expected invalid-state reject, got {other:?}"),
    }

    let mut missing =
        RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    match plugin.on_request_received(&mut missing).await {
        PluginResult::Reject {
            status_code, body, ..
        } => {
            assert_eq!(status_code, 400);
            assert_eq!(body, r#"{"error":"Missing state"}"#);
        }
        other => panic!("expected missing-state reject, got {other:?}"),
    }
}

#[tokio::test]
async fn browser_state_cookie_blocks_cross_browser_callback_without_consuming_flow() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    let mut challenge_ctx = html_ctx();
    let (location, correlation_cookie) = match plugin
        .authenticate(&mut challenge_ctx, &ConsumerIndex::new(&[]))
        .await
    {
        PluginResult::Reject { headers, .. } => (
            headers.get("location").cloned().expect("authorization URL"),
            headers
                .get("set-cookie")
                .cloned()
                .expect("correlation cookie"),
        ),
        other => panic!("expected browser challenge, got {other:?}"),
    };
    assert!(correlation_cookie.contains("Secure"));
    assert!(correlation_cookie.contains("HttpOnly"));
    assert!(correlation_cookie.contains("SameSite=Lax"));
    let state = Url::parse(&location)
        .expect("authorization URL parses")
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("state parameter");

    let mut attacker_ctx = RequestContext::new(
        "198.51.100.9".into(),
        "GET".into(),
        "/oauth/callback".into(),
    );
    let correlation_cookie_name = correlation_cookie
        .split_once('=')
        .map(|(name, _)| name)
        .expect("correlation cookie name");
    attacker_ctx.headers.insert(
        "cookie".to_string(),
        format!("{correlation_cookie_name}=wrong-browser-binding"),
    );
    attacker_ctx
        .query_params
        .insert("state".to_string(), state.clone());
    assert_reject(
        plugin.on_request_received(&mut attacker_ctx).await,
        Some(400),
    );

    // The wrong browser must not consume the valid state. The initiating
    // browser reaches the next callback validation step (missing code).
    let cookie_pair = correlation_cookie
        .split(';')
        .next()
        .expect("cookie pair")
        .to_string();
    let mut browser_ctx =
        RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    browser_ctx
        .headers
        .insert("cookie".to_string(), cookie_pair);
    browser_ctx.query_params.insert("state".to_string(), state);
    match plugin.on_request_received(&mut browser_ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(body, r#"{"error":"Missing code"}"#);
            assert!(headers["set-cookie"].contains("Max-Age=0"));
        }
        other => panic!("expected missing-code rejection, got {other:?}"),
    }
}

#[tokio::test]
async fn pending_login_admission_is_bounded_per_source() {
    let mut config = base_config();
    config["behavior"]["state_cache_max_entries"] = json!(4);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(1);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    let mut first = html_ctx();
    assert_reject(
        plugin
            .authenticate(&mut first, &ConsumerIndex::new(&[]))
            .await,
        Some(302),
    );
    let mut same_source = html_ctx();
    assert_reject(
        plugin
            .authenticate(&mut same_source, &ConsumerIndex::new(&[]))
            .await,
        Some(503),
    );
    let mut other_source = html_ctx();
    other_source.client_ip = "192.0.2.10".to_string();
    assert_reject(
        plugin
            .authenticate(&mut other_source, &ConsumerIndex::new(&[]))
            .await,
        Some(302),
    );
}

#[tokio::test]
async fn pending_login_admission_is_bounded_globally_across_sources() {
    let mut config = base_config();
    config["behavior"]["state_cache_max_entries"] = json!(1);
    config["behavior"]["state_cache_max_entries_per_source"] = json!(1);
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();

    let mut first = html_ctx();
    assert_reject(
        plugin
            .authenticate(&mut first, &ConsumerIndex::new(&[]))
            .await,
        Some(302),
    );
    let mut distributed = html_ctx();
    distributed.client_ip = "192.0.2.99".to_string();
    assert_reject(
        plugin
            .authenticate(&mut distributed, &ConsumerIndex::new(&[]))
            .await,
        Some(503),
    );
}

#[tokio::test]
async fn explicit_jwks_uri_is_reported_as_active() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    assert_eq!(
        plugin.active_jwks_uris(),
        vec!["https://issuer.example.com/jwks".to_string()]
    );
}
