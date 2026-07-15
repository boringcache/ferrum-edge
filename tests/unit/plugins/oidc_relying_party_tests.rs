use ferrum_edge::_test_support::{
    oidc_open_session_cookie_for_test, oidc_sealed_refresh_session_cookie_for_test,
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

fn refresh_config(token_endpoint: &str) -> serde_json::Value {
    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(token_endpoint);
    config["providers"][0]["consumer_identity_claim"] = json!("email");
    config
}

fn session_ctx(set_cookie: &str) -> RequestContext {
    let mut ctx = RequestContext::new("127.0.0.1".into(), "GET".into(), "/app".into());
    ctx.headers.insert(
        "cookie".to_string(),
        set_cookie
            .split(';')
            .next()
            .expect("session cookie pair")
            .to_string(),
    );
    ctx
}

async fn rolling_cookie(
    plugin: &OidcRelyingParty,
    ctx: &mut RequestContext,
) -> Option<String> {
    let mut response_headers = HashMap::new();
    assert_continue(plugin.after_proxy(ctx, 200, &mut response_headers).await);
    response_headers.remove("set-cookie")
}

#[tokio::test]
async fn new_accepts_minimal_cookie_store_config() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.name(), "oidc_relying_party");
    assert_eq!(plugin.priority(), priority::OIDC_RELYING_PARTY);
}

#[tokio::test]
async fn principal_less_refresh_due_session_does_not_refresh_or_slide() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;
    let plugin = OidcRelyingParty::new(
        &refresh_config(&format!("{}/token", server.uri())),
        PluginHttpClient::default(),
    )
    .expect("valid refresh config");
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &plugin,
        json!({"sub": "subject-only", "exp": now + 3600}),
        Some("refresh-token".to_string()),
        true,
        true,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);

    assert_continue(plugin.authenticate(&mut ctx, &ConsumerIndex::new(&[])).await);
    assert!(ctx.authenticated_identity.is_none());
    assert!(rolling_cookie(&plugin, &mut ctx).await.is_none());
    assert_eq!(server.received_requests().await.expect("requests").len(), 0);
}

#[tokio::test]
async fn earlier_single_mode_principal_prevents_later_oidc_refresh_and_slide() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let oidc = Arc::new(
        OidcRelyingParty::new(
            &refresh_config(&format!("{}/token", server.uri())),
            PluginHttpClient::default(),
        )
        .expect("valid refresh config"),
    );
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({})).expect("valid key auth config"));
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "oidc@example.test",
            "exp": now + 3600
        }),
        Some("refresh-token".to_string()),
        true,
        true,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

    assert!(
        run_authentication_phase(
            AuthMode::Single,
            &[key_auth, oidc_plugin],
            &mut ctx,
            &ConsumerIndex::new(&[create_test_consumer()]),
        )
        .await
        .is_none()
    );
    assert_eq!(ctx.auth_method, Some("key_auth"));
    assert!(rolling_cookie(&oidc, &mut ctx).await.is_none());
    assert_eq!(server.received_requests().await.expect("requests").len(), 0);
}

#[tokio::test]
async fn multi_auth_supersession_discards_oidc_reject_without_refresh_state() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(500))
        .mount(&server)
        .await;
    let mut config = refresh_config(&format!("{}/token", server.uri()));
    config["providers"][0]["required_scopes"] = json!(["admin"]);
    let oidc = Arc::new(
        OidcRelyingParty::new(&config, PluginHttpClient::default())
            .expect("valid refresh config"),
    );
    let key_auth: Arc<dyn Plugin> =
        Arc::new(KeyAuth::new(&json!({})).expect("valid key auth config"));
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &oidc,
        json!({
            "sub": "oidc-subject",
            "email": "rejected@example.test",
            "scope": "read",
            "exp": now + 3600
        }),
        Some("refresh-token".to_string()),
        true,
        true,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);
    ctx.headers
        .insert("x-api-key".to_string(), "test-api-key".to_string());
    let oidc_plugin: Arc<dyn Plugin> = oidc.clone();

    assert!(
        run_authentication_phase(
            AuthMode::Multi,
            &[oidc_plugin, key_auth],
            &mut ctx,
            &ConsumerIndex::new(&[create_test_consumer()]),
        )
        .await
        .is_none()
    );
    assert_eq!(ctx.auth_method, Some("key_auth"));
    assert!(rolling_cookie(&oidc, &mut ctx).await.is_none());
    assert_eq!(server.received_requests().await.expect("requests").len(), 0);
}

#[tokio::test]
async fn accepted_oidc_refresh_commits_rotated_token_once() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "new-access-token",
            "refresh_token": "rotated-refresh-token",
            "token_type": "Bearer",
            "expires_in": 3600
        })))
        .mount(&server)
        .await;
    let plugin = OidcRelyingParty::new(
        &refresh_config(&format!("{}/token", server.uri())),
        PluginHttpClient::default(),
    )
    .expect("valid refresh config");
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "accepted@example.test",
            "exp": now + 3600
        }),
        Some("original-refresh-token".to_string()),
        true,
        false,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);

    assert_continue(plugin.authenticate(&mut ctx, &ConsumerIndex::new(&[])).await);
    let rolled = rolling_cookie(&plugin, &mut ctx)
        .await
        .expect("accepted refresh must emit its rolling cookie");
    let payload = oidc_open_session_cookie_for_test(&plugin, &rolled)
        .expect("rolling cookie opens");
    assert_eq!(payload["refresh_token_b64"], json!("rotated-refresh-token"));
    assert_eq!(payload["access_token_b64"], json!("new-access-token"));

    let mut repeated = session_ctx(&rolled);
    assert_continue(
        plugin
            .authenticate(&mut repeated, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
}

#[tokio::test]
async fn accepted_refresh_failure_commits_backoff_and_avoids_retry_storm() {
    let server = MockServer::start().await;
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(400).set_body_json(json!({
            "error": "temporarily_unavailable"
        })))
        .mount(&server)
        .await;
    let plugin = OidcRelyingParty::new(
        &refresh_config(&format!("{}/token", server.uri())),
        PluginHttpClient::default(),
    )
    .expect("valid refresh config");
    let now = chrono::Utc::now().timestamp();
    let cookie = oidc_sealed_refresh_session_cookie_for_test(
        &plugin,
        json!({
            "sub": "oidc-subject",
            "email": "accepted@example.test",
            "exp": now + 3600
        }),
        Some("refresh-token".to_string()),
        true,
        false,
    )
    .expect("session seals");
    let mut ctx = session_ctx(&cookie);

    assert_continue(plugin.authenticate(&mut ctx, &ConsumerIndex::new(&[])).await);
    let backed_off = rolling_cookie(&plugin, &mut ctx)
        .await
        .expect("refresh failure must emit its backoff cookie");
    let payload = oidc_open_session_cookie_for_test(&plugin, &backed_off)
        .expect("backoff cookie opens");
    assert!(payload["refresh_after_unix"].as_i64().is_some_and(|next| next > now));

    let mut repeated = session_ctx(&backed_off);
    assert_continue(
        plugin
            .authenticate(&mut repeated, &ConsumerIndex::new(&[]))
            .await,
    );
    assert_eq!(server.received_requests().await.expect("requests").len(), 1);
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
