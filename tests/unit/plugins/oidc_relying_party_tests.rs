use ferrum_edge::ConsumerIndex;
use ferrum_edge::plugins::validate_plugin_config;
use ferrum_edge::plugins::{
    Plugin, PluginHttpClient, PluginResult, RequestContext, oidc_relying_party::OidcRelyingParty,
    priority,
};
use serde_json::json;
use url::Url;
use wiremock::matchers::{method, path};
use wiremock::{Mock, MockServer, ResponseTemplate};

use super::jwks_auth_support::{build_rsa_jwks_from_pem, create_rs256_token};
use super::plugin_utils::assert_reject;

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

struct BrowserChallenge {
    state: String,
    nonce: String,
    cookie: String,
}

async fn issue_browser_challenge(plugin: &OidcRelyingParty) -> BrowserChallenge {
    let mut ctx = html_ctx();
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin
        .authenticate(&mut ctx, &ConsumerIndex::new(&[]))
        .await
    else {
        panic!("expected browser challenge");
    };
    assert_eq!(status_code, 302);
    let location = Url::parse(headers.get("location").expect("authorization URL"))
        .expect("authorization URL parses");
    let state = location
        .query_pairs()
        .find_map(|(key, value)| (key == "state").then(|| value.into_owned()))
        .expect("state parameter");
    let nonce = location
        .query_pairs()
        .find_map(|(key, value)| (key == "nonce").then(|| value.into_owned()))
        .expect("nonce parameter");
    let cookie = headers
        .get("set-cookie")
        .cloned()
        .expect("correlation cookie");

    BrowserChallenge {
        state,
        nonce,
        cookie,
    }
}

fn cookie_attribute<'a>(cookie: &'a str, expected_name: &str) -> Option<Option<&'a str>> {
    cookie.split(';').skip(1).find_map(|attribute| {
        let attribute = attribute.trim();
        let (name, value) = match attribute.split_once('=') {
            Some((name, value)) => (name.trim(), Some(value.trim())),
            None => (attribute, None),
        };
        name.eq_ignore_ascii_case(expected_name).then_some(value)
    })
}

fn cookie_pair(cookie: &str) -> &str {
    cookie
        .split(';')
        .next()
        .expect("cookie contains a name/value pair")
}

fn cookie_name(cookie: &str) -> &str {
    cookie_pair(cookie)
        .split_once('=')
        .map(|(name, _)| name)
        .expect("cookie has a name")
}

fn assert_host_only_correlation_cookie(cookie: &str, expected_max_age: &str) {
    assert_eq!(cookie_attribute(cookie, "domain"), None, "{cookie}");
    assert_eq!(
        cookie_attribute(cookie, "path"),
        Some(Some("/oauth/callback")),
        "{cookie}"
    );
    assert_eq!(
        cookie_attribute(cookie, "samesite"),
        Some(Some("Lax")),
        "{cookie}"
    );
    assert_eq!(
        cookie_attribute(cookie, "max-age"),
        Some(Some(expected_max_age)),
        "{cookie}"
    );
    assert_eq!(cookie_attribute(cookie, "secure"), Some(None), "{cookie}");
    assert_eq!(
        cookie_attribute(cookie, "httponly"),
        Some(None),
        "{cookie}"
    );
}

fn assert_same_correlation_scope(created: &str, cleared: &str) {
    for attribute in ["domain", "path", "samesite", "secure", "httponly"] {
        assert_eq!(
            cookie_attribute(created, attribute),
            cookie_attribute(cleared, attribute),
            "correlation cookie {attribute} scope changed between creation and clearing"
        );
    }
}

fn callback_context(challenge: &BrowserChallenge) -> RequestContext {
    let mut ctx =
        RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    ctx.headers.insert(
        "cookie".to_string(),
        cookie_pair(&challenge.cookie).to_string(),
    );
    ctx.query_params
        .insert("state".to_string(), challenge.state.clone());
    ctx
}

#[tokio::test]
async fn new_accepts_minimal_cookie_store_config() {
    let plugin = OidcRelyingParty::new(&base_config(), PluginHttpClient::default()).unwrap();
    assert_eq!(plugin.name(), "oidc_relying_party");
    assert_eq!(plugin.priority(), priority::OIDC_RELYING_PARTY);
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
async fn correlation_cookie_ignores_configured_session_domain() {
    let mut config = base_config();
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;

    assert_host_only_correlation_cookie(&challenge.cookie, "600");
}

#[tokio::test]
async fn successful_callback_clears_host_only_correlation_cookie_and_preserves_session_domain() {
    let server = MockServer::start().await;
    let public_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_public.pem");
    let private_key_pem = include_bytes!("../../../tests/fixtures/test_rsa_private.pem");
    Mock::given(method("GET"))
        .and(path("/jwks"))
        .respond_with(
            ResponseTemplate::new(200).set_body_json(build_rsa_jwks_from_pem(public_key_pem)),
        )
        .mount(&server)
        .await;

    let mut config = base_config();
    config["providers"][0]["token_endpoint"] = json!(format!("{}/token", server.uri()));
    config["providers"][0]["jwks_uri"] = json!(format!("{}/jwks", server.uri()));
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;
    let id_token = create_rs256_token(
        &json!({
            "iss": "https://issuer.example.com",
            "aud": "ferrum-gateway",
            "sub": "user-1",
            "nonce": challenge.nonce.as_str(),
        }),
        private_key_pem,
    );
    Mock::given(method("POST"))
        .and(path("/token"))
        .respond_with(ResponseTemplate::new(200).set_body_json(json!({
            "access_token": "access-token",
            "token_type": "Bearer",
            "expires_in": 3600,
            "id_token": id_token,
        })))
        .mount(&server)
        .await;

    let mut callback = callback_context(&challenge);
    callback
        .query_params
        .insert("code".to_string(), "authorization-code".to_string());
    let PluginResult::Reject {
        status_code,
        headers,
        ..
    } = plugin.on_request_received(&mut callback).await
    else {
        panic!("expected successful callback redirect");
    };
    assert_eq!(status_code, 302);
    let cookies: Vec<&str> = headers
        .get("set-cookie")
        .expect("session and correlation cookies")
        .lines()
        .collect();
    let session_cookie = cookies
        .iter()
        .copied()
        .find(|cookie| cookie.starts_with("ferrum_session="))
        .expect("durable session cookie");
    let correlation_cookie_name = cookie_name(&challenge.cookie);
    let cleared_correlation_cookie = cookies
        .iter()
        .copied()
        .find(|cookie| cookie_name(cookie) == correlation_cookie_name)
        .expect("cleared correlation cookie");

    assert_eq!(
        cookie_attribute(session_cookie, "domain"),
        Some(Some("example.com")),
        "durable session cookie must retain its configured domain"
    );
    assert_host_only_correlation_cookie(cleared_correlation_cookie, "0");
    assert_same_correlation_scope(&challenge.cookie, cleared_correlation_cookie);
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
    let mut config = base_config();
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
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
            assert_host_only_correlation_cookie(&headers["set-cookie"], "0");
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
    let mut config = base_config();
    config["session"]["domain"] = json!("example.com");
    let plugin = OidcRelyingParty::new(&config, PluginHttpClient::default()).unwrap();
    let challenge = issue_browser_challenge(&plugin).await;
    let state = challenge.state.clone();
    let correlation_cookie = &challenge.cookie;
    assert_host_only_correlation_cookie(correlation_cookie, "600");

    let mut attacker_ctx = RequestContext::new(
        "198.51.100.9".into(),
        "GET".into(),
        "/oauth/callback".into(),
    );
    let correlation_cookie_name = cookie_name(correlation_cookie);
    attacker_ctx.headers.insert(
        "cookie".to_string(),
        format!("{correlation_cookie_name}=wrong-browser-binding"),
    );
    attacker_ctx
        .query_params
        .insert("state".to_string(), state.clone());
    match plugin.on_request_received(&mut attacker_ctx).await {
        PluginResult::Reject {
            status_code,
            headers,
            ..
        } => {
            assert_eq!(status_code, 400);
            let cleared = headers
                .get("set-cookie")
                .expect("wrong-binding correlation cookie clear");
            assert_host_only_correlation_cookie(cleared, "0");
            assert_same_correlation_scope(correlation_cookie, cleared);
        }
        other => panic!("expected wrong-binding rejection, got {other:?}"),
    }

    // The wrong browser must not consume the valid state. The initiating
    // browser reaches the next callback validation step (missing code).
    let cookie_pair = cookie_pair(correlation_cookie).to_string();
    let mut browser_ctx =
        RequestContext::new("127.0.0.1".into(), "GET".into(), "/oauth/callback".into());
    browser_ctx
        .headers
        .insert("cookie".to_string(), cookie_pair);
    browser_ctx.query_params.insert("state".to_string(), state);
    match plugin.on_request_received(&mut browser_ctx).await {
        PluginResult::Reject { body, headers, .. } => {
            assert_eq!(body, r#"{"error":"Missing code"}"#);
            let cleared = &headers["set-cookie"];
            assert_host_only_correlation_cookie(cleared, "0");
            assert_same_correlation_scope(correlation_cookie, cleared);
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
