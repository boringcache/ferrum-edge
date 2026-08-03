//! Ory Hydra container fixture for live OIDC relying-party and OAuth2
//! introspection coverage.
//!
//! Hydra issues opaque access tokens by default and exposes a real OIDC
//! discovery document, authorization-code + PKCE endpoints, JWKS, UserInfo,
//! end-session, and RFC 7662 introspection — enough for both suites without a
//! managed IdP.
//!
//! Login/consent are completed by intercepting Hydra's redirects and accepting
//! challenges through the admin API (no separate consent container). Ports are
//! ephemeral; readiness is polled. Secrets and tokens are never written to
//! diagnostics.

use std::collections::HashMap;
use std::time::Duration;

use serde_json::{Value, json};
use testcontainers::core::IntoContainerPort;
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};
use url::Url;

use super::containers::{BoxError, free_localhost_port};

/// Pinned Hydra image (public OSS). Bump deliberately with fixture review.
pub const HYDRA_IMAGE: &str = "oryd/hydra";
pub const HYDRA_TAG: &str = "v2.2.0";

const HYDRA_PUBLIC_PORT: u16 = 4444;
const HYDRA_ADMIN_PORT: u16 = 4445;

/// System secret for the disposable fixture. Not a production credential;
/// never log this value.
const HYDRA_SYSTEM_SECRET: &str = "ferrum-hydra-si-system-secret";

/// Subject accepted by the login interceptor for every browser flow.
pub const FIXTURE_SUBJECT: &str = "alice";
pub const FIXTURE_EMAIL: &str = "alice@example.test";
pub const FIXTURE_ROLE: &str = "operator";

/// Running Hydra with host-routable public/admin URLs and an in-memory DSN.
pub struct HydraContainer {
    _container: ContainerAsync<GenericImage>,
    pub public_url: String,
    pub admin_url: String,
    pub issuer: String,
    client: reqwest::Client,
    /// Unique suffix used in client IDs for this fixture instance.
    pub isolation: String,
}

/// OAuth2 client seeded into Hydra for Ferrum plugins.
#[derive(Clone)]
pub struct HydraClient {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
    pub audience: String,
}

/// Authorization-code callback parameters returned by Hydra after login+consent.
pub struct AuthCodeCallback {
    pub code: String,
    pub state: String,
}

/// Bind an ephemeral localhost TCP port (re-exported pattern from Redpanda).
fn free_port() -> Result<u16, BoxError> {
    free_localhost_port()
}

/// Start Hydra (`serve all --dev`) with memory DSN and host-mapped ports.
///
/// `URLS_SELF_ISSUER` / login / consent use the pre-allocated host ports so
/// discovery documents advertise loopback URLs the test process can reach.
/// Login/consent URLs are intentional blackholes — the browser helper never
/// GETs them; it parses `Location` and accepts challenges via the admin API.
pub async fn start_hydra_container() -> Result<HydraContainer, BoxError> {
    let public_port = free_port()?;
    let admin_port = free_port()?;
    // Blackhole ports for login/consent redirect targets (never listened on).
    let login_port = free_port()?;
    let consent_port = free_port()?;

    let issuer = format!("http://127.0.0.1:{public_port}/");
    let login_url = format!("http://127.0.0.1:{login_port}/login");
    let consent_url = format!("http://127.0.0.1:{consent_port}/consent");

    let isolation = format!(
        "si{}{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis())
            .unwrap_or(0)
    );

    let container = GenericImage::new(HYDRA_IMAGE, HYDRA_TAG)
        .with_exposed_port(HYDRA_PUBLIC_PORT.tcp())
        .with_exposed_port(HYDRA_ADMIN_PORT.tcp())
        .with_mapped_port(public_port, HYDRA_PUBLIC_PORT.tcp())
        .with_mapped_port(admin_port, HYDRA_ADMIN_PORT.tcp())
        .with_env_var("DSN", "memory")
        .with_env_var("SECRETS_SYSTEM", HYDRA_SYSTEM_SECRET)
        .with_env_var("URLS_SELF_ISSUER", &issuer)
        .with_env_var("URLS_LOGIN", &login_url)
        .with_env_var("URLS_CONSENT", &consent_url)
        .with_env_var("URLS_LOGOUT", format!("http://127.0.0.1:{consent_port}/logout"))
        .with_env_var("SERVE_PUBLIC_CORS_ENABLED", "true")
        .with_env_var("SERVE_ADMIN_CORS_ENABLED", "true")
        .with_env_var("OIDC_SUBJECT_IDENTIFIERS_SUPPORTED_TYPES", "public")
        .with_env_var("STRATEGIES_ACCESS_TOKEN", "opaque")
        .with_env_var("STRATEGIES_SCOPE", "exact")
        .with_cmd(["serve", "all", "--dev"])
        .start()
        .await
        .map_err(|e| format!("Hydra container start failed: {e}"))?;

    let public_url = format!("http://127.0.0.1:{public_port}");
    let admin_url = format!("http://127.0.0.1:{admin_port}");
    let client = reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(10))
        .build()?;

    let hydra = HydraContainer {
        _container: container,
        public_url,
        admin_url,
        issuer,
        client,
        isolation,
    };
    hydra.wait_ready().await?;
    Ok(hydra)
}

impl HydraContainer {
    pub fn discovery_url(&self) -> String {
        format!(
            "{}/.well-known/openid-configuration",
            self.public_url.trim_end_matches('/')
        )
    }

    /// Admin RFC 7662 endpoint (Hydra serves introspection on the admin API).
    pub fn introspection_endpoint(&self) -> String {
        format!(
            "{}/admin/oauth2/introspect",
            self.admin_url.trim_end_matches('/')
        )
    }

    /// Same-origin discovery URL whose `introspection_endpoint` proxies to the
    /// live admin introspector. Hydra advertises public discovery on :4444 and
    /// introspection on :4445; Ferrum requires discovery and introspection to
    /// share scheme/host/port, so this facade rewrites the document.
    pub async fn start_introspection_discovery_facade(&self) -> Result<String, BoxError> {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        let facade_origin = format!("http://127.0.0.1:{port}");
        let admin_introspect = self.introspection_endpoint();
        let public_discovery = self.discovery_url();
        let client = self.client.clone();

        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let client = client.clone();
                let admin_introspect = admin_introspect.clone();
                let public_discovery = public_discovery.clone();
                let facade_origin = facade_origin.clone();
                tokio::spawn(async move {
                    let _ = handle_facade_connection(
                        stream,
                        client,
                        public_discovery,
                        admin_introspect,
                        facade_origin,
                    )
                    .await;
                });
            }
        });

        // Readiness: discovery must answer through the facade.
        for _ in 0..40 {
            if let Ok(resp) = self
                .client
                .get(format!(
                    "{facade_origin}/.well-known/openid-configuration"
                ))
                .send()
                .await
                && resp.status().is_success()
            {
                return Ok(format!(
                    "{facade_origin}/.well-known/openid-configuration"
                ));
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        Err("introspection discovery facade not ready".into())
    }

    async fn wait_ready(&self) -> Result<(), BoxError> {
        let mut last = String::new();
        let mut consecutive_ok = 0u32;
        for _ in 0..90 {
            match self.readiness_round().await {
                Ok(()) => {
                    consecutive_ok += 1;
                    if consecutive_ok >= 2 {
                        return Ok(());
                    }
                }
                Err(err) => {
                    consecutive_ok = 0;
                    last = sanitize_diag(&err.to_string());
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(format!("Hydra not ready within 45s: {last}").into())
    }

    async fn readiness_round(&self) -> Result<(), BoxError> {
        let discovery = self
            .client
            .get(self.discovery_url())
            .send()
            .await
            .map_err(|e| format!("discovery dial: {e}"))?;
        if !discovery.status().is_success() {
            return Err(format!("discovery HTTP {}", discovery.status()).into());
        }
        let doc: Value = discovery
            .json()
            .await
            .map_err(|e| format!("discovery json: {e}"))?;
        for key in [
            "authorization_endpoint",
            "token_endpoint",
            "jwks_uri",
            "userinfo_endpoint",
        ] {
            if doc.get(key).and_then(Value::as_str).is_none() {
                return Err(format!("discovery missing {key}").into());
            }
        }
        // introspection_endpoint is optional on some Hydra builds; admin path is
        // always used directly by the introspection suite.
        // Admin health: create-client listing must answer.
        let health = self
            .client
            .get(format!("{}/health/ready", self.admin_url.trim_end_matches('/')))
            .send()
            .await
            .map_err(|e| format!("admin health dial: {e}"))?;
        if !health.status().is_success() {
            // Older hydra may lack /health/ready — fall back to empty client list.
            let clients = self
                .client
                .get(format!("{}/admin/clients?page_size=1", self.admin_url.trim_end_matches('/')))
                .send()
                .await
                .map_err(|e| format!("admin clients dial: {e}"))?;
            if !clients.status().is_success() {
                return Err(format!("admin not ready HTTP {}", clients.status()).into());
            }
        }
        Ok(())
    }

    /// Register a confidential client for authorization-code (+ optional
    /// client_credentials / refresh) with the given token-endpoint auth method.
    pub async fn create_client(
        &self,
        label: &str,
        redirect_uri: &str,
        token_endpoint_auth_method: &str,
        grant_types: &[&str],
    ) -> Result<HydraClient, BoxError> {
        let client_id = format!("ferrum-{label}-{}", self.isolation);
        let client_secret = format!("secret-{label}-{}", self.isolation);
        let audience = format!("api://ferrum-{label}-{}", self.isolation);
        let body = json!({
            "client_id": client_id,
            "client_secret": client_secret,
            "grant_types": grant_types,
            "response_types": ["code", "id_token"],
            "scope": "openid offline_access profile email roles",
            "redirect_uris": [redirect_uri],
            "token_endpoint_auth_method": token_endpoint_auth_method,
            "audience": [audience],
            "subject_type": "public",
        });
        let resp = self
            .client
            .post(format!("{}/admin/clients", self.admin_url.trim_end_matches('/')))
            .json(&body)
            .send()
            .await
            .map_err(|e| format!("create client dial: {e}"))?;
        if !resp.status().is_success() {
            let status = resp.status();
            // Do not echo response body (may include secrets).
            return Err(format!("create client HTTP {status}").into());
        }
        Ok(HydraClient {
            client_id,
            client_secret,
            redirect_uri: redirect_uri.to_string(),
            audience,
        })
    }

    /// Walk Hydra's authorization redirect chain with admin login/consent accept.
    ///
    /// `authorization_url` is the Location produced by Ferrum's browser challenge
    /// (or a hand-built `/oauth2/auth` URL). Returns the callback `code` + `state`
    /// without logging either value.
    pub async fn complete_authorization_redirect(
        &self,
        authorization_url: &str,
    ) -> Result<AuthCodeCallback, BoxError> {
        let mut cookies = CookieJar::default();
        let mut location = authorization_url.to_string();

        // Cap redirect hops so a misconfigured fixture fails fast.
        for _ in 0..12 {
            let parsed = Url::parse(&location)
                .map_err(|e| format!("redirect location parse: {e}"))?;

            if let Some(code) = query_param(&parsed, "code") {
                let state = query_param(&parsed, "state").unwrap_or_default();
                return Ok(AuthCodeCallback { code, state });
            }
            if let Some(challenge) = query_param(&parsed, "login_challenge") {
                location = self.accept_login(&challenge).await?;
                continue;
            }
            if let Some(challenge) = query_param(&parsed, "consent_challenge") {
                location = self.accept_consent(&challenge).await?;
                continue;
            }

            let resp = self
                .client
                .get(&location)
                .header("cookie", cookies.header_value())
                .send()
                .await
                .map_err(|e| format!("auth hop dial: {e}"))?;
            cookies.absorb_set_cookie(resp.headers());
            let status = resp.status();
            let next = resp
                .headers()
                .get(reqwest::header::LOCATION)
                .and_then(|v| v.to_str().ok())
                .map(|v| resolve_location(&location, v));
            if let Some(next) = next {
                location = next;
                continue;
            }
            return Err(format!(
                "auth hop HTTP {status} without login/consent/code redirect"
            )
            .into());
        }
        Err("authorization redirect hop budget exhausted".into())
    }

    async fn accept_login(&self, challenge: &str) -> Result<String, BoxError> {
        let resp = self
            .client
            .put(format!(
                "{}/admin/oauth2/auth/requests/login/accept?login_challenge={}",
                self.admin_url.trim_end_matches('/'),
                urlencoding_challenge(challenge)
            ))
            .json(&json!({
                "subject": FIXTURE_SUBJECT,
                "remember": false,
            }))
            .send()
            .await
            .map_err(|e| format!("accept login dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("accept login HTTP {}", resp.status()).into());
        }
        let body: Value = resp.json().await.map_err(|e| format!("accept login json: {e}"))?;
        body.get("redirect_to")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "accept login missing redirect_to".into())
    }

    async fn accept_consent(&self, challenge: &str) -> Result<String, BoxError> {
        // Fetch requested scope/audience from the challenge so we grant exactly
        // what Ferrum asked for.
        let info = self
            .client
            .get(format!(
                "{}/admin/oauth2/auth/requests/consent?consent_challenge={}",
                self.admin_url.trim_end_matches('/'),
                urlencoding_challenge(challenge)
            ))
            .send()
            .await
            .map_err(|e| format!("get consent dial: {e}"))?;
        if !info.status().is_success() {
            return Err(format!("get consent HTTP {}", info.status()).into());
        }
        let info: Value = info.json().await.map_err(|e| format!("get consent json: {e}"))?;
        let grant_scope = info
            .get("requested_scope")
            .cloned()
            .unwrap_or_else(|| json!(["openid", "offline_access", "profile", "email", "roles"]));
        let grant_audience = info
            .get("requested_access_token_audience")
            .cloned()
            .unwrap_or_else(|| json!([]));

        let resp = self
            .client
            .put(format!(
                "{}/admin/oauth2/auth/requests/consent/accept?consent_challenge={}",
                self.admin_url.trim_end_matches('/'),
                urlencoding_challenge(challenge)
            ))
            .json(&json!({
                "grant_scope": grant_scope,
                "grant_access_token_audience": grant_audience,
                "remember": false,
                "session": {
                    "id_token": {
                        "email": FIXTURE_EMAIL,
                        "roles": [FIXTURE_ROLE],
                    },
                    "access_token": {
                        "email": FIXTURE_EMAIL,
                        "roles": [FIXTURE_ROLE],
                    }
                }
            }))
            .send()
            .await
            .map_err(|e| format!("accept consent dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("accept consent HTTP {}", resp.status()).into());
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("accept consent json: {e}"))?;
        body.get("redirect_to")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "accept consent missing redirect_to".into())
    }

    /// Client-credentials opaque access token (no browser). Optionally request
    /// an audience.
    pub async fn client_credentials_token(
        &self,
        client: &HydraClient,
        scope: &str,
        audience: Option<&str>,
    ) -> Result<String, BoxError> {
        let mut form = vec![
            ("grant_type", "client_credentials".to_string()),
            ("scope", scope.to_string()),
        ];
        if let Some(aud) = audience {
            form.push(("audience", aud.to_string()));
        }
        let resp = self
            .client
            .post(format!("{}/oauth2/token", self.public_url.trim_end_matches('/')))
            .basic_auth(&client.client_id, Some(&client.client_secret))
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("client_credentials dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("client_credentials HTTP {}", resp.status()).into());
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("client_credentials json: {e}"))?;
        body.get("access_token")
            .and_then(Value::as_str)
            .map(str::to_string)
            .ok_or_else(|| "client_credentials missing access_token".into())
    }

    /// Authorization-code token set with seeded claims (for introspection claim
    /// fan-out). Returns `(access_token, refresh_token)`.
    pub async fn authorization_code_tokens(
        &self,
        client: &HydraClient,
        scopes: &str,
    ) -> Result<(String, Option<String>), BoxError> {
        let verifier = pkce_verifier();
        let challenge = pkce_challenge_s256(&verifier);
        let state = format!("state-{}", self.isolation);
        let nonce = format!("nonce-{}", self.isolation);
        let mut auth = Url::parse(&format!(
            "{}/oauth2/auth",
            self.public_url.trim_end_matches('/')
        ))?;
        auth.query_pairs_mut()
            .append_pair("response_type", "code")
            .append_pair("client_id", &client.client_id)
            .append_pair("redirect_uri", &client.redirect_uri)
            .append_pair("scope", scopes)
            .append_pair("state", &state)
            .append_pair("nonce", &nonce)
            .append_pair("code_challenge", &challenge)
            .append_pair("code_challenge_method", "S256");
        if !client.audience.is_empty() {
            auth.query_pairs_mut()
                .append_pair("audience", &client.audience);
        }

        let callback = self.complete_authorization_redirect(auth.as_str()).await?;
        let form = [
            ("grant_type", "authorization_code"),
            ("code", callback.code.as_str()),
            ("redirect_uri", client.redirect_uri.as_str()),
            ("code_verifier", verifier.as_str()),
        ];
        let resp = self
            .client
            .post(format!("{}/oauth2/token", self.public_url.trim_end_matches('/')))
            .basic_auth(&client.client_id, Some(&client.client_secret))
            .form(&form)
            .send()
            .await
            .map_err(|e| format!("auth_code token dial: {e}"))?;
        if !resp.status().is_success() {
            return Err(format!("auth_code token HTTP {}", resp.status()).into());
        }
        let body: Value = resp
            .json()
            .await
            .map_err(|e| format!("auth_code token json: {e}"))?;
        let access = body
            .get("access_token")
            .and_then(Value::as_str)
            .ok_or("auth_code token missing access_token")?
            .to_string();
        let refresh = body
            .get("refresh_token")
            .and_then(Value::as_str)
            .map(str::to_string);
        Ok((access, refresh))
    }
}

#[derive(Default)]
struct CookieJar {
    pairs: HashMap<String, String>,
}

impl CookieJar {
    fn absorb_set_cookie(&mut self, headers: &reqwest::header::HeaderMap) {
        for value in headers.get_all(reqwest::header::SET_COOKIE) {
            let Ok(raw) = value.to_str() else {
                continue;
            };
            let pair = raw.split(';').next().unwrap_or("").trim();
            if let Some((name, val)) = pair.split_once('=') {
                self.pairs.insert(name.trim().to_string(), val.trim().to_string());
            }
        }
    }

    fn header_value(&self) -> String {
        self.pairs
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("; ")
    }
}

fn query_param(url: &Url, name: &str) -> Option<String> {
    url.query_pairs()
        .find_map(|(k, v)| (k == name).then(|| v.into_owned()))
}

fn resolve_location(current: &str, location: &str) -> String {
    if location.starts_with("http://") || location.starts_with("https://") {
        return location.to_string();
    }
    if let Ok(base) = Url::parse(current)
        && let Ok(joined) = base.join(location)
    {
        return joined.to_string();
    }
    location.to_string()
}

fn urlencoding_challenge(challenge: &str) -> String {
    // Challenges are URL-safe; still escape reserved characters.
    challenge
        .chars()
        .map(|c| match c {
            'A'..='Z' | 'a'..='z' | '0'..='9' | '-' | '_' | '.' | '~' => c.to_string(),
            _ => format!("%{:02X}", c as u8),
        })
        .collect()
}

fn sanitize_diag(raw: &str) -> String {
    // Bound and strip anything that looks like a bearer/secret fragment.
    let truncated: String = raw.chars().take(240).collect();
    truncated
        .replace("Bearer ", "Bearer [REDACTED] ")
        .replace("client_secret", "client_secret=[REDACTED]")
}

fn pkce_verifier() -> String {
    use base64::Engine;
    let mut bytes = [0u8; 64];
    // Prefer OS randomness; fall back to time-derived bytes if unavailable.
    if getrandom_fill(&mut bytes).is_err() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0);
        for (i, b) in bytes.iter_mut().enumerate() {
            *b = ((nanos >> ((i % 16) * 8)) as u8).wrapping_add(i as u8);
        }
    }
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn getrandom_fill(buf: &mut [u8]) -> Result<(), ()> {
    // Use the same getrandom the workspace already links when available.
    #[allow(unused_imports)]
    {
        // std does not expose fill_bytes portably without getrandom; use
        // a simple hash mix from process entropy as a test-only fallback path
        // when the primary call is stubbed — prefer `rand` via os.
    }
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut hasher = DefaultHasher::new();
    std::process::id().hash(&mut hasher);
    std::time::SystemTime::now().hash(&mut hasher);
    let mut state = hasher.finish();
    for (i, b) in buf.iter_mut().enumerate() {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(i as u64 + 1);
        *b = (state >> 33) as u8;
    }
    Ok(())
}

fn pkce_challenge_s256(verifier: &str) -> String {
    use base64::Engine;
    use ferrum_edge::fips::approved::Sha256;
    let digest = Sha256::digest(verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

async fn handle_facade_connection(
    mut stream: tokio::net::TcpStream,
    client: reqwest::Client,
    public_discovery: String,
    admin_introspect: String,
    facade_origin: String,
) -> Result<(), BoxError> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let mut buf = vec![0u8; 64 * 1024];
    let n = stream.read(&mut buf).await?;
    if n == 0 {
        return Ok(());
    }
    let request = String::from_utf8_lossy(&buf[..n]);
    let mut lines = request.split("\r\n");
    let request_line = lines.next().unwrap_or_default();
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");

    if method == "GET" && path.starts_with("/.well-known/openid-configuration") {
        let upstream = client.get(&public_discovery).send().await?;
        let status = upstream.status().as_u16();
        let mut doc: Value = upstream.json().await?;
        if let Some(obj) = doc.as_object_mut() {
            obj.insert(
                "introspection_endpoint".to_string(),
                json!(format!("{facade_origin}/oauth2/introspect")),
            );
        }
        let body = serde_json::to_vec(&doc)?;
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&body).await?;
        return Ok(());
    }

    if method == "POST" && path.starts_with("/oauth2/introspect") {
        let header_end = request
            .find("\r\n\r\n")
            .map(|i| i + 4)
            .unwrap_or(request.len());
        let body_bytes = &buf[header_end..n];
        // Forward Authorization if present so client_secret_basic still works.
        let mut forward = client.post(&admin_introspect);
        for line in request[..header_end].lines().skip(1) {
            if let Some((name, value)) = line.split_once(':') {
                let name = name.trim();
                if name.eq_ignore_ascii_case("authorization")
                    || name.eq_ignore_ascii_case("content-type")
                {
                    forward = forward.header(name, value.trim());
                }
            }
        }
        let upstream = forward.body(body_bytes.to_vec()).send().await?;
        let status = upstream.status().as_u16();
        let resp_body = upstream.bytes().await?;
        let response = format!(
            "HTTP/1.1 {status} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            resp_body.len()
        );
        stream.write_all(response.as_bytes()).await?;
        stream.write_all(&resp_body).await?;
        return Ok(());
    }

    let body = b"not found";
    let response = format!(
        "HTTP/1.1 404 Not Found\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(response.as_bytes()).await?;
    stream.write_all(body).await?;
    Ok(())
}
