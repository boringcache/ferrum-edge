# OIDC Relying Party

Ferrum Edge can act as an OpenID Connect relying party for browser-facing routes with the `oidc_relying_party` plugin. The plugin starts an authorization-code flow with PKCE, validates the returned ID token against provider JWKS, creates an encrypted gateway session cookie, optionally enriches claims from UserInfo, and can fan selected claims out to upstream request headers. The session uses a sliding idle window and, when a refresh token is available, transparently refreshes the access/ID tokens before they expire.

## Minimal Configuration

```yaml
plugin_name: oidc_relying_party
config:
  providers:
    - issuer: "https://idp.example.com/"
      discovery_url: "https://idp.example.com/.well-known/openid-configuration"
      client_id: ferrum-edge
      redirect_uri: "https://edge.example.com/oidc/callback"
      client_auth:
        method: client_secret_basic
        client_secret: "${OIDC_CLIENT_SECRET}"
      audiences: ["ferrum-edge"]
      claim_headers:
        email: X-Authenticated-Email
  session:
    encryption_secret: "${OIDC_SESSION_SECRET_32_BYTES_MIN}"
  behavior:
    post_login_default_path: "/"
```

Exactly one provider is supported. Use `discovery_url` for normal OIDC providers, or set `authorization_endpoint`, `token_endpoint`, and `jwks_uri` explicitly for providers without discovery. Discovery-provided endpoints must stay on the discovery host.

## Security Behavior

- `redirect_uri` must be an absolute URI and the callback path is handled by the plugin before proxying.
- The ID token issuer, audience, expiry, not-before, and nonce are validated.
- Sessions are sealed with AES-256-GCM. `session.encryption_secret` must be at least 32 bytes; `session.encryption_secret_previous` supports cookie rotation.
- `session.store` supports only `cookie`; Redis-backed server-side sessions are rejected until implemented.
- `behavior.trusted_redirect_hosts` gates post-login redirects. If no trusted redirect is available, the plugin uses `behavior.post_login_default_path`.
- UserInfo `sub` must match the ID token `sub`, and UserInfo cannot override protected ID token claims.
- Claim header mappings reject reserved headers, including `Authorization`, `Host`, hop-by-hop headers, and Ferrum consumer identity headers.

## Session Lifetime and Token Refresh

The gateway session has two bounds, both enforced on every request:

- **Absolute lifetime** — `session.ttl_secs` (default `3600`) measured from login. A session is never valid past this, regardless of activity.
- **Idle timeout** — `session.idle_ttl_secs` (default `1800`) of inactivity. This is a *sliding* window: each request advances the session's last-touch time, so an actively used session stays valid until the absolute lifetime. To keep the per-request cost and `Set-Cookie` churn low, the cookie is re-issued at most about twice per idle window (once more than half of `idle_ttl_secs` has elapsed since the last update), not on every request.

When the provider issues a refresh token (typically by adding the `offline_access` scope), the plugin proactively refreshes the tokens `behavior.refresh_skew_secs` (default `30`) before the access token expires:

- A new access token, a rotated refresh token, and an optional new ID token are accepted. A returned ID token is re-validated against the provider JWKS and must bind to the same subject; if it carries a `nonce` it must match the original login.
- On success, the refreshed claims drive scope/role checks and claim-header fan-out, and the session cookie is re-issued.
- Refresh is best-effort. A failure is not fatal: the existing session stays valid by its own ttl/idle bounds and the next attempt is deferred briefly so a flaky token endpoint is not retried on every request. The gateway session lifetime is governed by the cookie bounds above, not by access-token expiry.

Both a sliding update and a refresh re-issue the session cookie on the proxied response via `Set-Cookie`, preserving any cookie the backend also set.

## Client Authentication

Supported `client_auth.method` values are:

| Method | Notes |
|---|---|
| `client_secret_basic` | Sends the client secret with HTTP Basic auth |
| `client_secret_post` | Sends client credentials in the token request body |
| `private_key_jwt` | Signs a client assertion with RSA, EC, or EdDSA keys (`RS256`, `RS384`, `RS512`, `ES256`, `ES384`, `EdDSA`) |
| `none` | Public client mode, allowed only for localhost or loopback token endpoints |

## Logout

Requests to `providers[].logout_path` clear the local session. When the provider exposes an end-session endpoint and `behavior.rp_initiated_logout` is true, the plugin redirects to the provider logout endpoint with `post_logout_redirect_uri` when configured.

## Related Plugins

Use `oauth2_introspection` for API requests that already carry bearer access tokens and do not need a browser login flow. Use `jwks_auth` for self-contained JWT access tokens where local signature verification is enough.
