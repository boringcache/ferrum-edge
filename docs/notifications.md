# Notifications

Reusable, plugin-agnostic notification infrastructure. Lives at `src/notifications/`. Today the only consumer is the [`proxy_alerts` plugin](proxy_alerts.md); future subsystems (overload manager, mesh policy enforcement, custom plugins) can dispatch notifications to the same channels without re-implementing the transports.

## What's in the module

| Item | Path | Purpose |
|------|------|---------|
| `Notification` | `src/notifications/notification.rs` | Generic payload: title, body, severity, k/v fields, lifecycle action. No alert-specific fields. |
| `NotificationChannel` | `src/notifications/channels/mod.rs` | Enum over Slack / Teams / Discord / Webhook / Email. Uniform `dispatch` surface. |
| `parse_channels(json)` | `src/notifications/channels/mod.rs` | JSON → typed channel map with validation. |
| `dispatch(...)` | `src/notifications/dispatch.rs` | Bounded-concurrency fan-out helper. |
| `templating::render_template` | `src/notifications/templating.rs` | `${var}` substitution + dry-run validation. |

## Channel JSON schema

`channels` is a `{ name -> definition }` map. Each definition picks a transport via `"type"` and supplies its required fields.

### Common rules
- Channel name matches `[A-Za-z0-9_-]+`.
- Unknown properties on a selected channel variant are rejected (including fields that belong only to a different channel type). Generic webhook `headers` remain an open string map.
- `webhook_url` (Slack/Teams/Discord) and `url` (generic webhook) MUST be `http://` or `https://` with a host and no `user:pass@` userinfo segment. The `email` channel takes a bare `smtp_host` instead — no scheme, port, path, or credentials in that field.
- For each URL field there is a sibling `*_env` form (`webhook_url_env: "MY_ENV"`) that resolves via `std::env::var()` at construction. Combine with the gateway's secret resolver (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP` env-var suffixes) to keep credentials out of config files.
- Dispatch slow-call/error logs redact endpoint paths, query strings, and userinfo because incoming webhook credentials commonly live inside the URL.
- Response bodies are discarded after successful dispatches with a 1 MiB cap: responses advertising `Content-Length > 1 MiB` are rejected before any bytes are read, and otherwise the body is streamed and aborted once the running total crosses 1 MiB. Either path fails the send without buffering the whole body.
- Non-success responses are reported by status only, without surfacing or draining their bodies. Any drain bail-out (non-success status, advertised `Content-Length` over 1 MiB, streaming abort at 1 MiB, or transport error) drops the response without consuming the body; reqwest handles the protocol cleanup (HTTP/1.x closes the connection, HTTP/2 can reset the stream while keeping the connection reusable). This is acceptable for the typical alert cadence (up to a few notifications per second per channel) and avoids spending work on misbehaving endpoints.

### Slack (Incoming Webhook)

```json
{
  "type": "slack",
  "webhook_url": "https://hooks.slack.com/services/T/B/X",
  "channel_override": "#alerts",     // optional
  "username": "ferrum-edge",         // optional
  "icon_emoji": ":rotating_light:"   // optional
}
```

Posts a JSON payload using the legacy `attachments` schema (color side-bar + field grid). `Notification.fields` become `attachments[].fields` (`{title, value, short}`). `Notification.severity` maps to a hex color.

### Microsoft Teams (Office 365 connector)

```json
{
  "type": "teams",
  "webhook_url": "https://outlook.office.com/webhook/..."
}
```

Posts a `MessageCard` payload. `Notification.fields` become `sections[0].facts` (`{name, value}`). Teams `facts` always render full-width — `NotificationField.short` is ignored.

### Discord (webhook)

```json
{
  "type": "discord",
  "webhook_url": "https://discord.com/api/webhooks/...",
  "username": "ferrum-edge"          // optional
}
```

Posts an `embeds` payload. `Notification.fields` become `embeds[0].fields` (`{name, value, inline}`); `inline` mirrors `short`.

### Generic webhook

```json
{
  "type": "webhook",
  "url": "https://events.pagerduty.com/v2/enqueue",
  "method": "POST",                   // optional; one of POST | PUT | PATCH (default POST)
  "headers": {                        // optional
    "Content-Type": "application/json",
    "X-Auth-Token": "..."
  },
  "body_template": "{\"r\":\"${rule_name}\",\"sev\":\"${severity}\"}"
}
```

Renders `body_template` after `${var}` substitution and POSTs the result. The default `Content-Type: application/json` is added if the operator does not supply their own. For JSON content types (`application/json` or `*+json`), substituted values are escaped as JSON string content so quotes, backslashes, and control characters inside alert fields cannot break the body; place variables inside JSON strings unless the value is intentionally numeric/boolean text. Non-JSON content types keep raw substitution.

### Email (SMTP)

```json
{
  "type": "email",
  "smtp_host": "smtp.example.com",
  "smtp_port": 587,                    // optional; default 587 (starttls) / 465 (implicit_tls)
  "tls_mode": "starttls",              // optional; "starttls" | "implicit_tls" (default "starttls")
  "tls_server_name": "smtp.example.com", // optional; verified identity override, default smtp_host
  "username_env": "FERRUM_ALERT_SMTP_USERNAME",  // optional (inline "username" also accepted)
  "password_env": "FERRUM_ALERT_SMTP_PASSWORD",  // optional (inline "password" also accepted)
  "from": "ferrum@example.com",
  "to": ["oncall@example.com"],
  "subject_template": "[${severity}] ${title}",  // optional
  "body_template": "${body}\n\n${fields}",       // optional
  "helo_name": "example.com",          // optional; defaults to the domain of `from`
  "connect_timeout_ms": 5000,          // optional; 100..60000
  "command_timeout_ms": 10000          // optional; 100..120000
}
```

Sends a single-part `text/plain; charset=utf-8` message, base64 transfer-encoded, with `Date`, `From`, `To`, `Subject`, `Message-ID`, `MIME-Version`, `Auto-Submitted: auto-generated`, and `X-Ferrum-Notification-{Severity,Event-Action}` headers.

**TLS is mandatory and there is no downgrade path.**

- `starttls` connects in the clear, sends `EHLO`, requires an advertised `STARTTLS`, upgrades, and re-sends `EHLO` inside TLS (pre-TLS capabilities are discarded per RFC 3207 §4.2). A relay that does not advertise `STARTTLS` fails the send; the message is never delivered in cleartext. Any bytes the peer pipelines ahead of the handshake abort the session (command-injection defense).
- `implicit_tls` handshakes immediately after TCP connect (SMTPS, port 465).
- `AUTH` is only reachable inside a completed handshake — the authenticated phase requires a token minted at handshake completion, so credentials cannot precede TLS.
- Certificate verification is **always** enforced. Unlike the log-shipping sinks, this channel deliberately ignores `FERRUM_TLS_NO_VERIFY`: skipping verification here would hand the SMTP password to whatever answered the connect. Private CAs go through `FERRUM_TLS_CA_BUNDLE_PATH`, and `FERRUM_TLS_CRL_FILE_PATH` revocation applies. The rustls config is built once per channel on a blocking thread and reused.
- Plaintext SMTP is not offered at all; `tls_mode: "none"` is rejected at admission.
- Supported AUTH mechanisms are `PLAIN` and `LOGIN`. If credentials are configured and the server advertises neither, the send fails rather than proceeding unauthenticated.

Bounds (all enforced, all fail closed or truncate visibly):

| Bound | Value |
|-------|-------|
| Recipients (`to`) | 1–32, duplicates collapsed |
| Address length | 254 bytes; local part ≤ 64, domain ≤ 255, ASCII addr-spec only |
| `subject_template` / `body_template` | 1 KiB / 64 KiB |
| Rendered subject / body | 512 B / 32 KiB, enforced during template substitution; truncated with `...` / `[truncated]` |
| `${fields}` block | 8 KiB hard ceiling (names, values, separators, truncation marker); 512 B per value |
| SMTP reply | 1 KiB per line, 64 lines, 16 KiB total |
| Concurrent SMTP sessions per channel | 4 (further dispatches fail immediately rather than queue) |
| Timeouts | `connect_timeout_ms` applies independently to DNS resolution, TCP connect, and the TLS handshake (so a stalled connect can take up to 3× the configured value before it fails); `command_timeout_ms` bounds each command/reply exchange including `DATA` |

Security notes:

- Credentials resolve through the same inline / `*_env` convention as the other channels, so the gateway secret resolver (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP`) materializes them. They are never logged, never `Debug`-printed (the channel has a hand-written `Debug` impl), and never appear in an error.
- Delivery errors are structured and carry only a phase plus the numeric SMTP reply code — server reply text is always withheld because it is untrusted and can be attacker-influenced. A reply that echoes the configured password, or either credential in its on-the-wire base64 form, aborts the session with a dedicated error. The plaintext AUTH username is deliberately not watched: it is usually the mailbox address and relays legitimately echo addresses in `MAIL FROM` / `RCPT TO` replies.
- Multiline replies are parsed strictly: every line must repeat the same 3-digit code with a `-`/space separator, and a malformed, oversized, or truncated reply fails the send.
- Every templated value that reaches a header has its control characters folded to spaces, and the body is base64-encoded, so neither header injection nor premature `DATA` termination is reachable from template variables.
- The resolved SMTP address is screened against `FERRUM_BACKEND_ALLOW_IPS` / `FERRUM_BACKEND_DENY_CIDRS` before connecting, so a hostname that resolves into a denied range is refused.
- `smtp_host` participates in startup warmup/preflight DNS resolution (`NotificationChannel::warmup_hostnames`).

### Template variables provided by the notifications layer

These are always available to the operator-templated channels (generic `webhook` body, `email` subject/body), derived from the supplied `Notification`:

- `${title}` — notification title
- `${body}` — notification body
- `${severity}` — `info` / `low` / `medium` / `high` / `critical`
- `${event_action}` — `trigger` / `resolve` / `info`
- `${fired_at}` — RFC 3339 timestamp
- `${source}` — caller-defined identifier (e.g., `proxy_alerts:proxy_5xx`)
- `${subject_id}` — caller-defined subject (e.g., proxy name)
- `${namespace}` — caller-defined namespace

The `email` channel adds one more: `${fields}` — the notification's key/value rows rendered as `Name: value` lines.

Callers can supply additional variables via `dispatch_with_vars`. The [`proxy_alerts` plugin](proxy_alerts.md#webhook-template-variables) adds `${rule_name}`, `${proxy_id}`, `${observed}`, `${threshold}`, etc. Extra variables are consumed only by the `webhook` and `email` channels because Slack, Teams, and Discord use fixed native payload shapes. Generic notification variables win on key collisions, so a caller cannot shadow `${title}` or `${severity}`.

Special characters:
- `${name}` — variable substitution.
- `$$` — literal `$`.
- Unknown variables are passed through unmodified (`${typo}` stays as `${typo}` in the output) so misconfigured templates remain auditable. Unbalanced `${` is rejected at construction.
- `${metadata}`-style raw map injection is NOT supported; this would bypass the gateway's metadata-redaction layer.

## Dispatch helper

```rust
use std::sync::Arc;
use tokio::sync::Semaphore;
use ferrum_edge::notifications::{dispatch, Notification, NotificationChannel};
use ferrum_edge::plugins::utils::http_client::PluginHttpClient;

let sem = Arc::new(Semaphore::new(8));
dispatch(
    Arc::new(my_notification),
    &[Arc::clone(&channel)],
    &sem,
    &http_client,
    "my_subsystem",
);
```

`dispatch` is fire-and-forget: each channel send runs on its own `tokio::spawn` under the supplied semaphore. When permits are exhausted alerts are dropped with a `warn!` rather than queued — alert storms during a partial channel outage should be visible, not buffered. Each caller owns its own `Semaphore` so dispatch budgets do not interact across subsystems.

## Reusing the layer from a non-plugin caller

```rust
use std::sync::Arc;
use chrono::Utc;
use tokio::sync::Semaphore;
use ferrum_edge::notifications::{
    dispatch, EventAction, Notification, NotificationField, Severity,
    channels::parse_channels,
};

let channels = parse_channels(&serde_json::json!({
    "ops": {
        "type": "slack",
        "webhook_url": "https://hooks.slack.com/services/T/B/X"
    }
}))?;

let sem = Arc::new(Semaphore::new(4));
let n = Notification::builder("Gateway entered draining state")
    .body("FD usage at 96% — overload manager has shed new connections")
    .severity(Severity::High)
    .event_action(EventAction::Trigger)
    .source("overload_manager")
    .fired_at(Utc::now())
    .field("FD %", "96")
    .build();

dispatch(
    Arc::new(n),
    &channels.values().cloned().collect::<Vec<_>>(),
    &sem,
    &http_client,
    "overload_manager",
);
```

## When to extend this module

Add a new channel under `src/notifications/channels/<name>.rs` with:
- A `NewName::new(name: &str, value: &serde_json::Value) -> Result<Self, String>` constructor.
- A `dispatch(&self, &Notification, &PluginHttpClient) -> Result<(), String>` method.
- A `name(&self) -> &str` accessor.
- A new `NotificationChannel` variant.
- A match arm in `build_channel()` in `src/notifications/channels/mod.rs`.
- Snapshot / parse tests in `tests/unit/notifications/channels_tests.rs`.

Email / SMTP ships natively (see [Email (SMTP)](#email-smtp)). PagerDuty and Opsgenie remain deferred follow-ups — the generic webhook covers both via `body_template` and `headers` today.
