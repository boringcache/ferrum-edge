# Patch 003 — optional `WebSocketConfig::auto_pong`

## Status

| Field | Value |
|---|---|
| Patch ID | 003-optional-auto-pong |
| Target crate | `tungstenite` |
| Target version | 0.29.0 |
| State | **Applied via vendored crate at `vendor/tungstenite-0.29.0-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — not yet filed_ |
| Tracks | Ferrum Edge issue [#2963](https://github.com/ferrum-edge/ferrum-edge/issues/2963) — transparent WebSocket Ping/Pong through the shared H1/H2/H3 relay |

## Why this exists

Stock tungstenite auto-queues a local `Pong` on every received `Ping` (flushed on
the next read/write). That is correct for ordinary endpoints, but a transparent
proxy that also *forwards* `Message::Ping` then produces **two** Pongs for one
Ping (local framer + far side) and answers instantly even when the far side is
hung.

This patch adds `WebSocketConfig::auto_pong` (default `true`) so Ferrum's relay
can set `auto_pong = false` on proxy framers only. Explicit `Message::Pong`
writes are unchanged. Non-relay call sites (plugins, tests, ordinary clients)
keep the upstream default.

## Files

| File | Purpose |
|---|---|
| `tungstenite-auto-pong.patch` | Unified diff against the vendored 0.29.0 base (protocol config + Ping arm) |
| `README.md` | This status / retirement record |

## Hand-off — how to file upstream

1. Open an issue on [snapview/tungstenite-rs](https://github.com/snapview/tungstenite-rs) describing the transparent-proxy use case and proposing `WebSocketConfig::auto_pong` (default `true`).
2. Push a fork branch with the patch applied and open a PR.
3. Record the issue + PR numbers here, in `docs/dependency-policy.md`, and in
   `docs/vendored-patch-lifecycle.json`.

## Retirement

Retire when an upstream release consumed by ferrum-edge ships an equivalent
opt-out (same default-true semantics) **and** the co-vendored tungstenite /
tokio-tungstenite patches are also ready to retire (see the parent
[README](../README.md)). Until then this remains a deliberate, time-boxed fork
owned by `@jeremyjpj0916` under the dependency-policy SLA.

## Behavioral regressions

- Vendored: `auto_pong_default_queues_local_reply`,
  `auto_pong_disabled_does_not_queue_local_reply` in
  `vendor/tungstenite-0.29.0-ferrum-patched` (`--lib auto_pong`).
- External unit: `tests/unit/gateway_core/websocket_auto_pong_tests.rs`.
- Functional (shared `run_websocket_proxy`): H1/H2/H3 Ping transparency tests in
  `tests/functional/functional_websocket_test.rs` (`test_*websocket_ping_*`).
