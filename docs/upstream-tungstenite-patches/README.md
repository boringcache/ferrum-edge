# Vendored tungstenite patches: WebSocket takeover and bounded parsing

> Governance: tracked in [docs/dependency-policy.md](../dependency-policy.md). Any
> change to `vendor/tungstenite-0.29.0-ferrum-patched/` or
> `vendor/tokio-tungstenite-0.29.0-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## What this patches

Ferrum vendors patched copies of `tungstenite` and `tokio-tungstenite` so
WebSocket tunnel mode can recover bytes that the backend coalesced with the
`101 Switching Protocols` response before dropping to raw bidirectional relay.
The tungstenite copy also carries Ferrum's early frame-policy enforcement: the
declared payload length is checked before reservation, valid Close frames bypass
the application ceiling, and every control frame is still rejected above RFC
6455's 125-byte limit before allocation. Frame-policy failures retain a
distinct `CapacityError::FrameTooLong` origin so the gateway can select the
correct close reason when frame and reassembled-message ceilings are equal.

## Upstream tracking

| Crate | Upstream PR | Applied commits | Local version |
|---|---|---|---|
| `tungstenite` | <https://github.com/snapview/tungstenite-rs/pull/556> | `117597cbfccf2af44e97561cb2efa713d8454ed2`, `78db146fb240776a3082621ce054927488423e86` | 0.29.0 |
| `tungstenite` frame-limit origin | **Deliberate fork — not yet filed upstream** | Ferrum local | 0.29.0 |
| `tokio-tungstenite` | <https://github.com/snapview/tokio-tungstenite/pull/380> | `ba1d8f8897a09e4cdf1088456667e8c24ee15832` | 0.29.0 |

Both PRs were open when vendored. The local API names and return types match the
upstream proposals:

- `tungstenite::WebSocket::into_inner_with_read_buffer(self) -> (Stream, Bytes)`
- `tungstenite::WebSocketContext::into_read_buffer(self) -> Bytes`
- `tokio_tungstenite::WebSocketStream::into_inner_with_read_buffer(self) -> (S, tungstenite::Bytes)`

## Local modifications

- Copied the locked crates.io `0.29.0` sources under:
  - `vendor/tungstenite-0.29.0-ferrum-patched/`
  - `vendor/tokio-tungstenite-0.29.0-ferrum-patched/`
- Removed registry packaging files (`.cargo-ok`, `.cargo_vcs_info.json`,
  crate-local `Cargo.lock`, and `Cargo.toml.orig`) to match the existing
  Ferrum vendor layout.
- Applied the substantive upstream changes and tests.
- Added a short `Ferrum local patch` changelog section to each vendored crate
  because the packaged release source does not carry the upstream PR's
  `UNRELEASED` heading.
- Made the frame decoder's pre-reservation policy check opcode-aware. Text,
  Binary, continuation, Ping, and Pong payloads honor the caller ceiling; valid
  Close frames bypass it, while the protocol's 125-byte control-frame maximum
  remains an independent pre-allocation bound.
- Added `CapacityError::FrameTooLong` at that pre-reservation boundary. This is
  a deliberate Ferrum extension, owned by `@jeremyjpj0916`, and must be filed
  upstream or explicitly re-affirmed before the first stable release under the
  dependency-policy SLA. It preserves frame-vs-reassembly attribution without
  weakening either parser ceiling.
- Wired both crates through root `[patch.crates-io]`.

## Direct vendor-test commands

```bash
cargo test --manifest-path vendor/tungstenite-0.29.0-ferrum-patched/Cargo.toml --lib into_inner_with_read_buffer
cargo test --manifest-path vendor/tungstenite-0.29.0-ferrum-patched/Cargo.toml --lib size_limit_hit
cargo test --manifest-path vendor/tokio-tungstenite-0.29.0-ferrum-patched/Cargo.toml --config 'patch.crates-io.tungstenite.path="vendor/tungstenite-0.29.0-ferrum-patched"' --test into_inner_with_read_buffer
```

The explicit `--config` on the tokio-tungstenite command makes its standalone
manifest use the adjacent patched tungstenite copy.

## Ferrum gateway use

The tunnel-mode fast path calls
`WebSocketStream::into_inner_with_read_buffer()` immediately after the backend
handshake and before any WebSocket-frame operation. That point is a
frame-codec boundary, which satisfies the upstream accessor's documented
precondition. Ferrum writes the recovered backend bytes to the client before
starting the existing raw relay so later backend bytes cannot overtake them.
The parsed relay maps `FrameTooLong` only to the effective frame rule and
`MessageTooLong` only to the effective reassembled-message rule.

## Retirement condition

Do not retire these vendor directories merely because the PRs merge. Retire
only after **both** upstream takeover changes are present in published
compatible releases consumed by ferrum-edge and the consumed tungstenite
surface preserves an equivalent frame-vs-message capacity origin. If the
origin has not shipped upstream, carry forward only that documented minimal
extension until its own retirement condition is met.

At retirement:

1. Bump `tokio-tungstenite` / `tungstenite` dependency versions and update
   `Cargo.lock` through Cargo.
2. Remove these root `[patch.crates-io]` entries:
   - `tungstenite = { path = "vendor/tungstenite-0.29.0-ferrum-patched" }`
   - `tokio-tungstenite = { path = "vendor/tokio-tungstenite-0.29.0-ferrum-patched" }`
3. Delete both vendor directories.
4. Keep the gateway call-site logic using
   `WebSocketStream::into_inner_with_read_buffer()`.
5. Re-run the WebSocket tunnel regression and the broad Rust checks for the
   dependency bump.
