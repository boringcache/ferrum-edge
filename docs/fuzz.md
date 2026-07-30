# Adversarial fuzz and property-testing lane

Ferrum Edge carries a **separate** `fuzz/` cargo-fuzz workspace for hostile-input
testing of pure parsers and validators. libFuzzer, nightly, and `proptest` live
only under `fuzz/` — the production `ferrum-edge` binary does not depend on them.

## Targets and invariants

| Target | Surface | Budgets | Invariants |
|--------|---------|---------|------------|
| `traceparent` | W3C `traceparent` parse | 64 KiB input | Fail closed (`None`); accepted values round-trip |
| `config_decode` | YAML/JSON config decode + validation | 64 MiB doc (loader cap), 64 KiB fuzz input | No panic; validation errors only |
| `proxy_protocol` | PROXY v1/v2 header parse | 528-byte header cap | Fail closed; bounded address block |
| `mesh_udp_frame` | HBONE datagram framing | 64 KiB input, 256 frames/invocation | Length prefix bounded; encode/decode round-trip |
| `k8s_crd` | Istio/Gateway API JSON → translation | 32 objects, depth 64 | Fail-closed translation errors |
| `plugin_config` | Representative plugin JSON validation (one selector byte followed by JSON) | depth 64 | `validate_plugin_config` never panics |

Shared budgets and helpers live in `src/fuzz_support.rs`.

## Corpora

Seed only **synthetic boundary cases** under `fuzz/corpus/`. Never commit
production configs, JWTs, TLS material, or packet captures. The hosted workflow
rejects crash artifacts larger than 64 KiB before upload.

## Hosted CI

- **PR / `main` smoke** (`ci.yml` → `Fuzz Smoke`): locked `proptest` smoke tests
  plus ~8 s libFuzzer budget per target (`-runs=512`, `-max_len=4096`,
  `-rss_limit_mb=1024`).
- **Scheduled sanitizer lane** (`.github/workflows/fuzz.yml`): AddressSanitizer
  builds, 300 s per target, bounded crash artifacts uploaded after size/count
  checks, a 2048 MiB RSS cap, 7-day retention, and concurrency capped at two
  targets.

The fuzz crate links the main Ferrum Edge crate, whose Kafka dependency builds
`librdkafka` from source with OAuthBearer OIDC disabled. librdkafka 2.12.1
nevertheless includes `curl/curl.h` because one preprocessor guard tests whether
the disabled macro is defined instead of whether it is enabled. The isolated
fuzz dependency graph therefore activates `rdkafka`'s `curl-static` feature and
uses its real vendored curl headers. Production builds retain their existing
feature set, while the byte-frozen hosted workflows avoid relying on ambient
curl development headers or a nested Cargo configuration. They still install
the pinned workflow's required `protobuf-compiler` build dependency.

## Local workflow (optional)

Local builds are not required; GitHub Actions is the gate. When investigating a
crash locally:

```bash
cd fuzz
rustup toolchain install nightly-2025-07-01
cargo install cargo-fuzz --locked --version 0.13.1
cargo fuzz run traceparent corpus/traceparent/ -- -runs=0   # replay seeds
cargo fuzz run traceparent -- -max_total_time=60
```

Use only synthetic inputs. Scrub artifacts before sharing; never copy production
traffic into `corpus/`.

## Crash promotion

1. Reproduce from the uploaded artifact with `cargo fuzz run <target> <artifact>`.
2. Minimize: `cargo fuzz tmin <target> <artifact>`.
3. Add the minimized input to `fuzz/corpus/<target>/` with a descriptive name.
4. Add a permanent regression test under `tests/unit/` or `fuzz/tests/` when the
   crash encodes a real bug fix.
5. Do not merge corpora that contain secrets or customer data.

## Toolchain pins

| Component | Pin |
|-----------|-----|
| Rust (fuzz) | `nightly-2025-07-01` (`fuzz/rust-toolchain.toml`) |
| `cargo-fuzz` | `0.13.1` (pinned in admitted CI workflows) |
| `libfuzzer-sys` | `0.4.9` (`fuzz/Cargo.toml`) |
| `proptest` (smoke only) | `1.6.0` (`fuzz/Cargo.toml` dev-dep) |

Production `rust-toolchain.toml` remains `stable`; fuzz dependencies stay isolated
in the `fuzz/` crate per `docs/dependency-policy.md`.
