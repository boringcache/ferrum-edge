---
paths:
  - "src/tls/**"
  - "src/dtls/**"
  - "src/secrets/**"
  - "src/identity/**"
  - "src/modes/tls_reload.rs"
  - "src/admin/jwt_auth.rs"
  - "src/plugins/*auth*.rs"
  - "src/plugins/mtls_auth.rs"
  - "src/plugins/jwks_auth.rs"
  - "src/plugins/utils/http_client.rs"
  - "src/plugins/utils/metadata_redaction.rs"
  - "docs/frontend_tls.md"
  - "docs/backend_mtls.md"
  - "docs/database_tls.md"
  - "SECURITY.md"
  - "tests/unit/tls/**"
  - "tests/unit/secrets/**"
  - "tests/unit/identity/**"
  - "tests/integration/*tls*"
  - "tests/integration/*svid*"
  - "tests/integration/*mtls*"
  - "tests/functional/*tls*"
  - "tests/functional/*secrets*"
  - "tests/functional/*mtls*"
---

# TLS, Secrets, And Security Rules

## Boundary Security

- Validate hostile input at trust boundaries: path traversal, malformed PEM/DER, invalid SANs, oversized bodies, recursive embedded credentials, and archive/file names.
- Escape user input when interpolating JSON/XML response bodies.
- Preserve transaction metadata redaction for all logger sinks.

## TLS-Only And Frontend Admission

- Port `0` on plaintext proxy/admin/CP gRPC listener settings disables plaintext and is excluded from `reserved_gateway_ports()`.
- Gateway warns if plaintext is disabled and no TLS listener is configured.
- TLS/DTLS-terminating client-facing protocols must complete frontend crypto and plugin admission before dialing a backend.
- Frontend handshake failures and plugin rejects must not trip backend circuit breakers.
- Frontend TLS/DTLS handshakes are bounded by `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS`, default 10s. `0` disables.
- DTLS demux state is capped before per-peer channel/task allocation and released on handshake timeout.

## TLS Rotation Model

- Most file-based TLS materials are static operational inputs. Cert/key file changes require gateway restart or rolling redeploy unless explicitly listed below.
- Mesh peer-auth reload is limited to resolved inbound mTLS mode and frontend client CA verifier when `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`.
- Frontend cert/key live reload is enabled only when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`.
- Frontend watcher covers proxy HTTPS/H2/H3 and admin HTTPS cert/key paths at `FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS`, default 30s.
- On validated frontend change, rebuild rustls `ServerConfig`, rerun early-data and kTLS-secret-extraction settings, swap `SharedFrontendTls`, and notify H3 to call `Endpoint::set_server_config`.
- Reload parse, expiry, not-yet-valid, or key mismatch failures keep the previous config and emit `warn!`.
- In-flight TLS sessions keep their original `ServerConfig`; swapping must not tear down live sessions.
- DTLS frontend and operator-supplied per-proxy backend TLS paths remain static under frontend live reload.
- Gateway SVID cert/key/trust-bundle files are watched for backend client SVID rotation. Valid reload updates the SVID slot, preserves CP-delivered trust-bundle override, bumps `|svidg=<generation>`, drains old backend TLS caches, restarts HTTP health probes, and optionally force-drains old-generation pool entries after `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS`. This watcher rotates the **backend (outbound)** identity, and — when the gateway SVID also backs the **mesh inbound** listener's server cert (issue #1523 — no explicit `FERRUM_FRONTEND_TLS_*` set) — the inbound server certificate as well: the inbound credential is a live `ResolvesServerCert` (`tls::SvidServerCertResolver`) reading the same shared SVID slot, so new handshakes present the rotated leaf with no restart. The resolver is fail-closed: an empty slot or rotated-in material rustls rejects fails handshakes (warned once per bad snapshot, cached so there is no per-handshake rebuild), never serves a stale previous leaf. The **`FERRUM_MESH_CA_BACKEND=spire|internal`** source feeds the *same* slot instead of files (`start_mesh_ca_backend_svid_source`, mesh-only: `spire` = SPIRE Workload API fetch loop reusing `SvidFetchHandle`; `internal` = dev-only `bootstrap_dev_root` + `InternalCa`), blocked on the first SVID at startup (`MESH_CA_INITIAL_SVID_TIMEOUT`, 30s) so listeners never bind identity-less, then live-rotates it — so the identical `SvidServerCertResolver` + backend-pool-repartition rotation applies; the source differs, the slot and consumers do not. Explicit `FERRUM_GATEWAY_SVID_*` file material takes precedence when both are configured, and `FERRUM_MESH_WORKLOAD_SPIFFE_ID` pins the CA-fetched identity. Keep resolver and slot semantics in sync with `docs/mesh.md`'s mesh-identity section.
- Backend CA bundles and ordinary backend client cert/key paths remain restart-required.

## Backend Trust

- Backend CA chain order is proxy `backend_tls_server_ca_cert_path`, then global `FERRUM_TLS_CA_BUNDLE_PATH`, then webpki/system roots.
- Opt-out is explicit: `backend_tls_verify_server_cert: false` or `FERRUM_TLS_NO_VERIFY=true`.
- Proxy backend reqwest paths pass a fully built rustls `ClientConfig` through `use_preconfigured_tls(...)`; trust store construction stays in-house.
- Custom CA is exclusive and replaces built-in roots. For reqwest use `.tls_certs_only([cert])`; for rustls start with `RootCertStore::empty()`.
- Reqwest no-custom-CA helper clients use `rustls-platform-verifier` through the bundled `rustls` feature: macOS keychain, Windows cert store, then webpki fallback on Linux.
- Helper-client verifier behavior applies only when no global or per-plugin CA is configured.

## Validation, Expiry, And CRL

- Per-proxy TLS paths are validated by `validate_all_fields_with_ip_policy()` at config load.
- File mode refuses startup for invalid TLS paths. DB mode warns. DP rejects the update and keeps cached config. No silent fallback.
- `check_cert_expiry()` checks `notBefore` and `notAfter` on all surfaces. Expired certs are hard failures.
- Warn within `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS`, default 30.
- `FERRUM_TLS_CRL_FILE_PATH` is PEM, loaded once, and `Arc`-shared.
- CRL applies to frontend mTLS for H1/H2/H3/DTLS, all rustls backend paths, and rustls logging sinks.
- CRL does not apply to DP-to-CP gRPC or reqwest-based plugin paths because those stacks do not expose compatible CRL config.
- CRL reload requires restart.

## Pooling And Non-Rustls Paths

- Reqwest TLS paths use distinct `reqwest::Client` instances per cert/trust identity.
- The shared `PluginHttpClient` disables HTTP redirect following (`reqwest::redirect::Policy::none()`) in every constructor, matching the backend proxy client. A server-returned 3xx is surfaced to the caller, never chased, so a spoofed/compromised upstream cannot bounce plugin egress (log/webhook sinks, OIDC/JWKS discovery, AI federation) to an internal or cloud-metadata host. First-hop host pinning in callers like `jwks_auth` is necessary but not sufficient; the `DnsCacheResolver` IP screen goes through the resolved `BackendEgressPolicy` (`BackendEgressPolicy::is_allowed`), which by default blocks cloud-metadata/link-local, multicast, and unspecified ranges even under `FERRUM_BACKEND_ALLOW_IPS=both` (the dangerous-range baseline), while leaving loopback/RFC1918 reachable. A restrictive mode (`private`/`public`) or `FERRUM_BACKEND_DENY_CIDRS` tightens it further; `FERRUM_BACKEND_ALLOW_CIDRS` is the explicit escape hatch. The legacy `check_backend_ip_allowed(addr, &BackendAllowIps)` primitive remains for fixed-mode callers like ACME (always public).
- Rustls direct H2 and gRPC paths configure TLS per connection.
- `kafka_logging` uses librdkafka/OpenSSL: map `FERRUM_TLS_CA_BUNDLE_PATH` to `ssl.ca.location`, `FERRUM_TLS_NO_VERIFY` to `enable.ssl.certificate.verification=false`, and CRL to `producer_config.ssl.crl.location`.
- Redis applies global TLS flags through `PluginHttpClient` accessors.
- Rustls logging sinks (`tcp_logging` TLS, `ws_logging` wss, `udp_logging` DTLS) apply gateway CRLs through `PluginHttpClient::tls_crls()`.
- Plugins that bypass proxy dispatch and use shared `PluginHttpClient`, such as `ai_federation`, get global TLS only. For private endpoints, include internal CAs in the global bundle and include public roots too because custom CA is exclusive.

## External Secrets

- Secret resolution runs at startup before config load and before concurrent env access.
- Env suffixes resolve the base key: `_VAULT`, `_AWS`, `_AZURE`, `_GCP`, and `_FILE`.
- Backends are grouped per provider so one client is reused.
- Two providers setting the same base key is a conflict and must fail.
- Do not expose resolved secret values in errors or logs.
- Do not expose a secret's *source reference* either — file paths, Vault paths, ARNs, Key Vault URLs. Backend errors are sanitized at one boundary in `src/secrets/registry.rs` (`redact_source_reference`), which every startup and single-key fetch passes through; leaf backends additionally do not interpolate the reference themselves. Errors stay at base-key + provider + failure-class level. Redaction covers the *provider-normalized* components too, not just the operator's original string: `source_reference_candidates` re-parses the reference through `azure::parse_keyvault_reference` and adds the vault URL, secret name, and their recombined form, because Azure drops a trailing `/<version>` segment and the SDK echoes what it was actually asked for. A new provider that rewrites its reference before fetching must add its normalized components there.
- Startup env-secret resolution must not consult the conf-file-aware resolver. `startup_secret_fetch_timeout()` reads `FERRUM_SECRET_FETCH_TIMEOUT_SECONDS` from the environment only; `crate::config::conf_file::resolve_ferrum_var` initializes the process-wide `CONF_FILE_CACHE`, and priming it before `FERRUM_CONF_PATH_FILE` is materialized silently pins the wrong settings file for the whole process. The conf-aware `secret_fetch_timeout()` stays for the later runtime single-key/TLS-material fetches.
- `_FILE` reads run on a detached OS thread, not `tokio::task::spawn_blocking`. A FIFO or stalled mount blocks uninterruptibly; timing out a `spawn_blocking` join handle returns on schedule but runtime teardown then waits for the blocking pool, so `validate`/`run` hung anyway after honoring the timeout. A detached thread is owned by no runtime and is not joined at process exit. Do not "simplify" this back to `spawn_blocking`.
- Resolved values must not resurface in later config diagnostics. `secrets::record_external_secret_keys()` records the externally loaded base keys before config load; `config::env_config_macro::invalid_env_value` withholds the value for those keys, and `secrets::redact_external_secret_values()` filters the final rendered `validate`/`run` failure as a backstop. That backstop is a single left-to-right pass over the *original* diagnostic with deduplicated, longest-first values: substituted placeholders are never re-scanned. Do not reintroduce a `replace()` loop over the running message — resolved values that are substrings of the placeholder (`value`, `external`, `a`) then feed each pass the previous pass's output and amplify one startup error into megabytes. There is deliberately no minimum length for the value *as materialized*; mangling a diagnostic is acceptable, unbounded growth is not.
- Returned-error redaction is not sufficient on its own, twice over. (a) Validators re-render values before echoing them — list parsers trim entries, `FERRUM_TLS_EARLY_DATA_METHODS` uppercases them, the fmt layer JSON-escapes the record — so `secrets::derive_candidates` expands each value into a **bounded, enumerable** set of those forms (`(2 + 32 segments) * 3 * 2` max). Derived candidates carry a 3-byte minimum; the exact value does not. Do not replace this with an open-ended normalization or a per-message candidate rebuild. (b) `warn!`/`info!` emitted *during* config parsing never pass through a returned `Result` at all — a non-GET `FERRUM_TLS_EARLY_DATA_METHODS_FILE` leaks on a **successful** `validate`. `secrets::redact_log_record` therefore filters at the single emission boundary in `logging::non_blocking::RecordWriter::submit`, gated by a relaxed `AtomicBool` so processes without external secrets pay nothing. A record that grows past `FERRUM_LOG_MAX_RECORD_BYTES` under substitution is dropped through the existing oversized path, not enqueued past its reservation. Because a `validate` failure is filtered twice (returned error, then serialized record), redaction is **idempotent**: a span already equal to the placeholder is skipped verbatim unless a candidate at least as long matches there. Removing that skip does not leak, but it lets pass two shred pass one's placeholders on `value`/`external`/`source`-shaped secrets. Non-tracing operator output (`emit_bootstrap_error`, `validate`'s `Spec (...)` line) bypasses that boundary and is filtered at its own call site.
- `ResolvedEnvSecrets` vectors are sorted by base key. Candidate discovery iterates a `HashMap`, so reporting order would otherwise vary between processes.

## Identity And SPIFFE

- Preserve SPIFFE/SVID trust-domain parsing and URI SAN validation behavior.
- SVID rotation must not mix stale cert/key material with new trust bundles.
- Gateway SVID pool-key generation uses the SVID generation marker to prevent pool poisoning across rotations.
- kTLS paths must zeroize secret material on drop and must not consume the TLS stream before kernel install is confirmed.
- Dev-only identity shortcuts stay double-gated. The self-signed CA bootstrap (`bootstrap_dev_root`) requires `FERRUM_MESH_CA_BOOTSTRAP_DEV=true`, the `StaticAttestor` requires `FERRUM_MESH_ALLOW_STATIC_ID=true`, and a `mesh` data plane with **no workload identity** — neither file-based gateway SVID material (`FERRUM_GATEWAY_SVID_*`) nor a CA backend (`FERRUM_MESH_CA_BACKEND=spire|internal`, now wired to load + rotate a runtime SVID into the same slot; `internal` is itself the dev-only `bootstrap_dev_root` path) — requires `FERRUM_MESH_ALLOW_NO_CA=true` (enforced in `EnvConfig::validate()`; fail-closed otherwise; a CA backend also requires `FERRUM_MESH_WORKLOAD_SPIFFE_ID`, and file material takes precedence when both are set). All three opt-ins are read directly from the environment (NOT from `ferrum.conf`/`EnvConfig`) and are refused unconditionally when `FERRUM_MESH_PRODUCTION_MODE=true` — itself read via the canonical `identity::production_mode()` helper — so a config-file-only value can never bypass the production guard. Do not relax any gate or collapse the per-posture opt-ins (`FERRUM_MESH_CA_BOOTSTRAP_DEV`, `FERRUM_MESH_ALLOW_STATIC_ID`, `FERRUM_MESH_ALLOW_NO_CA`) into a single flag.
- The `FERRUM_MESH_ALLOW_NO_CA` config-time presence check (no identity *named* at all) has a runtime complement (`enforce_mesh_inbound_fail_closed`, `src/modes/mesh`), at both the startup TLS-setup path and PeerAuthentication live reload, with two deliberately different severities: a listener that would serve **plaintext** (resolved `ServerConfig` `None` — PeerAuthentication DISABLE, or no usable server identity) is refused under `FERRUM_MESH_PRODUCTION_MODE=true` and allowed-with-warning in dev (an explicit DISABLE, or a no-identity posture the config-time gate already acknowledged, is intentional); a **configured-but-unloadable SVID verifier** (all three `FERRUM_GATEWAY_SVID_*` named but the bundle failed to load while the listener serves TLS) is **fatal regardless of production**, mirroring the hard error a broken SVID cert/key already gets. At reload, refusal rejects the slice and keeps the last-good mTLS config (fail-closed by retention). Gateway SVID material also backs the inbound server cert when no `FERRUM_FRONTEND_TLS_*` is set, so an SVID-only mesh serves mTLS rather than plaintext. The runtime gate reads only `identity::production_mode()` (captured once at startup, threaded into the reload path); `identity::allow_no_ca()` is consulted **only** by the config-time gate. Do not move these guardrail reads into `EnvConfig`.
