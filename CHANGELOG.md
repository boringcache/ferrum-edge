# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Plugin egress no longer inherits ambient proxy configuration
  (GHSA-c4pj-vq6x-53rw). Backend dispatch `reqwest` clients (via
  `BackendTlsConfigBuilder::build_reqwest`), active health-check clients
  (primary, custom-TLS, and degraded DNS-cached fallbacks), the dedicated
  ClickHouse client built by `api_chargeback_sink` for custom CA / mTLS /
  relaxed-verification settings, and the dedicated `spec_expose` and
  `load_testing` clients now call `reqwest::ClientBuilder::no_proxy()` like the
  shared `PluginHttpClient` and its fallback builders. With a proxy selected
  from `HTTP_PROXY` / `HTTPS_PROXY` / `ALL_PROXY`, Ferrum resolved and screened
  the *proxy* while the proxy resolved and connected to the configured hostname,
  so the ultimate destination never passed `BackendEgressPolicy`. A CI guard
  now fails if any policy-governed `reqwest` builder drops `.no_proxy()`.
- `ws_logging` now enforces backend egress policy on the address it actually
  dials (GHSA-mp2j-gjfp-2vm8). Every connection and reconnection resolves the
  endpoint fresh (bypassing both DNS cache layers), rejects the complete A+AAAA
  answer if any candidate is denied, rechecks each candidate immediately before
  its socket is opened, and dials only screened addresses. The configured
  hostname is retained as the TLS SNI / certificate identity and the WebSocket
  `Host` authority. Previously the endpoint was handed to `tokio-tungstenite`,
  which resolved and dialed it outside the policy, so a hostname could rebind to
  a denied address between admission and any later reconnect.
- `kafka_logging` bootstrap parsing now matches the pinned librdkafka grammar
  (`[proto://]host[:port]`, URL-path truncation, bracketed-IPv6 port rules,
  empty host → `localhost`), so protocol-prefixed denied literals such as
  `PLAINTEXT://169.254.169.254:9092` are rejected instead of evading a
  `host:port`-only screen. Entries whose protocol prefix disagrees with
  `security_protocol` are rejected rather than silently truncating the broker
  list the way librdkafka would.
- `ai_semantic_cache` no longer discards Redis quarantine-`DEL` failures for
  malformed, oversized, empty, or otherwise inadmissible entries. Failed deletes
  are counted with rate-limited warnings that omit keys, payloads, credentials,
  and endpoints, and a bounded per-instance local suppressor (content fingerprint
  + 30s TTL, hard-capped, constant-work capacity eviction) prevents immediate
  re-download/parse/delete amplification of the same poisoned remote value while
  still reconsidering repaired replacements within that bound. Quarantine
  fingerprints are computed only after a Redis value fails admission, so valid
  hits are not hashed for poison markers. Invalid entries remain unserved;
  deletion failure cannot convert a miss into a hit (issue #3213).
- `response_caching` now applies RFC 9111 §3.5 shared-cache admission to the
  live request credential rather than only to a gateway-minted identity, so a
  gateway that forwards `Authorization` to a backend that validates it no longer
  retains the protected response without an explicit `public` /
  `must-revalidate` / `s-maxage` opt-in. `cache_key_include_consumer` remains a
  key-partition option but no longer overrides the origin's storage policy.
  Backend-side revocation, expiry, and scope changes are no longer masked for
  the entry's lifetime (GHSA-7f28-wh4x-5375).
- `Cache-Control` is parsed with quoted-string awareness, so the qualified
  `private="…"` and `no-cache="…"` field-name forms are understood. Named fields
  are removed from the retained entry instead of being replayed from the shared
  cache, and a malformed qualified argument fails closed to the bare directive.
  Connection-scoped and proxy-authentication response fields are also stripped
  before storage (GHSA-fpx2-5v4j-wqxq).
- `1xx`, `206`, and `304` can no longer be configured in
  `cacheable_status_codes`, are refused again at store time, and are never
  replayed; a response carrying `Content-Range` is likewise never stored. A
  caller can no longer poison a shared cache with a partial or validator-only
  representation (GHSA-v7fj-73gm-h625). **Breaking:** existing plugin rows
  containing those statuses must be repaired before upgrade — see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#response-cache-shared-storage-hardening).

### Changed

- **Breaking:** `kafka_logging` now fails closed under any restrictive backend
  egress policy, including the default posture. librdkafka resolves bootstrap
  hostnames itself and dials brokers advertised by cluster metadata, and the
  pinned `rdkafka 0.39` exposes no connect/resolve callback, so those addresses
  cannot be screened. The plugin is admitted only under a fully-open policy
  (`FERRUM_BACKEND_ALLOW_IPS=both`, no `FERRUM_BACKEND_DENY_CIDRS`,
  `FERRUM_BACKEND_BLOCK_DANGEROUS_RANGES=false`). Deployments that need Kafka log
  shipping under a restrictive policy should ship through a policy-aware sink
  (`http_logging`, `tcp_logging`, `ws_logging`, `loki_logging`) and bridge to
  Kafka outside the gateway. See
  [Backend Egress / SSRF Protection](docs/configuration.md#kafka_logging-requires-a-fully-open-egress-policy).

- Authenticated `/metrics` now renders TLS certificate gauges from a cached,
  non-secret TLS inventory snapshot and performs no certificate, private-key,
  Kubernetes, HSM, or cloud-secret I/O on the scrape path. The snapshot is
  refreshed by a bounded single-flight background task governed by the new
  `FERRUM_TLS_INVENTORY_SNAPSHOT_TTL_SECONDS` (default 300, `0` disables it), its
  freshness is exported as `ferrum_tls_inventory_snapshot_timestamp_seconds` /
  `ferrum_tls_inventory_snapshot_max_age_seconds`, and certificate gauges are
  absent until the first snapshot is published. `GET /admin/tls/inventory` still
  collects live.
- Added release governance requiring version tags to match the package version and
  requiring build-out breaking changes to be recorded here.
- Hardened `tcp_connection_throttle` config loading to fail closed for
  unsupported-only global targets, non-TCP scoped attachments, unknown config
  fields, and cleanup intervals above 86400 seconds. Existing deployments must
  remediate these rows before upgrade; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#tcp-connection-throttle-validation-hardening).

## [0.9.0]

Ferrum Edge 0.9.0 represents the current build-out baseline: a multi-protocol
edge proxy with file, database, control-plane, data-plane, mesh, injector, and
node-agent modes plus its plugin and operational tooling. This entry is
intentionally coarse-grained rather than a reconstruction of unreleased history;
see [GitHub Releases](https://github.com/ferrum-edge/ferrum-edge/releases) for
published release notes.

[Unreleased]: https://github.com/ferrum-edge/ferrum-edge/compare/v0.9.0...HEAD
[0.9.0]: https://github.com/ferrum-edge/ferrum-edge/releases/tag/v0.9.0
