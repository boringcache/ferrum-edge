# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- Plugin egress no longer inherits ambient proxy configuration
  (GHSA-c4pj-vq6x-53rw). The dedicated ClickHouse client built by
  `api_chargeback_sink` for custom CA / mTLS / relaxed-verification settings, and
  the dedicated `spec_expose` and `load_testing` clients, now call
  `reqwest::ClientBuilder::no_proxy()` like the shared `PluginHttpClient` and its
  fallback builders. With a proxy selected from `HTTP_PROXY` / `HTTPS_PROXY` /
  `ALL_PROXY`, Ferrum resolved and screened the *proxy* while the proxy resolved
  and connected to the configured hostname, so the ultimate destination never
  passed `BackendEgressPolicy`. A CI guard now fails if any policy-governed
  plugin `reqwest` builder drops `.no_proxy()`.
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
