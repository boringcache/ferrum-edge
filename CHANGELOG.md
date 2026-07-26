# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- **`request_deduplication` Redis ownership is now atomically fenced**
  (GHSA-f72h-jm2p-mc73). Ownership and completion share one versioned operation
  record per logical key. Completion is a compare-and-set on the owner's exact
  in-flight record, so an owner whose `inflight_ttl_seconds` lease expired can
  neither overwrite a successor's completed response nor publish while a
  successor owns the operation; such a completion is discarded locally too
  instead of being replayed as a non-authoritative result. Redis-mode logical
  keys move to `v4`, unconditionally include the matched proxy namespace even
  under an explicitly shared Redis prefix, and the record format is versioned,
  so a rolling upgrade reads and writes disjoint keys instead of mixing
  formats. Current-version records with missing ownership fences, impossible
  state fields, or mismatched inner/outer fingerprints fail closed. A new
  `on_redis_unavailable` field decides outage behavior and **defaults to
  `fail_closed` (HTTP 503)**; deployments that prefer the previous
  process-local fallback must set `on_redis_unavailable: "local_only"`.
- **`request_deduplication` rejects unknown configuration keys**
  (GHSA-h2c3-j3cm-7ghh). The runtime constructor and the OpenAPI
  `RequestDeduplicationConfig` schema now share one closed allowlist, so a
  misspelled `enforce_required` or `sync_mode` fails admission with a
  path-qualified diagnostic instead of silently reverting to a permissive
  default. Redis-only keys are additionally rejected outside
  `sync_mode: "redis"`. Existing configurations carrying stray keys, or
  `redis_*` fields in local mode, must be corrected before upgrade.
- **Completed external operations behind a synthetic response now leave a
  durable completion** (GHSA-8cr6-rw38-7j59). `serverless_function` terminate
  mode and `ai_federation` provider calls declare that their short-circuit
  performed the protected billable operation; deduplication publishes a
  non-replayable 409 completion tombstone — fenced in Redis mode — on buffered,
  empty/HEAD, streamed-fallthrough, and interrupted-delivery outcomes alike.
  Previously an interrupted delivery only held a bare in-flight marker, so an
  identical retry re-executed the operation once `inflight_ttl_seconds` elapsed.
  The tombstone is retained for `max(ttl_seconds, inflight_ttl_seconds)`: it
  replaces a marker that blocked duplicates for `inflight_ttl_seconds`, so a
  deployment configured with `inflight_ttl_seconds > ttl_seconds` never becomes
  re-executable sooner than it was before. Ordinary replayable completions keep
  `ttl_seconds`. The barrier also covers the case where the committed response
  itself cannot be retained as a replay — its request straddled a
  response-presentation-policy publication, or that policy is incomplete or
  `Dynamic` — instead of falling back to the bare in-flight lease. Serverless
  responses with stable, complete policy provenance are still stored as ordinary
  replays. The provenance contract is documented in
  `docs/plugin_execution_order.md`.
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
