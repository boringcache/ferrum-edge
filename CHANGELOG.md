# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security

- `body_validator` now enforces the validation it advertises on all four of its
  surfaces. Configured JSON Schemas are compiled once at plugin construction with
  the `jsonschema` crate under an explicit draft (`json_schema_draft`, default
  `draft2020-12`) instead of being interpreted by a partial handwritten
  evaluator, so `$ref`/`$defs`, union types, conditionals, and other standard
  keywords take effect and malformed schemas, invalid type names, non-local
  references, `$vocabulary` declarations, and over-budget schemas fail
  configuration closed; no external reference is ever retrieved. XML bodies are
  parsed with `roxmltree` rather than scanned for balanced tags, so multiple
  roots, text outside the root, invalid names or characters, malformed/unquoted/
  duplicate attributes, and undeclared entity references are rejected, external
  entity declarations are refused outright, and `required_xml_elements` matches
  parsed namespace-expanded names. Decoded gRPC protobuf messages must satisfy
  proto2 `required`-field initialization recursively, including inside present
  nested, repeated, map, and extension message values. Unknown top-level config
  keys and unknown keys inside a `protobuf_method_messages` entry are rejected
  before defaults, so a typo can no longer silently replace enforcement with a
  weaker policy. This is a breaking configuration change; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#body-validator-enforcement-hardening).

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
