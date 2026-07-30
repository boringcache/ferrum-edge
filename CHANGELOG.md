# Changelog

All notable changes to Ferrum Edge will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added

- API-spec YAML ingestion now expands anchors and aliases through a bounded
  libyaml event graph (node, depth, alias-reference, expanded-byte, and work
  budgets) with cycle / undefined-alias / duplicate-anchor /
  duplicate-mapping-key detection before JSON conversion (#3307). The expanded
  byte budget is a fail-closed upper bound on the compact JSON representation,
  including string/key escaping. Merge keys are applied when present. JSON and
  YAML share the same expanded-node admission cap so autodetection cannot
  weaken checks. Expansion also fails closed on non-core/local YAML tags,
  non-finite numbers, and integers outside the exact JSON `i64`/`u64` range.
  Scalar number and boolean mapping keys keep the stringified spelling the
  previous `serde_json::to_value` conversion produced (`200:` → `"200"`), so
  YAML that leaves status codes unquoted still ingests and already-stored specs
  still restore.
- Istio Telemetry `accessLogging.filter.expression` now supports bounded boolean
  expressions with `||`, `&&`, parentheses, and the existing `response.code`,
  `response.status`, and `response.duration` comparison atoms. `duration` is
  accepted as the documented latency shorthand, and duration thresholds accept
  integer milliseconds by default or explicit `ms` / `s` suffixes with checked
  millisecond conversion. Pure conjunctions continue to compile into flat
  `AccessLogFilter` fields; expressions containing `||` compile into a
  pre-evaluated `expression` AST consumed by the injected `stdout_logging`
  plugin.
- Machine-readable vendored-patch lifecycle inventory at
  `docs/vendored-patch-lifecycle.json`, enforced on every PR and weekly
  `dependency-audit` run by `scripts/check_vendored_patch_lifecycle.py`. The
  inventory records owner, upstream filing state (or deliberate-fork staging ref),
  co-retirement groups, compatible-release test status, and the shared retirement
  checklist for all eleven current `[patch.crates-io]` logical patches. Unfiled
  deliberate forks are flagged for upstream filing or dated owner reaffirmation
  rather than tracked only in GitHub issue #3335. Because the `dependency-audit`
  job that runs the gate is required to stay on full CI, the PR planner now keeps
  `docs/dependency-policy.md`, `docs/vendored-patch-lifecycle.json`, and
  `docs/upstream-*-patches/` off the lightweight documentation path.

### Security

- `soap_ws_security` no longer trusts client media-type selection
  (GHSA-435h-f785-wmm4). Content types are parsed structurally (`type/subtype`
  plus RFC 9110 parameters) and matched by exact essence instead of
  case-insensitive substring search, and the new `content_type.mode` defaults to
  `strict`: every request on a SOAP-protected proxy is governed, so a SOAP
  envelope labelled `application/octet-stream`, `text/plain`, or with no
  `Content-Type` at all is rejected (415) before backend dispatch rather than
  streamed to a backend that routes by path or SOAPAction. `mixed_route` is the
  explicit pass-through opt-out. SOAP 1.1/1.2, `application/xml`,
  `application/xop+xml`, and MTOM/XOP `multipart/related` are supported;
  MTOM validates the root part's envelope (selected by `start`, else the first
  part) and refuses a root part that is mislabelled, re-encoded, or absent.
  A `multipart/form-data; boundary=application/xml` request is no longer
  raw-scanned as an envelope. MTOM package framing is now a strict MIME
  contract, because the parser decides which bytes are the envelope: delimiter
  *lines* are recognized only at the body start or immediately after a CRLF with
  exact CRLF framing and no transport padding (so a `--boundary` sequence inside
  a preamble, a header value, an attachment payload, or the envelope itself is
  inert payload rather than framing); exactly one close-delimiter is required
  and the epilogue after it must not contain the boundary token; part headers
  must be US-ASCII, unfolded, well-formed `token: value` pairs carrying at most
  one `Content-Type` / `Content-ID` / `Content-Transfer-Encoding` each;
  `Content-ID` values must be package-unique and nonblank, and with `start`
  supplied exactly one part may match; and the whole package is framed and every
  part parsed before a root is selected, so no later ambiguity is missed by an
  early return. Part, header, and boundary-candidate ceilings stay fail-closed.
  Previously an unanchored byte-substring search let an attacker plant a
  boundary-shaped sequence in a payload or preamble and have Ferrum validate a
  fabricated envelope — or a truncated one — while the backend executed the real
  root part.
- `soap_ws_security` now authenticates the signer before performing
  attacker-selected XML work (GHSA-9g4v-h9hm-846r). Both the X.509 and SAML
  paths settle certificate trust and `SignatureValue`-over-`SignedInfo`
  verification *before* the first `<Reference>` is resolved, canonicalized, or
  digested, so an untrusted or forged signature costs constant work. Duplicate
  Reference URIs are rejected, the X.509 Reference ceiling drops from 64 to 8,
  SAML accepts exactly one Reference, one bounded id index is built per message
  in place of a full-envelope scan per Reference, the raw-attribute uniqueness
  guard is a single pass for the whole `SignedInfo`, and every canonicalization
  is charged against an aggregate per-message byte budget derived from the body
  length. Previously 64 References to one large element could force well over a
  gigabyte of scanning and canonicalization per unauthenticated request.
- `soap_ws_security` now establishes SOAP identity before authorization
  (GHSA-gfrx-43w6-jq3c). A configuration that establishes a principal
  (`username_token`, `x509_signature`, or `saml`) is an authentication plugin:
  it buffers the body before the authenticate phase, validates there, and
  publishes `authenticated_identity` plus a namespace-correct
  `identified_consumer`, so `access_control`, consumer-scoped `rate_limiting`,
  logging, retries, and chargeback all observe one authoritative SOAP identity
  instead of running before it exists. A timestamp-only policy establishes no
  principal, stays out of the authentication chain, and keeps validating in
  `before_proxy`; the two phases are mutually exclusive by configuration, so no
  message is validated twice. **Breaking:** an identity-establishing instance
  must be the proxy's sole authentication mechanism in either auth mode, and
  composing one with `compression`'s `decompress_request` is rejected at config
  admission; for that identity-establishing form an `on_final_request_body`
  guard additionally refuses to dispatch a message whose bytes changed after
  validation. A timestamp-only instance authenticates nobody and claims no
  integrity over the Body, so it does not bind the representation and stays
  composable with request-body transformers. Also **breaking:** because an
  identity-establishing instance is the proxy's sole authentication mechanism,
  a request the SOAP policy passes through — a non-SOAP media type under
  `content_type.mode: mixed_route`, or a governed envelope with no
  `wsse:Security` header under `reject_missing_security_header: false` —
  reaches the authentication chain with no identity and is answered `401`
  rather than forwarded anonymously; pair those options with a timestamp-only
  instance, or separate anonymous and SOAP-authenticated traffic onto different
  proxies.
- `soap_ws_security` X.509 signatures must now protect the backend-visible SOAP
  Body (GHSA-3mwq-c8j6-9xhp). `Envelope`/`Header`/`Body`/`Security` selection is
  namespace-qualified and positional rather than by local name, duplicate
  namespace-correct envelope elements and misplaced `wsse:Security` headers are
  rejected, and a successful X.509 verification now requires a Reference that
  resolves uniquely to the actual Body. `require_signed_timestamp` rejects a
  message with no Timestamp instead of passing vacuously, and pairing it with
  `timestamp.require: false` is refused at admission. Previously a trusted
  signature over only the Timestamp authorized an arbitrary rewritten operation,
  and a signed lookalike `<Body>` under another namespace could be selected in
  place of the real one. **Breaking:** because Ferrum implements no WS-Security
  attachment-signature transform, an X.509 signature cannot cover the octets an
  `xop:Include` stands for; an enabled `x509_signature` therefore now refuses
  both MTOM/XOP `multipart/related` and bare `application/xop+xml` with `415`
  before dispatch, and an explicit `content_type.allow_mtom: true` alongside it
  is refused at config admission. `username_token` and `saml` keep accepting
  MTOM/XOP — they authenticate who sent the message and never claimed integrity
  over attachment octets. Separately, `reject_missing_security_header: false`
  now governs an *absent header only*: on a governed representation, malformed
  XML, unsupported or ambiguous envelope structure, and XML parsing-budget
  failures reject with `400` regardless of that setting, so a gateway/backend
  parser disagreement can no longer become a pass-through that skips
  authentication, integrity, freshness, and replay for a message the backend
  still executes.
- `soap_ws_security` SAML assertions are now bound and single-use
  (GHSA-f44p-hfqr-cvcc). **Breaking:** `saml.audience`, the new
  `saml.recipient`, and `nonce.replay_scope` are required when SAML is enabled.
  An accepted assertion must carry a mandatory `Conditions` window with both
  `NotBefore` and `NotOnOrAfter` inside the new
  `saml.max_assertion_lifetime_seconds` cap (default 300), must be admitted by
  every `AudienceRestriction`, must carry one supported `SubjectConfirmation`
  (bearer only; `holder-of-key` is refused at admission) whose
  `SubjectConfirmationData` names `saml.recipient`, carries its own bounded
  `NotOnOrAfter`, and omits `InResponseTo`, and its assertion id is claimed for
  single use in the declared replay scope for the same fixed 93 601-second
  horizon as PasswordDigest nonces. `OneTimeUse` needs no special case because
  every accepted assertion is claimed exactly once. `process` scope is a
  single-replica declaration and makes no cross-replica claim; multi-replica
  SAML deployments must use `shared`. Previously a captured signed assertion
  could be replayed indefinitely beside a freshly minted outer Timestamp, and in
  the default configuration an assertion issued for another service by the same
  trusted IdP was accepted. An accepted assertion must also resolve exactly one
  namespace-correct, nonblank Subject `NameID` — the documented SAML principal —
  and that resolution now happens *before* the single-use claim, so an assertion
  that satisfies every binding but authenticates nobody fails closed with `401`
  without consuming replay state. Previously such an assertion was accepted,
  burned its replay id, and returned no principal, silently degrading the
  request to unauthenticated while letting an attacker spend a legitimate
  assertion id.

- `mcp_gateway` aggregate-router mode now validates `tools/call` results against
  discovered tool `outputSchema` values when
  `validation.validate_tool_results` is enabled
  (#3296). Schemas are audited and compiled at catalog construction (local
  references only; depth/node budgets), invalid schemas are refused at admission
  with field-specific diagnostics, and bounded caller-visible results are checked
  before release or audit publication. `structuredContent` and JSON text
  `content` variants are covered without validating a different representation
  than the caller receives; tool `isError` results and well-formed, error-only
  upstream JSON-RPC errors are preserved; event-stream / non-JSON / oversized
  results fail closed with JSON-RPC `-32012`. Transparent mode rejects the
  option because it has no mediated tool catalog. Result bodies are never
  logged.
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
- ACME issuance and renewal now route every connection through a
  Ferrum-controlled, public-only fresh-DNS connector; reject mixed/private DNS
  answers, answers above 64 addresses, ambiguous legacy numeric IPv4 host
  spellings, endpoint origin drift, credential-directory mismatch, legacy
  credential URL sets, hostile order resource URLs, redirects, and response
  bodies above 1 MiB while preserving HTTPS hostname/certificate verification.
  Fresh DNS plus all TCP candidates share one 30-second wall-clock budget.
  **Breaking:** ACME servers that advertise endpoints on another host or port,
  and pre-0.4 `instant-acme` credentials with embedded `urls`, must be migrated
  to the configured directory origin (#2407).
- `body_validator` now enforces the validation it advertises on all four of its
  surfaces. Configured JSON Schemas are compiled once at plugin construction with
  the `jsonschema` crate under an explicit draft (`json_schema_draft`, default
  `draft2020-12`) instead of being interpreted by a partial handwritten
  evaluator, so `$ref`/`$defs`, union types, conditionals, and other standard
  keywords take effect and malformed schemas, invalid type names, non-local
  references, `$vocabulary` declarations, and over-budget schemas fail
  configuration closed; local JSON Pointer targets are policy-audited even under
  normally literal containers, and no external reference is ever retrieved. XML
  bodies are parsed exactly, without Unicode whitespace trimming, with
  `roxmltree` rather than scanned for balanced tags, so multiple roots, text
  outside the root, invalid names or characters, malformed/unquoted/duplicate
  attributes, and undeclared entity references are rejected. External
  `SYSTEM`/`PUBLIC` identifiers on either the DOCTYPE or an entity declaration
  are refused outright, and `required_xml_elements` matches parsed
  namespace-expanded names. Decoded gRPC protobuf messages must satisfy
  proto2 `required`-field initialization recursively, including inside present
  nested, repeated, map, and extension message values. Unknown top-level config
  keys and unknown keys inside a `protobuf_method_messages` entry are rejected
  before defaults, so a typo can no longer silently replace enforcement with a
  weaker policy. This is a breaking configuration change; see the
  [Safe Upgrade Guide](docs/upgrade_guide.md#body-validator-enforcement-hardening).
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
  `Dynamic` — instead of falling back to the bare in-flight lease. Local
  response-byte admission failure and later protected-completion eviction now
  use an explicit fixed-size execution barrier carrying the completion's own
  authoritative retention clock; neither path can silently restart a shorter
  `inflight_ttl_seconds` lease. Stale owner hooks cannot clear the barrier or a
  successor because every transition remains fingerprint/token fenced. Per-key
  execution barriers are hard-capped at `max_entries`; overflow extends one
  fixed process-global deadline that returns 503 for applicable idempotency-key
  requests, preserving fail-closed retention without unbounded key storage.
  Serverless responses with stable, complete policy provenance are still stored
  as ordinary replays. The provenance contract is documented in
  `docs/plugin_execution_order.md`.
- Versioned standard and `-ebpf` multi-architecture images are now keylessly
  signed in Docker Hub and GHCR and carry final-manifest SLSA provenance plus
  per-platform SPDX SBOM attestations. A fail-closed publication gate requires
  identity, signature, subject-digest, source-commit, provenance, and SBOM
  verification and retracts a GitHub Release if attestation does not succeed
  (compatible with the trusted Cross `create-release.needs` contract).
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

### Added

- `fault_injection` now supports UDP and DTLS. Session admission aborts run in
  isolated per-source / per-DTLS-client `on_stream_connect` tasks; per-datagram
  delays and silent abort drops run on `on_udp_datagram` (client→backend) inside
  the established-session hook-ingress worker — never the shared listener recv
  loop — so one peer's delay cannot stall another. UDP/DTLS stream connect skips
  delay so the first-datagram path cannot stack two waits. Delays share the
  existing one-minute ceiling, `FERRUM_MAX_CONCURRENT_FAULT_DELAYS` budget, and
  shutdown cancellation; queued follow-ups remain under the hook-ingress
  byte/datagram caps (#3293).

### Changed

- Kubernetes controller Gateway API and Istio status patch batches now have a
  60-second wall-clock ceiling. A stalled Kubernetes API request can no longer
  retain the reconcile loop indefinitely; unfinished status updates are
  cancelled and retried by a later watch event or periodic full sync.

- Kubernetes controller Gateway API and Istio status writers now share one
  immutable `Arc<[K8sObject]>` generation per reconcile instead of each
  deep-cloning the full unstructured object snapshot. Status semantics,
  bounded update plans, route-conflict handling, and per-writer failure
  isolation are unchanged; deployments with neither writer still pay no
  snapshot clone cost (#3281).

- Gateway API `GRPCRoute` predicates are now translated instead of dropped.
  A pathless `matches[]` entry (method-only, header-only, or a rule with no
  `matches` at all) previously disappeared during translation, so valid gRPC
  rules never routed and their traffic fell through or 404'd. gRPC predicates
  are now represented independently of HTTP paths: an `Exact` `method` with
  both `service` and `method` becomes an exact `=/{service}/{method}` listen
  path, a service-only match becomes a `/{service}/` prefix, and every
  remaining shape materializes on the `/` listener behind a
  `mesh_route_dispatch` URI regex. Every emitted GRPCRoute match — exact-path
  matches included — additionally carries a case-insensitive gRPC
  `content-type` predicate, so a GRPCRoute only ever selects gRPC calls and
  can never capture ordinary HTTP traffic sharing the same hostname and path.
  That gate is the regex transcription of Ferrum's canonical native-gRPC
  content-type contract (`proxy::backend_dispatch::is_native_grpc_content_type`),
  so `application/grpc-web`, `application/grpc-web-text`, and lookalikes such as
  `application/grpcfoo` are refused exactly as the proxy's own dispatcher
  refuses them — gRPC-Web is served by configuring the trusted `grpc_web`
  plugin, which rewrites a verified request to native `application/grpc` before
  backend dispatch. A route-authored `content-type` match still replaces the
  gate, but it is validated against the same native contract first, so an
  operator header can only narrow the protocol boundary. GRPCRoutes share
  HTTPRoute's same-`(hostname, listen path)` collapse, so rule/match ordering
  and fall-through are preserved. Gateway API v1.5.1
  forbids merging rules between GRPCRoutes and HTTPRoutes: an HTTPRoute and a
  GRPCRoute attached to the same resolved listener with any intersecting
  hostname now resolve to exactly one accepted Route on that listener and
  hostname — oldest `metadata.creationTimestamp`,
  then `{namespace}/{name}`, then `kind` (the last only breaks a total tie: the
  two kinds may share a name and `creationTimestamp` has second granularity),
  independent of rule paths and of the order objects are observed in — and the losing Route materializes no proxy, upstream,
  plugin, or materialized-parent record and is reported `Accepted=False` with
  `reason: Conflicted`. "The same listener" is the *resolved* Gateway listener,
  not the literal `parentRefs[]` selector: a wildcard reference and a reference
  pinning that listener by `sectionName` or `port` contend with each other,
  while two wildcard references that `allowedRoutes.kinds` sends to different
  listeners do not. A wildcard reference spanning several listeners emits one
  shared conflict claim, and Ferrum's HTTP-family route representation is
  port-agnostic, so a claim kept for the listener it won would still route on
  the listener it lost: such a claim is conservatively withdrawn whole as soon
  as it loses on **any** listener it reaches. Route status always echoes the
  parentRef the operator wrote. Two Routes of different kinds that Gateway API
  requires be accepted *together* — because `allowedRoutes.kinds`, a
  `sectionName`/`port` pin, or separate Gateways send them to different
  listeners — still share Ferrum's single port-agnostic `(hosts, listen path)`
  slot and collapse into one ordered dispatch-rule list. Their predicates stay
  intact and disjoint there (the gRPC rules are content-type gated), and the
  alternative would emit two proxies with an identical `(hosts, listen path)`,
  which `validate_unique_listen_paths` rejects — aborting the entire config
  reload for the common "HTTP listener plus gRPC listener on one Gateway"
  topology, where a pathless GRPCRoute and an HTTPRoute `PathPrefix: /` rule
  both land on `/`. gRPC shapes Ferrum cannot represent exactly
  — `method.type: RegularExpression` (Ferrum cannot constrain a regex operand
  to a single gRPC path segment, so the predicate is refused rather than
  compiled into a matcher that could widen across service/method boundaries)
  or any other non-`Exact` `method.type`, a `method` block with neither
  `service` nor `method`, an `Exact` operand that is empty, over 1024 bytes
  (the CRD `MaxLength=1024`), present but not a string, or outside the v1.5.1
  CRD grammars, a non-native-gRPC `content-type` predicate, a non-`Exact`
  header match, a match entry carrying both `method` and Ferrum's hand-authored
  `path` extension (Ferrum cannot represent their conjunction, so honoring
  either half alone would widen the match), or an explicit
  `method: null` / `headers: null` (an explicit null is malformed input, not an
  omission, and must not widen into the any-gRPC-call or headerless match —
  omitting either field keeps its documented meaning) — are dropped fail
  closed with a field-specific translator warning that never echoes the
  operand.
  See
  [GRPCRoute predicate translation](docs/gateway_api_conformance.md#grpcroute-predicate-translation).

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
