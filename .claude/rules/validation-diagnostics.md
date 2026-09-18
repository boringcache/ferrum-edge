---
paths:
  - "src/**"
  - "tests/**"
---

# Validation Diagnostics

- Two layers: serde families are sanitized structurally at the document boundary;
  `startup::render_startup_error` sanitizes EVERY rendered cause independently
  with `sanitize_startup_cause`, then joins with `: `. For each ORIGINAL cause,
  redact configured database URLs and registered external secrets FIRST, then
  withhold quoted spans with `sanitize_custom_message`. A quote inside a URL or
  secret must not truncate the value before the credential scrubbers match it.
  If credential scrubbing changes quote/escape syntax, withhold that cause in
  full as `<redacted diagnostic>`: a secret can itself be a delimiter.
  Both `run` and `validate` use it. Never sanitize only the joined chain: an
  unterminated quote in one cause must not swallow the next cause's field/index
  or reason.
- Validation diagnostics: schema names in backticks; document values omitted or
  strings in double quotes with Debug escaping (`{value:?}`). This convention
  makes semantic validators safe by construction at rendering. BARE document
  value interpolation is a defect and is forbidden. Single-quoted interpolation
  without escaping is also unsafe when a value contains an apostrophe. Numeric
  values need explicit double quotes or omission (Debug does not quote numbers).
  For a JSON Value/type rejection, Debug-escape its Display string (for example
  `value = value.to_string()` with `{value:?}`), so numbers and whole containers
  are withheld as well as strings.
  The custom pass withholds double/single-quoted spans and keeps backticks;
  unterminated spans are withheld through the end of their own cause.
- Classify serde families only on the bare inner error, with an exact prefix at
  position zero. Keep `serde_path_to_error` path metadata separate until composition.
  Paths and unknown-field messages can echo document KEYS; never treat them as
  trusted error text or put credentials in keys.
- Native YAML and parser-level errors are custom text unless a value-tree
  deserialization supplies a separate bare inner error. Never scan a rendered
  path or context chain for a family. Do not retain raw errors below safe wrappers.
  Exception: the exact leading `duplicate entry with key "` family from the
  bare YAML Value parser preserves its document key as `duplicate field` metadata.
- Warnings/errors bypassing the final renderer must emit through
  `startup::sanitize_startup_cause` (with known URLs where available) or omit
  values. Quoting alone does NOT sanitize a tracing event. This includes backup,
  SQL/Mongo quarantine/rejection, validation-pipeline and unknown-plugin logs.
  Migration/backup version diagnostics omit values even before rendering.
  Regex-library errors can reproduce patterns bare: replace them with the
  field/index and a fixed rejection reason.
- Known converted sites: mesh config validators (services/cluster IPs, workload
  identities, hosts, policy/targetRefs names, CIDRs, ext-authz and JWT headers,
  trust bundles, remote clusters/gateways); CORS origin/method/header checks;
  gateway file loader, config migrator and backup loader; gateway host/reference
  validators; plugin provider/schema/tag-name and numeric-bound diagnostics;
  regex admission in plugin triggers, route dispatch, response mock, OpenAPI,
  AI prompt/response/tool/PII filters, bot detection and WAF; OpenAPI/AI tool
  JSON Schema compilation and plugin JSON type-rejection diagnostics; gateway
  mTLS compatibility and field-validation resource prefixes, consumer identity
  collisions, locality/subset names, methods/IPs, numeric field bounds, TLS/MaxMind sources,
  and plugin-construction identities; SQL/Mongo restore, reference, namespace,
  row-decode and admission diagnostics; conf/env/pool parsers and namespace/file
  load messages; CP namespace rejection, mesh startup paths, xDS carriers,
  federation/remote clusters, probe/injector names, node-agent addresses/paths,
  and revision identities; capture boolean/port/mark/UID/CIDR parsing and
  annotation overrides; shared unknown-key suggestions, rate-window/request/frame
  bounds, socket-host/egress errors, and notification channel/SMTP/template
  admission. Notification unknown-key failures retain the fixed `channels`
  schema context separately from supplied channel names and keys. Shared helper
  context that may contain document keys is Debug-escaped as a whole; callers
  must supply a separate fixed schema field when one is available. WAF
  rule/signature ordinals and API-spec extension request/response/bypass paths
  preserve this separate fixed context; supplied override IDs and extension
  keys never enter the visible prefix. SQL literals, fixed migration/listener/fault labels,
  and schema-only constants are not document-value interpolation. Preserve these
  conventions when adding sibling validators; keep field/index and reason.
- The #5594 logging/observability conversion covers HTTP/TCP/UDP/WebSocket,
  Kafka, file/stdout/syslog/StatsD logging, OpenTelemetry, Prometheus, transaction
  log schemas/exporters and proxy alerts. Alert rules, recovery settings and
  quiet-hour entries preserve fixed ordinals independently of supplied names;
  log-schema paths and socket diagnostics retain fixed fields and reasons.
  Registered rendered-output and captured-log tests cover constructor and
  configuration-admission messages. Runtime transport logs outside this
  configuration scope are not certified by the mechanical producer guard.
- The #5594 AI conversion covers prompt/response/PII filters, provider routing,
  semantic caching, token limits, tool governance and transcript audit admission.
  Provider/custom-pattern ordinals and fixed tool-pattern paths survive rendering;
  supplied tool/provider/method names, patterns, schema payloads and numeric values
  are withheld. JSON Schema and regex admission retain fixed classifications.
  Registered constructor/rendered-output regressions cover these configuration
  paths independently of the scoped mechanical producer guard.
- The constructor audit includes root/nested JSON object guards, file-mode
  plaintext Basic-auth consumer IDs, WAF stream/rule IDs and exemption/filter
  regex sets, gRPC-Web header elements, plugin numeric bounds and URL schemes,
  and Kubernetes port/weight/concurrency/sampling diagnostics. JSON Display
  strings must be Debug-escaped even when a sibling guard already does so.

- Scope of #5591: `src/config`, `src/modes`, `src/cli.rs`, `src/startup.rs`,
  `src/gateway_entry.rs`, `src/config_sources`, `src/grpc`, `src/capture`, and
  `src/plugins/waf`.
  Other plugin families remain under #5594. Withholding is conditional on safe
  producer interpolation: apostrophe-leading single-quoted values, bare values,
  and retained third-party parser text can still expose supplied data. Do not
  describe the renderer alone as fail-closed for arbitrary diagnostic text.
- The mechanical producer/emitter contract is
  `tests/unit/cli/diagnostic_source_guard_tests.rs` (registered in `cli/mod.rs`).
  Its explicit `ROOTS` list covers the above roots except `src/capture`, whose
  generated shell commands also use quoted interpolation. Capture parsing has
  rendered-output and captured-log regressions. The guard scans every Rust file
  in its roots, plus the converted shared unknown-key, rate-limit, and socket-host
  helpers and notifications, including multiline/nested macros
  and raw strings, for single-quoted interpolation in diagnostic macros and for
  named error/message captures in `warn!`/`error!` without a sanitizer call in
  that statement. Its exact, commented exception list contains SQL query syntax,
  not document-value diagnostics. Keep schema names in backticks. The guard
  prevents those syntax regressions in scope; it cannot infer whether arbitrary
  bare arguments are document values or prove third-party errors safe. Retain
  rendered-output/captured-log regressions for semantic and emission coverage.
