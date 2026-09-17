---
paths:
  - "src/**"
  - "tests/**"
---

# Validation Diagnostics

- Two layers: serde families are sanitized structurally at the document boundary;
  `startup::render_startup_error` sanitizes EVERY rendered cause independently
  with `sanitize_custom_message`, then joins with `: `. Both `run` and `validate`
  use it. Never sanitize only the joined chain: an unterminated quote in one
  cause must not swallow the next cause's field/index or reason.
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
- Warnings bypassing the final renderer must withhold at emission (as the
  validation pipeline does) or omit values. Migration/backup version diagnostics
  omit values even before rendering. Regex-library errors can reproduce patterns
  bare: replace them with the field/index and a fixed rejection reason.
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
  and revision identities. SQL literals, fixed migration/listener/fault labels,
  and schema-only constants are not document-value interpolation. Preserve these
  conventions when adding sibling validators; keep field/index and reason.
