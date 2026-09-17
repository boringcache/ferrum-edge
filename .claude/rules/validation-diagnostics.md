---
paths:
  - "src/**"
  - "tests/**"
---

# Validation Diagnostics

- Validation diagnostics: names in backticks, document values in double quotes
  with Debug escaping (`{value:?}`); the boundary sanitizer withholds double/single-quoted
  spans and keeps backticked ones. Unterminated spans are withheld through the end.
- Classify serde families only on the bare inner error, with an exact prefix at
  position zero. Keep `serde_path_to_error` path metadata separate until composition.
  Paths and unknown-field messages can echo document KEYS; never treat them as
  trusted error text or put credentials in keys.
- Native YAML and parser-level errors are custom text unless a value-tree
  deserialization supplies a separate bare inner error. Never scan a rendered
  path or context chain for a family. Do not retain raw errors below safe wrappers.
- Non-serde validators must withhold supplied scalar values at their own boundary;
  retain the field name, supported choices, and rejection reason.
