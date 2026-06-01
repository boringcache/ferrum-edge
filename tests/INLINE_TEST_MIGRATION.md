# Inline Test Migration Log

This log tracks source files investigated while moving inline tests from `src/`
into the external `tests/` tree. Keep entries grouped by logical migration PRs
so later passes do not duplicate work.

## PR 1: plugin utility core helpers

Moved inline tests into `tests/unit/plugins/plugin_utils_core_tests.rs`.

- `src/plugins/utils/cert_hash.rs`: moved 2 tests.
- `src/plugins/utils/claim_resolver.rs`: moved 3 tests.
- `src/plugins/utils/json_escape.rs`: moved 6 tests.
- `src/plugins/utils/jwt_verifier.rs`: moved 2 tests.
- `src/plugins/utils/query.rs`: moved 7 tests.
- `src/plugins/utils/scope_role_check.rs`: moved 2 tests.
- `src/plugins/utils/token_extract.rs`: moved 2 tests.

## Investigated backlog

Initial scan found many additional inline tests under `src/`, especially in
admin, config/runtime infrastructure, mesh/xDS, HTTP/3, Kubernetes controller,
and plugin utility modules. Migrate follow-up slices by subsystem and append the
exact files moved here.
