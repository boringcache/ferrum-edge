# Production Readiness Ledger — Ferrum Edge

Product-readiness epic executed 2026-07-12 (orchestrated multi-agent audit + remediation).
Method: four independent read-only audits (deferral markers, docs-vs-code truth, security
posture, ops/CI/release) → findings triaged → fixes implemented via reviewed PRs (codex
review loop + full CI + orchestrator review on every PR) → merged.

## Launch gate summary

| Gate | Status |
|------|--------|
| Feature set implemented or proven out of scope | PASS — zero doc overclaims across README/FEATURES/62 docs; all genuine deferrals documented with graceful behavior and tracked in #2110 |
| All deferral markers resolved or tracked | PASS — ~259 raw markers triaged: 1 medium fixed (PR #2113), 6 lows fixed (#2114) or tracked (#2110); rest benign |
| Critical/high/medium bugs fixed | PASS — 0 critical/high found in any audit; all 5 mediums fixed and merged |
| Docs truthful vs code | PASS — stale REFACTORING_PLAN.md retired, WEBSOCKET.md/admin_api.md corrected (PR #2112); config/openapi/plugin-priority parity verified clean |
| Security posture verified | PASS — 0 crit/high/med; both lows hardened (PR #2114); CRL revocation now symmetric inbound/outbound (PR #2113) |
| Deployment/CI/release readiness | PASS — tag↔version guard + CHANGELOG policy (PR #2109); flake redness remediated pre-epic (#2057/#2060 fixes + #2103), main monitored green through the epic |

## Merged work (all codex-clean + CI-green + orchestrator-reviewed)

| PR | Closes | Delivered |
|----|--------|-----------|
| #2105 | #2104 | Live two-cluster gate: blanket NEW-TCP REJECT firewall-proves Ambient east-west traversal; self-check asserts dest gateway inbound ports unreachable |
| #2109 | #2107 | release.yml tag↔Cargo-version guard gating all publish jobs; CHANGELOG.md + policy; docs/ci_cd.md |
| #2112 | #2111 | REFACTORING_PLAN.md retired (live remainder → #2110); WEBSOCKET.md tunnel-mode section (verified vs code); admin_api.md LB list |
| #2113 | #2106 | Mesh outbound SPIFFE CRL revocation parity (HBONE + mesh-mTLS pools), consuming the live-reload SharedCrlList slot with reload-race pooling guards; honest revocation docs (unknown-status allowance documented); revoked/unrevoked dial tests |
| #2114 | #2108 | CSR proof-of-possession verification (transport-agnostic, x509-parser verify); FERRUM_ADMIN_JWT_AUDIENCE (strict RFC 7519 default kept + pinned by test); stale UDP deferral message fixed; release image log level error→warn |

## Findings ledger (final)

| ID | Finding | Severity | Disposition |
|----|---------|----------|-------------|
| PR-001 | Ambient live-gate row not firewall-proven | Medium (test integrity) | FIXED (PR #2105) |
| PR-002 | Outbound mesh SPIFFE verification skipped CRLs (inbound-only asymmetry) | Medium (security) | FIXED (PR #2113, 3 codex rounds incl. live-reload slot + race guards) |
| PR-003 | InternalCa CSR path lacked proof-of-possession | Low (hardening) | FIXED (PR #2114 — real PoP verification) |
| PR-004 | SPIFFE Workload API JWT-SVID unimplemented (X.509 complete) | Low | TRACKED (#2110) |
| PR-005 | k8s controller Merge-Patch status writes (SSA TODO); naming-convention proxy-id | Low | TRACKED (#2110) |
| PR-006 | Stale "F3 §3.3 UDP not implemented" message | Low (accuracy) | FIXED (PR #2114) |
| PR-007 | Log schema not applied to WsDisconnectLogEntry | Low | TRACKED (#2110) |
| PR-008 | Main redness from flakes #2057/#2060 + port races | Medium (ops) | RESOLVED pre-epic (fixes + #2103); main monitored green through epic |
| PR-009 | No release tag↔version guard | Medium (ops) | FIXED (PR #2109) |
| PR-010 | No CHANGELOG/policy | Medium (ops) | FIXED (PR #2109) |
| PR-011 | Admin JWT lacked optional aud validation | Low (hardening) | FIXED (PR #2114; strict default deliberately kept — see below) |
| PR-012 | Release image log level hid startup warns | Low | FIXED (PR #2114) |
| PR-013 | No Helm chart for core gateway modes | Low | TRACKED (#2110) |
| PR-014 | Stress tests excluded from CI | Low | TRACKED (#2110) |
| PR-015 | Stale REFACTORING_PLAN.md; WEBSOCKET.md/admin_api.md gaps | Medium (stale root doc) | FIXED (PR #2112) |
| PR-016 | 11 documented feature deferrals (accurately labeled) | Low | TRACKED (#2110; mesh retry re-screen pre-tracked #2008) |

## Audit verifications (no action needed — recorded to prevent relitigating)

- Security: admin API single JWT gate with tiered observability exactly per rules; JWT
  validate_exp/nbf + fixed algorithm; constant-time credential comparisons; mesh authz
  DENY-first fail-closed; no secret logging; smuggling guards per RFC 9112; anchored
  resource-id validation; recursive credential rejection in spec extractor; deny.toml
  ignores all rationaled with future expiry; SSRF/DNS-rebinding posture (PR #1933) intact.
- Docs: configuration.md ↔ env_config.rs zero dead vars; openapi.yaml 1:1 with admin
  dispatch; all 82 plugins in openapi; priorities match plugin_execution_order.md.
- Ops: CI aggregate gate has no always()-escape; #[ignore] functional tests DO run
  (nextest --run-ignored=all); shard-coverage gates active; injector/node_agent/migrate
  modes all have functional tests; licenses consistent; Docker ports match docs.

## Deliberate decisions (do not "fix" without revisiting rationale)

- **Admin JWT `aud` unset ⇒ strict**: tokens carrying `aud` are rejected when
  FERRUM_ADMIN_JWT_AUDIENCE is unset (RFC 7519 §4.1.3, jsonwebtoken default, pre-existing
  behavior). Loosening would enable cross-service token replay under HS256 secret reuse.
  Pinned by `test_audience_unset_rejects_aud_bearing_token`.
- **Mesh CRL unknown-revocation allowance**: peers whose revocation status is
  undeterminable (no CRL from their issuing CA) are accepted, matching the shared inbound
  model; removing it would break federated meshes lacking per-CA CRLs. Documented in
  docs/mesh.md.
- Pre-existing intentional trade-offs re-confirmed: WAF body gates, JWKS retain guard,
  dedup try_lock eviction, MCP stale-template serving, H3 streaming-trailer limitation,
  kTLS KeyUpdate userspace fallback, mcp_gateway V1 tool-result rejection.

## Needs human decision

None blocking launch. Post-launch discretionary items live in #2110 (JWT-SVID Workload
API, SSA status writes, core-gateway Helm chart, scheduled stress job, admin CRUD
refactor idea inherited from the retired REFACTORING_PLAN.md).
