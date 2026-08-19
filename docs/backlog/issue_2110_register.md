# Issue #2110 — historical deferral register

**Captured:** 2026-07-12 production-readiness epic (umbrella register).

**Role:** Historical snapshot only — frozen 2026-07-12 checkbox register, not
the live product backlog and not a live tracker. Do not refresh this file to
chase GitHub issue state.

**Remaining open residuals:** [`PRODUCTION_READINESS.md`](../../PRODUCTION_READINESS.md)
(Current residual map). That ledger is also human-maintained; there is no
launch-readiness gate.

GitHub issue [#2110](https://github.com/ferrum-edge/ferrum-edge/issues/2110)
is CLOSED (COMPLETED, 2026-07-28). Keep this file so screening agents or docs
do not re-open completed rows from the issue body alone.

Protected automation note: `tests/performance/mesh/README.md` is a frozen
Trusted Cross surface (every path under `tests/performance/` is protected,
including Markdown). Its historical "Benches deferred (not yet implemented)"
prose is **not** the current backlog source of truth and must stay unchanged.
Current mesh HBONE/DNS perf status lives in
[`docs/protocol_perf_regression.md`](../protocol_perf_regression.md)
(`mesh-hbone-e2e` / `mesh-dns-e2e` suites; residual [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332)).

## Completed or superseded (do not reopen from #2110 alone)

| #2110 row | Resolution |
|---|---|
| Mesh HTTP retry-loop transport re-screen gap | Closed [#2008](https://github.com/ferrum-edge/ferrum-edge/issues/2008) |
| k8s controller status writer (Merge Patch → SSA) | [#2152](https://github.com/ferrum-edge/ferrum-edge/pull/2152) — intentional mixed strategy: resourceVersion-guarded RMW for Gateway API `Route.status.parents[]`, SSA + stable `fieldManager` for Gateway/GatewayClass conditions |
| k8s controller proxy-id naming convention | [#2152](https://github.com/ferrum-edge/ferrum-edge/pull/2152) — typed proxy-id mapping |
| Helm chart for core gateway modes | Shipped — [`charts/ferrum-gateway`](../../charts/ferrum-gateway/README.md), [`docs/kubernetes_deployment.md`](../kubernetes_deployment.md) |
| Scheduled stress tests excluded from PR CI | [`.github/workflows/scaling-regression.yml`](../../.github/workflows/scaling-regression.yml) |
| `WsDisconnectLogEntry` log schema | Implemented — [`docs/log_schema.md`](../log_schema.md) WebSocket disconnect family |
| Mesh TLS-SNI L4 routing | Supported — VirtualService `tls[]` SNI passthrough (`sniHosts`); see [`docs/mesh_supported_matrix.md`](../mesh_supported_matrix.md) and `tests/integration/mesh_l7_routing_tests.rs` |
| Remote-discovery JWT audience binding | Implemented — closed [#2475](https://github.com/ferrum-edge/ferrum-edge/issues/2475) |
| `ai_stream_router` `google_gemini` adapter | Implemented — [#3299](https://github.com/ferrum-edge/ferrum-edge/issues/3299) |
| Subset-scoped Istio HTTP connection-pool policy | Implemented by [#3547](https://github.com/ferrum-edge/ferrum-edge/pull/3547), resolving [#3228](https://github.com/ferrum-edge/ferrum-edge/issues/3228) / [#3240](https://github.com/ferrum-edge/ferrum-edge/issues/3240)–[#3242](https://github.com/ferrum-edge/ferrum-edge/issues/3242) |
| AI semantic-firewall token windows | Implemented — [#3302](https://github.com/ferrum-edge/ferrum-edge/issues/3302) (`streaming.window: tokens` with explicit bounded tokenizer) |
| Native-gRPC transcript capture | Implemented — [#3304](https://github.com/ferrum-edge/ferrum-edge/issues/3304) (descriptor-based gRPC enrollment in `src/plugins/ai_transcript_audit.rs`) |
| Pre-first-byte stream-router fallback | Closed [#3328](https://github.com/ferrum-edge/ferrum-edge/issues/3328) — explicit admission rejection (issue #3328) |
| Native SMTP/email notification channel | Implemented — [#3329](https://github.com/ferrum-edge/ferrum-edge/issues/3329) (`src/notifications/channels/email.rs`) |
| MongoDB replica-set change-stream wakeups | Implemented — [#3330](https://github.com/ferrum-edge/ferrum-edge/issues/3330) (`src/config/config_change_watch.rs` + `mongo_store.rs`) |
| Multicluster poller partition / last-good live gate | Implemented — [#3331](https://github.com/ferrum-edge/ferrum-edge/issues/3331) (`.github/workflows/multicluster-poller-partition-live.yml`) |
| SPIFFE Workload API JWT-SVID mint/validate/bundles | Implemented by [#3675](https://github.com/ferrum-edge/ferrum-edge/pull/3675), resolving [#3617](https://github.com/ferrum-edge/ferrum-edge/issues/3617); empty bundle success removed and the SPIRE serving boundary documented |
| EgressGateway UDP `ServiceEntry` materialization | Implemented — [#3263](https://github.com/ferrum-edge/ferrum-edge/issues/3263) (external UDP ports materialize a datagram-over-mesh destination allowlist consumed by the gateway's authenticated mesh CONNECT terminator, plus the source-side `Sidecar`/`Ambient` producer that originates the identity-pinned `udp` CONNECT; no UDP/DTLS listener, by design) |
| Ambient UDP enrolled-destination round trip | Implemented — [#3621](https://github.com/ferrum-edge/ferrum-edge/issues/3621) (`functional_mesh_live_source_capture_udp_manager_hbone_round_trip` covers source-capture → HBONE → enrolled destination pod-netns relay; `node-waypoint-ebpf-live` independently proves the relay mark admits the backend datagram through the enrolled-pod `tc_inbound` guard while unmarked traffic stays closed) |
| Live OIDC / OAuth2 introspection coverage | Implemented — [#3333](https://github.com/ferrum-edge/ferrum-edge/issues/3333) closed COMPLETED 2026-08-04 by [#3552](https://github.com/ferrum-edge/ferrum-edge/pull/3552) |
| NodeWaypoint observability + promotion gates | Implemented — [#3334](https://github.com/ferrum-edge/ferrum-edge/issues/3334) closed COMPLETED 2026-07-29 by [#3388](https://github.com/ferrum-edge/ferrum-edge/pull/3388) (follow-up [#3427](https://github.com/ferrum-edge/ferrum-edge/pull/3427)) |
| Vendored-patch upstream filing / retirement | Implemented — [#3335](https://github.com/ferrum-edge/ferrum-edge/issues/3335) closed COMPLETED 2026-07-30 by [#3446](https://github.com/ferrum-edge/ferrum-edge/pull/3446) (`docs/vendored-patch-lifecycle.json` + weekly `dependency-audit`) |
| Mesh/SPIRE CA-health signal + startup contract | Implemented — [#3608](https://github.com/ferrum-edge/ferrum-edge/issues/3608) closed COMPLETED 2026-08-08 by [#3668](https://github.com/ferrum-edge/ferrum-edge/pull/3668) |
| CNI ferrum-cni chaining uninstall/rollback | Implemented — [#3609](https://github.com/ferrum-edge/ferrum-edge/issues/3609) closed COMPLETED 2026-08-11 by [#3792](https://github.com/ferrum-edge/ferrum-edge/pull/3792) (ownership-scoped install/uninstall/rollback, chart pre-delete cleanup, hosted Rust+Helm gates, live kind lifecycle suite) |
| Cross-region CP failover topology | Implemented — [#3610](https://github.com/ferrum-edge/ferrum-edge/issues/3610) closed COMPLETED 2026-08-08 by [#3640](https://github.com/ferrum-edge/ferrum-edge/pull/3640) |
| CP/K8s authoritative mesh config revision | Implemented — [#3611](https://github.com/ferrum-edge/ferrum-edge/issues/3611) closed COMPLETED 2026-08-09 by [#3680](https://github.com/ferrum-edge/ferrum-edge/pull/3680) |
| Gateway API port-aware route representation | Implemented — [#3612](https://github.com/ferrum-edge/ferrum-edge/issues/3612) closed COMPLETED 2026-08-09 by [#3677](https://github.com/ferrum-edge/ferrum-edge/pull/3677) (`GatewayApiListenerKey` identity, real per-listener socket binding + reload/withdrawal, per-listener cross-kind retention, `Conflicted` status for same-port incompatible-shape refusals) |
| OIDC RP pending login state (HA) | Implemented — [#3613](https://github.com/ferrum-edge/ferrum-edge/issues/3613) closed COMPLETED 2026-08-08 by [#3672](https://github.com/ferrum-edge/ferrum-edge/pull/3672) |
| `ai_stream_router` Anthropic multimodal content | Implemented — [#3616](https://github.com/ferrum-edge/ferrum-edge/issues/3616) closed COMPLETED 2026-08-08 by [#3641](https://github.com/ferrum-edge/ferrum-edge/pull/3641) |
| TCP outbound PROXY protocol v2 | Implemented — [#3618](https://github.com/ferrum-edge/ferrum-edge/issues/3618) closed COMPLETED 2026-08-08 by [#3647](https://github.com/ferrum-edge/ferrum-edge/pull/3647) |
| TCP/kTLS kernel splice (frontend-TLS relay) | Implemented — [#3619](https://github.com/ferrum-edge/ferrum-edge/issues/3619) closed COMPLETED 2026-08-09 by [#3670](https://github.com/ferrum-edge/ferrum-edge/pull/3670) |
| HTTP/3 plain-HTTP/WebSocket to mesh-tagged targets | Implemented — [#3620](https://github.com/ferrum-edge/ferrum-edge/issues/3620) closed COMPLETED 2026-08-14 by [#3798](https://github.com/ferrum-edge/ferrum-edge/pull/3798) |
| Direct-H2 in-path body-size limits | Implemented — [#3622](https://github.com/ferrum-edge/ferrum-edge/issues/3622) closed COMPLETED 2026-08-08 by [#3646](https://github.com/ferrum-edge/ferrum-edge/pull/3646) |
| Admin read-only write audit logging | Implemented — [#3623](https://github.com/ferrum-edge/ferrum-edge/issues/3623) closed COMPLETED 2026-08-08 by [#3643](https://github.com/ferrum-edge/ferrum-edge/pull/3643) |
| Env-only reads ignoring `ferrum.conf` | Implemented — [#3624](https://github.com/ferrum-edge/ferrum-edge/issues/3624) closed COMPLETED 2026-08-08 by [#3644](https://github.com/ferrum-edge/ferrum-edge/pull/3644) |
| Gateway SVID auto-refresh (external/inline) | Implemented — [#3625](https://github.com/ferrum-edge/ferrum-edge/issues/3625) closed COMPLETED 2026-08-09 by [#3669](https://github.com/ferrum-edge/ferrum-edge/pull/3669) |

## Dedicated-tracker table retired (frozen; not a live backlog)

The 2026-08-06 dedicated-tracker table that presented itself as a current
backlog is retired. Those rows are recorded as Implemented above. This file
is not a live tracker and is not reconciled against GitHub on an ongoing
basis.

As of the 2026-08-18 residual-map reconcile, leftover OPEN residuals live only
on [`PRODUCTION_READINESS.md`](../../PRODUCTION_READINESS.md): mesh/HBONE/DNS
baseline publication ([#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332);
harnesses exist, `baseline.md` tables still `_TBD_`) and the 2026-08-15 scheduled
scaling CI tracker ([#3892](https://github.com/ferrum-edge/ferrum-edge/issues/3892);
PR #3895 in flight).

## Documented deferrals without a dedicated issue (in-place docs)

| Topic | Status | Anchor |
|---|---|---|
| DR `connectionPool.http.maxRequestsPerConnection` | Parsed/validated, not enforced; listed in K8s `deferred_fields` | [`docs/mesh.md`](../mesh.md), [`docs/mesh_supported_matrix.md`](../mesh_supported_matrix.md) |
| Mesh CP per-DP slice-version drift endpoint | Done (#3265) | [`docs/mesh.md`](../mesh.md) |
| EgressGateway TCP stream experimental | Behind `FERRUM_MESH_EGRESS_STREAM_ENABLED=false` default | [`docs/mesh.md`](../mesh.md) |

## #2110-only discretionary remnants

| Item | Notes |
|---|---|
| Admin CRUD refactor (retired `REFACTORING_PLAN.md` remainder) | Discretionary; fold into future admin-surface work |

## Explicit non-goals (unchanged)

- **EnvoyFilter / WasmPlugin** — explicitly not planned; rejected at config source
  ([`docs/mesh.md`](../mesh.md)). Listed in #2110 for completeness only; no
  implementation tracker.
