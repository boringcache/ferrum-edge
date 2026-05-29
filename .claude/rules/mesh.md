---
paths:
  - "src/modes/mesh/**"
  - "src/modes/injector.rs"
  - "src/modes/node_agent.rs"
  - "src/modes/node_agent_cni_server.rs"
  - "src/bin/ferrum-cni.rs"
  - "src/cni/**"
  - "src/capture/**"
  - "src/ebpf/**"
  - "src/grpc/mesh_*"
  - "src/k8s_controller/**"
  - "src/plugins/mesh/**"
  - "src/plugins/mesh_route_dispatch.rs"
  - "src/xds/**"
  - "src/service_discovery/mesh.rs"
  - "charts/ferrum-mesh/**"
  - "docs/mesh.md"
  - "docs/node_agent.md"
  - "docs/node_agent_security.md"
  - "docs/spire_deployment.md"
  - "docs/kubernetes_deployment.md"
  - "tests/conformance/**"
  - "tests/integration/*mesh*"
  - "tests/integration/*hbone*"
  - "tests/integration/*ambient*"
  - "tests/integration/*waypoint*"
  - "tests/integration/*ztunnel*"
  - "tests/integration/*cni*"
  - "tests/integration/*k8s*"
  - "tests/functional/*{mesh,node_agent,ambient,waypoint,ztunnel,cni,injector}*"
  - "tests/performance/mesh*/**"
---

# Mesh Rules

Full operator docs live in `docs/mesh.md`. Keep this file to implementation invariants.

## Topologies And Runtime

- `MeshTopology` drives listeners: `Sidecar` uses inbound 15006 mTLS and outbound 15001 capture; `Ambient` uses HBONE 15008 and outbound 15001; `EastWestGateway` uses SNI passthrough on 15443; `EgressGateway` uses mTLS inbound 15090 to external ServiceEntry backends.
- All topologies share the normal proxy and plugin chain.
- Mesh runtime state is `ArcSwap<Option<MeshSlice>>` in `runtime.rs`; slice apply is lock-free hot-swap like `GatewayConfig`.
- `wait_for_first_slice()` blocks startup until the first valid slice arrives.
- Native config consumption uses `MeshConfigSync.MeshSubscribe` gRPC. xDS uses ADS for CDS/EDS/LDS/RDS/SDS/ECDS/RTDS with 25 ms debounce.
- xDS apply uses Envoy-style resource warming (make-before-break), NOT a coherent-version gate: the DP tracks each type's `version_info` independently and builds a slice once all required types (CDS/EDS/LDS/RDS/ECDS — ECDS required so the first slice is never the unprotected name-only view) have a response and `reverse_translate` succeeds. The prior slice keeps serving via `ArcSwap` until the new one is ready; genuine structural errors (e.g. malformed ECDS carrier) NACK + roll back, but version skew does not — and a route referencing a service not yet present in CDS/EDS/LDS is SKIPPED (debug-logged) and retained, NOT NACKed, because xDS types arrive as independent responses and a NACKed SotW resource is not resent until reconnect (do not reintroduce a hard error there). `MeshSlice.version` becomes the newest (max) per-type version and is observability-only (`content_eq` ignores it). The CP re-sends only the types whose resource bytes changed — there is no forced coherent re-send, so a policy/workload-only ECDS update does not drag the name-only CDS/EDS/LDS/RDS along. Keep DP `REQUIRED_MESH_SLICE_TYPE_URLS` and the CP emitter in sync.
- Warming observability splits by sensitivity: the counter `ferrum_xds_warming_partial_applies_total{namespace}` is unauthenticated on `/metrics`, but the per-type `version_info` strings and still-missing required types ride the JWT-gated `GET /mesh/config-drift` `convergence` block (built by the DP via `MeshRuntimeState::set_xds_convergence`). Do NOT move per-type version strings onto `/metrics` — they embed config-change timestamps + content digests and would also explode label cardinality.
- xDS is Ferrum-CP-to-Ferrum-DP, not stock-Envoy/Istio-interoperable: CDS/EDS/LDS/RDS are name-only (service-port discovery); all security/policy slice fields and selector context (authz, PeerAuth, JWT, ServiceEntry, trust bundles, ProxyConfig, workloads, effective labels, outbound policy, telemetry, multi-cluster, sidecar egress scope) ride ECDS as Ferrum mesh-slice carriers. `src/xds/carrier.rs` (`MeshSliceCarrier`) is the single encode/decode source of truth; the CP emits via `translate_mesh_slice_carriers` and the DP recovers in `reverse_translate`, requiring both reserved carrier resource name and matching inner type URL. An xDS-built slice must stay functionally equivalent to a native-built one.
- Native and xDS clients use jittered exponential backoff from 1s to 30s, plus/minus 25%, multi-CP failover via `FERRUM_DP_CP_GRPC_URLS`, and JWT metadata.

## Scope And Policy Semantics

- Scope-aware resources must use the shared `policy_scope_applies_to_workload` / `scope_applies_to_workload` helpers. Do not fork predicates.
- Single-winner precedence (`WorkloadSelector` > `Namespace` > `MeshWide`) applies only where one effective setting is resolved, such as `PeerAuthentication` and `MeshProxyConfig`.
- `MeshPolicy` and `MeshRequestAuthentication` are additive after filtering. `MeshTelemetryResource` merges by section.
- Authorization evaluation is DENY first, then ALLOW. Any ALLOW rule with no match causes implicit deny.
- `RequestMatch` negative fields (`not_methods`, `not_paths`, `not_hosts`, `not_ports`) are conjunctive with positive fields in one rule. Do not split them into separate deny policies.
- Istio empty-rule translation must preserve action semantics: ALLOW with no `rules` is allow-nothing via a never-matching rule; DENY and AUDIT with no `rules` are no-ops.
- NodeWaypoint per-pod policy scoping (`per_pod_policy_scoping`) is resolved per request from `node_waypoint_policy_scope`. The HTTP/HBONE accept path populates it from the resolver (`proxy/mod.rs`); the TCP/UDP stream accept loops always pass `None`, so only `MeshWide` policies are evaluated on streams. A config-apply that has stream proxies + scoped policies in NodeWaypoint topology must keep emitting the one-shot warning. Do not silently start enforcing scoped stream policies without wiring the resolver end-to-end and updating `docs/mesh.md`.
- Mesh authz `source.ip`/`ipBlocks` uses `RequestContext::direct_client_ip` (immediate peer) and `remote.ip`/`remoteIpBlocks` uses `client_ip` (XFF-resolved) on the HTTP path; the stream path (`on_stream_connect`) has only `client_ip`, so both collapse to it. IP-block matchers fail closed when the tested IP is absent.

## Mesh Plugin Injection

- `inject_mesh_global_plugins()` auto-injects reserved-ID globals on slice apply: `__mesh_spiffe_identity` priority 940, `__mesh_authz` priority 2075, `__mesh_workload_metrics`, `__mesh_request_auth` only when JWT rules exist, and `__mesh_access_log` (a `stdout_logging` instance carrying the Telemetry `accessLogging` filter).
- Operator-managed globals of the same type override mesh-injected plugins.
- Mesh plugin injection must preserve normal plugin lifecycle ordering and transaction logging.

## HBONE Identity Boundary

- HBONE is HTTP/2 CONNECT over mTLS on port 15008.
- `is_hbone_connect()` only detects the wire shape (H2 CONNECT + optional `x-ferrum-mesh-protocol`/`x-istio-protocol: hbone` marker); it does not imply authentication and is only safe for non-relay decisions (path normalization, metadata tagging, body-buffering branch).
- Relaying a CONNECT as an HBONE tunnel requires an authenticated, trust-domain-verified peer (`ctx.peer_spiffe_id.is_some()`, i.e. `is_authenticated_hbone_connect()`). `handle_hbone_request` rejects a peerless CONNECT — bare or marker-bearing — with `403 Forbidden` before dialing/circuit-breaking any backend, stamping `mesh_authz.deny_policy=hbone_unauthenticated_peer`. The explicit marker path is not a bypass. This is separate from (and additive to) TLS-time trust-bundle peer verification.
- Baggage `source.principal` rewrites the authz principal only when the authenticated peer is in `mesh_authz.trusted_hbone_assertors` and the baggage trust domain matches the peer cert or `FERRUM_MESH_TRUST_DOMAIN_ALIASES`.
- Untrusted assertors keep their own peer-cert identity even when baggage is present.
- Dropped baggage must surface in transaction metadata as `mesh_authz.ignored_baggage.untrusted_assertor=true`; denied requests contribute `mesh_authz.deny_policy=untrusted_assertor`.
- Trust-domain mismatches use the existing `trust_domain_mismatch` reason.
- Default trusted assertor service accounts are `ztunnel` and `waypoint`. `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` accepts bare service-account names or full SPIFFE IDs.
- Explicit empty `trusted_hbone_assertors: []` disables baggage rewriting entirely.
- Keep fallback baggage key aliases in `HboneIdentity::from_headers()` in sync with tests.

## Node-Waypoint Per-Pod Policy Scope

- One node-waypoint listener serves many pods; source pod identity comes from the eBPF `connect4`/`connect6` cgroup-stamped `SO_COOKIE` record, resolved through `NodeWaypointIdentityResolver`.
- HBONE/HTTP and raw **TCP** stream accept paths both resolve the connection's pod identity and stamp `node_waypoint_policy_scope` (HTTP: `RequestContext`, TCP: `StreamConnectionContext`) via `policy_scope_for_pod(pod_uid)`, so `mesh_authz` enforces Namespace/WorkloadSelector-scoped policies per source pod. The TCP path threads the resolver `ProxyState` → `StreamListenerManager::set_node_waypoint_identity_resolver` (injected before the first stream reconcile) → `TcpListenerConfig` → accept loop (`resolve_node_waypoint_stream_scope`).
- **GAP-2M staging** (applies to both HBONE/HTTP and TCP paths equally): today the resolver's cookie map is populated by the connect-side `orig_dst_bridge`, but accept paths look up the accept-side `SO_COOKIE`. Until the GAP-2M sockops/sk_lookup bridge registers accept-side cookies, every node-waypoint connection resolves `None` and falls back to its documented unresolved-cookie behavior. When GAP-2M lands the existing wiring starts enforcing scoped policies without further proxy-side changes.
- An unresolved scope keeps **mesh-wide-only** policies and sets `mesh_authz.scope_missing=true`. Unlike the HBONE listener (which drops on unresolved identity), TCP streams fail-closed-soft — downgrade to mesh-wide, do not refuse the connection.
- **UDP/DTLS** stream proxies stay mesh-wide-only and pass `node_waypoint_policy_scope: None`: a shared UDP frontend socket carries one cookie for all clients and there are no UDP capture hooks, so there is no per-source-pod cookie to resolve. Do not "fix" this by resolving the listener socket's cookie — that misattributes every session to one identity.
- Only `NodeWaypoint` topology installs the resolver. Sidecar/Ambient/east-west/egress and non-mesh stream proxies pass `None` and are unchanged.

## PeerAuthentication And TLS Reload

- By default, inbound mesh mTLS mode resolves once from the initial slice.
- When all three `FERRUM_GATEWAY_SVID_*` paths are set, the inbound mTLS/HBONE listener uses a SPIFFE client-cert verifier that validates the peer SAN's trust domain against the gateway SVID local bundle plus slice federated bundles; without SVID material it falls back to chain-only verification over `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH`. STRICT requires a peer cert; PERMISSIVE trust-domain-validates an offered cert but still admits cert-less peers. The HBONE baggage trust-gate rests on this verified identity.
- The mesh `RequestAuthentication` (`jwks_auth`) plugin requires the JWT `exp` claim by default (`FERRUM_MESH_REQUEST_AUTH_REQUIRE_EXP=true`); operators may relax it. Expiry validation (rejecting present-but-expired `exp`) is always on.
- With `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, only resolved mTLS mode, frontend client CA verifier, and the lock-free SPIFFE SVID bundle slot (federated trust domains) may hot-swap on slice apply.
- Frontend cert/key paths remain restart-required inputs for mesh peer auth reload.
- Coverage includes mesh HTTP/HBONE termination listeners and mesh-shared TCP+TLS / UDP+DTLS stream listeners.
- `apply_mesh_inbound_tls_reload` publishes swapped `ServerConfig` into HBONE, shared stream TLS, and active `DtlsServer` frontend DTLS configs.
- Failed rebuilds keep the previous config for that path and log a warning; do not reject the whole slice.
- `Disable` is rejected for Ambient and EgressGateway slice updates and keeps the last good config.

## DestinationRule And Materialization

- DestinationRule `connectionPool.tcp.connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` and is enforced by HTTP/H2/H3, gRPC, TCP, and HBONE dispatch.
- Port-level `loadBalancer` and `outlierDetection` land on the same override slot and use isolated per-port LB counters/hash rings and passive thresholds for HTTP-family, gRPC, WebSocket, and HBONE.
- `connectionPool.http.maxRequestsPerConnection`, `idleTimeout`, and `http2MaxRequests` land on `http_max_requests_per_connection`, `http_idle_timeout_ms`, and `h2_max_concurrent_streams`.
- Dispatch projects port overrides through `resolve_effective_proxy_for_target()` onto the owned `Proxy` clone; direct H2 and gRPC builders consume H2 caps through `max_concurrent_streams` and `initial_max_send_streams`.
- `http_max_requests_per_connection` is wire-projected but currently inert at runtime because hyper lacks a close-after-N knob.
- `connectionPool.tcp.maxConnections` and `tcpKeepalive` land on `max_connections` and `tcp_keepalive`. `maxConnections` is enforced by stream-family (TCP/TCP+TLS) dispatch AND by HTTP-family WebSocket dispatch (H1/H2 in `proxy/mod.rs`, H3 in `http3/websocket.rs`): a WebSocket session opens one dedicated backend connection, so an RAII `backend_conn_limit::BackendConnectionGuard` on `ProxyState.backend_conn_limit` (keyed `(host, port)`, acquired in the WS connect loop, held for the session) bounds concurrent open connections and rejects over-cap upgrades with 503. `tcpKeepalive` stays stream-family only.
- `maxConnections` is NOT enforced for the pooled multiplexed HTTP transports (reqwest H1/H2, direct H2, gRPC, H3, HBONE): their connection lifecycle is pool-internal (reuse/sharding/idle eviction), so a request-keyed counter would measure request concurrency (`http2MaxRequests` territory, already wired via `h2_max_concurrent_streams`) not open connections, and would risk leaking a count through the shared `GenericPool` evict/replace paths. Do not add such a counter; use `h2_max_concurrent_streams` for H2/gRPC concurrency. See `docs/mesh.md` "DestinationRule `maxConnections` enforcement scope" and `src/backend_conn_limit.rs`.
- `maxConnections` exhaustion returns `StreamSetupKind::BackendMaxConnectionsExceeded` on stream-family and a 503 (`rejection_phase=backend_max_connections`) on WebSocket; keepalive setsockopt failures warn and continue.
- TCP/UDP/DTLS stream proxies enforce only connect timeout, max connections, and tcp keepalive per port; they use upstream-level LB/passive policy.
- Phantom DestinationRule ports are skipped with a warning.
- Admin API POST/PUT of `Upstream.port_overrides` is rejected; DestinationRule is canonical.
- `materialize_east_west_gateway_proxies()` creates SNI-passthrough TCP proxies only for east-west topology.
- `materialize_egress_gateway_proxies()` creates HTTP-family proxies from `mesh_external` ServiceEntries only for egress topology.

## Injector, Node Agent, And CNI

- Injector mode serves `POST /mutate` Kubernetes AdmissionReview and emits JSON patches only.
- Sidecars run as `PROXY_UID`; optional iptables init container requires `NET_ADMIN`.
- IPv4/IPv6 capture CIDRs must stay partitioned into `iptables` and `ip6tables` blocks. `FERRUM_MESH_IP6TABLES_ENABLED=auto|true|false` controls IPv6 fan-out.
- Cleanup scripts are best-effort even when `ip6tables` is missing.
- Injected SPIFFE ID format is `spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}`.
- JWT secrets in injected manifests use `SecretKeyRef`, never plaintext.
- Opt in with `ferrum.io/inject=true` or `ferrum.io/mesh=enabled`; opt out with `sidecar.istio.io/inject=false` or `ferrum.io/inject=false`.
- Node-agent CNI is opt-in with `FERRUM_NODE_AGENT_CNI_ENABLED=false` by default.
- When enabled, node-agent binds `FERRUM_NODE_AGENT_CNI_SOCKET_PATH` and the `ferrum-cni` binary forwards kubelet ADD/DEL/CHECK over that socket.
- kube-rs watcher remains source of truth; CNI only closes the kubelet-vs-watcher race and does not carry labels or annotations.

## Kubernetes Controller

- `FERRUM_K8S_CONTROLLER_ENABLED` and `FERRUM_K8S_POD_DISCOVERY_ENABLED` default true inside pods detected by `KUBERNETES_SERVICE_HOST`; outside pods they default false.
- Explicit operator `false` wins over pod detection.
- If `FERRUM_K8S_WATCH_NAMESPACES` is unset, watch scope falls back to CP scope: `Single`/`Set` use namespaced watches, `All` uses cluster-wide.
- Istio status writer patches `status.conditions[]` (a `FerrumAccepted` condition plus a `status.ferrum.translation` detail block) for all nine translated Istio kinds when `watch_istio == true`: AuthorizationPolicy, PeerAuthentication, RequestAuthentication, DestinationRule, VirtualService, ServiceEntry, WorkloadEntry, Sidecar, and Telemetry. Successful translation writes `FerrumAccepted=True`; a `K8sTranslateError` writes `FerrumAccepted=False`/`Invalid` with the translator's reason so rejections are visible to `kubectl`.
- Keep `istio_api_resource`/`is_supported_istio_kind` in `src/k8s_controller/istio_status.rs` in lock-step with `ISTIO_CRDS` in `src/k8s_controller/watcher.rs` (group + plural).
- Parsed-but-unenforced fields are surfaced as `status.ferrum.translation.deferred_fields` rather than only logged: DestinationRule `portLevelSettings[].tls`, per-subset `connectionPool.tcp.connectTimeout`/`outlierDetection`, and `connectionPool.http.{http1MaxPendingRequests,maxRetries,h2UpgradePolicy}`; VirtualService `http[].corsPolicy` (the only remaining HTTP-route field that is parsed but not projected — `mirror`/`mirrorPercentage`, `redirect`, and `rewrite` are now fully translated); Sidecar `ingress[]`. VirtualService `spec.tcp[]` and `spec.tls[]` route blocks are **not** deferred — the translator rejects them fail-closed and they surface as `FerrumAccepted=False`/`Invalid` status, not as `deferred_fields`. The DR `connectionPool.http` deferred set is mirrored by a translator warning in `src/config_sources/k8s/istio.rs`; keep the two lists in sync.
- Status writer failures, such as missing `subresources.status`, warn and no-op; they never abort reconcile.
- `ProxyConfig` is translated but not watched (`ISTIO_CRDS`) and not surfaced by the status writer.
