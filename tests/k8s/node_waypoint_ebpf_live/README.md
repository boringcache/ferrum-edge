# NodeWaypoint eBPF live datapath test

This harness validates the sidecarless NodeWaypoint capture path on a real
Linux Kubernetes cluster. It is intentionally not self-skipping: the CI job that
calls it must provide a disposable cluster with:

- at least two schedulable worker nodes;
- kernel >= 5.7, cgroup v2, and bpffs mounted;
- the capabilities and mounts from `docs/node_agent_security.md`;
- Istio security/networking CRDs installed so Ferrum CP can ingest
  `AuthorizationPolicy` and service/workload resources;
- `kubectl`, `helm`, `curl`, and node-level `bpftool` access through
  `kubectl debug node/...`.

The script renders the chart first and fails if an enabled eBPF node-agent or
NodeWaypoint proxy would use a non-`-ebpf` image. It then installs the chart,
installs a minimal SPIRE Server/Agent fixture by default, registers per-node
NodeWaypoint SVID entries, checks that every ambient NodeWaypoint pod reports a
fail-closed SPIRE Agent identity proof
(`ferrum_mesh_cert_expiry_seconds{spiffe_id=<per-node>,source="spire_agent"}`
with positive expiry, `ferrum_mesh_ca_health{ca_type="spire_agent"} 1`, and
`ferrum_mesh_trust_bundle_version{trust_domain=<domain>,source="spire_agent"}`
>= 1), checks
`/metrics` for `ferrum_node_agent_capture_state{state="ready"} 1`, proves the
explicit ingress redirect interface set for IPv4 and IPv6, then injects an
existing but wrong route device both across a replacement startup and as
post-start route drift. In both cases the node-agent must withdraw readiness
with bounded topology metrics and recover only after the original routes are
restored. The harness then collects BPF program/link/map evidence with
`bpftool`, creates same-node and cross-node
source/destination pods, verifies `src-a` Service ClusterIP traffic is admitted,
verifies `src-b` Service ClusterIP and direct Pod-IP attempts are rejected by the
live `AuthorizationPolicy`, and forces the `src-a` workload to be recreated with
a new UID on the same IPv4 address so stale source identity and registry state
cannot be reused or block the replacement; the runtime identity snapshot for the
replacement must not contain the deleted pod's old UID. The same-IPv4 reuse
assertion also waits for the replacement source allow path and post-recreation
deny regression check to succeed before passing. It is specific to the default
`kind-dual-stack-node-waypoint-ebpf` profile and its host-local CNI lease files;
other disposable profiles retain the non-forced delete/recreate stale-cleanup
check without requiring `stale_ip_reuse`. In
production SPIRE mode it also verifies that every ambient DaemonSet pod rejects
plaintext and no-client-SVID connections to the HBONE listener. The
no-client-SVID probe uses a valid authority-form CONNECT target
and accepts only a transport/protocol failure or Ferrum's explicit
`{"error":"Mesh authorization denied: missing per-pod policy scope"}` 403 denial,
not a generic non-200 response. It then temporarily pins the trusted HBONE
assertor inventory to a wrong SPIFFE ID to prove authenticated but untrusted
asserted workload identity fails closed with an attributed policy deny and
recovers after the default inventory is restored. That forged-assertion probe
accepts a direct 403 or the source-side 502 wrapper that explicitly reports the
destination HBONE CONNECT was rejected with 403; in both cases the destination
policy-deny counter for the expected NodeWaypoint assertor must increase.
The production SPIRE pass also restarts the SPIRE Agent DaemonSet and the
NodeWaypoint ambient DaemonSet, then waits for fresh SPIRE Agent SVID metrics,
registry/mesh-slice readiness, fresh source admission, allow/deny traffic, and
plaintext/no-client-SVID HBONE rejection before recording
`node_waypoint.identity.spire_restart_recovery`. It also asserts ADR
observability counter movement:
`node_waypoint.observability.hbone_handshake_inbound_tls_failure` (after
plaintext HBONE rejection),
`node_waypoint.observability.asserted_identity_rejected` (after forged
assertor rejection), and
`node_waypoint.observability.hbone_handshake_outbound_success` (after
cross-node Service allow).
On dual-stack clusters it also requires the IPv6 pod-netns ready
markers, IPv6 Service allow/deny behavior, and an IPv6 direct Pod-IP bypass
guard.

The chart render preflight and live install both verify the production identity
profile: `ambient.spire.enabled=true` must mount the SPIRE Agent Workload API
socket into the NodeWaypoint proxy and render
`FERRUM_MESH_CA_BACKEND=spire_agent`, `FERRUM_MESH_SPIRE_AGENT_SOCKET`,
per-node `FERRUM_MESH_WORKLOAD_SPIFFE_ID` using `$(FERRUM_K8S_NODE_NAME)`, and
`FERRUM_MESH_PRODUCTION_MODE=true`. The SPIRE fixture follows the upstream
Kubernetes k8s_psat registration pattern: each NodeWaypoint workload entry is
registered under the attested per-node SPIRE Agent parent ID, using the
Kubernetes node UID in
`spiffe://<trust-domain>/spire/agent/k8s_psat/<cluster>/<node-uid>`, plus
`k8s:node-name:<node>` so each NodeWaypoint DaemonSet pod receives the SVID
that discovery later pins for that node.

## NodeWaypoint UDP listener datapath (issue #3286)

`run_node_waypoint_udp_datapath_checks` drives **real datagrams** through the
UDP listener the NodeWaypoint materializes for the in-mesh `udp-echo` Service's
`protocol: UDP` port (`materialize_node_waypoint_udp_listeners`, enabled by
`ambient.env.FERRUM_MESH_NODE_WAYPOINT_UDP_LISTENERS_ENABLED=true` in the Helm
install). The listener binds that port number in the node's network namespace,
so a co-located enrolled pod reaches it at `<node IP>:$FERRUM_LIVE_UDP_LISTENER_PORT`
(default `15353`) and its source pod is attributed from the kernel-reported
ingress interface — its veth — before `mesh_authz` evaluates scoped policy.

The two UDP senders reuse the `src-a` / `src-b` ServiceAccounts, so the same
principal-keyed `AuthorizationPolicy` objects that govern the HTTP checks govern
these datagrams. Assertions, all observed from the datagram outcome:

- `node_waypoint.udp.listener_allow_attributed_source` — the admitted enrolled
  source reaches the backend and receives its echo.
- `node_waypoint.udp.listener_deny_scoped_policy` — the source the
  namespace-scoped `deny-src-b` policy names gets nothing.
- `node_waypoint.udp.listener_deny_unattributed_source` — an unenrolled pod
  (`udp-unmanaged`, outside the mesh namespace) has no registry binding for its
  veth and is refused.
- `node_waypoint.udp.listener_deny_spoofed_source` — the same unenrolled pod
  FORGES the admitted pod's source address over a raw socket and is still
  refused, because attribution is the ingress interface rather than the
  address. When the sandbox denies a raw socket the assertion records that the
  forged datagram could not be emitted instead of claiming a refusal; the
  unenrolled-source case above remains the required attribution proof, and the
  address-forging property itself is pinned by
  `one_pod_cannot_obtain_another_pods_scope_by_forging_its_source_address` in
  `tests/integration/mesh_node_waypoint_udp_scope_tests.rs`.
- `node_waypoint.udp.policy_change_denies_live` /
  `node_waypoint.udp.policy_withdrawal_recovers_live` — applying then deleting a
  DENY for the admitted principal converges both ways with the ambient
  DaemonSet's total container restart count unchanged, so recovery is a live
  reload rather than a data-plane restart.

DTLS listeners are **not** exercised here: `AppProtocol::Dtls` materialization,
its frontend-termination posture, and its bind-failure visibility are covered at
unit/integration level only.

Each run writes `target/node-waypoint-ebpf-live/live-assertions.json` using the
shared live-assertion schema from `tests/k8s/lib/live_assertions.sh`. The current
assertions are H2 evidence only; they do not promote NodeWaypoint or make it a
release-blocking GA contract row.

Set `FERRUM_LIVE_SPIRE_PRODUCTION=false` only for local eBPF-only debugging. In
that opt-out mode the ambient proxy is started with `FERRUM_MESH_ALLOW_NO_CA=true`;
the required CI workflow keeps production SPIRE enabled so a missing SVID cannot
fall back to plaintext.

Run manually:

```bash
FERRUM_EBPF_LIVE_ACK_DISPOSABLE=true \
tests/k8s/node_waypoint_ebpf_live/run.sh
```

Set `FERRUM_LIVE_REQUIRE_DUAL_STACK=true` for the dual-stack pass.
Set `FERRUM_LIVE_KUBE_CONTEXT=<context>` to run against a disposable cluster
that is not the current kube context; the harness switches to it before cluster
operations.
Set `FERRUM_LIVE_TRUST_DOMAIN=<domain>` to exercise a non-`cluster.local` trust
domain across SPIRE registration, Ferrum Kubernetes identity derivation, and
the workload `AuthorizationPolicy` principals.
Set `FERRUM_LIVE_DOCKER_NODE_EVIDENCE=true` when running against kind from the
Docker host; the harness will collect BPF evidence through the kind node
containers instead of pulling a separate `kubectl debug` image. The ingress
topology wrong-interface and drift cases require this access. With
`FERRUM_LIVE_TESTS_REQUIRED=1`, missing Docker/node route prerequisites fail the
run rather than skipping those cases.
