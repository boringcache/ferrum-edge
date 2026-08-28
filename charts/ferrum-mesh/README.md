# ferrum-mesh Helm chart

Deploys Ferrum Edge service-mesh components: control plane, sidecar injector,
east-west gateway, mesh CA, ambient/node-agent DaemonSets, and optional
observability assets. Core gateway modes (`database`, `file`, `cp`, `dp`) belong
in the sibling [`ferrum-gateway`](../ferrum-gateway) chart — the two charts share
naming, labelling, secret, and validation conventions.

| Component | Values key | Default | Notes |
|-----------|------------|---------|-------|
| Control plane | `controlPlane.enabled` | `false` | Requires DB + JWT secrets |
| Injector webhook | `injector.enabled` | `false` | Requires TLS Secret |
| East-west gateway | `eastWest.enabled` | `false` | Cross-cluster SNI passthrough |
| Mesh CA | `ca.enabled` | `false` | Fixed one replica in template |
| Ambient proxy | `ambient.enabled` | `false` | Requires `nodeAgent.enabled` |
| Node agent | `nodeAgent.enabled` | `false` | eBPF capture manager |

Example value overlays live under [`examples/`](examples/).

## Sidecar injector webhook self-exclusion

The mutating webhook uses `failurePolicy: Fail` so a broken admission path
cannot silently skip mesh injection. That fail-closed posture creates a
well-known bootstrap deadlock when the webhook intercepts its own replacement
pods: if every injector replica is unavailable, pod `CREATE` in the release
namespace is rejected and the injector cannot recover without manual
`MutatingWebhookConfiguration` deletion.

Three factors contribute to that outage:

| Factor | Mitigation in this chart |
| --- | --- |
| Single injector replica | Addressed separately in PR #4186 (`injector.replicas: 2`, PDB, topology spread) |
| `failurePolicy: Fail` | Intentional; kept for fail-closed injection |
| No self-exclusion | **This chart** — release namespace + injector pod label exclusions |

When `injector.enabled=true`, the rendered `MutatingWebhookConfiguration`:

1. **Always** appends `kubernetes.io/metadata.name NotIn [<release namespace>]`
   to `namespaceSelector`, even when `injector.namespaceSelector` is overridden.
   Pods in the release namespace (injector, control plane, mesh CA, east-west
   gateway) are therefore never gated on the webhook.
2. Sets `objectSelector` to `app.kubernetes.io/name NotIn [ferrum-mesh-injector]`
   so injector pods are excluded by label regardless of namespace.

Workloads in other namespaces still receive admission calls; opt-in/out behavior
is unchanged (`requireAnnotation`, pod annotations, and `ferrum.io/injection`
labels). Extend `injector.namespaceSelector` for platform namespaces such as
`gke-managed-system` or `openshift-*` before enabling broader injection.

## High availability and disruption

Data-path Deployments default to **two replicas** where the chart ships an HA
posture out of the box:

- `injector.replicas: 2` — mutating webhook; a drain must not take admission to zero.
- `eastWest.replicas: 2` — cross-cluster east-west SNI passthrough on port 15443.

Each enabled workload with `replicas >= 2` gets a PodDisruptionBudget when
`podDisruptionBudget.enabled` is true (the default), using `minAvailable: 1`.
When `replicas >= 2` and `topologySpreadConstraints` is unset, the chart also
spreads pods across `kubernetes.io/hostname` (`ScheduleAnyway`). Set
`topologySpreadConstraints: []` on a workload to disable the default spread.

**Explicit non-HA defaults** (PDB skipped — `minAvailable: 1` would block drains):

- `controlPlane.replicas: 1` — single-node lab installs (`examples/development-values.yaml`). Raise to `>= 2` before production control planes.
- `ca` — hard-coded to one replica in the template.

Set any data-path workload to `replicas: 1` only as a deliberate lab choice; the
PDB is omitted automatically.

## Graceful shutdown

Serving workloads (`controlPlane`, `ca`, `eastWest`, `ambient`) ship the same
additive drain contract as `ferrum-gateway` (`docs/graceful_shutdown.md`):

- `FERRUM_SHUTDOWN_DRAIN_SECONDS` / `FERRUM_SHUTDOWN_PREDRAIN_SECONDS`
- native `lifecycle.preStop.sleep` (Kubernetes 1.29+ SleepAction; distroless has no shell)
- `terminationGracePeriodSeconds: 110` covering preStop 30s + the 78s post-SIGTERM budget

Render fails when the grace period is under budget. On Kubernetes &lt;1.29 set
`shutdownPreStopSeconds: 0` and raise `shutdownPreDrainSeconds` to at least
readiness `failureThreshold × periodSeconds`. One-shot hooks/jobs (CNI uninstall)
and the injector/node-agent (not Ferrum serving modes) do not receive this
contract. East-west readiness is drain-aware `ferrum-edge health` against the
loopback admin listener — not `tcpSocket` on `tls-passthru`.

## Pod security and resources

`controlPlane`, `ca`, and `eastWest` default to restricted-compatible
PodSecurity (non-root 65532, drop ALL, no privilege escalation, read-only root,
RuntimeDefault seccomp, `/tmp` emptyDir) with non-empty CPU/memory requests and
limits. Ambient keeps `hostNetwork` and datapath capabilities (`NET_ADMIN` /
`NET_RAW`, plus `SYS_ADMIN`/`SYS_PTRACE` only for in-netns capture and
BPF/PERFMON for NodeWaypoint) after dropping ALL. `priorityClassName` is
optional; only ambient and node-agent default to `system-node-critical`. Empty
`priorityClassName` omits the field.

## Metrics scrape

`observability.enabled` (default `false`) does **not** change admin bind
addresses. When enabled, the chart renders `FERRUM_METRICS_*` auth env,
dedicated ClusterIP metrics Services for Deployments (the main CP/east-west
Services stay gRPC / tls-passthru), a `ServiceMonitor`, and `PodMonitor`s for
host-network DaemonSets. Alerts and monitors fail render without a scrape
credential (`observability.metrics.allowedCidrs` or
`bearerToken.existingSecret.name`). Inline `bearerToken.value` wires pod env
only. Optional Prometheus Operator CRDs stay gated on `observability.enabled`.
`FerrumMeshControlPlaneConfigStale` does not use `absent()` — it is silent
no-data until a scraped data plane emits the freshness timestamp.

See [`values.yaml`](values.yaml) for the fully commented value surface and
[`docs/kubernetes_deployment.md`](../../docs/kubernetes_deployment.md) for the
deployment guide.
