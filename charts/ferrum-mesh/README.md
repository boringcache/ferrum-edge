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

See [`values.yaml`](values.yaml) for the fully commented value surface and
[`docs/kubernetes_deployment.md`](../../docs/kubernetes_deployment.md) for the
deployment guide.
