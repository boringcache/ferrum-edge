# ferrum-mesh Helm chart

Deploys Ferrum Edge service-mesh components: control plane, sidecar injector,
east-west gateway, mesh CA, ambient/node-agent DaemonSets, and optional
observability assets. Core gateway modes (`database`, `file`, `cp`, `dp`) belong
in the sibling [`ferrum-gateway`](../ferrum-gateway) chart.

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
