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
readiness `failureThreshold × periodSeconds`. That remediation is real for every
serving workload here, `controlPlane` and `ca` included: `cp` mode honors
`FERRUM_SHUTDOWN_PREDRAIN_SECONDS` (its admin and CP-gRPC accept loops close on
the same broadcast the window delays, while `/health` already reports
`ready: false`). One-shot hooks/jobs (CNI uninstall) and the injector/node-agent
(not Ferrum serving modes) do not receive this contract. East-west readiness is
drain-aware `ferrum-edge health` against the loopback admin listener — not
`tcpSocket` on `tls-passthru`.

Every **enabled** computed probe must have a usable handler. Setting a
workload's `admin.httpPort: 0` while a computed probe stays enabled fails render
instead of silently omitting the probe — including ambient, where a missing
readiness probe would leave the host-network datapath unprobed. Supply
`probes.<probe>.override` or set `probes.<probe>.enabled: false` instead.
`probes.startup.override` is classified independently of liveness on every
workload (controlPlane, ca, eastWest, ambient, injector, node-agent).

## Admin listener validation

`<workload>.admin.bindAddress` and `<workload>.admin.allowedCidrs` are validated
against the same rules the binary applies, so a typo fails `helm template`
instead of CrashLooping the pod:

- `bindAddress` must be an IP literal. Hostnames (`localhost`, a Service name)
  are rejected — `EnvConfig::validate()` exits on them.
- `allowedCidrs` is parsed entry-for-entry like `CidrSet::parse_strict`: bare
  IPv4/IPv6 addresses or CIDRs, no brackets, prefixes in family range.
- For `controlPlane` and `ca` (which run `cp` mode and hard-fail on a
  non-loopback plaintext admin listener), a **full-family** allowlist —
  `0.0.0.0/0`, `::/0`, an IPv4-mapped `/96`, or a union that covers a whole
  family — does not count as protection. Use a narrower allowlist, keep the
  loopback default, or set `admin.allowInsecureHttp: true` (insecure development
  only).
- While the computed exec probes are enabled, a non-empty allowlist must cover
  the **exact** source the admin accept loop observes: `127.0.0.1` for an IPv4
  or `0.0.0.0` bind (including a concrete 127/8 or IPv4-mapped 127/8 dest such
  as `::ffff:127.0.0.2`), `::1` for an IPv6 wildcard bind. An IPv4-only
  allowlist in front of an IPv6 wildcard bind renders cleanly and then
  restart-loops the pod, so the chart refuses it.

`observability.metrics.allowedCidrs` is validated the same way; the runtime
parses `FERRUM_METRICS_ALLOWED_CIDRS` with the same strict parser.

## Pod security and resources

`controlPlane`, `ca`, and `eastWest` default to restricted-compatible
PodSecurity (non-root 65532, drop ALL, no privilege escalation, read-only root,
RuntimeDefault seccomp, `/tmp` emptyDir) with non-empty CPU/memory requests and
limits. Their `podSecurityContext` / `securityContext` are free-form and
rendered verbatim.

Ambient is different and its schema says so. It keeps `hostNetwork` and datapath
capabilities (`NET_ADMIN` / `NET_RAW`, plus `SYS_ADMIN`/`SYS_PTRACE` only for
in-netns capture and `BPF`/`PERFMON` for NodeWaypoint) after dropping ALL, and it
assembles its container `securityContext` field by field rather than rendering
the operator's map verbatim. `ambient.securityContext` therefore accepts only the
keys the template actually reads — `readOnlyRootFilesystem`, `capabilities.drop`,
`capabilities.add` — and rejects anything else at lint time rather than silently
ignoring it (`runAsUser` / `runAsGroup` are decided by the capture mode; the
privileged UDP preflight init container hard-codes no-escalation and that
field is not a steady-state proxy key). `capabilities.drop` must stay
`["ALL"]`, and `capabilities.add` **merges on top of** the datapath minimum: it
can add named capabilities but can never remove a required one. `ALL` and
`CAP_ALL` are rejected in `capabilities.add` — they would re-grant the complete
Linux capability set after `drop: ["ALL"]`. Capability names are validated
against `^(CAP_)?[A-Z][A-Z0-9_]*$` and rendered unquoted so NodeWaypoint and
Ambient UDP live/CI greps keep matching the datapath set. An explicit `drop: []`
is rejected — it is not silently rewritten to `[ALL]`; omit the key to keep the
default.

`priorityClassName` is optional; only ambient and node-agent default to
`system-node-critical`. Empty `priorityClassName` omits the field.

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
