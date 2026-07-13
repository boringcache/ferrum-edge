# ferrum-gateway Helm chart

Deploys the Ferrum Edge binary in one of the **core gateway** operating modes.
For the service-mesh components (mesh data plane, injector webhook, ambient
node-agent, mesh CA) use the sibling [`ferrum-mesh`](../ferrum-mesh) chart
instead — the two charts share naming, labelling, secret, and validation
conventions so they feel like one product.

| Mode | `mode` value | Proxy | Admin | Extra config |
|------|--------------|-------|-------|--------------|
| Database | `database` | yes | read/write | `database.*`, `admin.jwtSecret` (>=32) |
| File | `file` | yes | read-only | `file.inlineConfig` or `file.existingConfigMap` |
| Control plane | `cp` | no | read/write | `database.*`, `admin.jwtSecret`, `grpc.jwtSecret` (>=32) |
| Data plane | `dp` | yes | read-only | `dp.cpGrpcUrls`, `grpc.jwtSecret` (>=32) |

The `mode` value is first-class and required; any other value (mesh, injector,
node_agent, migrate) fails at template time with a pointer to the right chart.

## Security defaults you should know

- **Secrets are never generated or rendered into ConfigMaps.** Admin JWT, DB
  URL, and CP/DP gRPC JWT material come from inline values (dev only) or Secret
  references you own. The chart validates that database and cp modes have a
  `>=32`-char admin JWT secret, and that cp/dp modes have a `>=32`-char gRPC JWT
  secret, before it will render.
- **Admin binds to loopback by default.** Probes use the in-pod exec
  `ferrum-edge health` check, which works with the loopback default (a kubelet
  `httpGet` targets the pod IP and would miss a loopback listener). To expose
  admin through a Service set `admin.bindAddress=0.0.0.0` **and**
  `admin.service.enabled=true`. In the write-capable `database`/`cp` modes the
  binary hard-fails on a non-loopback **plaintext** admin bind unless you also
  set one of `admin.allowedCidrs`, admin TLS (`tls.admin.enabled` +
  `ports.adminHttp=0`), or `admin.allowInsecureHttp=true`; the chart mirrors this
  and fails render early. If you use `admin.allowedCidrs`, include `127.0.0.1/32`
  and `::1/128` so the exec health probe is not dropped.
- **Graceful shutdown** wires `terminationGracePeriodSeconds` to the
  `FERRUM_SHUTDOWN_DRAIN_SECONDS` drain window (grace must exceed drain + ~5s
  cleanup, enforced at render).

## Probes

Liveness/startup verify the process and admin listener; readiness verifies the
always-unauthenticated `/health` (which returns `status` + `ready` without
auth — sufficient for a probe). Defaults use the exec `ferrum-edge health`
command and auto-switch to the TLS variant when `ports.adminHttp=0`. Override a
handler entirely with `probes.override` (e.g. an `httpGet` when admin is bound
non-loopback).

## Quickstart per mode

### Database mode (PostgreSQL)

```bash
kubectl -n ferrum create secret generic ferrum-gateway-db \
  --from-literal=url='postgres://ferrum:<percent-encoded-pw>@postgres.ferrum.svc:5432/ferrum'
kubectl -n ferrum create secret generic ferrum-gateway-credentials \
  --from-literal=admin-jwt-secret="$(openssl rand -hex 32)"

helm install ferrum ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/database-values.yaml
```

### File mode (inline config, no Secrets)

```bash
helm install ferrum ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/file-values.yaml
```

File mode generates a random read-only admin JWT secret at startup, so no
credential Secret is required. Kubernetes does not send `SIGHUP` on ConfigMap
change; the chart stamps a config checksum so `helm upgrade` rolls pods, or run
`kubectl rollout restart` after editing config.

### Control plane + data plane pair

```bash
# Shared gRPC JWT secret + CP database + admin secret
kubectl -n ferrum create secret generic ferrum-cp-db \
  --from-literal=url='postgres://ferrum:<pw>@postgres.ferrum.svc:5432/ferrum'
kubectl -n ferrum create secret generic ferrum-grpc-credentials \
  --from-literal=admin-jwt-secret="$(openssl rand -hex 32)" \
  --from-literal=cp-dp-grpc-jwt-secret="$(openssl rand -hex 32)"

helm install ferrum-cp ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/cp-values.yaml
helm install ferrum-dp ./charts/ferrum-gateway -n ferrum \
  -f charts/ferrum-gateway/examples/dp-values.yaml
```

The CP renders a gRPC `Service` (`<release>-grpc:50051`) for data planes; point
`dp.cpGrpcUrls` at it. Production control planes should serve gRPC over TLS
(`tls.cpGrpc`) and DPs should pin CP trust (`tls.dpGrpc`) rather than relying on
plaintext.

## Ports and stream listeners

`ports.{proxyHttp,proxyHttps,adminHttp,adminHttps,cpGrpc}` drive both the
container ports and the `FERRUM_*_PORT` env; a value of `0` disables that
listener (e.g. `ports.adminHttp=0` for TLS-only admin). Raw TCP/UDP stream
proxy listeners are declared under `streamPorts` and, when `service: true`, are
published on the proxy Service:

```yaml
streamPorts:
  - name: postgres-tcp
    containerPort: 15432
    protocol: TCP
    service: true
  - name: dns-udp
    containerPort: 15353
    protocol: UDP
    service: true
```

## TLS material

Each surface under `tls.*` (`frontend`, `admin`, `backend`, `cpGrpc`, `dpGrpc`)
mounts a Secret read-only and sets the matching `FERRUM_*_TLS_*_PATH` env vars.
For the external-secret `_FILE` suffix pattern, use `secretFileMounts` to mount
an arbitrary Secret key and expose `<VAR>_FILE` pointing at it.

See [`values.yaml`](values.yaml) for the fully commented value surface and
[`docs/kubernetes_deployment.md`](../../docs/kubernetes_deployment.md) for the
deployment guide.
