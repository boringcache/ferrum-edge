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
| Data plane | `dp` | yes | read-only | `dp.cpGrpcUrls`, `admin.jwtSecret`, `grpc.jwtSecret` (>=32) |

The `mode` value is first-class and required; any other value (mesh, injector,
node_agent, migrate) fails at template time with a pointer to the right chart.

## Security defaults you should know

- **Secrets are never generated or rendered into ConfigMaps.** Admin JWT, DB
  URL, and CP/DP gRPC JWT material come from inline values (dev only) or Secret
  references you own. The chart validates that database, cp, and dp modes have
  a `>=32`-char admin JWT secret, and that cp/dp modes have a `>=32`-char gRPC
  JWT secret, before it will render. Required DB/JWT values may instead come
  from matching `secretFileMounts` entries and Ferrum's `_FILE` resolver.
- **Admin binds to loopback by default.** Probes use the in-pod exec
  `ferrum-edge health` check, which works with the loopback default (a kubelet
  `httpGet` targets the pod IP and would miss a loopback listener). To expose
  admin through a Service set `admin.bindAddress=0.0.0.0` **and**
  `admin.service.enabled=true`. In the write-capable `database`/`cp` modes the
  binary hard-fails on a non-loopback **plaintext** admin bind unless you also
  set one of `admin.allowedCidrs`, admin TLS (`tls.admin.enabled` +
  `ports.adminHttp=0`), or `admin.allowInsecureHttp=true`; TLS on 9443 does not
  protect a still-live plaintext listener on 9000. Literal `/0` CIDRs are
  rejected as ineffective protection; the binary is authoritative for other
  permit-all CIDR unions. If computed exec probes are enabled,
  `admin.allowedCidrs` must include exact source `127.0.0.1/32` (or the bare IP)
  because the admin TCP filter does not special-case loopback (an `::1` bind
  requires `::1/128` instead, and shifts the computed probes to `--host ::1`).
  `admin.bindAddress` must be an IP literal — any hostname (`localhost`,
  `admin.internal`, ...) is rejected at render (the binary requires an IP); use
  `127.0.0.1` or `::1`.
- **Probes and admin HTTPS.** When `ports.adminHttp=0` the computed exec probes
  auto-switch to `ferrum-edge health --tls` against admin HTTPS (`:9443`), which
  only serves when admin TLS material is configured. The chart therefore requires
  `tls.admin.enabled` + `tls.admin.secretName` in that combination (or that you
  override/disable the computed probes). Disabling **both** admin ports
  (`ports.adminHttp=0` and `ports.adminHttps=0`) leaves no admin listener for the
  computed probes and is rejected unless every computed probe is overridden.
- **CP/DP gRPC transport.** The binary rejects a non-loopback **plaintext** CP
  gRPC bind (`cp` mode, default `cp.grpcBindAddress=0.0.0.0`) and a non-loopback
  `http://` CP URL (`dp` mode) unless gRPC TLS is configured or you set
  `grpc.allowPlaintext=true` (renders `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT`). The
  chart mirrors that guard at render. Prefer `tls.cpGrpc`/`tls.dpGrpc` for
  production; the dev opt-in flows through the first-class `grpc.allowPlaintext`.
  IPv6 CP binds are bracketed automatically (`::` → `[::]:50051`). A loopback CP
  bind is unreachable through `cp.service`, so the chart requires
  `cp.service.enabled=false` with it; `ports.cpGrpc=0` disables the CP gRPC
  listener (the gRPC container port and CP Service are omitted). DP CP URL schemes
  are validated (http/https/grpc/grpcs) so typos fail at render, not at boot.
- **Chart-managed env is protected.** Every `FERRUM_*` var the chart renders from
  first-class values (mode, DB, JWTs, ports, bind address, allowlist, TLS paths,
  shutdown drain, DP URLs, gRPC plaintext opt-in, ...) is reserved: setting it
  through `env` or `extraEnv` fails render, so the process can never drift from
  the rendered probes/Services/ports. Generated `<name>_FILE` vars from
  `secretFileMounts` are reserved too, so `env`/`extraEnv` cannot shadow a
  required secret's file source.
- **TLS and `_FILE` Secret mounts are non-root readable.** They default to mode
  `0440` with pod `fsGroup: 65532`, matching the distroless nonroot image. Both
  `secretVolumeDefaultMode` and `podSecurityContext` are overridable for images
  with a different runtime identity.
- **Graceful shutdown** wires `terminationGracePeriodSeconds` to the
  `FERRUM_SHUTDOWN_DRAIN_SECONDS` drain window (grace must exceed drain + ~5s
  cleanup, enforced at render). `shutdownDrainSeconds: 0` is a valid "skip
  draining" value and is rendered explicitly; set it to `null` to fall back to
  the binary's 30s default.

## Probes

Liveness and startup run `ferrum-edge health --live` (GET `/live`), which
returns 200 whenever the process and admin listener are up — even during
startup or while serving degraded. Readiness runs `ferrum-edge health` (GET
`/health`), which returns 503 until the gateway is ready. Keeping them distinct
means an alive-but-unready pod (e.g. a `dp` that has lost its `cp`) is dropped
from Service endpoints **without** being restart-looped by liveness — never
point liveness at `/health`. The defaults use the exec `ferrum-edge health`
command and auto-switch to the TLS variant when `ports.adminHttp=0`.

Liveness and readiness have **separate** override knobs so a custom handler
cannot silently re-couple them. Replace only one probe's computed handler with
`probes.liveness.override` or `probes.readiness.override` (e.g. an `httpGet`
when admin is bound non-loopback); the startup probe reuses the liveness
handler.

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

The CP example release renders the gRPC Service
`ferrum-cp-ferrum-gateway-grpc:50051`; the paired DP example targets that exact
DNS name. In general the name is `<chart-fullname>-grpc`, truncated as one DNS
label. The quickstart pair explicitly opts into plaintext ClusterIP gRPC for
development. Production control planes should remove that opt-in, serve gRPC
over TLS (`tls.cpGrpc`), and have DPs pin CP trust (`tls.dpGrpc`).

## Ports and stream listeners

`ports.{proxyHttp,proxyHttps,adminHttp,adminHttps,cpGrpc}` drive both the
container ports and the `FERRUM_*_PORT` env; a value of `0` disables that
listener (e.g. `ports.adminHttp=0` for TLS-only admin). The proxy Service
publishes its HTTPS port when `tls.frontend.enabled=true` with a frontend TLS
Secret (file/database modes), or in `dp` mode whenever `ports.proxyHttps` is
nonzero — a DP binds HTTPS on the port alone and hot-swaps CP-delivered Gateway
TLS. Default file/database installs therefore do not advertise an unbound 443.
The admin Service publishes `admin-https` only when `tls.admin` is enabled with a
Secret. If no proxy port would be published (all proxy ports `0`, no frontend
TLS, no `service: true` stream port), the proxy Service is skipped entirely
rather than rendering an API-server-rejected empty `ports:` block.
Raw TCP/UDP stream proxy listeners are declared under `streamPorts` and, when
`service: true`, are published on the proxy Service:

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
an arbitrary Secret key and expose `<VAR>_FILE` pointing at it. Required sources
are matched by base name, for example `name: FERRUM_ADMIN_JWT_SECRET` renders
`FERRUM_ADMIN_JWT_SECRET_FILE` and satisfies the admin JWT render guard.

See [`values.yaml`](values.yaml) for the fully commented value surface and
[`docs/kubernetes_deployment.md`](../../docs/kubernetes_deployment.md) for the
deployment guide.
