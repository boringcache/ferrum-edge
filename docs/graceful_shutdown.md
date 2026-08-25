# Graceful Shutdown & Connection Draining

When the gateway receives SIGTERM or SIGINT, it performs a graceful shutdown that allows in-flight requests to complete before the process exits.

## Shutdown Sequence

Serving modes (database, file, dp, mesh) run these phases **sequentially**, each with its own bounded budget. The worst-case total is the sum of every phase below, not just `FERRUM_SHUTDOWN_DRAIN_SECONDS`.

1. **Signal received** — SIGTERM/SIGINT broadcasts shutdown to all components
2. **Accept loops exit** — no new connections are accepted on any listener (HTTP, HTTPS, H3, TCP, UDP)
3. **Drain phase begins** — the `draining` flag is set, causing:
   - All HTTP/1.1 responses include `Connection: close` (clients disconnect after their current request)
   - The gateway waits up to `FERRUM_SHUTDOWN_DRAIN_SECONDS` for all in-flight connections to complete
4. **Connection tracking** — every accepted connection creates a `ConnectionGuard` (RAII) that increments an atomic counter on accept and decrements on drop. The drain waiter monitors this counter
5. **Drain timeout** — if connections remain after the drain period, they are force-closed and the gateway proceeds with shutdown
6. **Transport pool drain** — sidecar-ingress Unix backend pools release held file descriptors under a bounded tail (5s driver drain + 1s reap; see `unix_backend_pool.rs`)
7. **Background task cleanup** — DNS refresh, config polling, overload monitor, health checks, and other background tasks get 5 seconds to clean up
8. **Audit flush** (database and cp modes) — accepted audit events drain for `clamp(FERRUM_SHUTDOWN_DRAIN_SECONDS, 5, 60)` seconds while the database handle is still alive
9. **Observability delivery** — deferred logging/notification workers drain for `FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS` (default 2s)
10. **Plugin finalizers** — chargeback snapshot and Kafka logging generations finalize (best-effort; allow headroom in the pod grace period)
11. **Process exit**

## Configuration

```bash
# Seconds to wait for in-flight connections to drain (default: 30)
# Set to 0 to skip draining (immediate shutdown)
FERRUM_SHUTDOWN_DRAIN_SECONDS=30

# Shared observability shutdown budget in milliseconds (default: 2000)
FERRUM_LOG_SHUTDOWN_DRAIN_TIMEOUT_MS=2000
```

### Worst-case budget (defaults)

With `FERRUM_SHUTDOWN_DRAIN_SECONDS=30` and the binary defaults above:

| Phase | Budget |
|---|---|
| In-flight drain | 30s |
| Transport pool tail | 6s |
| Background tasks | 5s |
| Audit flush (database/cp) | 30s (`clamp(30, 5, 60)`) |
| Observability delivery | 2s |
| Recommended finalizer slack | 5s |
| **Total** | **78s** |

## Deployment Recommendations

### Kubernetes

Set the pod's `terminationGracePeriodSeconds` to at least the full sequential budget. With the default drain of 30s that is **78s**; the Ferrum gateway Helm chart defaults to **80s** and validates at render time:

```
terminationGracePeriodSeconds >= drain
  + 6   # transport pool tail
  + 5   # background tasks
  + clamp(drain, 5, 60)   # audit flush (database/cp)
  + 2   # observability delivery (default)
  + 5   # finalizer slack
```

```yaml
spec:
  terminationGracePeriodSeconds: 80
  containers:
    - name: ferrum-edge
      env:
        - name: FERRUM_SHUTDOWN_DRAIN_SECONDS
          value: "30"
```

When using the Helm chart, `shutdownDrainSeconds` and `terminationGracePeriodSeconds` are wired together and the guard above is enforced at `helm template` time.

### Load Balancer Integration

1. Remove the gateway from the load balancer's target group (health check fails during drain since `/health` becomes unavailable after listeners close)
2. Wait for the LB to stop sending traffic (typically 1-2 health check intervals)
3. Send SIGTERM to the gateway
4. The gateway drains existing connections for up to `FERRUM_SHUTDOWN_DRAIN_SECONDS`

### Rolling Deploys

For zero-downtime rolling deploys:
- Run multiple gateway instances behind a load balancer
- Deploy one instance at a time
- The drain period ensures no in-flight requests are dropped during the switchover

## Interaction with Overload Manager

During the drain phase, the overload manager's `draining` flag is set, which causes `Connection: close` on all responses. This is independent of the overload manager's `disable_keepalive` action (which is pressure-triggered). Both flags produce the same `Connection: close` behavior — they are OR'd together.

During the drain phase, authenticated `GET /overload` detail reports `draining: true`. Unauthenticated callers still receive only `{"level": ...}` and must not be used for drain-state alerting.
