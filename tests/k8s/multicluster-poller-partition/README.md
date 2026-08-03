# Multicluster poller partition live gate

This fixture is the poller-driven companion to `multicluster-federation`. The
older suite remains unchanged and proves static SPIRE federation plus the
east-west datapath. This suite creates two disposable kind clusters, each with
a real Ferrum control plane, a real Ferrum mesh data plane, SPIRE, a local echo
workload, and an HTTPS federation-bundle endpoint.

Four TCP passthroughs in a uniquely named Toxiproxy container keep the fault
domains independent:

| Link | Consumer | Upstream | Faulted independently |
|---|---|---|---|
| `federation-a-to-b` | DP A trust poller | B HTTPS bundle endpoint | yes |
| `discovery-a-to-b` | DP A native remote-discovery poller | B Ferrum CP | yes |
| `federation-b-to-a` | DP B trust poller | A HTTPS bundle endpoint | yes |
| `discovery-b-to-a` | DP B native remote-discovery poller | A Ferrum CP | yes |

Toxiproxy is attached to the kind Docker network. The transport certificate
has its unique container IP as an IP SAN. Federation uses verified HTTPS;
native discovery uses verified gRPC TLS plus a client certificate, a distinct
per-cluster HS256 secret selected through `discovery_credential_ref`, and the
peer CP's `ferrum-mesh-discovery:<cluster>` audience. No skip-verify or
plaintext transport is enabled.

The fixture uses test-only 8-second endpoint and 12-second trust stale windows.
Every transition is condition-polled with an explicit deadline. It records
named JSON and Prometheus evidence at initial install, transient retention,
independent endpoint expiry/recovery, trust expiry/recovery, and in-flight
withdrawal. It also proves failure-series cardinality is bounded, endpoint and
control-plane labels are redacted, and admin cache ages agree with Prometheus.

The withdrawal boundary adds 20 seconds of downstream latency, observes
Toxiproxy byte movement to prove both polls are in flight, removes A's
`RemoteCluster`, sends SIGHUP through the shared process namespace, then
releases the fault. The retired generations must not reinstall trust,
endpoints, or freshness metrics.

Hosted CI owns execution. For an intentionally disposable local lab, the entry
point is:

```bash
FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true \
  tests/k8s/multicluster-poller-partition/run.sh
```

Cluster and Toxiproxy names must be unique. The script refuses pre-existing
names, hard-fails incomplete fault-layer startup, captures only redacted
topology diagnostics, and deletes both clusters and the fault container on
exit. GitHub Actions injects `run_id` and `run_attempt` into every name so
parallel and repeated runs cannot share state or ports.
