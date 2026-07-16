# Service Integration Tests

Functional integration tests for Ferrum's **external-middleware integrations** —
the code paths that can only be validated against the **real third-party
software** (a service registry, a directory server, …). Each backend runs as a
local container via [`testcontainers`](https://docs.rs/testcontainers) (Docker)
using free, open-source images. No managed or cloud service is ever involved,
and every fixture seeds its own fully-controlled data so the assertions are
deterministic.

This is its own `[[test]]` crate (declared in the root `Cargo.toml`, entry point
`mod.rs`), mirroring `tests/secrets_functional/`. It is **not** part of the
default unit/integration/functional suites; CI runs it as the dedicated
`test-service-integration` job.

## Why this suite exists

These integrations were previously only *config-validated* or only tested on
their *failure* path, leaving the real client logic uncovered:

| Backend | Code under test | Previous coverage | This suite adds |
| --- | --- | --- | --- |
| **Consul** (`src/service_discovery/consul.rs`) | `ConsulDiscoverer::discover()` — health-API JSON parsing | inline unit tests covered only `build_url()` | live Consul: Service-vs-Node address fallback, port/weight/tag extraction, `passing=true` health filter, per-tag filtering, unknown-service empty result |
| **LDAP** (`src/plugins/ldap_auth.rs`) | `ldap3` bind / search-then-bind / group membership, via `create_plugin` → `authenticate` | functional test only pointed the plugin at an *unreachable* server (500 / 401 paths) | live OpenLDAP: valid/invalid direct bind, search-then-bind, group-membership allow (Continue) vs deny (403) |

## Running locally

```bash
# All backends
cargo test --test service_integration

# One backend (the test-name filter selects the module)
cargo test --test service_integration consul
cargo test --test service_integration ldap
```

**With Docker:** the containers start and the assertions run.
**Without Docker:** each test prints `SKIP <test>: <service> unavailable …` and
returns green — the suite stays runnable on a developer machine with no Docker.

The skip/fail decision lives in `common::containers::fail_in_ci_else_skip`: in CI
(`CI` env var set, which GitHub Actions sets automatically) a container that
fails to start is a **hard failure**, so a broken image/setup fails the job
rather than silently passing.

## Container images (free / OSS)

| Backend | Image | Notes |
| --- | --- | --- |
| Consul | `hashicorp/consul:1.19` | `agent -dev`; readiness polled via `/v1/status/leader` |
| OpenLDAP | `osixia/openldap:1.5.0` | base `dc=example,dc=org`; test tree seeded via `ldapadd` exec (readiness handled by retry) |

Readiness is confirmed by **active polling** (Consul leader endpoint; LDAP
`ldapadd` retry), not by matching a startup log line — so the helpers do not
depend on which stream a given image logs to.

## CI

`.github/workflows/ci.yml` job `test-service-integration` runs on
`ubuntu-latest` (Docker available). Consul and LDAP run in one nextest
`--no-fail-fast` invocation, which preserves per-test reporting and continues
after one backend fails without allocating a second runner. It is wired into
the `test` aggregation gate, so it blocks merge on failure.

## Adding another external service

The high-value gaps closed here are the first wave. The same pattern extends to
the rest; follow `common/containers.rs` (and `tests/secrets_functional/` for the
cloud-SDK variant):

1. Add a `start_<svc>_container()` (+ a small fixture struct) to
   `common/containers.rs`. Prefer **active readiness polling** over a log-line
   wait. Seed fixtures via the container's API or an `exec` (see the Consul
   register helper and the LDAP `ldapadd` seeder).
2. Add a `<svc>.rs` module and register it in `mod.rs`.
3. Drive the **real** code: construct the plugin via
   `ferrum_edge::plugins::create_plugin(name, &config)` and call the relevant
   `Plugin` hook (`authenticate` / `log` / …), or call the integration type
   directly (as `ConsulDiscoverer` is here).
4. Add the module filter to the `test-service-integration` nextest invocation;
   the existing job row in the `test` gate summary covers the expanded suite.

### Candidates / roadmap

- **Kafka** (`kafka_logging`, `rdkafka` producer) — broker publish is untested.
  Use `apache/kafka` (KRaft, no ZooKeeper). The one wrinkle is the dynamic
  advertised-listener / host-port mapping (the broker must advertise the
  host-mapped port to the client); pin the host port for the dedicated matrix
  shard, or replicate the testcontainers-java startup-script approach. Verify
  against a real broker before landing — it is the trickiest of the set.
- **OIDC relying party / OAuth2 introspection** — login/session/introspection
  flows. Use `ory/hydra` or `keycloak`.

### Better served by in-process fakes (no container)

The observability sinks send over simple wire protocols, so an in-process fake
is more robust (and runs without Docker) than a full container — these belong in
`tests/integration/`, not here:

- **StatsD** (`statsd_logging`, UDP) — bind a `UdpSocket`, point the plugin at
  it, call `log()`, assert the received datagram's metric line format.
- **Loki / HTTP-style sinks** (`loki_logging`, `http_logging`) — receive the
  push with `wiremock` (already a dev-dependency) and assert the payload.
- **TCP sinks** (`tcp_logging`) — accept on a `TcpListener` and assert the
  framed bytes.
