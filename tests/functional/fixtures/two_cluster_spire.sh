#!/usr/bin/env bash
set -euo pipefail

# Minimal process-local SPIRE harness for the privileged two-cluster netns test.
# It deliberately uses join-token node attestation and the unix workload
# attestor: the fixture is validating Ferrum's live Workload API consumption,
# federated bundles, and cross-cluster datapath, not Kubernetes attestation.

command_name="${1:-}"
shift || true

wait_for_socket() {
  local socket="$1" label="$2"
  for _ in $(seq 1 100); do
    [[ -S "$socket" ]] && return 0
    sleep 0.1
  done
  echo "$label socket did not appear: $socket" >&2
  return 1
}

server_cli() {
  local root="$1"
  shift
  spire-server "$@" -socketPath "$root/server.sock"
}

case "$command_name" in
  start)
    root="${1:?root directory is required}"
    trust_domain="${2:?trust domain is required}"
    server_port="${3:?server port is required}"
    mkdir -p "$root/server-data" "$root/agent-data"
    chmod 0755 "$root"

    cat >"$root/server.conf" <<EOF
server {
  bind_address = "127.0.0.1"
  bind_port = "$server_port"
  socket_path = "$root/server.sock"
  trust_domain = "$trust_domain"
  data_dir = "$root/server-data"
  log_level = "DEBUG"
}
plugins {
  DataStore "sql" {
    plugin_data {
      database_type = "sqlite3"
      connection_string = "$root/server-data/datastore.sqlite3"
    }
  }
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "disk" {
    plugin_data { keys_path = "$root/server-data/keys.json" }
  }
}
EOF

    spire-server run -config "$root/server.conf" >"$root/server.log" 2>&1 &
    echo "$!" >"$root/server.pid"
    wait_for_socket "$root/server.sock" "SPIRE server"
    server_cli "$root" bundle show -format pem >"$root/bundle.pem"

    agent_id="spiffe://$trust_domain/spire/agent/netns-live"
    token="$(server_cli "$root" token generate -spiffeID "$agent_id" | awk '/Token:/ {print $2; exit}')"
    [[ -n "$token" ]] || {
      echo "SPIRE join token generation returned no token" >&2
      exit 1
    }

    cat >"$root/agent.conf" <<EOF
agent {
  data_dir = "$root/agent-data"
  log_level = "DEBUG"
  server_address = "127.0.0.1"
  server_port = "$server_port"
  socket_path = "$root/agent.sock"
  trust_domain = "$trust_domain"
  trust_bundle_path = "$root/bundle.pem"
}
plugins {
  NodeAttestor "join_token" { plugin_data {} }
  KeyManager "memory" { plugin_data {} }
  WorkloadAttestor "unix" { plugin_data {} }
}
EOF

    spire-agent run -config "$root/agent.conf" -joinToken "$token" >"$root/agent.log" 2>&1 &
    echo "$!" >"$root/agent.pid"
    wait_for_socket "$root/agent.sock" "SPIRE agent"
    chmod 0777 "$root/agent.sock"
    ;;

  federate)
    root_a="${1:?cluster A root is required}"
    td_a="${2:?cluster A trust domain is required}"
    root_b="${3:?cluster B root is required}"
    td_b="${4:?cluster B trust domain is required}"
    server_cli "$root_a" bundle show -format spiffe >"$root_a/bundle.spiffe"
    server_cli "$root_b" bundle show -format spiffe >"$root_b/bundle.spiffe"
    server_cli "$root_b" bundle set -format spiffe -id "spiffe://$td_a" <"$root_a/bundle.spiffe"
    server_cli "$root_a" bundle set -format spiffe -id "spiffe://$td_b" <"$root_b/bundle.spiffe"
    server_cli "$root_a" bundle list -id "spiffe://$td_b" -format spiffe >/dev/null
    server_cli "$root_b" bundle list -id "spiffe://$td_a" -format spiffe >/dev/null
    ;;

  register)
    root="${1:?root directory is required}"
    trust_domain="${2:?trust domain is required}"
    workload_id="${3:?workload SPIFFE ID is required}"
    peer_domain="${4:-}"
    args=(entry create
      -parentID "spiffe://$trust_domain/spire/agent/netns-live"
      -spiffeID "$workload_id"
      -selector unix:uid:1337)
    if [[ -n "$peer_domain" ]]; then
      args+=(-federatesWith "spiffe://$peer_domain")
    fi
    server_cli "$root" "${args[@]}"
    ;;

  stop)
    root="${1:?root directory is required}"
    for name in agent server; do
      if [[ -f "$root/$name.pid" ]]; then
        pid="$(cat "$root/$name.pid")"
        kill -TERM "$pid" 2>/dev/null || true
        for _ in $(seq 1 20); do
          kill -0 "$pid" 2>/dev/null || break
          sleep 0.1
        done
        kill -KILL "$pid" 2>/dev/null || true
      fi
    done
    ;;

  *)
    echo "usage: $0 {start|federate|register|stop} ..." >&2
    exit 2
    ;;
esac
