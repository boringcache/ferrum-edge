#!/usr/bin/env bash
set -euo pipefail

# Run after run.sh with FERRUM_LIVE_KEEP_RESOURCES=true. This deliberately
# makes one connection from an enrolled workload to the chart's excluded
# port 15020, then proves that the connect4 producer reached the userspace
# consumer and the __mesh_bpf_metrics exporter on the same node.

MESH_NS="${FERRUM_LIVE_MESH_NAMESPACE:-ferrum}"
WORKLOAD_NS="${FERRUM_LIVE_WORKLOAD_NAMESPACE:-ferrum-ebpf-live}"
AMBIENT_ADMIN_PORT="${FERRUM_LIVE_AMBIENT_ADMIN_PORT:-19010}"
ADMIN_JWT_SECRET="${FERRUM_LIVE_ADMIN_JWT_SECRET:-ferrum-edge-node-waypoint-live-admin-secret}"
ADMIN_JWT_ISSUER="${FERRUM_LIVE_ADMIN_JWT_ISSUER:-ferrum-edge}"
RESULTS_DIR="${FERRUM_LIVE_RESULTS_DIR:-target/node-waypoint-ebpf-live}/mesh-bpf-metrics"
LOCAL_PORT="${FERRUM_LIVE_BPF_METRICS_LOCAL_PORT:-19450}"

mkdir -p "$RESULTS_DIR"

source_pod="$(
  kubectl -n "$WORKLOAD_NS" get pod -l app=src-a \
    -o jsonpath='{.items[0].metadata.name}'
)"
source_node="$(
  kubectl -n "$WORKLOAD_NS" get "pod/$source_pod" \
    -o jsonpath='{.spec.nodeName}'
)"
ambient_pod="$(
  kubectl -n "$MESH_NS" get pod \
    -l app.kubernetes.io/name=ferrum-mesh-ambient \
    --field-selector "spec.nodeName=$source_node" \
    -o jsonpath='{.items[0].metadata.name}'
)"

if [[ -z "$source_pod" || -z "$source_node" || -z "$ambient_pod" ]]; then
  echo "could not resolve the source workload and same-node ambient proxy" >&2
  exit 1
fi

token="$(
  python3 - "$ADMIN_JWT_SECRET" "$ADMIN_JWT_ISSUER" <<'PY'
import base64
import hashlib
import hmac
import json
import sys
import time
import uuid

secret, issuer = sys.argv[1], sys.argv[2]
now = int(time.time())

def b64url(value):
    raw = json.dumps(value, separators=(",", ":"), sort_keys=True).encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

header = {"alg": "HS256", "typ": "JWT"}
claims = {
    "iss": issuer,
    "sub": "node-waypoint-ebpf-live",
    "iat": now,
    "nbf": now - 1,
    "exp": now + 600,
    "jti": str(uuid.uuid4()),
    "role": "admin",
}
signing_input = f"{b64url(header)}.{b64url(claims)}"
signature = hmac.new(secret.encode(), signing_input.encode(), hashlib.sha256).digest()
print(f"{signing_input}.{base64.urlsafe_b64encode(signature).rstrip(b'=').decode()}")
PY
)"

port_forward_log="$RESULTS_DIR/port-forward.log"
kubectl -n "$MESH_NS" port-forward \
  "pod/$ambient_pod" "$LOCAL_PORT:$AMBIENT_ADMIN_PORT" \
  >"$port_forward_log" 2>&1 &
port_forward_pid=$!
cleanup() {
  kill "$port_forward_pid" 2>/dev/null || true
  wait "$port_forward_pid" 2>/dev/null || true
}
trap cleanup EXIT

scrape_metrics() {
  local destination="$1"
  curl -fsS -H "Authorization: Bearer $token" \
    "http://127.0.0.1:$LOCAL_PORT/metrics" >"$destination"
}

before_file="$RESULTS_DIR/before.prom"
fetched=false
for _ in $(seq 1 30); do
  if scrape_metrics "$before_file"; then
    fetched=true
    break
  fi
  sleep 0.5
done
if [[ "$fetched" != "true" ]]; then
  echo "failed to fetch same-node ambient metrics before the bypass" >&2
  cat "$port_forward_log" >&2 || true
  exit 1
fi

metric='ferrum_mesh_bpf_drops_total{reason="exclude_port_hit"}'
metric_value() {
  local file="$1"
  awk -v metric="$metric" '$1 == metric { value = $2 } END { print value }' "$file"
}

before="$(metric_value "$before_file")"
if [[ ! "$before" =~ ^[0-9]+$ ]]; then
  echo "missing integer $metric baseline in ambient metrics" >&2
  grep 'ferrum_mesh_bpf_drops_total' "$before_file" >&2 || true
  exit 1
fi

# The connection is expected to fail because nothing listens on the excluded
# telemetry port. The connect4 hook emits exclude_port_hit before preserving
# the original destination, so the failed dial is still a real bypass event.
kubectl -n "$WORKLOAD_NS" exec "pod/$source_pod" -- \
  curl -fsS --connect-timeout 1 --max-time 1 \
  http://127.0.0.1:15020/ >/dev/null 2>&1 || true

after_file="$RESULTS_DIR/after.prom"
after="$before"
for _ in $(seq 1 30); do
  if scrape_metrics "$after_file"; then
    candidate="$(metric_value "$after_file")"
    if [[ "$candidate" =~ ^[0-9]+$ ]]; then
      after="$candidate"
      if ((after > before)); then
        break
      fi
    fi
  fi
  sleep 0.5
done

if ((after <= before)); then
  echo "expected $metric to increase after a real excluded-port connection; before=$before after=$after" >&2
  grep 'ferrum_mesh_bpf_drops_total' "$after_file" >&2 || true
  exit 1
fi

printf 'source_pod=%s\nsource_node=%s\nambient_pod=%s\nmetric=%s\nbefore=%s\nafter=%s\n' \
  "$source_pod" "$source_node" "$ambient_pod" "$metric" "$before" "$after" \
  >"$RESULTS_DIR/assertion.txt"
