#!/usr/bin/env bash
# Protocol regression extras: connection churn, long-lived soak with
# RSS/FD/task plateaus, and reload-under-load. Expects release-staged
# ferrum-edge / proto_backend / proto_bench binaries (same layout as
# run_protocol_test.sh --skip-build).
#
# Usage:
#   bash run_protocol_regression_scenarios.sh --output-dir DIR
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$(dirname "$SCRIPT_DIR")")")"
OUTPUT_DIR=""
GATEWAY_HTTP_PORT=8000
GATEWAY_HTTPS_PORT=8443
BACKEND_PID=""
GATEWAY_PID=""
SAMPLER_PID=""
BENCH_PID=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --output-dir) OUTPUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown arg: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
  echo "--output-dir is required" >&2
  exit 2
fi
mkdir -p "$OUTPUT_DIR"

cleanup() {
  [[ -n "${SAMPLER_PID}" ]] && kill "${SAMPLER_PID}" 2>/dev/null || true
  [[ -n "${BENCH_PID}" ]] && kill "${BENCH_PID}" 2>/dev/null || true
  [[ -n "${GATEWAY_PID}" ]] && kill "${GATEWAY_PID}" 2>/dev/null || true
  [[ -n "${BACKEND_PID}" ]] && kill "${BACKEND_PID}" 2>/dev/null || true
  for port in 3001 3010 3443 50052 \
              "${GATEWAY_HTTP_PORT}" "${GATEWAY_HTTPS_PORT}" 5010; do
    lsof -ti:"${port}" 2>/dev/null | xargs kill -9 2>/dev/null || true
  done
}
trap cleanup EXIT

sample_resources() {
  local pid="$1"
  local out="$2"
  local interval="$3"
  : > "${out}"
  while kill -0 "${pid}" 2>/dev/null; do
    local rss=0 fds=0 tasks=0
    if [[ -r "/proc/${pid}/status" ]]; then
      rss="$(awk '/VmRSS:/ {print $2 * 1024}' "/proc/${pid}/status" 2>/dev/null || echo 0)"
      tasks="$(awk '/Threads:/ {print $2}' "/proc/${pid}/status" 2>/dev/null || echo 0)"
    fi
    if [[ -d "/proc/${pid}/fd" ]]; then
      fds="$(ls -1 "/proc/${pid}/fd" 2>/dev/null | wc -l | tr -d ' ')"
    fi
    printf '%s %s %s %s\n' "$(date +%s)" "${rss}" "${fds}" "${tasks}" >> "${out}"
    sleep "${interval}"
  done
}

start_backend() {
  cd "${SCRIPT_DIR}"
  ./target/release/proto_backend > "${OUTPUT_DIR}/backend.log" 2>&1 &
  BACKEND_PID=$!
  for _ in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:3010/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "backend failed to start" >&2
  cat "${OUTPUT_DIR}/backend.log" >&2 || true
  exit 1
}

start_gateway() {
  local config="$1"
  shift
  local cert_dir="${SCRIPT_DIR}/certs"
  for _ in $(seq 1 10); do
    [[ -f "${cert_dir}/ca.pem" && -f "${cert_dir}/cert.pem" ]] && break
    sleep 1
  done

  cd "${PROJECT_ROOT}"
  env \
    FERRUM_MODE=file \
    "FERRUM_FILE_CONFIG_PATH=${config}" \
    "FERRUM_PROXY_HTTP_PORT=${GATEWAY_HTTP_PORT}" \
    "FERRUM_PROXY_HTTPS_PORT=${GATEWAY_HTTPS_PORT}" \
    FERRUM_LOG_LEVEL=error \
    FERRUM_ADD_VIA_HEADER=false \
    FERRUM_ADD_FORWARDED_HEADER=false \
    FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0 \
    FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0 \
    FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0 \
    FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS=0 \
    FERRUM_MAX_CONNECTIONS=0 \
    FERRUM_MAX_HEADER_COUNT=0 \
    FERRUM_MAX_URL_LENGTH_BYTES=0 \
    FERRUM_MAX_QUERY_PARAMS=0 \
    FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120 \
    FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true \
    FERRUM_POOL_CLEANUP_INTERVAL_SECONDS=30 \
    FERRUM_POOL_WARMUP_ENABLED=true \
    FERRUM_TLS_NO_VERIFY=true \
    FERRUM_FRONTEND_TLS_CERT_PATH="${cert_dir}/cert.pem" \
    FERRUM_FRONTEND_TLS_KEY_PATH="${cert_dir}/key.pem" \
    "$@" \
    ./target/release/ferrum-edge > "${OUTPUT_DIR}/gateway.log" 2>&1 &
  GATEWAY_PID=$!
  for _ in $(seq 1 20); do
    if curl -sf "http://127.0.0.1:${GATEWAY_HTTP_PORT}/health" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  echo "gateway failed to start" >&2
  cat "${OUTPUT_DIR}/gateway.log" >&2 || true
  exit 1
}

stop_gateway() {
  if [[ -n "${GATEWAY_PID}" ]]; then
    kill "${GATEWAY_PID}" 2>/dev/null || true
    wait "${GATEWAY_PID}" 2>/dev/null || true
    GATEWAY_PID=""
  fi
  for port in "${GATEWAY_HTTP_PORT}" "${GATEWAY_HTTPS_PORT}" 5010; do
    lsof -ti:"${port}" 2>/dev/null | xargs kill -9 2>/dev/null || true
  done
}

extract_json_object() {
  local path="$1"
  python3 - "$path" <<'PY'
import json, sys
raw = open(sys.argv[1], encoding="utf-8").read()
decoder = json.JSONDecoder()
idx = raw.find("{")
while idx != -1:
    try:
        obj, end = decoder.raw_decode(raw, idx)
        print(json.dumps(obj))
        raise SystemExit(0)
    except json.JSONDecodeError:
        idx = raw.find("{", idx + 1)
raise SystemExit("no JSON object found")
PY
}

echo "== protocol regression scenarios =="
start_backend

# ── Connection churn: force pool/idle churn with max idle disabled ───────────
echo "-- connection churn"
start_gateway \
  "${SCRIPT_DIR}/configs/http1_perf.yaml" \
  FERRUM_POOL_MAX_IDLE_PER_HOST=0 \
  FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=false
"${SCRIPT_DIR}/target/release/proto_bench" http1 \
  --target "http://127.0.0.1:${GATEWAY_HTTP_PORT}/echo" \
  --duration 8 \
  --concurrency 80 \
  --payload-size 1024 \
  --json > "${OUTPUT_DIR}/connection_churn.json" 2>"${OUTPUT_DIR}/connection_churn.log" || true
stop_gateway

# ── Long-lived soak + resource plateau sampling ──────────────────────────────
echo "-- soak + resource plateau"
start_gateway \
  "${SCRIPT_DIR}/configs/http1_tls_perf.yaml" \
  FERRUM_POOL_MAX_IDLE_PER_HOST=200
sample_resources "${GATEWAY_PID}" "${OUTPUT_DIR}/resource_samples.txt" 1 &
SAMPLER_PID=$!
"${SCRIPT_DIR}/target/release/proto_bench" saturate \
  --target "https://127.0.0.1:${GATEWAY_HTTPS_PORT}/echo" \
  --connections 200 \
  --ramp-seconds 5 \
  --hold-seconds 20 \
  --heartbeat-interval-ms 1000 \
  --payload-size 64 \
  --json > "${OUTPUT_DIR}/soak.json" 2>"${OUTPUT_DIR}/soak.log" || true
kill "${SAMPLER_PID}" 2>/dev/null || true
wait "${SAMPLER_PID}" 2>/dev/null || true
SAMPLER_PID=""
stop_gateway

# ── Reload under load (file-mode SIGHUP) ─────────────────────────────────────
echo "-- reload under load"
start_gateway \
  "${SCRIPT_DIR}/configs/http1_perf.yaml" \
  FERRUM_POOL_MAX_IDLE_PER_HOST=200
"${SCRIPT_DIR}/target/release/proto_bench" http1 \
  --target "http://127.0.0.1:${GATEWAY_HTTP_PORT}/echo" \
  --duration 12 \
  --concurrency 50 \
  --payload-size 1024 \
  --json > "${OUTPUT_DIR}/reload_under_load.json" 2>"${OUTPUT_DIR}/reload_under_load.log" &
BENCH_PID=$!
sleep 4
if kill -0 "${GATEWAY_PID}" 2>/dev/null; then
  kill -HUP "${GATEWAY_PID}" || true
  echo "sent SIGHUP to gateway pid=${GATEWAY_PID}"
fi
wait "${BENCH_PID}" || true
BENCH_PID=""
stop_gateway

python3 - "${OUTPUT_DIR}" <<'PY'
import json
import pathlib
import sys

out = pathlib.Path(sys.argv[1])

def load_bench(name: str):
    path = out / name
    if not path.is_file():
        return None
    raw = path.read_text(encoding="utf-8")
    decoder = json.JSONDecoder()
    idx = raw.find("{")
    while idx != -1:
        try:
            obj, _ = decoder.raw_decode(raw, idx)
            return obj
        except json.JSONDecodeError:
            idx = raw.find("{", idx + 1)
    return None

def error_rate(sample):
    if not sample:
        return 1.0
    total = int(sample.get("total_requests", 0)) + int(sample.get("total_errors", 0))
    if total <= 0:
        # saturate reports connect/heartbeat rates instead of request totals
        if "heartbeat_success_rate" in sample:
            return 1.0 - float(sample.get("heartbeat_success_rate", 0.0))
        return 1.0
    return float(sample.get("total_errors", 0)) / float(total)

rss, fds, tasks = [], [], []
sample_path = out / "resource_samples.txt"
if sample_path.is_file():
    for line in sample_path.read_text(encoding="utf-8").splitlines():
        parts = line.split()
        if len(parts) != 4:
            continue
        _, rss_v, fd_v, task_v = parts
        rss.append(int(float(rss_v)))
        fds.append(int(float(fd_v)))
        tasks.append(int(float(task_v)))

churn = load_bench("connection_churn.json")
reload_sample = load_bench("reload_under_load.json")
soak = load_bench("soak.json")

scenarios = {
    "connection_churn": {
        "error_rate": error_rate(churn),
        "sample": churn,
    },
    "reload_under_load": {
        "error_rate": error_rate(reload_sample),
        "sample": reload_sample,
    },
    "soak": {
        "sample": soak,
    },
    "resource_plateau": {
        "rss_bytes": rss,
        "fd_count": fds,
        "task_count": tasks,
        "sample_count": len(rss),
    },
}
(out / "scenarios.json").write_text(json.dumps(scenarios, indent=2) + "\n", encoding="utf-8")
print(json.dumps({"scenarios_written": str(out / "scenarios.json"), "sample_count": len(rss)}))
PY

echo "scenarios complete"
