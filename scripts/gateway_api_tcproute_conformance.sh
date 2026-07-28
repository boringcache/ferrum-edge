#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"

# Live TCPRoute black-box listeners (Gateway listener port == DP stream listen_port).
# Host ports map through kind NodePorts so CI can dial without in-cluster clients.
TCP_BLACKBOX_PORT_MAIN="${TCP_BLACKBOX_PORT_MAIN:-9001}"
TCP_BLACKBOX_PORT_CROSS="${TCP_BLACKBOX_PORT_CROSS:-9002}"
TCP_BLACKBOX_PORT_FAIL="${TCP_BLACKBOX_PORT_FAIL:-9003}"
TCP_BLACKBOX_PORT_DELETE="${TCP_BLACKBOX_PORT_DELETE:-9004}"
TCP_BLACKBOX_NODEPORT_MAIN="${TCP_BLACKBOX_NODEPORT_MAIN:-30901}"
TCP_BLACKBOX_NODEPORT_CROSS="${TCP_BLACKBOX_NODEPORT_CROSS:-30902}"
TCP_BLACKBOX_NODEPORT_FAIL="${TCP_BLACKBOX_NODEPORT_FAIL:-30903}"
TCP_BLACKBOX_NODEPORT_DELETE="${TCP_BLACKBOX_NODEPORT_DELETE:-30904}"
TCP_ECHO_BACKEND_PORT="${TCP_ECHO_BACKEND_PORT:-9090}"

DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
BACKEND_NAMESPACE="${BACKEND_NAMESPACE:-gateway-conformance-web-backend}"

apply_tcp_blackbox_backends() {
  cat <<YAML | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-tcp-a
  namespace: gateway-conformance-infra
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-tcp-a
  template:
    metadata:
      labels:
        app: blackbox-tcp-a
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: blackbox-tcp-a
            - name: LISTEN_PORT
              value: "${TCP_ECHO_BACKEND_PORT}"
          command: ["python", "-c"]
          args:
            - |
              import os, socket
              name = os.environ["BACKEND_NAME"].encode()
              port = int(os.environ["LISTEN_PORT"])
              srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              srv.bind(("", port))
              srv.listen()
              print(f"tcp echo {name.decode()} on {port}", flush=True)
              while True:
                  conn, _ = srv.accept()
                  with conn:
                      data = b""
                      while True:
                          chunk = conn.recv(4096)
                          if not chunk:
                              break
                          data += chunk
                          if len(data) >= 65536:
                              break
                      conn.sendall(name + b":" + data)
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-tcp-a
  namespace: gateway-conformance-infra
spec:
  selector:
    app: blackbox-tcp-a
  ports:
    - name: tcp
      port: ${TCP_ECHO_BACKEND_PORT}
      targetPort: ${TCP_ECHO_BACKEND_PORT}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-tcp-b
  namespace: gateway-conformance-infra
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-tcp-b
  template:
    metadata:
      labels:
        app: blackbox-tcp-b
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: blackbox-tcp-b
            - name: LISTEN_PORT
              value: "${TCP_ECHO_BACKEND_PORT}"
          command: ["python", "-c"]
          args:
            - |
              import os, socket
              name = os.environ["BACKEND_NAME"].encode()
              port = int(os.environ["LISTEN_PORT"])
              srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              srv.bind(("", port))
              srv.listen()
              print(f"tcp echo {name.decode()} on {port}", flush=True)
              while True:
                  conn, _ = srv.accept()
                  with conn:
                      data = b""
                      while True:
                          chunk = conn.recv(4096)
                          if not chunk:
                              break
                          data += chunk
                          if len(data) >= 65536:
                              break
                      conn.sendall(name + b":" + data)
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-tcp-b
  namespace: gateway-conformance-infra
spec:
  selector:
    app: blackbox-tcp-b
  ports:
    - name: tcp
      port: ${TCP_ECHO_BACKEND_PORT}
      targetPort: ${TCP_ECHO_BACKEND_PORT}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-tcp-cross
  namespace: gateway-conformance-web-backend
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-tcp-cross
  template:
    metadata:
      labels:
        app: blackbox-tcp-cross
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: blackbox-tcp-cross
            - name: LISTEN_PORT
              value: "${TCP_ECHO_BACKEND_PORT}"
          command: ["python", "-c"]
          args:
            - |
              import os, socket
              name = os.environ["BACKEND_NAME"].encode()
              port = int(os.environ["LISTEN_PORT"])
              srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              srv.bind(("", port))
              srv.listen()
              print(f"tcp echo {name.decode()} on {port}", flush=True)
              while True:
                  conn, _ = srv.accept()
                  with conn:
                      data = b""
                      while True:
                          chunk = conn.recv(4096)
                          if not chunk:
                              break
                          data += chunk
                          if len(data) >= 65536:
                              break
                      conn.sendall(name + b":" + data)
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-tcp-cross
  namespace: gateway-conformance-web-backend
spec:
  selector:
    app: blackbox-tcp-cross
  ports:
    - name: tcp
      port: ${TCP_ECHO_BACKEND_PORT}
      targetPort: ${TCP_ECHO_BACKEND_PORT}
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-tcp-empty
  namespace: gateway-conformance-infra
spec:
  ports:
    - name: tcp
      port: ${TCP_ECHO_BACKEND_PORT}
      targetPort: ${TCP_ECHO_BACKEND_PORT}
YAML
}
apply_tcp_blackbox_routes() {
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-tcp
  namespace: gateway-conformance-infra
spec:
  gatewayClassName: ferrum
  listeners:
    - name: tcp-main
      port: ${TCP_BLACKBOX_PORT_MAIN}
      protocol: TCP
      allowedRoutes:
        kinds:
          - kind: TCPRoute
        namespaces:
          from: Same
    - name: tcp-cross
      port: ${TCP_BLACKBOX_PORT_CROSS}
      protocol: TCP
      allowedRoutes:
        kinds:
          - kind: TCPRoute
        namespaces:
          from: Same
    - name: tcp-fail
      port: ${TCP_BLACKBOX_PORT_FAIL}
      protocol: TCP
      allowedRoutes:
        kinds:
          - kind: TCPRoute
        namespaces:
          from: Same
    - name: tcp-delete
      port: ${TCP_BLACKBOX_PORT_DELETE}
      protocol: TCP
      allowedRoutes:
        kinds:
          - kind: TCPRoute
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: blackbox-tcp-main
  namespace: gateway-conformance-infra
spec:
  parentRefs:
    - name: ferrum-blackbox-tcp
      sectionName: tcp-main
  rules:
    - backendRefs:
        - name: blackbox-tcp-a
          port: ${TCP_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: blackbox-tcp-cross
  namespace: gateway-conformance-infra
spec:
  parentRefs:
    - name: ferrum-blackbox-tcp
      sectionName: tcp-cross
  rules:
    - backendRefs:
        - name: blackbox-tcp-cross
          namespace: gateway-conformance-web-backend
          port: ${TCP_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-infra-tcproute-to-blackbox-tcp-cross
  namespace: gateway-conformance-web-backend
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: TCPRoute
      namespace: gateway-conformance-infra
  to:
    - group: ""
      kind: Service
      name: blackbox-tcp-cross
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: blackbox-tcp-fail
  namespace: gateway-conformance-infra
spec:
  parentRefs:
    - name: ferrum-blackbox-tcp
      sectionName: tcp-fail
  rules:
    - backendRefs:
        - name: blackbox-tcp-empty
          port: ${TCP_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: blackbox-tcp-delete
  namespace: gateway-conformance-infra
spec:
  parentRefs:
    - name: ferrum-blackbox-tcp
      sectionName: tcp-delete
  rules:
    - backendRefs:
        - name: blackbox-tcp-a
          port: ${TCP_ECHO_BACKEND_PORT}
YAML
}

tcp_exchange() {
  local host="$1"
  local port="$2"
  local payload="$3"
  python3 - "$host" "$port" "$payload" <<'PY'
import socket
import sys

host, port_s, payload = sys.argv[1], sys.argv[2], sys.argv[3].encode()
port = int(port_s)
with socket.create_connection((host, port), timeout=5) as sock:
    sock.sendall(payload)
    sock.shutdown(socket.SHUT_WR)
    chunks = []
    while True:
        chunk = sock.recv(4096)
        if not chunk:
            break
        chunks.append(chunk)
sys.stdout.buffer.write(b"".join(chunks))
PY
}

wait_for_tcp_echo() {
  local port="$1"
  local expected_prefix="$2"
  local payload="${3:-ping}"
  local body=""
  for _ in $(seq 1 60); do
    if body="$(tcp_exchange 127.0.0.1 "$port" "$payload" 2>/dev/null)" \
      && grep -q "^${expected_prefix}:" <<<"$body" \
      && grep -q "$payload" <<<"$body"; then
      printf '%s\n' "$body"
      return 0
    fi
    sleep 2
  done
  echo "expected TCP :${port} echo prefixed with ${expected_prefix} for payload ${payload}; last body=${body}" >&2
  return 1
}

assert_tcp_exchange_fails() {
  local port="$1"
  local label="$2"
  local body=""
  if body="$(tcp_exchange 127.0.0.1 "$port" "should-fail" 2>/dev/null)"; then
    if grep -qE '^blackbox-tcp-(a|b|cross):' <<<"$body"; then
      echo "${label}: unexpected successful TCP echo on :${port}: ${body}" >&2
      return 1
    fi
    # Accepted-then-reset/empty responses are still fail-closed (no backend echo).
    echo "${label}: TCP :${port} produced no successful backend echo"
    return 0
  fi
  echo "${label}: TCP :${port} connection failed closed"
  return 0
}

wait_for_tcproute_parent_condition() {
  local name="$1"
  local condition_type="$2"
  local expected_status="$3"
  local status=""
  for _ in $(seq 1 60); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get tcproute "$name" -o jsonpath="{.status.parents[0].conditions[?(@.type==\"${condition_type}\")].status}" 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ]; then
      echo "TCPRoute ${name} ${condition_type}=${status}"
      return 0
    fi
    sleep 2
  done
  echo "TCPRoute ${name} did not reach ${condition_type}=${expected_status} (got '${status}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get tcproute "$name" -o yaml >&2 || true
  return 1
}

wait_for_gateway_listener_attached_routes() {
  local gateway="$1"
  local listener="$2"
  local minimum="$3"
  local attached=""
  for _ in $(seq 1 60); do
    attached="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get gateway "$gateway" -o jsonpath="{.status.listeners[?(@.name==\"${listener}\")].attachedRoutes}" 2>/dev/null || true)"
    if [ -n "$attached" ] && [ "$attached" -ge "$minimum" ]; then
      echo "Gateway ${gateway} listener ${listener} attachedRoutes=${attached}"
      return 0
    fi
    sleep 2
  done
  echo "Gateway ${gateway} listener ${listener} attachedRoutes stayed below ${minimum} (got '${attached}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get gateway "$gateway" -o yaml >&2 || true
  return 1
}

run_tcp_blackbox_tests() {
  local report="$1"
  echo "" >> "$report"
  echo "## TCPRoute live data-plane" >> "$report"

  apply_tcp_blackbox_routes

  wait_for_tcproute_parent_condition blackbox-tcp-main Accepted True | tee -a "$report"
  wait_for_tcproute_parent_condition blackbox-tcp-main ResolvedRefs True | tee -a "$report"
  wait_for_tcproute_parent_condition blackbox-tcp-main Programmed True | tee -a "$report"
  wait_for_gateway_listener_attached_routes ferrum-blackbox-tcp tcp-main 1 | tee -a "$report"

  wait_for_tcp_echo "$TCP_BLACKBOX_PORT_MAIN" "blackbox-tcp-a" "main-ping" | tee -a "$report"
  echo "TCPRoute parent/listener attachment served tagged echo on :${TCP_BLACKBOX_PORT_MAIN}" >> "$report"

  wait_for_tcproute_parent_condition blackbox-tcp-cross Accepted True | tee -a "$report"
  wait_for_tcproute_parent_condition blackbox-tcp-cross ResolvedRefs True | tee -a "$report"
  wait_for_tcproute_parent_condition blackbox-tcp-cross Programmed True | tee -a "$report"
  wait_for_tcp_echo "$TCP_BLACKBOX_PORT_CROSS" "blackbox-tcp-cross" "cross-ping" | tee -a "$report"
  echo "TCPRoute cross-namespace backendRef with ReferenceGrant served echo on :${TCP_BLACKBOX_PORT_CROSS}" >> "$report"

  # Empty Service endpoints must fail closed (no successful tagged echo).
  wait_for_tcproute_parent_condition blackbox-tcp-fail Accepted True | tee -a "$report"
  assert_tcp_exchange_fails "$TCP_BLACKBOX_PORT_FAIL" "empty TCP backend endpoints" | tee -a "$report"
  echo "TCPRoute empty-endpoint backend failed closed on :${TCP_BLACKBOX_PORT_FAIL}" >> "$report"

  # Missing Service backendRef: replace the fail route and require fail-closed traffic.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tcproute blackbox-tcp-fail --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: blackbox-tcp-invalid
  namespace: gateway-conformance-infra
spec:
  parentRefs:
    - name: ferrum-blackbox-tcp
      sectionName: tcp-fail
  rules:
    - backendRefs:
        - name: blackbox-tcp-missing
          port: ${TCP_ECHO_BACKEND_PORT}
YAML
  sleep 5
  assert_tcp_exchange_fails "$TCP_BLACKBOX_PORT_FAIL" "missing TCP backend Service" | tee -a "$report"
  echo "TCPRoute missing backend Service failed closed on :${TCP_BLACKBOX_PORT_FAIL}" >> "$report"

  # Cross-namespace backendRef without ReferenceGrant must fail closed.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tcproute blackbox-tcp-invalid --wait=true
  kubectl -n "$BACKEND_NAMESPACE" delete referencegrant allow-infra-tcproute-to-blackbox-tcp-cross --ignore-not-found --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TCPRoute
metadata:
  name: blackbox-tcp-denied
  namespace: gateway-conformance-infra
spec:
  parentRefs:
    - name: ferrum-blackbox-tcp
      sectionName: tcp-fail
  rules:
    - backendRefs:
        - name: blackbox-tcp-cross
          namespace: gateway-conformance-web-backend
          port: ${TCP_ECHO_BACKEND_PORT}
YAML
  # Translation rejects unpermitted refs fail-closed; wait for status and refuse echo.
  for _ in $(seq 1 30); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get tcproute blackbox-tcp-denied -o jsonpath='{.status.parents[0].conditions[?(@.type=="ResolvedRefs")].status}' 2>/dev/null || true)"
    if [ "$status" = "False" ]; then
      break
    fi
    sleep 2
  done
  if [ "${status:-}" = "False" ]; then
    echo "TCPRoute denied cross-namespace backendRef reported ResolvedRefs=False" | tee -a "$report"
  else
    echo "TCPRoute denied cross-namespace backendRef status ResolvedRefs='${status:-}' (traffic still must fail closed)" | tee -a "$report"
  fi
  assert_tcp_exchange_fails "$TCP_BLACKBOX_PORT_FAIL" "unpermitted cross-namespace TCP backendRef" | tee -a "$report"
  echo "TCPRoute unpermitted cross-namespace backendRef failed closed on :${TCP_BLACKBOX_PORT_FAIL}" >> "$report"

  wait_for_tcp_echo "$TCP_BLACKBOX_PORT_MAIN" "blackbox-tcp-a" "pre-update" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch tcproute blackbox-tcp-main --type=json \
    -p='[{"op":"replace","path":"/spec/rules/0/backendRefs/0/name","value":"blackbox-tcp-b"}]'
  wait_for_tcp_echo "$TCP_BLACKBOX_PORT_MAIN" "blackbox-tcp-b" "post-update" | tee -a "$report"
  echo "TCPRoute update switched live traffic to blackbox-tcp-b on :${TCP_BLACKBOX_PORT_MAIN}" >> "$report"

  wait_for_tcp_echo "$TCP_BLACKBOX_PORT_DELETE" "blackbox-tcp-a" "pre-delete" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tcproute blackbox-tcp-delete --wait=true
  local delete_ok=0
  for _ in $(seq 1 30); do
    if ! tcp_exchange 127.0.0.1 "$TCP_BLACKBOX_PORT_DELETE" "post-delete" >/dev/null 2>&1; then
      delete_ok=1
      break
    fi
    sleep 2
  done
  if [ "$delete_ok" -ne 1 ]; then
    echo "deleted TCPRoute kept serving TCP echo on :${TCP_BLACKBOX_PORT_DELETE}" >&2
    return 1
  fi
  echo "deleted TCPRoute stopped serving on :${TCP_BLACKBOX_PORT_DELETE}" >> "$report"
}

run_blackbox() {
  local report="$RESULTS_DIR/gateway-api-blackbox.md"
  apply_tcp_blackbox_backends
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-tcp-a --timeout=180s
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-tcp-b --timeout=180s
  kubectl -n "$BACKEND_NAMESPACE" rollout status deployment/blackbox-tcp-cross --timeout=180s
  run_tcp_blackbox_tests "$report"
}

collect_diagnostics() {
  set +e
  kubectl get gatewayclasses,gateways,httproutes,grpcroutes,tcproutes,referencegrants -A -o yaml > "$RESULTS_DIR/gateway-api-resources.yaml"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-tcp-a --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tcp-a.log"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-tcp-b --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tcp-b.log"
  kubectl -n "$BACKEND_NAMESPACE" logs deployment/blackbox-tcp-cross --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tcp-cross.log"
  {
    echo ""
    echo "TCPRoute black-box ports: ${TCP_BLACKBOX_PORT_MAIN},${TCP_BLACKBOX_PORT_CROSS},${TCP_BLACKBOX_PORT_FAIL},${TCP_BLACKBOX_PORT_DELETE}"
  } >> "$RESULTS_DIR/CONFORMANCE.md"
}

case "${1:-}" in
  blackbox) run_blackbox ;;
  diagnostics) collect_diagnostics ;;
  *)
    echo "usage: $0 {blackbox|diagnostics}" >&2
    exit 2
    ;;
esac
