#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"

# Live TLSRoute black-box listeners (Gateway TLS Passthrough port == DP stream
# listen_port). Host ports map through kind NodePorts so CI can dial with SNI.
TLS_BLACKBOX_PORT_SNI="${TLS_BLACKBOX_PORT_SNI:-9011}"
TLS_BLACKBOX_PORT_CROSS="${TLS_BLACKBOX_PORT_CROSS:-9012}"
TLS_BLACKBOX_PORT_FAIL="${TLS_BLACKBOX_PORT_FAIL:-9013}"
TLS_BLACKBOX_PORT_DELETE="${TLS_BLACKBOX_PORT_DELETE:-9014}"
TLS_ECHO_BACKEND_PORT="${TLS_ECHO_BACKEND_PORT:-9443}"

DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
BACKEND_NAMESPACE="${BACKEND_NAMESPACE:-gateway-conformance-web-backend}"

TLS_SNI_A="${TLS_SNI_A:-a.tls.blackbox.example}"
TLS_SNI_B="${TLS_SNI_B:-b.tls.blackbox.example}"
TLS_SNI_CROSS="${TLS_SNI_CROSS:-cross.tls.blackbox.example}"
TLS_SNI_DELETE="${TLS_SNI_DELETE:-delete.tls.blackbox.example}"
TLS_SNI_UNKNOWN="${TLS_SNI_UNKNOWN:-unknown.tls.blackbox.example}"

create_tls_echo_secret() {
  local namespace="$1"
  local name="$2"
  local tmpdir
  tmpdir="$(mktemp -d)"
  openssl req -x509 -nodes -newkey rsa:2048 -days 1 \
    -keyout "$tmpdir/tls.key" \
    -out "$tmpdir/tls.crt" \
    -subj "/CN=*.tls.blackbox.example" \
    -addext "subjectAltName=DNS:*.tls.blackbox.example,DNS:a.tls.blackbox.example,DNS:b.tls.blackbox.example,DNS:cross.tls.blackbox.example,DNS:delete.tls.blackbox.example" \
    >/dev/null 2>&1
  kubectl -n "$namespace" create secret tls "$name" \
    --cert="$tmpdir/tls.crt" \
    --key="$tmpdir/tls.key" \
    --dry-run=client -o yaml | kubectl apply -f -
  rm -rf "$tmpdir"
}

tls_echo_deployment_yaml() {
  local name="$1"
  local namespace="$2"
  cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ${name}
  template:
    metadata:
      labels:
        app: ${name}
    spec:
      containers:
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: ${name}
            - name: LISTEN_PORT
              value: "${TLS_ECHO_BACKEND_PORT}"
          ports:
            - containerPort: ${TLS_ECHO_BACKEND_PORT}
          volumeMounts:
            - name: tls
              mountPath: /tls
              readOnly: true
          command: ["python", "-c"]
          args:
            - |
              import os, socket, ssl
              name = os.environ["BACKEND_NAME"].encode()
              port = int(os.environ["LISTEN_PORT"])
              ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
              ctx.load_cert_chain("/tls/tls.crt", "/tls/tls.key")
              srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
              srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              srv.bind(("", port))
              srv.listen()
              print(f"tls echo {name.decode()} on {port}", flush=True)
              while True:
                  conn, _ = srv.accept()
                  try:
                      with ctx.wrap_socket(conn, server_side=True) as ssock:
                          data = b""
                          while True:
                              chunk = ssock.recv(4096)
                              if not chunk:
                                  break
                              data += chunk
                              if len(data) >= 65536:
                                  break
                          ssock.sendall(name + b":" + data)
                  except Exception as exc:
                      print(f"tls echo session error: {exc}", flush=True)
                  finally:
                      try:
                          conn.close()
                      except Exception:
                          pass
      volumes:
        - name: tls
          secret:
            secretName: blackbox-tls-echo
---
apiVersion: v1
kind: Service
metadata:
  name: ${name}
  namespace: ${namespace}
spec:
  selector:
    app: ${name}
  ports:
    - name: tls
      port: ${TLS_ECHO_BACKEND_PORT}
      targetPort: ${TLS_ECHO_BACKEND_PORT}
YAML
}

apply_tls_blackbox_backends() {
  create_tls_echo_secret "$DP_GATEWAY_NAMESPACE" blackbox-tls-echo
  create_tls_echo_secret "$BACKEND_NAMESPACE" blackbox-tls-echo
  {
    tls_echo_deployment_yaml blackbox-tls-a "$DP_GATEWAY_NAMESPACE"
    echo "---"
    tls_echo_deployment_yaml blackbox-tls-b "$DP_GATEWAY_NAMESPACE"
    echo "---"
    tls_echo_deployment_yaml blackbox-tls-cross "$BACKEND_NAMESPACE"
    cat <<YAML
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-tls-empty
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  ports:
    - name: tls
      port: ${TLS_ECHO_BACKEND_PORT}
      targetPort: ${TLS_ECHO_BACKEND_PORT}
YAML
  } | kubectl apply -f -
}

apply_tls_blackbox_routes() {
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-tls
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  gatewayClassName: ferrum
  listeners:
    - name: tls-sni
      port: ${TLS_BLACKBOX_PORT_SNI}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
    - name: tls-cross
      port: ${TLS_BLACKBOX_PORT_CROSS}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
    - name: tls-fail
      port: ${TLS_BLACKBOX_PORT_FAIL}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
    - name: tls-delete
      port: ${TLS_BLACKBOX_PORT_DELETE}
      protocol: TLS
      tls:
        mode: Passthrough
      allowedRoutes:
        kinds:
          - kind: TLSRoute
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-a
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-sni
  hostnames:
    - ${TLS_SNI_A}
  rules:
    - backendRefs:
        - name: blackbox-tls-a
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-b
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-sni
  hostnames:
    - ${TLS_SNI_B}
  rules:
    - backendRefs:
        - name: blackbox-tls-b
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-cross
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-cross
  hostnames:
    - ${TLS_SNI_CROSS}
  rules:
    - backendRefs:
        - name: blackbox-tls-cross
          namespace: ${BACKEND_NAMESPACE}
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-infra-tlsroute-to-blackbox-tls-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: TLSRoute
      namespace: ${DP_GATEWAY_NAMESPACE}
  to:
    - group: ""
      kind: Service
      name: blackbox-tls-cross
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-fail
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-fail
  hostnames:
    - fail.tls.blackbox.example
  rules:
    - backendRefs:
        - name: blackbox-tls-empty
          port: ${TLS_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-delete
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-delete
  hostnames:
    - ${TLS_SNI_DELETE}
  rules:
    - backendRefs:
        - name: blackbox-tls-a
          port: ${TLS_ECHO_BACKEND_PORT}
YAML
}

tls_exchange() {
  local host="$1"
  local port="$2"
  local sni="$3"
  local payload="$4"
  python3 - "$host" "$port" "$sni" "$payload" <<'PY'
import socket
import ssl
import sys

host, port_s, sni, payload = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4].encode()
port = int(port_s)
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
with socket.create_connection((host, port), timeout=5) as sock:
    with ctx.wrap_socket(sock, server_hostname=sni) as ssock:
        ssock.sendall(payload)
        ssock.shutdown(socket.SHUT_WR)
        chunks = []
        while True:
            chunk = ssock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
sys.stdout.buffer.write(b"".join(chunks))
PY
}

wait_for_tls_echo() {
  local port="$1"
  local sni="$2"
  local expected_prefix="$3"
  local payload="${4:-ping}"
  local body=""
  for _ in $(seq 1 60); do
    if body="$(tls_exchange 127.0.0.1 "$port" "$sni" "$payload" 2>/dev/null)" \
      && grep -q "^${expected_prefix}:" <<<"$body" \
      && grep -q "$payload" <<<"$body"; then
      printf '%s\n' "$body"
      return 0
    fi
    sleep 2
  done
  echo "expected TLS :${port} SNI=${sni} echo prefixed with ${expected_prefix} for payload ${payload}; last body=${body}" >&2
  return 1
}

assert_tls_exchange_fails() {
  local port="$1"
  local sni="$2"
  local label="$3"
  local body=""
  if body="$(tls_exchange 127.0.0.1 "$port" "$sni" "should-fail" 2>/dev/null)"; then
    if [ -n "$body" ]; then
      echo "${label}: unexpected backend data on :${port} SNI=${sni}: ${body}" >&2
      return 1
    fi
    # Accepted-then-reset/empty responses are still fail-closed (no backend echo).
    echo "${label}: TLS :${port} SNI=${sni} produced no successful backend echo"
    return 0
  fi
  echo "${label}: TLS :${port} SNI=${sni} connection failed closed"
  return 0
}

wait_for_tlsroute_parent_condition() {
  local name="$1"
  local condition_type="$2"
  local expected_status="$3"
  local status=""
  for _ in $(seq 1 60); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get tlsroute "$name" -o jsonpath="{.status.parents[0].conditions[?(@.type==\"${condition_type}\")].status}" 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ]; then
      echo "TLSRoute ${name} ${condition_type}=${status}"
      return 0
    fi
    sleep 2
  done
  echo "TLSRoute ${name} did not reach ${condition_type}=${expected_status} (got '${status}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get tlsroute "$name" -o yaml >&2 || true
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

run_tls_blackbox_tests() {
  local report="$1"
  echo "" >> "$report"
  echo "## TLSRoute live data-plane (SNI passthrough)" >> "$report"

  apply_tls_blackbox_routes

  wait_for_tlsroute_parent_condition blackbox-tls-a Accepted True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-a ResolvedRefs True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-a Programmed True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-b Accepted True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-b ResolvedRefs True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-b Programmed True | tee -a "$report"
  wait_for_gateway_listener_attached_routes ferrum-blackbox-tls tls-sni 2 | tee -a "$report"

  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_A" "blackbox-tls-a" "sni-a-ping" | tee -a "$report"
  echo "TLSRoute SNI ${TLS_SNI_A} served tagged echo on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"
  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_B" "blackbox-tls-b" "sni-b-ping" | tee -a "$report"
  echo "TLSRoute SNI ${TLS_SNI_B} served tagged echo on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"

  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_UNKNOWN" "unmatched TLSRoute SNI" | tee -a "$report"
  echo "TLSRoute unmatched SNI ${TLS_SNI_UNKNOWN} failed closed on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"

  wait_for_tlsroute_parent_condition blackbox-tls-cross Accepted True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-cross ResolvedRefs True | tee -a "$report"
  wait_for_tlsroute_parent_condition blackbox-tls-cross Programmed True | tee -a "$report"
  wait_for_tls_echo "$TLS_BLACKBOX_PORT_CROSS" "$TLS_SNI_CROSS" "blackbox-tls-cross" "cross-ping" | tee -a "$report"
  echo "TLSRoute cross-namespace backendRef with ReferenceGrant served echo on :${TLS_BLACKBOX_PORT_CROSS}" >> "$report"

  # Empty Service endpoints must fail closed (no successful tagged echo).
  wait_for_tlsroute_parent_condition blackbox-tls-fail Accepted True | tee -a "$report"
  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_FAIL" "fail.tls.blackbox.example" "empty TLS backend endpoints" | tee -a "$report"
  echo "TLSRoute empty-endpoint backend failed closed on :${TLS_BLACKBOX_PORT_FAIL}" >> "$report"

  # Missing Service backendRef: replace the fail route and require fail-closed traffic.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tlsroute blackbox-tls-fail --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-invalid
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-fail
  hostnames:
    - fail.tls.blackbox.example
  rules:
    - backendRefs:
        - name: blackbox-tls-missing
          port: ${TLS_ECHO_BACKEND_PORT}
YAML
  sleep 5
  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_FAIL" "fail.tls.blackbox.example" "missing TLS backend Service" | tee -a "$report"
  echo "TLSRoute missing backend Service failed closed on :${TLS_BLACKBOX_PORT_FAIL}" >> "$report"

  # Cross-namespace backendRef without ReferenceGrant must fail closed.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tlsroute blackbox-tls-invalid --wait=true
  kubectl -n "$BACKEND_NAMESPACE" delete referencegrant allow-infra-tlsroute-to-blackbox-tls-cross --ignore-not-found --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: TLSRoute
metadata:
  name: blackbox-tls-denied
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-tls
      sectionName: tls-fail
  hostnames:
    - fail.tls.blackbox.example
  rules:
    - backendRefs:
        - name: blackbox-tls-cross
          namespace: ${BACKEND_NAMESPACE}
          port: ${TLS_ECHO_BACKEND_PORT}
YAML
  # Translation rejects unpermitted refs fail-closed; wait for status and refuse echo.
  local status=""
  for _ in $(seq 1 30); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get tlsroute blackbox-tls-denied -o jsonpath='{.status.parents[0].conditions[?(@.type=="ResolvedRefs")].status}' 2>/dev/null || true)"
    if [ "$status" = "False" ]; then
      break
    fi
    sleep 2
  done
  if [ "${status:-}" = "False" ]; then
    echo "TLSRoute denied cross-namespace backendRef reported ResolvedRefs=False" | tee -a "$report"
  else
    echo "TLSRoute denied cross-namespace backendRef status ResolvedRefs='${status:-}' (traffic still must fail closed)" | tee -a "$report"
  fi
  assert_tls_exchange_fails "$TLS_BLACKBOX_PORT_FAIL" "fail.tls.blackbox.example" "unpermitted cross-namespace TLS backendRef" | tee -a "$report"
  echo "TLSRoute unpermitted cross-namespace backendRef failed closed on :${TLS_BLACKBOX_PORT_FAIL}" >> "$report"

  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_A" "blackbox-tls-a" "pre-update" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch tlsroute blackbox-tls-a --type=json \
    -p='[{"op":"replace","path":"/spec/rules/0/backendRefs/0/name","value":"blackbox-tls-b"}]'
  wait_for_tls_echo "$TLS_BLACKBOX_PORT_SNI" "$TLS_SNI_A" "blackbox-tls-b" "post-update" | tee -a "$report"
  echo "TLSRoute update switched live SNI ${TLS_SNI_A} traffic to blackbox-tls-b on :${TLS_BLACKBOX_PORT_SNI}" >> "$report"

  wait_for_tls_echo "$TLS_BLACKBOX_PORT_DELETE" "$TLS_SNI_DELETE" "blackbox-tls-a" "pre-delete" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete tlsroute blackbox-tls-delete --wait=true
  local delete_ok=0
  for _ in $(seq 1 30); do
    if ! tls_exchange 127.0.0.1 "$TLS_BLACKBOX_PORT_DELETE" "$TLS_SNI_DELETE" "post-delete" >/dev/null 2>&1; then
      delete_ok=1
      break
    fi
    sleep 2
  done
  if [ "$delete_ok" -ne 1 ]; then
    echo "deleted TLSRoute kept serving TLS echo on :${TLS_BLACKBOX_PORT_DELETE}" >&2
    return 1
  fi
  echo "deleted TLSRoute stopped serving on :${TLS_BLACKBOX_PORT_DELETE}" >> "$report"
}

run_blackbox() {
  local report="$RESULTS_DIR/gateway-api-blackbox.md"
  apply_tls_blackbox_backends
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-tls-a --timeout=180s
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-tls-b --timeout=180s
  kubectl -n "$BACKEND_NAMESPACE" rollout status deployment/blackbox-tls-cross --timeout=180s
  run_tls_blackbox_tests "$report"
}

collect_diagnostics() {
  set +e
  kubectl get gatewayclasses,gateways,httproutes,grpcroutes,tcproutes,tlsroutes,referencegrants -A -o yaml > "$RESULTS_DIR/gateway-api-resources.yaml"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-tls-a --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tls-a.log"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-tls-b --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tls-b.log"
  kubectl -n "$BACKEND_NAMESPACE" logs deployment/blackbox-tls-cross --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-tls-cross.log"
  {
    echo ""
    echo "TLSRoute black-box ports: ${TLS_BLACKBOX_PORT_SNI},${TLS_BLACKBOX_PORT_CROSS},${TLS_BLACKBOX_PORT_FAIL},${TLS_BLACKBOX_PORT_DELETE}"
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
