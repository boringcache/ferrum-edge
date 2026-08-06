#!/usr/bin/env bash
# Live GRPCRoute black-box coverage for the Gateway API conformance lab.
#
# Upstream GATEWAY-GRPC (exact method / header / listener hostname / weight)
# is claimed via go test in gateway_api_data_plane_conformance.sh. This script
# adds Ferrum-specific live evidence the profile does not pin on v1.5.1:
# parent status, ReferenceGrant cross-namespace backends, fail-closed invalid /
# empty / unpermitted refs, backendRef update, deletion withdrawal, and
# trailers-only Unimplemented for unmatched methods — without inventing an
# extended GRPCRouteNamedRouteRule claim.
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"

DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
BACKEND_NAMESPACE="${BACKEND_NAMESPACE:-gateway-conformance-web-backend}"
GATEWAY_API_STATUS_ADDRESS="${GATEWAY_API_STATUS_ADDRESS:-127.0.0.1}"
GATEWAY_API_VERSION="${GATEWAY_API_VERSION:-v1.5.1}"

# Pinned to the same echo-basic tag Gateway API v1.5.1 conformance base uses.
GRPC_ECHO_IMAGE="${GRPC_ECHO_IMAGE:-gcr.io/k8s-staging-gateway-api/echo-basic:v20260204-monthly-2026.01-60-g28382302}"
GRPC_ECHO_SERVICE="gateway_api_conformance.echo_basic.grpcecho.GrpcEcho"
GRPC_METHOD_ECHO="${GRPC_ECHO_SERVICE}/Echo"
GRPC_METHOD_ECHO_TWO="${GRPC_ECHO_SERVICE}/EchoTwo"
GRPC_METHOD_ECHO_THREE="${GRPC_ECHO_SERVICE}/EchoThree"

apply_grpc_blackbox_backends() {
  cat <<YAML | kubectl apply -f -
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-grpc-a
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-grpc-a
  template:
    metadata:
      labels:
        app: blackbox-grpc-a
    spec:
      containers:
        - name: echo
          image: ${GRPC_ECHO_IMAGE}
          env:
            - name: POD_NAME
              value: blackbox-grpc-a
            - name: NAMESPACE
              value: ${DP_GATEWAY_NAMESPACE}
            - name: SERVICE_NAME
              value: blackbox-grpc-a
            - name: GRPC_ECHO_SERVER
              value: "true"
          ports:
            - name: http
              containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-grpc-a
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  selector:
    app: blackbox-grpc-a
  ports:
    - name: http
      port: 8080
      targetPort: 3000
      appProtocol: kubernetes.io/h2c
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-grpc-b
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-grpc-b
  template:
    metadata:
      labels:
        app: blackbox-grpc-b
    spec:
      containers:
        - name: echo
          image: ${GRPC_ECHO_IMAGE}
          env:
            - name: POD_NAME
              value: blackbox-grpc-b
            - name: NAMESPACE
              value: ${DP_GATEWAY_NAMESPACE}
            - name: SERVICE_NAME
              value: blackbox-grpc-b
            - name: GRPC_ECHO_SERVER
              value: "true"
          ports:
            - name: http
              containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-grpc-b
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  selector:
    app: blackbox-grpc-b
  ports:
    - name: http
      port: 8080
      targetPort: 3000
      appProtocol: kubernetes.io/h2c
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-grpc-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-grpc-cross
  template:
    metadata:
      labels:
        app: blackbox-grpc-cross
    spec:
      containers:
        - name: echo
          image: ${GRPC_ECHO_IMAGE}
          env:
            - name: POD_NAME
              value: blackbox-grpc-cross
            - name: NAMESPACE
              value: ${BACKEND_NAMESPACE}
            - name: SERVICE_NAME
              value: blackbox-grpc-cross
            - name: GRPC_ECHO_SERVER
              value: "true"
          ports:
            - name: http
              containerPort: 3000
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-grpc-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  selector:
    app: blackbox-grpc-cross
  ports:
    - name: http
      port: 8080
      targetPort: 3000
      appProtocol: kubernetes.io/h2c
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-grpc-empty
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  ports:
    - name: http
      port: 8080
      targetPort: 3000
YAML
}

apply_grpc_blackbox_routes() {
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-grpc
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  gatewayClassName: ferrum
  listeners:
    - name: http
      port: 80
      protocol: HTTP
      allowedRoutes:
        kinds:
          - kind: GRPCRoute
        namespaces:
          from: Selector
          selector:
            matchLabels:
              gateway-conformance: backend
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-exact
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  # Keep this authority distinct from the legacy declared-unsupported fixture
  # in gateway_api_data_plane_conformance.sh. Both suites share host port 80,
  # so reusing that fixture's authority would make its catch-all GRPCRoute
  # compete with these exact-method routes.
  hostnames: ["grpc-live.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: blackbox-grpc-a
          port: 8080
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: EchoTwo
      backendRefs:
        - name: blackbox-grpc-b
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-header
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  hostnames: ["grpc-header.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - headers:
            - name: version
              value: one
      backendRefs:
        - name: blackbox-grpc-a
          port: 8080
    - matches:
        - headers:
            - name: version
              value: two
      backendRefs:
        - name: blackbox-grpc-b
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-cross
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  hostnames: ["grpc-cross.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: blackbox-grpc-cross
          namespace: ${BACKEND_NAMESPACE}
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-infra-grpcroute-to-blackbox-grpc-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: GRPCRoute
      namespace: ${DP_GATEWAY_NAMESPACE}
  to:
    - group: ""
      kind: Service
      name: blackbox-grpc-cross
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-fail
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  hostnames: ["grpc-fail.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: blackbox-grpc-empty
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-update
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  hostnames: ["grpc-update.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: blackbox-grpc-a
          port: 8080
---
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-delete
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  hostnames: ["grpc-delete.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: blackbox-grpc-a
          port: 8080
YAML
}

grpc_call() {
  local authority="$1"
  local method="$2"
  local metadata="${3:-}"
  # Plaintext h2c prior-knowledge against the kind NodePort mapped to host :80.
  # Reflection is enabled on echo-basic, so no local .proto is required.
  if [ -n "$metadata" ]; then
    grpcurl -plaintext \
      -authority "$authority" \
      -emit-defaults \
      -H "$metadata" \
      "${GATEWAY_API_STATUS_ADDRESS}:80" \
      "$method"
  else
    grpcurl -plaintext \
      -authority "$authority" \
      -emit-defaults \
      "${GATEWAY_API_STATUS_ADDRESS}:80" \
      "$method"
  fi
}

wait_for_grpc_backend() {
  local authority="$1"
  local method="$2"
  local expected_backend="$3"
  local metadata="${4:-}"
  local body=""
  for _ in $(seq 1 60); do
    if body="$(grpc_call "$authority" "$method" "$metadata" 2>/dev/null)" \
      && grep -q "$expected_backend" <<<"$body"; then
      printf '%s\n' "$body"
      return 0
    fi
    sleep 2
  done
  echo "expected ${authority} ${method} to reach backend ${expected_backend}; last body=${body}" >&2
  return 1
}

wait_for_grpc_status() {
  local authority="$1"
  local method="$2"
  local expected_code="$3"
  local err=""
  for _ in $(seq 1 60); do
    if err="$(grpc_call "$authority" "$method" 2>&1 >/dev/null)"; then
      echo "expected non-OK gRPC status ${expected_code} for ${authority} ${method}, but call succeeded" >&2
      return 1
    fi
    if grep -Eq "Code:[[:space:]]*${expected_code}\\b|code[[:space:]]*=[[:space:]]*${expected_code}\\b|rpc error: code = ${expected_code}\\b" <<<"$err"; then
      printf '%s\n' "$err"
      return 0
    fi
    # Also accept Code: Unimplemented style names.
    if [ "$expected_code" = "Unimplemented" ] || [ "$expected_code" = "12" ]; then
      if grep -Eqi "Unimplemented|code = Unimplemented" <<<"$err"; then
        printf '%s\n' "$err"
        return 0
      fi
    fi
    sleep 2
  done
  echo "expected ${authority} ${method} to fail with gRPC ${expected_code}; last err=${err}" >&2
  return 1
}

assert_grpc_call_fails_closed() {
  local authority="$1"
  local method="$2"
  local label="$3"
  local err=""
  if err="$(grpc_call "$authority" "$method" 2>&1)"; then
    if grep -q "blackbox-grpc" <<<"$err"; then
      echo "${label}: unexpected backend echo for ${authority} ${method}: ${err}" >&2
      return 1
    fi
  fi
  echo "${label}: ${authority} ${method} failed closed"
  return 0
}

wait_for_grpcroute_parent_condition() {
  local name="$1"
  local condition_type="$2"
  local expected_status="$3"
  local status=""
  for _ in $(seq 1 60); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get grpcroute "$name" -o jsonpath="{.status.parents[0].conditions[?(@.type==\"${condition_type}\")].status}" 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ]; then
      echo "GRPCRoute ${name} ${condition_type}=${status}"
      return 0
    fi
    sleep 2
  done
  echo "GRPCRoute ${name} did not reach ${condition_type}=${expected_status} (got '${status}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get grpcroute "$name" -o yaml >&2 || true
  return 1
}

run_grpc_blackbox_tests() {
  local report="$1"
  echo "" >> "$report"
  echo "## GRPCRoute live data-plane" >> "$report"

  apply_grpc_blackbox_routes

  wait_for_grpcroute_parent_condition blackbox-grpc-exact Accepted True | tee -a "$report"
  wait_for_grpcroute_parent_condition blackbox-grpc-exact ResolvedRefs True | tee -a "$report"
  wait_for_grpcroute_parent_condition blackbox-grpc-exact Programmed True | tee -a "$report"

  wait_for_grpc_backend grpc-live.blackbox.example "$GRPC_METHOD_ECHO" "blackbox-grpc-a" | tee -a "$report"
  wait_for_grpc_backend grpc-live.blackbox.example "$GRPC_METHOD_ECHO_TWO" "blackbox-grpc-b" | tee -a "$report"
  echo "GRPCRoute exact method matching served Echo→a and EchoTwo→b" >> "$report"

  wait_for_grpc_status grpc-live.blackbox.example "$GRPC_METHOD_ECHO_THREE" Unimplemented | tee -a "$report"
  echo "GRPCRoute unmatched method failed closed with Unimplemented (trailers-only)" >> "$report"

  wait_for_grpc_backend grpc-header.blackbox.example "$GRPC_METHOD_ECHO" "blackbox-grpc-a" \
    'version: one' | tee -a "$report"
  wait_for_grpc_backend grpc-header.blackbox.example "$GRPC_METHOD_ECHO" "blackbox-grpc-b" \
    'version: two' | tee -a "$report"
  echo "GRPCRoute header matching selected backends by version metadata" >> "$report"

  wait_for_grpcroute_parent_condition blackbox-grpc-cross Accepted True | tee -a "$report"
  wait_for_grpcroute_parent_condition blackbox-grpc-cross ResolvedRefs True | tee -a "$report"
  wait_for_grpc_backend grpc-cross.blackbox.example "$GRPC_METHOD_ECHO" "blackbox-grpc-cross" | tee -a "$report"
  echo "GRPCRoute cross-namespace backendRef with ReferenceGrant served echo" >> "$report"

  wait_for_grpcroute_parent_condition blackbox-grpc-fail Accepted True | tee -a "$report"
  assert_grpc_call_fails_closed grpc-fail.blackbox.example "$GRPC_METHOD_ECHO" \
    "empty gRPC backend endpoints" | tee -a "$report"
  echo "GRPCRoute empty-endpoint backend failed closed" >> "$report"

  kubectl -n "$DP_GATEWAY_NAMESPACE" delete grpcroute blackbox-grpc-fail --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-invalid
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  hostnames: ["grpc-fail.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: blackbox-grpc-missing
          port: 8080
YAML
  sleep 5
  assert_grpc_call_fails_closed grpc-fail.blackbox.example "$GRPC_METHOD_ECHO" \
    "missing gRPC backend Service" | tee -a "$report"
  echo "GRPCRoute missing backend Service failed closed" >> "$report"

  kubectl -n "$DP_GATEWAY_NAMESPACE" delete grpcroute blackbox-grpc-invalid --wait=true
  kubectl -n "$BACKEND_NAMESPACE" delete referencegrant allow-infra-grpcroute-to-blackbox-grpc-cross \
    --ignore-not-found --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: GRPCRoute
metadata:
  name: blackbox-grpc-denied
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  hostnames: ["grpc-fail.blackbox.example"]
  parentRefs:
    - name: ferrum-blackbox-grpc
      sectionName: http
  rules:
    - matches:
        - method:
            service: gateway_api_conformance.echo_basic.grpcecho.GrpcEcho
            method: Echo
      backendRefs:
        - name: blackbox-grpc-cross
          namespace: ${BACKEND_NAMESPACE}
          port: 8080
YAML
  local status=""
  for _ in $(seq 1 30); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get grpcroute blackbox-grpc-denied -o jsonpath='{.status.parents[0].conditions[?(@.type=="ResolvedRefs")].status}' 2>/dev/null || true)"
    if [ "$status" = "False" ]; then
      break
    fi
    sleep 2
  done
  if [ "${status:-}" = "False" ]; then
    echo "GRPCRoute denied cross-namespace backendRef reported ResolvedRefs=False" | tee -a "$report"
  else
    echo "GRPCRoute denied cross-namespace backendRef status ResolvedRefs='${status:-}' (traffic still must fail closed)" | tee -a "$report"
  fi
  assert_grpc_call_fails_closed grpc-fail.blackbox.example "$GRPC_METHOD_ECHO" \
    "unpermitted cross-namespace gRPC backendRef" | tee -a "$report"
  echo "GRPCRoute unpermitted cross-namespace backendRef failed closed" >> "$report"

  wait_for_grpc_backend grpc-update.blackbox.example "$GRPC_METHOD_ECHO" "blackbox-grpc-a" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch grpcroute blackbox-grpc-update --type=json \
    -p='[{"op":"replace","path":"/spec/rules/0/backendRefs/0/name","value":"blackbox-grpc-b"}]'
  wait_for_grpc_backend grpc-update.blackbox.example "$GRPC_METHOD_ECHO" "blackbox-grpc-b" | tee -a "$report"
  echo "GRPCRoute update switched live traffic to blackbox-grpc-b" >> "$report"

  wait_for_grpc_backend grpc-delete.blackbox.example "$GRPC_METHOD_ECHO" "blackbox-grpc-a" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete grpcroute blackbox-grpc-delete --wait=true
  local delete_ok=0
  for _ in $(seq 1 30); do
    if ! grpc_call grpc-delete.blackbox.example "$GRPC_METHOD_ECHO" >/dev/null 2>&1; then
      delete_ok=1
      break
    fi
    # Successful call that somehow still echoes is also a failure; treat any OK as not-yet-withdrawn.
    sleep 2
  done
  if [ "$delete_ok" -ne 1 ]; then
    echo "deleted GRPCRoute kept serving gRPC echo on grpc-delete.blackbox.example" >&2
    return 1
  fi
  echo "deleted GRPCRoute stopped serving grpc-delete.blackbox.example" >> "$report"
}

run_blackbox() {
  local report="$RESULTS_DIR/gateway-api-blackbox.md"
  kubectl create namespace "$DP_GATEWAY_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl create namespace "$BACKEND_NAMESPACE" --dry-run=client -o yaml | kubectl apply -f -
  kubectl label namespace "$DP_GATEWAY_NAMESPACE" gateway-conformance=backend --overwrite
  kubectl label namespace "$BACKEND_NAMESPACE" gateway-conformance=backend --overwrite
  apply_grpc_blackbox_backends
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-grpc-a --timeout=180s
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-grpc-b --timeout=180s
  kubectl -n "$BACKEND_NAMESPACE" rollout status deployment/blackbox-grpc-cross --timeout=180s
  run_grpc_blackbox_tests "$report"
}

collect_diagnostics() {
  set +e
  kubectl get gatewayclasses,gateways,httproutes,grpcroutes,tcproutes,referencegrants -A -o yaml \
    > "$RESULTS_DIR/gateway-api-resources.yaml"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-grpc-a --all-containers --tail=1000 \
    > "$RESULTS_DIR/blackbox-grpc-a.log" 2>/dev/null || true
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-grpc-b --all-containers --tail=1000 \
    > "$RESULTS_DIR/blackbox-grpc-b.log" 2>/dev/null || true
  kubectl -n "$BACKEND_NAMESPACE" logs deployment/blackbox-grpc-cross --all-containers --tail=1000 \
    > "$RESULTS_DIR/blackbox-grpc-cross.log" 2>/dev/null || true
  {
    echo ""
    echo "GRPCRoute black-box: GATEWAY-GRPC claimed; Ferrum live checks cover status/ReferenceGrant/fail-closed/update/delete/Unimplemented."
    echo "Gateway API version pin: ${GATEWAY_API_VERSION}"
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
