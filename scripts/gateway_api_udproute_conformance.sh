#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="${ROOT_DIR:-$(pwd)}"
RESULTS_DIR="${RESULTS_DIR:-$ROOT_DIR/conformance-results}"

# Live UDPRoute black-box listeners (Gateway listener port == DP stream
# listen_port). Host ports map through kind UDP NodePorts so CI can dial the
# datagram path without an in-cluster client. Keep these in sync with
# scripts/gateway_api_conformance_lab_setup.sh.
UDP_BLACKBOX_PORT_MAIN="${UDP_BLACKBOX_PORT_MAIN:-9011}"
UDP_BLACKBOX_PORT_CROSS="${UDP_BLACKBOX_PORT_CROSS:-9012}"
UDP_BLACKBOX_PORT_FAIL="${UDP_BLACKBOX_PORT_FAIL:-9013}"
UDP_BLACKBOX_PORT_DELETE="${UDP_BLACKBOX_PORT_DELETE:-9014}"
UDP_ECHO_BACKEND_PORT="${UDP_ECHO_BACKEND_PORT:-9091}"

DP_GATEWAY_NAMESPACE="${DP_GATEWAY_NAMESPACE:-gateway-conformance-infra}"
BACKEND_NAMESPACE="${BACKEND_NAMESPACE:-gateway-conformance-web-backend}"

udp_echo_container() {
  # One datagram in, one tagged datagram out — no connection state, so the
  # backend proves UDP semantics survived translation rather than a stream
  # relay that happens to carry the bytes.
  local name="$1"
  cat <<YAML
        - name: echo
          image: python:3.13-alpine
          env:
            - name: BACKEND_NAME
              value: ${name}
            - name: LISTEN_PORT
              value: "${UDP_ECHO_BACKEND_PORT}"
          command: ["python", "-c"]
          args:
            - |
              import os, socket
              name = os.environ["BACKEND_NAME"].encode()
              port = int(os.environ["LISTEN_PORT"])
              srv = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
              srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
              srv.bind(("", port))
              print(f"udp echo {name.decode()} on {port}", flush=True)
              while True:
                  data, peer = srv.recvfrom(65535)
                  srv.sendto(name + b":" + data, peer)
YAML
}

apply_udp_blackbox_backends() {
  {
    cat <<YAML
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-udp-a
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-udp-a
  template:
    metadata:
      labels:
        app: blackbox-udp-a
    spec:
      containers:
YAML
    udp_echo_container blackbox-udp-a
    cat <<YAML
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-udp-a
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  selector:
    app: blackbox-udp-a
  ports:
    - name: udp
      protocol: UDP
      port: ${UDP_ECHO_BACKEND_PORT}
      targetPort: ${UDP_ECHO_BACKEND_PORT}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-udp-b
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-udp-b
  template:
    metadata:
      labels:
        app: blackbox-udp-b
    spec:
      containers:
YAML
    udp_echo_container blackbox-udp-b
    cat <<YAML
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-udp-b
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  selector:
    app: blackbox-udp-b
  ports:
    - name: udp
      protocol: UDP
      port: ${UDP_ECHO_BACKEND_PORT}
      targetPort: ${UDP_ECHO_BACKEND_PORT}
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: blackbox-udp-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  replicas: 1
  selector:
    matchLabels:
      app: blackbox-udp-cross
  template:
    metadata:
      labels:
        app: blackbox-udp-cross
    spec:
      containers:
YAML
    udp_echo_container blackbox-udp-cross
    cat <<YAML
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-udp-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  selector:
    app: blackbox-udp-cross
  ports:
    - name: udp
      protocol: UDP
      port: ${UDP_ECHO_BACKEND_PORT}
      targetPort: ${UDP_ECHO_BACKEND_PORT}
---
apiVersion: v1
kind: Service
metadata:
  name: blackbox-udp-empty
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  ports:
    - name: udp
      protocol: UDP
      port: ${UDP_ECHO_BACKEND_PORT}
      targetPort: ${UDP_ECHO_BACKEND_PORT}
YAML
  } | kubectl apply -f -
}

apply_udp_blackbox_routes() {
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1
kind: Gateway
metadata:
  name: ferrum-blackbox-udp
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  gatewayClassName: ferrum
  listeners:
    - name: udp-main
      port: ${UDP_BLACKBOX_PORT_MAIN}
      protocol: UDP
      allowedRoutes:
        kinds:
          - kind: UDPRoute
        namespaces:
          from: Same
    - name: udp-cross
      port: ${UDP_BLACKBOX_PORT_CROSS}
      protocol: UDP
      allowedRoutes:
        kinds:
          - kind: UDPRoute
        namespaces:
          from: Same
    - name: udp-fail
      port: ${UDP_BLACKBOX_PORT_FAIL}
      protocol: UDP
      allowedRoutes:
        kinds:
          - kind: UDPRoute
        namespaces:
          from: Same
    - name: udp-delete
      port: ${UDP_BLACKBOX_PORT_DELETE}
      protocol: UDP
      allowedRoutes:
        kinds:
          - kind: UDPRoute
        namespaces:
          from: Same
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: blackbox-udp-main
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-udp
      sectionName: udp-main
  rules:
    - backendRefs:
        - name: blackbox-udp-a
          port: ${UDP_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: blackbox-udp-cross
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-udp
      sectionName: udp-cross
  rules:
    - backendRefs:
        - name: blackbox-udp-cross
          namespace: ${BACKEND_NAMESPACE}
          port: ${UDP_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1beta1
kind: ReferenceGrant
metadata:
  name: allow-infra-udproute-to-blackbox-udp-cross
  namespace: ${BACKEND_NAMESPACE}
spec:
  from:
    - group: gateway.networking.k8s.io
      kind: UDPRoute
      namespace: ${DP_GATEWAY_NAMESPACE}
  to:
    - group: ""
      kind: Service
      name: blackbox-udp-cross
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: blackbox-udp-fail
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-udp
      sectionName: udp-fail
  rules:
    - backendRefs:
        - name: blackbox-udp-empty
          port: ${UDP_ECHO_BACKEND_PORT}
---
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: blackbox-udp-delete
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-udp
      sectionName: udp-delete
  rules:
    - backendRefs:
        - name: blackbox-udp-a
          port: ${UDP_ECHO_BACKEND_PORT}
YAML
}

udp_weighted_backend_patch() {
  # Merge patch body for the two-leg weighted backendRefs set. Emitted from a
  # helper (rather than a heredoc opened inside the `kubectl` command
  # substitution) so the heredoc receiver stays a plain literal `cat`.
  local weight_a="$1"
  local weight_b="$2"
  cat <<JSON
{"spec":{"rules":[{"backendRefs":[
  {"name":"blackbox-udp-a","port":${UDP_ECHO_BACKEND_PORT},"weight":${weight_a}},
  {"name":"blackbox-udp-b","port":${UDP_ECHO_BACKEND_PORT},"weight":${weight_b}}
]}]}}
JSON
}

udp_exchange() {
  local host="$1"
  local port="$2"
  local payload="$3"
  python3 - "$host" "$port" "$payload" <<'PY'
import socket
import sys

host, port_s, payload = sys.argv[1], sys.argv[2], sys.argv[3].encode()
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.settimeout(5)
try:
    sock.sendto(payload, (host, int(port_s)))
    data, _ = sock.recvfrom(65535)
finally:
    sock.close()
sys.stdout.buffer.write(data)
PY
}

wait_for_udp_echo() {
  local port="$1"
  local expected_prefix="$2"
  local payload="${3:-ping}"
  local body=""
  for _ in $(seq 1 60); do
    if body="$(udp_exchange 127.0.0.1 "$port" "$payload" 2>/dev/null)" \
      && grep -q "^${expected_prefix}:" <<<"$body" \
      && grep -q "$payload" <<<"$body"; then
      printf '%s\n' "$body"
      return 0
    fi
    sleep 2
  done
  echo "expected UDP :${port} echo prefixed with ${expected_prefix} for payload ${payload}; last body=${body}" >&2
  return 1
}

assert_udp_exchange_fails() {
  # UDP has no handshake, so fail-closed means "no backend datagram comes back"
  # (drop, or an ICMP-driven connection error). Require three independent
  # no-reply observations so one lost datagram cannot make a live backend look
  # fail-closed. Any received datagram, including an empty one, is a leak.
  local port="$1"
  local label="$2"
  local body=""
  for attempt in 1 2 3; do
    if body="$(udp_exchange 127.0.0.1 "$port" "should-fail-${attempt}" 2>/dev/null)"; then
      echo "${label}: unexpected backend datagram on :${port}: ${body}" >&2
      return 1
    fi
  done
  echo "${label}: UDP :${port} produced no backend datagram in three attempts (failed closed)"
  return 0
}

sample_udp_backends() {
  # Sample `count` INDEPENDENT UDP sessions and tally which backend answered.
  #
  # Ferrum keys a UDP session on the client 5-tuple and selects the backend
  # once per session, so a fresh socket per iteration (fresh ephemeral source
  # port) is exactly one independent weighted selection. Reusing one socket
  # would re-hit the same pinned target and prove nothing about distribution.
  local port="$1"
  local count="$2"
  local timeout="$3"
  python3 - "$port" "$count" "$timeout" <<'PY'
import socket
import sys

port, count, timeout = int(sys.argv[1]), int(sys.argv[2]), float(sys.argv[3])
tally = {}
drops = 0
for index in range(count):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(f"sample-{index}".encode(), ("127.0.0.1", port))
        data, _ = sock.recvfrom(65535)
        tag = data.split(b":", 1)[0].decode("ascii", "replace")
        tally[tag] = tally.get(tag, 0) + 1
    except OSError:
        drops += 1
    finally:
        sock.close()
for tag in sorted(tally):
    print(f"{tag} {tally[tag]}")
print(f"__drops__ {drops}")
PY
}

udp_sample_hits() {
  local sample="$1"
  local tag="$2"
  local hits
  hits="$(awk -v want="$tag" '$1==want {print $2}' <<<"$sample")"
  printf '%s\n' "${hits:-0}"
}

wait_for_weighted_udp_distribution() {
  # Bounded, statistically slack assertion: with two equally weighted valid
  # legs Ferrum's weighted round-robin alternates, so ~half of `count`
  # sessions land on each. Requiring only `min_each` leaves a wide margin for
  # datagram loss while still failing if one leg never receives traffic (which
  # is exactly the "only the first backendRef is used" defect).
  local port="$1"
  local count="$2"
  local min_each="$3"
  shift 3
  local expected=("$@")
  local sample=""
  local attempt
  for attempt in $(seq 1 12); do
    sample="$(sample_udp_backends "$port" "$count" 2 || true)"
    local satisfied=1
    local tag
    for tag in "${expected[@]}"; do
      if [ "$(udp_sample_hits "$sample" "$tag")" -lt "$min_each" ]; then
        satisfied=0
      fi
    done
    if [ "$satisfied" -eq 1 ]; then
      printf 'UDP :%s weighted sample over %s sessions: %s\n' \
        "$port" "$count" "$(tr '\n' ' ' <<<"$sample")"
      return 0
    fi
    sleep 3
  done
  echo "UDP :${port} never reached >=${min_each} sessions on each of ${expected[*]}; last sample=${sample}" >&2
  return 1
}

wait_for_exclusive_udp_backend() {
  # Every successful reply must carry `tag`, and at least `min_hits` replies
  # must arrive. This is the exact form of the zero-weight assertion: a
  # weight-0 leg is removed from the target set outright, so it can never
  # answer.
  local port="$1"
  local count="$2"
  local min_hits="$3"
  local tag="$4"
  local sample=""
  local attempt
  for attempt in $(seq 1 12); do
    sample="$(sample_udp_backends "$port" "$count" 2 || true)"
    local other
    other="$(awk -v want="$tag" '$1!=want && $1!="__drops__" {sum+=$2} END {print sum+0}' <<<"$sample")"
    if [ "$other" -eq 0 ] && [ "$(udp_sample_hits "$sample" "$tag")" -ge "$min_hits" ]; then
      printf 'UDP :%s served only %s over %s sessions: %s\n' \
        "$port" "$tag" "$count" "$(tr '\n' ' ' <<<"$sample")"
      return 0
    fi
    sleep 3
  done
  echo "UDP :${port} did not serve ${tag} exclusively; last sample=${sample}" >&2
  return 1
}

wait_for_invalid_leg_weight_is_dropped() {
  # A mixed rule (one resolvable leg, one unresolvable leg of equal weight)
  # must drop the invalid leg's share instead of handing it to the valid leg.
  # Pinned Gateway API v1.5.1 UDPRoute: "if an invalid backend is requested to
  # have 80% of the packets, then 80% of packets must be dropped instead."
  #
  # The thresholds are deliberately slack (round-robin makes the true split
  # ~50/50 of `count`), so this fails only on the two defects that matter:
  # every session succeeding (the invalid weight was renormalized onto the
  # valid leg) or every session dropping (the valid leg was withdrawn too).
  local port="$1"
  local count="$2"
  local min_hits="$3"
  local min_drops="$4"
  local tag="$5"
  local sample=""
  local attempt
  for attempt in $(seq 1 10); do
    sample="$(sample_udp_backends "$port" "$count" 2 || true)"
    if [ "$(udp_sample_hits "$sample" "$tag")" -ge "$min_hits" ] \
      && [ "$(udp_sample_hits "$sample" "__drops__")" -ge "$min_drops" ]; then
      printf 'UDP :%s mixed valid/invalid sample over %s sessions: %s\n' \
        "$port" "$count" "$(tr '\n' ' ' <<<"$sample")"
      return 0
    fi
    sleep 3
  done
  echo "UDP :${port} did not show both ${tag} replies and dropped sessions; last sample=${sample}" >&2
  return 1
}

wait_for_udproute_parent_condition() {
  local name="$1"
  local condition_type="$2"
  local expected_status="$3"
  local status=""
  for _ in $(seq 1 60); do
    status="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get udproute "$name" -o jsonpath="{.status.parents[0].conditions[?(@.type==\"${condition_type}\")].status}" 2>/dev/null || true)"
    if [ "$status" = "$expected_status" ]; then
      echo "UDPRoute ${name} ${condition_type}=${status}"
      return 0
    fi
    sleep 2
  done
  echo "UDPRoute ${name} did not reach ${condition_type}=${expected_status} (got '${status}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get udproute "$name" -o yaml >&2 || true
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

wait_for_gateway_listener_supported_kind() {
  local gateway="$1"
  local listener="$2"
  local kind="$3"
  local kinds=""
  for _ in $(seq 1 30); do
    kinds="$(kubectl -n "$DP_GATEWAY_NAMESPACE" get gateway "$gateway" -o jsonpath="{.status.listeners[?(@.name==\"${listener}\")].supportedKinds[*].kind}" 2>/dev/null || true)"
    if grep -qw "$kind" <<<"$kinds"; then
      echo "Gateway ${gateway} listener ${listener} supportedKinds=${kinds}"
      return 0
    fi
    sleep 2
  done
  echo "Gateway ${gateway} listener ${listener} never advertised supportedKinds ${kind} (got '${kinds}')" >&2
  kubectl -n "$DP_GATEWAY_NAMESPACE" get gateway "$gateway" -o yaml >&2 || true
  return 1
}

run_udp_blackbox_tests() {
  local report="$1"
  echo "" >> "$report"
  echo "## UDPRoute live data-plane" >> "$report"

  apply_udp_blackbox_routes

  wait_for_udproute_parent_condition blackbox-udp-main Accepted True | tee -a "$report"
  wait_for_udproute_parent_condition blackbox-udp-main ResolvedRefs True | tee -a "$report"
  wait_for_udproute_parent_condition blackbox-udp-main Programmed True | tee -a "$report"
  wait_for_gateway_listener_supported_kind ferrum-blackbox-udp udp-main UDPRoute | tee -a "$report"
  wait_for_gateway_listener_attached_routes ferrum-blackbox-udp udp-main 1 | tee -a "$report"

  wait_for_udp_echo "$UDP_BLACKBOX_PORT_MAIN" "blackbox-udp-a" "main-ping" | tee -a "$report"
  echo "UDPRoute parent/listener attachment served tagged datagram echo on :${UDP_BLACKBOX_PORT_MAIN}" >> "$report"

  wait_for_udproute_parent_condition blackbox-udp-cross Accepted True | tee -a "$report"
  wait_for_udproute_parent_condition blackbox-udp-cross ResolvedRefs True | tee -a "$report"
  wait_for_udproute_parent_condition blackbox-udp-cross Programmed True | tee -a "$report"
  wait_for_udp_echo "$UDP_BLACKBOX_PORT_CROSS" "blackbox-udp-cross" "cross-ping" | tee -a "$report"
  echo "UDPRoute cross-namespace backendRef with ReferenceGrant served echo on :${UDP_BLACKBOX_PORT_CROSS}" >> "$report"

  # Empty Service endpoints must fail closed (no backend datagram returns).
  wait_for_udproute_parent_condition blackbox-udp-fail Accepted True | tee -a "$report"
  assert_udp_exchange_fails "$UDP_BLACKBOX_PORT_FAIL" "empty UDP backend endpoints" | tee -a "$report"
  echo "UDPRoute empty-endpoint backend failed closed on :${UDP_BLACKBOX_PORT_FAIL}" >> "$report"

  # Missing Service backendRef: replace the fail route and require fail-closed traffic.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete udproute blackbox-udp-fail --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: blackbox-udp-invalid
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-udp
      sectionName: udp-fail
  rules:
    - backendRefs:
        - name: blackbox-udp-missing
          port: ${UDP_ECHO_BACKEND_PORT}
YAML
  wait_for_udproute_parent_condition blackbox-udp-invalid ResolvedRefs False | tee -a "$report"
  assert_udp_exchange_fails "$UDP_BLACKBOX_PORT_FAIL" "missing UDP backend Service" | tee -a "$report"
  echo "UDPRoute missing backend Service failed closed on :${UDP_BLACKBOX_PORT_FAIL}" >> "$report"

  # Cross-namespace backendRef without ReferenceGrant must fail closed.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete udproute blackbox-udp-invalid --wait=true
  kubectl -n "$BACKEND_NAMESPACE" delete referencegrant allow-infra-udproute-to-blackbox-udp-cross --ignore-not-found --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: blackbox-udp-denied
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-udp
      sectionName: udp-fail
  rules:
    - backendRefs:
        - name: blackbox-udp-cross
          namespace: ${BACKEND_NAMESPACE}
          port: ${UDP_ECHO_BACKEND_PORT}
YAML
  # Translation rejects unpermitted refs fail-closed. Require the controller's
  # negative status before probing traffic so the test cannot pass before the
  # new route has been reconciled.
  wait_for_udproute_parent_condition blackbox-udp-denied ResolvedRefs False | tee -a "$report"
  assert_udp_exchange_fails "$UDP_BLACKBOX_PORT_FAIL" "unpermitted cross-namespace UDP backendRef" | tee -a "$report"
  echo "UDPRoute unpermitted cross-namespace backendRef failed closed on :${UDP_BLACKBOX_PORT_FAIL}" >> "$report"

  wait_for_udp_echo "$UDP_BLACKBOX_PORT_MAIN" "blackbox-udp-a" "pre-update" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch udproute blackbox-udp-main --type=json \
    -p='[{"op":"replace","path":"/spec/rules/0/backendRefs/0/name","value":"blackbox-udp-b"}]'
  wait_for_udp_echo "$UDP_BLACKBOX_PORT_MAIN" "blackbox-udp-b" "post-update" | tee -a "$report"
  echo "UDPRoute update switched live datagram traffic to blackbox-udp-b on :${UDP_BLACKBOX_PORT_MAIN}" >> "$report"

  # backendRefs is a SET: both non-zero-weight legs must receive traffic. A
  # "first backendRef wins" implementation fails here because blackbox-udp-a
  # is never reached.
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch udproute blackbox-udp-main --type=merge \
    -p "$(udp_weighted_backend_patch 1 1)"
  wait_for_udproute_parent_condition blackbox-udp-main ResolvedRefs True | tee -a "$report"
  wait_for_weighted_udp_distribution "$UDP_BLACKBOX_PORT_MAIN" 24 4 \
    blackbox-udp-a blackbox-udp-b | tee -a "$report"
  echo "UDPRoute two-backend weighted set served both legs on :${UDP_BLACKBOX_PORT_MAIN}" >> "$report"

  # Weight-only update: dropping a leg to weight 0 removes it from the target
  # set, so the remaining leg must serve every session.
  kubectl -n "$DP_GATEWAY_NAMESPACE" patch udproute blackbox-udp-main --type=merge \
    -p "$(udp_weighted_backend_patch 1 0)"
  wait_for_exclusive_udp_backend "$UDP_BLACKBOX_PORT_MAIN" 12 6 blackbox-udp-a | tee -a "$report"
  echo "UDPRoute weight-only update withdrew the zero-weight leg on :${UDP_BLACKBOX_PORT_MAIN}" >> "$report"

  # Mixed valid/invalid weighted rule on the fail listener: the invalid leg's
  # share must be dropped, never renormalized onto the valid leg.
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete udproute blackbox-udp-denied --wait=true
  cat <<YAML | kubectl apply -f -
apiVersion: gateway.networking.k8s.io/v1alpha2
kind: UDPRoute
metadata:
  name: blackbox-udp-mixed
  namespace: ${DP_GATEWAY_NAMESPACE}
spec:
  parentRefs:
    - name: ferrum-blackbox-udp
      sectionName: udp-fail
  rules:
    - backendRefs:
        - name: blackbox-udp-a
          port: ${UDP_ECHO_BACKEND_PORT}
          weight: 1
        - name: blackbox-udp-missing
          port: ${UDP_ECHO_BACKEND_PORT}
          weight: 1
YAML
  wait_for_udproute_parent_condition blackbox-udp-mixed Accepted True | tee -a "$report"
  wait_for_udproute_parent_condition blackbox-udp-mixed ResolvedRefs False | tee -a "$report"
  wait_for_invalid_leg_weight_is_dropped "$UDP_BLACKBOX_PORT_FAIL" 16 3 3 blackbox-udp-a \
    | tee -a "$report"
  echo "UDPRoute mixed valid/invalid weighted rule dropped the invalid leg's share on :${UDP_BLACKBOX_PORT_FAIL}" >> "$report"

  wait_for_udp_echo "$UDP_BLACKBOX_PORT_DELETE" "blackbox-udp-a" "pre-delete" | tee -a "$report"
  kubectl -n "$DP_GATEWAY_NAMESPACE" delete udproute blackbox-udp-delete --wait=true
  local delete_ok=0
  local consecutive_failures=0
  for _ in $(seq 1 30); do
    if ! udp_exchange 127.0.0.1 "$UDP_BLACKBOX_PORT_DELETE" "post-delete" >/dev/null 2>&1; then
      consecutive_failures=$((consecutive_failures + 1))
      if [ "$consecutive_failures" -ge 3 ]; then
        delete_ok=1
        break
      fi
    else
      consecutive_failures=0
    fi
    sleep 2
  done
  if [ "$delete_ok" -ne 1 ]; then
    echo "deleted UDPRoute kept serving UDP echo on :${UDP_BLACKBOX_PORT_DELETE}" >&2
    return 1
  fi
  echo "deleted UDPRoute stopped serving on :${UDP_BLACKBOX_PORT_DELETE}" >> "$report"
}

run_blackbox() {
  local report="$RESULTS_DIR/gateway-api-blackbox.md"
  apply_udp_blackbox_backends
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-udp-a --timeout=180s
  kubectl -n "$DP_GATEWAY_NAMESPACE" rollout status deployment/blackbox-udp-b --timeout=180s
  kubectl -n "$BACKEND_NAMESPACE" rollout status deployment/blackbox-udp-cross --timeout=180s
  run_udp_blackbox_tests "$report"
}

collect_diagnostics() {
  set +e
  kubectl get udproutes -A -o yaml > "$RESULTS_DIR/gateway-api-udproutes.yaml"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-udp-a --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-udp-a.log"
  kubectl -n "$DP_GATEWAY_NAMESPACE" logs deployment/blackbox-udp-b --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-udp-b.log"
  kubectl -n "$BACKEND_NAMESPACE" logs deployment/blackbox-udp-cross --all-containers --tail=1000 > "$RESULTS_DIR/blackbox-udp-cross.log"
  {
    echo ""
    echo "UDPRoute black-box ports: ${UDP_BLACKBOX_PORT_MAIN},${UDP_BLACKBOX_PORT_CROSS},${UDP_BLACKBOX_PORT_FAIL},${UDP_BLACKBOX_PORT_DELETE}"
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
