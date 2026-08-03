#!/usr/bin/env bash
set -euo pipefail

# Real two-CP/two-DP poller partition gate. All state transitions are observed
# through active bounded polling; the only sleeps are polling-loop cadences.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../../.." && pwd)"
MANIFESTS="$ROOT_DIR/tests/k8s/multicluster-poller-partition/manifests.yaml"
RESULTS_DIR="${FERRUM_POLLER_RESULTS_DIR:-$ROOT_DIR/target/multicluster-poller-partition}"
ARTIFACT_DIR="${ARTIFACT_DIR:-$ROOT_DIR/.context/multicluster-poller-partition}"
source "$ROOT_DIR/tests/k8s/lib/live_assertions.sh"
source "$ROOT_DIR/tests/k8s/lib/spire.sh"

CLUSTER_A="${CLUSTER_A:-ferrum-poller-a}"
CLUSTER_B="${CLUSTER_B:-ferrum-poller-b}"
CONTEXT_A="kind-$CLUSTER_A"
CONTEXT_B="kind-$CLUSTER_B"
TOXIPROXY_CONTAINER="${TOXIPROXY_CONTAINER:-ferrum-poller-toxiproxy}"
TOXIPROXY_IMAGE="${TOXIPROXY_IMAGE:-ghcr.io/shopify/toxiproxy:2.12.0@sha256:9378ed52a28bc50edc1350f936f518f31fa95f0d15917d6eb40b8e376d1a214e}"
NS="${FERRUM_NAMESPACE:-ferrum}"
SPIRE_NS="${FERRUM_SPIRE_NAMESPACE:-spire-system}"
TD_A="${FERRUM_TRUST_DOMAIN_A:-cluster-a.test}"
TD_B="${FERRUM_TRUST_DOMAIN_B:-cluster-b.test}"
IMAGE_REPOSITORY="${FERRUM_IMAGE_REPOSITORY:-ferrum-edge}"
IMAGE_TAG="${FERRUM_IMAGE_TAG:-multicluster-poller-partition}"
IMAGE="$IMAGE_REPOSITORY:$IMAGE_TAG"
LIVE_ASSERTIONS_FILE="${FERRUM_LIVE_ASSERTIONS_FILE:-$RESULTS_DIR/live-assertions.json}"
LIVE_PLATFORM_PROFILE="${FERRUM_LIVE_PLATFORM_PROFILE:-kind-spire-toxiproxy-multicluster-pollers}"

FED_AB=federation-a-to-b
DISC_AB=discovery-a-to-b
FED_BA=federation-b-to-a
DISC_BA=discovery-b-to-a
FED_AB_PORT=15441
DISC_AB_PORT=15442
FED_BA_PORT=15443
DISC_BA_PORT=15444
NODE_A="" NODE_B="" TOXI_IP="" ADMIN_SECRET="" JWT_A="" JWT_B=""
INITIAL_TRUST_AGE=0 INITIAL_ENDPOINT_AGE=0
INITIAL_FEDERATION_SUCCESS_AT=0 INITIAL_DISCOVERY_SUCCESSES=0
RECORDED=" "

REQUIRED_LIVE_ASSERTIONS=(
  multicluster_poller.initial.polled_trust_endpoints_installed
  multicluster_poller.transient.last_good_retained
  multicluster_poller.transient.cache_age_increased
  multicluster_poller.endpoint.expired_fail_closed
  multicluster_poller.endpoint.remote_target_removed
  multicluster_poller.endpoint.recovered_same_generation
  multicluster_poller.trust.expired_fail_closed
  multicluster_poller.trust.inbound_outbound_recomputed
  multicluster_poller.trust.recovered_same_generation
  multicluster_poller.metrics.failure_backoff_recovery_bounded
  multicluster_poller.metrics.admin_status_parity
  multicluster_poller.withdrawal.inflight_generation_retired
  multicluster_poller.withdrawal.retired_state_not_reinstalled
)

mkdir -p "$RESULTS_DIR" "$ARTIFACT_DIR"

log() { printf '\n[multicluster-poller] %s\n' "$*"; }
need() { command -v "$1" >/dev/null 2>&1 || { echo "missing required command: $1" >&2; exit 127; }; }

record() {
  local id="$1" status="$2" outcome="${3:-}" diagnostic="${4:-}"
  ferrum_live_record_assertion "$LIVE_ASSERTIONS_FILE" "$id" "$status" \
    "mesh-dp" "mesh-dp" "$outcome" "" "" "" "$diagnostic"
  RECORDED="$RECORDED$id "
}

cleanup() {
  set +e
  if [[ -n "$TOXI_IP" ]]; then collect_diagnostics; fi
  docker rm -f "$TOXIPROXY_CONTAINER" >/dev/null 2>&1
  kind delete cluster --name "$CLUSTER_A" >/dev/null 2>&1
  kind delete cluster --name "$CLUSTER_B" >/dev/null 2>&1
}
trap cleanup EXIT

preflight() {
  for command in docker kind kubectl curl python3 openssl awk sed; do need "$command"; done
  docker info >/dev/null
  [[ "${FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE:-}" == true ]] || {
    echo "set FERRUM_MULTICLUSTER_LIVE_ACK_DISPOSABLE=true" >&2; exit 1;
  }
  if kind get clusters | grep -Fxq "$CLUSTER_A" || kind get clusters | grep -Fxq "$CLUSTER_B"; then
    echo "refusing to share pre-existing kind cluster state" >&2; exit 1
  fi
  if docker inspect "$TOXIPROXY_CONTAINER" >/dev/null 2>&1; then
    echo "refusing to share pre-existing Toxiproxy state" >&2; exit 1
  fi
}

wait_until() {
  local label="$1" timeout="$2" predicate="$3"; shift 3
  local deadline=$((SECONDS + timeout))
  while (( SECONDS < deadline )); do
    if run_wait_predicate "$predicate" "$@"; then return 0; fi
    sleep 1
  done
  echo "timed out waiting for $label (${timeout}s)" >&2
  return 1
}

# Keep polling dispatch explicit. Besides making the live contract auditable,
# this prevents a caller-controlled executable word from becoming an opaque
# tool-dispatch surface inside trusted CI automation.
run_wait_predicate() {
  local predicate="$1"; shift
  case "$predicate" in
    ages_increased_below_stale) ages_increased_below_stale "$@" ;;
    curl) curl "$@" ;;
    failure_counters_positive) failure_counters_positive "$@" ;;
    fresh_state) fresh_state "$@" ;;
    kubectl) kubectl "$@" ;;
    no_configured_state) no_configured_state "$@" ;;
    proxy_activity_increased) proxy_activity_increased "$@" ;;
    state_matches) state_matches "$@" ;;
    traffic_not_found) traffic_not_found "$@" ;;
    traffic_once) traffic_once "$@" ;;
    *) echo "unsupported wait predicate: $predicate" >&2; return 2 ;;
  esac
}

spire_bundle_b64der() {
  ferrum_spire_server_exec "$1" "$SPIRE_NS" bundle show -format pem 2>/dev/null |
    awk '/BEGIN CERTIFICATE/{cap=1;buf="";next}/END CERTIFICATE/{if(cap)print buf;cap=0;next}cap{gsub(/[[:space:]]/,"");buf=buf $0}'
}

mint_admin_jwt() {
  python3 - "$ADMIN_SECRET" <<'PY'
import base64, hashlib, hmac, json, sys, time, uuid
secret=sys.argv[1].encode(); now=int(time.time())
def enc(v): return base64.urlsafe_b64encode(json.dumps(v,separators=(",",":"),sort_keys=True).encode()).rstrip(b"=").decode()
head=enc({"alg":"HS256","typ":"JWT"})
body=enc({"iss":"ferrum-edge","sub":"poller-live","iat":now,"nbf":now-1,"exp":now+3600,"jti":str(uuid.uuid4()),"role":"admin"})
data=f"{head}.{body}"; sig=base64.urlsafe_b64encode(hmac.new(secret,data.encode(),hashlib.sha256).digest()).rstrip(b"=").decode()
print(f"{data}.{sig}")
PY
}

create_clusters_and_fault_layer() {
  kind create cluster --name "$CLUSTER_A" --wait 180s
  kind create cluster --name "$CLUSTER_B" --wait 180s
  kind load docker-image "$IMAGE" --name "$CLUSTER_A"
  kind load docker-image "$IMAGE" --name "$CLUSTER_B"
  NODE_A="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLUSTER_A-control-plane")"
  NODE_B="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$CLUSTER_B-control-plane")"
  [[ -n "$NODE_A" && -n "$NODE_B" ]] || { echo "kind node IP discovery failed" >&2; return 1; }

  docker run -d --name "$TOXIPROXY_CONTAINER" --network kind "$TOXIPROXY_IMAGE" \
    -host=0.0.0.0 -proxy-metrics >/dev/null
  TOXI_IP="$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' "$TOXIPROXY_CONTAINER")"
  [[ -n "$TOXI_IP" ]] || { echo "Toxiproxy IP discovery failed" >&2; return 1; }
  wait_until "Toxiproxy API" 30 curl -fsS "http://$TOXI_IP:8474/version" >/dev/null

  create_proxy "$FED_AB" "$FED_AB_PORT" "$NODE_B:32443"
  create_proxy "$DISC_AB" "$DISC_AB_PORT" "$NODE_B:32551"
  create_proxy "$FED_BA" "$FED_BA_PORT" "$NODE_A:32443"
  create_proxy "$DISC_BA" "$DISC_BA_PORT" "$NODE_A:32551"
  local count
  count="$(curl -fsS "http://$TOXI_IP:8474/proxies" | python3 -c 'import json,sys;print(len(json.load(sys.stdin)))')"
  [[ "$count" == 4 ]] || { echo "Toxiproxy fixture startup incomplete: $count/4 proxies" >&2; return 1; }
}

create_proxy() {
  curl -fsS -X POST -H 'Content-Type: application/json' "http://$TOXI_IP:8474/proxies" \
    --data "{\"name\":\"$1\",\"listen\":\"0.0.0.0:$2\",\"upstream\":\"$3\",\"enabled\":true}" >/dev/null
}

set_proxy() {
  curl -fsS -X POST -H 'Content-Type: application/json' "http://$TOXI_IP:8474/proxies/$1" \
    --data "{\"enabled\":$2}" >/dev/null
}

set_all_proxies() { local name; for name in "$FED_AB" "$DISC_AB" "$FED_BA" "$DISC_BA"; do set_proxy "$name" "$1"; done; }

add_latency() {
  curl -fsS -X POST -H 'Content-Type: application/json' "http://$TOXI_IP:8474/proxies/$1/toxics" \
    --data '{"name":"inflight","type":"latency","stream":"downstream","toxicity":1,"attributes":{"latency":60000,"jitter":0}}' >/dev/null
}

remove_latency() { curl -fsS -X DELETE "http://$TOXI_IP:8474/proxies/$1/toxics/inflight" >/dev/null; }

proxy_received_downstream_bytes() {
  curl -fsS "http://$TOXI_IP:8474/metrics" | awk -v proxy="$1" '
    /toxiproxy_proxy_received_bytes_total/ &&
      index($0,"proxy=\"" proxy "\"") &&
      index($0,"direction=\"downstream\"") {
        v=$NF+0; sum+=v; found=1
      }
    END {if(!found) exit 2; printf "%.0f\n",sum}'
}

proxy_activity_increased() {
  local current
  current="$(proxy_received_downstream_bytes "$1")" || return 1
  (( current > $2 ))
}

generate_transport_material() {
  openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=ferrum-poller-live-ca \
    -keyout "$ARTIFACT_DIR/ca-key.pem" -out "$ARTIFACT_DIR/ca.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj /CN=ferrum-poller-server \
    -keyout "$ARTIFACT_DIR/server-key.pem" -out "$ARTIFACT_DIR/server.csr" >/dev/null 2>&1
  printf 'subjectAltName=IP:%s\nextendedKeyUsage=serverAuth\n' "$TOXI_IP" > "$ARTIFACT_DIR/server.ext"
  openssl x509 -req -days 1 -in "$ARTIFACT_DIR/server.csr" -CA "$ARTIFACT_DIR/ca.pem" \
    -CAkey "$ARTIFACT_DIR/ca-key.pem" -CAcreateserial -extfile "$ARTIFACT_DIR/server.ext" \
    -out "$ARTIFACT_DIR/server.pem" >/dev/null 2>&1
  openssl req -newkey rsa:2048 -nodes -subj /CN=ferrum-poller-dp \
    -keyout "$ARTIFACT_DIR/client-key.pem" -out "$ARTIFACT_DIR/client.csr" >/dev/null 2>&1
  printf 'extendedKeyUsage=clientAuth\n' > "$ARTIFACT_DIR/client.ext"
  openssl x509 -req -days 1 -in "$ARTIFACT_DIR/client.csr" -CA "$ARTIFACT_DIR/ca.pem" \
    -CAkey "$ARTIFACT_DIR/ca-key.pem" -CAcreateserial -extfile "$ARTIFACT_DIR/client.ext" \
    -out "$ARTIFACT_DIR/client.pem" >/dev/null 2>&1
}

register_spire_workload() {
  local context="$1" td="$2" node parent
  while IFS= read -r node; do
    parent="$(ferrum_spire_k8s_psat_agent_parent_id_for_node "$context" "$SPIRE_NS" "$td" "$node")"
    ferrum_spire_register_k8s_workload "$context" "$SPIRE_NS" \
      "spiffe://$td/ns/$NS/sa/mesh-dp" "$parent" "$NS" mesh-dp "k8s:node-name:$node"
  done < <(ferrum_spire_agent_nodes "$context" "$SPIRE_NS")
}

apply_support_material() {
  local context="$1" td="$2" cluster="$3" local_secret="$4" peer_secret="$5" bundle
  kubectl --context "$context" create namespace "$NS" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
  kubectl --context "$context" -n "$NS" create secret generic poller-transport \
    --from-file=ca.pem="$ARTIFACT_DIR/ca.pem" --from-file=server.pem="$ARTIFACT_DIR/server.pem" \
    --from-file=server-key.pem="$ARTIFACT_DIR/server-key.pem" --from-file=client.pem="$ARTIFACT_DIR/client.pem" \
    --from-file=client-key.pem="$ARTIFACT_DIR/client-key.pem" --dry-run=client -o yaml |
    kubectl --context "$context" apply -f -
  kubectl --context "$context" -n "$NS" create secret generic poller-secrets \
    --from-literal=admin-jwt-secret="$ADMIN_SECRET" --from-literal=discovery-jwt-secret="$local_secret" \
    --from-literal=remote-discovery-credentials="{\"peer\":\"$peer_secret\"}" \
    --dry-run=client -o yaml | kubectl --context "$context" apply -f -
  bundle="$(spire_bundle_b64der "$context")"
  [[ -n "$bundle" ]] || { echo "empty SPIRE bundle for $cluster" >&2; return 1; }
  python3 - "$td" "$bundle" > "$ARTIFACT_DIR/bundle-$cluster.json" <<'PY'
import json,sys
print(json.dumps({"trust_domain":sys.argv[1],"x509_authorities":sys.argv[2].splitlines(),"jwt_authorities":[]}))
PY
  kubectl --context "$context" -n "$NS" create configmap federation-bundle \
    --from-file=bundle.json="$ARTIFACT_DIR/bundle-$cluster.json" --dry-run=client -o yaml |
    kubectl --context "$context" apply -f -
}

render_mesh_config() {
  local context="$1" local_cluster="$2" local_td="$3" local_service="$4" local_region="$5"
  local peer_cluster="$6" peer_td="$7" peer_service="$8" peer_node="$9" fed_port="${10}" disc_port="${11}"
  local peer_context="${12}" local_bundle peer_bundle remote_block
  local_bundle="$(spire_bundle_b64der "$context")"
  peer_bundle="$(spire_bundle_b64der "$peer_context")"
  remote_block="$(cat <<YAML
  multi_cluster:
    local_cluster: $local_cluster
    remote_clusters:
      - name: $peer_cluster
        trust_domain: $peer_td
        network: net-$peer_cluster
        control_plane_url: grpcs://$TOXI_IP:$disc_port
        federation_endpoint: https://$TOXI_IP:$fed_port/bundle
        discovery_credential_ref: peer
    east_west_gateways:
      - name: ew-$peer_cluster
        namespace: $NS
        host: $peer_node
        port: 31506
        sni_hosts:
          - $peer_service.$NS.svc.cluster.local
        trust_domain: $peer_td
        network: net-$peer_cluster
YAML
)"
  apply_mesh_config "$context" "$local_cluster" "$local_td" "$local_service" "$local_region" "$local_bundle" "$remote_block" "$peer_td" "$peer_bundle"
}

apply_mesh_config() {
  local context="$1" local_cluster="$2" local_td="$3" local_service="$4" local_region="$5" local_bundle="$6" remote_block="${7:-}"
  local peer_td="${8:-}" peer_bundle="${9:-}" authorities="" federated="" line
  while IFS= read -r line; do [[ -n "$line" ]] && authorities+="        - $line"$'\n'; done <<<"$local_bundle"
  if [[ -n "$peer_td" && -n "$peer_bundle" ]]; then
    federated="    federated:"$'\n'"      - trust_domain: $peer_td"$'\n'"        x509_authorities:"$'\n'
    while IFS= read -r line; do [[ -n "$line" ]] && federated+="          - $line"$'\n'; done <<<"$peer_bundle"
  fi
  kubectl --context "$context" -n "$NS" create configmap mesh-config --from-literal=mesh.yaml="$(cat <<YAML
mesh:
  workloads:
    - spiffe_id: spiffe://$local_td/ns/$NS/sa/mesh-dp
      service_name: $local_service
      namespace: $NS
      trust_domain: $local_td
      service_account: mesh-dp
      addresses: [127.0.0.1]
      locality: $local_region/zone-1
      ports:
        - {port: 8080, protocol: http, name: http}
      selector:
        labels: {app: echo}
        namespace: $NS
  services:
    - name: $local_service
      namespace: $NS
      ports:
        - {port: 8080, protocol: http, name: http}
      workloads:
        - spiffe_id: spiffe://$local_td/ns/$NS/sa/mesh-dp
  trust_bundles:
    local:
      trust_domain: $local_td
      x509_authorities:
$authorities$federated  peer_authentications:
    - name: strict
      namespace: $NS
      mtls_mode: strict
$remote_block
YAML
)" --dry-run=client -o yaml | kubectl --context "$context" apply -f -
}

apply_manifest() {
  local context="$1" td="$2" cluster="$3" service="$4" body="$5" region="$6"
  sed -e "s|__NAMESPACE__|$NS|g" -e "s|__TRUST_DOMAIN__|$td|g" \
    -e "s|__CLUSTER_NAME__|$cluster|g" -e "s|__ECHO_SERVICE__|$service|g" \
    -e "s|__ECHO_BODY__|$body|g" -e "s|__REGION__|$region|g" -e "s|__IMAGE__|$IMAGE|g" \
    "$MANIFESTS" | kubectl --context "$context" apply -f -
  kubectl --context "$context" -n "$NS" rollout status deploy/ferrum-cp --timeout=5m
  kubectl --context "$context" -n "$NS" rollout status deploy/federation-bundle --timeout=5m
  kubectl --context "$context" -n "$NS" rollout status deploy/echo --timeout=5m
}

admin_json() {
  kubectl --context "$1" -n "$NS" exec deploy/echo -c probe -- \
    curl -fsS -m 5 -H "Authorization: Bearer $2" http://127.0.0.1:15020/mesh/remote-clusters
}

metrics() {
  kubectl --context "$1" -n "$NS" exec deploy/echo -c probe -- \
    curl -fsS -m 5 -H "Authorization: Bearer $2" http://127.0.0.1:15020/metrics
}

state_matches() {
  local context="$1" token="$2" peer="$3" discovered="$4" trust_source="$5" outbound="$6" inbound="$7"
  admin_json "$context" "$token" | python3 -c '
import json,sys
peer,disc,source,outbound,inbound=sys.argv[1:]
d=json.load(sys.stdin); rows=[r for r in d["configured"] if r["cluster_name"]==peer]
ok=len(rows)==1 and rows[0]["discovered"]==(disc=="true") and rows[0]["trust_source"]==source and rows[0]["outbound_trust_active"]==(outbound=="true") and rows[0]["inbound_trust_active"]==(inbound=="true")
raise SystemExit(0 if ok else 1)' "$peer" "$discovered" "$trust_source" "$outbound" "$inbound"
}

no_configured_state() {
  admin_json "$1" "$2" | python3 -c 'import json,sys; d=json.load(sys.stdin); raise SystemExit(0 if not d["configured"] and not d["discovered"] else 1)'
}

traffic_once() {
  local context="$1" service="$2" expected="$3"
  kubectl --context "$context" -n "$NS" exec deploy/echo -c probe -- sh -c '
    body="$(curl -sS -m 5 -o /tmp/body -w "%{http_code}" -H "Host: $1" http://127.0.0.1:15001/ || true)"
    [ "$body" = 200 ] && grep -Fq "$2" /tmp/body
  ' sh "$service.$NS.svc.cluster.local" "$expected"
}

traffic_fails() { ! traffic_once "$1" "$2" "$3"; }

traffic_not_found() {
  local context="$1" service="$2"
  kubectl --context "$context" -n "$NS" exec deploy/echo -c probe -- sh -c '
    : >/tmp/body
    status="$(curl -sS -m 5 -o /tmp/body -w "%{http_code}" -H "Host: $1" http://127.0.0.1:15001/ || true)"
    [ "$status" = 404 ] && grep -Fq "Not Found" /tmp/body
  ' sh "$service.$NS.svc.cluster.local"
}

metric_value() {
  local context="$1" token="$2" metric="$3" selector="$4"
  metrics "$context" "$token" | awk -v metric="$metric" -v selector="$selector" '
    index($0,metric "{")==1 && index($0,selector){print $NF; found=1; exit} END{if(!found) print 0}'
}

failure_counters_positive() {
  local ff df
  ff="$(metric_value "$1" "$2" ferrum_mesh_federation_poll_failures_total "trust_domain=\"$3\"")"
  df="$(metric_value "$1" "$2" ferrum_mesh_remote_discovery_poll_failures_total "cluster=\"$4\"")"
  (( ff > 0 && df > 0 ))
}

ages_between() {
  admin_json "$1" "$2" | python3 -c '
import json,sys
peer,low,high=sys.argv[1],int(sys.argv[2]),int(sys.argv[3]); d=json.load(sys.stdin); r=next(x for x in d["configured"] if x["cluster_name"]==peer); x=next(y for y in d["discovered"] if y["cluster_name"]==peer)
raise SystemExit(0 if low <= r["trust_bundle_age_seconds"] < high and low <= x["age_seconds"] < high else 1)' "$3" "$4" "$5"
}

fresh_state() { ages_between "$1" "$2" "$3" 0 5; }

admin_ages() {
  admin_json "$1" "$2" | python3 -c '
import json,sys
d=json.load(sys.stdin); peer=sys.argv[1]; r=next(x for x in d["configured"] if x["cluster_name"]==peer); e=next(x for x in d["discovered"] if x["cluster_name"]==peer)
print(r["trust_bundle_age_seconds"],e["age_seconds"])' "$3"
}

ages_increased_below_stale() {
  local ages trust_age endpoint_age
  ages="$(admin_ages "$1" "$2" "$3")" || return 1
  read -r trust_age endpoint_age <<<"$ages"
  (( trust_age > INITIAL_TRUST_AGE && endpoint_age > INITIAL_ENDPOINT_AGE && endpoint_age < 8 && trust_age < 12 ))
}

capture_boundary() {
  admin_json "$1" "$2" > "$RESULTS_DIR/$3.json"
  metrics "$1" "$2" > "$RESULTS_DIR/$3.prom"
}

assert_metric_admin_parity() {
  local context="$1" token="$2" peer="$3" td="$4"
  local json_file="$RESULTS_DIR/parity.json" metrics_file="$RESULTS_DIR/parity.prom"
  admin_json "$context" "$token" > "$json_file"; metrics "$context" "$token" > "$metrics_file"
  python3 - "$json_file" "$metrics_file" "$peer" "$td" <<'PY'
import json,re,sys
d=json.load(open(sys.argv[1])); text=open(sys.argv[2]).read(); peer,td=sys.argv[3:]
r=next(x for x in d["configured"] if x["cluster_name"]==peer); e=next(x for x in d["discovered"] if x["cluster_name"]==peer)
def metric(name, labels):
  for line in text.splitlines():
    if line.startswith(name+"{") and all(f'{k}="{v}"' in line for k,v in labels.items()): return float(line.rsplit(" ",1)[1])
  raise SystemExit(f"missing {name}")
fa=metric("ferrum_mesh_federation_bundle_age_seconds",{"trust_domain":td})
ea=metric("ferrum_mesh_remote_discovery_endpoint_age_seconds",{"cluster":peer,"trust_domain":td})
if abs(fa-r["trust_bundle_age_seconds"])>2 or abs(ea-e["age_seconds"])>2: raise SystemExit("admin/metric cache-age parity exceeded 2s")
if 'endpoint="redacted"' not in text and "ferrum_mesh_federation_poll_failures_total" in text: raise SystemExit("federation endpoint label not redacted")
if 'control_plane="redacted"' not in text and "ferrum_mesh_remote_discovery_poll_failures_total" in text: raise SystemExit("control-plane label not redacted")
families={
 "ferrum_mesh_federation_poll_failures_total":f'trust_domain="{td}"',
 "ferrum_mesh_federation_bundle_age_seconds":f'trust_domain="{td}"',
 "ferrum_mesh_remote_discovery_poll_failures_total":f'cluster="{peer}"',
 "ferrum_mesh_remote_discovery_poll_successes_total":f'cluster="{peer}"',
 "ferrum_mesh_remote_discovery_endpoint_age_seconds":f'cluster="{peer}"',
}
for family,selector in families.items():
  matches=[line for line in text.splitlines() if line.startswith(family+"{") and selector in line]
  if len(matches)!=1: raise SystemExit(f"bounded cardinality violated for {family}: {len(matches)}")
PY
}

signal_reload() {
  local context="$1"
  wait_until "projected withdrawn mesh config" 30 kubectl --context "$context" -n "$NS" exec deploy/echo -c signal -- \
    sh -c '! grep -q "remote_clusters" /mesh/mesh.yaml'
  kubectl --context "$context" -n "$NS" exec deploy/echo -c signal -- sh -c \
    'pid="$(pidof ferrum-edge)"; [ -n "$pid" ]; kill -HUP $pid'
}

deploy_topology() {
  ferrum_spire_apply_minimal "$CONTEXT_A" "$TD_A" "$SPIRE_NS"
  ferrum_spire_apply_minimal "$CONTEXT_B" "$TD_B" "$SPIRE_NS"
  ferrum_spire_wait_ready "$CONTEXT_A" "$SPIRE_NS" 5m
  ferrum_spire_wait_ready "$CONTEXT_B" "$SPIRE_NS" 5m
  register_spire_workload "$CONTEXT_A" "$TD_A"
  register_spire_workload "$CONTEXT_B" "$TD_B"
  ADMIN_SECRET="$(openssl rand -hex 32)"
  local secret_a secret_b
  secret_a="$(openssl rand -hex 32)"; secret_b="$(openssl rand -hex 32)"
  apply_support_material "$CONTEXT_A" "$TD_A" cluster-a "$secret_a" "$secret_b"
  apply_support_material "$CONTEXT_B" "$TD_B" cluster-b "$secret_b" "$secret_a"
  render_mesh_config "$CONTEXT_A" cluster-a "$TD_A" echo-a region-a cluster-b "$TD_B" echo-b "$NODE_B" "$FED_AB_PORT" "$DISC_AB_PORT" "$CONTEXT_B"
  render_mesh_config "$CONTEXT_B" cluster-b "$TD_B" echo-b region-b cluster-a "$TD_A" echo-a "$NODE_A" "$FED_BA_PORT" "$DISC_BA_PORT" "$CONTEXT_A"
  apply_manifest "$CONTEXT_A" "$TD_A" cluster-a echo-a echo-a region-a
  apply_manifest "$CONTEXT_B" "$TD_B" cluster-b echo-b echo-b region-b
  JWT_A="$(mint_admin_jwt)"; JWT_B="$(mint_admin_jwt)"
}

scenario_initial() {
  wait_until "A initial polled trust and endpoints" 90 state_matches "$CONTEXT_A" "$JWT_A" cluster-b true polled true true
  wait_until "B initial polled trust and endpoints" 90 state_matches "$CONTEXT_B" "$JWT_B" cluster-a true polled true true
  wait_until "A initial cache freshness" 20 fresh_state "$CONTEXT_A" "$JWT_A" cluster-b
  read -r INITIAL_TRUST_AGE INITIAL_ENDPOINT_AGE < <(admin_ages "$CONTEXT_A" "$JWT_A" cluster-b)
  INITIAL_FEDERATION_SUCCESS_AT="$(metric_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_federation_last_success_timestamp_seconds "trust_domain=\"$TD_B\"")"
  INITIAL_DISCOVERY_SUCCESSES="$(metric_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_remote_discovery_poll_successes_total "cluster=\"cluster-b\"")"
  wait_until "A to B initial traffic" 60 traffic_once "$CONTEXT_A" echo-b echo-b
  wait_until "B to A initial traffic" 60 traffic_once "$CONTEXT_B" echo-a echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.initial.polled_trust_endpoints_installed
  record multicluster_poller.initial.polled_trust_endpoints_installed pass "both-directions-polled-and-200" "poller.initial.polled_trust_endpoints_installed.{json,prom}"
}

scenario_transient() {
  set_all_proxies false
  wait_until "bounded poll failures" 15 failure_counters_positive "$CONTEXT_A" "$JWT_A" "$TD_B" cluster-b
  wait_until "last-good cache ages increase below both stale windows" 12 ages_increased_below_stale "$CONTEXT_A" "$JWT_A" cluster-b
  traffic_once "$CONTEXT_A" echo-b echo-b; traffic_once "$CONTEXT_B" echo-a echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.transient.last_good_retained
  record multicluster_poller.transient.last_good_retained pass "traffic-200-during-short-partition" "poller.transient.last_good_retained.{json,prom}"
  record multicluster_poller.transient.cache_age_increased pass "trust-and-endpoint-age-3-to-7-seconds" "poller.transient.last_good_retained.json"
  local ff df
  ff="$(metric_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_federation_poll_failures_total "trust_domain=\"$TD_B\"")"
  df="$(metric_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_remote_discovery_poll_failures_total "cluster=\"cluster-b\"")"
  (( ff >= 1 && ff <= 5 && df >= 1 && df <= 5 )) || { echo "unbounded failure series during backoff: federation=$ff discovery=$df" >&2; return 1; }
  set_all_proxies true
  wait_until "same-generation transient recovery" 40 fresh_state "$CONTEXT_A" "$JWT_A" cluster-b
  wait_until "same-generation reverse recovery" 40 fresh_state "$CONTEXT_B" "$JWT_B" cluster-a
  local recovered_federation_at recovered_discovery_successes
  recovered_federation_at="$(metric_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_federation_last_success_timestamp_seconds "trust_domain=\"$TD_B\"")"
  recovered_discovery_successes="$(metric_value "$CONTEXT_A" "$JWT_A" ferrum_mesh_remote_discovery_poll_successes_total "cluster=\"cluster-b\"")"
  (( recovered_federation_at > INITIAL_FEDERATION_SUCCESS_AT && recovered_discovery_successes > INITIAL_DISCOVERY_SUCCESSES )) || {
    echo "poll recovery metrics did not advance" >&2; return 1;
  }
  assert_metric_admin_parity "$CONTEXT_A" "$JWT_A" cluster-b "$TD_B"
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.metrics.failure_backoff_recovery_cache_age
  record multicluster_poller.metrics.failure_backoff_recovery_bounded pass "bounded-series-redacted-labels-recovered" "poller.metrics.failure_backoff_recovery_cache_age.prom"
  record multicluster_poller.metrics.admin_status_parity pass "cache-ages-within-two-seconds" "parity.{json,prom}"
}

scenario_endpoint_expiry() {
  set_proxy "$DISC_AB" false
  wait_until "endpoint stale eviction independent of trust" 40 state_matches "$CONTEXT_A" "$JWT_A" cluster-b false polled true true
  wait_until "remote target removed with no-route reason" 20 traffic_not_found "$CONTEXT_A" echo-b
  traffic_once "$CONTEXT_B" echo-a echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.endpoint.expired_fail_closed_target_removed
  record multicluster_poller.endpoint.expired_fail_closed pass "endpoint-window-8s-404-Not-Found-trust-still-polled" "poller.endpoint.expired_fail_closed_target_removed.{json,prom}"
  record multicluster_poller.endpoint.remote_target_removed pass "configured-peer-not-discovered" "poller.endpoint.expired_fail_closed_target_removed.json"
  set_proxy "$DISC_AB" true
  wait_until "endpoint reinstall by live generation" 45 state_matches "$CONTEXT_A" "$JWT_A" cluster-b true polled true true
  wait_until "endpoint traffic recovery" 30 traffic_once "$CONTEXT_A" echo-b echo-b
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.endpoint.recovered_same_generation
  record multicluster_poller.endpoint.recovered_same_generation pass "no-slice-change-200" "poller.endpoint.recovered_same_generation.{json,prom}"
}

scenario_trust_expiry() {
  set_proxy "$FED_AB" false; set_proxy "$FED_BA" false
  wait_until "A trust stale eviction" 50 state_matches "$CONTEXT_A" "$JWT_A" cluster-b false none false false
  wait_until "B trust stale eviction" 50 state_matches "$CONTEXT_B" "$JWT_B" cluster-a false none false false
  wait_until "A trust fail closed with no-route reason" 15 traffic_not_found "$CONTEXT_A" echo-b
  wait_until "B trust fail closed with no-route reason" 15 traffic_not_found "$CONTEXT_B" echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.trust.expired_fail_closed_recomputed
  record multicluster_poller.trust.expired_fail_closed pass "trust-window-12s-bidirectional-404-Not-Found" "poller.trust.expired_fail_closed_recomputed.{json,prom}"
  record multicluster_poller.trust.inbound_outbound_recomputed pass "outbound=false-inbound=false-discovered=false" "poller.trust.expired_fail_closed_recomputed.json"
  set_proxy "$FED_AB" true; set_proxy "$FED_BA" true
  wait_until "A trust same-generation recovery" 60 state_matches "$CONTEXT_A" "$JWT_A" cluster-b true polled true true
  wait_until "B trust same-generation recovery" 60 state_matches "$CONTEXT_B" "$JWT_B" cluster-a true polled true true
  wait_until "A recovered traffic" 30 traffic_once "$CONTEXT_A" echo-b echo-b
  wait_until "B recovered traffic" 30 traffic_once "$CONTEXT_B" echo-a echo-a
  capture_boundary "$CONTEXT_A" "$JWT_A" poller.trust.recovered_same_generation
  record multicluster_poller.trust.recovered_same_generation pass "trust-and-discovery-reinstalled-without-slice" "poller.trust.recovered_same_generation.{json,prom}"
}

scenario_inflight_withdrawal() {
  local fed_before disc_before fault_started
  fed_before="$(proxy_received_downstream_bytes "$FED_AB")"
  disc_before="$(proxy_received_downstream_bytes "$DISC_AB")"
  add_latency "$FED_AB"; add_latency "$DISC_AB"
  fault_started=$SECONDS
  wait_until "federation poll in flight" 20 proxy_activity_increased "$FED_AB" "$fed_before"
  wait_until "discovery poll in flight" 20 proxy_activity_increased "$DISC_AB" "$disc_before"
  local local_bundle
  local_bundle="$(spire_bundle_b64der "$CONTEXT_A")"
  apply_mesh_config "$CONTEXT_A" cluster-a "$TD_A" echo-a region-a "$local_bundle" ""
  signal_reload "$CONTEXT_A"
  wait_until "withdrawn RemoteCluster accepted" 40 no_configured_state "$CONTEXT_A" "$JWT_A"
  (( SECONDS - fault_started < 50 )) || {
    echo "withdrawal did not retire the generation before the delayed responses could complete" >&2
    return 1
  }
  remove_latency "$FED_AB"; remove_latency "$DISC_AB"
  # Removing a toxic does not have to wake a delay already sleeping inside the
  # proxy. Observe longer than the full injected delay so both pre-withdrawal
  # responses have time to arrive and attempt their retired-generation writes.
  local deadline=$((SECONDS + 68))
  while (( SECONDS < deadline )); do
    no_configured_state "$CONTEXT_A" "$JWT_A" || { echo "retired poll generation reinstalled state" >&2; return 1; }
    sleep 1
  done
  metrics "$CONTEXT_A" "$JWT_A" > "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.prom"
  if grep -q "ferrum_mesh_federation_bundle_age_seconds{trust_domain=\"$TD_B\"" "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.prom" ||
     grep -q "ferrum_mesh_remote_discovery_endpoint_age_seconds{cluster=\"cluster-b\"" "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.prom"; then
    echo "withdrawn peer retained freshness metrics" >&2; return 1
  fi
  admin_json "$CONTEXT_A" "$JWT_A" > "$RESULTS_DIR/poller.withdrawal.inflight_generation_retired.json"
  record multicluster_poller.withdrawal.inflight_generation_retired pass "withdrawal-accepted-after-observed-inflight-bytes" "poller.withdrawal.inflight_generation_retired.{json,prom}"
  record multicluster_poller.withdrawal.retired_state_not_reinstalled pass "empty-beyond-full-delayed-response-window" "poller.withdrawal.inflight_generation_retired.json"
}

collect_diagnostics() {
  local context label
  for pair in "$CONTEXT_A:a" "$CONTEXT_B:b"; do
    context="${pair%%:*}"; label="${pair##*:}"
    kubectl --context "$context" -n "$NS" get pods -o wide > "$RESULTS_DIR/cluster-$label-pods.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" get events --sort-by=.lastTimestamp > "$RESULTS_DIR/cluster-$label-events.txt" 2>&1 || true
    kubectl --context "$context" -n "$NS" logs deploy/echo -c ferrum-edge --tail=500 > "$RESULTS_DIR/cluster-$label-dp.log" 2>&1 || true
    kubectl --context "$context" -n "$NS" logs deploy/ferrum-cp -c ferrum-edge --tail=500 > "$RESULTS_DIR/cluster-$label-cp.log" 2>&1 || true
  done
  curl -fsS "http://$TOXI_IP:8474/proxies" | python3 -c '
import json,sys
d=json.load(sys.stdin)
for v in d.values():
  v["upstream"]="redacted"; v["listen"]="redacted"
print(json.dumps(d,indent=2,sort_keys=True))' > "$RESULTS_DIR/toxiproxy-redacted.json" 2>/dev/null || true
}

main() {
  preflight
  export FERRUM_LIVE_REPO_ROOT="$ROOT_DIR"
  ferrum_live_assertions_init "$LIVE_ASSERTIONS_FILE" multicluster-poller-partition \
    "$(ferrum_live_git_commit)" "$LIVE_PLATFORM_PROFILE"
  [[ "${FERRUM_SKIP_IMAGE_BUILD:-0}" == 1 ]] || {
    echo "poller fixture requires a pre-packaged runtime image; set FERRUM_SKIP_IMAGE_BUILD=1" >&2
    return 1
  }
  create_clusters_and_fault_layer
  generate_transport_material
  deploy_topology
  scenario_initial
  scenario_transient
  scenario_endpoint_expiry
  scenario_trust_expiry
  scenario_inflight_withdrawal
  collect_diagnostics
  ferrum_live_assertions_require_all_passed "$LIVE_ASSERTIONS_FILE" "${REQUIRED_LIVE_ASSERTIONS[@]}"
  log "all poller partition boundaries passed"
}

main "$@"
