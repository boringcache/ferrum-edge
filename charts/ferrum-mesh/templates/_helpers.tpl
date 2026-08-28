{{/*
Ferrum mesh chart helpers. These helpers intentionally fail at template time for
invalid CP settings so an unusable control-plane pod is not rendered.
*/}}

{{- define "ferrum-mesh.validateOneSource" -}}
{{- $label := .label -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- $count := 0 -}}
{{- if $source.value -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $source.valueFrom -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if ne $count 1 -}}
{{- fail (printf "%s requires exactly one of value, existingSecret.name, or valueFrom" $label) -}}
{{- end -}}
{{- if and $source.value .minLength (lt (len $source.value) .minLength) -}}
{{- fail (printf "%s.value must be at least %d characters" $label (.minLength | int)) -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.validateControlPlaneInputs" -}}
{{- $needsCpConfig := or .Values.controlPlane.enabled .Values.ca.enabled -}}
{{- if $needsCpConfig -}}
{{- $cp := .Values.controlPlane | default dict -}}
{{- $env := $cp.env | default dict -}}
{{- range $reserved := list "FERRUM_DB_TYPE" "FERRUM_DB_URL" "FERRUM_ADMIN_JWT_SECRET" "FERRUM_CP_DP_GRPC_JWT_SECRET" "FERRUM_SHUTDOWN_DRAIN_SECONDS" "FERRUM_SHUTDOWN_PREDRAIN_SECONDS" "FERRUM_METRICS_BEARER_TOKEN" "FERRUM_METRICS_ALLOWED_CIDRS" -}}
{{- if hasKey $env $reserved -}}
{{- fail (printf "controlPlane.env.%s is reserved; use controlPlane.database, controlPlane.credentials, controlPlane shutdown values, or observability.metrics instead" $reserved) -}}
{{- end -}}
{{- end -}}
{{- $db := $cp.database | default dict -}}
{{- if not $db.type -}}
{{- fail "controlPlane.database.type is required when controlPlane.enabled or ca.enabled is true" -}}
{{- end -}}
{{- if not (has $db.type (list "sqlite" "postgres" "mysql" "mongodb")) -}}
{{- fail "controlPlane.database.type must be one of: sqlite, postgres, mysql, mongodb" -}}
{{- end -}}
{{- $urlFromCount := 0 -}}
{{- $existingDb := $db.existingSecret | default dict -}}
{{- $sqlite := $db.sqlite | default dict -}}
{{- if $db.url -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if $db.urlFrom -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if $existingDb.name -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if and (eq $db.type "sqlite") $sqlite.path -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if $db.host -}}{{- $urlFromCount = add $urlFromCount 1 -}}{{- end -}}
{{- if ne $urlFromCount 1 -}}
{{- fail "controlPlane.database requires exactly one URL source: url, urlFrom, existingSecret.name, sqlite.path, or structured host settings" -}}
{{- end -}}
{{- if and (ne $db.type "sqlite") $sqlite.path -}}
{{- fail "controlPlane.database.sqlite.path is valid only when controlPlane.database.type=sqlite" -}}
{{- end -}}
{{- if and (eq $db.type "sqlite") $db.host -}}
{{- fail "controlPlane.database.host is not valid when controlPlane.database.type=sqlite" -}}
{{- end -}}
{{- if and $db.host (or (eq $db.type "postgres") (eq $db.type "mysql")) (not $db.name) -}}
{{- fail "controlPlane.database.name is required for structured postgres/mysql database URLs" -}}
{{- end -}}
{{- $credSecret := $db.existingCredentialsSecret | default dict -}}
{{- if or $db.usernameFrom $db.passwordFrom $credSecret.name -}}
{{- fail "controlPlane.database structured Secret-backed username/password cannot be safely percent-encoded into FERRUM_DB_URL; use controlPlane.database.existingSecret or urlFrom with a fully encoded URL Secret instead" -}}
{{- end -}}
{{- if or $db.username $db.password -}}
{{- if not $db.host -}}{{- fail "controlPlane.database username/password require structured host settings" -}}{{- end -}}
{{- if not (and $db.username $db.password) -}}{{- fail "controlPlane.database structured credentials require both username and password, or neither" -}}{{- end -}}
{{- end -}}
{{- $creds := $cp.credentials | default dict -}}
{{- include "ferrum-mesh.validateOneSource" (dict "label" "controlPlane.credentials.adminJwtSecret" "source" ($creds.adminJwtSecret | default dict) "minLength" 32) -}}
{{- include "ferrum-mesh.validateOneSource" (dict "label" "controlPlane.credentials.cpDpGrpcJwtSecret" "source" ($creds.cpDpGrpcJwtSecret | default dict) "minLength" 32) -}}
{{/* Advisory GHSA-3f2j-wwqw-grmg: the fleet-wide cpDpGrpcJwtSecret is handed to
     the very data planes it authorizes, so it cannot separate tenants. A CP
     serving more than one namespace (FERRUM_CP_NAMESPACES naming a set, or "*")
     REFUSES TO START without FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH
     (src/modes/control_plane.rs / src/grpc/cp_trust.rs). Mirror that at render
     so the failure is a helm error, not a crash-looping pod that times out
     live CI installs. */}}
{{- $cpNamespacesRaw := "" -}}
{{- if hasKey $env "FERRUM_CP_NAMESPACES" -}}
{{- $cpNamespacesRaw = index $env "FERRUM_CP_NAMESPACES" | toString -}}
{{- end -}}
{{- $cpNsList := compact (splitList "," ($cpNamespacesRaw | replace " " "")) -}}
{{- $cpMultiNamespace := or (has "*" $cpNsList) (gt (len $cpNsList) 1) -}}
{{- $cpTrustBundle := "" -}}
{{- if hasKey $env "FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH" -}}
{{- $cpTrustBundle = index $env "FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH" | toString | trim -}}
{{- end -}}
{{- if and $cpMultiNamespace (eq $cpTrustBundle "") -}}
{{- fail (printf "controlPlane.env.FERRUM_CP_NAMESPACES=%q makes this a multi-namespace control plane, which refuses to start with only controlPlane.credentials.cpDpGrpcJwtSecret: that value is distributed to the data planes it would authorize, so any tenant holding it can re-sign the JWT `ns` claim and subscribe to another tenant (advisory GHSA-3f2j-wwqw-grmg). Set controlPlane.env.FERRUM_CP_DP_GRPC_TRUST_BUNDLE_PATH to a mounted JSON bundle of namespace-bound verification credentials (see docs/cp_namespace_tenancy.md), or serve one namespace per CP via FERRUM_NAMESPACE / a single FERRUM_CP_NAMESPACES entry." $cpNamespacesRaw) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.renderSecretEnv" -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
- name: {{ .name }}
{{- if $source.valueFrom }}
  valueFrom:
{{ toYaml $source.valueFrom | nindent 4 }}
{{- else if $existing.name }}
  valueFrom:
    secretKeyRef:
      name: {{ $existing.name | quote }}
      key: {{ default .defaultKey $existing.key | quote }}
{{- else }}
  value: {{ $source.value | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-mesh.uriComponentEncode" -}}
{{- . | toString | urlquery | replace "+" "%20" -}}
{{- end -}}

{{- define "ferrum-mesh.structuredDbUrl" -}}
{{- $db := . -}}
{{- $port := "" -}}
{{- if $db.port -}}{{- $port = printf ":%v" $db.port -}}{{- end -}}
{{- $host := $db.host -}}
{{- if and (contains ":" $host) (not (hasPrefix "[" $host)) -}}
{{- $host = printf "[%s]" $host -}}
{{- end -}}
{{- $auth := "" -}}
{{- if and $db.username $db.password -}}
{{- $auth = printf "%s:%s@" (include "ferrum-mesh.uriComponentEncode" $db.username) (include "ferrum-mesh.uriComponentEncode" $db.password) -}}
{{- end -}}
{{- $path := "" -}}
{{- if $db.name -}}{{- $path = printf "/%s" (include "ferrum-mesh.uriComponentEncode" $db.name) -}}{{- end -}}
{{- $query := "" -}}
{{- if $db.params -}}
{{- $pairs := list -}}
{{- range $key := keys $db.params | sortAlpha -}}
{{- $pairs = append $pairs (printf "%s=%s" (include "ferrum-mesh.uriComponentEncode" $key) (include "ferrum-mesh.uriComponentEncode" (get $db.params $key))) -}}
{{- end -}}
{{- if $pairs -}}{{- $query = printf "?%s" (join "&" $pairs) -}}{{- end -}}
{{- end -}}
{{- printf "%s://%s%s%s%s%s" $db.type $auth $host $port $path $query -}}
{{- end -}}

{{- define "ferrum-mesh.renderDbUrlEnv" -}}
{{- $db := .Values.controlPlane.database | default dict -}}
{{- $existing := $db.existingSecret | default dict -}}
{{- $sqlite := $db.sqlite | default dict -}}
- name: FERRUM_DB_URL
{{- if $db.urlFrom }}
  valueFrom:
{{ toYaml $db.urlFrom | nindent 4 }}
{{- else if $existing.name }}
  valueFrom:
    secretKeyRef:
      name: {{ $existing.name | quote }}
      key: {{ default "url" $existing.urlKey | quote }}
{{- else if $db.url }}
  value: {{ $db.url | quote }}
{{- else if and (eq $db.type "sqlite") $sqlite.path }}
  value: {{ printf "sqlite:%s?mode=%s" $sqlite.path (default "rwc" $sqlite.mode) | quote }}
{{- else }}
  value: {{ include "ferrum-mesh.structuredDbUrl" $db | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-mesh.renderControlPlaneRequiredEnv" -}}
{{- $cp := .Values.controlPlane | default dict -}}
{{- $db := $cp.database | default dict -}}
{{- $creds := $cp.credentials | default dict -}}
- name: FERRUM_DB_TYPE
  value: {{ $db.type | quote }}
{{ include "ferrum-mesh.renderDbUrlEnv" . }}
{{ include "ferrum-mesh.renderSecretEnv" (dict "name" "FERRUM_ADMIN_JWT_SECRET" "source" ($creds.adminJwtSecret | default dict) "defaultKey" "admin-jwt-secret") }}
{{ include "ferrum-mesh.renderSecretEnv" (dict "name" "FERRUM_CP_DP_GRPC_JWT_SECRET" "source" ($creds.cpDpGrpcJwtSecret | default dict) "defaultKey" "cp-dp-grpc-jwt-secret") }}
{{- end -}}

{{/*
Normalize an admin bind address into the host the in-pod exec probe must dial.
Wildcards become loopback; concrete binds are used as-is.
*/}}
{{- define "ferrum-mesh.adminProbeHost" -}}
{{- $bind := toString . -}}
{{- if or (eq $bind "") (eq $bind "0.0.0.0") (eq $bind "*") -}}
127.0.0.1
{{- else if eq $bind "::" -}}
::1
{{- else -}}
{{- $bind -}}
{{- end -}}
{{- end -}}

{{/*
Resolve admin HTTP port/bind from a workload env map, falling back to binary
defaults (9000 / 127.0.0.1). Returns a dict with keys port, bind, probeHost.
*/}}
{{- define "ferrum-mesh.adminProbeTargetFromEnv" -}}
{{- $env := . | default dict -}}
{{- $port := "9000" -}}
{{- if hasKey $env "FERRUM_ADMIN_HTTP_PORT" -}}
{{- $port = toString (index $env "FERRUM_ADMIN_HTTP_PORT") -}}
{{- end -}}
{{- $bind := "127.0.0.1" -}}
{{- if hasKey $env "FERRUM_ADMIN_BIND_ADDRESS" -}}
{{- $bind = toString (index $env "FERRUM_ADMIN_BIND_ADDRESS") -}}
{{- end -}}
{{- dict "port" $port "bind" $bind "probeHost" (include "ferrum-mesh.adminProbeHost" $bind) | toYaml -}}
{{- end -}}

{{/*
Build the process-only (/live) and dependency-aware (/health) exec handlers for
workloads that expose the admin listener. Liveness/startup MUST use --live so an
alive-but-degraded process is not restart-looped.

Dict keys:
  port      - listen port
  probeHost - dial host for in-pod exec
  tls       - optional; when truthy, append --tls --tls-no-verify (HTTPS-only)

Command argv is kept as a Helm list here; `ferrum-mesh.renderProbeHandler` emits
each item with `| quote` so hosts like `::1` / `127.0.0.1` and ports stay
double-quoted in the rendered manifest (go-yaml's plain `toYaml` leaves those
bare, which breaks frozen NodeWaypoint chart assertions).
*/}}
{{- define "ferrum-mesh.adminHealthHandlers" -}}
{{- $port := toString .port -}}
{{- $host := toString .probeHost -}}
{{- $tls := .tls | default false -}}
{{- $liveCmd := list "/app/ferrum-edge" "health" "--live" "-p" $port "--host" $host -}}
{{- $readyCmd := list "/app/ferrum-edge" "health" "-p" $port "--host" $host -}}
{{- if $tls -}}
{{- $liveCmd = list "/app/ferrum-edge" "health" "--live" "--tls" "--tls-no-verify" "-p" $port "--host" $host -}}
{{- $readyCmd = list "/app/ferrum-edge" "health" "--tls" "--tls-no-verify" "-p" $port "--host" $host -}}
{{- end -}}
{{- dict "live" (dict "exec" (dict "command" $liveCmd)) "ready" (dict "exec" (dict "command" $readyCmd)) | toYaml -}}
{{- end -}}

{{/*
Resolve whether node-agent admin TLS Secret mounts are fully configured.
Returns the string "true" or empty.
*/}}
{{- define "ferrum-mesh.nodeAgentAdminTlsConfigured" -}}
{{- $tls := . | default dict -}}
{{- if and $tls.enabled $tls.secretName $tls.certKey $tls.keyKey -}}
true
{{- end -}}
{{- end -}}

{{/*
Render one probe handler. Exec command lists are emitted item-by-item with
`| quote` so IPv6/IPv4 probe hosts and numeric ports match the quoted spelling
required by tests/k8s/node_waypoint_ebpf_live/run.sh. Non-exec handlers
(tcpSocket, httpGet overrides, …) still use toYaml.
*/}}
{{- define "ferrum-mesh.renderProbeHandler" -}}
{{- if and .exec .exec.command -}}
exec:
  command:
{{- range .exec.command }}
  - {{ . | quote }}
{{- end }}
{{- else -}}
{{- toYaml . }}
{{- end -}}
{{- end -}}

{{/*
Render independently configurable startup/liveness/readiness probes.
Required dict keys:
  probes         - values.<workload>.probes
  liveHandler    - non-empty handler used by liveness (empty → skip)
  readyHandler   - non-empty handler used by readiness (empty → skip)
Optional:
  startupHandler - non-empty handler used by startup. When omitted/empty,
                   startup falls back to liveHandler (backward-compatible:
                   a liveness.override still reaches startup unless an
                   explicit startup.override is supplied).
*/}}
{{- define "ferrum-mesh.renderProbes" -}}
{{- $probes := .probes | default dict -}}
{{- $startup := $probes.startup | default dict -}}
{{- $liveness := $probes.liveness | default dict -}}
{{- $readiness := $probes.readiness | default dict -}}
{{- $liveHandler := .liveHandler | default dict -}}
{{- $readyHandler := .readyHandler | default dict -}}
{{- $startupHandler := .startupHandler | default dict -}}
{{- if not $startupHandler -}}{{- $startupHandler = $liveHandler -}}{{- end -}}
{{- if and ($startup.enabled | default false) $startupHandler }}
          startupProbe:
            {{- /* Prefer a process-only handler (--live / TCP accept). Pointing
                   startup at dependency-aware readiness would kill a pod that
                   boots but stays legitimately unready (cert/config/CP wait). */}}
            {{- include "ferrum-mesh.renderProbeHandler" $startupHandler | nindent 12 }}
            failureThreshold: {{ $startup.failureThreshold }}
            periodSeconds: {{ $startup.periodSeconds }}
{{- end }}
{{- if and ($liveness.enabled | default false) $liveHandler }}
          livenessProbe:
            {{- include "ferrum-mesh.renderProbeHandler" $liveHandler | nindent 12 }}
            initialDelaySeconds: {{ $liveness.initialDelaySeconds }}
            periodSeconds: {{ $liveness.periodSeconds }}
{{- end }}
{{- if and ($readiness.enabled | default false) $readyHandler }}
          readinessProbe:
            {{- include "ferrum-mesh.renderProbeHandler" $readyHandler | nindent 12 }}
            initialDelaySeconds: {{ $readiness.initialDelaySeconds }}
            periodSeconds: {{ $readiness.periodSeconds }}
            {{- /* Rendered explicitly when set: failureThreshold × periodSeconds
                   is probe-driven endpoint-removal latency and pairs with
                   shutdownPreStopSeconds (issue #4266). */}}
            {{- if hasKey $readiness "failureThreshold" }}
            failureThreshold: {{ $readiness.failureThreshold }}
            {{- end }}
{{- end }}
{{- end -}}

{{/*
Release-bound node-proof generation for the Ambient UDP placement contract
(issue #3809).

The node-scoped cleanup attestation must be bound to a generation that cannot
RECUR, so an attestation written for one placement era can never authorize a
later one. This helper therefore reads ONLY the installed contract's persisted,
era-qualified `nodeProofGeneration` (`e<era>.<migration generation>`, stamped by
`udp-placement-contract.yaml` when a migration starts and carried forward
unchanged through finalize and every settled release after it).

It deliberately has NO derived fallback. A token derived from the release's
observable shape — `<target>-<phase>` — repeats the moment a target and phase
recur, so after a host -> pod -> host round trip an old settled-host proof would
name the NEW host era and a same-boot node that missed the intervening rollout
could replay it. The placement contract fail-closes a PRESENT era/generation
pair that is malformed, incomplete, out of bounds, or internally inconsistent
rather than coercing it to era 0; only the pre-contract absence of BOTH fields
may enter cleanup and stamp era 1. An initial install, and any contract
installed before this field existed, therefore yields NO proof generation, which
is fail-closed: the settled host DaemonSet refuses to render until an explicit
cleanup/finalize pair has stamped one.

Both DaemonSets include this SAME helper so the ambient preflight and the
node-agent's registry-synchronization publication can never disagree about
which era a proof belongs to.
*/}}
{{/*
Render the injector mutating webhook namespaceSelector. User-provided
matchExpressions are preserved, but the release namespace is always appended so
an override of injector.namespaceSelector cannot re-enable admission on the
chart's own namespace (issue #4155 bootstrap deadlock).
*/}}
{{- define "ferrum-mesh.renderInjectorWebhookNamespaceSelector" -}}
{{- $user := .namespaceSelector | default dict -}}
{{- $releaseNs := .Release.Namespace -}}
{{- $exprs := $user.matchExpressions | default list -}}
{{- $hasReleaseExclusion := false -}}
{{- range $exprs -}}
{{- if and (eq .key "kubernetes.io/metadata.name") (eq .operator "NotIn") (has $releaseNs .values) -}}
{{- $hasReleaseExclusion = true -}}
{{- end -}}
{{- end -}}
{{- if not $hasReleaseExclusion -}}
{{- $exprs = append $exprs (dict "key" "kubernetes.io/metadata.name" "operator" "NotIn" "values" (list $releaseNs)) -}}
{{- end -}}
{{- $selector := dict "matchExpressions" $exprs -}}
{{- if $user.matchLabels -}}
{{- $_ := set $selector "matchLabels" $user.matchLabels -}}
{{- end -}}
{{- $selector | toYaml -}}
{{- end -}}

{{- define "ferrum-mesh.ambientUdpNodeProofGeneration" -}}
{{- $env := default dict .Values.ambient.env -}}
{{- $topology := replace "-" "_" (lower (trim (toString (index $env "FERRUM_MESH_TOPOLOGY")))) -}}
{{- $result := "" -}}
{{- if and .Values.ambient.enabled (eq $topology "ambient") .Release.IsUpgrade -}}
{{- $contractName := printf "ferrum-mesh-udp-placement-%s" .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- $installed := lookup "v1" "ConfigMap" .Release.Namespace $contractName -}}
{{- if $installed -}}
{{- $data := default dict $installed.data -}}
{{- $result = trim (toString (default "" (index $data "nodeProofGeneration"))) -}}
{{- end -}}
{{- end -}}
{{- $result -}}
{{- end -}}

{{/*
Render hostname spread constraints for HA Deployments (replicas >= 2). When
topologySpreadConstraints is unset, apply a chart default across nodes. An
explicit empty slice disables spread even at higher replica counts.
*/}}
{{- define "ferrum-mesh.renderTopologySpreadConstraints" -}}
{{- $replicas := .replicas | int -}}
{{- if ge $replicas 2 -}}
{{- if kindIs "slice" .constraints -}}
{{- if gt (len .constraints) 0 }}
      topologySpreadConstraints:
{{- toYaml .constraints | nindent 8 }}
{{- end -}}
{{- else }}
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: kubernetes.io/hostname
          whenUnsatisfiable: ScheduleAnyway
          labelSelector:
            matchLabels:
              app.kubernetes.io/name: {{ .selectorName }}
              app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Render a PodDisruptionBudget when the workload is enabled, podDisruptionBudget
is enabled globally, and replicas >= 2. Single-replica workloads skip PDB so
minAvailable: 1 cannot block voluntary evictions during node drains.
*/}}
{{- define "ferrum-mesh.renderPodDisruptionBudget" -}}
{{- $root := .root -}}
{{- $pdb := $root.Values.podDisruptionBudget | default dict -}}
{{- $replicas := .replicas | int -}}
{{- if and .componentEnabled ($pdb.enabled | default false) (ge $replicas 2) -}}
apiVersion: policy/v1
kind: PodDisruptionBudget
metadata:
  name: {{ .name }}
  namespace: {{ $root.Release.Namespace }}
  labels:
    app.kubernetes.io/name: {{ .selectorName }}
    app.kubernetes.io/instance: {{ $root.Release.Name }}
spec:
  {{- if not (kindIs "invalid" $pdb.minAvailable) }}
  minAvailable: {{ $pdb.minAvailable }}
  {{- else if not (kindIs "invalid" $pdb.maxUnavailable) }}
  maxUnavailable: {{ $pdb.maxUnavailable }}
  {{- end }}
  selector:
    matchLabels:
      app.kubernetes.io/name: {{ .selectorName }}
      app.kubernetes.io/instance: {{ $root.Release.Name }}
{{- end -}}
{{- end -}}

{{/*
True when the bind is loopback (or empty, which the binary defaults to
127.0.0.1). Wildcards 0.0.0.0 / :: are not loopback.
*/}}
{{- define "ferrum-mesh.isLoopbackBind" -}}
{{- $bind := . | toString | trim | trimPrefix "[" | trimSuffix "]" -}}
{{- if or (eq $bind "") (eq $bind "127.0.0.1") (eq $bind "::1") (regexMatch "^127\\." $bind) -}}
true
{{- end -}}
{{- end -}}

{{/*
True when a secret-source dict has value, valueFrom, or existingSecret.name.
*/}}
{{- define "ferrum-mesh.sourceConfigured" -}}
{{- $source := . | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- if or $source.value $source.valueFrom $existing.name -}}
true
{{- end -}}
{{- end -}}

{{/*
0 or 1 of value / existingSecret.name / valueFrom. More than one fails.
*/}}
{{- define "ferrum-mesh.validateOptionalSource" -}}
{{- $label := .label -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- $count := 0 -}}
{{- if $source.value -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $source.valueFrom -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if gt $count 1 -}}
{{- fail (printf "%s must set at most one of value, existingSecret.name, or valueFrom" $label) -}}
{{- end -}}
{{- end -}}

{{/*
Resolve admin HTTP port/bind for a serving component. First-class
`<component>.admin` is the chart-managed source; an explicit env map entry
still wins so existing ambient.env.FERRUM_ADMIN_* collision tests and live
suites keep working. Returns YAML dict: port, bind, probeHost, allowInsecureHttp, allowedCidrs.
*/}}
{{- define "ferrum-mesh.resolveComponentAdmin" -}}
{{- $env := .env | default dict -}}
{{- $admin := .admin | default dict -}}
{{- $port := "9000" -}}
{{- if not (kindIs "invalid" $admin.httpPort) -}}
{{- $port = toString $admin.httpPort -}}
{{- end -}}
{{- if hasKey $env "FERRUM_ADMIN_HTTP_PORT" -}}
{{- $port = toString (index $env "FERRUM_ADMIN_HTTP_PORT") -}}
{{- end -}}
{{- $bind := "127.0.0.1" -}}
{{- if $admin.bindAddress -}}
{{- $bind = toString $admin.bindAddress -}}
{{- end -}}
{{- if hasKey $env "FERRUM_ADMIN_BIND_ADDRESS" -}}
{{- $bind = toString (index $env "FERRUM_ADMIN_BIND_ADDRESS") -}}
{{- end -}}
{{- dict "port" $port "bind" $bind "probeHost" (include "ferrum-mesh.adminProbeHost" $bind) "allowInsecureHttp" ($admin.allowInsecureHttp | default false) "allowedCidrs" ($admin.allowedCidrs | default "") | toYaml -}}
{{- end -}}

{{/*
Chart-managed admin env for a serving component. Skips keys already present
in the workload env map so an explicit override is not duplicated.
*/}}
{{- define "ferrum-mesh.adminEnv" -}}
{{- $env := .env | default dict -}}
{{- $resolved := .resolved -}}
{{- if not (hasKey $env "FERRUM_ADMIN_HTTP_PORT") }}
- name: FERRUM_ADMIN_HTTP_PORT
  value: {{ $resolved.port | quote }}
{{- end }}
{{- if not (hasKey $env "FERRUM_ADMIN_BIND_ADDRESS") }}
- name: FERRUM_ADMIN_BIND_ADDRESS
  value: {{ $resolved.bind | quote }}
{{- end }}
{{- if and $resolved.allowInsecureHttp (not (hasKey $env "FERRUM_ALLOW_INSECURE_ADMIN_HTTP")) }}
- name: FERRUM_ALLOW_INSECURE_ADMIN_HTTP
  value: "true"
{{- end }}
{{- $cidrs := trim ($resolved.allowedCidrs | toString) -}}
{{- if and $cidrs (not (hasKey $env "FERRUM_ADMIN_ALLOWED_CIDRS")) }}
- name: FERRUM_ADMIN_ALLOWED_CIDRS
  value: {{ $cidrs | quote }}
{{- end }}
{{- end -}}

{{/*
Shutdown drain env. Presence, not truthiness: shutdownDrainSeconds=0 must
still emit FERRUM_SHUTDOWN_DRAIN_SECONDS=0 or the binary falls back to 30s.
*/}}
{{- define "ferrum-mesh.shutdownEnv" -}}
{{- if not (kindIs "invalid" .shutdownDrainSeconds) }}
- name: FERRUM_SHUTDOWN_DRAIN_SECONDS
  value: {{ .shutdownDrainSeconds | quote }}
{{- end }}
{{- if not (kindIs "invalid" .shutdownPreDrainSeconds) }}
- name: FERRUM_SHUTDOWN_PREDRAIN_SECONDS
  value: {{ .shutdownPreDrainSeconds | quote }}
{{- end }}
{{- end -}}

{{/*
Native SleepAction preStop (Kubernetes 1.29+). Distroless has no shell.
Omitted when shutdownPreStopSeconds is 0.
*/}}
{{- define "ferrum-mesh.preStopLifecycle" -}}
{{- $preStop := int (.shutdownPreStopSeconds | default 0) -}}
{{- if gt $preStop 0 }}
lifecycle:
  preStop:
    sleep:
      seconds: {{ $preStop }}
{{- end -}}
{{- end -}}

{{/*
Metrics auth env. Only when observability.enabled. Bearer token is never
logged; inline value is for lab installs only.
*/}}
{{- define "ferrum-mesh.metricsEnv" -}}
{{- $obs := .Values.observability | default dict -}}
{{- if $obs.enabled }}
{{- $metrics := $obs.metrics | default dict -}}
{{- if $metrics.allowedCidrs }}
- name: FERRUM_METRICS_ALLOWED_CIDRS
  value: {{ $metrics.allowedCidrs | quote }}
{{- end }}
{{- if include "ferrum-mesh.sourceConfigured" ($metrics.bearerToken | default dict) }}
{{ include "ferrum-mesh.renderSecretEnv" (dict "name" "FERRUM_METRICS_BEARER_TOKEN" "source" ($metrics.bearerToken | default dict) "defaultKey" "metrics-bearer-token") }}
{{- end }}
{{- end }}
{{- end -}}

{{/*
Full additive post-SIGTERM shutdown budget (docs/graceful_shutdown.md):
  drain + 6s transport pool + 5s background + clamp(drain,5,60)s audit
  + 2s observability + 5s finalizer slack.
preStop and preDrain are billed to the same terminationGracePeriodSeconds
clock. Dict: root, component (string), values (component values).
*/}}
{{- define "ferrum-mesh.validateShutdown" -}}
{{- $root := .root -}}
{{- $component := .component -}}
{{- $v := .values | default dict -}}
{{- $drain := $v.shutdownDrainSeconds -}}
{{- $effectiveDrain := 30 -}}
{{- if not (kindIs "invalid" $drain) -}}{{- $effectiveDrain = int $drain -}}{{- end -}}
{{- $auditBudget := $effectiveDrain -}}
{{- if lt $auditBudget 5 -}}{{- $auditBudget = 5 -}}{{- end -}}
{{- if gt $auditBudget 60 -}}{{- $auditBudget = 60 -}}{{- end -}}
{{- $shutdownBudget := add $effectiveDrain (add 6 (add 5 (add $auditBudget (add 2 5)))) -}}
{{- $preStop := int ($v.shutdownPreStopSeconds | default 0) -}}
{{- $preDrain := int ($v.shutdownPreDrainSeconds | default 0) -}}
{{- $minGrace := add $preStop (add $preDrain $shutdownBudget) -}}
{{- $grace := $v.terminationGracePeriodSeconds -}}
{{- if kindIs "invalid" $grace -}}
{{- fail (printf "%s.terminationGracePeriodSeconds is required when the workload is enabled (minimum %d = preStop %ds + preDrain %ds + shutdown budget %ds)" $component $minGrace $preStop $preDrain $shutdownBudget) -}}
{{- end -}}
{{- if lt (int $grace) $minGrace -}}
{{- fail (printf "%s.terminationGracePeriodSeconds (%d) must be at least %d (preStop %ds + preDrain %ds + shutdown budget %ds, where the shutdown budget is drain %ds + transport pool 6s + background 5s + audit %ds + observability 2s + finalizer slack 5s); a null shutdownDrainSeconds uses the binary's 30s default" $component (int $grace) $minGrace $preStop $preDrain $shutdownBudget $effectiveDrain $auditBudget) -}}
{{- end -}}
{{- if gt $preStop 0 -}}
{{- $major := atoi (regexReplaceAll "[^0-9].*$" ($root.Capabilities.KubeVersion.Major | toString) "") -}}
{{- $minor := atoi (regexReplaceAll "[^0-9].*$" ($root.Capabilities.KubeVersion.Minor | toString) "") -}}
{{- /* helm template without --kube-version advertises 1.20.0. That sentinel is
     not a real cluster; skip so GitOps/client renders still emit the 1.29+
     SleepAction default. --kube-version 1.28.0 and real <1.29 clusters fail. */ -}}
{{- $helmTemplateDefault := and (eq $major 1) (eq $minor 20) -}}
{{- $sleepUnsupported := and (not $helmTemplateDefault) (or (lt $major 1) (and (eq $major 1) (lt $minor 29))) -}}
{{- if $sleepUnsupported -}}
{{- $kube := $root.Capabilities.KubeVersion.Version | default (printf "v%d.%d" $major $minor) -}}
{{- fail (printf "%s.shutdownPreStopSeconds=%d renders lifecycle.preStop.sleep (SleepAction), which requires Kubernetes 1.29+ (GA in 1.30). This cluster reports %s. Set %s.shutdownPreStopSeconds=0 to omit the hook and raise %s.shutdownPreDrainSeconds to at least readiness failureThreshold × periodSeconds so kube-proxy endpoint removal can finish after SIGTERM while /health already reports not-ready." $component $preStop $kube $component $component) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.validateServingShutdowns" -}}
{{- if .Values.controlPlane.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "controlPlane" "values" .Values.controlPlane) -}}
{{- end -}}
{{- if .Values.ca.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "ca" "values" .Values.ca) -}}
{{- end -}}
{{- if .Values.eastWest.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "eastWest" "values" .Values.eastWest) -}}
{{- end -}}
{{- if .Values.ambient.enabled -}}
{{- include "ferrum-mesh.validateShutdown" (dict "root" . "component" "ambient" "values" .Values.ambient) -}}
{{- end -}}
{{- end -}}

{{/*
Reserved chart-managed env names that must not appear in a workload env map.
*/}}
{{- define "ferrum-mesh.failReservedEnv" -}}
{{- $label := .label -}}
{{- $env := .env | default dict -}}
{{- range $name := .names -}}
{{- if hasKey $env $name -}}
{{- fail (printf "%s.%s is chart-managed; use the matching first-class value instead of overriding the rendered environment" $label $name) -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.shutdownAndMetricsReserved" -}}
FERRUM_SHUTDOWN_DRAIN_SECONDS
FERRUM_SHUTDOWN_PREDRAIN_SECONDS
FERRUM_METRICS_BEARER_TOKEN
FERRUM_METRICS_ALLOWED_CIDRS
{{- end -}}

{{/*
CP/CA hard-fail on non-loopback plaintext admin without an allowlist or the
insecure opt-in (mirrors src/config/env_config.rs). Mesh-mode workloads warn
at runtime; the chart still refuses a ServiceMonitor/PodMonitor scrape against
loopback because Prometheus cannot reach it.
*/}}
{{- define "ferrum-mesh.validatePlaintextAdmin" -}}
{{- $component := .component -}}
{{- $resolved := .resolved -}}
{{- $hardFail := .hardFail -}}
{{- $port := toString $resolved.port -}}
{{- if eq $port "0" -}}
{{- else -}}
{{- $loopback := include "ferrum-mesh.isLoopbackBind" $resolved.bind -}}
{{- if and (not $loopback) $hardFail -}}
{{- $cidrs := trim ($resolved.allowedCidrs | toString) -}}
{{- if and (not $cidrs) (not $resolved.allowInsecureHttp) -}}
{{- fail (printf "%s admin bind %q is a non-loopback plaintext listener. Set %s.admin.allowedCidrs, %s.admin.allowInsecureHttp=true (lab only), or keep the loopback default. Control-plane/CA mode refuses to start otherwise." $component $resolved.bind $component $component) -}}
{{- end -}}
{{- end -}}
{{- if and (not $loopback) $hardFail -}}
{{- $cidrs := trim ($resolved.allowedCidrs | toString) -}}
{{- if $cidrs -}}
{{- $hasLoopbackProbe := or (contains "127.0.0.1" $cidrs) (contains "127.0.0.0/8" $cidrs) (contains "::1" $cidrs) -}}
{{- if not $hasLoopbackProbe -}}
{{- fail (printf "%s.admin.allowedCidrs must include 127.0.0.1/32 (or 127.0.0.0/8) so in-pod exec probes can reach the admin listener" $component) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-mesh.validateObservability" -}}
{{- $obs := .Values.observability | default dict -}}
{{- if not $obs.enabled -}}
{{- else -}}
{{- $metrics := $obs.metrics | default dict -}}
{{- $alerts := $obs.alerts | default dict -}}
{{- $sm := $metrics.serviceMonitor | default dict -}}
{{- $pm := $metrics.podMonitor | default dict -}}
{{- /* Sprig `false | default true` treats false as empty. Presence: anything
     other than the string "false" keeps the observability default of on. */ -}}
{{- $smOn := ne ($sm.enabled | toString) "false" -}}
{{- $pmOn := ne ($pm.enabled | toString) "false" -}}
{{- $alertsOn := ne ($alerts.enabled | toString) "false" -}}
{{- $monitoringOn := or $smOn $pmOn -}}
{{- $allowedCidrs := trim ($metrics.allowedCidrs | default "") -}}
{{- if $allowedCidrs -}}
{{- range $raw := splitList "," $allowedCidrs -}}
{{- $entry := trim $raw -}}
{{- if or (contains "[" $entry) (contains "]" $entry) -}}
{{- fail (printf "observability.metrics.allowedCidrs entry %q uses bracketed IPv6 syntax, but the runtime requires bare IPv6 addresses/CIDRs (for example fd00::/8 or ::1/128)" $entry) -}}
{{- end -}}
{{- if or (eq $entry "") (and (not (contains "." $entry)) (not (contains ":" $entry))) -}}
{{- $display := $entry | default "<empty>" -}}
{{- fail (printf "observability.metrics.allowedCidrs entry %q is not a valid IP address or CIDR; expected forms such as 10.0.0.0/8, 192.168.1.1, ::1, or fd00::/8" $display) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $bearer := $metrics.bearerToken | default dict -}}
{{- include "ferrum-mesh.validateOptionalSource" (dict "label" "observability.metrics.bearerToken" "source" $bearer) -}}
{{- $hasBearer := include "ferrum-mesh.sourceConfigured" $bearer -}}
{{- if and (or $alertsOn $monitoringOn) (not $allowedCidrs) (not $hasBearer) -}}
{{- fail "observability.alerts or ServiceMonitor/PodMonitor is enabled without a scrape credential: set observability.metrics.bearerToken (value, existingSecret.name, or valueFrom) or a non-empty observability.metrics.allowedCidrs so /metrics scrapes can be authorized and alerts are not permanently no-data" -}}
{{- end -}}
{{- $bearerSecret := ($bearer.existingSecret | default dict).name | default "" -}}
{{- if and $monitoringOn (not $allowedCidrs) (not $bearerSecret) $hasBearer -}}
{{- fail "observability ServiceMonitor/PodMonitor without metrics.allowedCidrs requires observability.metrics.bearerToken.existingSecret.name so the monitor can attach Bearer authorization (inline bearerToken.value wires the pod env only — create the Secret out-of-band)" -}}
{{- end -}}
{{- $cpAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "env" (.Values.controlPlane.env | default dict) "admin" (.Values.controlPlane.admin | default dict)) | fromYaml -}}
{{- $caAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "env" (.Values.ca.env | default dict) "admin" (.Values.ca.admin | default dict)) | fromYaml -}}
{{- $ewAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "env" (.Values.eastWest.env | default dict) "admin" (.Values.eastWest.admin | default dict)) | fromYaml -}}
{{- $ambAdmin := include "ferrum-mesh.resolveComponentAdmin" (dict "env" (.Values.ambient.env | default dict) "admin" (.Values.ambient.admin | default dict)) | fromYaml -}}
{{- if and $smOn .Values.controlPlane.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $cpAdmin.bind -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with controlPlane.enabled=true requires a non-loopback controlPlane.admin.bindAddress (e.g. 0.0.0.0 or ::); loopback-bound admin is not reachable through a Service" -}}
{{- end -}}
{{- if eq (toString $cpAdmin.port) "0" -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with controlPlane.enabled=true requires a non-zero controlPlane.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $smOn .Values.ca.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $caAdmin.bind -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with ca.enabled=true requires a non-loopback ca.admin.bindAddress (e.g. 0.0.0.0 or ::); loopback-bound admin is not reachable through a Service" -}}
{{- end -}}
{{- if eq (toString $caAdmin.port) "0" -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with ca.enabled=true requires a non-zero ca.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $smOn .Values.eastWest.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $ewAdmin.bind -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with eastWest.enabled=true requires a non-loopback eastWest.admin.bindAddress (e.g. 0.0.0.0 or ::); loopback-bound admin is not reachable through a Service" -}}
{{- end -}}
{{- if eq (toString $ewAdmin.port) "0" -}}
{{- fail "observability.metrics.serviceMonitor.enabled=true with eastWest.enabled=true requires a non-zero eastWest.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $pmOn .Values.ambient.enabled -}}
{{- if include "ferrum-mesh.isLoopbackBind" $ambAdmin.bind -}}
{{- fail "observability.metrics.podMonitor.enabled=true with ambient.enabled=true requires a non-loopback ambient.admin.bindAddress (e.g. 0.0.0.0); hostNetwork loopback is not reachable from Prometheus" -}}
{{- end -}}
{{- if eq (toString $ambAdmin.port) "0" -}}
{{- fail "observability.metrics.podMonitor.enabled=true with ambient.enabled=true requires a non-zero ambient.admin.httpPort so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- if and $pmOn .Values.nodeAgent.enabled (.Values.nodeAgent.admin.enabled | default true) -}}
{{- $naBind := .Values.nodeAgent.admin.bindAddress | default "127.0.0.1" -}}
{{- $naPort := toString (.Values.nodeAgent.admin.port | default "19090") -}}
{{- if include "ferrum-mesh.isLoopbackBind" $naBind -}}
{{- fail "observability.metrics.podMonitor.enabled=true with nodeAgent.enabled=true requires a non-loopback nodeAgent.admin.bindAddress (e.g. 0.0.0.0); hostNetwork loopback is not reachable from Prometheus" -}}
{{- end -}}
{{- if eq $naPort "0" -}}
{{- fail "observability.metrics.podMonitor.enabled=true with nodeAgent.enabled=true requires a non-zero nodeAgent.admin.port so Prometheus can scrape /metrics" -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Sane non-empty resource requests. Empty resources{} would restore BestEffort.
*/}}
{{- define "ferrum-mesh.validateResources" -}}
{{- $component := .component -}}
{{- $res := .resources | default dict -}}
{{- $req := $res.requests | default dict -}}
{{- if or (not $req.cpu) (not $req.memory) -}}
{{- fail (printf "%s.resources.requests.cpu and %s.resources.requests.memory must be non-empty so the mesh workload is not BestEffort QoS" $component $component) -}}
{{- end -}}
{{- end -}}
