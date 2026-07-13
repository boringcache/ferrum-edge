{{/*
Ferrum Edge core-gateway chart helpers.

Design notes:
- Templates intentionally fail at render time for invalid or unsafe settings so
  an un-bootable pod (missing DB URL / JWT secret, or a non-loopback plaintext
  admin bind the binary hard-fails on in database/cp modes) is never rendered.
- Secret material is never rendered into ConfigMaps and never inlined into logs;
  credentials flow only through env values or Secret references the operator owns.
*/}}

{{- define "ferrum-gateway.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrum-gateway.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Suffixed names must leave room for the suffix BEFORE truncation, otherwise a
fullname already at the 63-char DNS-label limit drops the suffix and two
Services collide. Truncate the base to (63 - len(suffix)) first, then append.
*/}}
{{- define "ferrum-gateway.suffixedName" -}}
{{- $suffix := .suffix -}}
{{- $base := .base | trunc (int (sub 63 (len $suffix))) | trimSuffix "-" -}}
{{- printf "%s%s" $base $suffix | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrum-gateway.cpGrpcServiceName" -}}
{{- include "ferrum-gateway.suffixedName" (dict "base" (include "ferrum-gateway.fullname" .) "suffix" "-grpc") -}}
{{- end -}}

{{- define "ferrum-gateway.adminServiceName" -}}
{{- include "ferrum-gateway.suffixedName" (dict "base" (include "ferrum-gateway.fullname" .) "suffix" "-admin") -}}
{{- end -}}

{{- define "ferrum-gateway.configMapName" -}}
{{- include "ferrum-gateway.suffixedName" (dict "base" (include "ferrum-gateway.fullname" .) "suffix" "-config") -}}
{{- end -}}

{{- define "ferrum-gateway.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "ferrum-gateway.selectorLabels" -}}
app.kubernetes.io/name: {{ include "ferrum-gateway.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{- define "ferrum-gateway.labels" -}}
helm.sh/chart: {{ include "ferrum-gateway.chart" . }}
{{ include "ferrum-gateway.selectorLabels" . }}
app.kubernetes.io/part-of: ferrum-edge
app.kubernetes.io/component: gateway
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- with .Values.commonLabels }}
{{ toYaml . }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "ferrum-gateway.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-gateway.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/* File-mode config path (kept in sync with the ConfigMap mount). */}}
{{- define "ferrum-gateway.fileConfigPath" -}}
{{- $file := .Values.file | default dict -}}
{{- $dir := $file.mountPath | default "/etc/ferrum/config" -}}
{{- printf "%s/%s" (trimSuffix "/" $dir) ($file.fileName | default "config.yaml") -}}
{{- end -}}

{{/* Admin plaintext HTTP port (0 disables plaintext admin). */}}
{{- define "ferrum-gateway.adminHttpPort" -}}
{{- $ports := .Values.ports | default dict -}}
{{- if hasKey $ports "adminHttp" -}}{{- $ports.adminHttp -}}{{- else -}}9000{{- end -}}
{{- end -}}

{{/*
Return the first DP CP URL that is PLAINTEXT to a non-loopback host, or "" if
none. Mirrors cp_dp_grpc_url_is_nonloopback_plaintext() in
src/config/env_config.rs: http:// or grpc:// scheme to a host that is not
127.0.0.0/8, ::1, or (a subdomain of) localhost. The binary remains
authoritative for hosts this best-effort regex does not classify.
*/}}
{{- define "ferrum-gateway.dpPlaintextUrl" -}}
{{- $bad := "" -}}
{{- range $u := splitList "," (.Values.dp.cpGrpcUrls | default "") -}}
{{- $url := trim $u -}}
{{- if and $url (regexMatch "^(http|grpc)://" $url) -}}
{{- if not (regexMatch "^(http|grpc)://(127\\.[0-9]+\\.[0-9]+\\.[0-9]+|localhost|[^/@:]*\\.localhost|\\[::1\\])(:[0-9]+)?(/|$)" $url) -}}
{{- if not $bad -}}{{- $bad = $url -}}{{- end -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- $bad -}}
{{- end -}}

{{/* True when a secret source (value / existingSecret.name / valueFrom) is set. */}}
{{- define "ferrum-gateway.sourceConfigured" -}}
{{- $source := . | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- if or $source.value $source.valueFrom $existing.name -}}true{{- end -}}
{{- end -}}

{{/* Count secretFileMounts entries that resolve one required base env var. */}}
{{- define "ferrum-gateway.secretFileSourceCount" -}}
{{- $count := 0 -}}
{{- range .root.Values.secretFileMounts -}}
{{- if eq (.name | default "") $.envName -}}
{{- $count = add $count 1 -}}
{{- end -}}
{{- end -}}
{{- $count -}}
{{- end -}}

{{/*
Validate a single required secret source: exactly one of value,
existingSecret.name, valueFrom, or the matching secretFileMounts/_FILE source,
and (optionally) a minimum inline-value length.
*/}}
{{- define "ferrum-gateway.validateOneSource" -}}
{{- $label := .label -}}
{{- $source := .source | default dict -}}
{{- $existing := $source.existingSecret | default dict -}}
{{- $count := 0 -}}
{{- if $source.value -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $source.valueFrom -}}{{- $count = add $count 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $count = add $count 1 -}}{{- end -}}
{{- $fileCount := include "ferrum-gateway.secretFileSourceCount" (dict "root" .root "envName" .envName) | int -}}
{{- $count = add $count $fileCount -}}
{{- if ne $count 1 -}}
{{- fail (printf "%s requires exactly one of value, existingSecret.name, valueFrom, or secretFileMounts entry name=%s" $label .envName) -}}
{{- end -}}
{{- if and $source.value .minLength (lt (len $source.value) (.minLength | int)) -}}
{{- fail (printf "%s.value must be at least %d characters" $label (.minLength | int)) -}}
{{- end -}}
{{- end -}}

{{/* Render an env var from a secret source (value or Secret reference). */}}
{{- define "ferrum-gateway.renderSecretEnv" -}}
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

{{- define "ferrum-gateway.uriComponentEncode" -}}
{{- . | toString | urlquery | replace "+" "%20" -}}
{{- end -}}

{{- define "ferrum-gateway.structuredDbUrl" -}}
{{- $db := . -}}
{{- $port := "" -}}
{{- if $db.port -}}{{- $port = printf ":%v" $db.port -}}{{- end -}}
{{- $host := $db.host -}}
{{- if and (contains ":" $host) (not (hasPrefix "[" $host)) -}}
{{- $host = printf "[%s]" $host -}}
{{- end -}}
{{- $auth := "" -}}
{{- if and $db.username $db.password -}}
{{- $auth = printf "%s:%s@" (include "ferrum-gateway.uriComponentEncode" $db.username) (include "ferrum-gateway.uriComponentEncode" $db.password) -}}
{{- end -}}
{{- $path := "" -}}
{{- if $db.name -}}{{- $path = printf "/%s" (include "ferrum-gateway.uriComponentEncode" $db.name) -}}{{- end -}}
{{- $query := "" -}}
{{- if $db.params -}}
{{- $pairs := list -}}
{{- range $key := keys $db.params | sortAlpha -}}
{{- $pairs = append $pairs (printf "%s=%s" (include "ferrum-gateway.uriComponentEncode" $key) (include "ferrum-gateway.uriComponentEncode" (get $db.params $key))) -}}
{{- end -}}
{{- if $pairs -}}{{- $query = printf "?%s" (join "&" $pairs) -}}{{- end -}}
{{- end -}}
{{- printf "%s://%s%s%s%s%s" $db.type $auth $host $port $path $query -}}
{{- end -}}

{{- define "ferrum-gateway.renderDbUrlEnv" -}}
{{- $db := .Values.database | default dict -}}
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
  value: {{ include "ferrum-gateway.structuredDbUrl" $db | quote }}
{{- end }}
{{- end -}}

{{/* ---------------------------------------------------------------------------
Validation: fail render on missing/unsafe configuration.
--------------------------------------------------------------------------- */}}
{{- define "ferrum-gateway.validateDatabase" -}}
{{- $db := .Values.database | default dict -}}
{{- if not $db.type -}}
{{- fail (printf "database.type is required for mode=%s (one of: sqlite, postgres, mysql, mongodb)" .Values.mode) -}}
{{- end -}}
{{- if not (has $db.type (list "sqlite" "postgres" "mysql" "mongodb")) -}}
{{- fail "database.type must be one of: sqlite, postgres, mysql, mongodb" -}}
{{- end -}}
{{- $urlCount := 0 -}}
{{- $existing := $db.existingSecret | default dict -}}
{{- $sqlite := $db.sqlite | default dict -}}
{{- $dbUrlFileCount := include "ferrum-gateway.secretFileSourceCount" (dict "root" . "envName" "FERRUM_DB_URL") | int -}}
{{- if $db.url -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if $db.urlFrom -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if $existing.name -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if and (eq $db.type "sqlite") $sqlite.path -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- if $db.host -}}{{- $urlCount = add $urlCount 1 -}}{{- end -}}
{{- $urlCount = add $urlCount $dbUrlFileCount -}}
{{- if ne $urlCount 1 -}}
{{- fail "database requires exactly one URL source: url, urlFrom, existingSecret.name, sqlite.path, structured host settings, or secretFileMounts entry name=FERRUM_DB_URL" -}}
{{- end -}}
{{- if and (ne $db.type "sqlite") $sqlite.path -}}
{{- fail "database.sqlite.path is valid only when database.type=sqlite" -}}
{{- end -}}
{{- if and (eq $db.type "sqlite") $db.host -}}
{{- fail "database.host is not valid when database.type=sqlite" -}}
{{- end -}}
{{- if and $db.host (or (eq $db.type "postgres") (eq $db.type "mysql")) (not $db.name) -}}
{{- fail "database.name is required for structured postgres/mysql database URLs" -}}
{{- end -}}
{{- if or $db.username $db.password -}}
{{- if not $db.host -}}{{- fail "database username/password require structured host settings" -}}{{- end -}}
{{- if not (and $db.username $db.password) -}}{{- fail "database structured credentials require both username and password, or neither" -}}{{- end -}}
{{- end -}}
{{- end -}}

{{- define "ferrum-gateway.validate" -}}
{{- $mode := .Values.mode | default "" -}}
{{- if not (has $mode (list "database" "file" "cp" "dp")) -}}
{{- fail (printf "mode must be one of: database, file, cp, dp (got %q). The mesh, injector, and node_agent modes live in the ferrum-mesh chart, not this one." $mode) -}}
{{- end -}}
{{- if or (eq $mode "database") (eq $mode "cp") -}}
{{- include "ferrum-gateway.validateDatabase" . -}}
{{- end -}}
{{- if or (eq $mode "database") (eq $mode "cp") (eq $mode "dp") -}}
{{- include "ferrum-gateway.validateOneSource" (dict "label" "admin.jwtSecret" "source" (.Values.admin.jwtSecret | default dict) "minLength" 32 "root" . "envName" "FERRUM_ADMIN_JWT_SECRET") -}}
{{- end -}}
{{- $grpc := .Values.grpc | default dict -}}
{{- $tlsAll := .Values.tls | default dict -}}
{{- if eq $mode "cp" -}}
{{- include "ferrum-gateway.validateOneSource" (dict "label" "grpc.jwtSecret" "source" ($grpc.jwtSecret | default dict) "minLength" 32 "root" . "envName" "FERRUM_CP_DP_GRPC_JWT_SECRET") -}}
{{/* The binary rejects a non-loopback PLAINTEXT CP gRPC bind (no TLS) unless
     FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true (src/config/env_config.rs). */}}
{{- $cpBind := .Values.cp.grpcBindAddress | default "0.0.0.0" -}}
{{- $cpGrpcPort := include "ferrum-gateway.cpGrpcPort" . -}}
{{- $cpLoopback := or (hasPrefix "127." $cpBind) (eq $cpBind "::1") (eq $cpBind "[::1]") -}}
{{- $cpGrpcTls := $tlsAll.cpGrpc | default dict -}}
{{- $cpGrpcTlsSet := and $cpGrpcTls.enabled $cpGrpcTls.secretName -}}
{{- if and (ne ($cpGrpcPort | toString) "0") (not $cpLoopback) (not $cpGrpcTlsSet) (not $grpc.allowPlaintext) -}}
{{- fail (printf "mode=cp hard-fails on a non-loopback PLAINTEXT gRPC bind (%s:%v). Set one of: gRPC TLS (tls.cpGrpc.enabled + tls.cpGrpc.secretName), a loopback cp.grpcBindAddress (127.0.0.1), or grpc.allowPlaintext=true to explicitly permit plaintext config sync (dev only; pair with a NetworkPolicy)." $cpBind $cpGrpcPort) -}}
{{- end -}}
{{- end -}}
{{- if eq $mode "dp" -}}
{{- include "ferrum-gateway.validateOneSource" (dict "label" "grpc.jwtSecret" "source" ($grpc.jwtSecret | default dict) "minLength" 32 "root" . "envName" "FERRUM_CP_DP_GRPC_JWT_SECRET") -}}
{{- if not .Values.dp.cpGrpcUrls -}}
{{- fail "dp.cpGrpcUrls is required for mode=dp (comma-separated CP gRPC URLs, e.g. https://ferrum-cp:50051)" -}}
{{- end -}}
{{/* The binary rejects a non-loopback PLAINTEXT (http://) CP URL unless
     FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true (src/config/env_config.rs). */}}
{{- if not $grpc.allowPlaintext -}}
{{- $badUrl := include "ferrum-gateway.dpPlaintextUrl" . -}}
{{- if $badUrl -}}
{{- fail (printf "dp.cpGrpcUrls entry %q is PLAINTEXT to a non-loopback host; the DP JWT and config data would cross the network in cleartext. Use an https:// URL (with tls.dpGrpc for CA pinning), target a loopback host, or set grpc.allowPlaintext=true to explicitly permit plaintext config sync (dev only)." $badUrl) -}}
{{- end -}}
{{- end -}}
{{- end -}}
{{- if eq $mode "file" -}}
{{- $file := .Values.file | default dict -}}
{{- if and (not $file.inlineConfig) (not $file.existingConfigMap) -}}
{{- fail "mode=file requires either file.inlineConfig or file.existingConfigMap" -}}
{{- end -}}
{{- if and $file.inlineConfig $file.existingConfigMap -}}
{{- fail "set only one of file.inlineConfig or file.existingConfigMap, not both" -}}
{{- end -}}
{{- end -}}
{{/* Admin bind safety. The binary binds admin to loopback by default. */}}
{{- $admin := .Values.admin | default dict -}}
{{- $bind := $admin.bindAddress | default "" -}}
{{/* EnvConfig::validate() rejects any FERRUM_ADMIN_BIND_ADDRESS that is not an
     IP literal (src/config/env_config.rs), so the common `localhost` spelling
     boots and then exits. Reject it at render with the IP to use instead. */}}
{{- if eq (lower $bind) "localhost" -}}
{{- fail "admin.bindAddress=localhost is rejected: the binary requires FERRUM_ADMIN_BIND_ADDRESS to be an IP literal and exits otherwise. Use 127.0.0.1 (or ::1) for the loopback default, or 0.0.0.0/:: to expose admin through a Service." -}}
{{- end -}}
{{- $loopback := has $bind (list "" "127.0.0.1" "::1") -}}
{{- $adminHttpPort := include "ferrum-gateway.adminHttpPort" . -}}
{{- $adminSvc := $admin.service | default dict -}}
{{- if and $adminSvc.enabled $loopback -}}
{{- fail "admin.service.enabled=true requires admin.bindAddress to be a non-loopback address (e.g. 0.0.0.0 or ::); a loopback-bound admin listener is not reachable through a Service" -}}
{{- end -}}
{{- if and (not $loopback) (or (eq $mode "database") (eq $mode "cp")) (ne ($adminHttpPort | toString) "0") -}}
{{- $allowedCidrs := $admin.allowedCidrs | default "" -}}
{{- $containsCatchAll := regexMatch "(^|[[:space:],])[^[:space:],]+/0([[:space:],]|$)" $allowedCidrs -}}
{{- $hasEffectiveAllowlist := and $allowedCidrs (not $containsCatchAll) -}}
{{- $hasProtection := or $hasEffectiveAllowlist $admin.allowInsecureHttp -}}
{{- if not $hasProtection -}}
{{- if $containsCatchAll -}}
{{- fail "admin.allowedCidrs contains a /0 catch-all CIDR, which does not restrict a non-loopback plaintext admin listener. Use a narrower allowlist, TLS-only admin with ports.adminHttp=0, or admin.allowInsecureHttp=true for local development. The binary remains authoritative for equivalent permit-all CIDR unions." -}}
{{- end -}}
{{- fail (printf "mode=%s hard-fails on a non-loopback plaintext admin bind. Set one of: admin.allowedCidrs, admin TLS (tls.admin.enabled + ports.adminHttp=0), or admin.allowInsecureHttp=true with a NetworkPolicy" $mode) -}}
{{- end -}}
{{- end -}}
{{/* The default exec probes connect from 127.0.0.1, and the admin accept loop
     applies allowedCidrs to loopback like every other source. Require the exact
     probe source whenever at least one computed handler is active. */}}
{{- $probes := .Values.probes | default dict -}}
{{- $startup := $probes.startup | default dict -}}
{{- $liveness := $probes.liveness | default dict -}}
{{- $readiness := $probes.readiness | default dict -}}
{{- $defaultLiveProbe := and (or $startup.enabled $liveness.enabled) (not ($liveness.override | default dict)) -}}
{{- $defaultReadyProbe := and $readiness.enabled (not ($readiness.override | default dict)) -}}
{{/* ports.adminHttp=0 switches the computed exec probes to `health --tls`
     (admin HTTPS :9443), but the serving modes only start admin HTTPS when admin
     TLS material is configured (src/modes/*.rs). Without it there is no admin
     listener and the kubelet restart-loops the pod. Require admin TLS. */}}
{{- if and (eq ($adminHttpPort | toString) "0") (or $defaultLiveProbe $defaultReadyProbe) -}}
{{- $adminTls := $tlsAll.admin | default dict -}}
{{- if not (and $adminTls.enabled $adminTls.secretName) -}}
{{- fail "ports.adminHttp=0 makes the computed probes target admin HTTPS (:9443), but admin HTTPS only serves when admin TLS is configured. Set tls.admin.enabled=true with tls.admin.secretName, or override/disable every computed probe (probes.liveness.override + probes.readiness.override, or disable startup/liveness/readiness)." -}}
{{- end -}}
{{- end -}}
{{- if and $admin.allowedCidrs (or $defaultLiveProbe $defaultReadyProbe) -}}
{{- $hasProbeLoopback := regexMatch "(^|[[:space:],])127\\.0\\.0\\.1(/32)?([[:space:],]|$)" $admin.allowedCidrs -}}
{{- if not $hasProbeLoopback -}}
{{- fail "admin.allowedCidrs must include 127.0.0.1/32 (or bare 127.0.0.1) while the default exec probes are enabled; the admin TCP allowlist otherwise drops the in-pod health checks. Add the exact probe source or override/disable every computed probe handler." -}}
{{- end -}}
{{- end -}}
{{/* Graceful shutdown: give the pod time to drain plus the ~5s cleanup window.
     Use presence (not truthiness) checks so an intentional drain of 0 (skip
     draining, per docs/configuration.md) is honored instead of dropped. */}}
{{- $drain := .Values.shutdownDrainSeconds -}}
{{- $grace := .Values.terminationGracePeriodSeconds -}}
{{- if and (not (kindIs "invalid" $drain)) (not (kindIs "invalid" $grace)) (lt (int $grace) (add (int $drain) 5)) -}}
{{- fail (printf "terminationGracePeriodSeconds (%d) must be at least shutdownDrainSeconds + 5s cleanup (%d)" (int $grace) (add (int $drain) 5)) -}}
{{- end -}}
{{- end -}}

{{/* ---------------------------------------------------------------------------
Env assembly.
--------------------------------------------------------------------------- */}}
{{/* Canonical set of every FERRUM_* env the chart renders from first-class
     values. Overriding any of these through env/extraEnv desyncs the rendered
     probes, Services, ports, or Secret wiring from the running process, so both
     env passthroughs reject them. Keep this list the single source of truth. */}}
{{- define "ferrum-gateway.reservedEnv" -}}
FERRUM_MODE FERRUM_NAMESPACE FERRUM_DB_TYPE FERRUM_DB_URL FERRUM_ADMIN_JWT_SECRET FERRUM_CP_DP_GRPC_JWT_SECRET FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT FERRUM_DP_CP_GRPC_URLS FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS FERRUM_CP_GRPC_LISTEN_ADDR FERRUM_CP_NAMESPACES FERRUM_CP_REQUIRE_NAMESPACE_CLAIM FERRUM_FILE_CONFIG_PATH FERRUM_PROXY_HTTP_PORT FERRUM_PROXY_HTTPS_PORT FERRUM_ADMIN_HTTP_PORT FERRUM_ADMIN_HTTPS_PORT FERRUM_ADMIN_BIND_ADDRESS FERRUM_ADMIN_ALLOWED_CIDRS FERRUM_ALLOW_INSECURE_ADMIN_HTTP FERRUM_SHUTDOWN_DRAIN_SECONDS FERRUM_FRONTEND_TLS_CERT_PATH FERRUM_FRONTEND_TLS_KEY_PATH FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH FERRUM_ADMIN_TLS_CERT_PATH FERRUM_ADMIN_TLS_KEY_PATH FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH FERRUM_BACKEND_TLS_CLIENT_CERT_PATH FERRUM_BACKEND_TLS_CLIENT_KEY_PATH FERRUM_CP_GRPC_TLS_CERT_PATH FERRUM_CP_GRPC_TLS_KEY_PATH FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH FERRUM_DP_GRPC_TLS_CA_CERT_PATH FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH
{{- end -}}

{{- define "ferrum-gateway.modeEnv" -}}
{{- $mode := .Values.mode -}}
- name: FERRUM_MODE
  value: {{ $mode | quote }}
{{- if .Values.ferrumNamespace }}
- name: FERRUM_NAMESPACE
  value: {{ .Values.ferrumNamespace | quote }}
{{- end }}
{{- if or (eq $mode "database") (eq $mode "cp") }}
- name: FERRUM_DB_TYPE
  value: {{ .Values.database.type | quote }}
{{- $dbUrlFileCount := include "ferrum-gateway.secretFileSourceCount" (dict "root" . "envName" "FERRUM_DB_URL") | int }}
{{- if eq $dbUrlFileCount 0 }}
{{ include "ferrum-gateway.renderDbUrlEnv" . }}
{{- end }}
{{- end }}
{{- if include "ferrum-gateway.sourceConfigured" (.Values.admin.jwtSecret | default dict) }}
{{ include "ferrum-gateway.renderSecretEnv" (dict "name" "FERRUM_ADMIN_JWT_SECRET" "source" (.Values.admin.jwtSecret | default dict) "defaultKey" "admin-jwt-secret") }}
{{- end }}
{{- if eq $mode "cp" }}
{{- if include "ferrum-gateway.sourceConfigured" (.Values.grpc.jwtSecret | default dict) }}
{{ include "ferrum-gateway.renderSecretEnv" (dict "name" "FERRUM_CP_DP_GRPC_JWT_SECRET" "source" (.Values.grpc.jwtSecret | default dict) "defaultKey" "cp-dp-grpc-jwt-secret") }}
{{- end }}
- name: FERRUM_CP_GRPC_LISTEN_ADDR
  value: {{ printf "%s:%v" (.Values.cp.grpcBindAddress | default "0.0.0.0") (include "ferrum-gateway.cpGrpcPort" .) | quote }}
{{- if .Values.cp.namespaces }}
- name: FERRUM_CP_NAMESPACES
  value: {{ .Values.cp.namespaces | quote }}
{{- end }}
{{- if .Values.cp.requireNamespaceClaim }}
- name: FERRUM_CP_REQUIRE_NAMESPACE_CLAIM
  value: "true"
{{- end }}
{{- end }}
{{- if eq $mode "dp" }}
- name: FERRUM_DP_CP_GRPC_URLS
  value: {{ .Values.dp.cpGrpcUrls | quote }}
{{- if include "ferrum-gateway.sourceConfigured" (.Values.grpc.jwtSecret | default dict) }}
{{ include "ferrum-gateway.renderSecretEnv" (dict "name" "FERRUM_CP_DP_GRPC_JWT_SECRET" "source" (.Values.grpc.jwtSecret | default dict) "defaultKey" "cp-dp-grpc-jwt-secret") }}
{{- end }}
{{- if .Values.dp.failoverPrimaryRetrySeconds }}
- name: FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS
  value: {{ .Values.dp.failoverPrimaryRetrySeconds | quote }}
{{- end }}
{{- end }}
{{- if and (or (eq $mode "cp") (eq $mode "dp")) (.Values.grpc | default dict).allowPlaintext }}
- name: FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT
  value: "true"
{{- end }}
{{- if eq $mode "file" }}
- name: FERRUM_FILE_CONFIG_PATH
  value: {{ include "ferrum-gateway.fileConfigPath" . | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.cpGrpcPort" -}}
{{- $ports := .Values.ports | default dict -}}
{{- $ports.cpGrpc | default 50051 -}}
{{- end -}}

{{/* Proxy / admin port + bind env. Ports set to 0 disable the listener. */}}
{{- define "ferrum-gateway.portEnv" -}}
{{- $ports := .Values.ports | default dict -}}
{{- if hasKey $ports "proxyHttp" }}
- name: FERRUM_PROXY_HTTP_PORT
  value: {{ $ports.proxyHttp | quote }}
{{- end }}
{{- if hasKey $ports "proxyHttps" }}
- name: FERRUM_PROXY_HTTPS_PORT
  value: {{ $ports.proxyHttps | quote }}
{{- end }}
{{- if hasKey $ports "adminHttp" }}
- name: FERRUM_ADMIN_HTTP_PORT
  value: {{ $ports.adminHttp | quote }}
{{- end }}
{{- if hasKey $ports "adminHttps" }}
- name: FERRUM_ADMIN_HTTPS_PORT
  value: {{ $ports.adminHttps | quote }}
{{- end }}
{{- $admin := .Values.admin | default dict }}
{{- if $admin.bindAddress }}
- name: FERRUM_ADMIN_BIND_ADDRESS
  value: {{ $admin.bindAddress | quote }}
{{- end }}
{{- if $admin.allowedCidrs }}
- name: FERRUM_ADMIN_ALLOWED_CIDRS
  value: {{ $admin.allowedCidrs | quote }}
{{- end }}
{{- if $admin.allowInsecureHttp }}
- name: FERRUM_ALLOW_INSECURE_ADMIN_HTTP
  value: "true"
{{- end }}
{{- end -}}

{{/* Shutdown drain env (pairs with terminationGracePeriodSeconds). Presence, not
     truthiness: a documented 0 (skip draining) must still emit the env, else the
     binary falls back to its 30s default. */}}
{{- define "ferrum-gateway.shutdownEnv" -}}
{{- if not (kindIs "invalid" .Values.shutdownDrainSeconds) }}
- name: FERRUM_SHUTDOWN_DRAIN_SECONDS
  value: {{ .Values.shutdownDrainSeconds | quote }}
{{- end }}
{{- end -}}

{{/* TLS path env for each enabled surface. */}}
{{- define "ferrum-gateway.tlsEnv" -}}
{{- $tls := .Values.tls | default dict -}}
{{- $f := $tls.frontend | default dict -}}
{{- if and $f.enabled $f.secretName }}
- name: FERRUM_FRONTEND_TLS_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($f.mountPath | default "/etc/ferrum/tls/frontend")) ($f.certKey | default "tls.crt") | quote }}
- name: FERRUM_FRONTEND_TLS_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($f.mountPath | default "/etc/ferrum/tls/frontend")) ($f.keyKey | default "tls.key") | quote }}
{{- if $f.clientCaKey }}
- name: FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($f.mountPath | default "/etc/ferrum/tls/frontend")) $f.clientCaKey | quote }}
{{- end }}
{{- end }}
{{- $a := $tls.admin | default dict -}}
{{- if and $a.enabled $a.secretName }}
- name: FERRUM_ADMIN_TLS_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($a.mountPath | default "/etc/ferrum/tls/admin")) ($a.certKey | default "tls.crt") | quote }}
- name: FERRUM_ADMIN_TLS_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($a.mountPath | default "/etc/ferrum/tls/admin")) ($a.keyKey | default "tls.key") | quote }}
{{- if $a.clientCaKey }}
- name: FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($a.mountPath | default "/etc/ferrum/tls/admin")) $a.clientCaKey | quote }}
{{- end }}
{{- end }}
{{- $b := $tls.backend | default dict -}}
{{- if and $b.enabled $b.secretName }}
- name: FERRUM_BACKEND_TLS_CLIENT_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($b.mountPath | default "/etc/ferrum/tls/backend")) ($b.clientCertKey | default "tls.crt") | quote }}
- name: FERRUM_BACKEND_TLS_CLIENT_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($b.mountPath | default "/etc/ferrum/tls/backend")) ($b.clientKeyKey | default "tls.key") | quote }}
{{- end }}
{{- if eq .Values.mode "cp" }}
{{- $cg := $tls.cpGrpc | default dict -}}
{{- if and $cg.enabled $cg.secretName }}
- name: FERRUM_CP_GRPC_TLS_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($cg.mountPath | default "/etc/ferrum/tls/cp-grpc")) ($cg.certKey | default "tls.crt") | quote }}
- name: FERRUM_CP_GRPC_TLS_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($cg.mountPath | default "/etc/ferrum/tls/cp-grpc")) ($cg.keyKey | default "tls.key") | quote }}
{{- if $cg.clientCaKey }}
- name: FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($cg.mountPath | default "/etc/ferrum/tls/cp-grpc")) $cg.clientCaKey | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- if eq .Values.mode "dp" }}
{{- $dg := $tls.dpGrpc | default dict -}}
{{- if and $dg.enabled $dg.secretName }}
- name: FERRUM_DP_GRPC_TLS_CA_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($dg.mountPath | default "/etc/ferrum/tls/dp-grpc")) ($dg.caKey | default "ca.crt") | quote }}
{{- if $dg.clientCertKey }}
- name: FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($dg.mountPath | default "/etc/ferrum/tls/dp-grpc")) $dg.clientCertKey | quote }}
- name: FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH
  value: {{ printf "%s/%s" (trimSuffix "/" ($dg.mountPath | default "/etc/ferrum/tls/dp-grpc")) ($dg.clientKeyKey | default "tls.key") | quote }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{/* External-secret _FILE-suffix env: mount a Secret key and point <VAR>_FILE at it. */}}
{{- define "ferrum-gateway.secretFileEnv" -}}
{{- range .Values.secretFileMounts }}
- name: {{ printf "%s_FILE" .name }}
  value: {{ printf "%s/%s" (trimSuffix "/" (.mountPath | default (printf "/etc/ferrum/secret-files/%s" (lower .name)))) (.secretKey | default "value") | quote }}
{{- end }}
{{- end -}}

{{/* User-supplied simple string env, with reserved keys rejected. The same
     reserved set is enforced against extraEnv (list form) so neither passthrough
     can shadow a chart-managed FERRUM_* var. */}}
{{- define "ferrum-gateway.userEnv" -}}
{{- $reserved := splitList " " (include "ferrum-gateway.reservedEnv" .) -}}
{{- range $entry := .Values.extraEnv }}
{{- if has $entry.name $reserved }}
{{- fail (printf "extraEnv entry %s is managed by first-class chart values; set it through the dedicated value instead of extraEnv" $entry.name) }}
{{- end }}
{{- end }}
{{- range $name, $value := .Values.env }}
{{- if has $name $reserved }}
{{- fail (printf "env.%s is managed by first-class chart values; set it through the dedicated value instead of env" $name) }}
{{- end }}
- name: {{ $name }}
  value: {{ $value | quote }}
{{- end }}
{{- end -}}

{{/* ---------------------------------------------------------------------------
Volumes / mounts.
--------------------------------------------------------------------------- */}}
{{- define "ferrum-gateway.tlsVolumes" -}}
{{- $tls := .Values.tls | default dict -}}
{{- range $key, $section := $tls }}
{{- $s := $section | default dict }}
{{- if and $s.enabled $s.secretName }}
{{- if or (not (has $key (list "cpGrpc" "dpGrpc"))) (and (eq $key "cpGrpc") (eq $.Values.mode "cp")) (and (eq $key "dpGrpc") (eq $.Values.mode "dp")) }}
- name: {{ printf "tls-%s" ($key | kebabcase) }}
  secret:
    secretName: {{ $s.secretName | quote }}
    defaultMode: {{ $.Values.secretVolumeDefaultMode | default 288 }}
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.tlsMounts" -}}
{{- $tls := .Values.tls | default dict -}}
{{- $defaults := dict "frontend" "/etc/ferrum/tls/frontend" "admin" "/etc/ferrum/tls/admin" "backend" "/etc/ferrum/tls/backend" "cpGrpc" "/etc/ferrum/tls/cp-grpc" "dpGrpc" "/etc/ferrum/tls/dp-grpc" -}}
{{- range $key, $section := $tls }}
{{- $s := $section | default dict }}
{{- if and $s.enabled $s.secretName }}
{{- if or (not (has $key (list "cpGrpc" "dpGrpc"))) (and (eq $key "cpGrpc") (eq $.Values.mode "cp")) (and (eq $key "dpGrpc") (eq $.Values.mode "dp")) }}
- name: {{ printf "tls-%s" ($key | kebabcase) }}
  mountPath: {{ $s.mountPath | default (get $defaults $key) | quote }}
  readOnly: true
{{- end }}
{{- end }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.secretFileVolumes" -}}
{{- range $i, $m := .Values.secretFileMounts }}
- name: {{ printf "secret-file-%d" $i }}
  secret:
    secretName: {{ $m.secretName | quote }}
    defaultMode: {{ $.Values.secretVolumeDefaultMode | default 288 }}
    items:
      - key: {{ ($m.secretKey | default "value") | quote }}
        path: {{ ($m.secretKey | default "value") | quote }}
{{- end }}
{{- end -}}

{{- define "ferrum-gateway.secretFileMounts" -}}
{{- range $i, $m := .Values.secretFileMounts }}
- name: {{ printf "secret-file-%d" $i }}
  mountPath: {{ ($m.mountPath | default (printf "/etc/ferrum/secret-files/%s" (lower $m.name))) | quote }}
  readOnly: true
{{- end }}
{{- end -}}
