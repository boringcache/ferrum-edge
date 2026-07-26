#!/usr/bin/env bash
set -euo pipefail

# setup_mongo_tls.sh — Generate TLS certificates and start MongoDB containers for
# hosted/local Mongo TLS functional coverage (verify-full, require, mTLS).
#
# Usage:
#   ./setup_mongo_tls.sh [CERT_DIR]   Start containers (default: /tmp/ferrum-mongo-tls-certs)
#   ./setup_mongo_tls.sh --cleanup    Stop and remove containers
#   ./setup_mongo_tls.sh --help       Show this help message
#
# Exports nothing itself; CI wires FERRUM_TEST_MONGO_TLS_URL /
# FERRUM_TEST_MONGO_TLS_REQUIRE_URL / FERRUM_TEST_MONGO_MTLS_URL /
# FERRUM_TEST_MONGO_CERT_DIR after a successful run.

readonly TLS_CONTAINER="ferrum-test-mongo-tls"
readonly MTLS_CONTAINER="ferrum-test-mongo-mtls"
readonly TLS_PORT=27018
readonly MTLS_PORT=27019
readonly HEALTH_TIMEOUT=120  # seconds

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

log() { printf '[%s] %s\n' "$(date +%H:%M:%S)" "$*"; }
err() { log "ERROR: $*" >&2; }
die() { err "$@"; exit 1; }

usage() {
    sed -n '3,14s/^# \?//p' "$0"
    exit 0
}

# ---------------------------------------------------------------------------
# Cleanup
# ---------------------------------------------------------------------------

cleanup() {
    log "Stopping and removing MongoDB TLS containers..."
    for name in "$TLS_CONTAINER" "$MTLS_CONTAINER"; do
        if docker inspect "$name" &>/dev/null; then
            docker rm -f "$name" >/dev/null 2>&1 && log "Removed $name"
        else
            log "$name not found, skipping"
        fi
    done
    log "Cleanup complete."
}

# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------

generate_certs() {
    local cert_dir="$1"
    mkdir -p "$cert_dir"

    log "Generating MongoDB TLS certificates in $cert_dir ..."

    # --- CA ---
    openssl genrsa -out "$cert_dir/ca.key" 4096 2>/dev/null
    openssl req -new -x509 -days 3650 -key "$cert_dir/ca.key" \
        -out "$cert_dir/ca.crt" -subj "/CN=Ferrum Mongo Test CA" 2>/dev/null

    # --- Server cert (SAN covers the address CI and local tests dial) ---
    local server_ext
    server_ext=$(mktemp)
    cat > "$server_ext" <<EXTEOF
[v3_req]
subjectAltName = DNS:localhost,DNS:mongo-tls,DNS:mongo-mtls,IP:127.0.0.1
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = serverAuth
EXTEOF

    openssl genrsa -out "$cert_dir/server.key" 2048 2>/dev/null
    openssl req -new -key "$cert_dir/server.key" \
        -out "$cert_dir/server.csr" -subj "/CN=mongo-tls" 2>/dev/null
    openssl x509 -req -in "$cert_dir/server.csr" -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" -CAcreateserial -days 3650 \
        -extensions v3_req -extfile "$server_ext" \
        -out "$cert_dir/server.crt" 2>/dev/null
    rm -f "$server_ext" "$cert_dir/server.csr"

    # MongoDB requires a combined certificate+key PEM for --tlsCertificateKeyFile.
    cat "$cert_dir/server.crt" "$cert_dir/server.key" > "$cert_dir/mongodb.pem"

    # --- Client cert (mTLS) ---
    local client_ext
    client_ext=$(mktemp)
    cat > "$client_ext" <<EXTEOF
[v3_req]
keyUsage = digitalSignature, keyEncipherment
extendedKeyUsage = clientAuth
EXTEOF

    openssl genrsa -out "$cert_dir/client.key" 2048 2>/dev/null
    openssl req -new -key "$cert_dir/client.key" \
        -out "$cert_dir/client.csr" -subj "/CN=ferrum-mongo-client" 2>/dev/null
    openssl x509 -req -in "$cert_dir/client.csr" -CA "$cert_dir/ca.crt" \
        -CAkey "$cert_dir/ca.key" -CAcreateserial -days 3650 \
        -extensions v3_req -extfile "$client_ext" \
        -out "$cert_dir/client.crt" 2>/dev/null
    rm -f "$client_ext" "$cert_dir/client.csr" "$cert_dir/ca.srl"

    # Combined client PEM for in-container mongosh readiness probes.
    cat "$cert_dir/client.crt" "$cert_dir/client.key" > "$cert_dir/client.pem"

    # Restrict private keys; leave public certs readable for Docker copies.
    # mongodb.pem / client.pem are re-permissioned to 0600 inside the container
    # after copy (bind mounts may not preserve host mode bits).
    chmod 600 "$cert_dir/ca.key" "$cert_dir/server.key" "$cert_dir/client.key" \
        "$cert_dir/mongodb.pem" "$cert_dir/client.pem"
    chmod 644 "$cert_dir/ca.crt" "$cert_dir/server.crt" "$cert_dir/client.crt"

    log "Certificates generated successfully."
}

# ---------------------------------------------------------------------------
# Container startup
# ---------------------------------------------------------------------------

# Copy certs into the container filesystem with mongodb ownership. Bind-mount
# permission semantics (especially on macOS) are not reliable for mongod's
# 0600 key requirement.
start_mongo_tls_container() {
    local name="$1"
    local host_port="$2"
    local cert_dir="$3"
    local require_client_cert="$4"

    if docker inspect "$name" &>/dev/null; then
        log "Container $name already exists, removing..."
        docker rm -f "$name" >/dev/null
    fi

    if [[ "$require_client_cert" == "0" ]]; then
        log "Starting MongoDB TLS container ($name) on port $host_port (client certs optional) ..."
        docker run -d \
            --name "$name" \
            -p "${host_port}:27017" \
            -v "$cert_dir:/certs-src:ro" \
            --entrypoint bash \
            mongo:7 \
            -c '
                set -e
                mkdir -p /certs
                cp /certs-src/mongodb.pem /certs/mongodb.pem
                cp /certs-src/ca.crt /certs/ca.crt
                cp /certs-src/client.pem /certs/client.pem
                chown mongodb:mongodb /certs/mongodb.pem /certs/ca.crt /certs/client.pem
                chmod 600 /certs/mongodb.pem /certs/client.pem
                chmod 644 /certs/ca.crt
                exec docker-entrypoint.sh mongod \
                    --bind_ip_all \
                    --tlsMode requireTLS \
                    --tlsCertificateKeyFile /certs/mongodb.pem \
                    --tlsCAFile /certs/ca.crt \
                    --tlsAllowConnectionsWithoutCertificates
            ' >/dev/null
    else
        log "Starting MongoDB mTLS container ($name) on port $host_port (client certs required) ..."
        docker run -d \
            --name "$name" \
            -p "${host_port}:27017" \
            -v "$cert_dir:/certs-src:ro" \
            --entrypoint bash \
            mongo:7 \
            -c '
                set -e
                mkdir -p /certs
                cp /certs-src/mongodb.pem /certs/mongodb.pem
                cp /certs-src/ca.crt /certs/ca.crt
                cp /certs-src/client.pem /certs/client.pem
                chown mongodb:mongodb /certs/mongodb.pem /certs/ca.crt /certs/client.pem
                chmod 600 /certs/mongodb.pem /certs/client.pem
                chmod 644 /certs/ca.crt
                exec docker-entrypoint.sh mongod \
                    --bind_ip_all \
                    --tlsMode requireTLS \
                    --tlsCertificateKeyFile /certs/mongodb.pem \
                    --tlsCAFile /certs/ca.crt
            ' >/dev/null
    fi

    log "Container $name started."
}

# ---------------------------------------------------------------------------
# Health checks
# ---------------------------------------------------------------------------

wait_for_mongo_tls() {
    local name="$1"
    local require_client_cert="$2"
    local elapsed=0
    local ping_eval='quit(db.runCommand({ ping: 1 }).ok ? 0 : 1)'

    log "Waiting for $name to accept TLS connections (timeout: ${HEALTH_TIMEOUT}s) ..."

    while (( elapsed < HEALTH_TIMEOUT )); do
        if [[ "$require_client_cert" == "1" ]]; then
            if docker exec "$name" mongosh --quiet --tls --host 127.0.0.1 --port 27017 \
                    --tlsCAFile /certs/ca.crt \
                    --tlsCertificateKeyFile /certs/client.pem \
                    --eval "$ping_eval" &>/dev/null; then
                log "$name is ready (${elapsed}s)."
                return 0
            fi
        else
            if docker exec "$name" mongosh --quiet --tls --host 127.0.0.1 --port 27017 \
                    --tlsCAFile /certs/ca.crt \
                    --eval "$ping_eval" &>/dev/null; then
                log "$name is ready (${elapsed}s)."
                return 0
            fi
        fi
        sleep 2
        (( elapsed += 2 ))
    done

    err "$name did not become healthy within ${HEALTH_TIMEOUT}s."
    log "Container logs:"
    docker logs --tail 40 "$name" >&2
    return 1
}

wait_for_containers() {
    local tls_ok=0
    local mtls_ok=0

    wait_for_mongo_tls "$TLS_CONTAINER" 0 || tls_ok=1
    wait_for_mongo_tls "$MTLS_CONTAINER" 1 || mtls_ok=1

    if (( tls_ok != 0 || mtls_ok != 0 )); then
        die "One or more MongoDB TLS containers failed to start. Run '$0 --cleanup' to remove them."
    fi

    log "All MongoDB TLS containers are healthy and ready for testing."
    log ""
    log "Connection details (no credentials in this fixture):"
    log "  TLS verify-full / require: mongodb://127.0.0.1:${TLS_PORT}/ferrum_test"
    log "  mTLS:                      mongodb://127.0.0.1:${MTLS_PORT}/ferrum_test"
    log "  Cert dir:                  (set FERRUM_TEST_MONGO_CERT_DIR to the path passed to this script)"
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    case "${1:-}" in
        --cleanup)
            cleanup
            exit 0
            ;;
        --help|-h)
            usage
            ;;
    esac

    command -v docker >/dev/null 2>&1 || die "docker is not installed or not in PATH."
    command -v openssl >/dev/null 2>&1 || die "openssl is not installed or not in PATH."

    local cert_dir="${1:-/tmp/ferrum-mongo-tls-certs}"

    # Use absolute path
    mkdir -p "$cert_dir"
    cert_dir="$(cd "$cert_dir" && pwd)"

    generate_certs "$cert_dir"
    start_mongo_tls_container "$TLS_CONTAINER" "$TLS_PORT" "$cert_dir" 0
    start_mongo_tls_container "$MTLS_CONTAINER" "$MTLS_PORT" "$cert_dir" 1
    wait_for_containers

    log ""
    log "Certificates are in: $cert_dir"
    log "To tear down: $0 --cleanup"
}

main "$@"
