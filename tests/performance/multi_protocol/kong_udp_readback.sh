#!/bin/bash
# Hosted-only, pre-measurement queries of the CID returned by this fixture's run.
# No eval, dynamic executables, environment dumps, new gateway, or nginx -T.
set -uo pipefail
if [ "${GITHUB_ACTIONS:-}" != true ] || [ "${RUNNER_ENVIRONMENT:-}" != github-hosted ] || [ "${RUNNER_OS:-}" != Linux ]; then
    echo "Kong UDP readback requires the GitHub-hosted Linux fixture" >&2
    exit 2
fi
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CID="$1"
IMAGE="$2"
OUTPUT="$3"
python3 "$SCRIPT_DIR/kong_udp_readback.py" begin "$OUTPUT" "$CID" "$IMAGE" || exit 1

# The outer deadline bounds Docker transport; the inner one also ends a query
# in the container if its Docker client dies. Commands/flags stay literal for
# the trusted workflow scanner. Only validated identity/data slots vary.
for query in container image kong-version nginx-version package-version package-files nginx-hash; do
    case "$query" in
        container)
            timeout --kill-after=2s 12s docker inspect --format \
                '{"id":{{json .Id}},"image":{{json .Image}},"requested_image":{{json .Config.Image}},"running":{{json .State.Running}},"pid":{{json .State.Pid}},"started":{{json .State.StartedAt}}}' "$CID"
            ;;
        image)
            timeout --kill-after=2s 12s docker image inspect --format \
                '{"id":{{json .Id}},"repo_digests":{{json .RepoDigests}},"os":{{json .Os}},"architecture":{{json .Architecture}},"created":{{json .Created}},"revision":{{json (index .Config.Labels "org.opencontainers.image.revision")}},"source":{{json (index .Config.Labels "org.opencontainers.image.source")}}}' "$IMAGE"
            ;;
        kong-version)
            timeout --kill-after=2s 12s docker exec "$CID" timeout --kill-after=1s 8s kong version -a
            ;;
        nginx-version)
            timeout --kill-after=2s 12s docker exec "$CID" timeout --kill-after=1s 8s /usr/local/openresty/nginx/sbin/nginx -V
            ;;
        package-version)
            timeout --kill-after=2s 12s docker exec "$CID" timeout --kill-after=1s 8s dpkg-query -W '-f=${Package}\t${Version}\t${Architecture}\n' kong-enterprise-edition
            ;;
        package-files)
            timeout --kill-after=2s 12s docker exec "$CID" timeout --kill-after=1s 8s dpkg-query -L kong-enterprise-edition
            ;;
        nginx-hash)
            timeout --kill-after=2s 12s docker exec "$CID" timeout --kill-after=1s 8s sha256sum /usr/local/openresty/nginx/sbin/nginx
            ;;
    esac 2>&1 | python3 "$SCRIPT_DIR/kong_udp_readback.py" capture "$OUTPUT" "$query"
    statuses=("${PIPESTATUS[@]}")
    python3 "$SCRIPT_DIR/kong_udp_readback.py" status "$OUTPUT" "$query" "${statuses[0]}" "${statuses[1]}" || exit 1
    if [ "$query" = container ]; then
        # Never exec into a name, mutable tag, discovered container or mismatched CID.
        if ! python3 "$SCRIPT_DIR/kong_udp_readback.py" identity "$OUTPUT"; then
            python3 "$SCRIPT_DIR/kong_udp_readback.py" finish "$OUTPUT"
            exit 1
        fi
    fi
done

# Fixed top-level generated configs cover the standard stream injection file.
# No globs, recursive include expansion, symlink files, .kong_env, certificate
# contents or arbitrary package-listed paths. Unknown includes remain gaps.
for path in \
    /usr/local/kong/nginx.conf \
    /usr/local/kong/nginx-inject.conf \
    /usr/local/kong/nginx-kong.conf \
    /usr/local/kong/nginx-kong-inject.conf \
    /usr/local/kong/nginx-kong-gui-include.conf \
    /usr/local/kong/nginx-kong-stream.conf \
    /usr/local/kong/nginx-kong-stream-inject.conf \
    /usr/local/share/lua/5.1/kong/templates/nginx.lua \
    /usr/local/share/lua/5.1/kong/templates/nginx_kong_stream.lua \
    /usr/local/share/lua/5.1/kong/templates/nginx_kong_stream_inject.lua \
    /usr/local/share/lua/5.1/kong/templates/kong_defaults.lua \
    /usr/local/share/lua/5.1/kong/init.lua \
    /usr/local/share/lua/5.1/kong/runloop/handler.lua \
    /usr/local/share/lua/5.1/kong/runloop/balancer/init.lua \
    /usr/local/openresty/lualib/ngx/balancer.lua; do
    timeout --kill-after=2s 12s docker exec "$CID" timeout --kill-after=1s 8s sh -c '
        if [ -L "$1" ] || [ ! -f "$1" ]; then
            printf "refused non-regular or symlink file: %s\n" "$1" >&2
            exit 3
        fi
        sha256sum -- "$1" && cat -- "$1"
    ' readback "$path" 2>&1 | python3 "$SCRIPT_DIR/kong_udp_readback.py" capture "$OUTPUT" "$path"
    statuses=("${PIPESTATUS[@]}")
    python3 "$SCRIPT_DIR/kong_udp_readback.py" status "$OUTPUT" "$path" "${statuses[0]}" "${statuses[1]}" || exit 1
done
python3 "$SCRIPT_DIR/kong_udp_readback.py" finish "$OUTPUT"
