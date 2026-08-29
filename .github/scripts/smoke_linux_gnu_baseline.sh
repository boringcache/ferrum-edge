#!/usr/bin/env bash
# Oldest-baseline smoke for GNU ferrum-edge and ferrum-cni binaries.
#
# Docker argv0 stays a literal `docker` so trusted automation policy can
# statically inspect this file. Variable process argv in Python fails closed;
# this helper is the admitted smoke dispatcher. Host copies are chmod +x
# before the read-only /gnu mount.
set -euo pipefail

contract="${GITHUB_WORKSPACE:-.}/.github/linux-gnu-abi.toml"
if [[ ! -f "$contract" ]]; then
  echo "::error::missing GNU ABI contract $contract" >&2
  exit 1
fi

edge=""
cni=""
while [[ $# -gt 0 ]]; do
  case "$1" in
    --edge)
      edge="${2:?--edge requires a path}"
      shift 2
      ;;
    --cni)
      cni="${2:?--cni requires a path}"
      shift 2
      ;;
    *)
      echo "::error::unknown smoke argument $1" >&2
      exit 1
      ;;
  esac
done

if [[ -z "$edge" || -z "$cni" ]]; then
  echo "::error::smoke_linux_gnu_baseline.sh requires --edge and --cni" >&2
  exit 1
fi
if [[ ! -f "$edge" || -L "$edge" || ! -f "$cni" || -L "$cni" ]]; then
  echo "::error::GNU smoke requires regular ferrum-edge and ferrum-cni files" >&2
  exit 1
fi

machine="$(uname -m)"
case "$machine" in
  x86_64|amd64) platform=linux/amd64 ;;
  aarch64|arm64) platform=linux/arm64 ;;
  *)
    echo "::error::unsupported smoke host architecture ${machine}" >&2
    exit 1
    ;;
esac

floor_image="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["smoke"]["floor"]["image"])' "$contract")"
ubuntu_image="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["smoke"]["ubuntu2204"]["image"])' "$contract")"

require_digest() {
  local image="$1"
  if [[ "$image" != *"@sha256:"* ]]; then
    echo "::error::smoke image ${image} is not digest-pinned" >&2
    exit 1
  fi
}
require_digest "$floor_image"
require_digest "$ubuntu_image"

docker pull --platform "$platform" "$floor_image"
docker pull --platform "$platform" "$ubuntu_image"

tmp="$(mktemp -d "${TMPDIR:-/tmp}/ferrum-gnu-smoke.XXXXXX")"
rpc_pid=""
cleanup() {
  if [[ -n "$rpc_pid" ]]; then
    kill "$rpc_pid" >/dev/null 2>&1 || true
    wait "$rpc_pid" >/dev/null 2>&1 || true
  fi
  rm -rf "$tmp"
}
trap cleanup EXIT

stage="$tmp/gnu"
fixture="$tmp/fixture"
rpc_dir="$tmp/rpc"
mkdir -p "$stage" "$fixture/cni-bin" "$fixture/cni-conf" "$fixture/cni-sock" "$fixture/netns" "$rpc_dir"

cp -f -- "$edge" "$stage/ferrum-edge"
cp -f -- "$cni" "$stage/ferrum-cni"
if [[ -L "$stage/ferrum-edge" || -L "$stage/ferrum-cni" ]]; then
  echo "::error::staged GNU smoke copies must be regular files" >&2
  exit 1
fi
chmod +x -- "$stage/ferrum-edge" "$stage/ferrum-cni"

cat > "$fixture/spec.yaml" <<'SPEC'
version: "1"
proxies:
  - id: "smoke-proxy"
    name: "smoke"
    listen_path: "/smoke"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 9
    strip_listen_path: true
    auth_mode: single
    plugins: []
upstreams: []
consumers: []
plugin_configs: []
SPEC

cat > "$fixture/cni-conf/10-bridge.conf" <<'CNI'
{
  "cniVersion": "0.4.0",
  "name": "cni-smoke",
  "type": "bridge"
}
CNI

export FERRUM_GNU_SMOKE_RPC="$rpc_dir/cni.sock"
export FERRUM_GNU_SMOKE_READY="$rpc_dir/ready"
python3 <<'PY' &
import json
import os
import socket
import struct
import threading
from pathlib import Path

path = Path(os.environ["FERRUM_GNU_SMOKE_RPC"])
if path.exists():
    path.unlink()
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
sock.bind(str(path))
sock.listen(8)
sock.settimeout(0.5)
stop = threading.Event()


def recvall(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = conn.recv(size - len(chunks))
        if not piece:
            raise RuntimeError("RPC connection closed before a complete frame arrived")
        chunks.extend(piece)
    return bytes(chunks)


def loop() -> None:
    while not stop.is_set():
        try:
            conn, _unused = sock.accept()
        except socket.timeout:
            continue
        except OSError:
            if stop.is_set():
                return
            raise
        with conn:
            header = recvall(conn, 4)
            length = struct.unpack(">I", header)[0]
            body = recvall(conn, length)
            json.loads(body.decode("utf-8"))
            payload = json.dumps({"status": "ok"}).encode("utf-8")
            conn.sendall(struct.pack(">I", len(payload)) + payload)


thread = threading.Thread(target=loop, daemon=True)
thread.start()
Path(os.environ["FERRUM_GNU_SMOKE_READY"]).write_text("ready\n", encoding="utf-8")
try:
    thread.join()
finally:
    stop.set()
    sock.close()
PY
rpc_pid=$!
rpc_ready=false
for _ in $(seq 1 100); do
  if [[ -f "$FERRUM_GNU_SMOKE_READY" ]]; then
    rpc_ready=true
    break
  fi
  if ! kill -0 "$rpc_pid" >/dev/null 2>&1; then
    wait "$rpc_pid" || true
    echo "::error::GNU smoke RPC server exited before becoming ready" >&2
    exit 1
  fi
  sleep 0.1
done
if [[ "$rpc_ready" != true ]]; then
  echo "::error::GNU smoke RPC server did not become ready within 10 seconds" >&2
  exit 1
fi

require_json_key() {
  local key="$1"
  python3 -I -c 'import json,sys; payload=json.loads(sys.stdin.read()); raise SystemExit(0 if sys.argv[1] in payload else 1)' "$key"
}

smoke_image() {
  local image="$1"
  echo "smoking ferrum-edge and ferrum-cni on ${image}"

  docker run --rm \
    --platform "$platform" \
    --volume "$stage:/gnu:ro" \
    --volume "$fixture:/fixture:rw" \
    --volume "$rpc_dir:/rpc:rw" \
    --workdir /fixture \
    "$image" \
    /gnu/ferrum-edge version --json \
    | require_json_key version

  docker run --rm \
    --platform "$platform" \
    --volume "$stage:/gnu:ro" \
    --volume "$fixture:/fixture:rw" \
    --volume "$rpc_dir:/rpc:rw" \
    --workdir /fixture \
    --env FERRUM_MODE=file \
    --env FERRUM_FILE_CONFIG_PATH=/fixture/spec.yaml \
    "$image" \
    /gnu/ferrum-edge validate --mode file --spec /fixture/spec.yaml

  docker run --rm \
    --platform "$platform" \
    --volume "$stage:/gnu:ro" \
    --volume "$fixture:/fixture:rw" \
    --volume "$rpc_dir:/rpc:rw" \
    --workdir /fixture \
    "$image" \
    bash -lc '
      set -euo pipefail
      export FERRUM_MODE=file
      export FERRUM_FILE_CONFIG_PATH=/fixture/spec.yaml
      export FERRUM_PROXY_HTTP_PORT=18000
      export FERRUM_PROXY_HTTPS_PORT=0
      export FERRUM_ADMIN_HTTP_PORT=19000
      export FERRUM_ADMIN_HTTPS_PORT=0
      export FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1
      export FERRUM_LOG_LEVEL=warn
      export FERRUM_POOL_WARMUP_ENABLED=false
      /gnu/ferrum-edge run --mode file --spec /fixture/spec.yaml &
      pid=$!
      trap "kill \"$pid\" >/dev/null 2>&1 || true" EXIT
      for _ in $(seq 1 40); do
        if /gnu/ferrum-edge health --live --port 19000 >/dev/null 2>&1; then
          break
        fi
        sleep 0.5
      done
      /gnu/ferrum-edge health --live --port 19000
      for _ in $(seq 1 40); do
        if /gnu/ferrum-edge health --port 19000 >/dev/null 2>&1; then
          break
        fi
        sleep 0.5
      done
      /gnu/ferrum-edge health --port 19000
      kill "$pid"
      wait "$pid" >/dev/null 2>&1 || true
    '

  docker run --rm \
    --platform "$platform" \
    --volume "$stage:/gnu:ro" \
    --volume "$fixture:/fixture:rw" \
    --volume "$rpc_dir:/rpc:rw" \
    --workdir /fixture \
    --env CNI_COMMAND=VERSION \
    "$image" \
    /gnu/ferrum-cni \
    | require_json_key supportedVersions

  docker run --rm \
    --platform "$platform" \
    --volume "$stage:/gnu:ro" \
    --volume "$fixture:/fixture:rw" \
    --volume "$rpc_dir:/rpc:rw" \
    --workdir /fixture \
    "$image" \
    bash -lc '
      set -euo pipefail
      export HOST_BIN_DIR=/fixture/cni-bin
      export HOST_CONF_DIR=/fixture/cni-conf
      export HOST_SOCKET_DIR=/fixture/cni-sock
      export CONF_FILE_NAME=10-ferrum.conflist
      export CHAINED_WITH=bridge
      export SOCKET_PATH=/fixture/cni-sock/node-agent-cni.sock
      export OWNER_ID=smoke-owner
      export INSTALL_GENERATION=1
      /gnu/ferrum-cni install
      test -f /fixture/cni-conf/10-ferrum.conflist
      test -x /fixture/cni-bin/ferrum-cni
      /gnu/ferrum-cni uninstall
    '

  local add_config='{"cniVersion":"1.0.0","name":"cni-smoke","type":"ferrum-cni","ferrum":{"socketPath":"/rpc/cni.sock"}}'
  local command
  for command in ADD CHECK DEL; do
    printf '%s' "$add_config" | docker run --rm -i \
      --platform "$platform" \
      --volume "$stage:/gnu:ro" \
      --volume "$fixture:/fixture:rw" \
      --volume "$rpc_dir:/rpc:rw" \
      --workdir /fixture \
      --env CNI_COMMAND="$command" \
      --env CNI_CONTAINERID=smokecontainer \
      --env CNI_NETNS=/fixture/netns \
      --env CNI_IFNAME=eth0 \
      --env CNI_PATH=/gnu \
      --env CNI_ARGS='IgnoreUnknown=1;K8S_POD_NAMESPACE=smoke;K8S_POD_NAME=pod' \
      "$image" \
      /gnu/ferrum-cni
  done
}

smoke_image "$floor_image"
smoke_image "$ubuntu_image"
