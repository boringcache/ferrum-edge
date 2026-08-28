#!/usr/bin/env python3
"""Oldest-baseline smoke for published GNU ferrum-edge and ferrum-cni binaries.

Runs both binaries' operator commands inside digest-pinned images that match
the declared GLIBC floor (AlmaLinux 9) and Ubuntu 22.04. A moving
ubuntu-latest build host must not be able to ship a binary that cannot start
on those runtimes.
"""

from __future__ import annotations

import argparse
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import tomllib
from pathlib import Path
from typing import Any


REPO_ROOT = Path(__file__).resolve().parents[2]
CONTRACT_PATH = REPO_ROOT / ".github" / "linux-gnu-abi.toml"
SMOKE_SPEC = """\
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
"""
PRIMARY_CNI = """\
{
  "cniVersion": "0.4.0",
  "name": "cni-smoke",
  "type": "bridge"
}
"""
ADD_CONFIG = """\
{
  "cniVersion": "1.0.0",
  "name": "cni-smoke",
  "type": "ferrum-cni",
  "ferrum": {"socketPath": "/rpc/cni.sock"}
}
"""


def load_contract(path: Path = CONTRACT_PATH) -> dict[str, Any]:
    with path.open("rb") as handle:
        return tomllib.load(handle)


def docker_platform() -> str:
    machine = os.uname().machine
    if machine in {"x86_64", "amd64"}:
        return "linux/amd64"
    if machine in {"aarch64", "arm64"}:
        return "linux/arm64"
    raise RuntimeError(f"unsupported smoke host architecture {machine!r}")


def run_checked(command: list[str], *, input_text: str | None = None) -> subprocess.CompletedProcess[str]:
    completed = subprocess.run(
        command,
        check=False,
        capture_output=True,
        text=True,
        input=input_text,
    )
    if completed.returncode != 0:
        sys.stderr.write(completed.stdout)
        sys.stderr.write(completed.stderr)
        raise RuntimeError(f"command failed ({completed.returncode}): {' '.join(command)}")
    return completed


def recvall(conn: socket.socket, size: int) -> bytes:
    chunks = bytearray()
    while len(chunks) < size:
        piece = conn.recv(size - len(chunks))
        if not piece:
            raise RuntimeError("RPC connection closed before a complete frame arrived")
        chunks.extend(piece)
    return bytes(chunks)


class RpcServer:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._stop = threading.Event()
        self._sock: socket.socket | None = None
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        if self.path.exists():
            self.path.unlink()
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(str(self.path))
        sock.listen(8)
        sock.settimeout(0.5)
        self._sock = sock
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        assert self._sock is not None
        while not self._stop.is_set():
            try:
                conn, _unused = self._sock.accept()
            except socket.timeout:
                continue
            except OSError:
                if self._stop.is_set():
                    return
                raise
            with conn:
                header = recvall(conn, 4)
                length = struct.unpack(">I", header)[0]
                body = recvall(conn, length)
                json.loads(body.decode("utf-8"))
                payload = json.dumps({"status": "ok"}).encode("utf-8")
                conn.sendall(struct.pack(">I", len(payload)) + payload)

    def close(self) -> None:
        self._stop.set()
        if self._sock is not None:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread is not None:
            self._thread.join(timeout=5)


def docker_bash(
    image: str,
    platform: str,
    mounts: list[tuple[str, str, str]],
    script: str,
    *,
    input_text: str | None = None,
    env: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    command = [
        "docker",
        "run",
        "--rm",
        "--platform",
        platform,
        "--workdir",
        "/fixture",
    ]
    for source, dest, mode in mounts:
        command.extend(["--volume", f"{source}:{dest}:{mode}"])
    for key, value in (env or {}).items():
        command.extend(["--env", f"{key}={value}"])
    command.extend([image, "bash", "-lc", script])
    return run_checked(command, input_text=input_text)


def smoke_image(
    image: str,
    platform: str,
    edge: Path,
    cni: Path,
    fixture: Path,
    rpc_dir: Path,
) -> None:
    mounts = [
        (str(edge.parent), "/gnu", "ro"),
        (str(fixture), "/fixture", "rw"),
        (str(rpc_dir), "/rpc", "rw"),
    ]
    edge_name = edge.name
    cni_name = cni.name

    version = docker_bash(
        image,
        platform,
        mounts,
        f"chmod +x /gnu/{edge_name} /gnu/{cni_name} && /gnu/{edge_name} version --json",
    )
    payload = json.loads(version.stdout)
    if "version" not in payload:
        raise RuntimeError(f"{edge_name} version --json omitted version: {version.stdout!r}")

    docker_bash(
        image,
        platform,
        mounts,
        f"chmod +x /gnu/{edge_name} && "
        f"FERRUM_MODE=file FERRUM_FILE_CONFIG_PATH=/fixture/spec.yaml "
        f"/gnu/{edge_name} validate --mode file --spec /fixture/spec.yaml",
    )

    docker_bash(
        image,
        platform,
        mounts,
        f"""
set -euo pipefail
chmod +x /gnu/{edge_name}
export FERRUM_MODE=file
export FERRUM_FILE_CONFIG_PATH=/fixture/spec.yaml
export FERRUM_PROXY_HTTP_PORT=18000
export FERRUM_PROXY_HTTPS_PORT=0
export FERRUM_ADMIN_HTTP_PORT=19000
export FERRUM_ADMIN_HTTPS_PORT=0
export FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1
export FERRUM_LOG_LEVEL=warn
export FERRUM_POOL_WARMUP_ENABLED=false
/gnu/{edge_name} run --mode file --spec /fixture/spec.yaml &
pid=$!
trap 'kill "$pid" >/dev/null 2>&1 || true' EXIT
for _ in $(seq 1 40); do
  if /gnu/{edge_name} health --live --port 19000 >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
/gnu/{edge_name} health --live --port 19000
for _ in $(seq 1 40); do
  if /gnu/{edge_name} health --port 19000 >/dev/null 2>&1; then
    break
  fi
  sleep 0.5
done
/gnu/{edge_name} health --port 19000
kill "$pid"
wait "$pid" >/dev/null 2>&1 || true
""",
    )

    version_cni = docker_bash(
        image,
        platform,
        mounts,
        f"chmod +x /gnu/{cni_name} && CNI_COMMAND=VERSION /gnu/{cni_name}",
    )
    cni_payload = json.loads(version_cni.stdout)
    if "supportedVersions" not in cni_payload:
        raise RuntimeError(f"{cni_name} VERSION omitted supportedVersions: {version_cni.stdout!r}")

    (fixture / "cni-bin").mkdir(exist_ok=True)
    (fixture / "cni-conf").mkdir(exist_ok=True)
    (fixture / "cni-sock").mkdir(exist_ok=True)
    (fixture / "cni-conf" / "10-bridge.conf").write_text(PRIMARY_CNI, encoding="utf-8")
    docker_bash(
        image,
        platform,
        mounts,
        f"""
set -euo pipefail
chmod +x /gnu/{cni_name}
export HOST_BIN_DIR=/fixture/cni-bin
export HOST_CONF_DIR=/fixture/cni-conf
export HOST_SOCKET_DIR=/fixture/cni-sock
export CONF_FILE_NAME=10-ferrum.conflist
export CHAINED_WITH=bridge
export SOCKET_PATH=/fixture/cni-sock/node-agent-cni.sock
export OWNER_ID=smoke-owner
export INSTALL_GENERATION=1
/gnu/{cni_name} install
test -f /fixture/cni-conf/10-ferrum.conflist
test -x /fixture/cni-bin/ferrum-cni
/gnu/{cni_name} uninstall
""",
    )

    netns = fixture / "netns"
    netns.mkdir(exist_ok=True)
    for command in ("ADD", "CHECK", "DEL"):
        env = {
            "CNI_COMMAND": command,
            "CNI_CONTAINERID": "smokecontainer",
            "CNI_NETNS": "/fixture/netns",
            "CNI_IFNAME": "eth0",
            "CNI_PATH": "/gnu",
            "CNI_ARGS": "IgnoreUnknown=1;K8S_POD_NAMESPACE=smoke;K8S_POD_NAME=pod",
        }
        docker_bash(
            image,
            platform,
            mounts,
            f"chmod +x /gnu/{cni_name} && /gnu/{cni_name}",
            input_text=ADD_CONFIG,
            env=env,
        )


def run_smoke(edge: Path, cni: Path, contract: dict[str, Any]) -> None:
    if not edge.is_file() or edge.is_symlink() or not cni.is_file() or cni.is_symlink():
        raise RuntimeError("GNU smoke requires regular ferrum-edge and ferrum-cni files")
    platform = docker_platform()
    images = [
        contract["smoke"]["floor"]["image"],
        contract["smoke"]["ubuntu2204"]["image"],
    ]
    for image in images:
        if "@sha256:" not in image:
            raise RuntimeError(f"smoke image {image} is not digest-pinned")
        run_checked(["docker", "pull", "--platform", platform, image])

    with tempfile.TemporaryDirectory(prefix="ferrum-gnu-smoke-") as tmp:
        root = Path(tmp)
        fixture = root / "fixture"
        rpc_dir = root / "rpc"
        fixture.mkdir()
        rpc_dir.mkdir()
        (fixture / "spec.yaml").write_text(SMOKE_SPEC, encoding="utf-8")
        server = RpcServer(rpc_dir / "cni.sock")
        server.start()
        try:
            time.sleep(0.2)
            for image in images:
                print(f"smoking {edge.name} and {cni.name} on {image}", flush=True)
                smoke_image(image, platform, edge, cni, fixture, rpc_dir)
        finally:
            server.close()


def run_self_test() -> list[str]:
    failures: list[str] = []
    contract = load_contract()
    for key in ("floor", "ubuntu2204"):
        image = contract["smoke"][key]["image"]
        if "@sha256:" not in image:
            failures.append(f"smoke.{key} image is not digest-pinned")
    if "@sha256:" not in contract["sysroot"]["image"]:
        failures.append("sysroot image is not digest-pinned")
    if len(contract["sysroot"]["protoc_sha256"]) != 64:
        failures.append("protoc SHA-256 is not 64 hex characters")
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--edge", type=Path)
    parser.add_argument("--cni", type=Path)
    args = parser.parse_args(argv if argv is not None else sys.argv[1:])

    failures: list[str] = []
    if args.self_test:
        failures.extend(run_self_test())
    if args.edge is not None or args.cni is not None:
        if args.edge is None or args.cni is None:
            parser.error("--edge and --cni must be supplied together")
        try:
            run_smoke(args.edge, args.cni, load_contract())
        except Exception as error:
            failures.append(str(error))
    if not args.self_test and args.edge is None:
        parser.error("supply --edge/--cni and/or --self-test")

    for failure in failures:
        print(f"error: {failure}", file=sys.stderr)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
