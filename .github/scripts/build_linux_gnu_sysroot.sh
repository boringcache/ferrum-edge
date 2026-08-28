#!/usr/bin/env bash
# Build ferrum-edge and ferrum-cni inside the digest-pinned GNU sysroot so
# linked GLIBC symbols cannot track the GitHub-hosted runner image.
set -euo pipefail

contract="${GITHUB_WORKSPACE:-.}/.github/linux-gnu-abi.toml"
if [[ ! -f "$contract" ]]; then
  echo "::error::missing GNU ABI contract $contract" >&2
  exit 1
fi

sysroot_image="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["image"])' "$contract")"
sysroot_platform="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["platform"])' "$contract")"
protoc_url="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["protoc_url"])' "$contract")"
protoc_sha256="$(python3 -I -c 'import tomllib, pathlib, sys; c=tomllib.loads(pathlib.Path(sys.argv[1]).read_text()); print(c["sysroot"]["protoc_sha256"])' "$contract")"

if [[ -n "${LINUX_GNU_SYSROOT_IMAGE:-}" && "$LINUX_GNU_SYSROOT_IMAGE" != "$sysroot_image" ]]; then
  echo "::error::LINUX_GNU_SYSROOT_IMAGE does not match .github/linux-gnu-abi.toml" >&2
  exit 1
fi
if [[ -n "${LINUX_GNU_PROTOC_SHA256:-}" && "$LINUX_GNU_PROTOC_SHA256" != "$protoc_sha256" ]]; then
  echo "::error::LINUX_GNU_PROTOC_SHA256 does not match .github/linux-gnu-abi.toml" >&2
  exit 1
fi

target="${LINUX_GNU_TARGET:?LINUX_GNU_TARGET is required}"
features="${LINUX_GNU_FEATURES:?LINUX_GNU_FEATURES is required}"
profile="${LINUX_GNU_PROFILE:-release}"

if [[ "$target" != "x86_64-unknown-linux-gnu" ]]; then
  echo "::error::GNU sysroot builder only produces the x86_64 GNU target" >&2
  exit 1
fi

docker pull --platform "$sysroot_platform" "$sysroot_image"

work_root="$(pwd)"
cargo_home="${CARGO_HOME:-$HOME/.cargo}"
rustup_home="${RUSTUP_HOME:-$HOME/.rustup}"
mkdir -p "$cargo_home" "$rustup_home"

host_uid="$(id -u)"
host_gid="$(id -g)"

docker run --rm \
  --platform "$sysroot_platform" \
  --volume "$work_root:/src:rw" \
  --volume "$cargo_home:/opt/cargo:rw" \
  --volume "$rustup_home:/opt/rustup:rw" \
  --workdir /src \
  --env CARGO_HOME=/opt/cargo \
  --env RUSTUP_HOME=/opt/rustup \
  --env PATH="/opt/cargo/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  --env CARGO_TERM_COLOR=always \
  --env LIBZ_SYS_STATIC=1 \
  --env RUSTC_WRAPPER= \
  --env CARGO_BUILD_RUSTC_WRAPPER= \
  --env RUSTFLAGS= \
  --env CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc \
  --env PROTOC_URL="$protoc_url" \
  --env PROTOC_SHA256="$protoc_sha256" \
  --env LINUX_GNU_TARGET="$target" \
  --env LINUX_GNU_FEATURES="$features" \
  --env LINUX_GNU_PROFILE="$profile" \
  --env HOST_UID="$host_uid" \
  --env HOST_GID="$host_gid" \
  "$sysroot_image" \
  bash -lc '
    set -euo pipefail
    dnf -y install gcc gcc-c++ make cmake zlib-devel perl unzip curl ca-certificates libcurl-devel openssl-devel
    curl -fsSL "$PROTOC_URL" -o /tmp/protoc.zip
    echo "$PROTOC_SHA256  /tmp/protoc.zip" | sha256sum -c -
    unzip -o /tmp/protoc.zip -d /usr/local bin/protoc
    chmod +x /usr/local/bin/protoc
    rm /tmp/protoc.zip
    export PROTOC=/usr/local/bin/protoc
    cargo build --features "$LINUX_GNU_FEATURES" --profile "$LINUX_GNU_PROFILE" --target "$LINUX_GNU_TARGET"
    chown -R "${HOST_UID}:${HOST_GID}" \
      /src/target \
      /opt/cargo \
      /opt/rustup
  '
