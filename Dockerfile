# Multi-stage build for Ferrum Edge

# Build features for the main binary. Default = `cloud-secrets` (the historical
# image). Pass `--build-arg FEATURES=cloud-secrets,ebpf` to build the
# node-agent / ambient-mesh capture image, which also COPYs the compiled
# ferrum-ebpf ELF into the runtime image (see the ebpf-builder stage and the
# FERRUM_NODE_AGENT_BPF_ELF_PATH default below).
#
# KNOWN COUPLING (follow-up): the runtime stage's `COPY --from=ebpf-builder`
# is unconditional, so EVERY image build — including the default cloud-secrets
# image, which does not use the ELF — depends on the `ebpf-builder` stage
# (nightly + bpf-linker + `-Z build-std`). This adds build time and a new
# failure mode (nightly/bpf-linker availability) to the default image that it
# did not previously have. Decoupling the ELF copy (e.g. an ARG-selected
# source stage, or a dedicated capture image/target) so the default image does
# not require the eBPF toolchain — plus a CI job that actually builds the
# ebpf-builder stage so it stays verified — is a recommended follow-up. It is
# deliberately not done here because it changes the capture-image build
# interface and must be validated against the release/CI image-build scripts.
ARG FEATURES=cloud-secrets

# --- eBPF build stage (nightly, Linux only) ---
# Compiles the no_std `ferrum-ebpf` crate to a BPF ELF using nightly +
# `-Z build-std` against the bpfel-unknown-none target. The resulting ELF is
# COPY'd into the runtime image and loaded by node_agent / node-waypoint mesh
# mode at startup via aya. Linking requires `bpf-linker` (installed below).
#
# The ebpf/ workspace pins a nightly via ebpf/rust-toolchain.toml, but the
# `cargo +nightly` invocations below explicitly select the latest installed
# nightly — the `+nightly` override takes precedence over the toolchain file,
# so the pin is NOT what is used here. Both resolve to a nightly toolchain so
# the build works today; if the eBPF crate ever requires a *specific* pinned
# nightly, drop `+nightly` from the build below so the rust-toolchain.toml pin
# is honored (and install rust-src on that pinned toolchain). core-only
# build-std matches the crate's `#![no_std]` + `panic = "abort"`.
FROM rust:latest AS ebpf-builder
RUN rustup toolchain install nightly --component rust-src \
    && cargo +nightly install bpf-linker --locked
COPY ebpf/ /build/ebpf/
WORKDIR /build/ebpf
RUN cargo +nightly build \
        --release \
        -p ferrum-ebpf \
        --target bpfel-unknown-none \
        -Z build-std=core \
    && test -f target/bpfel-unknown-none/release/ferrum-ebpf

# Stage 1: Builder — rust:latest uses trixie (Debian 13), matching distroless/cc-debian13 glibc
FROM rust:latest AS builder
ARG FEATURES

# Install build dependencies
# clang/libclang-dev: required by bindgen (used by zstd-sys)
# cmake: required by some native C dependencies
RUN apt-get update && apt-get install -y \
    pkg-config \
    libssl-dev \
    protobuf-compiler \
    clang \
    libclang-dev \
    cmake \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# ── Dependency caching layer ─────────────────────────────────────────────
# Copy only manifests and build script first, so Docker can cache the
# expensive dependency download + compile step across source changes.
COPY Cargo.toml Cargo.lock build.rs ./
COPY proto ./proto
COPY custom_plugins ./custom_plugins
# Vendored crates referenced by [patch.crates-io] in Cargo.toml. Must be
# present before any `cargo build` (including the dummy-main dep-cache step
# below) — Cargo resolves patch paths during manifest load, not just at
# compile time.
COPY vendor ./vendor
# The main crate depends on shared no_std eBPF ABI types via a path dependency,
# so the Docker build context must include ebpf/ before any Cargo metadata load.
COPY ebpf ./ebpf

# Create a dummy main.rs to build dependencies only
RUN mkdir src && \
    echo 'fn main() { println!("dummy"); }' > src/main.rs && \
    cargo build --features "${FEATURES}" --release 2>/dev/null || true && \
    rm -rf src

# ── Build the real binary ───────────────────────────────────────────────
COPY src ./src
# Touch main.rs so cargo knows it changed (not the dummy)
RUN touch src/main.rs && cargo build --features "${FEATURES}" --release

# Stage 2: Distroless runtime — no OS packages, no shell, no CVEs
# Uses nonroot tag (UID 65532) for least-privilege execution.
# OpenSSL is vendored (statically linked) so libssl is not needed.
# ca-certificates are included in distroless/cc.
FROM gcr.io/distroless/cc-debian13:nonroot

WORKDIR /app

# Copy binary from builder
COPY --from=builder --chown=nonroot:nonroot /build/target/release/ferrum-edge /app/ferrum-edge
COPY --from=builder --chown=nonroot:nonroot /build/target/release/ferrum-cni /app/ferrum-cni

# Copy the compiled eBPF ELF. The node_agent / node-waypoint mesh mode loads it
# via aya only when the binary was built with `--features ebpf`; in the default
# image the file is present but unused (the mock backend attaches nothing).
# `FERRUM_NODE_AGENT_BPF_ELF_PATH` below points the aya loader at this path
# (the CARGO_MANIFEST_DIR-relative default in src/ebpf/loader.rs does not exist
# in the distroless runtime image).
COPY --from=ebpf-builder --chown=nonroot:nonroot \
    /build/ebpf/target/bpfel-unknown-none/release/ferrum-ebpf /app/bpf/ferrum-ebpf

# Set environment variables
ENV PATH="/app:${PATH}" \
    FERRUM_MODE=database \
    FERRUM_LOG_LEVEL=error \
    FERRUM_PROXY_HTTP_PORT=8000 \
    FERRUM_PROXY_HTTPS_PORT=8443 \
    FERRUM_ADMIN_HTTP_PORT=9000 \
    FERRUM_ADMIN_HTTPS_PORT=9443 \
    FERRUM_NODE_AGENT_BPF_ELF_PATH=/app/bpf/ferrum-ebpf

# Expose ports
EXPOSE 8000 8443 9000 9443 50051

# Health check using built-in CLI subcommand (no curl needed in distroless)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD ["/app/ferrum-edge", "health"]

# Add labels
LABEL org.opencontainers.image.title="Ferrum Edge" \
      org.opencontainers.image.description="High-performance edge proxy built in Rust" \
      org.opencontainers.image.source="https://github.com/ferrum-edge/ferrum-edge"

# Run the gateway (already running as nonroot via distroless tag)
ENTRYPOINT ["/app/ferrum-edge"]
CMD ["run"]
