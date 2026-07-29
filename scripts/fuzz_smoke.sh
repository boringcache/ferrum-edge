#!/usr/bin/env bash
# Deterministic smoke lane for hosted CI: property checks plus a short libFuzzer budget.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../fuzz" && pwd)"
cd "$ROOT"

export CARGO_TERM_COLOR=always

echo "Running fuzz property smoke tests..."
cargo test --quiet

if ! command -v cargo-fuzz >/dev/null 2>&1; then
  cargo install cargo-fuzz --locked --version 0.13.1
fi

TARGETS=(
  traceparent
  config_decode
  proxy_protocol
  mesh_udp_frame
  k8s_crd
  plugin_config
)

for target in "${TARGETS[@]}"; do
  echo "Fuzz smoke target: $target"
  cargo fuzz run "$target" -- \
    -runs=512 \
    -max_total_time=8 \
    -max_len=4096 \
    -timeout=2 \
    -rss_limit_mb=512
done

echo "Fuzz smoke lane complete."
