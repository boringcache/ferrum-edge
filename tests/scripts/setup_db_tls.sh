#!/usr/bin/env bash
# Compatibility wrapper for local docs and test diagnostics.
# Canonical script lives under the scanned CI automation root.
set -euo pipefail
script_dir=$(CDPATH= cd -- "$(dirname "$0")" && pwd)
exec "$script_dir/../../.github/scripts/setup_db_tls.sh" "$@"
