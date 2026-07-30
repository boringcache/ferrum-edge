#!/usr/bin/env bash
# Report the upstream status of each vendored, patched crate so that a fix
# merged upstream cannot sit unnoticed — once upstream ships, the vendor copy
# and its [patch.crates-io] entry should be retired (see each patch's docs).
#
# Run weekly by .github/workflows/dependency-audit.yml. Exits non-zero if any
# tracked upstream PR has MERGED (a retirement signal), so the scheduled run
# goes red and a maintainer follows the retirement checklist.
#
# Requires network access for api.github.com and crates.io. In Actions, set
# GH_TOKEN (or GITHUB_TOKEN) so upstream PR queries use authenticated REST API
# rate limits. Safe to run locally without a token for public upstream repos.
#
# Canonical inventory: docs/vendored-patch-lifecycle.json (enforced by
# scripts/check_vendored_patch_lifecycle.py on every PR and weekly).
#
# Delegates from this script's directory so a cwd-relative no-op cannot disable
# weekly upstream-status reporting.
set -uo pipefail

SCRIPT_DIR="$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)"
exec python3 "$SCRIPT_DIR/check_vendored_patch_lifecycle.py" --upstream-status
