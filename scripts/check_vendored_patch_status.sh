#!/usr/bin/env bash
# Report the upstream status of each vendored, patched crate so that a fix
# merged upstream cannot sit unnoticed — once upstream ships, the vendor copy
# and its [patch.crates-io] entry should be retired (see each patch's docs).
#
# Run weekly by .github/workflows/dependency-audit.yml. Exits non-zero if any
# tracked upstream PR has MERGED (a retirement signal), so the scheduled run
# goes red and a maintainer follows the retirement checklist.
#
# Requires `gh` (GitHub CLI, auto-authenticated via GH_TOKEN in Actions) and
# network access for crates.io. Safe to run locally if `gh auth status` is set up.
#
# Canonical inventory: docs/vendored-patch-lifecycle.json (enforced by
# scripts/check_vendored_patch_lifecycle.py on every PR and weekly).
set -uo pipefail

exec python3 scripts/check_vendored_patch_lifecycle.py --upstream-status
