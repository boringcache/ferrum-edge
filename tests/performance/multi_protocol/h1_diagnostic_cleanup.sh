#!/bin/bash
set -uo pipefail
# Names are allocated before docker run, including a timed-out create request.
[[ ${H1_DIAGNOSTIC_CONTAINER_PREFIX:-} =~ ^ferrum-h1-diag-[0-9a-f]{32}$ ]] || exit 2
[[ ${H1_DIAGNOSTIC_SESSION:-} =~ ^[1-9][0-9]*$ ]] || exit 2
[[ ${H1_DIAGNOSTIC_START_TICKS:-} =~ ^[1-9][0-9]*$ ]] || exit 2
status=0
# Each stage uses a fraction of the REMAINING helper budget, including its
# force-kill grace. Short diagnostic budgets cannot leave a long helper tail.
bounds() {
    python3 -c 'import os,sys,time; r=float(os.environ["H1_DIAGNOSTIC_CLEANUP_DEADLINE"])-time.monotonic(); sys.exit(1) if r<=0.01 else print(min(3,r/4), min(0.05,r/16))'
}
read -r bound grace < <(bounds) || exit 1
sudo -n \
    --preserve-env=H1_DIAGNOSTIC_SESSION,H1_DIAGNOSTIC_START_TICKS \
    timeout --signal=TERM --kill-after="${grace}s" "${bound}s" \
    python3 tests/performance/multi_protocol/h1_diagnostic_campaign.py cleanup-processes || status=1
mkdir -p "$H1_DIAGNOSTIC_OUTPUT/pairs/pair_001/diagnostics"
for arm in ferrum ferrum-exp-cutoff-one; do
    read -r bound grace < <(bounds) || exit 1
    timeout --signal=TERM --kill-after="${grace}s" "${bound}s" docker logs --timestamps \
        "$H1_DIAGNOSTIC_CONTAINER_PREFIX-$arm" \
        > "$H1_DIAGNOSTIC_OUTPUT/pairs/pair_001/diagnostics/${arm}_termination.log" 2>&1 || true
done
read -r bound grace < <(bounds) || exit 1
timeout --signal=TERM --kill-after="${grace}s" "${bound}s" docker rm -f \
    "$H1_DIAGNOSTIC_CONTAINER_PREFIX-ferrum" \
    "$H1_DIAGNOSTIC_CONTAINER_PREFIX-ferrum-exp-cutoff-one" || true
read -r bound grace < <(bounds) || exit 1
remaining=$(timeout --signal=TERM --kill-after="${grace}s" "${bound}s" docker ps --all --quiet \
    --filter "name=^/$H1_DIAGNOSTIC_CONTAINER_PREFIX-ferrum$" \
    --filter "name=^/$H1_DIAGNOSTIC_CONTAINER_PREFIX-ferrum-exp-cutoff-one$") || status=1
[ -z "$remaining" ] || status=1
exit "$status"
