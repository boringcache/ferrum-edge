#!/bin/bash
set -euo pipefail
# Fixed workload; the supervisor changes only its complete-campaign deadline.
exec bash tests/performance/multi_protocol/run_gateway_protocol_bench.sh \
    http1-tls --h1-profile diagnostic --gateways ferrum --skip-build \
    --duration 30 --concurrency 200 --pairs 1 --payload-sizes 5242880 \
    --wallclock-budget-seconds "$H1_DIAGNOSTIC_BUDGET" --output-dir "$H1_DIAGNOSTIC_OUTPUT"
