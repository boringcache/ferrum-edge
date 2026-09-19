#!/bin/bash
set -euo pipefail
exec python3 tests/performance/multi_protocol/h1_internal_profile.py \
    report-diagnostic "$H1_DIAGNOSTIC_OUTPUT"
