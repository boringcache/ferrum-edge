#!/usr/bin/env bash
# Fixed read-only command surface; the selected immutable image is data only.
set -euo pipefail
[[ ${FERRUM_H1_IMAGE_ID:?} =~ ^sha256:[0-9a-f]{64}$ ]]
exec docker image inspect --format '{{json .}}' "$FERRUM_H1_IMAGE_ID"
