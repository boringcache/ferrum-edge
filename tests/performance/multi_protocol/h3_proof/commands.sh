#!/usr/bin/env bash
# Fixed process inventory for hosted.py. Data never supplies a command or script.
set -euo pipefail
[[ ${GITHUB_ACTIONS:-} == true && ${RUNNER_ENVIRONMENT:-} == github-hosted ]]
[[ ${RUNNER_OS:-} == Linux && ${RUNNER_ARCH:-} == X64 ]]

case "${H3_PROOF_ACTION:?}" in
  clang-version) exec clang-18 --version ;;
  cc-version) exec cc --version ;;
  readelf-version) exec readelf --version ;;
  uname) exec uname -a ;;
  checkout) exec git rev-parse HEAD ;;
  packages)
    exec dpkg-query -W -f='${binary:Package}\t${Version}\t${source:Package}\t${source:Version}\n'
    ;;
  package-origins)
    exec apt-cache policy clang-18 llvm-18 libbpf-dev libbpf1 libelf-dev gcc \
      libelf1t64 zlib1g zlib1g-dev binutils libc6 libc6-dev linux-libc-dev iproute2 util-linux python3
    ;;
  package-version|package-record)
    case "${H3_PROOF_PACKAGE:?}" in
      clang-18|llvm-18|libbpf-dev|libbpf1|libelf-dev|gcc|libelf1t64|zlib1g|zlib1g-dev|binutils|libc6|libc6-dev|linux-libc-dev|iproute2|util-linux|python3) ;;
      *) exit 2 ;;
    esac
    if [[ $H3_PROOF_ACTION == package-version ]]; then
      exec dpkg-query -W '-f=${Version}' "$H3_PROOF_PACKAGE"
    fi
    [[ ${H3_PROOF_VERSION:?} =~ ^[0-9][A-Za-z0-9.+:~-]*$ ]]
    exec apt-cache show "$H3_PROOF_PACKAGE=$H3_PROOF_VERSION"
    ;;
  observer-build-id) exec readelf -n /tmp/ferrum-h3-proof/build/observer ;;
  pmu-build-id) exec readelf -n /tmp/ferrum-h3-proof/build/pmu ;;
  loopback) exec ip link set lo up ;;
  tracefs) exec mount -t tracefs tracefs /sys/kernel/tracing ;;
  isolate)
    [[ ${H3_PROOF_OUTPUT:?} == /* ]]
    exec unshare --net --mount --propagation private \
      python3 -B tests/performance/multi_protocol/h3_proof/hosted.py \
      --suite capability-v1 --output "$H3_PROOF_OUTPUT" --isolated
    ;;
  observer)
    case "${H3_PROOF_FAMILY:?}" in tx|rx|classic|attach|lifetime|destroy|group|process) ;; *) exit 2 ;; esac
    [[ ${H3_PROOF_NETNS:?} =~ ^[1-9][0-9]{0,19}$ ]]
    case "${H3_PROOF_CAPACITY:?}" in 1|512) ;; *) exit 2 ;; esac
    case "${H3_PROOF_FAULT:?}" in normal|missing-btf|missing-symbol) ;; *) exit 2 ;; esac
    case "${H3_PROOF_UNPRIVILEGED:?}" in
      true)
        exec setpriv --reuid=65534 --regid=65534 --clear-groups \
          --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
          /tmp/ferrum-h3-proof/build/observer /tmp/ferrum-h3-proof/build/observer.bpf.o \
          "$H3_PROOF_FAMILY" "$H3_PROOF_NETNS" "$H3_PROOF_CAPACITY" "$H3_PROOF_FAULT"
        ;;
      false)
        exec /tmp/ferrum-h3-proof/build/observer /tmp/ferrum-h3-proof/build/observer.bpf.o \
          "$H3_PROOF_FAMILY" "$H3_PROOF_NETNS" "$H3_PROOF_CAPACITY" "$H3_PROOF_FAULT"
        ;;
      *) exit 2 ;;
    esac
    ;;
  fixture)
    case "${H3_PROOF_MODE:?}" in
      offload|batches|read-failure|classic-select|classic-fallback|recvmmsg-cases) ;;
      *) exit 2 ;;
    esac
    exec setpriv --reuid=65534 --regid=65534 --clear-groups \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
      python3 -B tests/performance/multi_protocol/h3_proof/fixture.py "$H3_PROOF_MODE"
    ;;
  pmu-observer) exec /tmp/ferrum-h3-proof/build/pmu ;;
  pmu-fixture)
    exec setpriv --reuid=65534 --regid=65534 --clear-groups \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
      /tmp/ferrum-h3-proof/build/pmu
    ;;
  *) exit 2 ;;
esac
