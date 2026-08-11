# Ambient host-network UDP live-kernel gate (#3705)

Privileged hosted gate for the production Ambient host-network UDP capture
placement (`FERRUM_MESH_CAPTURE_UDP_HOST_NETNS_ENABLED=true` →
`ProxyHostUdpBackend`).

## What it proves

- Two independent workload netns / veth pairs
- IPv4 and IPv6 TPROXY delivery with original-destination recovery
- Kernel ingress-ifindex attribution and identical-tuple isolation by interface
- Transparent replies sourced from the captured destination
- Restart / reinstall and exact Ferrum-owned cleanup (table `33135`, priority
  `101`, chains `FERRUM_MESH_UDP_HOST` / `_GUARD_A` / `_GUARD_B`)
- Explicit negatives: source spoofing, missing/zero pktinfo, unenrolled /
  ambiguous interfaces, node-originated and inbound-to-pod traffic, fail-closed
  prerequisite / partial-install script contracts

## Skip-or-fail

`FERRUM_LIVE_TESTS_REQUIRED=1` (set by the workflow) converts missing root,
`unshare`/`ip`/`iptables`/`ip6tables`, or TPROXY primitives into hard failure.
Local ad-hoc runs without that flag may still print `SKIP:`.

## Diagnostics

Bounded, redacted snapshots of `ip rule` / table `33135`, Ferrum mangle chains,
interface indexes, and UDP bind state are written under
`target/ambient-host-udp-live/` and uploaded by the workflow.
