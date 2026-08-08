# Upstream h3-quinn patches

> Governance: tracked in [docs/dependency-policy.md](../dependency-policy.md). Any
> change to `vendor/h3-quinn-0.0.10-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

Tracks fixes we've drafted for the `h3-quinn` crate in
[hyperium/h3](https://github.com/hyperium/h3). Each numbered subdirectory is a
self-contained patch with the issue draft, PR description, unified diff, and a
lifecycle README explaining how to file the upstream artifacts and how to retire
the patch when it merges.

## Active patches

| ID | Title | Crate | Status | Tracked by |
|---|---|---|---|---|
| [001](001-stop-sending-during-in-flight-read/) | `RecvStream::stop_sending` must work while a read is in flight | `h3-quinn` | Applied (vendored at [`vendor/h3-quinn-0.0.10-ferrum-patched/`](../../vendor/h3-quinn-0.0.10-ferrum-patched/)) | Ferrum Edge full-duplex native-H3 gRPC (#3283) |

## Conventions

Each subdirectory is `NNN-short-kebab-summary/` with:

- `README.md` — Status, links, hand-off steps, and retirement plan
- `issue.md` — Bug report draft for upstream
- `pr-description.md` — PR description draft for upstream
- `<file>.patch` — The unified diff against the pinned upstream version

When a patch is upstreamed and we've bumped past the affected version, move its
directory to `_retired/NNN-...` with a `STATUS.md` noting the merge commit and
the local cleanup that closed it out.

See also: [`docs/http3.md`](../http3.md) for the runtime behavior these patches
affect, and [`docs/upstream-h3-patches/`](../upstream-h3-patches/README.md) for
the sibling patches against the `h3` crate itself.
