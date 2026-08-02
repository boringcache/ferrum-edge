#!/usr/bin/env python3
"""Audit the resolved cargo feature graph for the FIPS build profile.

The `crypto-ring` / `fips` cargo features in `Cargo.toml` are the *declared*
contract, and `src/fips/mod.rs` fails compilation when both or neither is
selected. Neither of those catches the failure mode this check exists for: a
**transitive** edge that re-enables `rustls/ring` (or leaves a dependency on its
ring arm) without this crate's own feature list mentioning it. That build looks
switched, reports a FIPS provider, and still routes some traffic through a
non-validated implementation.

So this reads what cargo actually resolved, not what the manifest asked for.

Usage:

    check_fips_feature_policy.py --manifest-check
        Static checks over `Cargo.toml` only. No cargo invocation, no network.

    check_fips_feature_policy.py --tree <path-to-cargo-tree-output> --profile fips
    check_fips_feature_policy.py --tree <path> --profile crypto-ring
        Audit `cargo tree -e features,no-dev` output for that profile.

The `no-dev` edge filter is load-bearing: test fixtures pin `ring` and `rustls/ring` as
dev-dependencies so the suite compiles under both profiles, and a dev-dependency
is never linked into the shipped binary. Auditing with dev-deps included would
report a ring edge that no deployment can reach.

Exit status is 0 when the profile is admissible and 1 otherwise, with every
violation printed.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
MANIFEST = REPO_ROOT / "Cargo.toml"

# Feature edges that must be present in the `fips` feature list and absent from
# it, paired with their `crypto-ring` counterparts. Each pair is one dependency
# whose aws-lc arm is gated on the absence of its ring arm, so "additively
# enable aws-lc" is not sufficient for it.
REQUIRED_FEATURE_PAIRS = (
    ("dep:ring", "dep:aws-lc-rs"),
    ("rustls/ring", "rustls/fips"),
    ("tokio-rustls/ring", "tokio-rustls/fips"),
    ("tonic/tls-ring", "tonic/tls-aws-lc"),
    ("quinn/rustls-ring", "quinn/rustls-aws-lc-rs-fips"),
    ("sqlx/tls-rustls-ring", "sqlx/tls-rustls-aws-lc-rs"),
    ("ldap3/tls-rustls-ring", "ldap3/tls-rustls-aws-lc-rs"),
    ("rcgen/ring", "rcgen/fips"),
    ("x509-parser/verify", "x509-parser/verify-aws"),
    ("jsonwebtoken/rust_crypto", "jsonwebtoken/aws_lc_rs"),
    ("hyper-rustls?/ring", "hyper-rustls?/fips"),
    ("instant-acme?/ring", "instant-acme?/fips"),
)

# The `fips` feature must additionally bind the validated module itself.
REQUIRED_FIPS_ONLY = ("aws-lc-rs/fips",)

# Dependencies that must never be declared with an inline crypto-backend
# feature: the backend belongs to the mutually exclusive feature pair, and an
# inline selection would silently win on both profiles.
FORBIDDEN_INLINE_DECLARATIONS = {
    "rustls": ("ring", "aws_lc_rs", "aws-lc-rs", "fips"),
    "tokio-rustls": ("ring", "aws_lc_rs", "aws-lc-rs", "fips"),
    "tonic": ("tls-ring", "tls-aws-lc"),
    "sqlx": ("runtime-tokio-rustls", "tls-rustls", "tls-rustls-ring"),
    "ldap3": ("tls-rustls-ring", "tls-rustls-aws-lc-rs"),
    "hyper-rustls": ("ring", "aws-lc-rs", "fips"),
    "instant-acme": ("ring", "aws-lc-rs", "fips"),
    "x509-parser": ("verify", "verify-aws"),
    "jsonwebtoken": ("rust_crypto", "aws_lc_rs"),
    "reqwest": ("rustls",),
}

# Dependencies that must be declared with `default-features = false`, because
# their default feature set selects a crypto backend.
REQUIRE_DEFAULT_FEATURES_OFF = ("quinn", "rcgen", "rustls", "tokio-rustls")

# `cargo tree -e features` prints feature edges as `crate feature "name"`.
FEATURE_EDGE = re.compile(r'^[^a-zA-Z0-9]*([A-Za-z0-9_.-]+) feature "([A-Za-z0-9_.-]+)"')
ANSI_ESCAPE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")

# Feature selections that must never appear in a resolved `fips` graph. Each
# one puts a non-validated implementation in control of a real traffic path.
FORBIDDEN_RESOLVED_FIPS = {
    ("rustls", "ring"),
    ("tokio-rustls", "ring"),
    ("quinn", "rustls-ring"),
    ("quinn-proto", "rustls-ring"),
    ("sqlx", "tls-rustls-ring"),
    ("sqlx-core", "_tls-rustls-ring-webpki"),
    ("sqlx-core", "_tls-rustls-ring-native-roots"),
    ("ldap3", "tls-rustls-ring"),
    ("tonic", "tls-ring"),
    ("hyper-rustls", "ring"),
    ("rcgen", "ring"),
    ("jsonwebtoken", "rust_crypto"),
    ("x509-parser", "verify"),
    ("rustls-webpki", "ring"),
    ("webpki", "ring"),
}

# Feature selections that must be present in a resolved `fips` graph.
REQUIRED_RESOLVED_FIPS = {
    ("aws-lc-rs", "fips"),
    ("rustls", "fips"),
}

# The ordinary profile's contract, so a change that quietly moves the default
# build onto a different backend is caught too.
REQUIRED_RESOLVED_RING = {
    ("rustls", "ring"),
}
FORBIDDEN_RESOLVED_RING = {
    ("aws-lc-rs", "fips"),
    ("rustls", "fips"),
}

# Ferrum-owned production code must not bypass `crate::fips::approved` by
# importing the independent RustCrypto reference implementations. Test code is
# deliberately exempt: it uses those crates to verify module-backed outputs
# against an implementation that does not share the production seam.
FORBIDDEN_PRODUCTION_CRATE_PATTERNS = (
    re.compile(r"\buse\s+sha2(?:::|\s*;)"),
    re.compile(r"\bsha2::"),
    re.compile(r"\buse\s+hmac(?:::|\s*;)"),
    re.compile(r"\bhmac::Hmac\b"),
)


def read_manifest() -> str:
    return MANIFEST.read_text(encoding="utf-8")


def feature_list(manifest: str, name: str) -> list[str]:
    """Extract one entry of the `[features]` table as a list of strings."""

    # Single-line spelling first: the multi-line pattern would otherwise run
    # past a one-line list's own closing bracket to the next block-closing `]`.
    match = re.search(rf"^{re.escape(name)} = \[([^\n\]]*)\]$", manifest, re.M)
    if match is None:
        match = re.search(rf"^{re.escape(name)} = \[(.*?)^\]", manifest, re.M | re.S)
    if match is None:
        return []
    return re.findall(r'"([^"]+)"', match.group(1))


def dependency_line(manifest: str, name: str) -> str | None:
    match = re.search(rf'^{re.escape(name)} = (\{{.*?\}}|"[^"]*")$', manifest, re.M)
    return match.group(1) if match else None


def check_manifest() -> list[str]:
    manifest = read_manifest()
    failures: list[str] = []

    ring_features = feature_list(manifest, "crypto-ring")
    fips_features = feature_list(manifest, "fips")
    if not ring_features:
        failures.append("Cargo.toml has no `crypto-ring` feature list")
    if not fips_features:
        failures.append("Cargo.toml has no `fips` feature list")

    default_features = feature_list(manifest, "default")
    if default_features != ["crypto-ring"]:
        failures.append(
            "the default feature set must be exactly [\"crypto-ring\"] so the ordinary "
            f"build is unchanged; found {default_features}"
        )

    for ring_edge, fips_edge in REQUIRED_FEATURE_PAIRS:
        if ring_edge not in ring_features:
            failures.append(f"`crypto-ring` must select {ring_edge!r}")
        if fips_edge not in fips_features:
            failures.append(f"`fips` must select {fips_edge!r}")
        if ring_edge in fips_features:
            failures.append(
                f"`fips` must not select the ring arm {ring_edge!r} — the aws-lc arm of that "
                "dependency is gated on its absence"
            )
        if fips_edge in ring_features:
            failures.append(f"`crypto-ring` must not select {fips_edge!r}")

    for edge in REQUIRED_FIPS_ONLY:
        if edge not in fips_features:
            failures.append(f"`fips` must select {edge!r} to bind the validated module")

    for dep, forbidden in FORBIDDEN_INLINE_DECLARATIONS.items():
        line = dependency_line(manifest, dep)
        if line is None:
            failures.append(f"dependency {dep!r} is not declared on its own line in Cargo.toml")
            continue
        inline = set(re.findall(r'"([^"]+)"', line))
        for feature in forbidden:
            if feature in inline:
                failures.append(
                    f"dependency {dep!r} must not select the crypto-backend feature "
                    f"{feature!r} inline; it belongs to the `crypto-ring` / `fips` pair"
                )

    for dep in REQUIRE_DEFAULT_FEATURES_OFF:
        line = dependency_line(manifest, dep)
        if line is None:
            failures.append(f"dependency {dep!r} is not declared on its own line in Cargo.toml")
        elif "default-features = false" not in line:
            failures.append(
                f"dependency {dep!r} must be declared with `default-features = false`; its "
                "default feature set selects a cryptographic backend"
            )

    dependency_table = re.search(
        r"^\[dependencies\]\s*$\n(.*?)(?=^\[)", manifest, re.M | re.S
    )
    if dependency_table is None:
        failures.append("Cargo.toml has no `[dependencies]` table")
    else:
        for reference_crate in ("sha2", "hmac"):
            if re.search(
                rf"^{re.escape(reference_crate)}\s*=",
                dependency_table.group(1),
                re.M,
            ):
                failures.append(
                    f"RustCrypto reference crate {reference_crate!r} must be dev-only; "
                    "production SHA-2/HMAC uses crate::fips::approved"
                )

    for source_path in sorted((REPO_ROOT / "src").rglob("*.rs")):
        # This module intentionally names the old API in rustdoc while
        # implementing the provider-backed compatibility surface itself.
        if source_path == REPO_ROOT / "src/fips/approved.rs":
            continue
        source = source_path.read_text(encoding="utf-8")
        if any(pattern.search(source) for pattern in FORBIDDEN_PRODUCTION_CRATE_PATTERNS):
            failures.append(
                f"{source_path.relative_to(REPO_ROOT)} imports a RustCrypto SHA-2/HMAC "
                "implementation; route it through crate::fips::approved"
            )

    return failures


def parse_tree(path: Path) -> set[tuple[str, str]]:
    selections: set[tuple[str, str]] = set()
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        match = FEATURE_EDGE.match(ANSI_ESCAPE.sub("", line).strip())
        if match:
            selections.add((match.group(1), match.group(2)))
    return selections


def check_tree(path: Path, profile: str) -> list[str]:
    selections = parse_tree(path)
    if not selections:
        return [
            f"no feature edges parsed from {path}; expected the output of "
            "`cargo tree -e features,no-dev`"
        ]

    if profile == "fips":
        required, forbidden = REQUIRED_RESOLVED_FIPS, FORBIDDEN_RESOLVED_FIPS
    elif profile == "crypto-ring":
        required, forbidden = REQUIRED_RESOLVED_RING, FORBIDDEN_RESOLVED_RING
    else:
        return [f"unknown profile {profile!r}"]

    failures: list[str] = []
    for crate, feature in sorted(required):
        if (crate, feature) not in selections:
            observed = sorted(
                selected_feature
                for selected_crate, selected_feature in selections
                if selected_crate == crate
            )
            failures.append(
                f"[{profile}] resolved graph is missing the required selection "
                f"{crate}/{feature}; observed {crate} features: {observed}"
            )
    for crate, feature in sorted(forbidden):
        if (crate, feature) in selections:
            failures.append(
                f"[{profile}] resolved graph still selects {crate}/{feature}, so a "
                "non-validated implementation remains in control of that path"
            )
    return failures


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest-check", action="store_true")
    parser.add_argument("--tree", type=Path)
    parser.add_argument("--profile", choices=("fips", "crypto-ring"))
    args = parser.parse_args()

    failures: list[str] = []
    if args.manifest_check or args.tree is None:
        failures.extend(check_manifest())
    if args.tree is not None:
        if args.profile is None:
            parser.error("--tree requires --profile")
        failures.extend(check_tree(args.tree, args.profile))

    if failures:
        print("FIPS feature-policy check FAILED:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1
    print("FIPS feature-policy check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
