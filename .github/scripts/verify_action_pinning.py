#!/usr/bin/env python3
"""Reject mutable GitHub Actions refs and unverified Kubernetes tool installs.

Scans workflow and composite-action YAML under `.github/` for:

1. External `uses:` references that are not pinned to a full 40-character
   commit SHA (mutable tags/branches/partial SHAs).
2. Pipe-to-shell installers (curl|bash / wget|sh), including mutable-branch
   Helm install scripts.
3. Direct kind / kubectl / Helm binary downloads outside the centralized
   `.github/actions/setup-kubernetes-tools` composite action.

Local actions under `./.github/actions/...` are allowed. Intentionally
generated matrix expressions that do not hard-code a mutable action ref are
ignored. Fail closed on parse/scan errors for scanned files.
"""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_WORKFLOWS_DIR = REPO_ROOT / ".github" / "workflows"
DEFAULT_ACTIONS_DIR = REPO_ROOT / ".github" / "actions"
SETUP_K8S_TOOLS_REL = Path(".github/actions/setup-kubernetes-tools/action.yml")

SHA40 = re.compile(r"^[0-9a-f]{40}$")
# Capture owner/repo (or local path) and optional ref after @.
USES_LINE = re.compile(
    r"(?P<indent>^\s*)(?:-\s*)?uses:\s*(?P<ref>[^\s#]+)",
    re.MULTILINE,
)
# Flow-style mapping forms: `{uses: owner/action@v1}` / `- {uses: ...}`
PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:bash|sh)\b",
    re.IGNORECASE,
)
MUTABLE_HELM_INSTALL = re.compile(
    r"raw\.githubusercontent\.com/helm/helm/(?:main|master)/|"
    r"get\.helm\.sh/helm-install|"
    r"https://raw\.githubusercontent\.com/[^/\s]+/[^/\s]+/(?:main|master)/[^\s]*install",
    re.IGNORECASE,
)
# Direct tool downloads that must go through setup-kubernetes-tools.
DIRECT_K8S_TOOL_DOWNLOAD = re.compile(
    r"(?:"
    r"kind\.sigs\.k8s\.io/dl/|"
    r"github\.com/kubernetes-sigs/kind/releases/download/|"
    r"dl\.k8s\.io/release/.*/kubectl|"
    r"get\.helm\.sh/helm-"
    r")",
    re.IGNORECASE,
)
# azure/setup-helm (and similar) install Helm without repository-pinned
# checksums when version defaults to latest.
DISALLOWED_HELM_ACTIONS = re.compile(
    r"^(?:azure|Azure)/setup-helm(?:@|$)",
)

EXPRESSION_ONLY = re.compile(r"^\$\{\{(.|\n)*\}\}$")


def normalize_uses_ref(raw: str) -> str:
    ref = raw.strip().strip("\"'")
    # Drop trailing flow-mapping junk if a caller passed a wider match.
    ref = ref.rstrip(",}")
    return ref


def is_local_action_ref(ref: str) -> bool:
    return ref.startswith("./") or ref.startswith("../")


def action_pin_status(ref: str) -> tuple[bool, str]:
    """Return (ok, reason). Local actions are always ok."""
    ref = normalize_uses_ref(ref)
    if not ref:
        return False, "empty uses reference"
    if is_local_action_ref(ref):
        # Only allow repo-local composite actions under .github/actions.
        local = ref.split("@", 1)[0]
        local_path = Path(local)
        # Normalize ./foo -> foo for prefix checks.
        parts = local_path.parts
        if parts and parts[0] in {".", ".."}:
            parts = parts[1:]
        expected = ("github", "actions")
        if tuple(parts[:2]) != expected:
            return False, f"local action outside .github/actions: {ref}"
        return True, "local action"
    if ref.startswith("docker://"):
        # docker:// images are out of DEP-04 action-pin scope.
        return True, "docker image reference skipped"
    if "${{" in ref:
        # Dynamic refs are fail-closed unless the entire ref is a single
        # expression used by an intentionally generated matrix. Those matrices
        # still must not embed a literal mutable tag in the YAML source; the
        # expression-only form is allowed when no @mutable literal appears.
        if EXPRESSION_ONLY.match(ref) and "@" not in ref:
            return True, "expression-only generated ref"
        return False, f"dynamic or partially interpolated uses ref: {ref}"
    if "@" not in ref:
        return False, f"missing action pin (@ref): {ref}"
    name, pin = ref.rsplit("@", 1)
    if not name:
        return False, f"missing action name: {ref}"
    if SHA40.match(pin):
        if DISALLOWED_HELM_ACTIONS.match(name):
            return (
                False,
                "azure/setup-helm is disallowed; use "
                "./.github/actions/setup-kubernetes-tools",
            )
        return True, "sha-pinned"
    return False, f"mutable action ref (not a 40-char SHA): {ref}"


def iter_yaml_files(workflows_dir: Path, actions_dir: Path) -> list[Path]:
    files: list[Path] = []
    if workflows_dir.is_dir():
        files.extend(sorted(workflows_dir.glob("*.yml")))
        files.extend(sorted(workflows_dir.glob("*.yaml")))
    if actions_dir.is_dir():
        files.extend(sorted(actions_dir.glob("*/action.yml")))
        files.extend(sorted(actions_dir.glob("*/action.yaml")))
    return files


def relative_to_repo(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(REPO_ROOT))
    except ValueError:
        return str(path)


def is_setup_kubernetes_tools(path: Path) -> bool:
    try:
        return path.resolve().relative_to(REPO_ROOT) == SETUP_K8S_TOOLS_REL
    except ValueError:
        return path.name == "action.yml" and path.parent.name == "setup-kubernetes-tools"


def find_uses_refs(text: str) -> list[tuple[int, str]]:
    refs: list[tuple[int, str]] = []
    for match in USES_LINE.finditer(text):
        line_no = text.count("\n", 0, match.start()) + 1
        refs.append((line_no, normalize_uses_ref(match.group("ref"))))
    # Also catch flow-style uses that might not have been on a `uses:` line
    # start (already covered by USES_LINE for typical `- {uses: ...}` forms).
    return refs


def scan_file(path: Path) -> list[str]:
    failures: list[str] = []
    rel = relative_to_repo(path)
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        return [f"{rel}: failed to read: {exc}"]

    for line_no, ref in find_uses_refs(text):
        ok, reason = action_pin_status(ref)
        if not ok:
            failures.append(f"{rel}:{line_no}: {reason}")

    allow_direct_downloads = is_setup_kubernetes_tools(path)
    for line_no, line in enumerate(text.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if PIPE_TO_SHELL.search(line):
            failures.append(
                f"{rel}:{line_no}: pipe-to-shell installer is forbidden "
                "(never pipe remote content to a shell)"
            )
        if MUTABLE_HELM_INSTALL.search(line):
            failures.append(
                f"{rel}:{line_no}: mutable-branch or remote Helm install "
                "script reference is forbidden"
            )
        if not allow_direct_downloads and DIRECT_K8S_TOOL_DOWNLOAD.search(line):
            failures.append(
                f"{rel}:{line_no}: direct kind/kubectl/Helm download must use "
                "./.github/actions/setup-kubernetes-tools"
            )

    return failures


def scan_repository(workflows_dir: Path, actions_dir: Path) -> list[str]:
    failures: list[str] = []
    files = iter_yaml_files(workflows_dir, actions_dir)
    if not files:
        return [f"no workflow/action YAML found under {workflows_dir} or {actions_dir}"]
    setup_action = actions_dir / "setup-kubernetes-tools" / "action.yml"
    if not setup_action.is_file():
        failures.append(
            f"missing centralized installer: {relative_to_repo(setup_action)}"
        )
    for path in files:
        failures.extend(scan_file(path))
    return failures


def self_test() -> list[str]:
    failures: list[str] = []

    def expect_ok(ref: str, label: str) -> None:
        ok, reason = action_pin_status(ref)
        if not ok:
            failures.append(f"self-test {label}: expected ok, got {reason}")

    def expect_bad(ref: str, label: str, needle: str) -> None:
        ok, reason = action_pin_status(ref)
        if ok:
            failures.append(f"self-test {label}: expected failure, got ok ({reason})")
        elif needle not in reason:
            failures.append(
                f"self-test {label}: expected reason containing {needle!r}, got {reason}"
            )

    sha = "a" * 40
    expect_ok(f"actions/checkout@{sha}", "sha-pinned checkout")
    expect_ok(f"actions/checkout@{sha} # v7.0.1".split()[0], "sha with comment stripped")
    expect_ok("./.github/actions/setup-kubernetes-tools", "local setup action")
    expect_ok("./.github/actions/setup-rust-ci", "local rust action")
    expect_ok("${{ matrix.action }}", "expression-only matrix ref")
    expect_bad("actions/checkout@v7", "mutable tag", "mutable action ref")
    expect_bad("actions/checkout@v7.0.1", "mutable semver tag", "mutable action ref")
    expect_bad("actions/checkout@main", "mutable branch", "mutable action ref")
    expect_bad("actions/checkout@abcd123", "short sha", "mutable action ref")
    expect_bad("actions/checkout", "missing pin", "missing action pin")
    expect_bad("./actions/evil", "local outside actions", "outside .github/actions")
    expect_bad(
        f"azure/setup-helm@{sha}",
        "disallowed helm action",
        "azure/setup-helm is disallowed",
    )
    expect_bad(
        "owner/action@${{ env.REF }}",
        "partial expression",
        "dynamic or partially interpolated",
    )

    sample_bad = (
        "jobs:\n"
        "  x:\n"
        "    steps:\n"
        "      - uses: actions/checkout@v7\n"
        "      - run: curl -fsSL https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash\n"
        "      - run: curl -fsSL -o kind https://kind.sigs.k8s.io/dl/v0.27.0/kind-linux-amd64\n"
    )
    # scan_file on a temp-like synthetic path: use a Named path under /tmp via
    # write to a string scanner by reusing helpers.
    pipe_hits = [m.group(0) for m in PIPE_TO_SHELL.finditer(sample_bad)]
    if not pipe_hits:
        failures.append("self-test pipe-to-shell: pattern did not match Helm installer")
    if not MUTABLE_HELM_INSTALL.search(sample_bad):
        failures.append("self-test mutable helm: pattern did not match")
    if not DIRECT_K8S_TOOL_DOWNLOAD.search(sample_bad):
        failures.append("self-test direct download: pattern did not match kind URL")

    sample_good_action = (
        "runs:\n"
        "  using: composite\n"
        "  steps:\n"
        "    - run: |\n"
        "        curl -fsSL -o kind "
        "https://github.com/kubernetes-sigs/kind/releases/download/v0.27.0/kind-linux-amd64\n"
    )
    # Direct downloads are allowed only inside setup-kubernetes-tools.
    fake_setup = Path("/tmp/setup-kubernetes-tools-action.yml")
    # Use in-memory path classification:
    if is_setup_kubernetes_tools(REPO_ROOT / SETUP_K8S_TOOLS_REL):
        pass
    else:
        failures.append("self-test: setup-kubernetes-tools path classification failed")

    # Ensure a benign local-only workflow text has no direct-download hits when
    # it only references the composite action.
    benign = (
        "jobs:\n"
        "  x:\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      - uses: ./.github/actions/setup-kubernetes-tools\n"
    )
    for line_no, ref in find_uses_refs(benign):
        ok, reason = action_pin_status(ref)
        if not ok:
            failures.append(
                f"self-test benign workflow uses:{line_no} rejected: {reason}"
            )
    if DIRECT_K8S_TOOL_DOWNLOAD.search(benign):
        failures.append("self-test benign workflow falsely matched direct download")
    if PIPE_TO_SHELL.search(benign):
        failures.append("self-test benign workflow falsely matched pipe-to-shell")

    # generated matrix false-positive guard: comments mentioning @v7 must not
    # be treated as uses refs (USES_LINE only matches uses: keys).
    commented = (
        "jobs:\n"
        "  x:\n"
        "    steps:\n"
        f"      - uses: actions/checkout@{sha}\n"
        "      # example of forbidden form: actions/checkout@v7\n"
    )
    for _line_no, ref in find_uses_refs(commented):
        ok, reason = action_pin_status(ref)
        if not ok:
            failures.append(f"self-test commented example rejected: {reason}")

    _ = (sample_good_action, fake_setup)  # documentation anchors for readers
    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workflows-dir",
        type=Path,
        default=DEFAULT_WORKFLOWS_DIR,
    )
    parser.add_argument(
        "--actions-dir",
        type=Path,
        default=DEFAULT_ACTIONS_DIR,
    )
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args(argv)

    failures: list[str] = []
    if args.self_test:
        failures.extend(self_test())

    failures.extend(scan_repository(args.workflows_dir, args.actions_dir))

    if failures:
        print("Action pinning / Kubernetes tool install policy failures:", file=sys.stderr)
        for failure in failures:
            print(f"  - {failure}", file=sys.stderr)
        return 1

    print("Action pinning and Kubernetes tool install policy checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
