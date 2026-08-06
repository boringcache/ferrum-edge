#!/usr/bin/env python3
"""Reject container-runtime escape mounts in Ferrum node-agent/ambient charts.

`docs/node_agent_security.md` claims CI rejects chart diffs that add a container
runtime socket mount or `privileged: true` on the node-agent / ambient
workloads. This checker is that gate.

Trusted CI extracts this script from the base branch (see the always-on
`chart-runtime-lint` job in `.github/workflows/ci.yml`) and runs it against the
pull request's chart tree, so a malicious PR cannot replace the checker while
still passing the gate. That job is deliberately separate from `ci-plan`: the
trusted ARM64 Cross build policy freezes the per-job digest of every
Cross-sensitive `ci.yml` job, and `ci-plan` is one of them.

The scanner reasons about chart workload/value content after stripping Helm and
YAML comments, so prose such as the existing RuntimeDefault/containerd seccomp
comment does not false-positive.

Usage:
  python3 -I .github/scripts/check_node_agent_chart_runtime.py --self-test
  python3 -I .github/scripts/check_node_agent_chart_runtime.py
  python3 -I .github/scripts/check_node_agent_chart_runtime.py --root <path>
"""

from __future__ import annotations

import argparse
import re
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]


def default_repo_root() -> Path:
    """Resolve the Ferrum checkout when the script may be base-extracted to TEMP.

    Trusted CI copies this file under `$RUNNER_TEMP` and runs it with
    `python3 -I`, so `__file__`-relative parents are not the repository. Prefer
    the process working directory (CI checks out and runs from the repo root)
    and only fall back to the in-tree `.github/scripts/` layout.
    """

    cwd = Path.cwd()
    if (cwd / "charts" / "ferrum-mesh" / "templates").is_dir():
        return cwd
    if (REPO_ROOT / "charts" / "ferrum-mesh" / "templates").is_dir():
        return REPO_ROOT
    return cwd


# Fail closed if any of these governed surfaces is missing or unreadable.
REQUIRED_RELATIVE_PATHS: tuple[str, ...] = (
    "charts/ferrum-mesh/templates/node-agent-daemonset.yaml",
    "charts/ferrum-mesh/templates/ambient-daemonset.yaml",
    "charts/ferrum-mesh/values.yaml",
)

# Every rendered template and every values/example input is governed. Keeping
# this recursive and chart-wide prevents a rename, a second DaemonSet template,
# a helper fragment, or the sibling gateway chart from becoming an escape hatch.
GOVERNED_GLOBS: tuple[str, ...] = (
    "charts/**/templates/**/*",
    "charts/**/values*.yaml",
    "charts/**/values*.yml",
    "charts/**/values*.json",
    "charts/**/examples/**/*.yaml",
    "charts/**/examples/**/*.yml",
    "charts/**/examples/**/*.json",
    "charts/**/files/**/*",
)

HELM_COMMENT_RE = re.compile(r"\{\{-?\s*/\*.*?\*/\s*-?\}\}", re.DOTALL)
FULL_LINE_HASH_COMMENT_RE = re.compile(r"(?m)^\s*#.*$")
# Trailing YAML `#` comments outside simple quoted scalars.
TRAILING_HASH_COMMENT_RE = re.compile(
    r"(?m)^(?P<code>(?:[^#'\"\n]|'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\")*?)\s+#.*$"
)

# Reject a privileged field unless its value is a literal false. This catches
# hard-coded true, inline YAML/JSON, and Helm expressions such as
# `privileged: {{ .Values.foo }}` whose default might be false but which would
# otherwise create an operator-controlled privilege escalation.
PRIVILEGED_ASSIGNMENT_RE = re.compile(
    r"(?im)(?:^[ \t]*|[,{][ \t]*)[\"']?privileged[\"']?[ \t]*:[ \t]*"
    r"(?P<value>[^,}\n]+)"
)
LITERAL_FALSE_VALUES = frozenset(("false", '"false"', "'false'"))

# Path / socket references that grant container-runtime or host-escape access.
PROHIBITED_REFERENCE_RES: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("docker.sock", re.compile(r"docker\.sock", re.IGNORECASE)),
    ("containerd.sock", re.compile(r"containerd\.sock", re.IGNORECASE)),
    ("crio.sock", re.compile(r"cri-?o\.sock", re.IGNORECASE)),
    ("runtime.sock", re.compile(r"(?:^|[\s\"'=/])runtime\.sock\b", re.IGNORECASE)),
    ("/var/run/docker", re.compile(r"/var/run/docker(?:/|\b)", re.IGNORECASE)),
    ("/var/lib/docker", re.compile(r"/var/lib/docker(?:/|\b)", re.IGNORECASE)),
    ("/run/containerd", re.compile(r"/run/containerd(?:/|\b)", re.IGNORECASE)),
    (
        "/var/run/containerd",
        re.compile(r"/var/run/containerd(?:/|\b)", re.IGNORECASE),
    ),
    (
        "/var/lib/containerd",
        re.compile(r"/var/lib/containerd(?:/|\b)", re.IGNORECASE),
    ),
    ("/run/crio", re.compile(r"/run/cri-?o(?:/|\b)", re.IGNORECASE)),
    ("/var/run/crio", re.compile(r"/var/run/cri-?o(?:/|\b)", re.IGNORECASE)),
    ("/var/lib/crio", re.compile(r"/var/lib/cri-?o(?:/|\b)", re.IGNORECASE)),
)


def strip_chart_comments(text: str) -> str:
    """Remove Helm block comments and YAML `#` comments before scanning."""

    without_helm = HELM_COMMENT_RE.sub("", text)
    without_full = FULL_LINE_HASH_COMMENT_RE.sub("", without_helm)
    return TRAILING_HASH_COMMENT_RE.sub(r"\g<code>", without_full)


def iter_scan_paths(root: Path) -> list[Path]:
    paths: set[Path] = set()
    missing: list[str] = []
    for relative in REQUIRED_RELATIVE_PATHS:
        path = root / relative
        if not path.is_file():
            missing.append(relative)
            continue
        paths.add(path)
    if missing:
        raise FileNotFoundError(
            "required node-agent/ambient chart surfaces missing or not regular "
            f"files: {', '.join(missing)}"
        )
    for pattern in GOVERNED_GLOBS:
        for path in sorted(root.glob(pattern)):
            if path.is_file():
                paths.add(path)
    return sorted(paths)


def scan_text(relative: str, text: str) -> list[str]:
    content = strip_chart_comments(text)
    findings: list[str] = []
    for match in PRIVILEGED_ASSIGNMENT_RE.finditer(content):
        value = match.group("value").strip().lower()
        if value not in LITERAL_FALSE_VALUES:
            findings.append(
                f"{relative}: privileged must be literal false "
                "(true or dynamic values are prohibited)"
            )
            break
    for label, pattern in PROHIBITED_REFERENCE_RES:
        if pattern.search(content):
            findings.append(
                f"{relative}: prohibited container-runtime/host-escape "
                f"reference ({label})"
            )
    return findings


def scan_file(root: Path, path: Path) -> list[str]:
    try:
        relative = path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError as exc:
        raise ValueError(f"scan path escapes repository root: {path}") from exc
    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise OSError(f"unreadable chart surface {relative}: {exc}") from exc
    return scan_text(relative, text)


def check_repository(root: Path | None = None) -> list[str]:
    base = default_repo_root() if root is None else root
    if not base.is_dir():
        raise NotADirectoryError(f"chart check root is not a directory: {base}")
    findings: list[str] = []
    for path in iter_scan_paths(base):
        findings.extend(scan_file(base, path))
    return findings


def _write(path: Path, contents: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(contents, encoding="utf-8")


def _required_tree(root: Path, *, node_agent: str, ambient: str, values: str) -> None:
    _write(root / REQUIRED_RELATIVE_PATHS[0], node_agent)
    _write(root / REQUIRED_RELATIVE_PATHS[1], ambient)
    _write(root / REQUIRED_RELATIVE_PATHS[2], values)


_CLEAN_NODE_AGENT = """\
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ferrum-mesh-node-agent
spec:
  template:
    spec:
      containers:
        - name: ferrum-edge
          securityContext:
            privileged: false
          volumeMounts:
            - name: bpf-fs
              mountPath: /sys/fs/bpf
            - name: cgroup
              mountPath: /sys/fs/cgroup
              readOnly: true
      volumes:
        - name: bpf-fs
          hostPath:
            path: /sys/fs/bpf
        - name: cgroup
          hostPath:
            path: /sys/fs/cgroup
"""

_CLEAN_AMBIENT = """\
apiVersion: apps/v1
kind: DaemonSet
metadata:
  name: ferrum-mesh-ambient
spec:
  template:
    spec:
      containers:
        - name: ferrum-edge
          volumeMounts:
            - name: spire-agent-socket
              mountPath: /run/spire/sockets
              readOnly: true
      volumes:
        - name: spire-agent-socket
          hostPath:
            path: /run/spire/sockets
"""

_CLEAN_VALUES = """\
nodeAgent:
  enabled: true
  security:
    # Pod-wide seccomp profile. RuntimeDefault is the containerd default
    # and permits every syscall the agent needs.
    seccompProfile:
      type: RuntimeDefault
  cni:
    hostSocketDir: /var/run/ferrum
    socketFileName: node-agent-cni.sock
ambient:
  enabled: true
  spire:
    socketHostPath: /run/spire/sockets
"""


def run_self_test() -> list[str]:
    """Synthetic fixtures: prohibited examples fail; legitimate chart content passes."""

    failures: list[str] = []

    with tempfile.TemporaryDirectory(prefix="ferrum-chart-runtime-lint-") as tmp:
        good_root = Path(tmp) / "good"
        _required_tree(
            good_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        try:
            findings = check_repository(good_root)
        except Exception as exc:  # noqa: BLE001 - self-test must surface any failure
            failures.append(f"clean fixture unexpectedly raised: {exc}")
        else:
            if findings:
                failures.append(f"clean fixture unexpectedly failed: {findings}")

        comment_only = Path(tmp) / "comment-only"
        _required_tree(
            comment_only,
            node_agent=(
                _CLEAN_NODE_AGENT
                + "\n# Do not mount /var/run/docker.sock or containerd.sock\n"
            ),
            ambient=(
                _CLEAN_AMBIENT
                + "\n{{- /* privileged: true and /run/containerd are forbidden */ -}}\n"
            ),
            values=_CLEAN_VALUES,
        )
        try:
            findings = check_repository(comment_only)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"comment-only fixture unexpectedly raised: {exc}")
        else:
            if findings:
                failures.append(
                    f"comment-only documentation fixture false-positived: {findings}"
                )

        bad_cases: list[tuple[str, str, str, str]] = [
            (
                "docker.sock mount",
                _CLEAN_NODE_AGENT.replace(
                    "path: /sys/fs/bpf",
                    "path: /var/run/docker.sock",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "containerd host storage",
                _CLEAN_NODE_AGENT.replace(
                    "path: /sys/fs/cgroup",
                    "path: /var/lib/containerd",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "crio socket",
                _CLEAN_NODE_AGENT,
                _CLEAN_AMBIENT.replace(
                    "path: /run/spire/sockets",
                    "path: /var/run/crio/crio.sock",
                    1,
                ),
                _CLEAN_VALUES,
            ),
            (
                "runtime.sock spelling",
                _CLEAN_NODE_AGENT.replace(
                    "mountPath: /sys/fs/bpf",
                    "mountPath: /var/run/runtime.sock",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "privileged true",
                _CLEAN_NODE_AGENT.replace("privileged: false", "privileged: true", 1),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "dynamic privileged value",
                _CLEAN_NODE_AGENT.replace(
                    "privileged: false",
                    "privileged: {{ .Values.nodeAgent.security.privileged }}",
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "inline privileged true",
                _CLEAN_NODE_AGENT.replace(
                    "securityContext:\n            privileged: false",
                    'securityContext: {"privileged": true}',
                    1,
                ),
                _CLEAN_AMBIENT,
                _CLEAN_VALUES,
            ),
            (
                "values docker socket path",
                _CLEAN_NODE_AGENT,
                _CLEAN_AMBIENT,
                _CLEAN_VALUES + "\n  extraHostPath: /var/run/docker.sock\n",
            ),
        ]
        for label, node_agent, ambient, values in bad_cases:
            bad_root = Path(tmp) / label.replace(" ", "-")
            _required_tree(
                bad_root,
                node_agent=node_agent,
                ambient=ambient,
                values=values,
            )
            try:
                findings = check_repository(bad_root)
            except Exception as exc:  # noqa: BLE001
                failures.append(f"{label}: prohibited fixture raised: {exc}")
                continue
            if not findings:
                failures.append(f"{label}: prohibited fixture was not rejected")

        renamed_surface_root = Path(tmp) / "additional-template"
        _required_tree(
            renamed_surface_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        _write(
            renamed_surface_root
            / "charts/ferrum-gateway/templates/runtime-access-daemonset.yaml",
            """\
apiVersion: apps/v1
kind: DaemonSet
spec:
  template:
    spec:
      volumes:
        - name: runtime
          hostPath:
            path: /run/containerd/containerd.sock
""",
        )
        try:
            findings = check_repository(renamed_surface_root)
        except Exception as exc:  # noqa: BLE001
            failures.append(f"additional template fixture raised: {exc}")
        else:
            if not findings:
                failures.append(
                    "additional/renamed chart template was not governed"
                )

        missing_root = Path(tmp) / "missing"
        _write(missing_root / REQUIRED_RELATIVE_PATHS[0], _CLEAN_NODE_AGENT)
        # ambient + values deliberately absent
        try:
            check_repository(missing_root)
        except FileNotFoundError:
            pass
        else:
            failures.append("missing required chart surfaces did not fail closed")

        unreadable_root = Path(tmp) / "unreadable"
        _required_tree(
            unreadable_root,
            node_agent=_CLEAN_NODE_AGENT,
            ambient=_CLEAN_AMBIENT,
            values=_CLEAN_VALUES,
        )
        target = unreadable_root / REQUIRED_RELATIVE_PATHS[0]
        target.chmod(0)
        try:
            try:
                check_repository(unreadable_root)
            except OSError:
                pass
            else:
                # Some environments (e.g. root) may still read mode 0 files.
                if target.read_text(encoding="utf-8") == _CLEAN_NODE_AGENT:
                    pass  # cannot simulate unreadable; skip assertion
                else:
                    failures.append("unreadable chart surface did not fail closed")
        finally:
            target.chmod(0o644)

    # The live repository tree must also pass (guards regressing main).
    try:
        live_findings = check_repository(default_repo_root())
    except Exception as exc:  # noqa: BLE001
        failures.append(f"repository chart scan raised: {exc}")
    else:
        if live_findings:
            failures.append(f"repository chart scan failed: {live_findings}")

    return failures


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Reject prohibited container-runtime mounts and privileged: true "
            "in Ferrum node-agent/ambient chart surfaces"
        )
    )
    parser.add_argument(
        "--root",
        type=Path,
        default=None,
        help="repository root to scan (default: ferrum-edge checkout root)",
    )
    parser.add_argument(
        "--self-test",
        action="store_true",
        help="run synthetic fixtures and scan the live chart tree",
    )
    args = parser.parse_args(argv)

    if args.self_test:
        failures = run_self_test()
        for failure in failures:
            print(f"::error::self-test: {failure}", file=sys.stderr)
        if failures:
            return 1
        print(
            "node-agent/ambient chart runtime lint self-test passed "
            "(required surfaces plus recursive chart templates/values/examples)"
        )
        return 0

    try:
        findings = check_repository(args.root)
    except (OSError, ValueError, NotADirectoryError, FileNotFoundError) as exc:
        print(f"::error::chart runtime lint failed closed: {exc}", file=sys.stderr)
        return 1

    for finding in findings:
        print(f"::error::{finding}", file=sys.stderr)
    if findings:
        return 1
    print(
        "node-agent/ambient chart runtime lint passed "
        "(required surfaces plus recursive chart templates/values/examples)"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
