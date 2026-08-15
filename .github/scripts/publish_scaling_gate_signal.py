#!/usr/bin/env python3
"""Durable signal for Scheduled Scaling Regression (issue #3892).

When the weekly scale/load matrix is red, or the last successful run on `main`
is older than the freshness ceiling, this program upserts a GitHub issue labeled
`launch-blocker` + `severity:high`. A fresh green run closes that issue as
completed. Launch-readiness therefore cannot stay green while the scaling gate
is red or stale.

The program never grants itself extra credentials: it uses the job-scoped
GITHUB_TOKEN with `issues: write` and `actions: read` only. It refuses
pull_request events and refuses to mutate issues off `refs/heads/main`.
Missing, malformed, or API-failed history is treated as stale (fail-closed).
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable


MARKER = "<!-- ferrum-scaling-gate-signal -->"
ISSUE_TITLE = "[CI] Scheduled Scaling Regression is red or stale"
ISSUE_LABELS = ("launch-blocker", "severity:high")
SIGNAL_AUTHOR = "github-actions[bot]"
ISSUE_LIST_PER_PAGE = 30
ISSUE_LIST_MAX_PAGES = 5
WORKFLOW_FILE = "scaling-regression.yml"
# Weekly cadence (7d) plus one day so Sunday–Friday freshness checks do not
# fire between a healthy Saturday run and the next scheduled window.
MAX_AGE_SECONDS = 8 * 24 * 60 * 60
MAX_RESPONSE_BYTES = 1 << 20
USER_AGENT = "ferrum-edge-scaling-gate-signal"
API_VERSION = "2022-11-28"
ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
RED_RESULTS = frozenset({"failure", "cancelled", "timed_out"})
GREEN_RESULTS = frozenset({"success"})
SKIPPED_RESULTS = frozenset({"skipped", ""})


class SignalError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Decision:
    action: str  # "open" | "close"
    reason: str
    fail_job: bool


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(value: Any, label: str = "timestamp") -> datetime:
    if not isinstance(value, str) or not ISO_Z_RE.fullmatch(value):
        raise SignalError("schema", f"malformed {label}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise SignalError("schema", f"malformed {label}") from exc
    if parsed.tzinfo is None:
        raise SignalError("schema", f"{label} missing timezone")
    return parsed.astimezone(timezone.utc)


def decide(
    job_result: str,
    last_success_age_seconds: int | None,
    history_error: str | None,
) -> Decision:
    """Pure policy. `last_success_age_seconds` is None when no success exists."""

    result = (job_result or "").strip().lower()
    if result in GREEN_RESULTS:
        return Decision("close", "scaling matrix succeeded", False)
    if result in RED_RESULTS:
        return Decision("open", f"scaling matrix result is {result}", False)
    if result not in SKIPPED_RESULTS:
        return Decision("open", f"unknown scaling job result {result!r}", True)
    if history_error:
        return Decision("open", f"scaling history unknown: {history_error}", True)
    if last_success_age_seconds is None:
        return Decision("open", "no successful scaling run on main", True)
    if last_success_age_seconds > MAX_AGE_SECONDS:
        return Decision(
            "open",
            f"last successful scaling run is {last_success_age_seconds}s old",
            True,
        )
    return Decision("close", "last successful scaling run is within freshness", False)


def issue_body(reason: str, run_url: str) -> str:
    return (
        f"{MARKER}\n"
        "The Scheduled Scaling Regression gate is red or stale. This issue is the\n"
        "durable signal so a broken 10k/30k scale lane cannot silently look launch-ready.\n"
        "\n"
        f"Reason: {reason}\n"
        f"Run: {run_url}\n"
        "\n"
        "The next successful scheduled or dispatched scaling run on `main` closes this\n"
        "issue as completed. Do not close it as not_planned while the gate is still red.\n"
    )


def require_repo(value: str) -> str:
    if not REPO_RE.fullmatch(value):
        raise SignalError("schema", "malformed GITHUB_REPOSITORY")
    return value


def api_request(
    method: str,
    url: str,
    token: str,
    body: dict[str, Any] | None = None,
) -> Any:
    data = None
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "User-Agent": USER_AGENT,
        "X-GitHub-Api-Version": API_VERSION,
    }
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    request = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            if len(raw) > MAX_RESPONSE_BYTES:
                raise SignalError("schema", "GitHub API response exceeded bound")
            if not raw:
                return None
            try:
                return json.loads(raw.decode("utf-8"))
            except (UnicodeDecodeError, json.JSONDecodeError) as exc:
                raise SignalError("schema", "malformed GitHub API JSON") from exc
    except urllib.error.HTTPError as exc:
        detail = exc.read(4096).decode("utf-8", errors="replace")
        raise SignalError("api", f"GitHub API {exc.code} for {method} {url}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise SignalError("api", f"GitHub API transport error: {exc}") from exc


def last_success_age_seconds(
    repo: str,
    token: str,
    now: datetime,
    request: Callable[[str, str, str, dict[str, Any] | None], Any] = api_request,
) -> tuple[int | None, str | None]:
    query = urllib.parse.urlencode(
        {
            "branch": "main",
            "status": "success",
            "per_page": "5",
        }
    )
    url = (
        f"https://api.github.com/repos/{repo}/actions/workflows/"
        f"{WORKFLOW_FILE}/runs?{query}"
    )
    try:
        payload = request("GET", url, token, None)
    except SignalError as exc:
        return None, f"{exc.code}: {exc.message}"
    if not isinstance(payload, dict):
        return None, "schema: workflow runs payload is not an object"
    runs = payload.get("workflow_runs")
    if not isinstance(runs, list):
        return None, "schema: workflow_runs is not a list"
    for entry in runs:
        if not isinstance(entry, dict):
            continue
        if entry.get("conclusion") != "success":
            continue
        head_branch = entry.get("head_branch")
        if head_branch not in (None, "main"):
            continue
        stamp = entry.get("updated_at") or entry.get("run_started_at") or entry.get("created_at")
        try:
            finished = parse_iso8601(stamp, "workflow run timestamp")
        except SignalError as exc:
            return None, f"{exc.code}: {exc.message}"
        age = int((now - finished).total_seconds())
        if age < 0:
            return None, "schema: workflow run timestamp is in the future"
        return age, None
    return None, None


def _issue_number(item: dict[str, Any], label: str) -> int:
    number = item.get("number")
    if not isinstance(number, int) or number <= 0:
        raise SignalError("schema", f"{label} signal issue is missing number")
    return number


def _has_exact_signal_identity(item: dict[str, Any]) -> bool:
    body = item.get("body")
    return item.get("title") == ISSUE_TITLE and isinstance(body, str) and MARKER in body


def _author_login(item: dict[str, Any]) -> str | None:
    user = item.get("user")
    if not isinstance(user, dict):
        return None
    login = user.get("login")
    return login if isinstance(login, str) else None


def require_publisher_owned_signal(item: Any, label: str) -> dict[str, Any]:
    if not isinstance(item, dict) or item == {}:
        raise SignalError("schema", f"{label} signal issue is not a durable object")
    if not _has_exact_signal_identity(item):
        raise SignalError("schema", f"{label} signal issue is missing title or marker")
    login = _author_login(item)
    if login is None:
        raise SignalError("schema", f"{label} signal issue author is malformed")
    if login != SIGNAL_AUTHOR:
        raise SignalError("schema", f"{label} signal issue is not publisher-owned")
    _issue_number(item, label)
    return item


def find_signal_issue(
    repo: str,
    token: str,
    request: Callable[[str, str, str, dict[str, Any] | None], Any] = api_request,
) -> dict[str, Any] | None:
    matches: list[dict[str, Any]] = []
    for page in range(1, ISSUE_LIST_MAX_PAGES + 1):
        query = urllib.parse.urlencode(
            {
                "state": "all",
                "labels": ",".join(ISSUE_LABELS),
                "per_page": str(ISSUE_LIST_PER_PAGE),
                "page": str(page),
            }
        )
        payload = request("GET", f"https://api.github.com/repos/{repo}/issues?{query}", token, None)
        if not isinstance(payload, list):
            raise SignalError("schema", "issue listing payload is not a list")
        if len(payload) > ISSUE_LIST_PER_PAGE:
            raise SignalError("schema", "issue listing page exceeded bound")
        for item in payload:
            if not isinstance(item, dict):
                raise SignalError("schema", "issue listing item is not an object")
            if "pull_request" in item:
                continue
            if not _has_exact_signal_identity(item):
                continue
            login = _author_login(item)
            if login is None:
                raise SignalError("schema", "signal issue author is malformed")
            if login != SIGNAL_AUTHOR:
                continue
            _issue_number(item, "existing")
            matches.append(item)
        if len(payload) < ISSUE_LIST_PER_PAGE:
            break
        if page == ISSUE_LIST_MAX_PAGES:
            raise SignalError("schema", "issue listing exceeded pagination bound")
    if len(matches) > 1:
        raise SignalError("schema", "ambiguous publisher-owned signal issues")
    if not matches:
        return None
    return matches[0]


def apply_decision(
    repo: str,
    token: str,
    decision: Decision,
    run_url: str,
    mutate: bool,
    request: Callable[[str, str, str, dict[str, Any] | None], Any] = api_request,
) -> None:
    if not mutate:
        print(f"scaling-gate-signal: {decision.action} ({decision.reason}); not mutating off main")
        return
    existing = find_signal_issue(repo, token, request)
    body = issue_body(decision.reason, run_url)
    if decision.action == "open":
        if existing is None:
            created = request(
                "POST",
                f"https://api.github.com/repos/{repo}/issues",
                token,
                {
                    "title": ISSUE_TITLE,
                    "body": body,
                    "labels": list(ISSUE_LABELS),
                },
            )
            owned = require_publisher_owned_signal(created, "created")
            print(f"scaling-gate-signal: opened issue #{owned['number']}")
            return
        number = existing.get("number")
        if not isinstance(number, int):
            raise SignalError("schema", "existing signal issue is missing number")
        patch: dict[str, Any] = {"body": body, "labels": list(ISSUE_LABELS)}
        if existing.get("state") != "open":
            patch["state"] = "open"
        request("PATCH", f"https://api.github.com/repos/{repo}/issues/{number}", token, patch)
        print(f"scaling-gate-signal: updated issue #{number}")
        return
    if existing is None or existing.get("state") != "open":
        print("scaling-gate-signal: no open signal issue to close")
        return
    number = existing.get("number")
    if not isinstance(number, int):
        raise SignalError("schema", "existing signal issue is missing number")
    request(
        "PATCH",
        f"https://api.github.com/repos/{repo}/issues/{number}",
        token,
        {
            "state": "closed",
            "state_reason": "completed",
            "body": body,
        },
    )
    print(f"scaling-gate-signal: closed issue #{number} as completed")


def run_live(now: datetime) -> int:
    event_name = os.environ.get("GITHUB_EVENT_NAME", "")
    if event_name in {"pull_request", "pull_request_target", "merge_group"}:
        print("::error::refusing to run the scaling-gate signal on a pull-request event", file=sys.stderr)
        return 1
    repo = require_repo(os.environ.get("GITHUB_REPOSITORY", ""))
    token = os.environ.get("GITHUB_TOKEN", "")
    if not token:
        raise SignalError("config", "GITHUB_TOKEN is missing")
    ref = os.environ.get("GITHUB_REF", "")
    mutate = ref == "refs/heads/main"
    job_result = os.environ.get("SCALING_JOB_RESULT", "skipped")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com").rstrip("/")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if run_id else server

    age: int | None = None
    history_error: str | None = None
    if (job_result or "").strip().lower() not in GREEN_RESULTS | RED_RESULTS:
        age, history_error = last_success_age_seconds(repo, token, now)

    decision = decide(job_result, age, history_error)
    print(f"scaling-gate-signal: {decision.action} because {decision.reason}")
    apply_decision(repo, token, decision, run_url, mutate)
    return 1 if decision.fail_job else 0


def self_test() -> int:
    failures: list[str] = []

    def expect(decision: Decision, action: str, fail_job: bool, label: str) -> None:
        if decision.action != action or decision.fail_job != fail_job:
            failures.append(
                f"{label}: expected action={action} fail_job={fail_job}, "
                f"got action={decision.action} fail_job={decision.fail_job}"
            )

    expect(decide("success", None, None), "close", False, "matrix success")
    expect(decide("failure", None, None), "open", False, "matrix failure")
    expect(decide("cancelled", 10, None), "open", False, "matrix cancelled")
    expect(decide("skipped", 60, None), "close", False, "fresh skipped")
    expect(decide("skipped", MAX_AGE_SECONDS + 1, None), "open", True, "stale skipped")
    expect(decide("skipped", None, None), "open", True, "never green")
    expect(decide("skipped", None, "api: boom"), "open", True, "history unknown")
    expect(decide("weird", 1, None), "open", True, "unknown result")

    def signal_issue(
        number: int,
        *,
        title: str = ISSUE_TITLE,
        body: str | None = None,
        state: str = "open",
        login: str = SIGNAL_AUTHOR,
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        issue: dict[str, Any] = {
            "number": number,
            "title": title,
            "body": MARKER + "\nowned" if body is None else body,
            "state": state,
            "user": {"login": login},
        }
        if extra:
            issue.update(extra)
        return issue

    def listing_request(items: list[Any]) -> Callable[[str, str, str, dict[str, Any] | None], Any]:
        def request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
            if method != "GET" or "/issues?" not in url:
                raise AssertionError(f"unexpected {method} {url}")
            if "state=all" not in url or "labels=" not in url:
                raise AssertionError(f"listing must be bounded labeled state=all: {url}")
            return items

        return request

    def expect_none(items: list[Any], label: str) -> None:
        found = find_signal_issue("ferrum-edge/ferrum-edge", "token", listing_request(items))
        if found is not None:
            failures.append(f"{label}: expected spoof to be ignored, got {found!r}")

    def expect_error(items: list[Any], label: str) -> None:
        try:
            find_signal_issue("ferrum-edge/ferrum-edge", "token", listing_request(items))
        except SignalError:
            return
        failures.append(f"{label}: expected fail-closed SignalError")

    expect_none(
        [signal_issue(7, title="unrelated spoof", body=MARKER + "\nmarker only")],
        "marker-only spoof",
    )
    expect_none(
        [signal_issue(8, body="title only, no marker")],
        "title-only spoof",
    )
    expect_none(
        [signal_issue(9, login="alice")],
        "user-authored exact-title+marker spoof",
    )
    expect_error(
        [signal_issue(11), signal_issue(12)],
        "multiple bot-owned matches",
    )

    closed = signal_issue(13, state="closed")
    found_closed = find_signal_issue(
        "ferrum-edge/ferrum-edge", "token", listing_request([closed])
    )
    if found_closed != closed:
        failures.append("closed publisher-owned signal must be selectable for reopen")

    captured: list[tuple[str, str, dict[str, Any] | None]] = []

    def fake_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        captured.append((method, url, body))
        if method == "GET" and "/issues?" in url:
            return []
        if method == "POST" and url.endswith("/issues"):
            assert body is not None
            assert body["title"] == ISSUE_TITLE
            assert body["labels"] == list(ISSUE_LABELS)
            assert MARKER in body["body"]
            return signal_issue(42, body=body["body"])
        raise AssertionError(f"unexpected {method} {url}")

    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("open", "scaling matrix result is failure", False),
        "https://github.com/ferrum-edge/ferrum-edge/actions/runs/1",
        True,
        fake_request,
    )
    if not any(method == "POST" and url.endswith("/issues") for method, url, _ in captured):
        failures.append("self-test expected issue creation on open")

    captured.clear()

    def reopen_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        captured.append((method, url, body))
        if method == "GET" and "/issues?" in url:
            return [closed]
        if method == "PATCH" and url.endswith("/issues/13"):
            assert body is not None
            assert body.get("state") == "open"
            return closed
        raise AssertionError(f"unexpected {method} {url}")

    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("open", "scaling matrix result is failure", False),
        "https://github.com/ferrum-edge/ferrum-edge/actions/runs/1",
        True,
        reopen_request,
    )
    if not any(method == "PATCH" and url.endswith("/issues/13") for method, url, _ in captured):
        failures.append("self-test expected closed publisher-owned issue to be reopened")

    def empty_create(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        if method == "GET" and "/issues?" in url:
            return []
        if method == "POST" and url.endswith("/issues"):
            return {}
        raise AssertionError(f"unexpected {method} {url}")

    try:
        apply_decision(
            "ferrum-edge/ferrum-edge",
            "token",
            Decision("open", "scaling matrix result is failure", False),
            "https://github.com/ferrum-edge/ferrum-edge/actions/runs/1",
            True,
            empty_create,
        )
        failures.append("empty create response must fail closed")
    except SignalError as exc:
        if exc.code != "schema":
            failures.append(f"empty create must fail schema-closed, got {exc.code}")

    def no_mutate_request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
        raise AssertionError("off-main must not call GitHub")

    apply_decision(
        "ferrum-edge/ferrum-edge",
        "token",
        Decision("open", "stale", True),
        "https://example.invalid",
        False,
        no_mutate_request,
    )

    body = issue_body("reason", "https://example.invalid/run")
    if MARKER not in body or "Launch Readiness Gate" in body:
        failures.append("issue body must carry the marker and must not spoof required check names")

    if MAX_AGE_SECONDS != 8 * 24 * 60 * 60:
        failures.append("freshness ceiling drifted from the weekly-plus-one-day contract")

    if failures:
        for failure in failures:
            print(f"::error::self-test: {failure}")
        return 1
    print("scaling-gate-signal self-test passed")
    return 0


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    if args.self_test:
        return self_test()
    try:
        return run_live(utc_now())
    except SignalError as exc:
        print(f"::error::{exc.code}: {exc.message}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
