#!/usr/bin/env python3
"""Durable signal for Scheduled Scaling Regression (issue #3892).

When the weekly scale/load matrix is red, or the latest scaling-regression run
on `main` is not a completed success within the freshness ceiling, this program
upserts a GitHub issue labeled `launch-blocker` + `severity:high`. The current
matrix result is authoritative for the scaling workflow itself: success closes,
failure/cancel/timeout opens. Freshness inspects the latest run on `main` and
must not treat an older success as green over a newer non-success. Only a
latest completed success within the ceiling closes the issue. Launch-readiness
therefore cannot stay green while the scaling gate is red or stale.

The program never grants itself extra credentials: it uses the job-scoped
GITHUB_TOKEN with `issues: write` and `actions: read` only. It refuses
pull_request events and refuses to mutate issues off `refs/heads/main`.
Missing, malformed, out-of-order, future-dated, or API-failed history is
treated as stale (fail-closed).
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
from datetime import datetime, timedelta, timezone
from typing import Any, Callable


MARKER = "<!-- ferrum-scaling-gate-signal -->"
ISSUE_TITLE = "[CI] Scheduled Scaling Regression is red or stale"
ISSUE_LABELS = ("launch-blocker", "severity:high")
SIGNAL_AUTHOR = "github-actions[bot]"
ISSUE_LIST_PER_PAGE = 30
ISSUE_LIST_MAX_PAGES = 5
WORKFLOW_FILE = "scaling-regression.yml"
WORKFLOW_RUN_LIST_PER_PAGE = 5
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
NON_TERMINAL_STATUSES = frozenset(
    {"queued", "in_progress", "waiting", "requested", "pending"}
)


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


@dataclass(frozen=True)
class LatestRun:
    status: str
    conclusion: str | None
    age_seconds: int


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
    latest: LatestRun | None,
    history_error: str | None,
) -> Decision:
    """Pure policy. Current matrix success/failure/cancel/timeout is authoritative.

    Freshness (`skipped`) inspects the latest scaling-regression run on `main`.
    Only a latest completed success within the ceiling may close. A newer
    non-success, in-progress, malformed, or missing history cannot be greened
    by an older success.
    """

    result = (job_result or "").strip().lower()
    if result in GREEN_RESULTS:
        return Decision("close", "scaling matrix succeeded", False)
    if result in RED_RESULTS:
        return Decision("open", f"scaling matrix result is {result}", False)
    if result not in SKIPPED_RESULTS:
        return Decision("open", f"unknown scaling job result {result!r}", True)
    if history_error:
        return Decision("open", f"scaling history unknown: {history_error}", True)
    if latest is None:
        return Decision("open", "no scaling-regression run on main", True)
    status = (latest.status or "").strip().lower()
    conclusion = (latest.conclusion or "").strip().lower()
    if status in NON_TERMINAL_STATUSES:
        return Decision("open", f"latest scaling run is {status}", True)
    if status != "completed":
        return Decision("open", f"unknown latest scaling run status {status!r}", True)
    if conclusion in GREEN_RESULTS:
        if latest.age_seconds > MAX_AGE_SECONDS:
            return Decision(
                "open",
                f"latest successful scaling run is {latest.age_seconds}s old",
                True,
            )
        return Decision("close", "latest successful scaling run is within freshness", False)
    if not conclusion:
        return Decision("open", "latest scaling run conclusion is missing", True)
    return Decision("open", f"latest scaling run conclusion is {conclusion}", True)


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


def latest_run_on_main(
    repo: str,
    token: str,
    now: datetime,
    request: Callable[[str, str, str, dict[str, Any] | None], Any] = api_request,
) -> tuple[LatestRun | None, str | None]:
    """Return the newest scaling-regression run on `main`, not the last success.

    GitHub lists workflow runs by created_at descending. Freshness must honor
    that order: a newer failure, cancel, timeout, skip, or in-progress run
    cannot be greened by an older success still inside the eight-day window.
    Out-of-order, malformed, or future-dated history fails closed.
    """

    query = urllib.parse.urlencode(
        {
            "branch": "main",
            "per_page": str(WORKFLOW_RUN_LIST_PER_PAGE),
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
    if len(runs) > WORKFLOW_RUN_LIST_PER_PAGE:
        return None, "schema: workflow runs page exceeded bound"
    if not runs:
        return None, None

    previous_created: datetime | None = None
    for entry in runs:
        if not isinstance(entry, dict):
            return None, "schema: workflow run item is not an object"
        head_branch = entry.get("head_branch")
        if head_branch not in (None, "main"):
            return None, "schema: workflow run is not on main"
        try:
            created = parse_iso8601(entry.get("created_at"), "workflow run created_at")
        except SignalError as exc:
            return None, f"{exc.code}: {exc.message}"
        if created > now:
            return None, "schema: workflow run timestamp is in the future"
        if previous_created is not None and created > previous_created:
            return None, "schema: workflow runs are out of order"
        previous_created = created

    latest_entry = runs[0]
    if not isinstance(latest_entry, dict):
        return None, "schema: workflow run item is not an object"
    stamp = (
        latest_entry.get("updated_at")
        or latest_entry.get("run_started_at")
        or latest_entry.get("created_at")
    )
    try:
        finished = parse_iso8601(stamp, "workflow run timestamp")
    except SignalError as exc:
        return None, f"{exc.code}: {exc.message}"
    if finished > now:
        return None, "schema: workflow run timestamp is in the future"
    age = int((now - finished).total_seconds())
    if age < 0:
        return None, "schema: workflow run timestamp is in the future"

    status = latest_entry.get("status")
    if not isinstance(status, str) or not status.strip():
        return None, "schema: workflow run status is malformed"
    conclusion = latest_entry.get("conclusion")
    if conclusion is not None and not isinstance(conclusion, str):
        return None, "schema: workflow run conclusion is malformed"
    normalized_conclusion = conclusion.strip().lower() if isinstance(conclusion, str) else None
    if normalized_conclusion == "":
        normalized_conclusion = None
    return (
        LatestRun(
            status=status.strip().lower(),
            conclusion=normalized_conclusion,
            age_seconds=age,
        ),
        None,
    )


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

    latest: LatestRun | None = None
    history_error: str | None = None
    if (job_result or "").strip().lower() not in GREEN_RESULTS | RED_RESULTS:
        latest, history_error = latest_run_on_main(repo, token, now)

    decision = decide(job_result, latest, history_error)
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
    expect(
        decide("cancelled", LatestRun("completed", "success", 10), None),
        "open",
        False,
        "matrix cancelled",
    )
    expect(
        decide("success", LatestRun("completed", "failure", 60), None),
        "close",
        False,
        "current success remains authoritative",
    )
    expect(
        decide("failure", LatestRun("completed", "success", 60), None),
        "open",
        False,
        "current failure remains authoritative",
    )
    expect(decide("skipped", None, None), "open", True, "never green")
    expect(decide("skipped", None, "api: boom"), "open", True, "history unknown")
    expect(decide("weird", None, None), "open", True, "unknown result")

    now = datetime(2026, 8, 15, 12, 0, 0, tzinfo=timezone.utc)

    def iso(delta: timedelta) -> str:
        return (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")

    def workflow_run(
        *,
        created: timedelta,
        status: str = "completed",
        conclusion: str | None = "success",
        head_branch: str | None = "main",
        extra: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        stamp = iso(created)
        run: dict[str, Any] = {
            "created_at": stamp,
            "updated_at": stamp,
            "status": status,
            "conclusion": conclusion,
            "head_branch": head_branch,
        }
        if extra:
            run.update(extra)
        return run

    def history_request(
        runs: list[Any],
    ) -> Callable[[str, str, str, dict[str, Any] | None], Any]:
        def request(method: str, url: str, token: str, body: dict[str, Any] | None) -> Any:
            if method != "GET" or f"/workflows/{WORKFLOW_FILE}/runs?" not in url:
                raise AssertionError(f"unexpected {method} {url}")
            if "status=success" in url:
                raise AssertionError(f"must not query only successful runs: {url}")
            if "branch=main" not in url:
                raise AssertionError(f"must query main branch runs: {url}")
            if f"per_page={WORKFLOW_RUN_LIST_PER_PAGE}" not in url:
                raise AssertionError(f"must bound workflow run pagination: {url}")
            return {"workflow_runs": runs}

        return request

    def expect_history(runs: list[Any], action: str, fail_job: bool, label: str) -> None:
        latest, err = latest_run_on_main(
            "ferrum-edge/ferrum-edge", "token", now, history_request(runs)
        )
        expect(decide("skipped", latest, err), action, fail_job, label)

    older_fresh_success = workflow_run(created=timedelta(days=7))
    expect_history(
        [
            workflow_run(created=timedelta(hours=8), conclusion="failure"),
            older_fresh_success,
        ],
        "open",
        True,
        "newer failure plus older fresh success",
    )
    expect_history(
        [
            workflow_run(
                created=timedelta(minutes=20),
                status="in_progress",
                conclusion=None,
            ),
            older_fresh_success,
        ],
        "open",
        True,
        "latest in-progress plus older success",
    )
    expect_history(
        [workflow_run(created=timedelta(days=1))],
        "close",
        False,
        "latest fresh success",
    )
    expect_history(
        [workflow_run(created=timedelta(days=9))],
        "open",
        True,
        "stale latest success",
    )
    expect_history(
        ["not-an-object", older_fresh_success],
        "open",
        True,
        "malformed latest item",
    )
    expect_history(
        [workflow_run(created=timedelta(days=-1))],
        "open",
        True,
        "future timestamp",
    )
    expect_history(
        [
            workflow_run(created=timedelta(days=7)),
            workflow_run(created=timedelta(hours=1)),
        ],
        "open",
        True,
        "out-of-order history",
    )

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
    if MARKER not in body:
        failures.append("issue body must carry the durable signal marker")

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
