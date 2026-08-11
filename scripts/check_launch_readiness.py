#!/usr/bin/env python3
"""Fail-closed launch readiness gate for PRODUCTION_READINESS.md.

Computes a live launch verdict from:
  - docs/launch-blocker-policy.json (labels, tiers, tracked inventory, state machine)
  - docs/launch-exemptions.json (structured, expiring exemptions)
  - paginated GitHub Issues + Pull Request cross-references
  - paginated repository security advisories (redacted count only)

Never executes issue/PR/advisory text. Never emits private advisory confidential
fields. Missing token, API/rate-limit/pagination/schema/staleness failures yield
UNKNOWN and a non-zero exit.

Modes:
  --self-test   deterministic fixture tests only (no network)
  --verify      live evaluation + document claim parity
  --require-pass  with --verify, also demand computed PASS (release/tag)
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
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable


ROOT = Path(__file__).resolve().parents[1]
POLICY_PATH = ROOT / "docs" / "launch-blocker-policy.json"
EXEMPTIONS_PATH = ROOT / "docs" / "launch-exemptions.json"
USER_AGENT = "ferrum-edge-launch-readiness (github.com/ferrum-edge/ferrum-edge)"
MAX_RESPONSE_BYTES = 1 << 20
MAX_PAGES = 50
SEVERITIES = ("critical", "high", "medium")
VERDICTS = ("PASS", "FAIL", "UNKNOWN")
ISSUE_STATES = (
    "open",
    "in_flight",
    "merged_awaiting_issue_close",
    "closed_completed",
    "closed_other",
    "exempted",
)

SHA_RE = re.compile(r"^[0-9a-f]{40}$")
ISO_Z_RE = re.compile(
    r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})$"
)
OWNER_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$")
REPO_RE = re.compile(r"^[\w.-]+/[\w.-]+$")
LABEL_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9:._/-]{0,63}$")


class GateError(Exception):
    """Fail-closed evaluation error that becomes UNKNOWN or hard failure."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass
class IssueRecord:
    number: int
    state: str
    state_reason: str | None
    labels: set[str]
    severity: str
    source: str
    linked_open_prs: list[int] = field(default_factory=list)
    linked_merged_prs: list[int] = field(default_factory=list)
    classification: str = "open"


@dataclass
class Evaluation:
    verdict: str
    launch_tier: str
    target_sha: str
    as_of: str
    policy_version: str
    classification_version: str
    blocking_issues: list[dict[str, Any]]
    cleared_issues: list[dict[str, Any]]
    exempted_issues: list[dict[str, Any]]
    in_flight: list[dict[str, Any]]
    counts_by_severity: dict[str, int]
    private_blocker_count: int
    unknown_reasons: list[str] = field(default_factory=list)


def utc_now() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso8601(value: str) -> datetime:
    if not isinstance(value, str) or not ISO_Z_RE.fullmatch(value):
        raise GateError("schema", "malformed timestamp")
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError as exc:
        raise GateError("schema", "malformed timestamp") from exc
    if parsed.tzinfo is None:
        raise GateError("schema", "timestamp missing timezone")
    return parsed.astimezone(timezone.utc)


def load_json_file(path: Path) -> Any:
    try:
        with path.open(encoding="utf-8") as handle:
            return json.load(handle)
    except FileNotFoundError as exc:
        raise GateError("schema", f"missing file {path.name}") from exc
    except json.JSONDecodeError as exc:
        raise GateError("schema", f"malformed JSON in {path.name}") from exc


def require_dict(value: Any, label: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise GateError("schema", f"{label} must be an object")
    return value


def require_str(value: Any, label: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise GateError("schema", f"{label} must be a non-empty string")
    return value


def require_int(value: Any, label: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise GateError("schema", f"{label} must be a positive integer")
    return value


def validate_policy(policy: dict[str, Any]) -> None:
    require_str(policy.get("policy_version"), "policy_version")
    require_str(policy.get("classification_version"), "classification_version")
    repo = require_str(policy.get("repository"), "repository")
    if not REPO_RE.fullmatch(repo):
        raise GateError("schema", "repository must be owner/name")
    labels = require_dict(policy.get("labels"), "labels")
    for key in ("launch_blocker", "launch_exempted"):
        label = require_str(labels.get(key), f"labels.{key}")
        if not LABEL_RE.fullmatch(label):
            raise GateError("schema", f"labels.{key} malformed")
    severity_labels = require_dict(labels.get("severity"), "labels.severity")
    for sev in SEVERITIES:
        label = require_str(severity_labels.get(sev), f"labels.severity.{sev}")
        if not LABEL_RE.fullmatch(label):
            raise GateError("schema", f"labels.severity.{sev} malformed")
    tiers = require_dict(policy.get("tiers"), "tiers")
    for tier_name, tier in tiers.items():
        if not isinstance(tier_name, str) or not tier_name:
            raise GateError("schema", "tier name malformed")
        tier_obj = require_dict(tier, f"tiers.{tier_name}")
        blocking = tier_obj.get("blocking_severities")
        if not isinstance(blocking, list) or not blocking:
            raise GateError("schema", f"tiers.{tier_name}.blocking_severities")
        for sev in blocking:
            if sev not in SEVERITIES:
                raise GateError("schema", f"unknown severity {sev!r}")
    default_tier = require_str(policy.get("default_launch_tier"), "default_launch_tier")
    if default_tier not in tiers:
        raise GateError("schema", "default_launch_tier missing from tiers")
    freshness = policy.get("freshness_max_age_seconds")
    if not isinstance(freshness, int) or isinstance(freshness, bool) or freshness < 1:
        raise GateError("schema", "freshness_max_age_seconds malformed")
    tracked = policy.get("tracked_blockers")
    if not isinstance(tracked, list):
        raise GateError("schema", "tracked_blockers must be a list")
    seen: set[int] = set()
    for idx, entry in enumerate(tracked):
        obj = require_dict(entry, f"tracked_blockers[{idx}]")
        number = require_int(obj.get("issue"), f"tracked_blockers[{idx}].issue")
        if number in seen:
            raise GateError("schema", f"duplicate tracked issue {number}")
        seen.add(number)
        sev = require_str(obj.get("severity"), f"tracked_blockers[{idx}].severity")
        if sev not in SEVERITIES:
            raise GateError("schema", f"tracked_blockers[{idx}].severity invalid")
        require_str(obj.get("note"), f"tracked_blockers[{idx}].note")
    private = require_dict(policy.get("private_advisories"), "private_advisories")
    if private.get("representation") != "redacted_count_only":
        raise GateError("schema", "private advisories must be redacted_count_only")
    never_emit = private.get("never_emit_fields")
    if not isinstance(never_emit, list) or "summary" not in never_emit:
        raise GateError("schema", "private never_emit_fields incomplete")
    opaque = require_dict(private.get("opaque_input"), "private_advisories.opaque_input")
    count = opaque.get("redacted_blocking_count")
    if not isinstance(count, int) or isinstance(count, bool) or count < 0:
        raise GateError("schema", "opaque redacted_blocking_count malformed")
    parse_iso8601(require_str(opaque.get("as_of"), "opaque_input.as_of"))
    max_age = opaque.get("max_age_seconds")
    if not isinstance(max_age, int) or isinstance(max_age, bool) or max_age < 1:
        raise GateError("schema", "opaque max_age_seconds malformed")
    document = require_dict(policy.get("document"), "document")
    for key in ("path", "marker_begin", "marker_end", "historical_marker"):
        require_str(document.get(key), f"document.{key}")
    require_str(policy.get("exemptions_path"), "exemptions_path")


def validate_exemptions(data: dict[str, Any], now: datetime) -> list[dict[str, Any]]:
    require_str(data.get("exemptions_version"), "exemptions_version")
    raw = data.get("exemptions")
    if not isinstance(raw, list):
        raise GateError("schema", "exemptions must be a list")
    validated: list[dict[str, Any]] = []
    seen_ids: set[str] = set()
    for idx, entry in enumerate(raw):
        obj = require_dict(entry, f"exemptions[{idx}]")
        eid = require_str(obj.get("id"), f"exemptions[{idx}].id")
        if eid in seen_ids:
            raise GateError("schema", f"duplicate exemption id {eid}")
        seen_ids.add(eid)
        issue = require_int(obj.get("issue"), f"exemptions[{idx}].issue")
        tiers = obj.get("launch_tiers")
        if not isinstance(tiers, list) or not tiers or not all(isinstance(t, str) for t in tiers):
            raise GateError("schema", f"exemptions[{idx}].launch_tiers malformed")
        for field_name in ("owner", "approver", "rationale", "compensating_control"):
            value = require_str(obj.get(field_name), f"exemptions[{idx}].{field_name}")
            if field_name in ("owner", "approver") and not OWNER_RE.fullmatch(value):
                raise GateError("schema", f"exemptions[{idx}].{field_name} malformed")
        approved_at = parse_iso8601(require_str(obj.get("approved_at"), f"exemptions[{idx}].approved_at"))
        expires_at = parse_iso8601(require_str(obj.get("expires_at"), f"exemptions[{idx}].expires_at"))
        if expires_at <= approved_at:
            raise GateError("schema", f"exemptions[{idx}] expires_at must be after approved_at")
        expired = expires_at <= now
        validated.append(
            {
                "id": eid,
                "issue": issue,
                "launch_tiers": list(tiers),
                "owner": obj["owner"],
                "approver": obj["approver"],
                "rationale": obj["rationale"],
                "compensating_control": obj["compensating_control"],
                "approved_at": obj["approved_at"],
                "expires_at": obj["expires_at"],
                "expired": expired,
            }
        )
    return validated


def github_token() -> str | None:
    token = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN")
    if token is None:
        return None
    if not isinstance(token, str) or not token.strip():
        return None
    return token.strip()


def auth_headers(token: str | None) -> dict[str, str]:
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def parse_link_next(link_header: str | None) -> str | None:
    if not link_header:
        return None
    # RFC 5988: <url>; rel="next"
    for part in link_header.split(","):
        piece = part.strip()
        if 'rel="next"' not in piece and "rel=next" not in piece:
            continue
        if piece.startswith("<") and ">" in piece:
            return piece[1 : piece.index(">")]
    return None


def http_get_json(
    url: str,
    token: str | None,
    *,
    opener: Callable[[urllib.request.Request], Any] | None = None,
) -> tuple[Any, dict[str, str]]:
    request = urllib.request.Request(url, headers=auth_headers(token))
    open_fn = opener or urllib.request.urlopen
    try:
        with open_fn(request, timeout=30) as response:
            raw = response.read(MAX_RESPONSE_BYTES + 1)
            headers = {k.lower(): v for k, v in response.headers.items()}
            status = getattr(response, "status", 200)
    except urllib.error.HTTPError as exc:
        if exc.code == 401 or exc.code == 403:
            # Distinguish rate limit when possible without echoing bodies.
            retry = exc.headers.get("Retry-After") if exc.headers else None
            remaining = exc.headers.get("X-RateLimit-Remaining") if exc.headers else None
            if remaining == "0" or retry is not None or exc.code == 403:
                raise GateError("rate_limit", f"HTTP {exc.code} rate-limit or auth denial") from exc
            raise GateError("api", f"HTTP {exc.code}") from exc
        if exc.code == 404:
            raise GateError("api", "HTTP 404") from exc
        raise GateError("api", f"HTTP {exc.code}") from exc
    except urllib.error.URLError as exc:
        raise GateError("api", f"transport failure ({type(exc).__name__})") from exc
    except GateError:
        raise
    except Exception as exc:  # noqa: BLE001 — fail closed on unexpected transport
        raise GateError("api", f"request failed ({type(exc).__name__})") from exc

    if status == 401:
        raise GateError("token", "unauthorized")
    if len(raw) > MAX_RESPONSE_BYTES:
        raise GateError("api", "response exceeded size cap")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise GateError("schema", "malformed JSON response") from exc
    return payload, headers


def paginate(
    url: str,
    token: str | None,
    *,
    opener: Callable[[urllib.request.Request], Any] | None = None,
) -> list[Any]:
    items: list[Any] = []
    next_url: str | None = url
    pages = 0
    while next_url:
        pages += 1
        if pages > MAX_PAGES:
            raise GateError("pagination", "exceeded max pages without completion")
        payload, headers = http_get_json(next_url, token, opener=opener)
        if not isinstance(payload, list):
            raise GateError("schema", "expected list page from GitHub API")
        items.extend(payload)
        next_url = parse_link_next(headers.get("link"))
        if next_url is None and len(payload) == 0 and pages == 1:
            break
    return items


def severity_from_labels(labels: set[str], policy: dict[str, Any]) -> str | None:
    severity_map = policy["labels"]["severity"]
    found: list[str] = []
    for sev, label in severity_map.items():
        if label in labels:
            found.append(sev)
    if len(found) > 1:
        raise GateError("schema", "issue has multiple severity labels")
    if not found:
        return None
    return found[0]


def classify_issue(
    record: IssueRecord,
    *,
    blocking_severities: set[str],
    exemptions: list[dict[str, Any]],
    launch_tier: str,
    policy: dict[str, Any],
) -> str:
    if record.severity not in blocking_severities:
        return "closed_completed" if record.state == "closed" else "open"

    active_exemptions = [
        ex
        for ex in exemptions
        if ex["issue"] == record.number
        and launch_tier in ex["launch_tiers"]
        and not ex["expired"]
    ]
    expired_exemptions = [
        ex
        for ex in exemptions
        if ex["issue"] == record.number
        and launch_tier in ex["launch_tiers"]
        and ex["expired"]
    ]
    if expired_exemptions and not active_exemptions and record.state != "closed":
        # Expired exemption returns the issue to the blocker set.
        pass
    if active_exemptions:
        return "exempted"

    label_exempt = policy["labels"]["launch_exempted"]
    if label_exempt in record.labels and not active_exemptions:
        # Label alone is insufficient; structured exemption required.
        raise GateError(
            "schema",
            f"issue #{record.number} has {label_exempt} without structured exemption",
        )

    if record.state == "closed":
        completed = set(policy.get("closed_completed_reasons") or [])
        if record.state_reason in completed:
            return "closed_completed"
        return "closed_other"

    if record.linked_merged_prs and not record.linked_open_prs:
        if policy.get("merged_pr_clears_blocker_before_issue_close"):
            return "closed_completed"
        return "merged_awaiting_issue_close"

    if record.linked_open_prs:
        if policy.get("in_flight_clears_blocker"):
            return "closed_completed"
        return "in_flight"

    return "open"


def issue_public_summary(record: IssueRecord) -> dict[str, Any]:
    return {
        "issue": record.number,
        "severity": record.severity,
        "classification": record.classification,
        "state_reason": record.state_reason,
        "open_prs": list(record.linked_open_prs),
        "merged_prs": list(record.linked_merged_prs),
        "source": record.source,
    }


def extract_document_claim(text: str, policy: dict[str, Any]) -> dict[str, Any]:
    begin = policy["document"]["marker_begin"]
    end = policy["document"]["marker_end"]
    if text.count(begin) != 1 or text.count(end) != 1:
        raise GateError("schema", "live readiness markers missing or duplicated")
    start = text.index(begin) + len(begin)
    stop = text.index(end)
    if stop < start:
        raise GateError("schema", "live readiness markers out of order")
    block = text[start:stop].strip()
    # Prefer fenced JSON inside the marker block.
    fence = re.search(r"```json\s*(\{.*?\})\s*```", block, re.DOTALL)
    raw = fence.group(1) if fence else block
    try:
        claim = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise GateError("schema", "live readiness claim is not valid JSON") from exc
    claim_obj = require_dict(claim, "live readiness claim")
    verdict = require_str(claim_obj.get("verdict"), "claim.verdict")
    if verdict not in VERDICTS:
        raise GateError("schema", "claim.verdict invalid")
    require_str(claim_obj.get("policy_version"), "claim.policy_version")
    require_str(claim_obj.get("classification_version"), "claim.classification_version")
    require_str(claim_obj.get("launch_tier"), "claim.launch_tier")
    return claim_obj


def assert_document_historical_separation(text: str, policy: dict[str, Any]) -> None:
    historical = policy["document"]["historical_marker"]
    if historical not in text:
        raise GateError("schema", "historical marker missing from PRODUCTION_READINESS.md")
    # Unscoped launch claims outside the live marker block are forbidden.
    begin = policy["document"]["marker_begin"]
    end = policy["document"]["marker_end"]
    live_start = text.index(begin)
    live_end = text.index(end) + len(end)
    outside = text[:live_start] + text[live_end:]
    forbidden = (
        "None blocking launch.",
        "None blocking launch",
        "0 critical/high/medium findings; regression tests added",
    )
    # Allow the forbidden phrases only after the historical marker.
    hist_idx = outside.find(historical)
    pre_hist = outside[:hist_idx]
    for phrase in forbidden:
        if phrase in pre_hist:
            raise GateError(
                "schema",
                "unscoped clean-launch claim appears outside live/historical sections",
            )


def compute_verdict(
    records: list[IssueRecord],
    *,
    private_blocker_count: int,
    unknown_reasons: list[str],
) -> str:
    if unknown_reasons:
        return "UNKNOWN"
    blocking = [
        r
        for r in records
        if r.classification
        in {"open", "in_flight", "merged_awaiting_issue_close", "closed_other"}
    ]
    if blocking or private_blocker_count > 0:
        return "FAIL"
    return "PASS"


def build_evaluation(
    *,
    policy: dict[str, Any],
    records: list[IssueRecord],
    private_blocker_count: int,
    launch_tier: str,
    target_sha: str,
    as_of: datetime,
    unknown_reasons: list[str],
) -> Evaluation:
    counts = {sev: 0 for sev in SEVERITIES}
    blocking: list[dict[str, Any]] = []
    cleared: list[dict[str, Any]] = []
    exempted: list[dict[str, Any]] = []
    in_flight: list[dict[str, Any]] = []
    for record in records:
        summary = issue_public_summary(record)
        if record.classification == "exempted":
            exempted.append(summary)
        elif record.classification == "closed_completed":
            cleared.append(summary)
        elif record.classification in {
            "open",
            "in_flight",
            "merged_awaiting_issue_close",
            "closed_other",
        }:
            blocking.append(summary)
            counts[record.severity] = counts.get(record.severity, 0) + 1
            if record.classification == "in_flight":
                in_flight.append(summary)
        else:
            cleared.append(summary)
    verdict = compute_verdict(
        records,
        private_blocker_count=private_blocker_count,
        unknown_reasons=unknown_reasons,
    )
    return Evaluation(
        verdict=verdict,
        launch_tier=launch_tier,
        target_sha=target_sha,
        as_of=as_of.strftime("%Y-%m-%dT%H:%M:%SZ"),
        policy_version=str(policy["policy_version"]),
        classification_version=str(policy["classification_version"]),
        blocking_issues=blocking,
        cleared_issues=cleared,
        exempted_issues=exempted,
        in_flight=in_flight,
        counts_by_severity=counts,
        private_blocker_count=private_blocker_count,
        unknown_reasons=list(unknown_reasons),
    )


def evaluation_public_dict(evaluation: Evaluation) -> dict[str, Any]:
    return {
        "verdict": evaluation.verdict,
        "launch_tier": evaluation.launch_tier,
        "target_sha": evaluation.target_sha,
        "as_of": evaluation.as_of,
        "policy_version": evaluation.policy_version,
        "classification_version": evaluation.classification_version,
        "counts_by_severity": evaluation.counts_by_severity,
        "blocking_issues": evaluation.blocking_issues,
        "in_flight": evaluation.in_flight,
        "exempted_issues": evaluation.exempted_issues,
        "cleared_issues": evaluation.cleared_issues,
        "private_blockers_redacted_count": evaluation.private_blocker_count,
        "unknown_reasons": evaluation.unknown_reasons,
    }


def redact_advisory(item: dict[str, Any], never_emit: set[str]) -> dict[str, Any]:
    """Keep only state/severity for policy evaluation; drop confidential fields."""
    state = item.get("state")
    severity = item.get("severity")
    if not isinstance(state, str) or not isinstance(severity, str):
        raise GateError("schema", "advisory missing state/severity")
    # Intentionally ignore every other field, including those in never_emit.
    _ = never_emit
    return {"state": state, "severity": severity}


def count_private_blockers(
    advisories: list[dict[str, Any]],
    *,
    policy: dict[str, Any],
    launch_tier: str,
) -> int:
    private = policy["private_advisories"]
    never_emit = set(private["never_emit_fields"])
    blocking_states = set(private["blocking_states"])
    severities = set(private["blocking_severities_by_tier"][launch_tier])
    count = 0
    for item in advisories:
        if not isinstance(item, dict):
            raise GateError("schema", "advisory page entry not an object")
        redacted = redact_advisory(item, never_emit)
        if redacted["state"] in blocking_states and redacted["severity"] in severities:
            count += 1
    return count


def parse_issue_payload(
    payload: dict[str, Any],
    *,
    policy: dict[str, Any],
    default_severity: str | None,
    source: str,
) -> IssueRecord:
    number = payload.get("number")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise GateError("schema", "issue number malformed")
    state = payload.get("state")
    if state not in {"open", "closed"}:
        raise GateError("schema", "issue state malformed")
    state_reason = payload.get("state_reason")
    if state_reason is not None and not isinstance(state_reason, str):
        raise GateError("schema", "issue state_reason malformed")
    label_items = payload.get("labels")
    if not isinstance(label_items, list):
        raise GateError("schema", "issue labels malformed")
    labels: set[str] = set()
    for label in label_items:
        if isinstance(label, dict):
            name = label.get("name")
        else:
            name = label
        if not isinstance(name, str) or not LABEL_RE.fullmatch(name):
            raise GateError("schema", "issue label name malformed")
        labels.add(name)
    severity = severity_from_labels(labels, policy) or default_severity
    if severity is None:
        raise GateError("schema", f"issue #{number} missing severity")
    return IssueRecord(
        number=number,
        state=state,
        state_reason=state_reason,
        labels=labels,
        severity=severity,
        source=source,
    )


def fetch_issue(
    repo: str,
    number: int,
    token: str | None,
    *,
    opener: Callable[[urllib.request.Request], Any] | None = None,
) -> dict[str, Any]:
    url = f"https://api.github.com/repos/{repo}/issues/{number}"
    payload, _headers = http_get_json(url, token, opener=opener)
    if not isinstance(payload, dict):
        raise GateError("schema", "issue payload not an object")
    # Pull requests share the issues API; reject PR nodes for tracked issues.
    if "pull_request" in payload:
        raise GateError("schema", f"tracked #{number} is a pull request, not an issue")
    return payload


def fetch_timeline_prs(
    repo: str,
    number: int,
    token: str | None,
    *,
    opener: Callable[[urllib.request.Request], Any] | None = None,
) -> tuple[list[int], list[int]]:
    """Return (open_pr_numbers, merged_pr_numbers) from timeline cross-references.

    Timeline bodies are untrusted; only numeric PR numbers and merged/state
    booleans are retained. Extra pull GETs are avoided when the timeline event
    already carries merged_at/state. HTTP 404/406/410/415 yield empty lists so a
    deprecated preview media type cannot false-clear blockers (the issue remains
    open/blocked via its primary state).
    """
    url = (
        f"https://api.github.com/repos/{repo}/issues/{number}/timeline"
        f"?per_page=100"
    )
    open_prs: list[int] = []
    merged_prs: list[int] = []
    next_url: str | None = url
    pages = 0
    while next_url:
        pages += 1
        if pages > MAX_PAGES:
            raise GateError("pagination", "timeline exceeded max pages")
        request = urllib.request.Request(
            next_url,
            headers={
                **auth_headers(token),
                "Accept": "application/vnd.github.mockingbird-preview+json",
            },
        )
        open_fn = opener or urllib.request.urlopen
        try:
            with open_fn(request, timeout=30) as response:
                raw = response.read(MAX_RESPONSE_BYTES + 1)
                headers = {k.lower(): v for k, v in response.headers.items()}
        except urllib.error.HTTPError as exc:
            if exc.code in {404, 406, 410, 415}:
                return [], []
            if exc.code in {401, 403}:
                raise GateError("rate_limit", f"HTTP {exc.code} on timeline") from exc
            raise GateError("api", f"HTTP {exc.code} on timeline") from exc
        except urllib.error.URLError as exc:
            raise GateError("api", f"timeline transport ({type(exc).__name__})") from exc
        if len(raw) > MAX_RESPONSE_BYTES:
            raise GateError("api", "timeline response exceeded size cap")
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            raise GateError("schema", "malformed timeline JSON") from exc
        if not isinstance(payload, list):
            raise GateError("schema", "timeline page must be a list")
        for event in payload:
            if not isinstance(event, dict):
                continue
            if event.get("event") != "cross-referenced":
                continue
            source = event.get("source")
            if not isinstance(source, dict):
                continue
            issue = source.get("issue")
            if not isinstance(issue, dict):
                continue
            pr = issue.get("pull_request")
            if not isinstance(pr, dict):
                continue
            pr_number = issue.get("number")
            if not isinstance(pr_number, int) or isinstance(pr_number, bool) or pr_number < 1:
                continue
            merged_at = pr.get("merged_at")
            state = issue.get("state")
            if isinstance(merged_at, str) and merged_at:
                if pr_number not in merged_prs:
                    merged_prs.append(pr_number)
            elif state == "open":
                if pr_number not in open_prs:
                    open_prs.append(pr_number)
        next_url = parse_link_next(headers.get("link"))
    # A PR number should not appear in both lists.
    open_only = [n for n in open_prs if n not in merged_prs]
    return open_only, merged_prs


def fetch_labeled_blocker_issues(
    repo: str,
    policy: dict[str, Any],
    token: str | None,
    *,
    opener: Callable[[urllib.request.Request], Any] | None = None,
) -> list[dict[str, Any]]:
    labels = policy["labels"]
    blocker = labels["launch_blocker"]
    # GitHub issues API label filter is AND for comma-separated values; query
    # once per severity label and dedupe.
    collected: dict[int, dict[str, Any]] = {}
    for sev, sev_label in labels["severity"].items():
        query = urllib.parse.urlencode(
            {
                "state": "all",
                "labels": f"{blocker},{sev_label}",
                "per_page": "100",
            }
        )
        url = f"https://api.github.com/repos/{repo}/issues?{query}"
        page_items = paginate(url, token, opener=opener)
        for item in page_items:
            if not isinstance(item, dict):
                raise GateError("schema", "issues page entry not an object")
            if "pull_request" in item:
                continue
            number = item.get("number")
            if not isinstance(number, int):
                raise GateError("schema", "labeled issue number malformed")
            collected[number] = item
            _ = sev  # severity comes from labels on the issue itself
    return list(collected.values())


def fetch_advisories(
    repo: str,
    token: str | None,
    *,
    opener: Callable[[urllib.request.Request], Any] | None = None,
) -> list[dict[str, Any]]:
    url = f"https://api.github.com/repos/{repo}/security-advisories?per_page=100"
    return [
        item
        for item in paginate(url, token, opener=opener)
        if isinstance(item, dict)
    ]


def resolve_private_blocker_count(
    *,
    policy: dict[str, Any],
    launch_tier: str,
    token: str | None,
    now: datetime,
    opener: Callable[[urllib.request.Request], Any] | None = None,
    advisory_fetcher: Callable[..., list[dict[str, Any]]] | None = None,
) -> int:
    """Return redacted private blocker count.

    Prefer live API when authorized. On 403/404, fall back to the opaque
    policy input if it is within its freshness window; otherwise UNKNOWN.
    """
    private = policy["private_advisories"]
    opaque = private["opaque_input"]
    opaque_count = int(opaque["redacted_blocking_count"])
    opaque_as_of = parse_iso8601(str(opaque["as_of"]))
    max_age = int(opaque["max_age_seconds"])
    opaque_age = (now - opaque_as_of).total_seconds()
    if opaque_age < 0:
        raise GateError("staleness", "opaque private advisory as_of is in the future")

    advisory_fetch = advisory_fetcher or fetch_advisories
    try:
        advisories = advisory_fetch(policy["repository"], token, opener=opener)
        return count_private_blockers(
            advisories, policy=policy, launch_tier=launch_tier
        )
    except GateError as exc:
        if exc.code in {"api", "rate_limit"} and (
            "HTTP 403" in exc.message
            or "HTTP 404" in exc.message
            or "rate-limit" in exc.message
        ):
            if opaque_age > max_age:
                raise GateError(
                    "staleness",
                    "private advisory opaque input expired and live API unavailable",
                ) from exc
            return opaque_count
        raise


def evaluate_live(
    *,
    policy: dict[str, Any],
    exemptions: list[dict[str, Any]],
    launch_tier: str,
    target_sha: str,
    token: str | None,
    as_of: datetime | None = None,
    opener: Callable[[urllib.request.Request], Any] | None = None,
    issue_fetcher: Callable[..., dict[str, Any]] | None = None,
    timeline_fetcher: Callable[..., tuple[list[int], list[int]]] | None = None,
    labeled_fetcher: Callable[..., list[dict[str, Any]]] | None = None,
    advisory_fetcher: Callable[..., list[dict[str, Any]]] | None = None,
) -> Evaluation:
    unknown: list[str] = []
    now = as_of or utc_now()
    if token is None:
        unknown.append("missing_token")
        return build_evaluation(
            policy=policy,
            records=[],
            private_blocker_count=0,
            launch_tier=launch_tier,
            target_sha=target_sha,
            as_of=now,
            unknown_reasons=unknown,
        )

    if launch_tier not in policy["tiers"]:
        raise GateError("schema", f"unknown launch tier {launch_tier}")
    blocking_severities = set(policy["tiers"][launch_tier]["blocking_severities"])
    repo = policy["repository"]

    issue_fetch = issue_fetcher or fetch_issue
    timeline_fetch = timeline_fetcher or fetch_timeline_prs
    labeled_fetch = labeled_fetcher or fetch_labeled_blocker_issues
    advisory_fetch = advisory_fetcher or fetch_advisories

    by_number: dict[int, IssueRecord] = {}
    try:
        for tracked in policy["tracked_blockers"]:
            number = int(tracked["issue"])
            payload = issue_fetch(repo, number, token, opener=opener)
            record = parse_issue_payload(
                payload,
                policy=policy,
                default_severity=str(tracked["severity"]),
                source="tracked",
            )
            open_prs, merged_prs = timeline_fetch(
                repo, number, token, opener=opener
            )
            record.linked_open_prs = open_prs
            record.linked_merged_prs = merged_prs
            by_number[number] = record

        for payload in labeled_fetch(repo, policy, token, opener=opener):
            number = payload.get("number")
            if not isinstance(number, int):
                raise GateError("schema", "labeled issue number malformed")
            if number in by_number:
                # Merge labels from live payload into tracked record.
                extra = parse_issue_payload(
                    payload,
                    policy=policy,
                    default_severity=by_number[number].severity,
                    source="label+tracked",
                )
                by_number[number].labels |= extra.labels
                by_number[number].source = "label+tracked"
                continue
            record = parse_issue_payload(
                payload,
                policy=policy,
                default_severity=None,
                source="label",
            )
            if policy["labels"]["launch_blocker"] not in record.labels:
                continue
            open_prs, merged_prs = timeline_fetch(
                repo, number, token, opener=opener
            )
            record.linked_open_prs = open_prs
            record.linked_merged_prs = merged_prs
            by_number[number] = record

        private_count = resolve_private_blocker_count(
            policy=policy,
            launch_tier=launch_tier,
            token=token,
            now=now,
            opener=opener,
            advisory_fetcher=advisory_fetch,
        )
    except GateError as exc:
        unknown.append(f"{exc.code}:{exc.message}")
        return build_evaluation(
            policy=policy,
            records=[],
            private_blocker_count=0,
            launch_tier=launch_tier,
            target_sha=target_sha,
            as_of=now,
            unknown_reasons=unknown,
        )

    records: list[IssueRecord] = []
    try:
        for record in sorted(by_number.values(), key=lambda r: r.number):
            if record.severity not in blocking_severities:
                # Still classify for reporting, but non-blocking severities clear.
                record.classification = "closed_completed"
                records.append(record)
                continue
            record.classification = classify_issue(
                record,
                blocking_severities=blocking_severities,
                exemptions=exemptions,
                launch_tier=launch_tier,
                policy=policy,
            )
            records.append(record)
    except GateError as exc:
        unknown.append(f"{exc.code}:{exc.message}")
        return build_evaluation(
            policy=policy,
            records=[],
            private_blocker_count=0,
            launch_tier=launch_tier,
            target_sha=target_sha,
            as_of=now,
            unknown_reasons=unknown,
        )

    # Freshness: evaluation as_of must be "now" within policy window relative to
    # the checker's clock (guards stale injected clocks in tests / callers).
    age = abs((utc_now() - now).total_seconds())
    if age > int(policy["freshness_max_age_seconds"]):
        unknown.append("staleness:evaluation clock outside freshness window")

    return build_evaluation(
        policy=policy,
        records=records,
        private_blocker_count=private_count,
        launch_tier=launch_tier,
        target_sha=target_sha,
        as_of=now,
        unknown_reasons=unknown,
    )


def verify_claim_against_evaluation(
    claim: dict[str, Any], evaluation: Evaluation
) -> list[str]:
    errors: list[str] = []
    if claim.get("verdict") != evaluation.verdict:
        errors.append(
            f"claimed verdict {claim.get('verdict')!r} != computed {evaluation.verdict!r}"
        )
    if claim.get("policy_version") != evaluation.policy_version:
        errors.append("claimed policy_version mismatch")
    if claim.get("classification_version") != evaluation.classification_version:
        errors.append("claimed classification_version mismatch")
    if claim.get("launch_tier") != evaluation.launch_tier:
        errors.append("claimed launch_tier mismatch")
    # Manual PASS cannot disagree with computed state (covered above). Also
    # reject a claimed PASS when unknown reasons exist.
    if claim.get("verdict") == "PASS" and evaluation.verdict != "PASS":
        errors.append("manual PASS disagrees with computed state")
    claimed_private = claim.get("private_blockers_redacted_count")
    if claimed_private is not None:
        if claimed_private != evaluation.private_blocker_count:
            errors.append("private redacted count mismatch")
    claimed_counts = claim.get("counts_by_severity")
    if isinstance(claimed_counts, dict):
        for sev in SEVERITIES:
            if int(claimed_counts.get(sev, 0)) != int(
                evaluation.counts_by_severity.get(sev, 0)
            ):
                errors.append(f"severity count mismatch for {sev}")
                break
    return errors


def print_safe_summary(evaluation: Evaluation) -> None:
    payload = evaluation_public_dict(evaluation)
    # Ensure no accidental advisory confidential keys.
    text = json.dumps(payload, indent=2, sort_keys=True)
    for banned in (
        "ghsa_id",
        "cve_id",
        "description",
        "html_url",
        "vulnerabilities",
    ):
        if banned in text:
            raise GateError("schema", "refusing to emit confidential advisory fields")
    print(text)


# ---------------------------------------------------------------------------
# Fixture-driven self-tests
# ---------------------------------------------------------------------------


def _base_policy() -> dict[str, Any]:
    return {
        "policy_version": "1",
        "classification_version": "launch-blocker-v1",
        "repository": "ferrum-edge/ferrum-edge",
        "default_launch_tier": "ga",
        "freshness_max_age_seconds": 3600,
        "labels": {
            "launch_blocker": "launch-blocker",
            "launch_exempted": "launch-exempted",
            "severity": {
                "critical": "severity:critical",
                "high": "severity:high",
                "medium": "severity:medium",
            },
        },
        "tiers": {
            "ga": {"blocking_severities": ["critical", "high", "medium"]},
            "beta": {"blocking_severities": ["critical", "high"]},
            "experimental": {"blocking_severities": ["critical"]},
        },
        "state_machine": {},
        "closed_completed_reasons": ["completed"],
        "closed_other_reasons": ["not_planned", "duplicate", None],
        "in_flight_clears_blocker": False,
        "merged_pr_clears_blocker_before_issue_close": False,
        "tracked_blockers": [],
        "private_advisories": {
            "enabled": True,
            "blocking_states": ["triage", "draft"],
            "closed_states": ["closed", "published", "withdrawn"],
            "blocking_severities_by_tier": {
                "ga": ["critical", "high", "medium"],
                "beta": ["critical", "high"],
                "experimental": ["critical"],
            },
            "representation": "redacted_count_only",
            "never_emit_fields": [
                "summary",
                "description",
                "ghsa_id",
                "cve_id",
                "html_url",
                "url",
                "vulnerabilities",
                "identifiers",
                "cvss",
                "cwes",
                "credits",
            ],
            "opaque_input": {
                "redacted_blocking_count": 0,
                "as_of": "2026-08-11T12:00:00Z",
                "max_age_seconds": 604800,
            },
        },
        "document": {
            "path": "PRODUCTION_READINESS.md",
            "marker_begin": "<!-- launch-readiness:begin -->",
            "marker_end": "<!-- launch-readiness:end -->",
            "historical_marker": "<!-- launch-readiness:historical -->",
        },
        "exemptions_path": "docs/launch-exemptions.json",
    }


def _issue(
    number: int,
    *,
    state: str = "open",
    state_reason: str | None = None,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "number": number,
        "state": state,
        "state_reason": state_reason,
        "labels": [{"name": name} for name in (labels or [])],
    }


class _FixtureOpener:
    """Minimal urlopen stand-in; self-tests prefer explicit fetch hooks."""

    def __init__(self, mapping: dict[str, Any]):
        self.mapping = mapping

    def __call__(self, request: urllib.request.Request, timeout: int = 30):  # noqa: ARG002
        raise AssertionError(f"unexpected URL fetch in fixture test: {request.full_url}")


def run_self_test() -> int:
    failures: list[str] = []

    def check(name: str, cond: bool, detail: str = "") -> None:
        if not cond:
            failures.append(f"{name}: {detail}" if detail else name)

    policy = _base_policy()
    try:
        validate_policy(policy)
        check("policy validates", True)
    except GateError as exc:
        check("policy validates", False, exc.message)

    # Expired / malformed exemptions rejected.
    now = datetime(2026, 8, 11, tzinfo=timezone.utc)
    try:
        validate_exemptions(
            {
                "exemptions_version": "1",
                "exemptions": [
                    {
                        "id": "ex-bad",
                        "issue": 1,
                        "launch_tiers": ["ga"],
                        "owner": "owner1",
                        "approver": "owner1",
                        "rationale": "r",
                        "compensating_control": "c",
                        "approved_at": "2026-01-01T00:00:00Z",
                        "expires_at": "2026-01-01T00:00:00Z",
                    }
                ],
            },
            now,
        )
        check("reject equal expiry", False, "expected schema error")
    except GateError:
        check("reject equal expiry", True)

    try:
        validate_exemptions(
            {
                "exemptions_version": "1",
                "exemptions": [
                    {
                        "id": "ex-malformed",
                        "issue": "x",
                        "launch_tiers": ["ga"],
                        "owner": "owner1",
                        "approver": "owner1",
                        "rationale": "r",
                        "compensating_control": "c",
                        "approved_at": "2026-01-01T00:00:00Z",
                        "expires_at": "2026-12-01T00:00:00Z",
                    }
                ],
            },
            now,
        )
        check("reject malformed exemption issue", False)
    except GateError:
        check("reject malformed exemption issue", True)

    expired = validate_exemptions(
        {
            "exemptions_version": "1",
            "exemptions": [
                {
                    "id": "ex-old",
                    "issue": 99,
                    "launch_tiers": ["ga"],
                    "owner": "owner1",
                    "approver": "approver1",
                    "rationale": "temporary",
                    "compensating_control": "feature flag off",
                    "approved_at": "2026-01-01T00:00:00Z",
                    "expires_at": "2026-02-01T00:00:00Z",
                }
            ],
        },
        now,
    )
    check("expired exemption marked", expired[0]["expired"] is True)

    # Synthetic critical + launch-blocker => FAIL.
    def issue_fetch_factory(payloads: dict[int, dict[str, Any]]):
        def _fetch(repo: str, number: int, token: str | None, opener=None):  # noqa: ARG001
            if number not in payloads:
                raise GateError("api", "HTTP 404")
            return payloads[number]

        return _fetch

    def timeline_factory(mapping: dict[int, tuple[list[int], list[int]]]):
        def _fetch(repo: str, number: int, token: str | None, opener=None):  # noqa: ARG001
            return mapping.get(number, ([], []))

        return _fetch

    critical_open = {
        1001: _issue(
            1001,
            labels=["launch-blocker", "severity:critical"],
        )
    }
    policy_tracked = _base_policy()
    policy_tracked["tracked_blockers"] = [
        {"issue": 1001, "severity": "critical", "note": "fixture"}
    ]
    evaluation = evaluate_live(
        policy=policy_tracked,
        exemptions=[],
        launch_tier="ga",
        target_sha="a" * 40,
        token="dummy",
        as_of=now,
        opener=_FixtureOpener({}),
        issue_fetcher=issue_fetch_factory(critical_open),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("critical open => FAIL", evaluation.verdict == "FAIL", evaluation.verdict)
    check("critical counted", evaluation.counts_by_severity["critical"] == 1)

    # Every configured severity/tier blocks appropriately.
    for sev in SEVERITIES:
        payloads = {
            2000: _issue(2000, labels=["launch-blocker", f"severity:{sev}"])
        }
        pol = _base_policy()
        pol["tracked_blockers"] = [{"issue": 2000, "severity": sev, "note": "n"}]
        ev = evaluate_live(
            policy=pol,
            exemptions=[],
            launch_tier="ga",
            target_sha="b" * 40,
            token="dummy",
            as_of=now,
            issue_fetcher=issue_fetch_factory(payloads),
            timeline_fetcher=timeline_factory({}),
            labeled_fetcher=lambda *a, **k: [],
            advisory_fetcher=lambda *a, **k: [],
        )
        check(f"ga blocks {sev}", ev.verdict == "FAIL", ev.verdict)

    # Medium does not block experimental.
    payloads = {
        2001: _issue(2001, labels=["launch-blocker", "severity:medium"])
    }
    pol = _base_policy()
    pol["tracked_blockers"] = [{"issue": 2001, "severity": "medium", "note": "n"}]
    ev = evaluate_live(
        policy=pol,
        exemptions=[],
        launch_tier="experimental",
        target_sha="c" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory(payloads),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("experimental ignores medium", ev.verdict == "PASS", ev.verdict)

    # In-flight open PR does not clear.
    payloads = {
        3001: _issue(3001, labels=["launch-blocker", "severity:high"])
    }
    pol = _base_policy()
    pol["tracked_blockers"] = [{"issue": 3001, "severity": "high", "note": "n"}]
    ev = evaluate_live(
        policy=pol,
        exemptions=[],
        launch_tier="ga",
        target_sha="d" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory(payloads),
        timeline_fetcher=timeline_factory({3001: ([555], [])}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("in_flight still FAIL", ev.verdict == "FAIL", ev.verdict)
    check(
        "in_flight classification",
        ev.blocking_issues
        and ev.blocking_issues[0]["classification"] == "in_flight",
        str(ev.blocking_issues),
    )

    # Merged PR without issue close still blocks.
    ev = evaluate_live(
        policy=pol,
        exemptions=[],
        launch_tier="ga",
        target_sha="e" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory(payloads),
        timeline_fetcher=timeline_factory({3001: ([], [556])}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check(
        "merged awaiting close blocks",
        ev.blocking_issues
        and ev.blocking_issues[0]["classification"] == "merged_awaiting_issue_close",
        str(ev.blocking_issues),
    )

    # Closed completed clears.
    payloads = {
        4001: _issue(
            4001,
            state="closed",
            state_reason="completed",
            labels=["launch-blocker", "severity:high"],
        )
    }
    pol = _base_policy()
    pol["tracked_blockers"] = [{"issue": 4001, "severity": "high", "note": "n"}]
    ev = evaluate_live(
        policy=pol,
        exemptions=[],
        launch_tier="ga",
        target_sha="f" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory(payloads),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("closed completed => PASS", ev.verdict == "PASS", ev.verdict)

    # duplicate / not_planned do not clear.
    for reason in ("duplicate", "not_planned", None):
        payloads = {
            4002: _issue(
                4002,
                state="closed",
                state_reason=reason,
                labels=["launch-blocker", "severity:high"],
            )
        }
        pol = _base_policy()
        pol["tracked_blockers"] = [{"issue": 4002, "severity": "high", "note": "n"}]
        ev = evaluate_live(
            policy=pol,
            exemptions=[],
            launch_tier="ga",
            target_sha="1" * 40,
            token="dummy",
            as_of=now,
            issue_fetcher=issue_fetch_factory(payloads),
            timeline_fetcher=timeline_factory({}),
            labeled_fetcher=lambda *a, **k: [],
            advisory_fetcher=lambda *a, **k: [],
        )
        check(
            f"closed_other {reason!r} blocks",
            ev.verdict == "FAIL"
            and ev.blocking_issues
            and ev.blocking_issues[0]["classification"] == "closed_other",
            str(ev.verdict),
        )

    # Valid exemption clears; expired returns to blocker set.
    payloads = {
        5001: _issue(5001, labels=["launch-blocker", "severity:high"])
    }
    pol = _base_policy()
    pol["tracked_blockers"] = [{"issue": 5001, "severity": "high", "note": "n"}]
    valid_ex = [
        {
            "id": "ex-ok",
            "issue": 5001,
            "launch_tiers": ["ga"],
            "owner": "owner1",
            "approver": "approver1",
            "rationale": "beta only path disabled",
            "compensating_control": "feature flag",
            "approved_at": "2026-08-01T00:00:00Z",
            "expires_at": "2026-12-01T00:00:00Z",
            "expired": False,
        }
    ]
    ev = evaluate_live(
        policy=pol,
        exemptions=valid_ex,
        launch_tier="ga",
        target_sha="2" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory(payloads),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("valid exemption => PASS", ev.verdict == "PASS", ev.verdict)
    check("exempted reported", len(ev.exempted_issues) == 1)

    expired_ex = [{**valid_ex[0], "expires_at": "2026-08-01T00:00:00Z", "expired": True}]
    ev = evaluate_live(
        policy=pol,
        exemptions=expired_ex,
        launch_tier="ga",
        target_sha="3" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory(payloads),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("expired exemption => FAIL", ev.verdict == "FAIL", ev.verdict)

    # Missing token => UNKNOWN.
    ev = evaluate_live(
        policy=_base_policy(),
        exemptions=[],
        launch_tier="ga",
        target_sha="4" * 40,
        token=None,
        as_of=now,
    )
    check("missing token UNKNOWN", ev.verdict == "UNKNOWN", ev.verdict)

    # API failure => UNKNOWN.
    def boom(*a, **k):
        raise GateError("api", "HTTP 500")

    ev = evaluate_live(
        policy=policy_tracked,
        exemptions=[],
        launch_tier="ga",
        target_sha="5" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=boom,
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("api failure UNKNOWN", ev.verdict == "UNKNOWN", ev.verdict)

    # Rate limit => UNKNOWN.
    def rate_limited(*a, **k):
        raise GateError("rate_limit", "HTTP 403 rate-limit or auth denial")

    ev = evaluate_live(
        policy=policy_tracked,
        exemptions=[],
        launch_tier="ga",
        target_sha="6" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=rate_limited,
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("rate limit UNKNOWN", ev.verdict == "UNKNOWN", ev.verdict)

    # Pagination helper must walk Link: rel=next and not drop pages.
    pages = {
        "https://example.test/items?page=1": (
            [{"n": 1}, {"n": 2}],
            {"link": '<https://example.test/items?page=2>; rel="next"'},
        ),
        "https://example.test/items?page=2": (
            [{"n": 3}],
            {},
        ),
    }

    class PageOpener:
        def __call__(self, request: urllib.request.Request, timeout: int = 30):  # noqa: ARG002
            url = request.full_url
            if url not in pages:
                raise AssertionError(url)

            class Resp:
                def __init__(self):
                    body, hdrs = pages[url]
                    self._body = json.dumps(body).encode()
                    self.headers = hdrs
                    self.status = 200

                def read(self, n: int = -1):
                    return self._body if n < 0 else self._body[:n]

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return Resp()

    items = paginate("https://example.test/items?page=1", "tok", opener=PageOpener())
    check("pagination aggregates pages", [i["n"] for i in items] == [1, 2, 3])

    # Schema mismatch on list page => GateError.
    class BadPage:
        def __call__(self, request: urllib.request.Request, timeout: int = 30):  # noqa: ARG002
            class Resp:
                status = 200
                headers = {}

                def read(self, n: int = -1):
                    data = b'{"not":"list"}'
                    return data if n < 0 else data[:n]

                def __enter__(self):
                    return self

                def __exit__(self, *a):
                    return False

            return Resp()

    try:
        paginate("https://example.test/bad", "tok", opener=BadPage())
        check("schema mismatch list", False)
    except GateError as exc:
        check("schema mismatch list", exc.code == "schema", exc.message)

    # Private advisory: redacted count only; confidential fields never emitted.
    advisories = [
        {
            "ghsa_id": "GHSA-SECRET-SHOULD-NOT-APPEAR",
            "summary": "confidential summary",
            "description": "confidential description",
            "state": "draft",
            "severity": "high",
            "html_url": "https://example.invalid/secret",
        },
        {
            "ghsa_id": "GHSA-CLOSED",
            "summary": "closed",
            "state": "closed",
            "severity": "critical",
        },
    ]
    count = count_private_blockers(
        advisories, policy=_base_policy(), launch_tier="ga"
    )
    check("private draft counts", count == 1)
    ev = evaluate_live(
        policy=_base_policy(),
        exemptions=[],
        launch_tier="ga",
        target_sha="7" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory({}),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: advisories,
    )
    check("private blockers cause FAIL", ev.verdict == "FAIL", ev.verdict)
    check("private redacted count", ev.private_blocker_count == 1)
    private_fail_ev = ev

    # Opaque fallback when live advisory API is forbidden.
    def forbid_advisories(*a, **k):
        raise GateError("api", "HTTP 403")

    ev = evaluate_live(
        policy=_base_policy(),
        exemptions=[],
        launch_tier="ga",
        target_sha="9" * 40,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory({}),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=forbid_advisories,
    )
    check("opaque fallback PASS", ev.verdict == "PASS", ev.verdict)
    check("opaque fallback count 0", ev.private_blocker_count == 0)

    stale_pol = _base_policy()
    stale_pol["private_advisories"]["opaque_input"]["as_of"] = "2020-01-01T00:00:00Z"
    ev = evaluate_live(
        policy=stale_pol,
        exemptions=[],
        launch_tier="ga",
        target_sha="a1" * 20,
        token="dummy",
        as_of=now,
        issue_fetcher=issue_fetch_factory({}),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=forbid_advisories,
    )
    check("stale opaque UNKNOWN", ev.verdict == "UNKNOWN", ev.verdict)
    try:
        print_safe_summary(private_fail_ev)
    except GateError:
        check("summary redaction", False, "print_safe_summary raised")
    else:
        public = evaluation_public_dict(private_fail_ev)
        dumped = json.dumps(public)
        check("no ghsa in public dict", "GHSA-" not in dumped)
        check("no summary in public dict", "confidential" not in dumped)

    # Manual PASS disagrees with computed FAIL.
    claim = {
        "verdict": "PASS",
        "policy_version": "1",
        "classification_version": "launch-blocker-v1",
        "launch_tier": "ga",
        "private_blockers_redacted_count": 0,
        "counts_by_severity": {"critical": 0, "high": 0, "medium": 0},
    }
    errs = verify_claim_against_evaluation(claim, evaluation)
    check("manual PASS rejected", any("disagrees" in e or "!=" in e for e in errs), str(errs))

    # Document marker extraction + historical separation.
    doc = (
        "# Title\n\n"
        "## Live launch gate\n"
        "<!-- launch-readiness:begin -->\n"
        "```json\n"
        + json.dumps(
            {
                "verdict": "FAIL",
                "policy_version": "1",
                "classification_version": "launch-blocker-v1",
                "launch_tier": "ga",
                "private_blockers_redacted_count": 0,
                "counts_by_severity": {"critical": 1, "high": 0, "medium": 0},
            }
        )
        + "\n```\n"
        "<!-- launch-readiness:end -->\n\n"
        "<!-- launch-readiness:historical -->\n"
        "Historical static audit run found 0 critical/high/medium findings.\n"
    )
    claim = extract_document_claim(doc, _base_policy())
    check("extract claim verdict", claim["verdict"] == "FAIL")
    try:
        assert_document_historical_separation(doc, _base_policy())
        check("historical separation ok", True)
    except GateError as exc:
        check("historical separation ok", False, exc.message)

    bad_doc = (
        "None blocking launch.\n"
        "<!-- launch-readiness:begin -->\n"
        '{"verdict":"FAIL","policy_version":"1","classification_version":"launch-blocker-v1","launch_tier":"ga"}\n'
        "<!-- launch-readiness:end -->\n"
        "<!-- launch-readiness:historical -->\n"
    )
    try:
        assert_document_historical_separation(bad_doc, _base_policy())
        check("reject unscoped claim", False)
    except GateError:
        check("reject unscoped claim", True)

    # Staleness window.
    old = datetime(2020, 1, 1, tzinfo=timezone.utc)
    ev = evaluate_live(
        policy=_base_policy(),
        exemptions=[],
        launch_tier="ga",
        target_sha="8" * 40,
        token="dummy",
        as_of=old,
        issue_fetcher=issue_fetch_factory({}),
        timeline_fetcher=timeline_factory({}),
        labeled_fetcher=lambda *a, **k: [],
        advisory_fetcher=lambda *a, **k: [],
    )
    check("stale clock UNKNOWN", ev.verdict == "UNKNOWN", ev.verdict)

    # Checked-in policy/exemptions/docs load.
    try:
        repo_policy = load_json_file(POLICY_PATH)
        validate_policy(require_dict(repo_policy, "repo policy"))
        check("repo policy loads", True)
    except GateError as exc:
        check("repo policy loads", False, exc.message)
    try:
        repo_ex = load_json_file(EXEMPTIONS_PATH)
        validate_exemptions(require_dict(repo_ex, "repo exemptions"), utc_now())
        check("repo exemptions load", True)
    except GateError as exc:
        check("repo exemptions load", False, exc.message)

    if failures:
        print("SELF-TEST FAILURES:", file=sys.stderr)
        for item in failures:
            # Avoid workflow-command injection from fixture names.
            safe = item.replace("\n", " ").replace("::", ":")
            print(f"- {safe}", file=sys.stderr)
        return 1
    print("launch-readiness self-test: PASS")
    return 0


def run_verify(args: argparse.Namespace) -> int:
    if not SHA_RE.fullmatch(args.target_sha):
        print("error: --target-sha must be a 40-char lowercase hex commit", file=sys.stderr)
        return 1
    try:
        policy = require_dict(load_json_file(POLICY_PATH), "policy")
        validate_policy(policy)
        exemptions_raw = require_dict(load_json_file(EXEMPTIONS_PATH), "exemptions")
        exemptions = validate_exemptions(exemptions_raw, utc_now())
        # Expired exemptions remain listed but marked expired; classify_issue
        # ignores them. Malformed already rejected.
        doc_path = ROOT / policy["document"]["path"]
        document = doc_path.read_text(encoding="utf-8")
        assert_document_historical_separation(document, policy)
        claim = extract_document_claim(document, policy)
    except GateError as exc:
        print(f"error: {exc.code}: {exc.message}", file=sys.stderr)
        return 1

    token = github_token()
    evaluation = evaluate_live(
        policy=policy,
        exemptions=exemptions,
        launch_tier=args.launch_tier,
        target_sha=args.target_sha,
        token=token,
    )
    print_safe_summary(evaluation)

    errors = verify_claim_against_evaluation(claim, evaluation)
    if evaluation.verdict == "UNKNOWN":
        errors.append("computed verdict is UNKNOWN (fail closed)")
    if args.require_pass and evaluation.verdict != "PASS":
        errors.append(
            f"release/tag requires PASS, computed {evaluation.verdict}"
        )
    if errors:
        for err in errors:
            safe = err.replace("\n", " ").replace("::", ":")
            print(f"error: {safe}", file=sys.stderr)
        return 1
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--require-pass", action="store_true")
    parser.add_argument("--launch-tier", default="ga")
    parser.add_argument("--target-sha", default="")
    args = parser.parse_args(argv)

    if args.self_test and args.verify:
        print("error: choose one of --self-test or --verify", file=sys.stderr)
        return 1
    if args.self_test:
        return run_self_test()
    if args.verify:
        if not args.target_sha:
            print("error: --verify requires --target-sha", file=sys.stderr)
            return 1
        return run_verify(args)
    print("error: specify --self-test or --verify", file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
