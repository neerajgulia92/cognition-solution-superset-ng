# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""Tests for the Devin security remediation automation.

These live next to the scripts rather than under ``tests/unit_tests`` because
the scripts are standalone modules (they run on a bare Actions runner with no
install step) whose names would collide with modules of the same name inside
the Superset test suite.
"""

# The automation scripts deliberately avoid Superset imports so they can run
# on a bare Actions runner; the tests stay standard library only for the same
# reason, hence stdlib json rather than superset.utils.json.
import json  # noqa: TID251
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import pytest

SCRIPTS = Path(__file__).parent.parent
sys.path.insert(0, str(SCRIPTS))

import common  # noqa: E402
import dispatch  # noqa: E402
import merge  # noqa: E402
import metrics  # noqa: E402
import poll  # noqa: E402
import scan  # noqa: E402
import sync_issues  # noqa: E402
import verify  # noqa: E402


class _AnyTime:
    """Matches any timestamp, so assertions can compare whole payloads."""

    def __eq__(self, other: object) -> bool:
        return isinstance(other, str)

    def __repr__(self) -> str:
        return "<any timestamp>"


ANY_TIME = _AnyTime()


def test_markers_round_trip() -> None:
    body = "\n".join(
        [
            common.marker(common.FINGERPRINT_PREFIX, "osv:flask:2.3.3"),
            common.marker(common.FINGERPRINT_PREFIX, "npm:dompurify"),
            "## Finding",
        ]
    )
    assert common.find_marker(body, common.FINGERPRINT_PREFIX) == "osv:flask:2.3.3"
    assert common.find_markers(body, common.FINGERPRINT_PREFIX) == [
        "osv:flask:2.3.3",
        "npm:dompurify",
    ]
    assert common.find_markers(body, common.SESSION_MARKER_PREFIX) == []


def test_find_marker_ignores_unterminated_marker() -> None:
    assert common.find_marker("<!-- sec-fp: osv:flask:2.3.3", "sec-fp") is None


def test_require_https_rejects_other_schemes() -> None:
    assert common.require_https("https://api.github.com") == "https://api.github.com"
    for url in ("http://api.github.com", "file:///etc/passwd"):
        with pytest.raises(ValueError, match="non-HTTPS"):
            common.require_https(url)


def test_parse_requirements_reads_exact_pins(tmp_path: Path) -> None:
    path = tmp_path / "base.txt"
    path.write_text(
        "\n".join(
            [
                "# comment",
                "Flask==2.3.3",
                "celery[redis]==5.5.3",
                "paramiko==3.5.1 ; python_version >= '3.10'",
                "-r other.txt",
                "unpinned>=1.0",
                "",
            ]
        )
    )
    assert scan.parse_requirements(str(path)) == {
        "flask": "2.3.3",
        "celery": "5.5.3",
        "paramiko": "3.5.1",
    }


def test_normalise_severity_collapses_bandit_medium() -> None:
    assert scan.normalise_severity("MEDIUM") == "MODERATE"
    assert scan.normalise_severity("high") == "HIGH"
    assert scan.normalise_severity("") == ""


def test_scan_npm_skips_low_severity_and_chain_links(tmp_path: Path) -> None:
    audit = {
        "vulnerabilities": {
            "dompurify": {
                "severity": "moderate",
                "isDirect": True,
                "via": [
                    {
                        "source": 1,
                        "url": "https://github.com/advisories/GHSA-x",
                        "title": "XSS",
                        "severity": "moderate",
                    }
                ],
                "fixAvailable": {"name": "dompurify", "version": "3.2.4"},
            },
            "chain-link": {
                "severity": "high",
                "isDirect": False,
                "via": ["dompurify"],
            },
            "noise": {"severity": "low", "isDirect": True, "via": []},
        }
    }
    path = tmp_path / "npm-audit.json"
    path.write_text(json.dumps(audit))

    findings = scan.scan_npm(str(path))
    assert [f["fingerprint"] for f in findings] == ["npm:dompurify"]
    assert findings[0]["severity"] == "MODERATE"


def test_scan_bandit_groups_selected_rules_only(tmp_path: Path) -> None:
    report = {
        "results": [
            {
                "test_id": "B324",
                "test_name": "hashlib",
                "issue_text": "weak MD5",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "superset/a.py",
                "line_number": 1,
            },
            {
                "test_id": "B324",
                "test_name": "hashlib",
                "issue_text": "weak MD5",
                "issue_severity": "HIGH",
                "issue_confidence": "HIGH",
                "filename": "superset/b.py",
                "line_number": 2,
            },
            {
                "test_id": "B101",
                "test_name": "assert_used",
                "issue_text": "assert",
                "issue_severity": "LOW",
                "issue_confidence": "HIGH",
                "filename": "superset/c.py",
                "line_number": 3,
            },
        ]
    }
    path = tmp_path / "bandit.json"
    path.write_text(json.dumps(report))

    findings = scan.scan_bandit(str(path))
    assert [f["fingerprint"] for f in findings] == ["bandit:B324"]
    assert len(findings[0]["locations"]) == 2


def test_render_body_is_stable_and_marked() -> None:
    finding: dict[str, Any] = {
        "source": "osv",
        "fingerprint": "osv:flask:2.3.3",
        "severity": "LOW",
        "package": "flask",
        "version": "2.3.3",
        "scopes": ["base"],
        "advisories": [
            {
                "id": "GHSA-1",
                "cves": ["CVE-1"],
                "severity": "LOW",
                "summary": "bad | thing",
                "fixed_versions": ["2.3.4"],
            }
        ],
        "title": "[Security] flask 2.3.3 has known vulnerabilities",
    }
    body = sync_issues.render_body(finding)
    assert body == sync_issues.render_body(finding)
    assert sync_issues.MANAGED_MARKER in body
    assert common.find_marker(body, common.FINGERPRINT_PREFIX) == "osv:flask:2.3.3"
    # Pipes in advisory text must not break the markdown table.
    assert "bad \\| thing" in body


class FakeGitHub:
    """In-memory stand-in for the subset of the GitHub API the scripts use."""

    def __init__(self, issues: list[dict[str, Any]]) -> None:
        self.repo = "acme/superset-ng"
        self.issues = issues
        self.comments_by_issue: dict[int, list[dict[str, Any]]] = {}
        self.created: list[dict[str, Any]] = []
        self.added_labels: list[tuple[int, list[str]]] = []
        self.removed_labels: list[tuple[int, str]] = []
        self.updates: list[tuple[int, dict[str, Any]]] = []
        self.edited_comments: list[tuple[int, str]] = []
        self.events_by_issue: dict[int, list[dict[str, Any]]] = {}
        self.pull_requests: dict[int, dict[str, Any]] = {}
        self.checks_by_sha: dict[str, list[dict[str, Any]]] = {}
        self.statuses_by_sha: dict[str, list[dict[str, Any]]] = {}
        self.merged: list[int] = []

    def ensure_labels(self) -> None:
        pass

    def open_issues(self, labels: str | None = None) -> list[dict[str, Any]]:
        if labels is None:
            return self.issues
        return [
            issue
            for issue in self.issues
            if labels in {label["name"] for label in issue["labels"]}
        ]

    def get_issue(self, number: int) -> dict[str, Any]:
        return next(issue for issue in self.issues if issue["number"] == number)

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        issue = {
            "number": 1000 + len(self.created),
            "title": title,
            "body": body,
            "labels": [{"name": label} for label in labels],
        }
        self.created.append(issue)
        self.issues.append(issue)
        return issue

    def update_issue(self, number: int, **fields: Any) -> dict[str, Any]:
        self.updates.append((number, fields))
        return self.get_issue(number)

    def comments(self, number: int) -> list[dict[str, Any]]:
        return self.comments_by_issue.get(number, [])

    def events(self, number: int) -> list[dict[str, Any]]:
        return self.events_by_issue.get(number, [])

    def pull_request(self, number: int) -> dict[str, Any]:
        return self.pull_requests[number]

    def check_runs(self, ref: str) -> list[dict[str, Any]]:
        return self.checks_by_sha.get(ref, [])

    def combined_status(self, ref: str) -> dict[str, Any]:
        return {"statuses": self.statuses_by_sha.get(ref, [])}

    def merge_pull_request(
        self, number: int, method: str = "squash", title: str | None = None
    ) -> dict[str, Any]:
        self.merged.append(number)
        self.pull_requests[number]["merged_at"] = "2026-08-02T04:00:00Z"
        return {"merged": True}

    def comment(self, number: int, body: str) -> dict[str, Any]:
        entry = {"id": len(self.comments_by_issue.get(number, [])), "body": body}
        self.comments_by_issue.setdefault(number, []).append(entry)
        return entry

    def edit_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        self.edited_comments.append((comment_id, body))
        return {"id": comment_id, "body": body}

    def add_labels(self, number: int, labels: list[str]) -> None:
        self.added_labels.append((number, labels))
        issue = self.get_issue(number)
        names = {label["name"] for label in issue["labels"]}
        issue["labels"] = [{"name": name} for name in names | set(labels)]

    def remove_label(self, number: int, label: str) -> None:
        self.removed_labels.append((number, label))


class FakeDevin:
    def __init__(self, session: dict[str, Any] | None = None) -> None:
        self.created: list[dict[str, Any]] = []
        self.session = session or {}

    def create_session(self, **kwargs: Any) -> dict[str, Any]:
        self.created.append(kwargs)
        session_id = f"devin-{len(self.created)}"
        return {"session_id": session_id, "url": f"https://app.devin.ai/{session_id}"}

    def get_session(self, session_id: str) -> dict[str, Any]:
        return self.session


def _finding(fingerprint: str) -> dict[str, Any]:
    return {
        "source": "osv",
        "fingerprint": fingerprint,
        "severity": "HIGH",
        "package": fingerprint.split(":")[1],
        "version": "1.0.0",
        "title": f"[Security] {fingerprint}",
    }


def test_index_by_fingerprint_covers_multi_fingerprint_issues() -> None:
    body = "\n".join(
        [
            common.marker(common.FINGERPRINT_PREFIX, "osv:pip:25.1.1"),
            common.marker(common.FINGERPRINT_PREFIX, "osv:pytest:7.4.4"),
        ]
    )
    github = FakeGitHub(
        [{"number": 5, "title": "dev deps", "body": body, "labels": []}]
    )
    index = sync_issues.index_by_fingerprint(github)
    assert set(index) == {"osv:pip:25.1.1", "osv:pytest:7.4.4"}
    assert index["osv:pip:25.1.1"]["number"] == 5


def test_close_resolved_keeps_issues_with_a_live_fingerprint() -> None:
    grouped = {
        "number": 5,
        "title": "dev deps",
        "body": "",
        "labels": [{"name": common.LABEL_AUTOMATED}],
    }
    handwritten = {"number": 6, "title": "manual", "body": "", "labels": []}
    existing = {
        "osv:pip:25.1.1": grouped,
        "osv:pytest:7.4.4": grouped,
        "osv:flask:2.3.3": handwritten,
    }
    github = FakeGitHub([grouped, handwritten])

    # One of the grouped fingerprints still reproduces: nothing closes.
    closed = sync_issues.close_resolved(
        github, existing, [_finding("osv:pip:25.1.1")], dry_run=False
    )
    assert closed == []

    # Nothing reproduces: only the automated issue closes.
    closed = sync_issues.close_resolved(github, existing, [], dry_run=False)
    assert closed == [(5, "dev deps")]
    assert (5, {"state": "closed"}) in github.updates


def test_queue_untriaged_drip_feeds_the_oldest_untouched_findings() -> None:
    def issue(number: int, labels: list[str]) -> dict[str, Any]:
        return {
            "number": number,
            "title": f"finding {number}",
            "body": "",
            "labels": [{"name": name} for name in labels],
        }

    untouched_new = issue(9, [common.LABEL_AUTOMATED])
    untouched_old = issue(3, [common.LABEL_AUTOMATED])
    in_flight = issue(4, [common.LABEL_AUTOMATED, common.LABEL_WORKING])
    handwritten = issue(5, [])
    existing = {
        "osv:a:1": untouched_new,
        "osv:b:1": untouched_old,
        # A grouped issue appears under several fingerprints but is one issue.
        "osv:b:2": untouched_old,
        "osv:c:1": in_flight,
        "osv:d:1": handwritten,
    }
    github = FakeGitHub([untouched_new, untouched_old, in_flight, handwritten])

    queued = sync_issues.queue_untriaged(github, existing, limit=1, dry_run=False)
    assert queued == [3]
    assert github.added_labels == [(3, [common.LABEL_QUEUED])]


def test_dispatch_is_idempotent_per_issue() -> None:
    issue = {
        "number": 7,
        "title": "[Security] flask",
        "body": "body",
        "labels": [{"name": common.LABEL_QUEUED}],
    }
    github = FakeGitHub([issue])
    devin = FakeDevin()

    session_id = dispatch.dispatch(
        github, devin, issue, base_branch="master", max_acu=None, dry_run=False
    )
    assert session_id == "devin-1"
    assert (7, [common.LABEL_WORKING]) in github.added_labels
    assert (7, common.LABEL_QUEUED) in github.removed_labels
    prompt = devin.created[0]["prompt"]
    assert "Closes #7" in prompt
    assert "SECURITY.md" in prompt

    # A second run finds the session marker and does not start another session.
    assert (
        dispatch.dispatch(
            github, devin, issue, base_branch="master", max_acu=None, dry_run=False
        )
        is None
    )
    assert len(devin.created) == 1


def test_render_status_reports_pull_request_and_verdict() -> None:
    session = {
        "status_enum": "finished",
        "pull_request": {"url": "https://github.com/acme/superset-ng/pull/9"},
        "structured_output": {
            "verdict": "fixed",
            "summary": "Bumped flask to 2.3.4.",
            "files_changed": ["requirements/base.txt"],
        },
        "messages": [{"type": "devin_message", "message": "done"}],
    }
    body = poll.render_status(session, "devin-abc")
    assert common.find_marker(body, poll.STATUS_MARKER_PREFIX) == "devin-abc"
    assert "https://github.com/acme/superset-ng/pull/9" in body
    assert "`fixed`" in body
    assert "requirements/base.txt" in body


def test_upsert_status_comment_rewrites_in_place() -> None:
    github = FakeGitHub([{"number": 8, "title": "t", "body": "", "labels": []}])
    github.comment(8, poll.render_status({"status_enum": "working"}, "devin-abc"))
    poll.upsert_status_comment(
        github, 8, poll.render_status({"status_enum": "blocked"}, "devin-abc")
    )
    assert len(github.comments(8)) == 1
    assert len(github.edited_comments) == 1
    assert "`blocked`" in github.edited_comments[0][1]


def test_upsert_status_comment_skips_write_when_only_the_clock_moved() -> None:
    github = FakeGitHub([{"number": 8, "title": "t", "body": "", "labels": []}])
    session = {"status_enum": "working"}
    github.comment(8, poll.render_status(session, "devin-abc"))
    poll.upsert_status_comment(github, 8, poll.render_status(session, "devin-abc"))
    assert github.edited_comments == []


def _tracked_issue(
    number: int,
    state: str = "open",
    created_at: str = "2026-08-01T00:00:00Z",
    closed_at: str | None = None,
    labels: list[str] | None = None,
) -> dict[str, Any]:
    return {
        "number": number,
        "title": f"[Security] finding {number}",
        "state": state,
        "created_at": created_at,
        "closed_at": closed_at,
        "labels": [{"name": name} for name in labels or [common.LABEL_SECURITY]],
        "fix_verified": None,
    }


def test_collect_issue_reconstructs_the_pipeline_timeline() -> None:
    issue = _tracked_issue(
        10, labels=[common.LABEL_SECURITY, common.LABEL_PR_OPEN], state="open"
    )
    github = FakeGitHub([issue])
    github.events_by_issue[10] = [
        {"event": "labeled", "created_at": "2026-08-01T01:00:00Z", "label": None},
        {
            "event": "labeled",
            "created_at": "2026-08-01T02:00:00Z",
            "label": {"name": common.LABEL_QUEUED},
        },
        # A re-queue must not reset the clock on the original request.
        {
            "event": "labeled",
            "created_at": "2026-08-03T02:00:00Z",
            "label": {"name": common.LABEL_QUEUED},
        },
    ]
    github.comments_by_issue[10] = [
        {
            "id": 1,
            "created_at": "2026-08-01T03:00:00Z",
            "body": common.marker(common.SESSION_MARKER_PREFIX, "devin-abc"),
        },
        {
            "id": 2,
            "created_at": "2026-08-01T09:00:00Z",
            "body": common.marker(
                common.METRICS_MARKER_PREFIX,
                json.dumps(
                    {
                        "checked_at": "2026-08-01T09:00:00Z",
                        "pull_request": ("https://github.com/acme/superset-ng/pull/99"),
                        "status": "finished",
                        "verdict": "fixed",
                    }
                ),
            ),
        },
    ]
    github.pull_requests[99] = {"state": "closed", "merged_at": "2026-08-02T03:00:00Z"}

    record = metrics.collect_issue(github, issue)
    assert record["session_id"] == "devin-abc"
    assert record["verdict"] == "fixed"
    assert record["hours_queue_to_session"] == 1.0
    assert record["hours_session_to_pr"] == 6.0
    assert record["pull_request_state"] == "merged"
    assert record["hours_session_to_merge"] == 24.0


def test_pull_request_number_ignores_foreign_repositories() -> None:
    repo = "acme/superset-ng"
    assert (
        metrics.pull_request_number("https://github.com/acme/superset-ng/pull/7", repo)
        == 7
    )
    assert (
        metrics.pull_request_number("https://github.com/other/x/pull/7", repo) is None
    )
    assert metrics.pull_request_number(None, repo) is None


def test_build_report_counts_funnel_outcomes_and_stalls() -> None:
    now = metrics.parse_time("2026-08-05T00:00:00Z")
    assert now is not None
    records = [
        # Fixed with a PR.
        {
            **_tracked_issue(1),
            "labels": [common.LABEL_PR_OPEN],
            "queued_at": "2026-08-01T00:00:00Z",
            "session_id": "devin-1",
            "session_started_at": "2026-08-01T01:00:00Z",
            "pull_request": "https://github.com/acme/x/pull/1",
            "pull_request_seen_at": "2026-08-01T02:00:00Z",
            "pull_request_state": "merged",
            "merged_at": "2026-08-01T04:00:00Z",
            "verdict": "fixed",
            "hours_queue_to_session": 1.0,
            "hours_session_to_pr": 1.0,
            "hours_session_to_merge": 3.0,
            "hours_filed_to_closed": 96.0,
        },
        # Session running far longer than the stall threshold.
        {
            **_tracked_issue(2),
            "labels": [common.LABEL_WORKING],
            "queued_at": "2026-08-01T00:00:00Z",
            "session_id": "devin-2",
            "session_started_at": "2026-08-01T00:00:00Z",
            "pull_request": None,
            "pull_request_seen_at": None,
            "pull_request_state": None,
            "merged_at": None,
            "verdict": None,
            "hours_queue_to_session": 0.0,
            "hours_session_to_pr": None,
            "hours_session_to_merge": None,
            "hours_filed_to_closed": None,
        },
        # Never queued: still awaiting triage.
        {
            **_tracked_issue(3),
            "labels": [common.LABEL_SECURITY],
            "queued_at": None,
            "session_id": None,
            "session_started_at": None,
            "pull_request": None,
            "pull_request_seen_at": None,
            "pull_request_state": None,
            "merged_at": None,
            "verdict": None,
            "hours_queue_to_session": None,
            "hours_session_to_pr": None,
            "hours_session_to_merge": None,
            "hours_filed_to_closed": None,
        },
    ]

    report = metrics.build_report(records, now)
    assert [stage["count"] for stage in report["funnel"]] == [3, 2, 2, 1, 0]
    assert report["backlog"]["awaiting_triage"] == 1
    assert report["outcomes"]["verdicts"] == {"fixed": 1, "pending": 1}
    assert report["outcomes"]["resolved_without_human"] == 1
    assert [item["number"] for item in report["stalled"]] == [2]
    assert report["latency_hours"]["queue_to_session"]["count"] == 2

    # ``closed`` is outside the funnel chain, so it never reports a drop-off.
    dashboard = metrics.render(report)
    assert "| Issue closed | 0 | - |" in dashboard
    assert "#2: session `devin-2` has run for over" in dashboard


def test_dora_scores_merged_pull_requests_as_deliveries() -> None:
    weeks = {
        "2026-W31": {
            "filed": 3,
            "dispatched": 2,
            "pull_requests": 1,
            "merged": 1,
            "closed": 1,
        },
        # A quiet week must not dilute the frequency: nothing was dispatched.
        "2026-W32": {
            "filed": 0,
            "dispatched": 0,
            "pull_requests": 0,
            "merged": 0,
            "closed": 0,
        },
    }
    records = [
        {
            "labels": [],
            "session_id": "devin-1",
            "verdict": "fixed",
            "pull_request_state": "merged",
            "hours_session_to_merge": 5.0,
            "hours_filed_to_closed": 10.0,
        },
        {
            "labels": [],
            "session_id": "devin-2",
            "verdict": "fixed",
            "pull_request_state": "rejected",
            "hours_session_to_merge": None,
            "hours_filed_to_closed": None,
        },
        {
            "labels": [common.LABEL_BLOCKED],
            "session_id": "devin-3",
            "verdict": "blocked",
            "pull_request_state": None,
            "hours_session_to_merge": None,
            "hours_filed_to_closed": None,
        },
    ]

    keys = metrics.dora(records, weeks)
    assert keys["deployment_frequency"] == {
        "merged_pull_requests": 1,
        "active_weeks": 1,
        "per_week": 1.0,
    }
    assert keys["lead_time_for_change_hours"]["median"] == 5.0
    assert keys["lead_time_for_change_hours"]["band"] == "Elite"
    # Two of the three terminal attempts did not deliver a merged fix.
    assert keys["change_failure_rate"]["rate"] == 0.67
    assert keys["time_to_restore_hours"]["band"] == "Elite"


def test_dora_band_thresholds() -> None:
    assert metrics.dora_band(1.0) == "Elite"
    assert metrics.dora_band(48.0) == "High"
    assert metrics.dora_band(24 * 10) == "Medium"
    assert metrics.dora_band(24 * 60) == "Low"
    assert metrics.dora_band(None) == "n/a"


def test_percentile_uses_nearest_rank() -> None:
    assert metrics.percentile([1.0, 2.0, 3.0, 4.0], 0.5) == 3.0
    assert metrics.percentile([1.0, 2.0, 3.0, 4.0], 0.9) == 4.0
    assert metrics.percentile([], 0.5) is None


def _pr_open_issue(number: int = 7, pull: int = 99) -> dict[str, Any]:
    return {
        "number": number,
        "title": "[Security] flask",
        "body": "",
        "labels": [{"name": common.LABEL_PR_OPEN}],
    }


def _record_pull(github: FakeGitHub, issue: int, url: str) -> None:
    """Write the status comment the poller would have left."""
    payload = json.dumps({"pull_request": url, "status": "finished"})
    github.comment(issue, common.marker(common.METRICS_MARKER_PREFIX, payload))


def test_merge_waits_for_checks_then_merges() -> None:
    issue = _pr_open_issue()
    github = FakeGitHub([issue])
    _record_pull(github, 7, "https://github.com/acme/superset-ng/pull/99")
    github.pull_requests[99] = {
        "state": "open",
        "draft": False,
        "merged_at": None,
        "mergeable": True,
        "title": "fix: md5",
        "head": {"sha": "abc"},
    }

    # A check still running defers the merge rather than forcing it.
    github.checks_by_sha["abc"] = [{"name": "tests", "status": "in_progress"}]
    outcome, detail = merge.consider(github, issue, dry_run=False)
    assert outcome == "waiting on checks"
    assert github.merged == []

    # A failure keeps it unmerged and names the offending check.
    github.checks_by_sha["abc"] = [
        {"name": "tests", "status": "completed", "conclusion": "failure"}
    ]
    outcome, detail = merge.consider(github, issue, dry_run=False)
    assert outcome == "checks failing"
    assert "tests (failure)" in detail
    assert github.merged == []

    # Green, and a skipped check does not count against it.
    github.checks_by_sha["abc"] = [
        {"name": "tests", "status": "completed", "conclusion": "success"},
        {"name": "optional", "status": "completed", "conclusion": "skipped"},
    ]
    outcome, _ = merge.consider(github, issue, dry_run=False)
    assert outcome == "merged"
    assert github.merged == [99]
    # The label survives the merge: verification, not merging, ends the work.
    assert github.removed_labels == []


def test_merge_leaves_conflicted_and_foreign_pull_requests_alone() -> None:
    issue = _pr_open_issue()
    github = FakeGitHub([issue])
    _record_pull(github, 7, "https://github.com/someone/else/pull/99")
    assert merge.consider(github, issue, dry_run=False) == (
        "skipped",
        "no pull request recorded",
    )

    github.comments_by_issue[7] = []
    _record_pull(github, 7, "https://github.com/acme/superset-ng/pull/99")
    github.pull_requests[99] = {
        "state": "open",
        "draft": False,
        "merged_at": None,
        "mergeable": False,
        "title": "fix: md5",
        "head": {"sha": "abc"},
    }
    github.checks_by_sha["abc"] = [
        {"name": "tests", "status": "completed", "conclusion": "success"}
    ]
    outcome, _ = merge.consider(github, issue, dry_run=False)
    assert outcome == "conflicted"
    assert github.merged == []


def test_merge_honours_legacy_commit_statuses() -> None:
    issue = _pr_open_issue()
    github = FakeGitHub([issue])
    _record_pull(github, 7, "https://github.com/acme/superset-ng/pull/99")
    github.pull_requests[99] = {
        "state": "open",
        "draft": False,
        "merged_at": None,
        "mergeable": True,
        "title": "fix: md5",
        "head": {"sha": "abc"},
    }
    github.statuses_by_sha["abc"] = [{"context": "ci/legacy", "state": "failure"}]
    outcome, detail = merge.consider(github, issue, dry_run=False)
    assert outcome == "checks failing"
    assert "ci/legacy (failure)" in detail


def _merged_issue(number: int = 7) -> dict[str, Any]:
    return {
        "number": number,
        "title": "[Security] md5",
        "state": "open",
        "created_at": "2026-08-01T00:00:00Z",
        "closed_at": None,
        "body": common.marker(common.FINGERPRINT_PREFIX, "bandit:B324:superset/x.py"),
        "labels": [{"name": common.LABEL_PR_OPEN}, {"name": common.LABEL_AUTOMATED}],
    }


def _merged_github(merged_at: str | None = "2026-08-02T04:00:00Z") -> FakeGitHub:
    issue = _merged_issue()
    github = FakeGitHub([issue])
    _record_pull(github, 7, "https://github.com/acme/superset-ng/pull/99")
    github.pull_requests[99] = {"state": "closed", "merged_at": merged_at}
    return github


SCANNED_AFTER = datetime(2026, 8, 2, 6, 0, tzinfo=timezone.utc)
SCANNED_BEFORE = datetime(2026, 8, 2, 1, 0, tzinfo=timezone.utc)


def test_verify_closes_the_issue_when_the_finding_stops_reproducing() -> None:
    github = _merged_github()
    outcome, _ = verify.verify(
        github,
        github.issues[0],
        reproducing=set(),
        scanned_at=SCANNED_AFTER,
        dry_run=False,
    )
    assert outcome == "verified"
    assert github.updates == [(7, {"state": "closed"})]
    assert (7, common.LABEL_PR_OPEN) in github.removed_labels
    body = github.comments_by_issue[7][-1]["body"]
    assert "Fix verified" in body
    assert json.loads(
        common.find_marker(body, common.VERIFIED_MARKER_PREFIX) or "{}"
    ) == {
        "pull_request": 99,
        "verified": True,
        "remaining": [],
        "checked_at": ANY_TIME,
    }


def test_verify_reopens_when_the_merged_fix_did_not_work() -> None:
    github = _merged_github()
    outcome, _ = verify.verify(
        github,
        github.issues[0],
        reproducing={"bandit:B324:superset/x.py"},
        scanned_at=SCANNED_AFTER,
        dry_run=False,
    )
    assert outcome == "not verified"
    # The issue stays open; only a scan of the merged result can close it.
    assert github.updates == []
    assert (7, [common.LABEL_BLOCKED]) in github.added_labels
    assert "still reproduces" in github.comments_by_issue[7][-1]["body"]


def test_verify_defers_when_the_scan_predates_the_merge() -> None:
    github = _merged_github()
    outcome, detail = verify.verify(
        github,
        github.issues[0],
        reproducing=set(),
        scanned_at=SCANNED_BEFORE,
        dry_run=False,
    )
    assert outcome == "deferred"
    assert "merged after the scan" in detail
    assert github.updates == []


def test_verify_rules_on_a_pull_request_only_once() -> None:
    github = _merged_github()
    verify.verify(
        github,
        github.issues[0],
        reproducing=set(),
        scanned_at=SCANNED_AFTER,
        dry_run=False,
    )
    outcome, _ = verify.verify(
        github,
        github.issues[0],
        reproducing=set(),
        scanned_at=SCANNED_AFTER,
        dry_run=False,
    )
    assert outcome == "skipped"
    assert github.updates == [(7, {"state": "closed"})]


def test_verify_ignores_an_unmerged_pull_request() -> None:
    github = _merged_github(merged_at=None)
    outcome, detail = verify.verify(
        github,
        github.issues[0],
        reproducing=set(),
        scanned_at=SCANNED_AFTER,
        dry_run=False,
    )
    assert (outcome, detail) == ("skipped", "no merged pull request")


def test_verify_requires_every_fingerprint_to_be_gone() -> None:
    github = _merged_github()
    github.issues[0]["body"] += "\n" + common.marker(
        common.FINGERPRINT_PREFIX, "osv:flask:2.3.3"
    )
    outcome, detail = verify.verify(
        github,
        github.issues[0],
        reproducing={"osv:flask:2.3.3"},
        scanned_at=SCANNED_AFTER,
        dry_run=False,
    )
    assert outcome == "not verified"
    assert "osv:flask:2.3.3" in detail


def test_verify_writes_nothing_in_a_dry_run() -> None:
    github = _merged_github()
    outcome, _ = verify.verify(
        github,
        github.issues[0],
        reproducing=set(),
        scanned_at=SCANNED_AFTER,
        dry_run=True,
    )
    assert outcome == "would verify"
    assert github.updates == []
    assert len(github.comments_by_issue[7]) == 1


def test_metrics_reports_verification_separately_from_merging() -> None:
    github = _merged_github()
    github.comment(
        7,
        common.marker(
            common.VERIFIED_MARKER_PREFIX,
            json.dumps({"pull_request": 99, "verified": True, "remaining": []}),
        ),
    )
    github.issues[0]["state"] = "closed"
    github.issues[0]["closed_at"] = "2026-08-02T06:00:00Z"
    record = metrics.collect_issue(github, github.issues[0])
    assert record["fix_verified"] is True

    report = metrics.build_report([record], datetime(2026, 8, 3, tzinfo=timezone.utc))
    assert report["outcomes"]["merged"] == 1
    assert report["outcomes"]["fix_verified"] == 1
    assert report["outcomes"]["awaiting_verification"] == 0


def test_metrics_counts_a_merge_awaiting_its_re_scan() -> None:
    github = _merged_github()
    record = metrics.collect_issue(github, github.issues[0])
    report = metrics.build_report([record], datetime(2026, 8, 3, tzinfo=timezone.utc))
    assert record["fix_verified"] is None
    assert report["outcomes"]["awaiting_verification"] == 1
