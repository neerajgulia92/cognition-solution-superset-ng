#
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
"""Report on the effectiveness of the security remediation pipeline.

The pipeline already records everything it does on the issues themselves --
labels for the queue state, a marker comment per session, and a machine
readable payload on the status comment. This derives the analytics from that
record, so there is no separate datastore to keep in sync and the numbers can
always be traced back to a visible artefact on an issue.

Answers, for an engineering leader:

  * is the queue draining?          backlog and weekly throughput
  * is the automation succeeding?   verdict mix and remediation rate
  * is it fast enough?              median/p90 latency per pipeline stage
  * is anything stuck?              stalled sessions and blocked issues
  * how does it compare?            the DORA four keys, scoped to this pipeline
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timedelta, timezone
from typing import Any

from common import (
    find_marker,
    GitHub,
    LABEL_AUTOMATED,
    LABEL_BLOCKED,
    LABEL_PR_OPEN,
    LABEL_QUEUED,
    LABEL_SECURITY,
    LABEL_WORKING,
    METRICS_MARKER_PREFIX,
    SESSION_MARKER_PREFIX,
    VERIFIED_MARKER_PREFIX,
    write_summary,
)

STALLED_AFTER_HOURS = 24

# The DORA keys are defined for a delivery pipeline; the mapping used here
# treats a merged remediation pull request as the deployment, so:
#
#   deployment frequency  merged remediation PRs per active week
#   lead time for change  session started -> its PR merged
#   change failure rate   remediations needing a human (blocked session, or a
#                         PR closed without merging) over all terminal attempts
#   time to restore       finding filed -> its issue closed
#
# The thresholds are the published DORA performance bands, adapted to hours.
DORA_BANDS = [
    ("Elite", 24.0),
    ("High", 24.0 * 7),
    ("Medium", 24.0 * 30),
]

# The order a finding travels through the pipeline. Each stage counts every
# issue that reached it, including the ones that have since moved on, so the
# drop-off between two stages is the number lost at that step. ``closed`` sits
# outside the chain: an issue can be closed by a human without ever being
# queued, so differencing it against the stage above would be meaningless.
FUNNEL = [
    ("filed", "Finding filed as an issue", True),
    ("queued", "Labelled `devin-fix`", True),
    ("session", "Devin session started", True),
    ("pull_request", "Remediation PR opened", True),
    ("closed", "Issue closed", False),
]


def parse_time(value: str | None) -> datetime | None:
    if not value:
        return None
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def hours_between(start: datetime | None, end: datetime | None) -> float | None:
    if not start or not end:
        return None
    return round((end - start).total_seconds() / 3600, 2)


def percentile(values: list[float], fraction: float) -> float | None:
    """Nearest-rank percentile; the sample sizes here are far too small for
    interpolation to mean anything."""
    if not values:
        return None
    ordered = sorted(values)
    index = min(len(ordered) - 1, int(round(fraction * (len(ordered) - 1))))
    return ordered[index]


def summarise(values: list[float]) -> dict[str, float | int | None]:
    return {
        "count": len(values),
        "median": percentile(values, 0.5),
        "p90": percentile(values, 0.9),
        "max": max(values) if values else None,
    }


def dora_band(hours: float | None) -> str:
    if hours is None:
        return "n/a"
    for name, ceiling in DORA_BANDS:
        if hours <= ceiling:
            return name
    return "Low"


def iso_week(moment: datetime) -> str:
    year, week, _ = moment.isocalendar()
    return f"{year}-W{week:02d}"


def pull_request_number(url: str | None, repo: str) -> int | None:
    """The PR number, but only for pull requests in this repository."""
    prefix = f"/{repo}/pull/"
    if not url or prefix not in url:
        return None
    tail = url.split(prefix, 1)[1].split("/")[0]
    return int(tail) if tail.isdigit() else None


def collect_issue(github: GitHub, issue: dict[str, Any]) -> dict[str, Any]:
    """Reconstruct one finding's journey from its labels, events and comments."""
    number = issue["number"]
    labels = {label["name"] for label in issue.get("labels", [])}

    queued_at: datetime | None = None
    for event in github.events(number):
        if event.get("event") != "labeled":
            continue
        if (event.get("label") or {}).get("name") == LABEL_QUEUED:
            # First time it was queued: re-queues after a blocked session
            # should not reset the clock on the original request.
            queued_at = queued_at or parse_time(event.get("created_at"))

    session_id: str | None = None
    session_started_at: datetime | None = None
    status: dict[str, Any] = {}
    status_at: datetime | None = None
    verification: dict[str, Any] = {}
    for comment in github.comments(number):
        body = comment["body"]
        found = find_marker(body, SESSION_MARKER_PREFIX)
        if found and not session_id:
            session_id = found
            session_started_at = parse_time(comment.get("created_at"))
        payload = find_marker(body, METRICS_MARKER_PREFIX)
        if payload:
            status = json.loads(payload)
            status_at = parse_time(status.get("checked_at"))
        checked = find_marker(body, VERIFIED_MARKER_PREFIX)
        if checked:
            verification = json.loads(checked)

    created_at = parse_time(issue.get("created_at"))
    closed_at = parse_time(issue.get("closed_at"))
    pull_request = status.get("pull_request")

    # The PR is the unit of delivery, so its merge state is what decides
    # whether a remediation actually landed.
    merged_at: datetime | None = None
    pull_request_state: str | None = None
    if number_of_pr := pull_request_number(pull_request, github.repo):
        details = github.pull_request(number_of_pr)
        merged_at = parse_time(details.get("merged_at"))
        pull_request_state = (
            "merged"
            if merged_at
            else ("rejected" if details.get("state") == "closed" else "open")
        )

    return {
        "number": number,
        "title": issue["title"],
        "state": issue["state"],
        "labels": sorted(labels),
        "created_at": issue.get("created_at"),
        "closed_at": issue.get("closed_at"),
        "queued_at": queued_at.isoformat() if queued_at else None,
        "session_id": session_id,
        "session_started_at": (
            session_started_at.isoformat() if session_started_at else None
        ),
        "session_status": status.get("status"),
        "verdict": status.get("verdict"),
        "pull_request": pull_request,
        # A PR is only observed once the poller has seen it, so the poll
        # timestamp is the earliest defensible answer to "when did it land".
        "pull_request_seen_at": (
            status_at.isoformat() if status_at and pull_request else None
        ),
        "hours_queue_to_session": hours_between(queued_at, session_started_at),
        "pull_request_state": pull_request_state,
        "merged_at": merged_at.isoformat() if merged_at else None,
        "hours_session_to_pr": hours_between(
            session_started_at, status_at if pull_request else None
        ),
        "hours_session_to_merge": hours_between(session_started_at, merged_at),
        "hours_filed_to_closed": hours_between(created_at, closed_at),
        # None until a scan has run against the merged result: a merge is a
        # claim that the finding is gone, not evidence of it.
        "fix_verified": verification.get("verified"),
        "verified_at": verification.get("checked_at"),
    }


def dora(
    records: list[dict[str, Any]], weeks: dict[str, dict[str, int]]
) -> dict[str, Any]:
    """The four keys, with a merged remediation PR as the unit of delivery."""
    merged = [r for r in records if r["pull_request_state"] == "merged"]
    rejected = [r for r in records if r["pull_request_state"] == "rejected"]
    blocked = [
        r
        for r in records
        if r["session_id"]
        and (r["verdict"] == "blocked" or LABEL_BLOCKED in r["labels"])
    ]
    # Only weeks in which the pipeline did something count towards the rate:
    # a week with no findings to fix is not a week it underperformed.
    active_weeks = [w for w in weeks.values() if w["dispatched"] or w["merged"]]

    lead_time = summarise(
        [r["hours_session_to_merge"] for r in merged if r["hours_session_to_merge"]]
    )
    restore = summarise(
        [
            r["hours_filed_to_closed"]
            for r in records
            if r["hours_filed_to_closed"] is not None
        ]
    )
    attempts = len(merged) + len(rejected) + len(blocked)

    return {
        "deployment_frequency": {
            "merged_pull_requests": len(merged),
            "active_weeks": len(active_weeks),
            "per_week": (
                round(len(merged) / len(active_weeks), 2) if active_weeks else None
            ),
        },
        "lead_time_for_change_hours": {
            **lead_time,
            "band": dora_band(
                lead_time["median"] if isinstance(lead_time["median"], float) else None
            ),
        },
        "change_failure_rate": {
            "terminal_attempts": attempts,
            "failed": len(rejected) + len(blocked),
            "rate": (
                round((len(rejected) + len(blocked)) / attempts, 2)
                if attempts
                else None
            ),
        },
        "time_to_restore_hours": {
            **restore,
            "band": dora_band(
                restore["median"] if isinstance(restore["median"], float) else None
            ),
        },
    }


def build_report(records: list[dict[str, Any]], now: datetime) -> dict[str, Any]:
    """Aggregate the per-issue records into the numbers worth reporting."""
    open_records = [r for r in records if r["state"] == "open"]
    with_session = [r for r in records if r["session_id"]]
    with_pr = [r for r in records if r["pull_request"]]

    counts = {
        "filed": len(records),
        "queued": len([r for r in records if r["queued_at"]]),
        "session": len(with_session),
        "pull_request": len(with_pr),
        "closed": len([r for r in records if r["state"] == "closed"]),
    }

    verdicts: dict[str, int] = {}
    for record in with_session:
        verdicts[record["verdict"] or "pending"] = (
            verdicts.get(record["verdict"] or "pending", 0) + 1
        )

    stalled = [
        r
        for r in with_session
        if not r["pull_request"]
        and LABEL_WORKING in r["labels"]
        and (parse_time(r["session_started_at"]) or now)
        < now - timedelta(hours=STALLED_AFTER_HOURS)
    ]

    weeks: dict[str, dict[str, int]] = {}
    for record in records:
        for field, key in (
            ("created_at", "filed"),
            ("session_started_at", "dispatched"),
            ("pull_request_seen_at", "pull_requests"),
            ("merged_at", "merged"),
            ("closed_at", "closed"),
        ):
            moment = parse_time(record[field])
            if not moment:
                continue
            bucket = weeks.setdefault(
                iso_week(moment),
                {
                    "filed": 0,
                    "dispatched": 0,
                    "pull_requests": 0,
                    "merged": 0,
                    "closed": 0,
                },
            )
            bucket[key] += 1

    return {
        "generated_at": now.isoformat(),
        "backlog": {
            "open": len(open_records),
            "awaiting_triage": len(
                [r for r in open_records if not r["queued_at"] and not r["session_id"]]
            ),
            "queued": len([r for r in open_records if LABEL_QUEUED in r["labels"]]),
            "in_flight": len([r for r in open_records if LABEL_WORKING in r["labels"]]),
            "pr_open": len([r for r in open_records if LABEL_PR_OPEN in r["labels"]]),
            "blocked": len([r for r in open_records if LABEL_BLOCKED in r["labels"]]),
        },
        "funnel": [
            {
                "stage": stage,
                "label": label,
                "count": counts[stage],
                "in_chain": in_chain,
            }
            for stage, label, in_chain in FUNNEL
        ],
        "outcomes": {
            "sessions": len(with_session),
            "verdicts": dict(sorted(verdicts.items())),
            # Of the sessions that reached a verdict, the share that produced a
            # change or justified not making one. A blocked session is the
            # failure signal: it needed a human.
            "resolved_without_human": len(
                [
                    r
                    for r in with_session
                    if r["verdict"] in ("fixed", "false_positive", "not_reachable")
                ]
            ),
            "needed_human": len(
                [
                    r
                    for r in with_session
                    if r["verdict"] == "blocked" or LABEL_BLOCKED in r["labels"]
                ]
            ),
            # A merge is a claim; a scan of the merged result is the evidence.
            "merged": len([r for r in records if r["pull_request_state"] == "merged"]),
            "fix_verified": len([r for r in records if r["fix_verified"] is True]),
            "fix_failed_verification": len(
                [r for r in records if r["fix_verified"] is False]
            ),
            "awaiting_verification": len(
                [
                    r
                    for r in records
                    if r["pull_request_state"] == "merged" and r["fix_verified"] is None
                ]
            ),
        },
        "latency_hours": {
            "queue_to_session": summarise(
                [
                    r["hours_queue_to_session"]
                    for r in records
                    if r["hours_queue_to_session"] is not None
                ]
            ),
            "session_to_pull_request": summarise(
                [
                    r["hours_session_to_pr"]
                    for r in records
                    if r["hours_session_to_pr"] is not None
                ]
            ),
            "filed_to_closed": summarise(
                [
                    r["hours_filed_to_closed"]
                    for r in records
                    if r["hours_filed_to_closed"] is not None
                ]
            ),
        },
        "dora": dora(records, weeks),
        "throughput_by_week": [
            {"week": week, **values} for week, values in sorted(weeks.items())
        ],
        "stalled": [
            {
                "number": r["number"],
                "session_id": r["session_id"],
                "started_at": r["session_started_at"],
            }
            for r in stalled
        ],
        "issues": records,
    }


def _row(name: str, stats: dict[str, float | int | None]) -> str:
    def cell(key: str) -> str:
        value = stats[key]
        return f"{value:.1f}" if isinstance(value, float) else "-"

    return f"| {name} | {stats['count']} | {cell('median')} | {cell('p90')} | {cell('max')} |"  # noqa: E501


def render_dora(keys: dict[str, Any]) -> list[str]:
    frequency = keys["deployment_frequency"]
    lead = keys["lead_time_for_change_hours"]
    failure = keys["change_failure_rate"]
    restore = keys["time_to_restore_hours"]

    def hours(value: float | int | None) -> str:
        return f"{value:.1f}h" if isinstance(value, float) else "-"

    def percent(value: float | int | None) -> str:
        return f"{value * 100:.0f}%" if isinstance(value, float) else "-"

    return [
        "## DORA four keys",
        "",
        "_A merged remediation pull request is the unit of delivery._",
        "",
        "| Key | Value | Band |",
        "| --- | --- | --- |",
        f"| Deployment frequency | {frequency['per_week'] or 0} merged PRs / "
        f"active week ({frequency['merged_pull_requests']} total) | - |",
        f"| Lead time for change | {hours(lead['median'])} median, "
        f"{hours(lead['p90'])} p90 | {lead['band']} |",
        f"| Change failure rate | {percent(failure['rate'])} "
        f"({failure['failed']}/{failure['terminal_attempts']} attempts) | - |",
        f"| Time to restore service | {hours(restore['median'])} median, "
        f"{hours(restore['p90'])} p90 | {restore['band']} |",
        "",
    ]


def render(report: dict[str, Any]) -> str:
    """Render the report as the markdown dashboard."""
    backlog = report["backlog"]
    outcomes = report["outcomes"]
    total_filed = report["funnel"][0]["count"]
    prs = report["funnel"][3]["count"]

    lines = [
        "# Security remediation pipeline",
        "",
        f"_Generated {report['generated_at'][:16].replace('T', ' ')} UTC._",
        "",
        *render_dora(report["dora"]),
        "## Headline",
        "",
        "| Metric | Value |",
        "| --- | --- |",
        f"| Findings tracked | {total_filed} |",
        f"| Open | {backlog['open']} |",
        f"| Remediation PRs produced | {prs} |",
        f"| Sessions run | {outcomes['sessions']} |",
        f"| Resolved without a human | {outcomes['resolved_without_human']} |",
        f"| Needed a human | {outcomes['needed_human']} |",
        f"| Fixes merged | {outcomes['merged']} |",
        f"| Fixes verified by a re-scan | {outcomes['fix_verified']} |",
        f"| Merged but still reproducing | {outcomes['fix_failed_verification']} |",
        f"| Awaiting verification | {outcomes['awaiting_verification']} |",
        "",
        "## Backlog",
        "",
        "| State | Count |",
        "| --- | --- |",
        f"| Awaiting triage | {backlog['awaiting_triage']} |",
        f"| Queued (`devin-fix`) | {backlog['queued']} |",
        f"| Session in flight (`devin-working`) | {backlog['in_flight']} |",
        f"| PR open (`devin-pr-open`) | {backlog['pr_open']} |",
        f"| Blocked (`devin-blocked`) | {backlog['blocked']} |",
        "",
        "## Funnel",
        "",
        "| Stage | Reached | Drop-off |",
        "| --- | --- | --- |",
    ]

    previous: int | None = None
    for stage in report["funnel"]:
        if not stage["in_chain"] or previous is None:
            drop = "-"
        else:
            drop = str(previous - stage["count"])
        lines.append(f"| {stage['label']} | {stage['count']} | {drop} |")
        if stage["in_chain"]:
            previous = stage["count"]

    lines += [
        "",
        "## Session outcomes",
        "",
        "| Verdict | Sessions |",
        "| --- | --- |",
    ]
    if outcomes["verdicts"]:
        for verdict, count in outcomes["verdicts"].items():
            lines.append(f"| `{verdict}` | {count} |")
    else:
        lines.append("| _no sessions yet_ | 0 |")

    lines += [
        "",
        "## Latency (hours)",
        "",
        "| Stage | Samples | Median | p90 | Max |",
        "| --- | --- | --- | --- | --- |",
        _row("Queued -> session started", report["latency_hours"]["queue_to_session"]),
        _row(
            "Session started -> PR open",
            report["latency_hours"]["session_to_pull_request"],
        ),
        _row("Filed -> issue closed", report["latency_hours"]["filed_to_closed"]),
        "",
        "## Throughput by week",
        "",
        "| Week | Filed | Dispatched | PRs | Merged | Closed |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for week in report["throughput_by_week"]:
        lines.append(
            f"| {week['week']} | {week['filed']} | {week['dispatched']} "
            f"| {week['pull_requests']} | {week['merged']} | {week['closed']} |"
        )
    if not report["throughput_by_week"]:
        lines.append("| _no activity_ | 0 | 0 | 0 | 0 | 0 |")

    lines += ["", "## Attention required", ""]
    attention = [
        f"- #{item['number']}: session `{item['session_id']}` has run for over "
        f"{STALLED_AFTER_HOURS}h without a pull request"
        for item in report["stalled"]
    ]
    attention += [
        f"- #{r['number']}: blocked, needs a human"
        for r in report["issues"]
        if LABEL_BLOCKED in r["labels"] and r["state"] == "open"
    ]
    attention += [
        f"- #{r['number']}: {r['pull_request']} merged but the finding still "
        "reproduces"
        for r in report["issues"]
        if r["fix_verified"] is False
    ]
    lines += attention or ["- Nothing stalled or blocked."]

    lines += [
        "",
        "## Per-issue detail",
        "",
        "| Issue | State | Verdict | Session | Pull request | PR state | Verified |",
        "| --- | --- | --- | --- | --- | --- | --- |",
    ]
    verified_cell = {True: "yes", False: "**no**", None: "-"}
    for record in sorted(report["issues"], key=lambda r: r["number"]):
        session = f"`{record['session_id']}`" if record["session_id"] else "-"
        lines.append(
            f"| #{record['number']} | {record['state']} "
            f"| `{record['verdict'] or '-'}` | {session} "
            f"| {record['pull_request'] or '-'} "
            f"| {record['pull_request_state'] or '-'} "
            f"| {verified_cell[record['fix_verified']]} |"
        )
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--json-out", default="metrics.json")
    parser.add_argument("--markdown-out", default="METRICS.md")
    parser.add_argument(
        "--dashboard-issue",
        type=int,
        help="issue whose body is replaced with the dashboard",
    )
    args = parser.parse_args()

    github = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])

    tracked = [
        issue
        for issue in github.issues("all")
        if {LABEL_SECURITY, LABEL_AUTOMATED}
        & {label["name"] for label in issue.get("labels", [])}
    ]
    records = [collect_issue(github, issue) for issue in tracked]
    report = build_report(records, datetime.now(timezone.utc))
    dashboard = render(report)

    with open(args.json_out, "w", encoding="utf-8") as handle:
        json.dump(report, handle, indent=2, sort_keys=True)
    with open(args.markdown_out, "w", encoding="utf-8") as handle:
        handle.write(dashboard + "\n")

    write_summary(dashboard)

    if args.dashboard_issue:
        github.update_issue(args.dashboard_issue, body=dashboard)

    print(f"{len(records)} findings analysed -> {args.json_out}, {args.markdown_out}")


if __name__ == "__main__":
    main()
