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
"""Reconcile Devin remediation sessions with their GitHub issues.

For every open issue labelled ``devin-working`` this reads the session id from
the issue's marker comment, fetches the session, and:

  * rewrites a single status comment in place (no comment spam)
  * moves labels as the session progresses (working -> blocked / pr-open)
  * writes a fleet-level status table to the workflow job summary
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any

from common import (
    Devin,
    find_marker,
    GitHub,
    HttpError,
    LABEL_BLOCKED,
    LABEL_PR_OPEN,
    LABEL_WORKING,
    marker,
    METRICS_MARKER_PREFIX,
    SESSION_MARKER_PREFIX,
    write_summary,
)

STATUS_MARKER_PREFIX = "devin-status"

TERMINAL = {"finished", "expired"}


def render_status(session: dict[str, Any], session_id: str) -> str:
    status = session.get("status_enum") or session.get("status") or "unknown"
    pull_request = (session.get("pull_request") or {}).get("url")
    structured = session.get("structured_output") or {}
    updated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    url = f"https://app.devin.ai/sessions/{session_id.removeprefix('devin-')}"
    # A machine-readable copy of the same facts, so the reporting layer never
    # has to parse the rendered table back out of the comment.
    payload = json.dumps(
        {
            "session_id": session_id,
            "status": status,
            "verdict": structured.get("verdict"),
            "pull_request": pull_request,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )
    lines = [
        marker(STATUS_MARKER_PREFIX, session_id),
        marker(METRICS_MARKER_PREFIX, payload),
        "### Devin remediation status",
        "",
        "| Field | Value |",
        "| --- | --- |",
        f"| Session | {url} |",
        f"| Status | `{status}` |",
        f"| Pull request | {pull_request or '_none yet_'} |",
    ]
    if structured.get("verdict"):
        lines.append(f"| Verdict | `{structured['verdict']}` |")
    lines.append(f"| Last checked | {updated} |")

    if structured.get("summary"):
        lines += ["", "**Session summary**", "", structured["summary"]]
    if structured.get("files_changed"):
        lines += ["", "**Files changed**", ""] + [
            f"- `{path}`" for path in structured["files_changed"]
        ]

    messages = [
        m for m in session.get("messages", []) if m.get("type") == "devin_message"
    ]
    if messages:
        last = messages[-1]["message"].strip()
        if len(last) > 1200:
            last = last[:1200] + " ..."
        lines += [
            "",
            "<details><summary>Latest session message</summary>",
            "",
            last,
            "",
            "</details>",
        ]
    return "\n".join(lines)


def strip_checked_at(body: str) -> str:
    """Drop the fields that change on every poll, for change detection."""
    return "\n".join(
        line
        for line in body.splitlines()
        if "Last checked" not in line and METRICS_MARKER_PREFIX not in line
    ).strip()


def upsert_status_comment(github: GitHub, number: int, body: str) -> None:
    for comment in github.comments(number):
        if find_marker(comment["body"], STATUS_MARKER_PREFIX):
            if strip_checked_at(comment["body"]) != strip_checked_at(body):
                github.edit_comment(comment["id"], body)
            return
    github.comment(number, body)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issue", type=int, help="poll a single issue")
    args = parser.parse_args()

    github = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
    devin = Devin(os.environ["DEVIN_API_KEY"])

    # Filtering by label client-side: the server-side label filter is served
    # from an index that lags labelling by seconds, long enough for a poll
    # triggered by the dispatch workflow to miss the session it just started.
    issues = (
        [github.get_issue(args.issue)]
        if args.issue
        else [
            issue
            for issue in github.open_issues()
            if LABEL_WORKING in {label["name"] for label in issue.get("labels", [])}
        ]
    )

    rows = []
    for issue in issues:
        number = issue["number"]
        session_id = next(
            (
                find_marker(c["body"], SESSION_MARKER_PREFIX)
                for c in github.comments(number)
                if find_marker(c["body"], SESSION_MARKER_PREFIX)
            ),
            None,
        )
        if not session_id:
            print(f"#{number}: no session marker, skipping")
            continue

        try:
            session = devin.get_session(session_id)
        except HttpError as ex:
            print(f"#{number}: failed to fetch {session_id}: {ex}")
            continue

        upsert_status_comment(github, number, render_status(session, session_id))

        status = session.get("status_enum") or session.get("status") or ""
        pull_request = (session.get("pull_request") or {}).get("url")
        verdict = (session.get("structured_output") or {}).get("verdict")

        if pull_request:
            github.add_labels(number, [LABEL_PR_OPEN])
            github.remove_label(number, LABEL_WORKING)
            github.remove_label(number, LABEL_BLOCKED)
        elif status == "blocked" or verdict == "blocked":
            github.add_labels(number, [LABEL_BLOCKED])
        elif status in TERMINAL:
            # Finished without a PR: needs a human to decide what happened.
            github.add_labels(number, [LABEL_BLOCKED])
            github.remove_label(number, LABEL_WORKING)

        rows.append(
            (number, issue["title"], status, verdict or "-", pull_request or "-")
        )

    summary = [
        "## Devin remediation fleet",
        "",
        "| Issue | Title | Session status | Verdict | Pull request |",
        "| --- | --- | --- | --- | --- |",
    ]
    for number, title, status, verdict, pull_request in rows:
        summary.append(
            f"| #{number} | {title[:60]} | `{status}` | `{verdict}` | {pull_request} |"
        )
    if not rows:
        summary.append("| - | _no active remediation sessions_ | - | - | - |")
    write_summary("\n".join(summary))


if __name__ == "__main__":
    main()
