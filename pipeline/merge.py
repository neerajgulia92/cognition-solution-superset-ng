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
"""Merge remediation pull requests whose checks have gone green.

This closes the loop: without it a finding stops at "a pull request exists",
which is not the same as "the vulnerability is gone". Merging is also what
makes the DORA numbers mean anything, since a merged pull request is the unit
of delivery the metrics count.

Nothing is merged on judgement. A pull request qualifies only when every check
has finished successfully, the pull request is not a draft, and GitHub itself
reports it as mergeable -- so branch protection stays authoritative and a red
or still-running suite simply defers the merge to the next run.

Usage:
    python merge.py [--issue N] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from common import (
    LABEL_PR_OPEN,
    METRICS_MARKER_PREFIX,
    GitHub,
    HttpError,
    find_markers,
    write_summary,
)

# Check conclusions that do not stand in the way of a merge. A skipped or
# neutral run is a check that decided it had nothing to say.
PASSING = {"success", "skipped", "neutral"}


def pull_request_number(issue: dict[str, Any], github: GitHub) -> int | None:
    """The remediation pull request the poller recorded on the issue."""
    prefix = f"/{github.repo}/pull/"
    for comment in github.comments(issue["number"]):
        for payload in find_markers(comment["body"] or "", METRICS_MARKER_PREFIX):
            url = json.loads(payload).get("pull_request")
            if url and prefix in url:
                tail = url.split(prefix, 1)[1].split("/")[0]
                if tail.isdigit():
                    return int(tail)
    return None


def check_state(github: GitHub, sha: str) -> tuple[str, list[str]]:
    """Roll every check run and commit status on a commit into one verdict.

    Returns ``pending`` while anything is still running, ``failing`` with the
    names that failed, or ``passing`` when everything that reported is happy.
    """
    pending: list[str] = []
    failing: list[str] = []

    for run in github.check_runs(sha):
        if run["status"] != "completed":
            pending.append(run["name"])
        elif run["conclusion"] not in PASSING:
            failing.append(f"{run['name']} ({run['conclusion']})")

    # Older integrations report commit statuses rather than check runs.
    combined = github.combined_status(sha)
    for status in combined.get("statuses", []):
        if status["state"] == "pending":
            pending.append(status["context"])
        elif status["state"] not in ("success",):
            failing.append(f"{status['context']} ({status['state']})")

    if failing:
        return "failing", failing
    if pending:
        return "pending", pending
    return "passing", []


def consider(github: GitHub, issue: dict[str, Any], dry_run: bool) -> tuple[str, str]:
    """Decide what to do with one issue's remediation pull request."""
    number = pull_request_number(issue, github)
    if number is None:
        return "skipped", "no pull request recorded"

    pull = github.pull_request(number)
    if pull.get("merged_at"):
        return "already merged", f"#{number}"
    if pull["state"] != "open":
        return "closed unmerged", f"#{number}"
    if pull.get("draft"):
        return "draft", f"#{number}"

    state, names = check_state(github, pull["head"]["sha"])
    if state == "pending":
        return "waiting on checks", f"#{number}: {', '.join(names[:3])}"
    if state == "failing":
        return "checks failing", f"#{number}: {', '.join(names[:3])}"

    # `mergeable` is computed asynchronously; null means "ask again shortly".
    if pull.get("mergeable") is False:
        return "conflicted", f"#{number}"
    if pull.get("mergeable") is None:
        return "mergeability unknown", f"#{number}"

    if dry_run:
        return "would merge", f"#{number}"

    try:
        github.merge_pull_request(number, title=f"{pull['title']} (#{number})")
    except HttpError as ex:
        # 405 is GitHub refusing the merge, e.g. an unsatisfied protection rule.
        return "merge refused", f"#{number}: {ex.status}"

    github.comment(
        issue["number"],
        f"Remediation pull request #{number} merged automatically: every check "
        "passed and the branch was mergeable.",
    )
    github.remove_label(issue["number"], LABEL_PR_OPEN)
    return "merged", f"#{number}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issue", type=int, help="consider a single issue number")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    github = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])

    if args.issue:
        issues = [github.get_issue(args.issue)]
    else:
        issues = github.open_issues(labels=LABEL_PR_OPEN)

    results = [(issue["number"], *consider(github, issue, args.dry_run)) for issue in issues]
    merged = [r for r in results if r[1] == "merged"]

    lines = ["## Remediation merges", "", f"- merged: {len(merged)}", ""]
    if results:
        lines += ["| Issue | Outcome | Detail |", "| --- | --- | --- |"]
        lines += [f"| #{n} | {outcome} | {detail} |" for n, outcome, detail in results]
    write_summary("\n".join(lines))

    for number, outcome, detail in results:
        print(f"#{number}: {outcome} — {detail}")


if __name__ == "__main__":
    main()
