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
# specific language governing programs and limitations
# under the License.
"""Confirm that a merged remediation actually removed the finding.

A merged pull request is a claim, not proof. The session said it fixed the
vulnerability and a reviewer agreed, but neither of them re-ran the scanner
against the merged result. This stage does, and it is the only thing in the
pipeline entitled to close a finding as fixed.

It needs no re-scan of its own: the run's ``scan`` stage already produced a
findings document from a fresh checkout of the target's default branch. The
fingerprints in that document are compared with the fingerprints the issue
tracks:

    gone        -> the fix is verified; comment and close the issue
    still there -> the merge did not fix it; reopen the work as blocked

A scan taken before the merge landed proves nothing, so a finding whose pull
request merged after the scan ran is deferred to the next run rather than
judged against stale evidence. Either verdict is written to the issue as a
marker, so it is recorded once and the next run does not re-litigate a
decision it already made.

Usage:
    python verify.py --findings findings.json [--issue N] [--dry-run]
"""

from __future__ import annotations

import argparse
import json
import os
from datetime import datetime, timezone
from typing import Any

from common import (
    FINGERPRINT_PREFIX,
    LABEL_AUTOMATED,
    LABEL_BLOCKED,
    LABEL_PR_OPEN,
    METRICS_MARKER_PREFIX,
    VERIFIED_MARKER_PREFIX,
    GitHub,
    find_marker,
    find_markers,
    marker,
    write_summary,
)


def load_scan(path: str) -> tuple[set[str], datetime | None]:
    """Every fingerprint the latest scan reproduced, and when it ran."""
    with open(path, encoding="utf-8") as handle:
        document = json.load(handle)
    generated = document.get("generated_at")
    return (
        {finding["fingerprint"] for finding in document["findings"]},
        datetime.fromisoformat(generated) if generated else None,
    )


def merged_pull_request(
    github: GitHub, number: int
) -> tuple[int, str, datetime] | None:
    """The remediation pull request for this issue, if it has been merged."""
    prefix = f"/{github.repo}/pull/"
    url: str | None = None
    for comment in github.comments(number):
        payload = find_marker(comment["body"] or "", METRICS_MARKER_PREFIX)
        if payload:
            url = json.loads(payload).get("pull_request") or url

    if not url or prefix not in url:
        return None
    tail = url.split(prefix, 1)[1].split("/")[0]
    if not tail.isdigit():
        return None

    merged_at = github.pull_request(int(tail)).get("merged_at")
    if not merged_at:
        return None
    return int(tail), url, datetime.fromisoformat(merged_at.replace("Z", "+00:00"))


def already_verified(github: GitHub, number: int, pull: int) -> bool:
    """Whether this exact pull request has been ruled on before."""
    for comment in github.comments(number):
        for payload in find_markers(comment["body"] or "", VERIFIED_MARKER_PREFIX):
            if json.loads(payload).get("pull_request") == pull:
                return True
    return False


def verify(
    github: GitHub,
    issue: dict[str, Any],
    reproducing: set[str],
    scanned_at: datetime | None,
    dry_run: bool,
) -> tuple[str, str]:
    """Rule on one issue whose remediation pull request has been merged."""
    number = issue["number"]
    labels = {label["name"] for label in issue.get("labels", [])}
    if LABEL_AUTOMATED not in labels:
        return "skipped", "not an automated finding"

    found = merged_pull_request(github, number)
    if found is None:
        return "skipped", "no merged pull request"
    pull, url, merged_at = found

    if already_verified(github, number, pull):
        return "skipped", f"#{pull} already verified"

    if scanned_at is None or merged_at > scanned_at:
        # The scan predates the merge, so it cannot say anything about it.
        return "deferred", f"#{pull} merged after the scan"

    fingerprints = find_markers(issue.get("body") or "", FINGERPRINT_PREFIX)
    if not fingerprints:
        return "skipped", "issue carries no fingerprint"

    # An issue can group several fingerprints, and a partial fix is not a fix.
    remaining = [f for f in fingerprints if f in reproducing]
    fixed = not remaining

    if dry_run:
        return ("would verify" if fixed else "would reopen"), f"#{pull}"

    payload = json.dumps(
        {
            "pull_request": pull,
            "verified": fixed,
            "remaining": remaining,
            "checked_at": datetime.now(timezone.utc).isoformat(),
        },
        separators=(",", ":"),
        sort_keys=True,
    )

    if fixed:
        github.comment(
            number,
            "\n".join(
                [
                    marker(VERIFIED_MARKER_PREFIX, payload),
                    f"### Fix verified — {url} merged",
                    "",
                    "The scanner was re-run against the merged result and this "
                    "finding no longer reproduces "
                    f"({', '.join(f'`{f}`' for f in fingerprints)}). Closing.",
                ]
            ),
        )
        github.remove_label(number, LABEL_PR_OPEN)
        github.update_issue(number, state="closed")
        return "verified", f"#{pull}"

    github.comment(
        number,
        "\n".join(
            [
                marker(VERIFIED_MARKER_PREFIX, payload),
                f"### Fix not verified — {url} merged, finding still reproduces",
                "",
                "The scanner was re-run against the merged result and still "
                f"reports {', '.join(f'`{f}`' for f in remaining)}. Reopening "
                "for another attempt.",
            ]
        ),
    )
    github.remove_label(number, LABEL_PR_OPEN)
    github.add_labels(number, [LABEL_BLOCKED])
    return "not verified", f"#{pull}: {', '.join(remaining[:2])}"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", default="findings.json")
    parser.add_argument("--issue", type=int, help="verify a single issue number")
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    if not os.path.exists(args.findings):
        # Without a scan there is nothing to check the merge against, and
        # guessing would mean closing findings on no evidence.
        print(f"no findings document at {args.findings}; skipping verification")
        return

    github = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
    reproducing, scanned_at = load_scan(args.findings)

    issues = (
        [github.get_issue(args.issue)]
        if args.issue
        else github.open_issues(labels=LABEL_PR_OPEN)
    )
    results = [
        (issue["number"], *verify(github, issue, reproducing, scanned_at, args.dry_run))
        for issue in issues
    ]
    verified = [r for r in results if r[1] == "verified"]

    lines = [
        "## Fix verification",
        "",
        f"- verified and closed: {len(verified)}",
        "",
    ]
    if results:
        lines += ["| Issue | Outcome | Detail |", "| --- | --- | --- |"]
        lines += [f"| #{n} | {outcome} | {detail} |" for n, outcome, detail in results]
    write_summary("\n".join(lines))

    for number, outcome, detail in results:
        print(f"#{number}: {outcome} — {detail}")


if __name__ == "__main__":
    main()
