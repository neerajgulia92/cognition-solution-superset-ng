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
"""Start a Devin remediation session for security issues.

Called with ``--issue N`` (the ``issues: labeled`` trigger) or with no issue at
all, in which case every open issue labelled ``devin-fix`` that has no live
session is dispatched, up to ``--max-sessions``.

Bookkeeping lives entirely on the issue: the session id is stored in a hidden
marker inside the status comment, so a re-run never double-dispatches.
"""

from __future__ import annotations

import argparse
import os
import textwrap
from typing import Any

from common import (
    Devin,
    find_marker,
    GitHub,
    LABEL_BLOCKED,
    LABEL_PR_OPEN,
    LABEL_QUEUED,
    LABEL_WORKING,
    marker,
    SESSION_MARKER_PREFIX,
    write_summary,
)

PROMPT_TEMPLATE = """\
You are remediating a security finding in the repository `{repo}` \
(a fork of apache/superset). Work on a branch off `{base_branch}` and open a \
pull request against `{base_branch}` in `{repo}`.

## Issue #{number}: {title}

{body}

## What to do

1. Read `SECURITY.md` and `AGENTS.md` first. Superset's threat model decides \
whether this is an in-scope vulnerability or a hardening change, and the answer \
belongs in the pull request description.
2. Reproduce/confirm the finding in the current checkout before changing \
anything. If the finding does not reproduce or is a false positive, do NOT \
invent a fix: comment your reasoning on issue #{number} and stop.
3. Make the smallest correct change. For dependency findings, bump the pin to \
the fixed version and regenerate the lockfile/requirements the way the repo \
does it; do not hand-edit generated files.
4. Run the relevant checks: `pre-commit run` on staged files, plus the unit \
tests covering the code you touched.
5. Open ONE pull request titled with a Conventional Commit prefix \
(`fix(security): ...` or `chore(deps): ...`) whose body follows \
`.github/PULL_REQUEST_TEMPLATE.md`, states the reachability assessment, and \
contains the line `Closes #{number}`.

## Constraints

- Only touch files required by this finding. No drive-by refactors, no \
reformatting of unrelated code, no changes to other findings' code.
- Never weaken or delete a test to make CI pass.
- If the correct fix is a major-version upgrade with breaking changes, do the \
compatibility work only if it stays reviewable; otherwise open the PR with the \
safe part and explain the remainder on the issue.
- If you end up blocked, say so explicitly in your final message.

## Output

Finish by emitting the structured output requested by this session: `verdict` \
(one of `fixed`, `false_positive`, `not_reachable`, `blocked`), \
`pull_request_url` when a PR exists, a one-paragraph `summary`, and \
`files_changed`.
"""

OUTPUT_SCHEMA = {
    "type": "object",
    "properties": {
        "verdict": {
            "type": "string",
            "enum": ["fixed", "false_positive", "not_reachable", "blocked"],
        },
        "pull_request_url": {"type": "string"},
        "summary": {"type": "string"},
        "files_changed": {"type": "array", "items": {"type": "string"}},
    },
    "required": ["verdict", "summary"],
}


def session_id_for_issue(github: GitHub, number: int) -> str | None:
    for comment in github.comments(number):
        session_id = find_marker(comment["body"], SESSION_MARKER_PREFIX)
        if session_id:
            return session_id
    return None


def dispatch(
    github: GitHub,
    devin: Devin,
    issue: dict[str, Any],
    base_branch: str,
    max_acu: int | None,
    dry_run: bool,
) -> str | None:
    number = issue["number"]
    if session_id_for_issue(github, number):
        print(f"#{number}: session already exists, skipping")
        return None

    body = textwrap.shorten(issue.get("body") or "", width=8000, placeholder=" ...")
    prompt = PROMPT_TEMPLATE.format(
        repo=github.repo,
        base_branch=base_branch,
        number=number,
        title=issue["title"],
        body=body,
    )
    if dry_run:
        print(f"[dry-run] would dispatch #{number}\n{prompt[:600]}")
        return None

    session = devin.create_session(
        prompt=prompt,
        title=f"Security remediation: {issue['title'][:80]}",
        tags=["security-automation", f"{github.repo}#{number}"],
        idempotent=True,
        max_acu_limit=max_acu,
        structured_output_schema=OUTPUT_SCHEMA,
    )
    session_id = session["session_id"]
    github.comment(
        number,
        "\n".join(
            [
                marker(SESSION_MARKER_PREFIX, session_id),
                "### Automated remediation started",
                "",
                f"- Devin session: {session['url']}",
                f"- Session id: `{session_id}`",
                f"- Target branch: `{base_branch}`",
                "",
                "Status updates and the resulting pull request are posted here by "
                "`security-devin-poll.yml`.",
            ]
        ),
    )
    github.add_labels(number, [LABEL_WORKING])
    github.remove_label(number, LABEL_QUEUED)
    github.remove_label(number, LABEL_BLOCKED)
    print(f"#{number}: dispatched {session_id}")
    return session_id


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--issue", type=int, help="dispatch a single issue number")
    parser.add_argument("--max-sessions", type=int, default=3)
    parser.add_argument("--max-acu", type=int, default=None)
    parser.add_argument(
        "--base-branch", default=os.environ.get("BASE_BRANCH", "master")
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    github = GitHub(os.environ["GITHUB_REPOSITORY"], os.environ["GITHUB_TOKEN"])
    devin = Devin(os.environ["DEVIN_API_KEY"])

    if args.issue:
        issues = [github.get_issue(args.issue)]
    else:
        # Labels are filtered client-side: the server-side label filter is
        # served from an index that lags labelling by seconds.
        issues = [
            issue
            for issue in github.open_issues()
            if LABEL_QUEUED
            in (labels := {la["name"] for la in issue.get("labels", [])})
            and not labels & {LABEL_WORKING, LABEL_PR_OPEN}
        ][: args.max_sessions]

    dispatched = []
    for issue in issues:
        session_id = dispatch(
            github, devin, issue, args.base_branch, args.max_acu, args.dry_run
        )
        if session_id:
            dispatched.append((issue["number"], session_id))

    write_summary(
        "\n".join(
            ["## Devin dispatch", "", f"- sessions started: {len(dispatched)}", ""]
            + [f"- #{n} -> `{s}`" for n, s in dispatched]
        )
    )


if __name__ == "__main__":
    main()
