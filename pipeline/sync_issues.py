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
"""Turn scanner findings into GitHub issues, idempotently.

Each issue carries a hidden ``<!-- sec-fp: ... -->`` marker holding the finding
fingerprint. On every run:

  * a finding with no matching open issue creates one
  * a finding matching a machine-generated issue refreshes the body if it drifted
  * an open automated issue whose finding disappeared is commented on and closed

An issue may carry several fingerprints, which is how a hand-written issue that
covers a group of related findings ("vulnerable dev dependencies") suppresses
the per-package issues the scanner would otherwise file. Hand-written bodies are
never rewritten: only issues containing the ``<!-- sec-managed -->`` marker are.

Optionally the freshly created issues are labelled ``devin-fix``, which is the
trigger the remediation workflow listens on.
"""

from __future__ import annotations

import argparse
import json
import os
from typing import Any

from common import (
    find_markers,
    FINGERPRINT_PREFIX,
    GitHub,
    LABEL_AUTOMATED,
    LABEL_QUEUED,
    LABEL_SECURITY,
    marker,
    write_summary,
)

MANAGED_MARKER = "<!-- sec-managed -->"

SEVERITY_LABEL = {"CRITICAL": "dependencies", "HIGH": "dependencies"}


def render_body(finding: dict[str, Any]) -> str:
    lines = [
        MANAGED_MARKER,
        marker(FINGERPRINT_PREFIX, finding["fingerprint"]),
        "## Finding",
        "",
        f"- **Source**: `{finding['source']}`",
        f"- **Severity**: {finding['severity']}",
    ]
    if finding.get("package"):
        lines.append(
            f"- **Package**: `{finding['package']}` (`{finding.get('version', '')}`)"
        )
    if finding.get("scopes"):
        lines.append(f"- **Requirement files**: {', '.join(finding['scopes'])}")
    if finding.get("via"):
        lines.append(f"- **Reached via**: {' -> '.join(finding['via'])}")
    if finding.get("direct") is not None and finding["source"] == "npm-audit":
        lines.append(f"- **Direct dependency**: {finding['direct']}")

    if finding.get("advisories"):
        lines += [
            "",
            "| Advisory | CVE | Severity | Fixed in | Summary |",
            "| --- | --- | --- | --- | --- |",
        ]
        for advisory in finding["advisories"]:
            identifier = advisory.get("id") or ""
            url = advisory.get("url") or (
                f"https://github.com/advisories/{identifier}"
                if str(identifier).startswith("GHSA")
                else ""
            )
            link = f"[{identifier}]({url})" if url else str(identifier)
            lines.append(
                "| {} | {} | {} | {} | {} |".format(
                    link,
                    ", ".join(advisory.get("cves", [])) or "-",
                    advisory.get("severity") or "-",
                    ", ".join(advisory.get("fixed_versions", [])) or "-",
                    (advisory.get("summary") or "-").replace("|", "\\|"),
                )
            )

    if finding.get("locations"):
        lines += ["", "### Locations", ""]
        for location in finding["locations"]:
            lines.append(
                f"- `{location['file']}:{location['line']}` "
                f"({location['severity']}/{location['confidence']})"
            )
        if finding.get("more_info"):
            lines += ["", f"Rule reference: {finding['more_info']}"]

    lines += [
        "",
        "## Remediation expectations",
        "",
        "- Assess reachability in Superset before changing code; record the "
        "conclusion in the pull request.",
        "- Per `AGENTS.md`, a finding must name the `SECURITY.md` capability-matrix "
        "row it violates and the principal the attacker is assumed to hold. If it "
        "cannot, treat it as a hardening change rather than a vulnerability fix.",
        "- Keep the change minimal and reviewable; no drive-by refactors.",
        "",
        "---",
        "",
        "_Filed automatically by `scripts/security_automation/scan.py`. Add the "
        f"`{LABEL_QUEUED}` label to hand this to a Devin remediation session._",
    ]
    return "\n".join(lines)


def index_by_fingerprint(github: GitHub) -> dict[str, dict[str, Any]]:
    """Map every fingerprint carried by an open issue to that issue.

    Every open issue is listed rather than filtering server-side by label: the
    label filter is served from an index that lags issue creation by seconds,
    which is long enough for a re-run to file a duplicate.
    """
    existing: dict[str, dict[str, Any]] = {}
    for issue in github.open_issues():
        for fingerprint in find_markers(issue.get("body") or "", FINGERPRINT_PREFIX):
            existing[fingerprint] = issue
    return existing


def issue_labels(finding: dict[str, Any], auto_queue: bool) -> list[str]:
    labels = [LABEL_SECURITY, LABEL_AUTOMATED]
    if extra := SEVERITY_LABEL.get(finding["severity"]):
        labels.append(extra)
    if auto_queue:
        labels.append(LABEL_QUEUED)
    return labels


def queue_untriaged(
    github: GitHub,
    existing: dict[str, dict[str, Any]],
    limit: int,
    dry_run: bool,
) -> list[int]:
    """Label the oldest untouched findings so remediation picks them up.

    ``--auto-queue`` only reaches issues created by the run that files them,
    which leaves a backlog filed by earlier runs sitting untriaged forever.
    This drip-feeds that backlog at a rate the operator chooses instead of
    dispatching a session for every open finding at once.
    """
    candidates = []
    for issue in {i["number"]: i for i in existing.values()}.values():
        labels = {label["name"] for label in issue.get("labels", [])}
        if LABEL_AUTOMATED not in labels:
            continue
        # Any devin-* label means the issue is queued, running, or done with.
        if any(label.startswith("devin-") for label in labels):
            continue
        candidates.append(issue["number"])

    queued = sorted(candidates)[:limit]
    for number in queued:
        if dry_run:
            print(f"[dry-run] queue: #{number}")
        else:
            github.add_labels(number, [LABEL_QUEUED])
    return queued


def close_resolved(
    github: GitHub,
    existing: dict[str, dict[str, Any]],
    findings: list[dict[str, Any]],
    dry_run: bool,
) -> list[tuple[int, str]]:
    """Close automated issues whose every fingerprint stopped reproducing."""
    seen = {finding["fingerprint"] for finding in findings}
    by_issue: dict[int, tuple[dict[str, Any], list[str]]] = {}
    for fingerprint, issue in existing.items():
        by_issue.setdefault(issue["number"], (issue, []))[1].append(fingerprint)

    closed = []
    for issue, fingerprints in by_issue.values():
        labels = {label["name"] for label in issue.get("labels", [])}
        if LABEL_AUTOMATED not in labels:
            continue
        if any(fingerprint in seen for fingerprint in fingerprints):
            continue
        if dry_run:
            print(f"[dry-run] close: #{issue['number']}")
        else:
            github.comment(
                issue["number"],
                "The latest scan no longer reproduces this finding "
                f"({', '.join(f'`{f}`' for f in fingerprints)}). Closing "
                "automatically.",
            )
            github.update_issue(issue["number"], state="closed")
        closed.append((issue["number"], issue["title"]))
    return closed


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--findings", default="findings.json")
    parser.add_argument(
        "--auto-queue",
        action="store_true",
        help=f"label newly created issues `{LABEL_QUEUED}` to trigger remediation",
    )
    parser.add_argument(
        "--queue-untriaged",
        type=int,
        default=0,
        metavar="N",
        help=f"also label up to N existing untriaged findings `{LABEL_QUEUED}`",
    )
    parser.add_argument(
        "--close-resolved",
        action="store_true",
        help="close automated issues whose finding no longer reproduces",
    )
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    repo = os.environ["GITHUB_REPOSITORY"]
    github = GitHub(repo, os.environ["GITHUB_TOKEN"])

    with open(args.findings, encoding="utf-8") as handle:
        findings = json.load(handle)["findings"]

    if not args.dry_run:
        github.ensure_labels()

    existing = index_by_fingerprint(github)

    created: list[tuple[int, str]] = []
    updated: list[tuple[int, str]] = []
    for finding in findings:
        body = render_body(finding)
        issue = existing.get(finding["fingerprint"])
        if issue is None:
            if args.dry_run:
                print(f"[dry-run] create: {finding['title']}")
                created.append((0, finding["title"]))
                continue
            new_issue = github.create_issue(
                finding["title"], body, issue_labels(finding, args.auto_queue)
            )
            created.append((new_issue["number"], finding["title"]))
        elif (
            MANAGED_MARKER in (issue.get("body") or "")
            and (issue.get("body") or "").strip() != body.strip()
        ):
            if args.dry_run:
                print(f"[dry-run] update: #{issue['number']}")
            else:
                github.update_issue(issue["number"], body=body)
            updated.append((issue["number"], finding["title"]))

    closed = (
        close_resolved(github, existing, findings, args.dry_run)
        if args.close_resolved
        else []
    )
    queued = (
        queue_untriaged(github, existing, args.queue_untriaged, args.dry_run)
        if args.queue_untriaged > 0
        else []
    )

    summary = [
        "## Issue sync",
        "",
        f"- created: {len(created)}",
        f"- updated: {len(updated)}",
        f"- closed: {len(closed)}",
        f"- queued: {len(queued)}",
        "",
    ]
    for number, title in created:
        summary.append(f"- new #{number}: {title}")
    for number in queued:
        summary.append(f"- queued #{number}")
    write_summary("\n".join(summary))


if __name__ == "__main__":
    main()
