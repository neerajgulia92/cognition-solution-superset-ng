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
"""Collect security findings and emit a normalised findings document.

Sources:
  * pinned Python requirements resolved against the OSV.dev batch API
  * ``npm audit --json`` output for the frontend workspace
  * ``bandit`` JSON output for the ``superset`` package

Each finding is normalised to a stable ``fingerprint`` so ``sync_issues.py`` can
create issues idempotently across runs.

Usage:
    python scripts/security_automation/scan.py \
        --requirements requirements/base.txt requirements/development.txt \
        --npm-audit /tmp/npm-audit.json \
        --bandit /tmp/bandit.json \
        --out findings.json --report report.md
"""

from __future__ import annotations

import argparse
import json
import os
import re
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from common import require_https

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
OSV_VULN_URL = "https://api.osv.dev/v1/vulns/"
PIN_RE = re.compile(r"^([A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?==([^\s;]+)")

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MODERATE": 2, "MEDIUM": 2, "LOW": 3, "": 4}
# bandit says MEDIUM, npm/OSV say MODERATE; collapse to one bucket.
SEVERITY_ALIASES = {"MEDIUM": "MODERATE"}
# bandit rules that are worth an issue; the LOW/noise rules are excluded on
# purpose so the automation does not drown the tracker in `assert` findings.
BANDIT_RULES = {"B324", "B301", "B102", "B704", "B310", "B608"}


def normalise_severity(value: str) -> str:
    upper = (value or "").upper()
    return SEVERITY_ALIASES.get(upper, upper)


def _post_json(url: str, payload: dict[str, Any]) -> Any:
    req = urllib.request.Request(  # noqa: S310
        require_https(url),
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as response:  # noqa: S310
        return json.load(response)


def _get_json(url: str) -> Any:
    with urllib.request.urlopen(require_https(url), timeout=60) as response:  # noqa: S310
        return json.load(response)


def parse_requirements(path: str) -> dict[str, str]:
    pins: dict[str, str] = {}
    with open(path, encoding="utf-8") as handle:
        for raw in handle:
            match = PIN_RE.match(raw.split("#")[0].strip())
            if match:
                pins[match.group(1).lower()] = match.group(2)
    return pins


def _advisory(vuln_id: str) -> dict[str, Any]:
    detail = _get_json(OSV_VULN_URL + vuln_id)
    fixed: set[str] = set()
    for affected in detail.get("affected", []):
        for entry in affected.get("ranges", []):
            for event in entry.get("events", []):
                if "fixed" in event:
                    fixed.add(event["fixed"])
    return {
        "id": vuln_id,
        "cves": [a for a in detail.get("aliases", []) if a.startswith("CVE")],
        "severity": detail.get("database_specific", {}).get("severity", ""),
        "summary": (detail.get("summary") or "").strip(),
        "fixed_versions": sorted(fixed),
    }


def scan_python(requirement_files: list[str]) -> list[dict[str, Any]]:
    scopes: dict[tuple[str, str], set[str]] = defaultdict(set)
    for path in requirement_files:
        scope = os.path.splitext(os.path.basename(path))[0]
        for name, version in parse_requirements(path).items():
            scopes[(name, version)].add(scope)

    packages = sorted(scopes)
    queries = [
        {"package": {"name": name, "ecosystem": "PyPI"}, "version": version}
        for name, version in packages
    ]
    results = _post_json(OSV_BATCH_URL, {"queries": queries})["results"]

    findings: list[dict[str, Any]] = []
    for (name, version), result in zip(packages, results, strict=True):
        # PYSEC entries duplicate the GHSA records for these packages.
        advisories = [
            _advisory(vuln["id"])
            for vuln in result.get("vulns", [])
            if not vuln["id"].startswith("PYSEC")
        ]
        if not advisories:
            continue
        severity = min(
            (a["severity"] for a in advisories),
            key=lambda s: SEVERITY_ORDER.get(s.upper(), 4),
        )
        findings.append(
            {
                "source": "osv",
                "fingerprint": f"osv:{name}:{version}",
                "severity": normalise_severity(severity),
                "package": name,
                "version": version,
                "scopes": sorted(scopes[(name, version)]),
                "advisories": advisories,
                "title": f"[Security] {name} {version} has known vulnerabilities",
            }
        )
    return findings


def scan_npm(audit_path: str) -> list[dict[str, Any]]:
    with open(audit_path, encoding="utf-8") as handle:
        audit = json.load(handle)

    findings = []
    for name, entry in audit.get("vulnerabilities", {}).items():
        severity = normalise_severity(entry.get("severity", ""))
        if SEVERITY_ORDER.get(severity, 4) > SEVERITY_ORDER["MODERATE"]:
            continue
        advisories = [
            {
                "id": via.get("source"),
                "url": via.get("url"),
                "summary": via.get("title"),
                "severity": (via.get("severity") or "").upper(),
            }
            for via in entry.get("via", [])
            if isinstance(via, dict)
        ]
        via_packages = [via for via in entry.get("via", []) if isinstance(via, str)]
        # Intermediate links in a dependency chain carry no advisory of their
        # own and are not actionable; the root cause and the direct dependency
        # that pulls it in are.
        if not advisories and not entry.get("isDirect"):
            continue
        findings.append(
            {
                "source": "npm-audit",
                "fingerprint": f"npm:{name}",
                "severity": severity,
                "package": name,
                "version": entry.get("range", ""),
                "direct": entry.get("isDirect", False),
                "via": via_packages,
                "advisories": advisories,
                "title": f"[Security] npm {name} is vulnerable ({severity.lower()})",
            }
        )
    return findings


def scan_bandit(bandit_path: str) -> list[dict[str, Any]]:
    with open(bandit_path, encoding="utf-8") as handle:
        report = json.load(handle)

    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for result in report.get("results", []):
        test_id = result["test_id"]
        if test_id not in BANDIT_RULES:
            continue
        if result["issue_severity"] == "LOW":
            continue
        grouped[test_id].append(result)

    findings = []
    for test_id, results in grouped.items():
        severity = min(
            (r["issue_severity"] for r in results),
            key=lambda s: SEVERITY_ORDER.get(s.upper(), 4),
        )
        findings.append(
            {
                "source": "bandit",
                "fingerprint": f"bandit:{test_id}",
                "severity": normalise_severity(severity),
                "rule": test_id,
                "title": (
                    f"[Security] bandit {test_id}: {results[0]['issue_text'][:80]}"
                ),
                "locations": [
                    {
                        "file": r["filename"],
                        "line": r["line_number"],
                        "severity": r["issue_severity"],
                        "confidence": r["issue_confidence"],
                        "code": (r.get("code") or "").strip(),
                    }
                    for r in sorted(
                        results, key=lambda r: (r["filename"], r["line_number"])
                    )
                ],
                "more_info": results[0].get("more_info"),
            }
        )
    return findings


def render_report(findings: list[dict[str, Any]]) -> str:
    generated = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts: dict[str, int] = defaultdict(int)
    for finding in findings:
        counts[finding["severity"] or "UNKNOWN"] += 1

    lines = [
        "# Security scan report",
        "",
        f"Generated: {generated}",
        "",
        "| Severity | Findings |",
        "| --- | --- |",
    ]
    for severity in ("CRITICAL", "HIGH", "MODERATE", "LOW", "UNKNOWN"):
        if counts.get(severity):
            lines.append(f"| {severity} | {counts[severity]} |")
    lines += ["", "| Source | Finding | Severity |", "| --- | --- | --- |"]
    for finding in sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 4)):
        lines.append(
            f"| `{finding['source']}` | {finding['title']} | {finding['severity']} |"
        )
    return "\n".join(lines) + "\n"


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--requirements", nargs="*", default=[])
    parser.add_argument("--npm-audit")
    parser.add_argument("--bandit")
    parser.add_argument("--out", default="findings.json")
    parser.add_argument("--report", default="report.md")
    args = parser.parse_args()

    findings: list[dict[str, Any]] = []
    if args.requirements:
        findings += scan_python(args.requirements)
    if args.npm_audit and os.path.exists(args.npm_audit):
        findings += scan_npm(args.npm_audit)
    if args.bandit and os.path.exists(args.bandit):
        findings += scan_bandit(args.bandit)

    findings.sort(
        key=lambda f: (SEVERITY_ORDER.get(f["severity"], 4), f["fingerprint"])
    )
    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump(
            {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "findings": findings,
            },
            handle,
            indent=2,
        )
    with open(args.report, "w", encoding="utf-8") as handle:
        handle.write(render_report(findings))
    print(f"{len(findings)} findings written to {args.out}")


if __name__ == "__main__":
    main()
