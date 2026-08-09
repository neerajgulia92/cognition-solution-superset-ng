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
"""Shared helpers for the security remediation automation.

Only the standard library is used so the scripts run on a bare GitHub Actions
runner without an install step.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any

GITHUB_API = os.environ.get("GITHUB_API_URL", "https://api.github.com")
DEVIN_API = os.environ.get("DEVIN_API_BASE", "https://api.devin.ai/v1")

FINGERPRINT_PREFIX = "sec-fp"
SESSION_MARKER_PREFIX = "devin-session"
METRICS_MARKER_PREFIX = "devin-metrics"
VERIFIED_MARKER_PREFIX = "sec-verified"

LABEL_SECURITY = "security"
LABEL_AUTOMATED = "automated-finding"
LABEL_QUEUED = "devin-fix"
LABEL_WORKING = "devin-working"
LABEL_BLOCKED = "devin-blocked"
LABEL_PR_OPEN = "devin-pr-open"

LABEL_DEFINITIONS = [
    (LABEL_SECURITY, "d73a4a", "Security vulnerability finding"),
    (LABEL_AUTOMATED, "5319e7", "Filed by the automated security scanner"),
    (LABEL_QUEUED, "0e8a16", "Queued for automated remediation by Devin"),
    (LABEL_WORKING, "fbca04", "A Devin session is actively remediating this"),
    (LABEL_BLOCKED, "b60205", "The Devin remediation session needs human input"),
    (LABEL_PR_OPEN, "1d76db", "A remediation pull request is open"),
    ("dependencies", "0366d6", "Dependency upgrade"),
    ("code-quality", "c2e0c6", "Code quality / hardening"),
]


def require_https(url: str) -> str:
    """Reject non-HTTPS URLs before they reach ``urlopen``."""
    if not url.startswith("https://"):
        raise ValueError(f"refusing to call a non-HTTPS URL: {url}")
    return url


class HttpError(RuntimeError):
    def __init__(self, status: int, body: str, url: str) -> None:
        super().__init__(f"{status} from {url}: {body[:500]}")
        self.status = status
        self.body = body


def _request(
    url: str,
    token: str,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    accept: str = "application/vnd.github+json",
    retries: int = 3,
) -> Any:
    data = json.dumps(payload).encode() if payload is not None else None
    headers = {
        "Authorization": f"Bearer {token}",
        "Accept": accept,
        "Content-Type": "application/json",
        "User-Agent": "superset-ng-security-automation",
    }
    last_error: Exception | None = None
    for attempt in range(retries):
        req = urllib.request.Request(  # noqa: S310
            require_https(url), data=data, headers=headers, method=method
        )
        try:
            with urllib.request.urlopen(req, timeout=60) as response:  # noqa: S310
                body = response.read().decode()
                return json.loads(body) if body else None
        except urllib.error.HTTPError as ex:
            body = ex.read().decode()
            # Retry transient server-side and secondary-rate-limit failures only.
            if ex.code in (429, 500, 502, 503, 504) and attempt < retries - 1:
                last_error = HttpError(ex.code, body, url)
                time.sleep(2**attempt * 3)
                continue
            raise HttpError(ex.code, body, url) from ex
        except urllib.error.URLError as ex:
            last_error = ex
            if attempt < retries - 1:
                time.sleep(2**attempt * 3)
                continue
            raise
    raise RuntimeError(f"exhausted retries for {url}") from last_error


class GitHub:
    """Minimal GitHub REST client scoped to a single repository."""

    def __init__(self, repo: str, token: str) -> None:
        self.repo = repo
        self.token = token

    def _url(self, path: str) -> str:
        return f"{GITHUB_API}/repos/{self.repo}{path}"

    def paginate(self, path: str) -> list[dict[str, Any]]:
        items: list[dict[str, Any]] = []
        page = 1
        while True:
            sep = "&" if "?" in path else "?"
            batch = _request(
                self._url(f"{path}{sep}per_page=100&page={page}"), self.token
            )
            if not batch:
                return items
            items.extend(batch)
            if len(batch) < 100:
                return items
            page += 1

    def ensure_labels(self) -> None:
        existing = {label["name"] for label in self.paginate("/labels")}
        for name, color, description in LABEL_DEFINITIONS:
            if name in existing:
                continue
            _request(
                self._url("/labels"),
                self.token,
                "POST",
                {"name": name, "color": color, "description": description},
            )

    def open_issues(self, labels: str | None = None) -> list[dict[str, Any]]:
        query = "/issues?state=open"
        if labels:
            query += f"&labels={urllib.parse.quote(labels)}"
        # The issues endpoint also returns pull requests; filter them out.
        return [i for i in self.paginate(query) if "pull_request" not in i]

    def create_issue(self, title: str, body: str, labels: list[str]) -> dict[str, Any]:
        return _request(
            self._url("/issues"),
            self.token,
            "POST",
            {"title": title, "body": body, "labels": labels},
        )

    def update_issue(self, number: int, **fields: Any) -> dict[str, Any]:
        return _request(self._url(f"/issues/{number}"), self.token, "PATCH", fields)

    def get_issue(self, number: int) -> dict[str, Any]:
        return _request(self._url(f"/issues/{number}"), self.token)

    def comments(self, number: int) -> list[dict[str, Any]]:
        return self.paginate(f"/issues/{number}/comments")

    def issues(self, state: str = "all") -> list[dict[str, Any]]:
        """Every issue in the given state, pull requests excluded."""
        return [
            i
            for i in self.paginate(f"/issues?state={state}")
            if "pull_request" not in i
        ]

    def events(self, number: int) -> list[dict[str, Any]]:
        """Issue events, which carry the timestamp of each label change."""
        return self.paginate(f"/issues/{number}/events")

    def pull_request(self, number: int) -> dict[str, Any]:
        return _request(self._url(f"/pulls/{number}"), self.token)

    def check_runs(self, ref: str) -> list[dict[str, Any]]:
        """Every check run reported against a commit."""
        result = _request(self._url(f"/commits/{ref}/check-runs?per_page=100"), self.token)
        return result.get("check_runs", []) if result else []

    def combined_status(self, ref: str) -> dict[str, Any]:
        """The legacy commit status rollup, which check runs do not cover."""
        return _request(self._url(f"/commits/{ref}/status"), self.token)

    def merge_pull_request(
        self, number: int, method: str = "squash", title: str | None = None
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {"merge_method": method}
        if title:
            payload["commit_title"] = title
        return _request(self._url(f"/pulls/{number}/merge"), self.token, "PUT", payload)

    def comment(self, number: int, body: str) -> dict[str, Any]:
        return _request(
            self._url(f"/issues/{number}/comments"), self.token, "POST", {"body": body}
        )

    def edit_comment(self, comment_id: int, body: str) -> dict[str, Any]:
        return _request(
            self._url(f"/issues/comments/{comment_id}"),
            self.token,
            "PATCH",
            {"body": body},
        )

    def add_labels(self, number: int, labels: list[str]) -> None:
        _request(
            self._url(f"/issues/{number}/labels"),
            self.token,
            "POST",
            {"labels": labels},
        )

    def remove_label(self, number: int, label: str) -> None:
        try:
            _request(
                self._url(f"/issues/{number}/labels/{urllib.parse.quote(label)}"),
                self.token,
                "DELETE",
            )
        except HttpError as ex:
            if ex.status != 404:
                raise


class Devin:
    """Minimal client for the Devin sessions API."""

    def __init__(self, token: str) -> None:
        self.token = token

    def create_session(
        self,
        prompt: str,
        title: str,
        tags: list[str],
        idempotent: bool = True,
        max_acu_limit: int | None = None,
        structured_output_schema: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "prompt": prompt,
            "title": title,
            "tags": tags,
            "idempotent": idempotent,
        }
        if max_acu_limit:
            payload["max_acu_limit"] = max_acu_limit
        if structured_output_schema:
            payload["structured_output_schema"] = structured_output_schema
        return _request(
            f"{DEVIN_API}/sessions",
            self.token,
            "POST",
            payload,
            accept="application/json",
        )

    def get_session(self, session_id: str) -> dict[str, Any]:
        return _request(
            f"{DEVIN_API}/sessions/{session_id}",
            self.token,
            accept="application/json",
        )

    def send_message(self, session_id: str, message: str) -> Any:
        return _request(
            f"{DEVIN_API}/sessions/{session_id}/message",
            self.token,
            "POST",
            {"message": message},
            accept="application/json",
        )


def marker(prefix: str, value: str) -> str:
    """Render a hidden HTML marker used to make comments/issues addressable."""
    return f"<!-- {prefix}: {value} -->"


def find_marker(text: str, prefix: str) -> str | None:
    values = find_markers(text, prefix)
    return values[0] if values else None


def find_markers(text: str, prefix: str) -> list[str]:
    """Return every value carried by ``<!-- prefix: value -->`` markers."""
    token = f"<!-- {prefix}: "
    values = []
    start = text.find(token)
    while start != -1:
        start += len(token)
        end = text.find(" -->", start)
        if end == -1:
            break
        values.append(text[start:end])
        start = text.find(token, end)
    return values


def write_summary(markdown: str) -> None:
    """Append markdown to the GitHub Actions job summary when available."""
    path = os.environ.get("GITHUB_STEP_SUMMARY")
    if not path:
        print(markdown)
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(markdown + "\n")


def set_output(name: str, value: str) -> None:
    path = os.environ.get("GITHUB_OUTPUT")
    if not path:
        return
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"{name}={value}\n")
