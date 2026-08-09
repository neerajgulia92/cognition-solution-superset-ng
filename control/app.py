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
"""The pipeline's control plane: run it, schedule it, and serve its state.

In GitHub Actions the pipeline is four workflows chained by cron. Locally
there is no Actions runner, so this service plays that role: the same stage
scripts, run in the same order, either on demand or on a schedule, with the
run history and the generated metrics exposed as JSON for Grafana to read.

Endpoints:
    GET  /                  the control panel
    POST /api/run           start a run (JSON body: {"stages": [...]})
    GET  /api/run           the same, for links from a Grafana panel
    GET  /api/status        current run, schedule and history
    GET  /api/runs          run history
    GET  /metrics.json      the latest metrics document
    GET  /api/issues        the findings table, flattened for Grafana
    GET  /healthz
"""

from __future__ import annotations

import asyncio
import json
import os
import shlex
from collections import deque
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Deque

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from fastapi import Body, FastAPI, HTTPException
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

PIPELINE = Path(os.environ.get("PIPELINE_DIR", "/app/pipeline"))
DATA = Path(os.environ.get("DATA_DIR", "/data"))
METRICS_JSON = DATA / "metrics.json"
METRICS_MD = DATA / "METRICS.md"
FINDINGS = DATA / "findings.json"
REPORT = DATA / "security-report.md"
BANDIT = DATA / "bandit.json"
BANDIT_TARGET = os.environ.get("BANDIT_TARGET", "superset")

REPOSITORY = os.environ.get("TARGET_REPOSITORY", "neerajgulia92/superset-ng")
TARGET_CHECKOUT = Path(os.environ.get("TARGET_CHECKOUT", "/target"))
TARGET_REF = os.environ.get("TARGET_REF", "master")
SCHEDULE = os.environ.get("PIPELINE_CRON", "0 * * * *")
QUEUE_UNTRIAGED = os.environ.get("QUEUE_UNTRIAGED", "1")
MAX_SESSIONS = os.environ.get("MAX_SESSIONS", "1")
# Off by default: the fix pull request is meant to be reviewed and merged by
# an engineer, and the pipeline picks the work back up once it lands.
AUTO_MERGE = os.environ.get("AUTO_MERGE", "false").lower() == "true"
# Off by default. This stack scans Python dependencies and code, but not npm,
# so a finding filed by the CI scanner from `npm audit` would look resolved
# here and be closed for the wrong reason.
CLOSE_RESOLVED = os.environ.get("CLOSE_RESOLVED", "false").lower() == "true"
DRY_RUN = os.environ.get("DRY_RUN", "false").lower() == "true"

# The pipeline in order. Every stage is the same script the GitHub workflows
# run; only the arguments differ, so the local and hosted paths cannot drift.
STAGES: dict[str, list[str]] = {
    "scan": [
        "scan.py",
        "--out",
        str(FINDINGS),
        "--report",
        str(REPORT),
    ],
    "sync": [
        "sync_issues.py",
        "--findings",
        str(FINDINGS),
        "--queue-untriaged",
        QUEUE_UNTRIAGED,
        *(["--close-resolved"] if CLOSE_RESOLVED else []),
    ],
    "dispatch": ["dispatch.py", "--max-sessions", MAX_SESSIONS],
    "poll": ["poll.py"],
    "merge": ["merge.py"],
    "verify": ["verify.py", "--findings", str(FINDINGS)],
    "metrics": [
        "metrics.py",
        "--json-out",
        str(METRICS_JSON),
        "--markdown-out",
        str(METRICS_MD),
    ],
}
DEFAULT_STAGES = [name for name in STAGES if name != "merge" or AUTO_MERGE]

app = FastAPI(title="Superset-NG remediation control plane")
scheduler = AsyncIOScheduler(timezone="UTC")

history: Deque[dict[str, Any]] = deque(maxlen=25)
current: dict[str, Any] | None = None
lock = asyncio.Lock()


def now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def environment() -> dict[str, str]:
    env = dict(os.environ)
    env["GITHUB_REPOSITORY"] = REPOSITORY
    env["PYTHONPATH"] = str(PIPELINE)
    # The scanner reads dependency manifests out of a checkout of the target.
    env.setdefault("PYTHONUNBUFFERED", "1")
    return env


def scan_arguments() -> list[str]:
    """Point the scanner at whichever manifests the target checkout has."""
    extra: list[str] = []
    requirements = [
        TARGET_CHECKOUT / "requirements" / "base.txt",
        TARGET_CHECKOUT / "requirements" / "development.txt",
    ]
    present = [str(path) for path in requirements if path.exists()]
    if present:
        extra += ["--requirements", *present]
    if BANDIT.exists():
        extra += ["--bandit", str(BANDIT)]
    return extra


async def refresh_target() -> None:
    """Pull the target's default branch before scanning it.

    Verification depends on this: a merged fix only shows up as gone once the
    checkout has advanced to the commit the merge produced.
    """
    if not (TARGET_CHECKOUT / ".git").exists():
        return
    process = await asyncio.create_subprocess_exec(
        "git",
        "-C",
        str(TARGET_CHECKOUT),
        "fetch",
        "--depth",
        "1",
        "origin",
        TARGET_REF,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await process.communicate()
    if process.returncode != 0:
        # An unreachable remote must not fail the run; the existing checkout
        # is stale but still scannable, and verification simply defers.
        return
    checkout = await asyncio.create_subprocess_exec(
        "git",
        "-C",
        str(TARGET_CHECKOUT),
        "checkout",
        "-q",
        "FETCH_HEAD",
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await checkout.communicate()


async def run_bandit() -> None:
    """Refresh the bandit report the scanner reads its code findings from.

    Best effort: a target checkout without the source tree, or a bandit that
    exits non-zero because it found something, must not fail the scan stage.
    """
    source = TARGET_CHECKOUT / BANDIT_TARGET
    if not source.exists():
        return
    process = await asyncio.create_subprocess_exec(
        "bandit",
        "-q",
        "-r",
        str(source),
        "-f",
        "json",
        "-o",
        str(BANDIT),
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )
    await process.communicate()


async def run_stage(name: str) -> dict[str, Any]:
    """Run one stage as a subprocess and capture what it said."""
    command = list(STAGES[name])
    if name == "scan":
        await refresh_target()
        await run_bandit()
        command += scan_arguments()
    if DRY_RUN and name in ("sync", "dispatch", "merge", "verify"):
        command.append("--dry-run")

    started = now()
    process = await asyncio.create_subprocess_exec(
        "python",
        *command,
        cwd=str(PIPELINE),
        env=environment(),
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    output, _ = await process.communicate()
    text = output.decode(errors="replace")
    return {
        "stage": name,
        "command": shlex.join(["python", *command]),
        "started_at": started,
        "finished_at": now(),
        "exit_code": process.returncode,
        "ok": process.returncode == 0,
        # Keep the tail: the interesting part of a failure is at the end.
        "output": text[-4000:],
    }


async def run_pipeline(stages: list[str], trigger: str) -> dict[str, Any]:
    """Run the requested stages in pipeline order, stopping at the first failure."""
    global current

    if lock.locked():
        raise HTTPException(409, "a run is already in progress")

    async with lock:
        ordered = [name for name in STAGES if name in stages]
        run: dict[str, Any] = {
            "id": now(),
            "trigger": trigger,
            "stages": ordered,
            "started_at": now(),
            "finished_at": None,
            "results": [],
            "ok": None,
            "dry_run": DRY_RUN,
        }
        current = run
        try:
            for name in ordered:
                result = await run_stage(name)
                run["results"].append(result)
                if not result["ok"]:
                    # A failed scan makes every later stage meaningless.
                    break
            run["ok"] = all(r["ok"] for r in run["results"])
        finally:
            run["finished_at"] = now()
            current = None
            history.appendleft(run)
        return run


@app.on_event("startup")
async def start_scheduler() -> None:
    if not SCHEDULE or SCHEDULE.lower() == "off":
        return
    scheduler.add_job(
        lambda: asyncio.create_task(run_pipeline(DEFAULT_STAGES, "schedule")),
        CronTrigger.from_crontab(SCHEDULE, timezone="UTC"),
        id="pipeline",
        max_instances=1,
        coalesce=True,
    )
    scheduler.start()


def next_run() -> str | None:
    job = scheduler.get_job("pipeline")
    return job.next_run_time.isoformat(timespec="seconds") if job else None


def requested_stages(stages: list[str] | None) -> list[str]:
    if not stages or stages == ["all"]:
        return DEFAULT_STAGES
    unknown = [s for s in stages if s not in STAGES]
    if unknown:
        raise HTTPException(400, f"unknown stages: {', '.join(unknown)}")
    return stages


@app.post("/api/run")
async def api_run(body: dict[str, Any] = Body(default={})) -> dict[str, Any]:
    stages = requested_stages(body.get("stages"))
    return await run_pipeline(stages, body.get("trigger", "manual"))


@app.get("/api/run")
async def api_run_via_link(stages: str = "all") -> RedirectResponse:
    """Trigger from a plain link, which is all a Grafana panel can render."""
    names = requested_stages([s for s in stages.split(",") if s])
    asyncio.create_task(run_pipeline(names, "manual"))
    return RedirectResponse("/?started=1", status_code=303)


@app.get("/api/status")
async def api_status() -> dict[str, Any]:
    return {
        "repository": REPOSITORY,
        "schedule": SCHEDULE,
        "next_run": next_run(),
        "auto_merge": AUTO_MERGE,
        "close_resolved": CLOSE_RESOLVED,
        "dry_run": DRY_RUN,
        "running": current is not None,
        "current": current,
        "last_run": history[0] if history else None,
    }


@app.get("/api/runs")
async def api_runs() -> list[dict[str, Any]]:
    """Run history, flattened enough for a Grafana table."""
    return [
        {
            "id": run["id"],
            "trigger": run["trigger"],
            "started_at": run["started_at"],
            "finished_at": run["finished_at"],
            "ok": run["ok"],
            "stages": ", ".join(run["stages"]),
            "failed_stage": next(
                (r["stage"] for r in run["results"] if not r["ok"]), None
            ),
        }
        for run in history
    ]


def metrics_document() -> dict[str, Any]:
    if not METRICS_JSON.exists():
        return {}
    return json.loads(METRICS_JSON.read_text())


@app.get("/metrics.json")
async def metrics() -> JSONResponse:
    return JSONResponse(metrics_document())


@app.get("/api/issues")
async def issues() -> list[dict[str, Any]]:
    return metrics_document().get("issues", [])


@app.get("/healthz")
async def healthz() -> dict[str, str]:
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def panel() -> str:
    return (Path(__file__).parent / "panel.html").read_text()
