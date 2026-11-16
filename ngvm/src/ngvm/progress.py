# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""Where the daily run is, step by step, as it runs (v0.26.2).

A run is a chain of steps, each in the image of its pillar, and until now the only way to know where
it was, was to read the logs of the pod. Every step writes one record when it starts and one when it
ends, on the working volume and to the decision service, which serves them to the supervision page
and to the chat (`get_run_progress`).

A record is small and says only what the step itself knows: the run it belongs to (the moment the
run took the working volume), its order and its pillar, its state, when it started and ended, how
long it took, its exit code, the pod and the container (`kubectl logs <pod> -c <step>`), and what it
left behind (files and bytes of its output path). The numbers of the pillars (CVEs, decisions,
tickets) are not copied here: the page asks the services that own them.

Run from the step's shell, never on the critical path: a failure prints a warning and exits 0, so
supervision cannot be the reason a run stops.

    python -m ngvm.progress start --step triage --dir /data/progress --run-file /data/.ngvm-run/started
    python -m ngvm.progress end --step triage --code 3 --output /data/output ... (same options)
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import json
import os
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from . import __version__

SCHEMA = "ngvm.progress/1"
# Order and pillar of each step of the daily run (deploy/charts/ngvm-tenant/templates/cronjob-daily.yaml);
# a step that is not here is kept, last, under the pillar `other`.
STEPS: dict[str, tuple[int, str]] = {
    "collect": (1, "detection"),
    "via": (2, "watch"),
    "detect": (3, "detection"),
    "assets": (4, "triage"),
    "triage": (5, "triage"),
    "inventory": (6, "watch"),
    "publish": (7, "triage"),
    "dispatch": (8, "dispatch"),
}
PILLARS = ("watch", "detection", "triage", "dispatch", "other")
STATES = ("running", "done", "partial", "failed")
RUN_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
STEP_NAME = re.compile(r"^[a-z][a-z-]{0,31}$")
MAX_WALK = 20000  # files counted at most under an output directory
TIMEOUT = 10.0  # seconds: the step waits no longer for the decision service


def state_of(code: int) -> str:
    """The state a step ends in: 3 is a partial step (a warning), as everywhere in the run."""
    return "done" if code == 0 else "partial" if code == 3 else "failed"


def run_id(path: str | Path | None) -> str:
    """The run's id: the epoch second the first step took the working volume (/data/.ngvm-run/started),
    the same for every step of the chain. Unknown (a step run by hand): the day and hour."""
    if path:
        try:
            value = Path(path).read_text(encoding="utf-8").strip()
        except OSError:
            value = ""
        if value.isdigit():
            return value
    return dt.datetime.now(dt.UTC).strftime("%Y%m%dT%H%M")


def started_at(run: str) -> str:
    """When the run started, from its id; the id of a run started by hand is not an epoch."""
    if run.isdigit():
        return dt.datetime.fromtimestamp(int(run), dt.UTC).isoformat(timespec="seconds")
    return ""


def outputs(path: str | Path | None) -> dict[str, int] | None:
    """What the step left on the volume: files and bytes of a file or of a directory tree. None when
    the path was not given or does not exist (a step that writes nothing, or wrote nothing)."""
    if not path:
        return None
    p = Path(path)
    if p.is_file():
        try:
            return {"files": 1, "bytes": p.stat().st_size}
        except OSError:
            return None
    if not p.is_dir():
        return {"files": 0, "bytes": 0}
    files = size = 0
    for root, _dirs, names in os.walk(p):
        for name in names:
            try:
                size += (Path(root) / name).stat().st_size
            except OSError:
                continue
            files += 1
            if files >= MAX_WALK:
                return {"files": files, "bytes": size, "truncated": 1}
    return {"files": files, "bytes": size}


def record(
    step: str,
    run: str,
    tenant: str = "",
    state: str = "running",
    code: int | None = None,
    pod: str = "",
    output: str | Path | None = None,
    seconds: float | None = None,
    now: dt.datetime | None = None,
) -> dict[str, Any]:
    """One step's record, ready to write and to push."""
    order, pillar = STEPS.get(step, (99, "other"))
    moment = (now or dt.datetime.now(dt.UTC)).isoformat(timespec="seconds")
    out: dict[str, Any] = {
        "schema": SCHEMA,
        "tenant": tenant,
        "run": run,
        "run_started_at": started_at(run),
        "step": step,
        "order": order,
        "pillar": pillar,
        "state": state,
        "version": __version__,
        "pod": pod or os.environ.get("HOSTNAME", ""),
    }
    if state == "running":
        out["started_at"] = moment
    else:
        out["ended_at"] = moment
        if code is not None:
            out["code"] = code
        if seconds is not None:
            out["seconds"] = round(seconds, 1)
        counted = outputs(output)
        if counted is not None:
            out["outputs"] = counted
    return out


def write(directory: str | Path, entry: dict[str, Any]) -> Path:
    """The record on the working volume, one file per step: what the chain did, even if no push got
    through. Merged with what `start` wrote, so the end record keeps the start moment."""
    folder = Path(directory)
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / f"{entry['order']:02d}-{entry['step']}.json"
    merged = {**(load(path) or {}), **entry}
    tmp = path.with_name(f".{path.name}.tmp")
    tmp.write_text(json.dumps(merged, ensure_ascii=False), encoding="utf-8")
    os.replace(tmp, path)
    return path


def load(path: str | Path) -> dict[str, Any] | None:
    try:
        data = json.loads(Path(path).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    return data if isinstance(data, dict) else None


def push(url: str, tenant: str, token: str, entry: dict[str, Any], timeout: float = TIMEOUT) -> str:
    """The record to the decision service; the reason it did not get through, or an empty string.

    The service is in the tenant's namespace: no proxy, whatever HTTPS_PROXY says for the way out.
    """
    target = f"{url.rstrip('/')}/v1/tenants/{tenant}/progress"
    body = json.dumps(entry).encode("utf-8")
    request = urllib.request.Request(  # noqa: S310 - http:// inside the namespace, from the chart
        target,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {token}",
            "User-Agent": f"ngvm-progress/{__version__}",
        },
    )
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    try:
        with opener.open(request, timeout=timeout) as answer:
            if answer.status not in (200, 202):
                return f"the decision service answered {answer.status}"
    except urllib.error.HTTPError as exc:
        return f"the decision service answered {exc.code}"
    except (urllib.error.URLError, OSError, ValueError) as exc:
        return f"the decision service cannot be reached ({exc})"
    return ""


def _secret(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8").strip()
    except OSError:
        return ""


def main(argv: list[str] | None = None) -> int:
    """Always 0: a step never fails because its progress could not be recorded."""
    parser = argparse.ArgumentParser(prog="python -m ngvm.progress", description="where a step of the run is")
    parser.add_argument("state", choices=("start", "end"))
    parser.add_argument("--step", required=True)
    parser.add_argument("--dir", default="/data/progress", help="where the records are kept on the volume")
    parser.add_argument("--run-file", default="/data/.ngvm-run/started", help="the run's id")
    parser.add_argument("--code", type=int, default=0, help="the step's exit code (with end)")
    parser.add_argument("--output", default="", help="what the step wrote: a file or a directory")
    parser.add_argument("--url", default="", help="decision service; nothing pushed without it")
    parser.add_argument("--tenant", default="")
    parser.add_argument("--token-file", default="", help="the publish token of the decision service")
    parser.add_argument("--timeout-seconds", type=float, default=TIMEOUT)
    args = parser.parse_args(argv)

    if not STEP_NAME.match(args.step):
        print(f"  WARN  progress: {args.step!r} is not a step name", file=sys.stderr)
        return 0
    run = run_id(args.run_file)
    ending = args.state == "end"
    entry = record(
        args.step,
        run,
        tenant=args.tenant,
        state=state_of(args.code) if ending else "running",
        code=args.code if ending else None,
        output=args.output or None,
    )
    folder = Path(args.dir)
    if ending:
        before = load(folder / f"{entry['order']:02d}-{entry['step']}.json") or {}
        if before.get("run") == run and before.get("started_at"):
            with contextlib.suppress(ValueError):
                entry["seconds"] = round(
                    (
                        dt.datetime.fromisoformat(entry["ended_at"]) - dt.datetime.fromisoformat(before["started_at"])
                    ).total_seconds(),
                    1,
                )
        elif before.get("run") != run:
            before = {}  # a record of an older run: this run starts the step afresh
        entry = {**before, **entry}
    try:
        write(folder, entry)
    except OSError as exc:
        print(f"  WARN  progress: nothing written on the volume ({exc})", file=sys.stderr)
    if args.url and args.tenant and args.token_file:
        token = _secret(args.token_file)
        if not token:
            print(f"  WARN  progress: {args.token_file} is empty: the step is not shown on the page", file=sys.stderr)
            return 0
        reason = push(args.url, args.tenant, token, entry, args.timeout_seconds)
        if reason:
            print(f"  WARN  progress: {reason}: the step is not shown on the page", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
