# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The supervision page of a tenant's run (v0.26.2): the four pillars in the order they run, with
the state of each step and the numbers worth watching.

Served by `verdict tools` on `/run`, reached through the review page's oauth2-proxy, which signs the
analyst in with the tenant's identity provider; the NetworkPolicy lets only the proxy and the chat
reach this port. The page holds no state of its own: it reads the chain of steps from the decision
service and the numbers from the services that own them (`Tools._progress_data`), and shows them. No
script and no image: style and text only (CSP below), so nothing a vendor's text carries can run.

A page is not a dashboard: it answers "where is the run, and is each pillar healthy", and names what
to open when the answer is no (the pod and container of a step, the review page for the alerts).
"""

from __future__ import annotations

import html
from typing import Any

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; img-src 'none'; "
    "form-action 'none'"
)
LATE = "<span class='badge failed'>late</span> "
REFRESH = 30  # seconds: the page asks for itself again while a run is going on
PILLARS = (
    ("watch", "1 · Watch", "the CVEs published and the alerts drafted"),
    ("detection", "2 · Detection", "what the collectors and the scans found on the assets"),
    ("triage", "3 · Triage", "the decisions of the run and what they cost"),
    ("dispatch", "4 · Dispatch", "the tickets of the remediation and their SLA"),
)
STATE_TEXT = {
    "running": "running",
    "done": "done",
    "partial": "partial",
    "failed": "failed",
    "waiting": "waiting",
}
STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;margin:0;color:#1a1a1a;background:#f7f7f5}
header{background:#1f2933;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
header b{font-weight:600}header span{font-size:13px;color:#cbd2d9}
main{max-width:1180px;margin:0 auto;padding:16px 24px 48px}
h2{margin:28px 0 10px;font-size:17px}
.chain{display:flex;flex-wrap:wrap;gap:8px;align-items:stretch}
.step{background:#fff;border:1px solid #e3e3e0;border-top:3px solid #9aa5b1;padding:8px 12px;min-width:150px;flex:1}
.step.watch{border-top-color:#0b4a8a}.step.detection{border-top-color:#8a5a0b}
.step.triage{border-top-color:#1d5b2c}.step.dispatch{border-top-color:#5b1d4a}
.step b{display:block;font-size:14px}
.step .num{font-size:13px;color:#555}
.badge{display:inline-block;padding:1px 8px;border-radius:10px;font-size:12px;background:#e3e3e0;margin:3px 0}
.done{background:#e2f5e6;color:#1d5b2c}.running{background:#e1effd;color:#0b4a8a}
.partial{background:#fdf3d7;color:#7a5600}.failed{background:#fde2e1;color:#8a1c14}.waiting{color:#666}
.cards{display:flex;flex-wrap:wrap;gap:12px}
.card{background:#fff;border:1px solid #e3e3e0;padding:12px 16px;flex:1 1 260px}
.card h3{margin:0 0 2px;font-size:15px}
.card p.note{margin:0 0 8px}
table.kpi{border-collapse:collapse;width:100%}
.kpi td{border-bottom:1px solid #f0f0ed;padding:3px 0;font-size:14px;vertical-align:top}
.kpi td.v{text-align:right;font-variant-numeric:tabular-nums;font-weight:600;padding-left:8px}
table.list{border-collapse:collapse;width:100%;background:#fff}
.list th,.list td{border-bottom:1px solid #e3e3e0;padding:6px 8px;text-align:left;font-size:13px}
.list th{background:#eeeeea}
.note{color:#555;font-size:13px}.warn{color:#8a1c14}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#eeeeea;padding:1px 4px}
footer{color:#555;font-size:13px;margin-top:28px;border-top:1px solid #e3e3e0;padding-top:10px}
a{color:#0b4a8a}
"""


class Safe(str):
    """A piece of HTML this module built itself: `_kpi` prints it as it is."""


def _e(value: Any) -> str:
    return value if isinstance(value, Safe) else html.escape("" if value is None else str(value))


def span(seconds: Any) -> str:
    """A duration in words: 48s, 3 min 20 s, 1 h 04."""
    try:
        total = int(float(seconds))
    except (TypeError, ValueError):
        return ""
    if total < 60:
        return f"{total} s"
    if total < 3600:
        return f"{total // 60} min {total % 60:02d} s"
    return f"{total // 3600} h {(total % 3600) // 60:02d}"


def size(nbytes: Any) -> str:
    try:
        value = float(nbytes)
    except (TypeError, ValueError):
        return ""
    for unit in ("B", "kB", "MB", "GB"):
        if value < 1024 or unit == "GB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return ""


def moment(value: Any) -> str:
    """A moment as the page shows it: 2026-11-15 06:12 (UTC left out, the header says it)."""
    text = _e(value)[:16]
    return text.replace("T", " ") if text else "—"


def _kpi(rows: list[tuple[str, Any] | None]) -> str:
    """The numbers of one pillar; a row with nothing to say (None, empty) is left out."""
    cells = "".join(
        f"<tr><td>{_e(row[0])}</td><td class='v'>{_e(row[1])}</td></tr>"
        for row in rows
        if row and row[1] not in (None, "", [], {})
    )
    return f"<table class='kpi'>{cells}</table>" if cells else "<p class='note'>nothing to show yet</p>"


def _warn(value: Any) -> Safe:
    return Safe(f"<span class='warn'>{html.escape(str(value))}</span>")


def _step_card(step: dict[str, Any]) -> str:
    state = step.get("state", "waiting")
    numbers = []
    if step.get("seconds") is not None:
        numbers.append(span(step["seconds"]))
    outputs = step.get("outputs") or {}
    if outputs.get("files") is not None:
        numbers.append(f"{outputs['files']} file(s), {size(outputs.get('bytes', 0))}")
    if state == "running" and step.get("started_at"):
        numbers.append(f"since {moment(step['started_at'])}")
    if state == "failed" and step.get("code") is not None:
        numbers.append(f"exit {step['code']}")
    return (
        f"<div class='step {_e(step.get('pillar', 'other'))}'>"
        f"<b>{_e(step.get('step', ''))}</b>"
        f"<span class='badge {_e(state)}'>{_e(STATE_TEXT.get(state, state))}</span>"
        f"<div class='num'>{_e(' · '.join(n for n in numbers if n)) or '—'}</div>"
        "</div>"
    )


def _chain(run: dict[str, Any]) -> str:
    steps = run.get("steps") or []
    if not steps:
        return (
            "<p class='note'>No step has reported yet: either no run has started since this version was "
            "deployed, or the steps cannot reach the decision service (their log says so, with a WARN).</p>"
        )
    return f"<div class='chain'>{''.join(_step_card(s) for s in steps)}</div>"


def _watch(p: dict[str, Any]) -> str:
    failing = p.get("failing_sources") or []
    rows: list[tuple[str, Any] | None] = [
        ("New CVEs in 24 h", p.get("new_cves_24h")),
        ("of which in KEV", p.get("new_cves_kev")),
        ("of which CVSS ≥ 9", p.get("new_cves_critical")),
        ("Alerts drafted in 24 h", p.get("alerts_last_24h")),
        ("Alerts to review", (p.get("alerts_by_status") or {}).get("pending")),
        ("Alerts waiting for translation", (p.get("alerts_by_status") or {}).get("translating")),
        ("Last passage of the watch", moment(p.get("last_passage")) if p.get("last_passage") else None),
        ("Sources failing", _warn(len(failing)) if failing else 0),
    ]
    extra = ""
    if failing:
        names = ", ".join(f"{f.get('source')} ({f.get('failed_passages_in_a_row')} passages)" for f in failing[:6])
        extra = f"<p class='note warn'>{html.escape(names)}</p>"
    if p.get("state"):
        extra += f"<p class='note'>{_e(p['state'])}</p>"
    return _kpi(rows) + extra


def _detection(p: dict[str, Any]) -> str:
    late = p.get("late_or_refused") or []
    coverage = p.get("coverage") or {}
    share = coverage.get("covered_share")
    rows: list[tuple[str, Any] | None] = [
        ("Assets of the run", p.get("assets")),
        ("Assets with findings", p.get("assets_with_findings")),
        ("Scanned / known assets", f"{share * 100:.0f} %" if isinstance(share, (int, float)) else None),
        ("Collectors", p.get("collectors")),
        ("Late or refused", _warn(len(late)) if late else 0),
    ]
    extra = ""
    if late:
        names = ", ".join(f"{x.get('collector')}/{x.get('source')}" for x in late[:8])
        extra = f"<p class='note warn'>{html.escape(names)}</p>"
    return _kpi(rows) + extra


def _triage(p: dict[str, Any]) -> str:
    findings = p.get("findings") or {}
    kev = p.get("kev") or {}
    llm = p.get("llm_usage") or {}
    rows: list[tuple[str, Any] | None] = [
        ("Decisions ACT", findings.get("ACT")),
        ("ATTEND", findings.get("ATTEND")),
        ("TRACK", findings.get("TRACK")),
        ("ACT in KEV", kev.get("ACT")),
        ("Flagged for review", p.get("needs_review")),
        ("CVEs read", p.get("cve_count")),
        ("LLM questions", llm.get("calls") if llm else None),
        ("from the cache", llm.get("cached") if llm else None),
        ("LLM tokens", llm.get("tokens") if llm else None),
    ]
    sla = p.get("sla") or {}
    overdue = sla.get("overdue") if isinstance(sla, dict) else None
    if overdue:
        rows.append(("Past the client's SLA", _warn(overdue)))
    return _kpi(rows)


def _dispatch(p: dict[str, Any]) -> str:
    by_state = p.get("by_state") or {}
    rows: list[tuple[str, Any] | None] = [
        ("Tickets", p.get("tickets")),
        ("Open", by_state.get("open", by_state.get("sent"))),
        ("Resolved", by_state.get("resolved", by_state.get("closed"))),
        ("With a reference in the ITSM", p.get("with_itsm_ref")),
        ("Waiting for a validator", p.get("pending_requests")),
    ]
    extra = f"<p class='note'>{_e(p['state'])}</p>" if p.get("state") else ""
    return _kpi(rows) + extra


BLOCKS = {"watch": _watch, "detection": _detection, "triage": _triage, "dispatch": _dispatch}


def _agents(data: dict[str, Any]) -> str:
    """The agents that run beside the chain: the shared intelligence service and the collectors."""
    agents = data.get("agents") or {}
    collectors = agents.get("collectors") or []
    rows = "".join(
        f"<tr><td>{_e(c.get('collector'))}</td><td>{_e(c.get('source'))}</td>"
        f"<td>{moment(c.get('last_push'))}</td>"
        f"<td>{_e(c.get('age_hours'))}</td>"
        f"<td>{LATE if c.get('stale') else ''}"
        f"{_warn(str(c.get('last_error'))[:120]) if c.get('last_error') else ''}</td></tr>"
        for c in collectors[:40]
    )
    table = (
        "<table class='list'><tr><th>Collector</th><th>Source</th><th>Last push</th><th>Age (h)</th><th></th></tr>"
        f"{rows}</table>"
        if rows
        else "<p class='note'>No collector pushes to this tenant (the run scans by itself).</p>"
    )
    volume = agents.get("shared_intelligence_volume") or {}
    used = volume.get("used_percent")
    radar = _kpi(
        [
            ("Shared intelligence", agents.get("shared_intelligence")),
            ("Volume used", _warn(f"{used} %") if volume.get("alert") else f"{used} %") if used is not None else None,
            ("Free", f"{volume.get('free_gb')} GB" if volume.get("free_gb") is not None else None),
            ("Watch service", agents.get("watch")),
            ("Decision service", agents.get("decision")),
            ("Detection service", agents.get("detection")),
            ("Next daily run", moment(agents.get("next_daily_run")) if agents.get("next_daily_run") else None),
        ]
    )
    return (
        "<h2>Beside the chain</h2><div class='cards'>"
        f"<div class='card'><h3>Permanent agents</h3><p class='note'>services that run all day</p>{radar}</div>"
        f"<div class='card' style='flex:2 1 520px'><h3>Collectors</h3>"
        f"<p class='note'>what they pushed and how old it was</p>{table}</div></div>"
    )


def page(data: dict[str, Any], review_url: str = "") -> str:
    """The whole page, from what `Tools._progress_data` gathered."""
    tenant = _e(data.get("tenant", ""))
    run = data.get("run") or {}
    pillars = data.get("pillars") or {}
    state = run.get("state", "")
    head = (
        f"<b>NGVM run — {tenant}</b>"
        f"<span>{_e(STATE_TEXT.get(state, state) or 'no run reported yet')}"
        f"{' · run of ' + moment(run.get('run_started_at')) if run.get('run_started_at') else ''}"
        f" · times in UTC · this page refreshes every {REFRESH} s</span>"
    )
    cards = "".join(
        f"<div class='card'><h3>{_e(title)}</h3><p class='note'>{_e(note)}</p>"
        f"{BLOCKS[key](pillars.get(key) or {})}</div>"
        for key, title, note in PILLARS
    )
    pod = next((s.get("pod") for s in reversed(run.get("steps") or []) if s.get("pod")), "")
    logs = (
        f"<p class='note'>The log of a step: <code>kubectl -n ngvm-{tenant} logs {_e(pod)} -c &lt;step&gt;</code></p>"
        if pod
        else ""
    )
    link = f"<p class='note'><a href='{_e(review_url)}'>The alerts to review</a></p>" if review_url else ""
    previous = data.get("previous_run") or {}
    footer = (
        f"Run <code>{_e(run.get('run', 'none'))}</code>, last reported {moment(run.get('updated_at'))}"
        f"{' · the run before ended ' + _e(STATE_TEXT.get(previous.get('state', ''), previous.get('state', ''))) if previous.get('state') else ''}"  # noqa: E501
        " · the steps come from the decision service, the numbers from the service that owns each of them"
    )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f'<meta http-equiv="refresh" content="{REFRESH}">'
        f"<title>NGVM run — {tenant}</title><style>{STYLE}</style></head><body>"
        f"<header>{head}</header><main>"
        f"<h2>The run, step by step</h2>{_chain(run)}{logs}"
        f"<h2>The four pillars</h2><div class='cards'>{cards}</div>"
        f"{_agents(data)}{link}"
        f"<footer>{footer}</footer>"
        "</main></body></html>"
    )
