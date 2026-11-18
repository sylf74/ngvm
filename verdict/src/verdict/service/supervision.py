# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The supervision page of a tenant's run (v0.26.2): the four pillars in the order they run, with
the state of each step and the numbers worth watching.

Served by `verdict tools` on `/run`, reached through the review page's oauth2-proxy, which signs the
analyst in with the tenant's identity provider; the NetworkPolicy lets only the proxy and the chat
reach this port. The page holds no state of its own: it reads the chain of steps from the decision
service and the numbers from the services that own them (`Tools._progress_data`), and shows them.
Its look and its shell come from `pages.py`: style and text only, no script.

A page is not a dashboard: it answers "where is the run, and is each pillar healthy", and names what
to open when the answer is no (the pod and container of a step, the review page for the alerts).
"""

from __future__ import annotations

import html
from typing import Any

from . import triagepages
from .pages import CSP, Safe, badge, card, esc, kpi, moment, shell, size, span, warn

__all__ = ["CSP", "REFRESH", "page"]

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
        f"<div class='step {esc(step.get('pillar', 'other'))}'>"
        f"<b>{esc(step.get('step', ''))}</b>"
        f"{badge(STATE_TEXT.get(state, state), state)}"
        f"<div class='num'>{esc(' · '.join(n for n in numbers if n)) or '—'}</div>"
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
        ("Sources failing", warn(len(failing)) if failing else 0),
    ]
    extra = ""
    if failing:
        names = ", ".join(f"{f.get('source')} ({f.get('failed_passages_in_a_row')} passages)" for f in failing[:6])
        extra = f"<p class='note warn'>{html.escape(names)}</p>"
    if p.get("state"):
        extra += f"<p class='note'>{esc(p['state'])}</p>"
    return kpi(rows) + extra


def _detection(p: dict[str, Any]) -> str:
    late = p.get("late_or_refused") or []
    coverage = p.get("coverage") or {}
    share = coverage.get("covered_share")
    rows: list[tuple[str, Any] | None] = [
        ("Assets of the run", p.get("assets")),
        ("Assets with findings", p.get("assets_with_findings")),
        ("Scanned / known assets", f"{share * 100:.0f} %" if isinstance(share, (int, float)) else None),
        ("Collectors", p.get("collectors")),
        ("Late or refused", warn(len(late)) if late else 0),
    ]
    extra = ""
    if late:
        names = ", ".join(f"{x.get('collector')}/{x.get('source')}" for x in late[:8])
        extra = f"<p class='note warn'>{html.escape(names)}</p>"
    return kpi(rows) + extra


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
        # v0.28.0: the keys of llm_usage (questions, from_cache, tokens); the page read others
        ("LLM questions", llm.get("questions", llm.get("calls")) if llm else None),
        ("from the cache", llm.get("from_cache", llm.get("cached")) if llm else None),
        ("LLM tokens", _tokens(llm) if llm else None),
        ("LLM questions without an answer", warn(llm["failed"]) if llm.get("failed") else None),
    ]
    sla = p.get("sla") or {}
    overdue = sla.get("overdue") if isinstance(sla, dict) else None
    if overdue:
        rows.append(("Past the client's SLA", warn(overdue)))
    return kpi(rows)


def _tokens(llm: dict[str, Any]) -> int | None:
    if "prompt_tokens" in llm or "completion_tokens" in llm:
        return int(llm.get("prompt_tokens") or 0) + int(llm.get("completion_tokens") or 0)
    return llm.get("tokens")


def _dispatch(p: dict[str, Any]) -> str:
    by_state = p.get("by_state") or {}
    rows: list[tuple[str, Any] | None] = [
        ("Tickets", p.get("tickets")),
        ("Open", by_state.get("open", by_state.get("sent"))),
        ("Resolved", by_state.get("resolved", by_state.get("closed"))),
        ("With a reference in the ITSM", p.get("with_itsm_ref")),
        ("Waiting for a validator", p.get("pending_requests")),
    ]
    extra = f"<p class='note'>{esc(p['state'])}</p>" if p.get("state") else ""
    return kpi(rows) + extra


BLOCKS = {"watch": _watch, "detection": _detection, "triage": _triage, "dispatch": _dispatch}


def _agents(data: dict[str, Any]) -> str:
    """The agents that run beside the chain: the shared intelligence service and the collectors."""
    agents = data.get("agents") or {}
    collectors = agents.get("collectors") or []
    rows = "".join(
        f"<tr><td>{esc(c.get('collector'))}</td><td>{esc(c.get('source'))}</td>"
        f"<td>{moment(c.get('last_push'))}</td>"
        f"<td>{esc(c.get('age_hours'))}</td>"
        f"<td>{badge('late', 'failed') if c.get('stale') else ''}"
        f"{warn(str(c.get('last_error'))[:120]) if c.get('last_error') else ''}</td></tr>"
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
    radar = kpi(
        [
            ("Shared intelligence", agents.get("shared_intelligence")),
            ("Volume used", warn(f"{used} %") if volume.get("alert") else f"{used} %") if used is not None else None,
            ("Free", f"{volume.get('free_gb')} GB" if volume.get("free_gb") is not None else None),
            ("Watch service", agents.get("watch")),
            ("Decision service", agents.get("decision")),
            ("Last run made by", agents.get("last_run_version")),
            ("Detection service", agents.get("detection")),
            ("Next daily run", moment(agents.get("next_daily_run")) if agents.get("next_daily_run") else None),
        ]
    )
    return (
        "<h2>Beside the chain</h2><div class='cards'>"
        + card("Permanent agents", "services that run all day", radar)
        + card("Collectors", "what they pushed and how old it was", table, grow="2 1 520px")
        + "</div>"
    )


def page(data: dict[str, Any], review_url: str = "", triage: dict[str, Any] | None = None) -> str:
    """The whole page, from what `Tools._progress_data` gathered; `triage` the SSVC tree the run's
    decisions walked and the time it took (v0.28.0)."""
    tenant = esc(data.get("tenant", ""))
    run = data.get("run") or {}
    pillars = data.get("pillars") or {}
    state = run.get("state", "")
    head = (
        f"<b>NGVM run — {tenant}</b>"
        f"<span>{esc(STATE_TEXT.get(state, state) or 'no run reported yet')}"
        f"{' · run of ' + moment(run.get('run_started_at')) if run.get('run_started_at') else ''}"
        f" · times in UTC · this page refreshes every {REFRESH} s"
        f" · {triagepages.nav('/run')}</span>"
    )
    cards = "".join(card(title, note, BLOCKS[key](pillars.get(key) or {})) for key, title, note in PILLARS)
    pod = next((s.get("pod") for s in reversed(run.get("steps") or []) if s.get("pod")), "")
    logs = (
        f"<p class='note'>The log of a step: <code>kubectl -n ngvm-{tenant} logs {esc(pod)} -c &lt;step&gt;</code></p>"
        if pod
        else ""
    )
    link = f"<p class='note'><a href='{esc(review_url)}'>The alerts to review</a></p>" if review_url else ""
    previous = data.get("previous_run") or {}
    before = previous.get("state", "")
    footer = Safe(
        f"Run <code>{esc(run.get('run', 'none'))}</code>, last reported {moment(run.get('updated_at'))}"
        f"{' · the run before ended ' + esc(STATE_TEXT.get(before, before)) if before else ''}"
        " · the steps come from the decision service, the numbers from the service that owns each of them"
    )
    body = (
        f"<h2>The run, step by step</h2>{_chain(run)}{logs}"
        f"<h2>The four pillars</h2><div class='cards'>{cards}</div>"
        f"{triagepages.run_section(triage or {})}"
        f"{_agents(data)}{link}"
    )
    return shell(f"NGVM run — {tenant}", head, body, footer, refresh=REFRESH)
