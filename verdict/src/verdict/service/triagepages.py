# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The pages of the triage (v0.28.0): the SSVC tree a run walked, the time it took, one decision.

Served by `verdict tools` beside the run and exposure pages, behind the same sign-in, built with the
same pieces (`pages.py`): no script, no image, nothing fetched. The tree is an SVG drawn in the page:
one column per decision point, one box per value with the decisions that took it, and between two
columns a band as wide as the decisions that went from one value to the next. On the page of one
decision, its own path is drawn over the run's.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote, urlencode

from .pages import Safe, badge, card, esc, kpi, shell, span, warn
from .ssvcgraph import COLUMNS, path_of

COL_W, BOX_W, HEIGHT, GAP, MIN_BOX, TOP = 168, 104, 300, 6, 24, 30
LEVEL_CLASS = {"ACT": "open", "ATTEND": "controlled", "TRACK": "small"}
FILL = {"act": "#fde2e1", "attend": "#fdf3d7", "track": "#e2f5e6", "track*": "#e2f5e6"}
OUTCOMES = {
    "cache": "answered by the cache",
    "llm": "answered by the LLM",
    "timeout": "not answered in time",
    "rejected": "answer rejected by the guard",
    "error": "LLM error",
    "budget": "LLM budget reached",
    "stopped": "LLM left aside for the run",
    "not asked": "template (decision not sent to the LLM)",
    "off": "LLM off",
}


def nav(current: str = "") -> str:
    """The links between the analysts' pages, the same on each."""
    items = (("/home", "home"), ("/run", "run"), ("/decision", "decisions"), ("/exposure", "exposure paths"))
    return " · ".join(
        f"<b>{esc(label)}</b>" if href == current else f"<a href='{href}'>{esc(label)}</a>" for href, label in items
    )


def ms(value: Any) -> str:
    """A time in ms as a page writes it: 12 ms, 3.4 s, 9 min 02 s."""
    try:
        v = float(value)
    except (TypeError, ValueError):
        return ""
    if v < 1000:
        return f"{v:.0f} ms"
    if v < 60000:
        return f"{v / 1000:.1f} s"
    return span(v / 1000)


def _fill(point: str, value: str) -> str:
    if point == "delivery_decision":
        return FILL.get(value.lower(), "#f0f0ed")
    if point == "ssvc_decision":
        return FILL.get(value, "#f0f0ed")
    return "#f4f5f7"


def _layout(column: dict[str, Any], total: int) -> list[tuple[dict[str, Any], float, float]]:
    """(value, y, height) of each box of a column, heights after the decisions that took it."""
    values = column["values"]
    room = HEIGHT - GAP * max(0, len(values) - 1)
    heights = [max(MIN_BOX, room * v["count"] / total) if total else MIN_BOX for v in values]
    y, out = float(TOP), []
    for v, h in zip(values, heights, strict=True):
        out.append((v, y, h))
        y += h + GAP
    return out


def svg(graph: dict[str, Any], highlight: list[str] | None = None, link_level: bool = True) -> str:
    """The tree walked by the decisions of `graph` (ssvcgraph.graph); `highlight` one path over it."""
    total = graph.get("decisions") or 0
    columns = graph.get("columns") or []
    if not total or not columns:
        return "<p class='note'>No decision in this run.</p>"
    boxes: dict[tuple[int, str], tuple[float, float, int]] = {}
    height = TOP
    parts: list[str] = []
    for i, column in enumerate(columns):
        x = i * COL_W + 4
        parts.append(
            f"<text x='{x}' y='16' font-size='12' font-weight='600' fill='#1a1a1a'>{esc(column['label'])}</text>"
        )
        for v, y, h in _layout(column, total):
            boxes[(i, v["value"])] = (y, h, v["count"])
            height = max(height, y + h)
    # the bands, under the boxes
    out_used: dict[tuple[int, str], float] = {}
    in_used: dict[tuple[int, str], float] = {}
    index = {c["point"]: i for i, c in enumerate(columns)}
    on_path = set()
    if highlight:
        on_path = {(i, highlight[i], highlight[i + 1]) for i in range(len(highlight) - 1)}
    for link in graph.get("links") or []:
        if not isinstance(link, dict):  # a list cut short for a chat answer says so with a text
            continue
        i, a = index.get(link["from"][0]), link["from"][1]
        j, b = index.get(link["to"][0]), link["to"][1]
        if i is None or j is None or (i, a) not in boxes or (j, b) not in boxes:
            continue
        ya, ha, ca = boxes[(i, a)]
        yb, hb, cb = boxes[(j, b)]
        n = link["count"]
        ta, tb = ha * n / ca, hb * n / cb
        y0 = ya + out_used.get((i, a), 0.0)
        y2 = yb + in_used.get((j, b), 0.0)
        out_used[(i, a)] = out_used.get((i, a), 0.0) + ta
        in_used[(j, b)] = in_used.get((j, b), 0.0) + tb
        x1, x2 = i * COL_W + 4 + BOX_W, j * COL_W + 4
        xm = (x1 + x2) / 2
        lit = (i, a, b) in on_path
        colour, opacity = ("#0b4a8a", "0.75") if lit else ("#9aa5b1", "0.35" if not highlight else "0.18")
        parts.append(
            f"<path d='M{x1:.1f},{y0:.1f} C{xm:.1f},{y0:.1f} {xm:.1f},{y2:.1f} {x2:.1f},{y2:.1f} "
            f"L{x2:.1f},{y2 + tb:.1f} C{xm:.1f},{y2 + tb:.1f} {xm:.1f},{y0 + ta:.1f} {x1:.1f},{y0 + ta:.1f} Z' "
            f"fill='{colour}' fill-opacity='{opacity}'><title>{esc(a)} → {esc(b)}: {n}</title></path>"
        )
    for i, column in enumerate(columns):
        x = i * COL_W + 4
        for v, y, h in _layout(column, total):
            lit = bool(highlight) and highlight[i] == v["value"]
            stroke, width = ("#0b4a8a", 2.5) if lit else ("#9aa5b1", 1)
            title = f"{v['value']}: {v['count']} decision(s), {v['review']} for review, {ms(v['ms'])}"
            box = (
                f"<rect x='{x}' y='{y:.1f}' width='{BOX_W}' height='{h:.1f}' rx='3' "
                f"fill='{_fill(column['point'], v['value'])}' stroke='{stroke}' stroke-width='{width}'>"
                f"<title>{esc(title)}</title></rect>"
                f"<text x='{x + 6}' y='{y + 15:.1f}' font-size='12' font-weight='600' fill='#1a1a1a'>"
                f"{esc(v['value'])}</text>"
            )
            if h >= 38:
                box += (
                    f"<text x='{x + 6}' y='{y + 30:.1f}' font-size='11' fill='#444'>{v['count']}"
                    f"{' · ' + ms(v['ms']) if v.get('ms') else ''}</text>"
                )
            if link_level and column["point"] == "delivery_decision":
                box = f"<a href='/decision?{urlencode({'level': v['value']})}'>{box}</a>"
            parts.append(box)
    width = len(columns) * COL_W
    return (
        "<div class='drawing'>"
        f"<svg class='graph' viewBox='0 0 {width} {height + 8:.0f}' width='100%' height='{height + 8:.0f}' "
        f"role='img' aria-label='SSVC tree walked by the decisions'>{''.join(parts)}</svg></div>"
    )


def paths_table(graph: dict[str, Any]) -> str:
    rows = "".join(
        "<tr>"
        + "".join(f"<td>{esc(v)}</td>" for v in p["path"])
        + f"<td class='v'>{p['count']}</td><td class='v'>{p['review']}</td><td class='v'>{ms(p['ms'])}</td></tr>"
        for p in graph.get("paths") or []
    )
    if not rows:
        return ""
    head = "".join(f"<th>{esc(label)}</th>" for _p, label, _v in COLUMNS)
    more = graph.get("paths_total", 0) - len(graph.get("paths") or [])
    return f"<table class='list'><tr>{head}<th>Decisions</th><th>For review</th><th>Time</th></tr>{rows}</table>" + (
        f"<p class='note'>and {more} path(s) taken less often</p>" if more > 0 else ""
    )


def time_cards(timing: dict[str, Any]) -> str:
    """Where the triage time went, in three cards."""
    phases = timing.get("phases") or {}
    llm = timing.get("llm") or {}
    totals = timing.get("totals_ms") or {}
    step = kpi(
        [
            ("The step, reading to writing", span(timing.get("step_seconds"))),
            ("Deciding", span(timing.get("decide_seconds"))),
            ("of which the decisions", span(phases.get("decisions")) if phases else None),
            ("of which the rationales", span(phases.get("rationales")) if phases else None),
            ("SSVC inputs of the CVEs", ms(totals.get("inputs_ms")) if totals else None),
            ("Decisions on the assets", ms(totals.get("decide_ms")) if totals else None),
            ("Rationales", ms(totals.get("llm_ms")) if totals else None),
        ]
    )
    failed = llm.get("failed_seconds")
    asked = kpi(
        [
            ("Questions", llm.get("questions")),
            ("from the cache", llm.get("from_cache")),
            ("Time of the answers", span(llm.get("seconds")) if llm.get("seconds") is not None else None),
            ("Without an answer", warn(llm["failed"]) if llm.get("failed") else None),
            ("of which not in time", warn(llm["timeouts"]) if llm.get("timeouts") else None),
            ("Time waiting for them", warn(span(failed)) if failed else None),
        ]
    )
    outcomes = "".join(
        f"<tr><td>{esc(OUTCOMES.get(o['outcome'], o['outcome']))}</td><td class='v'>{o['decisions']}</td>"
        f"<td class='v'>{ms(o['ms'])}</td></tr>"
        for o in timing.get("rationales") or []
    )
    rationale = (
        f"<table class='kpi'><tr><td></td><td class='v'>decisions</td><td class='v'>time</td></tr>{outcomes}</table>"
        if outcomes
        else "<p class='note'>nothing to show yet</p>"
    )
    q = timing.get("decide_ms") or {}
    if q:
        rationale += (
            f"<p class='note'>A decision on an asset: {ms(q['p50'])} median, {ms(q['p95'])} for 95 %, "
            f"{ms(q['max'])} at most.</p>"
        )
    out = (
        "<div class='cards'>"
        + card("The triage step", "from the triage's own clock", step)
        + card("The LLM", "every question of the run, answered or not", asked)
        + card("The rationales", "per decision, what its rationale cost", rationale)
        + "</div>"
    )
    slow = timing.get("slowest") or []
    if slow:
        rows = "".join(
            f"<tr><td><a href='/decision?{urlencode({'cve': s['cve'], 'asset': s['asset']})}'>{esc(s['cve'])}</a></td>"
            f"<td>{esc(s['asset'])}</td><td class='v'>{ms(s.get('ms'))}</td><td class='v'>{ms(s.get('inputs_ms'))}</td>"
            f"<td class='v'>{ms(s.get('decide_ms'))}</td><td class='v'>{ms(s.get('llm_ms'))}</td>"
            f"<td>{esc(OUTCOMES.get(s.get('llm', ''), s.get('llm', '')))}</td></tr>"
            for s in slow
        )
        out += (
            "<h3>The decisions that cost most</h3><table class='list'><tr><th>CVE</th><th>Asset</th><th>All</th>"
            f"<th>SSVC inputs</th><th>Decision</th><th>Rationale</th><th></th></tr>{rows}</table>"
        )
    if timing.get("note"):
        out += f"<p class='note'>{esc(timing['note'])}</p>"
    return out


def run_section(data: dict[str, Any]) -> str:
    """The part of the run page about the triage: the tree walked and the time it took."""
    if not data:
        return ""
    if data.get("state"):
        return f"<h2>The triage, decision by decision</h2><p class='note'>{esc(data['state'])}</p>"
    return (
        "<h2>The triage, decision by decision</h2>"
        "<p class='note'>Each decision goes through the same points of the SSVC tree (CISA Coordinator) before "
        "its delivery decision; a band is as wide as the decisions that went that way. A box of the last column "
        "lists its decisions.</p>"
        + svg(data)
        + "<h3>The paths taken most</h3>"
        + paths_table(data)
        + "<h2>Where the triage time went</h2>"
        + time_cards(data.get("timing") or {})
    )


# -- the page of one decision, and the search --------------------------------------------------------
def _assessed(label: str, a: Any) -> str:
    if not isinstance(a, dict):
        return f"<tr><td>{esc(label)}</td><td class='v'>{esc(a)}</td><td></td></tr>"
    source = a.get("source", "")
    note = a.get("note", "")
    kind = "estimated" if source in ("cvss-heuristic", "llm", "default", "references") else ""
    return (
        f"<tr><td>{esc(label)}</td><td class='v'>{esc(a.get('value'))}</td>"
        f"<td>{esc(source)}{' — ' + esc(note) if note else ''}"
        f"{' ' + badge('estimated', 'controlled') if kind else ''}</td></tr>"
    )


def _decision(d: dict[str, Any], graph: dict[str, Any]) -> str:
    level = d.get("delivery_decision", "")
    timing = d.get("timing") or {}
    exposure = d.get("exposure") or ("open" if d.get("publicly_exposed") else "")
    inputs = (
        "<table class='list'><tr><th>Point</th><th>Value</th><th>From</th></tr>"
        + _assessed("Exploitation", d.get("exploitation"))
        + _assessed("Automatable", d.get("automatable"))
        + _assessed("Technical impact", d.get("technical_impact"))
        + _assessed("Mission & well-being", d.get("mission_wellbeing"))
        + f"<tr><td>Exposure</td><td class='v'>{esc(exposure)}</td><td>{esc(d.get('exposure_source'))}</td></tr>"
        + "</table>"
    )
    facts = kpi(
        [
            ("SSVC outcome (CISA Coordinator)", d.get("ssvc_decision")),
            ("BOD 26-04 timeline", d.get("bod_timeline")),
            ("Due", d.get("due_date")),
            ("In KEV", "yes" if d.get("in_kev") else "no"),
            ("EPSS", f"{d['epss']:.3f}" if isinstance(d.get("epss"), (int, float)) else None),
            ("CVSS", (d.get("cvss") or {}).get("score") if isinstance(d.get("cvss"), dict) else None),
            ("Priority", (d.get("sla") or {}).get("priority")),
        ]
    )
    reasons = "".join(f"<li>{esc(r)}</li>" for r in d.get("reasons") or [])
    review = "".join(f"<li>{esc(r)}</li>" for r in d.get("review_reasons") or [])
    spent = kpi(
        [
            ("SSVC inputs of the CVE", ms(timing.get("inputs_ms")) if timing else None),
            ("Decision on the asset", ms(timing.get("decide_ms")) if timing else None),
            ("Rationale of its CVE", ms(timing.get("llm_ms")) if timing else None),
            ("Rationale from", OUTCOMES.get(timing.get("llm", ""), timing.get("llm")) if timing else None),
        ]
    )
    if not timing:
        spent = "<p class='note'>This run was made before v0.28.0: its decisions carry no time.</p>"
    return (
        f"<h2>{esc(d.get('cve_id'))} on {esc(d.get('asset_id'))} {badge(level, LEVEL_CLASS.get(level, ''))}"
        f"{' ' + badge('for review', 'controlled') if d.get('needs_review') else ''}</h2>"
        f"<p class='note'>{esc(d.get('asset_description'))}</p>"
        "<h3>Its path through the SSVC tree, over the run's</h3>"
        + svg(graph, path_of(d), link_level=False)
        + "<div class='cards'>"
        + card("The inputs", "each value and where it comes from", inputs, grow="2 1 520px")
        + card("The decision", "", facts)
        + "</div><div class='cards'>"
        + card("Why", "the delivery decision from the SSVC outcome", f"<ul>{reasons}</ul>" if reasons else "")
        + card("For review because", "", f"<ul>{review}</ul>" if review else "<p class='note'>not for review</p>")
        + card("What it cost", "", spent)
        + "</div>"
        + f"<h3>Rationale</h3><p>{esc(d.get('rationale'))}</p>"
        f"<p class='note'>{esc(d.get('rationale_source'))}</p>"
        + (f"<h3>The CVE</h3><p class='note'>{esc(d.get('description'))}</p>" if d.get("description") else "")
    )


def _form(query: dict[str, str]) -> str:
    def field(name: str, label: str, size: int) -> str:
        return (
            f"<label>{esc(label)} <input name='{name}' size='{size}' maxlength='200' "
            f"value='{esc(query.get(name, ''))}'></label> "
        )

    levels = "".join(
        f"<option{' selected' if query.get('level') == lv else ''}>{lv}</option>"
        for lv in ("", "ACT", "ATTEND", "TRACK")
    )
    return (
        "<form method='get' action='/decision' class='card'>"
        + field("cve", "CVE", 18)
        + field("asset", "Asset", 22)
        + field("q", "Text", 22)
        + f"<label>Decision <select name='level'>{levels}</select></label> "
        "<button type='submit'>Search</button></form>"
    )


def decision_page(data: dict[str, Any]) -> str:
    """One decision with its path, or the decisions a search found, or the search alone."""
    tenant = esc(data.get("tenant", ""))
    query = data.get("query") or {}
    head = f"<b>NGVM decisions — {tenant}</b><span>{nav('/decision')}</span>"
    body = "<h2>Find a decision</h2>" + _form(query)
    if data.get("decision"):
        body += _decision(data["decision"], data.get("graph") or {})
    elif "items" in data:
        items = data["items"]
        rows = "".join(
            f"<tr><td>{badge(i.get('level', ''), LEVEL_CLASS.get(i.get('level', ''), ''))}</td>"
            f"<td><a href='/decision?{urlencode({'id': i['id']})}'>{esc(i.get('cve'))}</a></td>"
            f"<td>{esc(i.get('asset'))}</td><td>{esc(i.get('title'))}</td>"
            f"<td>{'yes' if i.get('needs_review') else ''}</td></tr>"
            for i in items
        )
        total = data.get("total", len(items))
        body += (
            f"<h2>{total} decision(s)</h2>"
            + (
                "<table class='list'><tr><th></th><th>CVE</th><th>Asset</th><th>What</th><th>For review</th></tr>"
                f"{rows}</table>"
                if rows
                else "<p class='note'>No decision of the last run matches.</p>"
            )
            + (f"<p class='note'>the first {len(items)} shown; narrow the search</p>" if total > len(items) else "")
        )
    elif data.get("not_found"):
        body += f"<p class='note'>{esc(data['not_found'])}</p>"
    footer = Safe("The decisions of the last run, from the decision service; nothing on this page is computed again")
    return shell(f"NGVM decisions — {tenant}", head, body, footer)


# -- the central page -----------------------------------------------------------------------------------
def home_page(data: dict[str, Any]) -> str:
    """One page to reach the others (v0.28.0): the run, the decisions, the exposure, the dashboards, the chat."""
    tenant = esc(data.get("tenant", ""))
    run = data.get("run") or {}
    summary = data.get("summary") or {}
    findings = summary.get("findings") or {}
    head = f"<b>NGVM — {tenant}</b><span>{nav('/home')} · times in UTC</span>"

    def tile(title: str, href: str, note: str, body: str, external: bool = False) -> str:
        target = " rel='noopener noreferrer'" if external else ""
        return card(title, note, body + f"<p><a href='{esc(href)}'{target}>Open</a></p>")

    tiles = [
        tile(
            "The run",
            "/run",
            "the daily chain, step by step, and the time of the triage",
            kpi([("State", run.get("state_text")), ("Started", run.get("started")), ("Next", data.get("next_run"))]),
        ),
        tile(
            "The decisions",
            "/decision",
            "find one by CVE or asset, and its path through the SSVC tree",
            kpi(
                [
                    ("ACT", findings.get("ACT")),
                    ("ATTEND", findings.get("ATTEND")),
                    ("TRACK", findings.get("TRACK")),
                    ("For review", summary.get("needs_review")),
                ]
            ),
        ),
        tile(
            "The exposure paths",
            "/exposure",
            "why an asset is exposed as it is, and where the paths meet",
            kpi([("Assets", summary.get("assets")), ("With a finding", summary.get("assets_with_findings"))]),
        ),
    ]
    watch = data.get("watch") or {}
    if data.get("review_url"):
        tiles.append(
            tile(
                "The watch",
                data["review_url"],
                "the alerts drafted on the CVEs published, to review",
                kpi([("Last passage", watch.get("last_passage")), ("Alerts in 24 h", watch.get("alerts_last_24h"))]),
            )
        )
    for link in data.get("links") or []:
        tiles.append(tile(link["name"], link["url"], link.get("note", ""), "", external=True))
    body = "<div class='cards'>" + "".join(tiles) + "</div>"
    footer = Safe(f"Run <code>{esc(run.get('run', 'none'))}</code> · the numbers come from the services that own them")
    return shell(f"NGVM — {tenant}", head, body, footer)


def decision_href(rid: str) -> str:
    return "/decision?id=" + quote(rid, safe="")
