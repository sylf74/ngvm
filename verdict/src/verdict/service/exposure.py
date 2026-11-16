# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The exposure page of a tenant's assets (v0.26.3): why an asset is exposed as it is, drawn.

Since v0.24.0 the exposure of an asset is computed from a path and the path is kept as the proof of
the value: the internet or a zone, a flow, a service, the asset, each step with the source that saw
it and the day it was seen. The chat tells that path in words (`get_exposure_path`); read as a chain
of boxes it takes a second instead of a paragraph, and an analyst sees at once where the chain could
be cut — the same reading the chokepoints will give for a whole client later.

Served by `verdict tools` on `/exposure`, beside the run page and behind the same sign-in. Without
an asset it lists those the run exposes most, open first and most ACT first; with `?asset=<id>` it
draws that asset's path. It computes nothing: the exposures, the paths and their proofs come from
the decision service, which holds the run.
"""

from __future__ import annotations

from typing import Any
from urllib.parse import quote

from .pages import CSP, Safe, badge, card, esc, kpi, moment, shell, warn

__all__ = ["CSP", "page"]

EXPOSURES = ("open", "controlled", "small")
# What each kind of step is, in a few words: an analyst should not have to know the graph's words.
KINDS = {
    "internet": "the internet",
    "zone": "a zone of the client",
    "service": "a service reached on the asset",
    "endpoint": "a published endpoint",
    "host": "the asset itself",
    "image": "a container image",
    "declared": "declared by the client",
    "process": "a process of the asset",
    "component": "a component carried by the asset",
}
WHY = {
    "open": "reached from the internet, or seen off the premises",
    "controlled": "reached from a zone of the client, and not from the internet",
    "small": "reached from a zone that few can enter, on proof",
}


COLUMN_TITLES = ("The way in", "Zones", "What answers", "Assets")
# The drawing carries its own colours, as attributes: an SVG whose look depends on a stylesheet is
# black on black the day a rule is missing (v0.27.1). Fill, then stroke, by kind of node.
COLOURS = {
    "internet": ("#fde2e1", "#8a1c14"),
    "zone": ("#fdf3d7", "#8a5a0b"),
    "service": ("#e1effd", "#0b4a8a"),
    "endpoint": ("#f3e1fd", "#5b1d4a"),
    "declared": ("#f3e1fd", "#5b1d4a"),
    "host": ("#e2f5e6", "#1d5b2c"),
    "image": ("#e2f5e6", "#1d5b2c"),
}
PLAIN = ("#f7f7f5", "#9aa5b1")
INK, FADED = "#1a1a1a", "#555555"
BOX_W, BOX_H, GAP_Y, COL_W, PER_COLUMN = 196, 44, 56, 244, 8
MARGIN_TOP = 34


def _short(text: str, keep: int = 26) -> str:
    return text if len(text) <= keep else text[: keep - 1] + "…"


def _layout(nodes: list[dict[str, Any]]) -> tuple[dict[str, tuple[int, int]], list[list[dict[str, Any]]], int]:
    """Where each node is drawn: its column, then the heaviest first inside the column."""
    columns: list[list[dict[str, Any]]] = [[], [], [], []]
    for node in sorted(nodes, key=lambda n: (-n.get("findings", 0), -n.get("assets", 0), n.get("node", ""))):
        column = node.get("column", 3)
        if isinstance(column, int) and 0 <= column <= 3:
            columns[column].append(node)
    at: dict[str, tuple[int, int]] = {}
    for index, column in enumerate(columns):
        for row, node in enumerate(column[:PER_COLUMN]):
            at[str(node.get("node"))] = (index * COL_W, MARGIN_TOP + row * GAP_Y)
    rows = max((len(c[:PER_COLUMN]) for c in columns), default=0)
    return at, columns, MARGIN_TOP + max(rows, 1) * GAP_Y


def _svg(graph: dict[str, Any], focus: str = "") -> str:
    """The paths that lead to the findings that matter, drawn: the way in on the left, the assets on
    the right, a link as thick as what sits behind it. An SVG written here, no script, no image."""
    nodes = graph.get("nodes") or []
    if not nodes:
        return ""
    at, columns, height = _layout(nodes)
    heaviest = max((e.get("findings", 0) for e in graph.get("edges") or []), default=1) or 1
    links = []
    for edge in graph.get("edges") or []:
        start, end = at.get(str(edge.get("source"))), at.get(str(edge.get("target")))
        if not start or not end:
            continue
        x1, y1 = start[0] + BOX_W, start[1] + BOX_H // 2
        x2, y2 = end[0], end[1] + BOX_H // 2
        width = 1 + 4 * (edge.get("findings", 0) / heaviest)
        told = " · ".join(
            str(part)
            for part in (
                edge.get("via"),
                f"{edge.get('findings', 0)} findings on {edge.get('assets', 0)} asset(s)",
                edge.get("evidence"),
                (edge.get("seen") or "")[:10],
            )
            if part
        )
        links.append(
            f"<path d='M{x1},{y1} C{x1 + COL_W // 3},{y1} {x2 - COL_W // 3},{y2} {x2},{y2}' fill='none' "
            f"stroke='#9aa5b1' stroke-width='{width:.1f}' stroke-opacity='0.55'>"
            f"<title>{esc(told)}</title></path>"
        )
    boxes = []
    for node in nodes:
        spot = at.get(str(node.get("node")))
        if not spot:
            continue
        x, y = spot
        kind = str(node.get("kind", ""))
        ident = str(node.get("node", ""))
        label = str(node.get("label") or ident)
        counts = f"{node.get('findings', 0)} findings · {node.get('assets', 0)} asset(s)"
        fill, stroke = COLOURS.get(kind, PLAIN)
        here = ident == focus
        box = (
            f"<g><title>{esc(label)} — {esc(counts)}</title>"
            f"<rect x='{x}' y='{y}' width='{BOX_W}' height='{BOX_H}' rx='2' fill='{fill}' stroke='{stroke}' "
            f"stroke-width='{3 if here else 1}' class='n-{esc(kind)}'/>"
            f"<text x='{x + 8}' y='{y + 18}' font-size='13' fill='{INK}'>{esc(_short(label))}</text>"
            f"<text x='{x + 8}' y='{y + 34}' font-size='11' fill='{FADED}'>{esc(counts)}</text></g>"
        )
        # Navigation by vertex (v0.27.2): a link, not a script, so the page's CSP stays as it is —
        # an asset leads to its own page, anything else to the neighbourhood centred on it.
        if not here:
            where = (
                f"/exposure?asset={quote(ident, safe='')}"
                if kind in ("host", "image")
                else f"/exposure?node={quote(ident, safe='')}"
            )
            box = f"<a href='{where}'>{box}</a>"
        boxes.append(box)
    titles = "".join(
        f"<text x='{i * COL_W}' y='16' font-size='11' fill='{FADED}'>{esc(title)}</text>"
        for i, title in enumerate(COLUMN_TITLES)
        if columns[i]
    )
    more = "".join(
        f"<text x='{i * COL_W}' y='{height - 14}' font-size='11' fill='{FADED}'>+{len(column) - PER_COLUMN} more</text>"
        for i, column in enumerate(columns)
        if len(column) > PER_COLUMN
    )
    width = 3 * COL_W + BOX_W
    return (
        f"<svg viewBox='0 0 {width} {height}' width='100%' height='{height}' role='img' "
        f"xmlns='http://www.w3.org/2000/svg' class='graph'>{titles}{''.join(links)}{''.join(boxes)}{more}</svg>"
    )


def _chokepoints(graph: dict[str, Any]) -> str:
    """The ranking under the drawing: what to close, and what it would take out of the client's way."""
    items = graph.get("chokepoints") or []
    if not items:
        return (
            "<p class='note'>No path leads to a finding at this level in the latest run: either nothing is "
            "decided ACT, or the exposures rest on assumptions rather than on observed paths.</p>"
        )
    rows = []
    for node in items:
        examples = node.get("examples") or []
        named = ", ".join(esc(name) for name in examples[:6])
        rest = node.get("assets", 0) - len(examples[:6])
        # The table is the way into the drawing (v0.27.2): the heaviest node first, one click to what
        # is behind it. On a client of a few hundred assets no whole graph is readable, so the reading
        # starts here rather than by looking for a box.
        where = f"/exposure?node={quote(str(node.get('node', '')), safe='')}"
        rows.append(
            f"<tr><td><a href='{where}'>{esc(node.get('label'))}</a></td><td>{esc(node.get('kind'))}</td>"
            f"<td>{warn(node.get('findings', 0))}</td><td>{esc(node.get('assets', 0))}</td>"
            f"<td class='note'>{named}{f' and {rest} more' if rest > 0 else ''}</td></tr>"
        )
    kept = len(items)
    total = graph.get("chokepoints_total", kept)
    note = f"<p class='note'>{kept} of {total} shown, the heaviest first.</p>" if total > kept else ""
    return (
        "<table class='list'><tr><th>Chokepoint</th><th>What it is</th><th>Findings behind</th>"
        f"<th>Assets</th><th>Some of them</th></tr>{''.join(rows)}</table>{note}"
    )


def _graph_block(graph: dict[str, Any]) -> str:
    """The drawing and its ranking, with what the run could not prove said plainly."""
    if not graph or graph.get("state"):
        return ""
    level = esc(graph.get("level", "ACT"))
    without = graph.get("assets_without_path", 0)
    counted = kpi(
        [
            (f"Assets with a {level} finding", graph.get("assets_with_findings")),
            (f"{level} findings behind them", graph.get("findings")),
            ("Chokepoints found", graph.get("chokepoints_total")),
            ("Assets with no path (assumed)", warn(without) if without else 0),
        ]
    )
    drawn = _svg(graph)
    picture = (
        f"<div class='drawing'>{Safe(drawn)}</div>"
        if drawn
        else "<p class='note'>Nothing to draw: no observed path leads to a finding at this level.</p>"
    )
    levels = " · ".join(f"<a href='/exposure?level={lv}'>{lv}</a>" for lv in ("ACT", "ATTEND", "TRACK"))
    return (
        f"<h2>Where the ways in meet</h2>"
        f"<p class='note'>Paths to the assets carrying a {level} decision · {Safe(levels)}</p>"
        f"{picture}"
        "<div class='cards'>"
        + card("What is behind them", "", counted)
        + card(
            "What to close first",
            "the findings behind a node, not the node itself",
            _chokepoints(graph),
            "2 1 520px",
        )
        + "</div>"
    )


def _behind(graph: dict[str, Any]) -> str:
    """The assets whose path goes through the node in focus, the heaviest first."""
    found = graph.get("behind") or {}
    rows = "".join(
        f"<tr><td><a href='/exposure?asset={quote(str(a.get('id', '')), safe='')}'>"
        f"{esc(a.get('name') or a.get('id'))}</a></td><td>{warn(a.get('findings', 0))}</td></tr>"
        for a in found.get("assets") or []
    )
    if not rows:
        return "<p class='note'>No asset at this level passes through this node in the latest run.</p>"
    shown, total = len(found.get("assets") or []), found.get("assets_total", 0)
    note = f"<p class='note'>{shown} of {total} shown, the heaviest first.</p>" if total > shown else ""
    return f"<table class='list'><tr><th>Asset</th><th>Findings behind this node</th></tr>{rows}</table>{note}"


def _node_page(graph: dict[str, Any], tenant: str, depth: int) -> tuple[str, str, str]:
    """The page centred on one node: its neighbourhood, and the assets behind it.

    The whole graph of a client of a few hundred assets fits in no page, and zooming into a drawing
    nobody can read does not help: this page draws the node asked for and what is within `depth` hops
    of it, both ways, and says how much of the graph it left out (v0.27.2).
    """
    focus = graph.get("focus") or {}
    ident = str(focus.get("node", ""))
    label = str(focus.get("label") or ident)
    kind = str(focus.get("kind", ""))
    level = esc(graph.get("level", "ACT"))
    behind = graph.get("behind") or {}
    hops = int(graph.get("depth", depth) or depth)
    head = (
        f"<b>Exposure — {esc(label)}</b>"
        f"<span>{esc(KINDS.get(kind, kind))} · {hops} hop(s) around it · {level} findings"
        " · <a href='/exposure'>the whole picture</a> · <a href='/run'>the run</a></span>"
    )
    facts = kpi(
        [
            ("What it is", esc(KINDS.get(kind, kind))),
            (f"{level} findings behind it", warn(focus.get("findings", 0))),
            ("Assets behind it", behind.get("assets_total", focus.get("assets", 0))),
            ("Nodes drawn", f"{len(graph.get('nodes') or [])} of {graph.get('nodes_total', 0)}"),
            ("Node", Safe(f"<code>{esc(ident)}</code>")),
        ]
    )
    reach = " · ".join(f"<a href='/exposure?node={quote(ident, safe='')}&amp;depth={d}'>{d}</a>" for d in (1, 2, 3))
    drawn = _svg(graph, ident)
    picture = (
        f"<div class='drawing'>{Safe(drawn)}</div>"
        if drawn
        else "<p class='note'>Nothing to draw around this node.</p>"
    )
    body = (
        f"<h2>Around this node</h2>"
        f"<p class='note'>Hops drawn: {Safe(reach)} · a box leads to its own neighbourhood, an asset to its page</p>"
        f"{picture}"
        "<div class='cards'>"
        + card("What it carries", "", facts)
        + card(
            "The assets behind it",
            f"their {level} findings would be out of reach if this node were closed",
            _behind(graph),
            "2 1 520px",
        )
        + "</div>"
    )
    footer = Safe(
        "What is drawn is what the run observed, not every way in: a client with two paths to the same "
        "asset sees both, and nothing here says a path is the only one"
    )
    return head, body, footer


def _hop(step: dict[str, Any]) -> str:
    """One step of the path: what this node is."""
    kind = str(step.get("kind", ""))
    return (
        f"<div class='hop {esc(kind)}'><b>{esc(step.get('label') or step.get('node', ''))}</b>"
        f"<div class='num'>{esc(KINDS.get(kind, kind))}</div></div>"
    )


def _crossing(step: dict[str, Any]) -> str:
    """The link into a step: what was crossed to enter it, what saw it and when. A step carries the
    evidence of the edge that leads to it (v0.24.0), so it is written on that link, never beside the
    step before it."""
    lines = []
    if step.get("source"):
        lines.append(f"seen by {step['source']}")
    if step.get("seen"):
        lines.append(moment(step["seen"])[:10])
    via = step.get("via", "")
    told = " · ".join(lines)
    return f"<div class='link'>→{f'<b>{esc(via)}</b>' if via else ''}{f'<div>{esc(told)}</div>' if told else ''}</div>"


def _path(detail: dict[str, Any]) -> str:
    steps = detail.get("path") or []
    if not steps:
        return (
            "<p class='note'>No path: this exposure is an assumption, not a proof. The run takes the worst "
            "case when nothing it collected reaches the asset — a scan of it, a flow declared by the client, "
            "or a sighting off the premises would settle it.</p>"
        )
    drawn = [_hop(steps[0])]
    for step in steps[1:]:
        drawn.append(_crossing(step))
        drawn.append(_hop(step))
    return f"<div class='path'>{''.join(drawn)}</div>"


def _services(detail: dict[str, Any]) -> str:
    services = detail.get("services") or []
    if not services:
        return "<p class='note'>No service listed on this asset by the collection.</p>"
    rows = "".join(
        f"<tr><td>{esc(s.get('port'))}</td><td>{esc(s.get('protocol') or s.get('view'))}</td>"
        f"<td>{esc(s.get('name') or s.get('product') or '')}</td><td>{esc(s.get('source') or s.get('view'))}</td>"
        f"<td>{moment(s.get('at') or s.get('seen'))[:10]}</td></tr>"
        for s in services[:40]
    )
    return (
        f"<table class='list'><tr><th>Port</th><th>How</th><th>What</th><th>Source</th><th>Seen</th></tr>{rows}</table>"
    )


def _asset_page(detail: dict[str, Any], tenant: str, gaps: list[dict[str, Any]]) -> tuple[str, str, str]:
    """The page of one asset: its path, what it serves, and the gaps that concern it."""
    asset = str(detail.get("asset", ""))
    exposure = str(detail.get("exposure", ""))
    assumed = bool(detail.get("assumed"))
    head = (
        f"<b>Exposure — {esc(detail.get('name') or asset)}</b>"
        f"<span>{badge(exposure or 'unknown', 'assumed' if assumed else exposure)}"
        f" · {esc(WHY.get(exposure, ''))} · times in UTC"
        " · <a href='/exposure'>all the assets</a> · <a href='/run'>the run</a></span>"
    )
    mine = [g for g in gaps if g.get("asset") == asset or (not g.get("asset") and g.get("kind") == "no-external-scan")]
    gap_block = ""
    if mine:
        rows = "".join(
            f"<tr><td>{esc(g.get('kind'))}</td><td>{esc(g.get('name'))}</td><td>{esc(g.get('detail'))}</td></tr>"
            for g in mine[:10]
        )
        gap_block = card(
            "Where the client's declaration and the observation differ",
            "an exposure gap is never a silent correction: the observation is kept, the difference is said",
            f"<table class='list'><tr><th>Gap</th><th>Where</th><th>What differs</th></tr>{rows}</table>",
            grow="2 1 520px",
        )
    facts = kpi(
        [
            ("Exposure", badge(exposure or "unknown", "assumed" if assumed else exposure)),
            ("Rests on", "an assumption, nothing proves it" if assumed else esc(detail.get("exposure_source", ""))),
            ("Where the value comes from", detail.get("origin", "")),
            ("Zone", detail.get("zone", "")),
            ("Asset", Safe(f"<code>{esc(asset)}</code>")),
            ("Run", detail.get("run", "")),
        ]
    )
    body = (
        f"<h2>How this asset is reached</h2>{_path(detail)}"
        "<div class='cards'>"
        + card("The value and its proof", "", facts)
        + card("What it serves", "the ports the collection saw on it", _services(detail), grow="2 1 520px")
        + "</div>"
        + (f"<div class='cards'>{gap_block}</div>" if gap_block else "")
    )
    footer = Safe(
        "The path is the proof the run kept for this exposure; in the chat, "
        "« pourquoi web01 est-il exposé ? » gives the same thing in words"
    )
    return head, body, footer


def _list_page(
    assets: list[dict[str, Any]], tenant: str, total: int, chosen: str, graph: str = ""
) -> tuple[str, str, str]:
    """The assets of the run, those the client cannot hide first."""
    head = (
        f"<b>Exposure — {esc(tenant)}</b>"
        f"<span>{esc(len(assets))} of {esc(total)} assets{f' · exposure {esc(chosen)}' if chosen else ''}"
        " · most ACT first · <a href='/run'>the run</a></span>"
    )
    chips = [f"<a href='/exposure?exposure={e}'>{e}</a>" for e in EXPOSURES]
    links = " · ".join([*chips, "<a href='/exposure'>all</a>"])
    rows = "".join(
        f"<tr><td><a href='/exposure?asset={quote(str(a.get('asset', '')), safe='')}'>"
        f"{esc(a.get('name') or a.get('asset'))}</a></td>"
        f"<td>{badge(str(a.get('exposure') or 'unknown'), str(a.get('exposure') or 'assumed'))}</td>"
        f"<td>{esc(a.get('zone') or '')}</td>"
        f"<td>{warn(a['counts']['ACT']) if (a.get('counts') or {}).get('ACT') else 0}</td>"
        f"<td>{esc((a.get('counts') or {}).get('ATTEND', 0))}</td>"
        f"<td>{esc((a.get('origins') or {}).get('exposure', ''))}</td></tr>"
        for a in assets
    )
    table = (
        "<table class='list'><tr><th>Asset</th><th>Exposure</th><th>Zone</th><th>ACT</th><th>ATTEND</th>"
        f"<th>Exposure from</th></tr>{rows}</table>"
        if rows
        else "<p class='note'>No asset in the latest run.</p>"
    )
    body = f"{graph}<h2>The assets of the run</h2><p class='note'>{Safe(links)}</p>{table}"
    footer = Safe(
        "An exposure from <code>assumed</code> is the worst case taken for want of proof, not a measure: "
        "a scan of the asset or a flow declared by the client settles it"
    )
    return head, body, footer


def page(data: dict[str, Any]) -> str:
    """The exposure page, from what `Tools._exposure_data` gathered: one asset, or the list."""
    tenant = str(data.get("tenant", ""))
    detail = data.get("asset") or {}
    if data.get("not_found"):
        head = (
            f"<b>Exposure — {esc(tenant)}</b><span>asset not in the latest run"
            " · <a href='/exposure'>all the assets</a></span>"
        )
        body = (
            f"<p class='note'>The latest run knows no asset called <code>{esc(data['not_found'])}</code>. "
            "It may have been scanned under another name, or not scanned at all.</p>"
        )
        return shell(f"Exposure — {tenant}", head, body)
    if data.get("node"):  # v0.27.2: the neighbourhood of one node
        graph = data.get("graph") or {}
        asked = str(data["node"])
        if graph.get("state") or not graph:
            head = (
                f"<b>Exposure — {esc(tenant)}</b><span>the decision service did not answer"
                " · <a href='/exposure'>all the assets</a></span>"
            )
            body = (
                f"<p class='note'>The graph could not be read: {esc(graph.get('state', 'no answer'))}. "
                "The paths themselves are on each asset's page.</p>"
            )
            return shell(f"Exposure — {tenant}", head, body)
        if graph.get("focus_unknown") or not graph.get("focus"):
            head = (
                f"<b>Exposure — {esc(tenant)}</b><span>node not in the latest run"
                " · <a href='/exposure'>the whole picture</a></span>"
            )
            body = (
                f"<p class='note'>No observed path of the latest run goes through "
                f"<code>{esc(asked)}</code>. A node is named by the run that saw it, so a link kept from "
                "an earlier run may point at something this one no longer observes — or the level asked "
                "for has no finding behind it.</p>"
            )
            return shell(f"Exposure — {tenant}", head, body)
        head, body, footer = _node_page(graph, tenant, int(data.get("depth") or 2))
        return shell(f"Exposure — {graph['focus'].get('label') or asked}", head, body, footer)
    if detail:
        head, body, footer = _asset_page(detail, tenant, data.get("exposure_gaps") or [])
        title = f"Exposure — {detail.get('name') or detail.get('asset', '')}"
    else:
        head, body, footer = _list_page(
            data.get("assets") or [],
            tenant,
            int(data.get("total") or 0),
            str(data.get("exposure") or ""),
            _graph_block(data.get("graph") or {}),
        )
        title = f"Exposure — {tenant}"
    return shell(title, head, body, footer)
