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


def _hop(step: dict[str, Any], last: bool) -> str:
    """One step of the path, and the link to the next: what was crossed, who saw it, when."""
    kind = str(step.get("kind", ""))
    seen = step.get("seen", "")
    lines = [KINDS.get(kind, kind)]
    if step.get("source"):
        lines.append(f"seen by {step['source']}")
    if seen:
        lines.append(moment(seen)[:10])
    box = (
        f"<div class='hop {esc(kind)}'><b>{esc(step.get('label') or step.get('node', ''))}</b>"
        f"<div class='num'>{esc(' · '.join(line for line in lines if line))}</div></div>"
    )
    if last:
        return box
    via = step.get("via", "")
    return box + f"<div class='link'>→{f'<b>{esc(via)}</b>' if via else ''}</div>"


def _path(detail: dict[str, Any]) -> str:
    steps = detail.get("path") or []
    if not steps:
        return (
            "<p class='note'>No path: this exposure is an assumption, not a proof. The run takes the worst "
            "case when nothing it collected reaches the asset — a scan of it, a flow declared by the client, "
            "or a sighting off the premises would settle it.</p>"
        )
    hops = "".join(_hop(step, n == len(steps) - 1) for n, step in enumerate(steps))
    return f"<div class='path'>{hops}</div>"


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


def _list_page(assets: list[dict[str, Any]], tenant: str, total: int, chosen: str) -> tuple[str, str, str]:
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
    body = f"<h2>The assets of the run</h2><p class='note'>{Safe(links)}</p>{table}"
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
    if detail:
        head, body, footer = _asset_page(detail, tenant, data.get("exposure_gaps") or [])
        title = f"Exposure — {detail.get('name') or detail.get('asset', '')}"
    else:
        head, body, footer = _list_page(
            data.get("assets") or [], tenant, int(data.get("total") or 0), str(data.get("exposure") or "")
        )
        title = f"Exposure — {tenant}"
    return shell(title, head, body, footer)
