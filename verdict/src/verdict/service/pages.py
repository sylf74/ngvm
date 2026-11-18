# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""What the analysts' pages of the tool server are made of (v0.26.3): one look, one shell, no script.

The run page (`supervision.py`, v0.26.2) and the exposure page (`exposure.py`, v0.26.3) are served by
`verdict tools` behind the review page's oauth2-proxy. They are built here so that an analyst moving
from one to the other finds the same page: the same header, the same cards, the same way of writing a
duration, a size or a moment.

Style and text only: no script, no image, no outside font (the CSP below says so), so nothing a
vendor's advisory or a client's asset name can carry will run in an analyst's browser. Everything a
page prints goes through `esc`, except what this module built itself (`Safe`).
"""

from __future__ import annotations

import html
from typing import Any

CSP = (
    "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'; img-src 'none'; "
    "form-action 'self'"
)
STYLE = """
body{font-family:system-ui,-apple-system,Segoe UI,Arial,sans-serif;margin:0;color:#1a1a1a;background:#f7f7f5}
header{background:#1f2933;color:#fff;padding:12px 24px;display:flex;justify-content:space-between;align-items:center}
header b{font-weight:600}header span{font-size:13px;color:#cbd2d9}
header a{color:#cbd2d9}
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
.kpi td.v{text-align:right;font-variant-numeric:tabular-nums;font-weight:600;padding-left:8px;white-space:nowrap}
table.list{border-collapse:collapse;width:100%;background:#fff}
.list th,.list td{border-bottom:1px solid #e3e3e0;padding:6px 8px;text-align:left;font-size:13px}
.list th{background:#eeeeea}
.note{color:#555;font-size:13px}.warn{color:#8a1c14}
code{font-family:ui-monospace,Menlo,Consolas,monospace;font-size:12px;background:#eeeeea;padding:1px 4px}
footer{color:#555;font-size:13px;margin-top:28px;border-top:1px solid #e3e3e0;padding-top:10px}
a{color:#0b4a8a}
.path{display:flex;flex-wrap:wrap;align-items:stretch;gap:0}
.hop{background:#fff;border:1px solid #e3e3e0;border-left:3px solid #9aa5b1;padding:8px 12px;min-width:150px}
.hop.internet{border-left-color:#8a1c14}.hop.zone{border-left-color:#8a5a0b}
.hop.service{border-left-color:#0b4a8a}.hop.host{border-left-color:#1d5b2c}
.hop.image{border-left-color:#1d5b2c}.hop.endpoint{border-left-color:#5b1d4a}
.hop b{display:block;font-size:14px;word-break:break-all}
.hop .num{font-size:12px;color:#555}
.link{align-self:center;padding:0 6px;color:#555;font-size:13px;text-align:center;min-width:64px}
.link b{display:block;font-size:12px;color:#1a1a1a;font-weight:600}
.drawing{background:#fff;border:1px solid #e3e3e0;padding:8px 12px;overflow-x:auto}
svg.graph{display:block;min-width:940px}
svg.graph a:hover rect{stroke-width:2}
.open{background:#fde2e1;color:#8a1c14}.controlled{background:#fdf3d7;color:#7a5600}
.small{background:#e2f5e6;color:#1d5b2c}.assumed{background:#e3e3e0;color:#444}
"""


class Safe(str):
    """A piece of HTML this module or a page built itself: `esc` leaves it as it is."""


def esc(value: Any) -> str:
    return value if isinstance(value, Safe) else html.escape("" if value is None else str(value))


def warn(value: Any) -> Safe:
    return Safe(f"<span class='warn'>{html.escape(str(value))}</span>")


def badge(text: str, kind: str = "") -> Safe:
    return Safe(f"<span class='badge {html.escape(kind)}'>{html.escape(text)}</span>")


def span(seconds: Any) -> str:
    """A duration in words: 48 s, 3 min 20 s, 1 h 04."""
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
    """A moment as a page shows it: 2026-11-15 06:12 (UTC left out, the header says it)."""
    text = esc(value)[:16]
    return text.replace("T", " ") if text else "—"


def day(value: Any) -> str:
    """The day of a moment: 2026-11-15."""
    return esc(value)[:10] or "—"


def kpi(rows: list[tuple[str, Any] | None]) -> str:
    """The numbers of one card; a row with nothing to say (None, empty) is left out."""
    cells = "".join(
        f"<tr><td>{esc(row[0])}</td><td class='v'>{esc(row[1])}</td></tr>"
        for row in rows
        if row and row[1] not in (None, "", [], {})
    )
    return f"<table class='kpi'>{cells}</table>" if cells else "<p class='note'>nothing to show yet</p>"


def card(title: str, note: str, body: str, grow: str = "") -> str:
    style = f" style='flex:{grow}'" if grow else ""
    return (
        f"<div class='card'{style}><h3>{esc(title)}</h3>{f'<p class=note>{esc(note)}</p>' if note else ''}{body}</div>"
    )


def shell(title: str, head: str, body: str, footer: str = "", refresh: int = 0) -> str:
    """The page itself: one document, its style inside, nothing fetched from anywhere."""
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        f"{f'<meta http-equiv=refresh content={refresh}>' if refresh else ''}"
        f"<title>{esc(title)}</title><style>{STYLE}</style></head><body>"
        f"<header>{head}</header><main>{body}"
        f"{f'<footer>{footer}</footer>' if footer else ''}"
        "</main></body></html>"
    )


def message(title: str, head: str, text: str) -> str:
    """A page that says why there is nothing to show: a service out of reach, an asset unknown."""
    return shell(title, head, f"<p class='note'>{esc(text)}</p>")
