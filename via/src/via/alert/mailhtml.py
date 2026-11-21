# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The HTML body of an alert mail (v0.29.0), laid out from the sheet's Markdown.

The sheet is Markdown (`# title`, `## section`), the reference an analyst may edit and translate;
the mail is laid out from it, so an edited or translated sheet gets the same layout. Sections are
known by the catalogue's heading keys, in any language of the catalogue; a heading outside it is
shown as a plain card.

Mail clients keep inline styles only and Outlook lays out tables, not flex boxes: a centred table of
680 px, one row per section. Colours are fixed (no reliance on the client's dark mode); white text
sits on colours with a contrast of 4.5:1 at least. Outlook for Windows draws no rounded corners: the
blocks are square there. The sent mail names no product: the sender is the client's watch.
"""

from __future__ import annotations

import html
import re
from typing import Any

from .fiche import _inline, kind_reason
from .i18n import heading_key, t

WIDTH = 680
FONT = "'Segoe UI',Helvetica,Arial,sans-serif"
INK, MUTED, LINE, PAPER, SOFT = "#1f2933", "#52606d", "#e4e7eb", "#ffffff", "#f5f7fa"
CVE_BLOCK = "#3b5b7a"  # slate blue; white text 7:1
KIND_COLOURS = {  # band (light tint), its edge, the tag (white text)
    "alerte": ("#f8e4e2", "#efc9c5", "#b42318"),
    "hot_topic": ("#fdeee3", "#f6d5bd", "#c2410c"),
    "information": ("#e6eef7", "#c9d8ea", "#1d5fa8"),
}
CHARACTERISTICS = ("h.product", "h.type", "h.cvss", "h.impact")
LINK = re.compile(r"\[([^\]]+)\]\((https?://[^)\s]+)\)")
_YES = ("yes", "oui", "ja", "sí", "si", "sim")
_AVAILABLE = ("available", "disponible", "verfügbar")


def kind_of_entry(entry: dict[str, Any]) -> str:
    kind = (entry.get("kind") or {}).get("kind") if isinstance(entry.get("kind"), dict) else entry.get("kind")
    if kind in KIND_COLOURS:
        return kind
    return "alerte" if entry.get("level") == "urgent" else "information"


def parse(text: str) -> tuple[str, list[tuple[str, str, list[str]]]]:
    """(title, [(heading key or "", heading, lines)]) of a sheet in the watch's Markdown."""
    title, sections, current = "", [], None
    for line in text.splitlines():
        if line.startswith("# ") and not title:
            title = line[2:].strip()
        elif line.startswith("## "):
            heading = line[3:].strip()
            current = (heading_key(heading) or "", heading, [])
            sections.append(current)
        elif line.strip():
            if current is None:
                current = ("", "", [])
                sections.append(current)
            current[2].append(line.rstrip())
    return title, sections


def headline(title: str) -> str:
    """The title without its `[KIND]` prefix."""
    return re.sub(r"^\[[^\]]+\]\s*", "", title)


def subject(text: str, entry: dict[str, Any], lang: str = "en", fallback: str = "") -> str:
    """`[Alert] <title>`: the kind as the client reads it, then the title."""
    title = next((line[2:].strip() for line in text.splitlines() if line.startswith("# ")), fallback)
    return f"[{t(lang, 'kind.subject.' + kind_of_entry(entry))}] {headline(title)}"


# -- the blocks -------------------------------------------------------------------------------------
def _bullet(line: str) -> str:
    return line[2:] if line.startswith("- ") else line


def _card(heading: str, inner: str) -> str:
    return (
        f'<tr><td style="padding:24px 32px 0 32px">'
        f'<h2 style="margin:0 0 10px 0;font-size:16px;line-height:1.3;color:{INK};font-family:{FONT}">'
        f"{html.escape(heading)}</h2>{inner}</td></tr>"
    )


def _paragraphs(lines: list[str]) -> str:
    out, items = [], []
    for line in lines:
        if line.startswith("- "):
            items.append(f'<li style="margin:0 0 4px 0">{_inline(line[2:])}</li>')
            continue
        if items:
            out.append(f'<ul style="margin:0 0 8px 0;padding-left:20px">{"".join(items)}</ul>')
            items = []
        if line.startswith("|"):
            continue  # tables: _table
        out.append(f'<p style="margin:0 0 8px 0">{_inline(line)}</p>')
    if items:
        out.append(f'<ul style="margin:0 0 8px 0;padding-left:20px">{"".join(items)}</ul>')
    style = f"font-size:14px;line-height:1.6;color:#323f4b;font-family:{FONT}"
    return f'<div style="{style}">{"".join(out)}</div>'


def _table(lines: list[str]) -> str:
    rows = []
    for line in lines:
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if not all(set(c) <= set("-: ") for c in cells):
            rows.append(cells)
    if not rows:
        return ""
    head = "".join(
        f'<th align="left" style="padding:10px 12px;background:{SOFT};color:{MUTED};font-size:12px;'
        f'font-weight:600;text-transform:uppercase;letter-spacing:0.04em;border-bottom:1px solid {LINE}">'
        f"{_inline(c)}</th>"
        for c in rows[0]
    )
    body = "".join(
        "<tr>"
        + "".join(
            f'<td style="padding:10px 12px;border-top:1px solid {LINE};font-size:14px;color:{INK}">{_inline(c)}</td>'
            for c in r
        )
        + "</tr>"
        for r in rows[1:]
    )
    return (
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:separate;'
        f'border:1px solid #d9e2ec;border-radius:10px;font-family:{FONT}"><tr>{head}</tr>{body}</table>'
    )


def _sources(heading: str, lines: list[str]) -> str:
    """The CVE block: the CVEs with their pills, then the chronology of the sources."""
    cves, events = [], []
    for raw in lines:
        line = _bullet(raw)
        parts = line.split(" · ")
        if re.match(r"^CVE-\d{4}-\d+", line) and len(parts) > 1:
            pills = "".join(
                '<span style="display:inline-block;background:#4d6b88;border-radius:999px;padding:3px 10px;'
                f'margin:0 6px 4px 0;font-size:13px;color:#ffffff">{html.escape(p)}</span>'
                for p in parts[1:]
            )
            cves.append(
                f'<tr><td style="padding:0 0 10px 0"><span style="font-size:20px;font-weight:700;color:#ffffff;'
                f'margin-right:10px">{html.escape(parts[0])}</span>{pills}</td></tr>'
            )
            continue
        when, _, rest = line.partition(" — ")
        if not rest:
            when, rest = "", line
        rest = LINK.sub(r'<a href="\2" style="color:#ffffff;text-decoration:underline">\1</a>', html.escape(rest))
        rest = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", rest).replace(" — ", " · ")
        events.append(
            '<tr><td valign="top" style="padding:9px 14px 9px 0;width:170px;font-size:13px;color:#dbe4ee;'
            f'border-top:1px solid #56728e">{html.escape(when)}</td>'
            f'<td valign="top" style="padding:9px 0;font-size:14px;color:#ffffff;border-top:1px solid #56728e">'
            f"{rest}</td></tr>"
        )
    inner = (
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation">{"".join(cves)}</table>'
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation">{"".join(events)}</table>'
    )
    return (
        '<tr><td style="padding:24px 32px 0 32px">'
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation" bgcolor="{CVE_BLOCK}" '
        f'style="background:{CVE_BLOCK};border-radius:14px;font-family:{FONT}"><tr><td style="padding:20px 24px">'
        f'<div style="font-size:12px;font-weight:700;letter-spacing:0.1em;color:#dbe4ee;margin:0 0 12px 0">'
        f"{html.escape(heading.upper())}</div>{inner}</td></tr></table></td></tr>"
    )


def _characteristics(lang: str, rows: list[tuple[str, list[str]]]) -> str:
    body = "".join(
        f'<tr><td valign="top" style="width:170px;padding:10px 12px;background:{SOFT};color:{MUTED};'
        f'font-size:14px;border-top:1px solid {LINE}">{html.escape(h)}</td>'
        f'<td valign="top" style="padding:10px 12px;font-size:14px;color:{INK};border-top:1px solid {LINE}">'
        + "<br>".join(_inline(_bullet(x)) for x in lines)
        + "</td></tr>"
        for h, lines in rows
    )
    table = (
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="border-collapse:separate;'
        f'border:1px solid #d9e2ec;border-radius:10px;font-family:{FONT};line-height:1.5">{body}</table>'
    )
    return _card(t(lang, "h.characteristics"), table)


def _tile_colours(index: int, value: str) -> tuple[str, str]:
    low = value.strip().lower()
    if index < 2 and low.startswith(_YES):
        return "#fbeaea", "#7a2323"  # exploitation known, public exploit
    if index == 2 and low.startswith(_AVAILABLE):
        return "#e6f4ea", "#1e5631"  # a fix
    return "#f0f2f5", "#3e4c59"


def _exploitation(heading: str, lines: list[str]) -> str:
    tiles = []
    for i, raw in enumerate(lines):
        label, sep, value = _bullet(raw).partition(":")
        if not sep:
            label, value = "", label
        bg, fg = _tile_colours(i, value)
        tiles.append(
            f'<td valign="top" width="50%" style="padding:4px"><div style="background:{bg};border-radius:10px;'
            f'padding:12px 14px"><div style="font-size:12px;color:{fg}">{html.escape(label.strip())}</div>'
            f'<div style="font-size:14px;font-weight:600;color:{fg}">{_inline(value.strip())}</div></div></td>'
        )
    rows = "".join("<tr>" + "".join(tiles[i : i + 2]) + "</tr>" for i in range(0, len(tiles), 2))
    return _card(
        heading,
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="font-family:{FONT}">'
        f"{rows}</table>",
    )


def _delay(heading: str, lines: list[str]) -> str:
    first = _bullet(lines[0]) if lines else ""
    value = re.sub(r"^\*\*(.+)\*\*$", r"\1", first)
    rest = "".join(
        f'<div style="font-size:13px;line-height:1.5;color:#3e4c59;margin-top:4px">{_inline(_bullet(x))}</div>'
        for x in lines[1:]
    )
    return (
        '<tr><td style="padding:24px 32px 0 32px">'
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation" style="background:{SOFT};'
        f'border:1px solid #d9e2ec;border-radius:10px;font-family:{FONT}"><tr><td style="padding:14px 18px">'
        f'<div style="font-size:14px;color:{MUTED}">{html.escape(heading)}</div>'
        f'<div style="font-size:18px;font-weight:700;color:{INK};margin:4px 0 6px 0">{_inline(value)}</div>'
        f"{rest}</td></tr></table></td></tr>"
    )


def _links(heading: str, lines: list[str]) -> str:
    buttons, items = [], []
    for raw in lines:
        line = _bullet(raw)
        found = LINK.search(line)
        if found and len(buttons) < 2 and not re.match(r"^CVE-\d{4}-\d+", found.group(1)):
            buttons.append(
                f'<a href="{html.escape(found.group(2))}" style="display:inline-block;background:{CVE_BLOCK};'
                f"color:#ffffff;text-decoration:none;border-radius:8px;padding:10px 16px;margin:0 8px 8px 0;"
                f'font-size:14px;font-weight:600">{html.escape(found.group(1))}</a>'
            )
        url = line if line.startswith("http") else ""
        shown = f'<a href="{html.escape(url)}">{html.escape(url)}</a>' if url else _inline(line)
        items.append(f'<li style="margin:0 0 2px 0">{shown}</li>')
    inner = (
        f"<div>{''.join(buttons)}</div>"
        f'<ul style="margin:4px 0 0 0;padding-left:20px;font-size:13px;line-height:1.7;color:{MUTED};'
        f'font-family:{FONT};word-break:break-all">{"".join(items)}</ul>'
    )
    return _card(heading, inner)


# -- the mail ---------------------------------------------------------------------------------------
def render(text: str, entry: dict[str, Any], lang: str = "en", note: str = "") -> str:
    """The HTML body of the mail of `entry` (the alert's index entry) from its sheet `text`;
    `note`: HTML shown before the sheet (the analysts' validation note, never sent to the client)."""
    title, sections = parse(text)
    kind = kind_of_entry(entry)
    band, edge, tag = KIND_COLOURS[kind]
    reason = kind_reason(entry.get("kind") if isinstance(entry.get("kind"), dict) else None, lang)
    meta = " · ".join(x for x in (entry.get("client_name") or "", entry.get("issued_local") or "") if x)
    rows = [
        f'<tr><td bgcolor="{band}" style="background:{band};padding:24px 32px;border-bottom:1px solid {edge};'
        f'border-radius:12px 12px 0 0;font-family:{FONT}">'
        f'<span style="display:inline-block;background:{tag};color:#ffffff;border-radius:999px;padding:5px 14px;'
        f'font-size:12px;font-weight:700;letter-spacing:0.08em">{html.escape(t(lang, "kind." + kind))}</span>'
        + (f'<span style="font-size:13px;color:{MUTED};margin-left:12px">{html.escape(meta)}</span>' if meta else "")
        + f'<h1 style="margin:12px 0 0 0;font-size:24px;line-height:1.3;font-weight:600;color:{INK}">'
        f"{html.escape(headline(title))}</h1>"
        + (f'<div style="font-size:13px;color:{MUTED};margin-top:8px">{html.escape(reason)}</div>' if reason else "")
        + "</td></tr>"
    ]
    if note:
        rows.append(f'<tr><td style="padding:24px 32px 0 32px;font-family:{FONT}">{note}</td></tr>')
    characteristics: list[tuple[str, list[str]]] = []
    placed = False
    for key, heading, lines in sections:
        if key in CHARACTERISTICS:
            characteristics.append((heading, lines))
            continue
        if characteristics and not placed:
            rows.append(_characteristics(lang, characteristics))
            placed = True
        if key == "h.sources":
            rows.append(_sources(heading, lines))
        elif key == "h.assets":
            table = _table(lines)
            rest = [x for x in lines if not x.startswith("|")]
            rows.append(_card(heading, table + (_paragraphs(rest) if rest else "")))
        elif key == "h.exploitation":
            rows.append(_exploitation(heading, lines))
        elif key == "h.delay":
            rows.append(_delay(heading, lines))
        elif key == "h.links":
            rows.append(_links(heading, lines))
        else:
            rows.append(_card(heading, _paragraphs(lines)) if heading else _card("", _paragraphs(lines)))
    if characteristics and not placed:
        rows.append(_characteristics(lang, characteristics))
    foot = []
    if entry.get("id"):
        foot.append(t(lang, "foot.ref", ref=entry["id"], date=entry.get("issued_local") or ""))
    if entry.get("docx"):
        foot.append(t(lang, "foot.word"))
    rows.append(
        f'<tr><td style="padding:18px 32px;margin-top:28px;background:{SOFT};border-top:1px solid {LINE};'
        f'border-radius:0 0 12px 12px;font-size:12px;line-height:1.6;color:#616e7c;font-family:{FONT}">'
        f"{html.escape(' '.join(foot))}</td></tr>"
    )
    rows.insert(len(rows) - 1, '<tr><td style="height:28px;line-height:28px;font-size:0">&nbsp;</td></tr>')
    return (
        f'<table width="100%" cellpadding="0" cellspacing="0" role="presentation" bgcolor="#eef1f4" '
        f'style="background:#eef1f4"><tr><td align="center" style="padding:24px 12px">'
        f'<table width="{WIDTH}" cellpadding="0" cellspacing="0" role="presentation" bgcolor="{PAPER}" '
        f'style="width:{WIDTH}px;max-width:100%;background:{PAPER};border:1px solid {LINE};border-radius:12px;'
        f'color:{INK};font-family:{FONT}">{"".join(rows)}</table></td></tr></table>'
    )
