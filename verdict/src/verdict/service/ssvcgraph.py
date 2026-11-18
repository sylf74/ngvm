# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""The decisions of a run as the SSVC tree walked them, and what they cost (v0.28.0).

Each decision of the triage goes through the same points: Exploitation, Automatable, Technical
Impact, Mission & Well-being, then the SSVC outcome of the CISA Coordinator tree and the delivery
decision (ACT, ATTEND, TRACK). Counted over the decisions of a run, that walk is a graph: how many
decisions took each value, how many went from one value to the next, the paths taken most, and the
time each part of the walk cost (`TriageRow.timing`, v0.28.0). Nothing is computed again here: the
values and the times are those the triage recorded.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any

# (field of the row, label, values in the order they are drawn)
COLUMNS: tuple[tuple[str, str, tuple[str, ...]], ...] = (
    ("exploitation", "Exploitation", ("none", "poc", "active")),
    ("automatable", "Automatable", ("no", "yes")),
    ("technical_impact", "Technical impact", ("partial", "total")),
    ("mission_wellbeing", "Mission & well-being", ("low", "medium", "high")),
    ("ssvc_decision", "SSVC outcome", ("track", "track*", "attend", "act")),
    ("delivery_decision", "Decision", ("TRACK", "ATTEND", "ACT")),
)
PATHS_MAX = 20
TIMES = ("inputs_ms", "decide_ms", "llm_ms")


def value(row: dict[str, Any], name: str) -> str:
    """The value a decision took at one point: an assessed input carries it with its source."""
    v = row.get(name)
    if isinstance(v, dict):
        v = v.get("value")
    return str(v) if v not in (None, "") else "unknown"


def cost(row: dict[str, Any], shared: int = 1) -> float:
    """What the decision cost, in ms (0 for a run made before v0.28.0). A rationale is asked once
    for a CVE and a decision whatever its assets: each of its `shared` decisions bears its part."""
    timing = row.get("timing") or {}
    own = float(sum(timing.get(k) or 0 for k in TIMES[:2]))
    return own + float(timing.get("llm_ms") or 0) / max(1, shared)


def _shares(rows: list[dict[str, Any]]) -> Counter[tuple[str, str]]:
    return Counter((r.get("cve_id", ""), r.get("delivery_decision", "")) for r in rows)


def path_of(row: dict[str, Any]) -> list[str]:
    return [value(row, name) for name, _label, _values in COLUMNS]


def graph(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """The tree walked by `rows`: per point its values, between points the flows, the paths taken most."""
    counts: list[Counter[str]] = [Counter() for _ in COLUMNS]
    review: list[Counter[str]] = [Counter() for _ in COLUMNS]
    spent: list[defaultdict[str, float]] = [defaultdict(float) for _ in COLUMNS]
    flows: list[Counter[tuple[str, str]]] = [Counter() for _ in COLUMNS[1:]]
    paths: Counter[tuple[str, ...]] = Counter()
    path_ms: defaultdict[tuple[str, ...], float] = defaultdict(float)
    path_review: Counter[tuple[str, ...]] = Counter()
    shares = _shares(rows)
    for row in rows:
        p = path_of(row)
        ms = cost(row, shares[(row.get("cve_id", ""), row.get("delivery_decision", ""))])
        asks = bool(row.get("needs_review"))
        for i, v in enumerate(p):
            counts[i][v] += 1
            spent[i][v] += ms
            if asks:
                review[i][v] += 1
        for i in range(len(p) - 1):
            flows[i][(p[i], p[i + 1])] += 1
        key = tuple(p)
        paths[key] += 1
        path_ms[key] += ms
        if asks:
            path_review[key] += 1
    columns = []
    for i, (name, label, order) in enumerate(COLUMNS):
        seen = [v for v in order if counts[i][v]] + sorted(v for v in counts[i] if v not in order)
        columns.append(
            {
                "point": name,
                "label": label,
                "values": [
                    {"value": v, "count": counts[i][v], "review": review[i][v], "ms": round(spent[i][v], 1)}
                    for v in seen
                ],
            }
        )
    links = [
        {"from": [COLUMNS[i][0], a], "to": [COLUMNS[i + 1][0], b], "count": n}
        for i, flow in enumerate(flows)
        for (a, b), n in sorted(flow.items(), key=lambda kv: -kv[1])
    ]
    top = sorted(paths.items(), key=lambda kv: (-kv[1], kv[0]))[:PATHS_MAX]
    return {
        "decisions": len(rows),
        "columns": columns,
        "links": links,
        "paths": [{"path": list(k), "count": n, "review": path_review[k], "ms": round(path_ms[k], 1)} for k, n in top],
        "paths_total": len(paths),
    }


def _quantile(values: list[float], q: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    return round(ordered[min(len(ordered) - 1, int(q * len(ordered)))], 1)


def timing(rows: list[dict[str, Any]], document: dict[str, Any]) -> dict[str, Any]:
    """Where the triage time went: per part, per outcome of the rationale, the slowest decisions."""
    timed = [r for r in rows if r.get("timing")]
    t = document.get("timing") or {}
    usage = document.get("llm_usage") or {}
    out: dict[str, Any] = {
        "measured": bool(timed),
        "step_seconds": t.get("seconds"),
        "decide_seconds": t.get("decide_seconds"),
        "phases": t.get("phases") or {},
        "llm_timeouts": t.get("llm_timeouts"),
        "llm": {
            k: usage[k]
            for k in ("questions", "from_cache", "seconds", "failed", "timeouts", "failed_seconds")
            if k in usage
        },
        "slowest": (t.get("slowest") or [])[:10],
    }
    if not timed:
        out["note"] = "this run was made before v0.28.0: its decisions carry no time"
        return out
    out["totals_ms"] = {k: round(sum((r["timing"].get(k) or 0) for r in timed), 1) for k in TIMES[:2]}
    groups: dict[tuple[str, str], float] = {}
    for r in timed:  # a rationale is asked once for a CVE and a decision, whatever its assets
        key = (r.get("cve_id", ""), r.get("delivery_decision", ""))
        groups[key] = max(groups.get(key, 0.0), float(r["timing"].get("llm_ms") or 0))
    out["totals_ms"]["llm_ms"] = round(sum(groups.values()), 1)
    outcomes: Counter[str] = Counter()
    outcome_ms: defaultdict[str, float] = defaultdict(float)
    seen_groups: set[tuple[str, str, str]] = set()
    for r in timed:
        o = str(r["timing"].get("llm") or "unknown")
        outcomes[o] += 1
        key = (r.get("cve_id", ""), r.get("delivery_decision", ""), o)
        if key not in seen_groups:
            seen_groups.add(key)
            outcome_ms[o] += float(r["timing"].get("llm_ms") or 0)
    out["rationales"] = [
        {"outcome": o, "decisions": n, "ms": round(outcome_ms[o], 1)} for o, n in outcomes.most_common()
    ]
    decide = [float(r["timing"].get("decide_ms") or 0) for r in timed]
    out["decide_ms"] = {"p50": _quantile(decide, 0.5), "p95": _quantile(decide, 0.95), "max": round(max(decide), 1)}
    return out
