# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""What the paths to the assets that matter go through (v0.27.0): the chokepoints of a run.

Since v0.24.0 each asset's exposure rests on a path kept as its proof. Read one by one, those paths
answer "why this asset"; read together, they answer a question the client asks instead: *where do we
act first*. A zone, a published endpoint or a port that carries the way in to forty assets with ACT
decisions is worth one ticket, not forty — and the number to put in that ticket is how many findings
sit behind it.

Computed here, in memory, from the run the decision service already holds: the assets of the triage
document with their path, and the decisions counted per asset. No graph database, no new storage, and
nothing pushed: the run is the source, and a tenant per subsidiary keeps each graph small (HLD D21).

What this is not: a minimum cut. A chokepoint is a node every listed path goes through, counted; a
client with two ways in to the same asset sees both, each with what is behind it. Nothing here says a
path is the only one — it says what the run observed, which is what the client can act on.
"""

from __future__ import annotations

from typing import Any

SCHEMA = "ngvm.exposure_graph/1"
LEVELS = ("ACT", "ATTEND", "TRACK")
# Where each kind of node sits when the paths are drawn, left to right: the way in, the client's
# zones, what answers on the asset, the asset itself.
COLUMNS = {
    "internet": 0,
    "zone": 1,
    "endpoint": 2,
    "service": 2,
    "declared": 2,
    "host": 3,
    "image": 3,
    "process": 3,
    "component": 3,
}
# The internet is on every path in and cannot be closed: it is drawn, never ranked as a chokepoint.
NOT_A_CHOKEPOINT = ("internet",)
EXAMPLES = 8  # assets named per chokepoint; the rest are counted


def _counts(rows: list[dict[str, Any]]) -> dict[str, int]:
    out = dict.fromkeys(LEVELS, 0)
    for row in rows:
        level = row.get("delivery_decision", "")
        if level in out:
            out[level] += 1
    return out


def analyse(
    assets: list[dict[str, Any]],
    by_asset: dict[str, list[dict[str, Any]]],
    level: str = "ACT",
    top: int = 40,
    max_nodes: int = 60,
) -> dict[str, Any]:
    """The chokepoints of the run and the graph of the paths they are on.

    `assets` are the triage document's asset entries (id, name, exposure, exposure_path), `by_asset`
    its findings per asset. Only the assets carrying at least one finding at `level` are walked: a
    path to an asset with nothing to fix is not a way in worth a ticket.
    """
    level = level if level in LEVELS else "ACT"
    nodes: dict[str, dict[str, Any]] = {}
    edges: dict[tuple[str, str, str], dict[str, Any]] = {}
    considered = without_path = 0
    findings_total = 0

    for asset in assets:
        asset_id = str(asset.get("id", ""))
        counts = _counts(by_asset.get(asset_id, []))
        weight = counts[level]
        if weight <= 0:
            continue
        considered += 1
        findings_total += weight
        path = list(asset.get("exposure_path") or [])
        if not path:
            without_path += 1  # an assumed exposure: nothing observed leads to it, nothing to cut
            continue
        for index, step in enumerate(path):
            node = nodes.setdefault(
                str(step.get("node", "")),
                {
                    "node": str(step.get("node", "")),
                    "kind": str(step.get("kind", "")),
                    "label": str(step.get("label") or step.get("node", "")),
                    "column": COLUMNS.get(str(step.get("kind", "")), min(index, 3)),
                    "assets": 0,
                    "findings": 0,
                    "is_asset": False,
                    "examples": [],
                },
            )
            node["assets"] += 1
            node["findings"] += weight
            if index == len(path) - 1:  # the asset itself is the target, not a way in
                node["is_asset"] = True
            elif len(node["examples"]) < EXAMPLES:
                node["examples"].append(asset.get("name") or asset_id)
            if index + 1 < len(path):
                nxt = path[index + 1]
                key = (str(step.get("node", "")), str(nxt.get("node", "")), str(nxt.get("via", "")))
                edge = edges.setdefault(
                    key,
                    # The step entered carries what was crossed to enter it, and the proof of it.
                    {
                        "source": key[0],
                        "target": key[1],
                        "via": key[2],
                        "evidence": str(nxt.get("source", "")),
                        "seen": str(nxt.get("seen", "")),
                        "assets": 0,
                        "findings": 0,
                    },  # fmt: skip
                )
                edge["assets"] += 1
                edge["findings"] += weight

    ranked = sorted(
        (n for n in nodes.values() if not n["is_asset"] and n["kind"] not in NOT_A_CHOKEPOINT),
        # As much behind it first; then the node nearest the way in, which covers the rest of the path.
        key=lambda n: (-n["findings"], -n["assets"], n["column"], n["node"]),
    )
    kept = _drawable(nodes, edges, max_nodes)
    return {
        "schema": SCHEMA,
        "level": level,
        "assets_with_findings": considered,
        "assets_without_path": without_path,
        "findings": findings_total,
        "chokepoints": [_public(n) for n in ranked[:top]],
        "chokepoints_total": len(ranked),
        **kept,
    }


def _public(node: dict[str, Any]) -> dict[str, Any]:
    out = {k: v for k, v in node.items() if k != "is_asset"}
    out["examples"] = list(node["examples"])
    return out


def _drawable(
    nodes: dict[str, dict[str, Any]], edges: dict[tuple[str, str, str], dict[str, Any]], max_nodes: int
) -> dict[str, Any]:
    """What a page can draw: the heaviest nodes, the edges between those, and what was left out."""
    ordered = sorted(nodes.values(), key=lambda n: (-n["findings"], -n["assets"], n["node"]))
    keep = {n["node"] for n in ordered[:max_nodes]}
    drawn = [_public(n) for n in ordered if n["node"] in keep]
    links = [e for e in edges.values() if e["source"] in keep and e["target"] in keep]
    links.sort(key=lambda e: (-e["findings"], -e["assets"], e["source"], e["target"]))
    return {
        "nodes": drawn,
        "edges": links,
        "nodes_total": len(nodes),
        "edges_total": len(edges),
        "truncated": len(nodes) > len(drawn),
    }
