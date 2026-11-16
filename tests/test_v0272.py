# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.2: navigating the graph of the paths by vertex.

v0.27.0 drew the paths of a run and ranked what they go through. On a client of a few hundred assets
that drawing is cut down to its heaviest nodes, and no amount of zooming makes an unreadable picture
readable: what the operator wants is to pick a node and see what is behind it. So the page asks the
decision service for the neighbourhood of one node — the assets and findings that pass through it,
and what sits within a couple of hops either way — and every box of every drawing is a link to that
neighbourhood. A link, not a script: the page's Content-Security-Policy is unchanged.
"""

from __future__ import annotations

import re

from verdict.service import chokepoints, exposure
from verdict.service.index import QueryError

from .conftest import ROOT
from .test_v0270 import ASSETS, BY_ASSET, GRAPH, TENANT, _index


# -- the neighbourhood of one node -----------------------------------------------------------------
def test_one_hop_keeps_what_touches_the_node() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET, focus="zone:dmz", depth=1)
    assert out["focus"]["node"] == "zone:dmz" and out["depth"] == 1
    assert {n["node"] for n in out["nodes"]} == {
        "internet",  # walked both ways: what leads to the node as well as what it leads to
        "zone:dmz",
        "service:host:web01:443/tcp",
        "service:host:web02:443/tcp",
    }
    assert {n["node"]: n["distance"] for n in out["nodes"]}["zone:dmz"] == 0
    kept = {n["node"] for n in out["nodes"]}
    assert all(e["source"] in kept and e["target"] in kept for e in out["edges"])
    assert out["truncated"]  # the rest of the graph is not drawn, and the page says so


def test_two_hops_reach_the_assets_behind_it() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET, focus="zone:dmz", depth=2)
    at = {n["node"]: n["distance"] for n in out["nodes"]}
    assert at["host:web01"] == 2 and at["host:web02"] == 2 and at["internet"] == 1
    assert "zone:lan" not in at  # another way in, on no path through this node


def test_the_assets_behind_it_are_named_and_counted() -> None:
    behind = chokepoints.analyse(ASSETS, BY_ASSET, focus="zone:dmz")["behind"]
    assert [(a["name"], a["findings"]) for a in behind["assets"]] == [("web01", 7), ("web02", 5)]
    assert (behind["assets_total"], behind["findings"]) == (2, 12)
    lan = chokepoints.analyse(ASSETS, BY_ASSET, focus="zone:lan")["behind"]
    assert [a["name"] for a in lan["assets"]] == ["db01"]  # quiet is TRACK only: not at this level


def test_the_node_in_focus_is_always_drawn() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET, focus="host:web02", depth=3, max_nodes=1)
    assert "host:web02" in {n["node"] for n in out["nodes"]}


def test_a_node_this_run_never_saw_is_said_not_guessed() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET, focus="zone:gone")
    assert out["focus_unknown"] == "zone:gone" and "focus" not in out and "behind" not in out
    assert out["nodes"]  # the whole graph comes back: the analyst is not left with an empty page


def test_the_depth_is_kept_inside_its_bounds() -> None:
    assert chokepoints.analyse(ASSETS, BY_ASSET, focus="zone:dmz", depth=0)["depth"] == 1
    assert chokepoints.analyse(ASSETS, BY_ASSET, focus="zone:dmz", depth=9)["depth"] == chokepoints.DEPTH_MAX
    assert "depth" not in chokepoints.analyse(ASSETS, BY_ASSET)  # no node asked for: the whole graph


# -- the decision service serves it ----------------------------------------------------------------
def test_the_route_takes_a_node_and_a_depth() -> None:
    out = _index().exposure_graph({"node": "zone:dmz", "depth": "1"})
    assert out["focus"]["label"] == "dmz" and out["depth"] == 1
    assert out["behind"]["assets_total"] == 2
    assert _index().exposure_graph({})["chokepoints"][0]["node"] == "zone:dmz"  # unchanged without it


def test_what_the_route_refuses_of_the_depth() -> None:
    index = _index()
    for query in ({"depth": "0"}, {"depth": "4"}, {"depth": "x"}):
        try:
            index.exposure_graph({"node": "zone:dmz", **query})
        except QueryError:
            continue
        raise AssertionError(query)


def test_the_contract_carries_the_pivot() -> None:
    contract = (ROOT / "ngvm/src/ngvm/schemas/openapi/verdict.v1.yaml").read_text(encoding="utf-8")
    assert "name: node" in contract and "name: depth" in contract
    assert "focus_unknown" in contract and "distance" in contract


# -- the page pivots -------------------------------------------------------------------------------
NEIGHBOURHOOD = {
    **GRAPH,
    "depth": 2,
    "focus": {"node": "zone:dmz", "kind": "zone", "label": "dmz", "column": 1, "assets": 2, "findings": 12},
    "behind": {
        "assets": [{"id": "host:web01", "name": "web01", "findings": 7}],
        "assets_total": 1,
        "findings": 7,
    },
    "nodes": [
        {"node": "internet", "kind": "internet", "label": "internet", "column": 0, "assets": 2,
         "findings": 12, "distance": 1},
        {"node": "zone:dmz", "kind": "zone", "label": "dmz", "column": 1, "assets": 2, "findings": 12,
         "distance": 0},
        {"node": "host:web01", "kind": "host", "label": "web01", "column": 3, "assets": 1, "findings": 7,
         "distance": 2},
    ],
}  # fmt: skip


def test_every_box_of_the_whole_graph_leads_somewhere() -> None:
    page = exposure.page({"tenant": TENANT, "assets": [], "total": 0, "graph": GRAPH})
    assert "<a href='/exposure?node=internet'>" in page  # a way in leads to its own neighbourhood
    assert "<a href='/exposure?node=zone%3Admz'>" in page
    assert "<a href='/exposure?asset=host%3Aweb01'>" in page  # an asset still leads to its own path
    assert "<a href='/exposure?node=zone%3Admz'>dmz</a>" in page  # and so does the ranking's label


def test_the_page_centred_on_a_node_shows_what_is_behind_it() -> None:
    page = exposure.page({"tenant": TENANT, "node": "zone:dmz", "depth": 2, "graph": NEIGHBOURHOOD})
    assert "Exposure — dmz" in page and "a zone of the client" in page
    assert "2 hop(s) around it" in page
    assert "<svg viewBox=" in page and "<script" not in page  # a drawing, never a script
    assert "stroke-width='3'" in page  # the node in focus is marked, and is not a link to itself
    assert "<a href='/exposure?node=zone%3Admz'>" not in page
    assert "The assets behind it" in page and "<a href='/exposure?asset=host%3Aweb01'>web01</a>" in page
    assert "<a href='/exposure?node=zone%3Admz&amp;depth=1'>1</a>" in page  # one or three hops instead
    assert "<a href='/exposure'>the whole picture</a>" in page


def test_the_drawing_of_a_neighbourhood_keeps_its_own_colours() -> None:
    page = exposure.page({"tenant": TENANT, "node": "zone:dmz", "depth": 2, "graph": NEIGHBOURHOOD})
    svg = page.split("<svg")[1].split("</svg>")[0]
    for element in re.findall(r"<(?:rect|text) [^>]*>", svg):
        assert "fill='#" in element, element


def test_a_stale_link_is_explained_rather_than_drawn_empty() -> None:
    graph = {**GRAPH, "focus_unknown": "zone:gone"}
    page = exposure.page({"tenant": TENANT, "node": "zone:gone", "graph": graph})
    assert "node not in the latest run" in page and "zone:gone" in page
    assert "named by the run that saw it" in page


def test_a_decision_service_that_does_not_answer_takes_nothing_down() -> None:
    page = exposure.page({"tenant": TENANT, "node": "zone:dmz", "graph": {"state": "service unreachable"}})
    assert "service unreachable" in page and "<a href='/exposure'>all the assets</a>" in page


def test_the_tools_service_passes_the_node_through() -> None:
    tools = (ROOT / "verdict/src/verdict/service/tools.py").read_text(encoding="utf-8")
    assert '"node": node, "depth": str(depth)' in tools
    assert 'node = (query.get("node") or "")[:200]' in tools


def test_release_recorded() -> None:
    assert "## v0.27.2 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(27\.([2-9]|\d\d+)|2[89]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
