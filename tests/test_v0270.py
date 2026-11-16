# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.0: where the ways in meet — the chokepoints of a run, and the graph of its paths.

v0.24.0 kept, for each asset, the path its exposure rests on. Read one by one those paths say why an
asset is exposed; read together they say where to act first: the zone, the published endpoint or the
port that carries the way in to the assets that matter. The decision service computes that from the
run it already holds — no graph database, nothing pushed — the chat answers `list_chokepoints`, and
the exposure page draws it.
"""

from __future__ import annotations

import re

import httpx

from ngvm.service import Problem, TokenSet, digest
from verdict.service import chokepoints, exposure
from verdict.service.index import QueryError, RunIndex
from verdict.service.server import Service
from verdict.service.store import RunStore

from .conftest import ROOT
from .test_v0232 import _tools

TENANT = "example-client"


def _steps(*raw: tuple) -> list[dict]:
    names = ("node", "kind", "label", "via", "source", "seen")
    return [dict(zip(names, step + ("",) * (len(names) - len(step)), strict=True)) for step in raw]


WEB01 = _steps(
    ("internet", "internet", "internet"),
    ("zone:dmz", "zone", "dmz", "flow", "flows/0"),
    ("service:host:web01:443/tcp", "service", "web01 443/tcp", "reaches", "openvas", "2026-11-15T04:12:00+00:00"),
    ("host:web01", "host", "web01", "listens", "openvas", "2026-11-15T04:12:00+00:00"),
)
WEB02 = _steps(
    ("internet", "internet", "internet"),
    ("zone:dmz", "zone", "dmz", "flow", "flows/0"),
    ("service:host:web02:443/tcp", "service", "web02 443/tcp", "reaches", "openvas"),
    ("host:web02", "host", "web02", "listens", "openvas"),
)
DB01 = _steps(("zone:lan", "zone", "lan"), ("host:db01", "host", "db01", "member_of", "networks"))
ASSETS = [
    {"id": "host:web01", "name": "web01", "exposure": "open", "exposure_path": WEB01},
    {"id": "host:web02", "name": "web02", "exposure": "open", "exposure_path": WEB02},
    {"id": "host:db01", "name": "db01", "exposure": "controlled", "exposure_path": DB01},
    {"id": "host:pc9", "name": "pc9", "exposure": "open"},  # assumed: no path
    {"id": "host:quiet", "name": "quiet", "exposure": "small", "exposure_path": DB01},
]
BY_ASSET = {
    "host:web01": [{"delivery_decision": "ACT"}] * 7 + [{"delivery_decision": "ATTEND"}] * 3,
    "host:web02": [{"delivery_decision": "ACT"}] * 5,
    "host:db01": [{"delivery_decision": "ACT"}] * 2,
    "host:pc9": [{"delivery_decision": "ACT"}],
    "host:quiet": [{"delivery_decision": "TRACK"}] * 9,
}


# -- what the paths have in common -----------------------------------------------------------------
def test_the_chokepoints_are_ranked_by_what_sits_behind_them() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET)
    assert out["schema"] == "ngvm.exposure_graph/1" and out["level"] == "ACT"
    assert (out["assets_with_findings"], out["assets_without_path"], out["findings"]) == (4, 1, 15)
    first = out["chokepoints"][0]
    assert (first["node"], first["findings"], first["assets"]) == ("zone:dmz", 12, 2)
    assert first["examples"] == ["web01", "web02"]
    ranked = [c["node"] for c in out["chokepoints"]]
    assert "internet" not in ranked  # on every way in, and nobody can close it
    assert "host:web01" not in ranked  # the asset is the target, not a passage
    assert ranked == ["zone:dmz", "service:host:web01:443/tcp", "service:host:web02:443/tcp", "zone:lan"]


def test_an_asset_with_nothing_to_fix_is_not_a_way_in() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET)
    assert "host:quiet" not in [n["node"] for n in out["nodes"]]  # only TRACK: no path drawn for it
    attend = chokepoints.analyse(ASSETS, BY_ASSET, level="ATTEND")
    assert attend["assets_with_findings"] == 1 and attend["findings"] == 3
    assert [c["node"] for c in attend["chokepoints"]] == ["zone:dmz", "service:host:web01:443/tcp"]
    assert chokepoints.analyse(ASSETS, BY_ASSET, level="nonsense")["level"] == "ACT"


def test_the_graph_carries_what_was_crossed_and_what_saw_it() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET)
    edges = {(e["source"], e["target"]): e for e in out["edges"]}
    way_in = edges[("internet", "zone:dmz")]
    assert (way_in["via"], way_in["evidence"]) == ("flow", "flows/0")  # the step entered carries its proof
    assert (way_in["assets"], way_in["findings"]) == (2, 12)  # both web servers come this way
    served = edges[("service:host:web01:443/tcp", "host:web01")]
    assert (served["via"], served["evidence"], served["seen"][:10]) == ("listens", "openvas", "2026-11-15")
    columns = {n["node"]: n["column"] for n in out["nodes"]}
    assert columns["internet"] == 0 and columns["zone:dmz"] == 1
    assert columns["service:host:web01:443/tcp"] == 2 and columns["host:web01"] == 3


def test_a_big_graph_is_cut_down_for_drawing() -> None:
    out = chokepoints.analyse(ASSETS, BY_ASSET, max_nodes=3)
    assert out["truncated"] and len(out["nodes"]) == 3 and out["nodes_total"] == 8
    kept = {n["node"] for n in out["nodes"]}
    assert all(e["source"] in kept and e["target"] in kept for e in out["edges"])  # no link to nowhere
    assert out["chokepoints_total"] == 4  # the ranking is not cut by max_nodes


def test_the_examples_are_capped_and_counted() -> None:
    many = [
        {"id": f"host:h{n}", "name": f"h{n}", "exposure": "open",
         "exposure_path": _steps(("zone:dmz", "zone", "dmz"), (f"host:h{n}", "host", f"h{n}", "member_of"))}
        for n in range(20)
    ]  # fmt: skip
    out = chokepoints.analyse(many, {f"host:h{n}": [{"delivery_decision": "ACT"}] for n in range(20)})
    dmz = out["chokepoints"][0]
    assert dmz["assets"] == 20 and len(dmz["examples"]) == chokepoints.EXAMPLES


# -- the decision service answers for the run it holds ---------------------------------------------
def _index() -> RunIndex:
    rows = [
        {"cve_id": f"CVE-2026-{n:04d}", "asset_id": asset.split(":")[1], "asset_id_full": asset,
         "delivery_decision": level, "ssvc_decision": level}
        for asset, levels in (("host:web01", ["ACT"] * 7), ("host:web02", ["ACT"] * 5), ("host:db01", ["ACT"] * 2))
        for n, level in enumerate(levels)
    ]  # fmt: skip
    document = {"rows": rows, "assets": ASSETS, "client": {"id": TENANT, "language": "fr"}}
    receipt = {"id": "20261116T060000000000Z-abcdef123456", "generated_at": "2026-11-16T06:00:00+00:00"}
    return RunIndex(receipt, document)


def test_the_service_computes_it_from_the_run_it_already_has() -> None:
    out = _index().exposure_graph({})
    assert out["run"]["id"].startswith("20261116T") and out["level"] == "ACT"
    assert out["chokepoints"][0]["node"] == "zone:dmz"
    assert out["assets_with_findings"] == 3  # pc9 has no finding in this document


def test_what_the_route_refuses() -> None:
    index = _index()
    for query in ({"level": "nope"}, {"top": "0"}, {"top": "x"}, {"max_nodes": "900"}):
        try:
            index.exposure_graph(query)
        except QueryError:
            continue
        raise AssertionError(query)
    assert index.exposure_graph({"level": "act"})["level"] == "ACT"  # the case is the analyst's business


def test_the_route_is_served_to_a_reader(tmp_path) -> None:
    digests = tmp_path / "digests"
    digests.write_text(
        f"publish {digest('publish-token-0123456789abcdef')}\nread {digest('read-token-0123456789abcdef')}\n"
    )
    service = Service(TENANT, TokenSet.load(digests, {"publish", "read"}), RunStore(tmp_path / "store"))
    try:
        service.read(TENANT, "read-token-0123456789abcdef", "exposure-graph", {})
    except Problem as problem:
        assert problem.status == 404  # no run pushed yet: said plainly, never an empty graph
    else:
        raise AssertionError("a tenant with no run has no graph")
    server = (ROOT / "verdict/src/verdict/service/server.py").read_text()
    assert 'if rest == "exposure-graph"' in server


# -- the page draws it -----------------------------------------------------------------------------
GRAPH = {
    "schema": "ngvm.exposure_graph/1", "run": "r7", "level": "ACT", "assets_with_findings": 3,
    "assets_without_path": 1, "findings": 14, "chokepoints_total": 4, "nodes_total": 8, "edges_total": 6,
    "truncated": False,
    "chokepoints": [
        {"node": "zone:dmz", "kind": "zone", "label": "dmz", "column": 1, "assets": 2, "findings": 12,
         "examples": ["web01", "web02"]},
    ],
    "nodes": [
        {"node": "internet", "kind": "internet", "label": "internet", "column": 0, "assets": 2, "findings": 12},
        {"node": "zone:dmz", "kind": "zone", "label": "dmz", "column": 1, "assets": 2, "findings": 12},
        {"node": "host:web01", "kind": "host", "label": "web01", "column": 3, "assets": 1, "findings": 7},
    ],
    "edges": [
        {"source": "internet", "target": "zone:dmz", "via": "flow", "evidence": "flows/0", "seen": "",
         "assets": 2, "findings": 12},
        {"source": "zone:dmz", "target": "host:web01", "via": "member_of", "evidence": "networks", "seen": "",
         "assets": 1, "findings": 7},
    ],
}  # fmt: skip


def test_the_graph_is_drawn_on_the_page() -> None:
    page = exposure.page({"tenant": TENANT, "assets": [], "total": 0, "graph": GRAPH})
    assert "<svg viewBox=" in page and "<script" not in page
    assert page.count("<rect ") == 3 and page.count("<path d=") == 2
    assert "class='n-internet'" in page and "class='n-zone'" in page and "class='n-host'" in page
    assert "<title>flow · 12 findings on 2 asset(s) · flows/0</title>" in page  # the link says what it carries
    assert "<a href='/exposure?asset=host%3Aweb01'>" in page  # an asset leads to its own path
    assert "The way in" in page and "Assets" in page
    assert "Chokepoint" in page and ">dmz</td>" in page and "web01, web02" in page
    assert "Assets with no path (assumed)" in page and "class='warn'>1</span>" in page
    assert "<a href='/exposure?level=ATTEND'>ATTEND</a>" in page


def test_a_run_whose_paths_lead_nowhere() -> None:
    empty = {**GRAPH, "chokepoints": [], "nodes": [], "edges": [], "chokepoints_total": 0}
    page = exposure.page({"tenant": TENANT, "assets": [], "total": 0, "graph": empty})
    assert "Nothing to draw" in page and "No path leads to a finding at this level" in page


def test_a_decision_service_without_the_route_does_not_break_the_page() -> None:
    page = exposure.page({"tenant": TENANT, "assets": [], "total": 0, "graph": {"state": "answered 404"}})
    assert "Where the ways in meet" not in page and "The assets of the run" in page


def test_the_link_of_a_step_carries_what_was_crossed_to_enter_it() -> None:
    """The evidence of a step is the evidence of the edge leading to it, so it belongs on that link."""
    detail = {"asset": "host:web01", "name": "web01", "exposure": "open", "path": WEB01, "services": []}
    page = exposure.page({"tenant": TENANT, "asset": detail})
    between = re.findall(r"<div class='link'>→<b>([a-z_]+)</b>(?:<div>([^<]*)</div>)?", page)
    assert [via for via, _ in between] == ["flow", "reaches", "listens"]  # three links for four steps
    assert between[0][1] == "seen by flows/0"
    assert between[1][1] == "seen by openvas · 2026-11-15"
    assert "the internet</div>" in page  # the box says what the node is, the link what was crossed


# -- the chat ---------------------------------------------------------------------------------------
def _handler(asked: list):
    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.path, dict(request.url.params)))
        if request.url.path.endswith("/exposure-graph"):
            return httpx.Response(200, json=GRAPH)
        if request.url.path.endswith("/assets"):
            return httpx.Response(200, json={"items": [], "total": 0})
        return httpx.Response(404, json={"detail": "no"})

    return handler


def test_the_chat_asks_for_the_chokepoints(tmp_path) -> None:
    from verdict.service.tools import openapi

    spec = openapi(TENANT)
    tool = spec["paths"]["/chokepoints"]["get"]
    assert tool["operationId"] == "list_chokepoints"
    assert "what should we close first" in tool["description"]
    assert {p["name"] for p in tool["parameters"]} == {"level", "top", "run"}
    asked: list = []
    out = _tools(tmp_path, _handler(asked)).call(
        "chat-token-0123456789abcdef0123456789", "/chokepoints", {"level": "ATTEND"}
    )
    assert out["chokepoints"][0]["node"] == "zone:dmz"
    assert asked[0][1] == {"level": "ATTEND"}


def test_the_page_asks_for_the_level_it_shows(tmp_path) -> None:
    asked: list = []
    tools = _tools(tmp_path, _handler(asked))
    tools._exposure_data(level="ATTEND")
    assert ("/v1/tenants/example-client/exposure-graph", {"level": "ATTEND"}) in asked


def test_an_old_decision_service_does_not_take_the_page_down(tmp_path) -> None:
    """A tenant whose decision service is older than this version still gets its assets."""

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/assets"):
            return httpx.Response(200, json={"items": [], "total": 0})
        return httpx.Response(404, json={"detail": "no such route"})

    data = _tools(tmp_path, handler)._exposure_data()
    assert data["graph"] == {"state": "no such route"} and data["total"] == 0
    assert "Where the ways in meet" not in exposure.page(data)


def test_documented() -> None:
    operations = (ROOT / "docs/operations.md").read_text()
    assert "chokepoint" in operations.lower() and "list_chokepoints" in operations
    assert "list_chokepoints" in (ROOT / "docs/chat.md").read_text()
    assert "list_chokepoints" in (ROOT / "docs/chat-questions.md").read_text()


def test_release_recorded() -> None:
    assert "## v0.27.0 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(2[7-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
