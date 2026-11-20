# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.28.1: the pages read the decision service whole; one dashboard address, the portal's Grafana.

- The pages of the tool server read the decision service through the helper of the chat, which cuts
  every list to ten items and puts a text in place of the rest: the run page of a tenant of ten
  thousand decisions failed on that text (500), the exposure page drew ten nodes at most. The pages
  now read it whole; the chat's answers keep their size.
- One portal (the reporting database and its Grafana): `NGVM_GRAFANA_URL` alone, `NGVM_PORTAL_URL` is
  gone.
"""

from __future__ import annotations

import re

import httpx
import yaml

from verdict.service import supervision, triagepages

from .conftest import ROOT
from .test_v0232 import TENANT, _tools

LINKS = [{"from": ["exploitation", f"v{i}"], "to": ["automatable", "no"], "count": 1} for i in range(25)]
GRAPH = {
    "run": {"id": "r1"},
    "decisions": 25,
    "columns": [
        {"point": "exploitation", "label": "Exploitation",
         "values": [{"value": f"v{i}", "count": 1, "review": 0, "ms": 1.0} for i in range(25)]},
        {"point": "automatable", "label": "Automatable",
         "values": [{"value": "no", "count": 25, "review": 0, "ms": 25.0}]},
    ],
    "links": LINKS,
    "paths": [],
    "paths_total": 25,
    "timing": {"measured": False, "note": "this run was made before v0.28.0: its decisions carry no time"},
}  # fmt: skip
NODES = [{"id": f"zone:z{i}", "kind": "zone", "label": f"z{i}", "weight": 30 - i} for i in range(30)]


def _handler(asked: list):
    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.path)
        if request.url.path.endswith("/triage-graph"):
            return httpx.Response(200, json=GRAPH)
        if request.url.path.endswith("/exposure-graph"):
            return httpx.Response(200, json={"nodes": NODES, "edges": [], "chokepoints": [], "level": "ACT"})
        if request.url.path.endswith("/assets"):
            return httpx.Response(200, json={"items": [], "total": 0})
        return httpx.Response(404, json={"detail": "no"})

    return handler


def test_the_pages_read_the_decision_service_whole(tmp_path) -> None:
    tools = _tools(tmp_path, _handler([]), max_chars=4000)
    graph = tools._triage_graph({})
    assert graph["links"] == LINKS  # 25 flows, none cut nor replaced by a text
    assert len(tools._exposure_data()["graph"]["nodes"]) == 30
    page = supervision.page({"tenant": TENANT, "run": {}, "pillars": {}}, "", graph)
    assert page.count("<path d=") == 25
    # the chat's answers keep their size
    assert len(tools._get("triage-graph", {})["links"]) == 11  # ten and "… 15 more"


def test_a_list_cut_for_the_chat_is_not_drawn() -> None:
    cut = {**GRAPH, "links": [*LINKS[:3], "… 22 more"]}
    page = triagepages.svg(cut)
    assert page.count("<path d=") == 3


def test_one_dashboard_address() -> None:
    pipeline = (ROOT / "templates/client-pipeline.yml").read_text(encoding="utf-8")
    assert "NGVM_PORTAL_URL" not in pipeline
    assert "--set pages.links[0].name=Grafana --set pages.links[0].url=$NGVM_GRAFANA_URL" in pipeline
    for doc in ("docs/kubernetes.md", "docs/operations.md"):
        assert "NGVM_PORTAL_URL" not in (ROOT / doc).read_text(encoding="utf-8")
    values = yaml.safe_load((ROOT / "deploy/charts/ngvm-tenant/values.yaml").read_text(encoding="utf-8"))
    assert values["pages"] == {"links": []}


def test_documented() -> None:
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert "| v0.28.1 (current) |" in hld or "| v0.28.1 |" in hld  # the next release takes "(current)"


def test_release_recorded() -> None:
    assert "## v0.28.1 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(28\.([1-9]|\d\d+)|29\.\d+|[3-9]\d\.\d+)$", chart, re.M)
