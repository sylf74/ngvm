# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.26.3: the exposure path of an asset, drawn.

Since v0.24.0 an exposure rests on a path kept as its proof, and the chat tells it in words. The tool
server now draws it beside the run page, behind the same sign-in: the internet or a zone, the flow,
the service, the asset, each step with who saw it and when; and, without an asset, the assets of the
run to pick from. The look of both pages comes from one place (`pages.py`).
"""

from __future__ import annotations

import json
import re

import httpx
import pytest

from ngvm.service import Problem
from verdict.service import exposure, pages, supervision

from .conftest import ROOT
from .test_v0232 import _tools

TENANT = "example-client"
REVIEW = ROOT / "deploy/charts/ngvm-tenant/templates/review.yaml"
PATH = [
    {"node": "internet", "kind": "internet", "label": "internet", "via": "443/tcp"},
    {"node": "zone:dmz", "kind": "zone", "label": "dmz", "via": "443/tcp", "source": "flows/0"},
    {"node": "service:host:web01:443/tcp", "kind": "service", "label": "443/tcp", "via": "listens",
     "source": "openvas", "seen": "2026-11-15T04:12:00+00:00"},
    {"node": "host:web01", "kind": "host", "label": "web01.lab.example", "source": "openvas",
     "seen": "2026-11-15T04:12:00+00:00"},
]  # fmt: skip
DETAIL = {
    "run": "20261116T060000Z-abc123def456", "asset": "host:web01", "name": "web01.lab.example",
    "exposure": "open", "exposure_source": "graph", "zone": "dmz", "assumed": False,
    "origin": "flow from the internet to zone dmz on 443/tcp (flows/0)", "path": PATH,
    "services": [{"port": "443/tcp", "view": "network", "name": "https", "source": "openvas",
                  "at": "2026-11-15T04:12:00+00:00"}],
}  # fmt: skip
GAPS = [
    {"kind": "undeclared-flow", "asset": "host:web01", "name": "lan -> dmz 8080/tcp",
     "detail": "2 asset(s) reached from lan on 8080/tcp, allowed by no flow: web01, web02"},
    {"kind": "no-external-scan", "asset": "", "name": "example-client", "detail": "no external scan"},
]  # fmt: skip
ASSETS = [
    {"asset": "host:web01", "name": "web01.lab.example", "exposure": "open", "zone": "dmz",
     "counts": {"ACT": 7, "ATTEND": 31, "TRACK": 112}, "origins": {"exposure": "graph"}},
    {"asset": "host:pc042", "name": "pc042", "exposure": "open", "zone": "",
     "counts": {"ACT": 0, "ATTEND": 4, "TRACK": 40}, "origins": {"exposure": "assumed"}},
]  # fmt: skip


# -- the path of one asset -------------------------------------------------------------------------
def test_the_path_is_drawn_step_by_step() -> None:
    page = exposure.page({"tenant": TENANT, "asset": DETAIL, "exposure_gaps": GAPS})
    assert "<script" not in page and "src=" not in page
    hops = re.findall(r"<div class='hop ([a-z]+)'><b>([^<]*)</b>", page)
    assert hops == [
        ("internet", "internet"), ("zone", "dmz"), ("service", "443/tcp"), ("host", "web01.lab.example"),
    ]  # fmt: skip
    assert page.count("<div class='link'>") == len(PATH) - 1  # one link between two steps, no more
    assert "<b>443/tcp</b>" in page and "<b>listens</b>" in page  # what each step was crossed by
    assert "seen by openvas · 2026-11-15" in page  # the proof of the step, and its day
    assert "class='badge open'>open" in page
    assert "reached from the internet, or seen off the premises" in page
    assert "flow from the internet to zone dmz on 443/tcp (flows/0)" in page  # where the value comes from


def test_the_gaps_shown_are_those_of_the_asset() -> None:
    page = exposure.page({"tenant": TENANT, "asset": DETAIL, "exposure_gaps": GAPS})
    assert "undeclared-flow" in page and "lan -&gt; dmz 8080/tcp" in page
    assert "no-external-scan" in page  # the client's own gap concerns every asset
    other = {**DETAIL, "asset": "host:db01"}
    page = exposure.page({"tenant": TENANT, "asset": other, "exposure_gaps": GAPS})
    assert "undeclared-flow" not in page and "no-external-scan" in page


def test_an_assumed_exposure_says_that_nothing_proves_it() -> None:
    assumed = {**DETAIL, "exposure": "open", "exposure_source": "assumed", "assumed": True, "path": [], "services": []}
    page = exposure.page({"tenant": TENANT, "asset": assumed})
    assert "No path: this exposure is an assumption, not a proof" in page
    assert "an assumption, nothing proves it" in page
    assert "class='badge assumed'" in page
    assert "No service listed on this asset" in page


def test_an_asset_the_run_does_not_know() -> None:
    page = exposure.page({"tenant": TENANT, "not_found": "host:nope"})
    assert "knows no asset called" in page and "host:nope" in page
    assert "<a href='/exposure'>" in page  # the way back


def test_what_the_page_shows_is_escaped() -> None:
    hostile = {**DETAIL, "name": "<img src=x>", "origin": "<b>x</b>",
               "path": [{"node": "host:x", "kind": "host", "label": "<script>alert(1)</script>"}]}  # fmt: skip
    page = exposure.page({"tenant": TENANT, "asset": hostile})
    assert "<img src=x>" not in page and "&lt;img src=x&gt;" in page
    assert "<script>" not in page and "&lt;script&gt;alert(1)&lt;/script&gt;" in page


# -- the assets to pick from -----------------------------------------------------------------------
def test_the_list_keeps_the_order_the_run_gave() -> None:
    page = exposure.page({"tenant": TENANT, "assets": ASSETS, "total": 1240})
    names = re.findall(r"<td><a href='/exposure\?asset=([^']+)'>([^<]*)</a></td>", page)
    assert [n for _, n in names] == ["web01.lab.example", "pc042"]  # most ACT first, as served
    assert names[0][0] == "host%3Aweb01"  # the id, safe in a link
    assert "2 of 1240 assets" in page
    assert "class='badge assumed'>assumed" not in page  # the badge carries the exposure, not its origin
    assert "<a href='/exposure?exposure=open'>open</a>" in page
    assert "class='warn'>7</span>" in page and "<td>0</td>" in page  # ACT shown, zero plainly


def test_the_list_says_what_an_assumed_exposure_is_worth() -> None:
    page = exposure.page({"tenant": TENANT, "assets": ASSETS, "total": 2})
    assert "the worst case taken for want of proof, not a measure" in page


# -- what the tool server gathers ------------------------------------------------------------------
def _handler(asked: list, detail: dict | None = None, status: int = 200):
    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.path, dict(request.url.params), str(request.url)))
        if request.url.path.endswith("/exposure"):
            if status != 200:
                return httpx.Response(status, json={"detail": "no such asset"})
            return httpx.Response(200, json=detail or DETAIL)
        if request.url.path.endswith("/summary"):
            return httpx.Response(200, json={"run_id": "r7", "exposure_gaps": GAPS})
        if request.url.path.endswith("/assets"):
            return httpx.Response(200, json={"items": ASSETS, "total": 1240})
        return httpx.Response(404, json={"detail": "no"})

    return handler


def test_one_asset_is_asked_of_the_decision_service(tmp_path) -> None:
    asked: list = []
    tools = _tools(tmp_path, _handler(asked))
    data = tools._exposure_data("host:web01")
    assert data["asset"]["name"] == "web01.lab.example" and data["exposure_gaps"] == GAPS
    assert asked[0][0] == f"/v1/tenants/{TENANT}/assets/host:web01/exposure"
    tools._exposure_data("host:a/b")  # an id that carries a slash stays one path segment
    assert "/assets/host%3Aa%2Fb/exposure" in asked[-2][2]  # the whole id is one segment


def test_an_asset_the_service_does_not_have(tmp_path) -> None:
    tools = _tools(tmp_path, _handler([], status=404))
    data = tools._exposure_data("host:nope")
    assert data["not_found"] == "host:nope" and "asset" not in data
    with pytest.raises(Problem):  # anything else is not hidden
        _tools(tmp_path, _handler([], status=503))._exposure_data("host:web01")


def test_the_assets_are_asked_with_the_filter(tmp_path) -> None:
    asked: list = []
    tools = _tools(tmp_path, _handler(asked))
    data = tools._exposure_data(exposure="open")
    assert data["total"] == 1240 and len(data["assets"]) == 2
    assert asked[0][1] == {"limit": "200", "exposure": "open"}
    _tools(tmp_path, _handler(asked))._exposure_data(exposure="nonsense")
    assert "exposure" not in asked[-1][1]  # only the three the run knows


def test_the_page_is_served_and_who_looked_is_journaled(tmp_path) -> None:
    from ngvm.audit import AuditLog

    journal = tmp_path / "audit.jsonl"
    tools = _tools(tmp_path, _handler([]), audit=AuditLog("tools", path=journal))
    page = tools.exposure_page("analyst@example.org", {"asset": "host:web01"})
    assert "How this asset is reached" in page
    entry = json.loads(journal.read_text().splitlines()[0])
    assert (entry["actor"], entry["action"], entry["target"]) == ("analyst@example.org", "page:exposure", "/exposure")
    assert entry["params"] == {"asset": "host:web01"}


# -- one look for the analysts' pages --------------------------------------------------------------
def test_the_pages_share_their_shell() -> None:
    assert supervision.CSP is pages.CSP and exposure.CSP is pages.CSP
    assert "default-src 'none'" in pages.CSP and "script" not in pages.CSP
    page = pages.shell("T", "<b>T</b>", "<p>body</p>", "footer", refresh=30)
    assert page.startswith("<!doctype html>") and "refresh content=30" in page
    assert "<footer>footer</footer>" in page and "<script" not in page
    assert pages.esc("<b>") == "&lt;b&gt;" and pages.esc(pages.Safe("<b>x</b>")) == "<b>x</b>"
    assert pages.kpi([("a", 1), ("b", None), None, ("c", "")]) == (
        "<table class='kpi'><tr><td>a</td><td class='v'>1</td></tr></table>"
    )
    assert (pages.span(48), pages.size(2048), pages.moment("2026-11-15T06:18:00+00:00")) == (
        "48 s", "2.0 kB", "2026-11-15 06:18",
    )  # fmt: skip


def test_the_run_page_leads_to_the_exposure_page(tmp_path) -> None:
    page = supervision.page({"tenant": TENANT, "run": {}, "pillars": {}, "agents": {}})
    assert "<a href='/exposure'>exposure paths</a>" in page


def test_the_page_is_behind_the_sign_in_of_the_review_page() -> None:
    review = REVIEW.read_text()
    assert '- --upstream={{ printf "http://%s-tools:8080/exposure" $name }}' in review
    assert '- --upstream={{ printf "http://%s-tools:8080/run" $name }}' in review


def test_documented() -> None:
    operations = (ROOT / "docs/operations.md").read_text()
    assert "/exposure" in operations and "get_exposure_path" in operations
    assert "the worst case taken for want of proof" in operations  # what an assumed exposure is worth
    assert "/exposure" in (ROOT / "docs/chat-questions.md").read_text()


def test_release_recorded() -> None:
    assert "## v0.26.3 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(26\.([3-9]|\d\d+)|2[7-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
