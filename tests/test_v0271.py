# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.1: the drawing of the paths carries its own colours.

The boxes of the graph took their fill from a stylesheet rule that was never written, and an SVG
rectangle with no fill is black: the first real page showed black on black. A drawing is data, not
decoration — it says its own colours now, and this checks it keeps saying them.
"""

from __future__ import annotations

import re

from verdict.service import exposure

from .conftest import ROOT
from .test_v0270 import GRAPH, TENANT


def test_every_box_and_label_says_its_own_colour() -> None:
    drawing = exposure.page({"tenant": TENANT, "assets": [], "total": 0, "graph": GRAPH})
    svg = drawing.split("<svg")[1].split("</svg>")[0]
    for element in re.findall(r"<(?:rect|text) [^>]*>", svg):
        assert "fill='#" in element, element
    assert all("stroke='#" in r for r in re.findall(r"<rect [^>]*>", svg))


def test_a_kind_the_table_does_not_know_is_still_visible() -> None:
    graph = {
        **GRAPH,
        "nodes": [{"node": "x", "kind": "process", "label": "x", "column": 3, "assets": 1, "findings": 1}],
        "edges": [],
    }
    svg = exposure.page({"tenant": TENANT, "assets": [], "total": 0, "graph": graph}).split("<svg")[1]
    fill, stroke = exposure.PLAIN
    assert f"fill='{fill}' stroke='{stroke}'" in svg


def test_release_recorded() -> None:
    assert "## v0.27.1 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(27\.([1-9]|\d\d+)|2[89]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
