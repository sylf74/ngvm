# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.28.0: the triage measured, decision by decision, and the pages to read it.

- Each decision carries what it cost (inputs_ms, decide_ms, llm_ms, llm), the run where the time went
  and its slowest decisions; triage.csv has the columns.
- A question the LLM did not answer in time is not asked again (180 s, three times: nine minutes for a
  rationale); the time spent waiting for the questions without an answer is counted; three of them,
  consecutive or not, leave the LLM aside; the rationales go through a window, not batches.
- The decision service gives the SSVC tree walked by the run (`triage-graph`); the run page draws it
  with the time; a page per decision draws its path over it, with a search; a central page links
  the pages, the dashboards and the chat.
"""

from __future__ import annotations

import copy
import json
import re
import time

import httpx
import pytest
import yaml

from ngvm.llm import LlmClient, LlmError
from verdict.report import write_json
from verdict.service import ssvcgraph, supervision, triagepages
from verdict.service.index import RunIndex
from verdict.service.pages import CSP
from verdict.triage import Triage

from .conftest import ROOT, fake_llm_transport
from .test_pipeline import _by_cve, _run

SCHEMA = {"type": "object", "properties": {"a": {"type": "string"}}, "required": ["a"], "additionalProperties": False}


# -- 1. the LLM: a timeout is not asked again, and what failed is counted -------------------------------
def test_a_question_not_answered_in_time_is_not_asked_again(settings) -> None:
    asked: list[int] = []

    def slow(request: httpx.Request) -> httpx.Response:
        asked.append(1)
        raise httpx.ReadTimeout("timed out")

    settings.llm.max_retries = 2
    llm = LlmClient(settings.llm, transport=httpx.MockTransport(slow))
    with pytest.raises(LlmError, match="rationale: timed out after 180 s"):
        llm.structured("s", "u", "rationale", SCHEMA)
    assert len(asked) == 1  # before v0.28.0: three times
    u = llm.usage_summary()
    assert (u["failed"], u["timeouts"], u["seconds"]) == (1, 1, 0.0) and u["failed_seconds"] >= 0

    bad: list[int] = []

    def broken(request: httpx.Request) -> httpx.Response:
        bad.append(1)
        return httpx.Response(200, json={"choices": [{"message": {"content": "not json"}}]})

    llm = LlmClient(settings.llm, transport=httpx.MockTransport(broken))
    with pytest.raises(LlmError):
        llm.structured("s", "u", "rationale", SCHEMA)
    assert len(bad) == 3 and llm.usage_summary()["failed"] == 1 and llm.usage_summary()["timeouts"] == 0


def test_the_cache_is_told_per_thread(settings, tmp_path) -> None:
    settings.llm.cache_file = str(tmp_path / "cache.json")
    llm = LlmClient(settings.llm, transport=fake_llm_transport(lambda name, body: {"a": "x"}))
    llm.structured("s", "u", "rationale", SCHEMA)
    assert llm.last_from_cache() is False
    llm.structured("s", "u", "rationale", SCHEMA)
    assert llm.last_from_cache() is True


# -- 2. the triage: every decision timed, the timeouts leave the LLM aside -----------------------------
def test_every_decision_says_what_it_cost(settings, sources, profile, tmp_path) -> None:
    run = _run(settings, sources, profile)
    assert run.rows and all(set(r.timing) == {"inputs_ms", "decide_ms", "llm_ms", "llm"} for r in run.rows)
    assert {r.timing["llm"] for r in run.rows} == {"off"}
    t = run.timing
    assert set(t["phases"]) == {"decisions", "rationales"} and t["llm_timeouts"] == 0
    assert len(t["slowest"]) == min(10, len(run.rows)) and {"cve", "asset", "ms"} <= set(t["slowest"][0])
    from verdict.report import write_csv

    write_csv(run, tmp_path / "triage.csv")
    head = (tmp_path / "triage.csv").read_text().splitlines()[0]
    assert head.endswith(";inputs_ms;decide_ms;llm_ms;llm")


def _many(run, n: int) -> list:
    base = next(r for r in run.rows if r.delivery_decision in ("ACT", "ATTEND"))
    rows = []
    for i in range(n):
        r = copy.deepcopy(base)
        r.cve_id, r.asset_id = f"CVE-2099-{20000 + i}", f"host{i}"
        rows.append(r)
    return rows


def test_three_timeouts_leave_the_llm_aside(settings, sources, profile) -> None:
    run = _run(settings, sources, profile)
    rows = _many(run, 8)
    asked: list[str] = []

    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        cve = re.search(r"CVE-2099-\d+", body["messages"][1]["content"]).group(0)
        asked.append(cve)
        if cve in ("CVE-2099-20000", "CVE-2099-20002", "CVE-2099-20004"):  # not consecutive
            raise httpx.ReadTimeout("timed out")
        content = json.dumps({"summary": "Decision for the CVE.", "action": "Plan it."})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    settings.llm.enabled, settings.llm.parallel = True, 1
    triage = Triage(settings, LlmClient(settings.llm, transport=httpx.MockTransport(handler)))
    for r in rows:
        r.timing = {"inputs_ms": 0.0, "decide_ms": 0.0, "llm_ms": 0.0, "llm": "not asked"}
    triage._llm_rationales(rows)
    assert triage.llm_timeouts == 3 and "3 questions not answered in time" in triage.llm_stopped
    assert len(asked) == 5  # asked once each, and no more after the third timeout
    outcomes = [r.timing["llm"] for r in rows]
    assert outcomes == ["timeout", "llm", "timeout", "llm", "timeout", "stopped", "stopped", "stopped"]
    assert all(r.rationale_source.startswith("template (LLM left aside") for r in rows[5:])


def test_a_slow_rationale_no_longer_holds_the_others(settings, sources, profile) -> None:
    """A window: with two places, the fast groups go on while one waits (a batch waited for it)."""
    run = _run(settings, sources, profile)
    rows = _many(run, 6)

    def handler(request: httpx.Request) -> httpx.Response:
        if "CVE-2099-20000" in json.loads(request.content)["messages"][1]["content"]:
            time.sleep(0.6)
        content = json.dumps({"summary": "Decision for the CVE.", "action": "Plan it."})
        return httpx.Response(200, json={"choices": [{"message": {"content": content}}]})

    settings.llm.enabled, settings.llm.parallel = True, 2
    triage = Triage(settings, LlmClient(settings.llm, transport=httpx.MockTransport(handler)))
    for r in rows:
        r.timing = {"inputs_ms": 0.0, "decide_ms": 0.0, "llm_ms": 0.0, "llm": "not asked"}
    started = time.perf_counter()
    triage._llm_rationales(rows)
    assert time.perf_counter() - started < 1.0
    assert rows[0].timing["llm_ms"] >= 500 and all(r.timing["llm_ms"] < 500 for r in rows[1:])
    assert {r.timing["llm"] for r in rows} == {"llm"}


def test_the_llm_run_records_the_outcomes(settings, sources, profile) -> None:
    def answer(name, body):
        if name == "ssvc_inputs":
            return {"automatable": "no", "technical_impact": "partial", "justification": "Local user required."}
        if name == "product_match":
            return {"same_product": False, "justification": "Mobile client, not the gateway OS."}
        return {"summary": "Decision for the CVE.", "action": "Plan it."}

    settings.llm.enabled = True
    run = _run(settings, sources, profile, LlmClient(settings.llm, transport=fake_llm_transport(answer)))
    by = _by_cve(run)
    assert {r.timing["llm"] for r in run.rows} <= {"llm", "not asked", "rejected"}
    assert by["CVE-2024-3400"].timing["llm"] == "llm"
    assert {"failed", "timeouts", "failed_seconds"} <= set(run.llm_usage)


# -- 3. the tree walked, from the decision service ------------------------------------------------------
@pytest.fixture
def index(settings, sources, profile, tmp_path):
    run = _run(settings, sources, profile)
    write_json(run, tmp_path / "triage.json")
    doc = json.loads((tmp_path / "triage.json").read_text())
    return RunIndex({"id": "r1", "generated_at": doc["generated_at"]}, doc)


def test_the_tree_walked_by_the_run(index) -> None:
    g = index.triage_graph({})
    assert g["decisions"] == len(index.rows)
    assert [c["point"] for c in g["columns"]] == [c[0] for c in ssvcgraph.COLUMNS]
    for column in g["columns"]:
        assert sum(v["count"] for v in column["values"]) == g["decisions"]
    for i in range(len(g["columns"]) - 1):  # every decision goes from one point to the next
        point = g["columns"][i]["point"]
        assert sum(link["count"] for link in g["links"] if link["from"][0] == point) == g["decisions"]
    assert sum(p["count"] for p in g["paths"]) == g["decisions"]
    assert g["timing"]["measured"] and set(g["timing"]["totals_ms"]) == {"inputs_ms", "decide_ms", "llm_ms"}
    act = index.triage_graph({"level": "ACT"})
    assert act["decisions"] == sum(1 for r in index.rows if r["delivery_decision"] == "ACT")
    with pytest.raises(ValueError):
        index.triage_graph({"level": "SOON"})


def test_a_rationale_is_counted_once_for_its_assets() -> None:
    rows = [
        {"cve_id": "CVE-1", "delivery_decision": "ACT", "timing": {"inputs_ms": 1, "decide_ms": 1, "llm_ms": 900}},
        {"cve_id": "CVE-1", "delivery_decision": "ACT", "timing": {"inputs_ms": 0, "decide_ms": 1, "llm_ms": 900}},
        {"cve_id": "CVE-1", "delivery_decision": "ACT", "timing": {"inputs_ms": 0, "decide_ms": 1, "llm_ms": 900}},
    ]
    g = ssvcgraph.graph(rows)
    assert g["columns"][0]["values"][0]["ms"] == 904.0  # 4 ms of decisions, one rationale of 900 ms
    assert ssvcgraph.timing(rows, {})["totals_ms"]["llm_ms"] == 900.0


def test_a_run_made_before_v0280() -> None:
    rows = [{"cve_id": "CVE-1", "delivery_decision": "TRACK", "exploitation": {"value": "none"}}]
    t = ssvcgraph.timing(rows, {})
    assert t["measured"] is False and "before v0.28.0" in t["note"]
    assert ssvcgraph.graph(rows)["columns"][1]["values"][0]["value"] == "unknown"


def test_the_contract_carries_the_graph() -> None:
    spec = yaml.safe_load((ROOT / "ngvm/src/ngvm/schemas/openapi/verdict.v1.yaml").read_text(encoding="utf-8"))
    assert spec["paths"]["/v1/tenants/{tenant}/triage-graph"]["get"]["operationId"] == "getTriageGraph"
    assert "TriageGraph" in spec["components"]["schemas"]


# -- 4. the pages ---------------------------------------------------------------------------------------------
def test_the_run_page_draws_the_tree_and_the_time(index) -> None:
    page = supervision.page({"tenant": "lab", "run": {}, "pillars": {}}, "", index.triage_graph({}))
    assert "The triage, decision by decision" in page and "<svg class='graph'" in page
    assert "Where the triage time went" in page and "The paths taken most" in page
    assert "<script" not in page and "href='/decision?level=ACT'" in page
    assert "<a href='/home'>home</a>" in page
    older = supervision.page({"tenant": "lab", "run": {}, "pillars": {}}, "", {"state": "no such route"})
    assert "no such route" in older and "<svg" not in older


def test_the_page_of_a_decision(index) -> None:
    rid = next(iter(index.by_id))
    d = index.decision(rid)
    page = triagepages.decision_page({"tenant": "lab", "query": {}, "decision": d, "graph": index.triage_graph({})})
    assert f"{d['cve_id']} on {d['asset_id']}" in page and "Its path through the SSVC tree" in page
    assert "stroke-width='2.5'" in page  # its path drawn over the run's
    assert "What it cost" in page and "<form method='get' action='/decision'" in page
    found = triagepages.decision_page({"tenant": "lab", "query": {"cve": "<b>"}, "items": [], "total": 0})
    assert "No decision of the last run matches" in found and "value='&lt;b&gt;'" in found
    assert "form-action 'self'" in CSP and "script-src" not in CSP


def test_the_central_page() -> None:
    page = triagepages.home_page(
        {
            "tenant": "lab",
            "run": {"run": "r1", "state_text": "done"},
            "summary": {"findings": {"ACT": 3}},
            "review_url": "https://alerts.example.org",
            "links": [{"name": "Grafana", "url": "https://grafana.example.org", "note": "dashboards"}],
        }
    )
    for href in ("/run", "/decision", "/exposure", "https://alerts.example.org", "https://grafana.example.org"):
        assert f"href='{href}'" in page
    assert "rel='noopener noreferrer'" in page


def test_the_links_of_the_central_page(capsys) -> None:
    from verdict.service.cli import _links

    out = _links(["Chat=https://chat.example.org", "Grafana=http://grafana.example.org", "Reports=https://"])
    assert out == [{"name": "Chat", "url": "https://chat.example.org", "note": "ask the decisions of the run in words"}]
    assert capsys.readouterr().err.count("left out") == 2


def test_the_pages_are_served_and_routed() -> None:
    from verdict.service.tools import PAGE_PATHS

    assert {"/home", "/decision", "/decision/", "/run", "/exposure"} <= PAGE_PATHS
    review = (ROOT / "deploy/charts/ngvm-tenant/templates/review.yaml").read_text(encoding="utf-8")
    assert '-tools:8080/decision" $name' in review and '-tools:8080/home" $name' in review
    chat = (ROOT / "deploy/charts/ngvm-tenant/templates/chat.yaml").read_text(encoding="utf-8")
    assert "--link=Chat=" in chat and "range .Values.pages.links" in chat
    values = yaml.safe_load((ROOT / "deploy/charts/ngvm-tenant/values.yaml").read_text(encoding="utf-8"))
    assert values["pages"] == {"links": []}
    pipeline = (ROOT / "templates/client-pipeline.yml").read_text(encoding="utf-8")
    assert '"Reports|${NGVM_PORTAL_URL:-}" "Grafana|${NGVM_GRAFANA_URL:-}"' in pipeline
    assert "$LINKS $PULL" in pipeline


# -- 5. documented ------------------------------------------------------------------------------------
def test_documented() -> None:
    kube = (ROOT / "docs/kubernetes.md").read_text(encoding="utf-8")
    assert "| `NGVM_GRAFANA_URL` |" in kube and "| `NGVM_PORTAL_URL` |" in kube
    llm = (ROOT / "docs/llm.md").read_text(encoding="utf-8")
    assert "max_timeouts" in llm
    ops = (ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert "questions not answered in time" in ops
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert "| v0.28.0 (current) |" in hld


def test_release_recorded() -> None:
    assert "## v0.28.0 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(28\.\d+|29\.\d+|[3-9]\d\.\d+)$", chart, re.M)
