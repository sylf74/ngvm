# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.4: the chat never concludes without knowing; a passage of the watch is never too big.

- A CVE in no decision of the run is not, for all that, a CVE that does not concern the tenant: the
  run may predate it, or NGVM may not know it. The decision service's 404 said « no asset is
  concerned », the chat read it so for a CVE published after the run. `get_cve` now asks the shared
  intelligence service and says which; `concerned` stays null unless it is known.
- Every tool's definition goes with every question: a tenant may offer its chat a subset
  (`NGVM_CHAT_TOOLS`, `core` for a model of a 16k context).
- A passage that drafted many alerts was refused whole (413) and seen again at every passage: its
  files now go in batches, the passage is named, and a passage sent again is recorded once.
"""

from __future__ import annotations

import base64
import json
import re
from pathlib import Path

import httpx
import pytest
import yaml

from ngvm.service import Problem
from via.service.client import WatchClient, _batches
from via.service.server import STAGED_BODIES

from .conftest import ROOT
from .test_v0160 import RUN, TENANT, service  # noqa: F401 - the watch service on files and PostgreSQL
from .test_v0232 import CHAT, _tools

RUN_AT = "2026-11-18T04:45:00+00:00"


# -- 1. get_cve says why a CVE is in no decision -----------------------------------------------------
def _handler(asked: list, records: dict | None = None, errors: dict | None = None, intel_down: bool = False):
    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.host, request.url.path))
        if request.url.host == "intel.example":
            if intel_down:
                return httpx.Response(503, json={"detail": "down"})
            cves = json.loads(request.content)["cves"]
            return httpx.Response(200, json={
                "records": [records[c] for c in cves if records and c in records],
                "errors": [{"cve": c, "error": errors[c]} for c in cves if errors and c in errors],
            })  # fmt: skip
        if request.url.path.endswith("/runs"):
            return httpx.Response(200, json={"items": [{"id": "r9", "generated_at": RUN_AT}]})
        if "/cves/" in request.url.path:
            return httpx.Response(404, json={"detail": "this CVE is in no decision of this run"})
        return httpx.Response(404, json={"detail": "no"})

    return handler


def _cve_tools(tmp_path, handler, intel: bool = True):
    extra = {"intel_url": "http://intel.example", "intel_token": "i"} if intel else {}
    return _tools(tmp_path, handler, **extra)


def _record(cve: str, published: str, updated: str = "", state: str = "PUBLISHED") -> dict:
    return {"cve_id": cve, "published": published, "updated": updated or published, "state": state,
            "description": "An example product lets a remote attacker run code.",
            "affected": [{"vendor": "Example", "product": "Widget"}]}  # fmt: skip


def test_a_cve_published_after_the_run_is_said_newer_not_harmless(tmp_path) -> None:
    cve = "CVE-2026-114938"
    tools = _cve_tools(tmp_path, _handler([], records={cve: _record(cve, "2026-11-18T04:50:10+00:00")}))
    out = tools.call(CHAT, f"/cves/{cve}", {})
    assert out["state"] == "newer_than_run" and out["concerned"] is None and out["in_run"] is False
    assert out["run"] == {"id": "r9", "generated_at": RUN_AT}
    assert "could not see it" in out["why"] and "list_alerts" in out["why"]
    assert out["products"] == [{"vendor": "Example", "product": "Widget"}]


def test_a_cve_the_run_knew_is_said_not_detected_with_what_detection_covers(tmp_path) -> None:
    cve = "CVE-2026-10001"
    record = _record(cve, "2026-11-10T08:00:00+00:00", updated="2026-11-18T05:00:00+00:00")
    out = _cve_tools(tmp_path, _handler([], records={cve: record})).call(CHAT, f"/cves/{cve}", {})
    assert out["state"] == "not_detected_at_run" and out["detected_at_run"] is False
    assert out["concerned"] is None  # not detected is not « not concerned »
    assert "scanners and the declared inventory" in out["why"] and "updated after the run" in out["why"]


def test_a_cve_ngvm_does_not_know_is_no_conclusion(tmp_path) -> None:
    cve = "CVE-2026-99999"
    out = _cve_tools(tmp_path, _handler([], errors={cve: "not found at CVE.org"})).call(CHAT, f"/cves/{cve}", {})
    assert out["state"] == "unknown_to_ngvm" and out["concerned"] is None
    assert "not found at CVE.org" in out["why"] and "no conclusion" in out["why"]


def test_a_rejected_cve_is_the_only_conclusion_without_the_run(tmp_path) -> None:
    cve = "CVE-2026-10002"
    record = _record(cve, "2026-11-01T08:00:00+00:00", state="REJECTED")
    out = _cve_tools(tmp_path, _handler([], records={cve: record})).call(CHAT, f"/cves/{cve}", {})
    assert out["state"] == "rejected" and out["concerned"] is False


def test_without_the_shared_service_the_answer_says_it_cannot_conclude(tmp_path) -> None:
    for tools in (
        _cve_tools(tmp_path, _handler([]), intel=False),
        _cve_tools(tmp_path, _handler([], intel_down=True)),
    ):
        out = tools.call(CHAT, "/cves/CVE-2026-10003", {})
        assert out["state"] == "not_in_run" and out["concerned"] is None and "no conclusion" in out["why"]


def test_a_cve_in_the_run_is_answered_by_the_run_alone(tmp_path) -> None:
    asked: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append(request.url.host)
        return httpx.Response(200, json={"cve": "CVE-2026-10004", "concerned": True, "run": {"id": "r9"}})

    out = _cve_tools(tmp_path, handler).call(CHAT, "/cves/CVE-2026-10004", {})
    assert out["concerned"] is True and "intel.example" not in asked


def test_the_tool_and_the_service_no_longer_say_not_concerned_for_unknown() -> None:
    from verdict.service.tools import OPERATIONS

    description = next(s for _p, op, s, _q, _u in OPERATIONS if op == "get_cve")
    assert "A 404 means no asset of the tenant is concerned" not in description
    assert "concerned: null" in description and "newer_than_run" in description
    server = (ROOT / "verdict/src/verdict/service/server.py").read_text(encoding="utf-8")
    assert "no asset of the tenant is concerned by this CVE" not in server
    assert "does not say the tenant is not concerned" in server


# -- 2. the tools a tenant offers its chat ----------------------------------------------------------
def test_core_is_a_dozen_tools_that_exist() -> None:
    from verdict.service.tools import CORE, offered, tool_names

    assert set(CORE) <= set(tool_names()) and 10 <= len(CORE) <= 14
    assert offered("") is None and offered("all") is None
    assert offered("core") == frozenset(CORE)
    assert offered("core, list_chokepoints") == frozenset(CORE) | {"list_chokepoints"}
    with pytest.raises(ValueError, match="get_cvee"):
        offered("core,get_cvee")  # a typo does not silently take a tool away


def test_a_tool_not_offered_is_not_described_nor_answered(tmp_path) -> None:
    from verdict.service.tools import CORE, offered

    tools = _tools(tmp_path, _handler([]), tools=offered("core"))
    ops = {o["operationId"] for item in tools.spec["paths"].values() for o in item.values()}
    assert ops == set(CORE)
    with pytest.raises(Problem) as p:
        tools.call(CHAT, "/chokepoints", {})
    assert p.value.status == 404 and "list_chokepoints is not offered" in p.value.detail


def test_core_leaves_room_in_a_small_context() -> None:
    from verdict.service.tools import offered, openapi

    def size(spec: dict) -> int:
        return len(json.dumps([o for item in spec["paths"].values() for o in item.values()]))

    every, core = size(openapi("lab")), size(openapi("lab", offered("core")))
    assert core < every / 2 and core < 25_000  # characters: about 4,000 tokens of definitions


def test_export_says_its_filters_once() -> None:
    from verdict.service.tools import OPERATIONS

    params = next(q for _p, op, _s, q, _u in OPERATIONS if op == "export_decisions")
    level = next(p for p in params if p["name"] == "level")
    assert level["description"] == "as in search_decisions"


def test_the_tenant_sets_it_and_the_chart_passes_it(tmp_path) -> None:
    import importlib.util

    spec = importlib.util.spec_from_file_location("chat_values", ROOT / "deploy/chat/chat_values.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    source = (ROOT / "deploy/chat/chat_values.py").read_text(encoding="utf-8")
    assert "NGVM_CHAT_TOOLS" in source and 'chat["offeredTools"]' in source
    chart = (ROOT / "deploy/charts/ngvm-tenant/templates/chat.yaml").read_text(encoding="utf-8")
    assert "- --tools={{ $chat.offeredTools }}" in chart
    values = yaml.safe_load((ROOT / "deploy/charts/ngvm-tenant/values.yaml").read_text(encoding="utf-8"))
    assert values["chat"]["offeredTools"] == ""
    assert isinstance(values["chat"]["tools"], dict)  # chat.tools is the tool server's container
    cli = (ROOT / "verdict/src/verdict/service/cli.py").read_text(encoding="utf-8")
    assert '"--tools"' in cli and "tool(s) offered" in cli


# -- 3. a passage in batches ------------------------------------------------------------------------
def _alerts(base: Path, count: int, size: int) -> Path:
    alerts = base / "alerts"
    alerts.mkdir(parents=True, exist_ok=True)
    index = []
    for i in range(count):
        aid = f"lab-CERTFR-2026-ALE-{i:03d}"
        index.append({"id": aid, "docx": f"{aid}.docx"})
        (alerts / f"{aid}.md").write_text(f"# {aid}\n")
        (alerts / f"{aid}.html").write_text(f"<h1>{aid}</h1>")
        (alerts / f"{aid}.docx").write_bytes(bytes(range(256)) * (size // 256))
    (alerts / "index.json").write_text(json.dumps(index))
    return alerts


def test_a_passage_too_big_for_one_body_is_recorded_in_batches(tmp_path, service) -> None:  # noqa: F811
    svc, url, _ = service
    svc.max_bytes = 600_000  # a small service: one body cannot take the passage whole
    alerts = _alerts(tmp_path, 6, 200_000)
    client = WatchClient(url, TENANT, RUN)
    try:
        out = client.put_run({"seen": ["x"]}, [], alerts, batch_bytes=300_000)
    finally:
        client.close()
    assert out["alerts"] == 6 and out["run"] and out["passage"]
    kept = svc.store.alert(TENANT, "lab-CERTFR-2026-ALE-005")
    assert kept is not None
    data = svc.store.file(TENANT, kept["run"], "lab-CERTFR-2026-ALE-005.docx")
    assert data == (alerts / "lab-CERTFR-2026-ALE-005.docx").read_bytes()  # whole, byte for byte
    assert svc.store.staged(TENANT, out["passage"]) == {}  # nothing left staged


def test_the_same_passage_sent_twice_is_recorded_once(tmp_path, service) -> None:  # noqa: F811
    svc, _, _ = service
    files = {
        "index.json": base64.b64encode(json.dumps([{"id": "lab-A-1"}]).encode()).decode(),
        "lab-A-1.md": base64.b64encode(b"# A").decode(),
        "lab-A-1.html": base64.b64encode(b"<h1>A</h1>").decode(),
    }
    body = json.dumps({"state": {"s": 1}, "events": [], "files": files, "passage": "20261118T0450Z-abc123"}).encode()
    first = svc.put_run(TENANT, RUN, body, False)
    again = svc.put_run(TENANT, RUN, body, False)  # a retry after a timeout
    assert again["replayed"] is True and again["run"] == first["run"] and "replayed" not in first
    assert len(svc.store.runs(TENANT)) == 1
    late = svc.stage_files(TENANT, RUN, "20261118T0450Z-abc123", json.dumps({"files": files}).encode(), False)
    assert late == {"passage": "20261118T0450Z-abc123", "recorded": True, "staged": 0}


def test_a_passage_must_still_hold_every_file_its_index_names(tmp_path, service) -> None:  # noqa: F811
    svc, _, _ = service
    passage = "20261118T0500Z-def456"
    index = base64.b64encode(json.dumps([{"id": "lab-B-1"}]).encode()).decode()
    svc.stage_files(TENANT, RUN, passage, json.dumps({"files": {"index.json": index}}).encode(), False)
    body = json.dumps({"state": {}, "events": [], "files": {}, "passage": passage}).encode()
    with pytest.raises(Problem) as p:
        svc.put_run(TENANT, RUN, body, False)
    assert p.value.status == 422 and "missing lab-B-1.md" in p.value.detail


def test_what_a_passage_may_stage_is_bounded(tmp_path, service) -> None:  # noqa: F811
    svc, _, _ = service
    svc.max_bytes = 2000
    big = base64.b64encode(b"x" * 1400).decode()  # one batch: within a body of 2000 bytes
    passage = "20261118T0510Z-0a0b0c"
    for i in range(STAGED_BODIES * svc.max_bytes // 1400):
        svc.stage_files(TENANT, RUN, passage, json.dumps({"files": {f"f{i}.md": big}}).encode(), False)
    with pytest.raises(Problem) as p:
        svc.stage_files(TENANT, RUN, passage, json.dumps({"files": {"more.md": big}}).encode(), False)
    assert p.value.status == 413 and f"more than {STAGED_BODIES} times" in p.value.detail
    with pytest.raises(Problem):
        svc.stage_files(TENANT, RUN, "../../etc", json.dumps({"files": {}}).encode(), False)


def test_a_small_passage_goes_in_one_body_as_before(tmp_path, service) -> None:  # noqa: F811
    svc, url, _ = service
    asked: list = []
    real = httpx.HTTPTransport()

    class Spy(httpx.BaseTransport):
        def handle_request(self, request: httpx.Request) -> httpx.Response:
            asked.append(request.url.path)
            return real.handle_request(request)

    client = WatchClient(url, TENANT, RUN, transport=Spy())
    try:
        out = client.put_run({"s": 1}, [], _alerts(tmp_path, 1, 1024))
    finally:
        client.close()
    assert out["alerts"] == 1 and not any(p.endswith("/files") for p in asked)


def test_an_older_service_gets_the_passage_whole(tmp_path) -> None:
    posted: list = []

    def handler(request: httpx.Request) -> httpx.Response:
        posted.append(request.url.path)
        if request.url.path.endswith("/files"):
            return httpx.Response(404, json={"detail": "no such route"})
        return httpx.Response(202, json={"run": "r", "alerts": 2, "events": 0})

    client = WatchClient("http://via.example", TENANT, RUN, transport=httpx.MockTransport(handler))
    out = client.put_run({}, [], _alerts(tmp_path, 2, 4096), batch_bytes=1000)
    assert out["alerts"] == 2 and posted[-1].endswith("/watch/runs") and posted[0].endswith("/files")


def test_files_are_grouped_under_the_batch_size() -> None:
    sizes = {"a": 400, "b": 400, "c": 400, "huge": 5000}
    assert _batches(sizes, 900) == [["a", "b"], ["c"], ["huge"]]


def test_the_contract_and_the_tables() -> None:
    contract = yaml.safe_load((ROOT / "ngvm/src/ngvm/schemas/openapi/via.v1.yaml").read_text())
    stage = contract["paths"]["/v1/tenants/{tenant}/watch/runs/{passage}/files"]["post"]
    assert stage["operationId"] == "stageWatchFiles"
    body = contract["paths"]["/v1/tenants/{tenant}/watch/runs"]["post"]["requestBody"]
    assert "passage" in body["content"]["application/json"]["schema"]["properties"]
    from via.service.pgstore import MIGRATIONS

    last = MIGRATIONS[-1].sql
    assert "CREATE TABLE via.staged" in last and "CREATE TABLE via.passages" in last
    assert "via.staged FORCE ROW LEVEL SECURITY" in last and "via.passages FORCE ROW LEVEL SECURITY" in last


# -- 4. documented ------------------------------------------------------------------------------------
def test_documented() -> None:
    chat = (ROOT / "docs/chat.md").read_text(encoding="utf-8")
    assert "## 9a. A model of a small context (v0.27.4)" in chat and "`NGVM_CHAT_TOOLS`" in chat
    assert "newer_than_run" in chat
    lld = (ROOT / "docs/lld/vulnerability-intelligence.md").read_text(encoding="utf-8")
    assert "POST watch/runs/{passage}/files" in lld and "`via.passages`" in lld
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert "a passage named and its files sent in batches (v0.27.4" in hld
    assert "`NGVM-Portal-Viewers` and `NGVM-Portal-Admins`" in hld  # Keycloak kept in the backlog
    triage = (ROOT / "docs/lld/triage-prioritization.md").read_text(encoding="utf-8")
    assert "`not_detected_at_run`" in triage


def test_release_recorded() -> None:
    assert "## v0.27.4 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(27\.([4-9]|\d\d+)|2[89]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
