# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.26.2: the supervision page of the run.

Until now, where a run had got to was only in the logs of its pod. Each step of the daily chain now
says where it is, at its start and at its end: on the working volume and to the decision service,
which keeps the last runs and serves them. The tool server shows the chain and the numbers worth
watching for each of the four pillars, on `/run` behind the review page's sign-in, and answers
`get_run_progress` in the chat.
"""

from __future__ import annotations

import datetime as dt
import json
import re

import httpx
import pytest

from ngvm import progress
from ngvm.service import Problem, TokenSet, digest
from verdict.service import supervision
from verdict.service.server import Service
from verdict.service.store import PROGRESS_KEEP, RunStore

from .conftest import ROOT
from .test_v0232 import CHAT, _tools

BIG = b'{"schema": "ngvm.progress/1", "run": "1", "step": "via", "state": "done", "x": "' + b"y" * 9000 + b'"}'
PUBLISH = "publish-token-0123456789abcdef0123"
READ = "read-token-0123456789abcdef012345"
TENANT = "example-client"
HELPERS = ROOT / "deploy/charts/ngvm-tenant/templates/_helpers.tpl"
DAILY = ROOT / "deploy/charts/ngvm-tenant/templates/cronjob-daily.yaml"
REVIEW = ROOT / "deploy/charts/ngvm-tenant/templates/review.yaml"
CHAT_YAML = ROOT / "deploy/charts/ngvm-tenant/templates/chat.yaml"


# -- what a step records ---------------------------------------------------------------------------
def test_a_step_records_its_start_then_its_end(tmp_path) -> None:
    lock = tmp_path / ".ngvm-run"
    lock.mkdir()
    (lock / "started").write_text("1763240400")
    work = tmp_path / "work"
    work.mkdir()
    (work / "records.json").write_text("x" * 2048)
    common = ["--dir", str(tmp_path / "progress"), "--run-file", str(lock / "started")]

    assert progress.main(["start", "--step", "via", *common]) == 0
    written = json.loads((tmp_path / "progress" / "02-via.json").read_text())
    assert written["run"] == "1763240400" and written["state"] == "running" and written["pillar"] == "watch"
    assert written["order"] == 2 and written["started_at"] and "ended_at" not in written
    assert dt.datetime.fromisoformat(written["run_started_at"])  # the moment the run took the volume

    assert progress.main(["end", "--step", "via", "--code", "3", "--output", str(work), *common]) == 0
    ended = json.loads((tmp_path / "progress" / "02-via.json").read_text())
    assert ended["state"] == "partial" and ended["code"] == 3  # exit 3: a warning, the run goes on
    assert ended["started_at"] == written["started_at"] and ended["seconds"] >= 0
    assert ended["outputs"] == {"files": 1, "bytes": 2048}


def test_a_step_is_never_stopped_by_its_own_supervision(tmp_path) -> None:
    """No volume to write on, no service to reach, a name that is not a step: the step goes on."""
    assert progress.main(["start", "--step", "via", "--dir", "/proc/nowhere/progress"]) == 0
    assert progress.main(["start", "--step", "NOPE", "--dir", str(tmp_path)]) == 0
    assert not list(tmp_path.glob("*.json"))
    token = tmp_path / "token"
    token.write_text("publish-token-0123456789abcdef0123")
    assert (
        progress.main(
            [
                "end",
                "--step",
                "via",
                "--dir",
                str(tmp_path),
                "--url",
                "http://127.0.0.1:1",
                "--tenant",
                "lab",
                "--token-file",
                str(token),
                "--timeout-seconds",
                "0.2",
            ],
        )  # fmt: skip
        == 0
    )
    assert json.loads((tmp_path / "02-via.json").read_text())["state"] == "done"  # kept all the same


def test_a_step_of_another_run_does_not_borrow_its_start(tmp_path) -> None:
    folder = tmp_path / "progress"
    progress.write(folder, progress.record("triage", "1763240400", state="running"))
    entry = progress.record("triage", "1763326800", state="done", code=0)
    progress.write(folder, entry)
    kept = json.loads((folder / "05-triage.json").read_text())
    assert kept["run"] == "1763326800"
    assert progress.state_of(0) == "done" and progress.state_of(3) == "partial" and progress.state_of(1) == "failed"


def test_a_run_started_by_hand_still_has_an_id(tmp_path) -> None:
    run = progress.run_id(tmp_path / "absent")
    assert re.match(r"^\d{8}T\d{4}$", run) and progress.started_at(run) == ""


# -- the decision service keeps the chain ----------------------------------------------------------
def _service(tmp_path, backend=None) -> Service:
    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(PUBLISH)}\nread {digest(READ)}\n")
    if backend:
        from ngvm.db import Database
        from verdict.service.pgstore import MIGRATIONS, PgRunStore

        db = Database(backend, "verdict", MIGRATIONS)
        db.init()
        store: RunStore | PgRunStore = PgRunStore(db)
    else:
        store = RunStore(tmp_path / "store")
    return Service(TENANT, TokenSet.load(digests, {"publish", "read"}), store)


def _push(service: Service, step: str, run: str = "1763240400", **kw) -> dict:
    entry = progress.record(step, run, tenant=TENANT, **kw)
    return service.put_progress(TENANT, PUBLISH, json.dumps(entry).encode())


def test_the_chain_of_a_run_as_the_steps_report_it(tmp_path, backend) -> None:
    service = _service(tmp_path, backend)
    _push(service, "collect")
    _push(service, "collect", state="done", code=0, seconds=412.0)
    _push(service, "via", state="running")
    chain = service.progress(TENANT, READ, {})["runs"][0]
    assert [s["step"] for s in chain["steps"]] == ["collect", "via"]  # in the order of the run
    assert chain["steps"][0]["state"] == "done" and chain["steps"][0]["seconds"] == 412.0
    assert chain["steps"][0]["started_at"] and chain["steps"][0]["ended_at"]  # the end kept the start
    assert chain["run"] == "1763240400" and chain["updated_at"]


def test_a_record_carries_nothing_but_a_step_s_own_state(tmp_path, backend) -> None:
    service = _service(tmp_path, backend)
    entry = progress.record("triage", "1763240400", tenant=TENANT, state="done", code=0)
    entry.update({"findings": {"ACT": 9000}, "pod": "p" * 400, "seconds": True, "order": 7, "tenant": "other"})
    chain = service.put_progress(TENANT, PUBLISH, json.dumps(entry).encode())
    (step,) = chain["steps"]
    assert "findings" not in step  # a step does not write the numbers of a pillar
    assert len(step["pod"]) == 120 and step["tenant"] == TENANT and "seconds" not in step
    assert step["order"] == 7


def test_what_the_service_refuses(tmp_path) -> None:
    service = _service(tmp_path)
    for body, status in (
        (b"{", 400),
        (json.dumps({"schema": "other", "run": "1", "step": "via", "state": "done"}).encode(), 422),
        (json.dumps({"schema": progress.SCHEMA, "run": "../x", "step": "via", "state": "done"}).encode(), 422),
        (json.dumps({"schema": progress.SCHEMA, "run": "1", "step": "Via!", "state": "done"}).encode(), 422),
        (json.dumps({"schema": progress.SCHEMA, "run": "1", "step": "via", "state": "finished"}).encode(), 422),
        (BIG, 413),
    ):
        with pytest.raises(Problem) as problem:
            service.put_progress(TENANT, PUBLISH, body)
        assert problem.value.status == status
    with pytest.raises(Problem) as problem:
        service.put_progress(TENANT, READ, json.dumps(progress.record("via", "1")).encode())
    assert problem.value.status == 401  # a read token does not push
    with pytest.raises(Problem) as problem:
        service.progress(TENANT, READ, {"limit": "9"})
    assert problem.value.status == 400


def test_the_last_runs_are_kept_and_the_older_ones_go(tmp_path, backend) -> None:
    """Pushed one after another, in the same second: the order never rests on the file's own date."""
    service = _service(tmp_path, backend)
    pushed = [str(1763240400 + n * 86400) for n in range(PROGRESS_KEEP + 2)]
    for run in pushed:
        _push(service, "collect", run=run, state="done", code=0)
    runs = service.progress(TENANT, READ, {"limit": str(PROGRESS_KEEP)})["runs"]
    assert [r["run"] for r in runs] == list(reversed(pushed[-PROGRESS_KEEP:]))  # the last written first
    chain = _push(service, "via", run=pushed[-1], state="running")
    assert [s["step"] for s in chain["steps"]] == ["collect", "via"]  # the run kept is the one still running


def test_the_chains_are_ordered_on_what_they_say_not_on_the_file_s_date(tmp_path) -> None:
    """Seven runs written at the very same moment: the one kept is still the last, and the older
    ones go. Ordering on the file's mtime kept an older chain and dropped the newest (v0.26.2)."""
    store = RunStore(tmp_path / "store")
    moment = dt.datetime(2026, 11, 16, 6, 0, 0, tzinfo=dt.UTC)
    runs = [str(1763240400 + n * 86400) for n in range(PROGRESS_KEEP + 3)]
    for run in runs:
        store.put_progress(TENANT, progress.record("collect", run, tenant=TENANT, state="done", code=0), now=moment)
    assert [c["run"] for c in store.progress(TENANT, PROGRESS_KEEP + 3)] == list(reversed(runs[-PROGRESS_KEEP:]))


def test_the_route_of_the_contract() -> None:
    import yaml

    spec = yaml.safe_load((ROOT / "ngvm/src/ngvm/schemas/openapi/verdict.v1.yaml").read_text())
    route = spec["paths"]["/v1/tenants/{tenant}/progress"]
    assert route["post"]["security"] == [{"publishToken": []}]
    assert route["get"]["security"] == [{"readToken": []}]
    assert spec["components"]["schemas"]["ProgressStep"]["properties"]["state"]["enum"] == [
        "running", "done", "partial", "failed",
    ]  # fmt: skip
    server = (ROOT / "verdict/src/verdict/service/server.py").read_text()
    assert 'if rest == "progress"' in server


# -- the tool server gathers the chain and the numbers ---------------------------------------------
STEPS = [
    {"step": "collect", "order": 1, "pillar": "detection", "state": "done", "seconds": 412.0, "code": 0,
     "outputs": {"files": 34, "bytes": 12500000}, "pod": "ngvm-lab-daily-29384-abcde"},
    {"step": "via", "order": 2, "pillar": "watch", "state": "partial", "seconds": 88.0, "code": 3},
    {"step": "triage", "order": 5, "pillar": "triage", "state": "running", "started_at": "2026-11-15T06:18:00+00:00"},
]  # fmt: skip
BEFORE = [*({**s, "state": "done", "code": 0} for s in STEPS), {"step": "publish", "order": 7, "pillar": "triage",
                                                                "state": "done", "code": 0}]  # fmt: skip
SUMMARY = {
    "run_id": "r7", "ngvm_version": "0.26.2", "findings": {"ACT": 24, "ATTEND": 180}, "kev": {"ACT": 5},
    "needs_review": 7, "cve_count": 1200, "assets": 1240, "assets_with_findings": 311,
    "coverage": {"covered_share": 0.93}, "llm_usage": {"questions": 120, "from_cache": 104},
}  # fmt: skip
VIA = {
    "version": "0.26.2", "state": "ok", "last_passage": "2026-11-15T05:40:00+00:00", "alerts_last_24h": 2,
    "failing_sources": [{"source": "vendor-x", "failed_passages_in_a_row": 6}],
}  # fmt: skip
DETECT = {"version": "0.26.2", "collectors": [{"id": "lan", "sources": [
    {"source": "openvas", "age_hours": 5.2, "stale": False, "last_received_at": "2026-11-15T05:00:00+00:00"},
    {"source": "cmdb", "age_hours": 50.0, "stale": True, "last_error": "refused"},
]}]}  # fmt: skip


def _handler(asked: list, runs=None):
    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.host, request.url.path, dict(request.url.params)))
        if request.url.host == "detect.example":
            return httpx.Response(200, json=DETECT)
        if request.url.host == "via.example":
            if request.url.path.endswith("/alerts"):
                items = [{"status": s} for s in ("pending", "pending", "sent", "translating")]
                return httpx.Response(200, json={"items": items, "total": 4})
            return httpx.Response(200, json=VIA)
        if request.url.host == "intel.example":
            params = request.url.params
            total = 3 if params.get("kev") == "true" else 17 if params.get("min_cvss") else 412
            if request.url.path == "/v1/status":
                return httpx.Response(200, json={"version": "0.26.2",
                                                 "volume": {"used_percent": 88, "free_bytes": 600000000,
                                                            "alert": True}})  # fmt: skip
            return httpx.Response(200, json={"total": total, "items": []})
        if request.url.host == "dispatch.example":
            return httpx.Response(200, json={"total": 70, "items": [], "counts": {
                "by_state": {"open": 12, "resolved": 58}, "by_level": {"ACT": 70}, "with_itsm_ref": 70}})  # fmt: skip
        if request.url.path.endswith("/progress"):
            answer = {"schema": "ngvm.progress_runs/1", "tenant": TENANT, "runs": runs if runs is not None else []}
            return httpx.Response(200, json=answer)
        if request.url.path.endswith("/summary"):
            return httpx.Response(200, json=SUMMARY)
        if request.url.path.endswith("/status"):
            return httpx.Response(200, json={"version": "0.26.2", "runs": 7, "latest_run": {}})
        return httpx.Response(404, json={"detail": "no"})

    return handler


def _progress_tools(tmp_path, runs):
    return _tools(
        tmp_path, _handler([], runs), via_url="http://via.example", via_token="v",
        detect_url="http://detect.example", detect_token="d", dispatch_url="http://dispatch.example",
        dispatch_token="p", intel_url="http://intel.example", intel_token="i",
    )  # fmt: skip


def test_the_chat_says_where_the_run_is(tmp_path) -> None:
    runs = [{"run": "1763240400", "run_started_at": "2026-11-15T06:00:00+00:00",
             "updated_at": "2026-11-15T06:21:00+00:00", "steps": STEPS},
            {"run": "1763154000", "steps": BEFORE}]  # fmt: skip
    out = _progress_tools(tmp_path, runs).call(CHAT, "/run-progress", {})
    assert out["run"]["state"] == "running"  # a step still running: the run goes on
    assert out["previous_run"] == {"run": "1763154000", "state": "done"}
    steps = {s["step"]: s for s in out["run"]["steps"]}
    assert steps["publish"]["state"] == "waiting"  # not reached yet, known from the run before
    assert steps["collect"]["outputs"]["files"] == 34
    watch = out["pillars"]["watch"]
    assert (watch["new_cves_24h"], watch["new_cves_kev"], watch["new_cves_critical"]) == (412, 3, 17)
    assert watch["alerts_by_status"] == {"pending": 2, "sent": 1, "translating": 1}
    assert watch["failing_sources"][0]["source"] == "vendor-x"
    assert out["pillars"]["detection"]["late_or_refused"][0]["source"] == "cmdb"
    assert out["pillars"]["triage"]["findings"]["ACT"] == 24 and out["pillars"]["triage"]["needs_review"] == 7
    assert out["pillars"]["dispatch"]["by_state"] == {"open": 12, "resolved": 58}
    assert out["agents"]["shared_intelligence_volume"] == {"used_percent": 88, "free_gb": 0.6, "alert": True}
    assert [c["source"] for c in out["agents"]["collectors"]] == ["openvas", "cmdb"]


def test_a_failed_step_decides_the_state_of_the_run(tmp_path) -> None:
    steps = [{"step": "collect", "order": 1, "pillar": "detection", "state": "done", "code": 0},
             {"step": "via", "order": 2, "pillar": "watch", "state": "failed", "code": 1}]  # fmt: skip
    out = _progress_tools(tmp_path, [{"run": "1", "steps": steps}]).call(CHAT, "/run-progress", {})
    assert out["run"]["state"] == "failed"
    assert [s["step"] for s in out["run"]["steps"]] == ["collect", "via"]  # nothing added: the chain stopped


def test_the_chat_answers_before_any_run_reported(tmp_path) -> None:
    out = _progress_tools(tmp_path, []).call(CHAT, "/run-progress", {})
    assert out["run"] == {} and out["previous_run"] == {}
    assert out["pillars"]["triage"]["findings"]["ACT"] == 24  # the pillars answer all the same


def test_the_chain_and_the_numbers_are_not_asked_twice_in_a_row(tmp_path) -> None:
    asked: list = []
    tools = _tools(tmp_path, _handler(asked, []), via_url="http://via.example", via_token="v")
    tools.call(CHAT, "/run-progress", {})
    count = len(asked)
    tools.call(CHAT, "/run-progress", {})
    assert len(asked) == count  # kept for a few seconds: the page asks for itself again


def test_the_tool_is_in_the_contract(tmp_path) -> None:
    from verdict.service.tools import openapi

    spec = openapi(TENANT)
    assert spec["paths"]["/run-progress"]["get"]["operationId"] == "get_run_progress"
    assert "where is the run" in spec["paths"]["/run-progress"]["get"]["description"]


# -- the page --------------------------------------------------------------------------------------
def test_the_page_shows_the_chain_and_the_pillars(tmp_path) -> None:
    runs = [{"run": "1763240400", "run_started_at": "2026-11-15T06:00:00+00:00", "steps": STEPS}]
    tools = _progress_tools(tmp_path, runs)
    page = tools.page("analyst@example.org")
    assert "<script" not in page and "src=" not in page  # style and text only
    assert supervision.CSP in supervision.CSP and "default-src 'none'" in supervision.CSP
    assert "NGVM run — example-client" in page
    for step in ("collect", "via", "triage"):
        assert f"<b>{step}</b>" in page
    assert "class='badge running'" in page and "class='badge partial'" in page
    assert "6 min 52 s" in page  # 412 seconds
    assert "11.9 MB" in page or "11.9 MB" in page.replace("&nbsp;", " ")
    assert "New CVEs in 24 h" in page and ">412<" in page
    assert "Decisions ACT" in page and "Past the client&#x27;s SLA" not in page  # no SLA overdue here
    assert "kubectl -n ngvm-example-client logs ngvm-lab-daily-29384-abcde -c &lt;step&gt;" in page
    assert "<span class='warn'>88 %</span>" in page  # the shared volume is nearly full
    assert "class='badge failed'>late" in page  # the collector that has not pushed


def test_the_page_says_so_when_no_step_has_reported(tmp_path) -> None:
    page = _progress_tools(tmp_path, []).page("")
    assert "No step has reported yet" in page and "no run reported yet" in page


def test_what_the_page_shows_is_escaped(tmp_path) -> None:
    steps = [{"step": "collect", "order": 1, "pillar": "detection", "state": "done",
              "pod": "<img src=x>", "code": 0}]  # fmt: skip
    page = _progress_tools(tmp_path, [{"run": "<b>x</b>", "steps": steps}]).page("")
    assert "<img src=x>" not in page and "&lt;img src=x&gt;" in page
    assert "<b>x</b>" not in page.split("</style></head>")[1].replace("<b>collect</b>", "")


def test_who_looked_at_the_page_is_journaled(tmp_path) -> None:
    from ngvm.audit import AuditLog

    journal = tmp_path / "audit.jsonl"
    tools = _tools(tmp_path, _handler([], []), audit=AuditLog("tools", path=journal))
    tools.page("analyst@example.org")
    tools.page("")
    lines = [json.loads(line) for line in journal.read_text().splitlines()]
    assert [(e["actor"], e["actor_kind"], e["action"], e["target"]) for e in lines] == [
        ("analyst@example.org", "user", "page:run", "/run"),
        ("analyst (not forwarded)", "token", "page:run", "/run"),
    ]


def test_durations_and_sizes_in_words() -> None:
    assert (supervision.span(48), supervision.span(200), supervision.span(3860)) == ("48 s", "3 min 20 s", "1 h 04")
    assert (supervision.size(512), supervision.size(2048), supervision.size(12500000)) == ("512 B", "2.0 kB", "11.9 MB")
    assert supervision.span("") == "" and supervision.size(None) == ""
    assert supervision.moment("2026-11-15T06:18:00+00:00") == "2026-11-15 06:18" and supervision.moment("") == "—"


# -- the chain says where it is, in the chart ------------------------------------------------------
def test_every_step_says_where_it_is() -> None:
    daily, helpers = DAILY.read_text(), HELPERS.read_text()
    assert "ngvm_progress start 0" in daily
    assert 'trap \'rc=$?; ngvm_progress end "$rc"; if [ "$rc" -ne 0 ]; then ngvm_release; fi\' EXIT' in daily
    assert "trap 'rc=$?; ngvm_progress end \"$rc\"; ngvm_release' EXIT" in daily  # the last step of the chain
    assert '{{- define "ngvm-tenant.progress" -}}' in helpers
    assert "python -m ngvm.progress" in helpers and "|| true" in helpers  # never stops a step
    assert "--token-file /secrets/verdict-publish-token" in helpers
    assert "if $root.Values.verdict.enabled" in helpers and "ngvm_progress() { :; }" in helpers
    for step, output in (("collect", "/data/work/detect"), ("via", "/data/work/records.json"),
                         ("triage", "/data/output"), ("assets", "/data/work/assets")):  # fmt: skip
        assert f'"name" "{step}" "pillar" ' in daily
        assert f'"output" "{output}"' in daily
    assert "progress: true" in (ROOT / "deploy/charts/ngvm-tenant/values.yaml").read_text()


def test_the_page_is_behind_the_sign_in_of_the_review_page() -> None:
    review, chat = REVIEW.read_text(), CHAT_YAML.read_text()
    assert '- --upstream={{ printf "http://%s-tools:8080/run" $name }}' in review
    assert review.count("{{- if .Values.chat.enabled }}") >= 1
    assert '(dict "root" . "component" "tools")' in review  # the proxy may reach the tool server
    assert '(dict "root" . "component" "review")' in chat  # which accepts the proxy
    assert "{{- if and .Values.watch.enabled .Values.watch.review.enabled }}" in chat


def test_documented() -> None:
    operations = (ROOT / "docs/operations.md").read_text()
    assert "/run" in operations and "get_run_progress" in operations
    assert "supervision" in operations.lower()
    assert "get_run_progress" in (ROOT / "docs/chat.md").read_text()


def test_release_recorded() -> None:
    assert "## v0.26.2 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(26\.([2-9]|\d\d+)|2[7-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)


def test_the_record_of_a_step_is_small() -> None:
    entry = progress.record("collect", "1763240400", tenant=TENANT, state="done", code=0)
    assert len(json.dumps(entry)) < 512
    assert set(entry) <= {"schema", "tenant", "run", "run_started_at", "step", "order", "pillar", "state",
                          "version", "pod", "started_at", "ended_at", "seconds", "code", "outputs"}  # fmt: skip
    assert progress.record("nope", "1", state="running")["pillar"] == "other"
    assert dt.datetime.fromisoformat(entry["started_at"] if "started_at" in entry else entry["ended_at"])
