# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.28.2: the corrections found while validating v0.28.1 on the tenant `lab`.

Blocking:
- An application row written without a publisher (Cyberwatch gives none) could not be read again: the
  whole table failed, and with it every passage of the watch (three days without a passage). The row
  keeps its fields; an unreadable row is left out with a warning.
- The via step stopped at the first batch of the shared service that failed: 5 batches of 29 kept,
  58 754 findings without a record. Every batch is asked; the CVEs of the batches lost are read from
  the sources directly.
- A finding read but not decided (no record) was closed as fixed when its asset had been scanned
  again: 58 397 findings closed. The run lists its undecided findings; the history leaves them as
  they were.
"""

from __future__ import annotations

import gzip
import json
import re

import httpx
import pytest

from ngvm import applications as apps
from ngvm.db import Database
from ngvm.service import TokenSet, digest
from verdict.service.index import row_id
from verdict.service.pgstore import MIGRATIONS, PgRunStore
from verdict.service.server import Service
from via.intel import collect as intel_collect
from via.intel import remote

from .conftest import ROOT
from .test_v0181 import LATER, PUBLISH, READ, _doc

# -- 1. the applications table ----------------------------------------------------------------------


def test_a_row_without_a_publisher_is_read_back():
    row = apps.Row(key="|7-zip", vendor="", name="7-Zip", sources=["cyberwatch"])
    data = json.loads(json.dumps(row.to_dict()))
    assert data["vendor"] == "" and data["name"] == "7-Zip" and data["key"] == "|7-zip"
    assert apps.load_table([data])["|7-zip"].name == "7-Zip"


def test_rows_written_before_the_fix_are_read_and_a_bad_row_is_left_out():
    written_by_v0281 = {"key": "|django", "name": "Django", "state": "new", "sources": ["cyberwatch"]}
    no_name = {"key": "|b095ce3088aa", "state": "new"}
    broken = {"name": "no key", "state": "new"}
    unknown_state = {"key": "|x", "vendor": "v", "name": "x", "state": "lost"}
    skipped: list[str] = []
    table = apps.load_table([written_by_v0281, no_name, broken, unknown_state], skipped)
    assert set(table) == {"|django", "|b095ce3088aa"}
    assert table["|django"].vendor == "" and table["|b095ce3088aa"].name == "|b095ce3088aa"
    assert len(skipped) == 2 and all("left out" in s for s in skipped)


# -- 2. the batches of the shared service -------------------------------------------------------------


def _service(fail: set[int], calls: list[int]):
    def handler(request: httpx.Request) -> httpx.Response:
        body = json.loads(request.content)
        n = len(calls) + 1
        calls.append(n)
        if n in fail:
            raise httpx.ReadTimeout("timed out", request=request)
        errors = [{"cve": c, "error": "not found"} for c in body["cves"]]
        return httpx.Response(200, json={"records": [], "errors": errors})

    return httpx.MockTransport(handler)


def test_a_failed_batch_no_longer_stops_the_others(monkeypatch):
    monkeypatch.setattr(remote, "BATCH", 2)
    calls: list[int] = []
    client = remote.IntelClient("http://intel", "t", transport=_service({2}, calls))
    ids = [f"CVE-2026-{i:05d}" for i in range(1, 9)]  # 4 batches
    _, errors, notes = client.records(ids)
    assert calls == [1, 2, 3, 4]
    assert client.unanswered == ids[2:4] and len(errors) == 6
    assert any(n.startswith("WARN intel: batch 2 of 4 failed") for n in notes)


def test_two_failed_batches_in_a_row_leave_the_rest_unasked(monkeypatch):
    monkeypatch.setattr(remote, "BATCH", 2)
    calls: list[int] = []
    client = remote.IntelClient("http://intel", "t", transport=_service({2, 3}, calls))
    ids = [f"CVE-2026-{i:05d}" for i in range(1, 11)]  # 5 batches
    client.records(ids)
    assert calls == [1, 2, 3] and client.unanswered == ids[2:]


def test_a_single_batch_that_fails_still_raises():
    client = remote.IntelClient("http://intel", "t", transport=_service({1}, []))
    with pytest.raises(remote.IntelError):
        client.records(["CVE-2026-00001"])


def test_the_cves_of_lost_batches_are_read_from_the_sources(monkeypatch, settings, sources):
    monkeypatch.setattr(remote, "BATCH", 2)
    sources.settings.intel_url, sources.settings.intel_token_file = "http://intel", None
    monkeypatch.setenv("NGVM_INTEL_TOKEN", "t")
    asked: list[list[str]] = []

    def direct(_sources, cve_ids, packages=False):
        asked.append(list(cve_ids))
        return intel_collect.Collection(requested=list(cve_ids), notes=["direct"])

    monkeypatch.setattr(intel_collect, "collect_direct", direct)
    ids = [f"CVE-2026-{i:05d}" for i in range(1, 7)]
    out = intel_collect.collect_shared(sources, ids, transport=_service({2}, []))
    assert asked == [ids[2:4]]
    assert any("2 CVEs of failed batches read from the sources directly" in n for n in out.notes)
    sources.settings.intel_fallback = False
    asked.clear()
    out = intel_collect.collect_shared(sources, ids, transport=_service({2}, []))
    assert asked == [] and any("not read (intel_fallback false)" in n for n in out.notes)
    assert {e["cve"] for e in out.errors if e["error"] == "shared service batch failed"} == set(ids[2:4])


# -- 3. the undecided findings are not closed -------------------------------------------------------------


def test_the_run_lists_its_undecided_findings(settings, sources, profile, tmp_path):
    doc = _doc(settings, sources, profile, tmp_path)
    assert "undecided" not in doc or doc["undecided"] == sorted(doc["undecided"])
    schema = json.loads((ROOT / "ngvm/src/ngvm/schemas/triage.schema.json").read_text())
    assert schema["properties"]["undecided"]["items"]["type"] == "string"


def test_a_finding_without_a_record_this_run_is_not_closed(tenant_db, settings, sources, profile, tmp_path):
    doc = _doc(settings, sources, profile, tmp_path)
    digests = tmp_path / "digests"
    digests.write_text(f"publish {digest(PUBLISH)}\nread {digest(READ)}\n")
    db = Database(tenant_db, "verdict", MIGRATIONS)
    db.init()
    service = Service(doc["client"]["id"], TokenSet.load(digests, {"publish", "read"}), PgRunStore(db))
    tenant = service.tenant

    def push(d, key):
        return service.push(tenant, PUBLISH, key, gzip.compress(json.dumps(d).encode()), True)

    push({**doc, "generated_at": "2026-11-19T07:15:00+00:00"}, "d1")
    by_asset: dict[str, list] = {}
    for r in doc["rows"]:
        by_asset.setdefault(r.get("asset_id_full") or r["asset_id"], []).append(r)
    short, patched = sorted(by_asset)[:2]
    rows = [r for r in doc["rows"] if (r.get("asset_id_full") or r["asset_id"]) not in (short, patched)]
    rescanned_all = [{**a, "scans": {k: LATER for k in a["scans"]}} for a in doc["assets"]]
    undecided = sorted(row_id(r) for r in by_asset[short])  # read, no record this time
    push({**doc, "generated_at": "2026-11-20T07:15:00+00:00", "rows": rows, "assets": rescanned_all,
          "undecided": undecided}, "d2")  # fmt: skip
    closed = service.read(tenant, READ, "findings/closed", {"since": "2026-11-01", "limit": "200"})
    assert {i["asset"] for i in closed["items"]} == {patched}
    unverified = service.read(tenant, READ, "findings/unverified", {"since": "2026-11-01", "limit": "200"})
    assert short not in {i["asset"] for i in unverified["items"]}
    with db.tx(tenant) as conn:
        states = conn.execute(
            "SELECT closed_at, unverified_since FROM verdict.findings WHERE tenant = %s AND finding = ANY(%s)",
            (tenant, undecided),
        ).fetchall()
    assert len(states) == len(undecided) and all(c is None and u is None for c, u in states)


def test_the_triage_warns_when_records_are_missing():
    source = (ROOT / "verdict/src/verdict/cli.py").read_text()
    assert "UNDECIDED_WARN = 0.10" in source and "kept open, not closed" in source


# -- 4. the address check and the shared service the job deploys ----------------------------------------


def test_the_shared_service_the_job_deploys_passes_the_check(tmp_path):
    from .test_v0273 import _check

    url = "http://ngvm-hub-intel.ngvm-hub.svc:8080"
    first = _check(tmp_path, NGVM_INTEL_URL=url, NGVM_INTEL_SERVE="true", NGVM_DEPLOY_NAMESPACE="ngvm-hub")
    assert first.returncode == 0, first.stderr
    assert "service ngvm-hub-intel in namespace ngvm-hub, deployed by this job" in first.stdout
    elsewhere = _check(tmp_path, NGVM_INTEL_URL=url, NGVM_INTEL_SERVE="true", NGVM_DEPLOY_NAMESPACE="ngvm-lab")
    client = _check(tmp_path, NGVM_INTEL_URL=url, NGVM_DEPLOY_NAMESPACE="ngvm-hub")
    assert elsewhere.returncode == 1 and client.returncode == 1  # a client of a missing service still stops


def test_the_deploy_job_gives_its_namespace_to_the_check():
    text = (ROOT / "templates/client-pipeline.yml").read_text(encoding="utf-8")
    job = text[text.index("\ndeploy-k8s:") :]
    assert job.index('NS="${NGVM_K8S_NAMESPACE') < job.index('NGVM_DEPLOY_NAMESPACE="$NS" sh .ngvm/deploy/k8s/check')


# -- 5. a 403 on the code of NGVM says what to do ---------------------------------------------------------


def test_a_fetch_refused_names_the_job_token_permissions(tmp_path):
    import shutil

    if shutil.which("sh") is None:
        pytest.skip("needs a POSIX shell")
    from .test_v0275 import TOKEN, _fetch

    repo = f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org:443/vulnops/clients/lab.git"
    code, out, _ = _fetch(tmp_path, "", CI_REPOSITORY_URL=repo)
    assert code == 1 and "could not be fetched from vulnops/ngvm by any address" in out
    assert "refused (403) to the job token of" in out and "Job token permissions, add this project or its group" in out
    assert TOKEN not in out


# -- 6. the watch says when it has no shared service ------------------------------------------------------


def test_the_watch_says_it_reads_no_shared_feed(settings, sources, capsys):
    from via.alert import watch

    sources.settings.intel_url = ""
    src = watch.Source("ngvm-intel", "NGVM — shared feed", "radar", "intel")
    assert watch._read_intel(sources, src, watch.State()) == []
    assert "no shared service (NGVM_INTEL_URL not set)" in capsys.readouterr().out


# -- 7, 8. the chat's date and why a CVE is unknown ----------------------------------------------------


def test_every_chat_answer_gives_today_and_the_spec_says_why(tmp_path):
    from .test_v0274 import CHAT, _cve_tools, _handler

    tools = _cve_tools(tmp_path, _handler([], errors={"CVE-2026-115560": "CVE record not found"}))
    out = tools.handle(CHAT, "/cves/CVE-2026-115560", {})
    assert re.fullmatch(r"\d{4}-\d{2}-\d{2}", out["today"])
    assert "never with what you believe the date is" in tools.spec["info"]["description"]


def test_a_cve_not_in_the_cve_list_is_not_published(tmp_path):
    from .test_v0274 import CHAT, _cve_tools, _handler

    out = _cve_tools(tmp_path, _handler([], errors={"CVE-2026-115560": "CVE record not found"})).call(
        CHAT, "/cves/CVE-2026-115560", {}
    )
    assert out["state"] == "not_published" and out["concerned"] is None and "reserved" in out["why"]


def test_sources_out_of_reach_are_not_a_verdict_on_the_cve(tmp_path):
    from .test_v0274 import CHAT, _cve_tools, _handler

    error = "cvelistV5 not read: relay timed out"
    out = _cve_tools(tmp_path, _handler([], errors={"CVE-2026-90018": error})).call(CHAT, "/cves/CVE-2026-90018", {})
    assert out["state"] == "source_unavailable" and "ask again later" in out["why"]


# -- 9. a burst of publications on one product -----------------------------------------------------------


def _weak_alert(n: int, host):
    from ngvm.models import AffectedEntry, VulnRecord
    from via.alert import watch

    cve = f"CVE-2026-{90000 + n}"
    record = VulnRecord(cve, "PUBLISHED", "2026-11-19T14:00:00Z", "a flaw", [], [],
                        [AffectedEntry("Linux", "Linux", [], "affected", [], "cna")], None, None, [])  # fmt: skip
    item = watch.Item(f"CVE:{cve}", "cve", cve, [cve], "2026-11-19T14:00:00Z", source="CVE (cvelistV5)")
    return watch.Alert(f"homelab-CVE-{cve}", "homelab", "info", item, [record], [], [], {},
                       possible=[(host, "linux-headers-6.8.0-147 6.8.0-147.147")])  # fmt: skip


def test_a_burst_of_weak_alerts_is_one_alert():
    from types import SimpleNamespace

    from via.alert import fiche, watch
    from via.alert.i18n import reason

    host = SimpleNamespace(id="host:gitlab", name="gitlab")
    burst = [_weak_alert(n, host) for n in range(35)]
    urgent = dataclasses_replace(_weak_alert(99, host), level="urgent", reasons=["kev"])
    out = watch.gather_bursts([*burst, urgent], "homelab")
    assert len(out) == 2 and out[0] is urgent
    one = out[1]
    assert len(one.item.cves) == 35 and one.reasons == ["burst:35"] and one.level == "info"
    assert one.id.startswith("homelab-burst-linux-linux-") and len(one.possible) == 1
    assert "35 publications about the same product" in reason("en", "burst:35")
    assert "regroupées en une alerte" in reason("fr", "burst:35")
    assert fiche.MAX_PRODUCT_LINES == 20
    few = watch.gather_bursts(burst[: watch.BURST_MIN - 1], "homelab")
    assert len(few) == watch.BURST_MIN - 1  # under the threshold, each alert stays


# -- 10. the pages answer before the proxy -------------------------------------------------------------


def test_the_numbers_of_the_home_page_are_asked_in_parallel_each_bounded(tmp_path, monkeypatch):
    import threading
    import time

    from verdict.service import tools as tools_mod

    from .test_v0232 import _tools

    monkeypatch.setattr(tools_mod, "PAGE_CALL_TIMEOUT", 0.5)
    in_flight, most = [0], [0]
    lock = threading.Lock()

    def handler(request: httpx.Request) -> httpx.Response:
        with lock:
            in_flight[0] += 1
            most[0] = max(most[0], in_flight[0])
        try:
            time.sleep(0.2)
            if request.url.path.endswith("/summary"):
                raise httpx.ReadTimeout("slow", request=request)
            return httpx.Response(200, json={})
        finally:
            with lock:
                in_flight[0] -= 1

    tools = _tools(tmp_path, handler)
    started = time.monotonic()
    data = tools._progress_data(max_age=0)
    assert time.monotonic() - started < 2.0 and most[0] >= 3  # not the sum of the calls
    assert data["pillars"]["triage"]["state"] == "the decision service did not answer within 0.5 s"


def test_a_page_says_the_decision_service_is_slow_before_the_proxy_gives_up(tmp_path):
    from verdict.service import tools as tools_mod

    from .test_v0232 import _tools

    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("slow", request=request)

    with pytest.raises(tools_mod.Problem) as caught:
        _tools(tmp_path, handler)._raw("triage-graph", {})
    assert caught.value.status == 504 and "try again" in caught.value.detail
    assert tools_mod.PAGE_READ_TIMEOUT < 30 and tools_mod.PAGE_CALL_TIMEOUT < 30  # the proxy waits 30 s


# -- 11. the new CVEs never wait behind a collection -----------------------------------------------------


def test_new_records_answers_from_memory_or_at_once_while_collecting(tmp_path):
    from ngvm.service import Problem

    from .test_v0220 import READ as INTEL_READ
    from .test_v0220 import _service

    service = _service(tmp_path)
    first = service.new_records(INTEL_READ, {"since": "2099-10-05"})
    assert service.new_records(INTEL_READ, {"since": "2099-10-05"}) is first  # from memory
    service.collect_lock.acquire()
    try:
        stale = service.new_records(INTEL_READ, {"since": "2099-10-05"})
        assert stale["total"] == first["total"]
        service._new_cache.clear()
        with pytest.raises(Problem) as caught:
            service.new_records(INTEL_READ, {"since": "2099-10-05"})
        assert caught.value.status == 503
    finally:
        service.collect_lock.release()


# -- 13. Cyberwatch's libraries go through OSV ------------------------------------------------------------


def test_cyberwatch_libraries_are_typed_with_their_purl():
    from detect import cyberwatch

    comps = {c["name"]: c for c in cyberwatch._components({"packages": [
        {"product": "actionpack", "version": "7.1.3", "type": "Packages::Gem"},
        {"product": "Django", "version": "4.2.1", "type": "Packages::Pip"},
        {"product": "org.apache.logging.log4j:log4j-core", "version": "2.17.1", "type": "Packages::Maven"},
        {"product": "log4j-core", "version": "2.17.1", "type": "Packages::Maven"},
        {"product": "7-Zip", "version": "23.01", "type": "Packages::Msi"},
        {"product": "openssl", "version": "3.0.7", "type": "Packages::Rpm"},
    ]})}  # fmt: skip
    assert comps["actionpack"]["purl"] == "pkg:gem/actionpack@7.1.3" and comps["actionpack"]["type"] == "library"
    assert comps["Django"]["purl"] == "pkg:pypi/django@4.2.1"
    maven = comps["org.apache.logging.log4j:log4j-core"]["purl"]
    assert maven == "pkg:maven/org.apache.logging.log4j/log4j-core@2.17.1"
    assert comps["log4j-core"]["type"] == "application"  # no group: no purl, the table as before
    assert comps["7-Zip"]["type"] == "win" and comps["openssl"]["type"] == "rpm"
    assert not apps.is_application(comps["Django"]) and apps.is_application(comps["7-Zip"])


def dataclasses_replace(obj, **kw):
    import dataclasses

    return dataclasses.replace(obj, **kw)


def test_documented() -> None:
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert "| v0.28.2 (current) |" in hld or "| v0.28.2 |" in hld
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "`undecided`" in changelog and "job token permissions" in changelog


def test_release_recorded() -> None:
    assert "## v0.28.2 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(28\.([2-9]|\d\d+)|29\.\d+|[3-9]\d\.\d+)$", chart, re.M)
