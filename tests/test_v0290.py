# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.29.0: the corrections found on 2026-11-20 and 21.

- GTI: a daily budget kept on the cache volume, shared by every request and tenant; a CVE unknown to
  GTI (404) is not asked again for `gti_missing_hours`.
- The collector's installer logs in to the registry in the persistent file and removes a stale one.
- The chat's new CVEs: an overview by subject, the period said, the CNA of each record.
- Dispatch: the iTop caller hint when the caller is already an e-mail; the job's failure named.
- The address check stops on a host naming a namespace that does not exist.
- The alert mail: its kind (Alerte, Hot Topic, Information) by rules of the profile, the CVE and
  its sources first, a designed HTML body, the delay with its source.
"""

from __future__ import annotations

import datetime as dt
import re

import httpx
import pytest

from ngvm.service import Problem
from via.intel.gti import enrich
from via.intel.sources import GTI_BUDGET_FILE, DailyBudget, Sources, cache_validity_hours

from .conftest import FIXTURES, ROOT
from .test_gti import CVES, _records
from .test_v0220 import READ, _service
from .test_v0232 import CHAT, _tools


# -- 1. GTI: a daily budget and the CVEs GTI does not know ------------------------------------------
def _net(settings, handler):
    return Sources(settings.sources, transport=httpx.MockTransport(handler))


def test_the_daily_budget_is_shared_by_every_request(settings, sources, monkeypatch, tmp_path) -> None:
    monkeypatch.setenv("GTI_API_KEY", "k")
    settings.sources.gti_daily_calls = 3
    settings.sources.gti_workers = 1
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(200, json={"data": {"id": "x", "attributes": {}}})

    records = _records(sources, CVES)
    first = _net(settings, handler)  # one request of the shared service: a new Sources each time
    enrich(first, records[:2])
    second = _net(settings, handler)
    notes = enrich(second, records[2:])
    assert len(calls) == 3  # 2 + 1, not 2 + 2: the budget is the day's, not the request's
    assert any("daily budget of 3 calls spent" in n and "1 CVE not looked up today" in n for n in notes)
    used = DailyBudget(tmp_path / "cache" / GTI_BUDGET_FILE, 3).used()
    assert used["calls"] == 3 and used["daily"] == 3
    again = _net(settings, handler)
    enrich(again, records[:2])  # cached answers are read even when the budget is spent
    assert len(calls) == 3 and all(r.gti is not None for r in records[:2])


def test_the_budget_starts_again_the_next_day(tmp_path) -> None:
    day = [dt.datetime(2026, 11, 20, 23, 0, tzinfo=dt.UTC)]
    budget = DailyBudget(tmp_path / GTI_BUDGET_FILE, 1, now=lambda: day[0])
    assert budget.take() and not budget.take()
    day[0] = dt.datetime(2026, 11, 21, 0, 5, tzinfo=dt.UTC)
    assert budget.take()
    assert DailyBudget(tmp_path / GTI_BUDGET_FILE, 0).take()  # 0: no cap


def test_a_cve_unknown_to_gti_is_not_asked_again(settings, sources, monkeypatch) -> None:
    monkeypatch.setenv("GTI_API_KEY", "k")
    settings.sources.gti_workers = 1
    calls = []

    def handler(request):
        calls.append(request.url.path)
        return httpx.Response(404)

    records = _records(sources, CVES[:2])
    enrich(_net(settings, handler), records)
    enrich(_net(settings, handler), records)  # the next request: the 404 is remembered
    assert len(calls) == 2
    assert all(_net(settings, handler).gti_cached(r.cve_id) for r in records)
    settings.sources.gti_missing_hours = 0
    enrich(_net(settings, handler), records)
    assert len(calls) == 4
    assert cache_validity_hours(settings.sources) >= 72 or settings.sources.gti_missing_hours == 0


def test_the_settings_and_the_status_say_the_budget(monkeypatch, tmp_path) -> None:
    from ngvm.config import describe_gti, load_settings

    monkeypatch.setenv("NGVM_GTI_ENABLED", "true")
    monkeypatch.setenv("NGVM_GTI_DAILY_CALLS", "250")
    monkeypatch.setenv("NGVM_GTI_MISSING_HOURS", "96")
    monkeypatch.setenv("NGVM_GTI_CACHE_HOURS", "48")
    loaded = load_settings()
    assert (loaded.sources.gti_daily_calls, loaded.sources.gti_missing_hours) == (250, 96.0)
    line = describe_gti(loaded)
    assert "250 a day (UTC)" in line and "cached 48 h" in line and "unknown CVEs 96 h" in line
    assert "gti_daily_calls" in (ROOT / "docs/gti.md").read_text(encoding="utf-8")
    pipeline = (ROOT / "templates/client-pipeline.yml").read_text(encoding="utf-8")
    assert all(v in pipeline for v in ("NGVM_GTI_MAX_CALLS", "NGVM_GTI_DAILY_CALLS", "NGVM_GTI_MISSING_HOURS"))

    service = _service(tmp_path, gti=True)
    DailyBudget(tmp_path / "cache" / GTI_BUDGET_FILE, service.settings.sources.gti_daily_calls).take()
    status = service.status(READ)
    assert status["gti"]["calls"] == 1 and status["gti"]["daily"] == service.settings.sources.gti_daily_calls
    assert "gti" not in _service(tmp_path / "off").status(READ)


# -- 2. the collector's installer and the upgrade of its image -------------------------------------
def test_the_installer_logs_in_to_the_persistent_file() -> None:
    import subprocess

    script = ROOT / "deploy/collector/install-collector.sh"
    text = script.read_text(encoding="utf-8")
    assert subprocess.run(["bash", "-n", str(script)], check=False).returncode == 0
    login = text[text.index('step "image $IMAGE"') : text.index("GROUP_ADD=")]
    assert "AUTHFILE=/root/.config/containers/auth.json" in login
    assert 'docker logout --authfile "$stale" "$REGISTRY"' in login
    assert 'docker login "${AUTH[@]}"' in login and 'docker pull "${AUTH[@]}"' in login
    doc = (ROOT / "docs/collectors.md").read_text(encoding="utf-8")
    assert "**Upgrade the image**" in doc and "systemctl daemon-reload" in doc
    assert "/run/containers/0/auth.json" in doc


# -- 3. the chat's new CVEs: an overview by subject ----------------------------------------------
def _record(cve, cna, vendor, product, text, score, at="2099-11-21T06:00:06.000Z"):
    return {
        "dataType": "CVE_RECORD",
        "dataVersion": "5.1",
        "cveMetadata": {"cveId": cve, "state": "PUBLISHED", "datePublished": at, "assignerShortName": cna},
        "containers": {
            "cna": {
                "descriptions": [{"lang": "en", "value": text}],
                "affected": [{"vendor": vendor, "product": product, "versions": [], "defaultStatus": "affected"}],
                "metrics": [{"cvssV3_1": {"version": "3.1", "vectorString": "CVSS:3.1/AV:N", "baseScore": score}}],
            }
        },
    }


def _burst_fixtures(tmp_path):
    import json
    import shutil

    fx = tmp_path / "fixtures"
    shutil.copytree(FIXTURES, fx)
    text = "The Plugin {} WordPress plugin before 1.{} does not check a nonce"
    wp = [_record(f"CVE-2099-2000{i}", "WPScan", "Unknown", f"Plugin {i}", text.format(i, i), 6.1) for i in range(6)]
    kernel = _record("CVE-2099-30001", "Linux", "Linux", "Linux", "In the Linux kernel, the following...", 5.5)
    gate = _record("CVE-2099-40001", "acme-psirt", "Acme", "SecureGate", "Authentication bypass in SecureGate", 9.8)
    for r in [*wp, kernel, gate]:
        (fx / "cves" / f"{r['cveMetadata']['cveId']}.json").write_text(json.dumps(r))
    new = [{"cveId": r["cveMetadata"]["cveId"]} for r in [*wp, kernel, gate]]
    log = [{"fetchTime": "2099-11-21T06:10:00.000Z", "new": new, "updated": []}]
    (fx / "deltaLog.json").write_text(json.dumps(log))
    return fx


def test_the_shared_service_groups_the_new_cves_by_subject(tmp_path) -> None:
    service = _service(tmp_path)
    service.fixtures = str(_burst_fixtures(tmp_path))
    out = service.new_records(READ, {"since": "2099-11-20", "group": "subject"})
    assert out["since"].startswith("2099-11-20T00:00:00") and out["total"] == 8 and "items" not in out
    subjects = {g["subject"]: g for g in out["subjects"]}
    assert subjects["WordPress"]["count"] == 6 and subjects["WordPress"]["cnas"] == ["WPScan"]
    assert subjects["Linux kernel"]["count"] == 1 and subjects["Acme"]["max_cvss"] == 9.8
    assert out["subjects"][0]["subject"] == "Acme"  # the highest CVSS before the volume
    one = service.new_records(READ, {"since": "2099-11-20", "subject": "wordpress"})
    assert one["total"] == 6 and {i["subject"] for i in one["items"]} == {"WordPress"}
    assert one["items"][0]["cna"] == "WPScan"
    whole = service.new_records(READ, {})
    assert whole["since"] is None and any("whole deltaLog" in n for n in whole["notes"])
    with pytest.raises(Problem):
        service.new_records(READ, {"group": "vendor"})


def test_the_new_cves_ask_gti_nothing(tmp_path, monkeypatch) -> None:
    from via.intel import collect as collect_mod

    service = _service(tmp_path, gti=True)
    service.fixtures = str(_burst_fixtures(tmp_path))
    asked = []
    monkeypatch.setattr(collect_mod, "enrich", lambda sources, records: asked.append(len(records)) or [])
    service.new_records(READ, {"since": "2099-11-20", "kev": "true"})
    service.new_records(READ, {"since": "2099-11-20", "group": "subject"})
    assert asked == []


def test_the_chat_gives_an_overview_of_the_last_24_hours(tmp_path) -> None:
    asked = []
    many = [f"CVE-2099-2{i:04}" for i in range(300)]
    subjects = [
        {"subject": "WordPress", "count": 300, "kev": 0, "max_cvss": 8.8, "cves": many},
        {"subject": "Acme", "count": 1, "kev": 0, "max_cvss": 7.5, "cves": ["CVE-2099-40001"]},
    ]

    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.host, dict(request.url.params)))
        if request.url.host == "intel.example":
            return httpx.Response(200, json={"since": request.url.params.get("since"), "total": 301,
                                             "counts": {"new": 301, "updated": 0}, "subjects": subjects})  # fmt: skip
        return httpx.Response(200, json={"items": [{"id": "a1", "cves": ["CVE-2099-40001"]}]})

    tools = _tools(tmp_path, handler, intel_url="http://intel.example", intel_token="t",
                   via_url="http://via.example", via_token="v")  # fmt: skip
    out = tools.call(CHAT, "/new-cves", {})
    params = asked[0][1]
    assert params["group"] == "subject" and params["since"]
    since = dt.datetime.fromisoformat(params["since"])
    assert dt.timedelta(hours=23) < dt.datetime.now(dt.UTC) - since < dt.timedelta(hours=25)
    assert out["notes"][0] == "no period asked: the last 24 hours"
    assert [g["subject"] for g in out["subjects"]] == ["Acme", "WordPress"]  # a tenant alert before volume
    wp = out["subjects"][1]
    assert len(wp["cves"]) == 5 and wp["more_cves"] == 295 and out["subjects"][0]["alerts"] == 1
    tools.call(CHAT, "/new-cves", {"subject": "WordPress"})
    assert "group" not in asked[-2][1] and asked[-2][1]["subject"] == "WordPress"
    tools.close()


# -- 4. dispatch: the iTop caller, the failure of the job named --------------------------------------
def _itop_check(caller: str, found: int) -> str:
    from dispatch.connectors.itop import ItopConnector
    from dispatch.rules import Rules

    from .test_v0200 import RULES

    def handler(request: httpx.Request) -> httpx.Response:
        objects = {f"Person::{i}": {"code": 0, "fields": {"id": str(i)}} for i in range(1, found + 1)}
        return httpx.Response(200, json={"code": 0, "objects": objects or None})

    rules = Rules.from_dict({**RULES, "targets": {"itsm": {**RULES["targets"]["itsm"], "caller": caller}}})
    return ItopConnector(rules.targets["itsm"], "secret", transport=httpx.MockTransport(handler)).check()


def test_two_persons_with_the_caller_s_e_mail_are_not_told_to_give_an_e_mail() -> None:
    says = _itop_check("owner@example.org", 2)
    assert says.startswith("iTop: 2 Persons with email 'owner@example.org' in 'Lab'")
    assert "remove the duplicate in iTop" in says and "of its own" in says
    assert "give `caller` the e-mail of one of them" not in says
    assert "give `caller` the e-mail of one of them" in _itop_check("NGVM", 2)  # a name: the e-mail helps


def test_the_dispatch_step_names_the_publish_step_as_the_cause() -> None:
    daily = (ROOT / "deploy/charts/ngvm-tenant/templates/cronjob-daily.yaml").read_text(encoding="utf-8")
    dispatch = daily[daily.index('define "ngvm-tenant.step.dispatch"') :]
    dispatch = dispatch[: dispatch.index("{{- end -}}")]
    assert "because of the step publish, not of the dispatch" in dispatch and "exit 1" in dispatch


# -- 5. the address check: a namespace that no longer exists ----------------------------------------
def test_a_dsn_to_a_namespace_that_no_longer_exists_stops_the_deployment(tmp_path) -> None:
    from .test_v0273 import _check

    dsn = "postgresql://ngvm_writer:pw-0123456789@portal-portal-db-rw.old-portal:5432/ngvm"
    done = _check(tmp_path, NGVM_REPORTING_DSN_K8S=dsn)
    assert done.returncode == 1
    assert "ERROR NGVM_REPORTING_DSN_K8S points at portal-portal-db-rw.old-portal" in done.stderr
    assert "no namespace old-portal" in done.stderr and "pw-0123456789" not in done.stdout + done.stderr
    done = _check(tmp_path, NGVM_RELAY_URL="http://relay.lan:3128", NGVM_INTEL_URL="https://intel.xn--p1ai")
    assert done.returncode == 0 and done.stderr == ""  # a top-level domain: outside, left alone


# -- 6. the alert mail: its kind, the CVE and its sources first, the layout, the delay's source -------
def test_the_kind_follows_the_rules_of_the_profile() -> None:
    from via.alert.kinds import classify, rules

    def kind(**facts):
        return classify({"decision": "", "kev": False, "epss": None, "cvss": None, **facts}).kind

    assert kind(decision="ACT") == "alerte"
    assert kind(decision="ATTEND", kev=True) == "hot_topic" and kind(decision="ATTEND", epss=0.12) == "hot_topic"
    assert kind(decision="ATTEND", epss=0.05) == "information" and kind(decision="TRACK", kev=True) == "information"
    assert kind(kev=True) == "alerte" and kind(epss=0.86) == "hot_topic" and kind(epss=0.42) == "information"
    own = {"kinds": {"untriaged": [{"kind": "hot_topic", "when": {"epss_min": 0.5}}]}}
    assert classify({"decision": "", "kev": True, "epss": 0.6}, own).kind == "hot_topic"  # first rule wins
    assert rules(own)["triaged"][0]["when"] == {"decision": "ACT"}  # the list not given keeps its default
    got = classify({"decision": "", "kev": True})
    assert got.to_dict() == {"kind": "alerte", "triaged": False, "decision": "", "rule": got.rule}


def test_the_profile_accepts_the_rules_of_the_kinds() -> None:
    from ngvm.profile import validate_profile_data

    base = {"schema_version": 2, "client": {"id": "x", "name": "X", "updated": "2026-11-21"}}
    good = {"triaged": [{"kind": "alerte", "when": {"decision": ["ACT"]}}],
            "untriaged": [{"kind": "hot_topic", "when": {"kev": False, "epss_min": 0.8}}]}  # fmt: skip
    assert validate_profile_data({**base, "alerts": {"kinds": good}}) == []
    bad = {"untriaged": [{"kind": "red", "when": {"epss_min": 80}}]}
    assert validate_profile_data({**base, "alerts": {"kinds": bad}}) != []


def test_the_run_s_decisions_go_with_the_inventory(tmp_path) -> None:
    from via.alert.inventory import for_watch, load

    assets = {"schema": "vulnops.assets/1", "client_id": "lab", "generated_at": "2026-11-21T06:00:00+00:00",
              "assets": []}  # fmt: skip
    findings = {"generated_at": "2026-11-21T06:00:00+00:00", "client_id": "lab", "findings": []}
    triage = {"rows": [{"cve_id": "CVE-2099-1", "asset_id": "web01", "asset_id_full": "host:web01",
                        "delivery_decision": "ACT"}]}  # fmt: skip
    _, compact = for_watch(assets, findings, triage)
    assert compact["decisions"] == {"host:web01": {"CVE-2099-1": "ACT"}}
    assert "decisions" not in for_watch(assets, findings)[1]
    from ngvm.io import validate_watch_findings

    validate_watch_findings(compact)
    base = tmp_path / "lab"
    base.mkdir()
    import json

    (base / "assets.json").write_text(json.dumps(assets))
    (base / "watch-findings.json").write_text(json.dumps(compact))
    assert load(tmp_path, "lab").decisions == {("host:web01", "CVE-2099-1"): "ACT"}
    daily = (ROOT / "deploy/charts/ngvm-tenant/templates/cronjob-daily.yaml").read_text(encoding="utf-8")
    assert '${TRIAGE_DOC:+--triage "$TRIAGE_DOC"}' in daily


def _watch_alerts(tmp_path, language="en"):
    """The watch of the example client on the fixtures, its sheets and mails."""
    import json
    import subprocess
    import sys

    from .test_v0162 import PROFILE, WATCH_ALONE

    profile = PROFILE
    if language != "en":
        import yaml

        data = yaml.safe_load(PROFILE.read_text(encoding="utf-8"))
        data["client"]["language"] = language
        profile = tmp_path / "client.yaml"
        profile.write_text(yaml.safe_dump(data, allow_unicode=True), encoding="utf-8")
    run = subprocess.run(
        [sys.executable, "-c", WATCH_ALONE, str(profile), str(ROOT / "config" / "settings.yaml"), str(FIXTURES),
         str(tmp_path)],
        capture_output=True, text=True, env={"PATH": "/usr/bin:/bin", "HOME": str(tmp_path)}, timeout=120,
    )  # fmt: skip
    assert run.returncode == 0, run.stderr[-2000:]
    index = json.loads(run.stdout.strip().splitlines()[-1])
    return {a["id"]: a for a in index}, tmp_path / "alerts"


def test_the_sheet_opens_on_the_cve_and_its_sources(tmp_path) -> None:
    index, out = _watch_alerts(tmp_path)
    pan = index["example-client-CERTFR-2024-ALE-006"]
    assert pan["kind"]["kind"] == "alerte" and pan["kind"]["rule"]["when"] == {"kev": True}
    md = (out / f"{pan['id']}.md").read_text(encoding="utf-8")
    headings = [line[3:] for line in md.splitlines() if line.startswith("## ")]
    assert headings[:3] == ["CVE and sources", "Why this alert", "Your assets concerned"]
    assert "CVE" not in headings  # the ids are in the sources
    sources = md[md.index("## CVE and sources") : md.index("## Why this alert")]
    assert "- CVE-2024-3400 · CVSS 10 critical · KEV yes · EPSS 0.94" in sources
    lines = [x for x in sources.splitlines() if x.startswith("- 2024")]
    assert "**palo_alto** (CNA) publishes the CVE" in lines[0] and "07:20 UTC" in lines[0]
    assert "**CERT-FR** publishes CERTFR-2024-ALE-006" in lines[1]
    assert "**CISA KEV** adds it" in lines[2]  # a day alone after the moments of that day
    assert md.startswith("# [ALERT] ")
    delay = md[md.index("## Recommended remediation delay") :].splitlines()
    assert delay[2] == "**3 days, with a forensic investigation**"
    assert delay[3].startswith("Source: CISA BOD 26-04 (in KEV, asset exposed on the Internet")
    assert "information" in {a["kind"]["kind"] for a in index.values()}


def test_the_mail_is_laid_out_and_names_no_product(tmp_path) -> None:
    from via.alert import mailhtml

    index, out = _watch_alerts(tmp_path)
    pan = index["example-client-CERTFR-2024-ALE-006"]
    md = (out / f"{pan['id']}.md").read_text(encoding="utf-8")
    page = (out / f"{pan['id']}.html").read_text(encoding="utf-8")
    assert page == mailhtml.render(md, pan)
    assert "#b42318" in page and "#f8e4e2" in page and ">ALERT</span>" in page  # the tag carries the colour
    assert page.index("CVE AND SOURCES") < page.index("Why this alert") < page.index("Characteristics")
    assert 'bgcolor="#3b5b7a"' in page and "border-radius:14px" in page
    assert "Classed Alert: CVE in the KEV catalog, not yet assessed by the triage." in page
    assert "<code" in page and "`CVSS:3.1" not in page
    assert "NGVM" not in page and "ngvm" not in page.lower().replace(pan["id"], "")
    assert "display:flex" not in page  # tables: what Outlook lays out
    assert mailhtml.subject(md, pan) == "[Alert] Vulnérabilité dans Palo Alto Networks PAN-OS"
    for kind, tag in (("hot_topic", "#c2410c"), ("information", "#1d5fa8")):
        other = mailhtml.render(md, {**pan, "kind": {"kind": kind}})
        assert tag in other and "#b42318" not in other
    old = {k: v for k, v in pan.items() if k != "kind"}  # an alert drafted before v0.29.0
    assert mailhtml.kind_of_entry(old) == "alerte" and mailhtml.kind_of_entry({"level": "info"}) == "information"


def test_the_mail_in_french(tmp_path) -> None:
    from via.alert import mailhtml

    index, out = _watch_alerts(tmp_path, "fr")
    pan = index["example-client-CERTFR-2024-ALE-006"]
    md = (out / f"{pan['id']}.md").read_text(encoding="utf-8")
    page = mailhtml.render(md, pan, "fr")
    assert ">ALERTE</span>" in page and "Caractéristiques" in page
    assert "Classée Alerte : CVE au catalogue KEV, pas encore évaluée par le triage." in page
    assert mailhtml.subject(md, pan, "fr").startswith("[Alerte] ")
    assert pan["issued_local"] and not pan["issued_local"].endswith("UTC")  # Europe/Paris for a French client


def test_the_delay_says_its_source() -> None:
    import dataclasses

    from ngvm import sla
    from ngvm.models import CvssMetric, VulnRecord
    from ngvm.ssvc import remediation_delay
    from via.alert.fiche import delay_lines
    from via.alert.kinds import Kind

    record = VulnRecord("CVE-2099-48211", "PUBLISHED", "2099-11-20T14:02:00Z", "x", [],
                        [CvssMetric("3.1", "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8, "CRITICAL", "cna")],
                        [], None, None, [], kev={"dateAdded": "2099-11-21"})  # fmt: skip
    policy = sla.parse({"timezone": "Europe/Paris", "rules": [
        {"priority": "P0", "days": 2, "when": {"kev": True}},
        {"priority": "P1", "days": 5, "calendar": "business", "when": {"level": "ACT", "exposure": "open"}},
    ]})  # fmt: skip

    @dataclasses.dataclass
    class A:
        sla: object
        kind: object = None
        client_name: str = "Exemple SA"
        client_id: str = "exemple-sa"

    value, lines = delay_lines(A(policy), record, True, "conservative", "fr")
    assert value == "2 jours calendaires"
    assert lines[1] == "Source : SLA Exemple SA, règle P0 (CVE au catalogue KEV)."
    assert lines[2].startswith("Référence CISA BOD 26-04 pour le même cas : 3 jours")
    hot = dataclasses.replace(record, kev=None)
    value, lines = delay_lines(A(policy), hot, True, "conservative", "fr")
    assert value == remediation_delay(hot, True, "conservative", "fr")
    assert lines[1].startswith("Source : CISA BOD 26-04 (hors KEV, actif exposé sur Internet, automatisable")
    assert "fixé par le prochain run quotidien" in lines[2]
    value, lines = delay_lines(A(policy, Kind("alerte", True, "ACT", {})), hot, True, "conservative", "en")
    assert value == "5 business days" and "rule P1 (decision ACT, exposure open)" in lines[1]
    value, lines = delay_lines(A(None), hot, False, "conservative", "en")
    assert lines[1].startswith("Source: CISA BOD 26-04 (not in KEV, asset not exposed") and len(lines) == 2


# -- the release ----------------------------------------------------------------------------------
def test_release_recorded() -> None:
    assert "## v0.29.0 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(29\.\d+|[3-9]\d\.\d+)$", chart, re.M)
