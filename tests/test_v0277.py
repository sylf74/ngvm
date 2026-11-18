# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.7: a relay of the sources that keeps office hours.

- The step `via` of the daily run checks the relay before reading any source: one line and a stop
  when it cannot be reached, instead of a trace on the first list.
- A list of new CVEs that cannot be read (deltaLog, KEV) is a warning: the scanners' CVEs are kept.
- The watch has its own schedule (`NGVM_WATCH_SCHEDULE`), so that it can keep the relay's hours.
"""

from __future__ import annotations

import dataclasses
import datetime as dt
import json
import re

import httpx

from ngvm.config import SourceSettings
from via.intel import cli as intel_cli
from via.intel.collect import select_cve_ids
from via.intel.sources import Relay, SourceError, Sources

from .conftest import ROOT

SINCE = dt.datetime(2026, 11, 17, 4, 45, tzinfo=dt.UTC)


class _Lists:
    def __init__(self, delta=None, kev=None):
        self.delta, self.kev = delta, kev

    def new_cve_ids(self, since, include_updated=False):
        if isinstance(self.delta, Exception):
            raise self.delta
        return self.delta or []

    def kev_added_since(self, since):
        if isinstance(self.kev, Exception):
            raise self.kev
        return self.kev or []


# -- 1. a list that cannot be read is a warning --------------------------------------------------------
def test_a_list_missing_keeps_the_scanners_cves() -> None:
    warnings: list[str] = []
    down = SourceError("GET https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/deltaLog.json: timed out")
    ids = select_cve_ids(_Lists(delta=down, kev=["CVE-2026-0002"]), ["cve-2026-0001"], SINCE, warnings=warnings)
    assert ids == ["CVE-2026-0001", "CVE-2026-0002"]
    assert len(warnings) == 1 and warnings[0].startswith("CVEs published since 2026-11-17T04:45+00:00 not read: GET")
    warnings.clear()
    lists = _Lists(delta=["CVE-2026-0003"], kev=SourceError("KEV feed not found"))
    assert select_cve_ids(lists, [], SINCE, warnings=warnings) == ["CVE-2026-0003"]
    assert warnings == ["KEV additions since 2026-11-17T04:45+00:00 not read: KEV feed not found"]
    assert select_cve_ids(_Lists(delta=["CVE-2026-0003"]), ["CVE-2026-0003"], SINCE) == ["CVE-2026-0003"]


# -- 2. the relay checked first ---------------------------------------------------------------------------
def test_the_relay_probe() -> None:
    relay = Relay("https://relay.example.org", ["www.cisa.gov"], "t")

    def closed(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    def answers(request: httpx.Request) -> httpx.Response:
        assert str(request.url) == "https://relay.example.org/"
        return httpx.Response(404)

    with httpx.Client(transport=httpx.MockTransport(closed)) as client:
        assert relay.problem(client) == "ConnectTimeout: timed out"
    with httpx.Client(transport=httpx.MockTransport(answers)) as client:
        assert relay.problem(client) is None  # any HTTP answer: the relay is there


def _run(monkeypatch, tmp_path, capsys, handler, intel_url: str = "") -> tuple[int, str, str, list[str]]:
    seen: list[str] = []

    def recording(request: httpx.Request) -> httpx.Response:
        seen.append(str(request.url))
        return handler(request)

    monkeypatch.setenv("NGVM_RELAY_URL", "https://relay.example.org")
    monkeypatch.setenv("NGVM_RELAY_HOSTS", "raw.githubusercontent.com,www.cisa.gov")
    if intel_url:
        monkeypatch.setenv("NGVM_INTEL_URL", intel_url)

    def sources(settings: SourceSettings, fixtures_dir=None) -> Sources:
        settings = dataclasses.replace(settings, cache_dir=str(tmp_path / "cache"))
        return Sources(settings, transport=httpx.MockTransport(recording))

    monkeypatch.setattr(intel_cli, "Sources", sources)
    args = ["collect", "--settings", str(ROOT / "config" / "settings.yaml"), "--since", "26h",
            "--out", str(tmp_path / "records.json")]  # fmt: skip
    code = intel_cli.main(args)
    out = capsys.readouterr()
    return code, out.out, out.err, seen


def test_a_relay_closed_stops_the_step_in_one_line(monkeypatch, tmp_path, capsys) -> None:
    def closed(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    code, out, err, seen = _run(monkeypatch, tmp_path, capsys, closed)
    assert code == 1
    assert seen == ["https://relay.example.org/"]  # no source asked once the relay is known closed
    assert "ERROR the relay of the sources https://relay.example.org cannot be reached (ConnectTimeout" in err
    assert "NGVM_K8S_SCHEDULE" in err and "Traceback" not in err


def test_a_relay_up_with_a_list_down_goes_on(monkeypatch, tmp_path, capsys) -> None:
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path == "/":
            return httpx.Response(404)
        if "deltaLog" in request.url.path:
            return httpx.Response(502)
        if "known_exploited" in request.url.path:
            day = dt.date.today().isoformat()
            return httpx.Response(200, json={"vulnerabilities": [{"cveID": "CVE-2026-0042", "dateAdded": day}]})
        return httpx.Response(404)

    code, out, err, seen = _run(monkeypatch, tmp_path, capsys, handler)
    assert code == 0, err
    assert "WARN CVEs published since" in out and "HTTP 502: going on with the other CVEs" in out
    records = json.loads((tmp_path / "records.json").read_text())
    assert records["requested"] == ["CVE-2026-0042"]


def test_with_the_shared_service_the_relay_is_not_checked(monkeypatch, tmp_path, capsys) -> None:
    def closed(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectTimeout("timed out")

    code, out, err, seen = _run(monkeypatch, tmp_path, capsys, closed, intel_url="http://intel.example")
    assert "https://relay.example.org/" not in seen
    assert "cannot be reached" not in err and "Traceback" not in err
    assert code == 2  # both lists down, no CVE given: nothing selected, as before


# -- 3. the watch's own schedule -------------------------------------------------------------------------
def test_the_watch_schedule() -> None:
    template = (ROOT / "templates/client-pipeline.yml").read_text(encoding="utf-8")
    assert '--set watch.schedule="${NGVM_WATCH_SCHEDULE:-*/10 * * * *}"' in template
    kube = (ROOT / "docs/kubernetes.md").read_text(encoding="utf-8")
    assert "| `NGVM_WATCH_SCHEDULE` | Optional (v0.27.7)" in kube


# -- 4. documented ------------------------------------------------------------------------------------
def test_documented() -> None:
    relay = (ROOT / "deploy/relay/README.md").read_text(encoding="utf-8")
    assert "## A relay that keeps hours" in relay and "`15 8 * * 1-5`" in relay
    ops = (ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert 'cannot be reached" (v0.27.7)' in ops and 'KEV additions … not read" (v0.27.7)' in ops
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert "| v0.27.7 (current) |" in hld


def test_release_recorded() -> None:
    assert "## v0.27.7 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(27\.([7-9]|\d\d+)|2[89]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
