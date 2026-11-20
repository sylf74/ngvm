# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.26.0: a watch and a shared intelligence service that hold.

What the incident of 13 to 15 November showed. A cache file half written on a full volume was
read as fresh for ever: the cache is now written whole or not at all, an unreadable file is
fetched again, a full volume is said in clear and stops nothing, old files are removed, and the
service says the room left on its volume.
"""

from __future__ import annotations

import errno
import json
import os
import re
import time

import httpx
import pytest

from ngvm.config import Settings
from ngvm.service import TokenSet
from via.intel import sources as src
from via.intel.service import IntelService, IntelStore
from via.intel.sources import Sources, purge_cache, write_cache

from .conftest import ROOT

KEV = {"vulnerabilities": [{"cveID": "CVE-2024-0001", "dateAdded": "2024-01-02"}]}


def _sources(tmp_path, handler) -> Sources:
    settings = Settings().sources
    settings.cache_dir = str(tmp_path / "cache")
    return Sources(settings, transport=httpx.MockTransport(handler))


def test_a_cache_file_is_written_whole_or_not_at_all(tmp_path, monkeypatch) -> None:
    path = tmp_path / "cache" / "a.json"
    write_cache(path, '{"a": 1}')
    assert json.loads(path.read_text()) == {"a": 1} and os.listdir(path.parent) == ["a.json"]

    def boom(tmp, final):  # the volume fills between the write and the rename
        raise OSError(errno.ENOSPC, "No space left on device")

    monkeypatch.setattr(src.os, "replace", boom)
    with pytest.raises(src.CacheFullError, match="cache volume is full"):
        write_cache(path, '{"a": 2}')
    assert json.loads(path.read_text()) == {"a": 1}  # the previous file is whole
    assert os.listdir(path.parent) == ["a.json"]  # and no temporary file is left


def test_an_unreadable_cache_file_is_fetched_again(tmp_path, capsys) -> None:
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(str(request.url))
        return httpx.Response(200, json=KEV)

    sources = _sources(tmp_path, handler)
    assert "CVE-2024-0001" in sources.kev()
    cached = next((tmp_path / "cache").glob("*.json"))
    cached.write_text(cached.read_text()[:20])  # truncated, and still fresh
    again = _sources(tmp_path, handler)
    assert "CVE-2024-0001" in again.kev() and len(calls) == 2 and again.cache_repaired == 1
    assert "WARN cache unreadable, fetched again" in capsys.readouterr().err
    assert json.loads(cached.read_text()) == KEV


def test_a_full_volume_is_said_and_stops_nothing(tmp_path, monkeypatch, capsys) -> None:
    def full(path, text):
        raise src.CacheFullError(f"the cache volume is full ({path.parent})")

    monkeypatch.setattr(src, "write_cache", full)
    sources = _sources(tmp_path, lambda request: httpx.Response(200, json=KEV))
    assert "CVE-2024-0001" in sources.kev()  # the answer is used, only not kept
    assert "cache volume is full" in sources.cache_full
    assert capsys.readouterr().err.count("WARN the cache volume is full") == 1


def test_old_cache_files_are_removed(tmp_path) -> None:
    cache = tmp_path / "cache"
    cache.mkdir()
    now = time.time()
    for name, age_hours in (("old.json", 30), ("old.none", 30), ("new.json", 1), ("left.tmp", 30), ("other.db", 99)):
        (cache / name).write_text("x" * 10)
        os.utime(cache / name, (now - age_hours * 3600, now - age_hours * 3600))
    (cache / "osv").mkdir()
    assert purge_cache(cache, 24, now) == (3, 1, 10)
    assert sorted(os.listdir(cache)) == ["new.json", "osv", "other.db"]


def test_the_service_says_the_room_left_on_its_volume(tmp_path) -> None:
    settings = Settings()
    settings.sources.cache_dir = str(tmp_path / "cache")
    (tmp_path / "cache").mkdir()
    (tmp_path / "cache" / "a.json").write_text("{}")
    service = IntelService(TokenSet({}), IntelStore(tmp_path / "store"), settings)
    line = service.purge()
    assert line.startswith(("cache: 0 old files removed, 1 kept", "WARN cache: 0 old files removed, 1 kept"))
    assert "% used" in line and service.cache == {"files": 1, "bytes": 2}
    volume = service.storage()
    assert 0 <= volume["used_percent"] <= 100 and volume["alert"] == (volume["used_percent"] >= 85)


def test_an_alert_is_mailed_to_the_analysts_at_most_once(tmp_path) -> None:
    from via.alert.cli import _already_mailed

    assert _already_mailed(None) == set() and _already_mailed(str(tmp_path / "none.json")) == set()
    path = tmp_path / "mailed.json"
    path.write_text('["homelab-CERTFR-2026-AVI-1535"]')
    assert _already_mailed(str(path)) == {"homelab-CERTFR-2026-AVI-1535"}
    path.write_text("not json")
    assert _already_mailed(str(path)) == set()  # said as a WARN, the mails are sent
    cli = (ROOT / "via/src/via/alert/cli.py").read_text()
    assert 'if a["id"] in mailed:' in cli and "already mailed by an earlier passage" in cli
    service = (ROOT / "via/src/via/service/cli.py").read_text()
    assert 'mailed=str(work / "mailed.json")' in service
    assert 'e.get("event") == "analysts" and e.get("result")' in service


def test_the_phases_of_a_passage_and_its_memory_are_logged(tmp_path) -> None:
    from ngvm.run import Phases, peak_memory_mb

    phases = Phases()
    with phases("discover"):
        pass
    phases.start("sheets")
    phases.stop("sheets")
    assert set(phases.to_dict()) == {"discover", "sheets"}
    assert phases.line().startswith("timing: discover ") and "peak memory" in phases.line()
    assert peak_memory_mb() > 0
    cli = (ROOT / "via/src/via/alert/cli.py").read_text()
    assert 'with phases("match")' in cli and 'print(f"  {phases.line()}")' in cli


def test_the_records_are_asked_in_batches_that_answer(tmp_path) -> None:
    from via.intel import remote

    assert remote.BATCH <= 500 and remote.TIMEOUT >= 180
    source = (ROOT / "via/src/via/intel/remote.py").read_text()
    # v0.28.2: a failed batch no longer ends the request (the batch is lost alone, the next ones asked)
    assert ("the batches that answered are kept" in source and "if n == 1:\n                    raise" in source) or (
        "the batch is lost alone, the next ones are asked" in source
    )


def test_the_volumes_and_the_memory_are_set_by_the_pipeline() -> None:
    values = (ROOT / "deploy/charts/ngvm-tenant/values.yaml").read_text()
    assert "activeDeadlineSeconds: 1800" in values
    pipeline = (ROOT / "templates/client-pipeline.yml").read_text()
    for name, target in (
        ("NGVM_WATCH_MEMORY", "watch.run.resources.limits.memory"),
        ("NGVM_WATCH_DEADLINE", "watch.run.activeDeadlineSeconds"),
        ("NGVM_INTEL_SIZE", "intel.serve.storage.size"),
    ):
        assert f'if [ -n "${{{name}:-}}" ]; then' in pipeline and target in pipeline
    kubernetes = (ROOT / "docs/kubernetes.md").read_text()
    assert "NGVM_INTEL_SIZE" in kubernetes and "NGVM_WATCH_MEMORY" in kubernetes


def test_release_recorded() -> None:
    assert "## v0.26.0 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(2[6-9]|[3-9]\d)\.\d+$", chart, re.M)
