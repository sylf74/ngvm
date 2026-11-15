# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.26.1: a mail is recorded as it is sent, not at the end of the passage.

v0.26.0 read what had already been mailed, but a passage kept its journal in the same call as its
state, at the very end: a passage killed after its mails pushed neither, so the next one saw
nothing and mailed the same alerts again — the case the fix was for. Each mail now reaches the
journal and the service as it is sent.
"""

from __future__ import annotations

import re

from .conftest import ROOT

WATCH = ROOT / "via/src/via/alert/cli.py"
SERVICE = ROOT / "via/src/via/service/cli.py"


def test_each_mail_is_recorded_as_it_is_sent() -> None:
    cli = WATCH.read_text()
    assert "def record(entry: dict) -> None:" in cli
    assert "journal.append(log_path, [entry])" in cli and "sink([entry])" in cli
    for event in (
        'journal.event("analysts", a, to=analysts, result=result)',
        'journal.event("analysts", a, to=analysts, error=str(exc))',
        'journal.event("analysts", a, to=["teams"], result=result)',
        'journal.event("analysts", a, to=["teams"], error=str(exc))',
    ):
        assert f"record({event})" in cli
    assert 'events.append(journal.event("analysts"' not in cli  # no mail kept for the end any more


def test_a_journal_the_service_refuses_does_not_stop_the_passage() -> None:
    cli = WATCH.read_text()
    assert "mail sent, journal not kept by the service" in cli
    assert 'sink = getattr(args, "on_event", None)' in cli


def test_the_service_keeps_each_mail_at_once() -> None:
    assert "on_event=client.add_events" in SERVICE.read_text()


def test_release_recorded() -> None:
    assert "## v0.26.1 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(26\.([1-9]|\d\d+)|2[7-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
