# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.2: the first server is one without a NoSchedule or NoExecute taint.

RKE2's helm-install jobs, the network among them, do not tolerate the operator's taints: a
tainted first server never gets Ready. The plan of the libvirt example (cn0 tainted) starts the
cluster on cn1 and adds cn0 last; a cluster whose servers are all tainted fails a check.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

from .conftest import ROOT

MAIN = ROOT / "deploy/tofu/modules/platform/main.tf"


def test_the_tainted_servers_come_last() -> None:
    main = MAIN.read_text()
    assert 'endswith(t, ":PreferNoSchedule")' in main
    assert re.search(r"servers\s+= concat\(\[for n in local.all_servers : n if !contains\(local.blocked, n\)\]", main)
    assert 'check "untainted_server"' in main


@pytest.mark.skipif(not shutil.which("tofu"), reason="OpenTofu not installed (the CI job tofu runs it)")
def test_the_plan_starts_the_cluster_on_an_untainted_server(tmp_path) -> None:
    env = dict(os.environ, PLAN_JSON=str(tmp_path / "plan"))
    run = subprocess.run([str(ROOT / "deploy/tofu/check.sh"), "--offline"], env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    changes = {
        r["address"]: r["change"]["after"]
        for r in json.loads((tmp_path / "plan-libvirt.json").read_text())["resource_changes"]
    }
    names = [
        changes[f"module.platform.terraform_data.rke2_{s}[0]"]["triggers_replace"]["env"]
        for s in ("first", "second", "third")
    ]
    assert [e["NODE_NAME"] for e in names] == ["cn1", "cn2", "cn0"]
    assert names[0]["SERVER_URL"] == "" and names[0]["TAINTS"] == ""
    assert names[2]["SERVER_URL"] == "https://192.0.2.102:9345"


def test_release_recorded() -> None:
    assert "## v0.25.2 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([2-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
