# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.8: no `kubectl apply` through the GitLab agent, and a Ceph cluster that may warn.

A client-side apply reads the cluster's OpenAPI schema, which the GitLab agent server refuses to
serve: every deployment of a tenant stopped on the namespace. And the addons step waited for
HEALTH_OK, which Ceph 20 never reaches on a kernel older than Linux 7.0 (the CSI keys keep the
aes type): it now waits for a cluster that is Ready and steady, and says the warning.
"""

from __future__ import annotations

import re

from .conftest import ROOT

PIPELINE = ROOT / "templates/client-pipeline.yml"
ADDONS = ROOT / "deploy/tofu/scripts/addons.sh"


def test_the_pipeline_never_applies_through_the_agent() -> None:
    text = PIPELINE.read_text()
    commands = "\n".join(line for line in text.splitlines() if not line.lstrip().startswith("#"))
    assert "kubectl apply" not in commands and "apply -f -" not in commands
    assert 'kubectl get namespace "$NS" > /dev/null 2>&1 || kubectl create namespace "$NS"' in text
    assert 'kubectl -n "$NS" create -f -' in text  # the send job's manifest
    assert 'create configmap "ngvm-edits-$CI_PIPELINE_ID" --from-file=edits/\n' in text


def test_a_ceph_cluster_that_warns_does_not_stop_the_step() -> None:
    script = ADDONS.read_text()
    assert '[ "$health" != HEALTH_ERR ]' in script and "HEALTH_OK" in script
    assert "steady=$((steady + 1))" in script and '[ "$steady" -lt 6 ] || break' in script
    assert "WARN Ceph is $health" in script
    assert 'fail "Ceph is in HEALTH_ERR' in script


def test_release_recorded() -> None:
    assert "## v0.25.8 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([8-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
