# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.7: Rook-Ceph on nodes with SELinux, the ingress on its address, a step that checks.

On Rocky, SELinux refused the Ceph pods their folder on the node: they run privileged for it. The
HelmChartConfig that turned the Service of RKE2's ingress into a LoadBalancer made the chart fail:
the platform makes a Service of its own. The step no longer ends on a Ceph cluster whose pods do
not start, nor on an ingress without its address.
"""

from __future__ import annotations

import re

from .conftest import ROOT
from .test_v0250 import UBUNTU, _run, _work
from .test_v0251 import ROOK

SCRIPT = ROOT / "deploy/tofu/scripts/addons.sh"


def test_the_ceph_pods_are_privileged_for_their_folder(tmp_path) -> None:
    work, root = _work(tmp_path, "addons", ROOK, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    assert "hostpathRequiresPrivileged: true\n" in (work / "rook-operator.yaml").read_text()


def test_the_ingress_has_a_service_of_its_own(tmp_path) -> None:
    work, root = _work(tmp_path, "addons", ROOK | {"STORAGE": "none"}, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    manifests = (root / "manifests.yaml").read_text()
    assert "kind: HelmChartConfig" not in manifests
    service = manifests[manifests.index("kind: Service") :]
    assert "  type: LoadBalancer\n  externalTrafficPolicy: Local\n" in service
    assert "{name: http, port: 80, targetPort: web}" in service
    assert "{name: https, port: 443, targetPort: websecure}" in service
    work, root = _work(tmp_path / "2", "addons", ROOK | {"STORAGE": "none", "INGRESS": "ingress-nginx"}, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    assert "{name: https, port: 443, targetPort: https}" in (root / "manifests.yaml").read_text()


def test_the_step_checks_what_it_made() -> None:
    script = SCRIPT.read_text()
    assert "CrashLoopBackOff|Error" in script and "Ceph: pods that do not start" in script
    assert '"$health" != HEALTH_ERR' in script and "WARN Ceph is $health" in script  # v0.26.0: no wait for HEALTH_OK
    assert "did not get $METALLB_INGRESS_IP from MetalLB" in script
    assert "kubectl -n kube-system delete helmchartconfig" in script  # the one v0.25.1 left


def test_release_recorded() -> None:
    assert "## v0.25.7 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([7-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
