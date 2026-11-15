# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.10: the CSI drivers of Rook, and a storage that is checked before it is called ready.

Since Rook 1.20 the operator chart installs the ceph-csi-operator, which deploys nothing until a
Driver and an OperatorConfig name what to run: those come from the ceph-csi-drivers chart. Without
it the cluster was healthy, `ceph-block` was the default class, and every PVC of every tenant
stayed Pending for ever. The addons step installs that chart and ends only on a driver registered.
"""

from __future__ import annotations

import re

from .conftest import ROOT
from .test_v0250 import UBUNTU, _run, _work
from .test_v0251 import ROOK

SCRIPT = ROOT / "deploy/tofu/scripts/addons.sh"


def test_the_drivers_chart_comes_between_the_operator_and_the_cluster(tmp_path) -> None:
    work, root = _work(tmp_path, "addons", ROOK, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    log = (root / "commands.log").read_text()
    operator = log.index("RUN helm upgrade --install rook-ceph rook-release/rook-ceph")
    drivers = log.index("RUN helm upgrade --install ceph-csi-drivers ceph-csi-operator/ceph-csi-drivers")
    cluster = log.index("RUN helm upgrade --install rook-ceph-cluster")
    assert operator < drivers < cluster
    assert "RUN helm repo add ceph-csi-operator https://charts.example.org/csi" in log


def test_the_drivers_keep_the_names_of_the_storage_class_and_tolerate_the_taints(tmp_path) -> None:
    work, root = _work(tmp_path, "addons", ROOK, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    values = (work / "csi-drivers.yaml").read_text()
    assert "name: rook-ceph.rbd.csi.ceph.com" in values and "name: rook-ceph.cephfs.csi.ceph.com" in values
    assert values.count('{key: "example.org/no-avx2", operator: Exists}') == 2  # node and controller plugins
    assert "name: rook-csi-operator-image-set-configmap" in values
    assert "nfs:\n    enabled: false" in values


def test_the_step_ends_only_on_a_driver_that_is_registered() -> None:
    script = SCRIPT.read_text()
    assert "kubectl get csidriver rook-ceph.rbd.csi.ceph.com" in script
    assert 'fail "no CSI driver rook-ceph.rbd.csi.ceph.com' in script
    assert "csi.ceph.io/driver-name=rook-ceph.rbd.csi.ceph.com" in script
    assert script.index("ceph-csi-drivers ceph-csi-operator") < script.index("kubectl get csidriver")


def test_release_recorded() -> None:
    assert "## v0.25.10 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.(1[0-9]|[2-9]\d)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
