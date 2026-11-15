# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.6: the netfilter modules of Rocky Linux 10 before RKE2 starts.

The cloud images of RHEL 10 and its derivatives leave xt_conntrack and xt_comment in
kernel-modules-extra: kube-proxy set no rule, the CNI could not reach the API by its service
address, flannel stopped on br_netfilter, and the node never got Ready. The step installs the
package of the running kernel and loads br_netfilter, now and at every boot.
"""

from __future__ import annotations

import re

from .conftest import ROOT
from .test_v0250 import RKE2, ROCKY, UBUNTU, _run, _work

SCRIPT = ROOT / "deploy/tofu/scripts/rke2.sh"


def test_a_rocky_node_gets_its_kernel_modules_before_rke2(tmp_path) -> None:
    work, root = _work(tmp_path, "rke2", RKE2, {"token": "t"}, ROCKY)
    run = _run("rke2.sh", work, root)
    assert run.returncode == 0, run.stderr
    log = (root / "commands.log").read_text()
    assert log.index("RUN ensure kernel modules xt_conntrack xt_comment") < log.index("RUN install rke2")
    assert log.index("RUN modprobe br_netfilter") < log.index("RUN install rke2")
    assert (root / "etc/modules-load.d/ngvm-rke2.conf").read_text() == "br_netfilter\n"


def test_an_ubuntu_node_needs_nothing(tmp_path) -> None:
    work, root = _work(tmp_path, "rke2", RKE2, {"token": "t"}, UBUNTU)
    run = _run("rke2.sh", work, root)
    assert run.returncode == 0, run.stderr
    assert "kernel modules" not in (root / "commands.log").read_text()
    assert "modprobe" not in (root / "commands.log").read_text()


def test_the_package_is_the_one_of_the_running_kernel() -> None:
    script = SCRIPT.read_text()
    assert 'dnf install -y -q "kernel-modules-extra-$kernel"' in script and "kernel=$(uname -r)" in script
    assert "modinfo xt_conntrack" in script and "reboot, apply again" in script


def test_release_recorded() -> None:
    assert "## v0.25.6 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([6-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
