# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.5: a VM whose making failed is made again by the next apply.

OpenTofu does not run the removal of a step that failed, and the script left a VM that exists as
it was: a VM that never answered stayed for ever. The script now marks a VM it is making
(<pool>/<name>.creating) until its SSH port answers, and removes a marked VM before making it.
"""

from __future__ import annotations

import os
import re
import subprocess

from .conftest import ROOT
from .test_v0250 import _run
from .test_v0251 import _vm


def test_a_vm_whose_making_failed_is_made_again(tmp_path) -> None:
    work, root = _vm(tmp_path)
    (root / "mnt/virt/cn2.creating").write_text("")
    run = _run("vm-libvirt.sh", work, root)
    assert run.returncode == 0, run.stderr
    assert "its making failed last time" in run.stdout + run.stderr
    log = (root / "commands.log").read_text()
    removed = log.index("RUN rm -f /mnt/virt/cn2.qcow2 /mnt/virt/cn2-data*.qcow2")
    assert removed < log.index("qemu-img convert") < log.index("RUN virt-install --name cn2")
    assert not (root / "mnt/virt/cn2.creating").exists()


def test_a_new_vm_is_not_removed_first_and_leaves_no_mark(tmp_path) -> None:
    work, root = _vm(tmp_path)
    run = _run("vm-libvirt.sh", work, root)
    assert run.returncode == 0, run.stderr
    assert "RUN rm -f" not in (root / "commands.log").read_text()
    assert not (root / "mnt/virt/cn2.creating").exists()


def test_the_removal_takes_the_mark_away(tmp_path) -> None:
    work, root = _vm(tmp_path)
    (root / "mnt/virt/cn2.creating").write_text("")
    env = dict(os.environ, NGVM_TEST_ROOT=str(root))
    run = subprocess.run(
        ["bash", str(work / "scripts/vm-libvirt.sh"), str(work), "destroy"], env=env, capture_output=True, text=True
    )
    assert run.returncode == 0, run.stderr
    assert not (root / "mnt/virt/cn2.creating").exists()


def test_release_recorded() -> None:
    assert "## v0.25.5 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([5-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
