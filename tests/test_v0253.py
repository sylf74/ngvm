# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.3: a VM's network found by its MAC address, on Rocky as on Ubuntu.

cloud-init's NetworkManager renderer (Rocky) ignores a match by a pattern of names, so the
network-config matches the interface by a fixed MAC address that virt-install gives it. The VM
step waits for its SSH port; a VM made again runs the platform's steps again.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import subprocess

import pytest

from .conftest import ROOT
from .test_v0250 import _run
from .test_v0251 import VM, _vm

LIBVIRT = ROOT / "deploy/tofu/libvirt"


def test_virt_install_gets_the_mac_address(tmp_path) -> None:
    work, root = _vm(tmp_path, VM | {"MAC": "52:54:00:0a:1b:2c", "ADDRESS": "192.0.2.103"})
    run = _run("vm-libvirt.sh", work, root)
    assert run.returncode == 0, run.stderr
    log = (root / "commands.log").read_text()
    assert "--network bridge=ovs0,virtualport_type=openvswitch,model=virtio,mac=52:54:00:0a:1b:2c" in log


def test_a_bad_mac_address_stops_the_step(tmp_path) -> None:
    work, root = _vm(tmp_path, VM | {"MAC": "aa:bb"})
    run = _run("vm-libvirt.sh", work, root)
    assert run.returncode != 0 and "MAC: 52:54:00:xx:xx:xx" in run.stderr + run.stdout


def test_the_network_config_matches_the_mac_address() -> None:
    template = (LIBVIRT / "network-config.yaml.tftpl").read_text()
    assert 'macaddress: "${mac}"' in template and "name:" not in template
    script = (ROOT / "deploy/tofu/scripts/vm-libvirt.sh").read_text()
    assert "/dev/tcp/$ADDRESS/22" in script and "not reachable on $ADDRESS:22" in script
    main = (LIBVIRT / "main.tf").read_text()
    assert "mac        = local.mac[each.key]" in main and "terraform_data.vm[n].id" in main


@pytest.mark.skipif(not shutil.which("tofu"), reason="OpenTofu not installed (the CI job tofu runs it)")
def test_the_plan_gives_each_vm_its_mac_address(tmp_path) -> None:
    env = dict(os.environ, PLAN_JSON=str(tmp_path / "plan"))
    run = subprocess.run([str(ROOT / "deploy/tofu/check.sh"), "--offline"], env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    changes = {
        r["address"]: r["change"]["after"]
        for r in json.loads((tmp_path / "plan-libvirt.json").read_text())["resource_changes"]
    }
    vm = changes['terraform_data.vm["cn1"]']
    h = hashlib.md5(b"cn1").hexdigest()
    mac = f"52:54:00:{h[0:2]}:{h[2:4]}:{h[4:6]}"
    assert vm["triggers_replace"]["mac"] == mac
    assert f"MAC='{mac}'" in vm["input"]["env"] and "ADDRESS='192.0.2.102'" in vm["input"]["env"]


def test_release_recorded() -> None:
    assert "## v0.25.3 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([3-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
