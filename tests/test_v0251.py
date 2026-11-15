# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.1: the cluster on VMs of several KVM hosts, with Rook-Ceph and MetalLB.

The VMs are made over SSH with virt-install (Open vSwitch, extra disks for Rook-Ceph), the nodes
get their taints and labels, Rook-Ceph tolerates them, MetalLB puts the ingress on its address.
The scripts run in a test root (NGVM_TEST_ROOT), the plan of the libvirt example when OpenTofu is
installed.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess

import pytest

from .conftest import ROOT
from .test_v0250 import ADDONS, RKE2, ROCKY, UBUNTU, _run, _work

VM = {
    "NAME": "cn2", "VCPU": "4", "MEMORY_MB": "16384", "DISK_GB": "60", "CPUSET": "0-7",
    "IMAGE_URL": "https://dl.example.org/images/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2",
    "POOL_DIR": "/mnt/virt", "NETWORK": "ovs:ovs0", "DATA_DISKS": "200;dev:/dev/disk/by-id/ata-EXAMPLE",
    "OSINFO": "linux2022", "HTTP_PROXY_URL": "", "HTTPS_PROXY_URL": "", "NO_PROXY_LIST": "",
}  # fmt: skip


def _vm(tmp_path, env=VM):
    work, root = _work(tmp_path, "vm", env, {}, ROCKY)
    (root / "mnt/virt").mkdir(parents=True)
    (work / "user-data").write_text("#cloud-config\n")
    (work / "network-config").write_text("version: 2\n")
    return work, root


def test_a_vm_on_open_vswitch_with_its_disks_for_rook(tmp_path) -> None:
    work, root = _vm(tmp_path)
    run = _run("vm-libvirt.sh", work, root)
    assert run.returncode == 0, run.stderr
    log = (root / "commands.log").read_text()
    assert "RUN download https://dl.example.org/images/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2" in log
    base = "/mnt/virt/ngvm-images/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2"
    assert f"qemu-img convert -O qcow2 {base} /mnt/virt/cn2.qcow2" in log
    assert "RUN qemu-img resize -q /mnt/virt/cn2.qcow2 60G" in log
    assert "RUN qemu-img create -q -f qcow2 /mnt/virt/cn2-data1.qcow2 200G" in log
    install = next(line for line in log.splitlines() if line.startswith("RUN virt-install"))
    assert "--metadata description=ngvm:cn2" in install and "--vcpus 4,cpuset=0-7" in install
    assert "--network bridge=ovs0,virtualport_type=openvswitch,model=virtio" in install
    assert "--disk path=/dev/disk/by-id/ata-EXAMPLE,format=raw,bus=virtio,cache=none" in install
    assert f"--cloud-init user-data={work}/user-data,network-config={work}/network-config" in install
    assert "--cpu host-passthrough" in install and "--autostart" in install


def test_a_vm_removed_with_the_disks_it_made_only(tmp_path) -> None:
    work, root = _vm(tmp_path)
    env = dict(os.environ, NGVM_TEST_ROOT=str(root))
    run = subprocess.run(
        ["bash", str(work / "scripts/vm-libvirt.sh"), str(work), "destroy"], env=env, capture_output=True, text=True
    )
    assert run.returncode == 0, run.stderr
    assert "RUN rm -f /mnt/virt/cn2.qcow2 /mnt/virt/cn2-data*.qcow2" in (root / "commands.log").read_text()


def test_a_vm_refuses_a_bad_disk_or_network(tmp_path) -> None:
    work, root = _vm(tmp_path / "a", VM | {"DATA_DISKS": "big"})
    assert "DATA_DISKS: a size in GB or dev:<path>" in _run("vm-libvirt.sh", work, root).stderr
    work, root = _vm(tmp_path / "b", VM | {"NETWORK": "ovs0"})
    assert "NETWORK: ovs:<bridge>" in _run("vm-libvirt.sh", work, root).stderr
    work, root = _vm(tmp_path / "c", VM | {"NETWORK": "bridge:br0", "DATA_DISKS": "", "CPUSET": ""})
    assert _run("vm-libvirt.sh", work, root).returncode == 0
    install = (root / "commands.log").read_text()
    assert "--network bridge=br0,model=virtio" in install and "--vcpus 4 " in install


def test_a_node_gets_its_taints_and_labels_and_lvm2_for_rook(tmp_path) -> None:
    env = RKE2 | {"TAINTS": "example.org/no-avx2=true:NoSchedule", "LABELS": "zone=a;disk=ssd", "STORAGE": "rook-ceph"}
    work, root = _work(tmp_path, "rke2", env, {"token": "t"}, UBUNTU)
    run = _run("rke2.sh", work, root)
    assert run.returncode == 0, run.stderr
    config = (root / "etc/rancher/rke2/config.yaml").read_text()
    assert 'node-taint:\n  - "example.org/no-avx2=true:NoSchedule"\n' in config
    assert 'node-label:\n  - "zone=a"\n  - "disk=ssd"\n' in config
    assert "lvm2" in (root / "commands.log").read_text()
    work, root = _work(tmp_path / "2", "rke2", RKE2, {"token": "t"}, UBUNTU)
    assert _run("rke2.sh", work, root).returncode == 0
    assert "node-taint" not in (root / "etc/rancher/rke2/config.yaml").read_text()


ROOK = ADDONS | {
    "STORAGE": "rook-ceph", "ROOK_VERSION": "v1.21.0", "ROOK_CHART_REPO": "https://charts.example.org/rook",
    "ROOK_DEVICE_FILTER": "^vd[b-z]$", "ROOK_FAILURE_DOMAIN": "chassis", "NODES": "4",
    "TOLERATE": "example.org/no-avx2",
    "METALLB": "true", "METALLB_ADDRESSES": "192.0.2.200-192.0.2.220", "METALLB_INGRESS_IP": "192.0.2.200",
    "METALLB_CHART_REPO": "https://charts.example.org/metallb", "METALLB_VERSION": "", "INGRESS": "traefik",
    "CERT_MANAGER": "false", "CNPG": "false", "AGENT": "false",
}  # fmt: skip


def test_rook_ceph_on_the_extra_disks_tolerating_the_taints(tmp_path) -> None:
    work, root = _work(tmp_path, "addons", ROOK, {}, UBUNTU)
    run = _run("addons.sh", work, root)
    assert run.returncode == 0, run.stderr
    tolerations = '[{key: "example.org/no-avx2", operator: Exists}]'
    assert f"pluginTolerations: {tolerations}" in (work / "rook-operator.yaml").read_text()
    cluster = (work / "rook-cluster.yaml").read_text()
    assert "mon:\n    count: 3\n" in cluster and "mgr:\n    count: 2\n" in cluster  # 4 nodes: 3 mons at most
    assert (
        "failureDomain: chassis" in cluster
        and 'deviceFilter: "^vd[b-z]$"' in cluster
        and "replicated:\n        size: 3\n" in cluster
    )
    assert "name: ceph-block\n      isDefault: true" in cluster and f"tolerations: {tolerations}" in cluster
    log = (root / "commands.log").read_text()
    assert "helm upgrade --install rook-ceph rook-release/rook-ceph --version v1.21.0" in log
    assert "local-path" not in log  # the default StorageClass is Ceph's


def test_one_node_has_one_mon_and_one_replica(tmp_path) -> None:
    work, root = _work(tmp_path, "addons", ROOK | {"NODES": "1", "TOLERATE": "", "METALLB": "false"}, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    cluster = (work / "rook-cluster.yaml").read_text()
    assert "count: 1\n    allowMultiplePerNode" in cluster and "size: 1\n" in cluster and "tolerations: []" in cluster


def test_metallb_puts_the_ingress_on_its_address(tmp_path) -> None:
    work, root = _work(tmp_path, "addons", ROOK | {"STORAGE": "none"}, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    manifests = (root / "manifests.yaml").read_text()
    assert "kind: IPAddressPool" in manifests and "    - 192.0.2.200-192.0.2.220\n" in manifests
    assert "kind: L2Advertisement" in manifests and "ipAddressPools: [ngvm]" in manifests
    assert "name: ngvm-ingress-lb\n  namespace: kube-system" in manifests  # its own Service since v0.25.7
    assert "metallb.io/loadBalancerIPs: 192.0.2.200" in manifests
    assert "app.kubernetes.io/name: rke2-traefik" in manifests
    work, root = _work(tmp_path / "2", "addons", ROOK | {"STORAGE": "none", "INGRESS": "ingress-nginx"}, {}, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    assert "app.kubernetes.io/name: rke2-ingress-nginx" in (root / "manifests.yaml").read_text()


def test_the_libvirt_root_needs_no_provider() -> None:
    versions = (ROOT / "deploy/tofu/libvirt/versions.tf").read_text()
    assert "required_providers" not in versions
    main = (ROOT / "deploy/tofu/libvirt/main.tf").read_text()
    assert "scripts/vm-libvirt.sh $W destroy" in main and "physical_host = m.hypervisor" in main


@pytest.mark.skipif(not shutil.which("tofu"), reason="OpenTofu not installed (the CI job tofu runs it)")
def test_the_plan_of_the_libvirt_example(tmp_path) -> None:
    env = dict(os.environ, PLAN_JSON=str(tmp_path / "plan"))
    run = subprocess.run([str(ROOT / "deploy/tofu/check.sh"), "--offline"], env=env, capture_output=True, text=True)
    assert run.returncode == 0, run.stdout + run.stderr
    changes = {
        r["address"]: r["change"]["after"]
        for r in json.loads((tmp_path / "plan-libvirt.json").read_text())["resource_changes"]
    }
    assert sorted(a for a in changes if a.startswith("terraform_data.vm")) == [
        f'terraform_data.vm["cn{i}"]' for i in range(4)
    ]
    vm = changes['terraform_data.vm["cn0"]']["input"]
    assert vm["host"] == "192.0.2.10" and "NETWORK='ovs:ovs0'" in vm["env"] and "DATA_DISKS='200'" in vm["env"]
    tainted = changes["module.platform.terraform_data.rke2_third[0]"]["triggers_replace"]["env"]
    assert tainted["NODE_NAME"] == "cn0" and tainted["TAINTS"] == "example.org/no-avx2=true:NoSchedule"
    assert tainted["LABELS"] == "topology.rook.io/chassis=hyp00"
    addons = changes["module.platform.terraform_data.addons[0]"]["triggers_replace"]["env"]
    assert (
        addons["STORAGE"] == "rook-ceph"
        and addons["ROOK_FAILURE_DOMAIN"] == "chassis"
        and addons["NODES"] == "4"
        and addons["METALLB_INGRESS_IP"] == "192.0.2.200"
    )


def test_release_recorded() -> None:
    assert "## v0.25.1 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([1-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
