# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.4: the default route of a VM as 0.0.0.0/0, not `default`.

The cloud-init of Rocky 10 (24.4, NetworkManager) fails on `to: default` ("Address default is not
a valid ip address") and then applies nothing: no address, no hostname, no administrator.
"""

from __future__ import annotations

import re

from .conftest import ROOT


def test_the_default_route_is_an_address() -> None:
    template = (ROOT / "deploy/tofu/libvirt/network-config.yaml.tftpl").read_text()
    assert "to: default" not in template
    assert '- to: ${strcontains(gateway, ":") ? "::/0" : "0.0.0.0/0"}' in template
    assert "via: ${gateway}" in template and 'macaddress: "${mac}"' in template


def test_release_recorded() -> None:
    assert "## v0.25.4 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.([4-9]|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
