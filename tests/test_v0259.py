# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.25.9: GitLab's CA reaches the agent, and a CA that does not validate stops the step.

The agent's chart dropped `config.caCert` in its 2.0.0 for `config.kasCaCert`, and Helm ignores a
value a chart does not know: the agent of a cluster made by OpenTofu got no CA, looped for hours on
"certificate signed by unknown authority", and every deployment of a tenant timed out on a tunnel
that was never there. The CA is now given under the name the chart reads, and checked first.
"""

from __future__ import annotations

import re

from .conftest import ROOT
from .test_v0250 import ADDONS, UBUNTU, _run, _work

SCRIPT = ROOT / "deploy/tofu/scripts/addons.sh"


def test_the_ca_is_given_under_the_name_the_chart_reads(tmp_path) -> None:
    pem = "-----BEGIN CERTIFICATE-----\nAA\n-----END CERTIFICATE-----\n"
    stage = {"agent-token": "glagent-x", "gitlab-ca.pem": pem}
    work, root = _work(tmp_path, "addons", ADDONS, stage, UBUNTU)
    assert _run("addons.sh", work, root).returncode == 0
    values = (work / "agent-values.yaml").read_text()
    assert "  kasCaCert: |\n    -----BEGIN CERTIFICATE-----\n" in values
    assert "caCert: |" not in values.replace("kasCaCert: |", "")


def test_a_ca_that_does_not_validate_the_agent_server_stops_the_step() -> None:
    script = SCRIPT.read_text()
    assert '--cacert "$WORK/stage/gitlab-ca.pem"' in script and '"https://${KAS_ADDRESS#*://}"' in script
    assert '[ "$rc" != 60 ]' in script  # 60: curl could not verify the certificate
    assert "does not validate $KAS_ADDRESS" in script
    check = script.index('--cacert "$WORK/stage/gitlab-ca.pem"')
    assert check < script.index('helm upgrade --install "$AGENT_NAME"')


def test_release_recorded() -> None:
    assert "## v0.25.9 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(25\.(9|\d\d+)|2[6-9]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
