# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.6: the address of GitLab a runner really uses, read where the runner wrote it.

`CI_REPOSITORY_URL` keeps GitLab's advertised address whatever the runner's `clone_url`: a runner
outside the LAN, without `NGVM_SERVER_URL`, tried the internal address twice and stopped. The jobs
now read the remote `origin` of the checkout the runner has just made, then the rest as before.
"""

from __future__ import annotations

import re
import shutil
from pathlib import Path

import pytest

from ngvm.gitlab import api_base, origin_url, repository_base

from .conftest import ROOT
from .test_v0275 import TEMPLATE, TOKEN, _fetch

INTERNAL = f"https://gitlab-ci-token:{TOKEN}@gitlab.int.example.org/vulnops/clients/lab.git"
PUBLIC = f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org/vulnops/clients/lab.git"


# -- 1. the checkout's origin first -----------------------------------------------------------------
def test_the_block_reads_the_checkout() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert "remote get-url origin" in text and text.count("ngvm_base()") == 1
    assert 'for BASE in "$ORIGIN_BASE" "$REPO_BASE" "${NGVM_SERVER_URL:-}"' in text


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_a_runner_with_a_clone_url(tmp_path: Path) -> None:
    # GitLab advertises the internal address; the runner fetched by its clone_url, the public one
    code, out, tried = _fetch(tmp_path, "gitlab.example.org/", ORIGIN=PUBLIC, CI_REPOSITORY_URL=INTERNAL)
    assert code == 0, out
    assert tried == [f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org/vulnops/ngvm.git"]
    assert "NGVM v0.27.5 fetched from gitlab.example.org" in out and "WARN" not in out and TOKEN not in out


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_a_runner_of_the_lan(tmp_path: Path) -> None:
    code, out, tried = _fetch(tmp_path, "gitlab.int.example.org", ORIGIN=INTERNAL, CI_REPOSITORY_URL=INTERNAL)
    assert code == 0, out
    assert len(tried) == 1 and "fetched from gitlab.int.example.org" in out


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_an_origin_without_token_or_suffix(tmp_path: Path) -> None:
    origin = "https://gitlab.example.org:8443/git/vulnops/clients/lab"
    code, out, tried = _fetch(tmp_path, "8443/git/vulnops/ngvm.git", ORIGIN=origin, CI_REPOSITORY_URL=INTERNAL)
    assert code == 0, out
    assert tried == [f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org:8443/git/vulnops/ngvm.git"]


# -- 2. the GitLab API by the same address ----------------------------------------------------------
def _checkout(tmp_path: Path, url: str) -> Path:
    git = tmp_path / "project" / ".git"
    git.mkdir(parents=True)
    (git / "config").write_text(
        '[core]\n\tbare = false\n[remote "upstream"]\n\turl = https://other.example.org/x.git\n'
        f'[remote "origin"]\n\turl = {url}\n\tfetch = +refs/heads/*:refs/remotes/origin/*\n[branch "main"]\n'
    )
    return tmp_path / "project"


def test_api_base_reads_the_checkout(tmp_path: Path) -> None:
    project = _checkout(tmp_path, PUBLIC)
    assert origin_url(str(project)) == PUBLIC
    job = {
        "CI_PROJECT_DIR": str(project),
        "CI_PROJECT_PATH": "vulnops/clients/lab",
        "CI_REPOSITORY_URL": INTERNAL,
        "CI_API_V4_URL": "https://gitlab.int.example.org/api/v4",
    }
    assert repository_base(job) == "https://gitlab.example.org"
    assert api_base(job) == "https://gitlab.example.org/api/v4"
    assert api_base({**job, "NGVM_SERVER_URL": "https://gitlab.lan.example.org"}).startswith("https://gitlab.lan.")
    # no checkout: CI_REPOSITORY_URL as before
    assert api_base({**job, "CI_PROJECT_DIR": str(tmp_path / "none")}) == "https://gitlab.int.example.org/api/v4"
    assert origin_url(None) is None


# -- 3. documented ------------------------------------------------------------------------------------
def test_documented() -> None:
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert "v0.27.5 did not, as its notes said, make the variable" in changelog
    openvas = (ROOT / "docs/openvas.md").read_text(encoding="utf-8")
    assert "read on the remote `origin` of the job's checkout (since\n   v0.27.6)" in openvas
    ops = (ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert "In v0.27.5 only, a runner outside the LAN" in ops
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert "| v0.27.6 (current) |" in hld


def test_release_recorded() -> None:
    assert "## v0.27.6 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(27\.([6-9]|\d\d+)|2[89]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
