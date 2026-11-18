# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.5: every job fetches the code of NGVM by the address its runner already reaches.

- Each job cloned the code at `NGVM_SERVER_URL`, else at GitLab's advertised address: a runner
  outside the LAN needed the variable, and the variable set on a group sent the runners of the LAN to
  an address they could not reach (403). The jobs now try the address the runner fetched the project
  from (`CI_REPOSITORY_URL`), then `NGVM_SERVER_URL`, then GitLab's own; one block for every job.
- The GitLab API, in a job, is read by the same address unless `NGVM_SERVER_URL` is set (the pods).
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from ngvm.gitlab import api_base, repository_base

from .conftest import ROOT

TEMPLATE = ROOT / "templates/client-pipeline.yml"
TOKEN = "job-token-123"  # an invented token: it must never be printed

FAKE_GIT = r"""#!/bin/sh
for a in "$@"; do url="$last"; last="$a"; done
echo "$url" >> "$GIT_LOG"
case "$url" in
  *"$GOOD"*) if [ -n "$GOOD" ]; then mkdir -p "$last"; exit 0; fi ;;
esac
echo "fatal: unable to access '$url': The requested URL returned error: 403" >&2
exit 128
"""


# -- 1. one way to fetch the code, for every job -----------------------------------------------------
def test_one_block_for_every_job() -> None:
    text = TEMPLATE.read_text(encoding="utf-8")
    assert text.count("&fetch_ngvm |") == 1 and text.count("- *fetch_ngvm\n") == 2
    assert 'BASE="${NGVM_SERVER_URL' not in text and "A2VM_SERVER_URL" not in text
    assert text.count("git -c advice.detachedHead=false clone") == 1
    jobs = yaml.safe_load(text)
    scripts = [jobs[".ngvm"]["before_script"], jobs["deploy-k8s"]["script"], jobs["send-alerts-k8s"]["script"]]
    for script in scripts:
        assert sum("CI_REPOSITORY_URL" in line for line in script) == 1
    # the pods still get GitLab's address for the API
    assert '"${NGVM_SERVER_URL:-$CI_SERVER_URL}"' in text


def _block() -> str:
    jobs = yaml.safe_load(TEMPLATE.read_text(encoding="utf-8"))
    return next(line for line in jobs[".ngvm"]["before_script"] if "CI_REPOSITORY_URL" in line)


def _fetch(tmp_path: Path, good: str, **env: str) -> tuple[int, str, list[str]]:
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir(exist_ok=True)
    (bin_dir / "git").write_text(FAKE_GIT)
    (bin_dir / "timeout").write_text('#!/bin/sh\nshift\nexec "$@"\n')
    for tool in ("git", "timeout"):
        (bin_dir / tool).chmod(0o755)
    log = tmp_path / "git.log"
    log.unlink(missing_ok=True)
    work = tmp_path / "job"
    work.mkdir(exist_ok=True)
    base = {
        "PATH": f"{bin_dir}:{os.environ['PATH']}",
        "GIT_LOG": str(log),
        "GOOD": good,
        "CI_JOB_TOKEN": TOKEN,
        "NGVM_REF": "v0.27.5",
        "NGVM_PROJECT": "vulnops/ngvm",
        "CI_PROJECT_PATH": "vulnops/clients/lab",
        "CI_SERVER_PROTOCOL": "https",
        "CI_SERVER_HOST": "gitlab.example.org",
        "CI_SERVER_PORT": "443",
    }
    base.update(env)
    done = subprocess.run(["sh", "-c", _block()], cwd=work, env=base, capture_output=True, text=True)
    tried = log.read_text().splitlines() if log.exists() else []
    return done.returncode, done.stdout + done.stderr, tried


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_the_runners_own_address_first(tmp_path: Path) -> None:
    repo = f"https://gitlab-ci-token:{TOKEN}@gitlab.int.example.org/vulnops/clients/lab.git"
    code, out, tried = _fetch(
        tmp_path, "gitlab.int.example.org", CI_REPOSITORY_URL=repo, NGVM_SERVER_URL="https://gitlab.example.org"
    )
    assert code == 0, out
    assert tried == [f"https://gitlab-ci-token:{TOKEN}@gitlab.int.example.org/vulnops/ngvm.git"]
    assert "NGVM v0.27.5 fetched from gitlab.int.example.org" in out and "WARN" not in out


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_the_next_address_when_one_fails(tmp_path: Path) -> None:
    repo = f"https://gitlab-ci-token:{TOKEN}@gitlab.int.example.org/vulnops/clients/lab.git"
    code, out, tried = _fetch(
        tmp_path,
        "//gitlab-ci-token:" + TOKEN + "@gitlab.example.org/",
        CI_REPOSITORY_URL=repo,
        NGVM_SERVER_URL="https://gitlab.example.org/",
    )
    assert code == 0, out
    assert [re.sub(r"//[^@]*@", "//", t) for t in tried] == [
        "https://gitlab.int.example.org/vulnops/ngvm.git",
        "https://gitlab.example.org/vulnops/ngvm.git",
    ]
    assert "WARN  NGVM not fetched from gitlab.int.example.org: fatal: unable to access 'https://gitlab.int" in out
    assert "fetched from gitlab.example.org" in out and TOKEN not in out


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_a_gitlab_under_a_path_keeps_it(tmp_path: Path) -> None:
    repo = f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org:8443/git/vulnops/clients/lab.git"
    code, out, tried = _fetch(tmp_path, "8443/git/vulnops/ngvm.git", CI_REPOSITORY_URL=repo)
    assert code == 0, out
    assert tried == [f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org:8443/git/vulnops/ngvm.git"]


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_no_address_answers(tmp_path: Path) -> None:
    repo = f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org:443/vulnops/clients/lab.git"
    code, out, tried = _fetch(tmp_path, "", CI_REPOSITORY_URL=repo)
    assert code == 1
    assert len(tried) == 1  # the repository's address and GitLab's own are the same: tried once
    assert "ERROR NGVM v0.27.5 could not be fetched from vulnops/ngvm by any address" in out
    assert TOKEN not in out


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs a POSIX shell")
def test_without_repository_url(tmp_path: Path) -> None:
    code, out, tried = _fetch(tmp_path, "gitlab.example.org")
    assert code == 0, out
    assert tried == [f"https://gitlab-ci-token:{TOKEN}@gitlab.example.org:443/vulnops/ngvm.git"]


# -- 2. the GitLab API by the same address ----------------------------------------------------------
def test_api_base() -> None:
    job = {
        "CI_REPOSITORY_URL": f"https://gitlab-ci-token:{TOKEN}@gitlab.int.example.org/vulnops/clients/lab.git",
        "CI_PROJECT_PATH": "vulnops/clients/lab",
        "CI_API_V4_URL": "https://gitlab.example.org/api/v4",
    }
    assert api_base(job) == "https://gitlab.int.example.org/api/v4"
    assert api_base({**job, "NGVM_SERVER_URL": "https://gitlab.example.org/"}) == "https://gitlab.example.org/api/v4"
    assert api_base({"CI_API_V4_URL": "https://gitlab.example.org/api/v4"}) == "https://gitlab.example.org/api/v4"
    under = {
        "CI_REPOSITORY_URL": "https://gitlab-ci-token:x@gitlab.example.org:8443/git/a/b.git",
        "CI_PROJECT_PATH": "a/b",
    }
    assert repository_base(under) == "https://gitlab.example.org:8443/git"
    assert repository_base({"CI_REPOSITORY_URL": "https://gitlab.example.org/x/y.git"}) == "https://gitlab.example.org"
    assert repository_base({}) is None


# -- 3. documented ------------------------------------------------------------------------------------
def test_documented() -> None:
    openvas = (ROOT / "docs/openvas.md").read_text(encoding="utf-8")
    assert "(`clone_url`, since v0.27.5)" in openvas and "Never set it on a group" in openvas
    ops = (ROOT / "docs/operations.md").read_text(encoding="utf-8")
    assert 'by any address" (v0.27.5)' in ops
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert "| v0.27.5 (current) |" in hld and "`CI_REPOSITORY_URL`" in hld
    assert "(`CI_REPOSITORY_URL`), then" in (ROOT / "docs/deployment.md").read_text(encoding="utf-8")


def test_release_recorded() -> None:
    assert "## v0.27.5 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(27\.([5-9]|\d\d+)|2[89]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
