# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""v0.27.3: refuse rather than stay silent.

The lot of reliability found on the first days of the platform. Silent blindness is the worst
failure this product has: a database restored from a dump made before v0.25.0 kept policies
testing the setting of the older name, and every service then saw an empty tenant and said so
calmly. A service now checks the isolation of its tables at start and refuses to start when it
does not hold; the repair is the
operator's explicit act. An address to a Service that does not exist stops the deployment instead
of failing in every pod. And smaller defects: the watch's LLM answers could not be written, the
supervision page read a field the contract does not have and the version of the last run as the
service's, and the drawing of the paths kept four columns for two.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
from pathlib import Path

import httpx
import pytest
import yaml

from ngvm import db as ngdb
from verdict.service import exposure

from .conftest import ROOT
from .test_v0232 import CHAT, _tools
from .test_v0262 import STEPS, SUMMARY, TENANT, VIA

WATCH = ROOT / "deploy/charts/ngvm-tenant/templates/watch.yaml"
VALUES = ROOT / "deploy/charts/ngvm-tenant/values.yaml"
CHECK = ROOT / "deploy/k8s/check-addresses.sh"
PIPELINE = ROOT / "templates/client-pipeline.yml"
KUBERNETES = ROOT / "docs/kubernetes.md"


# -- 1. the isolation of the tenant's database, checked at start ------------------------------------
def _components():
    from detect.intake.pgstore import MIGRATIONS as DETECT
    from dispatch.store import MIGRATIONS as DISPATCH
    from ngvm.actions import MIGRATIONS as ACTIONS
    from ngvm.audit import MIGRATIONS as AUDIT
    from verdict.service.pgstore import MIGRATIONS as VERDICT
    from via.service.pgstore import MIGRATIONS as VIA_MIGRATIONS

    return {"via": VIA_MIGRATIONS, "detect": DETECT, "verdict": VERDICT, "dispatch": DISPATCH,
            "actions": ACTIONS, "audit": AUDIT}  # fmt: skip


def test_every_component_keeps_its_schema_and_nothing_else() -> None:
    assert set(_components()) == set(ngdb.SCHEMAS)
    sql = ngdb.repair_sql()
    assert all(f"'{s}'" in sql for s in ngdb.SCHEMAS)  # the repair covers every schema


def test_a_fresh_database_holds_for_every_component(tenant_db) -> None:
    for component, migrations in _components().items():
        db = ngdb.Database(tenant_db, component, migrations, size=1)
        db.init()
        db.check_isolation()  # raises if a table of the version were not kept to one tenant
        db.close()


def _as_restored_from_an_older_dump(dsn: str) -> None:
    import psycopg

    with psycopg.connect(dsn, autocommit=True) as conn:
        conn.execute(
            "ALTER POLICY runs_tenant ON verdict.runs USING (tenant = current_setting('legacy.tenant', true)) "
            "WITH CHECK (tenant = current_setting('legacy.tenant', true))"
        )
        conn.execute("ALTER TABLE verdict.findings NO FORCE ROW LEVEL SECURITY")
        conn.execute("DROP POLICY push_keys_tenant ON verdict.push_keys")


def test_a_database_restored_from_an_older_dump_is_refused_at_start(tenant_db, monkeypatch) -> None:
    from verdict.service.pgstore import MIGRATIONS

    ngdb.Database(tenant_db, "verdict", MIGRATIONS, size=1).init()
    _as_restored_from_an_older_dump(tenant_db)
    monkeypatch.setenv("NGVM_DB_DSN", tenant_db)
    with pytest.raises(ngdb.IsolationError) as caught:
        ngdb.open_database("verdict", MIGRATIONS)
    problems = caught.value.problems
    assert "verdict.runs: policy runs_tenant tests legacy.tenant, not ngvm.tenant" in problems
    assert any(p.startswith("verdict.findings: row-level security not forced") for p in problems)
    assert "verdict.push_keys: no policy" in problems
    message = str(caught.value)
    assert "refusing to start" in message and "ngvm db repair" in message and "§5.1" in message
    assert "password" not in message and "app@" not in message  # host and database only
    assert isinstance(caught.value, ngdb.DatabaseError)  # the services print it and exit 2


def test_the_operator_repairs_it_once_and_the_service_starts(tenant_db, monkeypatch, capsys) -> None:
    from ngvm.cli import main
    from verdict.service.pgstore import MIGRATIONS

    ngdb.Database(tenant_db, "verdict", MIGRATIONS, size=1).init()
    _as_restored_from_an_older_dump(tenant_db)
    monkeypatch.setenv("NGVM_DB_DSN", tenant_db)
    assert main(["db", "check"]) == 1
    assert "FAIL  verdict.runs: policy runs_tenant tests legacy.tenant" in capsys.readouterr().err
    assert main(["db", "repair"]) == 0
    out = capsys.readouterr().out
    assert "FIXED dropped policy runs_tenant on verdict.runs" in out
    assert "FIXED created policy runs_tenant on verdict.runs" in out
    assert "FIXED forced row-level security on verdict.findings" in out
    assert "FIXED created policy push_keys_tenant on verdict.push_keys" in out
    assert "OK    verdict: every table kept to one tenant" in out
    assert main(["db", "repair"]) == 0 and "OK    nothing to repair" in capsys.readouterr().out
    db = ngdb.open_database("verdict", MIGRATIONS)  # starts now
    assert db is not None
    db.close()


def test_a_policy_that_lets_every_row_through_is_not_isolation(tenant_db) -> None:
    import psycopg

    from via.service.pgstore import MIGRATIONS

    db = ngdb.Database(tenant_db, "via", MIGRATIONS, size=1)
    db.init()
    table = sorted(_tables(tenant_db, "via"))[0]
    with psycopg.connect(tenant_db, autocommit=True) as conn:
        conn.execute(f"CREATE POLICY open_all ON via.{table} USING (true)")
    with pytest.raises(ngdb.IsolationError) as caught:
        db.check_isolation()
    assert f"via.{table}: policy open_all tests no setting, not ngvm.tenant" in caught.value.problems
    assert any("open_all" in line for line in db.repair_isolation())
    db.check_isolation()
    db.close()


def _tables(dsn: str, schema: str) -> set[str]:
    import psycopg

    with psycopg.connect(dsn) as conn:
        rows = conn.execute(
            "SELECT table_name FROM information_schema.columns WHERE table_schema = %s AND column_name = 'tenant'",
            (schema,),
        ).fetchall()
    return {r[0] for r in rows}


def test_the_repair_is_the_operators_act_never_the_services() -> None:
    import inspect

    source = inspect.getsource(ngdb.open_database)
    assert "check_isolation()" in source and "repair" not in source.split('"""')[-1]
    sql = (ROOT / "ngvm/src/ngvm/data/repair-policies.sql").read_text(encoding="utf-8")
    assert ngdb.repair_sql() == sql  # packaged with ngvm: the same file the operator runs with psql
    assert "RAISE NOTICE" in sql and "current_setting(''ngvm.tenant'', true)" in sql


def test_db_check_needs_the_services_connection(monkeypatch, capsys) -> None:
    from ngvm.cli import main

    monkeypatch.delenv("NGVM_DB_DSN", raising=False)
    monkeypatch.delenv("NGVM_DB_DSN_FILE", raising=False)
    assert main(["db", "check"]) == 2
    assert "NGVM_DB_DSN_FILE" in capsys.readouterr().err
    assert main(["db", "repair", "--sql"]) == 0
    assert capsys.readouterr().out == ngdb.repair_sql()


def test_documented_for_the_operator() -> None:
    doc = KUBERNETES.read_text(encoding="utf-8")
    assert "### 5.1 A database whose isolation does not hold (v0.27.3)" in doc
    assert "psql -d app -v ON_ERROR_STOP=1 < ngvm/src/ngvm/data/repair-policies.sql" in doc
    assert "rollout restart deploy -l ngvm/tenant=lab" in doc
    assert "made before v0.25.0" in doc and "ngvm db check" in doc


# -- 3. the watch's LLM answers are written somewhere they can be -----------------------------------
def test_the_passages_keep_the_llm_answers_on_a_claim_of_their_own() -> None:
    text = WATCH.read_text(encoding="utf-8")
    assert "name: {{ $name }}-watch-llm-cache" in text and "accessModes: [ReadWriteOnce]" in text
    assert 'claimName: {{ include "ngvm-tenant.name" $root }}-watch-llm-cache' in text
    assert "value: {{ if .cache }}/llm-cache/llm-cache.json{{ else }}/tmp/llm-cache.json{{ end }}" in text
    passage = [line for line in text.splitlines() if '"container" "watch"' in line]
    assert passage and '"cache" $w.llmCache.enabled' in passage[0]
    send = [line for line in text.splitlines() if '"container" "send"' in line]
    assert send and '"cache"' not in send[0]  # a send may run during a passage: it keeps its own
    assert "concurrencyPolicy: Forbid" in text  # one passage at a time: ReadWriteOnce is enough
    values = yaml.safe_load(VALUES.read_text(encoding="utf-8"))
    assert values["watch"]["llmCache"] == {"enabled": True, "size": "1Gi", "storageClass": ""}
    pipeline = PIPELINE.read_text(encoding="utf-8")
    assert '"${NGVM_WATCH_LLM_CACHE:-true}" = "false"' in pipeline and "watch.llmCache.enabled=false" in pipeline


def test_the_daily_run_keeps_its_cache_where_it_was() -> None:
    helpers = (ROOT / "deploy/charts/ngvm-tenant/templates/_helpers.tpl").read_text(encoding="utf-8")
    assert 'export NGVM_LLM_CACHE_FILE="${NGVM_LLM_CACHE_FILE:-/data/llm-cache.json}"' in helpers


# -- 4. the supervision page ------------------------------------------------------------------------
DETECT = {"version": "0.27.3", "collectors": [{"id": "lan", "sources": [
    {"source": "openvas", "max_age_hours": 26, "age_hours": 5.2, "stale": False,
     "last_received_at": "2026-11-17T05:00:00+00:00"},
    {"source": "cmdb", "max_age_hours": 26, "stale": True},
]}]}  # fmt: skip


def _handler(asked: list):
    def handler(request: httpx.Request) -> httpx.Response:
        asked.append((request.url.host, request.url.path))
        if request.url.host == "detect.example":
            return httpx.Response(200, json=DETECT)
        if request.url.host == "via.example":
            return httpx.Response(200, json=VIA if not request.url.path.endswith("/alerts") else {"items": []})
        if request.url.path.endswith("/progress"):
            return httpx.Response(200, json={"schema": "ngvm.progress_runs/1", "tenant": TENANT,
                                             "runs": [{"run": "1", "steps": STEPS}]})  # fmt: skip
        if request.url.path.endswith("/summary"):
            return httpx.Response(200, json={**SUMMARY, "ngvm_version": "0.27.2"})  # made before the upgrade
        if request.url.path.endswith("/status"):
            return httpx.Response(200, json={"service": "verdict", "version": "0.27.3", "runs": 7})
        return httpx.Response(404, json={"detail": "no"})

    return handler


def _supervision(tmp_path, asked):
    return _tools(tmp_path, _handler(asked), via_url="http://via.example", via_token="v",
                  detect_url="http://detect.example", detect_token="d")  # fmt: skip


def test_the_last_push_is_the_field_of_the_contract(tmp_path) -> None:
    out = _supervision(tmp_path, []).call(CHAT, "/run-progress", {})
    pushes = {c["source"]: c["last_push"] for c in out["agents"]["collectors"]}
    assert pushes == {"openvas": "2026-11-17T05:00:00+00:00", "cmdb": ""}
    contract = yaml.safe_load((ROOT / "ngvm/src/ngvm/schemas/openapi/detect.v1.yaml").read_text())
    fields = contract["components"]["schemas"]["CollectorStatus"]["properties"]["sources"]["items"]["properties"]
    assert "last_received_at" in fields and "last_push" not in fields and "pushed_at" not in fields


def test_the_decision_service_says_its_own_version(tmp_path) -> None:
    asked: list = []
    tools = _supervision(tmp_path, asked)
    out = tools.call(CHAT, "/run-progress", {})
    assert out["agents"]["decision"] == "0.27.3"  # the service that runs
    assert out["agents"]["last_run_version"] == "0.27.2"  # the version that made the last run
    assert ("verdict.example", f"/v1/tenants/{TENANT}/status") in asked
    page = tools.page("analyst@example.org")
    assert "Decision service" in page and "0.27.3" in page
    assert "Last run made by" in page and "2026-11-17 05:00" in page


def test_the_status_route_is_in_the_contract() -> None:
    contract = yaml.safe_load((ROOT / "ngvm/src/ngvm/schemas/openapi/verdict.v1.yaml").read_text())
    route = contract["paths"]["/v1/tenants/{tenant}/status"]["get"]
    schema = route["responses"]["200"]["content"]["application/json"]["schema"]
    assert route["operationId"] == "serviceStatus" and set(schema["required"]) == {"service", "version", "runs"}


# -- 5. an address to a missing Service stops the deployment ---------------------------------------
FAKE_KUBECTL = """#!/bin/sh
case "$*" in
  "get namespace ngvm-via"|"get namespace ngvm-portal"|"get namespace locked") exit 0 ;;
  "get namespace "*) echo 'Error from server (NotFound): namespaces "x" not found' >&2; exit 1 ;;
  "-n ngvm-via get service ngvm-via-intel -o name") echo service/ngvm-via-intel ;;
  "-n ngvm-portal get service portal-portal-db-rw -o name") echo service/portal-portal-db-rw ;;
  "-n locked get service "*) echo 'Error from server (Forbidden): services is forbidden' >&2; exit 1 ;;
  *) echo 'Error from server (NotFound): services "x" not found' >&2; exit 1 ;;
esac
"""


def _check(tmp_path: Path, **variables: str) -> subprocess.CompletedProcess:
    sh = shutil.which("sh")
    if sh is None:
        pytest.skip("no sh here")
    kubectl = tmp_path / "bin" / "kubectl"
    kubectl.parent.mkdir(exist_ok=True)
    kubectl.write_text(FAKE_KUBECTL)
    kubectl.chmod(0o755)
    env = {"PATH": f"{kubectl.parent}{os.pathsep}{os.environ.get('PATH', '')}", **variables}
    return subprocess.run([sh, str(CHECK)], env=env, capture_output=True, text=True, timeout=30)


def test_addresses_to_services_that_exist_pass(tmp_path) -> None:
    done = _check(
        tmp_path,
        NGVM_INTEL_URL="http://ngvm-via-intel.ngvm-via.svc:8080",
        NGVM_REPORTING_DSN="postgresql://ngvm_writer:pw-0123456789@portal-portal-db-rw.ngvm-portal:5432/ngvm",
        NGVM_LLM_BASE_URL="http://llm.lab.example:8000/v1, http://gpu01:8000/v1",
    )
    assert done.returncode == 0, done.stderr
    assert "OK    NGVM_INTEL_URL: service ngvm-via-intel in namespace ngvm-via" in done.stdout
    assert "OK    NGVM_REPORTING_DSN: service portal-portal-db-rw in namespace ngvm-portal" in done.stdout
    assert "llm.lab.example" not in done.stdout and "gpu01" not in done.stdout  # outside: left alone
    assert "pw-0123456789" not in done.stdout + done.stderr  # never a value


def test_the_intel_url_of_the_incident_stops_the_deployment(tmp_path) -> None:
    done = _check(tmp_path, NGVM_INTEL_URL="http://ngvm-intel.ngvm-via.svc.cluster.local:8080/")
    assert done.returncode == 1
    assert "ERROR NGVM_INTEL_URL points at the service ngvm-intel in the namespace ngvm-via" in done.stderr


def test_a_connection_string_in_key_value_form_and_a_named_portal(tmp_path) -> None:
    secret = "dbname=ngvm host=db-rw.ngvm-portal password=pw-0123456789 sslmode=verify-full"
    done = _check(tmp_path, NGVM_REPORTING_DSN_CLIENT=secret)
    assert done.returncode == 1
    assert "NGVM_REPORTING_DSN_CLIENT points at the service db-rw in the namespace ngvm-portal" in done.stderr
    assert "pw-0123456789" not in done.stdout + done.stderr


def test_a_file_variable_is_read_and_a_forbidden_check_only_warns(tmp_path) -> None:
    dsn = tmp_path / "dsn"
    dsn.write_text("postgresql://w:pw-0123456789@portal-portal-db-rw.ngvm-portal/ngvm")
    done = _check(tmp_path, NGVM_REPORTING_DSN=str(dsn), NGVM_RELAY_URL="https://relay.locked.svc")
    assert done.returncode == 0
    assert "OK    NGVM_REPORTING_DSN: service portal-portal-db-rw" in done.stdout
    assert "WARN  NGVM_RELAY_URL: cannot check the service relay in locked" in done.stdout


def test_a_host_whose_second_label_is_no_namespace_is_outside(tmp_path) -> None:
    done = _check(tmp_path, NGVM_INTEL_URL="https://intel.example:8443", NGVM_RELAY_URL="http://relay.lan:3128")
    assert done.returncode == 0 and done.stdout == "" and done.stderr == ""


def test_deploy_checks_the_addresses_before_it_changes_anything() -> None:
    text = PIPELINE.read_text(encoding="utf-8")
    job = text[text.index("\ndeploy-k8s:") :]
    check = job.index("sh .ngvm/deploy/k8s/check-addresses.sh")
    assert check < job.index('kubectl create namespace "$NS"') and check < job.index("upsert()")
    assert job.index("*legacy_variables") < check  # the older names already read as NGVM_*
    assert CHECK.stat().st_mode & 0o111  # executable, and run with sh in any case


def test_the_check_is_posix_and_clean() -> None:
    text = CHECK.read_text(encoding="utf-8")
    assert text.startswith("#!/bin/sh\n") and "[[ " not in text and "local " not in text  # no bashism
    shellcheck = shutil.which("shellcheck")
    if shellcheck:
        done = subprocess.run([shellcheck, "-s", "sh", str(CHECK)], capture_output=True, text=True)
        assert done.returncode == 0, done.stdout


# -- 6. the drawing folds onto the columns it uses -------------------------------------------------
def _graph(columns: list[int]) -> dict:
    nodes = [{"node": f"n{i}", "kind": "zone", "column": c, "findings": 1, "assets": 1} for i, c in enumerate(columns)]
    return {"nodes": nodes, "edges": []}


def test_two_columns_are_drawn_two_columns_wide() -> None:
    svg = exposure._svg(_graph([1, 3]))
    width = exposure.COL_W + exposure.BOX_W
    assert f"viewBox='0 0 {width} " in svg
    xs = sorted({int(x) for x in re.findall(r"<rect x='(\d+)'", svg)})
    assert xs == [0, exposure.COL_W]  # the zones first, the assets next to them
    assert re.search(r"<text x='0' y='16'[^>]*>Zones<", svg)
    assert re.search(rf"<text x='{exposure.COL_W}' y='16'[^>]*>Assets<", svg)


def test_four_columns_keep_their_width_and_one_column_is_one_box_wide() -> None:
    assert f"viewBox='0 0 {3 * exposure.COL_W + exposure.BOX_W} " in exposure._svg(_graph([0, 1, 2, 3]))
    assert f"viewBox='0 0 {exposure.BOX_W} " in exposure._svg(_graph([2, 2]))


# -- 7. what the documents say ---------------------------------------------------------------------
def test_the_portal_needs_its_registry() -> None:
    doc = (ROOT / "docs/reporting.md").read_text(encoding="utf-8")
    assert "**The images' registry is needed**" in doc and "`registry` block beside it" in doc
    assert "image.pullSecret" in doc and "post-install hook times out" in doc


def test_the_rationale_is_said_in_english_where_it_is() -> None:
    settings = (ROOT / "config/settings.yaml").read_text(encoding="utf-8")
    assert "# English rationale (guarded, template fallback)" in settings
    assert "French rationale" not in settings + (ROOT / "README.md").read_text(encoding="utf-8")


def test_documented_in_the_hld_and_the_layout() -> None:
    hld = (ROOT / "docs/hld/00-product-strategy.md").read_text(encoding="utf-8")
    assert re.search(r"\| v0\.27\.3( \(current\))? \|", hld) and "| v0.27.2 |" in hld
    assert "refuses to start rather than answer from an empty tenant" in hld
    assert "| `deploy/k8s/` |" in (ROOT / "CLAUDE.md").read_text(encoding="utf-8")
    doc = KUBERNETES.read_text(encoding="utf-8")
    assert "`deploy/k8s/check-addresses.sh`" in doc and "ngvm-<tenant>-watch-llm-cache" in doc


def test_release_recorded() -> None:
    assert "## v0.27.3 — " in (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    chart = (ROOT / "deploy/charts/ngvm-tenant/Chart.yaml").read_text()
    assert re.search(r"^version: 0\.(27\.([3-9]|\d\d+)|2[89]\.\d+|[3-9]\d\.\d+)$", chart, re.M)
