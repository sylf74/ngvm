# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
"""`ngvm validate client.yaml ...`: check client profiles against their schema, and the client
project's pipeline file: the template included and the code fetched must be the same version.
`ngvm db check` / `ngvm db repair` (v0.27.3): the tenant isolation of the tenant's database, read
from NGVM_DB_DSN_FILE or NGVM_DB_DSN as the services read it (docs/kubernetes.md §5.1)."""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

import yaml

from .config import env
from .profile import ProfileError, load_profile


class _CiLoader(yaml.SafeLoader):
    """Reads .gitlab-ci.yml whatever GitLab tags it uses (!reference …)."""


_CiLoader.add_multi_constructor("!", lambda loader, suffix, node: None)


def check_ci(path: str | Path, environ=None) -> list[str]:
    """Problems of the pipeline file: the include `ref:` of the NGVM project must equal NGVM_REF."""
    environ = os.environ if environ is None else environ
    data = yaml.load(Path(path).read_text(encoding="utf-8"), Loader=_CiLoader) or {}
    project = env("PROJECT", "vulnops/ngvm", environ=environ)
    includes = data.get("include") or []
    includes = [includes] if isinstance(includes, dict) else includes
    refs = [i.get("ref") for i in includes if isinstance(i, dict) and i.get("project") == project]
    if not refs:
        return []  # not a client project of this NGVM (or the template included otherwise)
    variables = data.get("variables") or {}
    declared = variables.get("NGVM_REF") or variables.get("A2VM_REF")
    if isinstance(declared, dict):
        declared = declared.get("value")
    running = env("REF", "", environ=environ) or declared
    problems = []
    for ref in refs:
        if ref is None:
            problems.append(f"{path}: include of {project} without `ref:` (the default branch moves under you)")
        elif running and str(ref) != str(running):
            problems.append(
                f"{path}: include ref {ref} but NGVM_REF {running}: the pipeline template and the code "
                "would come from two versions; set both to the same tag"
            )
    return problems


def db_command(action: str, print_sql: bool = False) -> int:
    """`ngvm db check|repair`: the isolation of every NGVM schema present in the database."""
    from .db import SCHEMAS, Database, DatabaseError, dsn_from_env, isolation_problems, repair_sql

    if action == "repair" and print_sql:
        print(repair_sql(), end="")
        return 0
    try:
        dsn = dsn_from_env()
        if not dsn:
            print("no database: set NGVM_DB_DSN_FILE (or NGVM_DB_DSN), as for the services", file=sys.stderr)
            return 2
        db = Database(dsn, "ngvm-db", [], size=1)
        if action == "repair":
            changes = db.repair_isolation()
            for line in changes:
                print(f"FIXED {line}")
            if not changes:
                print("OK    nothing to repair")
        failed = 0
        with db.tx("") as conn:
            present = [s for s in SCHEMAS if conn.execute("SELECT to_regnamespace(%s)", (s,)).fetchone()[0]]
            for schema in present:
                problems = isolation_problems(conn, schema)
                failed += len(problems)
                for p in problems:
                    print(f"FAIL  {p}", file=sys.stderr)
                if not problems:
                    print(f"OK    {schema}: every table kept to one tenant ({db.describe()})")
        db.close()
    except DatabaseError as exc:
        print(exc, file=sys.stderr)
        return 2
    if not present:
        print("OK    no NGVM schema in this database yet")
    return 1 if failed else 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="ngvm", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    v = sub.add_parser("validate", help="validate client profiles against the schema")
    v.add_argument("profiles", nargs="+")
    v.add_argument("--ci", default=".gitlab-ci.yml", help="client project pipeline file, checked when present")
    d = sub.add_parser("db", help="the tenant isolation of the tenant's database (check, or repair it)")
    d.add_argument("action", choices=["check", "repair"])
    d.add_argument("--sql", action="store_true", help="repair: print the SQL instead of running it (psql)")
    args = parser.parse_args(argv)
    if args.command == "db":
        return db_command(args.action, args.sql)

    failed = 0
    if args.ci and Path(args.ci).exists():
        try:
            problems = check_ci(args.ci)
        except yaml.YAMLError as exc:
            problems = [f"{args.ci}: not readable YAML: {exc}"]
        for p in problems:
            failed += 1
            print(f"FAIL  {p}", file=sys.stderr)
        if not problems:
            print(f"OK    {args.ci} (NGVM include ref and NGVM_REF agree)")
    for path in args.profiles:
        try:
            profile = load_profile(path)
            print(f"OK    {path} ({profile.id}, {len(profile.assets)} assets)")
            if profile.external:
                print(
                    f"      external scan: {profile.external.client} (max {profile.external.max_age_days} days), "
                    f"{len(profile.published)} published endpoint(s)"
                )
            for warning in profile.warnings:
                print(f"WARN  {path}: {warning}")
        except (ProfileError, OSError) as exc:
            failed += 1
            print(f"FAIL  {exc}", file=sys.stderr)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
