#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# Checks of deploy/tofu without any machine (CI job `tofu`, tests/test_v0250.py):
#   - the files formatted (tofu fmt) and the scripts clean (bash -n, shellcheck when present);
#   - every root valid (tofu validate), or only those without a provider with --offline;
#   - the plans of existing/ and libvirt/terraform.tfvars.example, their files replaced by placeholders.
# Usage: deploy/tofu/check.sh [--offline]   (TOFU: the command, tofu by default)

set -euo pipefail
OFFLINE=false
[ "${1:-}" != --offline ] || OFFLINE=true
TOFU=${TOFU:-tofu}
HERE=$(cd "$(dirname "$0")" && pwd)
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT

echo "== fmt"
"$TOFU" fmt -check -recursive "$HERE"
for f in "$HERE"/*/terraform.tfvars.example; do
  cp "$f" "$TMP/example.tfvars"
  "$TOFU" fmt -check "$TMP/example.tfvars" > /dev/null || { echo "not formatted: $f" >&2; exit 1; }
done

echo "== scripts"
for f in "$HERE"/scripts/*.sh "$HERE"/check.sh; do bash -n "$f"; done
if command -v shellcheck > /dev/null; then shellcheck -x -P "$HERE/scripts" "$HERE"/scripts/*.sh "$HERE/check.sh"; fi

echo "== validate"
roots=(modules/platform existing libvirt)
[ "$OFFLINE" = true ] || roots+=(scaleway azure)
for r in "${roots[@]}"; do
  TF_DATA_DIR="$TMP/data-${r//\//-}" "$TOFU" -chdir="$HERE/$r" init -backend=false -input=false > "$TMP/init.log" 2>&1 \
    || { cat "$TMP/init.log"; exit 1; }
  TF_DATA_DIR="$TMP/data-${r//\//-}" "$TOFU" -chdir="$HERE/$r" validate -no-color > /dev/null
  echo "$r: valid"
done

mkdir -p "$TMP/tree/deploy" "$TMP/home"
cp -r "$HERE" "$TMP/tree/deploy/tofu"
cp -r "$HERE/../charts" "$TMP/tree/deploy/charts"
rm -rf "$TMP/tree/deploy/tofu/"*/.terraform "$TMP/tree/deploy/tofu/modules/"*/.terraform
for r in existing libvirt; do
  echo "== plan of $r/terraform.tfvars.example"
  root=$TMP/tree/deploy/tofu/$r
  cp "$root/terraform.tfvars.example" "$root/terraform.tfvars"
  printf 'terraform {\n  backend "local" {}\n}\n' > "$root/backend_override.tf"
  # shellcheck disable=SC2088 # the paths as written in a tfvars, expanded below
  for f in $(grep -o '"~/[^"]*"' "$root/terraform.tfvars" | tr -d '"' | sort -u) "~/.ssh/id_ed25519.pub"; do
    p="$TMP/home/${f#\~/}"
    mkdir -p "$(dirname "$p")"
    [ -e "$p" ] || echo placeholder > "$p"
  done
  HOME="$TMP/home" TF_DATA_DIR="$TMP/data-plan-$r" "$TOFU" -chdir="$root" init -input=false > "$TMP/init.log" 2>&1 \
    || { cat "$TMP/init.log"; exit 1; }
  HOME="$TMP/home" TF_DATA_DIR="$TMP/data-plan-$r" "$TOFU" -chdir="$root" plan -input=false -no-color -out="$TMP/plan-$r" > "$TMP/plan.log" \
    || { cat "$TMP/plan.log"; exit 1; }
  grep -E '^Plan:' "$TMP/plan.log"
  HOME="$TMP/home" TF_DATA_DIR="$TMP/data-plan-$r" "$TOFU" -chdir="$root" show -json "$TMP/plan-$r" > "${PLAN_JSON:-$TMP/plan}-$r.json"
done
echo "deploy/tofu: checks passed"
