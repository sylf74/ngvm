#!/bin/sh
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# Called by the job deploy-k8s before it changes anything (v0.27.3): every address the tenant gives
# its pods that names a Service of this cluster must name one that exists. An address to a missing
# Service deployed fine and failed in every pod, every passage, without the deployment saying so.
#
# Usage: check-addresses.sh, with the variables below in the environment and kubectl's context set.
#   NGVM_INTEL_URL, NGVM_RELAY_URL       one URL each
#   NGVM_LLM_BASE_URL                    one URL or several, comma-separated
#   NGVM_REPORTING_DSN, _DSN_<NAME>      postgresql:// URIs or key=value strings (or File variables)
# A host names a Service of the cluster when it is `<svc>.<ns>.svc[.cluster.local]`, or `<svc>.<ns>`
# where <ns> is a namespace of the cluster; any other host is outside (left alone). Only variable
# names, Services and namespaces are printed, never a value (a connection string holds a password).
# Exit 1 when a Service is missing; a check kubectl may not make (forbidden) is a warning.

set -u
failed=0

# host_of VALUE: the host of a URL, a postgresql:// URI or a libpq key=value string ("" if none).
host_of() {
  v=$1
  case "$v" in
    *://*)
      v=${v#*://}
      v=${v%%[/?#]*}
      v=${v##*@}
      case "$v" in
        \[*) v="" ;;
        *) v=${v%%:*} ;;
      esac
      ;;
    *host=*)
      v=$(printf ' %s\n' "$v" | sed -n 's/.*[[:space:]]host=\([^[:space:]]*\).*/\1/p' | head -n 1)
      ;;
    *) v="" ;;
  esac
  printf '%s' "$v" | tr '[:upper:]' '[:lower:]'
}

# check NAME VALUE: the Service a value names, if any, must exist.
check() {
  name=$1
  host=$(host_of "$2")
  host=${host%.}
  [ -n "$host" ] || return 0
  svc=""; ns=""
  case "$host" in
    *.*.svc|*.*.svc.cluster.local)
      rest=${host%.svc*}
      svc=${rest%%.*}; ns=${rest#*.}
      ;;
    *.*)
      first=${host%%.*}; second=${host#*.}
      case "$second" in
        *.*) return 0 ;;
      esac
      if kubectl get namespace "$second" > /dev/null 2>&1; then svc=$first; ns=$second; else return 0; fi
      ;;
    *) return 0 ;;
  esac
  case "$ns" in
    *.*|"") return 0 ;;
  esac
  if out=$(kubectl -n "$ns" get service "$svc" -o name 2>&1); then
    echo "OK    $name: service $svc in namespace $ns"
  elif printf '%s' "$out" | grep -q 'NotFound'; then
    echo "ERROR $name points at the service $svc in the namespace $ns, which does not exist: correct the variable" \
      "(kubectl -n $ns get services lists those there)" >&2
    failed=1
  else
    echo "WARN  $name: cannot check the service $svc in $ns from this job ($(printf '%s' "$out" | head -n 1 | cut -c1-120))"
  fi
}

# value NAME: the variable's value, or the content of the file it names (File variable).
value() {
  eval "v=\${$1:-}"
  if [ -n "$v" ] && [ -f "$v" ]; then v=$(cat "$v"); fi
  printf '%s' "$v"
}

for name in NGVM_INTEL_URL NGVM_RELAY_URL; do
  check "$name" "$(value "$name")"
done
old_ifs=$IFS; IFS=','
for url in $(value NGVM_LLM_BASE_URL); do
  IFS=$old_ifs
  check NGVM_LLM_BASE_URL "$(printf '%s' "$url" | tr -d ' ')"
done
IFS=$old_ifs
for name in NGVM_REPORTING_DSN $(env | sed -n 's/^\(NGVM_REPORTING_DSN_[A-Z0-9_]*\)=.*/\1/p' | sort -u); do
  check "$name" "$(value "$name")"
done
exit "$failed"
