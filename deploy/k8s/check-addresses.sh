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
# where <ns> is a namespace of the cluster; `<a>.<b>` where <b> has a dash (no top-level domain has
# one) and is no namespace stops the job too (v0.29.0); any other host is outside (left alone). Only variable
# names, Services and namespaces are printed, never a value (a connection string holds a password).
# Exit 1 when a Service is missing; a check kubectl may not make (forbidden) is a warning.
# NGVM_DEPLOY_NAMESPACE (v0.28.2): the namespace this job deploys. With NGVM_INTEL_SERVE true, the
# shared service's own `<release>-intel` there is created by this deployment: the first deployment of
# the tenant that serves it was refused for the Service it was about to create.

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

# namespace_like LABEL: a label no top-level domain can be (a dash, not an IDN's xn--).
namespace_like() {
  case "$1" in
    xn--*) return 1 ;;
    *-*) return 0 ;;
    *) return 1 ;;
  esac
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
      if nsout=$(kubectl get namespace "$second" 2>&1); then
        svc=$first; ns=$second
      elif printf '%s' "$nsout" | grep -q 'NotFound' && namespace_like "$second"; then
        # v0.29.0: `<svc>.<ns>` of a namespace that no longer exists was taken for a host outside the
        # cluster: NGVM_REPORTING_DSN_K8S still named the portal's former namespace, and publish
        # refused six runs in a row. A second label with a dash is no top-level domain: a namespace.
        echo "ERROR $name points at $first.$second: there is no namespace $second in this cluster:" \
          "correct the variable (kubectl get namespaces lists them)" >&2
        failed=1
        return 0
      else
        return 0
      fi
      ;;
    *) return 0 ;;
  esac
  case "$ns" in
    *.*|"") return 0 ;;
  esac
  if [ "$name" = NGVM_INTEL_URL ] && [ "${NGVM_INTEL_SERVE:-}" = true ] \
    && [ "$ns" = "${NGVM_DEPLOY_NAMESPACE:-}" ] && [ "${svc%-intel}" != "$svc" ]; then
    echo "OK    $name: service $svc in namespace $ns, deployed by this job (NGVM_INTEL_SERVE)"
    return 0
  fi
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
