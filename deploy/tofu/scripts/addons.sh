#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# What the platform installs in the cluster once RKE2 runs (docs/platform.md §5), from the first
# server: Helm, a default StorageClass, cert-manager and its ClusterIssuer, the CloudNativePG
# operator, the GitLab agent. Called by OpenTofu as `addons.sh <work dir>`, with addons.env:
#   HELM_VERSION, HELM_URL            Helm on the server (https://get.helm.sh)
#   STORAGE                           local-path, rook-ceph or none
#   LOCAL_PATH_URL                    manifest of the local-path provisioner
#   ROOK_VERSION, ROOK_CHART_REPO, ROOK_DEVICE_FILTER   Rook-Ceph on the nodes' extra disks
#   ROOK_FAILURE_DOMAIN               host, or chassis (the label topology.rook.io/chassis: a KVM host)
#   NODES                             how many nodes (mons and replicas: 3 at most)
#   TOLERATE                          taint keys of the nodes, tolerated by Rook-Ceph
#   METALLB, METALLB_ADDRESSES, METALLB_INGRESS_IP, METALLB_CHART_REPO, METALLB_VERSION
#   INGRESS                           ingress-nginx or traefik (RKE2's): its Service on METALLB_INGRESS_IP
#   CERT_MANAGER, CERT_MANAGER_CHART, CERT_MANAGER_VERSION
#   ISSUER                            none, ca or acme: a ClusterIssuer ISSUER_NAME
#   ISSUER_NAME, ACME_EMAIL, ACME_SERVER, INGRESS_CLASS
#   CNPG, CNPG_URL                    the CloudNativePG operator (deploy/cnpg/README.md)
#   AGENT, AGENT_NAME, KAS_ADDRESS, AGENT_CHART_REPO, AGENT_VERSION   the GitLab agent
#   HTTP_PROXY_URL, HTTPS_PROXY_URL, NO_PROXY_LIST
# and in stage/: issuer-ca.crt, issuer-ca.key (ISSUER=ca), agent-token, gitlab-ca.pem.

set -euo pipefail
WORK=${1:?usage: addons.sh <work dir>}
# shellcheck source=lib.sh
. "$WORK/scripts/lib.sh"
load_env "$WORK/addons.env"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || fail "run as root"
proxy_env
export PATH="$PATH:/var/lib/rancher/rke2/bin:/usr/local/bin" KUBECONFIG=/etc/rancher/rke2/rke2.yaml
if [ -n "${HTTP_PROXY_URL:-}" ]; then
  no_proxy="${no_proxy:+$no_proxy,}127.0.0.1,localhost,.svc,.cluster.local"
  export no_proxy NO_PROXY=$no_proxy
fi

k() { run kubectl "$@"; }
# apply_stdin: a manifest on stdin, applied server-side.
apply_stdin() {
  if [ -n "$ROOT" ]; then cat >> "$ROOT/manifests.yaml"; echo --- >> "$ROOT/manifests.yaml"; return 0; fi
  kubectl apply --server-side --force-conflicts -f -
}
# secret_from NAMESPACE NAME KEY=STAGED...: a generic Secret from staged files (never printed).
secret_from() {
  local ns=$1 name=$2 args=() kv
  shift 2
  for kv in "$@"; do args+=("--from-file=${kv%%=*}=$WORK/stage/${kv#*=}"); done
  if [ -n "$ROOT" ]; then printf 'RUN secret %s/%s\n' "$ns" "$name" >> "$ROOT/commands.log"; return 0; fi
  kubectl -n "$ns" create secret generic "$name" "${args[@]}" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
}
namespace() { printf 'apiVersion: v1\nkind: Namespace\nmetadata:\n  name: %s\n' "$1" | apply_stdin > /dev/null; }

log "helm $HELM_VERSION"
if [ -z "$ROOT" ] && ! { command -v helm > /dev/null && helm version --short | grep -q "^$HELM_VERSION"; }; then
  case "$(uname -m)" in x86_64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; *) fail "architecture $(uname -m)" ;; esac
  tmp=$(mktemp -d)
  tgz="helm-$HELM_VERSION-linux-$arch.tar.gz"
  curl -sfL "$HELM_URL/$tgz" -o "$tmp/$tgz"
  curl -sfL "$HELM_URL/$tgz.sha256sum" -o "$tmp/$tgz.sha256sum"
  (cd "$tmp" && sha256sum -c --quiet "$tgz.sha256sum") || fail "helm: checksum mismatch"
  tar -xzf "$tmp/$tgz" -C "$tmp"
  install -m 0755 "$tmp/linux-$arch/helm" /usr/local/bin/helm
  rm -rf "$tmp"
fi

if [ "${STORAGE:-local-path}" = local-path ]; then
  log "storage: local-path provisioner"
  k apply -f "$LOCAL_PATH_URL"
  if [ -z "$ROOT" ] && ! kubectl get storageclass -o jsonpath='{range .items[*]}{.metadata.annotations.storageclass\.kubernetes\.io/is-default-class}{"\n"}{end}' | grep -qx true; then
    kubectl patch storageclass local-path -p '{"metadata":{"annotations":{"storageclass.kubernetes.io/is-default-class":"true"}}}'
  fi
fi

if [ "${STORAGE:-local-path}" = rook-ceph ]; then
  log "storage: Rook-Ceph $ROOK_VERSION"
  n=${NODES:-1}
  [ "$n" -le 3 ] || n=3
  mgr=1
  [ "$n" -lt 2 ] || mgr=2
  tolerations="[]"
  if [ -n "${TOLERATE:-}" ]; then
    tolerations="[$(printf '%s' "$TOLERATE" | awk -F, '{for (i = 1; i <= NF; i++) printf "%s{key: \"%s\", operator: Exists}", (i > 1 ? ", " : ""), $i}')]"
  fi
  cat > "$WORK/rook-operator.yaml" <<ROOK_OPERATOR
csi:
  provisionerTolerations: $tolerations
  pluginTolerations: $tolerations
tolerations: $tolerations
ROOK_OPERATOR
  cat > "$WORK/rook-cluster.yaml" <<ROOK_CLUSTER
operatorNamespace: rook-ceph
toolbox:
  enabled: true
cephClusterSpec:
  mon:
    count: $n
    allowMultiplePerNode: false
  mgr:
    count: $mgr
  dashboard:
    enabled: false
  storage:
    useAllNodes: true
    useAllDevices: false
    deviceFilter: "$ROOK_DEVICE_FILTER"
  placement:
    all:
      tolerations: $tolerations
cephBlockPools:
  - name: ceph-blockpool
    spec:
      failureDomain: ${ROOK_FAILURE_DOMAIN:-host}
      replicated:
        size: $n
    storageClass:
      enabled: true
      name: ceph-block
      isDefault: true
      reclaimPolicy: Delete
      allowVolumeExpansion: true
      volumeBindingMode: Immediate
      parameters:
        imageFormat: "2"
        imageFeatures: layering
        csi.storage.k8s.io/provisioner-secret-name: rook-csi-rbd-provisioner
        csi.storage.k8s.io/provisioner-secret-namespace: rook-ceph
        csi.storage.k8s.io/controller-expand-secret-name: rook-csi-rbd-provisioner
        csi.storage.k8s.io/controller-expand-secret-namespace: rook-ceph
        csi.storage.k8s.io/node-stage-secret-name: rook-csi-rbd-node
        csi.storage.k8s.io/node-stage-secret-namespace: rook-ceph
        csi.storage.k8s.io/fstype: ext4
cephFileSystems: []
cephObjectStores: []
ROOK_CLUSTER
  run helm repo add rook-release "$ROOK_CHART_REPO" --force-update > /dev/null
  run helm upgrade --install rook-ceph rook-release/rook-ceph --version "$ROOK_VERSION" -n rook-ceph --create-namespace \
    -f "$WORK/rook-operator.yaml" --wait --timeout 15m
  run helm upgrade --install rook-ceph-cluster rook-release/rook-ceph-cluster --version "$ROOK_VERSION" -n rook-ceph \
    -f "$WORK/rook-cluster.yaml" --timeout 15m
  if [ -z "$ROOT" ]; then
    log "waiting for the Ceph cluster (30 minutes at most)"
    kubectl -n rook-ceph wait cephcluster/rook-ceph --for=jsonpath='{.status.phase}'=Ready --timeout 30m
    kubectl -n rook-ceph get cephcluster rook-ceph -o jsonpath='{.status.ceph.health}{"\n"}'
  fi
fi

if [ "${METALLB:-false}" = true ]; then
  log "MetalLB, the ingress on $METALLB_INGRESS_IP"
  run helm repo add metallb "$METALLB_CHART_REPO" --force-update > /dev/null
  mversion=()
  [ -z "${METALLB_VERSION:-}" ] || mversion=(--version "$METALLB_VERSION")
  run helm upgrade --install metallb metallb/metallb -n metallb-system --create-namespace "${mversion[@]}" --wait --timeout 10m
  addresses=$(printf '%s' "$METALLB_ADDRESSES" | awk -F, '{for (i = 1; i <= NF; i++) printf "    - %s\n", $i}')
  pool="apiVersion: metallb.io/v1beta1
kind: IPAddressPool
metadata:
  name: ngvm
  namespace: metallb-system
spec:
  addresses:
$addresses
---
apiVersion: metallb.io/v1beta1
kind: L2Advertisement
metadata:
  name: ngvm
  namespace: metallb-system
spec:
  ipAddressPools: [ngvm]"
  applied=false
  for _ in $(seq 12); do
    if printf '%s\n' "$pool" | apply_stdin > /dev/null; then applied=true; break; fi
    sleep 10
  done
  [ "$applied" = true ] || fail "MetalLB: the address pool was refused (its webhook not ready?)"
  if [ "${INGRESS:-ingress-nginx}" = traefik ]; then
    chart=rke2-traefik
    values="    service:
      enabled: true
      type: LoadBalancer
      annotations:
        metallb.io/loadBalancerIPs: $METALLB_INGRESS_IP
      spec:
        externalTrafficPolicy: Local"
  else
    chart=rke2-ingress-nginx
    values="    controller:
      service:
        enabled: true
        type: LoadBalancer
        annotations:
          metallb.io/loadBalancerIPs: $METALLB_INGRESS_IP
        externalTrafficPolicy: Local"
  fi
  printf 'apiVersion: helm.cattle.io/v1\nkind: HelmChartConfig\nmetadata:\n  name: %s\n  namespace: kube-system\nspec:\n  valuesContent: |-\n%s\n' \
    "$chart" "$values" | apply_stdin > /dev/null
fi

if [ "${CERT_MANAGER:-true}" = true ]; then
  log "cert-manager $CERT_MANAGER_VERSION"
  run helm upgrade --install cert-manager "$CERT_MANAGER_CHART" --version "$CERT_MANAGER_VERSION" \
    -n cert-manager --create-namespace --set crds.enabled=true --wait --timeout 10m
  case "${ISSUER:-none}" in
    ca)
      if [ ! -s "$WORK/stage/issuer-ca.crt" ] || [ ! -s "$WORK/stage/issuer-ca.key" ]; then
        fail "ISSUER=ca: stage issuer-ca.crt and issuer-ca.key"
      fi
      if [ -z "$ROOT" ]; then
        kubectl -n cert-manager create secret tls "$ISSUER_NAME-ca" --cert="$WORK/stage/issuer-ca.crt" \
          --key="$WORK/stage/issuer-ca.key" --dry-run=client -o yaml | kubectl apply -f - > /dev/null
      fi
      apply_stdin <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: $ISSUER_NAME
spec:
  ca:
    secretName: $ISSUER_NAME-ca
EOF
      ;;
    acme)
      apply_stdin <<EOF
apiVersion: cert-manager.io/v1
kind: ClusterIssuer
metadata:
  name: $ISSUER_NAME
spec:
  acme:
    email: $ACME_EMAIL
    server: $ACME_SERVER
    privateKeySecretRef:
      name: $ISSUER_NAME-account
    solvers:
      - http01:
          ingress:
            ingressClassName: $INGRESS_CLASS
EOF
      ;;
    none) ;;
    *) fail "ISSUER: none, ca or acme" ;;
  esac
fi

if [ "${CNPG:-true}" = true ]; then
  log "CloudNativePG operator"
  k apply --server-side --force-conflicts -f "$CNPG_URL"
  k rollout status deployment -n cnpg-system cnpg-controller-manager --timeout 10m
fi

if [ "${AGENT:-false}" = true ]; then
  log "GitLab agent $AGENT_NAME"
  [ -s "$WORK/stage/agent-token" ] || fail "AGENT=true: stage agent-token (the agent's token)"
  ns="gitlab-agent-$AGENT_NAME"
  namespace "$ns"
  secret_from "$ns" gitlab-agent-token token=agent-token
  {
    printf 'config:\n  kasAddress: "%s"\n  secretName: gitlab-agent-token\n' "$KAS_ADDRESS"
    if [ -s "$WORK/stage/gitlab-ca.pem" ]; then
      echo "  caCert: |"
      sed 's/^/    /' "$WORK/stage/gitlab-ca.pem"
    fi
    if [ -n "${HTTP_PROXY_URL:-}" ]; then
      printf 'extraEnv:\n  - {name: HTTPS_PROXY, value: "%s"}\n  - {name: NO_PROXY, value: "%s"}\n' \
        "${HTTPS_PROXY_URL:-$HTTP_PROXY_URL}" "$NO_PROXY"
    fi
  } > "$WORK/agent-values.yaml"
  run helm repo add gitlab "$AGENT_CHART_REPO" --force-update > /dev/null
  version=()
  [ -z "${AGENT_VERSION:-}" ] || version=(--version "$AGENT_VERSION")
  run helm upgrade --install "$AGENT_NAME" gitlab/gitlab-agent -n "$ns" "${version[@]}" \
    -f "$WORK/agent-values.yaml" --wait --timeout 10m
fi
log "addons done"
