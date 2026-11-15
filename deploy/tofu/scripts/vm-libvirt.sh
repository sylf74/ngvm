#!/bin/bash
# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# A VM on a KVM host with libvirt (docs/platform.md §8), made with virt-install from a cloud image
# and cloud-init. Called by OpenTofu on the KVM host as `vm-libvirt.sh <work dir>`, with vm.env:
#   NAME          the VM (libvirt domain)
#   VCPU, MEMORY_MB, DISK_GB
#   CPUSET        host CPUs the vCPUs run on (e.g. 0-7: the P-cores of a hybrid CPU), or empty
#   IMAGE_URL     cloud image (qcow2), downloaded once into POOL_DIR/ngvm-images
#   POOL_DIR      where the disks of the VMs are (e.g. /mnt/virt)
#   NETWORK       ovs:<bridge> (Open vSwitch), bridge:<bridge> (Linux bridge) or network:<name>
#   DATA_DISKS    extra disks, ';'-separated: <size in GB> (a qcow2 in POOL_DIR) or dev:<path>
#                 (a block device of the host, e.g. /dev/disk/by-id/…): for Rook-Ceph
#   OSINFO        virt-install --osinfo (linux2022 by default; generic when unknown)
#   HTTP_PROXY_URL, HTTPS_PROXY_URL, NO_PROXY_LIST
# and user-data, network-config (cloud-init) in the work dir. A VM that exists is left as it is;
# a domain of that name not made by NGVM stops the step.
#   vm-libvirt.sh <work dir> destroy: the VM and the disks this script made, removed.

set -euo pipefail
WORK=${1:?usage: vm-libvirt.sh <work dir> [destroy]}
ACTION=${2:-create}
# shellcheck source=lib.sh
. "$WORK/scripts/lib.sh"
load_env "$WORK/vm.env"
[ -n "$ROOT" ] || [ "$(id -u)" -eq 0 ] || fail "run as root"
[[ "$NAME" =~ ^[a-z0-9][a-z0-9-]{0,62}$ ]] || fail "not a VM name: $NAME"
MARK="ngvm:$NAME"

# virsh_ ARGS...: virsh on the local hypervisor (printed in tests).
virsh_() {
  if [ -n "$ROOT" ]; then printf 'RUN virsh %s\n' "$*" >> "$ROOT/commands.log"; return 1; fi
  virsh -c qemu:///system "$@"
}
exists() { virsh_ dominfo "$NAME" > /dev/null 2>&1; }
ours() { virsh_ desc "$NAME" 2>/dev/null | grep -qx "$MARK"; }

if [ "$ACTION" = destroy ]; then
  if exists; then
    ours || fail "domain $NAME was not made by NGVM: left as it is"
    log "VM $NAME removed"
    virsh_ destroy "$NAME" > /dev/null 2>&1 || true
    virsh_ undefine "$NAME" --nvram > /dev/null 2>&1 || virsh_ undefine "$NAME" > /dev/null
  fi
  run rm -f "$POOL_DIR/$NAME.qcow2" "$POOL_DIR/$NAME"-data*.qcow2
  exit 0
fi

if exists; then
  ours || fail "a domain $NAME exists and was not made by NGVM: remove it first (virsh undefine $NAME)"
  log "VM $NAME exists: left as it is"
  exit 0
fi

proxy_env
if [ "$(os_family)" = debian ]; then install_packages virtinst qemu-utils curl; else install_packages virt-install qemu-img curl; fi
[ -d "$ROOT$POOL_DIR" ] || fail "no folder $POOL_DIR on this host"

log "image $IMAGE_URL"
images=$POOL_DIR/ngvm-images
install -d -m 0755 "$ROOT$images"
base=$images/$(basename "${IMAGE_URL%%\?*}")
if [ ! -s "$ROOT$base" ]; then
  if [ -n "$ROOT" ]; then
    printf 'RUN download %s\n' "$IMAGE_URL" >> "$ROOT/commands.log"
  else
    curl -fL --retry 3 -o "$base.part" "$IMAGE_URL"
    mv -f "$base.part" "$base"
  fi
fi

log "disks of $NAME in $POOL_DIR"
disk=$POOL_DIR/$NAME.qcow2
[ ! -e "$ROOT$disk" ] || fail "$disk exists: remove it, or the VM it belonged to"
run qemu-img convert -O qcow2 "$base" "$disk"
run qemu-img resize -q "$disk" "${DISK_GB}G"
disks=(--disk "path=$disk,format=qcow2,bus=virtio")
i=0
IFS=';' read -ra extra <<< "${DATA_DISKS:-}"
for d in "${extra[@]}"; do
  [ -n "$d" ] || continue
  i=$((i + 1))
  case "$d" in
    dev:*)
      dev=${d#dev:}
      [ -n "$ROOT" ] || [ -b "$dev" ] || fail "not a block device: $dev"
      disks+=(--disk "path=$dev,format=raw,bus=virtio,cache=none") ;;
    *[!0-9]*) fail "DATA_DISKS: a size in GB or dev:<path>, not $d" ;;
    *)
      f=$POOL_DIR/$NAME-data$i.qcow2
      [ ! -e "$ROOT$f" ] || fail "$f exists"
      run qemu-img create -q -f qcow2 "$f" "${d}G"
      disks+=(--disk "path=$f,format=qcow2,bus=virtio") ;;
  esac
done

case "$NETWORK" in
  ovs:*) net="bridge=${NETWORK#ovs:},virtualport_type=openvswitch,model=virtio" ;;
  bridge:*) net="bridge=${NETWORK#bridge:},model=virtio" ;;
  network:*) net="network=${NETWORK#network:},model=virtio" ;;
  *) fail "NETWORK: ovs:<bridge>, bridge:<bridge> or network:<name>" ;;
esac
vcpus=$VCPU
[ -z "${CPUSET:-}" ] || vcpus="$VCPU,cpuset=$CPUSET"
osinfo=${OSINFO:-linux2022}
if [ -z "$ROOT" ] && command -v osinfo-query > /dev/null && ! osinfo-query os "short-id=$osinfo" 2>/dev/null | grep -q "$osinfo"; then
  osinfo=generic
fi

log "VM $NAME: $VCPU vCPU, $MEMORY_MB MB, $NETWORK"
run virt-install --name "$NAME" --metadata "description=$MARK" --memory "$MEMORY_MB" --vcpus "$vcpus" \
  --cpu host-passthrough --osinfo "$osinfo" --import "${disks[@]}" --network "$net" \
  --cloud-init "user-data=$WORK/user-data,network-config=$WORK/network-config" \
  --graphics none --console pty,target_type=serial --autostart --noautoconsole
log "VM $NAME started"
