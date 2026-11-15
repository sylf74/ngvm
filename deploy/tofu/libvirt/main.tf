# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# VMs on KVM hosts with libvirt, made over SSH with virt-install (scripts/vm-libvirt.sh), then the
# platform on them (docs/platform.md §8). Several hosts, Open vSwitch or Linux bridges, static
# addresses by cloud-init, extra disks for Rook-Ceph. A VM is made once: a change of its size is
# not applied to it; removing it from `machines` removes it and its disks.

locals {
  scripts = "${path.module}/../scripts"
  key     = try(var.platform.ssh.private_key_file, "") == "" ? "" : pathexpand(var.platform.ssh.private_key_file)
  proxy = {
    HTTP_PROXY_URL  = try(var.platform.network.http_proxy, "")
    HTTPS_PROXY_URL = try(var.platform.network.https_proxy, "")
    NO_PROXY_LIST   = join(",", try(var.platform.network.no_proxy, []))
  }
  vm_env = {
    for n, m in var.machines : n => merge(local.proxy, {
      NAME       = n
      VCPU       = tostring(m.vcpu)
      MEMORY_MB  = tostring(m.memory_mb)
      DISK_GB    = tostring(m.disk_gb)
      CPUSET     = m.cpuset
      IMAGE_URL  = var.images[m.os]
      POOL_DIR   = var.hypervisors[m.hypervisor].pool_dir
      NETWORK    = var.hypervisors[m.hypervisor].network
      DATA_DISKS = join(";", [for d in m.data_disks : d.device != "" ? "dev:${d.device}" : tostring(d.size_gb)])
      OSINFO     = "linux2022"
    })
  }
}

check "hypervisors_of_machines" {
  assert {
    condition     = alltrue([for m in var.machines : contains(keys(var.hypervisors), m.hypervisor)])
    error_message = "machines: each hypervisor must be one of var.hypervisors."
  }
}

resource "terraform_data" "vm" {
  for_each = var.machines
  # what makes the VM again (and so loses its disks): its host, its system; not its size
  triggers_replace = {
    hypervisor = each.value.hypervisor
    os         = each.value.os
    address    = each.value.address
  }
  # what the removal needs (a destroy step reads only this)
  input = {
    host    = var.hypervisors[each.value.hypervisor].address
    user    = var.hypervisors[each.value.hypervisor].user
    port    = var.hypervisors[each.value.hypervisor].port
    key     = local.key
    work    = "/tmp/ngvm-tofu-vm-${each.key}"
    scripts = local.scripts
    env     = join("", [for k, v in local.vm_env[each.key] : "${k}='${replace(v, "'", "'\\''")}'\n"])
  }

  connection {
    type        = "ssh"
    host        = self.input.host
    user        = self.input.user
    port        = self.input.port
    private_key = self.input.key == "" ? null : file(self.input.key)
    agent       = self.input.key == ""
    timeout     = "5m"
  }

  provisioner "remote-exec" {
    inline = ["rm -rf ${self.input.work} && mkdir -m 700 ${self.input.work}"]
  }
  provisioner "file" {
    source      = self.input.scripts
    destination = self.input.work
  }
  provisioner "file" {
    content     = self.input.env
    destination = "${self.input.work}/vm.env"
  }
  provisioner "file" {
    content = templatefile("${path.module}/user-data.yaml.tftpl", {
      hostname   = each.key
      user       = var.admin_user
      public_key = trimspace(file(pathexpand(var.ssh_public_key_file)))
    })
    destination = "${self.input.work}/user-data"
  }
  provisioner "file" {
    content = templatefile("${path.module}/network-config.yaml.tftpl", {
      address = each.value.address
      gateway = var.gateway
      dns     = var.dns
      search  = var.search_domains
    })
    destination = "${self.input.work}/network-config"
  }
  provisioner "remote-exec" {
    inline = ["W=${self.input.work}; if [ \"$(id -u)\" -eq 0 ]; then S=; else S='sudo -n'; fi; $S bash $W/scripts/vm-libvirt.sh $W; rc=$?; $S rm -rf $W; exit $rc"]
  }

  provisioner "remote-exec" {
    when   = destroy
    inline = ["rm -rf ${self.input.work} && mkdir -m 700 ${self.input.work}"]
  }
  provisioner "file" {
    when        = destroy
    source      = self.input.scripts
    destination = self.input.work
  }
  provisioner "file" {
    when        = destroy
    content     = self.input.env
    destination = "${self.input.work}/vm.env"
  }
  provisioner "remote-exec" {
    when   = destroy
    inline = ["W=${self.input.work}; if [ \"$(id -u)\" -eq 0 ]; then S=; else S='sudo -n'; fi; $S bash $W/scripts/vm-libvirt.sh $W destroy; rc=$?; $S rm -rf $W; exit $rc"]
  }
}

locals {
  hosts = {
    for n, m in var.machines : n => {
      address       = split("/", m.address)[0]
      user          = var.admin_user
      roles         = m.roles
      physical_host = m.hypervisor
      taints        = m.taints
      labels        = m.labels
    }
  }
}

module "platform" {
  source     = "../modules/platform"
  depends_on = [terraform_data.vm]

  hosts       = local.hosts
  ssh         = try(var.platform.ssh, {})
  network     = try(var.platform.network, {})
  cluster     = try(var.platform.cluster, null)
  addons      = try(var.platform.addons, {})
  portal      = try(var.platform.portal, {})
  registry    = try(var.platform.registry, {})
  collectors  = try(var.platform.collectors, {})
  keycloak    = try(var.platform.keycloak, {})
  secrets_dir = try(var.platform.secrets_dir, "~/.ngvm/secrets")
  revision    = try(var.platform.revision, "1")
}
