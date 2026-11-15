# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
variable "hypervisors" {
  description = "The KVM hosts (libvirt), by name, reached by SSH as root or with passwordless sudo. pool_dir: where the VMs' disks go. network: ovs:<bridge> (Open vSwitch), bridge:<bridge> or network:<libvirt network>."
  type = map(object({
    address  = string
    user     = optional(string, "root")
    port     = optional(number, 22)
    pool_dir = optional(string, "/var/lib/libvirt/images")
    network  = optional(string, "network:default")
  }))
  validation {
    condition     = alltrue([for h in var.hypervisors : can(regex("^(ovs|bridge|network):[A-Za-z0-9_.-]+$", h.network))])
    error_message = "hypervisors: network is ovs:<bridge>, bridge:<bridge> or network:<name>."
  }
}

variable "machines" {
  description = "The VMs, by name (the libvirt domain and the host name), on one hypervisor each, with their roles (as modules/platform hosts). address: static, with its prefix (192.0.2.41/24). data_disks: extra disks for Rook-Ceph, a size in GB (a qcow2 in pool_dir) or a block device of the host. cpuset: host CPUs of the vCPUs. taints, labels: of the Kubernetes node."
  type = map(object({
    hypervisor = string
    roles      = list(string)
    address    = string
    os         = optional(string, "rocky")
    vcpu       = optional(number, 2)
    memory_mb  = optional(number, 4096)
    disk_gb    = optional(number, 40)
    cpuset     = optional(string, "")
    data_disks = optional(list(object({
      size_gb = optional(number, 0)
      device  = optional(string, "")
    })), [])
    taints = optional(list(string), [])
    labels = optional(list(string), [])
  }))
  validation {
    condition = alltrue([for n, m in var.machines : (
      can(regex("^[a-z0-9][a-z0-9-]{0,62}$", n)) && contains(["ubuntu", "rocky"], m.os) && can(cidrhost(m.address, 0)) && m.disk_gb >= 20 &&
      alltrue([for d in m.data_disks : (d.size_gb > 0) != (d.device != "")])
    )])
    error_message = "machines: names in lower-case letters, digits and dashes; os ubuntu or rocky; address with its prefix (192.0.2.41/24); disk_gb 20 or more; each data disk a size_gb or a device."
  }
}

variable "images" {
  description = "Cloud image per os (qcow2), downloaded once on each KVM host. Rocky Linux 10 needs x86-64-v3 (AVX2): on an older CPU, ubuntu."
  type        = map(string)
  default = {
    ubuntu = "https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img"
    rocky  = "https://dl.rockylinux.org/pub/rocky/10/images/x86_64/Rocky-10-GenericCloud-Base.latest.x86_64.qcow2"
  }
}

variable "gateway" {
  description = "Default gateway of the VMs."
  type        = string
}

variable "dns" {
  description = "DNS servers of the VMs."
  type        = list(string)
}

variable "search_domains" {
  description = "DNS search domains of the VMs."
  type        = list(string)
  default     = []
}

variable "admin_user" {
  description = "The administrator of the VMs (passwordless sudo)."
  type        = string
  default     = "ngvm"
}

variable "ssh_public_key_file" {
  description = "Public key of the administrator (its private key in platform.ssh.private_key_file, or in the SSH agent; the same key reaches the KVM hosts)."
  type        = string
  default     = "~/.ssh/id_ed25519.pub"
}

variable "platform" {
  description = "The rest of the platform, as the variables of modules/platform except hosts."
  type        = any
  default     = {}
}
