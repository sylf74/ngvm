# SPDX-License-Identifier: LicenseRef-ngvm-proprietary
# OpenTofu (or Terraform 1.6 and later): the KVM hosts are reached by SSH, no provider.
terraform {
  required_version = ">= 1.6"
  # The state in GitLab (docs/platform.md §2).
  backend "http" {}
}
