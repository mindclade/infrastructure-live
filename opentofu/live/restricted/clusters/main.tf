variable "environment" {
  type = string
  validation {
    condition     = var.environment == "restricted"
    error_message = "This root is bound exclusively to restricted."
  }
}

variable "enabled" {
  type    = bool
  default = false
}
variable "approved_iam_principals" {
  description = "Environment-scoped externally qualified IAM principals used by policy validation."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for principal in var.approved_iam_principals : can(regex("^(serviceAccount|group|principal|principalSet):[^[:space:]]+$", principal))
    ])
    error_message = "Approved IAM principals must be explicit workload, service-account, or group identities."
  }
}
variable "approved_resource_references" {
  description = "Environment-scoped externally qualified project IDs and immutable resource references used by policy validation."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for reference in var.approved_resource_references : length(reference) <= 2048 && can(regex("^[A-Za-z0-9][A-Za-z0-9._:/@+\\[\\]-]*$", reference))
    ])
    error_message = "Approved resource references must be explicit, non-secret, whitespace-free GCP or immutable artifact identifiers."
  }
}
variable "config" {
  type = object({
    project_id                    = optional(string)
    name                          = optional(string)
    region                        = optional(string)
    node_locations                = optional(set(string), [])
    network_id                    = optional(string)
    subnetwork_id                 = optional(string)
    pods_secondary_range_name     = optional(string)
    services_secondary_range_name = optional(string)
    master_ipv4_cidr_block        = optional(string)
    database_encryption_key_name  = optional(string)
    release_channel               = optional(string, "REGULAR")
    resource_labels               = optional(map(string), {})
    workload_accounts = optional(map(object({
      account_id           = string
      display_name         = string
      namespace            = string
      service_account_name = string
      project_roles        = optional(set(string), [])
    })), {})
    node_pools = optional(map(object({
      service_account     = string
      machine_type        = optional(string, "e2-standard-4")
      disk_type           = optional(string, "pd-balanced")
      disk_size_gb        = optional(number, 100)
      min_nodes           = optional(number, 0)
      max_nodes           = optional(number, 3)
      spot                = optional(bool, false)
      accelerator_profile = optional(string)
      accelerator         = optional(object({ type = string, count = number, gpu_driver_version = optional(string, "INSTALLATION_DISABLED") }))
      taints              = optional(list(object({ key = string, value = string, effect = string })), [])
      labels              = optional(map(string), {})
      resource_labels     = optional(map(string), {})
      tags                = optional(set(string), [])
    })), {})
    argocd = optional(object({
      enabled                     = optional(bool, false)
      service_account_id          = optional(string, "argocd-management")
      kubernetes_namespace        = optional(string, "external-secrets")
      kubernetes_service_accounts = optional(set(string), ["external-secrets"])
      secret_references           = optional(set(string), [])
      membership_id               = string
    }))
  })
  default = {}
}

locals {
  environment_catalog = one([
    for environment in yamldecode(file("${path.root}/../../../../catalog/environments.yaml")).environments :
    environment if environment.name == var.environment
  ])
  region_profile = one([
    for profile in yamldecode(file("${path.root}/../../../../catalog/regions.yaml")).regions :
    profile if profile.name == local.environment_catalog.regionProfile
  ])
  accelerator_profiles = {
    for profile in yamldecode(file("${path.root}/../../../../catalog/accelerator-profiles.yaml")).acceleratorProfiles :
    profile.name => profile if contains(local.environment_catalog.acceleratorProfiles, profile.name)
  }
  resource_profile = one([
    for profile in yamldecode(file("${path.root}/../../../../catalog/resource-profiles.yaml")).resourceProfiles :
    profile if profile.name == local.environment_catalog.resourceProfile
  ])
}

module "stack" {
  source               = "../../../stacks/clusters"
  environment          = var.environment
  enabled              = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location     = local.region_profile.primaryLocation
  recovery_location    = local.region_profile.recoveryLocation
  accelerator_profiles = local.accelerator_profiles
  resource_profile     = local.resource_profile
  config               = var.config
}
