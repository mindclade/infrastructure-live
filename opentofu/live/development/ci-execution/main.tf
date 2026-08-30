variable "environment" {
  type = string
  validation {
    condition     = var.environment == "development"
    error_message = "This root is bound exclusively to development."
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
    project_id                            = optional(string)
    region                                = optional(string)
    subnetwork_id                         = optional(string)
    network_project_id                    = optional(string)
    network_id                            = optional(string)
    name                                  = optional(string, "buildkite-agents")
    machine_type                          = optional(string, "e2-standard-4")
    boot_image                            = optional(string)
    agent_image                           = optional(string)
    token_secret_id                       = optional(string)
    token_secret_version                  = optional(string)
    agent_image_secret_contract_verified  = optional(bool, false)
    agent_job_isolation_contract_verified = optional(bool, false)
    dependency_mirror_endpoints = optional(object({
      bazel_registry_url     = optional(string)
      bazel_remote_cache_url = optional(string)
      buf_registry_url       = optional(string)
      go_proxy_url           = optional(string)
      nix_substituter_url    = optional(string)
      npm_registry_url       = optional(string)
      oci_registry_url       = optional(string)
      python_index_url       = optional(string)
      rust_sparse_index_url  = optional(string)
    }), {})
    dependency_mirror_contract_verified = optional(bool, false)
    workspace_tmpfs_mb                  = optional(number, 8192)
    allowed_egress_rules = optional(map(object({
      destination_cidrs = set(string)
      protocol          = string
      ports             = set(string)
    })), {})
    min_replicas = optional(number, 1)
    max_replicas = optional(number, 10)
    labels       = optional(map(string), {})
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
}

module "stack" {
  source            = "../../../stacks/ci-execution"
  environment       = var.environment
  enabled           = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location  = local.region_profile.primaryLocation
  recovery_location = local.region_profile.recoveryLocation
  config            = var.config
}
