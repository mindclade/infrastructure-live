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
    project_id               = optional(string)
    location                 = optional(string)
    key_ring_name            = optional(string)
    key_name                 = optional(string)
    key_encrypter_decrypters = optional(set(string), [])
    bucket_id                = optional(string, "platform")
    retention_days           = optional(number, 30)
    source_projects          = optional(set(string), [])
    sink_writer_binding_mode = optional(string, "enforce")
    sink_writer_identities   = optional(map(string), {})
    log_filter               = optional(string, "logName:*")
    labels                   = optional(map(string), {})
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
  source            = "../../../stacks/observability"
  environment       = var.environment
  enabled           = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location  = local.region_profile.primaryLocation
  recovery_location = local.region_profile.recoveryLocation
  config            = var.config
}
