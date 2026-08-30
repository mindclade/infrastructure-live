variable "environment" {
  type = string
  validation {
    condition     = var.environment == "production"
    error_message = "This root is bound exclusively to production."
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
    project_id    = optional(string)
    location      = optional(string)
    key_ring_name = optional(string)
    keys = optional(map(object({
      purpose                    = optional(string, "ENCRYPT_DECRYPT")
      rotation_period            = optional(string, "7776000s")
      destroy_scheduled_duration = optional(string, "2592000s")
      labels                     = optional(map(string), {})
      encrypter_decrypters       = optional(set(string), [])
    })), {})
    repositories = optional(map(object({
      location       = string
      format         = optional(string, "DOCKER")
      description    = optional(string, "Mindclade immutable artifacts")
      key_name       = string
      immutable_tags = optional(bool, true)
      labels         = optional(map(string), {})
    })), {})
    buckets = optional(map(object({
      location                = string
      key_name                = string
      retention_days          = number
      lock_retention          = optional(bool, false)
      soft_delete_days        = optional(number, 30)
      noncurrent_version_days = optional(number, 365)
      labels                  = optional(map(string), {})
    })), {})
    repository_readers = optional(map(set(string)), {})
    repository_writers = optional(map(set(string)), {})
    bucket_readers     = optional(map(set(string)), {})
    bucket_writers     = optional(map(set(string)), {})
    ci_evidence_archive = optional(object({
      identity_project_id         = optional(string)
      audit_sink_binding_mode     = optional(string, "discover")
      audit_sink_writer_identity  = optional(string)
      audit_notification_channels = optional(set(string), [])
      inventory_schedule = optional(object({
        start = object({ day = number, month = number, year = number })
        end   = object({ day = number, month = number, year = number })
      }))
    }), {})
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
  resource_profile = one([
    for profile in yamldecode(file("${path.root}/../../../../catalog/resource-profiles.yaml")).resourceProfiles :
    profile if profile.name == local.environment_catalog.resourceProfile
  ])
}

module "stack" {
  source                      = "../../../stacks/artifacts"
  environment                 = var.environment
  enabled                     = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location            = local.region_profile.primaryLocation
  recovery_location           = local.region_profile.recoveryLocation
  ci_evidence_archive_profile = local.resource_profile.ciEvidenceArchive
  config                      = var.config
}
