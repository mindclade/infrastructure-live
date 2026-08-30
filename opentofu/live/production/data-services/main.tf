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
    region        = optional(string)
    network_id    = optional(string)
    key_ring_name = optional(string)
    keys = optional(map(object({
      purpose                    = optional(string, "ENCRYPT_DECRYPT")
      rotation_period            = optional(string, "7776000s")
      destroy_scheduled_duration = optional(string, "2592000s")
      labels                     = optional(map(string), {})
      encrypter_decrypters       = optional(set(string), [])
    })), {})
    database = optional(object({
      name                           = string
      key_name                       = string
      database_version               = optional(string, "POSTGRES_16")
      tier                           = optional(string, "db-custom-2-7680")
      availability_type              = optional(string, "REGIONAL")
      backup_retention_days          = optional(number, 35)
      transaction_log_retention_days = optional(number, 7)
      labels                         = optional(map(string), {})
    }))
    topics          = optional(map(object({ key_name = string, message_retention_duration = optional(string, "604800s"), labels = optional(map(string), {}) })), {})
    subscriptions   = optional(map(object({ topic = string, ack_deadline_seconds = optional(number, 60), message_retention_duration = optional(string, "604800s"), retain_acked_messages = optional(bool, false), exactly_once_delivery = optional(bool, true), labels = optional(map(string), {}) })), {})
    publishers      = optional(map(set(string)), {})
    subscribers     = optional(map(set(string)), {})
    secret_bindings = optional(map(object({ secret_id = string, member = string })), {})
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
  source            = "../../../stacks/data-services"
  environment       = var.environment
  enabled           = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location  = local.region_profile.primaryLocation
  recovery_location = local.region_profile.recoveryLocation
  resource_profile  = local.resource_profile
  config            = var.config
}
