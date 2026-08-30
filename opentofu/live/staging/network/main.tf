variable "environment" {
  type = string
  validation {
    condition     = var.environment == "staging"
    error_message = "This root is bound exclusively to staging."
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
    project_id          = optional(string)
    region              = optional(string)
    network_name        = optional(string)
    routing_mode        = optional(string, "GLOBAL")
    service_project_ids = optional(set(string), [])
    subnets = optional(map(object({
      region                = string
      cidr                  = string
      private_google_access = optional(bool, true)
      flow_logs             = optional(bool, true)
      secondary_ranges      = optional(map(string), {})
    })), {})
    private_zones = optional(map(object({ dns_name = string, description = optional(string, "Managed private zone"), labels = optional(map(string), {}) })), {})
    private_service_access = optional(object({
      address       = string
      prefix_length = number
    }))
    nat_ip_count = optional(number, 1)
    allowed_egress_rules = optional(map(object({
      destination_cidrs = set(string)
      protocol          = string
      ports             = set(string)
    })), {})
    labels = optional(map(string), {})
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
  source            = "../../../stacks/network"
  environment       = var.environment
  enabled           = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location  = local.region_profile.primaryLocation
  recovery_location = local.region_profile.recoveryLocation
  config            = var.config
}
