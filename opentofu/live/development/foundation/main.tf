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
    project_id      = optional(string)
    project_name    = optional(string)
    organization_id = optional(string)
    folder_id       = optional(string)
    billing_account = optional(string)
    services        = optional(set(string), [])
    labels          = optional(map(string), {})
  })
  default = {}
}

locals {
  environment_catalog = one([
    for environment in yamldecode(file("${path.root}/../../../../catalog/environments.yaml")).environments :
    environment if environment.name == var.environment
  ])
  project_class = one([
    for project_class in yamldecode(file("${path.root}/../../../../catalog/project-classes.yaml")).projectClasses :
    project_class if project_class.name == local.environment_catalog.projectClass
  ])
  approved_services = toset(one([
    for capability in yamldecode(file("${path.root}/../../../../catalog/service-capabilities.yaml")).serviceCapabilities :
    capability.requiredApis if capability.name == "foundation"
  ]))
}

module "stack" {
  source = "../../../stacks/foundation"

  environment       = var.environment
  enabled           = var.enabled && local.environment_catalog.enabled
  project_class     = local.project_class
  approved_services = local.approved_services
  config            = var.config
}
