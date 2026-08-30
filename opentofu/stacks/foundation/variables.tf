variable "environment" {
  type = string
  validation {
    condition     = contains(["development", "staging", "production", "restricted"], var.environment)
    error_message = "environment must be a supported immutable tier."
  }
}

variable "enabled" {
  type    = bool
  default = false
}
variable "project_class" {
  description = "Catalog-derived project authority for the immutable environment."
  type = object({
    folderBindingRequired   = bool
    billingBindingRequired  = bool
    deletionProtection      = bool
    sharedVpcServiceProject = bool
    allowedEnvironmentTiers = list(string)
  })
}
variable "approved_services" {
  description = "Exact union of catalog service-capability required APIs."
  type        = set(string)
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
