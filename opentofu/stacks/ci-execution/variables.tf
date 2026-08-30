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
variable "primary_location" {
  description = "Catalog-derived primary location for the immutable environment."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = !var.enabled || (var.primary_location != null && can(regex("^[a-z]+-[a-z]+[0-9]$", var.primary_location)))
    error_message = "An enabled stack requires its catalog-derived primary location."
  }
}
variable "recovery_location" {
  description = "Catalog-derived recovery location, when the environment profile defines one."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = var.recovery_location == null || (can(regex("^[a-z]+-[a-z]+[0-9]$", var.recovery_location)) && var.recovery_location != var.primary_location)
    error_message = "A recovery location must be a distinct region."
  }
}
variable "config" {
  type = object({
    project_id                            = optional(string)
    region                                = optional(string)
    subnetwork_id                         = optional(string)
    name                                  = optional(string, "buildkite-agents")
    machine_type                          = optional(string, "e2-standard-4")
    boot_image                            = optional(string)
    agent_image                           = optional(string)
    token_secret_id                       = optional(string)
    token_secret_version                  = optional(string)
    agent_image_secret_contract_verified  = optional(bool, false)
    agent_job_isolation_contract_verified = optional(bool, false)
    min_replicas                          = optional(number, 1)
    max_replicas                          = optional(number, 10)
    labels                                = optional(map(string), {})
  })
  default = {}
}
