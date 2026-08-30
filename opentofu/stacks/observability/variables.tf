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
