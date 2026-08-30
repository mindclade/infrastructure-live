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
  })
  default = {}
}
