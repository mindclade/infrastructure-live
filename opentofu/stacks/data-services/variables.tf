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
variable "resource_profile" {
  description = "Catalog-derived resource authority for the immutable environment."
  type = object({
    highAvailabilityRequired   = bool
    deletionProtectionRequired = bool
    backupRetentionDays        = number
    minimumZones               = number
    costGuardrail              = string
  })
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
