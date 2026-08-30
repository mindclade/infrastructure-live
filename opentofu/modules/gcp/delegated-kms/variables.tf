variable "enabled" {
  type    = bool
  default = false
}
variable "project_id" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.project_id != null
    error_message = "project_id must be bound before activation."
  }
}
variable "location" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.location != null
    error_message = "location must be bound before activation."
  }
}
variable "key_ring_name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.key_ring_name != null
    error_message = "key_ring_name must be bound before activation."
  }
}
variable "keys" {
  type = map(object({
    purpose                    = optional(string, "ENCRYPT_DECRYPT")
    algorithm                  = optional(string, "GOOGLE_SYMMETRIC_ENCRYPTION")
    protection_level           = optional(string, "SOFTWARE")
    rotation_period            = optional(string, "7776000s")
    destroy_scheduled_duration = optional(string, "2592000s")
    labels                     = optional(map(string), {})
    encrypter_decrypters       = optional(set(string), [])
  }))
  default = {}
  validation {
    condition     = !var.enabled || length(var.keys) > 0
    error_message = "At least one delegated key is required when enabled."
  }
  validation {
    condition = !var.enabled || alltrue([
      for key in values(var.keys) : (
        key.algorithm == "GOOGLE_SYMMETRIC_ENCRYPTION" &&
        contains(["SOFTWARE", "HSM"], key.protection_level)
      )
    ])
    error_message = "Delegated keys require the approved symmetric algorithm and an explicit supported protection level."
  }
  validation {
    condition = !var.enabled || alltrue([
      for key in values(var.keys) : length(key.encrypter_decrypters) > 0 && alltrue([
        for member in key.encrypter_decrypters : can(regex("^serviceAccount:[^@[:space:]]+@[^@[:space:]]+\\.iam\\.gserviceaccount\\.com$", member))
      ])
    ])
    error_message = "Every enabled key requires at least one explicit qualified service-account encrypter/decrypter binding."
  }
}
