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
variable "bucket_id" {
  type    = string
  default = "platform"
}
variable "retention_days" {
  type    = number
  default = 30
  validation {
    condition     = var.retention_days >= 30 && var.retention_days <= 3650
    error_message = "Log retention must be between 30 and 3650 days."
  }
}
variable "minimum_retention_days" {
  description = "Catalog-derived minimum retention for the immutable environment."
  type        = number
  default     = 30
  validation {
    condition     = contains([30, 90, 365], var.minimum_retention_days)
    error_message = "minimum_retention_days must be a supported catalog-derived boundary."
  }
}
variable "kms_key_name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.kms_key_name != null
    error_message = "A delegated log encryption key is required when enabled."
  }
}
variable "source_projects" {
  type    = set(string)
  default = []
  validation {
    condition     = !var.enabled || var.project_id == null || !contains(var.source_projects, var.project_id)
    error_message = "A same-project log sink has no unique writer identity and must not be included in source_projects."
  }
}
variable "sink_writer_binding_mode" {
  description = "discover creates sinks without IAM so provider-issued identities can be reviewed; enforce binds only exact reviewed identities."
  type        = string
  default     = "enforce"
  validation {
    condition     = contains(["discover", "enforce"], var.sink_writer_binding_mode)
    error_message = "sink_writer_binding_mode must be discover or enforce."
  }
  validation {
    condition     = !var.enabled || var.sink_writer_binding_mode != "discover" || length(var.source_projects) > 0
    error_message = "Discovery mode is valid only for an enabled sink with explicit source projects."
  }
}
variable "sink_writer_identities" {
  description = "Provider-issued sink writer identities keyed by source project after a reviewed discovery apply."
  type        = map(string)
  default     = {}
  validation {
    condition = alltrue([
      for identity in values(var.sink_writer_identities) : can(regex("^serviceAccount:[^@[:space:]]+@[^@[:space:]]+\\.iam\\.gserviceaccount\\.com$", identity))
    ])
    error_message = "Sink writer identities must be explicit Google service accounts."
  }
  validation {
    condition = !var.enabled || (
      var.sink_writer_binding_mode == "discover"
      ? length(var.sink_writer_identities) == 0
      : toset(keys(var.sink_writer_identities)) == var.source_projects
    )
    error_message = "Discovery accepts no writer bindings; enforcement requires one exact provider-issued identity for every source project."
  }
}
variable "log_filter" {
  type    = string
  default = "logName:*"
}
