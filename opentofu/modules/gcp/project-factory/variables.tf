variable "enabled" {
  description = "Whether this module may manage resources."
  type        = bool
  default     = false
}

variable "project_id" {
  description = "Globally unique project identifier supplied through an approved binding."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = !var.enabled || (var.project_id != null && can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.project_id)))
    error_message = "project_id must be bound to a valid project identifier before activation."
  }
}

variable "project_name" {
  description = "Human-readable project name."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = !var.enabled || (var.project_name != null && length(var.project_name) >= 4)
    error_message = "project_name is required when enabled."
  }
}

variable "organization_id" {
  description = "Organization binding; mutually exclusive with folder_id."
  type        = string
  default     = null
  nullable    = true
}

variable "folder_id" {
  description = "Folder binding; mutually exclusive with organization_id."
  type        = string
  default     = null
  nullable    = true
}

variable "billing_account" {
  description = "Billing account binding supplied by the protected apply environment."
  type        = string
  default     = null
  nullable    = true
  sensitive   = true
  validation {
    condition     = !var.enabled || !var.billing_binding_required || var.billing_account != null
    error_message = "The catalog project class requires billing_account before activation."
  }
}

variable "folder_binding_required" {
  type    = bool
  default = true
}

variable "billing_binding_required" {
  type    = bool
  default = true
}

variable "deletion_protection_required" {
  type    = bool
  default = true
}

variable "services" {
  description = "Google APIs enabled without disabling them on teardown."
  type        = set(string)
  default     = []
  validation {
    condition     = alltrue([for service in var.services : can(regex("^[a-z0-9.-]+\\.googleapis\\.com$", service))])
    error_message = "Every service must be a googleapis.com service name."
  }
}

variable "approved_services" {
  description = "Catalog-derived closed API allowlist."
  type        = set(string)
  default     = []
}

variable "labels" {
  description = "Governance and cost-allocation labels."
  type        = map(string)
  default     = {}
}
