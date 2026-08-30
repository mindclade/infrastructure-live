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
variable "name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.name != null
    error_message = "name must be bound before activation."
  }
}
variable "region" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.region != null
    error_message = "region must be bound before activation."
  }
}
variable "network_id" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.network_id != null
    error_message = "network_id must be bound before activation."
  }
}
variable "kms_key_name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.kms_key_name != null
    error_message = "kms_key_name must be bound before activation."
  }
}
variable "database_version" {
  type    = string
  default = "POSTGRES_16"
}
variable "tier" {
  type    = string
  default = "db-custom-2-7680"
}
variable "availability_type" {
  type    = string
  default = "REGIONAL"
  validation {
    condition     = contains(["ZONAL", "REGIONAL"], var.availability_type)
    error_message = "availability_type must be ZONAL or REGIONAL."
  }
}
variable "backup_retention_days" {
  type    = number
  default = 35
  validation {
    condition     = var.backup_retention_days >= 7 && var.backup_retention_days <= 365
    error_message = "backup_retention_days must be between 7 and 365."
  }
}
variable "transaction_log_retention_days" {
  type    = number
  default = 7
  validation {
    condition     = var.transaction_log_retention_days >= 1 && var.transaction_log_retention_days <= 7
    error_message = "transaction log retention must be between 1 and 7 days."
  }
}
variable "minimum_backup_retention_days" {
  description = "Catalog-derived minimum retained daily backups."
  type        = number
  default     = 7
  validation {
    condition     = var.minimum_backup_retention_days >= 7 && var.minimum_backup_retention_days <= 365
    error_message = "minimum_backup_retention_days must be a supported catalog boundary."
  }
}
variable "high_availability_required" {
  type    = bool
  default = false
}
variable "deletion_protection_required" {
  type    = bool
  default = true
}
variable "labels" {
  type    = map(string)
  default = {}
}
