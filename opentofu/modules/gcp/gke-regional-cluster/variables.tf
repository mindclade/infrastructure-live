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
    condition     = !var.enabled || (var.region != null && can(regex("^[a-z]+-[a-z]+[0-9]$", var.region)))
    error_message = "A regional location must be bound before activation; zonal locations are prohibited."
  }
}
variable "node_locations" {
  type    = set(string)
  default = []
}
variable "minimum_zones" {
  description = "Catalog-derived minimum distinct cluster zones."
  type        = number
  default     = 1
  validation {
    condition     = var.minimum_zones >= 1 && var.minimum_zones <= 3
    error_message = "minimum_zones must be between one and three."
  }
}
variable "deletion_protection_required" {
  type    = bool
  default = true
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
variable "subnetwork_id" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.subnetwork_id != null
    error_message = "subnetwork_id must be bound before activation."
  }
}
variable "pods_secondary_range_name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.pods_secondary_range_name != null
    error_message = "pods_secondary_range_name must be bound before activation."
  }
}
variable "services_secondary_range_name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.services_secondary_range_name != null
    error_message = "services_secondary_range_name must be bound before activation."
  }
}
variable "master_ipv4_cidr_block" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition = !var.enabled || (
      var.master_ipv4_cidr_block != null &&
      can(cidrnetmask(var.master_ipv4_cidr_block)) &&
      try(tonumber(split("/", var.master_ipv4_cidr_block)[1]), 0) == 28 &&
      try(cidrhost(var.master_ipv4_cidr_block, 0), "") == try(split("/", var.master_ipv4_cidr_block)[0], "invalid")
    )
    error_message = "A canonical, non-overlapping IPv4 /28 control-plane network must be bound before activation."
  }
}
variable "database_encryption_key_name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.database_encryption_key_name != null
    error_message = "A delegated database encryption key is required when enabled."
  }
}
variable "release_channel" {
  type    = string
  default = "REGULAR"
  validation {
    condition     = contains(["REGULAR", "STABLE"], var.release_channel)
    error_message = "Only REGULAR or STABLE release channels are permitted."
  }
}
variable "resource_labels" {
  type    = map(string)
  default = {}
}
