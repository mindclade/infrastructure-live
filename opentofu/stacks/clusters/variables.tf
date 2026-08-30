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
variable "accelerator_profiles" {
  type = map(object({
    enabled                       = bool
    acceleratorType               = string
    acceleratorCount              = number
    spotPermitted                 = bool
    confidentialWorkloadPermitted = bool
    dedicatedNodePool             = bool
    maximumNodes                  = number
    regionBinding                 = optional(string)
    quotaBinding                  = optional(string)
  }))
  default = {}
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
    project_id                    = optional(string)
    name                          = optional(string)
    region                        = optional(string)
    node_locations                = optional(set(string), [])
    network_id                    = optional(string)
    subnetwork_id                 = optional(string)
    pods_secondary_range_name     = optional(string)
    services_secondary_range_name = optional(string)
    master_ipv4_cidr_block        = optional(string)
    database_encryption_key_name  = optional(string)
    release_channel               = optional(string, "REGULAR")
    resource_labels               = optional(map(string), {})
    workload_accounts = optional(map(object({
      account_id           = string
      display_name         = string
      namespace            = string
      service_account_name = string
      project_roles        = optional(set(string), [])
    })), {})
    node_pools = optional(map(object({
      service_account     = string
      machine_type        = optional(string, "e2-standard-4")
      disk_type           = optional(string, "pd-balanced")
      disk_size_gb        = optional(number, 100)
      min_nodes           = optional(number, 0)
      max_nodes           = optional(number, 3)
      spot                = optional(bool, false)
      accelerator_profile = optional(string)
      accelerator         = optional(object({ type = string, count = number, gpu_driver_version = optional(string, "INSTALLATION_DISABLED") }))
      taints              = optional(list(object({ key = string, value = string, effect = string })), [])
      labels              = optional(map(string), {})
      resource_labels     = optional(map(string), {})
      tags                = optional(set(string), [])
    })), {})
    argocd = optional(object({
      enabled                     = optional(bool, false)
      service_account_id          = optional(string, "argocd-management")
      kubernetes_namespace        = optional(string, "external-secrets")
      kubernetes_service_accounts = optional(set(string), ["external-secrets"])
      secret_references           = optional(set(string), [])
      membership_id               = string
    }))
  })
  default = {}
}
