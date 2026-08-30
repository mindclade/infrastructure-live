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
    project_id          = optional(string)
    region              = optional(string)
    network_name        = optional(string)
    routing_mode        = optional(string, "GLOBAL")
    service_project_ids = optional(set(string), [])
    subnets = optional(map(object({
      region                = string
      cidr                  = string
      private_google_access = optional(bool, true)
      flow_logs             = optional(bool, true)
      secondary_ranges      = optional(map(string), {})
    })), {})
    private_zones = optional(map(object({ dns_name = string, description = optional(string, "Managed private zone"), labels = optional(map(string), {}) })), {})
    private_service_access = optional(object({
      address       = string
      prefix_length = number
    }))
    nat_ip_count = optional(number, 1)
    allowed_egress_rules = optional(map(object({
      destination_cidrs = set(string)
      protocol          = string
      ports             = set(string)
    })), {})
    labels = optional(map(string), {})
  })
  default = {}
}
