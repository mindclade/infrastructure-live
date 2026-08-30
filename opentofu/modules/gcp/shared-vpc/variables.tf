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
variable "network_name" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || (var.network_name != null && can(regex("^[a-z][a-z0-9-]{1,62}$", var.network_name)))
    error_message = "network_name is required when enabled."
  }
}
variable "routing_mode" {
  type    = string
  default = "GLOBAL"
  validation {
    condition     = contains(["GLOBAL", "REGIONAL"], var.routing_mode)
    error_message = "routing_mode must be GLOBAL or REGIONAL."
  }
}
variable "service_project_ids" {
  description = "Explicit workload projects attached to this Shared VPC host."
  type        = set(string)
  default     = []
  validation {
    condition = !var.enabled || (
      length(var.service_project_ids) > 0 &&
      alltrue([for project_id in var.service_project_ids : can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", project_id))])
    )
    error_message = "Enabled Shared VPC requires at least one valid service-project ID."
  }
}
variable "subnets" {
  type = map(object({
    region                = string
    cidr                  = string
    private_google_access = optional(bool, true)
    flow_logs             = optional(bool, true)
    secondary_ranges      = optional(map(string), {})
  }))
  default = {}
  validation {
    condition     = !var.enabled || length(var.subnets) > 0
    error_message = "At least one explicitly bound subnet is required when enabled."
  }
  validation {
    condition = alltrue(flatten([
      for subnet in values(var.subnets) : [
        for cidr in concat([subnet.cidr], values(subnet.secondary_ranges)) :
        can(cidrnetmask(cidr)) &&
        try(cidrhost(cidr, 0), "") == try(split("/", cidr)[0], "invalid")
      ]
    ]))
    error_message = "Primary and secondary subnet ranges must be canonical IPv4 CIDRs."
  }
  validation {
    condition = alltrue([
      for cidr in concat(
        flatten([
          for subnet in values(var.subnets) :
          concat([subnet.cidr], values(subnet.secondary_ranges))
        ]),
        var.private_service_access == null ? [] : ["${var.private_service_access.address}/${var.private_service_access.prefix_length}"]
        ) : length([
          for other_cidr in concat(
            flatten([
              for subnet in values(var.subnets) :
              concat([subnet.cidr], values(subnet.secondary_ranges))
            ]),
            var.private_service_access == null ? [] : ["${var.private_service_access.address}/${var.private_service_access.prefix_length}"]
          ) : other_cidr
          if try(cidrcontains(cidr, other_cidr) || cidrcontains(other_cidr, cidr), true)
      ]) == 1
    ])
    error_message = "Primary, secondary, and private-service CIDRs must be pairwise non-overlapping."
  }
}
variable "private_service_access" {
  description = "Explicit, non-overlapping address allocation for private managed-service connectivity."
  type = object({
    address       = string
    prefix_length = number
  })
  default  = null
  nullable = true
  validation {
    condition = var.private_service_access == null ? true : (
      var.private_service_access.prefix_length >= 16 &&
      var.private_service_access.prefix_length <= 24 &&
      can(cidrnetmask("${var.private_service_access.address}/${var.private_service_access.prefix_length}")) &&
      try(cidrhost("${var.private_service_access.address}/${var.private_service_access.prefix_length}", 0), "") == var.private_service_access.address
    )
    error_message = "Private service access must be an IPv4 network address with a /16 through /24 prefix."
  }
}
variable "labels" {
  type    = map(string)
  default = {}
}
