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
variable "name" {
  type    = string
  default = "controlled-egress"
}
variable "subnetwork_ids" {
  type    = set(string)
  default = []
  validation {
    condition     = !var.enabled || length(var.subnetwork_ids) > 0
    error_message = "At least one explicit subnetwork is required when enabled."
  }
}
variable "nat_ip_count" {
  type    = number
  default = 1
  validation {
    condition     = var.nat_ip_count >= 1 && var.nat_ip_count <= 8
    error_message = "nat_ip_count must be between one and eight."
  }
}
variable "allowed_egress_rules" {
  description = "Reviewed, named IPv4 destination and transport rules; default routes and protocol wildcards are prohibited."
  type = map(object({
    destination_cidrs = set(string)
    protocol          = string
    ports             = set(string)
  }))
  default = {}
  validation {
    condition = !var.enabled || (
      length(var.allowed_egress_rules) > 0 &&
      alltrue(flatten([
        for name, rule in var.allowed_egress_rules : [
          can(regex("^[a-z][a-z0-9-]{2,40}$", name)),
          contains(["tcp", "udp"], rule.protocol),
          length(rule.destination_cidrs) > 0,
          length(rule.ports) > 0,
          alltrue([for cidr in rule.destination_cidrs :
            can(cidrnetmask(cidr)) &&
            try(tonumber(split("/", cidr)[1]), 0) > 0 &&
            try(cidrhost(cidr, 0), "") == try(split("/", cidr)[0], "invalid")
          ]),
          try(
            sum([
              for cidr in rule.destination_cidrs :
              pow(2, 32 - tonumber(split("/", cidr)[1]))
              if !anytrue([
                for covering_cidr in rule.destination_cidrs :
                covering_cidr != cidr &&
                tonumber(split("/", covering_cidr)[1]) < tonumber(split("/", cidr)[1]) &&
                cidrcontains(covering_cidr, cidr)
              ])
            ]) < pow(2, 32),
            false
          ),
          alltrue([for port in rule.ports :
            can(regex("^[0-9]{1,5}(-[0-9]{1,5})?$", port)) &&
            try(tonumber(split("-", port)[0]), 0) >= 1 &&
            try(tonumber(split("-", port)[0]), 65536) <= 65535 &&
            try(tonumber(split("-", port)[length(split("-", port)) - 1]), 0) >= try(tonumber(split("-", port)[0]), 65536) &&
            try(tonumber(split("-", port)[length(split("-", port)) - 1]), 65536) <= 65535
          ])
        ]
      ]))
    )
    error_message = "Enabled egress requires named TCP/UDP rules with canonical IPv4 CIDRs whose union is not a default route and bounded ports."
  }
}
variable "labels" {
  type    = map(string)
  default = {}
}
