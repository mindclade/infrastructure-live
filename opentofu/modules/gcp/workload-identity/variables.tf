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
variable "accounts" {
  type = map(object({
    account_id           = string
    display_name         = string
    namespace            = string
    service_account_name = string
    project_roles        = optional(set(string), [])
  }))
  default = {}
  validation {
    condition     = !var.enabled || length(var.accounts) > 0
    error_message = "At least one workload identity mapping is required when enabled."
  }
  validation {
    condition = alltrue([
      for account in values(var.accounts) : can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", account.account_id))
    ])
    error_message = "Every account_id must be a valid deterministic service-account ID."
  }
  validation {
    condition = alltrue(flatten([for account in values(var.accounts) : [
      for role in account.project_roles : contains([
        "roles/cloudsql.client",
        "roles/logging.logWriter",
        "roles/monitoring.metricWriter",
        "roles/serviceusage.serviceUsageConsumer",
      ], role)
    ]]))
    error_message = "Workload project roles must be in the explicit least-privilege capability allowlist; use resource-scoped modules for all other access."
  }
}
