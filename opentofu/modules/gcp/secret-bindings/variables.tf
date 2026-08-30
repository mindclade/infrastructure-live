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
variable "bindings" {
  description = "References to pre-existing Secret Manager secrets and narrowly scoped members. Secret payloads are never accepted."
  type = map(object({
    secret_id = string
    member    = string
  }))
  default = {}
  validation {
    condition     = !var.enabled || length(var.bindings) > 0
    error_message = "At least one explicit secret reference is required when enabled."
  }
  validation {
    condition     = alltrue([for binding in values(var.bindings) : can(regex("^(serviceAccount|principal|principalSet):", binding.member))])
    error_message = "Secret access is limited to workload or federated principals."
  }
}
