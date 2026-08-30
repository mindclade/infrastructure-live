variable "enabled" {
  type    = bool
  default = false
}
variable "project_id" {
  type     = string
  default  = null
  nullable = true
}
variable "region" {
  type     = string
  default  = null
  nullable = true
}
variable "subnetwork_id" {
  type     = string
  default  = null
  nullable = true
}
variable "name" {
  type    = string
  default = "buildkite-agents"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.name))
    error_message = "name must be a valid deterministic service-account ID."
  }
}
variable "machine_type" {
  type    = string
  default = "e2-standard-4"
}
variable "boot_image" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || (var.boot_image != null && can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/images/[a-z]([-a-z0-9]{0,61}[a-z0-9])?$", var.boot_image)))
    error_message = "An immutable Compute Engine image resource must be bound when enabled; image families are prohibited."
  }
}
variable "agent_image" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || (var.agent_image != null && can(regex("^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$", var.agent_image)))
    error_message = "The agent image must be a lowercase, shell-safe OCI repository with an immutable sha256 digest."
  }
}
variable "token_secret_id" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || (var.token_secret_id != null && can(regex("^[A-Za-z][A-Za-z0-9_-]{0,254}$", var.token_secret_id)))
    error_message = "A shell-safe Secret Manager secret ID is required when enabled."
  }
}
variable "token_secret_version" {
  description = "Immutable numeric Secret Manager version resolved by the qualified agent image."
  type        = string
  default     = null
  nullable    = true
  validation {
    condition     = !var.enabled || (var.token_secret_version != null && can(regex("^[1-9][0-9]*$", var.token_secret_version)))
    error_message = "An explicit numeric Secret Manager version is required when enabled; aliases and latest are prohibited."
  }
}
variable "agent_image_secret_contract_verified" {
  description = "External qualification that the exact image digest resolves BUILDKITE_TOKEN_SECRET_RESOURCE with ADC without logging or persisting the token."
  type        = bool
  default     = false
}
variable "agent_job_isolation_contract_verified" {
  description = "External qualification that jobs cannot access agent credentials, metadata, or the long-lived registration token and that JAT-only one-job isolation is enforced."
  type        = bool
  default     = false
}
variable "min_replicas" {
  type    = number
  default = 1
  validation {
    condition     = !var.enabled || var.min_replicas >= 1
    error_message = "At least one warm agent is required because CPU autoscaling cannot scale from zero on queue demand."
  }
}
variable "max_replicas" {
  type    = number
  default = 10
  validation {
    condition     = var.max_replicas >= 1 && var.max_replicas <= 100
    error_message = "max_replicas must be between one and 100."
  }
}
variable "labels" {
  type    = map(string)
  default = {}
}
