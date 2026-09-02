variable "enabled" {
  description = "Connected-resource gate. This must remain false while the cache boundary is disabled."
  type        = bool
  default     = false
}

variable "environment" {
  description = "Owning immutable environment tier."
  type        = string

  validation {
    condition     = contains(["development", "staging", "production", "restricted"], var.environment)
    error_message = "The Bazel cache caller must use a canonical environment tier."
  }
}

variable "location" {
  description = "Regional cache authority location."
  type        = string
  default     = "us-central1"

  validation {
    condition     = var.location == "us-central1"
    error_message = "The development cache authority is pinned to us-central1."
  }
}

variable "boundary" {
  description = "cache-boundary.v2 evidence and activation contract for the Bazel HTTP cache."
  type = object({
    schema_version             = string
    qualification              = string
    cache_mode                 = string
    cache_used                 = bool
    cache_outputs_are_evidence = bool
    endpoint                   = optional(string)
    namespace = object({
      schema_version   = string
      classification   = string
      namespace_epoch  = string
      trust_class      = string
      system           = string
      toolchain_digest = optional(string)
      build_mode       = string
    })
    # Only these Bazel targets may be served from or written to the cache. An
    # empty allowlist means nothing is cacheable, which is the disabled state.
    cacheable_targets        = list(string)
    iam_qualification_digest = optional(string)
    write_activation_digest  = optional(string)
    cacheless_canary = object({
      required         = bool
      status           = string
      evidence_locator = optional(string)
      evidence_digest  = optional(string)
    })
    poison_recovery = object({
      required = bool
      status   = string
      runbook  = string
    })
  })

  validation {
    condition = (
      var.boundary.schema_version == "cache-boundary.v2" &&
      contains(["DISABLED", "IAM_QUALIFIED", "WRITE_ACTIVATED"], var.boundary.qualification) &&
      contains(["disabled", "read", "write"], var.boundary.cache_mode) &&
      !var.boundary.cache_outputs_are_evidence &&
      var.boundary.namespace.schema_version == "cache-namespace.v2" &&
      var.boundary.namespace.classification == "internal" &&
      var.boundary.namespace.system == "x86_64-linux" &&
      var.boundary.cacheless_canary.required &&
      var.boundary.poison_recovery.required &&
      var.boundary.poison_recovery.runbook == "runbooks/bazel-cache-recovery.md"
    )
    error_message = "The Bazel cache must use the exact v2 boundary/namespace schemas, internal classification, x86_64-linux system, and mandatory recovery controls."
  }

  validation {
    condition = (
      var.boundary.qualification == "DISABLED" ||
      length(var.boundary.cacheable_targets) > 0
    )
    error_message = "A qualified Bazel cache must declare an explicit cacheable-target allowlist."
  }
}

variable "protected_inputs" {
  description = "Protected identifiers and evidence locators. Every field stays null while disabled."
  type = object({
    project_id                         = optional(string)
    cache_bucket_name                  = optional(string)
    operation_bucket_name              = optional(string)
    external_audit_bucket_name         = optional(string)
    iam_qualification_evidence_locator = optional(string)
    write_activation_evidence_locator  = optional(string)
    # Protected-main Buildkite writers. Empty until write activation.
    writer_wif_principal_sets = optional(set(string), [])
    # Pull-request readers. Reads are authenticated: the repositories are
    # internal or private, so the cache is never anonymously readable.
    reader_wif_principal_sets = optional(set(string), [])
  })
  default = {}
}

variable "quotas" {
  description = "Non-secret retention and size limits for the cache namespace."
  type = object({
    cache_retention_days     = number
    operation_retention_days = number
    max_object_bytes         = number
  })
  default = {
    cache_retention_days     = 30
    operation_retention_days = 400
    max_object_bytes         = 1073741824
  }
}
