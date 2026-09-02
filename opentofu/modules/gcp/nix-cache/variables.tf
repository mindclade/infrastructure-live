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
    error_message = "The Nix cache caller must use a canonical environment tier."
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
  description = "cache-boundary.v2 evidence and activation contract."
  type = object({
    schema_version             = string
    qualification              = string
    source_revision            = optional(string)
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
    iam_qualification_digest = optional(string)
    write_activation_digest  = optional(string)
    signer_public_key_digest = optional(string)
    audit_sink_digest        = optional(string)
    cacheless_canary = object({
      required         = bool
      status           = string
      evidence_locator = optional(string)
      evidence_digest  = optional(string)
    })
    poison_recovery = object({
      required         = bool
      status           = string
      runbook          = string
      evidence_locator = optional(string)
      evidence_digest  = optional(string)
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
      var.boundary.namespace.system == "aarch64-linux" &&
      var.boundary.cacheless_canary.required &&
      var.boundary.poison_recovery.required &&
      var.boundary.poison_recovery.runbook == "runbooks/nix-cache-recovery.md"
    )
    error_message = "The Nix cache must use the exact v2 boundary/namespace schemas, internal classification, aarch64-linux system, and mandatory recovery controls."
  }

  validation {
    condition = (
      (
        var.boundary.qualification == "DISABLED" &&
        var.boundary.source_revision == null &&
        var.boundary.cache_mode == "disabled" &&
        !var.boundary.cache_used &&
        var.boundary.endpoint == null &&
        var.boundary.namespace.namespace_epoch == "disabled-v2" &&
        var.boundary.namespace.trust_class == "untrusted" &&
        var.boundary.namespace.toolchain_digest == null &&
        var.boundary.namespace.build_mode == "cacheless" &&
        var.boundary.iam_qualification_digest == null &&
        var.boundary.write_activation_digest == null &&
        var.boundary.signer_public_key_digest == null &&
        var.boundary.audit_sink_digest == null &&
        var.boundary.cacheless_canary.status == "NOT_RUN" &&
        var.boundary.cacheless_canary.evidence_locator == null &&
        var.boundary.cacheless_canary.evidence_digest == null &&
        var.boundary.poison_recovery.status == "NOT_RUN" &&
        var.boundary.poison_recovery.evidence_locator == null &&
        var.boundary.poison_recovery.evidence_digest == null
      ) ||
      (
        var.boundary.qualification == "IAM_QUALIFIED" &&
        var.boundary.cache_mode == "read" &&
        var.boundary.cache_used &&
        var.boundary.endpoint == "https://nix-cache.mindclade.com" &&
        can(regex("^[0-9a-f]{40}$", var.boundary.source_revision)) &&
        can(regex("^epoch-[1-9][0-9]*$", var.boundary.namespace.namespace_epoch)) &&
        var.boundary.namespace.trust_class == "verified" &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.namespace.toolchain_digest)) &&
        var.boundary.namespace.build_mode == "substitute-read" &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.iam_qualification_digest)) &&
        var.boundary.write_activation_digest == null &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.signer_public_key_digest)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.audit_sink_digest)) &&
        var.boundary.cacheless_canary.status == "PASSED" &&
        can(regex("^gs://[^[:space:]]+$", var.boundary.cacheless_canary.evidence_locator)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.cacheless_canary.evidence_digest)) &&
        var.boundary.poison_recovery.status == "PASSED" &&
        can(regex("^gs://[^[:space:]]+$", var.boundary.poison_recovery.evidence_locator)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.poison_recovery.evidence_digest))
      ) ||
      (
        var.boundary.qualification == "WRITE_ACTIVATED" &&
        var.boundary.cache_mode == "write" &&
        var.boundary.cache_used &&
        var.boundary.endpoint == "https://nix-cache.mindclade.com" &&
        can(regex("^[0-9a-f]{40}$", var.boundary.source_revision)) &&
        can(regex("^epoch-[1-9][0-9]*$", var.boundary.namespace.namespace_epoch)) &&
        var.boundary.namespace.trust_class == "protected" &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.namespace.toolchain_digest)) &&
        var.boundary.namespace.build_mode == "substitute-write" &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.iam_qualification_digest)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.write_activation_digest)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.signer_public_key_digest)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.audit_sink_digest)) &&
        var.boundary.cacheless_canary.status == "PASSED" &&
        can(regex("^gs://[^[:space:]]+$", var.boundary.cacheless_canary.evidence_locator)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.cacheless_canary.evidence_digest)) &&
        var.boundary.poison_recovery.status == "PASSED" &&
        can(regex("^gs://[^[:space:]]+$", var.boundary.poison_recovery.evidence_locator)) &&
        can(regex("^sha256:[0-9a-f]{64}$", var.boundary.poison_recovery.evidence_digest))
      )
    )
    error_message = "cache-boundary.v2 transitions must bind exact disabled, IAM-qualified read, or protected write-activated evidence."
  }
}

variable "protected_inputs" {
  description = "Connected identifiers and evidence locators supplied only after independent qualification."
  type = object({
    project_id                         = optional(string)
    cache_bucket_name                  = optional(string)
    health_bucket_name                 = optional(string)
    operation_bucket_name              = optional(string)
    external_audit_bucket_name         = optional(string)
    signer_secret_resource             = optional(string)
    iam_qualification_evidence_locator = optional(string)
    write_activation_evidence_locator  = optional(string)
    publisher_wif_principal_sets       = set(string)
    gateway_wif_principal_sets         = set(string)
  })

  validation {
    condition = (
      var.protected_inputs.project_id == null ||
      can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.protected_inputs.project_id))
    )
    error_message = "The connected cache project must be one exact protected Google Cloud project ID."
  }

  validation {
    condition = alltrue([
      for bucket in compact([
        var.protected_inputs.cache_bucket_name,
        var.protected_inputs.health_bucket_name,
        var.protected_inputs.operation_bucket_name,
        var.protected_inputs.external_audit_bucket_name,
      ]) : can(regex("^[a-z0-9][a-z0-9._-]{1,61}[a-z0-9]$", bucket))
      ]) && length(distinct(compact([
        var.protected_inputs.cache_bucket_name,
        var.protected_inputs.health_bucket_name,
        var.protected_inputs.operation_bucket_name,
        var.protected_inputs.external_audit_bucket_name,
        ]))) == length(compact([
        var.protected_inputs.cache_bucket_name,
        var.protected_inputs.health_bucket_name,
        var.protected_inputs.operation_bucket_name,
        var.protected_inputs.external_audit_bucket_name,
    ]))
    error_message = "Cache, health, operation, and external audit buckets must be distinct exact protected bucket names."
  }

  validation {
    condition = (
      var.protected_inputs.signer_secret_resource == null ||
      can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/secrets/nix-cache-signing-key$", var.protected_inputs.signer_secret_resource))
    )
    error_message = "The signer must reference only the bootstrap-owned nix-cache-signing-key Secret Manager resource."
  }

  validation {
    condition = alltrue(concat(
      [for principal in var.protected_inputs.publisher_wif_principal_sets : can(regex("^principalSet://iam\\.googleapis\\.com/projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[a-z][a-z0-9-]+/attribute\\.[A-Za-z0-9_]+/[^*?[:space:]]+$", principal))],
      [for principal in var.protected_inputs.gateway_wif_principal_sets : can(regex("^principalSet://iam\\.googleapis\\.com/projects/[1-9][0-9]*/locations/global/workloadIdentityPools/[a-z][a-z0-9-]+/attribute\\.[A-Za-z0-9_]+/[^*?[:space:]]+$", principal))],
    ))
    error_message = "Cache WIF inputs must be exact numeric-project principalSet identities without wildcard claims."
  }

  validation {
    condition = alltrue([
      for locator in compact([
        var.protected_inputs.iam_qualification_evidence_locator,
        var.protected_inputs.write_activation_evidence_locator,
      ]) : can(regex("^gs://[^/[:space:]]+/[^#[:space:]]+#[1-9][0-9]*$", locator))
    ])
    error_message = "Qualification and activation evidence locators must bind an exact immutable GCS object generation."
  }

  validation {
    condition = var.boundary.qualification == "DISABLED" || try(
      var.protected_inputs.cache_bucket_name == "${var.protected_inputs.project_id}-nix-cache-${var.boundary.namespace.namespace_epoch}" &&
      var.protected_inputs.health_bucket_name == "${var.protected_inputs.project_id}-nix-cache-health-${var.boundary.namespace.namespace_epoch}" &&
      var.protected_inputs.operation_bucket_name == "${var.protected_inputs.project_id}-nix-cache-operation-${var.boundary.namespace.namespace_epoch}",
      false,
    )
    error_message = "Connected cache, health, and operation buckets must be immutable project-and-namespace-epoch names."
  }
}

variable "gateway" {
  description = "Nix-compatible authenticated HTTPS gateway contract."
  type = object({
    hostname        = string
    scheme          = string
    allowed_methods = list(string)
    authentication  = string
    implementation  = string
  })

  validation {
    condition = (
      var.gateway.hostname == "nix-cache.mindclade.com" &&
      var.gateway.scheme == "https" &&
      length(var.gateway.allowed_methods) == 2 &&
      var.gateway.allowed_methods[0] == "GET" &&
      var.gateway.allowed_methods[1] == "HEAD" &&
      var.gateway.authentication == "google-oidc-bearer-or-netrc" &&
      var.gateway.implementation == "external-managed-https-gateway"
    )
    error_message = "The Nix gateway must remain an authenticated external managed HTTPS endpoint accepting only GET and HEAD."
  }
}

variable "quotas" {
  description = "Gateway and publisher enforcement contract consumed by the connected edge implementation."
  type = object({
    publisher_writes_per_minute = number
    gateway_reads_per_minute    = number
    maximum_cache_bytes         = number
  })

  validation {
    condition = (
      var.quotas.publisher_writes_per_minute == 600 &&
      var.quotas.gateway_reads_per_minute == 6000 &&
      var.quotas.maximum_cache_bytes == 1099511627776
    )
    error_message = "Cache quotas must match the reviewed 600 write/minute, 6000 read/minute, and 1 TiB contract."
  }
}

variable "legacy_v1_compatibility_enabled" {
  description = "Legacy cache-boundary.v1 compatibility is permanently disabled."
  type        = bool
  default     = false

  validation {
    condition     = !var.legacy_v1_compatibility_enabled
    error_message = "cache-boundary.v1 compatibility may not be enabled."
  }
}
