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
variable "ci_evidence_archive_profile" {
  description = "Catalog-owned production CI evidence archive policy and its sole location override."
  type = object({
    enabled            = bool
    location           = string
    storageClass       = string
    replicationMode    = string
    kmsProtectionLevel = string
    kmsRotationPeriod  = string
    retentionDays      = number
    retentionLocked    = bool
    retentionLockReceipt = optional(object({
      receiptVersion           = string
      canaryObjectUri          = string
      canaryGeneration         = string
      verifierIdentity         = string
      verifierDigest           = string
      denialEvidenceDigest     = string
      auditEvidenceDigest      = string
      platformApprovalIdentity = string
      securityApprovalIdentity = string
      approvedAt               = string
      sourceCommit             = string
      receiptDigest            = string
    }))
    softDeleteDays          = number
    versioningEnabled       = bool
    archiveAfterDays        = number
    archiveMinimumSizeBytes = number
    deleteAfterDays         = number
  })
  default  = null
  nullable = true
  validation {
    condition = var.ci_evidence_archive_profile == null || (
      var.ci_evidence_archive_profile.location == "NAM4" &&
      var.ci_evidence_archive_profile.storageClass == "STANDARD" &&
      var.ci_evidence_archive_profile.replicationMode == "DEFAULT" &&
      var.ci_evidence_archive_profile.kmsProtectionLevel == "SOFTWARE" &&
      var.ci_evidence_archive_profile.kmsRotationPeriod == "7776000s" &&
      var.ci_evidence_archive_profile.retentionDays == 2555 &&
      var.ci_evidence_archive_profile.softDeleteDays == 30 &&
      !var.ci_evidence_archive_profile.versioningEnabled &&
      var.ci_evidence_archive_profile.archiveAfterDays == 90 &&
      var.ci_evidence_archive_profile.archiveMinimumSizeBytes == 1048576 &&
      var.ci_evidence_archive_profile.deleteAfterDays == var.ci_evidence_archive_profile.retentionDays &&
      !var.ci_evidence_archive_profile.retentionLocked &&
      try(var.ci_evidence_archive_profile.retentionLockReceipt == null, true)
    )
    error_message = "The CI evidence archive must match the catalog-approved NAM4, CMEK, unlocked retention, recovery, and lifecycle contract; no self-asserted retention-lock receipt is accepted."
  }
}

variable "nix_cache" {
  description = "Fail-closed development Nix cache boundary and protected activation inputs."
  type = object({
    enabled = bool
    boundary = object({
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
    protected_inputs = object({
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
    gateway = object({
      hostname        = string
      scheme          = string
      allowed_methods = list(string)
      authentication  = string
      implementation  = string
    })
    quotas = object({
      publisher_writes_per_minute = number
      gateway_reads_per_minute    = number
      maximum_cache_bytes         = number
    })
    legacy_v1_compatibility_enabled = bool
  })
  default = {
    enabled = false
    boundary = {
      schema_version             = "cache-boundary.v2"
      qualification              = "DISABLED"
      source_revision            = null
      cache_mode                 = "disabled"
      cache_used                 = false
      cache_outputs_are_evidence = false
      endpoint                   = null
      namespace = {
        schema_version   = "cache-namespace.v2"
        classification   = "internal"
        namespace_epoch  = "disabled-v2"
        trust_class      = "untrusted"
        system           = "aarch64-linux"
        toolchain_digest = null
        build_mode       = "cacheless"
      }
      iam_qualification_digest = null
      write_activation_digest  = null
      signer_public_key_digest = null
      audit_sink_digest        = null
      cacheless_canary = {
        required         = true
        status           = "NOT_RUN"
        evidence_locator = null
        evidence_digest  = null
      }
      poison_recovery = {
        required         = true
        status           = "NOT_RUN"
        runbook          = "runbooks/nix-cache-recovery.md"
        evidence_locator = null
        evidence_digest  = null
      }
    }
    protected_inputs = {
      project_id                         = null
      cache_bucket_name                  = null
      health_bucket_name                 = null
      operation_bucket_name              = null
      external_audit_bucket_name         = null
      signer_secret_resource             = null
      iam_qualification_evidence_locator = null
      write_activation_evidence_locator  = null
      publisher_wif_principal_sets       = []
      gateway_wif_principal_sets         = []
    }
    gateway = {
      hostname        = "nix-cache.mindclade.com"
      scheme          = "https"
      allowed_methods = ["GET", "HEAD"]
      authentication  = "google-oidc-bearer-or-netrc"
      implementation  = "external-managed-https-gateway"
    }
    quotas = {
      publisher_writes_per_minute = 600
      gateway_reads_per_minute    = 6000
      maximum_cache_bytes         = 1099511627776
    }
    legacy_v1_compatibility_enabled = false
  }
}
variable "config" {
  type = object({
    project_id    = optional(string)
    location      = optional(string)
    key_ring_name = optional(string)
    keys = optional(map(object({
      purpose                    = optional(string, "ENCRYPT_DECRYPT")
      rotation_period            = optional(string, "7776000s")
      destroy_scheduled_duration = optional(string, "2592000s")
      labels                     = optional(map(string), {})
      encrypter_decrypters       = optional(set(string), [])
    })), {})
    repositories = optional(map(object({
      location       = string
      format         = optional(string, "DOCKER")
      description    = optional(string, "Mindclade immutable artifacts")
      key_name       = string
      immutable_tags = optional(bool, true)
      labels         = optional(map(string), {})
    })), {})
    buckets = optional(map(object({
      location                = string
      key_name                = string
      retention_days          = number
      lock_retention          = optional(bool, false)
      soft_delete_days        = optional(number, 30)
      noncurrent_version_days = optional(number, 365)
      labels                  = optional(map(string), {})
    })), {})
    repository_readers = optional(map(set(string)), {})
    repository_writers = optional(map(set(string)), {})
    bucket_readers     = optional(map(set(string)), {})
    bucket_writers     = optional(map(set(string)), {})
    ci_evidence_archive = optional(object({
      identity_project_id         = optional(string)
      audit_sink_binding_mode     = optional(string, "discover")
      audit_sink_writer_identity  = optional(string)
      audit_notification_channels = optional(set(string), [])
      inventory_schedule = optional(object({
        start = object({ day = number, month = number, year = number })
        end   = object({ day = number, month = number, year = number })
      }))
    }), {})
  })
  default = {}
  validation {
    condition = try(var.config.project_id, null) == null || can(regex(
      "^[a-z][a-z0-9-]{4,28}[a-z0-9]$",
      var.config.project_id,
    ))
    error_message = "The artifacts project ID must be null before binding or an exact Google Cloud project ID."
  }
  validation {
    condition = try(var.config.ci_evidence_archive.identity_project_id, null) == null || can(regex(
      "^[a-z][a-z0-9-]{4,28}[a-z0-9]$",
      var.config.ci_evidence_archive.identity_project_id,
    ))
    error_message = "The CI evidence archive identity project must be an explicit Google Cloud project ID."
  }
  validation {
    condition     = contains(["discover", "enforce"], try(var.config.ci_evidence_archive.audit_sink_binding_mode, "discover"))
    error_message = "The archive audit sink binding mode must be discover or enforce."
  }
  validation {
    condition = try(var.config.ci_evidence_archive.audit_sink_writer_identity, null) == null || can(regex(
      "^serviceAccount:[^@[:space:]]+@[^@[:space:]]+\\.iam\\.gserviceaccount\\.com$",
      var.config.ci_evidence_archive.audit_sink_writer_identity,
    ))
    error_message = "The archive audit sink writer must be a reviewed provider-issued service account, never a principal or principalSet."
  }
  validation {
    condition = (
      try(var.config.ci_evidence_archive.audit_sink_binding_mode, "discover") == "discover"
      ? try(var.config.ci_evidence_archive.audit_sink_writer_identity, null) == null
      : try(var.config.ci_evidence_archive.audit_sink_writer_identity, null) != null
    )
    error_message = "Discovery accepts no sink writer identity; enforcement requires the exact reviewed provider-issued identity."
  }
  validation {
    condition = alltrue([
      for channel in try(var.config.ci_evidence_archive.audit_notification_channels, []) : can(regex(
        "^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/notificationChannels/[1-9][0-9]*$",
        channel,
      ))
    ])
    error_message = "Archive audit notification channels must be immutable Google Monitoring channel resource names."
  }
  validation {
    condition = try(var.config.ci_evidence_archive.inventory_schedule, null) == null || (
      var.config.ci_evidence_archive.inventory_schedule.start.year >= 2026 &&
      var.config.ci_evidence_archive.inventory_schedule.end.year <= 2126 &&
      var.config.ci_evidence_archive.inventory_schedule.start.month >= 1 &&
      var.config.ci_evidence_archive.inventory_schedule.start.month <= 12 &&
      var.config.ci_evidence_archive.inventory_schedule.end.month >= 1 &&
      var.config.ci_evidence_archive.inventory_schedule.end.month <= 12 &&
      var.config.ci_evidence_archive.inventory_schedule.start.day >= 1 &&
      var.config.ci_evidence_archive.inventory_schedule.start.day <= 28 &&
      var.config.ci_evidence_archive.inventory_schedule.end.day >= 1 &&
      var.config.ci_evidence_archive.inventory_schedule.end.day <= 28 &&
      format(
        "%04d%02d%02d",
        var.config.ci_evidence_archive.inventory_schedule.start.year,
        var.config.ci_evidence_archive.inventory_schedule.start.month,
        var.config.ci_evidence_archive.inventory_schedule.start.day,
        ) < format(
        "%04d%02d%02d",
        var.config.ci_evidence_archive.inventory_schedule.end.year,
        var.config.ci_evidence_archive.inventory_schedule.end.month,
        var.config.ci_evidence_archive.inventory_schedule.end.day,
      )
    )
    error_message = "The inventory schedule must use valid bounded dates with start before end."
  }
}

variable "bazel_cache" {
  description = "Fail-closed Bazel HTTP cache boundary. Defaults to the disabled state; enabling is an explicit, separately reviewed change."
  type = object({
    enabled = bool
    boundary = object({
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
    protected_inputs = object({
      project_id                         = optional(string)
      cache_bucket_name                  = optional(string)
      operation_bucket_name              = optional(string)
      external_audit_bucket_name         = optional(string)
      iam_qualification_evidence_locator = optional(string)
      write_activation_evidence_locator  = optional(string)
      writer_wif_principal_sets          = optional(set(string), [])
      reader_wif_principal_sets          = optional(set(string), [])
    })
    quotas = object({
      cache_retention_days     = number
      operation_retention_days = number
      max_object_bytes         = number
    })
  })

  default = {
    enabled = false
    boundary = {
      schema_version             = "cache-boundary.v2"
      qualification              = "DISABLED"
      cache_mode                 = "disabled"
      cache_used                 = false
      cache_outputs_are_evidence = false
      namespace = {
        schema_version  = "cache-namespace.v2"
        classification  = "internal"
        namespace_epoch = "e1"
        trust_class     = "protected"
        system          = "x86_64-linux"
        build_mode      = "hermetic"
      }
      cacheable_targets = []
      cacheless_canary = {
        required = true
        status   = "REQUIRED_NOT_RUN"
      }
      poison_recovery = {
        required = true
        status   = "REQUIRED_NOT_EXERCISED"
        runbook  = "runbooks/bazel-cache-recovery.md"
      }
    }
    protected_inputs = {}
    quotas = {
      cache_retention_days     = 30
      operation_retention_days = 400
      max_object_bytes         = 1073741824
    }
  }
}
