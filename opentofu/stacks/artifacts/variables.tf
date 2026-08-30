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
