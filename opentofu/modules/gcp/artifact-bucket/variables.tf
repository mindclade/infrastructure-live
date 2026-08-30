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
variable "buckets" {
  type = map(object({
    location                = string
    storage_class           = optional(string, "STANDARD")
    rpo                     = optional(string)
    kms_key_name            = string
    retention_days          = number
    lock_retention          = optional(bool, false)
    soft_delete_days        = optional(number, 30)
    versioning_enabled      = optional(bool, true)
    noncurrent_version_days = optional(number, 365)
    archive_after_days      = optional(number)
    archive_minimum_bytes   = optional(number)
    delete_after_days       = optional(number)
    require_lock_receipt    = optional(bool, false)
    retention_lock_verifier = optional(string)
    retention_lock_receipt = optional(object({
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
    labels = optional(map(string), {})
  }))
  default = {}
  validation {
    condition = !var.enabled || (length(var.buckets) > 0 && alltrue([
      for bucket in values(var.buckets) :
      bucket.kms_key_name != "" &&
      bucket.storage_class == "STANDARD" &&
      (bucket.rpo == null || contains(["DEFAULT", "ASYNC_TURBO"], bucket.rpo)) &&
      contains(["public", "internal", "confidential", "restricted"], lookup(bucket.labels, "data_classification", "")) &&
      bucket.retention_days >= max(7, lookup({ public = 0, internal = 30, confidential = 90, restricted = 365 }, lookup(bucket.labels, "data_classification", ""), 366)) &&
      bucket.retention_days <= 3650 &&
      lookup(bucket.labels, "data_classification", "") != "restricted" &&
      !bucket.lock_retention &&
      bucket.soft_delete_days >= 7 && bucket.soft_delete_days <= 90 &&
      bucket.noncurrent_version_days >= 1 && bucket.noncurrent_version_days <= 3650 &&
      ((bucket.archive_after_days == null && bucket.archive_minimum_bytes == null) || (
        try(bucket.archive_after_days >= 1, false) &&
        try(bucket.archive_minimum_bytes >= 1, false)
      )) &&
      (bucket.delete_after_days == null || try(bucket.delete_after_days >= bucket.retention_days, false)) &&
      try(bucket.retention_lock_receipt == null, true)
    ]))
    error_message = "Enabled buckets require Standard storage, an approved replication mode, CMEK, an approved non-restricted data classification, 7-3650 day class-minimum retention, an unlocked retention policy, 7-90 day soft delete, bounded version cleanup, complete Archive transition inputs, deletion no earlier than retention, and no operator-supplied lock receipt. Restricted or locked buckets remain intentionally unreachable pending independent cryptographic authorization."
  }
}
variable "readers" {
  type    = map(set(string))
  default = {}
}
variable "writers" {
  type    = map(set(string))
  default = {}
}
variable "insights_collectors" {
  description = "Exact Storage Insights service agents granted metadata collection, keyed by bucket."
  type        = map(set(string))
  default     = {}
  validation {
    condition = alltrue(flatten([
      for members in values(var.insights_collectors) : [
        for member in members : can(regex(
          "^serviceAccount:service-[1-9][0-9]*@gcp-sa-storageinsights\\.iam\\.gserviceaccount\\.com$",
          member,
        ))
      ]
    ]))
    error_message = "Storage Insights collectors must be exact project-number-derived service agents."
  }
}
