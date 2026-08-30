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
    kms_key_name            = string
    retention_days          = number
    lock_retention          = optional(bool, false)
    soft_delete_days        = optional(number, 30)
    noncurrent_version_days = optional(number, 365)
    labels                  = optional(map(string), {})
  }))
  default = {}
  validation {
    condition = !var.enabled || (length(var.buckets) > 0 && alltrue([
      for bucket in values(var.buckets) :
      bucket.kms_key_name != "" &&
      contains(["public", "internal", "confidential", "restricted"], lookup(bucket.labels, "data_classification", "")) &&
      bucket.retention_days >= max(7, lookup({ public = 0, internal = 30, confidential = 90, restricted = 365 }, lookup(bucket.labels, "data_classification", ""), 366)) &&
      bucket.retention_days <= 3650 &&
      (lookup(bucket.labels, "data_classification", "") != "restricted" || bucket.lock_retention) &&
      bucket.soft_delete_days >= 7 && bucket.soft_delete_days <= 90 &&
      bucket.noncurrent_version_days >= 1 && bucket.noncurrent_version_days <= 3650
    ]))
    error_message = "Enabled buckets require CMEK, an approved data classification, 7-3650 day class-minimum retention, locked restricted retention, 7-90 day soft delete, and 1-3650 day noncurrent-version retention."
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
