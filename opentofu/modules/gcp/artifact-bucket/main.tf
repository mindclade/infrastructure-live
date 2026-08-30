locals {
  access = {
    for entry in flatten(concat([
      for bucket, members in var.readers : [for member in members : { key = "${bucket}-reader-${sha256(member)}", bucket = bucket, role = "roles/storage.objectViewer", member = member }]
      ], [
      for bucket, members in var.writers : [for member in members : { key = "${bucket}-writer-${sha256(member)}", bucket = bucket, role = "roles/storage.objectCreator", member = member }]
      ], [
      for bucket, members in var.insights_collectors : [for member in members : { key = "${bucket}-insights-${sha256(member)}", bucket = bucket, role = "roles/storage.insightsCollectorService", member = member }]
    ])) : entry.key => entry
  }
}

resource "google_storage_bucket" "this" {
  for_each = var.enabled ? var.buckets : {}

  project                     = var.project_id
  name                        = each.key
  location                    = each.value.location
  storage_class               = each.value.storage_class
  rpo                         = each.value.rpo
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = each.value.labels

  versioning { enabled = each.value.versioning_enabled }
  encryption { default_kms_key_name = each.value.kms_key_name }
  soft_delete_policy { retention_duration_seconds = each.value.soft_delete_days * 86400 }
  retention_policy {
    retention_period = each.value.retention_days * 86400
    is_locked        = each.value.lock_retention
  }
  dynamic "lifecycle_rule" {
    for_each = each.value.versioning_enabled ? [true] : []
    content {
      condition { days_since_noncurrent_time = each.value.noncurrent_version_days }
      action { type = "Delete" }
    }
  }
  dynamic "lifecycle_rule" {
    for_each = each.value.archive_after_days == null ? [] : [true]
    content {
      condition {
        age                   = each.value.archive_after_days
        size_above_bytes      = each.value.archive_minimum_bytes
        matches_storage_class = ["STANDARD"]
        with_state            = "LIVE"
      }
      action {
        type          = "SetStorageClass"
        storage_class = "ARCHIVE"
      }
    }
  }
  dynamic "lifecycle_rule" {
    for_each = each.value.delete_after_days == null ? [] : [true]
    content {
      condition {
        age                   = each.value.delete_after_days
        matches_storage_class = ["STANDARD", "ARCHIVE"]
        with_state            = "LIVE"
      }
      action { type = "Delete" }
    }
  }

  lifecycle {
    prevent_destroy = true

    precondition {
      condition     = !each.value.lock_retention
      error_message = "Irreversible retention locking is intentionally unreachable: no operator-supplied receipt is accepted as independent authorization."
    }
  }
}

resource "google_storage_bucket_iam_member" "access" {
  for_each = var.enabled ? local.access : {}

  bucket = each.value.bucket
  role   = each.value.role
  member = each.value.member

  depends_on = [google_storage_bucket.this]
}
