locals {
  access = {
    for entry in flatten(concat([
      for bucket, members in var.readers : [for member in members : { key = "${bucket}-reader-${sha256(member)}", bucket = bucket, role = "roles/storage.objectViewer", member = member }]
      ], [
      for bucket, members in var.writers : [for member in members : { key = "${bucket}-writer-${sha256(member)}", bucket = bucket, role = "roles/storage.objectCreator", member = member }]
    ])) : entry.key => entry
  }
}

resource "google_storage_bucket" "this" {
  for_each = var.enabled ? var.buckets : {}

  project                     = var.project_id
  name                        = each.key
  location                    = each.value.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"
  force_destroy               = false
  labels                      = each.value.labels

  versioning { enabled = true }
  encryption { default_kms_key_name = each.value.kms_key_name }
  soft_delete_policy { retention_duration_seconds = each.value.soft_delete_days * 86400 }
  retention_policy {
    retention_period = each.value.retention_days * 86400
    is_locked        = each.value.lock_retention
  }
  lifecycle_rule {
    condition { days_since_noncurrent_time = each.value.noncurrent_version_days }
    action { type = "Delete" }
  }

  lifecycle { prevent_destroy = true }
}

resource "google_storage_bucket_iam_member" "access" {
  for_each = var.enabled ? local.access : {}

  bucket = each.value.bucket
  role   = each.value.role
  member = each.value.member

  depends_on = [google_storage_bucket.this]
}
