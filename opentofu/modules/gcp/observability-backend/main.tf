locals {
  sink_name = "mindclade-central-observability"
}

resource "google_logging_project_bucket_config" "platform" {
  count = var.enabled ? 1 : 0

  project        = var.project_id
  location       = var.location
  bucket_id      = var.bucket_id
  retention_days = var.retention_days
  cmek_settings { kms_key_name = var.kms_key_name }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.retention_days >= var.minimum_retention_days
      error_message = "Log retention must meet the immutable environment minimum before activation."
    }
  }
}

resource "google_logging_project_sink" "source" {
  for_each = var.enabled ? var.source_projects : toset([])

  project                = each.value
  name                   = local.sink_name
  destination            = "logging.googleapis.com/projects/${var.project_id}/locations/${var.location}/buckets/${var.bucket_id}"
  filter                 = var.log_filter
  unique_writer_identity = true

  depends_on = [google_logging_project_bucket_config.platform]
}

data "google_logging_sink" "discovered_source" {
  for_each = var.enabled && var.sink_writer_binding_mode == "enforce" ? var.sink_writer_identities : {}

  id = "projects/${each.key}/sinks/${local.sink_name}"
}

resource "google_project_iam_member" "sink_writer" {
  for_each = var.enabled && var.sink_writer_binding_mode == "enforce" ? var.sink_writer_identities : {}

  project = var.project_id
  role    = "roles/logging.bucketWriter"
  member  = each.value

  lifecycle {
    precondition {
      condition = (
        each.value == data.google_logging_sink.discovered_source[each.key].writer_identity &&
        each.value == google_logging_project_sink.source[each.key].writer_identity
      )
      error_message = "Each approved sink writer must match both the previously discovered sink and the current provider-issued identity."
    }
  }
}

resource "google_monitoring_monitored_project" "source" {
  for_each = var.enabled ? var.source_projects : toset([])

  metrics_scope = var.project_id
  name          = each.value
}
