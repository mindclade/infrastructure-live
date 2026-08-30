module "kms" {
  source = "../../modules/gcp/delegated-kms"

  enabled       = var.enabled
  project_id    = try(var.config.project_id, null)
  location      = var.primary_location
  key_ring_name = try(var.config.key_ring_name, null)
  keys = {
    for name, key in var.config.keys : name => merge(key, {
      labels = merge(key.labels, { environment = var.environment })
    })
  }
}

module "registry" {
  source = "../../modules/gcp/artifact-registry"

  depends_on = [module.kms]

  enabled    = var.enabled
  project_id = try(var.config.project_id, null)
  repositories = {
    for name, repository in var.config.repositories : name => merge(repository, {
      kms_key_name = module.kms.key_ids[repository.key_name]
      location     = var.primary_location
      labels       = merge(repository.labels, { environment = var.environment })
    })
  }
  readers = var.config.repository_readers
  writers = var.config.repository_writers
}

module "buckets" {
  source = "../../modules/gcp/artifact-bucket"

  depends_on = [module.kms]

  enabled    = var.enabled
  project_id = try(var.config.project_id, null)
  buckets = {
    for name, bucket in var.config.buckets : name => merge(bucket, {
      kms_key_name = module.kms.key_ids[bucket.key_name]
      location     = var.primary_location
      labels       = merge(bucket.labels, { environment = var.environment })
    })
  }
  readers = var.config.bucket_readers
  writers = var.config.bucket_writers
}

locals {
  ci_evidence_archive_enabled       = var.enabled && try(var.ci_evidence_archive_profile.enabled, false)
  ci_evidence_identity_project      = try(var.config.ci_evidence_archive.identity_project_id, null)
  ci_evidence_audit_sink_mode       = try(var.config.ci_evidence_archive.audit_sink_binding_mode, "discover")
  ci_evidence_audit_sink_writer     = try(var.config.ci_evidence_archive.audit_sink_writer_identity, null)
  ci_evidence_notification_channels = try(var.config.ci_evidence_archive.audit_notification_channels, [])
  ci_evidence_inventory_schedule    = try(var.config.ci_evidence_archive.inventory_schedule, null)
  ci_evidence_archive_connected = local.ci_evidence_archive_enabled && alltrue([
    try(var.config.project_id, null) != null,
    local.ci_evidence_identity_project != null,
    local.ci_evidence_inventory_schedule != null,
    length(local.ci_evidence_notification_channels) > 0,
    local.ci_evidence_audit_sink_mode == "discover" || local.ci_evidence_audit_sink_writer != null,
  ])
  ci_evidence_bucket_name           = local.ci_evidence_archive_connected ? "${var.config.project_id}-production-ci-evidence" : null
  ci_evidence_target_project_number = local.ci_evidence_archive_connected ? tostring(data.google_project.ci_evidence_archive_target[0].number) : null
  ci_evidence_storage_agent         = local.ci_evidence_archive_connected ? "serviceAccount:service-${local.ci_evidence_target_project_number}@gs-project-accounts.iam.gserviceaccount.com" : null
  ci_evidence_insights_agent        = local.ci_evidence_archive_connected ? "serviceAccount:service-${local.ci_evidence_target_project_number}@gcp-sa-storageinsights.iam.gserviceaccount.com" : null
  ci_evidence_writer                = local.ci_evidence_archive_connected ? "serviceAccount:ci-evidence-writer@${local.ci_evidence_identity_project}.iam.gserviceaccount.com" : null
  ci_evidence_verifier              = local.ci_evidence_archive_connected ? "serviceAccount:ci-evidence-verifier@${local.ci_evidence_identity_project}.iam.gserviceaccount.com" : null
  ci_evidence_audit_sink_name       = "mindclade-ci-evidence-audit"
  ci_evidence_audit_filter = local.ci_evidence_archive_connected ? join("\n", [
    "resource.type=\"gcs_bucket\"",
    "resource.labels.bucket_name=\"${local.ci_evidence_bucket_name}\"",
    "(log_id(\"cloudaudit.googleapis.com/activity\") OR log_id(\"cloudaudit.googleapis.com/data_access\"))",
  ]) : null
  ci_evidence_lock_receipt = try(var.ci_evidence_archive_profile.retentionLockReceipt, null)
}

data "google_project" "ci_evidence_archive_target" {
  count = local.ci_evidence_archive_connected ? 1 : 0

  project_id = var.config.project_id
}

module "ci_evidence_archive_kms" {
  source = "../../modules/gcp/delegated-kms"

  enabled       = local.ci_evidence_archive_connected
  project_id    = try(var.config.project_id, null)
  location      = local.ci_evidence_archive_connected ? lower(var.ci_evidence_archive_profile.location) : null
  key_ring_name = local.ci_evidence_archive_connected ? "ci-evidence" : null
  keys = local.ci_evidence_archive_connected ? {
    archive = {
      protection_level = var.ci_evidence_archive_profile.kmsProtectionLevel
      rotation_period  = var.ci_evidence_archive_profile.kmsRotationPeriod
      labels = {
        data_classification = "internal"
        environment         = var.environment
        owner               = "platform-operations"
        purpose             = "ci-evidence"
      }
      encrypter_decrypters = [local.ci_evidence_storage_agent]
    }
  } : {}
}

module "ci_evidence_archive_bucket" {
  source = "../../modules/gcp/artifact-bucket"

  depends_on = [module.ci_evidence_archive_kms]

  enabled    = local.ci_evidence_archive_connected
  project_id = try(var.config.project_id, null)
  buckets = local.ci_evidence_archive_connected ? {
    (local.ci_evidence_bucket_name) = {
      location                = var.ci_evidence_archive_profile.location
      storage_class           = var.ci_evidence_archive_profile.storageClass
      rpo                     = var.ci_evidence_archive_profile.replicationMode
      kms_key_name            = module.ci_evidence_archive_kms.key_ids["archive"]
      retention_days          = var.ci_evidence_archive_profile.retentionDays
      lock_retention          = var.ci_evidence_archive_profile.retentionLocked
      soft_delete_days        = var.ci_evidence_archive_profile.softDeleteDays
      versioning_enabled      = var.ci_evidence_archive_profile.versioningEnabled
      noncurrent_version_days = 365
      archive_after_days      = var.ci_evidence_archive_profile.archiveAfterDays
      archive_minimum_bytes   = var.ci_evidence_archive_profile.archiveMinimumSizeBytes
      delete_after_days       = var.ci_evidence_archive_profile.deleteAfterDays
      require_lock_receipt    = true
      retention_lock_verifier = local.ci_evidence_verifier
      retention_lock_receipt  = local.ci_evidence_lock_receipt
      labels = {
        data_classification = "internal"
        environment         = var.environment
        owner               = "platform-operations"
        purpose             = "ci-evidence"
        security_owner      = "security"
      }
    }
  } : {}
  readers = local.ci_evidence_archive_connected ? {
    (local.ci_evidence_bucket_name) = [local.ci_evidence_verifier]
  } : {}
  writers = local.ci_evidence_archive_connected ? {
    (local.ci_evidence_bucket_name) = compact([
      local.ci_evidence_writer,
      local.ci_evidence_insights_agent,
    ])
  } : {}
  insights_collectors = local.ci_evidence_archive_connected ? {
    (local.ci_evidence_bucket_name) = [local.ci_evidence_insights_agent]
  } : {}
}

resource "google_project_iam_audit_config" "ci_evidence_storage" {
  count = local.ci_evidence_archive_connected ? 1 : 0

  project = var.config.project_id
  service = "storage.googleapis.com"

  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }

  lifecycle { prevent_destroy = true }
}

resource "google_logging_project_sink" "ci_evidence_audit" {
  count = local.ci_evidence_archive_connected ? 1 : 0

  project                = var.config.project_id
  name                   = local.ci_evidence_audit_sink_name
  destination            = "storage.googleapis.com/${local.ci_evidence_bucket_name}"
  filter                 = local.ci_evidence_audit_filter
  unique_writer_identity = true

  depends_on = [module.ci_evidence_archive_bucket]

  lifecycle { prevent_destroy = true }
}

data "google_logging_sink" "ci_evidence_audit" {
  count = local.ci_evidence_archive_connected && local.ci_evidence_audit_sink_mode == "enforce" ? 1 : 0

  id = "projects/${var.config.project_id}/sinks/${local.ci_evidence_audit_sink_name}"
}

resource "google_storage_bucket_iam_member" "ci_evidence_audit_sink_writer" {
  count = local.ci_evidence_archive_connected && local.ci_evidence_audit_sink_mode == "enforce" ? 1 : 0

  bucket = local.ci_evidence_bucket_name
  role   = "roles/storage.objectCreator"
  member = local.ci_evidence_audit_sink_writer

  depends_on = [module.ci_evidence_archive_bucket, google_logging_project_sink.ci_evidence_audit]

  lifecycle {
    precondition {
      condition = (
        local.ci_evidence_audit_sink_writer == google_logging_project_sink.ci_evidence_audit[0].writer_identity &&
        local.ci_evidence_audit_sink_writer == data.google_logging_sink.ci_evidence_audit[0].writer_identity
      )
      error_message = "The audit sink receives object-create access only after the configured principal matches both the managed and independently rediscovered provider-issued identities."
    }
  }
}

resource "google_logging_metric" "ci_evidence_security_event" {
  count = local.ci_evidence_archive_connected ? 1 : 0

  project = var.config.project_id
  name    = "ci_evidence_archive_security_event"
  filter  = "${local.ci_evidence_audit_filter}\n(protoPayload.methodName=~\"storage\\.(buckets\\.(delete|lockRetentionPolicy|setIamPolicy|update)|objects\\.delete)\" OR protoPayload.status.code!=0)"

  metric_descriptor {
    metric_kind  = "DELTA"
    value_type   = "INT64"
    unit         = "1"
    display_name = "CI evidence archive security events"
  }

  lifecycle { prevent_destroy = true }
}

resource "google_monitoring_alert_policy" "ci_evidence_security_event" {
  count = local.ci_evidence_archive_connected ? 1 : 0

  project               = var.config.project_id
  display_name          = "CI evidence archive security event"
  combiner              = "OR"
  enabled               = true
  notification_channels = local.ci_evidence_notification_channels

  conditions {
    display_name = "Archive policy mutation, deletion, or denied access"
    condition_threshold {
      filter          = "metric.type=\"logging.googleapis.com/user/${google_logging_metric.ci_evidence_security_event[0].name}\" AND resource.type=\"gcs_bucket\""
      comparison      = "COMPARISON_GT"
      duration        = "0s"
      threshold_value = 0
      aggregations {
        alignment_period   = "60s"
        per_series_aligner = "ALIGN_SUM"
      }
    }
  }

  alert_strategy { auto_close = "604800s" }
  documentation {
    content   = "Investigate the exact CI evidence archive generation, audit log, IAM policy, retention state, and source plan before acknowledging."
    mime_type = "text/markdown"
  }

  lifecycle { prevent_destroy = true }
}

resource "google_storage_insights_report_config" "ci_evidence_inventory" {
  count = local.ci_evidence_archive_connected ? 1 : 0

  project         = var.config.project_id
  location        = var.ci_evidence_archive_profile.location
  display_name    = "CI evidence archive daily inventory"
  deletion_policy = "PREVENT"
  force_destroy   = false

  frequency_options {
    frequency = "DAILY"
    start_date {
      day   = local.ci_evidence_inventory_schedule.start.day
      month = local.ci_evidence_inventory_schedule.start.month
      year  = local.ci_evidence_inventory_schedule.start.year
    }
    end_date {
      day   = local.ci_evidence_inventory_schedule.end.day
      month = local.ci_evidence_inventory_schedule.end.month
      year  = local.ci_evidence_inventory_schedule.end.year
    }
  }

  csv_options {
    record_separator = "\n"
    delimiter        = ","
    header_required  = true
  }

  object_metadata_report_options {
    metadata_fields = [
      "bucket",
      "crc32c",
      "md5Hash",
      "name",
      "project",
      "retentionExpirationTime",
      "size",
      "storageClass",
      "timeCreated",
      "updated",
    ]
    storage_filters { bucket = local.ci_evidence_bucket_name }
    storage_destination_options {
      bucket           = local.ci_evidence_bucket_name
      destination_path = "inventory/"
    }
  }

  depends_on = [module.ci_evidence_archive_bucket]

  lifecycle { prevent_destroy = true }
}
