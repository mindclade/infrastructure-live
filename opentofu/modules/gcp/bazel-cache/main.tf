terraform {
  required_providers {
    google = {
      source = "hashicorp/google"
    }
  }
}

locals {
  qualified = contains(["IAM_QUALIFIED", "WRITE_ACTIVATED"], var.boundary.qualification)
  connected = var.enabled && local.qualified

  # A disabled cache must carry no protected identifier at all; a connected one
  # must carry every identifier its qualification level requires. Write
  # principals appear only at WRITE_ACTIVATED, so a read-qualified cache cannot
  # be silently promoted by adding a principal.
  protected_inputs_bound = alltrue([
    var.protected_inputs.project_id != null,
    var.protected_inputs.cache_bucket_name != null,
    var.protected_inputs.operation_bucket_name != null,
    var.protected_inputs.external_audit_bucket_name != null,
    var.protected_inputs.iam_qualification_evidence_locator != null,
    length(var.protected_inputs.reader_wif_principal_sets) > 0,
    var.boundary.qualification != "WRITE_ACTIVATED" || (
      var.protected_inputs.write_activation_evidence_locator != null &&
      length(var.protected_inputs.writer_wif_principal_sets) > 0
    ),
    var.boundary.qualification == "WRITE_ACTIVATED" || length(var.protected_inputs.writer_wif_principal_sets) == 0,
  ])

  project_id = local.connected ? var.protected_inputs.project_id : null

  bucket_contracts = local.connected ? {
    cache = {
      name           = var.protected_inputs.cache_bucket_name
      retention_days = var.quotas.cache_retention_days
      purpose        = "bazel-cache"
    }
    operation = {
      name           = var.protected_inputs.operation_bucket_name
      retention_days = var.quotas.operation_retention_days
      purpose        = "cache-operation-evidence"
    }
  } : {}

  writer_principal = local.connected ? "serviceAccount:${google_service_account.writer[0].email}" : null
  reader_principal = local.connected ? "serviceAccount:${google_service_account.reader[0].email}" : null
}

resource "google_kms_key_ring" "cache" {
  count = local.connected ? 1 : 0

  project  = local.project_id
  name     = "bazel-cache-${var.boundary.namespace.namespace_epoch}"
  location = var.location

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = local.protected_inputs_bound
      error_message = "No Bazel cache resource may connect until every protected identifier and qualification input is bound."
    }
  }
}

resource "google_kms_crypto_key" "cache" {
  for_each = local.connected ? toset(["cache", "operation"]) : toset([])

  name                       = each.value
  key_ring                   = google_kms_key_ring.cache[0].id
  purpose                    = "ENCRYPT_DECRYPT"
  rotation_period            = "7776000s"
  destroy_scheduled_duration = "2592000s"
  deletion_policy            = "PREVENT"
  labels = {
    data_classification = "internal"
    environment         = var.environment
    owner               = "platform"
    purpose             = "bazel-${each.value}"
  }

  lifecycle { prevent_destroy = true }
}

data "google_storage_project_service_account" "cache" {
  count = local.connected ? 1 : 0

  project = local.project_id
}

resource "google_kms_crypto_key_iam_member" "storage" {
  for_each = local.connected ? google_kms_crypto_key.cache : {}

  crypto_key_id = each.value.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.cache[0].email_address}"
}

resource "google_storage_bucket" "cache" {
  for_each = local.bucket_contracts

  project                     = local.project_id
  name                        = each.value.name
  location                    = var.location
  storage_class               = "STANDARD"
  uniform_bucket_level_access = true
  # The estate's repositories are internal or private. Cache contents derive
  # from that source, so the cache is never anonymously readable; pull-request
  # readers authenticate through their own workload identity.
  public_access_prevention = "enforced"
  force_destroy            = false

  encryption { default_kms_key_name = google_kms_crypto_key.cache[each.key].id }
  versioning { enabled = true }
  soft_delete_policy { retention_duration_seconds = 2592000 }

  dynamic "retention_policy" {
    for_each = each.value.retention_days > 0 ? [each.value.retention_days] : []
    content {
      retention_period = retention_policy.value * 86400
      is_locked        = false
    }
  }

  lifecycle_rule {
    condition { days_since_noncurrent_time = 7 }
    action { type = "Delete" }
  }

  labels = {
    data_classification = "internal"
    environment         = var.environment
    namespace_epoch     = var.boundary.namespace.namespace_epoch
    owner               = "platform"
    purpose             = each.value.purpose
  }

  depends_on = [google_kms_crypto_key_iam_member.storage]

  lifecycle { prevent_destroy = true }
}

resource "google_service_account" "writer" {
  count = local.connected ? 1 : 0

  project         = local.project_id
  account_id      = "bazel-cache-writer"
  display_name    = "Bazel cache create-only writer for protected builds"
  deletion_policy = "PREVENT"

  lifecycle { prevent_destroy = true }
}

resource "google_service_account" "reader" {
  count = local.connected ? 1 : 0

  project         = local.project_id
  account_id      = "bazel-cache-reader"
  display_name    = "Bazel cache authenticated read-only consumer"
  deletion_policy = "PREVENT"

  lifecycle { prevent_destroy = true }
}

# objectCreator, never objectAdmin: a protected build may add an entry and can
# neither overwrite nor delete one, so a poisoned entry cannot replace a good one.
resource "google_storage_bucket_iam_member" "writer_create_only" {
  for_each = local.connected && var.boundary.qualification == "WRITE_ACTIVATED" ? local.bucket_contracts : {}

  bucket = google_storage_bucket.cache[each.key].name
  role   = "roles/storage.objectCreator"
  member = local.writer_principal
}

# Readers see only the cache bucket. Operation evidence is not readable by the
# pull-request identity.
resource "google_storage_bucket_iam_member" "reader_read_only" {
  count = local.connected ? 1 : 0

  bucket = google_storage_bucket.cache["cache"].name
  role   = "roles/storage.objectViewer"
  member = local.reader_principal
}

resource "google_service_account_iam_member" "writer_wif" {
  for_each = local.connected && var.boundary.qualification == "WRITE_ACTIVATED" ? var.protected_inputs.writer_wif_principal_sets : toset([])

  service_account_id = google_service_account.writer[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value
}

resource "google_service_account_iam_member" "reader_wif" {
  for_each = local.connected ? var.protected_inputs.reader_wif_principal_sets : toset([])

  service_account_id = google_service_account.reader[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value
}

resource "google_project_iam_audit_config" "cache_storage" {
  count = local.connected ? 1 : 0

  project = local.project_id
  service = "storage.googleapis.com"
  audit_log_config { log_type = "ADMIN_READ" }
  audit_log_config { log_type = "DATA_READ" }
  audit_log_config { log_type = "DATA_WRITE" }

  lifecycle { prevent_destroy = true }
}

resource "google_logging_project_sink" "cache_external_audit" {
  count = local.connected ? 1 : 0

  project                = local.project_id
  name                   = "bazel-cache-external-audit"
  destination            = "storage.googleapis.com/${var.protected_inputs.external_audit_bucket_name}"
  unique_writer_identity = true
  filter = join("\n", [
    "resource.type=\"gcs_bucket\"",
    "resource.labels.bucket_name=(\"${var.protected_inputs.cache_bucket_name}\" OR \"${var.protected_inputs.operation_bucket_name}\")",
    "(log_id(\"cloudaudit.googleapis.com/activity\") OR log_id(\"cloudaudit.googleapis.com/data_access\"))",
  ])

  lifecycle { prevent_destroy = true }
}
