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
  protected_inputs_bound = alltrue([
    var.protected_inputs.project_id != null,
    var.protected_inputs.cache_bucket_name != null,
    var.protected_inputs.health_bucket_name != null,
    var.protected_inputs.operation_bucket_name != null,
    var.protected_inputs.external_audit_bucket_name != null,
    var.protected_inputs.signer_secret_resource != null,
    var.protected_inputs.iam_qualification_evidence_locator != null,
    length(var.protected_inputs.gateway_wif_principal_sets) > 0,
    var.boundary.qualification != "WRITE_ACTIVATED" || (
      var.protected_inputs.write_activation_evidence_locator != null &&
      length(var.protected_inputs.publisher_wif_principal_sets) > 0
    ),
  ])
  project_id = local.connected ? var.protected_inputs.project_id : null
  bucket_contracts = local.connected ? {
    cache = {
      name           = var.protected_inputs.cache_bucket_name
      retention_days = 30
      key_name       = "cache"
      purpose        = "nix-cache"
    }
    health = {
      name           = var.protected_inputs.health_bucket_name
      retention_days = 90
      key_name       = "health"
      purpose        = "cache-health"
    }
    operation = {
      name           = var.protected_inputs.operation_bucket_name
      retention_days = 400
      key_name       = "operation"
      purpose        = "cache-operation-evidence"
    }
  } : {}
  publisher_principal = local.connected ? "serviceAccount:${google_service_account.publisher[0].email}" : null
  gateway_principal   = local.connected ? "serviceAccount:${google_service_account.gateway[0].email}" : null
}

resource "google_kms_key_ring" "cache" {
  count = local.connected ? 1 : 0

  project  = local.project_id
  name     = "nix-cache-${var.boundary.namespace.namespace_epoch}"
  location = var.location

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = local.protected_inputs_bound
      error_message = "No Nix cache resource may connect until every protected identifier and qualification input is bound."
    }
  }
}

resource "google_kms_crypto_key" "cache" {
  for_each = local.connected ? toset(["cache", "health", "operation"]) : toset([])

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
    purpose             = "nix-${each.value}"
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
  public_access_prevention    = "enforced"
  force_destroy               = false

  encryption { default_kms_key_name = google_kms_crypto_key.cache[each.value.key_name].id }
  versioning { enabled = true }
  soft_delete_policy { retention_duration_seconds = 2592000 }

  dynamic "retention_policy" {
    for_each = each.value.retention_days > 0 ? [each.value.retention_days] : []
    content {
      retention_period = retention_policy.value * 86400
      is_locked        = false
    }
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

resource "google_service_account" "publisher" {
  count = local.connected ? 1 : 0

  project         = local.project_id
  account_id      = "nix-cache-publisher"
  display_name    = "Nix cache create-only publisher"
  deletion_policy = "PREVENT"

  lifecycle { prevent_destroy = true }
}

resource "google_service_account" "gateway" {
  count = local.connected ? 1 : 0

  project         = local.project_id
  account_id      = "nix-cache-gateway"
  display_name    = "Nix cache authenticated read gateway"
  deletion_policy = "PREVENT"

  lifecycle { prevent_destroy = true }
}

resource "google_storage_bucket_iam_member" "publisher_create_only" {
  for_each = local.connected && var.boundary.qualification == "WRITE_ACTIVATED" ? local.bucket_contracts : {}

  bucket = google_storage_bucket.cache[each.key].name
  role   = "roles/storage.objectCreator"
  member = local.publisher_principal
}

resource "google_storage_bucket_iam_member" "gateway_read_only" {
  count = local.connected ? 1 : 0

  bucket = google_storage_bucket.cache["cache"].name
  role   = "roles/storage.objectViewer"
  member = local.gateway_principal
}

resource "google_service_account_iam_member" "publisher_wif" {
  for_each = local.connected && var.boundary.qualification == "WRITE_ACTIVATED" ? var.protected_inputs.publisher_wif_principal_sets : toset([])

  service_account_id = google_service_account.publisher[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = each.value
}

resource "google_service_account_iam_member" "gateway_wif" {
  for_each = local.connected ? var.protected_inputs.gateway_wif_principal_sets : toset([])

  service_account_id = google_service_account.gateway[0].name
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
  name                   = "nix-cache-external-audit"
  destination            = "storage.googleapis.com/${var.protected_inputs.external_audit_bucket_name}"
  unique_writer_identity = true
  filter = join("\n", [
    "resource.type=\"gcs_bucket\"",
    "resource.labels.bucket_name=(\"${var.protected_inputs.cache_bucket_name}\" OR \"${var.protected_inputs.health_bucket_name}\" OR \"${var.protected_inputs.operation_bucket_name}\")",
    "(log_id(\"cloudaudit.googleapis.com/activity\") OR log_id(\"cloudaudit.googleapis.com/data_access\"))",
  ])

  lifecycle { prevent_destroy = true }
}
