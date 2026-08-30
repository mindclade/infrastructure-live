resource "google_sql_database_instance" "this" {
  count = var.enabled ? 1 : 0

  project             = var.project_id
  name                = var.name
  region              = var.region
  database_version    = var.database_version
  encryption_key_name = var.kms_key_name
  deletion_protection = var.deletion_protection_required

  settings {
    tier                        = var.tier
    availability_type           = var.availability_type
    disk_type                   = "PD_SSD"
    disk_autoresize             = true
    deletion_protection_enabled = var.deletion_protection_required
    user_labels                 = var.labels

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = var.transaction_log_retention_days
      start_time                     = "03:00"

      backup_retention_settings {
        retained_backups = var.backup_retention_days
        retention_unit   = "COUNT"
      }
    }

    ip_configuration {
      ipv4_enabled                                  = false
      private_network                               = var.network_id
      enable_private_path_for_google_cloud_services = true
      ssl_mode                                      = "TRUSTED_CLIENT_CERTIFICATE_REQUIRED"
    }

    insights_config {
      query_insights_enabled  = true
      record_application_tags = true
      record_client_address   = false
    }

    maintenance_window {
      day          = 7
      hour         = 4
      update_track = "stable"
    }
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.backup_retention_days >= var.minimum_backup_retention_days
      error_message = "Backup retention must meet the immutable environment resource profile."
    }
    precondition {
      condition     = !var.high_availability_required || var.availability_type == "REGIONAL"
      error_message = "This environment resource profile requires REGIONAL Cloud SQL availability."
    }
  }
}
