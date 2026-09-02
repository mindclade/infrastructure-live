output "repository_ids" { value = module.registry.repository_ids }
output "bucket_ids" { value = module.buckets.bucket_ids }
output "kms_key_ids" { value = module.kms.key_ids }
output "nix_cache" {
  description = "Fail-closed cache-boundary.v2 and non-secret infrastructure handoff."
  value = {
    cache_boundary          = module.nix_cache.cache_boundary
    infrastructure_contract = module.nix_cache.infrastructure_contract
    bucket_ids              = module.nix_cache.bucket_ids
    kms_key_ids             = module.nix_cache.kms_key_ids
  }
}
output "ci_evidence_archive" {
  value = {
    catalog_enabled             = try(var.ci_evidence_archive_profile.enabled, false)
    connected_inputs_bound      = local.ci_evidence_archive_connected
    project_id                  = try(var.config.project_id, null)
    target_project_number       = local.ci_evidence_target_project_number
    identity_project_id         = local.ci_evidence_identity_project
    bucket_name                 = local.ci_evidence_bucket_name
    bucket_ids                  = module.ci_evidence_archive_bucket.bucket_ids
    kms_key_ids                 = module.ci_evidence_archive_kms.key_ids
    location                    = try(var.ci_evidence_archive_profile.location, null)
    storage_service_agent       = local.ci_evidence_storage_agent
    storage_insights_agent      = local.ci_evidence_insights_agent
    writer_principal            = local.ci_evidence_writer
    verifier_principal          = local.ci_evidence_verifier
    audit_sink_binding_mode     = local.ci_evidence_audit_sink_mode
    audit_sink_writer_identity  = local.ci_evidence_archive_connected ? google_logging_project_sink.ci_evidence_audit[0].writer_identity : null
    audit_notification_channels = local.ci_evidence_notification_channels
    audit_sink_id               = local.ci_evidence_archive_connected ? google_logging_project_sink.ci_evidence_audit[0].id : null
    alert_policy_id             = local.ci_evidence_archive_connected ? google_monitoring_alert_policy.ci_evidence_security_event[0].id : null
    inventory_report_id         = local.ci_evidence_archive_connected ? google_storage_insights_report_config.ci_evidence_inventory[0].id : null
    retention_locked            = try(var.ci_evidence_archive_profile.retentionLocked, false)
    retention_lock_receipt      = local.ci_evidence_lock_receipt
  }

  precondition {
    condition = !local.ci_evidence_archive_connected || local.ci_evidence_audit_sink_mode != "enforce" || (
      local.ci_evidence_audit_sink_writer == google_logging_project_sink.ci_evidence_audit[0].writer_identity &&
      local.ci_evidence_audit_sink_writer == data.google_logging_sink.ci_evidence_audit[0].writer_identity
    )
    error_message = "The enforced audit sink writer must exactly match both the managed and independently rediscovered provider-issued identities."
  }

  precondition {
    condition = (
      !try(var.ci_evidence_archive_profile.retentionLocked, false) &&
      local.ci_evidence_lock_receipt == null
    )
    error_message = "Retention lock is intentionally unreachable; a catalog receipt cannot authorize an irreversible provider mutation."
  }
}
