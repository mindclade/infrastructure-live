output "cache_boundary" {
  description = "Exact non-secret cache-boundary.v2 contract. Cache outputs are never evidence."
  value       = var.boundary

  precondition {
    condition     = var.enabled == local.qualified
    error_message = "The connected resource gate must exactly match read/write cache qualification."
  }
  precondition {
    condition     = !var.enabled || var.environment == "development"
    error_message = "Only the development cache authority may be connected in v2."
  }
  precondition {
    condition = local.qualified ? local.protected_inputs_bound : alltrue([
      var.protected_inputs.project_id == null,
      var.protected_inputs.cache_bucket_name == null,
      var.protected_inputs.operation_bucket_name == null,
      var.protected_inputs.external_audit_bucket_name == null,
      var.protected_inputs.iam_qualification_evidence_locator == null,
      var.protected_inputs.write_activation_evidence_locator == null,
      length(var.protected_inputs.writer_wif_principal_sets) == 0,
      length(var.protected_inputs.reader_wif_principal_sets) == 0,
    ])
    error_message = "Disabled cache source must not contain protected identifiers, evidence locators, or WIF principals."
  }
  precondition {
    # Read qualification must not carry write principals. Promotion to write is a
    # separate reviewed step with its own evidence locator, never a side effect
    # of adding a principal to a read-qualified cache.
    condition     = var.boundary.qualification == "WRITE_ACTIVATED" || length(var.protected_inputs.writer_wif_principal_sets) == 0
    error_message = "Write principals may exist only once the cache is write-activated."
  }
  precondition {
    condition     = !var.boundary.cache_outputs_are_evidence
    error_message = "Cache outputs are accelerators and may never be treated as build or release evidence."
  }
}

output "infrastructure_contract" {
  description = "Non-secret cache activation, IAM, and audit handoff."
  value = {
    endpoint                           = var.boundary.endpoint
    namespace_epoch                    = var.boundary.namespace.namespace_epoch
    cacheable_targets                  = var.boundary.cacheable_targets
    iam_qualification_evidence_locator = var.protected_inputs.iam_qualification_evidence_locator
    iam_qualification_digest           = var.boundary.iam_qualification_digest
    write_activation_evidence_locator  = var.protected_inputs.write_activation_evidence_locator
    write_activation_digest            = var.boundary.write_activation_digest
    audit_sink_writer_identity         = local.connected ? google_logging_project_sink.cache_external_audit[0].writer_identity : null
    writer_principal                   = local.writer_principal
    reader_principal                   = local.reader_principal
    quotas                             = var.quotas
  }
}

output "bucket_ids" {
  description = "Connected cache and operation bucket IDs; empty while disabled."
  value       = { for name, bucket in google_storage_bucket.cache : name => bucket.id }
}

output "kms_key_ids" {
  description = "Connected CMEK resource IDs; empty while disabled."
  value       = { for name, key in google_kms_crypto_key.cache : name => key.id }
}
