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
      var.protected_inputs.health_bucket_name == null,
      var.protected_inputs.operation_bucket_name == null,
      var.protected_inputs.external_audit_bucket_name == null,
      var.protected_inputs.signer_secret_resource == null,
      var.protected_inputs.iam_qualification_evidence_locator == null,
      var.protected_inputs.write_activation_evidence_locator == null,
      length(var.protected_inputs.publisher_wif_principal_sets) == 0,
      length(var.protected_inputs.gateway_wif_principal_sets) == 0,
    ])
    error_message = "Disabled cache source must not contain protected identifiers, evidence locators, or WIF principals."
  }
}

output "infrastructure_contract" {
  description = "Non-secret cache activation, gateway, IAM, and audit handoff."
  value = {
    endpoint                           = var.boundary.endpoint
    namespace_epoch                    = var.boundary.namespace.namespace_epoch
    iam_qualification_evidence_locator = var.protected_inputs.iam_qualification_evidence_locator
    iam_qualification_digest           = var.boundary.iam_qualification_digest
    write_activation_evidence_locator  = var.protected_inputs.write_activation_evidence_locator
    write_activation_digest            = var.boundary.write_activation_digest
    signer_public_key_digest           = var.boundary.signer_public_key_digest
    signer_secret_resource             = var.protected_inputs.signer_secret_resource
    audit_sink_digest                  = var.boundary.audit_sink_digest
    audit_sink_writer_identity         = local.connected ? google_logging_project_sink.cache_external_audit[0].writer_identity : null
    publisher_principal                = local.publisher_principal
    gateway_principal                  = local.gateway_principal
    legacy_v1_compatibility_enabled    = var.legacy_v1_compatibility_enabled
    gateway = {
      hostname        = var.gateway.hostname
      endpoint        = var.boundary.endpoint
      scheme          = var.gateway.scheme
      allowed_methods = var.gateway.allowed_methods
      authentication  = var.gateway.authentication
      implementation  = var.gateway.implementation
    }
    quotas = var.quotas
  }
}

output "bucket_ids" {
  description = "Connected cache, health, and operation bucket IDs; empty while disabled."
  value       = { for name, bucket in google_storage_bucket.cache : name => bucket.id }
}

output "kms_key_ids" {
  description = "Connected CMEK resource IDs; empty while disabled."
  value       = { for name, key in google_kms_crypto_key.cache : name => key.id }
}
