output "environment" { value = var.environment }
output "stack" { value = "artifacts" }
output "enabled" {
  value = var.enabled

  precondition {
    condition = var.enabled == one([
      for environment in yamldecode(file("${path.root}/../../../../catalog/environments.yaml")).environments :
      environment.enabled if environment.name == var.environment
    ])
    error_message = "Root activation must exactly match the authoritative environment catalog entry."
  }
}
output "region_authority" {
  value = {
    primary_location  = local.region_profile.primaryLocation
    recovery_location = local.region_profile.recoveryLocation
    ci_evidence_archive = merge({
      enabled  = local.resource_profile.ciEvidenceArchive.enabled
      location = local.resource_profile.ciEvidenceArchive.location
    }, module.stack.ci_evidence_archive)
  }

  precondition {
    condition     = !var.enabled || local.region_profile.enabled
    error_message = "An enabled root requires its selected catalog region profile to be enabled."
  }
  precondition {
    condition     = var.enabled ? local.region_profile.primaryLocation != null : true
    error_message = "An enabled root requires the selected catalog primary location."
  }
  precondition {
    condition     = local.region_profile.recoveryLocation == null || local.region_profile.recoveryLocation != local.region_profile.primaryLocation
    error_message = "A catalog recovery location must be distinct from the primary location."
  }
  precondition {
    condition = var.enabled ? (
      var.config.location == local.region_profile.primaryLocation &&
      alltrue([for repository in values(var.config.repositories) : repository.location == local.region_profile.primaryLocation]) &&
      alltrue([for bucket in values(var.config.buckets) : bucket.location == local.region_profile.primaryLocation])
    ) : true
    error_message = "All configured locations must equal the authoritative catalog primary location."
  }
  precondition {
    condition = !local.resource_profile.ciEvidenceArchive.enabled || (
      var.enabled &&
      var.config.project_id != null &&
      try(var.config.ci_evidence_archive.identity_project_id, null) != null &&
      try(var.config.ci_evidence_archive.inventory_schedule, null) != null &&
      length(try(var.config.ci_evidence_archive.audit_notification_channels, [])) > 0 &&
      module.stack.ci_evidence_archive.connected_inputs_bound
    )
    error_message = "CI evidence archive activation requires the production root, explicit target and identity projects, provider-derived service agents, an inventory schedule, and alert delivery."
  }
  precondition {
    condition = !local.resource_profile.ciEvidenceArchive.enabled || alltrue([
      for principal in compact([
        module.stack.ci_evidence_archive.storage_service_agent,
        module.stack.ci_evidence_archive.storage_insights_agent,
        module.stack.ci_evidence_archive.writer_principal,
        module.stack.ci_evidence_archive.verifier_principal,
        module.stack.ci_evidence_archive.audit_sink_binding_mode == "enforce" ? module.stack.ci_evidence_archive.audit_sink_writer_identity : null,
      ]) : contains(var.approved_iam_principals, principal)
    ])
    error_message = "Every exact archive service agent, writer, verifier, and enforced sink writer must be present in the environment-wide IAM authority set."
  }
}
output "resources" { value = module.stack }
