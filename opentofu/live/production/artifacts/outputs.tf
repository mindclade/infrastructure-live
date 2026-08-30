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
  }

  precondition {
    condition     = var.enabled == local.region_profile.enabled
    error_message = "Root activation must match the selected catalog region profile state."
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
}
output "resources" { value = module.stack }
