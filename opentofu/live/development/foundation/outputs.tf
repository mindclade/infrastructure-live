output "environment" { value = var.environment }
output "stack" { value = "foundation" }
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
output "resources" { value = module.stack }
