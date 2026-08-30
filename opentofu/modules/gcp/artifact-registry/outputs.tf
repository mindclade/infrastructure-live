output "repository_ids" { value = var.enabled ? { for name, repository in google_artifact_registry_repository.this : name => repository.id } : {} }
output "repository_locations" { value = var.enabled ? { for name, repository in google_artifact_registry_repository.this : name => repository.location } : {} }
