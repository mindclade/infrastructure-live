output "project_id" {
  description = "Managed project identifier, or null while disabled."
  value       = var.enabled ? google_project.this[0].project_id : null
}

output "project_number" {
  description = "Managed project number, or null while disabled."
  value       = var.enabled ? google_project.this[0].number : null
}

output "enabled_services" {
  description = "Services owned by this module."
  value       = var.enabled ? sort(keys(google_project_service.required)) : []
}
