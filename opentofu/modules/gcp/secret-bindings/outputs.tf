output "secret_references" {
  description = "Non-sensitive resource references; never secret versions or payloads."
  value       = var.enabled ? { for name, secret in data.google_secret_manager_secret.referenced : name => secret.id } : {}
}
