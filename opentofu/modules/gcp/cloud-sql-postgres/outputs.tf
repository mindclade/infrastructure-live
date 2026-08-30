output "instance_id" { value = var.enabled ? google_sql_database_instance.this[0].id : null }
output "connection_name" { value = var.enabled ? google_sql_database_instance.this[0].connection_name : null }
output "private_ip_address" {
  value     = var.enabled ? google_sql_database_instance.this[0].private_ip_address : null
  sensitive = true
}
