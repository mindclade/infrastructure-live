output "cluster_id" {
  value      = var.enabled ? "projects/${var.project_id}/locations/${var.region}/clusters/${var.name}" : null
  depends_on = [google_container_cluster.this]
}
output "cluster_name" { value = var.enabled ? google_container_cluster.this[0].name : null }
output "endpoint" {
  value     = var.enabled ? google_container_cluster.this[0].endpoint : null
  sensitive = true
}
output "workload_identity_pool" { value = var.enabled ? google_container_cluster.this[0].workload_identity_config[0].workload_pool : null }
