output "network_id" { value = var.enabled ? local.network_reference : null }
output "network_name" { value = var.enabled ? google_compute_network.this[0].name : null }
output "service_project_ids" { value = var.enabled ? sort(var.service_project_ids) : [] }
output "subnetwork_ids" { value = var.enabled ? { for name, subnet in google_compute_subnetwork.this : name => subnet.id } : {} }
output "subnetwork_cidrs" { value = var.enabled ? { for name, subnet in google_compute_subnetwork.this : name => subnet.ip_cidr_range } : {} }
output "private_service_connection" { value = var.enabled ? google_service_networking_connection.private_services[0].peering : null }
