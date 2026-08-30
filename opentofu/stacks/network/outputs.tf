output "network_id" { value = module.shared_vpc.network_id }
output "service_project_ids" { value = module.shared_vpc.service_project_ids }
output "subnetwork_ids" { value = module.shared_vpc.subnetwork_ids }
output "private_service_connection" { value = module.shared_vpc.private_service_connection }
output "private_dns_zone_ids" { value = module.private_dns.zone_ids }
output "egress_addresses" { value = module.egress.egress_addresses }
