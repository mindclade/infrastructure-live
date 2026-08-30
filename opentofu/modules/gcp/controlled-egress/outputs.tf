output "router_id" { value = var.enabled && var.manage_nat ? google_compute_router.this[0].id : null }
output "nat_id" { value = var.enabled && var.manage_nat ? google_compute_router_nat.this[0].id : null }
output "egress_addresses" { value = var.enabled && var.manage_nat ? google_compute_address.nat[*].address : [] }
