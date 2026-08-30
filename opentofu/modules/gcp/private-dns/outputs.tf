output "zone_ids" { value = var.enabled ? { for name, zone in google_dns_managed_zone.private : name => zone.id } : {} }
output "name_servers" { value = var.enabled ? { for name, zone in google_dns_managed_zone.private : name => zone.name_servers } : {} }
