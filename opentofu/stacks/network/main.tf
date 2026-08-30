module "shared_vpc" {
  source = "../../modules/gcp/shared-vpc"

  enabled             = var.enabled
  project_id          = try(var.config.project_id, null)
  network_name        = try(var.config.network_name, null)
  routing_mode        = var.config.routing_mode
  service_project_ids = var.config.service_project_ids
  subnets = {
    for name, subnet in var.config.subnets : name => merge(subnet, {
      region = var.primary_location
    })
  }
  private_service_access = try(var.config.private_service_access, null)
  labels                 = merge(var.config.labels, { environment = var.environment })
}

module "private_dns" {
  source = "../../modules/gcp/private-dns"

  enabled    = var.enabled && length(var.config.private_zones) > 0
  project_id = try(var.config.project_id, null)
  zones = {
    for name, zone in var.config.private_zones : name => merge(zone, {
      network_urls = toset([module.shared_vpc.network_id])
      labels       = merge(zone.labels, { environment = var.environment })
    })
  }
}

module "egress" {
  source = "../../modules/gcp/controlled-egress"

  enabled              = var.enabled
  project_id           = try(var.config.project_id, null)
  region               = var.primary_location
  network_id           = module.shared_vpc.network_id
  subnetwork_ids       = toset(values(module.shared_vpc.subnetwork_ids))
  nat_ip_count         = var.config.nat_ip_count
  allowed_egress_rules = var.config.allowed_egress_rules
  labels               = merge(var.config.labels, { environment = var.environment })
}
