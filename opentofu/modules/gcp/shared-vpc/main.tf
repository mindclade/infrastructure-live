locals {
  network_reference = var.enabled ? "projects/${var.project_id}/global/networks/${var.network_name}" : null
}

resource "google_compute_network" "this" {
  count = var.enabled ? 1 : 0

  project                 = var.project_id
  name                    = var.network_name
  auto_create_subnetworks = false
  routing_mode            = var.routing_mode
  mtu                     = 1460

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = var.private_service_access != null
      error_message = "An explicit private service access allocation is required before network activation."
    }
  }
}

resource "google_compute_shared_vpc_host_project" "this" {
  count = var.enabled ? 1 : 0

  project    = var.project_id
  depends_on = [google_compute_network.this]
}

resource "google_compute_shared_vpc_service_project" "this" {
  for_each = var.enabled ? var.service_project_ids : toset([])

  host_project    = var.project_id
  service_project = each.value

  depends_on = [google_compute_shared_vpc_host_project.this]

  lifecycle {
    prevent_destroy = true
    precondition {
      condition     = each.value != var.project_id
      error_message = "A Shared VPC service project must differ from its host project."
    }
  }
}

resource "google_compute_subnetwork" "this" {
  for_each = var.enabled ? var.subnets : {}

  project                  = var.project_id
  name                     = each.key
  region                   = each.value.region
  network                  = local.network_reference
  ip_cidr_range            = each.value.cidr
  private_ip_google_access = each.value.private_google_access
  stack_type               = "IPV4_ONLY"

  dynamic "secondary_ip_range" {
    for_each = each.value.secondary_ranges
    content {
      range_name    = secondary_ip_range.key
      ip_cidr_range = secondary_ip_range.value
    }
  }

  dynamic "log_config" {
    for_each = each.value.flow_logs ? [1] : []
    content {
      aggregation_interval = "INTERVAL_5_SEC"
      flow_sampling        = 0.5
      metadata             = "INCLUDE_ALL_METADATA"
    }
  }

  depends_on = [google_compute_network.this]

  lifecycle { prevent_destroy = true }
}

resource "google_compute_firewall" "deny_ingress" {
  count = var.enabled ? 1 : 0

  project       = var.project_id
  name          = "${var.network_name}-deny-ingress"
  network       = local.network_reference
  direction     = "INGRESS"
  priority      = 65534
  source_ranges = ["0.0.0.0/0"]

  deny { protocol = "all" }
  log_config { metadata = "INCLUDE_ALL_METADATA" }

  depends_on = [google_compute_network.this]
}

resource "google_compute_global_address" "private_services" {
  count = var.enabled ? 1 : 0

  project       = var.project_id
  name          = "${var.network_name}-private-services"
  purpose       = "VPC_PEERING"
  address_type  = "INTERNAL"
  network       = local.network_reference
  address       = var.private_service_access.address
  prefix_length = var.private_service_access.prefix_length

  depends_on = [google_compute_network.this]

  lifecycle { prevent_destroy = true }
}

resource "google_service_networking_connection" "private_services" {
  count = var.enabled ? 1 : 0

  network                 = local.network_reference
  service                 = "servicenetworking.googleapis.com"
  reserved_peering_ranges = [google_compute_global_address.private_services[0].name]

  depends_on = [google_compute_network.this]

  lifecycle { prevent_destroy = true }
}
