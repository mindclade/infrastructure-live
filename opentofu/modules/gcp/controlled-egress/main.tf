resource "google_compute_router" "this" {
  count = var.enabled && var.manage_nat ? 1 : 0

  project = var.project_id
  name    = "${var.name}-router"
  region  = var.region
  network = var.network_id
}

resource "google_compute_address" "nat" {
  count = var.enabled && var.manage_nat ? var.nat_ip_count : 0

  project      = var.project_id
  name         = "${var.name}-nat-${count.index}"
  region       = var.region
  address_type = "EXTERNAL"
  network_tier = "PREMIUM"
  labels       = var.labels

  lifecycle { prevent_destroy = true }
}

resource "google_compute_firewall" "allow_egress" {
  for_each = var.enabled ? var.allowed_egress_rules : {}

  project            = var.project_id
  name               = "${var.name}-allow-${each.key}"
  network            = var.network_id
  direction          = "EGRESS"
  priority           = var.allow_priority
  destination_ranges = sort(each.value.destination_cidrs)
  target_tags        = sort(var.target_tags)

  allow {
    protocol = each.value.protocol
    ports    = sort(each.value.ports)
  }

  log_config { metadata = "INCLUDE_ALL_METADATA" }
}

resource "google_compute_firewall" "deny_egress" {
  count = var.enabled ? 1 : 0

  project            = var.project_id
  name               = "${var.name}-deny-unreviewed-egress"
  network            = var.network_id
  direction          = "EGRESS"
  priority           = var.deny_priority
  destination_ranges = ["0.0.0.0/0"]
  target_tags        = sort(var.target_tags)

  deny { protocol = "all" }
  log_config { metadata = "INCLUDE_ALL_METADATA" }

  lifecycle {
    precondition {
      condition     = var.allow_priority < var.deny_priority
      error_message = "The explicit allowlist must have higher precedence than the default-deny rule."
    }
    precondition {
      condition     = !var.require_target_scope || length(var.target_tags) > 0
      error_message = "This egress boundary requires at least one explicit target tag."
    }
    precondition {
      condition     = length(setsubtract(var.required_rule_names, toset(keys(var.allowed_egress_rules)))) == 0
      error_message = "The egress allowlist omits one or more capability-required named rules."
    }
  }
}

resource "google_compute_router_nat" "this" {
  count = var.enabled && var.manage_nat ? 1 : 0

  project                             = var.project_id
  name                                = "${var.name}-nat"
  region                              = var.region
  router                              = google_compute_router.this[0].name
  nat_ip_allocate_option              = "MANUAL_ONLY"
  nat_ips                             = google_compute_address.nat[*].self_link
  source_subnetwork_ip_ranges_to_nat  = "LIST_OF_SUBNETWORKS"
  enable_endpoint_independent_mapping = false
  min_ports_per_vm                    = 256

  dynamic "subnetwork" {
    for_each = var.subnetwork_ids
    content {
      name                    = subnetwork.value
      source_ip_ranges_to_nat = ["ALL_IP_RANGES"]
    }
  }

  log_config {
    enable = true
    filter = "ALL"
  }
}
