resource "google_dns_managed_zone" "private" {
  for_each = var.enabled ? var.zones : {}

  project     = var.project_id
  name        = each.key
  dns_name    = each.value.dns_name
  description = each.value.description
  visibility  = "private"
  labels      = each.value.labels

  private_visibility_config {
    dynamic "networks" {
      for_each = each.value.network_urls
      content { network_url = networks.value }
    }
  }

  lifecycle { prevent_destroy = true }
}
