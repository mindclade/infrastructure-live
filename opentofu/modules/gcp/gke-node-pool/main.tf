resource "google_container_node_pool" "this" {
  count = var.enabled ? 1 : 0

  project  = var.project_id
  name     = var.name
  location = var.location
  cluster  = var.cluster_id

  autoscaling {
    total_min_node_count = var.min_nodes
    total_max_node_count = var.max_nodes
    location_policy      = var.spot ? "ANY" : "BALANCED"
  }

  management {
    auto_repair  = true
    auto_upgrade = true
  }

  upgrade_settings {
    strategy        = "SURGE"
    max_surge       = 1
    max_unavailable = 0
  }

  node_config {
    machine_type    = var.machine_type
    disk_type       = var.disk_type
    disk_size_gb    = var.disk_size_gb
    service_account = var.service_account
    oauth_scopes    = ["https://www.googleapis.com/auth/cloud-platform"]
    spot            = var.spot
    labels          = var.labels
    resource_labels = var.resource_labels
    tags            = sort(var.tags)

    metadata = { disable-legacy-endpoints = "true" }
    shielded_instance_config {
      enable_secure_boot          = true
      enable_integrity_monitoring = true
    }
    workload_metadata_config { mode = "GKE_METADATA" }

    dynamic "guest_accelerator" {
      for_each = var.accelerator == null ? [] : [var.accelerator]
      content {
        type  = guest_accelerator.value.type
        count = guest_accelerator.value.count
        gpu_driver_installation_config { gpu_driver_version = guest_accelerator.value.gpu_driver_version }
      }
    }

    dynamic "taint" {
      for_each = var.taints
      content {
        key    = taint.value.key
        value  = taint.value.value
        effect = taint.value.effect
      }
    }
  }

  lifecycle {
    precondition {
      condition     = !var.enabled || alltrue([var.project_id != null, var.cluster_id != null, var.location != null, var.name != null, var.service_account != null])
      error_message = "Project, cluster, location, pool name, and service account must be bound before activation."
    }
    precondition {
      condition     = var.accelerator == null || length(var.taints) > 0
      error_message = "Accelerator pools must be isolated with an explicit taint."
    }
    precondition {
      condition = var.accelerator == null ? var.accelerator_profile == null : (
        var.accelerator_profile != null &&
        try(var.accelerator_profile.enabled, false) &&
        try(var.accelerator_profile.dedicated_node_pool, false) &&
        try(var.accelerator_profile.accelerator_type, "") == var.accelerator.type &&
        try(var.accelerator_profile.accelerator_count, 0) == var.accelerator.count &&
        var.max_nodes <= try(var.accelerator_profile.maximum_nodes, 0) &&
        (!var.spot || try(var.accelerator_profile.spot_permitted, false)) &&
        coalesce(try(var.accelerator_profile.region_binding, null), "") == var.location &&
        coalesce(try(var.accelerator_profile.quota_binding, null), "") != ""
      )
      error_message = "Accelerators require an enabled, region/quota-bound catalog profile with matching type, count, Spot policy, and node ceiling."
    }
  }
}
