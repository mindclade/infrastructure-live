resource "google_container_cluster" "this" {
  count = var.enabled ? 1 : 0

  project        = var.project_id
  name           = var.name
  location       = var.region
  node_locations = sort(var.node_locations)

  network                     = var.network_id
  subnetwork                  = var.subnetwork_id
  remove_default_node_pool    = true
  initial_node_count          = 1
  deletion_protection         = var.deletion_protection_required
  enable_shielded_nodes       = true
  enable_intranode_visibility = true
  enable_l4_ilb_subsetting    = true
  networking_mode             = "VPC_NATIVE"
  resource_labels             = var.resource_labels

  release_channel { channel = var.release_channel }

  private_cluster_config {
    enable_private_nodes    = true
    enable_private_endpoint = true
    master_ipv4_cidr_block  = var.master_ipv4_cidr_block
    master_global_access_config { enabled = false }
  }

  ip_allocation_policy {
    cluster_secondary_range_name  = var.pods_secondary_range_name
    services_secondary_range_name = var.services_secondary_range_name
    stack_type                    = "IPV4"
  }

  workload_identity_config { workload_pool = "${var.project_id}.svc.id.goog" }
  datapath_provider = "ADVANCED_DATAPATH"

  database_encryption {
    state    = "ENCRYPTED"
    key_name = var.database_encryption_key_name
  }

  binary_authorization { evaluation_mode = "PROJECT_SINGLETON_POLICY_ENFORCE" }
  cost_management_config { enabled = true }

  logging_config {
    enable_components = ["APISERVER", "CONTROLLER_MANAGER", "SCHEDULER", "SYSTEM_COMPONENTS", "WORKLOADS"]
  }
  monitoring_config {
    enable_components = ["APISERVER", "CONTROLLER_MANAGER", "SCHEDULER", "SYSTEM_COMPONENTS", "STORAGE", "POD", "DEPLOYMENT", "STATEFULSET", "DAEMONSET", "HPA", "CADVISOR", "KUBELET"]
    managed_prometheus { enabled = true }
  }

  lifecycle {
    prevent_destroy = true
    precondition {
      condition = length(var.node_locations) >= var.minimum_zones && alltrue([
        for zone in var.node_locations : can(regex("^[a-z]+-[a-z]+[0-9]-[a-z]$", zone)) && startswith(zone, "${var.region}-")
      ])
      error_message = "Explicit cluster zones must meet the immutable environment resource profile and belong to the bound region."
    }
  }
}
