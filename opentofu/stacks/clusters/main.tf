module "cluster" {
  source = "../../modules/gcp/gke-regional-cluster"

  enabled                       = var.enabled
  project_id                    = try(var.config.project_id, null)
  name                          = try(var.config.name, null)
  region                        = var.primary_location
  node_locations                = var.config.node_locations
  minimum_zones                 = var.resource_profile.minimumZones
  deletion_protection_required  = var.resource_profile.deletionProtectionRequired
  network_id                    = try(var.config.network_id, null)
  subnetwork_id                 = try(var.config.subnetwork_id, null)
  pods_secondary_range_name     = try(var.config.pods_secondary_range_name, null)
  services_secondary_range_name = try(var.config.services_secondary_range_name, null)
  master_ipv4_cidr_block        = try(var.config.master_ipv4_cidr_block, null)
  database_encryption_key_name  = try(var.config.database_encryption_key_name, null)
  release_channel               = var.config.release_channel
  resource_labels               = merge(var.config.resource_labels, { environment = var.environment })
}

module "workload_identity" {
  source = "../../modules/gcp/workload-identity"

  enabled    = var.enabled && length(var.config.workload_accounts) > 0
  project_id = try(var.config.project_id, null)
  accounts   = var.config.workload_accounts
}

module "node_pool" {
  for_each = var.enabled ? var.config.node_pools : {}
  source   = "../../modules/gcp/gke-node-pool"

  enabled         = true
  project_id      = var.config.project_id
  cluster_id      = module.cluster.cluster_id
  location        = var.primary_location
  name            = each.key
  service_account = each.value.service_account
  machine_type    = each.value.machine_type
  disk_type       = each.value.disk_type
  disk_size_gb    = each.value.disk_size_gb
  min_nodes       = each.value.min_nodes
  max_nodes       = each.value.max_nodes
  spot            = each.value.spot
  accelerator     = each.value.accelerator
  accelerator_profile = each.value.accelerator == null ? null : try({
    enabled             = var.accelerator_profiles[each.value.accelerator_profile].enabled
    accelerator_type    = var.accelerator_profiles[each.value.accelerator_profile].acceleratorType
    accelerator_count   = var.accelerator_profiles[each.value.accelerator_profile].acceleratorCount
    spot_permitted      = var.accelerator_profiles[each.value.accelerator_profile].spotPermitted
    dedicated_node_pool = var.accelerator_profiles[each.value.accelerator_profile].dedicatedNodePool
    maximum_nodes       = var.accelerator_profiles[each.value.accelerator_profile].maximumNodes
    region_binding      = var.accelerator_profiles[each.value.accelerator_profile].regionBinding
    quota_binding       = var.accelerator_profiles[each.value.accelerator_profile].quotaBinding
  }, null)
  taints          = each.value.taints
  labels          = merge(each.value.labels, { environment = var.environment })
  resource_labels = merge(each.value.resource_labels, { environment = var.environment })
  tags            = each.value.tags
}

module "argocd_cloud_prerequisites" {
  source = "../../modules/gcp/argocd-management"

  enabled                     = var.enabled && try(var.config.argocd.enabled, false)
  project_id                  = try(var.config.project_id, null)
  service_account_id          = try(var.config.argocd.service_account_id, "argocd-management")
  kubernetes_namespace        = try(var.config.argocd.kubernetes_namespace, "external-secrets")
  kubernetes_service_accounts = try(var.config.argocd.kubernetes_service_accounts, toset(["external-secrets"]))
  secret_references           = try(var.config.argocd.secret_references, toset([]))
  cluster_memberships = try(var.config.argocd.enabled, false) ? {
    (var.config.argocd.membership_id) = {
      location              = var.primary_location
      cluster_resource_link = "//container.googleapis.com/${module.cluster.cluster_id}"
    }
  } : {}
}
