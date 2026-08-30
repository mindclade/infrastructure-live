locals {
  agent_network_tag = "${var.config.name}-${var.environment}-ephemeral"
}

module "execution_egress" {
  source = "../../modules/gcp/controlled-egress"

  enabled              = var.enabled
  project_id           = try(var.config.network_project_id, null)
  region               = var.primary_location
  network_id           = try(var.config.network_id, null)
  name                 = "${var.config.name}-egress"
  manage_nat           = false
  subnetwork_ids       = []
  allowed_egress_rules = var.config.allowed_egress_rules
  required_rule_names = toset([
    "buildkite-control-plane",
    "dependency-mirror",
    "google-apis",
    "source-control",
  ])
  target_tags          = toset([local.agent_network_tag])
  require_target_scope = true
  allow_priority       = 900
  deny_priority        = 1000
  labels               = merge(var.config.labels, { environment = var.environment })
}

module "agents" {
  source = "../../modules/gcp/buildkite-agents"

  depends_on = [module.execution_egress]

  enabled                               = var.enabled
  project_id                            = try(var.config.project_id, null)
  region                                = var.primary_location
  subnetwork_id                         = try(var.config.subnetwork_id, null)
  network_tag                           = local.agent_network_tag
  name                                  = var.config.name
  machine_type                          = var.config.machine_type
  boot_image                            = try(var.config.boot_image, null)
  agent_image                           = try(var.config.agent_image, null)
  token_secret_id                       = try(var.config.token_secret_id, null)
  token_secret_version                  = try(var.config.token_secret_version, null)
  agent_image_secret_contract_verified  = var.config.agent_image_secret_contract_verified
  agent_job_isolation_contract_verified = var.config.agent_job_isolation_contract_verified
  dependency_mirror_endpoints           = var.config.dependency_mirror_endpoints
  dependency_mirror_contract_verified   = var.config.dependency_mirror_contract_verified
  workspace_tmpfs_mb                    = var.config.workspace_tmpfs_mb
  min_replicas                          = var.config.min_replicas
  max_replicas                          = var.config.max_replicas
  labels                                = merge(var.config.labels, { environment = var.environment })
}
