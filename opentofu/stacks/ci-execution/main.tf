module "agents" {
  source = "../../modules/gcp/buildkite-agents"

  enabled                               = var.enabled
  project_id                            = try(var.config.project_id, null)
  region                                = var.primary_location
  subnetwork_id                         = try(var.config.subnetwork_id, null)
  name                                  = var.config.name
  machine_type                          = var.config.machine_type
  boot_image                            = try(var.config.boot_image, null)
  agent_image                           = try(var.config.agent_image, null)
  token_secret_id                       = try(var.config.token_secret_id, null)
  token_secret_version                  = try(var.config.token_secret_version, null)
  agent_image_secret_contract_verified  = var.config.agent_image_secret_contract_verified
  agent_job_isolation_contract_verified = var.config.agent_job_isolation_contract_verified
  min_replicas                          = var.config.min_replicas
  max_replicas                          = var.config.max_replicas
  labels                                = merge(var.config.labels, { environment = var.environment })
}
