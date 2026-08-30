module "kms" {
  source = "../../modules/gcp/delegated-kms"

  enabled       = var.enabled
  project_id    = try(var.config.project_id, null)
  location      = var.primary_location
  key_ring_name = try(var.config.key_ring_name, null)
  keys = var.enabled ? {
    (var.config.key_name) = {
      labels               = merge(var.config.labels, { environment = var.environment })
      encrypter_decrypters = var.config.key_encrypter_decrypters
    }
  } : {}
}

module "backend" {
  source = "../../modules/gcp/observability-backend"

  depends_on = [module.kms]

  enabled        = var.enabled
  project_id     = try(var.config.project_id, null)
  location       = var.primary_location
  bucket_id      = var.config.bucket_id
  retention_days = var.config.retention_days
  minimum_retention_days = lookup({
    development = 30
    staging     = 90
    production  = 90
    restricted  = 365
  }, var.environment)
  kms_key_name             = try(module.kms.key_ids[var.config.key_name], null)
  source_projects          = var.config.source_projects
  sink_writer_binding_mode = var.config.sink_writer_binding_mode
  sink_writer_identities   = var.config.sink_writer_identities
  log_filter               = var.config.log_filter
}
