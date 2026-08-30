module "kms" {
  source = "../../modules/gcp/delegated-kms"

  enabled       = var.enabled
  project_id    = try(var.config.project_id, null)
  location      = var.primary_location
  key_ring_name = try(var.config.key_ring_name, null)
  keys = {
    for name, key in var.config.keys : name => merge(key, {
      labels = merge(key.labels, { environment = var.environment })
    })
  }
}

module "postgres" {
  source = "../../modules/gcp/cloud-sql-postgres"

  depends_on = [module.kms]

  enabled                        = var.enabled && try(var.config.database != null, false)
  project_id                     = try(var.config.project_id, null)
  name                           = try(var.config.database.name, null)
  region                         = var.primary_location
  network_id                     = try(var.config.network_id, null)
  kms_key_name                   = try(module.kms.key_ids[var.config.database.key_name], null)
  database_version               = try(var.config.database.database_version, "POSTGRES_16")
  tier                           = try(var.config.database.tier, "db-custom-2-7680")
  availability_type              = try(var.config.database.availability_type, "REGIONAL")
  backup_retention_days          = try(var.config.database.backup_retention_days, 35)
  transaction_log_retention_days = try(var.config.database.transaction_log_retention_days, 7)
  minimum_backup_retention_days  = var.resource_profile.backupRetentionDays
  high_availability_required     = var.resource_profile.highAvailabilityRequired
  deletion_protection_required   = var.resource_profile.deletionProtectionRequired
  labels                         = merge(try(var.config.database.labels, {}), { environment = var.environment })
}

module "transport" {
  source = "../../modules/gcp/pubsub-transport"

  depends_on = [module.kms]

  enabled    = var.enabled && length(var.config.topics) > 0
  project_id = try(var.config.project_id, null)
  topics = {
    for name, topic in var.config.topics : name => merge(topic, {
      kms_key_name = module.kms.key_ids[topic.key_name]
      labels       = merge(topic.labels, { environment = var.environment })
    })
  }
  subscriptions = {
    for name, subscription in var.config.subscriptions : name => merge(subscription, {
      labels = merge(subscription.labels, { environment = var.environment })
    })
  }
  publishers  = var.config.publishers
  subscribers = var.config.subscribers
}

module "secret_references" {
  source = "../../modules/gcp/secret-bindings"

  enabled    = var.enabled && length(var.config.secret_bindings) > 0
  project_id = try(var.config.project_id, null)
  bindings   = var.config.secret_bindings
}
