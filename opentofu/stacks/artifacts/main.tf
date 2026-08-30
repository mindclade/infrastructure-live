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

module "registry" {
  source = "../../modules/gcp/artifact-registry"

  depends_on = [module.kms]

  enabled    = var.enabled
  project_id = try(var.config.project_id, null)
  repositories = {
    for name, repository in var.config.repositories : name => merge(repository, {
      kms_key_name = module.kms.key_ids[repository.key_name]
      location     = var.primary_location
      labels       = merge(repository.labels, { environment = var.environment })
    })
  }
  readers = var.config.repository_readers
  writers = var.config.repository_writers
}

module "buckets" {
  source = "../../modules/gcp/artifact-bucket"

  depends_on = [module.kms]

  enabled    = var.enabled
  project_id = try(var.config.project_id, null)
  buckets = {
    for name, bucket in var.config.buckets : name => merge(bucket, {
      kms_key_name = module.kms.key_ids[bucket.key_name]
      location     = var.primary_location
      labels       = merge(bucket.labels, { environment = var.environment })
    })
  }
  readers = var.config.bucket_readers
  writers = var.config.bucket_writers
}
