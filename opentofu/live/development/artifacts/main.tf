variable "environment" {
  type = string
  validation {
    condition     = var.environment == "development"
    error_message = "This root is bound exclusively to development."
  }
}

variable "enabled" {
  type    = bool
  default = false
}
variable "nix_cache" {
  description = "Protected cache-boundary.v2 activation inputs. Null identifiers are required while disabled."
  type = object({
    enabled = bool
    boundary = object({
      schema_version             = string
      qualification              = string
      source_revision            = optional(string)
      cache_mode                 = string
      cache_used                 = bool
      cache_outputs_are_evidence = bool
      endpoint                   = optional(string)
      namespace = object({
        schema_version   = string
        classification   = string
        namespace_epoch  = string
        trust_class      = string
        system           = string
        toolchain_digest = optional(string)
        build_mode       = string
      })
      iam_qualification_digest = optional(string)
      write_activation_digest  = optional(string)
      signer_public_key_digest = optional(string)
      audit_sink_digest        = optional(string)
      cacheless_canary = object({
        required         = bool
        status           = string
        evidence_locator = optional(string)
        evidence_digest  = optional(string)
      })
      poison_recovery = object({
        required         = bool
        status           = string
        runbook          = string
        evidence_locator = optional(string)
        evidence_digest  = optional(string)
      })
    })
    protected_inputs = object({
      project_id                         = optional(string)
      cache_bucket_name                  = optional(string)
      health_bucket_name                 = optional(string)
      operation_bucket_name              = optional(string)
      external_audit_bucket_name         = optional(string)
      signer_secret_resource             = optional(string)
      iam_qualification_evidence_locator = optional(string)
      write_activation_evidence_locator  = optional(string)
      publisher_wif_principal_sets       = set(string)
      gateway_wif_principal_sets         = set(string)
    })
    gateway = object({
      hostname        = string
      scheme          = string
      allowed_methods = list(string)
      authentication  = string
      implementation  = string
    })
    quotas = object({
      publisher_writes_per_minute = number
      gateway_reads_per_minute    = number
      maximum_cache_bytes         = number
    })
    legacy_v1_compatibility_enabled = bool
  })
}
variable "approved_iam_principals" {
  description = "Environment-scoped externally qualified IAM principals used by policy validation."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for principal in var.approved_iam_principals : can(regex("^(serviceAccount|group|principal|principalSet):[^[:space:]]+$", principal))
    ])
    error_message = "Approved IAM principals must be explicit workload, service-account, or group identities."
  }
}
variable "approved_resource_references" {
  description = "Environment-scoped externally qualified project IDs and immutable resource references used by policy validation."
  type        = set(string)
  default     = []
  validation {
    condition = alltrue([
      for reference in var.approved_resource_references : length(reference) <= 2048 && can(regex("^[A-Za-z0-9][A-Za-z0-9._:/@+\\[\\]-]*$", reference))
    ])
    error_message = "Approved resource references must be explicit, non-secret, whitespace-free GCP or immutable artifact identifiers."
  }
}
variable "config" {
  type = object({
    project_id    = optional(string)
    location      = optional(string)
    key_ring_name = optional(string)
    keys = optional(map(object({
      purpose                    = optional(string, "ENCRYPT_DECRYPT")
      rotation_period            = optional(string, "7776000s")
      destroy_scheduled_duration = optional(string, "2592000s")
      labels                     = optional(map(string), {})
      encrypter_decrypters       = optional(set(string), [])
    })), {})
    repositories = optional(map(object({
      location       = string
      format         = optional(string, "DOCKER")
      description    = optional(string, "Mindclade immutable artifacts")
      key_name       = string
      immutable_tags = optional(bool, true)
      labels         = optional(map(string), {})
    })), {})
    buckets = optional(map(object({
      location                = string
      key_name                = string
      retention_days          = number
      lock_retention          = optional(bool, false)
      soft_delete_days        = optional(number, 30)
      noncurrent_version_days = optional(number, 365)
      labels                  = optional(map(string), {})
    })), {})
    repository_readers = optional(map(set(string)), {})
    repository_writers = optional(map(set(string)), {})
    bucket_readers     = optional(map(set(string)), {})
    bucket_writers     = optional(map(set(string)), {})
  })
  default = {}
}

locals {
  environment_catalog = one([
    for environment in yamldecode(file("${path.root}/../../../../catalog/environments.yaml")).environments :
    environment if environment.name == var.environment
  ])
  region_profile = one([
    for profile in yamldecode(file("${path.root}/../../../../catalog/regions.yaml")).regions :
    profile if profile.name == local.environment_catalog.regionProfile
  ])
}

module "stack" {
  source            = "../../../stacks/artifacts"
  environment       = var.environment
  enabled           = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location  = local.region_profile.primaryLocation
  recovery_location = local.region_profile.recoveryLocation
  config            = var.config
  nix_cache         = var.nix_cache
}
