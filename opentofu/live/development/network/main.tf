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
variable "estate_ci_edge" {
  description = "Protected external managed HTTPS Gateway and delegated DNS inputs for estate-ci.mindclade.com."
  type = object({
    connected                           = bool
    hostname                            = string
    gateway_class                       = string
    certificate_map_id                  = optional(string)
    certificate_ids                     = set(string)
    cloud_armor_policy_id               = optional(string)
    iap_oauth_client_id_secret_resource = optional(string)
    iap_oauth_client_secret_resource    = optional(string)
    delegated_dns_zone_id               = optional(string)
    delegated_dns_records               = list(object({ name = string, type = string, ttl = number, rrdatas = list(string) }))
  })

  validation {
    condition = (
      var.estate_ci_edge.hostname == "estate-ci.mindclade.com" &&
      var.estate_ci_edge.gateway_class == "gke-l7-global-external-managed" &&
      (
        (
          !var.estate_ci_edge.connected &&
          var.estate_ci_edge.certificate_map_id == null &&
          length(var.estate_ci_edge.certificate_ids) == 0 &&
          var.estate_ci_edge.cloud_armor_policy_id == null &&
          var.estate_ci_edge.iap_oauth_client_id_secret_resource == null &&
          var.estate_ci_edge.iap_oauth_client_secret_resource == null &&
          var.estate_ci_edge.delegated_dns_zone_id == null &&
          length(var.estate_ci_edge.delegated_dns_records) == 0
        ) ||
        (
          var.estate_ci_edge.connected &&
          can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/global/certificateMaps/[a-z][a-z0-9-]+$", var.estate_ci_edge.certificate_map_id)) &&
          length(var.estate_ci_edge.certificate_ids) > 0 &&
          alltrue([for id in var.estate_ci_edge.certificate_ids : can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/locations/global/certificates/[a-z][a-z0-9-]+$", id))]) &&
          can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/global/securityPolicies/[a-z][a-z0-9-]+$", var.estate_ci_edge.cloud_armor_policy_id)) &&
          can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/secrets/[a-z][a-z0-9-]+/versions/[1-9][0-9]*$", var.estate_ci_edge.iap_oauth_client_id_secret_resource)) &&
          can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/secrets/[a-z][a-z0-9-]+/versions/[1-9][0-9]*$", var.estate_ci_edge.iap_oauth_client_secret_resource)) &&
          can(regex("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/managedZones/[a-z][a-z0-9-]+$", var.estate_ci_edge.delegated_dns_zone_id)) &&
          length(var.estate_ci_edge.delegated_dns_records) > 0
        )
      )
    )
    error_message = "The estate CI edge must use the exact hostname and external managed Gateway class; every protected edge/DNS input stays null until connected."
  }
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
    project_id          = optional(string)
    region              = optional(string)
    network_name        = optional(string)
    routing_mode        = optional(string, "GLOBAL")
    service_project_ids = optional(set(string), [])
    subnets = optional(map(object({
      region                = string
      cidr                  = string
      private_google_access = optional(bool, true)
      flow_logs             = optional(bool, true)
      secondary_ranges      = optional(map(string), {})
    })), {})
    private_zones = optional(map(object({ dns_name = string, description = optional(string, "Managed private zone"), labels = optional(map(string), {}) })), {})
    private_service_access = optional(object({
      address       = string
      prefix_length = number
    }))
    nat_ip_count = optional(number, 1)
    allowed_egress_rules = optional(map(object({
      destination_cidrs = set(string)
      protocol          = string
      ports             = set(string)
    })), {})
    labels = optional(map(string), {})
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
  source            = "../../../stacks/network"
  environment       = var.environment
  enabled           = var.enabled && local.environment_catalog.enabled && local.region_profile.enabled
  primary_location  = local.region_profile.primaryLocation
  recovery_location = local.region_profile.recoveryLocation
  config            = var.config
}
