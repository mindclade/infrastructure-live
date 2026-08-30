variable "enabled" {
  type    = bool
  default = false
}
variable "project_id" {
  type     = string
  default  = null
  nullable = true
}
variable "service_account_id" {
  type    = string
  default = "argocd-management"
  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{4,28}[a-z0-9]$", var.service_account_id))
    error_message = "service_account_id must be a valid deterministic service-account ID."
  }
}
variable "kubernetes_namespace" {
  type    = string
  default = "external-secrets"
}
variable "kubernetes_service_accounts" {
  type    = set(string)
  default = ["external-secrets"]
  validation {
    condition     = alltrue([for account in var.kubernetes_service_accounts : account == "external-secrets"])
    error_message = "Only the External Secrets service account may impersonate the secret-access identity."
  }
}
variable "secret_references" {
  type    = set(string)
  default = []
}
variable "cluster_memberships" {
  type = map(object({
    location              = string
    cluster_resource_link = string
  }))
  default = {}
}
