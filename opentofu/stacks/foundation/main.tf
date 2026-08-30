module "project" {
  source = "../../modules/gcp/project-factory"

  enabled                      = var.enabled
  project_id                   = try(var.config.project_id, null)
  project_name                 = try(var.config.project_name, null)
  organization_id              = try(var.config.organization_id, null)
  folder_id                    = try(var.config.folder_id, null)
  billing_account              = try(var.config.billing_account, null)
  folder_binding_required      = var.project_class.folderBindingRequired
  billing_binding_required     = var.project_class.billingBindingRequired
  deletion_protection_required = var.project_class.deletionProtection
  approved_services            = var.approved_services
  services                     = var.config.services
  labels                       = merge(var.config.labels, { environment = var.environment })
}
