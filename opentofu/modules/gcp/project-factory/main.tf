resource "google_project" "this" {
  count = var.enabled ? 1 : 0

  project_id          = var.project_id
  name                = var.project_name
  org_id              = var.organization_id
  folder_id           = var.folder_id
  billing_account     = var.billing_account
  auto_create_network = false
  deletion_policy     = var.deletion_protection_required ? "PREVENT" : "DELETE"
  labels              = var.labels

  lifecycle {
    prevent_destroy = true
    precondition {
      condition = var.folder_binding_required ? (
        var.folder_id != null && var.organization_id == null
        ) : (
        (var.organization_id == null) != (var.folder_id == null)
      )
      error_message = "The catalog project class requires an exclusive folder binding before activation."
    }
    precondition {
      condition     = alltrue([for key in ["environment", "owner", "managed_by", "cost_center", "data_classification"] : lookup(var.labels, key, "") != ""])
      error_message = "labels must contain nonempty environment, owner, managed_by, cost_center, and data_classification values."
    }
    precondition {
      condition     = !var.enabled || var.services == var.approved_services
      error_message = "Enabled foundation APIs must exactly equal the foundation service-capability catalog entry."
    }
  }
}

resource "google_project_service" "required" {
  for_each = var.enabled ? var.services : toset([])

  project                    = google_project.this[0].project_id
  service                    = each.value
  disable_dependent_services = false
  disable_on_destroy         = false
}
