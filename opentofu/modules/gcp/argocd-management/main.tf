resource "google_service_account" "controller" {
  count = var.enabled ? 1 : 0

  project      = var.project_id
  account_id   = var.service_account_id
  display_name = "Argo CD cloud prerequisite identity"

  lifecycle {
    precondition {
      condition     = var.project_id != null
      error_message = "project_id must be bound before activation."
    }
  }
}

resource "google_service_account_iam_member" "workload_identity" {
  for_each = var.enabled ? var.kubernetes_service_accounts : toset([])

  service_account_id = google_service_account.controller[0].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${var.kubernetes_namespace}/${each.value}]"
}

resource "google_secret_manager_secret_iam_member" "referenced" {
  for_each = var.enabled ? var.secret_references : toset([])

  project   = var.project_id
  secret_id = each.value
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.service_account_id}@${var.project_id}.iam.gserviceaccount.com"

  depends_on = [google_service_account.controller]
}

resource "google_gke_hub_membership" "cluster" {
  for_each = var.enabled ? var.cluster_memberships : {}

  project       = var.project_id
  membership_id = each.key
  location      = each.value.location

  endpoint {
    gke_cluster { resource_link = each.value.cluster_resource_link }
  }

  lifecycle { prevent_destroy = true }
}
