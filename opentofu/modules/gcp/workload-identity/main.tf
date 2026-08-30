locals {
  project_roles = {
    for entry in flatten([
      for account_name, account in var.accounts : [
        for role in account.project_roles : {
          key          = "${account_name}-${sha256(role)}"
          account_name = account_name
          role         = role
        }
      ]
    ]) : entry.key => entry
  }
}

resource "google_service_account" "workload" {
  for_each = var.enabled ? var.accounts : {}

  project      = var.project_id
  account_id   = each.value.account_id
  display_name = each.value.display_name
}

resource "google_service_account_iam_member" "kubernetes" {
  for_each = var.enabled ? var.accounts : {}

  service_account_id = google_service_account.workload[each.key].name
  role               = "roles/iam.workloadIdentityUser"
  member             = "serviceAccount:${var.project_id}.svc.id.goog[${each.value.namespace}/${each.value.service_account_name}]"
}

resource "google_project_iam_member" "workload" {
  for_each = var.enabled ? local.project_roles : {}

  project = var.project_id
  role    = each.value.role
  member  = "serviceAccount:${each.value.account_id}@${var.project_id}.iam.gserviceaccount.com"

  depends_on = [google_service_account.workload]
}
