data "google_secret_manager_secret" "referenced" {
  for_each = var.enabled ? var.bindings : {}

  project   = var.project_id
  secret_id = each.value.secret_id
}

resource "google_secret_manager_secret_iam_member" "accessor" {
  for_each = var.enabled ? var.bindings : {}

  project   = var.project_id
  secret_id = data.google_secret_manager_secret.referenced[each.key].secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = each.value.member
}
