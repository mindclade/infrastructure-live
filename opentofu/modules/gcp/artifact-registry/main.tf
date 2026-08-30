locals {
  access = {
    for entry in flatten(concat([
      for repository, members in var.readers : [for member in members : { key = "${repository}-reader-${sha256(member)}", repository = repository, role = "roles/artifactregistry.reader", member = member }]
      ], [
      for repository, members in var.writers : [for member in members : { key = "${repository}-writer-${sha256(member)}", repository = repository, role = "roles/artifactregistry.writer", member = member }]
    ])) : entry.key => entry
  }
}

resource "google_artifact_registry_repository" "this" {
  for_each = var.enabled ? var.repositories : {}

  project       = var.project_id
  location      = each.value.location
  repository_id = each.key
  description   = each.value.description
  format        = each.value.format
  kms_key_name  = each.value.kms_key_name
  labels        = each.value.labels

  dynamic "docker_config" {
    for_each = each.value.format == "DOCKER" ? [1] : []
    content { immutable_tags = each.value.immutable_tags }
  }

  lifecycle { prevent_destroy = true }
}

resource "google_artifact_registry_repository_iam_member" "access" {
  for_each = var.enabled ? local.access : {}

  project    = var.project_id
  location   = var.repositories[each.value.repository].location
  repository = each.value.repository
  role       = each.value.role
  member     = each.value.member

  depends_on = [google_artifact_registry_repository.this]
}
