locals {
  key_ring_reference = var.enabled ? "projects/${var.project_id}/locations/${var.location}/keyRings/${var.key_ring_name}" : null
  key_references = var.enabled ? {
    for name in keys(var.keys) : name => "projects/${var.project_id}/locations/${var.location}/keyRings/${var.key_ring_name}/cryptoKeys/${name}"
  } : {}
  access = {
    for entry in flatten([
      for key_name, key in var.keys : [
        for member in key.encrypter_decrypters : {
          id       = "${key_name}-${sha256(member)}"
          key_name = key_name
          member   = member
        }
      ]
    ]) : entry.id => entry
  }
}

resource "google_kms_key_ring" "this" {
  count = var.enabled ? 1 : 0

  project  = var.project_id
  location = var.location
  name     = var.key_ring_name

  lifecycle { prevent_destroy = true }
}

resource "google_kms_crypto_key" "this" {
  for_each = var.enabled ? var.keys : {}

  name                       = each.key
  key_ring                   = local.key_ring_reference
  purpose                    = each.value.purpose
  rotation_period            = each.value.rotation_period
  destroy_scheduled_duration = each.value.destroy_scheduled_duration
  labels                     = each.value.labels

  depends_on = [google_kms_key_ring.this]

  lifecycle { prevent_destroy = true }
}

resource "google_kms_crypto_key_iam_member" "encrypter_decrypter" {
  for_each = var.enabled ? local.access : {}

  crypto_key_id = local.key_references[each.value.key_name]
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = each.value.member

  depends_on = [google_kms_crypto_key.this]
}
