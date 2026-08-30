output "key_ring_id" {
  value      = local.key_ring_reference
  depends_on = [google_kms_crypto_key_iam_member.encrypter_decrypter]
}
output "key_ids" {
  value      = local.key_references
  depends_on = [google_kms_crypto_key_iam_member.encrypter_decrypter]
}
