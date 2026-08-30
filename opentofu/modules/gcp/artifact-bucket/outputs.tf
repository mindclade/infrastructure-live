output "bucket_ids" { value = var.enabled ? { for name, bucket in google_storage_bucket.this : name => bucket.id } : {} }
output "bucket_urls" { value = var.enabled ? { for name, bucket in google_storage_bucket.this : name => bucket.url } : {} }
