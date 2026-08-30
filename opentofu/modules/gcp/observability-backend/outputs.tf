output "log_bucket_id" { value = var.enabled ? google_logging_project_bucket_config.platform[0].id : null }
output "metrics_scope" { value = var.enabled ? var.project_id : null }
output "sink_writer_identities" { value = var.enabled ? { for project, sink in google_logging_project_sink.source : project => sink.writer_identity } : {} }
