output "service_account_email" { value = var.enabled ? google_service_account.agent[0].email : null }
output "instance_group_id" { value = var.enabled ? google_compute_region_instance_group_manager.agent[0].id : null }
