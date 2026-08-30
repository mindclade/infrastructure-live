output "service_account_emails" { value = var.enabled ? { for name, account in google_service_account.workload : name => account.email } : {} }
output "kubernetes_principals" { value = var.enabled ? { for name, account in var.accounts : name => "serviceAccount:${var.project_id}.svc.id.goog[${account.namespace}/${account.service_account_name}]" } : {} }
