output "service_account_email" { value = var.enabled ? google_service_account.controller[0].email : null }
output "membership_ids" { value = var.enabled ? { for name, membership in google_gke_hub_membership.cluster : name => membership.id } : {} }
output "authority_boundary" { value = "cloud-prerequisites-only; Argo CD and Kubernetes resources are owned by gitops" }
