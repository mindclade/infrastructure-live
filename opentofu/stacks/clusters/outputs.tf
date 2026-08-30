output "cluster_id" { value = module.cluster.cluster_id }
output "cluster_name" { value = module.cluster.cluster_name }
output "workload_identity_pool" { value = module.cluster.workload_identity_pool }
output "node_pool_ids" { value = { for name, pool in module.node_pool : name => pool.node_pool_id } }
output "workload_service_accounts" { value = module.workload_identity.service_account_emails }
output "argocd_prerequisite_identity" { value = module.argocd_cloud_prerequisites.service_account_email }
output "cluster_membership_ids" { value = module.argocd_cloud_prerequisites.membership_ids }
