output "node_pool_id" { value = var.enabled ? google_container_node_pool.this[0].id : null }
output "instance_group_urls" { value = var.enabled ? google_container_node_pool.this[0].instance_group_urls : [] }
