output "database_instance_id" { value = module.postgres.instance_id }
output "database_connection_name" { value = module.postgres.connection_name }
output "topic_ids" { value = module.transport.topic_ids }
output "subscription_ids" { value = module.transport.subscription_ids }
output "secret_references" { value = module.secret_references.secret_references }
output "kms_key_ids" { value = module.kms.key_ids }
