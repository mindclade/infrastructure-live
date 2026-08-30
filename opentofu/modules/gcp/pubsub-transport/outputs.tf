output "topic_ids" { value = var.enabled ? { for name, topic in google_pubsub_topic.this : name => topic.id } : {} }
output "subscription_ids" { value = var.enabled ? { for name, subscription in google_pubsub_subscription.this : name => subscription.id } : {} }
