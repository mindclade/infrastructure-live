locals {
  access = {
    for entry in flatten(concat([
      for topic, members in var.publishers : [for member in members : { key = "${topic}-publisher-${sha256(member)}", resource = topic, role = "roles/pubsub.publisher", member = member }]
      ], [
      for subscription, members in var.subscribers : [for member in members : { key = "${subscription}-subscriber-${sha256(member)}", resource = subscription, role = "roles/pubsub.subscriber", member = member }]
    ])) : entry.key => entry
  }
}

resource "google_pubsub_topic" "this" {
  for_each = var.enabled ? var.topics : {}

  project                    = var.project_id
  name                       = each.key
  kms_key_name               = each.value.kms_key_name
  message_retention_duration = each.value.message_retention_duration
  labels                     = each.value.labels

  lifecycle { prevent_destroy = true }
}

resource "google_pubsub_subscription" "this" {
  for_each = var.enabled ? var.subscriptions : {}

  project                      = var.project_id
  name                         = each.key
  topic                        = "projects/${var.project_id}/topics/${each.value.topic}"
  ack_deadline_seconds         = each.value.ack_deadline_seconds
  message_retention_duration   = each.value.message_retention_duration
  retain_acked_messages        = each.value.retain_acked_messages
  enable_exactly_once_delivery = each.value.exactly_once_delivery
  labels                       = each.value.labels

  retry_policy {
    minimum_backoff = "10s"
    maximum_backoff = "600s"
  }

  expiration_policy { ttl = "" }
  depends_on = [google_pubsub_topic.this]

  lifecycle { prevent_destroy = true }
}

resource "google_pubsub_topic_iam_member" "publisher" {
  for_each = var.enabled ? { for key, value in local.access : key => value if value.role == "roles/pubsub.publisher" } : {}
  project  = var.project_id
  topic    = each.value.resource
  role     = each.value.role
  member   = each.value.member

  depends_on = [google_pubsub_topic.this]
}

resource "google_pubsub_subscription_iam_member" "subscriber" {
  for_each     = var.enabled ? { for key, value in local.access : key => value if value.role == "roles/pubsub.subscriber" } : {}
  project      = var.project_id
  subscription = each.value.resource
  role         = each.value.role
  member       = each.value.member

  depends_on = [google_pubsub_subscription.this]
}
