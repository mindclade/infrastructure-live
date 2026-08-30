variable "enabled" {
  type    = bool
  default = false
}
variable "project_id" {
  type     = string
  default  = null
  nullable = true
  validation {
    condition     = !var.enabled || var.project_id != null
    error_message = "project_id must be bound before activation."
  }
}
variable "topics" {
  type = map(object({
    kms_key_name               = string
    message_retention_duration = optional(string, "604800s")
    labels                     = optional(map(string), {})
  }))
  default = {}
  validation {
    condition     = !var.enabled || (length(var.topics) > 0 && alltrue([for topic in values(var.topics) : topic.kms_key_name != ""]))
    error_message = "Enabled topics require CMEK references."
  }
}
variable "subscriptions" {
  type = map(object({
    topic                      = string
    ack_deadline_seconds       = optional(number, 60)
    message_retention_duration = optional(string, "604800s")
    retain_acked_messages      = optional(bool, false)
    exactly_once_delivery      = optional(bool, true)
    labels                     = optional(map(string), {})
  }))
  default = {}
  validation {
    condition     = alltrue([for subscription in values(var.subscriptions) : contains(keys(var.topics), subscription.topic)])
    error_message = "Every subscription must name a topic managed by this module."
  }
}
variable "publishers" {
  type    = map(set(string))
  default = {}
}
variable "subscribers" {
  type    = map(set(string))
  default = {}
}
