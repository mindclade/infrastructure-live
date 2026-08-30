variable "enabled" {
  type    = bool
  default = false
}
variable "project_id" {
  type     = string
  default  = null
  nullable = true
}
variable "cluster_id" {
  type     = string
  default  = null
  nullable = true
}
variable "location" {
  type     = string
  default  = null
  nullable = true
}
variable "name" {
  type     = string
  default  = null
  nullable = true
}
variable "service_account" {
  type     = string
  default  = null
  nullable = true
}
variable "machine_type" {
  type    = string
  default = "e2-standard-4"
}
variable "disk_type" {
  type    = string
  default = "pd-balanced"
}
variable "disk_size_gb" {
  type    = number
  default = 100
}
variable "min_nodes" {
  type    = number
  default = 0
}
variable "max_nodes" {
  type    = number
  default = 3
}
variable "spot" {
  type    = bool
  default = false
}
variable "accelerator" {
  type     = object({ type = string, count = number, gpu_driver_version = optional(string, "INSTALLATION_DISABLED") })
  default  = null
  nullable = true
  validation {
    condition     = var.accelerator == null || var.accelerator.gpu_driver_version == "INSTALLATION_DISABLED"
    error_message = "Accelerator driver installation must be disabled for digest-pinned GPU Operator ownership."
  }
}
variable "accelerator_profile" {
  description = "Resolved provider-free catalog authority for an accelerator node pool."
  type = object({
    enabled             = bool
    accelerator_type    = string
    accelerator_count   = number
    spot_permitted      = bool
    dedicated_node_pool = bool
    maximum_nodes       = number
    region_binding      = optional(string)
    quota_binding       = optional(string)
  })
  default  = null
  nullable = true
}
variable "taints" {
  type    = list(object({ key = string, value = string, effect = string }))
  default = []
}
variable "labels" {
  type    = map(string)
  default = {}
}
variable "resource_labels" {
  description = "GCP resource-manager labels used for governance and cost allocation."
  type        = map(string)
  default     = {}
}
variable "tags" {
  type    = set(string)
  default = []
}
