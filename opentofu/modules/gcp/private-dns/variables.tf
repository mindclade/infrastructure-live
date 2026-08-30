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
variable "zones" {
  type = map(object({
    dns_name     = string
    description  = optional(string, "Managed private zone")
    network_urls = set(string)
    labels       = optional(map(string), {})
  }))
  default = {}
  validation {
    condition     = !var.enabled || (length(var.zones) > 0 && alltrue([for zone in values(var.zones) : endswith(zone.dns_name, ".") && length(zone.network_urls) > 0]))
    error_message = "Enabled private zones require an absolute DNS name and at least one explicit network."
  }
}
