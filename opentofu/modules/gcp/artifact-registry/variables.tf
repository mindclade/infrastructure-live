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
variable "repositories" {
  type = map(object({
    location       = string
    format         = optional(string, "DOCKER")
    description    = optional(string, "Mindclade immutable artifacts")
    kms_key_name   = string
    immutable_tags = optional(bool, true)
    labels         = optional(map(string), {})
  }))
  default = {}
  validation {
    condition     = !var.enabled || (length(var.repositories) > 0 && alltrue([for repository in values(var.repositories) : repository.kms_key_name != "" && contains(["DOCKER", "MAVEN", "NPM", "PYTHON", "APT", "YUM", "GENERIC", "GO"], repository.format) && (repository.format != "DOCKER" || repository.immutable_tags)]))
    error_message = "Enabled repositories require an approved format, CMEK reference, and immutable Docker tags."
  }
}
variable "readers" {
  type    = map(set(string))
  default = {}
}
variable "writers" {
  type    = map(set(string))
  default = {}
}
