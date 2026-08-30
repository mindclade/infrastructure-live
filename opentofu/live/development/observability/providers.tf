provider "google" {
  project = try(var.config.project_id, null)
  region  = try(var.config.location, null)
}
