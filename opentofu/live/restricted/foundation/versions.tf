terraform {
  required_version = ">= 1.12.1, < 1.13.0"

  required_providers {
    google = {
      source  = "hashicorp/google"
      version = "= 7.43.0"
    }
  }
}
