locals {
  agent_image_b64 = var.enabled ? base64encode(var.agent_image) : ""
  token_secret_resource_b64 = var.enabled ? base64encode(
    "projects/${var.project_id}/secrets/${var.token_secret_id}/versions/${var.token_secret_version}"
  ) : ""
  dependency_mirror_manifest = {
    apiVersion        = "ci.mindclade.dev/v1"
    kind              = "DependencyMirrorManifest"
    coldCacheRequired = true
    endpoints         = var.dependency_mirror_endpoints
  }
  dependency_mirror_manifest_b64 = var.enabled ? base64encode(jsonencode(local.dependency_mirror_manifest)) : ""
  dependency_mirror_manifest_digest = var.enabled ? "sha256:${sha256(jsonencode(
    local.dependency_mirror_manifest
  ))}" : ""
}

resource "google_service_account" "agent" {
  count = var.enabled ? 1 : 0

  project      = var.project_id
  account_id   = var.name
  display_name = "Ephemeral Buildkite agents"
}

resource "google_secret_manager_secret_iam_member" "token" {
  count = var.enabled ? 1 : 0

  project   = var.project_id
  secret_id = var.token_secret_id
  role      = "roles/secretmanager.secretAccessor"
  member    = "serviceAccount:${var.name}@${var.project_id}.iam.gserviceaccount.com"

  depends_on = [google_service_account.agent]
}

resource "google_project_iam_member" "logging" {
  count = var.enabled ? 1 : 0

  project = var.project_id
  role    = "roles/logging.logWriter"
  member  = "serviceAccount:${var.name}@${var.project_id}.iam.gserviceaccount.com"

  depends_on = [google_service_account.agent]
}

resource "google_compute_instance_template" "agent" {
  count = var.enabled ? 1 : 0

  depends_on = [
    google_project_iam_member.logging,
    google_secret_manager_secret_iam_member.token,
  ]

  project      = var.project_id
  name_prefix  = "${var.name}-"
  machine_type = var.machine_type
  labels       = var.labels
  tags         = [var.network_tag]

  disk {
    source_image = var.boot_image
    auto_delete  = true
    boot         = true
    disk_type    = "pd-balanced"
    disk_size_gb = 50
  }

  network_interface {
    subnetwork = var.subnetwork_id
  }

  service_account {
    email  = "${var.name}@${var.project_id}.iam.gserviceaccount.com"
    scopes = ["https://www.googleapis.com/auth/cloud-platform"]
  }

  metadata = {
    block-project-ssh-keys = "true"
    enable-oslogin         = "true"
    startup-script         = <<-EOT
      #!/bin/bash
      set -euo pipefail
      umask 077

      readonly image_b64='${local.agent_image_b64}'
      readonly secret_resource_b64='${local.token_secret_resource_b64}'
      readonly image="$(printf '%s' "$${image_b64}" | base64 --decode)"
      readonly secret_resource="$(printf '%s' "$${secret_resource_b64}" | base64 --decode)"
      readonly registry="$${image%%/*}"
      readonly docker_config="$(mktemp -d)"
      export DOCKER_CONFIG="$${docker_config}"

      cleanup() {
        docker logout "$${registry}" >/dev/null 2>&1 || true
        rm -rf -- "$${docker_config}"
        shutdown -h now || true
      }
      trap cleanup EXIT

      token_json="$(curl --fail --silent --show-error \
        --header 'Metadata-Flavor: Google' \
        'http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token')"
      access_token="$(printf '%s' "$${token_json}" | sed -n 's/.*"access_token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
      test -n "$${access_token}"
      printf '%s' "$${access_token}" | docker login --username oauth2accesstoken --password-stdin "$${registry}" >/dev/null
      unset access_token token_json

      docker pull "$${image}"
      docker run --name buildkite-agent --rm \
        --read-only \
        --cap-drop=ALL \
        --security-opt=no-new-privileges:true \
        --pids-limit=512 \
        --tmpfs /tmp:rw,noexec,nosuid,nodev,size=256m \
        --tmpfs /workspace:rw,nosuid,nodev,size=${var.workspace_tmpfs_mb}m \
        --env BUILDKITE_BUILD_PATH=/workspace \
        --env BUILDKITE_AGENT_DISCONNECT_AFTER_JOB=true \
        --env BUILDKITE_AGENT_DISCONNECT_AFTER_IDLE_TIMEOUT=300 \
        --env MINDCLADE_COLD_CACHE_REQUIRED=true \
        --env "MINDCLADE_DEPENDENCY_MIRROR_MANIFEST_B64=${local.dependency_mirror_manifest_b64}" \
        --env "MINDCLADE_DEPENDENCY_MIRROR_MANIFEST_DIGEST=${local.dependency_mirror_manifest_digest}" \
        --env "BUILDKITE_TOKEN_SECRET_RESOURCE=$${secret_resource}" \
        "$${image}"
    EOT
  }

  shielded_instance_config {
    enable_secure_boot          = true
    enable_vtpm                 = true
    enable_integrity_monitoring = true
  }

  lifecycle {
    create_before_destroy = true
    precondition {
      condition     = alltrue([var.project_id != null, var.region != null, var.subnetwork_id != null])
      error_message = "Project, region, and private subnetwork must be bound before activation."
    }
    precondition {
      condition     = var.min_replicas <= var.max_replicas
      error_message = "min_replicas cannot exceed max_replicas."
    }
    precondition {
      condition     = var.agent_image_secret_contract_verified
      error_message = "The exact agent image digest must be qualified for the runtime Secret Manager contract before activation; stock images are not assumed compatible."
    }
    precondition {
      condition     = var.agent_job_isolation_contract_verified
      error_message = "The exact agent image and execution design must be qualified for JAT-only one-job isolation without workload access to metadata or agent credentials."
    }
    precondition {
      condition     = var.dependency_mirror_contract_verified
      error_message = "The exact agent image must be qualified to route every declared dependency authority and cache through the closed mirror manifest during a cold-cache build."
    }
  }
}

resource "google_compute_region_instance_group_manager" "agent" {
  count = var.enabled ? 1 : 0

  project            = var.project_id
  name               = var.name
  region             = var.region
  base_instance_name = var.name

  version { instance_template = google_compute_instance_template.agent[0].id }

  update_policy {
    type                  = "PROACTIVE"
    minimal_action        = "REPLACE"
    max_surge_fixed       = 1
    max_unavailable_fixed = 0
    replacement_method    = "SUBSTITUTE"
  }
}

resource "google_compute_region_autoscaler" "agent" {
  count = var.enabled ? 1 : 0

  project = var.project_id
  name    = "${var.name}-autoscaler"
  region  = var.region
  target  = google_compute_region_instance_group_manager.agent[0].id

  autoscaling_policy {
    min_replicas    = var.min_replicas
    max_replicas    = var.max_replicas
    cooldown_period = 120
    cpu_utilization { target = 0.7 }
  }
}
