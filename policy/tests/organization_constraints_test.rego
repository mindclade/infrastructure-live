package mindclade.infrastructure.organization_constraints

import rego.v1

test_rejects_long_lived_key if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_service_account_key.automation",
			"type": "google_service_account_key",
			"change": {"actions": ["create"], "after": {}},
		}],
	}
	count(violations) == 1
}

test_rejects_dangerous_administrative_roles if {
	roles := {
		"roles/cloudkms.admin",
		"roles/iam.serviceAccountKeyAdmin",
		"roles/iam.securityAdmin",
		"roles/resourcemanager.projectIamAdmin",
		"roles/resourcemanager.organizationAdmin",
		"roles/resourcemanager.folderAdmin",
		"roles/billing.admin",
	}
	every role in roles {
		member := "serviceAccount:automation@logical.iam.gserviceaccount.com"
		violations := deny with input as {
			"variables": {
				"approved_iam_principals": {"value": [member]},
			},
			"resource_changes": [{
				"address": "google_project_iam_member.unsafe",
				"type": "google_project_iam_member",
				"change": {"actions": ["create"], "after": {
					"role": role,
					"member": member,
				}},
			}],
		}
		count(violations) == 2
	}
}

test_accepts_noop_plan if {
	violations := deny with input as {"resource_changes": []}
	count(violations) == 0
}

test_rejects_revoked_noop_iam_principal if {
	violations := deny with input as {
		"variables": {"approved_iam_principals": {"value": []}},
		"resource_changes": [{
			"address": "google_secret_manager_secret_iam_member.revoked",
			"type": "google_secret_manager_secret_iam_member",
			"change": {"actions": ["no-op"], "after": {
				"role": "roles/secretmanager.secretAccessor",
				"member": "serviceAccount:revoked@restricted-project.iam.gserviceaccount.com",
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_revoked_noop_resource_reference if {
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": ["restricted-project"]}},
		"resource_changes": [{
			"address": "google_compute_firewall.revoked",
			"type": "google_compute_firewall",
			"change": {"actions": ["no-op"], "after": {
				"project": "restricted-project",
				"network": "projects/development-host/global/networks/development-vpc",
			}},
		}],
	}
	count(violations) == 1
}

test_allows_delete_of_revoked_iam_principal_for_separate_destructive_review if {
	violations := deny with input as {
		"variables": {"approved_iam_principals": {"value": []}},
		"resource_changes": [{
			"address": "google_secret_manager_secret_iam_member.revoked",
			"type": "google_secret_manager_secret_iam_member",
			"change": {"actions": ["delete"], "after": null},
		}],
	}
	count(violations) == 0
}

test_rejects_public_principal_in_members_collection if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_project_iam_binding.viewer",
			"type": "google_project_iam_binding",
			"change": {"actions": ["create"], "after": {
				"role": "roles/logging.viewer",
				"members": ["group:operators@mindclade.dev", "allUsers"],
			}},
		}],
	}
	count(violations) == 2
}

test_rejects_authoritative_private_members_binding if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_project_iam_binding.viewer",
			"type": "google_project_iam_binding",
			"change": {"actions": ["create"], "after": {
				"role": "roles/logging.viewer",
				"members": ["group:operators@mindclade.dev", "serviceAccount:reader@workload.iam.gserviceaccount.com"],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_unmanaged_iam_policy_resource if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_storage_bucket_iam_policy.authoritative",
			"type": "google_storage_bucket_iam_policy",
			"change": {"actions": ["create"], "after": {}},
		}],
	}
	count(violations) == 1
}

test_rejects_unapproved_role_on_approved_secret_principal if {
	member := "serviceAccount:restricted-worker@restricted-project.iam.gserviceaccount.com"
	violations := deny with input as {
		"variables": {"approved_iam_principals": {"value": [member]}},
		"resource_changes": [{
			"address": "google_secret_manager_secret_iam_member.unsafe",
			"type": "google_secret_manager_secret_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/secretmanager.admin",
				"member": member,
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_restricted_to_development_principal_binding if {
	violations := deny with input as {
		"variables": {
			"environment": {"value": "restricted"},
			"approved_iam_principals": {"value": [
				"serviceAccount:restricted-worker@restricted-project.iam.gserviceaccount.com",
			]},
		},
		"resource_changes": [{
			"address": "module.stack.module.secrets.google_secret_manager_secret_iam_member.accessor[\"worker\"]",
			"type": "google_secret_manager_secret_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/secretmanager.secretAccessor",
				"member": "serviceAccount:development-worker@development-project.iam.gserviceaccount.com",
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_exact_environment_approved_principal if {
	member := "serviceAccount:restricted-worker@restricted-project.iam.gserviceaccount.com"
	violations := deny with input as {
		"variables": {
			"environment": {"value": "restricted"},
			"approved_iam_principals": {"value": [member]},
		},
		"resource_changes": [{
			"address": "module.stack.module.secrets.google_secret_manager_secret_iam_member.accessor[\"worker\"]",
			"type": "google_secret_manager_secret_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/secretmanager.secretAccessor",
				"member": member,
			}},
		}],
	}
	count(violations) == 0
}

test_all_repository_iam_member_types_require_exact_approval if {
	every resource_type in governed_iam_member_types {
		some role in allowed_iam_roles_by_type[resource_type]
		violations := deny with input as {
			"variables": {
				"environment": {"value": "production"},
				"approved_iam_principals": {"value": []},
			},
			"resource_changes": [{
				"address": sprintf("%s.unapproved", [resource_type]),
				"type": resource_type,
				"change": {"actions": ["create"], "after": {
					"role": role,
					"member": "serviceAccount:worker@production-project.iam.gserviceaccount.com",
				}},
			}],
		}
		count(violations) == 1
	}
}

test_missing_approval_input_fails_closed if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_kms_crypto_key_iam_member.unapproved",
			"type": "google_kms_crypto_key_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
				"member": "serviceAccount:worker@production-project.iam.gserviceaccount.com",
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_unknown_computed_sink_writer_identity if {
	violations := deny with input as {
		"variables": {
			"environment": {"value": "production"},
			"approved_iam_principals": {"value": []},
		},
		"resource_changes": [{
			"address": "module.stack.module.backend.google_project_iam_member.sink_writer[\"source-project\"]",
			"type": "google_project_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/logging.bucketWriter",
				"member": null,
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_verified_provider_issued_sink_writer_identity if {
	member := "serviceAccount:p123456789-123456@gcp-sa-logging.iam.gserviceaccount.com"
	violations := deny with input as {
		"variables": {
			"environment": {"value": "production"},
			"approved_iam_principals": {"value": [member]},
		},
		"resource_changes": [{
			"address": "module.stack.module.backend.google_project_iam_member.sink_writer[\"source-project\"]",
			"type": "google_project_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/logging.bucketWriter",
				"member": member,
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_project_outside_catalog_class_controls if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.project.google_project.this[0]",
			"type": "google_project",
			"change": {"actions": ["create"], "after": {
				"folder_id": "",
				"billing_account": "",
				"deletion_policy": "DELETE",
				"labels": {
					"environment": "development",
					"owner": "infrastructure",
					"data_classification": "internal",
					"cost_center": "platform",
				},
			}},
		}],
	}
	count(violations) == 3
}

test_accepts_provider_shaped_catalog_project_class if {
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": [
			"folders/1234567890",
			"000000-000000-000000",
		]}},
		"resource_changes": [{
			"address": "module.stack.module.project.google_project.this[0]",
			"type": "google_project",
			"change": {"actions": ["create"], "after": {
				"folder_id": "folders/1234567890",
				"billing_account": "000000-000000-000000",
				"deletion_policy": "PREVENT",
				"labels": {
					"environment": "development",
					"owner": "infrastructure",
					"data_classification": "internal",
					"cost_center": "platform",
				},
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_provider_resource_outside_catalog_primary_location if {
	violations := deny with input as {
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.this[0]",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"location": "us-east1",
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_resource_in_catalog_primary_location if {
	violations := deny with input as {
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.this[0]",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"location": "us-central1",
			}},
		}],
	}
	count(violations) == 0
}

test_accepts_only_catalog_enabled_ci_evidence_location_override if {
	violations := deny with input as {
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
			"ci_evidence_archive": {"enabled": true, "location": "NAM4"},
		}}}},
		"resource_changes": [
			{
				"address": "module.stack.module.ci_evidence_archive_bucket.google_storage_bucket.this[\"project-production-ci-evidence\"]",
				"type": "google_storage_bucket",
				"change": {"actions": ["create"], "after": {"location": "NAM4"}},
			},
			{
				"address": "module.stack.module.ci_evidence_archive_kms.google_kms_key_ring.this[0]",
				"type": "google_kms_key_ring",
				"change": {"actions": ["create"], "after": {"location": "nam4"}},
			},
		],
	}
	count(violations) == 0
}

test_rejects_nam4_for_non_evidence_resources if {
	violations := deny with input as {
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
			"ci_evidence_archive": {"enabled": true, "location": "NAM4"},
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.buckets.google_storage_bucket.this[\"ordinary-artifacts\"]",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {"location": "NAM4"}},
		}],
	}
	count(violations) == 1
}

test_rejects_disabled_ci_evidence_location_override if {
	violations := deny with input as {
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
			"ci_evidence_archive": {"enabled": false, "location": "NAM4"},
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.ci_evidence_archive_bucket.google_storage_bucket.this[\"project-production-ci-evidence\"]",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {"location": "NAM4"}},
		}],
	}
	count(violations) == 1
}

test_rejects_restricted_cluster_referencing_development_network if {
	violations := deny with input as {
		"variables": {
			"environment": {"value": "restricted"},
			"approved_resource_references": {"value": [
				"restricted-project",
				"projects/restricted-host/global/networks/restricted-vpc",
				"projects/restricted-host/regions/us-central1/subnetworks/restricted-gke",
			]},
		},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.this[0]",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"project": "restricted-project",
				"location": "us-central1",
				"network": "projects/development-host/global/networks/development-vpc",
				"subnetwork": "projects/restricted-host/regions/us-central1/subnetworks/restricted-gke",
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_restricted_dns_referencing_development_network if {
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": [
			"restricted-project",
			"projects/restricted-host/global/networks/restricted-vpc",
		]}},
		"resource_changes": [{
			"address": "module.stack.module.private_dns.google_dns_managed_zone.private[\"services\"]",
			"type": "google_dns_managed_zone",
			"change": {"actions": ["create"], "after": {
				"project": "restricted-project",
				"private_visibility_config": [{"networks": [{
					"network_url": "projects/development-host/global/networks/development-vpc",
				}]}],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_same_environment_cluster_references if {
	references := [
		"restricted-project",
		"projects/restricted-host/global/networks/restricted-vpc",
		"projects/restricted-host/regions/us-central1/subnetworks/restricted-gke",
	]
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": references}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.this[0]",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"project": references[0],
				"location": "us-central1",
				"network": references[1],
				"subnetwork": references[2],
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_unknown_provider_network_reference if {
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": ["restricted-project"]}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.this[0]",
			"type": "google_container_cluster",
			"change": {
				"actions": ["create"],
				"after": {"project": "restricted-project", "location": "us-central1", "network": null},
				"after_unknown": {"network": true},
			},
		}],
	}
	count(violations) == 1
}

test_rejects_unapproved_provider_shaped_bucket_cmek if {
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": ["restricted-project"]}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"recovery_location": "us-east1",
		}}}},
		"resource_changes": [{
			"address": "module.stack.module.buckets.google_storage_bucket.this[\"restricted-artifacts\"]",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {
				"project": "restricted-project",
				"location": "US-CENTRAL1",
				"encryption": [{"default_kms_key_name": "projects/development/locations/us-central1/keyRings/data/cryptoKeys/artifacts"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_provider_shaped_mutable_buildkite_images if {
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": [
			"projects/base-images/global/images/family/stable",
		]}},
		"resource_changes": [{
			"address": "module.stack.module.agents.google_compute_instance_template.agent[0]",
			"type": "google_compute_instance_template",
			"change": {"actions": ["create"], "after": {
				"disk": [{"source_image": "projects/base-images/global/images/family/stable"}],
				"metadata": {"gce-container-declaration": "image: us-docker.pkg.dev/build/agents/agent:latest"},
			}},
		}],
	}
	count(violations) == 3
}

test_accepts_provider_shaped_immutable_buildkite_images if {
	boot_image := "projects/base-images/global/images/buildkite-20260829"
	agent_image := "us-docker.pkg.dev/build/agents/agent@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	secret_resource := "projects/build-project/secrets/buildkite-agent-token/versions/7"
	startup_script := sprintf("#!/bin/bash\nreadonly image_b64='%s'\nreadonly secret_resource_b64='%s'\nMetadata-Flavor: Google\ndocker run --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --env BUILDKITE_AGENT_DISCONNECT_AFTER_JOB=true --env BUILDKITE_AGENT_DISCONNECT_AFTER_IDLE_TIMEOUT=300\nshutdown -h now", [
		base64.encode(agent_image),
		base64.encode(secret_resource),
	])
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": [boot_image, agent_image, secret_resource]}},
		"resource_changes": [{
			"address": "module.stack.module.agents.google_compute_instance_template.agent[0]",
			"type": "google_compute_instance_template",
			"change": {"actions": ["create"], "after": {
				"disk": [{"source_image": boot_image}],
				"metadata": {"startup-script": startup_script},
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_mutable_startup_agent_image if {
	boot_image := "projects/base-images/global/images/buildkite-20260829"
	agent_image := "us-docker.pkg.dev/build/agents/agent:latest"
	secret_resource := "projects/build-project/secrets/buildkite-agent-token/versions/7"
	startup_script := sprintf("#!/bin/bash\nreadonly image_b64='%s'\nreadonly secret_resource_b64='%s'\nMetadata-Flavor: Google\ndocker run --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --env BUILDKITE_AGENT_DISCONNECT_AFTER_JOB=true --env BUILDKITE_AGENT_DISCONNECT_AFTER_IDLE_TIMEOUT=300\nshutdown -h now", [
		base64.encode(agent_image),
		base64.encode(secret_resource),
	])
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": [
			boot_image,
			agent_image,
			secret_resource,
		]}},
		"resource_changes": [{
			"address": "module.stack.module.agents.google_compute_instance_template.agent[0]",
			"type": "google_compute_instance_template",
			"change": {"actions": ["create"], "after": {
				"disk": [{"source_image": boot_image}],
				"metadata": {"startup-script": startup_script},
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_shell_metacharacters_hidden_in_encoded_agent_image if {
	secret_resource := "projects/build-project/secrets/buildkite-agent-token/versions/7"
	encoded_secret_resource := base64.encode(secret_resource)
	unsafe_images := {
		"cmVwby9pbWFnZSc7aWQ+L3RtcC9wd247I0BzaGEyNTY6YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==",
		"cmVwby9pbWFnZTtpZEBzaGEyNTY6YWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYQ==",
		"cmVwby9pbWFnZSQoaWQpQHNoYTI1NjphYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh",
		"cmVwby9pbWFnZWBpZGBAc2hhMjU2OmFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWE=",
		"cmVwby9pbWFnZVxcYmFkQHNoYTI1NjphYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFhYWFh",
	}
	every encoded in unsafe_images {
		violations := deny with input as {
			"variables": {"approved_resource_references": {"value": [
				"projects/base-images/global/images/buildkite-20260829",
				base64.decode(encoded),
				secret_resource,
			]}},
			"resource_changes": [{
				"address": "module.stack.module.agents.google_compute_instance_template.agent[0]",
				"type": "google_compute_instance_template",
				"change": {"actions": ["create"], "after": {
					"disk": [{"source_image": "projects/base-images/global/images/buildkite-20260829"}],
					"metadata": {"startup-script": sprintf("#!/bin/bash\nreadonly image_b64='%s'\nreadonly secret_resource_b64='%s'\nMetadata-Flavor: Google\ndocker run --read-only --cap-drop=ALL --security-opt=no-new-privileges:true --env BUILDKITE_AGENT_DISCONNECT_AFTER_JOB=true --env BUILDKITE_AGENT_DISCONNECT_AFTER_IDLE_TIMEOUT=300\nshutdown -h now", [encoded, encoded_secret_resource])},
				}},
			}],
		}
		count(violations) == 1
	}
}

test_accepts_exact_ci_evidence_writer_verifier_and_service_agent_role_separation if {
	verifier := "serviceAccount:ci-evidence-verifier@identity-project.iam.gserviceaccount.com"
	writer := "serviceAccount:ci-evidence-writer@identity-project.iam.gserviceaccount.com"
	insights := "serviceAccount:service-123456789012@gcp-sa-storageinsights.iam.gserviceaccount.com"
	storage_agent := "serviceAccount:service-123456789012@gs-project-accounts.iam.gserviceaccount.com"
	bucket := "project-production-ci-evidence"
	violations := deny with input as {
		"variables": {
			"approved_iam_principals": {"value": [verifier, writer, insights, storage_agent]},
			"approved_resource_references": {"value": [bucket, "kms-key"]},
		},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"ci_evidence_archive": {
				"verifier_principal": verifier,
				"writer_principal": writer,
				"storage_insights_agent": insights,
				"storage_service_agent": storage_agent,
			},
		}}}},
		"resource_changes": [
			archive_bucket_iam_change("viewer", "roles/storage.objectViewer", verifier, bucket),
			archive_bucket_iam_change("writer", "roles/storage.objectCreator", writer, bucket),
			archive_bucket_iam_change("inventory-writer", "roles/storage.objectCreator", insights, bucket),
			archive_bucket_iam_change("inventory-reader", "roles/storage.insightsCollectorService", insights, bucket),
			{
				"address": "module.stack.module.ci_evidence_archive_kms.google_kms_crypto_key_iam_member.encrypter_decrypter[\"archive\"]",
				"type": "google_kms_crypto_key_iam_member",
				"change": {"actions": ["create"], "after": {
					"crypto_key_id": "kms-key",
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"member": storage_agent,
				}},
			},
		],
	}
	count(violations) == 0
}

test_rejects_ci_evidence_writer_verifier_swap_even_when_both_are_approved if {
	verifier := "serviceAccount:ci-evidence-verifier@identity-project.iam.gserviceaccount.com"
	writer := "serviceAccount:ci-evidence-writer@identity-project.iam.gserviceaccount.com"
	bucket := "project-production-ci-evidence"
	violations := deny with input as {
		"variables": {
			"approved_iam_principals": {"value": [verifier, writer]},
			"approved_resource_references": {"value": [bucket]},
		},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"ci_evidence_archive": {"verifier_principal": verifier, "writer_principal": writer},
		}}}},
		"resource_changes": [archive_bucket_iam_change("swapped", "roles/storage.objectViewer", writer, bucket)],
	}
	count(violations) == 1
}

test_rejects_ci_evidence_principal_set_even_when_generically_approved if {
	principal := "principalSet://iam.googleapis.com/projects/123/locations/global/workloadIdentityPools/pool/attribute.role/writer"
	bucket := "project-production-ci-evidence"
	violations := deny with input as {
		"variables": {
			"approved_iam_principals": {"value": [principal]},
			"approved_resource_references": {"value": [bucket]},
		},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"ci_evidence_archive": {
				"writer_principal": "serviceAccount:ci-evidence-writer@identity-project.iam.gserviceaccount.com",
			},
		}}}},
		"resource_changes": [archive_bucket_iam_change("principal-set", "roles/storage.objectCreator", principal, bucket)],
	}
	count(violations) == 1
}

test_accepts_exact_ci_evidence_audit_sink_alert_and_inventory_plan if {
	project := "evidence-project"
	bucket := "evidence-project-production-ci-evidence"
	destination := sprintf("storage.googleapis.com/%s", [bucket])
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": [project, destination]}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"primary_location": "us-central1",
			"ci_evidence_archive": {
				"enabled": true,
				"project_id": project,
				"bucket_name": bucket,
				"location": "NAM4",
			},
		}}}},
		"resource_changes": [
			{
				"address": "module.stack.google_project_iam_audit_config.ci_evidence_storage[0]",
				"type": "google_project_iam_audit_config",
				"change": {"actions": ["create"], "after": {
					"project": project,
					"service": "storage.googleapis.com",
					"audit_log_config": [
						{"log_type": "DATA_READ", "exempted_members": []},
						{"log_type": "DATA_WRITE", "exempted_members": []},
					],
				}},
			},
			{
				"address": "module.stack.google_logging_project_sink.ci_evidence_audit[0]",
				"type": "google_logging_project_sink",
				"change": {"actions": ["create"], "after": {
					"project": project,
					"name": "mindclade-ci-evidence-audit",
					"destination": destination,
					"unique_writer_identity": true,
					"filter": sprintf("resource.labels.bucket_name=\"%s\" cloudaudit.googleapis.com/activity cloudaudit.googleapis.com/data_access", [bucket]),
				}},
			},
			{
				"address": "module.stack.google_logging_metric.ci_evidence_security_event[0]",
				"type": "google_logging_metric",
				"change": {"actions": ["create"], "after": {
					"project": project,
					"name": "ci_evidence_archive_security_event",
					"filter": "storage\\.(buckets\\.(delete|lockRetentionPolicy|setIamPolicy|update)|objects\\.delete) protoPayload.status.code!=0",
				}},
			},
			{
				"address": "module.stack.google_monitoring_alert_policy.ci_evidence_security_event[0]",
				"type": "google_monitoring_alert_policy",
				"change": {"actions": ["create"], "after": {
					"project": project,
					"enabled": true,
					"notification_channels": ["projects/evidence-project/notificationChannels/1"],
					"conditions": [{}],
				}},
			},
			{
				"address": "module.stack.google_storage_insights_report_config.ci_evidence_inventory[0]",
				"type": "google_storage_insights_report_config",
				"change": {"actions": ["create"], "after": {
					"project": project,
					"location": "NAM4",
					"deletion_policy": "PREVENT",
					"force_destroy": false,
					"frequency_options": [{"frequency": "DAILY"}],
					"object_metadata_report_options": [{
						"metadata_fields": ["crc32c", "name", "retentionExpirationTime", "size"],
						"storage_filters": [{"bucket": bucket}],
						"storage_destination_options": [{"bucket": bucket, "destination_path": "inventory/"}],
					}],
				}},
			},
		],
	}
	count(violations) == 0
}

test_rejects_ci_evidence_data_access_audit_exemption if {
	project := "evidence-project"
	violations := deny with input as {
		"variables": {"approved_resource_references": {"value": [project]}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"ci_evidence_archive": {"project_id": project},
		}}}},
		"resource_changes": [{
			"address": "module.stack.google_project_iam_audit_config.ci_evidence_storage[0]",
			"type": "google_project_iam_audit_config",
			"change": {"actions": ["create"], "after": {
				"project": project,
				"service": "storage.googleapis.com",
				"audit_log_config": [
					{"log_type": "DATA_READ", "exempted_members": ["serviceAccount:excluded@example.iam.gserviceaccount.com"]},
					{"log_type": "DATA_WRITE", "exempted_members": []},
				],
			}},
		}],
	}
	count(violations) == 1
}

archive_bucket_iam_change(key, role, member, bucket) := {
	"address": sprintf("module.stack.module.ci_evidence_archive_bucket.google_storage_bucket_iam_member.access[\"%s\"]", [key]),
	"type": "google_storage_bucket_iam_member",
	"change": {"actions": ["create"], "after": {
		"bucket": bucket,
		"role": role,
		"member": member,
	}},
}
