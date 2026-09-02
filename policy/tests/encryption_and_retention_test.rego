package mindclade.infrastructure.encryption_and_retention

import rego.v1

disabled_cache_boundary := {
	"schema_version": "cache-boundary.v2",
	"qualification": "DISABLED",
	"source_revision": null,
	"cache_mode": "disabled",
	"cache_used": false,
	"cache_outputs_are_evidence": false,
	"endpoint": null,
	"namespace": {
		"schema_version": "cache-namespace.v2",
		"classification": "internal",
		"namespace_epoch": "disabled-v2",
		"trust_class": "untrusted",
		"system": "aarch64-linux",
		"toolchain_digest": null,
		"build_mode": "cacheless",
	},
	"iam_qualification_digest": null,
	"write_activation_digest": null,
	"signer_public_key_digest": null,
	"audit_sink_digest": null,
	"cacheless_canary": {"required": true, "status": "NOT_RUN", "evidence_locator": null, "evidence_digest": null},
	"poison_recovery": {"required": true, "status": "NOT_RUN", "runbook": "runbooks/nix-cache-recovery.md", "evidence_locator": null, "evidence_digest": null},
}

disabled_cache_contract := {
	"kind": "NixCacheContract",
	"boundary": disabled_cache_boundary,
	"legacy_v1_compatibility_enabled": false,
	"gateway": {
		"hostname": "nix-cache.mindclade.com",
		"scheme": "https",
		"allowed_methods": ["GET", "HEAD"],
		"authentication": "google-oidc-bearer-or-netrc",
		"implementation": "external-managed-https-gateway",
	},
	"iam": {
		"publisher_roles": ["roles/storage.objectCreator"],
		"gateway_roles": ["roles/storage.objectViewer"],
		"audit_sink_writer_bound_by_cache_owner": false,
	},
}

qualified_cache_health := {
	"cacheless_canary": {
		"required": true,
		"status": "PASSED",
		"evidence_locator": "gs://mindclade-evidence/cache/canary.json#17",
		"evidence_digest": sprintf("sha256:%064d", [1]),
	},
	"poison_recovery": {
		"required": true,
		"status": "PASSED",
		"runbook": "runbooks/nix-cache-recovery.md",
		"evidence_locator": "gs://mindclade-evidence/cache/recovery.json#19",
		"evidence_digest": sprintf("sha256:%064d", [2]),
	},
}

read_cache_boundary := object.union(disabled_cache_boundary, object.union(qualified_cache_health, {
	"qualification": "IAM_QUALIFIED",
	"source_revision": sprintf("%040d", [1]),
	"cache_mode": "read",
	"cache_used": true,
	"endpoint": "https://nix-cache.mindclade.com",
	"namespace": {
		"namespace_epoch": "epoch-1",
		"trust_class": "verified",
		"toolchain_digest": sprintf("sha256:%064d", [3]),
		"build_mode": "substitute-read",
	},
	"iam_qualification_digest": sprintf("sha256:%064d", [4]),
	"signer_public_key_digest": sprintf("sha256:%064d", [5]),
	"audit_sink_digest": sprintf("sha256:%064d", [6]),
}))

write_cache_boundary := object.union(read_cache_boundary, {
	"qualification": "WRITE_ACTIVATED",
	"cache_mode": "write",
	"namespace": {"trust_class": "protected", "build_mode": "substitute-write"},
	"write_activation_digest": sprintf("sha256:%064d", [7]),
})

test_accepts_disabled_cache_boundary_v2 if {
	violations := deny with input as disabled_cache_contract
	count(violations) == 0
}

test_accepts_iam_qualified_read_boundary if {
	candidate := object.union(disabled_cache_contract, {"boundary": read_cache_boundary})
	violations := deny with input as candidate
	count(violations) == 0
}

test_accepts_protected_write_activated_boundary if {
	candidate := object.union(disabled_cache_contract, {"boundary": write_cache_boundary})
	violations := deny with input as candidate
	count(violations) == 0
}

test_rejects_read_without_iam_qualification_digest if {
	bad_boundary := object.union(read_cache_boundary, {"iam_qualification_digest": null})
	candidate := object.union(disabled_cache_contract, {"boundary": bad_boundary})
	violations := deny with input as candidate
	count(violations) == 1
}

test_rejects_write_without_protected_trust if {
	bad_boundary := object.union(write_cache_boundary, {"namespace": {"trust_class": "verified"}})
	candidate := object.union(disabled_cache_contract, {"boundary": bad_boundary})
	violations := deny with input as candidate
	count(violations) == 1
}

test_rejects_cache_poison_recovery_bypass if {
	bad_recovery := object.union(disabled_cache_boundary.poison_recovery, {"required": false})
	bad_boundary := object.union(disabled_cache_boundary, {"poison_recovery": bad_recovery})
	candidate := object.union(disabled_cache_contract, {"boundary": bad_boundary})
	violations := deny with input as candidate
	count(violations) == 1
}

test_rejects_cache_publisher_read_authority if {
	bad_iam := object.union(disabled_cache_contract.iam, {"publisher_roles": ["roles/storage.objectAdmin"]})
	candidate := object.union(disabled_cache_contract, {"iam": bad_iam})
	violations := deny with input as candidate
	count(violations) == 1
}

test_rejects_publicly_exposable_bucket if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_storage_bucket.artifacts",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {"uniform_bucket_level_access": false, "public_access_prevention": "inherited", "labels": {"data_classification": "public"}}},
		}],
	}
	count(violations) == 2
}

test_accepts_hardened_standard_bucket if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_storage_bucket.artifacts",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {"uniform_bucket_level_access": true, "public_access_prevention": "enforced", "labels": {"data_classification": "internal"}, "retention_policy": [{"retention_period": 2592000}]}},
		}],
	}
	count(violations) == 0
}

test_rejects_storage_without_data_classification if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_storage_bucket.artifacts",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {
				"uniform_bucket_level_access": true,
				"public_access_prevention": "enforced",
				"labels": {},
				"retention_policy": [{"retention_period": 31536000}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_restricted_storage_below_catalog_retention if {
	violations := deny with input as {
		"variables": {"environment": {"value": "restricted"}},
		"resource_changes": [{
			"address": "google_storage_bucket.restricted",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {
				"uniform_bucket_level_access": true,
				"public_access_prevention": "enforced",
				"labels": {"data_classification": "restricted"},
				"retention_policy": [{"retention_period": 604800, "is_locked": true}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_unlocked_restricted_storage if {
	violations := deny with input as {
		"variables": {"environment": {"value": "restricted"}},
		"resource_changes": [{
			"address": "google_storage_bucket.restricted",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {
				"uniform_bucket_level_access": true,
				"public_access_prevention": "enforced",
				"labels": {"data_classification": "restricted"},
				"retention_policy": [{"retention_period": 31536000, "is_locked": false}],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_locked_restricted_storage if {
	violations := deny with input as {
		"variables": {"environment": {"value": "restricted"}},
		"resource_changes": [{
			"address": "google_storage_bucket.restricted",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {
				"uniform_bucket_level_access": true,
				"public_access_prevention": "enforced",
				"labels": {"data_classification": "restricted"},
				"retention_policy": [{"retention_period": 31536000, "is_locked": true}],
			}},
		}],
	}
	count(violations) == 0
}

test_accepts_production_ci_evidence_archive_contract if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.ci_evidence_archive_bucket.google_storage_bucket.this[\"project-production-ci-evidence\"]",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {
				"storage_class": "STANDARD",
				"rpo": "DEFAULT",
				"force_destroy": false,
				"uniform_bucket_level_access": true,
				"public_access_prevention": "enforced",
				"labels": {"data_classification": "internal", "purpose": "ci-evidence"},
				"versioning": [{"enabled": false}],
				"soft_delete_policy": [{"retention_duration_seconds": 2592000}],
				"retention_policy": [{"retention_period": 220752000, "is_locked": false}],
				"encryption": [{"default_kms_key_name": "projects/project/locations/nam4/keyRings/ci-evidence/cryptoKeys/archive"}],
				"lifecycle_rule": [
					{
						"action": [{"type": "SetStorageClass", "storage_class": "ARCHIVE"}],
						"condition": [{"age": 90, "size_above_bytes": 1048576, "matches_storage_class": ["STANDARD"], "with_state": "LIVE"}],
					},
					{
						"action": [{"type": "Delete"}],
						"condition": [{"age": 2555, "matches_storage_class": ["STANDARD", "ARCHIVE"], "with_state": "LIVE"}],
					},
				],
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_ci_evidence_archive_lifecycle_drift if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.ci_evidence_archive_bucket.google_storage_bucket.this[\"project-production-ci-evidence\"]",
			"type": "google_storage_bucket",
			"change": {"actions": ["update"], "after": {
				"storage_class": "STANDARD",
				"rpo": "DEFAULT",
				"force_destroy": false,
				"uniform_bucket_level_access": true,
				"public_access_prevention": "enforced",
				"labels": {"data_classification": "internal", "purpose": "ci-evidence"},
				"versioning": [{"enabled": false}],
				"soft_delete_policy": [{"retention_duration_seconds": 2592000}],
				"retention_policy": [{"retention_period": 220752000, "is_locked": false}],
				"encryption": [{"default_kms_key_name": "projects/project/locations/nam4/keyRings/ci-evidence/cryptoKeys/archive"}],
				"lifecycle_rule": [],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_ci_evidence_archive_software_key if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.ci_evidence_archive_kms.google_kms_crypto_key.this[\"archive\"]",
			"type": "google_kms_crypto_key",
			"change": {"actions": ["update"], "after": {
				"version_template": [{"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protection_level": "SOFTWARE"}],
				"rotation_period": "7776000s",
				"labels": {"data_classification": "internal", "purpose": "ci-evidence"},
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_ci_evidence_archive_key_contract_drift if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.ci_evidence_archive_kms.google_kms_crypto_key.this[\"archive\"]",
			"type": "google_kms_crypto_key",
			"change": {"actions": ["update"], "after": {
				"version_template": [{"algorithm": "GOOGLE_SYMMETRIC_ENCRYPTION", "protection_level": "HSM"}],
				"rotation_period": "7776000s",
				"labels": {"data_classification": "internal", "purpose": "ci-evidence"},
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_short_restricted_observability_retention if {
	violations := deny with input as {
		"variables": {"environment": {"value": "restricted"}},
		"resource_changes": [{
			"address": "module.stack.module.backend.google_logging_project_bucket_config.platform[0]",
			"type": "google_logging_project_bucket_config",
			"change": {"actions": ["create"], "after": {
				"retention_days": 90,
				"cmek_settings": [{"kms_key_name": "projects/logging/locations/us/keyRings/logs/cryptoKeys/platform"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_observability_without_cmek if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.backend.google_logging_project_bucket_config.platform[0]",
			"type": "google_logging_project_bucket_config",
			"change": {"actions": ["create"], "after": {"retention_days": 90, "cmek_settings": []}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_protected_observability_bucket if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.backend.google_logging_project_bucket_config.platform[0]",
			"type": "google_logging_project_bucket_config",
			"change": {"actions": ["create"], "after": {
				"retention_days": 90,
				"cmek_settings": [{"kms_key_name": "projects/logging/locations/us/keyRings/logs/cryptoKeys/platform"}],
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_new_cmek_without_qualified_service_agent if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.kms.google_kms_crypto_key.this[\"logs\"]",
			"type": "google_kms_crypto_key",
			"change": {"actions": ["create"], "after": {
				"key_ring": "projects/logging/locations/us/keyRings/logs",
				"name": "platform",
				"labels": {"data_classification": "internal"},
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_new_cmek_with_qualified_service_agent if {
	violations := deny with input as {
		"resource_changes": [
			{
				"address": "module.stack.module.kms.google_kms_crypto_key.this[\"logs\"]",
				"type": "google_kms_crypto_key",
				"change": {"actions": ["create"], "after": {
					"key_ring": "projects/logging/locations/us/keyRings/logs",
					"name": "platform",
					"labels": {"data_classification": "internal"},
				}},
			},
			{
				"address": "module.stack.module.kms.google_kms_crypto_key_iam_member.encrypter_decrypter[\"logs-agent\"]",
				"type": "google_kms_crypto_key_iam_member",
				"change": {"actions": ["create"], "after": {
					"crypto_key_id": "projects/logging/locations/us/keyRings/logs/cryptoKeys/platform",
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"member": "serviceAccount:service-123456789@gcp-sa-logging.iam.gserviceaccount.com",
				}},
			},
		],
	}
	count(violations) == 0
}

test_rejects_each_new_cmek_without_its_own_binding if {
	violations := deny with input as {
		"resource_changes": [
			{
				"address": "module.stack.module.kms.google_kms_crypto_key.this[\"logs\"]",
				"type": "google_kms_crypto_key",
				"change": {"actions": ["create"], "after": {
					"key_ring": "projects/platform/locations/us/keyRings/shared",
					"name": "logs",
					"labels": {"data_classification": "internal"},
				}},
			},
			{
				"address": "module.stack.module.kms.google_kms_crypto_key.this[\"metrics\"]",
				"type": "google_kms_crypto_key",
				"change": {"actions": ["create"], "after": {
					"key_ring": "projects/platform/locations/us/keyRings/shared",
					"name": "metrics",
					"labels": {"data_classification": "internal"},
				}},
			},
			{
				"address": "module.stack.module.kms.google_kms_crypto_key_iam_member.encrypter_decrypter[\"logs-agent\"]",
				"type": "google_kms_crypto_key_iam_member",
				"change": {"actions": ["create"], "after": {
					"crypto_key_id": "projects/platform/locations/us/keyRings/shared/cryptoKeys/logs",
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"member": "serviceAccount:service-123456789@gcp-sa-logging.iam.gserviceaccount.com",
				}},
			},
		],
	}
	count(violations) == 1
	some message in violations
	contains(message, `google_kms_crypto_key.this["metrics"]`)
}

test_accepts_multiple_new_cmeks_with_corresponding_bindings if {
	violations := deny with input as {
		"resource_changes": [
			{
				"address": "module.stack.module.kms.google_kms_crypto_key.this[\"logs\"]",
				"type": "google_kms_crypto_key",
				"change": {"actions": ["create"], "after": {
					"key_ring": "projects/platform/locations/us/keyRings/shared",
					"name": "logs",
					"labels": {"data_classification": "internal"},
				}},
			},
			{
				"address": "module.stack.module.kms.google_kms_crypto_key.this[\"metrics\"]",
				"type": "google_kms_crypto_key",
				"change": {"actions": ["create"], "after": {
					"key_ring": "projects/platform/locations/us/keyRings/shared",
					"name": "metrics",
					"labels": {"data_classification": "internal"},
				}},
			},
			{
				"address": "module.stack.module.kms.google_kms_crypto_key_iam_member.encrypter_decrypter[\"logs-agent\"]",
				"type": "google_kms_crypto_key_iam_member",
				"change": {"actions": ["create"], "after": {
					"crypto_key_id": "projects/platform/locations/us/keyRings/shared/cryptoKeys/logs",
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"member": "serviceAccount:service-123456789@gcp-sa-logging.iam.gserviceaccount.com",
				}},
			},
			{
				"address": "module.stack.module.kms.google_kms_crypto_key_iam_member.encrypter_decrypter[\"metrics-agent\"]",
				"type": "google_kms_crypto_key_iam_member",
				"change": {"actions": ["create"], "after": {
					"crypto_key_id": "projects/platform/locations/us/keyRings/shared/cryptoKeys/metrics",
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"member": "serviceAccount:service-123456789@gcp-sa-monitoring.iam.gserviceaccount.com",
				}},
			},
		],
	}
	count(violations) == 0
}

test_rejects_non_service_account_cmek_binding if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_kms_crypto_key_iam_member.unsafe",
			"type": "google_kms_crypto_key_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
				"member": "group:operators@mindclade.dev",
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_restricted_root_data_mislabel if {
	violations := deny with input as {
		"variables": {"environment": {"value": "restricted"}},
		"resource_changes": [{
			"address": "google_pubsub_topic.events",
			"type": "google_pubsub_topic",
			"change": {"actions": ["create"], "after": {"labels": {"data_classification": "confidential"}}},
		}],
	}
	count(violations) == 1
}

test_rejects_restricted_project_with_public_classification if {
	violations := deny with input as {
		"variables": {"environment": {"value": "restricted"}},
		"resource_changes": [{
			"address": "module.stack.module.project.google_project.this[0]",
			"type": "google_project",
			"change": {"actions": ["create"], "after": {
				"labels": {"data_classification": "public"},
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_restricted_project_with_restricted_classification if {
	violations := deny with input as {
		"variables": {"environment": {"value": "restricted"}},
		"resource_changes": [{
			"address": "module.stack.module.project.google_project.this[0]",
			"type": "google_project",
			"change": {"actions": ["create"], "after": {
				"labels": {"data_classification": "restricted"},
			}},
		}],
	}
	count(violations) == 0
}

test_accepts_production_catalog_data_class if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "google_storage_bucket.artifacts",
			"type": "google_storage_bucket",
			"change": {"actions": ["create"], "after": {
				"uniform_bucket_level_access": true,
				"public_access_prevention": "enforced",
				"labels": {"data_classification": "confidential"},
				"retention_policy": [{"retention_period": 7776000}],
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_provider_shaped_mutable_docker_tags if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_artifact_registry_repository.images",
			"type": "google_artifact_registry_repository",
			"change": {"actions": ["create"], "after": {
				"format": "DOCKER",
				"docker_config": [{"immutable_tags": false}],
				"labels": {"data_classification": "internal"},
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_immutable_docker_tags if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_artifact_registry_repository.images",
			"type": "google_artifact_registry_repository",
			"change": {"actions": ["create"], "after": {
				"format": "DOCKER",
				"docker_config": [{"immutable_tags": true}],
				"labels": {"data_classification": "internal"},
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_provider_shaped_protected_database_without_cmek if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.postgres.google_sql_database_instance.this",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {
				"encryption_key_name": "",
				"settings": [{"user_labels": {"data_classification": "confidential"}}],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_protected_database_with_cmek if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.postgres.google_sql_database_instance.this",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {
				"encryption_key_name": "projects/logical/locations/us/keyRings/data/cryptoKeys/database",
				"settings": [{"user_labels": {"data_classification": "restricted"}}],
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_ci_evidence_retention_lock_without_receipt if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"ci_evidence_archive": {"retention_locked": true, "retention_lock_receipt": null},
		}}}},
		"resource_changes": [archive_lock_change(true)],
	}
	count(violations) == 1
}

test_rejects_ci_evidence_retention_lock_even_with_self_asserted_generation_bound_receipt if {
	bucket := "project-production-ci-evidence"
	verifier := "serviceAccount:ci-evidence-verifier@identity-project.iam.gserviceaccount.com"
	receipt := exact_lock_receipt(bucket, verifier)
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"ci_evidence_archive": {
				"retention_locked": true,
				"retention_lock_receipt": receipt,
				"verifier_principal": verifier,
			},
		}}}},
		"resource_changes": [archive_lock_change(true)],
	}
	count(violations) == 1
}

test_rejects_ci_evidence_retention_lock_with_tampered_canary_generation if {
	bucket := "project-production-ci-evidence"
	verifier := "serviceAccount:ci-evidence-verifier@identity-project.iam.gserviceaccount.com"
	receipt := object.union(exact_lock_receipt(bucket, verifier), {"canaryGeneration": "43"})
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"planned_values": {"outputs": {"region_authority": {"value": {
			"ci_evidence_archive": {
				"retention_locked": true,
				"retention_lock_receipt": receipt,
				"verifier_principal": verifier,
			},
		}}}},
		"resource_changes": [archive_lock_change(true)],
	}
	count(violations) == 1
}

archive_lock_change(locked) := {
	"address": "module.stack.module.ci_evidence_archive_bucket.google_storage_bucket.this[\"project-production-ci-evidence\"]",
	"type": "google_storage_bucket",
	"change": {"actions": ["update"], "after": {
		"name": "project-production-ci-evidence",
		"location": "NAM4",
		"storage_class": "STANDARD",
		"rpo": "DEFAULT",
		"uniform_bucket_level_access": true,
		"public_access_prevention": "enforced",
		"force_destroy": false,
		"labels": {"data_classification": "internal", "purpose": "ci-evidence"},
		"versioning": [{"enabled": false}],
		"soft_delete_policy": [{"retention_duration_seconds": 2592000}],
		"retention_policy": [{"retention_period": 220752000, "is_locked": locked}],
		"encryption": [{"default_kms_key_name": "projects/project/locations/nam4/keyRings/ci-evidence/cryptoKeys/archive"}],
		"lifecycle_rule": [
			{"action": [{"type": "SetStorageClass", "storage_class": "ARCHIVE"}], "condition": [{"age": 90, "size_above_bytes": 1048576, "with_state": "LIVE", "matches_storage_class": ["STANDARD"]}]},
			{"action": [{"type": "Delete"}], "condition": [{"age": 2555, "with_state": "LIVE", "matches_storage_class": ["STANDARD", "ARCHIVE"]}]},
		],
	}},
}

exact_lock_receipt(bucket, verifier) := object.union(base, {
	"receiptDigest": sprintf("sha256:%s", [crypto.sha256(concat("\n", [
		base.receiptVersion,
		base.canaryObjectUri,
		base.canaryGeneration,
		base.verifierIdentity,
		base.verifierDigest,
		base.denialEvidenceDigest,
		base.auditEvidenceDigest,
		base.platformApprovalIdentity,
		base.securityApprovalIdentity,
		base.approvedAt,
		base.sourceCommit,
	]))]),
}) if {
	source_commit := "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	base := {
		"receiptVersion": "ci-evidence-retention-lock/v1",
		"canaryObjectUri": sprintf("gs://%s/qualification/canary/%s/evidence.json#42", [bucket, source_commit]),
		"canaryGeneration": "42",
		"verifierIdentity": verifier,
		"verifierDigest": "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
		"denialEvidenceDigest": "sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc",
		"auditEvidenceDigest": "sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd",
		"platformApprovalIdentity": "group:platform-operations@mindclade.dev",
		"securityApprovalIdentity": "group:security@mindclade.dev",
		"approvedAt": "2026-08-30T12:00:00Z",
		"sourceCommit": source_commit,
	}
}
