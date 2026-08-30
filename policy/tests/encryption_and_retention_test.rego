package mindclade.infrastructure.encryption_and_retention

import rego.v1

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
			"change": {"actions": ["create"], "after": {"labels": {"data_classification": "internal"}}},
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
				"change": {"actions": ["create"], "after": {"labels": {"data_classification": "internal"}}},
			},
			{
				"address": "module.stack.module.kms.google_kms_crypto_key_iam_member.encrypter_decrypter[\"logs-agent\"]",
				"type": "google_kms_crypto_key_iam_member",
				"change": {"actions": ["create"], "after": {
					"role": "roles/cloudkms.cryptoKeyEncrypterDecrypter",
					"member": "serviceAccount:service-123456789@gcp-sa-logging.iam.gserviceaccount.com",
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
