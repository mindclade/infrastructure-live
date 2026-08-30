package mindclade.infrastructure.database_recovery

import rego.v1

test_rejects_unrecoverable_database if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_sql_database_instance.primary",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {"settings": [{"backup_configuration": [{"enabled": false, "point_in_time_recovery_enabled": false}], "user_labels": {"environment": "development"}}]}},
		}],
	}
	count(violations) == 2
}

test_accepts_recoverable_development_database if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_sql_database_instance.primary",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {"settings": [{"backup_configuration": [{"enabled": true, "point_in_time_recovery_enabled": true}], "user_labels": {"environment": "development"}}]}},
		}],
	}
	count(violations) == 0
}

test_rejects_provider_shaped_unprotected_production_database if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.postgres.google_sql_database_instance.this",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {
				"deletion_protection": false,
				"settings": [{
					"availability_type": "ZONAL",
					"user_labels": {"environment": "production"},
					"backup_configuration": [{"enabled": true, "point_in_time_recovery_enabled": true, "backup_retention_settings": [{"retained_backups": 35}]}],
				}],
			}},
		}],
	}
	count(violations) == 2
}

test_rejects_staging_database_below_catalog_retention if {
	violations := deny with input as {
		"variables": {"environment": {"value": "staging"}},
		"resource_changes": [{
			"address": "module.stack.module.postgres.google_sql_database_instance.this[0]",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {
				"deletion_protection": true,
				"settings": [{
					"availability_type": "REGIONAL",
					"backup_configuration": [{
						"enabled": true,
						"point_in_time_recovery_enabled": true,
						"backup_retention_settings": [{"retained_backups": 7}],
					}],
				}],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_profile_compliant_database if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.postgres.google_sql_database_instance.this[0]",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {
				"deletion_protection": true,
				"settings": [{
					"availability_type": "REGIONAL",
					"backup_configuration": [{
						"enabled": true,
						"point_in_time_recovery_enabled": true,
						"backup_retention_settings": [{"retained_backups": 35}],
					}],
				}],
			}},
		}],
	}
	count(violations) == 0
}
