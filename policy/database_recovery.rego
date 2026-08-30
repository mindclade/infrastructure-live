package mindclade.infrastructure.database_recovery

import rego.v1

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_sql_database_instance"
	after := object.get(change.change, "after", {})
	settings := first(object.get(after, "settings", []))
	backup := first(object.get(settings, "backup_configuration", []))
	not object.get(backup, "enabled", false)
	message := sprintf("%s: automated backups are required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_sql_database_instance"
	after := object.get(change.change, "after", {})
	settings := first(object.get(after, "settings", []))
	backup := first(object.get(settings, "backup_configuration", []))
	not object.get(backup, "point_in_time_recovery_enabled", false)
	message := sprintf("%s: point-in-time recovery is required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_sql_database_instance"
	environment := root_environment
	environment in {"development", "staging", "production", "restricted"}
	after := object.get(change.change, "after", {})
	not object.get(after, "deletion_protection", false)
	message := sprintf("%s: %s resource profile requires deletion protection", [change.address, environment])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_sql_database_instance"
	environment := root_environment
	environment in {"staging", "production", "restricted"}
	after := object.get(change.change, "after", {})
	settings := first(object.get(after, "settings", []))
	object.get(settings, "availability_type", "") != "REGIONAL"
	message := sprintf("%s: %s resource profile requires regional availability", [change.address, environment])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_sql_database_instance"
	environment := root_environment
	environment in {"development", "staging", "production", "restricted"}
	minimum := object.get({"development": 7, "staging": 14, "production": 35, "restricted": 35}, environment, 366)
	after := object.get(change.change, "after", {})
	settings := first(object.get(after, "settings", []))
	backup := first(object.get(settings, "backup_configuration", []))
	retention := first(object.get(backup, "backup_retention_settings", []))
	object.get(retention, "retained_backups", 0) < minimum
	message := sprintf("%s: %s resource profile requires at least %d retained daily backups", [change.address, environment, minimum])
}

root_environment := object.get(object.get(object.get(input, "variables", {}), "environment", {}), "value", "")

first(values) := values[0] if { count(values) > 0 }
first(values) := {} if { count(values) == 0 }

mutates(actions) if {
	some action in actions
	action in {"create", "update", "delete"}
}
