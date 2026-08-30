package mindclade.infrastructure.encryption_and_retention

import rego.v1

data_resource_types := {
	"google_artifact_registry_repository",
	"google_kms_crypto_key",
	"google_project",
	"google_pubsub_subscription",
	"google_pubsub_topic",
	"google_sql_database_instance",
	"google_storage_bucket",
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type in data_resource_types
	after := object.get(change.change, "after", {})
	classification := object.get(data_labels(change.type, after), "data_classification", "")
	not valid_data_class(classification)
	message := sprintf("%s: an approved data_classification label is required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type in data_resource_types
	expected := object.get(object.get(object.get(input, "variables", {}), "environment", {}), "value", "")
	expected in {"development", "staging", "production", "restricted"}
	after := object.get(change.change, "after", {})
	classification := object.get(data_labels(change.type, after), "data_classification", "")
	not environment_allows(expected, classification)
	message := sprintf("%s: data classification %s is not allowed in %s", [change.address, classification, expected])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_storage_bucket"
	after := object.get(change.change, "after", {})
	not object.get(after, "uniform_bucket_level_access", false)
	message := sprintf("%s: uniform bucket-level access is required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_artifact_registry_repository"
	after := object.get(change.change, "after", {})
	object.get(after, "format", "") == "DOCKER"
	docker := first(object.get(after, "docker_config", []))
	not object.get(docker, "immutable_tags", false)
	message := sprintf("%s: Docker artifact tags must be immutable", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_storage_bucket"
	after := object.get(change.change, "after", {})
	object.get(after, "public_access_prevention", "") != "enforced"
	message := sprintf("%s: public access prevention must be enforced", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_storage_bucket"
	after := object.get(change.change, "after", {})
	classification := object.get(object.get(after, "labels", {}), "data_classification", "")
	valid_data_class(classification)
	minimum := object.get({"public": 0, "internal": 2592000, "confidential": 7776000, "restricted": 31536000}, classification, 0)
	policy := first(object.get(after, "retention_policy", []))
	object.get(policy, "retention_period", 0) < minimum
	message := sprintf("%s: %s data requires at least %d seconds retention", [change.address, classification, minimum])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_sql_database_instance"
	after := object.get(change.change, "after", {})
	settings := first(object.get(after, "settings", []))
	labels := object.get(settings, "user_labels", {})
	object.get(labels, "data_classification", "") in {"confidential", "restricted"}
	object.get(after, "encryption_key_name", "") == ""
	message := sprintf("%s: protected databases require delegated CMEK", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_storage_bucket"
	after := object.get(change.change, "after", {})
	classification := object.get(object.get(after, "labels", {}), "data_classification", "")
	classification == "restricted"
	policy := first(object.get(after, "retention_policy", []))
	not object.get(policy, "is_locked", false)
	message := sprintf("%s: restricted retention must be irreversibly locked", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_logging_project_bucket_config"
	environment := root_environment
	minimum := object.get({"development": 30, "staging": 90, "production": 90, "restricted": 365}, environment, 3651)
	after := object.get(change.change, "after", {})
	object.get(after, "retention_days", 0) < minimum
	message := sprintf("%s: %s log retention requires at least %d days", [change.address, environment, minimum])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_logging_project_bucket_config"
	after := object.get(change.change, "after", {})
	cmek := first(object.get(after, "cmek_settings", []))
	object.get(cmek, "kms_key_name", "") == ""
	message := sprintf("%s: centralized logs require delegated CMEK", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	"create" in change.change.actions
	change.type == "google_kms_crypto_key"
	not has_qualified_kms_binding
	message := sprintf("%s: new CMEK requires an explicit qualified service-agent binding in the same plan", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_kms_crypto_key_iam_member"
	after := object.get(change.change, "after", {})
	object.get(after, "role", "") == "roles/cloudkms.cryptoKeyEncrypterDecrypter"
	member := object.get(after, "member", "")
	not regex.match("^serviceAccount:[^@[:space:]]+@[^@[:space:]]+\\.iam\\.gserviceaccount\\.com$", member)
	message := sprintf("%s: CMEK encrypter/decrypter must be an explicit qualified service account", [change.address])
}

has_qualified_kms_binding if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_kms_crypto_key_iam_member"
	after := object.get(change.change, "after", {})
	object.get(after, "role", "") == "roles/cloudkms.cryptoKeyEncrypterDecrypter"
	regex.match("^serviceAccount:[^@[:space:]]+@[^@[:space:]]+\\.iam\\.gserviceaccount\\.com$", object.get(after, "member", ""))
}

data_labels(resource_type, after) := object.get(first(object.get(after, "settings", [])), "user_labels", {}) if {
	resource_type == "google_sql_database_instance"
}
data_labels(resource_type, after) := object.get(after, "labels", {}) if {
	resource_type != "google_sql_database_instance"
}

valid_data_class(classification) if {
	classification in {"public", "internal", "confidential", "restricted"}
}

environment_allows("development", classification) if { classification in {"public", "internal"} }
environment_allows("staging", classification) if { classification in {"public", "internal", "confidential"} }
environment_allows("production", classification) if { classification in {"public", "internal", "confidential"} }
environment_allows("restricted", "restricted")

root_environment := object.get(object.get(object.get(input, "variables", {}), "environment", {}), "value", "")

first(values) := values[0] if { count(values) > 0 }
first(values) := {} if { count(values) == 0 }

mutates(actions) if {
	some action in actions
	action in {"create", "update", "delete"}
}
