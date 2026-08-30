package mindclade.infrastructure.cost_guardrails

import rego.v1

labelled_types := {
	"google_project",
	"google_storage_bucket",
	"google_artifact_registry_repository",
	"google_compute_address",
	"google_compute_instance_template",
	"google_container_cluster",
	"google_container_node_pool",
	"google_dns_managed_zone",
	"google_kms_crypto_key",
	"google_pubsub_subscription",
	"google_pubsub_topic",
	"google_sql_database_instance",
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type in labelled_types
	expected := object.get(object.get(object.get(input, "variables", {}), "environment", {}), "value", "")
	expected in {"development", "staging", "production", "restricted"}
	after := object.get(change.change, "after", {})
	actual := object.get(resource_labels(change.type, after), "environment", "")
	actual != expected
	message := sprintf("%s: environment label %s must match immutable root environment %s", [change.address, actual, expected])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type in labelled_types
	after := object.get(change.change, "after", {})
	labels := resource_labels(change.type, after)
	some required in {"environment", "owner", "cost_center"}
	object.get(labels, required, "") == ""
	message := sprintf("%s: cost allocation label %s is required", [change.address, required])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_billing_budget"
	after := object.get(change.change, "after", {})
	amount := first(object.get(after, "amount", []))
	object.get(amount, "specified_amount", null) == null
	message := sprintf("%s: budget must use an explicit amount", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_billing_budget"
	after := object.get(change.change, "after", {})
	some threshold in object.get(after, "threshold_rules", [])
	object.get(threshold, "threshold_percent", 2) > 1
	message := sprintf("%s: budget thresholds cannot exceed 100 percent", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_node_pool"
	after := object.get(change.change, "after", {})
	node := first(object.get(after, "node_config", []))
	count(object.get(node, "guest_accelerator", [])) > 0
	autoscaling := first(object.get(after, "autoscaling", []))
	object.get(autoscaling, "total_max_node_count", object.get(autoscaling, "max_node_count", 0)) > 64
	message := sprintf("%s: accelerator autoscaling exceeds the approved safety ceiling", [change.address])
}

resource_labels(resource_type, after) := object.get(first(object.get(after, "settings", [])), "user_labels", {}) if {
	resource_type == "google_sql_database_instance"
}
resource_labels(resource_type, after) := object.get(after, "resource_labels", {}) if {
	resource_type == "google_container_cluster"
}
resource_labels(resource_type, after) := object.get(first(object.get(after, "node_config", [])), "resource_labels", {}) if {
	resource_type == "google_container_node_pool"
}
resource_labels(resource_type, after) := object.get(after, "labels", {}) if {
	resource_type != "google_sql_database_instance"
	resource_type != "google_container_cluster"
	resource_type != "google_container_node_pool"
}

first(values) := values[0] if { count(values) > 0 }
first(values) := {} if { count(values) == 0 }

mutates(actions) if {
	some action in actions
	action in {"create", "update", "delete"}
}
