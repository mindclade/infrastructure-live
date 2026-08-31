package mindclade.infrastructure.gke_security

import rego.v1

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	after := object.get(change.change, "after", {})
	private := first(object.get(after, "private_cluster_config", []))
	not object.get(private, "enable_private_nodes", false)
	message := sprintf("%s: private GKE nodes are required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	after := object.get(change.change, "after", {})
	private := first(object.get(after, "private_cluster_config", []))
	not object.get(private, "enable_private_endpoint", false)
	message := sprintf("%s: the GKE control plane endpoint must be private", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	after := object.get(change.change, "after", {})
	not network_policy_enforced(after)
	message := sprintf("%s: GKE network policy is required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	after := object.get(change.change, "after", {})
	not object.get(after, "enable_shielded_nodes", false)
	message := sprintf("%s: Shielded GKE Nodes are required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	after := object.get(change.change, "after", {})
	binary := first(object.get(after, "binary_authorization", []))
	object.get(binary, "evaluation_mode", "DISABLED") == "DISABLED"
	message := sprintf("%s: Binary Authorization must be enabled", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	environment := root_environment
	environment in {"development", "staging", "production", "restricted"}
	after := object.get(change.change, "after", {})
	not regex.match("^[a-z]+-[a-z]+[0-9]$", object.get(after, "location", ""))
	message := sprintf("%s: catalog resource profiles require a regional GKE location", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	environment := root_environment
	environment in {"development", "staging", "production", "restricted"}
	minimum := object.get({"development": 1, "staging": 2, "production": 3, "restricted": 3}, environment, 4)
	after := object.get(change.change, "after", {})
	count(object.get(after, "node_locations", [])) < minimum
	message := sprintf("%s: %s resource profile requires at least %d explicit GKE zones", [change.address, environment, minimum])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	environment := root_environment
	environment in {"development", "staging", "production", "restricted"}
	after := object.get(change.change, "after", {})
	not object.get(after, "deletion_protection", false)
	message := sprintf("%s: %s resource profile requires GKE deletion protection", [change.address, environment])
}

root_environment := object.get(object.get(object.get(input, "variables", {}), "environment", {}), "value", "")

first(values) := values[0] if count(values) > 0
first(values) := {} if count(values) == 0

network_policy_enforced(after) if {
	object.get(after, "datapath_provider", "") == "ADVANCED_DATAPATH"
}

network_policy_enforced(after) if {
	policy := first(object.get(after, "network_policy", []))
	object.get(policy, "enabled", false)
}

mutates(actions) if {
	some action in actions
	action in {"create", "update", "delete"}
}
