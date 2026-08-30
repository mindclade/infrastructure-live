package mindclade.infrastructure.accelerator_isolation

import rego.v1

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_node_pool"
	after := object.get(change.change, "after", {})
	node := first(object.get(after, "node_config", []))
	count(object.get(node, "guest_accelerator", [])) > 0
	not has_accelerator_taint(object.get(node, "taint", []))
	message := sprintf("%s: accelerator nodes require a dedicated NO_SCHEDULE taint", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_node_pool"
	after := object.get(change.change, "after", {})
	node := first(object.get(after, "node_config", []))
	count(object.get(node, "guest_accelerator", [])) > 0
	management := first(object.get(after, "management", []))
	not object.get(management, "auto_repair", false)
	message := sprintf("%s: accelerator pools require automatic repair", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_node_pool"
	after := object.get(change.change, "after", {})
	node := first(object.get(after, "node_config", []))
	labels := object.get(node, "resource_labels", {})
	object.get(labels, "environment", "") in {"production", "restricted"}
	count(object.get(node, "guest_accelerator", [])) > 0
	object.get(node, "spot", false)
	message := sprintf("%s: production-like accelerator pools cannot be Spot", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_node_pool"
	after := object.get(change.change, "after", {})
	node := first(object.get(after, "node_config", []))
	some accelerator in object.get(node, "guest_accelerator", [])
	driver := first(object.get(accelerator, "gpu_driver_installation_config", []))
	object.get(driver, "gpu_driver_version", "LATEST") == "LATEST"
	message := sprintf("%s: mutable latest GPU driver installation is prohibited", [change.address])
}

has_accelerator_taint(taints) if {
	some taint in taints
	object.get(taint, "key", "") == "mindclade.io/accelerator"
	object.get(taint, "effect", "") == "NO_SCHEDULE"
}

first(values) := values[0] if { count(values) > 0 }
first(values) := {} if { count(values) == 0 }

mutates(actions) if {
	some action in actions
	action in {"create", "update", "delete"}
}
