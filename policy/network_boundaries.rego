package mindclade.infrastructure.network_boundaries

import rego.v1

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_network"
	after := object.get(change.change, "after", {})
	object.get(after, "auto_create_subnetworks", false)
	message := sprintf("%s: automatic subnet creation is prohibited", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_subnetwork"
	after := object.get(change.change, "after", {})
	not object.get(after, "private_ip_google_access", false)
	message := sprintf("%s: Private Google Access is required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_firewall"
	after := object.get(change.change, "after", {})
	count(object.get(after, "allow", [])) > 0
	some cidr in object.get(after, "source_ranges", [])
	cidr in {"0.0.0.0/0", "::/0"}
	message := sprintf("%s: world-sourced allow rules are prohibited", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_router_nat"
	after := object.get(change.change, "after", {})
	object.get(after, "enable_endpoint_independent_mapping", true)
	message := sprintf("%s: endpoint-independent NAT mapping must be disabled", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_shared_vpc_service_project"
	after := object.get(change.change, "after", {})
	object.get(after, "host_project", "") == object.get(after, "service_project", "")
	message := sprintf("%s: Shared VPC host and service projects must be distinct", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_firewall"
	after := object.get(change.change, "after", {})
	object.get(after, "direction", "") == "EGRESS"
	count(object.get(after, "allow", [])) > 0
	default_route_covered(object.get(after, "destination_ranges", []))
	message := sprintf("%s: default-route egress allow rules are prohibited", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_firewall"
	after := object.get(change.change, "after", {})
	object.get(after, "direction", "") == "EGRESS"
	count(object.get(after, "allow", [])) > 0
	not reviewed_transport(after)
	message := sprintf("%s: egress allows require one logged TCP/UDP rule with explicit bounded ports", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_firewall"
	after := object.get(change.change, "after", {})
	object.get(after, "direction", "") == "EGRESS"
	count(object.get(after, "deny", [])) > 0
	not default_deny(after)
	message := sprintf("%s: egress deny rules must be a logged default deny", [change.address])
}

reviewed_transport(after) if {
	allow := object.get(after, "allow", [])
	count(allow) == 1
	object.get(allow[0], "protocol", "") in {"tcp", "udp"}
	ports := object.get(allow[0], "ports", [])
	count(ports) > 0
	every port in ports {
		regex.match("^[0-9]{1,5}(-[0-9]{1,5})?$", port)
	}
	count(object.get(after, "destination_ranges", [])) > 0
	count(object.get(after, "log_config", [])) == 1
}

default_deny(after) if {
	object.get(after, "priority", 0) == 65534
	object.get(after, "destination_ranges", []) == ["0.0.0.0/0"]
	deny_rules := object.get(after, "deny", [])
	count(deny_rules) == 1
	object.get(deny_rules[0], "protocol", "") == "all"
	count(object.get(after, "log_config", [])) == 1
}

default_route_covered(ranges) if {
	merged := net.cidr_merge(ranges)
	some default_route in {"0.0.0.0/0", "::/0"}
	default_route in merged
}

mutates(actions) if {
	some action in actions
	action in {"create", "update", "delete"}
}
