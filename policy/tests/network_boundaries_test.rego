package mindclade.infrastructure.network_boundaries

import rego.v1

test_rejects_world_allow if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.public",
			"type": "google_compute_firewall",
			"change": {
				"actions": ["create"],
				"after": {"allow": [{"protocol": "tcp"}], "source_ranges": ["0.0.0.0/0"]},
			},
		}],
	}
	count(violations) == 1
}

test_accepts_private_subnet if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_subnetwork.private",
			"type": "google_compute_subnetwork",
			"change": {"actions": ["create"], "after": {"private_ip_google_access": true}},
		}],
	}
	count(violations) == 0
}

test_rejects_default_route_egress_allow if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.open_egress",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"destination_ranges": ["0.0.0.0/0"],
				"allow": [{"protocol": "tcp", "ports": ["443"]}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_ipv6_default_route_egress_allow if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.ipv6_default_egress",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"destination_ranges": ["::/0"],
				"allow": [{"protocol": "tcp", "ports": ["443"]}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_split_default_route_egress_allow if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.split_default_egress",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"destination_ranges": ["0.0.0.0/1", "128.0.0.0/1"],
				"allow": [{"protocol": "tcp", "ports": ["443"]}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_fragmented_default_route_egress_allow if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.fragmented_default_egress",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"destination_ranges": ["0.0.0.0/2", "64.0.0.0/2", "128.0.0.0/2", "192.0.0.0/2"],
				"allow": [{"protocol": "tcp", "ports": ["443"]}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_incomplete_default_route_fragments if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.incomplete_egress",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"destination_ranges": ["0.0.0.0/1", "128.0.0.0/2"],
				"allow": [{"protocol": "tcp", "ports": ["443"]}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 0
}
test_rejects_any_protocol_egress_allow if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.any_egress",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"destination_ranges": ["192.0.2.0/24"],
				"allow": [{"protocol": "all", "ports": ["1-65535"]}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_private_sql_and_default_deny if {
	violations := deny with input as {
		"resource_changes": [
			{
				"address": "module.stack.module.egress.google_compute_firewall.allow_egress[\"private-sql\"]",
				"type": "google_compute_firewall",
				"change": {"actions": ["create"], "after": {
					"direction": "EGRESS",
					"destination_ranges": ["10.40.0.0/24"],
					"allow": [{"protocol": "tcp", "ports": ["5432"]}],
					"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
				}},
			},
			{
				"address": "module.stack.module.egress.google_compute_firewall.deny_egress[0]",
				"type": "google_compute_firewall",
				"change": {"actions": ["create"], "after": {
					"direction": "EGRESS",
					"priority": 65534,
					"destination_ranges": ["0.0.0.0/0"],
					"deny": [{"protocol": "all"}],
					"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
				}},
			},
		],
	}
	count(violations) == 0
}

test_accepts_workload_scoped_ci_default_deny if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.execution_egress.google_compute_firewall.deny_egress[0]",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"priority": 1000,
				"destination_ranges": ["0.0.0.0/0"],
				"target_tags": ["buildkite-agents-development-ephemeral"],
				"deny": [{"protocol": "all"}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_ci_default_deny_priority_without_target_scope if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.unscoped_ci_deny",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"priority": 1000,
				"destination_ranges": ["0.0.0.0/0"],
				"deny": [{"protocol": "all"}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_unapproved_scoped_default_deny_priority if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.unapproved_scoped_deny",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"priority": 999,
				"destination_ranges": ["0.0.0.0/0"],
				"target_tags": ["buildkite-agents-development-ephemeral"],
				"deny": [{"protocol": "all"}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_equivalent_prefix_zero_egress if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_compute_firewall.normalized_world",
			"type": "google_compute_firewall",
			"change": {"actions": ["create"], "after": {
				"direction": "EGRESS",
				"destination_ranges": ["1.2.3.4/0"],
				"allow": [{"protocol": "tcp", "ports": ["443"]}],
				"log_config": [{"metadata": "INCLUDE_ALL_METADATA"}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_shared_vpc_self_attachment if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.shared_vpc.google_compute_shared_vpc_service_project.this",
			"type": "google_compute_shared_vpc_service_project",
			"change": {"actions": ["create"], "after": {"host_project": "network-host", "service_project": "network-host"}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_endpoint_dependent_nat if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.egress.google_compute_router_nat.this[0]",
			"type": "google_compute_router_nat",
			"change": {"actions": ["create"], "after": {"enable_endpoint_independent_mapping": false}},
		}],
	}
	count(violations) == 0
}
