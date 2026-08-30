package mindclade.infrastructure.cost_guardrails

import rego.v1

test_rejects_unallocated_project_cost if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_project.workload",
			"type": "google_project",
			"change": {"actions": ["create"], "after": {"labels": {}}},
		}],
	}
	count(violations) == 3
}

test_accepts_allocated_project_cost if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_project.workload",
			"type": "google_project",
			"change": {"actions": ["create"], "after": {"labels": {"environment": "development", "owner": "infrastructure", "cost_center": "platform"}}},
		}],
	}
	count(violations) == 0
}

test_rejects_unallocated_database_cost if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_sql_database_instance.primary",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {"settings": [{"user_labels": {}}]}},
		}],
	}
	count(violations) == 3
}

test_accepts_allocated_database_cost if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_sql_database_instance.primary",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {"settings": [{"user_labels": {"environment": "production", "owner": "data-platform", "cost_center": "platform"}}]}},
		}],
	}
	count(violations) == 0
}

test_accepts_provider_shaped_allocated_node_pool_cost if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.node_pool.google_container_node_pool.this",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {"node_config": [{"labels": {"workload": "worker"}, "resource_labels": {"environment": "production", "owner": "infrastructure", "cost_center": "platform"}}]}},
		}],
	}
	count(violations) == 0
}

test_accepts_provider_shaped_allocated_cluster_cost if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.primary",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {"resource_labels": {"environment": "production", "owner": "infrastructure", "cost_center": "platform"}}},
		}],
	}
	count(violations) == 0
}

test_rejects_provider_shaped_production_database_mislabel if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.postgres.google_sql_database_instance.this",
			"type": "google_sql_database_instance",
			"change": {"actions": ["create"], "after": {"settings": [{"user_labels": {"environment": "development", "owner": "data-platform", "cost_center": "platform"}}]}},
		}],
	}
	count(violations) == 1
}

test_rejects_provider_shaped_production_node_pool_mislabel if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.node_pool.google_container_node_pool.this",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {"node_config": [{"labels": {"environment": "production"}, "resource_labels": {"environment": "development", "owner": "infrastructure", "cost_center": "platform"}}]}},
		}],
	}
	count(violations) == 1
}

test_rejects_accelerator_total_autoscaling_above_ceiling if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.node_pool.google_container_node_pool.this[0]",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {
				"autoscaling": [{"total_max_node_count": 65}],
				"node_config": [{
					"guest_accelerator": [{"type": "nvidia-h100-80gb", "count": 8}],
					"resource_labels": {"environment": "production", "owner": "infrastructure", "cost_center": "platform"},
				}],
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_accelerator_total_autoscaling_at_ceiling if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.node_pool.google_container_node_pool.this[0]",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {
				"autoscaling": [{"total_max_node_count": 64}],
				"node_config": [{
					"guest_accelerator": [{"type": "nvidia-h100-80gb", "count": 8}],
					"resource_labels": {"environment": "production", "owner": "infrastructure", "cost_center": "platform"},
				}],
			}},
		}],
	}
	count(violations) == 0
}
