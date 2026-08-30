package mindclade.infrastructure.accelerator_isolation

import rego.v1

test_rejects_unisolated_accelerator if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_container_node_pool.accelerator",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {
				"node_config": [{"guest_accelerator": [{"type": "nvidia-l4", "count": 1, "gpu_driver_installation_config": [{"gpu_driver_version": "INSTALLATION_DISABLED"}]}], "taint": [], "labels": {"workload": "accelerator"}, "resource_labels": {"environment": "development"}}],
				"management": [{"auto_repair": false}],
			}},
		}],
	}
	count(violations) == 2
}

test_accepts_isolated_accelerator if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_container_node_pool.accelerator",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {
				"node_config": [{"guest_accelerator": [{"type": "nvidia-l4", "count": 1, "gpu_driver_installation_config": [{"gpu_driver_version": "INSTALLATION_DISABLED"}]}], "taint": [{"key": "mindclade.io/accelerator", "effect": "NO_SCHEDULE"}], "labels": {"workload": "accelerator"}, "resource_labels": {"environment": "development"}}],
				"management": [{"auto_repair": true}],
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_provider_shaped_production_spot_accelerator if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.node_pool.google_container_node_pool.this",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {
				"node_config": [{
					"guest_accelerator": [{"type": "nvidia-h100-80gb", "count": 8, "gpu_driver_installation_config": [{"gpu_driver_version": "INSTALLATION_DISABLED"}]}],
					"taint": [{"key": "mindclade.io/accelerator", "effect": "NO_SCHEDULE"}],
					"labels": {"environment": "development"},
					"resource_labels": {"environment": "production"},
					"spot": true,
				}],
				"management": [{"auto_repair": true}],
			}},
		}],
	}
	count(violations) == 1
}

test_rejects_latest_gpu_driver if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_container_node_pool.accelerator",
			"type": "google_container_node_pool",
			"change": {"actions": ["create"], "after": {
				"node_config": [{
					"guest_accelerator": [{"type": "nvidia-l4", "count": 1, "gpu_driver_installation_config": [{"gpu_driver_version": "LATEST"}]}],
					"taint": [{"key": "mindclade.io/accelerator", "effect": "NO_SCHEDULE"}],
					"resource_labels": {"environment": "development"},
				}],
				"management": [{"auto_repair": true}],
			}},
		}],
	}
	count(violations) == 1
}
