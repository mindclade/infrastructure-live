package mindclade.infrastructure.gke_security

import rego.v1

test_rejects_public_unhardened_cluster if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_container_cluster.primary",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {"private_cluster_config": [], "network_policy": [], "binary_authorization": [], "enable_shielded_nodes": false}},
		}],
	}
	count(violations) == 5
}

test_accepts_hardened_cluster if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_container_cluster.primary",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"private_cluster_config": [{"enable_private_nodes": true, "enable_private_endpoint": true}],
				"network_policy": [{"enabled": true}],
				"binary_authorization": [{"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"}],
				"enable_shielded_nodes": true,
			}},
		}],
	}
	count(violations) == 0
}

test_accepts_advanced_datapath_cluster if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.primary",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"private_cluster_config": [{"enable_private_nodes": true, "enable_private_endpoint": true}],
				"datapath_provider": "ADVANCED_DATAPATH",
				"binary_authorization": [{"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"}],
				"enable_shielded_nodes": true,
			}},
		}],
	}
	count(violations) == 0
}

test_rejects_production_cluster_below_catalog_zone_minimum if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.this[0]",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"location": "us-central1",
				"node_locations": ["us-central1-a", "us-central1-b"],
				"deletion_protection": true,
				"private_cluster_config": [{"enable_private_nodes": true, "enable_private_endpoint": true}],
				"datapath_provider": "ADVANCED_DATAPATH",
				"binary_authorization": [{"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"}],
				"enable_shielded_nodes": true,
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_profile_compliant_production_cluster if {
	violations := deny with input as {
		"variables": {"environment": {"value": "production"}},
		"resource_changes": [{
			"address": "module.stack.module.cluster.google_container_cluster.this[0]",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {
				"location": "us-central1",
				"node_locations": ["us-central1-a", "us-central1-b", "us-central1-c"],
				"deletion_protection": true,
				"private_cluster_config": [{"enable_private_nodes": true, "enable_private_endpoint": true}],
				"datapath_provider": "ADVANCED_DATAPATH",
				"binary_authorization": [{"evaluation_mode": "PROJECT_SINGLETON_POLICY_ENFORCE"}],
				"enable_shielded_nodes": true,
			}},
		}],
	}
	count(violations) == 0
}
