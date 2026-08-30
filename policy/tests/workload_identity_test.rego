package mindclade.infrastructure.workload_identity

import rego.v1

test_rejects_cluster_without_workload_identity if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_container_cluster.primary",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {"workload_identity_config": []}},
		}],
	}
	count(violations) == 1
}

test_accepts_federated_cluster if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_container_cluster.primary",
			"type": "google_container_cluster",
			"change": {"actions": ["create"], "after": {"workload_identity_config": [{"workload_pool": "logical.svc.id.goog"}]}},
		}],
	}
	count(violations) == 0
}

test_rejects_provider_shaped_workload_key_admin if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.workload_identity.google_project_iam_member.workload[\"trainer\"]",
			"type": "google_project_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/cloudkms.admin",
				"member": "serviceAccount:trainer@logical.iam.gserviceaccount.com",
			}},
		}],
	}
	count(violations) == 2
}

test_rejects_provider_shaped_project_iam_admin if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "google_project_iam_member.unsafe",
			"type": "google_project_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/resourcemanager.projectIamAdmin",
				"member": "serviceAccount:automation@logical.iam.gserviceaccount.com",
			}},
		}],
	}
	count(violations) == 1
}

test_accepts_provider_shaped_workload_capability if {
	violations := deny with input as {
		"resource_changes": [{
			"address": "module.stack.module.workload_identity.google_project_iam_member.workload[\"trainer\"]",
			"type": "google_project_iam_member",
			"change": {"actions": ["create"], "after": {
				"role": "roles/cloudsql.client",
				"member": "serviceAccount:trainer@logical.iam.gserviceaccount.com",
			}},
		}],
	}
	count(violations) == 0
}
