package mindclade.infrastructure.workload_identity

import rego.v1

workload_project_roles := {
	"roles/cloudsql.client",
	"roles/logging.logWriter",
	"roles/monitoring.metricWriter",
	"roles/serviceusage.serviceUsageConsumer",
}

privileged_roles := {
	"roles/owner",
	"roles/editor",
	"roles/viewer",
	"roles/billing.admin",
	"roles/billing.projectManager",
	"roles/cloudkms.admin",
	"roles/cloudkms.orgAdmin",
	"roles/iam.organizationRoleAdmin",
	"roles/iam.roleAdmin",
	"roles/iam.securityAdmin",
	"roles/iam.serviceAccountAdmin",
	"roles/iam.serviceAccountKeyAdmin",
	"roles/iam.workloadIdentityPoolAdmin",
	"roles/resourcemanager.folderAdmin",
	"roles/resourcemanager.organizationAdmin",
	"roles/resourcemanager.projectCreator",
	"roles/resourcemanager.projectIamAdmin",
	"roles/serviceusage.serviceUsageAdmin",
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_service_account_key"
	message := sprintf("%s: workloads must use federation, not keys", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	contains(change.type, "_iam_")
	after := object.get(change.change, "after", {})
	role := object.get(after, "role", "")
	role in privileged_roles
	message := sprintf("%s: privileged identity role %s is prohibited", [change.address, role])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_project_iam_member"
	contains(change.address, "module.workload_identity.google_project_iam_member.workload")
	after := object.get(change.change, "after", {})
	role := object.get(after, "role", "")
	not role in workload_project_roles
	message := sprintf("%s: workload project role %s is outside the least-privilege capability allowlist", [change.address, role])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	after := object.get(change.change, "after", {})
	configs := object.get(after, "workload_identity_config", [])
	count(configs) == 0
	message := sprintf("%s: GKE Workload Identity is required", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_iam_workload_identity_pool"
	after := object.get(change.change, "after", {})
	object.get(after, "disabled", false)
	message := sprintf("%s: a disabled identity pool cannot authorize connected operation", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	contains(change.type, "_iam_")
	after := object.get(change.change, "after", {})
	object.get(after, "role", "") == "roles/iam.serviceAccountTokenCreator"
	member := object.get(after, "member", "")
	member in {"allUsers", "allAuthenticatedUsers"}
	message := sprintf("%s: public service-account impersonation is prohibited", [change.address])
}

mutates(actions) if {
	some action in actions
	action in {"create", "update", "delete"}
}
