package mindclade.infrastructure.organization_constraints

import rego.v1

primitive_roles := {"roles/owner", "roles/editor", "roles/viewer"}
public_principals := {"allUsers", "allAuthenticatedUsers"}
dangerous_admin_roles := {
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
}

# Every IAM member resource emitted by this repository must resolve to an exact
# principal qualified for the selected environment. The approval list is a
# reviewed root input covered by the canonical plan digest; protected apply
# separately requires the environment authority to attest that list.
governed_iam_member_types := {
	"google_artifact_registry_repository_iam_member",
	"google_kms_crypto_key_iam_member",
	"google_project_iam_member",
	"google_pubsub_subscription_iam_member",
	"google_pubsub_topic_iam_member",
	"google_secret_manager_secret_iam_member",
	"google_service_account_iam_member",
	"google_storage_bucket_iam_member",
}

allowed_iam_roles_by_type := {
	"google_artifact_registry_repository_iam_member": {"roles/artifactregistry.reader", "roles/artifactregistry.writer"},
	"google_kms_crypto_key_iam_member": {"roles/cloudkms.cryptoKeyEncrypterDecrypter"},
	"google_project_iam_member": {
		"roles/cloudsql.client",
		"roles/logging.bucketWriter",
		"roles/logging.logWriter",
		"roles/monitoring.metricWriter",
		"roles/serviceusage.serviceUsageConsumer",
	},
	"google_pubsub_subscription_iam_member": {"roles/pubsub.subscriber"},
	"google_pubsub_topic_iam_member": {"roles/pubsub.publisher"},
	"google_secret_manager_secret_iam_member": {"roles/secretmanager.secretAccessor"},
	"google_service_account_iam_member": {"roles/iam.workloadIdentityUser"},
	"google_storage_bucket_iam_member": {"roles/storage.insightsCollectorService", "roles/storage.objectCreator", "roles/storage.objectViewer"},
}

regional_field_by_type := {
	"google_artifact_registry_repository": "location",
	"google_compute_address": "region",
	"google_compute_region_autoscaler": "region",
	"google_compute_region_instance_group_manager": "region",
	"google_compute_router": "region",
	"google_compute_router_nat": "region",
	"google_compute_subnetwork": "region",
	"google_container_cluster": "location",
	"google_container_node_pool": "location",
	"google_gke_hub_membership": "location",
	"google_kms_key_ring": "location",
	"google_logging_project_bucket_config": "location",
	"google_sql_database_instance": "region",
	"google_storage_bucket": "location",
	"google_storage_insights_report_config": "location",
}

direct_reference_fields_by_type := {
	"google_artifact_registry_repository": {"kms_key_name"},
	"google_artifact_registry_repository_iam_member": {"repository"},
	"google_compute_firewall": {"network"},
	"google_compute_global_address": {"network"},
	"google_compute_router": {"network"},
	"google_compute_subnetwork": {"network"},
	"google_compute_shared_vpc_service_project": {"host_project", "service_project"},
	"google_container_cluster": {"network", "subnetwork"},
	"google_container_node_pool": {"cluster"},
	"google_kms_crypto_key": {"key_ring"},
	"google_kms_crypto_key_iam_member": {"crypto_key_id"},
	"google_logging_project_sink": {"destination"},
	"google_monitoring_monitored_project": {"metrics_scope", "name"},
	"google_project": {"billing_account", "folder_id", "org_id"},
	"google_pubsub_subscription": {"topic"},
	"google_pubsub_subscription_iam_member": {"subscription"},
	"google_pubsub_topic": {"kms_key_name"},
	"google_pubsub_topic_iam_member": {"topic"},
	"google_secret_manager_secret_iam_member": {"secret_id"},
	"google_service_networking_connection": {"network"},
	"google_sql_database_instance": {"encryption_key_name"},
	"google_storage_bucket_iam_member": {"bucket"},
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_service_account_key"
	message := sprintf("%s: long-lived service account keys are prohibited", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	contains(change.type, "_iam_")
	after := object.get(change.change, "after", {})
	role := object.get(after, "role", "")
	role in dangerous_admin_roles
	message := sprintf("%s: dangerous administrative role %s is prohibited", [change.address, role])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	contains(change.type, "_iam_")
	after := object.get(change.change, "after", {})
	role := object.get(after, "role", "")
	role in primitive_roles
	message := sprintf("%s: primitive IAM role %s is prohibited", [change.address, role])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	contains(change.type, "_iam_")
	after := object.get(change.change, "after", {})
	member := object.get(after, "member", "")
	member in public_principals
	message := sprintf("%s: public IAM principal %s is prohibited", [change.address, member])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type in governed_iam_member_types
	after := object.get(change.change, "after", {})
	member := object.get(after, "member", "")
	approved := object.get(object.get(object.get(input, "variables", {}), "approved_iam_principals", {}), "value", [])
	not member in approved
	message := sprintf("%s: IAM principal %v is not in the exact environment-scoped approval list", [change.address, member])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	contains(change.type, "_iam_")
	not change.type in governed_iam_member_types
	change.type != "google_project_iam_audit_config"
	message := sprintf("%s: IAM binding and policy resources outside the explicit member-resource contract are prohibited", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_archive_iam_member(change)
	after := object.get(change.change, "after", {})
	not valid_ci_evidence_archive_iam_member(after)
	message := sprintf("%s: CI evidence IAM must preserve the exact writer, verifier, service-agent role separation", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_archive_kms_member(change)
	after := object.get(change.change, "after", {})
	object.get(after, "role", "") != "roles/cloudkms.cryptoKeyEncrypterDecrypter"
	message := sprintf("%s: the archive CMEK role must remain encrypter/decrypter", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_archive_kms_member(change)
	after := object.get(change.change, "after", {})
	object.get(after, "member", "") != object.get(root_ci_evidence_archive, "storage_service_agent", "")
	message := sprintf("%s: the archive CMEK principal must be the exact target-project Storage service agent", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_project_iam_audit_config"
	not ci_evidence_storage_audit_config(change)
	message := sprintf("%s: project audit configuration is allowed only for the governed CI evidence archive", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_storage_audit_config(change)
	after := object.get(change.change, "after", {})
	not valid_ci_evidence_storage_audit_config(after)
	message := sprintf("%s: archive audit configuration must enable exact Storage DATA_READ and DATA_WRITE logs without exemptions", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_audit_sink(change)
	after := object.get(change.change, "after", {})
	not valid_ci_evidence_audit_sink(after)
	message := sprintf("%s: archive audit sink must route exact activity and Data Access logs to the evidence bucket with a unique writer", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_audit_metric(change)
	after := object.get(change.change, "after", {})
	not valid_ci_evidence_audit_metric(after)
	message := sprintf("%s: archive audit metric must detect policy mutation, deletion, and denied access", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_audit_alert(change)
	after := object.get(change.change, "after", {})
	not valid_ci_evidence_audit_alert(after)
	message := sprintf("%s: archive security alert must be enabled and deliver to at least one exact channel", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	ci_evidence_inventory(change)
	after := object.get(change.change, "after", {})
	not valid_ci_evidence_inventory(after)
	message := sprintf("%s: archive inventory must be daily, deletion-protected, and generation-aware in the evidence bucket", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type in governed_iam_member_types
	after := object.get(change.change, "after", {})
	role := object.get(after, "role", "")
	not role in allowed_iam_roles_by_type[change.type]
	message := sprintf("%s: IAM role %s is not permitted for %s", [change.address, role, change.type])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	field := regional_field_by_type[change.type]
	after := object.get(change.change, "after", {})
	actual := object.get(after, field, null)
	expected := expected_location(change)
	not same_location(actual, expected)
	message := sprintf("%s: %s location %v must match its catalog-authorized location %v", [change.address, field, actual, expected])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	after := object.get(change.change, "after", {})
	some field in {"project", "project_id"}
	reference := object.get(after, field, "")
	is_string(reference)
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	after := object.get(change.change, "after", {})
	some field in direct_reference_fields_by_type[change.type]
	reference := object.get(after, field, "")
	is_string(reference)
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_dns_managed_zone"
	after := object.get(change.change, "after", {})
	some visibility in object.get(after, "private_visibility_config", [])
	some network in object.get(visibility, "networks", [])
	reference := object.get(network, "network_url", "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_sql_database_instance"
	after := object.get(change.change, "after", {})
	settings := first(object.get(after, "settings", []))
	ip := first(object.get(settings, "ip_configuration", []))
	reference := object.get(ip, "private_network", "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_cluster"
	after := object.get(change.change, "after", {})
	encryption := first(object.get(after, "database_encryption", []))
	reference := object.get(encryption, "key_name", "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_storage_bucket"
	after := object.get(change.change, "after", {})
	encryption := first(object.get(after, "encryption", []))
	reference := object.get(encryption, "default_kms_key_name", "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_logging_project_bucket_config"
	after := object.get(change.change, "after", {})
	cmek := first(object.get(after, "cmek_settings", []))
	reference := object.get(cmek, "kms_key_name", "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_container_node_pool"
	after := object.get(change.change, "after", {})
	node := first(object.get(after, "node_config", []))
	reference := object.get(node, "service_account", "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_instance_template"
	after := object.get(change.change, "after", {})
	some collection in {"disk", "network_interface", "service_account"}
	field := {"disk": "source_image", "network_interface": "subnetwork", "service_account": "email"}[collection]
	some entry in object.get(after, collection, [])
	reference := object.get(entry, field, "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_gke_hub_membership"
	after := object.get(change.change, "after", {})
	some endpoint in object.get(after, "endpoint", [])
	some cluster in object.get(endpoint, "gke_cluster", [])
	reference := object.get(cluster, "resource_link", "")
	reference != ""
	not approved_resource_reference(reference)
	message := sprintf("%s: resource reference %v is not in the exact environment-scoped approval list", [change.address, reference])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	after_unknown := object.get(change.change, "after_unknown", {})
	governed_reference_is_unknown(change.type, after_unknown)
	message := sprintf("%s: a governed project, network, identity, or encryption reference is unknown at review time", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	contains(change.type, "_iam_")
	after := object.get(change.change, "after", {})
	some member in object.get(after, "members", [])
	member in public_principals
	message := sprintf("%s: public IAM principal %s is prohibited", [change.address, member])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_project"
	after := object.get(change.change, "after", {})
	labels := object.get(after, "labels", {})
	some required in {"environment", "owner", "data_classification", "cost_center"}
	object.get(labels, required, "") == ""
	message := sprintf("%s: project label %s is required", [change.address, required])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_project"
	after := object.get(change.change, "after", {})
	object.get(after, "folder_id", "") == ""
	message := sprintf("%s: catalog project classes require an explicit folder binding", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_project"
	after := object.get(change.change, "after", {})
	object.get(after, "billing_account", "") == ""
	message := sprintf("%s: catalog project classes require an explicit billing binding", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_project"
	after := object.get(change.change, "after", {})
	object.get(after, "deletion_policy", "") != "PREVENT"
	message := sprintf("%s: catalog project classes require deletion prevention", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_instance_template"
	after := object.get(change.change, "after", {})
	disk := first(object.get(after, "disk", []))
	sourceImage := object.get(disk, "source_image", "")
	not regex.match("^(https://www.googleapis.com/compute/v1/)?projects/[^/]+/global/images/[^/]+$", sourceImage)
	message := sprintf("%s: Buildkite boot image must be an immutable image resource", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_instance_template"
	after := object.get(change.change, "after", {})
	metadata := object.get(after, "metadata", {})
	object.get(metadata, "gce-container-declaration", "") != ""
	message := sprintf("%s: deprecated container declarations are prohibited", [change.address])
}

deny contains message if {
	some change in input.resource_changes
	mutates(change.change.actions)
	change.type == "google_compute_instance_template"
	after := object.get(change.change, "after", {})
	metadata := object.get(after, "metadata", {})
	script := object.get(metadata, "startup-script", "")
	not hardened_agent_script(script)
	message := sprintf("%s: Buildkite startup must use a digest-pinned, non-privileged runtime Secret Manager flow", [change.address])
}

hardened_agent_script(script) if {
	image := script_image(script)
	secret := script_secret_resource(script)
	regex.match("^[a-z0-9]+([._-][a-z0-9]+)*(:[0-9]{1,5})?(/[a-z0-9]+([._-][a-z0-9]+)*)+@sha256:[0-9a-f]{64}$", image)
	regex.match("^projects/[a-z][a-z0-9-]{4,28}[a-z0-9]/secrets/[A-Za-z][A-Za-z0-9_-]{0,254}/versions/[1-9][0-9]*$", secret)
	approved_resource_reference(image)
	approved_resource_reference(secret)
	contains(script, "docker run")
	contains(script, "--read-only")
	contains(script, "--cap-drop=ALL")
	contains(script, "--security-opt=no-new-privileges:true")
	contains(script, "BUILDKITE_AGENT_DISCONNECT_AFTER_JOB=true")
	contains(script, "BUILDKITE_AGENT_DISCONNECT_AFTER_IDLE_TIMEOUT=300")
	contains(script, "shutdown -h now")
	contains(script, "Metadata-Flavor: Google")
}

script_image(script) := base64.decode(encoded) if {
	encoded := encoded_script_assignment(script, "image")
}

script_secret_resource(script) := base64.decode(encoded) if {
	encoded := encoded_script_assignment(script, "secret_resource")
}

encoded_script_assignment(script, name) := encoded if {
	lines := [line |
		some raw in split(script, "\n")
		line := trim_space(raw)
		startswith(line, sprintf("readonly %s_b64=", [name]))
	]
	count(lines) == 1
	line := lines[0]
	regex.match(sprintf("^readonly %s_b64='[A-Za-z0-9+/]+={0,2}'$", [name]), line)
	parts := split(line, "'")
	count(parts) == 3
	encoded := parts[1]
}

first(values) := values[0] if { count(values) > 0 }
first(values) := {} if { count(values) == 0 }

root_primary_location := object.get(object.get(object.get(object.get(object.get(input, "planned_values", {}), "outputs", {}), "region_authority", {}), "value", {}), "primary_location", null)

root_ci_evidence_archive := object.get(object.get(object.get(object.get(object.get(input, "planned_values", {}), "outputs", {}), "region_authority", {}), "value", {}), "ci_evidence_archive", {})

ci_evidence_archive_iam_member(change) if {
	change.type == "google_storage_bucket_iam_member"
	startswith(change.address, "module.stack.module.ci_evidence_archive_bucket.google_storage_bucket_iam_member.access[")
}

ci_evidence_archive_kms_member(change) if {
	change.type == "google_kms_crypto_key_iam_member"
	startswith(change.address, "module.stack.module.ci_evidence_archive_kms.google_kms_crypto_key_iam_member.encrypter_decrypter[")
}

valid_ci_evidence_archive_iam_member(after) if {
	object.get(after, "role", "") == "roles/storage.objectViewer"
	object.get(after, "member", "") == object.get(root_ci_evidence_archive, "verifier_principal", "")
}

valid_ci_evidence_archive_iam_member(after) if {
	object.get(after, "role", "") == "roles/storage.insightsCollectorService"
	object.get(after, "member", "") == object.get(root_ci_evidence_archive, "storage_insights_agent", "")
}

valid_ci_evidence_archive_iam_member(after) if {
	object.get(after, "role", "") == "roles/storage.objectCreator"
	member := object.get(after, "member", "")
	member == object.get(root_ci_evidence_archive, "writer_principal", "")
}

valid_ci_evidence_archive_iam_member(after) if {
	object.get(after, "role", "") == "roles/storage.objectCreator"
	member := object.get(after, "member", "")
	member == object.get(root_ci_evidence_archive, "storage_insights_agent", "")
}

valid_ci_evidence_archive_iam_member(after) if {
	object.get(after, "role", "") == "roles/storage.objectCreator"
	object.get(root_ci_evidence_archive, "audit_sink_binding_mode", "") == "enforce"
	member := object.get(after, "member", "")
	member == object.get(root_ci_evidence_archive, "audit_sink_writer_identity", "")
}

ci_evidence_storage_audit_config(change) if {
	change.type == "google_project_iam_audit_config"
	startswith(change.address, "module.stack.google_project_iam_audit_config.ci_evidence_storage[")
}

valid_ci_evidence_storage_audit_config(after) if {
	object.get(after, "project", "") == object.get(root_ci_evidence_archive, "project_id", "")
	object.get(after, "service", "") == "storage.googleapis.com"
	configs := object.get(after, "audit_log_config", [])
	count(configs) == 2
	types := {object.get(config, "log_type", "") | some config in configs}
	types == {"DATA_READ", "DATA_WRITE"}
	every config in configs {
		count(object.get(config, "exempted_members", [])) == 0
	}
}

ci_evidence_audit_sink(change) if {
	change.type == "google_logging_project_sink"
	startswith(change.address, "module.stack.google_logging_project_sink.ci_evidence_audit[")
}

valid_ci_evidence_audit_sink(after) if {
	project := object.get(root_ci_evidence_archive, "project_id", "")
	bucket := object.get(root_ci_evidence_archive, "bucket_name", "")
	object.get(after, "project", "") == project
	object.get(after, "name", "") == "mindclade-ci-evidence-audit"
	object.get(after, "destination", "") == sprintf("storage.googleapis.com/%s", [bucket])
	object.get(after, "unique_writer_identity", false)
	filter := object.get(after, "filter", "")
	contains(filter, sprintf("resource.labels.bucket_name=\"%s\"", [bucket]))
	contains(filter, "cloudaudit.googleapis.com/activity")
	contains(filter, "cloudaudit.googleapis.com/data_access")
}

ci_evidence_audit_metric(change) if {
	change.type == "google_logging_metric"
	startswith(change.address, "module.stack.google_logging_metric.ci_evidence_security_event[")
}

valid_ci_evidence_audit_metric(after) if {
	object.get(after, "project", "") == object.get(root_ci_evidence_archive, "project_id", "")
	object.get(after, "name", "") == "ci_evidence_archive_security_event"
	filter := object.get(after, "filter", "")
	contains(filter, "storage\\.(buckets\\.(delete|lockRetentionPolicy|setIamPolicy|update)|objects\\.delete)")
	contains(filter, "protoPayload.status.code!=0")
}

ci_evidence_audit_alert(change) if {
	change.type == "google_monitoring_alert_policy"
	startswith(change.address, "module.stack.google_monitoring_alert_policy.ci_evidence_security_event[")
}

valid_ci_evidence_audit_alert(after) if {
	object.get(after, "project", "") == object.get(root_ci_evidence_archive, "project_id", "")
	object.get(after, "enabled", false)
	count(object.get(after, "notification_channels", [])) > 0
	count(object.get(after, "conditions", [])) == 1
}

ci_evidence_inventory(change) if {
	change.type == "google_storage_insights_report_config"
	startswith(change.address, "module.stack.google_storage_insights_report_config.ci_evidence_inventory[")
}

valid_ci_evidence_inventory(after) if {
	bucket := object.get(root_ci_evidence_archive, "bucket_name", "")
	object.get(after, "project", "") == object.get(root_ci_evidence_archive, "project_id", "")
	object.get(after, "location", "") == object.get(root_ci_evidence_archive, "location", "")
	object.get(after, "deletion_policy", "") == "PREVENT"
	object.get(after, "force_destroy", true) == false
	frequency := first(object.get(after, "frequency_options", []))
	object.get(frequency, "frequency", "") == "DAILY"
	metadata := first(object.get(after, "object_metadata_report_options", []))
	filters := first(object.get(metadata, "storage_filters", []))
	destination := first(object.get(metadata, "storage_destination_options", []))
	object.get(filters, "bucket", "") == bucket
	object.get(destination, "bucket", "") == bucket
	object.get(destination, "destination_path", "") == "inventory/"
	fields := object.get(metadata, "metadata_fields", [])
	"crc32c" in fields
	"name" in fields
	"retentionExpirationTime" in fields
	"size" in fields
}

expected_location(change) := object.get(root_ci_evidence_archive, "location", null) if {
	object.get(root_ci_evidence_archive, "enabled", false)
	ci_evidence_archive_resource(change)
}

expected_location(change) := root_primary_location if {
	not ci_evidence_archive_override(change)
}

ci_evidence_archive_override(change) if {
	object.get(root_ci_evidence_archive, "enabled", false)
	ci_evidence_archive_resource(change)
}

ci_evidence_archive_resource(change) if {
	change.type == "google_storage_bucket"
	startswith(change.address, "module.stack.module.ci_evidence_archive_bucket.google_storage_bucket.this[")
}

ci_evidence_archive_resource(change) if {
	change.type == "google_storage_insights_report_config"
	startswith(change.address, "module.stack.google_storage_insights_report_config.ci_evidence_inventory[")
}

ci_evidence_archive_resource(change) if {
	change.type == "google_kms_key_ring"
	startswith(change.address, "module.stack.module.ci_evidence_archive_kms.google_kms_key_ring.this[")
}

same_location(actual, expected) if {
	is_string(actual)
	is_string(expected)
	expected != ""
	lower(actual) == lower(expected)
}

approved_resource_reference(reference) if {
	approved := object.get(object.get(object.get(input, "variables", {}), "approved_resource_references", {}), "value", [])
	reference in approved
}

governed_reference_is_unknown(resource_type, after_unknown) if {
	some field in {"project", "project_id"}
	object.get(after_unknown, field, false) == true
}

governed_reference_is_unknown(resource_type, after_unknown) if {
	some field in direct_reference_fields_by_type[resource_type]
	object.get(after_unknown, field, false) == true
}

governed_reference_is_unknown("google_dns_managed_zone", after_unknown) if {
	some visibility in object.get(after_unknown, "private_visibility_config", [])
	some network in object.get(visibility, "networks", [])
	object.get(network, "network_url", false) == true
}

governed_reference_is_unknown("google_sql_database_instance", after_unknown) if {
	settings := first(object.get(after_unknown, "settings", []))
	ip := first(object.get(settings, "ip_configuration", []))
	object.get(ip, "private_network", false) == true
}

governed_reference_is_unknown("google_container_cluster", after_unknown) if {
	encryption := first(object.get(after_unknown, "database_encryption", []))
	object.get(encryption, "key_name", false) == true
}

governed_reference_is_unknown("google_container_node_pool", after_unknown) if {
	node := first(object.get(after_unknown, "node_config", []))
	object.get(node, "service_account", false) == true
}

governed_reference_is_unknown("google_compute_instance_template", after_unknown) if {
	some disk in object.get(after_unknown, "disk", [])
	object.get(disk, "source_image", false) == true
}

governed_reference_is_unknown("google_compute_instance_template", after_unknown) if {
	some interface in object.get(after_unknown, "network_interface", [])
	object.get(interface, "subnetwork", false) == true
}

governed_reference_is_unknown("google_compute_instance_template", after_unknown) if {
	some service_account in object.get(after_unknown, "service_account", [])
	object.get(service_account, "email", false) == true
}

governed_reference_is_unknown("google_gke_hub_membership", after_unknown) if {
	some endpoint in object.get(after_unknown, "endpoint", [])
	some cluster in object.get(endpoint, "gke_cluster", [])
	object.get(cluster, "resource_link", false) == true
}

governed_reference_is_unknown("google_storage_bucket", after_unknown) if {
	encryption := first(object.get(after_unknown, "encryption", []))
	object.get(encryption, "default_kms_key_name", false) == true
}

governed_reference_is_unknown("google_logging_project_bucket_config", after_unknown) if {
	cmek := first(object.get(after_unknown, "cmek_settings", []))
	object.get(cmek, "kms_key_name", false) == true
}

mutates(actions) if {
	some action in actions
	action in {"create", "update", "no-op"}
}
