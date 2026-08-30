import json
from pathlib import Path
import re
import unittest


ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENTS = ("development", "staging", "production", "restricted")


class CrossEnvironmentDenialTest(unittest.TestCase):
    def test_each_root_has_partial_backend_and_matching_identity(self):
        for variables in sorted((ROOT / "opentofu/live").glob("*/*/environment.auto.tfvars.json")):
            environment = variables.parts[-3]
            document = json.loads(variables.read_text(encoding="utf-8"))
            self.assertEqual(document["environment"], environment)
            backend = variables.with_name("backend.tf").read_text(encoding="utf-8")
            self.assertRegex(backend, r'backend\s+"gcs"\s*\{\s*\}')
            self.assertNotRegex(backend, r'\b(bucket|prefix)\s*=')

    def test_roots_do_not_reference_another_environment(self):
        for root in sorted(path for path in (ROOT / "opentofu/live").glob("*/*") if path.is_dir()):
            environment = root.parts[-2]
            source = "\n".join(path.read_text(encoding="utf-8") for path in root.glob("*.tf"))
            for other in ENVIRONMENTS:
                if other != environment:
                    self.assertNotIn(f"live/{other}/", source, f"{root} depends on {other}")

    def test_each_root_passes_its_immutable_environment_to_the_stack(self):
        roots = sorted(path for path in (ROOT / "opentofu/live").glob("*/*") if path.is_dir())
        self.assertEqual(len(roots), 28)
        for root in roots:
            source = (root / "main.tf").read_text(encoding="utf-8")
            self.assertEqual(len(re.findall(r"\benvironment\s*=\s*var\.environment\b", source)), 1, str(root))

    def test_targeted_module_activation_is_bound_directly_to_catalog_authority(self):
        roots = sorted(path for path in (ROOT / "opentofu/live").glob("*/*") if path.is_dir())
        self.assertEqual(len(roots), 28)
        for root in roots:
            source = (root / "main.tf").read_text(encoding="utf-8")
            self.assertIn("var.enabled && local.environment_catalog.enabled", source, str(root))
            if root.name != "foundation":
                self.assertIn("&& local.region_profile.enabled", source, str(root))

    def test_each_root_preconditions_activation_on_the_exact_catalog_entry(self):
        roots = sorted(path for path in (ROOT / "opentofu/live").glob("*/*") if path.is_dir())
        self.assertEqual(len(roots), 28)
        for root in roots:
            source = (root / "outputs.tf").read_text(encoding="utf-8")
            self.assertIn("var.enabled == one([", source, str(root))
            self.assertIn('environment.enabled if environment.name == var.environment', source, str(root))
            self.assertIn('../../../../catalog/environments.yaml', source, str(root))

    def test_live_roots_resolve_project_and_resource_authority_from_catalog(self):
        expected = {
            "foundation": ("project-classes.yaml", "project_class     = local.project_class"),
            "data-services": ("resource-profiles.yaml", "resource_profile  = local.resource_profile"),
            "clusters": ("resource-profiles.yaml", "resource_profile     = local.resource_profile"),
        }
        for stack, markers in expected.items():
            roots = sorted((ROOT / "opentofu/live").glob(f"*/{stack}/main.tf"))
            self.assertEqual(len(roots), 4)
            for root in roots:
                source = root.read_text(encoding="utf-8")
                for marker in markers:
                    self.assertIn(marker, source, str(root))

    def test_catalog_profile_controls_are_provider_enforced(self):
        sql = (ROOT / "opentofu/modules/gcp/cloud-sql-postgres/main.tf").read_text(encoding="utf-8")
        gke = (ROOT / "opentofu/modules/gcp/gke-regional-cluster/main.tf").read_text(encoding="utf-8")
        project = (ROOT / "opentofu/modules/gcp/project-factory/main.tf").read_text(encoding="utf-8")
        self.assertIn("var.backup_retention_days >= var.minimum_backup_retention_days", sql)
        self.assertIn('var.availability_type == "REGIONAL"', sql)
        self.assertIn("length(var.node_locations) >= var.minimum_zones", gke)
        self.assertIn("deletion_protection         = var.deletion_protection_required", gke)
        self.assertIn("var.folder_id != null && var.organization_id == null", project)
        self.assertIn('deletion_policy     = var.deletion_protection_required ? "PREVENT" : "DELETE"', project)
        self.assertIn("var.services == var.approved_services", project)
        for root in sorted((ROOT / "opentofu/live").glob("*/foundation/main.tf")):
            source = root.read_text(encoding="utf-8")
            self.assertIn('capability.name == "foundation"', source)
            self.assertNotIn("toset(flatten([", source)

    def test_protected_apply_requires_qualified_finops_budget(self):
        workflow = (ROOT / ".github/workflows/protected-apply.yml").read_text(encoding="utf-8")
        self.assertIn("INFRASTRUCTURE_FINOPS_BUDGET_READY", workflow)
        self.assertIn('test "${FINOPS_BUDGET_READY}" = "true"', workflow)
        self.assertIn("INFRASTRUCTURE_SHARED_VPC_GKE_IAM_READY", workflow)
        self.assertIn('test "${SHARED_VPC_GKE_IAM_READY}" = "true"', workflow)
        self.assertIn("INFRASTRUCTURE_CMEK_SERVICE_AGENT_BINDINGS_READY", workflow)
        self.assertIn('test "${CMEK_SERVICE_AGENT_BINDINGS_READY}" = "true"', workflow)
        self.assertIn("INFRASTRUCTURE_BINARY_AUTHORIZATION_READY", workflow)
        self.assertIn('test "${BINARY_AUTHORIZATION_READY}" = "true"', workflow)
        self.assertIn("INFRASTRUCTURE_IAM_PRINCIPALS_READY", workflow)
        self.assertIn('test "${IAM_PRINCIPALS_READY}" = "true"', workflow)
        self.assertIn("INFRASTRUCTURE_RESOURCE_REFERENCES_READY", workflow)
        self.assertIn('test "${RESOURCE_REFERENCES_READY}" = "true"', workflow)
        self.assertIn("INFRASTRUCTURE_IAM_PRINCIPALS_DIGEST", workflow)
        self.assertIn("approvedIamPrincipals", workflow)
        self.assertIn("approvedResourceReferences", workflow)
        self.assertIn("EXPECTED_RESOURCE_REFERENCES_DIGEST", workflow)
        self.assertIn("iamPrincipalsDigest", workflow)
        self.assertIn("resourceReferencesDigest", workflow)
        self.assertIn("unset TF_CLI_ARGS TF_CLI_ARGS_init TF_CLI_ARGS_plan TF_CLI_ARGS_apply", workflow)
        for stack in ("FOUNDATION", "NETWORK", "ARTIFACTS", "DATA_SERVICES", "CLUSTERS", "CI_EXECUTION", "OBSERVABILITY"):
            self.assertIn(f"INFRASTRUCTURE_REQUIRED_APIS_{stack}_READY", workflow)
        self.assertIn('case "${STACK}" in', workflow)

    def test_redacted_receipt_claim_does_not_overstate_external_evidence(self):
        security = (ROOT / "SECURITY.md").read_text(encoding="utf-8")
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("redacted locator", security)
        self.assertIn("is not live-system proof by itself", security)
        self.assertIn("environment record are authoritative", security)
        self.assertIn("not the receipt by itself", readme)
        self.assertIn("IAM-principal qualification digest", security)
        self.assertIn("resource-reference qualification digest", security)

    def test_every_root_declares_an_exact_iam_principal_approval_list(self):
        roots = sorted(path for path in (ROOT / "opentofu/live").glob("*/*") if path.is_dir())
        self.assertEqual(len(roots), 28)
        for root in roots:
            source = (root / "main.tf").read_text(encoding="utf-8")
            contract = json.loads((root / "environment.auto.tfvars.json").read_text(encoding="utf-8"))
            self.assertIn('variable "approved_iam_principals"', source, str(root))
            self.assertIn("Environment-scoped externally qualified IAM principals", source, str(root))
            self.assertEqual(contract["approved_iam_principals"], [], str(root))
            self.assertIn('variable "approved_resource_references"', source, str(root))
            self.assertEqual(contract["approved_resource_references"], [], str(root))

    def test_policy_covers_every_repository_iam_member_resource_type(self):
        policy = (ROOT / "policy/organization_constraints.rego").read_text(encoding="utf-8")
        resource_types = set()
        resource_pattern = re.compile(r'resource\s+"(google_[^"]+_iam_member)"')
        for path in sorted((ROOT / "opentofu").rglob("*.tf")):
            resource_types.update(resource_pattern.findall(path.read_text(encoding="utf-8")))
        self.assertEqual(
            resource_types,
            {
                "google_artifact_registry_repository_iam_member",
                "google_kms_crypto_key_iam_member",
                "google_project_iam_member",
                "google_pubsub_subscription_iam_member",
                "google_pubsub_topic_iam_member",
                "google_secret_manager_secret_iam_member",
                "google_service_account_iam_member",
                "google_storage_bucket_iam_member",
            },
        )
        for resource_type in resource_types:
            self.assertIn(f'"{resource_type}"', policy)
        self.assertIn("approved_iam_principals", policy)
        self.assertIn("allowed_iam_roles_by_type", policy)
        self.assertIn("approved_resource_references", policy)

    def test_location_bearing_roots_bind_catalog_region_authority(self):
        location_stacks = {"network", "artifacts", "data-services", "clusters", "ci-execution", "observability"}
        for stack in location_stacks:
            roots = sorted((ROOT / "opentofu/live").glob(f"*/{stack}"))
            self.assertEqual(len(roots), 4)
            for root in roots:
                source = (root / "main.tf").read_text(encoding="utf-8")
                outputs = (root / "outputs.tf").read_text(encoding="utf-8")
                self.assertIn("catalog/regions.yaml", source, str(root))
                self.assertIn("primary_location", source, str(root))
                self.assertIn("recovery_location", source, str(root))
                self.assertIn('output "region_authority"', outputs, str(root))
                self.assertIn("local.region_profile.primaryLocation", outputs, str(root))

        stack_markers = {
            "network": ["region = var.primary_location"],
            "artifacts": ["location     = var.primary_location"],
            "data-services": ["location      = var.primary_location", "region                         = var.primary_location"],
            "clusters": ["region                        = var.primary_location", "location        = var.primary_location"],
            "ci-execution": ["region                                = var.primary_location"],
            "observability": ["location       = var.primary_location"],
        }
        for stack, markers in stack_markers.items():
            source = (ROOT / "opentofu/stacks" / stack / "main.tf").read_text(encoding="utf-8")
            for marker in markers:
                self.assertIn(marker, source)

    def test_enabled_cmek_requires_explicit_qualified_service_agents(self):
        delegated = (ROOT / "opentofu/modules/gcp/delegated-kms/variables.tf").read_text(encoding="utf-8")
        observability = (ROOT / "opentofu/stacks/observability/main.tf").read_text(encoding="utf-8")
        self.assertIn("length(key.encrypter_decrypters) > 0", delegated)
        self.assertIn("serviceAccount:", delegated)
        self.assertIn("encrypter_decrypters", observability)
        for contract in sorted((ROOT / "opentofu/live").glob("*/observability/environment.auto.tfvars.json")):
            config = json.loads(contract.read_text(encoding="utf-8"))["config"]
            self.assertEqual(config["key_encrypter_decrypters"], [])

    def test_observability_sink_iam_uses_reviewed_two_phase_identity_flow(self):
        source = (ROOT / "opentofu/modules/gcp/observability-backend/main.tf").read_text(encoding="utf-8")
        variables = (ROOT / "opentofu/modules/gcp/observability-backend/variables.tf").read_text(encoding="utf-8")
        self.assertIn('var.sink_writer_binding_mode == "enforce"', source)
        self.assertIn("member  = each.value", source)
        self.assertIn("each.value == google_logging_project_sink.source[each.key].writer_identity", source)
        self.assertNotIn("member  = each.value.writer_identity", source)
        self.assertIn('contains(["discover", "enforce"]', variables)
        self.assertIn("toset(keys(var.sink_writer_identities)) == var.source_projects", variables)
        self.assertIn("!contains(var.source_projects, var.project_id)", variables)
        for contract in sorted((ROOT / "opentofu/live").glob("*/observability/environment.auto.tfvars.json")):
            config = json.loads(contract.read_text(encoding="utf-8"))["config"]
            self.assertEqual(config["sink_writer_binding_mode"], "enforce")
            self.assertEqual(config["sink_writer_identities"], {})

    def test_stacks_override_operator_environment_labels(self):
        expected_bindings = {
            "foundation": ["merge(var.config.labels, { environment = var.environment })"],
            "network": [
                "merge(var.config.labels, { environment = var.environment })",
                "merge(zone.labels, { environment = var.environment })",
            ],
            "artifacts": [
                "merge(key.labels, { environment = var.environment })",
                "merge(repository.labels, { environment = var.environment })",
                "merge(bucket.labels, { environment = var.environment })",
            ],
            "data-services": [
                "merge(key.labels, { environment = var.environment })",
                "merge(try(var.config.database.labels, {}), { environment = var.environment })",
                "merge(topic.labels, { environment = var.environment })",
                "merge(subscription.labels, { environment = var.environment })",
            ],
            "clusters": [
                "merge(var.config.resource_labels, { environment = var.environment })",
                "merge(each.value.labels, { environment = var.environment })",
                "merge(each.value.resource_labels, { environment = var.environment })",
            ],
            "ci-execution": ["merge(var.config.labels, { environment = var.environment })"],
            "observability": ["merge(var.config.labels, { environment = var.environment })"],
        }
        for stack, bindings in expected_bindings.items():
            source = (ROOT / "opentofu/stacks" / stack / "main.tf").read_text(encoding="utf-8")
            for binding in bindings:
                self.assertIn(binding, source, f"{stack} does not bind {binding}")

    def test_secret_access_identity_is_external_secrets_only(self):
        variables = (ROOT / "opentofu/modules/gcp/argocd-management/variables.tf").read_text(encoding="utf-8")
        self.assertIn('default = ["external-secrets"]', variables)
        self.assertIn('account == "external-secrets"', variables)
        self.assertNotIn("argocd-server", variables)
        self.assertNotIn("argocd-application-controller", variables)

    def test_workload_project_roles_use_an_explicit_capability_allowlist(self):
        variables = (ROOT / "opentofu/modules/gcp/workload-identity/variables.tf").read_text(encoding="utf-8")
        self.assertIn('"roles/cloudsql.client"', variables)
        self.assertIn('"roles/logging.logWriter"', variables)
        self.assertIn("explicit least-privilege capability allowlist", variables)
        for forbidden in ("roles/cloudkms.admin", "roles/resourcemanager.projectIamAdmin", "roles/iam.securityAdmin"):
            self.assertNotIn(f'"{forbidden}"', variables)

    def test_egress_is_allowlisted_and_default_denied(self):
        source = (ROOT / "opentofu/modules/gcp/controlled-egress/main.tf").read_text(encoding="utf-8")
        variables = (ROOT / "opentofu/modules/gcp/controlled-egress/variables.tf").read_text(encoding="utf-8")
        self.assertIn('resource "google_compute_firewall" "allow_egress"', source)
        self.assertIn('resource "google_compute_firewall" "deny_egress"', source)
        self.assertIn('destination_ranges = ["0.0.0.0/0"]', source)
        self.assertIn("length(var.allowed_egress_rules) > 0", variables)
        self.assertIn('try(tonumber(split("/", cidr)[1]), 0) > 0', variables)
        self.assertIn('contains(["tcp", "udp"], rule.protocol)', variables)
        stack = (ROOT / "opentofu/stacks/network/main.tf").read_text(encoding="utf-8")
        self.assertIn("allowed_egress_rules = var.config.allowed_egress_rules", stack)
        for contract in sorted((ROOT / "opentofu/live").glob("*/network/environment.auto.tfvars.json")):
            config = json.loads(contract.read_text(encoding="utf-8"))["config"]
            self.assertEqual(config["allowed_egress_rules"], {})

    def test_shared_vpc_requires_distinct_service_projects(self):
        source = (ROOT / "opentofu/modules/gcp/shared-vpc/main.tf").read_text(encoding="utf-8")
        variables = (ROOT / "opentofu/modules/gcp/shared-vpc/variables.tf").read_text(encoding="utf-8")
        self.assertIn('resource "google_compute_shared_vpc_service_project" "this"', source)
        self.assertIn("each.value != var.project_id", source)
        self.assertIn("length(var.service_project_ids) > 0", variables)
        for contract in sorted((ROOT / "opentofu/live").glob("*/network/environment.auto.tfvars.json")):
            config = json.loads(contract.read_text(encoding="utf-8"))["config"]
            self.assertEqual(config["service_project_ids"], [])

    def test_network_cidrs_reject_host_form_and_noncanonical_control_plane_ranges(self):
        shared = (ROOT / "opentofu/modules/gcp/shared-vpc/variables.tf").read_text(encoding="utf-8")
        gke = (ROOT / "opentofu/modules/gcp/gke-regional-cluster/variables.tf").read_text(encoding="utf-8")
        self.assertIn("can(cidrnetmask", shared)
        self.assertIn('cidrhost("${var.private_service_access.address}/${var.private_service_access.prefix_length}", 0)', shared)
        self.assertIn("== var.private_service_access.address", shared)
        self.assertIn("can(cidrnetmask(var.master_ipv4_cidr_block))", gke)
        self.assertIn('split("/", var.master_ipv4_cidr_block)[1]', gke)
        self.assertIn("== 28", gke)
        self.assertIn("cidrhost(var.master_ipv4_cidr_block, 0)", gke)

    def test_buildkite_images_are_immutable_when_enabled(self):
        variables = (ROOT / "opentofu/modules/gcp/buildkite-agents/variables.tf").read_text(encoding="utf-8")
        source = (ROOT / "opentofu/modules/gcp/buildkite-agents/main.tf").read_text(encoding="utf-8")
        self.assertIn("global/images/[a-z]", variables)
        self.assertIn("@sha256:[0-9a-f]{64}$", variables)
        self.assertIn("startup-script", source)
        self.assertIn("BUILDKITE_TOKEN_SECRET_RESOURCE", source)
        self.assertIn("agent_image_b64 = var.enabled ? base64encode(var.agent_image)", source)
        self.assertIn("readonly image_b64='${local.agent_image_b64}'", source)
        self.assertIn("token_secret_version", source)
        self.assertNotIn("readonly image='${var.agent_image}'", source)
        self.assertIn("BUILDKITE_AGENT_DISCONNECT_AFTER_JOB=true", source)
        self.assertIn("BUILDKITE_AGENT_DISCONNECT_AFTER_IDLE_TIMEOUT=300", source)
        self.assertIn("shutdown -h now", source)
        self.assertIn("--cap-drop=ALL", source)
        self.assertNotIn("gce-container-declaration", source)
        self.assertIn("var.min_replicas >= 1", variables)
        self.assertIn("var.min_replicas <= var.max_replicas", source)
        self.assertIn("var.agent_image_secret_contract_verified", source)
        self.assertIn("var.agent_job_isolation_contract_verified", source)
        for contract in sorted((ROOT / "opentofu/live").glob("*/ci-execution/environment.auto.tfvars.json")):
            config = json.loads(contract.read_text(encoding="utf-8"))["config"]
            self.assertGreaterEqual(config["min_replicas"], 1)
            self.assertIs(config["agent_image_secret_contract_verified"], False)
            self.assertIs(config["agent_job_isolation_contract_verified"], False)
            self.assertIsNone(config["token_secret_version"])
        workflow = (ROOT / ".github/workflows/protected-apply.yml").read_text(encoding="utf-8")
        self.assertIn("INFRASTRUCTURE_BUILDKITE_IMAGE_CONTRACT_READY", workflow)
        self.assertIn('test "${BUILDKITE_IMAGE_CONTRACT_READY}" = "true"', workflow)
        self.assertIn("INFRASTRUCTURE_BUILDKITE_JOB_ISOLATION_READY", workflow)

    def test_generated_service_account_iam_members_are_plan_known(self):
        buildkite = (ROOT / "opentofu/modules/gcp/buildkite-agents/main.tf").read_text(encoding="utf-8")
        workload = (ROOT / "opentofu/modules/gcp/workload-identity/main.tf").read_text(encoding="utf-8")
        argocd = (ROOT / "opentofu/modules/gcp/argocd-management/main.tf").read_text(encoding="utf-8")
        self.assertIn('serviceAccount:${var.name}@${var.project_id}.iam.gserviceaccount.com', buildkite)
        self.assertIn('serviceAccount:${each.value.account_id}@${var.project_id}.iam.gserviceaccount.com', workload)
        self.assertIn('serviceAccount:${var.service_account_id}@${var.project_id}.iam.gserviceaccount.com', argocd)
        self.assertNotIn("google_service_account.agent[0].email", buildkite)
        self.assertNotIn("google_service_account.controller[0].email", argocd)

    def test_no_static_credentials_or_kubernetes_provider(self):
        forbidden = re.compile(r'(?i)(google_service_account_key|private_key_data|client_secret\s*=|provider\s+"kubernetes"|provider\s+"helm")')
        for path in sorted((ROOT / "opentofu").rglob("*.tf")):
            self.assertIsNone(forbidden.search(path.read_text(encoding="utf-8")), str(path))


if __name__ == "__main__":
    unittest.main()
