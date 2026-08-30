import base64
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENTS = {"development", "staging", "production", "restricted"}
STACKS = {"foundation", "network", "artifacts", "data-services", "clusters", "ci-execution", "observability"}


def run_infractl(*arguments):
    runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
    candidates = sorted(path for path in runfiles.rglob("infractl") if path.is_file() and os.access(path, os.X_OK))
    if candidates:
        return subprocess.run([str(candidates[0]), *arguments], cwd=ROOT, text=True, capture_output=True, check=False)
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / "infractl"
        build = subprocess.run(["go", "build", "-o", str(binary), "./cmd/infractl"], cwd=ROOT / "tooling", text=True, capture_output=True, check=False)
        if build.returncode != 0:
            return build
        return subprocess.run([str(binary), *arguments], cwd=ROOT, text=True, capture_output=True, check=False)


def workflow_source(name):
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def workflow_step_source(workflow, name):
    marker = f"      - name: {name}\n"
    start = workflow.index(marker)
    end = workflow.find("\n      - name: ", start + len(marker))
    if end == -1:
        end = len(workflow)
    return workflow[start:end]


def test_ed25519_sign(message):
    # RFC 8032 arithmetic implemented with Python stdlib for a deterministic,
    # non-production test key. Runtime verification remains Go's crypto/ed25519.
    field = 2**255 - 19
    order = 2**252 + 27742317777372353535851937790883648493
    curve_d = (-121665 * pow(121666, field - 2, field)) % field
    sqrt_minus_one = pow(2, (field - 1) // 4, field)

    def recover_x(y):
        xx = (y * y - 1) * pow(curve_d * y * y + 1, field - 2, field)
        x = pow(xx, (field + 3) // 8, field)
        if (x * x - xx) % field != 0:
            x = (x * sqrt_minus_one) % field
        if x % 2:
            x = field - x
        return x

    def add(left, right):
        x1, y1 = left
        x2, y2 = right
        denominator = curve_d * x1 * x2 * y1 * y2
        return (
            (x1 * y2 + x2 * y1) * pow(1 + denominator, field - 2, field) % field,
            (y1 * y2 + x1 * x2) * pow(1 - denominator, field - 2, field) % field,
        )

    def multiply(point, scalar):
        result = (0, 1)
        addend = point
        while scalar:
            if scalar & 1:
                result = add(result, addend)
            addend = add(addend, addend)
            scalar >>= 1
        return result

    def encode(point):
        x, y = point
        return (y | ((x & 1) << 255)).to_bytes(32, "little")

    base_y = (4 * pow(5, field - 2, field)) % field
    base = (recover_x(base_y), base_y)
    seed = bytes.fromhex(
        "9d61b19deffd5a60ba844af492ec2cc4"
        "4449c5697b326919703bac031cae7f60"
    )
    expanded = hashlib.sha512(seed).digest()
    scalar = int.from_bytes(expanded[:32], "little")
    scalar &= (1 << 254) - 8
    scalar |= 1 << 254
    public_key = encode(multiply(base, scalar))
    nonce = int.from_bytes(hashlib.sha512(expanded[32:] + message).digest(), "little") % order
    encoded_nonce = encode(multiply(base, nonce))
    challenge = int.from_bytes(
        hashlib.sha512(encoded_nonce + public_key + message).digest(), "little"
    ) % order
    signature = encoded_nonce + ((nonce + challenge * scalar) % order).to_bytes(32, "little")
    return public_key, signature


def signed_export(
    directory, resources, stack="foundation", provenance_uri=None,
    tamper_payload=None, trusted_key_id=None,
):
    directory = Path(directory)
    resources_path = directory / "resources.json"
    payload_path = directory / "export.payload.json"
    signature_path = directory / "export.signature.json"
    output_path = directory / "export.json"
    resources_path.write_text(json.dumps(resources), encoding="utf-8")
    provenance_uri = provenance_uri or f"https://evidence.example/provenance/development-{stack}"
    arguments = [
        "--environment", "development",
        "--stack", stack,
        "--source-commit", "a" * 40,
        "--plan-digest", "sha256:" + "b" * 64,
        "--provider-lock-digest", "sha256:" + "c" * 64,
        "--backend-state-digest", "sha256:" + "d" * 64,
        "--backend-lineage", "123e4567-e89b-42d3-a456-426614174000",
        "--backend-serial", "17",
        "--schema-digest", "sha256:" + "e" * 64,
        "--generated-at", "2026-08-29T12:00:00Z",
        "--resources", str(resources_path),
        "--provenance-uri", provenance_uri,
        "--provenance-digest", "sha256:" + "f" * 64,
    ]
    payload_result = run_infractl(
        "exports", "payload", *arguments, "--output", str(payload_path)
    )
    if payload_result.returncode != 0:
        return payload_result, output_path

    payload = payload_path.read_bytes()
    public_key, detached_signature = test_ed25519_sign(payload)
    envelope = {
        "algorithm": "Ed25519",
        "keyId": "sha256:" + hashlib.sha256(public_key).hexdigest(),
        "publicKey": base64.b64encode(public_key).decode("ascii"),
        "value": base64.b64encode(detached_signature).decode("ascii"),
        "payloadDigest": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }
    signature_path.write_text(json.dumps(envelope), encoding="utf-8")
    if tamper_payload is not None:
        tamper_payload(resources_path, signature_path)
    result = run_infractl(
        "exports", "emit", *arguments,
        "--signature", str(signature_path),
        "--trusted-key-id", trusted_key_id or envelope["keyId"],
        "--output", str(output_path),
    )
    return result, output_path


class EnvironmentPlanContractTest(unittest.TestCase):
    def test_checked_out_blueprint_tree_is_exact_and_nonempty(self):
        if not (ROOT / ".git").exists():
            self.skipTest("Bazel runfiles intentionally expose only declared test data")
        environments = ("development", "staging", "production", "restricted")
        stacks = ("foundation", "network", "artifacts", "data-services", "clusters", "ci-execution", "observability")
        tofu_files = ("main", "variables", "outputs")
        live_files = ("backend.tf", "versions.tf", "providers.tf", "main.tf", "environment.auto.tfvars.json", "outputs.tf")
        modules = (
            "project-factory", "shared-vpc", "private-dns", "controlled-egress",
            "artifact-registry", "artifact-bucket", "cloud-sql-postgres",
            "pubsub-transport", "secret-bindings", "delegated-kms",
            "gke-regional-cluster", "gke-node-pool", "workload-identity",
            "observability-backend", "buildkite-agents", "argocd-management",
        )
        policies = (
            "organization_constraints", "network_boundaries", "workload_identity",
            "encryption_and_retention", "database_recovery", "gke_security",
            "accelerator_isolation", "cost_guardrails",
        )
        expected = {
            ".editorconfig", ".gitignore", "BUILD.bazel", "LICENSE", "MODULE.bazel",
            "README.md", "SECURITY.md", "component.yaml", "justfile",
            ".github/CODEOWNERS", ".github/dependabot.yml", ".github/pull_request_template.md",
            *{f".github/workflows/{name}.yml" for name in (
                "pull-request", "drift-detection", "protected-apply", "disaster-recovery",
            )},
            *{f"catalog/{name}.yaml" for name in (
                "environments", "regions", "project-classes", "data-classes",
                "resource-profiles", "accelerator-profiles", "service-capabilities",
            )},
            *{f"schemas/v1/{name}.schema.json" for name in (
                "environment", "region", "project_class", "data_class", "resource_profile",
                "accelerator_profile", "service_capability", "infrastructure_export",
            )},
            *{f"opentofu/modules/gcp/{module}/{name}.tf" for module in modules for name in tofu_files},
            *{f"opentofu/stacks/{stack}/{name}.tf" for stack in stacks for name in tofu_files},
            *{f"opentofu/live/{environment}/{stack}/{name}" for environment in environments for stack in stacks for name in live_files},
            *{f"policy/{name}.rego" for name in policies},
            *{f"policy/tests/{name}_test.rego" for name in policies},
            "tests/contract/test_environment_plan.py",
            *{f"tests/plan/test_{name}_plan.py" for name in ("development", "staging", "production")},
            "tests/security/test_cross_environment_denial.py",
            "tests/failure/test_partial_apply_reconciliation.py",
            "tests/drift/test_cloud_drift_classification.py",
            "tests/recovery/test_database_restore.py", "tests/recovery/test_artifact_restore.py",
            "tests/capacity/test_accelerator_profile.py",
            "tooling/cmd/infractl/main.go", "tooling/go.mod", "tooling/go.sum", "tooling/BUILD.bazel",
            *{f"tooling/internal/{name}/{name}.go" for name in ("catalog", "plan", "policy", "drift", "exports")},
            *{f"runbooks/{name}.md" for name in (
                "infrastructure-apply-failure", "cloud-drift", "network-isolation-failure",
                "cluster-control-plane-failure", "database-failover-and-restore",
                "artifact-storage-recovery", "regional-recovery",
            )},
        }
        ignored_directories = {".git", "__pycache__", ".pytest_cache", ".terraform"}
        actual = set()
        empty = []
        source_symlinks = []
        for directory, children, files in os.walk(ROOT, followlinks=False):
            relative_directory = Path(directory).relative_to(ROOT)
            for child in children:
                child_path = Path(directory) / child
                if child_path.is_symlink() and child not in ignored_directories and not child.startswith("bazel-"):
                    source_symlinks.append((relative_directory / child).as_posix())
            children[:] = [
                child for child in children
                if child not in ignored_directories and not child.startswith("bazel-")
            ]
            for name in files:
                if name == ".DS_Store" or name.endswith((".pyc", ".pyo")):
                    continue
                path = Path(directory) / name
                relative = path.relative_to(ROOT).as_posix()
                if path.is_symlink():
                    source_symlinks.append(relative)
                if path.stat().st_size == 0:
                    empty.append(relative)
                actual.add(relative)
        self.assertEqual(source_symlinks, [], "Blueprint source paths must be regular, non-symlink files")
        self.assertEqual(empty, [], "Blueprint source files must be non-empty")
        self.assertEqual(actual, expected)

    def test_component_metadata_reports_source_truth_without_live_authority(self):
        component = (ROOT / "component.yaml").read_text(encoding="utf-8")
        for field in (
            "  lifecycle: pre-production",
            "  maturity: pre-production",
            "  owner: platform-operations",
            "  security_reviewers:",
            "    - security",
            "  repository_class: infrastructure-source",
            "  trust_tier: privileged",
            "  recovery_tier: tier-0",
            "  production_authority: false",
        ):
            self.assertIn(field, component)
        self.assertNotIn("  production_authority: true", component)

    def test_pull_request_workflow_is_the_single_canonical_source_gate(self):
        workflow = workflow_source("pull-request.yml")
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")

        self.assertIn('"on":\n  pull_request:\n  merge_group:', workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("  required:\n    name: required", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn("@mindclade/platform-operations", codeowners)
        self.assertIn("@mindclade/security", codeowners)
        self.assertNotIn("@mindclade/infrastructure", codeowners)

    def test_protected_apply_policy_checks_no_change_plans_before_failing_closed(self):
        workflow = workflow_source("protected-apply.yml")
        step = workflow_step_source(workflow, "Recreate and verify the reviewed saved plan")
        cleanup = workflow_step_source(workflow, "Remove plan working material")

        self.assertIn("    environment: trusted-build", workflow)
        self.assertIn("    environment: infrastructure-apply", workflow)
        self.assertNotIn("environment: infrastructure-${{ inputs.environment }}-apply", workflow)
        self.assertIn("needs: [preflight, plan]", workflow)
        self.assertIn("infrastructure-live-${ENVIRONMENT}-plan", workflow)
        self.assertIn("infrastructure-live-${ENVIRONMENT}-apply", workflow)
        self.assertIn("https://github.mindclade.io/oidc/infrastructure-live/${ENVIRONMENT}/plan", workflow)
        self.assertIn("https://github.mindclade.io/oidc/infrastructure-live/${ENVIRONMENT}/apply", workflow)
        self.assertIn("GCP_WIF_PROVIDER_INFRASTRUCTURE_LIVE_DEVELOPMENT_PLAN", workflow)
        self.assertIn("GCP_WIF_PROVIDER_INFRASTRUCTURE_LIVE_RESTRICTED_APPLY", workflow)
        self.assertIn('plan_log="${RUNNER_TEMP}/reviewed.plan.log"', step)
        self.assertIn('-out="${saved_plan}" >"${plan_log}" 2>&1', step)
        self.assertIn("state pull", step)
        self.assertIn("provider_lock_digest", step)
        self.assertIn("backend_state_digest", step)
        self.assertIn("backend_serial", step)
        self.assertIn("backend_lineage", step)
        self.assertIn('[[ "${plan_status}" -ne 0 && "${plan_status}" -ne 2 ]]', step)
        self.assertLess(
            step.index('conftest test "${plan_json}"'),
            step.index('[[ "${plan_status}" -eq 0 ]]'),
        )
        self.assertIn("no-change plan passed policy evaluation", step)
        no_change_guard = step[step.index('[[ "${plan_status}" -eq 0 ]]') :]
        self.assertIn("exit 1", no_change_guard)
        self.assertNotIn('cat "${plan_log}"', step)
        self.assertNotIn('tee "${plan_log}"', step)
        self.assertIn("if: always()", cleanup)
        self.assertIn('"${RUNNER_TEMP}/reviewed.plan.log"', cleanup)
        self.assertIn('"${root}/.terraform.lock.hcl"', cleanup)
        self.assertIn("actions/upload-artifact@043fb46", workflow)
        self.assertIn("actions/download-artifact@3e5f45", workflow)
        self.assertIn('find "${bundle}" -mindepth 1 -maxdepth 1 ! -type f', workflow)
        self.assertIn("-lockfile=readonly", workflow)

    def test_protected_apply_post_plan_prints_only_a_redacted_drift_summary(self):
        workflow = workflow_source("protected-apply.yml")
        step = workflow_step_source(workflow, "Require post-apply zero drift")
        final_cleanup = workflow_step_source(workflow, "Remove transient plan material")

        self.assertIn('plan_log="${RUNNER_TEMP}/post-apply.plan.log"', step)
        self.assertIn('-out="${saved_plan}" >"${plan_log}" 2>&1', step)
        self.assertIn('"${RUNNER_TEMP}/infractl" plan classify', step)
        self.assertIn("{creates, updates, deletes, replaces, reads, noOps, safe}", step)
        self.assertIn("only the redacted classification is shown", step)
        self.assertIn("exit 2", step)
        self.assertNotIn('cat "${plan_log}"', step)
        self.assertNotIn('tee "${plan_log}"', step)
        self.assertIn("if: always()", final_cleanup)
        self.assertIn('"${RUNNER_TEMP}/post-apply.plan.log"', final_cleanup)
        self.assertIn('"${RUNNER_TEMP}/pre-apply.state.json"', final_cleanup)
        self.assertIn('"${RUNNER_TEMP}/post-apply.state.json"', final_cleanup)

    def test_drift_evidence_records_policy_outcome_without_policy_contents(self):
        workflow = workflow_source("drift-detection.yml")
        step = workflow_step_source(workflow, "Create a read-only drift plan and redacted evidence")

        self.assertIn("    environment: trusted-build", workflow)
        self.assertNotIn("environment: infrastructure-${{ matrix.environment }}-plan", workflow)
        self.assertIn("github.com/open-policy-agent/conftest@v0.69.0", workflow)
        self.assertIn('-out="${saved_plan}" >"${plan_log}" 2>&1', step)
        self.assertIn('[[ "${plan_status}" -ne 0 && "${plan_status}" -ne 2 ]]', step)
        self.assertIn('conftest test "${plan_json}"', step)
        self.assertIn('[[ "${policy_status}" -ne 0 && "${policy_status}" -ne 1 ]]', step)
        self.assertIn('--arg policyDigest "${policy_digest}"', step)
        self.assertIn('--argjson policyPassed "${policy_passed}"', step)
        self.assertIn("policyPassed: $policyPassed", step)
        self.assertIn("policyDigest: $policyDigest", step)
        self.assertNotIn("--slurpfile policy", step)
        self.assertIn('rm -f "${saved_plan}" "${plan_json}" "${plan_log}" "${classification}" "${policy_result}"', step)
        self.assertNotIn('cat "${plan_log}"', step)
        self.assertNotIn('tee "${plan_log}"', step)

        upload = workflow.index("- name: Retain redacted drift evidence only")
        drift_failure = workflow.index("- name: Fail when drift exists")
        policy_failure = workflow.index("- name: Fail when plan policy is denied")
        self.assertLess(upload, drift_failure)
        self.assertLess(upload, policy_failure)
        self.assertIn("steps.drift.outputs.policy_passed == 'false'", workflow)

    def test_all_recovery_scope_uses_the_same_dispatch_as_each_single_scope(self):
        workflow = workflow_source("disaster-recovery.yml")
        step = workflow_step_source(workflow, "Verify recovery tests without live access")

        self.assertIn("verify_scope()", step)
        self.assertIn("for scope in database artifacts network cluster regional; do", step)
        self.assertIn('verify_scope "${scope}"', step)
        self.assertIn("database|artifacts|network|cluster|regional", step)
        self.assertIn('verify_scope "${RECOVERY_SCOPE}"', step)
        self.assertIn("python3 tests/recovery/test_database_restore.py", step)
        self.assertIn("python3 tests/recovery/test_artifact_restore.py", step)
        self.assertIn("python3 tests/security/test_cross_environment_denial.py", step)
        self.assertIn("python3 tests/plan/test_production_plan.py", step)
        self.assertIn("python3 tests/failure/test_partial_apply_reconciliation.py", step)
        self.assertNotIn("test -s runbooks/", step)
        self.assertIn("Unsupported recovery scope", step)
        self.assertIn("return 1", step)
        self.assertIn("connectedQualification: false", workflow)
        self.assertIn("mutationPerformed: false", workflow)

    def test_catalogs_and_schemas_validate(self):
        result = run_infractl("catalog", "validate", "--root", str(ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, {"catalogs": 7, "schemas": 8})

    def test_ci_evidence_schema_is_production_only_and_retention_lock_is_unreachable(self):
        archive = {
            "enabled": False,
            "location": "NAM4",
            "storageClass": "STANDARD",
            "replicationMode": "DEFAULT",
            "kmsProtectionLevel": "SOFTWARE",
            "kmsRotationPeriod": "7776000s",
            "retentionDays": 2555,
            "retentionLocked": False,
            "retentionLockReceipt": None,
            "softDeleteDays": 30,
            "versioningEnabled": False,
            "archiveAfterDays": 90,
            "archiveMinimumSizeBytes": 1048576,
            "deleteAfterDays": 2555,
        }
        base_profiles = [
            {
                "name": "development", "highAvailabilityRequired": False,
                "deletionProtectionRequired": True, "backupRetentionDays": 7,
                "minimumZones": 1, "costGuardrail": "low",
            },
            {
                "name": "staging", "highAvailabilityRequired": True,
                "deletionProtectionRequired": True, "backupRetentionDays": 14,
                "minimumZones": 2, "costGuardrail": "moderate",
            },
            {
                "name": "production", "highAvailabilityRequired": True,
                "deletionProtectionRequired": True, "backupRetentionDays": 35,
                "minimumZones": 3, "costGuardrail": "reliability-first",
                "ciEvidenceArchive": archive,
            },
            {
                "name": "restricted", "highAvailabilityRequired": True,
                "deletionProtectionRequired": True, "backupRetentionDays": 35,
                "minimumZones": 3, "costGuardrail": "security-first",
            },
        ]

        def rejected(mutator):
            with tempfile.TemporaryDirectory() as directory:
                candidate = Path(directory)
                shutil.copytree(ROOT / "catalog", candidate / "catalog")
                shutil.copytree(ROOT / "schemas", candidate / "schemas")
                shutil.copytree(ROOT / "opentofu", candidate / "opentofu")
                profiles = json.loads(json.dumps(base_profiles))
                mutator(profiles)
                document = {
                    "apiVersion": "infrastructure.mindclade.dev/v1",
                    "kind": "ResourceProfileCatalog",
                    "resourceProfiles": profiles,
                }
                (candidate / "catalog/resource-profiles.yaml").write_text(
                    json.dumps(document), encoding="utf-8"
                )
                result = run_infractl("catalog", "validate", "--root", str(candidate))
                self.assertNotEqual(result.returncode, 0)
                self.assertTrue(result.stderr.strip())

        rejected(lambda profiles: profiles[2].pop("ciEvidenceArchive"))
        rejected(lambda profiles: profiles[1].update({"ciEvidenceArchive": archive}))

        def lock_without_receipt(profiles):
            profiles[2]["ciEvidenceArchive"]["retentionLocked"] = True

        rejected(lock_without_receipt)

        def lock_with_fabricated_receipt(profiles):
            archive = profiles[2]["ciEvidenceArchive"]
            archive["retentionLocked"] = True
            archive["retentionLockReceipt"] = {
                "receiptVersion": "ci-evidence-retention-lock/v1",
                "canaryObjectUri": "gs://bucket/qualification/canary/" + "a" * 40 + "/evidence.json#42",
                "canaryGeneration": "42",
                "verifierIdentity": "serviceAccount:ci-evidence-verifier@identity-project.iam.gserviceaccount.com",
                "verifierDigest": "sha256:" + "b" * 64,
                "denialEvidenceDigest": "sha256:" + "c" * 64,
                "auditEvidenceDigest": "sha256:" + "d" * 64,
                "platformApprovalIdentity": "group:platform-operations@mindclade.dev",
                "securityApprovalIdentity": "group:security@mindclade.dev",
                "approvedAt": "2026-08-30T12:00:00Z",
                "sourceCommit": "a" * 40,
                "receiptDigest": "sha256:" + "e" * 64,
            }

        rejected(lock_with_fabricated_receipt)

        def unlocked_with_receipt(profiles):
            profiles[2]["ciEvidenceArchive"]["retentionLockReceipt"] = {
                "receiptVersion": "ci-evidence-retention-lock/v1",
            }

        rejected(unlocked_with_receipt)

    def test_catalog_validation_resolves_references_and_activation(self):
        mutations = [
            ("catalog/environments.yaml", "regionProfile: central-us", "regionProfile: missing-region", "unknown region"),
            ("catalog/project-classes.yaml", "allowedEnvironmentTiers: [development]", "allowedEnvironmentTiers: [staging]", "disallowed tier"),
            ("catalog/environments.yaml", "enabled: false", "enabled: true", "incoherent activation"),
            ("catalog/resource-profiles.yaml", "name: staging", "name: development", "duplicate name"),
            ("catalog/service-capabilities.yaml", "dns.googleapis.com", "iamcredentials.googleapis.com", "unapproved required API"),
            ("catalog/service-capabilities.yaml", "log-bucket, metrics-scope", "log-bucket, project", "mismatched export kind"),
        ]
        for relative_path, original, replacement, label in mutations:
            with self.subTest(case=label), tempfile.TemporaryDirectory() as directory:
                candidate = Path(directory)
                shutil.copytree(ROOT / "catalog", candidate / "catalog")
                shutil.copytree(ROOT / "schemas", candidate / "schemas")
                shutil.copytree(ROOT / "opentofu", candidate / "opentofu")
                path = candidate / relative_path
                contents = path.read_text(encoding="utf-8")
                self.assertIn(original, contents)
                path.write_text(contents.replace(original, replacement, 1), encoding="utf-8")
                result = run_infractl("catalog", "validate", "--root", str(candidate))
                self.assertNotEqual(result.returncode, 0)

    def test_catalog_activation_cannot_be_bypassed_by_live_root(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            shutil.copytree(ROOT / "catalog", candidate / "catalog")
            shutil.copytree(ROOT / "schemas", candidate / "schemas")
            shutil.copytree(ROOT / "opentofu", candidate / "opentofu")
            contract = candidate / "opentofu/live/development/foundation/environment.auto.tfvars.json"
            document = json.loads(contract.read_text(encoding="utf-8"))
            self.assertIs(document["enabled"], False)
            document["enabled"] = True
            contract.write_text(json.dumps(document), encoding="utf-8")

            result = run_infractl("catalog", "validate", "--root", str(candidate))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("enabled state must equal catalog environment development", result.stderr)

    def test_environment_iam_principal_authority_is_identical_across_stacks(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            shutil.copytree(ROOT / "catalog", candidate / "catalog")
            shutil.copytree(ROOT / "schemas", candidate / "schemas")
            shutil.copytree(ROOT / "opentofu", candidate / "opentofu")
            contract = candidate / "opentofu/live/restricted/data-services/environment.auto.tfvars.json"
            document = json.loads(contract.read_text(encoding="utf-8"))
            document["approved_iam_principals"] = [
                "serviceAccount:worker@restricted-project.iam.gserviceaccount.com",
            ]
            contract.write_text(json.dumps(document), encoding="utf-8")

            result = run_infractl("catalog", "validate", "--root", str(candidate))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("approved_iam_principals must equal the environment-wide set", result.stderr)

    def test_enabled_live_locations_must_equal_catalog_primary_location(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            shutil.copytree(ROOT / "catalog", candidate / "catalog")
            shutil.copytree(ROOT / "schemas", candidate / "schemas")
            shutil.copytree(ROOT / "opentofu", candidate / "opentofu")

            environments = candidate / "catalog/environments.yaml"
            source = environments.read_text(encoding="utf-8")
            source = source.replace("  - name: development\n    enabled: false", "  - name: development\n    enabled: true", 1)
            environments.write_text(source, encoding="utf-8")

            regions = candidate / "catalog/regions.yaml"
            source = regions.read_text(encoding="utf-8")
            source = source.replace(
                "  - name: central-us\n    enabled: false\n    primaryLocation: null",
                "  - name: central-us\n    enabled: true\n    primaryLocation: us-central1",
                1,
            )
            regions.write_text(source, encoding="utf-8")

            accelerators = candidate / "catalog/accelerator-profiles.yaml"
            source = accelerators.read_text(encoding="utf-8")
            source = source.replace("  - name: gpu-development\n    enabled: false", "  - name: gpu-development\n    enabled: true", 1)
            source = source.replace("    regionBinding: null\n    quotaBinding: null", "    regionBinding: us-central1\n    quotaBinding: gpu_dev_quota", 1)
            accelerators.write_text(source, encoding="utf-8")

            for contract in sorted((candidate / "opentofu/live/development").glob("*/environment.auto.tfvars.json")):
                document = json.loads(contract.read_text(encoding="utf-8"))
                document["enabled"] = True
                stack = contract.parts[-2]
                if stack in {"network", "data-services", "clusters", "ci-execution"}:
                    document["config"]["region"] = "us-central1"
                elif stack in {"artifacts", "observability"}:
                    document["config"]["location"] = "us-central1"
                contract.write_text(json.dumps(document), encoding="utf-8")

            mismatch = candidate / "opentofu/live/development/network/environment.auto.tfvars.json"
            document = json.loads(mismatch.read_text(encoding="utf-8"))
            document["config"]["region"] = "us-east1"
            mismatch.write_text(json.dumps(document), encoding="utf-8")

            result = run_infractl("catalog", "validate", "--root", str(candidate))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("config.region must equal catalog primaryLocation us-central1", result.stderr)

    def test_every_state_root_is_present_and_disabled(self):
        files = sorted((ROOT / "opentofu/live").glob("*/*/environment.auto.tfvars.json"))
        self.assertEqual(len(files), len(ENVIRONMENTS) * len(STACKS))
        seen = set()
        for path in files:
            document = json.loads(path.read_text(encoding="utf-8"))
            environment, stack = path.parts[-3], path.parts[-2]
            seen.add((environment, stack))
            self.assertEqual(document["environment"], environment)
            self.assertIs(document["enabled"], False)
        self.assertEqual(seen, {(environment, stack) for environment in ENVIRONMENTS for stack in STACKS})

    def test_export_contract_requires_nonempty_immutable_resources(self):
        schema = json.loads((ROOT / "schemas/v1/infrastructure_export.schema.json").read_text(encoding="utf-8"))
        resources = schema["properties"]["spec"]["properties"]["resources"]
        self.assertEqual(resources.get("minItems"), 1)
        self.assertIs(resources.get("uniqueItems"), True)
        self.assertFalse(schema["additionalProperties"])
        metadata = schema["properties"]["metadata"]
        for field in (
            "planDigest", "providerLockDigest", "backendStateDigest",
            "backendLineage", "backendSerial", "sourceCommit",
        ):
            self.assertIn(field, metadata["required"])
        signature = schema["properties"]["spec"]["properties"]["evidence"]["properties"]["signature"]
        self.assertEqual(signature["properties"]["algorithm"]["const"], "Ed25519")
        self.assertEqual(
            set(signature["required"]),
            {"algorithm", "keyId", "publicKey", "value", "payloadDigest"},
        )

    def test_service_capabilities_exactly_cover_export_resource_kinds(self):
        capability_source = (ROOT / "catalog/service-capabilities.yaml").read_text(encoding="utf-8")
        capability_kinds = set()
        for values in re.findall(r"exportKinds: \[([^]]+)\]", capability_source):
            capability_kinds.update(value.strip() for value in values.split(","))
        schema = json.loads((ROOT / "schemas/v1/infrastructure_export.schema.json").read_text(encoding="utf-8"))
        schema_kinds = set(schema["properties"]["spec"]["properties"]["resources"]["items"]["properties"]["kind"]["enum"])
        self.assertEqual(capability_kinds, schema_kinds)

    def test_export_emission_is_complete_and_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = signed_export(directory, [
                {"kind": "project", "name": "logical-project", "uri": "//cloudresourcemanager.googleapis.com/projects/logical-project"},
            ])
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = output.read_text(encoding="utf-8")
            self.assertEqual(raw, json.dumps(json.loads(raw), separators=(",", ":")) + "\n")
            document = json.loads(raw)
            self.assertEqual(document["metadata"]["root"], "opentofu/live/development/foundation")
            self.assertEqual(document["metadata"]["backendSerial"], 17)
            self.assertEqual(document["spec"]["resources"][0]["name"], "logical-project")
            self.assertEqual(document["spec"]["evidence"]["signature"]["algorithm"], "Ed25519")

    def test_export_emission_binds_resource_kinds_to_their_producing_stack(self):
        with tempfile.TemporaryDirectory() as directory:
            def emit(stack, kind):
                result, output = signed_export(directory, [{
                    "kind": kind,
                    "name": "logical-database",
                    "uri": "//sqladmin.googleapis.com/projects/logical-project/instances/logical-database",
                }], stack=stack)
                return result, output

            rejected, output = emit("foundation", "database-instance")
            self.assertNotEqual(rejected.returncode, 0)
            self.assertEqual(
                json.loads(rejected.stderr)["error"],
                'resource kind "database-instance" is not allowed for stack "foundation"',
            )
            self.assertFalse(output.exists())

            accepted, output = emit("data-services", "database-instance")
            self.assertEqual(accepted.returncode, 0, accepted.stderr)
            self.assertTrue(output.exists())

    def test_export_emission_rejects_credential_bearing_or_mutable_uris(self):
        with tempfile.TemporaryDirectory() as directory:
            def emit(resource_uri, provenance_uri):
                return signed_export(directory, [
                    {"kind": "project", "name": "logical-project", "uri": resource_uri},
                ], provenance_uri=provenance_uri)

            safe_resource = "//cloudresourcemanager.googleapis.com/projects/logical-project"
            safe_provenance = "https://evidence.example/provenance/development-foundation"
            invalid_resources = [
                "//identity@cloudresourcemanager.googleapis.com/projects/logical-project",
                "//cloudresourcemanager.googleapis.com/projects/logical-project?version=1",
                "//cloudresourcemanager.googleapis.com/projects/logical-project#record",
                "//cloudresourcemanager.googleapis.com",
                "//cloudresourcemanager.googleapis.com/",
                "https://cloudresourcemanager.googleapis.com",
                "//cloudresourcemanager.googleapis.com/projects/" + "a" * 2049,
            ]
            invalid_provenance = [
                "https://identity@evidence.example/signatures/development-foundation",
                "https://evidence.example/signatures/development-foundation?version=1",
                "https://evidence.example/signatures/development-foundation#record",
                "https://evidence.example",
                "https://evidence.example/",
                "//evidence.example/signatures/development-foundation",
                "https://evidence.example/signatures/" + "a" * 2049,
            ]
            for uri in invalid_resources:
                with self.subTest(resource_uri=uri):
                    result, output = emit(uri, safe_provenance)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
            for uri in invalid_provenance:
                with self.subTest(evidence_uri=uri):
                    result, output = emit(safe_resource, uri)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())

    def test_export_rejects_tampering_and_invented_signature_references(self):
        resource = {
            "kind": "project",
            "name": "logical-project",
            "uri": "//cloudresourcemanager.googleapis.com/projects/logical-project",
        }
        with tempfile.TemporaryDirectory() as directory:
            def tamper_resources(resources_path, _signature_path):
                document = json.loads(resources_path.read_text(encoding="utf-8"))
                document[0]["name"] = "tampered-project"
                resources_path.write_text(json.dumps(document), encoding="utf-8")

            result, output = signed_export(
                directory, [resource], tamper_payload=tamper_resources,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("payloadDigest does not match the canonical export payload", result.stderr)
            self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as directory:
            def invent_reference(_resources_path, signature_path):
                signature_path.write_text(json.dumps({
                    "uri": "https://evidence.example/signatures/invented",
                    "digest": "sha256:" + "1" * 64,
                }), encoding="utf-8")

            result, output = signed_export(
                directory, [resource], tamper_payload=invent_reference,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("independently supplied trusted key ID", result.stderr)
            self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as directory:
            result, output = signed_export(
                directory, [resource], trusted_key_id="sha256:" + "9" * 64,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("independently supplied trusted key ID", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
