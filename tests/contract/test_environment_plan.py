# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportGeneralTypeIssues=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import base64
import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
ENVIRONMENTS = {"development", "staging", "production", "restricted"}
STACKS = {
    "foundation",
    "network",
    "artifacts",
    "data-services",
    "clusters",
    "ci-execution",
    "observability",
}


def run_infractl(*arguments):
    runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
    candidates = sorted(
        path for path in runfiles.rglob("infractl") if path.is_file() and os.access(path, os.X_OK)
    )
    if candidates:
        return subprocess.run(
            [str(candidates[0]), *arguments], cwd=ROOT, text=True, capture_output=True, check=False
        )
    with tempfile.TemporaryDirectory() as directory:
        binary = Path(directory) / "infractl"
        build = subprocess.run(
            ["go", "build", "-o", str(binary), "./cmd/infractl"],
            cwd=ROOT / "tooling",
            text=True,
            capture_output=True,
            check=False,
        )
        if build.returncode != 0:
            return build
        return subprocess.run(
            [str(binary), *arguments], cwd=ROOT, text=True, capture_output=True, check=False
        )


def workflow_source(name):
    return (ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8")


def workflow_step_source(workflow, name):
    marker = f"      - name: {name}\n"
    start = workflow.index(marker)
    end = workflow.find("\n      - name: ", start + len(marker))
    if end == -1:
        end = len(workflow)
    return workflow[start:end]


def test_p256_sign(message):
    # Deterministic, non-production P-256 arithmetic implemented with stdlib.
    # Runtime parsing and verification remain Go's crypto/x509 and crypto/ecdsa.
    field = int("ffffffff00000001000000000000000000000000ffffffffffffffffffffffff", 16)
    order = int("ffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551", 16)
    base = (
        int("6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296", 16),
        int("4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5", 16),
    )

    def add(left, right):
        if left is None:
            return right
        if right is None:
            return left
        x1, y1 = left
        x2, y2 = right
        if x1 == x2 and (y1 + y2) % field == 0:
            return None
        if left == right:
            slope = (3 * x1 * x1 - 3) * pow(2 * y1, field - 2, field) % field
        else:
            slope = (y2 - y1) * pow(x2 - x1, field - 2, field) % field
        x3 = (slope * slope - x1 - x2) % field
        return x3, (slope * (x1 - x3) - y1) % field

    def multiply(point, scalar):
        result = None
        addend = point
        while scalar:
            if scalar & 1:
                result = add(result, addend)
            addend = add(addend, addend)
            scalar >>= 1
        return result

    def integer(value):
        encoded = value.to_bytes((value.bit_length() + 7) // 8, "big")
        if encoded[0] & 0x80:
            encoded = b"\x00" + encoded
        return b"\x02" + bytes([len(encoded)]) + encoded

    scalar = (
        int.from_bytes(hashlib.sha256(b"mindclade-test-p256-key").digest(), "big") % (order - 1) + 1
    )
    public_x, public_y = multiply(base, scalar)
    uncompressed = b"\x04" + public_x.to_bytes(32, "big") + public_y.to_bytes(32, "big")
    public_key = (
        bytes.fromhex("3059301306072a8648ce3d020106082a8648ce3d030107034200") + uncompressed
    )
    digest = hashlib.sha256(message).digest()
    nonce = (
        int.from_bytes(hashlib.sha256(b"mindclade-test-p256-nonce" + digest).digest(), "big")
        % (order - 1)
        + 1
    )
    nonce_x, _ = multiply(base, nonce)
    r = nonce_x % order
    s = (pow(nonce, -1, order) * (int.from_bytes(digest, "big") + r * scalar)) % order
    encoded = integer(r) + integer(s)
    return public_key, b"\x30" + bytes([len(encoded)]) + encoded


def signed_export(
    directory,
    resources,
    stack="foundation",
    provenance_uri=None,
    tamper_payload=None,
    trusted_key_version=None,
    trusted_public_key_digest=None,
):
    directory = Path(directory)
    resources_path = directory / "resources.json"
    payload_path = directory / "export.payload.json"
    signature_path = directory / "export.signature.json"
    output_path = directory / "export.json"
    resources_path.write_text(json.dumps(resources), encoding="utf-8")
    provenance_uri = (
        provenance_uri
        or "https://github.com/mindclade/infrastructure-live/actions/runs/123456/attempts/1"
    )
    arguments = [
        "--environment",
        "development",
        "--stack",
        stack,
        "--source-commit",
        "a" * 40,
        "--plan-digest",
        "sha256:" + "b" * 64,
        "--provider-lock-digest",
        "sha256:" + "c" * 64,
        "--backend-state-digest",
        "sha256:" + "d" * 64,
        "--backend-lineage",
        "123e4567-e89b-42d3-a456-426614174000",
        "--backend-serial",
        "17",
        "--schema-digest",
        "sha256:" + "e" * 64,
        "--generated-at",
        "2026-08-29T12:00:00Z",
        "--resources",
        str(resources_path),
        "--provenance-uri",
        provenance_uri,
        "--provenance-digest",
        "sha256:" + "f" * 64,
    ]
    payload_result = run_infractl("exports", "payload", *arguments, "--output", str(payload_path))
    if payload_result.returncode != 0:
        return payload_result, output_path

    payload = payload_path.read_bytes()
    public_key, detached_signature = test_p256_sign(payload)
    key_version = "projects/mindclade-bootstrap/locations/us-central1/keyRings/bootstrap-signing/cryptoKeys/infrastructure-export/cryptoKeyVersions/7"
    envelope = {
        "algorithm": "EC_SIGN_P256_SHA256",
        "keyVersion": key_version,
        "publicKey": base64.b64encode(public_key).decode("ascii"),
        "publicKeyDigest": "sha256:" + hashlib.sha256(public_key).hexdigest(),
        "value": base64.b64encode(detached_signature).decode("ascii"),
        "payloadDigest": "sha256:" + hashlib.sha256(payload).hexdigest(),
    }
    signature_path.write_text(json.dumps(envelope), encoding="utf-8")
    if tamper_payload is not None:
        tamper_payload(resources_path, signature_path)
    result = run_infractl(
        "exports",
        "emit",
        *arguments,
        "--signature",
        str(signature_path),
        "--trusted-key-version",
        trusted_key_version or envelope["keyVersion"],
        "--trusted-public-key-digest",
        trusted_public_key_digest or envelope["publicKeyDigest"],
        "--output",
        str(output_path),
    )
    return result, output_path


class EnvironmentPlanContractTest(unittest.TestCase):
    def test_bazel_renovate_stages_nested_go_module(self):
        module = (ROOT / "MODULE.bazel").read_text(encoding="utf-8")
        for required in (
            'go_mod_from_file = "//tooling:go.mod"',
            'go_sum_from_file = "//tooling:go.sum"',
            "go_deps.from_file(go_mod = go_mod_from_file)",
        ):
            self.assertIn(required, module)

    def test_checked_out_blueprint_tree_is_exact_and_nonempty(self):
        if not (ROOT / ".git").exists():
            self.skipTest("Bazel runfiles intentionally expose only declared test data")
        environments = ("development", "staging", "production", "restricted")
        stacks = (
            "foundation",
            "network",
            "artifacts",
            "data-services",
            "clusters",
            "ci-execution",
            "observability",
        )
        tofu_files = ("main", "variables", "outputs")
        live_files = (
            "backend.tf",
            "versions.tf",
            "providers.tf",
            "main.tf",
            "environment.auto.tfvars.json",
            "outputs.tf",
        )
        modules = (
            "project-factory",
            "shared-vpc",
            "private-dns",
            "controlled-egress",
            "artifact-registry",
            "artifact-bucket",
            "cloud-sql-postgres",
            "pubsub-transport",
            "secret-bindings",
            "delegated-kms",
            "gke-regional-cluster",
            "gke-node-pool",
            "workload-identity",
            "observability-backend",
            "buildkite-agents",
            "argocd-management",
            "nix-cache",
            "bazel-cache",
        )
        policies = (
            "organization_constraints",
            "network_boundaries",
            "workload_identity",
            "encryption_and_retention",
            "database_recovery",
            "gke_security",
            "accelerator_isolation",
            "cost_guardrails",
        )
        expected = {
            ".bazelignore",
            ".bazelrc",
            ".bazelversion",
            ".editorconfig",
            ".gitignore",
            ".golangci.yml",
            ".markdownlint-cli2.yaml",
            ".pre-commit-config.yaml",
            ".vscode/extensions.json",
            ".vscode/settings.json",
            ".yamllint.yaml",
            "BUILD.bazel",
            "CONTRIBUTING.md",
            "LICENSE",
            "MODULE.bazel",
            "MODULE.bazel.lock",
            "README.md",
            "SECURITY.md",
            "component.yaml",
            "flake.lock",
            "flake.nix",
            "justfile",
            "biome.json",
            "pyproject.toml",
            "generated/bazelrc.common",
            "generated/nix-bazel-policy.lock.json",
            "generated/nix-bazel-policy.nix",
            "generated/toolchain-manifest.defaults.json",
            ".github/CODEOWNERS",
            ".github/actionlint.yaml",
            ".github/pull_request_template.md",
            ".github/renovate.json",
            *{
                f".github/workflows/{name}.yml"
                for name in (
                    "pull-request",
                    "drift-detection",
                    "protected-apply",
                    "disaster-recovery",
                )
            },
            *{
                f"catalog/{name}.yaml"
                for name in (
                    "environments",
                    "regions",
                    "project-classes",
                    "data-classes",
                    "resource-profiles",
                    "accelerator-profiles",
                    "service-capabilities",
                )
            },
            *{
                f"schemas/v1/{name}.schema.json"
                for name in (
                    "environment",
                    "region",
                    "project_class",
                    "data_class",
                    "resource_profile",
                    "accelerator_profile",
                    "service_capability",
                    "infrastructure_export",
                )
            },
            *{
                f"opentofu/modules/gcp/{module}/{name}.tf"
                for module in modules
                for name in tofu_files
            },
            *{f"opentofu/stacks/{stack}/{name}.tf" for stack in stacks for name in tofu_files},
            *{
                f"opentofu/live/{environment}/{stack}/{name}"
                for environment in environments
                for stack in stacks
                for name in live_files
            },
            *{f"policy/{name}.rego" for name in policies},
            *{f"policy/tests/{name}_test.rego" for name in policies},
            "tests/contract/test_environment_plan.py",
            "tests/contract/test_generated_policy.py",
            *{
                f"tests/plan/test_{name}_plan.py"
                for name in ("development", "staging", "production")
            },
            "tests/security/test_cross_environment_denial.py",
            "tests/failure/test_partial_apply_reconciliation.py",
            "tests/drift/test_cloud_drift_classification.py",
            "tests/recovery/test_database_restore.py",
            "tests/recovery/test_artifact_restore.py",
            "tests/capacity/test_accelerator_profile.py",
            "tooling/cmd/infractl/main.go",
            "tooling/go.mod",
            "tooling/go.sum",
            "tooling/BUILD.bazel",
            *{
                f"tooling/internal/{name}/{name}.go"
                for name in ("catalog", "plan", "policy", "drift", "exports")
            },
            *{
                f"runbooks/{name}.md"
                for name in (
                    "infrastructure-apply-failure",
                    "cloud-drift",
                    "network-isolation-failure",
                    "cluster-control-plane-failure",
                    "database-failover-and-restore",
                    "artifact-storage-recovery",
                    "nix-cache-recovery",
                    "bazel-cache-recovery",
                    "regional-recovery",
                )
            },
        }
        ignored_directories = {
            ".git",
            ".ruff_cache",
            "__pycache__",
            ".pytest_cache",
            ".terraform",
        }
        actual = set()
        empty = []
        source_symlinks = []
        for directory, children, files in os.walk(ROOT, followlinks=False):
            relative_directory = Path(directory).relative_to(ROOT)
            # Bazel creates bazel-bin, bazel-out, bazel-testlogs and
            # bazel-<workspace> as symlinks at the repository root only. Pruning
            # every directory named bazel-* at any depth would also hide real
            # source, such as opentofu/modules/gcp/bazel-cache, from this check.
            def is_root_bazel_symlink(name: str) -> bool:
                return (
                    relative_directory == Path()
                    and name.startswith("bazel-")
                    and (Path(directory) / name).is_symlink()
                )

            for child in children:
                child_path = Path(directory) / child
                if (
                    child_path.is_symlink()
                    and child not in ignored_directories
                    and not is_root_bazel_symlink(child)
                ):
                    source_symlinks.append((relative_directory / child).as_posix())
            children[:] = [
                child
                for child in children
                if child not in ignored_directories and not is_root_bazel_symlink(child)
            ]
            for name in files:
                path = Path(directory) / name
                relative = path.relative_to(ROOT).as_posix()
                if name == ".DS_Store" or name.endswith((".pyc", ".pyo")):
                    continue
                if relative == ".git":
                    continue
                if relative_directory == Path() and name.startswith("bazel-") and path.is_symlink():
                    continue
                if path.is_symlink():
                    source_symlinks.append(relative)
                if path.stat().st_size == 0:
                    empty.append(relative)
                actual.add(relative)
        self.assertEqual(
            source_symlinks, [], "Blueprint source paths must be regular, non-symlink files"
        )
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

    def test_ci_evidence_recovery_uses_the_canonical_repository_inventory(self):
        workflow = workflow_source("disaster-recovery.yml")
        activation = workflow_step_source(
            workflow, "Validate connected-verifier activation contract"
        )
        self.assertIn(
            r"(\.github|bootstrap|github-config|gitops|infrastructure-live|mindclade)",
            activation,
        )
        self.assertNotIn("mindclade-internal-monorepo", activation)

    def test_pull_request_workflow_is_the_single_canonical_source_gate(self):
        workflow = workflow_source("pull-request.yml")
        codeowners = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")

        self.assertTrue(workflow.startswith("name: Pull request\n"))
        self.assertIn('"on":\n  pull_request:\n  merge_group:', workflow)
        self.assertIn("permissions:\n  contents: read", workflow)
        self.assertIn("  required:\n    name: required", workflow)
        self.assertNotIn("id-token: write", workflow)
        self.assertNotIn("contents: write", workflow)
        self.assertIn(
            "mindclade/.github/.github/workflows/reusable-nix-validation.yml@fc5af9efc19b47078fe446feee750d7f4973195b",
            workflow,
        )
        self.assertIn("VALIDATE_RESULT: ${{ needs.validate.result }}", workflow)
        self.assertIn('test "${VALIDATE_RESULT}" = success', workflow)
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
        self.assertIn(
            "https://github.mindclade.io/oidc/infrastructure-live/${ENVIRONMENT}/plan", workflow
        )
        self.assertIn(
            "https://github.mindclade.io/oidc/infrastructure-live/${ENVIRONMENT}/apply", workflow
        )
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
        self.assertNotIn("matrix:", workflow)
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

    def test_protected_apply_qualifies_kms_before_mutation_and_emits_paired_completion(self):
        workflow = workflow_source("protected-apply.yml")
        readiness = workflow_step_source(
            workflow, "Prove the qualified HSM signer is usable before mutation"
        )
        completion = workflow_step_source(
            workflow, "Create and KMS-sign exact post-apply completion evidence"
        )
        upload = workflow_step_source(
            workflow, "Retain the signed export and bound apply receipt together"
        )

        self.assertIn(
            "google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
            workflow,
        )
        self.assertIn('version: "568.0.0"', workflow)
        for environment in ("DEVELOPMENT", "STAGING", "PRODUCTION", "RESTRICTED"):
            self.assertIn(f"INFRASTRUCTURE_EXPORT_KMS_KEY_VERSION_{environment}", workflow)
            self.assertIn(f"INFRASTRUCTURE_EXPORT_PUBLIC_KEY_PEM_B64_{environment}", workflow)
            self.assertIn(f"INFRASTRUCTURE_EXPORT_PUBLIC_KEY_DIGEST_{environment}", workflow)
        self.assertNotIn("INFRASTRUCTURE_EXPORT_KMS_PUBLIC_KEY_PEM_BASE64", workflow)
        self.assertLess(
            workflow.index("Prove the qualified HSM signer is usable before mutation"),
            workflow.index("Apply only the verified saved plan"),
        )
        for required in (
            "EC_SIGN_P256_SHA256",
            '(.protectionLevel == "HSM")',
            '(.state == "ENABLED")',
            "gcloud kms asymmetric-sign",
            "exports kms-readiness",
            "--trusted-public-key-base64",
        ):
            self.assertIn(required, readiness)
        self.assertIn('tofu -chdir="${root}" output -json |', completion)
        self.assertNotIn("output -json resources", completion)
        self.assertIn("exports resources", completion)
        self.assertIn('receipt_digest="sha256:', completion)
        self.assertIn('--provenance-digest "${receipt_digest}"', completion)
        self.assertIn("exports emit", completion)
        self.assertIn("--trusted-key-version", completion)
        self.assertIn("apply-receipt.json infrastructure-export.json", completion)
        self.assertIn("${{ runner.temp }}/infrastructure-completion/", upload)
        self.assertIn("compression-level: 0", upload)

    def test_drift_allocates_no_jobs_until_the_estate_is_connected(self):
        """Drift costs four job allocations connected, and zero otherwise.

        A separate preflight job used to gate the matrix, which meant every
        unconnected scheduled run still allocated a runner. The gate now sits on
        the matrix job, and each environment job re-makes the preflight
        assertions itself before any cloud identity is used.
        """
        workflow = workflow_source("drift-detection.yml")
        jobs = re.findall(r"(?m)^  ([a-z_-]+):$", workflow.split("\njobs:\n", 1)[1])
        self.assertEqual(["classify"], jobs, "drift must define exactly one matrix job")

        guard = 'github.ref == \'refs/heads/main\'\n      && vars.INFRASTRUCTURE_CONNECTED_READY == \'true\''
        self.assertIn(guard, workflow, "the matrix job itself must be gated")

        # The assertions the retired preflight job made must still be made.
        step = workflow_step_source(workflow, "Require qualified read-only bindings")
        self.assertIn('test "${GITHUB_REF}" = "refs/heads/main"', step)
        self.assertIn('test "${CONNECTED_READY}" = "true"', step)

        # And they must run before the job touches a cloud identity.
        self.assertLess(
            workflow.index("Require qualified read-only bindings"),
            workflow.index("Authenticate the read-only plan identity"),
        )

        self.assertEqual(
            ["development", "staging", "production", "restricted"],
            re.search(r"environment: \[([^\]]+)\]", workflow).group(1).replace(" ", "").split(","),
        )

    def test_drift_evidence_records_policy_outcome_without_policy_contents(self):
        workflow = workflow_source("drift-detection.yml")
        step = workflow_step_source(workflow, "Create a read-only drift plan and redacted evidence")
        authentication = workflow_step_source(workflow, "Authenticate the read-only plan identity")

        self.assertIn("    environment: trusted-build", workflow)
        self.assertNotIn("environment: infrastructure-${{ matrix.environment }}-plan", workflow)
        self.assertIn("github.com/open-policy-agent/conftest@v0.69.0", workflow)
        self.assertIn("          audience: sts.googleapis.com", authentication)
        self.assertNotIn("audience: ${{", authentication)
        self.assertIn('-out="${saved_plan}" >>"${plan_log}" 2>&1', step)
        self.assertIn('[[ "${plan_status}" -ne 0 && "${plan_status}" -ne 2 ]]', step)
        self.assertIn('conftest test "${plan_json}"', step)
        self.assertIn('[[ "${policy_status}" -ne 0 && "${policy_status}" -ne 1 ]]', step)
        self.assertIn('--arg policyDigest "${policy_digest}"', step)
        self.assertIn('--argjson policyPassed "${policy_passed}"', step)
        self.assertIn("policyPassed: $policyPassed", step)
        self.assertIn("policyDigest: $policyDigest", step)
        self.assertNotIn("--slurpfile policy", step)
        self.assertIn('rm -rf "${work_dir}"', step)
        self.assertIn("infrastructure.mindclade.dev/drift-manifest/v1", step)
        self.assertIn("printf 'failure_count=%s\\n'", step)
        self.assertNotIn('cat "${plan_log}"', step)
        self.assertNotIn('tee "${plan_log}"', step)

        upload = workflow.index("- name: Retain redacted drift evidence only")
        aggregate_failure = workflow.index("- name: Enforce aggregate drift result")
        self.assertLess(upload, aggregate_failure)
        self.assertIn('test "${FAILURE_COUNT}" = 0', workflow)

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
                "name": "development",
                "highAvailabilityRequired": False,
                "deletionProtectionRequired": True,
                "backupRetentionDays": 7,
                "minimumZones": 1,
                "costGuardrail": "low",
            },
            {
                "name": "staging",
                "highAvailabilityRequired": True,
                "deletionProtectionRequired": True,
                "backupRetentionDays": 14,
                "minimumZones": 2,
                "costGuardrail": "moderate",
            },
            {
                "name": "production",
                "highAvailabilityRequired": True,
                "deletionProtectionRequired": True,
                "backupRetentionDays": 35,
                "minimumZones": 3,
                "costGuardrail": "reliability-first",
                "ciEvidenceArchive": archive,
            },
            {
                "name": "restricted",
                "highAvailabilityRequired": True,
                "deletionProtectionRequired": True,
                "backupRetentionDays": 35,
                "minimumZones": 3,
                "costGuardrail": "security-first",
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
                "canaryObjectUri": "gs://bucket/qualification/canary/"
                + "a" * 40
                + "/evidence.json#42",
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
            (
                "catalog/environments.yaml",
                "regionProfile: central-us",
                "regionProfile: missing-region",
                "unknown region",
            ),
            (
                "catalog/project-classes.yaml",
                "allowedEnvironmentTiers: [development]",
                "allowedEnvironmentTiers: [staging]",
                "disallowed tier",
            ),
            (
                "catalog/environments.yaml",
                "enabled: false",
                "enabled: true",
                "incoherent activation",
            ),
            (
                "catalog/resource-profiles.yaml",
                "name: staging",
                "name: development",
                "duplicate name",
            ),
            (
                "catalog/service-capabilities.yaml",
                "dns.googleapis.com",
                "iamcredentials.googleapis.com",
                "unapproved required API",
            ),
            (
                "catalog/service-capabilities.yaml",
                "log-bucket, metrics-scope",
                "log-bucket, project",
                "mismatched export kind",
            ),
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
            contract = (
                candidate / "opentofu/live/development/foundation/environment.auto.tfvars.json"
            )
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
            contract = (
                candidate / "opentofu/live/restricted/data-services/environment.auto.tfvars.json"
            )
            document = json.loads(contract.read_text(encoding="utf-8"))
            document["approved_iam_principals"] = [
                "serviceAccount:worker@restricted-project.iam.gserviceaccount.com",
            ]
            contract.write_text(json.dumps(document), encoding="utf-8")

            result = run_infractl("catalog", "validate", "--root", str(candidate))
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "approved_iam_principals must equal the environment-wide set", result.stderr
            )

    def test_enabled_live_locations_must_equal_catalog_primary_location(self):
        with tempfile.TemporaryDirectory() as directory:
            candidate = Path(directory)
            shutil.copytree(ROOT / "catalog", candidate / "catalog")
            shutil.copytree(ROOT / "schemas", candidate / "schemas")
            shutil.copytree(ROOT / "opentofu", candidate / "opentofu")

            environments = candidate / "catalog/environments.yaml"
            source = environments.read_text(encoding="utf-8")
            source = source.replace(
                "  - name: development\n    enabled: false",
                "  - name: development\n    enabled: true",
                1,
            )
            source = source.replace(
                "    activationEnabled: false", "    activationEnabled: true", 1
            )
            environments.write_text(source, encoding="utf-8")

            regions = candidate / "catalog/regions.yaml"
            source = regions.read_text(encoding="utf-8")
            source = source.replace(
                "  - name: central-us\n    enabled: false\n    sourceReady: true",
                "  - name: central-us\n    enabled: true\n    sourceReady: true",
                1,
            )
            regions.write_text(source, encoding="utf-8")

            accelerators = candidate / "catalog/accelerator-profiles.yaml"
            source = accelerators.read_text(encoding="utf-8")
            source = source.replace(
                "  - name: gpu-development\n    enabled: false",
                "  - name: gpu-development\n    enabled: true",
                1,
            )
            source = source.replace(
                "    regionBinding: null\n    quotaBinding: null",
                "    regionBinding: us-central1\n    quotaBinding: gpu_dev_quota",
                1,
            )
            accelerators.write_text(source, encoding="utf-8")

            for contract in sorted(
                (candidate / "opentofu/live/development").glob("*/environment.auto.tfvars.json")
            ):
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
            self.assertIn(
                "config.region must equal catalog primaryLocation us-central1", result.stderr
            )

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
        self.assertEqual(
            seen, {(environment, stack) for environment in ENVIRONMENTS for stack in STACKS}
        )

    def test_development_platform_is_source_ready_in_authority_order_only(self):
        catalog = run_infractl("catalog", "validate", "--root", str(ROOT))
        self.assertEqual(catalog.returncode, 0, catalog.stderr + catalog.stdout)
        environments = (ROOT / "catalog/environments.yaml").read_text(encoding="utf-8")
        regions = (ROOT / "catalog/regions.yaml").read_text(encoding="utf-8")
        for contract in (
            "sourceReady: true",
            "activationEnabled: false",
            "authorityOrder: [foundation, network, artifacts, clusters, observability, ci-execution]",
            "sourceReadyCapabilities: [foundation, network, artifact-registry, gcs, cloud-kms, regional-private-gke, observability, ci, argocd-inputs, nix-cache, estate-ci-edge]",
            "dataServicesEnabled: false",
        ):
            self.assertIn(contract, environments)
        self.assertIn("primaryLocation: us-central1", regions)
        self.assertEqual(environments.count("sourceReady: true"), 1)
        self.assertEqual(regions.count("sourceReady: true"), 1)

    def test_estate_ci_and_argocd_protected_inputs_are_disconnected(self):
        network = json.loads(
            (ROOT / "opentofu/live/development/network/environment.auto.tfvars.json").read_text(
                encoding="utf-8"
            )
        )
        edge = network["estate_ci_edge"]
        self.assertIs(edge["connected"], False)
        self.assertEqual(edge["hostname"], "estate-ci.mindclade.com")
        self.assertEqual(edge["gateway_class"], "gke-l7-global-external-managed")
        self.assertIsNone(edge["certificate_map_id"])
        self.assertEqual(edge["certificate_ids"], [])
        self.assertIsNone(edge["cloud_armor_policy_id"])
        self.assertIsNone(edge["iap_oauth_client_secret_resource"])
        self.assertEqual(edge["delegated_dns_records"], [])

        clusters = json.loads(
            (ROOT / "opentofu/live/development/clusters/environment.auto.tfvars.json").read_text(
                encoding="utf-8"
            )
        )
        argocd = clusters["argocd_inputs"]
        self.assertIs(argocd["connected"], False)
        self.assertIsNone(argocd["membership_id"])
        self.assertEqual(argocd["secret_references"], [])
        self.assertIsNone(argocd["qualification_digest"])

    def test_flake_exports_aarch64_linux_generated_policy_copy(self):
        flake = (ROOT / "flake.nix").read_text(encoding="utf-8")
        for binding in (
            '"aarch64-linux"',
            'mode = "generated-copy";',
            'canonical_repository = "mindclade/infrastructure-live";',
            'source_path = "policy/encryption_and_retention.rego";',
            "cache-boundary.v2.rego",
        ):
            self.assertIn(binding, flake)

    def test_export_contract_requires_nonempty_immutable_resources(self):
        schema = json.loads(
            (ROOT / "schemas/v1/infrastructure_export.schema.json").read_text(encoding="utf-8")
        )
        resources = schema["properties"]["spec"]["properties"]["resources"]
        self.assertEqual(resources.get("minItems"), 1)
        self.assertIs(resources.get("uniqueItems"), True)
        self.assertFalse(schema["additionalProperties"])
        metadata = schema["properties"]["metadata"]
        for field in (
            "planDigest",
            "providerLockDigest",
            "backendStateDigest",
            "backendLineage",
            "backendSerial",
            "sourceCommit",
        ):
            self.assertIn(field, metadata["required"])
        signature = schema["properties"]["spec"]["properties"]["evidence"]["properties"][
            "signature"
        ]
        self.assertEqual(signature["properties"]["algorithm"]["const"], "EC_SIGN_P256_SHA256")
        self.assertEqual(
            set(signature["required"]),
            {"algorithm", "keyVersion", "publicKey", "publicKeyDigest", "value", "payloadDigest"},
        )

    def test_service_capabilities_exactly_cover_export_resource_kinds(self):
        capability_source = (ROOT / "catalog/service-capabilities.yaml").read_text(encoding="utf-8")
        capability_kinds = set()
        for values in re.findall(r"exportKinds: \[([^]]+)\]", capability_source):
            capability_kinds.update(value.strip() for value in values.split(","))
        schema = json.loads(
            (ROOT / "schemas/v1/infrastructure_export.schema.json").read_text(encoding="utf-8")
        )
        schema_kinds = set(
            schema["properties"]["spec"]["properties"]["resources"]["items"]["properties"]["kind"][
                "enum"
            ]
        )
        self.assertEqual(capability_kinds, schema_kinds)

    def test_actual_tofu_outputs_are_strictly_reduced_to_typed_capabilities(self):
        fixtures = {
            "foundation": (
                {"project_id": "mindclade-dev", "project_number": "123456", "enabled_services": []},
                {"project"},
            ),
            "network": (
                {
                    "network_id": "projects/mindclade-dev/global/networks/platform",
                    "service_project_ids": [],
                    "subnetwork_ids": {
                        "platform-subnet": "projects/mindclade-dev/regions/us-central1/subnetworks/platform-subnet"
                    },
                    "private_service_connection": "servicenetworking-googleapis-com",
                    "private_dns_zone_ids": {},
                    "egress_addresses": {},
                },
                {"network", "subnetwork"},
            ),
            "artifacts": (
                {
                    "repository_ids": {
                        "platform-images": "projects/mindclade-dev/locations/us-central1/repositories/platform-images"
                    },
                    "bucket_ids": {},
                    "kms_key_ids": {
                        "artifacts": "projects/mindclade-dev/locations/us-central1/keyRings/platform/cryptoKeys/artifacts"
                    },
                    "ci_evidence_archive": {},
                },
                {"artifact-registry", "kms-key-reference"},
            ),
            "data-services": (
                {
                    "database_instance_id": "mindclade-dev/postgres-primary",
                    "database_connection_name": "mindclade-dev:us-central1:postgres-primary",
                    "topic_ids": {},
                    "subscription_ids": {},
                    "secret_references": {},
                    "kms_key_ids": {},
                },
                {"database-instance"},
            ),
            "clusters": (
                {
                    "cluster_id": "projects/mindclade-dev/locations/us-central1/clusters/platform",
                    "cluster_name": "platform",
                    "workload_identity_pool": "mindclade-dev.svc.id.goog",
                    "node_pool_ids": {},
                    "workload_service_accounts": {},
                    "argocd_prerequisite_identity": None,
                    "cluster_membership_ids": {},
                },
                {"gke-cluster", "workload-identity-pool"},
            ),
            "ci-execution": (
                {
                    "service_account_email": "ci@mindclade-dev.iam.gserviceaccount.com",
                    "instance_group_id": "projects/mindclade-dev/regions/us-central1/instanceGroupManagers/buildkite-agents",
                },
                {"build-execution-pool"},
            ),
            "observability": (
                {
                    "log_bucket_id": "projects/mindclade-dev/locations/global/buckets/platform",
                    "metrics_scope": "mindclade-dev",
                    "sink_writer_identities": {},
                    "kms_key_ids": {},
                },
                {"log-bucket", "metrics-scope"},
            ),
        }
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for stack, (value, expected_kinds) in fixtures.items():
                with self.subTest(stack=stack):
                    input_path = directory / f"{stack}.input.json"
                    output_path = directory / f"{stack}.resources.json"
                    input_path.write_text(
                        json.dumps(
                            {
                                "resources": {
                                    "sensitive": False,
                                    "type": ["object", {}],
                                    "value": value,
                                },
                            }
                        ),
                        encoding="utf-8",
                    )
                    result = run_infractl(
                        "exports",
                        "resources",
                        "--stack",
                        stack,
                        "--input",
                        str(input_path),
                        "--output",
                        str(output_path),
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    resources = json.loads(output_path.read_text(encoding="utf-8"))
                    self.assertEqual({resource["kind"] for resource in resources}, expected_kinds)
                    self.assertNotIn("secret", output_path.read_text(encoding="utf-8").lower())

    def test_actual_tofu_output_reduction_fails_closed_on_null_unknown_or_unsafe_values(self):
        invalid = [
            {
                "resources": {
                    "sensitive": True,
                    "type": ["object", {}],
                    "value": {
                        "project_id": "mindclade-dev",
                        "project_number": "1",
                        "enabled_services": [],
                    },
                }
            },
            {"resources": {"sensitive": False, "type": ["object", {}], "value": None}},
            {
                "resources": {
                    "sensitive": False,
                    "type": ["object", {}],
                    "value": {"project_id": None, "project_number": "1", "enabled_services": []},
                }
            },
            {
                "resources": {
                    "sensitive": False,
                    "type": ["object", {}],
                    "value": {
                        "project_id": "mindclade-dev",
                        "project_number": "1",
                        "enabled_services": [],
                        "token": "invented",
                    },
                }
            },
            {
                "resources": {
                    "sensitive": False,
                    "type": ["object", {}],
                    "value": {
                        "project_id": "mindclade-dev?token=x",
                        "project_number": "1",
                        "enabled_services": [],
                    },
                }
            },
        ]
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            for index, value in enumerate(invalid):
                with self.subTest(index=index):
                    input_path = directory / f"invalid-{index}.json"
                    output_path = directory / f"invalid-{index}.out.json"
                    input_path.write_text(json.dumps(value), encoding="utf-8")
                    result = run_infractl(
                        "exports",
                        "resources",
                        "--stack",
                        "foundation",
                        "--input",
                        str(input_path),
                        "--output",
                        str(output_path),
                    )
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output_path.exists())

    def test_kms_readiness_binds_qualified_and_observed_p256_keys_and_challenge(self):
        with tempfile.TemporaryDirectory() as directory:
            directory = Path(directory)
            message = b"mindclade infrastructure-export readiness challenge\n"
            public_der, signature = test_p256_sign(message)
            encoded = base64.b64encode(public_der).decode("ascii")
            public_pem = (
                "-----BEGIN PUBLIC KEY-----\n"
                + "\n".join(encoded[index : index + 64] for index in range(0, len(encoded), 64))
                + "\n-----END PUBLIC KEY-----\n"
            )
            observed = directory / "observed.pem"
            challenge = directory / "challenge"
            detached = directory / "challenge.sig"
            output_der = directory / "qualified.der"
            observed.write_text(public_pem, encoding="ascii")
            challenge.write_bytes(message)
            detached.write_bytes(signature)
            trusted_b64 = base64.b64encode(public_pem.encode("ascii")).decode("ascii")
            digest = "sha256:" + hashlib.sha256(public_der).hexdigest()
            arguments = [
                "exports",
                "kms-readiness",
                "--trusted-public-key-base64",
                trusted_b64,
                "--observed-public-key",
                str(observed),
                "--trusted-public-key-digest",
                digest,
                "--message",
                str(challenge),
                "--signature",
                str(detached),
                "--output-public-key-der",
                str(output_der),
            ]
            result = run_infractl(*arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(output_der.read_bytes(), public_der)
            output_der.unlink()
            arguments[arguments.index(digest)] = "sha256:" + "0" * 64
            rejected = run_infractl(*arguments)
            self.assertNotEqual(rejected.returncode, 0)
            self.assertFalse(output_der.exists())

    def test_export_emission_is_complete_and_canonical(self):
        with tempfile.TemporaryDirectory() as directory:
            result, output = signed_export(
                directory,
                [
                    {
                        "kind": "project",
                        "name": "logical-project",
                        "uri": "//cloudresourcemanager.googleapis.com/projects/logical-project",
                    },
                ],
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = output.read_text(encoding="utf-8")
            self.assertEqual(raw, json.dumps(json.loads(raw), separators=(",", ":")) + "\n")
            document = json.loads(raw)
            self.assertEqual(document["metadata"]["root"], "opentofu/live/development/foundation")
            self.assertEqual(document["metadata"]["backendSerial"], 17)
            self.assertEqual(document["spec"]["resources"][0]["name"], "logical-project")
            self.assertEqual(
                document["spec"]["evidence"]["signature"]["algorithm"], "EC_SIGN_P256_SHA256"
            )

    def test_export_emission_binds_resource_kinds_to_their_producing_stack(self):
        with tempfile.TemporaryDirectory() as directory:

            def emit(stack, kind):
                result, output = signed_export(
                    directory,
                    [
                        {
                            "kind": kind,
                            "name": "logical-database",
                            "uri": "//sqladmin.googleapis.com/projects/logical-project/instances/logical-database",
                        }
                    ],
                    stack=stack,
                )
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
                return signed_export(
                    directory,
                    [
                        {"kind": "project", "name": "logical-project", "uri": resource_uri},
                    ],
                    provenance_uri=provenance_uri,
                )

            safe_resource = "//cloudresourcemanager.googleapis.com/projects/logical-project"
            safe_provenance = (
                "https://github.com/mindclade/infrastructure-live/actions/runs/123456/attempts/1"
            )
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
                directory,
                [resource],
                tamper_payload=tamper_resources,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(
                "payloadDigest does not match the canonical export payload", result.stderr
            )
            self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as directory:

            def invent_reference(_resources_path, signature_path):
                signature_path.write_text(
                    json.dumps(
                        {
                            "uri": "https://evidence.example/signatures/invented",
                            "digest": "sha256:" + "1" * 64,
                        }
                    ),
                    encoding="utf-8",
                )

            result, output = signed_export(
                directory,
                [resource],
                tamper_payload=invent_reference,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("independently supplied trusted KMS key version", result.stderr)
            self.assertFalse(output.exists())

        with tempfile.TemporaryDirectory() as directory:
            result, output = signed_export(
                directory,
                [resource],
                trusted_public_key_digest="sha256:" + "9" * 64,
            )
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("independently supplied trusted public-key digest", result.stderr)
            self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
