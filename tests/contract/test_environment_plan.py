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


class EnvironmentPlanContractTest(unittest.TestCase):
    def test_checked_out_blueprint_tree_is_exact_and_nonempty(self):
        if not (ROOT / ".git").exists():
            self.skipTest("Bazel runfiles intentionally expose only declared test data")
        files = [
            path for path in ROOT.rglob("*")
            if path.is_file()
            and ".git" not in path.parts
            and not any(part.startswith("bazel-") for part in path.parts)
        ]
        self.assertEqual(len(files), 310)
        self.assertEqual([str(path.relative_to(ROOT)) for path in files if path.stat().st_size == 0], [])

    def test_catalogs_and_schemas_validate(self):
        result = run_infractl("catalog", "validate", "--root", str(ROOT))
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report, {"catalogs": 7, "schemas": 8})

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
            resources = Path(directory) / "resources.json"
            output = Path(directory) / "export.json"
            resources.write_text(json.dumps([
                {"kind": "project", "name": "logical-project", "uri": "//cloudresourcemanager.googleapis.com/projects/logical-project"},
            ]), encoding="utf-8")
            result = run_infractl(
                "exports", "emit",
                "--environment", "development",
                "--stack", "foundation",
                "--source-commit", "a" * 40,
                "--plan-digest", "sha256:" + "b" * 64,
                "--schema-digest", "sha256:" + "c" * 64,
                "--generated-at", "2026-08-29T12:00:00Z",
                "--resources", str(resources),
                "--signature-uri", "https://evidence.example/signatures/development-foundation",
                "--signature-digest", "sha256:" + "d" * 64,
                "--provenance-uri", "https://evidence.example/provenance/development-foundation",
                "--provenance-digest", "sha256:" + "e" * 64,
                "--output", str(output),
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            raw = output.read_text(encoding="utf-8")
            self.assertEqual(raw, json.dumps(json.loads(raw), separators=(",", ":")) + "\n")
            document = json.loads(raw)
            self.assertEqual(document["metadata"]["root"], "opentofu/live/development/foundation")
            self.assertEqual(document["spec"]["resources"][0]["name"], "logical-project")

    def test_export_emission_rejects_credential_bearing_or_mutable_uris(self):
        with tempfile.TemporaryDirectory() as directory:
            resources = Path(directory) / "resources.json"
            output = Path(directory) / "export.json"

            def emit(resource_uri, signature_uri):
                resources.write_text(json.dumps([
                    {"kind": "project", "name": "logical-project", "uri": resource_uri},
                ]), encoding="utf-8")
                output.unlink(missing_ok=True)
                return run_infractl(
                    "exports", "emit",
                    "--environment", "development",
                    "--stack", "foundation",
                    "--source-commit", "a" * 40,
                    "--plan-digest", "sha256:" + "b" * 64,
                    "--schema-digest", "sha256:" + "c" * 64,
                    "--generated-at", "2026-08-29T12:00:00Z",
                    "--resources", str(resources),
                    "--signature-uri", signature_uri,
                    "--signature-digest", "sha256:" + "d" * 64,
                    "--provenance-uri", "https://evidence.example/provenance/development-foundation",
                    "--provenance-digest", "sha256:" + "e" * 64,
                    "--output", str(output),
                )

            safe_resource = "//cloudresourcemanager.googleapis.com/projects/logical-project"
            safe_signature = "https://evidence.example/signatures/development-foundation"
            invalid_resources = [
                "//identity@cloudresourcemanager.googleapis.com/projects/logical-project",
                "//cloudresourcemanager.googleapis.com/projects/logical-project?version=1",
                "//cloudresourcemanager.googleapis.com/projects/logical-project#record",
                "//cloudresourcemanager.googleapis.com",
                "//cloudresourcemanager.googleapis.com/",
                "https://cloudresourcemanager.googleapis.com",
                "//cloudresourcemanager.googleapis.com/projects/" + "a" * 2049,
            ]
            invalid_evidence = [
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
                    result = emit(uri, safe_signature)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())
            for uri in invalid_evidence:
                with self.subTest(evidence_uri=uri):
                    result = emit(safe_resource, uri)
                    self.assertNotEqual(result.returncode, 0)
                    self.assertFalse(output.exists())


if __name__ == "__main__":
    unittest.main()
