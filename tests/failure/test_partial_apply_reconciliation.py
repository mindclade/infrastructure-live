import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def reconciliation_document(serial=17):
    return {
        "apiVersion": "infrastructure.mindclade.dev/partial-apply-reconciliation/v1",
        "kind": "PartialApplyReconciliation",
        "root": "opentofu/live/production/data-services",
        "sourceCommit": "a" * 40,
        "planDigest": "sha256:" + "b" * 64,
        "operationId": "change/MC-1042",
        "backend": {
            "lineage": "123e4567-e89b-42d3-a456-426614174000",
            "serial": serial,
        },
        "resources": [
            {
                "address": "module.database.google_sql_database_instance.this[0]",
                "providerId": "projects/prod/instances/database",
                "stateDigest": "sha256:" + "c" * 64,
            },
            {
                "address": "module.network.google_compute_network.this[0]",
                "providerId": "projects/prod/global/networks/primary",
                "stateDigest": "sha256:" + "d" * 64,
            },
        ],
    }


def run_reconciliation(desired, observed):
    with tempfile.TemporaryDirectory() as directory:
        expected = Path(directory) / "desired.json"
        actual = Path(directory) / "observed.json"
        expected.write_text(json.dumps(desired), encoding="utf-8")
        actual.write_text(json.dumps(observed), encoding="utf-8")
        runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
        binaries = sorted(
            path for path in runfiles.rglob("infractl")
            if path.is_file() and os.access(path, os.X_OK)
        )
        if binaries:
            command = [
                str(binaries[0]), "reconciliation", "verify",
                "--desired", str(expected), "--observed", str(actual),
            ]
        else:
            binary = Path(directory) / "infractl"
            build = subprocess.run(
                ["go", "build", "-o", str(binary), "./cmd/infractl"],
                cwd=ROOT / "tooling", text=True, capture_output=True, check=False,
            )
            if build.returncode != 0:
                return build
            command = [
                str(binary), "reconciliation", "verify",
                "--desired", str(expected), "--observed", str(actual),
            ]
        return subprocess.run(
            command, cwd=ROOT, text=True, capture_output=True, check=False,
        )


class PartialApplyReconciliationTest(unittest.TestCase):
    def test_failure_runbook_requires_the_structured_fail_closed_verifier(self):
        runbook = (ROOT / "runbooks/infrastructure-apply-failure.md").read_text(
            encoding="utf-8"
        )
        for requirement in (
            "infractl reconciliation verify",
            "backend lineage",
            "backend serial",
            "provider IDs",
            "resumeAllowed=false",
            "refresh/import/compare",
            "create a new plan",
        ):
            self.assertIn(requirement, runbook)

    def test_missing_changed_and_unmanaged_provider_resources_require_import_compare_and_replan(self):
        desired = reconciliation_document()
        observed = reconciliation_document(serial=18)
        observed["resources"] = [
            {
                **desired["resources"][0],
                "stateDigest": "sha256:" + "e" * 64,
            },
            {
                "address": "module.unreviewed.google_storage_bucket.this[0]",
                "providerId": "projects/prod/buckets/unreviewed",
                "stateDigest": "sha256:" + "f" * 64,
            },
        ]

        result = run_reconciliation(desired, observed)

        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(
            {finding["kind"] for finding in report["findings"]},
            {"changed", "missing", "unmanaged"},
        )
        self.assertFalse(report["clean"])
        self.assertFalse(report["resumeAllowed"])
        self.assertEqual(
            report["nextAction"], "refresh-import-compare-then-replan"
        )
        self.assertEqual(report["priorBackendSerial"], 17)
        self.assertEqual(report["observedBackendSerial"], 18)
        self.assertNotIn("projects/prod", result.stdout)
        self.assertNotIn("sha256:" + "e" * 64, result.stdout)

    def test_clean_refresh_still_requires_a_new_plan_instead_of_saved_plan_replay(self):
        desired = reconciliation_document()
        observed = reconciliation_document(serial=17)

        result = run_reconciliation(desired, observed)

        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["clean"])
        self.assertFalse(report["resumeAllowed"])
        self.assertEqual(report["nextAction"], "replan-from-refreshed-state")

    def test_provider_identity_change_is_not_hidden_by_an_equal_state_digest(self):
        desired = reconciliation_document()
        observed = reconciliation_document(serial=18)
        observed["resources"][0]["providerId"] = "projects/prod/instances/recreated"

        result = run_reconciliation(desired, observed)

        self.assertEqual(result.returncode, 2, result.stderr)
        report = json.loads(result.stdout)
        self.assertIn(
            {
                "path": "module.database.google_sql_database_instance.this[0]",
                "kind": "changed",
            },
            report["findings"],
        )

    def test_ambiguous_transaction_lineage_or_serial_fails_before_classification(self):
        desired = reconciliation_document()
        mutations = (
            lambda observed: observed.update({"operationId": "change/MC-9999"}),
            lambda observed: observed["backend"].update({"serial": 19}),
            lambda observed: observed["backend"].update(
                {"lineage": "123e4567-e89b-42d3-a456-426614174001"}
            ),
            lambda observed: observed["resources"].append(
                dict(observed["resources"][0])
            ),
        )
        for mutate in mutations:
            with self.subTest(mutate=mutate):
                observed = reconciliation_document(serial=18)
                mutate(observed)
                result = run_reconciliation(desired, observed)
                self.assertEqual(result.returncode, 1)
                self.assertEqual(result.stdout, "")
                self.assertTrue(json.loads(result.stderr)["error"])


if __name__ == "__main__":
    unittest.main()
