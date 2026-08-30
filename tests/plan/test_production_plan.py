import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def classify(document):
    with tempfile.TemporaryDirectory() as directory:
        plan = Path(directory) / "plan.json"
        plan.write_text(json.dumps(document), encoding="utf-8")
        runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
        binaries = sorted(path for path in runfiles.rglob("infractl") if path.is_file() and os.access(path, os.X_OK))
        if binaries:
            command = [str(binaries[0]), "plan", "classify", "--input", str(plan)]
        else:
            binary = Path(directory) / "infractl"
            build = subprocess.run(["go", "build", "-o", str(binary), "./cmd/infractl"], cwd=ROOT / "tooling", text=True, capture_output=True, check=False)
            if build.returncode != 0:
                return build
            command = [str(binary), "plan", "classify", "--input", str(plan)]
        return subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)


class ProductionPlanTest(unittest.TestCase):
    def test_delete_and_replace_return_destructive_status(self):
        document = {
            "format_version": "1.2",
            "resource_changes": [
                {"address": "google_sql_database_instance.production", "change": {"actions": ["delete"]}},
                {"address": "google_container_cluster.production", "change": {"actions": ["delete", "create"]}},
            ],
        }
        result = classify(document)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["safe"])
        self.assertEqual((report["deletes"], report["replaces"]), (1, 1))

    def test_digest_ignores_only_timestamp_and_json_serialization(self):
        document = {
            "format_version": "1.2",
            "timestamp": "2026-08-29T12:00:00Z",
            "resource_changes": [
                {"address": "google_project.workload", "change": {"actions": ["create"]}},
            ],
            "planned_values": {
                "root_module": {"resources": [{"address": "google_project.workload", "values": {"name": "reviewed-project"}}]},
            },
        }
        first = classify(document)
        self.assertEqual(first.returncode, 0, first.stderr)
        first_digest = json.loads(first.stdout)["digest"]

        document["timestamp"] = "2026-08-29T12:05:00Z"
        second = classify(document)
        self.assertEqual(second.returncode, 0, second.stderr)
        self.assertEqual(json.loads(second.stdout)["digest"], first_digest)

        document["planned_values"]["root_module"]["resources"][0]["values"]["name"] = "changed-project"
        changed = classify(document)
        self.assertEqual(changed.returncode, 0, changed.stderr)
        self.assertNotEqual(json.loads(changed.stdout)["digest"], first_digest)


if __name__ == "__main__":
    unittest.main()
