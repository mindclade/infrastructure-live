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
        plan.write_text(json.dumps(document, separators=(",", ":")), encoding="utf-8")
        runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
        binaries = sorted(path for path in runfiles.rglob("infractl") if path.is_file() and os.access(path, os.X_OK))
        if binaries:
            command, cwd = [str(binaries[0]), "plan", "classify", "--input", str(plan)], ROOT
        else:
            binary = Path(directory) / "infractl"
            build = subprocess.run(["go", "build", "-o", str(binary), "./cmd/infractl"], cwd=ROOT / "tooling", text=True, capture_output=True, check=False)
            if build.returncode != 0:
                return build
            command, cwd = [str(binary), "plan", "classify", "--input", str(plan)], ROOT
        return subprocess.run(command, cwd=cwd, text=True, capture_output=True, check=False)


class DevelopmentPlanTest(unittest.TestCase):
    def test_create_and_update_are_redacted_and_safe(self):
        result = classify({
            "format_version": "1.2",
            "resource_changes": [
                {"address": "google_project.development", "change": {"actions": ["create"], "after": {"sensitive": "must-not-print"}}},
                {"address": "google_compute_network.development", "change": {"actions": ["update"], "after": {"name": "logical-network"}}},
            ],
        })
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertTrue(report["safe"])
        self.assertEqual((report["creates"], report["updates"]), (1, 1))
        self.assertNotIn("must-not-print", result.stdout)


if __name__ == "__main__":
    unittest.main()
