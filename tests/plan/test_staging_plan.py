import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def run_plan(document):
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


class StagingPlanTest(unittest.TestCase):
    def test_unknown_plan_format_fails_closed(self):
        result = run_plan({"resource_changes": []})
        self.assertEqual(result.returncode, 1)
        error = json.loads(result.stderr)
        self.assertIn("format_version", error["error"])

    def test_unknown_action_sequence_fails_closed(self):
        result = run_plan({
            "format_version": "1.2",
            "resource_changes": [{"address": "google_project.staging", "change": {"actions": ["forget"]}}],
        })
        self.assertEqual(result.returncode, 1)
        self.assertIn("unsupported action sequence", result.stderr)


if __name__ == "__main__":
    unittest.main()
