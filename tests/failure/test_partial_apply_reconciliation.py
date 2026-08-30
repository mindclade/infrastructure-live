import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


class PartialApplyReconciliationTest(unittest.TestCase):
    def test_missing_and_unmanaged_resources_are_both_detected(self):
        desired = {"resources": {"database": {"state": "ready"}, "network": {"state": "ready"}}}
        observed = {"resources": {"database": {"state": "degraded"}, "unreviewed": {"state": "ready"}}}
        with tempfile.TemporaryDirectory() as directory:
            expected = Path(directory) / "desired.json"
            actual = Path(directory) / "observed.json"
            expected.write_text(json.dumps(desired), encoding="utf-8")
            actual.write_text(json.dumps(observed), encoding="utf-8")
            runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
            binaries = sorted(path for path in runfiles.rglob("infractl") if path.is_file() and os.access(path, os.X_OK))
            if binaries:
                command = [str(binaries[0]), "drift", "classify", "--desired", str(expected), "--observed", str(actual)]
            else:
                binary = Path(directory) / "infractl"
                build = subprocess.run(["go", "build", "-o", str(binary), "./cmd/infractl"], cwd=ROOT / "tooling", text=True, capture_output=True, check=False)
                self.assertEqual(build.returncode, 0, build.stderr)
                command = [str(binary), "drift", "classify", "--desired", str(expected), "--observed", str(actual)]
            result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        kinds = {finding["kind"] for finding in report["findings"]}
        self.assertEqual(kinds, {"changed", "missing", "unmanaged"})
        self.assertNotIn("degraded", result.stdout)


if __name__ == "__main__":
    unittest.main()
