import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[2]


def classify(desired, observed):
    directory = tempfile.TemporaryDirectory()
    desired_path = Path(directory.name) / "desired.json"
    observed_path = Path(directory.name) / "observed.json"
    desired_path.write_text(json.dumps(desired, separators=(",", ":")), encoding="utf-8")
    observed_path.write_text(json.dumps(observed, separators=(",", ":")), encoding="utf-8")
    runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
    binaries = sorted(path for path in runfiles.rglob("infractl") if path.is_file() and os.access(path, os.X_OK))
    if binaries:
        command = [str(binaries[0]), "drift", "classify", "--desired", str(desired_path), "--observed", str(observed_path)]
    else:
        binary = Path(directory.name) / "infractl"
        build = subprocess.run(["go", "build", "-o", str(binary), "./cmd/infractl"], cwd=ROOT / "tooling", text=True, capture_output=True, check=False)
        if build.returncode != 0:
            directory.cleanup()
            return build
        command = [str(binary), "drift", "classify", "--desired", str(desired_path), "--observed", str(observed_path)]
    result = subprocess.run(command, cwd=ROOT, text=True, capture_output=True, check=False)
    directory.cleanup()
    return result


class CloudDriftClassificationTest(unittest.TestCase):
    def test_identical_observation_is_clean(self):
        document = {"resources": [{"kind": "network", "name": "primary"}]}
        result = classify(document, document)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["clean"])

    def test_findings_are_sorted_and_redacted(self):
        result = classify({"z": "reviewed", "a": "reviewed"}, {"z": "altered", "b": "unmanaged"})
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        paths = [finding["path"] for finding in report["findings"]]
        self.assertEqual(paths, sorted(paths))
        self.assertNotIn("altered", result.stdout)


if __name__ == "__main__":
    unittest.main()
