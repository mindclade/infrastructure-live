# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import json
import os
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def classify(desired, observed, *, raw=False):
    directory = tempfile.TemporaryDirectory()
    desired_path = Path(directory.name) / "desired.json"
    observed_path = Path(directory.name) / "observed.json"
    desired_data = desired if raw else json.dumps(desired, separators=(",", ":"))
    observed_data = observed if raw else json.dumps(observed, separators=(",", ":"))
    desired_path.write_text(desired_data, encoding="utf-8")
    observed_path.write_text(observed_data, encoding="utf-8")
    runfiles = Path(os.environ.get("TEST_SRCDIR", "/nonexistent"))
    binaries = sorted(
        path for path in runfiles.rglob("infractl") if path.is_file() and os.access(path, os.X_OK)
    )
    if binaries:
        command = [
            str(binaries[0]),
            "drift",
            "classify",
            "--desired",
            str(desired_path),
            "--observed",
            str(observed_path),
        ]
    else:
        binary = Path(directory.name) / "infractl"
        build = subprocess.run(
            ["go", "build", "-o", str(binary), "./cmd/infractl"],
            cwd=ROOT / "tooling",
            text=True,
            capture_output=True,
            check=False,
        )
        if build.returncode != 0:
            directory.cleanup()
            return build
        command = [
            str(binary),
            "drift",
            "classify",
            "--desired",
            str(desired_path),
            "--observed",
            str(observed_path),
        ]
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

    def test_distinct_large_integers_are_not_rounded_equal(self):
        desired = 9007199254740992
        observed = 9007199254740993
        result = classify({"generation": desired}, {"generation": observed})
        self.assertEqual(result.returncode, 2)
        report = json.loads(result.stdout)
        self.assertFalse(report["clean"])
        self.assertEqual(report["findings"], [{"path": "$.generation", "kind": "changed"}])
        self.assertNotIn(str(desired), result.stdout + result.stderr)
        self.assertNotIn(str(observed), result.stdout + result.stderr)

    def test_identical_large_integer_is_clean(self):
        generation = 9007199254740993
        result = classify({"generation": generation}, {"generation": generation})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertTrue(json.loads(result.stdout)["clean"])

    def test_trailing_json_value_is_rejected(self):
        result = classify('{"generation":1} {}', '{"generation":1}', raw=True)
        self.assertEqual(result.returncode, 1)
        self.assertIn("parse desired JSON: unexpected trailing JSON value", result.stderr)


if __name__ == "__main__":
    unittest.main()
