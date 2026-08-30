from pathlib import Path
import unittest


ROOT = Path(__file__).resolve().parents[2]


class ArtifactRestoreContractTest(unittest.TestCase):
    def test_bucket_module_preserves_recovery_controls(self):
        source = (ROOT / "opentofu/modules/gcp/artifact-bucket/main.tf").read_text(encoding="utf-8")
        for control in (
            "uniform_bucket_level_access = true",
            'public_access_prevention    = "enforced"',
            "versioning { enabled = true }",
            "soft_delete_policy",
            "retention_policy",
            "prevent_destroy = true",
        ):
            self.assertIn(control, source)

    def test_runbook_requires_checksum_and_non_destructive_restore(self):
        runbook = (ROOT / "runbooks/artifact-storage-recovery.md").read_text(encoding="utf-8").lower()
        for concept in ("checksum", "generation", "non-destructive", "approval", "evidence"):
            self.assertIn(concept, runbook)

    def test_bucket_retention_inputs_are_provider_bounded(self):
        source = (ROOT / "opentofu/modules/gcp/artifact-bucket/variables.tf").read_text(encoding="utf-8")
        self.assertIn("bucket.soft_delete_days >= 7 && bucket.soft_delete_days <= 90", source)
        self.assertIn("bucket.noncurrent_version_days >= 1 && bucket.noncurrent_version_days <= 3650", source)
        self.assertIn("bucket.retention_days <= 3650", source)


if __name__ == "__main__":
    unittest.main()
