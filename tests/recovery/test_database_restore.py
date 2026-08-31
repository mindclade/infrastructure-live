# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class DatabaseRestoreContractTest(unittest.TestCase):
    def test_database_module_preserves_recovery_controls(self):
        source = (ROOT / "opentofu/modules/gcp/cloud-sql-postgres/main.tf").read_text(
            encoding="utf-8"
        )
        for control in (
            "deletion_protection = var.deletion_protection_required",
            "availability_type",
            "backup_configuration",
            "point_in_time_recovery_enabled = true",
            "transaction_log_retention_days",
            "prevent_destroy = true",
        ):
            self.assertIn(control, source)

    def test_runbook_requires_restore_isolation_and_evidence(self):
        runbook = (
            (ROOT / "runbooks/database-failover-and-restore.md").read_text(encoding="utf-8").lower()
        )
        for concept in ("point-in-time", "isolated", "integrity", "approval", "rollback"):
            self.assertIn(concept, runbook)


if __name__ == "__main__":
    unittest.main()
