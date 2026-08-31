# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import json
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class ArtifactRestoreContractTest(unittest.TestCase):
    def test_bucket_module_preserves_recovery_controls(self):
        source = (ROOT / "opentofu/modules/gcp/artifact-bucket/main.tf").read_text(encoding="utf-8")
        for control in (
            "uniform_bucket_level_access = true",
            'public_access_prevention    = "enforced"',
            "force_destroy               = false",
            "versioning { enabled = each.value.versioning_enabled }",
            "soft_delete_policy",
            "retention_policy",
            "size_above_bytes",
            'type          = "SetStorageClass"',
            'storage_class = "ARCHIVE"',
            "prevent_destroy = true",
        ):
            self.assertIn(control, source)

    def test_runbook_requires_checksum_and_non_destructive_restore(self):
        runbook = (
            (ROOT / "runbooks/artifact-storage-recovery.md").read_text(encoding="utf-8").lower()
        )
        for concept in (
            "checksum",
            "generation",
            "non-destructive",
            "approval",
            "evidence",
            "nam4",
            "2,555",
            "retention lock",
            "objectcreator",
            "objectviewer",
        ):
            self.assertIn(concept, runbook)

    def test_bucket_retention_inputs_are_provider_bounded(self):
        source = (ROOT / "opentofu/modules/gcp/artifact-bucket/variables.tf").read_text(
            encoding="utf-8"
        )
        self.assertIn("bucket.soft_delete_days >= 7 && bucket.soft_delete_days <= 90", source)
        self.assertIn(
            "bucket.noncurrent_version_days >= 1 && bucket.noncurrent_version_days <= 3650", source
        )
        self.assertIn("bucket.retention_days <= 3650", source)
        self.assertIn("bucket.delete_after_days >= bucket.retention_days", source)

    def test_production_ci_evidence_profile_is_exact_and_disabled(self):
        profile = (ROOT / "catalog/resource-profiles.yaml").read_text(encoding="utf-8")
        for binding in (
            "ciEvidenceArchive:",
            "enabled: false",
            "location: NAM4",
            "storageClass: STANDARD",
            "replicationMode: DEFAULT",
            "kmsProtectionLevel: SOFTWARE",
            "kmsRotationPeriod: 7776000s",
            "retentionDays: 2555",
            "retentionLocked: false",
            "retentionLockReceipt: null",
            "softDeleteDays: 30",
            "versioningEnabled: false",
            "archiveAfterDays: 90",
            "archiveMinimumSizeBytes: 1048576",
            "deleteAfterDays: 2555",
        ):
            self.assertIn(binding, profile)

        contract = json.loads(
            (ROOT / "opentofu/live/production/artifacts/environment.auto.tfvars.json").read_text(
                encoding="utf-8"
            )
        )
        self.assertIs(contract["enabled"], False)
        self.assertIsNone(contract["config"]["project_id"])
        self.assertEqual(
            contract["config"]["ci_evidence_archive"],
            {
                "identity_project_id": None,
                "audit_sink_binding_mode": "discover",
                "audit_sink_writer_identity": None,
                "audit_notification_channels": [],
                "inventory_schedule": None,
            },
        )

    def test_ci_evidence_archive_names_and_iam_are_deterministic_and_least_privilege(self):
        stack = (ROOT / "opentofu/stacks/artifacts/main.tf").read_text(encoding="utf-8")
        bucket = (ROOT / "opentofu/modules/gcp/artifact-bucket/main.tf").read_text(encoding="utf-8")
        kms = (ROOT / "opentofu/modules/gcp/delegated-kms/main.tf").read_text(encoding="utf-8")
        self.assertIn('"${var.config.project_id}-production-ci-evidence"', stack)
        self.assertIn(
            'key_ring_name = local.ci_evidence_archive_connected ? "ci-evidence" : null', stack
        )
        self.assertIn(
            "protection_level = var.ci_evidence_archive_profile.kmsProtectionLevel", stack
        )
        self.assertIn('role = "roles/storage.objectViewer"', bucket)
        self.assertIn('role = "roles/storage.objectCreator"', bucket)
        self.assertIn("version_template {", kms)
        self.assertIn("protection_level = each.value.protection_level", kms)
        variables = (ROOT / "opentofu/stacks/artifacts/variables.tf").read_text(encoding="utf-8")
        self.assertNotIn("writer_principal      = optional", variables)
        self.assertNotIn("verifier_principal    = optional", variables)
        self.assertNotIn("storage_service_agent = optional", variables)
        self.assertIn("identity_project_id", variables)
        self.assertIn("never a principal or principalSet", variables)
        self.assertIn(
            '"serviceAccount:ci-evidence-writer@${local.ci_evidence_identity_project}.iam.gserviceaccount.com"',
            stack,
        )
        self.assertIn(
            '"serviceAccount:ci-evidence-verifier@${local.ci_evidence_identity_project}.iam.gserviceaccount.com"',
            stack,
        )
        self.assertIn(
            '"serviceAccount:service-${local.ci_evidence_target_project_number}@gs-project-accounts.iam.gserviceaccount.com"',
            stack,
        )
        self.assertIn('data "google_project" "ci_evidence_archive_target"', stack)

    def test_retention_lock_is_explicitly_unreachable_and_receipts_cannot_authorize_it(self):
        module = (ROOT / "opentofu/modules/gcp/artifact-bucket/main.tf").read_text(encoding="utf-8")
        variables = (ROOT / "opentofu/modules/gcp/artifact-bucket/variables.tf").read_text(
            encoding="utf-8"
        )
        stack = (ROOT / "opentofu/stacks/artifacts/outputs.tf").read_text(encoding="utf-8")
        for control in (
            "condition     = !each.value.lock_retention",
            "Irreversible retention locking is intentionally unreachable",
        ):
            self.assertIn(control, module)
        self.assertIn("!bucket.lock_retention", variables)
        self.assertIn("try(bucket.retention_lock_receipt == null, true)", variables)
        self.assertIn("no operator-supplied lock receipt", variables)
        self.assertIn("!try(var.ci_evidence_archive_profile.retentionLocked, false)", stack)
        self.assertIn("local.ci_evidence_lock_receipt == null", stack)
        self.assertIn("Retention lock is intentionally unreachable", stack)
        self.assertNotIn('receiptDigest == "sha256:${sha256(join(', module)

    def test_archive_provisions_fail_closed_audit_alert_and_inventory_contracts(self):
        stack = (ROOT / "opentofu/stacks/artifacts/main.tf").read_text(encoding="utf-8")
        for resource in (
            'resource "google_project_iam_audit_config" "ci_evidence_storage"',
            'resource "google_logging_project_sink" "ci_evidence_audit"',
            'resource "google_storage_bucket_iam_member" "ci_evidence_audit_sink_writer"',
            'resource "google_logging_metric" "ci_evidence_security_event"',
            'resource "google_monitoring_alert_policy" "ci_evidence_security_event"',
            'resource "google_storage_insights_report_config" "ci_evidence_inventory"',
        ):
            self.assertIn(resource, stack)
        for control in (
            'audit_log_config { log_type = "DATA_READ" }',
            'audit_log_config { log_type = "DATA_WRITE" }',
            "unique_writer_identity = true",
            "notification_channels = local.ci_evidence_notification_channels",
            'frequency = "DAILY"',
            'destination_path = "inventory/"',
            'deletion_policy = "PREVENT"',
            "only after the configured principal matches both the managed and independently rediscovered provider-issued identities",
        ):
            self.assertIn(control, stack)

    def test_disaster_recovery_source_path_is_cloud_independent_and_connected_path_is_fail_closed(
        self,
    ):
        workflow = (ROOT / ".github/workflows/disaster-recovery.yml").read_text(encoding="utf-8")
        connected_marker = "  verify-ci-evidence-connected:\n"
        source_only, connected = workflow.split(connected_marker, 1)

        self.assertIn("connectedQualification: false", source_only)
        self.assertIn("connectedReadPerformed: false", source_only)
        self.assertIn("retentionLockPerformed: false", source_only)
        self.assertNotIn("id-token: write", source_only)
        self.assertNotIn("google-github-actions/auth", source_only)
        self.assertNotIn("gcloud storage", source_only)

        for control in (
            "inputs.connected_ci_evidence_verification == true",
            "github.event_name == 'workflow_dispatch'",
            "github.ref == 'refs/heads/main'",
            "needs.verify.result == 'success'",
            "environment: infrastructure-apply",
            "id-token: write",
            "CI_EVIDENCE_VERIFIER_WIF_PROVIDER",
            "CI_EVIDENCE_VERIFIER_SERVICE_ACCOUNT",
            "CI_EVIDENCE_ARCHIVE_BUCKET",
            "github-ci-evidence/providers/verifier",
            "^sha256:[0-9a-f]{64}$",
            "ci-evidence\\.json#([1-9][0-9]*)$",
            "google-github-actions/auth@7c6bc770dae815cd3e89ee6cdf493a5fab2cc093",
            "google-github-actions/setup-gcloud@aa5489c8933f4cc7a4f7d45035b3b1440c9c10db",
            "gcloud storage objects describe",
            "gcloud storage cp",
            "iam/testPermissions",
            '["storage.objects.get","storage.objects.list"]',
            "storage.objects.create",
            "storage.objects.delete",
            "storage.objects.update",
            "storage.objects.overrideUnlockedRetention",
            "storage.objects.setRetention",
            "storage.objects.restore",
            "storage.buckets.enableObjectRetention",
            "storage.buckets.setIpFilter",
            "storage.managedFolders.setIamPolicy",
            "storage.multipartUploads.create",
            "mutationPerformed: false",
            "retentionLockPerformed: false",
        ):
            self.assertIn(control, connected)
        self.assertNotIn("audience:", connected)
        self.assertNotIn("gcloud storage rm", connected)
        self.assertNotIn("gcloud storage buckets update", connected)
        self.assertNotIn("gcloud storage objects delete", connected)


if __name__ == "__main__":
    unittest.main()
