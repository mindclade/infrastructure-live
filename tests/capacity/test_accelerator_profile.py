# pyright: basic, reportArgumentType=false, reportAttributeAccessIssue=false, reportCallIssue=false, reportOperatorIssue=false, reportOptionalMemberAccess=false, reportOptionalSubscript=false
import re
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class AcceleratorProfileContractTest(unittest.TestCase):
    def test_profiles_are_disabled_bounded_and_dedicated(self):
        source = (ROOT / "catalog/accelerator-profiles.yaml").read_text(encoding="utf-8")
        profiles = re.split(r"\n  - name: ", source)[1:]
        self.assertEqual(len(profiles), 4)
        for profile in profiles:
            self.assertIn("enabled: false", profile)
            self.assertIn("dedicatedNodePool: true", profile)
            maximum = int(re.search(r"maximumNodes: (\d+)", profile).group(1))
            self.assertLessEqual(maximum, 64)
        for profile in profiles:
            if profile.startswith(("gpu-production", "gpu-restricted")):
                self.assertIn("spotPermitted: false", profile)

    def test_node_pool_enforces_taints_and_repair(self):
        source = (ROOT / "opentofu/modules/gcp/gke-node-pool/main.tf").read_text(encoding="utf-8")
        self.assertIn("auto_repair  = true", source)
        self.assertIn("var.accelerator == null || length(var.taints) > 0", source)
        self.assertIn("Accelerator pools must be isolated", source)
        self.assertIn("var.accelerator_profile.enabled", source)
        self.assertIn("var.accelerator_profile.maximum_nodes", source)
        self.assertIn("var.accelerator_profile.quota_binding", source)
        self.assertIn("total_max_node_count = var.max_nodes", source)
        self.assertNotIn("max_node_count  = var.max_nodes", source)

    def test_cluster_roots_load_the_catalog_as_activation_authority(self):
        for source_path in sorted((ROOT / "opentofu/live").glob("*/clusters/main.tf")):
            source = source_path.read_text(encoding="utf-8")
            self.assertIn("yamldecode(file", source)
            self.assertIn("environments.yaml", source)
            self.assertIn("accelerator-profiles.yaml", source)
            self.assertIn(
                "contains(local.environment_catalog.acceleratorProfiles, profile.name)", source
            )
            self.assertIn("accelerator_profiles = local.accelerator_profiles", source)

    def test_development_cannot_select_the_production_profile(self):
        source = (ROOT / "opentofu/live/development/clusters/main.tf").read_text(encoding="utf-8")
        environment_catalog = (ROOT / "catalog/environments.yaml").read_text(encoding="utf-8")
        development = environment_catalog.split("- name: development", 1)[1].split(
            "- name: staging", 1
        )[0]
        self.assertIn("acceleratorProfiles: [gpu-development]", development)
        self.assertNotIn("gpu-production", development)
        self.assertIn(
            "profile.name => profile if contains(local.environment_catalog.acceleratorProfiles, profile.name)",
            source,
        )

    def test_mutable_latest_driver_is_not_a_default(self):
        sources = [
            ROOT / "opentofu/modules/gcp/gke-node-pool/variables.tf",
            ROOT / "opentofu/stacks/clusters/variables.tf",
            *sorted((ROOT / "opentofu/live").glob("*/clusters/main.tf")),
        ]
        for path in sources:
            source = path.read_text(encoding="utf-8")
            self.assertNotIn('optional(string, "LATEST")', source, str(path))


if __name__ == "__main__":
    unittest.main()
