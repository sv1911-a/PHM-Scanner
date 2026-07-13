import unittest

from spectre.core.artifacts import ArtifactType, extract_artifacts, hash_type
from spectre.core.models import Category, Evidence, Finding, InvestigationReport, PluginResult
from spectre.core.artifacts import artifacts_from_report


class ArtifactTests(unittest.TestCase):
    def test_extract_common_artifacts(self):
        artifacts = extract_artifacts("Contact admin@example.org at https://github.com/python/cpython from 8.8.8.8")
        values = {(artifact.type, artifact.value) for artifact in artifacts}
        self.assertIn((ArtifactType.EMAIL, "admin@example.org"), values)
        self.assertIn((ArtifactType.URL, "https://github.com/python/cpython"), values)
        self.assertIn((ArtifactType.GITHUB_REPO, "python/cpython"), values)
        self.assertIn((ArtifactType.IP, "8.8.8.8"), values)

    def test_hash_type(self):
        self.assertEqual(hash_type("a" * 64), "sha256")

    def test_artifacts_from_report(self):
        finding = Finding(
            title="Test finding",
            description="test",
            category=Category.TECHNICAL,
            plugin="test_plugin",
            evidence=[Evidence(source="test", value="Resolved 1.1.1.1 for cloudflare.com")],
        )
        report = InvestigationReport(
            target="cloudflare.com",
            category=Category.TECHNICAL,
            results=[PluginResult(plugin="test_plugin", category=Category.TECHNICAL, target="cloudflare.com", status="ok", findings=[finding])],
        )
        artifacts = artifacts_from_report(report)
        artifact_values = {artifact["value"] for artifact in artifacts}
        self.assertIn("1.1.1.1", artifact_values)
        self.assertIn("cloudflare.com", artifact_values)


if __name__ == "__main__":
    unittest.main()
