import unittest

from spectre.core.models import Category, Evidence, Finding, InvestigationReport, PluginResult
from spectre.core.artifacts import artifacts_from_report
from spectre.core.recommendations import build_next_steps


class RecommendationTests(unittest.TestCase):
    def test_file_url_recommendation(self):
        finding = Finding(
            title="Native file triage",
            description="strings found",
            category=Category.FILE,
            plugin="file_analysis",
            evidence=[Evidence(source="file.string", value="callback https://example.org/api")],
        )
        report = InvestigationReport(
            target="sample.bin",
            category=Category.FILE,
            results=[PluginResult(plugin="file_analysis", category=Category.FILE, target="sample.bin", status="ok", findings=[finding])],
        )
        report.metadata["artifacts"] = artifacts_from_report(report)
        steps = build_next_steps(report)
        titles = {step["title"] for step in steps}
        self.assertIn("Analyze discovered URLs or domains", titles)

    def test_crypto_recommendation(self):
        report = InvestigationReport(target="<crypto-input>", category=Category.CRYPTO, results=[])
        steps = build_next_steps(report)
        self.assertTrue(steps)


if __name__ == "__main__":
    unittest.main()
