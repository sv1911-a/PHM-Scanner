import unittest

from spectre.core.models import Category, TargetContext
from spectre.plugins.technical.technology_fingerprint import TechnologyFingerprintPlugin


class TechnologyFingerprintTests(unittest.TestCase):
    def test_malicious_server_header_is_not_technology(self):
        plugin = TechnologyFingerprintPlugin()
        raw = {
            "url": "https://example.test",
            "status": 200,
            "headers": {"server": "; DELETE carlos FROM users --"},
            "html_excerpt": "<html><body>Hello</body></html>",
        }
        findings = plugin.analyze(TargetContext("https://example.test", Category.TECHNICAL), raw)
        technologies = findings[0].metadata["technologies"]
        self.assertNotIn("; DELETE carlos FROM users --", technologies)
        self.assertNotIn("Server", technologies)

    def test_known_server_header_can_be_signal(self):
        plugin = TechnologyFingerprintPlugin()
        raw = {
            "url": "https://example.test",
            "status": 200,
            "headers": {"server": "nginx/1.24.0"},
            "html_excerpt": "<html><body>Hello</body></html>",
        }
        findings = plugin.analyze(TargetContext("https://example.test", Category.TECHNICAL), raw)
        self.assertIn("nginx", findings[0].metadata["technologies"])


if __name__ == "__main__":
    unittest.main()
