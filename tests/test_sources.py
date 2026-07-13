import tempfile
import unittest
from pathlib import Path

from spectre.sources.cache import SourceCache
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.crtsh.adapter import CRTSHAdapter
from spectre.sources.github.adapter import parse_repo_slug, scan_text_for_secrets, technology_hints
from spectre.sources.wayback.adapter import WaybackAdapter


class SourceAdapterTests(unittest.TestCase):
    def test_domain_normalization(self):
        self.assertEqual(normalize_domain("https://Example.COM/path"), "example.com")
        self.assertTrue(is_domain("example.com"))
        self.assertFalse(is_domain("not a domain"))

    def test_repo_slug_parser(self):
        self.assertEqual(parse_repo_slug("https://github.com/python/cpython"), ("python", "cpython"))
        self.assertEqual(parse_repo_slug("python/cpython"), ("python", "cpython"))

    def test_secret_scanner_redacts(self):
        findings = scan_text_for_secrets("api_key='ABCDEFGHIJKLMNOPQRSTUVWXYZ123456'", "config.txt")
        self.assertEqual(len(findings), 1)
        self.assertIn("...", findings[0]["redacted_value"])
        self.assertNotIn("ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", findings[0]["redacted_value"])

    def test_technology_hints(self):
        hints = technology_hints([{"path": "package.json"}, {"path": ".github/workflows/ci.yml"}])
        self.assertIn("Node.js / JavaScript", hints)
        self.assertIn("GitHub Actions", hints)

    def test_source_cache_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            cache = SourceCache(Path(directory) / "cache.db")
            cache.set("dns", "example.com", {"ok": True}, ttl_seconds=60)
            self.assertEqual(cache.get("dns", "example.com"), {"ok": True})

    def test_crtsh_name_extraction(self):
        names = CRTSHAdapter._extract_names("*.api.example.com\nmail.example.com", "example.com")
        self.assertIn("api.example.com", names)
        self.assertIn("mail.example.com", names)

    def test_wayback_timeline(self):
        timeline = WaybackAdapter._timeline([
            {"timestamp": "20200101000000"},
            {"timestamp": "20200501000000"},
            {"timestamp": "20210101000000"},
        ])
        self.assertEqual(timeline, {"2020": 2, "2021": 1})


if __name__ == "__main__":
    unittest.main()
