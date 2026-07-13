import tempfile
import unittest
from pathlib import Path

from phm.analysis.file.native import analyze_file, detect_signatures, extract_strings, shannon_entropy


class FileAnalysisTests(unittest.TestCase):
    def test_magic_detection_png(self):
        matches = detect_signatures(b"\x89PNG\r\n\x1a\n" + b"rest")
        self.assertEqual(matches[0]["name"], "PNG image")
        self.assertEqual(matches[0]["artifact_type"], "image")

    def test_extract_strings(self):
        strings = extract_strings(b"\x00hello world\x00http://example.org/path\x00", min_length=4)
        self.assertIn("hello world", strings)
        self.assertIn("http://example.org/path", strings)

    def test_entropy(self):
        self.assertEqual(shannon_entropy(b""), 0.0)
        self.assertGreater(shannon_entropy(bytes(range(256))), 7.0)

    def test_analyze_file(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "sample.pdf"
            path.write_bytes(b"%PDF-1.7\nhello@example.org\n")
            result = analyze_file(path)
            self.assertEqual(result["signatures"][0]["name"], "PDF document")
            self.assertTrue(result["extension_matches_signature"])
            self.assertIn("sha256", result["hashes"])


if __name__ == "__main__":
    unittest.main()
