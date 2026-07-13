import unittest

from phm.core.registry import registry


class RegistryTests(unittest.TestCase):
    def test_builtin_plugins_registered(self):
        grouped = registry.grouped_names()
        self.assertIn("technical", grouped)
        self.assertIn("personal", grouped)
        self.assertIn("crypto", grouped)
        self.assertIn("dns_lookup", grouped["technical"])
        self.assertIn("username_lookup", grouped["personal"])
        self.assertIn("base64_decoder", grouped["crypto"])


if __name__ == "__main__":
    unittest.main()
