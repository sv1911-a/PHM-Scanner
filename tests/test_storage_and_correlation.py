import tempfile
import unittest
from pathlib import Path

from phm.core.correlation import build_relationship_graph
from phm.core.models import Category, Evidence, Finding, InvestigationReport, PluginResult
from phm.core.storage import InvestigationStore


class StorageAndCorrelationTests(unittest.TestCase):
    def sample_report(self):
        finding = Finding(
            title="Resolved IP addresses",
            description="example.com resolved",
            category=Category.TECHNICAL,
            plugin="dns_lookup",
            evidence=[Evidence(source="system_resolver", value="93.184.216.34")],
        )
        result = PluginResult(
            plugin="dns_lookup",
            category=Category.TECHNICAL,
            target="example.com",
            status="ok",
            findings=[finding],
            raw={"domain": "example.com", "addresses": ["93.184.216.34"]},
        )
        return InvestigationReport(target="example.com", category=Category.TECHNICAL, results=[result])

    def test_relationship_graph_extracts_entities(self):
        graph = build_relationship_graph(self.sample_report())
        labels = {node["label"] for node in graph["nodes"]}
        self.assertIn("example.com", labels)
        self.assertIn("93.184.216.34", labels)
        self.assertGreaterEqual(graph["summary"]["edge_count"], 1)

    def test_storage_roundtrip(self):
        with tempfile.TemporaryDirectory() as directory:
            db_path = Path(directory) / "phm.db"
            store = InvestigationStore(db_path)
            investigation_id = store.save(self.sample_report())
            rows = store.list()
            self.assertEqual(rows[0]["id"], investigation_id)
            loaded = store.load(investigation_id)
            self.assertEqual(loaded["target"], "example.com")
            self.assertEqual(loaded["category"], "technical")


if __name__ == "__main__":
    unittest.main()
