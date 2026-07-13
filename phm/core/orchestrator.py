"""Investigation orchestration workflow."""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Iterable

from phm.core.artifacts import artifacts_from_report
from phm.core.correlation import build_relationship_graph
from phm.core.models import Category, InvestigationReport, PluginResult, TargetContext
from phm.core.recommendations import build_next_steps
from phm.core.registry import registry
from phm.core.summary import build_summary


class InvestigationOrchestrator:
    """Coordinates category selection, plugin discovery, collection, and reporting."""

    def run(
        self,
        category: Category,
        target_value: str,
        plugin_names: Iterable[str] | None = None,
        options: dict | None = None,
        max_workers: int = 4,
    ) -> InvestigationReport:
        """Run all detected plugins for a target/category."""

        target = TargetContext(value=target_value, category=category, options=options or {})

        if plugin_names:
            plugins = [registry.get(name) for name in plugin_names]
            detections = registry.detect(target, plugins)
        else:
            detections = registry.detect(target)

        results: list[PluginResult] = []
        if not detections:
            return InvestigationReport(
                target=target.value,
                category=category,
                results=[],
                metadata={"message": "No applicable plugins detected."},
            )

        # Passive plugins are isolated and safe to run concurrently. Future active
        # plugins can opt out by setting passive=False and being scheduled serially.
        passive = [plugin for plugin, _ in detections if plugin.passive]
        active = [plugin for plugin, _ in detections if not plugin.passive]

        if passive:
            workers = max(1, min(max_workers, len(passive)))
            with ThreadPoolExecutor(max_workers=workers) as executor:
                future_map = {executor.submit(plugin.run, target): plugin.name for plugin in passive}
                for future in as_completed(future_map):
                    results.append(future.result())

        for plugin in active:
            results.append(plugin.run(target))

        results.sort(key=lambda result: result.plugin)
        report = InvestigationReport(
            target=target.value,
            category=category,
            results=results,
            metadata={
                "workflow": [
                    "input",
                    "category_selection",
                    "plugin_discovery",
                    "data_collection",
                    "analysis",
                    "correlation",
                    "reporting",
                ]
            },
        )
        report.metadata["artifacts"] = artifacts_from_report(report)
        report.metadata["relationship_graph"] = build_relationship_graph(report)
        report.metadata["summary"] = build_summary(report)
        report.metadata["next_steps"] = build_next_steps(report)
        return report
