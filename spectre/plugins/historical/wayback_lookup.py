"""Wayback Machine historical intelligence plugin."""

from __future__ import annotations

from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.wayback.adapter import WaybackAdapter


@registry.register
class WaybackLookupPlugin(BasePlugin):
    name = "wayback_lookup"
    category = Category.HISTORICAL
    description = "Collect historical snapshot leads from the Internet Archive Wayback Machine."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        domain = normalize_domain(target.value)
        ok = is_domain(domain)
        return Detection(ok, 0.9 if ok else 0.0, "domain target for Wayback history" if ok else "not a domain")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        adapter = WaybackAdapter(
            timeout=float(target.options.get("timeout", 12.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 86400)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.lookup(target.value, limit=int(target.options.get("wayback_limit", 50)))

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        snapshots = raw.get("snapshots", [])
        timeline = raw.get("timeline", {})
        evidence: list[Evidence] = [
            Evidence(source="wayback.closest", value=raw.get("closest", {})),
            Evidence(source="wayback.snapshot_count", value=len(snapshots)),
            Evidence(source="wayback.timeline", value=timeline),
        ]
        for snapshot in snapshots[:20]:
            evidence.append(Evidence(source="wayback.snapshot", value=snapshot))
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="wayback.error", value=error))

        return [
            Finding(
                title="Wayback historical snapshot intelligence",
                description=f"Collected {len(snapshots)} historical snapshot lead(s) and year-level timeline counts from the Wayback Machine.",
                category=self.category,
                plugin=self.name,
                confidence=0.82 if snapshots or raw.get("closest") else 0.45,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"adapter": raw.get("metadata", {}), "cdx_url": raw.get("cdx_url")},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
