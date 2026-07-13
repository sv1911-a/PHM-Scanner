"""RDAP lookup plugin for technical intelligence."""

from __future__ import annotations

import ipaddress
from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.rdap.adapter import RDAPAdapter


@registry.register
class RDAPLookupPlugin(BasePlugin):
    name = "rdap_lookup"
    category = Category.TECHNICAL
    description = "Collect structured RDAP registration/network data for domains or IP addresses."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        try:
            ipaddress.ip_address(value.strip("[]"))
            return Detection(True, 0.9, "valid IP RDAP target")
        except ValueError:
            pass
        domain = normalize_domain(value)
        ok = is_domain(domain)
        return Detection(ok, 0.86 if ok else 0.0, "domain RDAP target" if ok else "not domain/IP")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        adapter = RDAPAdapter(
            timeout=float(target.options.get("timeout", 8.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.lookup(target.value)

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        summary = raw.get("summary", {})
        evidence: list[Evidence] = [
            Evidence(source="rdap.type", value=raw.get("type")),
            Evidence(source="rdap.handle", value=summary.get("handle")),
            Evidence(source="rdap.status", value=summary.get("status")),
            Evidence(source="rdap.events", value=summary.get("events")),
        ]
        for ns in summary.get("nameservers", [])[:20]:
            evidence.append(Evidence(source="rdap.nameserver", value=ns))
        for entity in summary.get("entities", [])[:12]:
            evidence.append(Evidence(source="rdap.entity", value=entity))
        if summary.get("network"):
            evidence.append(Evidence(source="rdap.network", value=summary["network"]))
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="rdap.error", value=error))

        return [
            Finding(
                title="RDAP structured registration intelligence",
                description="Collected structured RDAP data for the target using a free public bootstrap endpoint.",
                category=self.category,
                plugin=self.name,
                confidence=0.86 if summary else 0.45,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"adapter": raw.get("metadata", {}), "rdap_url": raw.get("url")},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
