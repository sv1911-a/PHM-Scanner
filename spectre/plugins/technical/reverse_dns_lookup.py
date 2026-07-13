"""Reverse DNS lookup plugin."""

from __future__ import annotations

import ipaddress
from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.reverse_dns.adapter import ReverseDNSAdapter


@registry.register
class ReverseDNSLookupPlugin(BasePlugin):
    name = "reverse_dns_lookup"
    category = Category.TECHNICAL
    description = "Resolve PTR/reverse DNS names for IP addresses."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        try:
            ipaddress.ip_address(target.value.strip().strip("[]"))
            return Detection(True, 0.93, "valid IP address for reverse DNS")
        except ValueError:
            return Detection(False, 0.0, "not an IP address")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        adapter = ReverseDNSAdapter(
            timeout=float(target.options.get("timeout", 8.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.lookup(target.value)

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        evidence = [
            Evidence(source="reverse_dns.ip", value=raw.get("ip")),
            Evidence(source="reverse_dns.hostname", value=raw.get("hostname")),
            Evidence(source="reverse_dns.aliases", value=raw.get("aliases", [])),
            Evidence(source="reverse_dns.addresses", value=raw.get("addresses", [])),
        ]
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="reverse_dns.error", value=error))
        return [
            Finding(
                title="Reverse DNS intelligence",
                description="Reverse DNS lookup completed for the IP address." if raw.get("hostname") else "No reverse DNS hostname was returned for the IP address.",
                category=self.category,
                plugin=self.name,
                confidence=0.88 if raw.get("hostname") else 0.5,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"adapter": raw.get("metadata", {})},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
