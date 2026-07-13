"""WHOIS lookup plugin for technical intelligence."""

from __future__ import annotations

from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.whois.adapter import WhoisAdapter


@registry.register
class WhoisLookupPlugin(BasePlugin):
    name = "whois_lookup"
    category = Category.TECHNICAL
    description = "Perform passive WHOIS lookup through the WHOIS source adapter."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        domain = normalize_domain(target.value)
        ok = is_domain(domain)
        return Detection(ok, 0.85 if ok else 0.0, "domain-like input" if ok else "not a domain")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        adapter = WhoisAdapter(
            timeout=float(target.options.get("timeout", 8.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.lookup(target.value)

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        fields = raw.get("fields", {})
        evidence = [Evidence(source=f"whois:{key}", value=value) for key, values in fields.items() for value in values]
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="whois.error", value=error))
        if fields:
            description = "WHOIS registration metadata was extracted for the domain."
            confidence = 0.9
        else:
            description = "WHOIS source returned limited or no normalized registration metadata."
            confidence = 0.55
            evidence = evidence or [Evidence(source="whois_response_excerpt", value=raw.get("whois_response_excerpt") or raw.get("iana_response_excerpt", ""))]
        return [
            Finding(
                title="WHOIS registration metadata",
                description=description,
                category=self.category,
                plugin=self.name,
                confidence=confidence,
                severity=Severity.INFO,
                evidence=evidence[:40],
                metadata={"referred_server": raw.get("referred_server"), "adapter": raw.get("metadata", {})},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
