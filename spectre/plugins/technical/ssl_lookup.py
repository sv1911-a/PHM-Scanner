"""SSL/TLS certificate intelligence plugin."""

from __future__ import annotations

from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.ssl.adapter import SSLAdapter


@registry.register
class SSLLookupPlugin(BasePlugin):
    name = "ssl_lookup"
    category = Category.TECHNICAL
    description = "Collect public TLS certificate metadata through the SSL source adapter."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        domain = normalize_domain(target.value)
        ok = is_domain(domain)
        return Detection(ok, 0.82 if ok else 0.0, "domain-like input for TLS" if ok else "not a domain")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        adapter = SSLAdapter(
            timeout=float(target.options.get("timeout", 8.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.lookup(target.value, port=int(target.options.get("port", 443)))

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        severity = Severity.INFO
        confidence = 0.92
        expiry = raw.get("days_until_expiry")
        description = "TLS certificate metadata was collected."
        if isinstance(expiry, int) and expiry < 0:
            severity = Severity.HIGH
            description = "TLS certificate appears to be expired."
        elif isinstance(expiry, int) and expiry <= 30:
            severity = Severity.MEDIUM
            description = "TLS certificate expires within 30 days."

        evidence = [
            Evidence(source="tls.subject", value=raw.get("subject")),
            Evidence(source="tls.issuer", value=raw.get("issuer")),
            Evidence(source="tls.not_after", value=raw.get("not_after")),
            Evidence(source="tls.days_until_expiry", value=raw.get("days_until_expiry")),
            Evidence(source="tls.version", value=raw.get("tls_version")),
            Evidence(source="tls.san_count", value=raw.get("san_count")),
        ]
        for san in raw.get("subject_alt_names", [])[:12]:
            evidence.append(Evidence(source="tls.subject_alt_name", value=san))
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="tls.error", value=error))
        return [
            Finding(
                title="TLS certificate intelligence",
                description=description,
                category=self.category,
                plugin=self.name,
                confidence=confidence,
                severity=severity,
                evidence=evidence,
                metadata={"serial_number": raw.get("serial_number"), "cipher": raw.get("cipher"), "adapter": raw.get("metadata", {})},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
