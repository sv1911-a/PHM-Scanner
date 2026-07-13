"""CRT.SH certificate transparency plugin."""

from __future__ import annotations

from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.sources.common import is_domain, normalize_domain
from phm.sources.crtsh.adapter import CRTSHAdapter


@registry.register
class CRTSHLookupPlugin(BasePlugin):
    name = "crtsh_lookup"
    category = Category.TECHNICAL
    description = "Discover certificate transparency subdomain and certificate leads from crt.sh."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        domain = normalize_domain(target.value)
        ok = is_domain(domain)
        return Detection(ok, 0.88 if ok else 0.0, "domain target for certificate transparency" if ok else "not a domain")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        adapter = CRTSHAdapter(
            timeout=float(target.options.get("timeout", 12.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 86400)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.lookup(
            target.value,
            include_wildcard=True,
            limit=int(target.options.get("crtsh_limit", 500)),
        )

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        subdomains = raw.get("subdomains", [])
        certs = raw.get("certificates", [])
        evidence: list[Evidence] = [
            Evidence(source="crtsh.query", value=raw.get("query")),
            Evidence(source="crtsh.certificate_count", value=len(certs)),
            Evidence(source="crtsh.subdomain_count", value=len(subdomains)),
        ]
        for subdomain in subdomains[:50]:
            evidence.append(Evidence(source="crtsh.subdomain", value=subdomain))
        for cert in certs[:15]:
            evidence.append(Evidence(source="crtsh.certificate", value=cert))
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="crtsh.error", value=error))

        return [
            Finding(
                title="Certificate Transparency intelligence",
                description=f"Found {len(subdomains)} unique DNS name lead(s) and {len(certs)} certificate record(s) via crt.sh.",
                category=self.category,
                plugin=self.name,
                confidence=0.82 if subdomains or certs else 0.45,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"adapter": raw.get("metadata", {}), "source_url": raw.get("url")},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
