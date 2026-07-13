"""DNS lookup plugin for technical intelligence."""

from __future__ import annotations

from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.sources.common import is_domain, normalize_domain
from phm.sources.dns.adapter import DNSAdapter

# Backward-compatible helper used by older plugins.
_normalize_domain = normalize_domain


@registry.register
class DNSLookupPlugin(BasePlugin):
    name = "dns_lookup"
    category = Category.TECHNICAL
    description = "Resolve DNS records through the DNS source adapter."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        domain = normalize_domain(target.value)
        ok = is_domain(domain)
        return Detection(ok, 0.95 if ok else 0.0, "domain-like input" if ok else "not a domain")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        adapter = DNSAdapter(
            timeout=float(target.options.get("timeout", 8.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.lookup(target.value)

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        addresses = [*raw.get("a_records", []), *raw.get("aaaa_records", [])]
        evidence: list[Evidence] = []
        for address in addresses:
            evidence.append(Evidence(source="dns.address", value=address))
        for mx in raw.get("mx_records", []):
            evidence.append(Evidence(source="dns.mx", value=mx))
        for ns in raw.get("ns_records", []):
            evidence.append(Evidence(source="dns.ns", value=ns))
        for txt in raw.get("txt_records", [])[:10]:
            evidence.append(Evidence(source="dns.txt", value=txt))
        for cname in raw.get("cname_records", []):
            evidence.append(Evidence(source="dns.cname", value=cname))
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="dns.error", value=error))

        if addresses or raw.get("mx_records") or raw.get("ns_records"):
            findings.append(
                Finding(
                    title="DNS intelligence",
                    description=(
                        f"{raw['domain']} returned {len(raw.get('a_records', []))} A, "
                        f"{len(raw.get('aaaa_records', []))} AAAA, {len(raw.get('mx_records', []))} MX, "
                        f"and {len(raw.get('ns_records', []))} NS record(s)."
                    ),
                    category=self.category,
                    plugin=self.name,
                    confidence=0.93,
                    severity=Severity.INFO,
                    evidence=evidence,
                    metadata={"reverse_dns": raw.get("reverse_dns", {}), "adapter": raw.get("metadata", {})},
                )
            )
        else:
            findings.append(
                Finding(
                    title="No DNS records resolved",
                    description="The DNS adapter did not return common records for the target.",
                    category=self.category,
                    plugin=self.name,
                    confidence=0.55,
                    severity=Severity.LOW,
                    evidence=evidence or [Evidence(source="dns.raw", value=raw)],
                    metadata={"adapter": raw.get("metadata", {})},
                )
            )
        return findings

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
