"""Aggregate technical intelligence plugin powered by source adapters."""

from __future__ import annotations

from typing import Any, Callable

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.crtsh.adapter import CRTSHAdapter
from spectre.sources.dns.adapter import DNSAdapter
from spectre.sources.github.adapter import GitHubAdapter
from spectre.sources.rdap.adapter import RDAPAdapter
from spectre.sources.ssl.adapter import SSLAdapter
from spectre.sources.wayback.adapter import WaybackAdapter
from spectre.sources.whois.adapter import WhoisAdapter


@registry.register
class TechnicalIntelligencePlugin(BasePlugin):
    """Aggregate free technical intelligence source adapters.

    This is optional by default to avoid duplicating the individual DNS/WHOIS/SSL
    plugins during normal runs. Invoke explicitly with:

        spectre technical example.com --plugin technical_intelligence
    """

    name = "technical_intelligence"
    category = Category.TECHNICAL
    description = "Aggregate domain technical intelligence from DNS, WHOIS, RDAP, SSL, CRT.SH, Wayback, and GitHub adapters."
    passive = True
    default_enabled = False

    def detect(self, target: TargetContext) -> Detection:
        domain = normalize_domain(target.value)
        ok = is_domain(domain)
        return Detection(ok, 0.9 if ok else 0.0, "domain aggregate intelligence target" if ok else "not a domain")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        domain = normalize_domain(target.value)
        timeout = float(target.options.get("timeout", 8.0))
        adapter_kwargs = {
            "timeout": timeout,
            "use_cache": bool(target.options.get("cache", False)),
            "cache_ttl": int(target.options.get("cache_ttl", 3600)),
            "cache_path": str(target.options.get("cache_path", "investigations/source_cache.db")),
        }
        raw: dict[str, Any] = {"domain": domain, "sources": {}, "errors": []}

        def safe_collect(name: str, func: Callable[[], dict[str, Any]]) -> None:
            try:
                raw["sources"][name] = func()
            except Exception as exc:  # noqa: BLE001 - aggregate plugin should degrade source-by-source
                raw["sources"][name] = {"errors": [f"{type(exc).__name__}: {exc}"]}
                raw["errors"].append(f"{name}: {type(exc).__name__}: {exc}")

        safe_collect("dns", lambda: DNSAdapter(**adapter_kwargs).lookup(domain))
        safe_collect("whois", lambda: WhoisAdapter(**adapter_kwargs).lookup(domain))
        safe_collect("rdap", lambda: RDAPAdapter(**adapter_kwargs).lookup(domain))
        safe_collect("ssl", lambda: SSLAdapter(**adapter_kwargs).lookup(domain))
        safe_collect("crtsh", lambda: CRTSHAdapter(**adapter_kwargs).lookup(domain, limit=int(target.options.get("crtsh_limit", 300))))
        safe_collect("wayback", lambda: WaybackAdapter(**adapter_kwargs).lookup(domain, limit=int(target.options.get("wayback_limit", 30))))
        safe_collect("github", lambda: GitHubAdapter(timeout=timeout, use_cache=adapter_kwargs["use_cache"], cache_ttl=adapter_kwargs["cache_ttl"], cache_path=adapter_kwargs["cache_path"]).search(domain, per_page=10, include_code=True))
        return raw

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        sources = raw.get("sources", {})
        dns = sources.get("dns", {})
        whois = sources.get("whois", {})
        rdap = sources.get("rdap", {})
        ssl = sources.get("ssl", {})
        crtsh = sources.get("crtsh", {})
        wayback = sources.get("wayback", {})
        github = sources.get("github", {})

        evidence: list[Evidence] = []
        for address in [*dns.get("a_records", []), *dns.get("aaaa_records", [])]:
            evidence.append(Evidence(source="dns.address", value=address))
        for mx in dns.get("mx_records", []):
            evidence.append(Evidence(source="dns.mx", value=mx))
        for ns in dns.get("ns_records", []):
            evidence.append(Evidence(source="dns.ns", value=ns))
        for key, values in whois.get("fields", {}).items():
            for value in values[:5]:
                evidence.append(Evidence(source=f"whois.{key}", value=value))
        rdap_summary = rdap.get("summary", {})
        if rdap_summary:
            evidence.append(Evidence(source="rdap.status", value=rdap_summary.get("status")))
            evidence.append(Evidence(source="rdap.events", value=rdap_summary.get("events")))
            for ns in rdap_summary.get("nameservers", [])[:10]:
                evidence.append(Evidence(source="rdap.nameserver", value=ns))
        if ssl:
            evidence.extend(
                [
                    Evidence(source="ssl.issuer", value=ssl.get("issuer")),
                    Evidence(source="ssl.not_after", value=ssl.get("not_after")),
                    Evidence(source="ssl.san_count", value=ssl.get("san_count")),
                ]
            )
            for san in ssl.get("subject_alt_names", [])[:10]:
                evidence.append(Evidence(source="ssl.subject_alt_name", value=san))
        evidence.append(Evidence(source="crtsh.subdomain_count", value=len(crtsh.get("subdomains", []))))
        for subdomain in crtsh.get("subdomains", [])[:25]:
            evidence.append(Evidence(source="crtsh.subdomain", value=subdomain))
        evidence.append(Evidence(source="wayback.snapshot_count", value=len(wayback.get("snapshots", []))))
        if wayback.get("timeline"):
            evidence.append(Evidence(source="wayback.timeline", value=wayback.get("timeline")))
        repos = (github.get("repository_search") or {}).get("items", []) if isinstance(github.get("repository_search"), dict) else []
        for repo in repos[:10]:
            evidence.append(Evidence(source="github.repository_lead", value={"full_name": repo.get("full_name"), "html_url": repo.get("html_url"), "updated_at": repo.get("updated_at")}))
        if github.get("code_error"):
            evidence.append(Evidence(source="github.code_search_note", value=github["code_error"]))
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="source.error", value=error))

        source_success_count = sum(1 for value in sources.values() if not value.get("errors"))
        return [
            Finding(
                title="Aggregate technical intelligence",
                description=f"Collected adapter-backed intelligence from {source_success_count}/7 free technical sources: DNS, WHOIS, RDAP, SSL, CRT.SH, Wayback, and GitHub.",
                category=self.category,
                plugin=self.name,
                confidence=0.84 if source_success_count else 0.35,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"sources": sorted(sources), "source_success_count": source_success_count},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
