"""HTTP technology fingerprinting plugin."""

from __future__ import annotations

import re
import urllib.error
import urllib.request
from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.plugins.technical.dns_lookup import _normalize_domain

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$")

SIGNATURES: dict[str, list[re.Pattern[str]]] = {
    "WordPress": [re.compile(r"wp-content|wp-includes", re.I), re.compile(r"<meta name=['\"]generator['\"] content=['\"]WordPress", re.I)],
    "Drupal": [re.compile(r"Drupal.settings|/sites/default/", re.I)],
    "Joomla": [re.compile(r"/media/system/js/|content=['\"]Joomla!", re.I)],
    "React": [re.compile(r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__|react(?:\.production)?\.min\.js", re.I)],
    "Next.js": [re.compile(r"/_next/static/|__NEXT_DATA__", re.I)],
    "Angular": [re.compile(r"ng-version|ng-app|angular(?:\.min)?\.js", re.I)],
    "Vue.js": [re.compile(r"data-v-|vue(?:\.runtime)?(?:\.global)?(?:\.prod)?\.js", re.I)],
    "jQuery": [re.compile(r"jquery[-.]\d|jquery\.min\.js", re.I)],
    "Bootstrap": [re.compile(r"bootstrap(?:\.bundle)?(?:\.min)?\.(?:css|js)", re.I)],
    "Cloudflare": [re.compile(r"cloudflare", re.I)],
    "Google Analytics": [re.compile(r"googletagmanager\.com|google-analytics\.com|gtag\(", re.I)],
}

HEADER_HINTS = {
    "cf-ray": "Cloudflare",
    "x-vercel-id": "Vercel",
    "x-nextjs-cache": "Next.js",
}

SAFE_HEADER_VALUE_RE = re.compile(r"^[A-Za-z0-9 ._+:/()-]{1,80}$")
SAFE_POWERED_BY = {
    "php": "PHP",
    "express": "Express",
    "asp.net": "ASP.NET",
    "next.js": "Next.js",
}
SAFE_SERVER_NAMES = {
    "nginx": "nginx",
    "apache": "Apache",
    "cloudflare": "Cloudflare",
    "openresty": "OpenResty",
    "microsoft-iis": "Microsoft IIS",
    "iis": "Microsoft IIS",
    "envoy": "Envoy",
    "caddy": "Caddy",
}


@registry.register
class TechnologyFingerprintPlugin(BasePlugin):
    name = "technology_fingerprint"
    category = Category.TECHNICAL
    description = "Fingerprint web technologies from HTTP headers and public HTML signatures."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        if value.startswith(("http://", "https://")):
            return Detection(True, 0.9, "URL target")
        domain = _normalize_domain(value)
        ok = bool(_DOMAIN_RE.match(domain))
        return Detection(ok, 0.75 if ok else 0.0, "domain-like web target" if ok else "not a web target")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        value = target.value.strip()
        urls = [value] if value.startswith(("http://", "https://")) else [f"https://{_normalize_domain(value)}", f"http://{_normalize_domain(value)}"]
        timeout = float(target.options.get("timeout", 8.0))
        last_error = ""
        for url in urls:
            request = urllib.request.Request(url, headers={"User-Agent": "SPECTRE-OSINT/0.1"})
            try:
                with urllib.request.urlopen(request, timeout=timeout) as response:  # noqa: S310 - analyst-provided target
                    body = response.read(300_000).decode("utf-8", errors="replace")
                    headers = {key.lower(): value for key, value in response.headers.items()}
                    return {
                        "url": response.geturl(),
                        "status": response.status,
                        "headers": headers,
                        "html_excerpt": body[:120_000],
                        "content_length_sampled": len(body),
                    }
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                last_error = f"{url}: {exc}"
        raise RuntimeError(f"HTTP fingerprinting failed: {last_error}")

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        headers = raw.get("headers", {})
        html = raw.get("html_excerpt", "")
        technologies: dict[str, set[str]] = {}

        server_header = headers.get("server", "")
        safe_server = self._safe_server_technology(server_header)
        if safe_server:
            technologies.setdefault(safe_server, set()).add("safe_server_header")

        powered_by = headers.get("x-powered-by", "")
        safe_powered = self._safe_powered_by(powered_by)
        if safe_powered:
            technologies.setdefault(safe_powered, set()).add("safe_x_powered_by_header")

        generator = headers.get("x-generator", "")
        if generator and SAFE_HEADER_VALUE_RE.match(generator):
            technologies.setdefault(generator.strip(), set()).add("safe_x_generator_header")

        for header, label in HEADER_HINTS.items():
            if headers.get(header):
                technologies.setdefault(label, set()).add(f"header:{header}")

        combined = "\n".join([html, "\n".join(f"{k}: {v}" for k, v in headers.items() if k != "server")])
        for tech, patterns in SIGNATURES.items():
            for pattern in patterns:
                if pattern.search(combined):
                    technologies.setdefault(tech, set()).add(f"signature:{pattern.pattern[:60]}")

        evidence = [Evidence(source="http.status", value=raw.get("status")), Evidence(source="http.url", value=raw.get("url"))]
        if server_header:
            evidence.append(Evidence(source="http.server_header", value=server_header, metadata={"interpreted_as_technology": bool(safe_server)}))
        for tech, reasons in sorted(technologies.items()):
            evidence.append(Evidence(source="technology", value={"name": tech, "reasons": sorted(reasons)}))

        return [
            Finding(
                title="Web technology fingerprint",
                description=f"Detected {len(technologies)} technology/header signal(s) from public HTTP response data.",
                category=self.category,
                plugin=self.name,
                confidence=0.78 if technologies else 0.5,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"technologies": sorted(technologies)},
            )
        ]

    @staticmethod
    def _safe_server_technology(value: str) -> str:
        if not value or not SAFE_HEADER_VALUE_RE.match(value):
            return ""
        lowered = value.lower()
        for token, label in SAFE_SERVER_NAMES.items():
            if token in lowered:
                return label
        return ""

    @staticmethod
    def _safe_powered_by(value: str) -> str:
        if not value or not SAFE_HEADER_VALUE_RE.match(value):
            return ""
        lowered = value.lower()
        for token, label in SAFE_POWERED_BY.items():
            if token in lowered:
                return label
        return ""

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
