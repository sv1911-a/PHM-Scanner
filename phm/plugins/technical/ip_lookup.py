"""IP lookup plugin for technical intelligence."""

from __future__ import annotations

import ipaddress
import json
import socket
import urllib.error
import urllib.request
from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    value = value.strip().strip("[]")
    try:
        return ipaddress.ip_address(value)
    except ValueError:
        return None


@registry.register
class IPLookupPlugin(BasePlugin):
    name = "ip_lookup"
    category = Category.TECHNICAL
    description = "Classify IP addresses, perform reverse DNS, and optionally collect public RDAP data."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        ip = _parse_ip(target.value)
        return Detection(ip is not None, 0.99 if ip else 0.0, "valid IP address" if ip else "not an IP address")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        ip = _parse_ip(target.value)
        if ip is None:
            raise ValueError("target is not an IP address")

        reverse = ""
        try:
            reverse = socket.gethostbyaddr(str(ip))[0]
        except Exception:
            pass

        rdap: dict[str, Any] = {}
        # Public RDAP is passive but network-dependent. It is enabled by default
        # for public addresses and gracefully degrades offline.
        rdap_error = ""
        if not (ip.is_private or ip.is_loopback or ip.is_reserved or ip.is_link_local or ip.is_multicast):
            url = f"https://rdap.org/ip/{ip}"
            try:
                with urllib.request.urlopen(url, timeout=float(target.options.get("timeout", 8.0))) as response:  # noqa: S310 - fixed public RDAP endpoint
                    rdap = json.loads(response.read().decode("utf-8", errors="replace"))
            except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError) as exc:
                rdap_error = f"RDAP unavailable: {exc}"

        return {
            "ip": str(ip),
            "version": ip.version,
            "is_global": ip.is_global,
            "is_private": ip.is_private,
            "is_loopback": ip.is_loopback,
            "is_reserved": ip.is_reserved,
            "is_multicast": ip.is_multicast,
            "reverse_dns": reverse,
            "rdap": rdap,
            "rdap_error": rdap_error,
        }

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        evidence = [
            Evidence(source="classification", value={key: raw[key] for key in ["version", "is_global", "is_private", "is_loopback", "is_reserved", "is_multicast"]}),
        ]
        if raw.get("reverse_dns"):
            evidence.append(Evidence(source="reverse_dns", value=raw["reverse_dns"]))
        rdap = raw.get("rdap") or {}
        if rdap:
            for key in ["name", "type", "country", "startAddress", "endAddress"]:
                if rdap.get(key):
                    evidence.append(Evidence(source=f"rdap:{key}", value=rdap[key]))
            if rdap.get("entities"):
                evidence.append(Evidence(source="rdap:entities_count", value=len(rdap["entities"])))
        elif raw.get("rdap_error"):
            evidence.append(Evidence(source="rdap_error", value=raw["rdap_error"]))

        return [
            Finding(
                title="IP address intelligence",
                description="IP address classification, reverse DNS, and public RDAP data where available.",
                category=self.category,
                plugin=self.name,
                confidence=0.92,
                severity=Severity.INFO,
                evidence=evidence,
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
