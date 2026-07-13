"""ASN lookup plugin using Team Cymru's public WHOIS service."""

from __future__ import annotations

import ipaddress
import re
import socket
from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.plugins.technical.dns_lookup import _normalize_domain

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$")


def _resolve_ips(value: str) -> list[str]:
    value = value.strip()
    try:
        return [str(ipaddress.ip_address(value))]
    except ValueError:
        pass
    domain = _normalize_domain(value)
    if not _DOMAIN_RE.match(domain):
        return []
    infos = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    return sorted({info[4][0] for info in infos})


def _query_cymru(ip: str, timeout: float = 8.0) -> dict[str, str]:
    query = f" -v {ip}\n"
    with socket.create_connection(("whois.cymru.com", 43), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(query.encode("ascii"))
        chunks: list[bytes] = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    text = b"".join(chunks).decode("utf-8", errors="replace")
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    if len(lines) < 2:
        return {"ip": ip, "raw": text}
    headers = [part.strip().lower().replace(" ", "_") for part in lines[0].split("|")]
    values = [part.strip() for part in lines[1].split("|")]
    parsed = {headers[index]: values[index] for index in range(min(len(headers), len(values)))}
    parsed["ip"] = ip
    parsed["raw"] = text
    return parsed


@registry.register
class ASNLookupPlugin(BasePlugin):
    name = "asn_lookup"
    category = Category.TECHNICAL
    description = "Map IPs/domains to ASN ownership using public Team Cymru WHOIS."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        try:
            ipaddress.ip_address(value)
            return Detection(True, 0.94, "valid IP address")
        except ValueError:
            domain = _normalize_domain(value)
            ok = bool(_DOMAIN_RE.match(domain))
            return Detection(ok, 0.72 if ok else 0.0, "domain can be resolved to ASN" if ok else "not IP/domain")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        timeout = float(target.options.get("timeout", 8.0))
        ips = _resolve_ips(target.value)
        records: list[dict[str, str]] = []
        errors: list[str] = []
        for ip in ips[:12]:
            try:
                address = ipaddress.ip_address(ip)
                if address.is_private or address.is_loopback or address.is_reserved or address.is_multicast:
                    records.append({"ip": ip, "note": "non-public address; ASN lookup skipped"})
                    continue
                records.append(_query_cymru(ip, timeout))
            except Exception as exc:  # noqa: BLE001 - passive enrichment should degrade gracefully
                errors.append(f"{ip}: {type(exc).__name__}: {exc}")
        return {"target": target.value, "ips": ips, "records": records, "errors": errors}

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        evidence: list[Evidence] = []
        for record in raw.get("records", []):
            if record.get("as"):
                evidence.append(
                    Evidence(
                        source="asn_record",
                        value={
                            "ip": record.get("ip"),
                            "asn": record.get("as"),
                            "prefix": record.get("bgp_prefix"),
                            "cc": record.get("cc"),
                            "registry": record.get("registry"),
                            "allocated": record.get("allocated"),
                            "name": record.get("as_name"),
                        },
                    )
                )
            else:
                evidence.append(Evidence(source="asn_record", value=record))
        for error in raw.get("errors", []):
            evidence.append(Evidence(source="asn_error", value=error))
        return [
            Finding(
                title="ASN ownership intelligence",
                description=f"Collected ASN enrichment for {len(raw.get('records', []))} address(es).",
                category=self.category,
                plugin=self.name,
                confidence=0.82 if evidence else 0.45,
                severity=Severity.INFO,
                evidence=evidence,
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
