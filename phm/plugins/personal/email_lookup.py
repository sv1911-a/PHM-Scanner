"""Email lookup plugin for personal intelligence.

This plugin is deliberately conservative: it validates syntax and domain
resolution but does not enumerate private accounts, bypass controls, or query
breach datasets. Future breach integrations should require explicit scope and
API/provider terms review.
"""

from __future__ import annotations

import hashlib
import re
import socket
from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")


@registry.register
class EmailLookupPlugin(BasePlugin):
    name = "email_lookup"
    category = Category.PERSONAL
    description = "Analyze a public email identifier with strict passive safeguards."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        ok = bool(_EMAIL_RE.match(value))
        return Detection(ok, 0.97 if ok else 0.0, "email-like input" if ok else "not an email address")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        email = target.value.strip().lower()
        local, domain = email.rsplit("@", 1)
        domain_addresses: list[str] = []
        resolver_error = ""
        try:
            infos = socket.getaddrinfo(domain, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            domain_addresses = sorted({info[4][0] for info in infos})
        except socket.gaierror as exc:
            resolver_error = str(exc)

        return {
            "email": email,
            "local_part": local,
            "domain": domain,
            "domain_addresses": domain_addresses,
            "domain_resolver_error": resolver_error,
            "sha256": hashlib.sha256(email.encode()).hexdigest(),
            "md5_for_legacy_avatar_lookup": hashlib.md5(email.encode()).hexdigest(),  # noqa: S324 - non-security identifier hash
            "privacy_note": "No breach or social-provider queries were performed by this MVP plugin.",
        }

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        evidence = [
            Evidence(source="email.domain", value=raw["domain"]),
            Evidence(source="email.local_part_length", value=len(raw["local_part"])),
            Evidence(source="email.sha256", value=raw["sha256"]),
            Evidence(source="privacy_note", value=raw["privacy_note"]),
        ]
        if raw.get("domain_addresses"):
            evidence.append(Evidence(source="domain_resolution", value=raw["domain_addresses"]))
            description = "Email syntax is valid and the domain resolves via the system resolver."
            confidence = 0.9
        else:
            evidence.append(Evidence(source="domain_resolver_error", value=raw.get("domain_resolver_error", "")))
            description = "Email syntax is valid, but the domain did not resolve via the system resolver."
            confidence = 0.7
        return [
            Finding(
                title="Passive email identifier analysis",
                description=description,
                category=self.category,
                plugin=self.name,
                confidence=confidence,
                severity=Severity.INFO,
                evidence=evidence,
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
