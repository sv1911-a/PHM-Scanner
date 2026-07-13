"""Simple target auto-detection for `spectre analyze`.

The goal is user-facing simplicity: one command should choose a sensible first
analysis path without making the user understand internal modules.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from spectre.core.models import Category
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.github.adapter import parse_repo_slug

_EMAIL_RE = re.compile(r"^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@([A-Za-z0-9-]+\.)+[A-Za-z]{2,63}$")
_HASH_RE = re.compile(r"^(?:[A-Fa-f0-9]{32}|[A-Fa-f0-9]{40}|[A-Fa-f0-9]{56}|[A-Fa-f0-9]{64}|[A-Fa-f0-9]{96}|[A-Fa-f0-9]{128})$")
_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,39}$")
_BASE64ISH_RE = re.compile(r"^[A-Za-z0-9+/\s_-]+={0,2}$")
_HEXISH_RE = re.compile(r"^(?:0x)?[0-9A-Fa-f\s:.-]{4,}$")


@dataclass(slots=True)
class AnalysisPlan:
    """A small plan for automatically running an analysis."""

    target: str
    target_type: str
    category: Category
    plugins: list[str] | None = None
    use_crypto_engine: bool = False
    confidence: float = 0.0
    reason: str = ""
    notes: list[str] = field(default_factory=list)


def plan_analysis(target: str) -> AnalysisPlan:
    """Return a sensible default analysis plan for a target."""

    raw = target.strip()
    path = Path(raw)
    if path.exists() and path.is_file():
        return AnalysisPlan(
            target=raw,
            target_type="file",
            category=Category.FILE,
            plugins=["file_analysis"],
            confidence=0.99,
            reason="local file path exists",
        )

    if parse_repo_slug(raw):
        return AnalysisPlan(
            target=raw,
            target_type="github_repository",
            category=Category.TECHNICAL,
            plugins=["github_repo_analysis"],
            confidence=0.96,
            reason="GitHub repository URL or owner/repo slug",
        )

    if raw.startswith(("http://", "https://")):
        host = normalize_domain(raw)
        plugins = ["technology_fingerprint"]
        if is_domain(host):
            plugins = ["dns_lookup", "rdap_lookup", "ssl_lookup", "technology_fingerprint"]
        return AnalysisPlan(
            target=raw,
            target_type="url",
            category=Category.TECHNICAL,
            plugins=plugins,
            confidence=0.93,
            reason="HTTP/HTTPS URL",
        )

    try:
        ipaddress.ip_address(raw.strip("[]"))
        return AnalysisPlan(
            target=raw,
            target_type="ip_address",
            category=Category.TECHNICAL,
            plugins=None,
            confidence=0.96,
            reason="valid IP address",
        )
    except ValueError:
        pass

    if _EMAIL_RE.fullmatch(raw):
        return AnalysisPlan(
            target=raw,
            target_type="email",
            category=Category.PERSONAL,
            plugins=["email_lookup"],
            confidence=0.95,
            reason="email address pattern",
        )

    if _HASH_RE.fullmatch(raw):
        return AnalysisPlan(
            target=raw,
            target_type="hash",
            category=Category.CRYPTO,
            plugins=["hash_identifier"],
            confidence=0.92,
            reason="known hex digest length",
        )

    if is_domain(raw):
        return AnalysisPlan(
            target=raw,
            target_type="domain",
            category=Category.TECHNICAL,
            plugins=None,
            confidence=0.9,
            reason="domain name pattern",
        )

    if _looks_encoded(raw):
        return AnalysisPlan(
            target=raw,
            target_type="encoded_or_ciphertext",
            category=Category.CRYPTO,
            plugins=None,
            use_crypto_engine=True,
            confidence=0.7,
            reason="encoded/ciphertext-like input",
        )

    if _USERNAME_RE.fullmatch(raw):
        return AnalysisPlan(
            target=raw,
            target_type="username",
            category=Category.PERSONAL,
            plugins=["username_lookup", "github_user_lookup"],
            confidence=0.65,
            reason="username-like input",
            notes=["Username detection is ambiguous. Results are leads, not proof of identity."],
        )

    return AnalysisPlan(
        target=raw,
        target_type="text",
        category=Category.CRYPTO,
        plugins=None,
        use_crypto_engine=True,
        confidence=0.35,
        reason="fallback to local crypto/text analysis",
    )


def _looks_encoded(value: str) -> bool:
    compact = re.sub(r"\s+", "", value.strip())
    if len(compact) < 4:
        return False
    if _HEXISH_RE.fullmatch(value) and len(re.sub(r"[^0-9A-Fa-f]", "", value)) % 2 == 0:
        return True
    if len(compact) % 4 in {0, 2, 3} and _BASE64ISH_RE.fullmatch(value):
        # Avoid treating normal short words as base64.
        return any(ch in value for ch in "=+/ _-") or len(compact) >= 12
    if "%" in value or "&quot;" in value or "&#" in value:
        return True
    return False
