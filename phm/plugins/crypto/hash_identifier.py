"""Hash identification plugin.

This is deterministic hash-format identification, not cracking. It identifies
likely hash families from length, alphabet, and known modular-crypt prefixes.
"""

from __future__ import annotations

import re
from typing import Any

from phm.core.artifacts import hash_type
from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry

_HEX_RE = re.compile(r"^[A-Fa-f0-9]+$")
_PREFIX_PATTERNS = [
    ("bcrypt", re.compile(r"^\$2[aby]\$\d{2}\$[./A-Za-z0-9]{53}$")),
    ("argon2", re.compile(r"^\$argon2(?:id|i|d)\$")),
    ("sha512crypt", re.compile(r"^\$6\$")),
    ("sha256crypt", re.compile(r"^\$5\$")),
    ("md5crypt", re.compile(r"^\$1\$")),
    ("phpass/wordpress", re.compile(r"^\$P\$[./A-Za-z0-9]{31}$")),
]
_LENGTH_CANDIDATES = {
    32: ["MD5", "NTLM", "MD4", "MD2"],
    40: ["SHA-1", "RIPEMD-160", "MySQL SHA1"],
    56: ["SHA-224"],
    64: ["SHA-256", "SHA3-256", "BLAKE2s-256"],
    96: ["SHA-384", "SHA3-384"],
    128: ["SHA-512", "SHA3-512", "BLAKE2b-512"],
}


@registry.register
class HashIdentifierPlugin(BasePlugin):
    name = "hash_identifier"
    category = Category.CRYPTO
    description = "Identify likely hash formats from deterministic signatures."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        if any(pattern.search(value) for _, pattern in _PREFIX_PATTERNS):
            return Detection(True, 0.96, "known hash prefix")
        ok = bool(_HEX_RE.fullmatch(value)) and len(value) in _LENGTH_CANDIDATES
        return Detection(ok, 0.9 if ok else 0.0, "hex digest length match" if ok else "not a known hash format")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        value = target.value.strip()
        candidates: list[dict[str, Any]] = []
        for name, pattern in _PREFIX_PATTERNS:
            if pattern.search(value):
                candidates.append({"name": name, "confidence": 0.96, "reason": "known modular crypt/token prefix"})
        if _HEX_RE.fullmatch(value) and len(value) in _LENGTH_CANDIDATES:
            for index, name in enumerate(_LENGTH_CANDIDATES[len(value)]):
                candidates.append({"name": name, "confidence": max(0.55, 0.9 - index * 0.08), "reason": f"{len(value)} hex characters"})
        return {"hash": value, "length": len(value), "family": hash_type(value), "candidates": candidates}

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        candidates = raw.get("candidates", [])
        evidence = [
            Evidence(source="hash.length", value=raw.get("length")),
            Evidence(source="hash.family", value=raw.get("family")),
        ]
        for candidate in candidates:
            evidence.append(Evidence(source="hash.candidate", value=candidate))
        return [
            Finding(
                title="Hash identification candidates",
                description=f"Identified {len(candidates)} possible hash format candidate(s). This does not crack or verify the hash.",
                category=self.category,
                plugin=self.name,
                confidence=candidates[0]["confidence"] if candidates else 0.35,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"candidates": candidates},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
