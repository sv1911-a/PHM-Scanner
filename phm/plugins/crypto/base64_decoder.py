"""Base64 decoder plugin."""

from __future__ import annotations

import base64
import binascii
import re
from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.crypto_engine import TransformCandidate, score_text

_B64_RE = re.compile(r"^[A-Za-z0-9+/\s_-]+={0,2}$")


def _decode_bytes(value: str) -> bytes:
    compact = re.sub(r"\s+", "", value.strip())
    # Accept both standard and URL-safe alphabets.
    padded = compact + "=" * ((4 - len(compact) % 4) % 4)
    return base64.b64decode(padded, validate=False)


@registry.register
class Base64DecoderPlugin(BasePlugin):
    name = "base64_decoder"
    category = Category.CRYPTO
    description = "Decode standard or URL-safe Base64 data."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        compact = re.sub(r"\s+", "", value)
        ok = len(compact) >= 4 and len(compact) % 4 in {0, 2, 3} and bool(_B64_RE.match(value))
        if not ok:
            return Detection(False, 0.0, "not base64-like")
        try:
            decoded = _decode_bytes(value)
            if not decoded:
                return Detection(False, 0.0, "empty decode")
        except (binascii.Error, ValueError):
            return Detection(False, 0.0, "base64 decoder rejected input")
        return Detection(True, 0.88, "base64-like alphabet and decodable padding")

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]:
        decoded = _decode_bytes(value).decode("utf-8", errors="replace")
        return [TransformCandidate(value=decoded, confidence=0.9, metadata={"encoding": "base64", "text_score": score_text(decoded)})]

    def collect(self, target: TargetContext) -> dict[str, Any]:
        candidates = self.decode_candidates(target.value, target.options)
        return {"candidates": [{"value": c.value, "confidence": c.confidence, "metadata": c.metadata} for c in candidates]}

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        for candidate in raw.get("candidates", []):
            findings.append(
                Finding(
                    title="Base64 decoded candidate",
                    description="Decoded input as Base64.",
                    category=self.category,
                    plugin=self.name,
                    confidence=candidate["confidence"],
                    severity=Severity.INFO,
                    evidence=[Evidence(source="decoded", value=candidate["value"])],
                    metadata=candidate.get("metadata", {}),
                )
            )
        return findings

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
