"""Hex decoder plugin."""

from __future__ import annotations

import binascii
import re
from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.crypto_engine import TransformCandidate, score_text

_HEX_RE = re.compile(r"^(?:0x)?[0-9a-fA-F\s:.-]+$")


def _clean_hex(value: str) -> str:
    clean = value.strip()
    if clean.lower().startswith("0x"):
        clean = clean[2:]
    return re.sub(r"[\s:.-]+", "", clean)


@registry.register
class HexDecoderPlugin(BasePlugin):
    name = "hex_decoder"
    category = Category.CRYPTO
    description = "Decode hexadecimal encoded bytes."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        clean = _clean_hex(target.value)
        ok = len(clean) >= 2 and len(clean) % 2 == 0 and bool(_HEX_RE.match(target.value))
        if not ok:
            return Detection(False, 0.0, "not hex-like")
        try:
            binascii.unhexlify(clean)
        except binascii.Error:
            return Detection(False, 0.0, "hex decoder rejected input")
        return Detection(True, 0.92, "even-length hex alphabet")

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]:
        clean = _clean_hex(value)
        decoded = binascii.unhexlify(clean).decode("utf-8", errors="replace")
        return [TransformCandidate(value=decoded, confidence=0.93, metadata={"encoding": "hex", "bytes": len(clean) // 2, "text_score": score_text(decoded)})]

    def collect(self, target: TargetContext) -> dict[str, Any]:
        candidates = self.decode_candidates(target.value, target.options)
        return {"candidates": [{"value": c.value, "confidence": c.confidence, "metadata": c.metadata} for c in candidates]}

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        return [
            Finding(
                title="Hex decoded candidate",
                description="Decoded input as hexadecimal bytes.",
                category=self.category,
                plugin=self.name,
                confidence=candidate["confidence"],
                severity=Severity.INFO,
                evidence=[Evidence(source="decoded", value=candidate["value"])],
                metadata=candidate.get("metadata", {}),
            )
            for candidate in raw.get("candidates", [])
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
