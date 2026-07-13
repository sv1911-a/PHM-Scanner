"""ROT13 decoder plugin."""

from __future__ import annotations

import codecs
from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.crypto_engine import TransformCandidate, score_text


@registry.register
class ROT13DecoderPlugin(BasePlugin):
    name = "rot13_decoder"
    category = Category.CRYPTO
    description = "Decode ROT13 substitution text."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        alpha_ratio = sum(1 for ch in value if ch.isalpha() or ch.isspace()) / max(1, len(value))
        ok = len(value) >= 4 and alpha_ratio >= 0.65 and bool(target.options.get("enable_rot13", True))
        # ROT13 is ambiguous, so confidence is intentionally lower than explicit encodings.
        return Detection(ok, 0.42 if ok else 0.0, "alphabetic text may be ROT13" if ok else "not ROT13-like")

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]:
        decoded = codecs.decode(value, "rot_13")
        if decoded == value:
            return []
        return [TransformCandidate(value=decoded, confidence=0.52, metadata={"encoding": "rot13", "text_score": score_text(decoded)})]

    def collect(self, target: TargetContext) -> dict[str, Any]:
        candidates = self.decode_candidates(target.value, target.options)
        return {"candidates": [{"value": c.value, "confidence": c.confidence, "metadata": c.metadata} for c in candidates]}

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        return [
            Finding(
                title="ROT13 decoded candidate",
                description="Decoded input as ROT13. ROT13 is ambiguous and should be analyst-verified.",
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
