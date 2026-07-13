"""URL decoder plugin."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import unquote_plus

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.crypto_engine import TransformCandidate, score_text

_URL_ESC_RE = re.compile(r"%[0-9a-fA-F]{2}|\+")


@registry.register
class URLDecoderPlugin(BasePlugin):
    name = "url_decoder"
    category = Category.CRYPTO
    description = "Decode URL percent-encoding and plus-as-space encoding."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        ok = bool(_URL_ESC_RE.search(target.value))
        return Detection(ok, 0.86 if ok else 0.0, "URL escape sequences present" if ok else "no URL escapes")

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]:
        decoded = unquote_plus(value)
        if decoded == value:
            return []
        return [TransformCandidate(value=decoded, confidence=0.88, metadata={"encoding": "url", "text_score": score_text(decoded)})]

    def collect(self, target: TargetContext) -> dict[str, Any]:
        candidates = self.decode_candidates(target.value, target.options)
        return {"candidates": [{"value": c.value, "confidence": c.confidence, "metadata": c.metadata} for c in candidates]}

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        return [
            Finding(
                title="URL decoded candidate",
                description="Decoded URL-encoded input.",
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
