"""Single-byte XOR decoder plugin for CTF-style crypto workflows."""

from __future__ import annotations

from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.crypto_engine import TransformCandidate, score_text


def _to_bytes(value: str) -> bytes:
    return value.encode("latin-1", errors="ignore")


def _has_non_printable(value: str) -> bool:
    return any(not (ch.isprintable() or ch in "\r\n\t") for ch in value)


@registry.register
class XORDecoderPlugin(BasePlugin):
    name = "xor_decoder"
    category = Category.CRYPTO
    description = "Brute-force single-byte XOR and rank readable candidates."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value
        force = bool(target.options.get("enable_xor") or target.options.get("force_xor"))
        ok = force or (len(value) >= 3 and _has_non_printable(value))
        return Detection(ok, 0.58 if ok else 0.0, "single-byte XOR candidate" if ok else "not XOR-like")

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]:
        options = options or {}
        data = _to_bytes(value)
        candidates: list[TransformCandidate] = []
        if not data:
            return candidates
        for key in range(1, 256):
            decoded_bytes = bytes(byte ^ key for byte in data)
            decoded = decoded_bytes.decode("utf-8", errors="replace")
            text_score = score_text(decoded)
            # Avoid flooding the graph with low-quality XOR noise.
            if text_score >= float(options.get("xor_min_text_score", 0.72)):
                candidates.append(
                    TransformCandidate(
                        value=decoded,
                        confidence=min(0.88, 0.45 + 0.45 * text_score),
                        metadata={"encoding": "xor_single_byte", "key_decimal": key, "key_hex": hex(key), "text_score": text_score},
                    )
                )
        candidates.sort(key=lambda item: item.confidence, reverse=True)
        return candidates[: int(options.get("xor_candidates", 5))]

    def collect(self, target: TargetContext) -> dict[str, Any]:
        candidates = self.decode_candidates(target.value, target.options)
        return {"candidates": [{"value": c.value, "confidence": c.confidence, "metadata": c.metadata} for c in candidates]}

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        return [
            Finding(
                title="Single-byte XOR decoded candidate",
                description="Candidate plaintext from brute-forced single-byte XOR.",
                category=self.category,
                plugin=self.name,
                confidence=candidate["confidence"],
                severity=Severity.INFO,
                evidence=[Evidence(source="decoded", value=candidate["value"]), Evidence(source="xor_key", value=candidate.get("metadata", {}))],
                metadata=candidate.get("metadata", {}),
            )
            for candidate in raw.get("candidates", [])
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
