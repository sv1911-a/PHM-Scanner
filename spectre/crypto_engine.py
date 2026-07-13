"""Smart cryptography/encoding engine.

The engine is deliberately deterministic: no AI, no model calls. It performs
bounded graph traversal over registered crypto transform plugins, ranks decode
candidates with confidence scoring, and returns a decoding graph for reporting.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol

from spectre.core.artifacts import artifacts_from_report
from spectre.core.models import Category, Evidence, Finding, InvestigationReport, PluginResult, Severity, TargetContext
from spectre.core.recommendations import build_next_steps
from spectre.core.registry import registry


@dataclass(slots=True)
class TransformCandidate:
    """One possible crypto transform output."""

    value: str
    confidence: float
    metadata: dict[str, Any] = field(default_factory=dict)


class CryptoTransformPlugin(Protocol):
    """Protocol implemented by crypto plugins used by SmartCryptoEngine."""

    name: str

    def detect(self, target: TargetContext): ...

    def decode_candidates(self, value: str, options: dict[str, Any] | None = None) -> list[TransformCandidate]: ...


@dataclass(slots=True)
class DecodeNode:
    id: int
    value: str
    path: list[str]
    confidence: float
    text_score: float
    parent: int | None = None
    transform: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


_COMMON_WORDS = {
    "the",
    "and",
    "that",
    "have",
    "for",
    "not",
    "with",
    "you",
    "this",
    "but",
    "flag",
    "ctf",
    "password",
    "secret",
    "token",
    "hello",
    "world",
}


def score_text(value: str) -> float:
    """Estimate whether decoded output looks like meaningful plaintext."""

    if not value:
        return 0.0
    printable = sum(1 for ch in value if ch.isprintable() or ch in "\r\n\t") / len(value)
    replacement_penalty = min(0.35, value.count("\ufffd") / max(1, len(value)))
    alpha_space = sum(1 for ch in value if ch.isalpha() or ch.isspace() or ch in "{}[]()_-:;,.!?@#$%&*/+=<>\"'") / len(value)
    words = [word.strip("{}[]()_-:;,.!?@#$%&*/+=<>\"'").lower() for word in value.split()]
    word_hits = sum(1 for word in words if word in _COMMON_WORDS)
    word_score = min(1.0, word_hits / 3) if words else 0.0
    length_bonus = min(0.12, len(value) / 500)
    score = 0.55 * printable + 0.25 * alpha_space + 0.15 * word_score + length_bonus - replacement_penalty
    return max(0.0, min(1.0, score))


def _node_confidence(text_score: float, path: list[str], candidate_confidences: list[float]) -> float:
    if not path:
        return 0.25 * text_score
    avg_transform = sum(candidate_confidences) / max(1, len(candidate_confidences))
    depth_reward = min(0.16, 0.04 * len(path))
    return max(0.0, min(1.0, 0.52 * text_score + 0.36 * avg_transform + depth_reward))


class SmartCryptoEngine:
    """Bounded beam-search decoder over registered crypto plugins."""

    def __init__(self, max_depth: int = 4, beam_width: int = 8) -> None:
        self.max_depth = max_depth
        self.beam_width = beam_width

    def run(self, input_value: str, options: dict[str, Any] | None = None) -> InvestigationReport:
        options = options or {}
        max_depth = int(options.get("max_depth", self.max_depth))
        beam_width = int(options.get("beam_width", self.beam_width))
        plugins = [plugin for plugin in registry.by_category(Category.CRYPTO) if hasattr(plugin, "decode_candidates")]

        graph: list[DecodeNode] = []
        root_score = score_text(input_value)
        root = DecodeNode(id=0, value=input_value, path=[], confidence=_node_confidence(root_score, [], []), text_score=root_score)
        graph.append(root)
        frontier = [root]
        best = root
        seen = {input_value}
        candidate_conf_by_node: dict[int, list[float]] = {0: []}

        next_id = 1
        for _depth in range(max_depth):
            expanded: list[DecodeNode] = []
            for node in frontier:
                context = TargetContext(value=node.value, category=Category.CRYPTO, options=options)
                for plugin in plugins:
                    detection = plugin.detect(context)
                    if not detection.applicable:
                        continue
                    try:
                        candidates = plugin.decode_candidates(node.value, options)
                    except Exception:
                        continue
                    for candidate in candidates:
                        value = candidate.value
                        if not value or value == node.value or value in seen:
                            continue
                        seen.add(value)
                        path = [*node.path, plugin.name]
                        inherited_confidences = candidate_conf_by_node.get(node.id, [])
                        candidate_confidences = [*inherited_confidences, candidate.confidence * detection.confidence]
                        text_score = score_text(value)
                        confidence = _node_confidence(text_score, path, candidate_confidences)
                        child = DecodeNode(
                            id=next_id,
                            value=value,
                            path=path,
                            parent=node.id,
                            transform=plugin.name,
                            text_score=text_score,
                            confidence=confidence,
                            metadata=candidate.metadata,
                        )
                        candidate_conf_by_node[next_id] = candidate_confidences
                        next_id += 1
                        graph.append(child)
                        expanded.append(child)
                        if child.confidence > best.confidence:
                            best = child
            if not expanded:
                break
            expanded.sort(key=lambda item: item.confidence, reverse=True)
            frontier = expanded[:beam_width]
            # Stop early when the best node is highly readable and the most recent
            # layer failed to produce an even better candidate.
            if best.confidence >= float(options.get("stop_confidence", 0.93)):
                break

        graph_data = [
            {
                "id": node.id,
                "parent": node.parent,
                "transform": node.transform,
                "path": node.path,
                "confidence": node.confidence,
                "text_score": node.text_score,
                "preview": node.value[:240],
                "metadata": node.metadata,
            }
            for node in graph
        ]

        finding = Finding(
            title="Smart crypto decode candidate",
            description="Highest-confidence decoding path found by deterministic graph traversal.",
            category=Category.CRYPTO,
            plugin="smart_crypto_engine",
            confidence=best.confidence,
            severity=Severity.INFO,
            evidence=[
                Evidence(source="decode_path", value=" -> ".join(best.path) if best.path else "none"),
                Evidence(source="plaintext_candidate", value=best.value),
                Evidence(source="graph_nodes", value=len(graph)),
            ],
            metadata={"best_node_id": best.id, "graph": graph_data},
        )
        result = PluginResult(
            plugin="smart_crypto_engine",
            category=Category.CRYPTO,
            target="<crypto-input>",
            status="ok",
            findings=[finding],
            raw={"best": {"value": best.value, "path": best.path, "confidence": best.confidence}, "graph": graph_data},
        )
        report = InvestigationReport(target="<crypto-input>", category=Category.CRYPTO, results=[result], metadata={"engine": "beam_search"})
        report.metadata["artifacts"] = artifacts_from_report(report)
        report.metadata["next_steps"] = build_next_steps(report)
        return report
