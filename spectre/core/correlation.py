"""Lightweight relationship graph correlation for SPECTRE reports.

This module is intentionally simple: it extracts common observables from plugin
findings and raw data, then links plugins/findings to the entities they mention.
It is the first step toward a richer graph database/correlation layer.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from spectre.core.models import InvestigationReport, to_primitive

_DOMAIN_RE = re.compile(r"\b(?:[a-zA-Z0-9-]{1,63}\.)+[a-zA-Z]{2,63}\b")
_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
_URL_RE = re.compile(r"https?://[^\s'\"<>]+")
_GITHUB_REPO_RE = re.compile(r"github\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)")
_EMAIL_RE = re.compile(r"\b[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,63}\b")


@dataclass(slots=True)
class GraphNode:
    id: str
    type: str
    label: str
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class GraphEdge:
    source: str
    target: str
    relationship: str
    confidence: float = 1.0
    metadata: dict[str, Any] = field(default_factory=dict)


def _add_node(nodes: dict[str, GraphNode], node_type: str, label: str, metadata: dict[str, Any] | None = None) -> str:
    node_id = f"{node_type}:{label}".lower()
    if node_id not in nodes:
        nodes[node_id] = GraphNode(id=node_id, type=node_type, label=label, metadata=metadata or {})
    elif metadata:
        nodes[node_id].metadata.update(metadata)
    return node_id


def _add_edge(edges: dict[tuple[str, str, str], GraphEdge], source: str, target: str, relationship: str, confidence: float = 1.0, metadata: dict[str, Any] | None = None) -> None:
    key = (source, target, relationship)
    if key not in edges:
        edges[key] = GraphEdge(source=source, target=target, relationship=relationship, confidence=confidence, metadata=metadata or {})


def _extract_entities(value: Any) -> list[tuple[str, str]]:
    text = str(value)
    entities: list[tuple[str, str]] = []
    for url in _URL_RE.findall(text):
        entities.append(("url", url.rstrip(".,)];")))
    for repo in _GITHUB_REPO_RE.findall(text):
        entities.append(("github_repo", repo.rstrip(".,)];")))
    for email in _EMAIL_RE.findall(text):
        entities.append(("email", email.lower()))
    for ip in _IP_RE.findall(text):
        entities.append(("ip", ip))
    for domain in _DOMAIN_RE.findall(text):
        # Avoid double-counting GitHub's host as a target domain in every URL.
        if domain.lower() not in {"github.com", "api.github.com", "www.github.com"}:
            entities.append(("domain", domain.lower()))
    # Preserve order but deduplicate.
    seen: set[tuple[str, str]] = set()
    unique: list[tuple[str, str]] = []
    for entity in entities:
        if entity not in seen:
            seen.add(entity)
            unique.append(entity)
    return unique


def build_relationship_graph(report: InvestigationReport) -> dict[str, Any]:
    """Build a serializable relationship graph from an investigation report."""

    nodes: dict[str, GraphNode] = {}
    edges: dict[tuple[str, str, str], GraphEdge] = {}

    target_id = _add_node(nodes, "target", report.target, {"category": report.category.value})

    for result in report.results:
        plugin_id = _add_node(nodes, "plugin", result.plugin, {"category": result.category.value, "status": result.status})
        _add_edge(edges, target_id, plugin_id, "processed_by")

        for finding_index, finding in enumerate(result.findings):
            finding_id = _add_node(
                nodes,
                "finding",
                f"{result.plugin}:{finding_index}:{finding.title}",
                {"confidence": finding.confidence, "severity": finding.severity.value},
            )
            _add_edge(edges, plugin_id, finding_id, "produced", finding.confidence)

            for evidence in finding.evidence:
                for entity_type, label in _extract_entities(evidence.value):
                    entity_id = _add_node(nodes, entity_type, label)
                    _add_edge(edges, finding_id, entity_id, "mentions", finding.confidence, {"source": evidence.source})
                    _add_edge(edges, target_id, entity_id, "related_to", finding.confidence, {"via": result.plugin})

        # Raw data often contains entities that are not duplicated in concise findings.
        raw = to_primitive(result.raw)
        for entity_type, label in _extract_entities(raw):
            entity_id = _add_node(nodes, entity_type, label)
            _add_edge(edges, plugin_id, entity_id, "observed", 0.75)
            _add_edge(edges, target_id, entity_id, "related_to", 0.75, {"via": result.plugin})

    return {
        "nodes": [to_primitive(node) for node in nodes.values()],
        "edges": [to_primitive(edge) for edge in edges.values()],
        "summary": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "entity_counts": _entity_counts(nodes.values()),
        },
    }


def _entity_counts(nodes) -> dict[str, int]:
    counts: dict[str, int] = {}
    for node in nodes:
        counts[node.type] = counts.get(node.type, 0) + 1
    return dict(sorted(counts.items()))
