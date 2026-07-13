"""Shared data models for PHM.

PHM is a self-contained cybersecurity analysis framework. These models are
kept intentionally small and deterministic so every module can produce
structured findings, evidence, artifacts, and reports through one interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Mapping


class Category(str, Enum):
    """Top-level PHM capability categories.

    Existing OSINT-oriented categories remain for compatibility, but new modules
    should generally be capability-oriented: file, binary, web, network, DNS,
    image, archive, metadata, document, identity, and crypto.
    """

    TECHNICAL = "technical"
    ORGANIZATION = "organization"
    PERSONAL = "personal"
    IDENTITY = "identity"
    DNS = "dns"
    NETWORK = "network"
    WEB = "web"
    FILE = "file"
    BINARY = "binary"
    IMAGE = "image"
    DOCUMENT = "document"
    ARCHIVE = "archive"
    METADATA = "metadata"
    GEOSPATIAL = "geospatial"
    MEDIA = "media"
    HISTORICAL = "historical"
    CRYPTO = "crypto"


class Severity(str, Enum):
    """Severity-like classification for reporting signal strength.

    PHM is not only a vulnerability scanner; this is used as a generic
    reporting label for analyst attention.
    """

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass(slots=True)
class Detection:
    """Result of plugin applicability detection."""

    applicable: bool
    confidence: float = 0.0
    reason: str = ""


@dataclass(slots=True)
class TargetContext:
    """Normalized input passed to plugins."""

    value: str
    category: Category
    options: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Evidence:
    """Supporting evidence for a finding."""

    source: str
    value: Any
    collected_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class Finding:
    """Analyst-facing result from a plugin."""

    title: str
    description: str
    category: Category
    plugin: str
    confidence: float = 1.0
    severity: Severity = Severity.INFO
    evidence: list[Evidence] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(slots=True)
class PluginResult:
    """Full output of one plugin execution."""

    plugin: str
    category: Category
    target: str
    status: str
    findings: list[Finding] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict)
    errors: list[str] = field(default_factory=list)
    started_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    completed_at: str | None = None


@dataclass(slots=True)
class InvestigationReport:
    """Aggregated report for a PHM run."""

    target: str
    category: Category
    results: list[PluginResult]
    generated_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    metadata: dict[str, Any] = field(default_factory=dict)


def to_primitive(obj: Any) -> Any:
    """Convert dataclasses/enums into JSON-serializable primitives."""

    if isinstance(obj, Enum):
        return obj.value
    if hasattr(obj, "__dataclass_fields__"):
        return {key: to_primitive(value) for key, value in asdict(obj).items()}
    if isinstance(obj, Mapping):
        return {str(key): to_primitive(value) for key, value in obj.items()}
    if isinstance(obj, list | tuple | set):
        return [to_primitive(value) for value in obj]
    return obj
