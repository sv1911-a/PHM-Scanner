"""Base classes for PHM source adapters."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from phm.sources.cache import SourceCache


@dataclass(slots=True)
class SourceMetadata:
    source: str
    cached: bool = False
    errors: list[str] = field(default_factory=list)
    rate: dict[str, str] = field(default_factory=dict)


class SourceAdapter:
    """Base adapter with optional cache helpers."""

    source_name = "base"

    def __init__(
        self,
        timeout: float = 8.0,
        use_cache: bool = False,
        cache_ttl: int = 3600,
        cache_path: str = "investigations/source_cache.db",
    ) -> None:
        self.timeout = timeout
        self.use_cache = use_cache
        self.cache_ttl = cache_ttl
        self.cache = SourceCache(cache_path) if use_cache else None

    def cache_get(self, key: str) -> Any | None:
        if not self.cache:
            return None
        value = self.cache.get(self.source_name, key)
        if isinstance(value, dict):
            value.setdefault("metadata", {})
            value["metadata"]["cached"] = True
        return value

    def cache_set(self, key: str, value: Any) -> None:
        if self.cache:
            self.cache.set(self.source_name, key, value, self.cache_ttl)
