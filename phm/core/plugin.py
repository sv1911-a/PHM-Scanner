"""Plugin contracts and base classes."""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any

from phm.core.models import Category, Detection, Finding, PluginResult, TargetContext


class PluginError(RuntimeError):
    """Raised by plugins for recoverable execution failures."""


class BasePlugin(ABC):
    """Base contract every PHM plugin must expose.

    All capabilities in PHM are plugins. Each plugin must implement the
    four public lifecycle methods required by the project specification:

    - detect()
    - collect()
    - analyze()
    - report()
    """

    name: str = "base"
    category: Category
    description: str = ""
    module: str = "general"
    capability: str = "analysis"
    consumes: tuple[str, ...] = ()
    produces: tuple[str, ...] = ()
    passive: bool = True
    default_enabled: bool = True
    local_first: bool = True
    network_required: bool = False
    external_tool_required: bool = False

    @abstractmethod
    def detect(self, target: TargetContext) -> Detection:
        """Return whether this plugin applies to the target."""

    @abstractmethod
    def collect(self, target: TargetContext) -> dict[str, Any]:
        """Collect raw data for the target."""

    @abstractmethod
    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        """Turn raw data into findings."""

    @abstractmethod
    def report(
        self,
        target: TargetContext,
        raw: dict[str, Any],
        findings: list[Finding],
        errors: list[str] | None = None,
    ) -> PluginResult:
        """Create a normalized PluginResult."""

    def run(self, target: TargetContext) -> PluginResult:
        """Execute the plugin lifecycle with error isolation."""

        started_at = datetime.now(timezone.utc).isoformat()
        raw: dict[str, Any] = {}
        findings: list[Finding] = []
        errors: list[str] = []
        status = "ok"
        try:
            raw = self.collect(target)
            findings = self.analyze(target, raw)
        except Exception as exc:  # noqa: BLE001 - plugin isolation boundary
            status = "error"
            errors.append(f"{type(exc).__name__}: {exc}")
        result = self.report(target, raw, findings, errors)
        result.started_at = started_at
        result.completed_at = datetime.now(timezone.utc).isoformat()
        if errors:
            result.status = status
        return result

    def _result(
        self,
        target: TargetContext,
        raw: dict[str, Any],
        findings: list[Finding],
        errors: list[str] | None = None,
    ) -> PluginResult:
        """Convenience implementation for report()."""

        errors = errors or []
        return PluginResult(
            plugin=self.name,
            category=self.category,
            target=target.value,
            status="error" if errors else "ok",
            findings=findings,
            raw=raw,
            errors=errors,
        )
