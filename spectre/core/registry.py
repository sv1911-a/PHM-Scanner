"""Plugin registration and discovery."""

from __future__ import annotations

import importlib
import pkgutil
from collections import defaultdict
from typing import Iterable

import spectre.plugins
from spectre.core.models import Category, Detection, TargetContext
from spectre.core.plugin import BasePlugin


class PluginRegistry:
    """Runtime registry for built-in and third-party plugins."""

    def __init__(self) -> None:
        self._plugin_classes: dict[str, type[BasePlugin]] = {}
        self._instances: dict[str, BasePlugin] = {}
        self._discovered = False

    def register(self, plugin_cls: type[BasePlugin]) -> type[BasePlugin]:
        """Register a plugin class.

        This method is intentionally decorator-friendly:

            @registry.register
            class DNSLookupPlugin(BasePlugin): ...
        """

        name = plugin_cls.name
        if not name or name == "base":
            raise ValueError(f"Plugin {plugin_cls!r} must define a unique name")
        self._plugin_classes[name] = plugin_cls
        self._instances.pop(name, None)
        return plugin_cls

    def discover(self) -> None:
        """Import all built-in plugin modules so decorators can register them."""

        if self._discovered:
            return
        package = spectre.plugins
        for module_info in pkgutil.walk_packages(package.__path__, package.__name__ + "."):
            if not module_info.ispkg:
                importlib.import_module(module_info.name)
        self._discovered = True

    def all(self) -> list[BasePlugin]:
        self.discover()
        return [self.get(name) for name in sorted(self._plugin_classes)]

    def get(self, name: str) -> BasePlugin:
        self.discover()
        if name not in self._plugin_classes:
            known = ", ".join(sorted(self._plugin_classes))
            raise KeyError(f"Unknown plugin '{name}'. Known plugins: {known}")
        if name not in self._instances:
            self._instances[name] = self._plugin_classes[name]()
        return self._instances[name]

    def by_category(self, category: Category, include_optional: bool = False) -> list[BasePlugin]:
        self.discover()
        return [plugin for plugin in self.all() if plugin.category == category and (include_optional or plugin.default_enabled)]

    def detect(self, target: TargetContext, plugins: Iterable[BasePlugin] | None = None) -> list[tuple[BasePlugin, Detection]]:
        """Return applicable plugins sorted by confidence."""

        candidate_plugins = list(plugins) if plugins is not None else self.by_category(target.category)
        detected: list[tuple[BasePlugin, Detection]] = []
        for plugin in candidate_plugins:
            detection = plugin.detect(target)
            if detection.applicable:
                detected.append((plugin, detection))
        detected.sort(key=lambda item: item[1].confidence, reverse=True)
        return detected

    def grouped_names(self) -> dict[str, list[str]]:
        self.discover()
        grouped: dict[str, list[str]] = defaultdict(list)
        for plugin in self.all():
            grouped[plugin.category.value].append(plugin.name)
        return {category: sorted(names) for category, names in sorted(grouped.items())}


registry = PluginRegistry()
