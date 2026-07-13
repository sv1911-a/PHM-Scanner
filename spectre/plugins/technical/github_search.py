"""GitHub search intelligence plugin."""

from __future__ import annotations

import ipaddress
from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry
from spectre.sources.common import is_domain, normalize_domain
from spectre.sources.github.adapter import GitHubAdapter


@registry.register
class GitHubSearchPlugin(BasePlugin):
    name = "github_search"
    category = Category.TECHNICAL
    description = "Search public GitHub repositories/users/code for target references through the GitHub source adapter."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        try:
            ipaddress.ip_address(value)
            return Detection(False, 0.0, "IP targets are not searched on GitHub by default")
        except ValueError:
            pass
        domain = normalize_domain(value)
        if is_domain(domain):
            return Detection(True, 0.7, "domain target can be searched on GitHub")
        if value.startswith("ghsearch:") and len(value.split(":", 1)[1].strip()) >= 3:
            return Detection(True, 0.65, "explicit GitHub search term")
        return Detection(False, 0.0, "not a GitHub search target")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        raw_value = target.value.strip()
        if raw_value.startswith("ghsearch:"):
            query_value = raw_value.split(":", 1)[1].strip()
        else:
            query_value = normalize_domain(raw_value) if is_domain(normalize_domain(raw_value)) else raw_value
        adapter = GitHubAdapter(
            timeout=float(target.options.get("timeout", 10.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.search(
            query_value,
            per_page=int(target.options.get("github_search_per_page", 10)),
            include_code=bool(target.options.get("github_code_search", True)),
        )

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        repos = (raw.get("repository_search") or {}).get("items", []) if isinstance(raw.get("repository_search"), dict) else []
        users = (raw.get("user_search") or {}).get("items", []) if isinstance(raw.get("user_search"), dict) else []
        code_items = raw.get("code_items", [])
        evidence = [
            Evidence(source="github.search.query", value=raw.get("query")),
            Evidence(source="github.search.repository_total_count", value=(raw.get("repository_search") or {}).get("total_count") if isinstance(raw.get("repository_search"), dict) else None),
            Evidence(source="github.search.user_total_count", value=(raw.get("user_search") or {}).get("total_count") if isinstance(raw.get("user_search"), dict) else None),
        ]
        for repo in repos[:10]:
            evidence.append(
                Evidence(
                    source="github.search.repository",
                    value={
                        "full_name": repo.get("full_name"),
                        "html_url": repo.get("html_url"),
                        "description": repo.get("description"),
                        "language": repo.get("language"),
                        "stars": repo.get("stargazers_count"),
                        "updated_at": repo.get("updated_at"),
                    },
                )
            )
        for user in users[:8]:
            evidence.append(Evidence(source="github.search.user", value={"login": user.get("login"), "html_url": user.get("html_url"), "type": user.get("type")}))
        for item in code_items[:8]:
            evidence.append(Evidence(source="github.search.code", value=item))
        if raw.get("code_error"):
            evidence.append(Evidence(source="github.search.code_note", value=raw["code_error"]))

        return [
            Finding(
                title="GitHub public search intelligence",
                description=f"Found {len(repos)} repository lead(s), {len(users)} user lead(s), and {len(code_items)} code lead(s) for the target.",
                category=self.category,
                plugin=self.name,
                confidence=0.78,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"rate": raw.get("rate", {}), "adapter": raw.get("metadata", {})},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
