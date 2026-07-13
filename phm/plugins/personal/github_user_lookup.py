"""GitHub user intelligence plugin."""

from __future__ import annotations

from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.sources.github.adapter import GitHubAdapter, parse_github_user


@registry.register
class GitHubUserLookupPlugin(BasePlugin):
    name = "github_user_lookup"
    category = Category.PERSONAL
    description = "Collect public GitHub user profile and repository summary metadata via the GitHub source adapter."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        user = parse_github_user(target.value)
        if user and "/" not in target.value.strip().replace("https://github.com/", ""):
            return Detection(True, 0.72, "GitHub username/URL candidate")
        return Detection(False, 0.0, "not a GitHub user target")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        username = parse_github_user(target.value)
        if not username:
            raise ValueError("target is not a GitHub username or user URL")
        adapter = GitHubAdapter(
            timeout=float(target.options.get("timeout", 10.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.user(username)

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        if raw.get("exists") is False:
            return [
                Finding(
                    title="GitHub user not found",
                    description="GitHub returned 404 for this username. This does not prove the identity is unused elsewhere.",
                    category=self.category,
                    plugin=self.name,
                    confidence=0.75,
                    severity=Severity.INFO,
                    evidence=[Evidence(source="github.login", value=raw.get("username")), Evidence(source="github.message", value=raw.get("message"))],
                    metadata={"rate": raw.get("rate", {}), "adapter": raw.get("metadata", {})},
                )
            ]
        profile = raw.get("profile", {})
        repos = raw.get("recent_repositories", [])
        evidence = [
            Evidence(source="github.login", value=profile.get("login")),
            Evidence(source="github.html_url", value=profile.get("html_url")),
            Evidence(source="github.name", value=profile.get("name")),
            Evidence(source="github.company", value=profile.get("company")),
            Evidence(source="github.blog", value=profile.get("blog")),
            Evidence(source="github.location", value=profile.get("location")),
            Evidence(source="github.public_repos", value=profile.get("public_repos")),
            Evidence(source="github.followers", value=profile.get("followers")),
            Evidence(source="github.created_at", value=profile.get("created_at")),
            Evidence(source="github.updated_at", value=profile.get("updated_at")),
        ]
        languages = sorted({repo.get("language") for repo in repos if repo.get("language")})
        evidence.append(Evidence(source="github.recent_repo_languages", value=languages))
        for repo in repos[:8]:
            evidence.append(Evidence(source="github.recent_repo", value=repo))
        return [
            Finding(
                title="GitHub user public profile intelligence",
                description=f"Collected public GitHub profile metadata and {len(repos)} recently updated owned repositories.",
                category=self.category,
                plugin=self.name,
                confidence=0.86,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"rate": raw.get("rate", {}), "adapter": raw.get("metadata", {})},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
