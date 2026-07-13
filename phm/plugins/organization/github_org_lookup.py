"""GitHub organization intelligence plugin."""

from __future__ import annotations

import re
from typing import Any

from phm.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from phm.core.plugin import BasePlugin
from phm.core.registry import registry
from phm.sources.github.adapter import GitHubAdapter

_ORG_RE = re.compile(r"^[A-Za-z0-9_.-]{2,80}$")


def _parse_org(value: str) -> str | None:
    value = value.strip().rstrip("/")
    match = re.search(r"github\.com/(?:orgs/)?([A-Za-z0-9_.-]+)(?:/)?$", value)
    if match:
        return match.group(1)
    if _ORG_RE.fullmatch(value) and "/" not in value and "@" not in value:
        return value
    return None


@registry.register
class GitHubOrgLookupPlugin(BasePlugin):
    name = "github_org_lookup"
    category = Category.ORGANIZATION
    description = "Collect public GitHub organization profile and repository metadata via the GitHub source adapter."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        org = _parse_org(target.value)
        return Detection(org is not None, 0.7 if org else 0.0, "GitHub organization candidate" if org else "not an org")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        org = _parse_org(target.value)
        if not org:
            raise ValueError("target is not a GitHub organization candidate")
        adapter = GitHubAdapter(
            timeout=float(target.options.get("timeout", 10.0)),
            use_cache=bool(target.options.get("cache", False)),
            cache_ttl=int(target.options.get("cache_ttl", 3600)),
            cache_path=str(target.options.get("cache_path", "investigations/source_cache.db")),
        )
        return adapter.organization(org)

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        if raw.get("exists") is False:
            return [
                Finding(
                    title="GitHub organization not found",
                    description="GitHub returned 404 for this organization candidate.",
                    category=self.category,
                    plugin=self.name,
                    confidence=0.75,
                    severity=Severity.INFO,
                    evidence=[Evidence(source="github.org.login", value=raw.get("org")), Evidence(source="github.message", value=raw.get("message"))],
                    metadata={"rate": raw.get("rate", {}), "adapter": raw.get("metadata", {})},
                )
            ]
        profile = raw.get("profile", {})
        repos = raw.get("repositories", [])
        languages = sorted({repo.get("language") for repo in repos if repo.get("language")})
        evidence = [
            Evidence(source="github.org.login", value=profile.get("login")),
            Evidence(source="github.org.html_url", value=profile.get("html_url")),
            Evidence(source="github.org.name", value=profile.get("name")),
            Evidence(source="github.org.company", value=profile.get("company")),
            Evidence(source="github.org.blog", value=profile.get("blog")),
            Evidence(source="github.org.location", value=profile.get("location")),
            Evidence(source="github.org.public_repos", value=profile.get("public_repos")),
            Evidence(source="github.org.created_at", value=profile.get("created_at")),
            Evidence(source="github.org.languages", value=languages),
            Evidence(source="github.org.public_members_sample", value=raw.get("public_members_sample", [])),
        ]
        for repo in repos[:10]:
            evidence.append(Evidence(source="github.org.repo", value=repo))
        return [
            Finding(
                title="GitHub organization public intelligence",
                description=f"Collected public GitHub organization metadata and {len(repos)} recently updated public repositories.",
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
