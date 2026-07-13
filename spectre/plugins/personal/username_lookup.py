"""Username lookup plugin for personal intelligence."""

from __future__ import annotations

import re
from typing import Any

from spectre.core.models import Category, Detection, Evidence, Finding, Severity, TargetContext
from spectre.core.plugin import BasePlugin
from spectre.core.registry import registry

_USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,39}$")

_PROFILE_TEMPLATES = {
    "github": "https://github.com/{username}",
    "gitlab": "https://gitlab.com/{username}",
    "x_twitter": "https://x.com/{username}",
    "reddit": "https://www.reddit.com/user/{username}",
    "hackernews": "https://news.ycombinator.com/user?id={username}",
    "keybase": "https://keybase.io/{username}",
}


@registry.register
class UsernameLookupPlugin(BasePlugin):
    name = "username_lookup"
    category = Category.PERSONAL
    description = "Generate passive username OSINT leads without account probing."
    passive = True

    def detect(self, target: TargetContext) -> Detection:
        value = target.value.strip()
        ok = bool(_USERNAME_RE.match(value)) and "@" not in value
        return Detection(ok, 0.82 if ok else 0.0, "username-like input" if ok else "not a username")

    def collect(self, target: TargetContext) -> dict[str, Any]:
        username = target.value.strip()
        templates = target.options.get("profile_templates") or _PROFILE_TEMPLATES
        leads = {name: template.format(username=username) for name, template in templates.items()}
        return {
            "username": username,
            "candidate_profile_urls": leads,
            "privacy_note": "Candidate URLs are generated as investigative leads only; this MVP does not probe platforms or confirm account ownership.",
        }

    def analyze(self, target: TargetContext, raw: dict[str, Any]) -> list[Finding]:
        leads = raw.get("candidate_profile_urls", {})
        evidence = [Evidence(source=f"candidate_profile:{name}", value=url) for name, url in leads.items()]
        evidence.append(Evidence(source="privacy_note", value=raw["privacy_note"]))
        return [
            Finding(
                title="Username investigative leads",
                description=f"Generated {len(leads)} candidate profile URLs for analyst review. These are not verified matches.",
                category=self.category,
                plugin=self.name,
                confidence=0.65,
                severity=Severity.INFO,
                evidence=evidence,
                metadata={"verified": False},
            )
        ]

    def report(self, target: TargetContext, raw: dict[str, Any], findings: list[Finding], errors: list[str] | None = None):
        return self._result(target, raw, findings, errors)
