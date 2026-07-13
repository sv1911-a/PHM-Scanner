"""Deterministic next-step recommendations for SPECTRE reports.

SPECTRE should not just dump output. It should help the user understand where to
look next. These recommendations are rule-based, transparent, and intentionally
simple. No AI is used.
"""

from __future__ import annotations

from typing import Any

from spectre.core.models import Category, InvestigationReport


def build_next_steps(report: InvestigationReport, limit: int = 8) -> list[dict[str, Any]]:
    """Build clear next investigation steps from report results and artifacts."""

    steps: list[dict[str, Any]] = []
    plugins = {result.plugin for result in report.results}
    artifacts = report.metadata.get("artifacts", []) if isinstance(report.metadata, dict) else []
    artifact_types = {artifact.get("type") for artifact in artifacts if isinstance(artifact, dict)}

    def add(title: str, why: str, command: str | None = None, priority: str = "medium") -> None:
        item = {"title": title, "why": why, "priority": priority}
        if command:
            item["command"] = command
        if item not in steps:
            steps.append(item)

    if report.category == Category.FILE:
        add(
            "Review extracted strings",
            "Strings often reveal URLs, domains, commands, file paths, debug messages, or suspicious indicators.",
            priority="high",
        )
        if "url" in artifact_types or "domain" in artifact_types:
            add(
                "Analyze discovered URLs or domains",
                "The file contains network indicators that may point to infrastructure, callbacks, or related services.",
                "spectre analyze <discovered-domain-or-url>",
                "high",
            )
        if "hash" in artifact_types:
            add(
                "Use hashes as stable identifiers",
                "Hashes help compare the file across investigations and external references without relying on filenames.",
                "spectre hash <sha256-or-md5>",
            )
        for result in report.results:
            for finding in result.findings:
                primary = finding.metadata.get("primary_signature") if isinstance(finding.metadata, dict) else None
                if isinstance(primary, dict) and primary.get("artifact_type") == "binary":
                    add(
                        "Perform binary triage next",
                        "The file appears to be an executable. Imports, sections, entropy, and embedded strings are likely important.",
                        "spectre binary <file>",
                        "high",
                    )

    if report.category == Category.TECHNICAL:
        if "domain" in artifact_types or report.target.count("."):
            if "ssl_lookup" not in plugins:
                add("Check TLS certificate details", "Certificates can reveal names, issuers, expiry, and related hostnames.", f"spectre analyze {report.target} --plugin ssl_lookup")
            if "crtsh_lookup" not in plugins:
                add("Search Certificate Transparency", "Certificate Transparency can reveal subdomains and historical infrastructure.", f"spectre analyze {report.target} --plugin crtsh_lookup --cache", "high")
            if "technology_fingerprint" not in plugins:
                add("Check the website surface", "HTTP headers and HTML often reveal technologies and security-relevant configuration.", f"spectre web https://{report.target}")
            if "github_search" not in plugins:
                add("Search GitHub for references", "Public repositories may mention domains, endpoints, deployment files, or leaked configuration references.", f"spectre analyze {report.target} --plugin github_search --cache")
        if "ip" in artifact_types or _looks_like_ip(report.target):
            if "reverse_dns_lookup" not in plugins:
                add("Check reverse DNS", "PTR records can reveal hostnames or infrastructure naming patterns.", f"spectre analyze {report.target} --plugin reverse_dns_lookup")
            if "rdap_lookup" not in plugins:
                add("Check RDAP ownership", "RDAP provides structured network ownership and registration details.", f"spectre analyze {report.target} --plugin rdap_lookup")

    if report.category == Category.PERSONAL:
        if "email_lookup" in plugins:
            add("Investigate the email domain", "The domain part of an email often gives stronger leads than the mailbox alone.", "spectre analyze <email-domain>")
        if "username_lookup" in plugins or "github_user_lookup" in plugins:
            add("Treat username matches as leads only", "The same username can belong to different people on different platforms. Verify before concluding.", priority="high")

    if report.category == Category.CRYPTO:
        if "hash_identifier" in plugins:
            add("Identify where the hash came from", "Hash type guesses are not proof. Context such as database, OS, or application matters.", priority="high")
        else:
            add("Inspect the decoded candidate", "If the result looks meaningful, use it as the next input or pivot. Many challenges have multiple layers.", priority="high")
            add("Try deeper decoding if needed", "If output still looks encoded, increase depth or analyze the result again.", "spectre analyze <decoded-output>")

    if report.category == Category.HISTORICAL:
        add("Compare historical and current content", "Archived URLs can reveal removed endpoints, old technologies, or exposed files.", priority="high")
        if "url" in artifact_types:
            add("Analyze archived URLs", "Historical URLs may expose old admin panels, APIs, or assets still referenced elsewhere.", "spectre analyze <archived-url>")

    if "github_repo" in artifact_types or "github_repo_analysis" in plugins:
        add("Review repository timeline and contributors", "Recent commits and active contributors help identify where development is happening.", priority="medium")
        add("Review redacted secret indicators", "Potential secrets are not proof, but they deserve careful validation and rotation if confirmed.", priority="high")

    if not steps:
        add(
            "Review the highest-confidence findings first",
            "Start with findings that have the strongest evidence and use any extracted results as pivots.",
            priority="medium",
        )

    return steps[:limit]


def _looks_like_ip(value: str) -> bool:
    parts = value.strip().split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(part) <= 255 for part in parts)
    except ValueError:
        return False
