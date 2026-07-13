"""Deterministic next-step recommendations for PHM reports.

PHM should not just dump output. It should help the user understand where to
look next. These recommendations are rule-based, transparent, and intentionally
simple. No AI is used.
"""

from __future__ import annotations

from typing import Any

from phm.core.models import Category, InvestigationReport
from phm.sources.common import normalize_domain


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
                "phm analyze <discovered-domain-or-url>",
                "high",
            )
        if "hash" in artifact_types:
            add(
                "Use hashes as stable identifiers",
                "Hashes help compare the file across investigations and external references without relying on filenames.",
                "phm hash <sha256-or-md5>",
            )
        for result in report.results:
            for finding in result.findings:
                primary = finding.metadata.get("primary_signature") if isinstance(finding.metadata, dict) else None
                if isinstance(primary, dict) and primary.get("artifact_type") == "binary":
                    add(
                        "Perform binary triage next",
                        "The file appears to be an executable. Imports, sections, entropy, and embedded strings are likely important.",
                        "phm binary <file>",
                        "high",
                    )

    if report.category == Category.TECHNICAL:
        host = normalize_domain(report.target) if report.target else report.target
        is_ip_target = _looks_like_ip(report.target)
        if "domain" in artifact_types or (host and host.count(".") and not is_ip_target):
            if "ssl_lookup" not in plugins:
                add("Check TLS certificate details", "Certificates can reveal names, issuers, expiry, and related hostnames.", f"phm analyze {host} --plugin ssl_lookup")
            if "crtsh_lookup" not in plugins:
                add("Search Certificate Transparency", "Certificate Transparency can reveal subdomains and historical infrastructure.", f"phm analyze {host} --plugin crtsh_lookup --cache", "high")
            if "technology_fingerprint" not in plugins:
                add("Check the website surface", "HTTP headers and HTML often reveal technologies and security-relevant configuration.", f"phm web https://{host}")
            else:
                add("Inspect robots.txt and sitemap.xml", "These files often reveal endpoints, admin paths, APIs, and content that normal browsing misses.", f"phm analyze https://{host}/robots.txt", "high")
                add("Review JavaScript for endpoints", "JavaScript files often contain API routes, feature flags, parameters, and authentication clues.", priority="high")
                add("Check security headers", "Headers can quickly show missing browser protections or unusual deployment choices.", priority="medium")
            if "github_search" not in plugins:
                add("Search GitHub for references", "Public repositories may mention domains, endpoints, deployment files, or leaked configuration references.", f"phm analyze {host} --plugin github_search --cache")
        if is_ip_target:
            if "reverse_dns_lookup" not in plugins:
                add("Check reverse DNS", "PTR records can reveal hostnames or infrastructure naming patterns.", f"phm analyze {report.target} --plugin reverse_dns_lookup")
            if "rdap_lookup" not in plugins:
                add("Check RDAP ownership", "RDAP provides structured network ownership and registration details.", f"phm analyze {report.target} --plugin rdap_lookup")
        elif "ip" in artifact_types:
            add("Review discovered IP addresses", "Resolved IPs can be checked individually for reverse DNS, RDAP ownership, and hosting patterns.", "phm analyze <discovered-ip>")

    if report.category == Category.PERSONAL:
        if "email_lookup" in plugins:
            add("Investigate the email domain", "The domain part of an email often gives stronger leads than the mailbox alone.", "phm analyze <email-domain>")
        if "username_lookup" in plugins or "github_user_lookup" in plugins:
            add("Treat username matches as leads only", "The same username can belong to different people on different platforms. Verify before concluding.", priority="high")

    if report.category == Category.CRYPTO:
        if "hash_identifier" in plugins:
            add("Identify where the hash came from", "Hash type guesses are not proof. Context such as database, OS, or application matters.", priority="high")
        else:
            add("Inspect the decoded candidate", "If the result looks meaningful, use it as the next input or pivot. Many challenges have multiple layers.", priority="high")
            add("Try deeper decoding if needed", "If output still looks encoded, analyze the result again or increase decoding depth.", "phm analyze <decoded-output>")
            add("Try XOR or rotation patterns", "Short CTF-style strings often use XOR, Caesar, ROT, or repeated simple transformations.", "phm crypto <input> --enable-xor", "medium")
            add("Look for common cipher clues", "Character set, length, repeated blocks, and frequency can hint at the next cipher family.", priority="medium")

    if report.category == Category.HISTORICAL:
        add("Compare historical and current content", "Archived URLs can reveal removed endpoints, old technologies, or exposed files.", priority="high")
        if "url" in artifact_types:
            add("Analyze archived URLs", "Historical URLs may expose old admin panels, APIs, or assets still referenced elsewhere.", "phm analyze <archived-url>")

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
