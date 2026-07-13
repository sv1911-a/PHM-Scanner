"""Compatibility exports for GitHub plugins.

GitHub collection now lives in the source-adapter layer. Plugin code should
prefer importing `GitHubAdapter` from `spectre.sources.github.adapter`; these
exports keep existing plugins stable during the adapter migration.
"""

from spectre.sources.github.adapter import (  # noqa: F401
    GITHUB_API_BASE,
    SECRET_PATTERNS,
    USER_AGENT,
    GitHubAdapter,
    GitHubAPIError,
    GitHubResponse,
    decode_blob_content,
    github_get,
    github_headers,
    parse_github_user,
    parse_repo_slug,
    redact_secret,
    scan_text_for_secrets,
    shannon_entropy,
    technology_hints,
)
