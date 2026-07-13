"""Common source-adapter helpers."""

from __future__ import annotations

import re
from urllib.parse import urlparse

_DOMAIN_RE = re.compile(r"^(?=.{1,253}$)(?!-)([A-Za-z0-9-]{1,63}\.)+[A-Za-z]{2,63}\.?$")


def normalize_domain(value: str) -> str:
    """Normalize a URL/domain-ish value to a lower-case hostname."""

    value = value.strip().lower()
    if "://" in value:
        parsed = urlparse(value)
        value = parsed.netloc or parsed.path
    value = re.sub(r"^https?://", "", value)
    value = value.split("/")[0].split(":")[0]
    return value.rstrip(".")


def is_domain(value: str) -> bool:
    return bool(_DOMAIN_RE.match(normalize_domain(value)))
