"""WHOIS source adapter."""

from __future__ import annotations

import re
import socket
from typing import Any

from spectre.sources.base import SourceAdapter
from spectre.sources.common import is_domain, normalize_domain

_WHOIS_SERVER_RE = re.compile(r"(?:refer|whois):\s*(\S+)", re.IGNORECASE)


class WhoisAdapter(SourceAdapter):
    """Port 43 WHOIS adapter with IANA referral support."""

    source_name = "whois"

    def lookup(self, domain: str) -> dict[str, Any]:
        normalized = normalize_domain(domain)
        if not is_domain(normalized):
            raise ValueError(f"not a valid domain: {domain}")
        cache_key = f"lookup:{normalized}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached

        result = {
            "domain": normalized,
            "iana_server": "whois.iana.org",
            "referred_server": "",
            "iana_response_excerpt": "",
            "whois_response_excerpt": "",
            "fields": {},
            "metadata": {"source": self.source_name, "cached": False},
            "errors": [],
        }
        try:
            iana = self._query("whois.iana.org", normalized)
            result["iana_response_excerpt"] = iana[:4000]
            match = _WHOIS_SERVER_RE.search(iana)
            if match:
                result["referred_server"] = match.group(1).strip()
        except OSError as exc:
            result["errors"].append(f"IANA WHOIS failed: {exc}")
            self.cache_set(cache_key, result)
            return result

        registrar_text = ""
        if result["referred_server"]:
            try:
                registrar_text = self._query(result["referred_server"], normalized)
            except OSError as exc:
                result["errors"].append(f"WHOIS query to {result['referred_server']} failed: {exc}")
        result["whois_response_excerpt"] = registrar_text[:12000]
        result["fields"] = self._extract_fields(registrar_text or result["iana_response_excerpt"])
        self.cache_set(cache_key, result)
        return result

    def _query(self, server: str, query: str) -> str:
        with socket.create_connection((server, 43), timeout=self.timeout) as sock:
            sock.settimeout(self.timeout)
            sock.sendall((query + "\r\n").encode("utf-8", errors="ignore"))
            chunks: list[bytes] = []
            while True:
                try:
                    chunk = sock.recv(4096)
                except socket.timeout:
                    break
                if not chunk:
                    break
                chunks.append(chunk)
        return b"".join(chunks).decode("utf-8", errors="replace")

    @staticmethod
    def _extract_fields(text: str) -> dict[str, list[str]]:
        wanted = {
            "registrar",
            "creation date",
            "created",
            "updated date",
            "registry expiry date",
            "expiry date",
            "name server",
            "domain status",
            "registrant organization",
            "registrant country",
        }
        fields: dict[str, list[str]] = {}
        for line in text.splitlines():
            if ":" not in line:
                continue
            key, value = line.split(":", 1)
            normalized = key.strip().lower()
            if normalized in wanted and value.strip():
                fields.setdefault(normalized, [])
                clean = value.strip()
                if clean not in fields[normalized]:
                    fields[normalized].append(clean)
        return fields
