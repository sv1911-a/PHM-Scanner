"""SSL/TLS certificate source adapter."""

from __future__ import annotations

import socket
import ssl as stdlib_ssl
from datetime import datetime, timezone
from typing import Any

from phm.sources.base import SourceAdapter
from phm.sources.common import is_domain, normalize_domain


class SSLAdapter(SourceAdapter):
    """Collect public TLS certificate metadata for a host."""

    source_name = "ssl"

    def lookup(self, host: str, port: int = 443) -> dict[str, Any]:
        normalized = normalize_domain(host)
        if not is_domain(normalized):
            raise ValueError(f"not a valid TLS hostname: {host}")
        cache_key = f"lookup:{normalized}:{port}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached

        context = stdlib_ssl.create_default_context()
        with socket.create_connection((normalized, port), timeout=self.timeout) as sock:
            with context.wrap_socket(sock, server_hostname=normalized) as tls:
                cert = tls.getpeercert()
                cipher = tls.cipher()
                version = tls.version()

        san = [value for key, value in cert.get("subjectAltName", []) if key.lower() == "dns"]
        not_before = self._parse_cert_time(cert.get("notBefore", ""))
        not_after = self._parse_cert_time(cert.get("notAfter", ""))
        days_until_expiry = None
        if not_after:
            expires = datetime.fromisoformat(not_after)
            days_until_expiry = (expires - datetime.now(timezone.utc)).days

        result = {
            "host": normalized,
            "port": port,
            "subject": self._name_tuple_to_dict(cert.get("subject")),
            "issuer": self._name_tuple_to_dict(cert.get("issuer")),
            "serial_number": cert.get("serialNumber"),
            "not_before": not_before,
            "not_after": not_after,
            "days_until_expiry": days_until_expiry,
            "subject_alt_names": san[:200],
            "san_count": len(san),
            "tls_version": version,
            "cipher": cipher,
            "metadata": {"source": self.source_name, "cached": False},
            "errors": [],
        }
        self.cache_set(cache_key, result)
        return result

    @staticmethod
    def _name_tuple_to_dict(items) -> dict[str, str]:
        parsed: dict[str, str] = {}
        for group in items or []:
            for key, value in group:
                parsed[key] = value
        return parsed

    @staticmethod
    def _parse_cert_time(value: str) -> str | None:
        if not value:
            return None
        try:
            return datetime.strptime(value, "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc).isoformat()
        except ValueError:
            return None
