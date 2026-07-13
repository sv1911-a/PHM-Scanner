"""Reverse DNS source adapter."""

from __future__ import annotations

import ipaddress
import socket
from typing import Any

from spectre.sources.base import SourceAdapter


class ReverseDNSAdapter(SourceAdapter):
    """Perform reverse DNS lookup for IP addresses using the system resolver."""

    source_name = "reverse_dns"

    def lookup(self, ip: str) -> dict[str, Any]:
        address = str(ipaddress.ip_address(ip.strip().strip("[]")))
        cache_key = f"lookup:{address}"
        cached = self.cache_get(cache_key)
        if cached is not None:
            return cached
        result: dict[str, Any] = {
            "ip": address,
            "hostname": "",
            "aliases": [],
            "addresses": [],
            "metadata": {"source": self.source_name, "cached": False},
            "errors": [],
        }
        try:
            hostname, aliases, addresses = socket.gethostbyaddr(address)
            result.update({"hostname": hostname, "aliases": aliases, "addresses": addresses})
        except Exception as exc:  # noqa: BLE001
            result["errors"].append(f"reverse DNS failed: {type(exc).__name__}: {exc}")
        self.cache_set(cache_key, result)
        return result
