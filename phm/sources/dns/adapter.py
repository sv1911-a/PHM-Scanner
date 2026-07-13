"""DNS source adapter."""

from __future__ import annotations

import socket
from typing import Any

from phm.sources.base import SourceAdapter
from phm.sources.common import is_domain, normalize_domain


class DNSAdapter(SourceAdapter):
    """Resolve DNS records using dnspython when available, with stdlib fallback."""

    source_name = "dns"

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
            "a_records": [],
            "aaaa_records": [],
            "mx_records": [],
            "txt_records": [],
            "ns_records": [],
            "cname_records": [],
            "soa_records": [],
            "reverse_dns": {},
            "metadata": {"source": self.source_name, "cached": False, "resolver": ""},
            "errors": [],
        }

        try:
            import dns.resolver  # type: ignore

            result["metadata"]["resolver"] = "dnspython"
            resolver = dns.resolver.Resolver()
            resolver.lifetime = self.timeout
            resolver.timeout = self.timeout
            result["a_records"] = self._resolve_record(resolver, normalized, "A")
            result["aaaa_records"] = self._resolve_record(resolver, normalized, "AAAA")
            result["mx_records"] = self._resolve_mx(resolver, normalized)
            result["txt_records"] = self._resolve_txt(resolver, normalized)
            result["ns_records"] = self._resolve_record(resolver, normalized, "NS")
            result["cname_records"] = self._resolve_record(resolver, normalized, "CNAME")
            result["soa_records"] = self._resolve_record(resolver, normalized, "SOA")
        except ImportError:
            result["metadata"]["resolver"] = "stdlib_socket"
            result["errors"].append("optional dependency 'dnspython' is not installed; only A/AAAA records are available")
            self._stdlib_lookup(normalized, result)
        except Exception as exc:  # noqa: BLE001 - resolver failures should degrade to stdlib
            result["errors"].append(f"dnspython lookup failed: {type(exc).__name__}: {exc}")
            result["metadata"]["resolver"] = "stdlib_socket_after_dnspython_error"
            self._stdlib_lookup(normalized, result)

        for address in [*result["a_records"], *result["aaaa_records"]]:
            try:
                result["reverse_dns"][address] = socket.gethostbyaddr(address)[0]
            except Exception:
                result["reverse_dns"][address] = ""

        self.cache_set(cache_key, result)
        return result

    def _stdlib_lookup(self, domain: str, result: dict[str, Any]) -> None:
        for family, key in [(socket.AF_INET, "a_records"), (socket.AF_INET6, "aaaa_records")]:
            try:
                infos = socket.getaddrinfo(domain, None, family, socket.SOCK_STREAM)
                result[key] = sorted({info[4][0] for info in infos})
            except socket.gaierror as exc:
                result["errors"].append(f"{family.name}: {exc}")

    @staticmethod
    def _resolve_record(resolver, domain: str, record_type: str) -> list[str]:
        try:
            return sorted({str(answer).rstrip(".") for answer in resolver.resolve(domain, record_type)})
        except Exception:
            return []

    @staticmethod
    def _resolve_mx(resolver, domain: str) -> list[dict[str, Any]]:
        try:
            return sorted(
                [
                    {"preference": int(answer.preference), "exchange": str(answer.exchange).rstrip(".")}
                    for answer in resolver.resolve(domain, "MX")
                ],
                key=lambda item: (item["preference"], item["exchange"]),
            )
        except Exception:
            return []

    @staticmethod
    def _resolve_txt(resolver, domain: str) -> list[str]:
        try:
            values = []
            for answer in resolver.resolve(domain, "TXT"):
                strings = getattr(answer, "strings", [])
                if strings:
                    values.append("".join(part.decode("utf-8", errors="replace") for part in strings))
                else:
                    values.append(str(answer).strip('"'))
            return sorted(set(values))
        except Exception:
            return []
