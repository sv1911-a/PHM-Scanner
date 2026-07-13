# SPECTRE Source Policy

SPECTRE should not become an API aggregator.

This means SPECTRE should not depend on third-party OSINT platforms to do its analysis.

Instead, SPECTRE should:

- analyze locally when possible
- implement its own logic when possible
- query public sources only when they are the real source of the data

## Good public sources

Some data must come from public internet sources.

These are acceptable because they are primary or authoritative sources.

Examples:

| Source | Why it is acceptable |
| --- | --- |
| DNS | DNS is the real source for domain records. |
| WHOIS | WHOIS is a registration protocol. |
| RDAP | RDAP is structured registration and network data. |
| SSL/TLS | Certificates can be collected directly from the target. |
| Certificate Transparency | CT logs are public certificate records. |
| GitHub | GitHub is the source for GitHub repositories. |
| Wayback Machine | Internet Archive is the source for archived web pages. |
| Reverse DNS | PTR records come from DNS infrastructure. |

## Current public-source adapters

SPECTRE currently has:

```text
DNSAdapter
WhoisAdapter
RDAPAdapter
SSLAdapter
CRTSHAdapter
WaybackAdapter
ReverseDNSAdapter
GitHubAdapter
```

These are used for real public data, not for outsourcing analysis.

## Local-first features

These should be prioritized because they do not need the internet.

| Feature | Status |
| --- | --- |
| Crypto decoding | Started |
| Hash identification | Started |
| File triage | Started |
| Artifact extraction | Started |
| Magic byte detection | Started |
| String extraction | Started |
| Entropy calculation | Started |

Future local-first features:

- EXIF parser
- PDF metadata parser
- OOXML metadata parser
- ZIP parser
- ELF parser
- PE parser
- Mach-O parser
- JavaScript endpoint extraction

## Optional enhanced sources

These may be added later, but they should not become core dependencies.

Examples:

| Source | Purpose |
| --- | --- |
| Shodan | exposed services and banners |
| Censys | certificates and hosts |
| SecurityTrails | historical DNS and subdomains |
| HackerTarget | convenience DNS and host data |

These are useful, but they are not the main identity of SPECTRE.

## Cache

SPECTRE can cache public-source results.

Example:

```bash
spectre domain example.com --cache --cache-ttl 3600
```

Default cache path:

```text
investigations/source_cache.db
```

This helps avoid repeating the same public lookups.

The source cache is separate from saved investigations.

```text
source cache = reused lookup results
investigation storage = saved reports
```
