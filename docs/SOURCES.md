# PHM-Scanner Lookups

PHM-Scanner should not become a dashboard for other OSINT tools.

Most analysis should happen inside PHM.

Some data must come from public sources because they are the real source of the information.

## Good public lookups

These are acceptable:

| Lookup | Why |
| --- | --- |
| DNS | DNS is where domain records come from. |
| WHOIS | WHOIS is a registration protocol. |
| RDAP | RDAP provides structured ownership and network data. |
| TLS certificates | Certificates can be collected directly from a website. |
| Certificate Transparency | CT logs are public certificate records. |
| GitHub | GitHub is the source for GitHub repositories. |
| Wayback Machine | Internet Archive stores archived web pages. |
| Reverse DNS | PTR records come from DNS. |

## Current lookups

PHM-Scanner currently supports:

```text
DNS
WHOIS
RDAP
TLS certificates
Certificate Transparency
Wayback Machine
Reverse DNS
GitHub
```

These are used to collect real public data, not to outsource analysis.

## Local checks come first

These work without the internet:

- file analysis
- crypto decoding
- hash identification
- string extraction
- file type detection
- entropy calculation

Future improvements should deepen these checks before adding more external services.

## Optional external services

These may be useful later, but they should not become required:

- Shodan
- Censys
- SecurityTrails
- HackerTarget

They should be optional extras only.

## Cache

PHM can cache lookup results:

```bash
phm analyze example.com --cache --cache-ttl 3600
```

Default cache path:

```text
investigations/source_cache.db
```

The cache is separate from saved investigations.

```text
cache = reused lookup results
saved investigation = report history
```
