# Spectre Checks

This document is for developers.

Users should not need to think about checks or modules. They should normally run:

```bash
spectre analyze <target>
```

Internally, Spectre is split into checks so the code stays maintainable.

## What is a check?

A check is one thing Spectre can do.

Examples:

- identify a file type
- extract strings
- identify a hash
- look up DNS records
- collect TLS certificate data
- inspect a GitHub repository
- decode Base64 text

## Current areas

| Area | Status | Examples |
| --- | --- | --- |
| File | Started | file type, hashes, entropy, strings |
| Crypto | Started | decoding and hash identification |
| Domain/IP | Started | DNS, WHOIS, RDAP, SSL, ASN, CT logs |
| Identity | Started | email and username checks |
| GitHub | Started | users, orgs, repos, commits, contributors |
| History | Started | Wayback snapshots |

## File checks

Current:

- detect file type
- calculate hashes
- calculate entropy
- extract strings
- check extension mismatch

Next:

- more file signatures
- embedded file detection
- better string extraction
- suspicious pattern detection

## Binary checks

Planned:

- PE parser
- ELF parser
- Mach-O parser
- imports
- exports
- sections
- symbols
- section entropy
- packer clues

## Web checks

Planned:

- headers
- cookies
- robots.txt
- sitemap.xml
- links
- JavaScript endpoints
- security headers
- technology clues

## Image checks

Planned:

- EXIF metadata
- GPS extraction
- thumbnails
- image hashes
- hidden metadata

## Archive checks

Planned:

- ZIP support
- TAR support
- GZIP support
- file listing
- hashes for files inside archives
- nested analysis

## Metadata checks

Planned:

- PDF metadata
- Office document metadata
- author fields
- timestamps
- embedded links
- embedded emails

## What every check should do

Every check should help answer:

```text
What is this?
What stands out?
What should I investigate next?
```

If a check only exists because it is technically interesting, it should wait.

## Main goal

All checks should make this command better:

```bash
spectre analyze <target>
```
