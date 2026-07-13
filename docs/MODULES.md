# SPECTRE Modules

This document is for developers.

Users should not need to think about modules.

Users should mainly run:

```bash
spectre analyze <target>
```

Modules exist internally so the code stays organized.

## Simple rule

A module is a capability area.

Examples:

- File
- Binary
- Web
- Image
- Archive
- Crypto
- Metadata
- DNS
- Network
- Identity

Modules should not just be wrappers around external services.

## User view vs developer view

User view:

```bash
spectre analyze suspicious.exe
```

Developer view:

```text
Auto-detect file
 ↓
Run file analysis
 ↓
Maybe run binary analysis later
 ↓
Extract strings, hashes, URLs, domains
 ↓
Create report
```

The user only sees the useful result.

## Current modules

| Module | Status | What it does |
| --- | --- | --- |
| File | Started | file type, hashes, entropy, strings |
| Crypto | Started | decoding and hash identification |
| Domain/IP | Started | DNS, WHOIS, RDAP, SSL, ASN, CRT.SH |
| Identity | Started | email and username checks |
| GitHub | Started | users, orgs, repos, commits, contributors |
| Historical | Started | Wayback snapshots |

## File module

Current features:

- detect file type
- calculate hashes
- calculate entropy
- extract strings
- check extension mismatch

Next features:

- more file signatures
- embedded file detection
- better string extraction
- suspicious pattern detection

## Binary module

Planned features:

- PE parser
- ELF parser
- Mach-O parser
- imports
- exports
- sections
- symbols
- entropy by section
- packer clues

Useful for:

- malware triage
- reverse engineering
- CTFs
- forensics

## Web module

Planned features:

- HTTP headers
- cookies
- robots.txt
- sitemap.xml
- HTML links
- JavaScript endpoints
- security headers
- technology detection

## Image module

Planned features:

- EXIF metadata
- GPS extraction
- thumbnails
- image hashes
- hidden metadata

## Archive module

Planned features:

- ZIP support
- TAR support
- GZIP support
- file listing
- hashes for files inside archives
- nested analysis

## Metadata module

Planned features:

- PDF metadata
- Office document metadata
- author fields
- timestamps
- embedded links
- embedded emails

## What every module should do

Every module should try to answer:

1. What is this target?
2. What useful information can we extract?
3. What looks suspicious or important?
4. What new results did we discover?
5. What should appear in the report?

## Internal plugin metadata

Plugins can describe themselves internally.

Example:

```python
module = "file"
capability = "native_file_triage"
consumes = ("file",)
produces = ("hash", "string", "url", "email", "domain")
```

This helps developers connect modules later.

Users do not need to see this.

## Main goal

Modules should make this command smarter:

```bash
spectre analyze <target>
```

That is the point.
