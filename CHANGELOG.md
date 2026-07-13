# Changelog

All notable changes to SPECTRE will be documented here.

## 0.1.0 - Unreleased

Initial framework release.

### Changed after Kali validation

- Reworded project identity to simply "SPECTRE" instead of a marketing tagline.
- Improved terminal report readability with summaries first and raw evidence hidden by default.
- Added `--verbose` for plugin names and raw evidence details.
- Added multi-candidate target detection with alternative interpretations.
- Hardened technology fingerprinting so unusual `Server` header values are not treated as technologies.
- Improved rule-based next-step recommendations.

### Added

- `spectre analyze <target>` workflow
- target auto-detection
- plugin system
- reporting system: terminal, JSON, CSV, Markdown, HTML
- SQLite investigation storage
- rule-based next-step recommendations
- finding extraction
- relationship graph metadata
- native file triage:
  - magic bytes
  - hashes
  - entropy
  - strings
  - extension/signature mismatch check
- crypto engine:
  - Base64
  - hex
  - URL decoding
  - ROT13
  - XOR candidates
  - hash identification
- technical/public-source analysis:
  - DNS
  - WHOIS
  - RDAP
  - IP lookup
  - reverse DNS
  - ASN lookup
  - SSL/TLS certificate lookup
  - CRT.SH lookup
  - web technology fingerprinting
- GitHub analysis:
  - users
  - organizations
  - repositories
  - search
  - contributors
  - redacted secret indicators
- Wayback Machine lookup
