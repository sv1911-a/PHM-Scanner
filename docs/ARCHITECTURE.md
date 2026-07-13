# Spectre Architecture

This document is for developers.

Users should not need to know how Spectre is built. They should be able to run:

```bash
spectre analyze <target>
```

and get useful results.

## Simple flow

```text
User gives Spectre a target
 ↓
Spectre detects what it is
 ↓
Spectre chooses useful checks
 ↓
Spectre runs them
 ↓
Spectre summarizes the results
 ↓
Spectre suggests what to investigate next
```

## Main folders

```text
spectre/
  cli.py          command-line interface
  core/           shared code
  analysis/       local analysis code
  sources/        public lookups
  plugins/        checks Spectre can run
  tests/          tests
```

## CLI

The main user command is:

```bash
spectre analyze <target>
```

Direct commands also exist:

```bash
spectre file sample.pdf
spectre dns example.com
spectre hash <hash>
spectre crypto <text>
```

They are useful when you want a specific check, but they should not be required for normal use.

## Detection

Detection lives in:

```text
spectre/core/autodetect.py
```

It scores possible interpretations of a target.

Example:

```bash
spectre analyze uryyb
```

Spectre can report:

```text
Detected: username (74%)
Other possibilities:
  - rot13_text (68%)
  - plain_text (20%)
```

This makes the choice visible instead of pretending there was only one answer.

## Checks

Checks live in:

```text
spectre/plugins/
```

A check can do things like:

- analyze a file
- identify a hash
- look up DNS records
- inspect TLS certificates
- check a GitHub repository
- decode text

Each check follows the same basic pattern:

```python
detect()
collect()
analyze()
report()
```

That consistency is for developers. Users should not need to care.

## Local analysis

Local analysis code lives in:

```text
spectre/analysis/
```

This is where Spectre does its own work instead of calling another tool.

Current example:

```text
spectre/analysis/file/native.py
```

It checks:

- file type
- hashes
- entropy
- strings
- extension mismatch

## Public lookups

Some information has to come from public sources.

Examples:

- DNS records
- RDAP records
- WHOIS records
- TLS certificates
- Certificate Transparency logs
- GitHub repositories
- Wayback Machine snapshots

That code lives in:

```text
spectre/sources/
```

These are lookups, not outsourced analysis.

## Findings

A finding is something Spectre learned.

Examples:

- this file is a PE executable
- this string contains a URL
- this domain has a valid TLS certificate
- this hash looks like MD5 or NTLM
- this website hides its server header

Findings are what users care about.

## Relationships

Spectre also connects related things.

Example:

```text
example.com
 ├── IP address
 ├── certificate
 ├── GitHub lead
 └── archived URL
```

This helps the report feel like an investigation instead of separate tool output.

## Next steps

Next-step suggestions live in:

```text
spectre/core/recommendations.py
```

They are simple rules.

No AI is used.

Examples:

- if a file contains URLs, suggest analyzing those URLs
- if a website was checked, suggest robots.txt and JavaScript review
- if a hash was identified, remind the user that context matters
- if a binary was detected, suggest binary triage

## Reports

Reports should be readable first and detailed second.

Default terminal reports show:

- detected target type
- summary
- interesting findings
- next steps

Raw details are shown with:

```bash
spectre analyze <target> --verbose
```

## Storage

Spectre can save investigations:

```bash
spectre analyze example.com --save
spectre storage list
spectre storage show 1
```

Saved data uses SQLite.

## Developer rule

The code can be organized internally however we need.

But the user experience should stay simple:

```bash
spectre analyze something
```

If a change makes users think harder, it should be reconsidered.
