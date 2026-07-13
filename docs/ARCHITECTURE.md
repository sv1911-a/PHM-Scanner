# SPECTRE Architecture

This document is for developers.

Users should not need to understand this.

The user-facing goal is:

```bash
spectre analyze <target>
```

SPECTRE should detect the target, run the right analysis, explain what matters, and suggest what to do next.

## Simple flow

```text
User runs command
 ↓
SPECTRE detects target type
 ↓
SPECTRE chooses checks
 ↓
SPECTRE runs plugins
 ↓
SPECTRE creates a report
```

## Internal flow

Internally, the flow is:

```text
Input
 ↓
Auto-detection
 ↓
Plan
 ↓
Plugins
 ↓
Analysis
 ↓
Findings
 ↓
Results
 ↓
Relationships
 ↓
Suggested next steps
 ↓
Report
```

## Main parts

```text
spectre/
  cli.py                  user commands
  core/                   framework code
  analysis/               local analysis code
  sources/                public data source code
  plugins/                analysis plugins
```

## CLI

The CLI is what users interact with.

The main command is:

```bash
spectre analyze <target>
```

Specific commands also exist:

```bash
spectre file sample.pdf
spectre dns example.com
spectre hash <hash>
spectre crypto <text>
```

But most users should start with `analyze`.

## Auto-detection

Auto-detection lives in:

```text
spectre/core/autodetect.py
```

It tries to identify the target type.

Examples:

| Input | Detected as |
| --- | --- |
| `sample.pdf` | file |
| `example.com` | domain |
| `8.8.8.8` | IP address |
| `person@example.com` | email |
| `https://github.com/python/cpython` | GitHub repository |
| `5d41402abc4b2a76b9719d911017c592` | hash |
| `SGVsbG8=` | encoded text |

After detection, SPECTRE chooses a sensible analysis plan.

## Core

The `core/` folder contains the framework.

```text
core/
  models.py        shared data structures
  plugin.py        plugin interface
  registry.py      plugin discovery
  orchestrator.py  runs investigations
  autodetect.py    chooses analysis automatically
  artifacts.py     extracts useful results
  correlation.py   finds relationships
  recommendations.py suggests next steps
  reporting.py     creates reports
  storage.py       saves investigations
```

## Plugins

Plugins do the actual work.

Every plugin follows the same pattern:

```python
detect()
collect()
analyze()
report()
```

This keeps everything consistent.

A file plugin, DNS plugin, hash plugin, and GitHub plugin all fit the same system.

## Analysis code

Local analysis code lives in:

```text
spectre/analysis/
```

This is where SPECTRE's own implementations should live.

Current example:

```text
spectre/analysis/file/native.py
```

It does:

- magic byte detection
- hashing
- entropy
- string extraction

No external tools are called.

## Public sources

Some data must come from public sources.

Examples:

- DNS
- RDAP
- WHOIS
- SSL/TLS certificates
- Certificate Transparency logs
- GitHub repositories
- Wayback Machine snapshots

That code lives in:

```text
spectre/sources/
```

These are not meant to turn SPECTRE into an API aggregator.

They are used only when the public source is the real source of the data.

## Results

SPECTRE extracts useful results from findings.

Examples:

- domains
- IP addresses
- URLs
- emails
- hashes
- GitHub repositories
- JWTs
- JavaScript endpoints

Internally these are called artifacts.

In user-facing docs, it is fine to call them results.

## Relationships

SPECTRE also tries to connect results.

Example:

```text
example.com
 ├── IP address
 ├── certificate
 ├── GitHub repository lead
 └── archived URL
```

This helps the report feel more like an investigation instead of a list of separate outputs.

## Suggested next steps

SPECTRE should help users decide what to do next.

Next-step suggestions live in:

```text
spectre/core/recommendations.py
```

These suggestions are rule-based and transparent.

No AI is used.

Examples:

- if a file contains URLs, suggest analyzing those URLs
- if a domain is analyzed, suggest certificates, web checks, or GitHub references
- if a hash is identified, remind the user that context matters
- if a binary is detected, suggest binary triage

## Storage

SPECTRE can save reports.

```bash
spectre analyze example.com --save
spectre storage list
spectre storage show 1
```

Saved reports use SQLite.

## Design rule

The architecture should stay hidden from the user.

The user should not need to know about:

- plugins
- modules
- adapters
- artifacts
- orchestration

They should be able to run:

```bash
spectre analyze something
```

and get useful results.

That is the main design goal.
