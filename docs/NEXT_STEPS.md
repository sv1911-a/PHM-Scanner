# SPECTRE Roadmap

The roadmap is now centered around one idea:

```bash
spectre analyze <target>
```

SPECTRE should detect the target and do the right thing.

The user should not need to understand internal modules.

## Priority 1: Improve `spectre analyze`

Current status:

`analyze` can detect:

- files
- domains
- IP addresses
- URLs
- emails
- usernames
- hashes
- GitHub repositories
- encoded text

Current reports also include rule-based suggested next steps.

Next steps:

- make detection more accurate
- make next-step suggestions more useful
- make reports cleaner
- choose better default checks for each target type
- show clearer messages like `Detected: PDF document` or `Detected: domain`
- avoid running slow checks unless they are useful
- add a `--fast` mode later
- add a `--deep` mode later

## Priority 2: Make file analysis better

Current status:

SPECTRE can analyze files with:

- magic bytes
- hashes
- entropy
- strings
- extension mismatch checks

Next steps:

- add more file signatures
- detect embedded files
- improve string extraction
- extract URLs, emails, hashes, domains, and JWTs from strings
- improve suspicious file scoring

## Priority 3: Add metadata analysis

Goal:

```bash
spectre analyze photo.jpg
spectre analyze report.pdf
```

SPECTRE should automatically check metadata.

Planned features:

- EXIF parser
- GPS extraction
- PDF metadata parser
- Office document metadata parser
- timestamps
- author fields
- embedded URLs and emails

## Priority 4: Add archive analysis

Goal:

```bash
spectre analyze sample.zip
```

SPECTRE should inspect archives safely.

Planned features:

- list archive contents
- hash archive members
- detect suspicious files inside archives
- analyze nested files
- extract useful results from nested files

## Priority 5: Add binary analysis

Goal:

```bash
spectre analyze suspicious.exe
```

SPECTRE should recognize and analyze binaries.

Planned features:

- PE parser
- ELF parser
- Mach-O parser
- imports
- exports
- symbols
- sections
- section entropy
- compiler clues
- packer clues
- interesting strings
- URLs and domains inside binaries

## Priority 6: Add web analysis

Goal:

```bash
spectre analyze https://example.com
```

SPECTRE should inspect websites.

Planned features:

- HTTP headers
- cookies
- robots.txt
- sitemap.xml
- HTML links
- JavaScript endpoints
- security headers
- technology detection

## Priority 7: Clean reports

Reports should be easy to read.

Next steps:

- show the detected target type
- show the most important findings first
- group results by type
- show relationships clearly
- add a timeline section when useful
- add a simple summary
- improve HTML reports
- add PDF export later

## Priority 8: Better saved investigations

Current status:

SPECTRE can save full reports in SQLite.

Next steps:

- save results separately
- save relationships separately
- search old investigations
- compare two investigations
- export graphs

## Priority 9: Keep advanced commands

Advanced users should still be able to run direct commands:

```bash
spectre dns example.com
spectre file sample.exe
spectre hash <hash>
spectre crypto <text>
```

But these should be optional.

The default should remain:

```bash
spectre analyze <target>
```

## Lower priority

These can wait:

- Shodan integration
- Censys integration
- SecurityTrails integration
- HackerTarget integration
- external tool integrations
- GUI

## Not a priority yet

Do not focus on these yet:

- AI summaries
- LLM agents
- multi-agent systems
- vector databases
- RAG pipelines

First, make SPECTRE useful with one command.
