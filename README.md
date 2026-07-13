# SPECTRE

SPECTRE helps with making workflows faster.

> Status: early-stage project / pre-1.0. APIs and commands may change.

Its job is not to replace analysts or solve every problem automatically.

Its job is to remove repetitive work, reduce tool overload, and help you reach the important parts of an investigation faster.

The main goal is simple:

```text
Install it, point it at something, and get a useful report with clear next steps.
```

Most users should only need one command:

```bash
spectre analyze <target>
```

Examples:

```bash
spectre analyze image.jpg
spectre analyze suspicious.exe
spectre analyze example.com
spectre analyze 8.8.8.8
spectre analyze person@example.com
spectre analyze 5d41402abc4b2a76b9719d911017c592
spectre analyze SGVsbG8=
```

SPECTRE tries to figure out what the target is, run the right checks, explain what it found, and suggest what to look at next.

## What SPECTRE does

SPECTRE answers three basic questions:

```text
What is this?
What stands out?
What should I investigate next?
```

SPECTRE can analyze:

- files
- binaries
- images
- documents
- archives
- domains
- IP addresses
- URLs
- emails
- usernames
- hashes
- GitHub repositories
- encoded or encrypted text

## What SPECTRE is not

SPECTRE is not:

- an AI assistant
- an API aggregator
- a wrapper around existing tools
- only an OSINT tool

SPECTRE should do as much analysis as possible itself.

For example:

- it should detect file types itself
- it should extract strings itself
- it should identify hashes itself
- it should parse formats itself where possible
- it should only use the internet when the internet is the real source of the data

## Quick start

Run from the project folder:

```bash
python -m spectre.cli analyze example.com
python -m spectre.cli analyze sample.pdf
python -m spectre.cli analyze 8.8.8.8
```

Or install locally:

```bash
python -m pip install -e .
spectre analyze example.com
```

Optional DNS support:

```bash
python -m pip install -e ".[dns]"
```

## The main command

Use this first:

```bash
spectre analyze <target>
```

SPECTRE will try to detect the target type.

Examples:

```bash
spectre analyze example.com
```

Runs domain and network checks.

```bash
spectre analyze suspicious.exe
```

Runs file analysis.

```bash
spectre analyze https://github.com/python/cpython
```

Runs GitHub repository analysis.

```bash
spectre analyze 5d41402abc4b2a76b9719d911017c592
```

Runs hash identification.

```bash
spectre analyze SGVsbG8=
```

Runs crypto/encoding analysis.

## More specific commands

If you already know what you want, you can still use direct commands.

### Files

```bash
spectre file sample.bin
spectre binary sample.exe
spectre image photo.jpg
spectre document report.pdf
spectre archive sample.zip
spectre metadata report.pdf
```

### Domains and IPs

```bash
spectre domain example.com
spectre dns example.com
spectre ip 8.8.8.8
spectre web https://example.com
```

### Identity

```bash
spectre email person@example.com
spectre username analyst
```

### Crypto and hashes

```bash
spectre hash 5d41402abc4b2a76b9719d911017c592
spectre crypto SGVsbG8=
```

### Storage

```bash
spectre analyze example.com --save
spectre storage list
spectre storage show 1
```

## Current features

SPECTRE currently has:

- automatic target detection through `spectre analyze`
- plugin system
- reports in terminal, JSON, CSV, Markdown, and HTML
- SQLite investigation storage
- file analysis
- hash identification
- crypto decoding
- DNS lookup
- WHOIS lookup
- RDAP lookup
- IP lookup
- reverse DNS lookup
- ASN lookup
- SSL/TLS certificate lookup
- Certificate Transparency lookup
- GitHub user, organization, repository, and search analysis
- Wayback Machine lookup
- result extraction
- relationship building
- suggested next steps

## Current file analysis

File analysis currently checks:

- file type using magic bytes
- file hashes
- entropy
- readable strings
- whether the file extension matches the detected type

It does this without calling external tools like `file` or `strings`.

## Reports

Choose a report format:

```bash
spectre analyze example.com --format json
spectre analyze sample.pdf --format html --output report.html
```

Supported formats:

- terminal
- JSON
- CSV
- Markdown
- HTML

## Results

SPECTRE tries to pull out useful results automatically.

Examples:

- domains
- IP addresses
- URLs
- emails
- hashes
- GitHub repositories
- coordinates
- JWTs
- JavaScript endpoints

These results can later be used by other parts of SPECTRE.

## Project layout

```text
spectre/
  cli.py                  command-line interface
  crypto_engine.py         crypto decoder

  core/                    framework code
  analysis/                local analysis code
  sources/                 public data source adapters
  plugins/                 analysis plugins
```

Most users do not need to care about this structure.

The structure exists so SPECTRE stays maintainable as it grows.

## Contributing

Contributions are welcome.

Useful links:

- `CONTRIBUTING.md` explains how to set up the project and open a pull request.
- `SECURITY.md` explains how to report security issues.
- `CHANGELOG.md` tracks project changes.
- `docs/` contains the project vision, roadmap, module plan, and source policy.

Before opening a pull request, run:

```bash
python -m unittest discover -s tests -v
```

## Development direction

The next priorities are:

1. Make `spectre analyze <target>` smarter
2. Improve file analysis
3. Add metadata parsing
4. Add archive analysis
5. Add binary analysis
6. Add web analysis
7. Improve reports
8. Improve saved investigations

The architecture is for developers.

The CLI is for users.

SPECTRE should feel simple:

```bash
spectre analyze something
```

And it should just work.
