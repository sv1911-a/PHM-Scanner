# Spectre Roadmap

Spectre has one goal:

```bash
spectre analyze <target>
```

The user shouldn't have to decide which tools to use.
Spectre should detect the target, perform the most useful first-pass analysis, highlight what matters, and suggest what to investigate next.

---

## Current Focus

Improve the default experience.

Every improvement should make Spectre:

- Faster to use
- Easier to understand
- More useful during real investigations
- Better at reducing repetitive work

If a feature doesn't improve one of those, it can wait.

---

# Near-term Goals

## Better Detection

- Improve target classification
- Handle ambiguous inputs more intelligently
- Show alternative interpretations when appropriate
- Improve default analysis selection

---

## Better Reports

- Cleaner terminal output
- Better summaries
- Less raw data
- Highlight important findings first
- Better HTML reports

---

## Better File Analysis

- Detect embedded files
- Improve string extraction
- Extract URLs, domains and emails
- Detect suspicious patterns
- Better file summaries

---

## Better Metadata

- Images (EXIF, GPS)
- PDFs
- Office documents
- Useful timestamps
- Author information

---

## Better Archive Analysis

- ZIP
- TAR
- GZIP
- Nested archives
- Recursive analysis

---

## Better Binary Analysis

- ELF
- PE
- Mach-O
- Imports
- Sections
- Entropy
- Compiler information
- Interesting strings

---

## Better Web Analysis

- robots.txt
- sitemap.xml
- Security headers
- JavaScript endpoint discovery
- Interesting parameters
- Authentication clues

---

## Better Infrastructure Analysis

Continue improving:

- DNS
- RDAP
- WHOIS
- ASN
- TLS
- Certificate Transparency

Focus on better summaries instead of more raw data.

---

## Better GitHub Analysis

- Repository timeline
- Dependency analysis
- CI/CD clues
- Infrastructure files
- Better secret detection

---

# Future

These are useful, but not important yet.

- GUI
- PDF reports
- Shodan
- Censys
- SecurityTrails
- External tool integrations
- AI features

---

# Guiding Principle

Whenever adding a feature, ask:

> Would this have saved me time during a real CTF or security investigation?

If the answer is no, don't build it yet.
