# PHM-Scanner Roadmap

The main goal is:

```bash
phm analyze <target>
```

PHM-Scanner should detect the target, run useful first-pass checks, summarize the results, and suggest what to investigate next.

## Rule for new work

Every new feature should answer yes to at least one question:

- Does it save time?
- Does it reduce manual work?
- Does it make the report clearer?
- Does it highlight something important?
- Does it help the user know what to do next?

If not, skip it for now.

## Priority 1: Improve `phm analyze`

Current detection supports:

- files
- domains
- IP addresses
- URLs
- emails
- usernames
- hashes
- GitHub repositories
- encoded text

Next:

- improve target scoring
- show better alternative interpretations
- choose better default checks
- avoid slow checks unless useful
- add `--fast`
- add `--deep`

## Priority 2: Improve file analysis

Current:

- magic bytes
- hashes
- entropy
- strings
- extension mismatch check
- URLs, domains, emails, IPs, hashes, JWTs, tokens, and API key detection
- embedded file signature checks
- possible secret checks

Next:

- more file signatures
- better embedded file detection
- better string extraction
- better suspicious pattern checks
- better summaries for files that deserve deeper analysis

## Priority 3: Improve binary triage

Current:

- basic PE hints
- basic ELF hints
- section entropy for PE
- suspicious import hints
- packer hints

Next:

- better PE parser
- better ELF parser
- Mach-O parser
- imports
- exports
- sections
- protections
- compiler clues
- clearer answer to: should I open this in Ghidra?

## Priority 4: Improve web analysis

Current:

- headers
- cookies
- security headers
- robots.txt
- sitemap.xml
- security.txt
- HTML comments
- JavaScript endpoints
- interesting parameters
- authentication clues
- technology clues

Next:

- better JavaScript endpoint extraction
- better API route detection
- better authentication clues
- better security header explanations
- better framework detection from multiple indicators

## Priority 5: Improve crypto analysis

Current:

- Base64
- Base32
- Base58
- Base85
- hex
- URL encoding
- ROT13
- Caesar-style shifts
- JWT
- compressed blob attempts
- XOR candidates
- hash identification

Next:

- better branch quality scoring
- better loop avoidance
- better readable-output detection
- basic frequency analysis
- Vigenere candidates where practical
- better PEM/OpenSSH handling

## Priority 6: Improve GitHub analysis

Current:

- users
- organizations
- repositories
- search
- contributors
- commits
- releases
- dependency/project files
- repository health
- redacted secret indicators

Next:

- repository timeline
- better CI/CD review
- better Docker/Terraform/Kubernetes clues
- dependency file parsing
- better secret rule configuration
- clearer repository summary

## Priority 7: Improve domain and IP summaries

Current:

- DNS
- WHOIS
- RDAP
- reverse DNS
- ASN
- TLS certificates
- Certificate Transparency

Next:

- better hosting provider summaries
- better CDN detection
- better mail provider summaries
- DNSSEC summary
- wildcard DNS check
- certificate summary cleanup
- ownership summary cleanup

## Priority 8: Improve reports

Current reports show:

- detected target type
- summary
- findings
- next steps

Next:

- better grouping of findings
- cleaner HTML reports
- better JSON structure for automation
- timeline section when useful
- fewer noisy details by default

## Lower priority

These can wait:

- GUI
- Shodan
- Censys
- SecurityTrails
- external tool integrations

First, make the default command genuinely useful.
