# Contributing to SPECTRE

Thanks for wanting to contribute.

SPECTRE is a cybersecurity workflow accelerator. The main user experience should stay simple:

```bash
spectre analyze <target>
```

The internal architecture can be modular, but the user should not need to understand it.

## Project principles

Before adding a feature, ask:

1. Does this save time for the user?
2. Does this reduce manual effort?
3. Does this make the report clearer?
4. Does this help the user know what to investigate next?
5. Can this be implemented natively instead of wrapping another tool?
6. Is the result deterministic and explainable?

Avoid features that are only technically interesting but do not improve the workflow.

## Development setup

```bash
git clone https://github.com/<your-username>/spectre.git
cd spectre
python -m pip install -e ".[dev,dns]"
python -m unittest discover -s tests -v
```

SPECTRE currently has no required runtime dependencies beyond Python's standard library.
Optional extras exist for better DNS support and development tools.

## Running SPECTRE locally

```bash
python -m spectre.cli --list-plugins
python -m spectre.cli analyze example.com
python -m spectre.cli analyze README.md
python -m spectre.cli analyze SGVsbG8=
```

## Adding a plugin

Plugins live in `spectre/plugins/`.

Every plugin should implement:

```python
detect()
collect()
analyze()
report()
```

A plugin should also describe what it does when possible:

```python
module = "file"
capability = "native_file_triage"
consumes = ("file",)
produces = ("hash", "string", "url")
local_first = True
network_required = False
external_tool_required = False
```

## Testing

Run all tests before opening a pull request:

```bash
python -m unittest discover -s tests -v
```

If you add a parser, plugin, detector, or report feature, add tests for it.

## Security and ethics

Only add features that support authorized analysis, research, education, defense, or CTF-style learning.

Do not add features whose primary purpose is credential theft, stealth, persistence, evasion, unauthorized access, or exploitation without clear defensive value.

## Pull requests

A good pull request should include:

- a short explanation of the user benefit
- tests
- documentation updates if user-facing behavior changes
- no secrets, API keys, databases, or generated reports committed
