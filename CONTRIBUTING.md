# Contributing to PHM-Scanner

PHM-Scanner is currently a single-maintainer project.

Issues and pull requests are welcome, but the scope should stay focused:

```bash
phm analyze <target>
```

The goal is to make that command more useful.

## Before adding something

Ask:

1. Does this save time during a real investigation or CTF?
2. Does this improve an existing check?
3. Does this make reports clearer?
4. Does this reduce manual work?
5. Can it work without adding a required external service?

If the answer is no, it can probably wait.

## Setup

```bash
git clone https://github.com/<your-username>/phm.git
cd phm
python -m pip install -e ".[dns]"
python -m unittest discover -s tests -v
```

## Running locally

```bash
python -m phm.cli analyze example.com
python -m phm.cli analyze SGVsbG8=
python -m phm.cli analyze README.md
```

## Tests

Run all tests before opening a pull request:

```bash
python -m unittest discover -s tests -v
```

Add tests when changing parsing, detection, reporting, or analysis behavior.

## Safety

Do not add features whose main purpose is credential theft, stealth, persistence, evasion, or unauthorized access.

PHM-Scanner is for authorized analysis, education, research, defense, and CTF practice.

## Pull requests

A good pull request includes:

- what changed
- why it helps the user
- tests
- documentation updates if behavior changed

Do not commit secrets, API keys, databases, generated reports, or private investigation data.
