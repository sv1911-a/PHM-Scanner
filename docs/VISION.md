# PHM-Scanner Vision

PHM-Scanner is a command-line tool that analyzes cybersecurity targets and performs the first steps of an investigation automatically.

The main command is:

```bash
phm analyze <target>
```

The user gives PHM something. PHM figures out what it is, runs useful checks, summarizes what matters, and suggests what to investigate next.

## What problem does PHM solve?

Security work often starts with the same questions:

```text
What is this?
What stands out?
What should I check next?
```

A file needs hashes and strings.

A domain needs DNS, certificates, and ownership checks.

A website needs headers, technologies, robots.txt, sitemap, and endpoints.

A hash needs identification.

Encoded text needs decoding attempts.

PHM-Scanner handles that first pass so the user can focus on the real problem.

## What PHM-Scanner should feel like

```bash
phm analyze suspicious.exe
```

PHM-Scanner should answer:

- what kind of file is it?
- what are its hashes?
- are there useful strings?
- are there URLs, domains, or secrets inside?
- should I open it in a reverse engineering tool?

```bash
phm analyze example.com
```

PHM-Scanner should answer:

- what DNS records exist?
- who owns it?
- what certificates are visible?
- is there a public website?
- what should I check next?

## What PHM-Scanner is not

PHM-Scanner is not:

- an auto-solver
- a replacement for analysts
- a replacement for specialist tools
- a dashboard for third-party OSINT platforms

PHM-Scanner should help users work faster, not pretend to think for them.

## Design rules

PHM should:

- choose useful checks automatically
- keep the main command simple
- show summaries before details
- explain why findings matter
- suggest next steps
- avoid noisy output by default
- show raw details only when the user asks for them

## Development focus

Do not add new areas unless there is a strong reason.

Improve the current areas first:

- crypto decoding
- file analysis
- binary triage
- web analysis
- GitHub repository review
- infrastructure summaries
- finding extraction
- reporting

## Success criteria

A user should finish using PHM-Scanner thinking:

```text
That saved me time.
I did not have to remember ten tools.
It showed me where to look next.
I will keep this installed.
```
