"""Reporting engine for SPECTRE outputs."""

from __future__ import annotations

import csv
import io
import json
from abc import ABC, abstractmethod
from html import escape
from pathlib import Path

from spectre.core.models import InvestigationReport, PluginResult, to_primitive


class Reporter(ABC):
    """Reporter base class."""

    format_name: str

    @abstractmethod
    def render(self, report: InvestigationReport) -> str:
        """Render an investigation report."""


class JSONReporter(Reporter):
    format_name = "json"

    def render(self, report: InvestigationReport) -> str:
        return json.dumps(to_primitive(report), indent=2, sort_keys=True, default=str)


class TerminalReporter(Reporter):
    format_name = "terminal"

    def render(self, report: InvestigationReport) -> str:
        lines: list[str] = []
        lines.append(f"SPECTRE Report :: {report.category.value.upper()} :: {report.target}")
        lines.append("=" * min(88, max(32, len(lines[-1]))))
        plan = report.metadata.get("analysis_plan") if isinstance(report.metadata, dict) else None
        if isinstance(plan, dict):
            detected = plan.get("target_type", "unknown")
            reason = plan.get("reason", "")
            lines.append(f"Detected: {detected}" + (f" ({reason})" if reason else ""))
        if not report.results:
            lines.append(report.metadata.get("message", "No results."))
            return "\n".join(lines)

        for result in report.results:
            lines.append("")
            status = result.status.upper()
            lines.append(f"[{status}] {result.plugin}")
            if result.errors:
                for error in result.errors:
                    lines.append(f"  ! {error}")
            if not result.findings:
                lines.append("  No findings.")
                continue
            for finding in result.findings:
                conf = round(finding.confidence * 100, 1)
                lines.append(f"  - {finding.title} ({finding.severity.value}, confidence={conf}%)")
                lines.append(f"    {finding.description}")
                for evidence in finding.evidence[:8]:
                    lines.append(f"    evidence: {evidence.source} = {evidence.value}")
                if len(finding.evidence) > 8:
                    lines.append(f"    ... {len(finding.evidence) - 8} more evidence items")

        next_steps = report.metadata.get("next_steps", []) if isinstance(report.metadata, dict) else []
        if next_steps:
            lines.append("")
            lines.append("Suggested next steps")
            lines.append("--------------------")
            for index, step in enumerate(next_steps[:6], start=1):
                title = step.get("title", "Review findings")
                why = step.get("why", "This may help continue the investigation.")
                priority = step.get("priority", "medium")
                lines.append(f"{index}. {title} [{priority}]")
                lines.append(f"   why: {why}")
                if step.get("command"):
                    lines.append(f"   try: {step['command']}")
        return "\n".join(lines)


class CSVReporter(Reporter):
    format_name = "csv"

    def render(self, report: InvestigationReport) -> str:
        buffer = io.StringIO()
        writer = csv.DictWriter(
            buffer,
            fieldnames=["category", "target", "plugin", "status", "title", "confidence", "severity", "description"],
        )
        writer.writeheader()
        for result in report.results:
            if not result.findings:
                writer.writerow(
                    {
                        "category": report.category.value,
                        "target": report.target,
                        "plugin": result.plugin,
                        "status": result.status,
                        "title": "",
                        "confidence": "",
                        "severity": "",
                        "description": "; ".join(result.errors),
                    }
                )
            for finding in result.findings:
                writer.writerow(
                    {
                        "category": report.category.value,
                        "target": report.target,
                        "plugin": result.plugin,
                        "status": result.status,
                        "title": finding.title,
                        "confidence": finding.confidence,
                        "severity": finding.severity.value,
                        "description": finding.description,
                    }
                )
        return buffer.getvalue()


class MarkdownReporter(Reporter):
    format_name = "markdown"

    def render(self, report: InvestigationReport) -> str:
        lines = [f"# SPECTRE Report: `{report.category.value}`", "", f"**Target:** `{report.target}`", ""]
        for result in report.results:
            lines.extend([f"## {result.plugin} ({result.status})", ""])
            for error in result.errors:
                lines.append(f"> Error: {error}")
            if not result.findings:
                lines.extend(["No findings.", ""])
                continue
            for finding in result.findings:
                lines.extend(
                    [
                        f"### {finding.title}",
                        "",
                        f"- Confidence: `{finding.confidence:.2f}`",
                        f"- Severity: `{finding.severity.value}`",
                        f"- Description: {finding.description}",
                        "",
                    ]
                )
                if finding.evidence:
                    lines.append("Evidence:")
                    for evidence in finding.evidence:
                        lines.append(f"- `{evidence.source}`: `{evidence.value}`")
                    lines.append("")
        next_steps = report.metadata.get("next_steps", []) if isinstance(report.metadata, dict) else []
        if next_steps:
            lines.extend(["## Suggested next steps", ""])
            for index, step in enumerate(next_steps, start=1):
                lines.append(f"{index}. **{step.get('title', 'Review findings')}** — {step.get('why', '')}")
                if step.get("command"):
                    lines.append(f"   - Try: `{step['command']}`")
            lines.append("")
        return "\n".join(lines)


class HTMLReporter(Reporter):
    format_name = "html"

    def render(self, report: InvestigationReport) -> str:
        body = [
            "<!doctype html><html><head><meta charset='utf-8'>",
            "<title>SPECTRE Report</title>",
            "<style>body{font-family:system-ui;margin:2rem;background:#0f1220;color:#e8eaf6}"
            ".card{border:1px solid #30364d;border-radius:12px;padding:1rem;margin:1rem 0;background:#171b2e}"
            ".muted{color:#aab}.ok{color:#7ee787}.error{color:#ff7b72}code{background:#222842;padding:.15rem .35rem;border-radius:4px}</style>",
            "</head><body>",
            f"<h1>SPECTRE Report: {escape(report.category.value)}</h1>",
            f"<p class='muted'>Target: <code>{escape(report.target)}</code></p>",
        ]
        for result in report.results:
            body.append(f"<section class='card'><h2>{escape(result.plugin)} <span class='{escape(result.status)}'>{escape(result.status)}</span></h2>")
            for error in result.errors:
                body.append(f"<p class='error'>{escape(error)}</p>")
            if not result.findings:
                body.append("<p>No findings.</p></section>")
                continue
            for finding in result.findings:
                body.append(f"<h3>{escape(finding.title)}</h3>")
                body.append(f"<p>{escape(finding.description)}</p>")
                body.append(f"<p class='muted'>confidence={finding.confidence:.2f}; severity={escape(finding.severity.value)}</p>")
                if finding.evidence:
                    body.append("<ul>")
                    for evidence in finding.evidence:
                        body.append(f"<li><code>{escape(evidence.source)}</code>: {escape(str(evidence.value))}</li>")
                    body.append("</ul>")
            body.append("</section>")
        next_steps = report.metadata.get("next_steps", []) if isinstance(report.metadata, dict) else []
        if next_steps:
            body.append("<section class='card'><h2>Suggested next steps</h2><ol>")
            for step in next_steps:
                body.append(f"<li><strong>{escape(step.get('title', 'Review findings'))}</strong><br><span class='muted'>{escape(step.get('why', ''))}</span>")
                if step.get("command"):
                    body.append(f"<br><code>{escape(step['command'])}</code>")
                body.append("</li>")
            body.append("</ol></section>")
        body.append("</body></html>")
        return "\n".join(body)


REPORTERS: dict[str, Reporter] = {
    reporter.format_name: reporter
    for reporter in [TerminalReporter(), JSONReporter(), CSVReporter(), MarkdownReporter(), HTMLReporter()]
}


def render_report(report: InvestigationReport, output_format: str = "terminal") -> str:
    try:
        reporter = REPORTERS[output_format]
    except KeyError as exc:
        known = ", ".join(sorted(REPORTERS))
        raise ValueError(f"Unsupported report format '{output_format}'. Known formats: {known}") from exc
    return reporter.render(report)


def write_report(rendered: str, path: str | Path) -> None:
    Path(path).write_text(rendered, encoding="utf-8")
