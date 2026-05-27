# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Console reporter using Rich for MemMark scan results."""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from memmark.scanner import ScanResult, Severity


class ConsoleReporter:
    """Formats and displays scan results in the console."""

    def __init__(self, console: Console | None = None) -> None:
        """Initialize console reporter.

        Args:
            console: Rich Console instance.
        """
        self.console = console or Console()

    def report(self, result: ScanResult) -> None:
        """Display full scan report.

        Args:
            result: ScanResult to display.
        """
        self._display_header(result)
        self._display_findings(result)
        self._display_summary(result)

    def _display_header(self, result: ScanResult) -> None:
        """Display scan header panel."""
        summary = result.to_dict()["summary"]
        status = (
            "[green]CLEAN[/green]"
            if summary["is_clean"]
            else "[red]ISSUES DETECTED[/red]"
        )

        self.console.print(
            Panel(
                f"Scan ID: {result.scan_id}\n"
                f"Timestamp: {result.timestamp.isoformat()}\n"
                f"Status: {status}\n"
                f"Memory Hash: {result.memory_hash[:32]}...",
                title="MemMark Memory Integrity Report",
                border_style="green" if summary["is_clean"] else "red",
            ),
        )

    def _display_findings(self, result: ScanResult) -> None:
        """Display findings table."""
        if not result.findings:
            self.console.print("\n[green]No findings — memory is clean.[/green]")
            return

        table = Table(title="Findings", show_lines=True)
        table.add_column("Severity", style="bold", width=10)
        table.add_column("Type", width=20)
        table.add_column("Memory ID", width=15)
        table.add_column("Description")
        table.add_column("Remediation", width=30)

        severity_styles = {
            Severity.CRITICAL: "red",
            Severity.HIGH: "red",
            Severity.MEDIUM: "yellow",
            Severity.LOW: "blue",
            Severity.INFO: "white",
        }

        for finding in result.findings:
            style = severity_styles.get(finding.severity, "white")
            table.add_row(
                f"[{style}]{finding.severity.value.upper()}[/{style}]",
                finding.finding_type.value,
                finding.memory_id or "—",
                finding.description,
                finding.remediation or "—",
            )

        self.console.print(table)

    def _display_summary(self, result: ScanResult) -> None:
        """Display summary statistics."""
        summary = result.to_dict()["summary"]

        self.console.print(
            Panel(
                f"Total Findings: {summary['total']}\n"
                f"  Critical: {summary['critical']}\n"
                f"  High: {summary['high']}\n"
                f"  Medium: {summary['medium']}\n"
                f"  Low: {summary['low']}",
                title="Summary",
            ),
        )
