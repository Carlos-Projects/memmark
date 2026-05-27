# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""HTML reporter for MemMark scan results using Jinja2 templates."""

from __future__ import annotations

from pathlib import Path

from jinja2 import BaseLoader, Environment

from memmark.scanner import ScanResult

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>MemMark Scan Report — {{ scan_id }}</title>
    <style>
        body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }
        .container { max-width: 900px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
        h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
        .status { padding: 15px; border-radius: 4px; margin: 20px 0; }
        .status.clean { background: #d4edda; color: #155724; border: 1px solid #c3e6cb; }
        .status.issues { background: #f8d7da; color: #721c24; border: 1px solid #f5c6cb; }
        table { width: 100%; border-collapse: collapse; margin: 20px 0; }
        th, td { padding: 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background: #f8f9fa; font-weight: 600; }
        .severity-critical { color: #dc3545; font-weight: bold; }
        .severity-high { color: #dc3545; }
        .severity-medium { color: #ffc107; }
        .severity-low { color: #17a2b8; }
        .severity-info { color: #6c757d; }
        .meta { color: #666; font-size: 0.9em; }
        .summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
        .summary-card { flex: 1; min-width: 120px; padding: 15px; background: #f8f9fa; border-radius: 4px; text-align: center; }
        .summary-card .count { font-size: 2em; font-weight: bold; }
        .summary-card .label { color: #666; font-size: 0.85em; }
    </style>
</head>
<body>
    <div class="container">
        <h1>MemMark Memory Integrity Report</h1>
        <p class="meta">Scan ID: {{ scan_id }} | Generated: {{ timestamp }}</p>

        <div class="status {{ 'clean' if is_clean else 'issues' }}">
            <strong>Status:</strong> {{ 'CLEAN — No critical or high severity findings' if is_clean else 'ISSUES DETECTED — Review findings below' }}
        </div>

        <div class="summary">
            <div class="summary-card"><div class="count">{{ total }}</div><div class="label">Total</div></div>
            <div class="summary-card"><div class="count" style="color:#dc3545">{{ critical }}</div><div class="label">Critical</div></div>
            <div class="summary-card"><div class="count" style="color:#dc3545">{{ high }}</div><div class="label">High</div></div>
            <div class="summary-card"><div class="count" style="color:#ffc107">{{ medium }}</div><div class="label">Medium</div></div>
            <div class="summary-card"><div class="count" style="color:#17a2b8">{{ low }}</div><div class="label">Low</div></div>
        </div>

        {% if findings %}
        <h2>Findings</h2>
        <table>
            <thead>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Memory ID</th>
                    <th>Description</th>
                    <th>Remediation</th>
                </tr>
            </thead>
            <tbody>
                {% for finding in findings %}
                <tr>
                    <td class="severity-{{ finding.severity }}">{{ finding.severity | upper }}</td>
                    <td>{{ finding.finding_type }}</td>
                    <td>{{ finding.memory_id or '—' }}</td>
                    <td>{{ finding.description }}</td>
                    <td>{{ finding.remediation or '—' }}</td>
                </tr>
                {% endfor %}
            </tbody>
        </table>
        {% else %}
        <p style="color: #28a745; font-weight: bold;">No findings — memory integrity verified.</p>
        {% endif %}

        <p class="meta">Memory Hash: {{ memory_hash }}</p>
    </div>
</body>
</html>
"""


class HtmlReporter:
    """Generates HTML reports from scan results."""

    def __init__(self) -> None:
        """Initialize HTML reporter with Jinja2 template."""
        self.env = Environment(loader=BaseLoader())
        self.template = self.env.from_string(HTML_TEMPLATE)

    def render(self, result: ScanResult) -> str:
        """Render scan result as HTML.

        Args:
            result: ScanResult to render.

        Returns:
            HTML string.
        """
        summary = result.to_dict()["summary"]
        return self.template.render(  # type: ignore[no-any-return]
            scan_id=result.scan_id,
            timestamp=result.timestamp.isoformat(),
            memory_hash=result.memory_hash,
            is_clean=summary["is_clean"],
            findings=[
                {
                    "severity": f.severity.value,
                    "finding_type": f.finding_type.value,
                    "memory_id": f.memory_id,
                    "description": f.description,
                    "remediation": f.remediation,
                }
                for f in result.findings
            ],
            total=summary["total"],
            critical=summary["critical"],
            high=summary["high"],
            medium=summary["medium"],
            low=summary["low"],
        )

    def save(self, result: ScanResult, path: str | Path) -> None:
        """Save HTML report to file.

        Args:
            result: ScanResult to render.
            path: Output file path.
        """
        content = self.render(result)
        Path(path).write_text(content, encoding="utf-8")
