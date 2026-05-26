"""JSON reporter for MemMark scan results."""

from __future__ import annotations

import json
from pathlib import Path

from memmark.scanner import ScanResult


class JsonReporter:
    """Exports scan results as JSON."""

    def render(self, result: ScanResult, indent: int = 2) -> str:
        """Render scan result as JSON string.

        Args:
            result: ScanResult to render.
            indent: JSON indentation level.

        Returns:
            JSON string.
        """
        return json.dumps(result.to_dict(), indent=indent, default=str)

    def save(self, result: ScanResult, path: str | Path) -> None:
        """Save scan result to JSON file.

        Args:
            result: ScanResult to save.
            path: Output file path.
        """
        content = self.render(result)
        Path(path).write_text(content, encoding="utf-8")

    def render_findings_only(self, result: ScanResult) -> str:
        """Render only findings as JSON array.

        Args:
            result: ScanResult to render.

        Returns:
            JSON array string.
        """
        findings = [f.to_dict() for f in result.findings]
        return json.dumps(findings, indent=2, default=str)
