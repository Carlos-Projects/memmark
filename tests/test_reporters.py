"""Tests for the reporter modules."""

import tempfile
from pathlib import Path

from memmark.reporters.console import ConsoleReporter
from memmark.reporters.html import HtmlReporter
from memmark.reporters.json import JsonReporter
from memmark.scanner import Finding, FindingType, ScanResult, Severity


def _make_result() -> ScanResult:
    return ScanResult(
        scan_id="test-report",
        findings=[
            Finding(
                FindingType.WATERMARK_MISSING,
                Severity.LOW,
                "Missing watermark",
                memory_id="mem-001",
            ),
            Finding(
                FindingType.POISONING_DETECTED,
                Severity.HIGH,
                "Poisoning detected",
                memory_id="mem-002",
            ),
        ],
    )


SAMPLE_RESULT = _make_result()
CLEAN_RESULT = ScanResult(scan_id="clean", memory_hash="abc")


class TestJsonReporter:
    def test_render(self) -> None:
        reporter = JsonReporter()
        output = reporter.render(SAMPLE_RESULT)
        assert "scan_id" in output
        assert "findings" in output
        assert "test-report" in output

    def test_render_clean(self) -> None:
        reporter = JsonReporter()
        output = reporter.render(CLEAN_RESULT)
        assert "is_clean" in output

    def test_save(self) -> None:
        reporter = JsonReporter()
        with tempfile.NamedTemporaryFile(suffix=".json", delete=False, mode="w") as f:
            reporter.save(SAMPLE_RESULT, f.name)
            path = f.name
        try:
            content = Path(path).read_text()
            assert "test-report" in content
        finally:
            Path(path).unlink()

    def test_render_findings_only(self) -> None:
        reporter = JsonReporter()
        output = reporter.render_findings_only(SAMPLE_RESULT)
        assert "WATERMARK_MISSING" in output or "watermark_missing" in output


class TestConsoleReporter:
    def test_report_with_findings(self) -> None:
        reporter = ConsoleReporter()
        # Just ensure it doesn't crash
        reporter.report(SAMPLE_RESULT)

    def test_report_clean(self) -> None:
        reporter = ConsoleReporter()
        reporter.report(CLEAN_RESULT)


class TestHtmlReporter:
    def test_render_with_findings(self) -> None:
        reporter = HtmlReporter()
        output = reporter.render(SAMPLE_RESULT)
        assert "MemMark" in output
        assert "scan_id" in output or "test-report" in output
        assert "MemMark" in output

    def test_render_clean(self) -> None:
        reporter = HtmlReporter()
        output = reporter.render(CLEAN_RESULT)
        assert "CLEAN" in output or "clean" in output.lower()

    def test_save(self) -> None:
        reporter = HtmlReporter()
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False, mode="w") as f:
            reporter.save(SAMPLE_RESULT, f.name)
            path = f.name
        try:
            content = Path(path).read_text()
            assert "MemMark" in content
        finally:
            Path(path).unlink()
