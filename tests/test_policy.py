"""Tests for the MCPGuard policy generation module."""

import tempfile
from pathlib import Path

import yaml

from memmark.policy.generator import MCPGuardPolicy
from memmark.scanner import Finding, FindingType, ScanResult, Severity


class TestMCPGuardPolicy:
    def test_init(self) -> None:
        policy = MCPGuardPolicy()
        assert policy.denied_tools == []
        assert not policy.block_injection
        assert not policy.is_restrictive

    def test_from_clean_scan(self, clean_scan_result: ScanResult) -> None:
        policy = MCPGuardPolicy.from_scan_result(clean_scan_result)
        assert not policy.is_restrictive
        assert not policy.block_injection

    def test_from_scan_with_findings(self, findings_scan_result: ScanResult) -> None:
        policy = MCPGuardPolicy.from_scan_result(findings_scan_result)
        assert policy.is_restrictive
        assert policy.block_injection
        assert policy.block_poisoning

    def test_poisoning_sets_block_flags(self, poisoned_scan_result: ScanResult) -> None:
        policy = MCPGuardPolicy.from_scan_result(poisoned_scan_result)
        assert policy.block_poisoning

    def test_add_denied_tool(self) -> None:
        policy = MCPGuardPolicy()
        policy.add_denied_tool("exec")
        assert "exec" in policy.denied_tools

    def test_add_denied_tool_dedup(self) -> None:
        policy = MCPGuardPolicy()
        policy.add_denied_tool("exec")
        policy.add_denied_tool("exec")
        assert policy.denied_tools == ["exec"]

    def test_add_allowed_tool(self) -> None:
        policy = MCPGuardPolicy()
        policy.add_allowed_tool("read_file")
        assert "read_file" in policy.allowed_tools

    def test_poisoning_with_tool_name(self) -> None:
        result = ScanResult(
            scan_id="test",
            findings=[
                Finding(
                    FindingType.POISONING_DETECTED,
                    Severity.CRITICAL,
                    "Bad tool",
                    evidence={"tool_name": "exec_shell"},
                ),
            ],
        )
        policy = MCPGuardPolicy.from_scan_result(result)
        assert "exec_shell" in policy.denied_tools

    def test_to_yaml_format(self) -> None:
        policy = MCPGuardPolicy()
        policy.block_injection = True
        policy.block_poisoning = True
        policy.add_denied_tool("exec")
        yaml_str = policy.to_yaml()
        assert "block_on_injection: true" in yaml_str
        assert "block_on_poisoning: true" in yaml_str
        assert "exec" in yaml_str

    def test_to_yaml_parses(self) -> None:
        policy = MCPGuardPolicy()
        yaml_str = policy.to_yaml()
        data = yaml.safe_load(yaml_str)
        assert data["mode"] == "http"
        assert data["rate_limit"] == 100

    def test_save(self) -> None:
        policy = MCPGuardPolicy()
        with tempfile.NamedTemporaryFile(suffix=".yaml", delete=False, mode="w") as f:
            policy.save(f.name)
            path = f.name
        try:
            content = Path(path).read_text()
            assert "mode: http" in content
        finally:
            Path(path).unlink()

    def test_default_rate_limit(self) -> None:
        policy = MCPGuardPolicy.from_scan_result(
            ScanResult(scan_id="test"),
            rate_limit=50,
            rate_window=30,
        )
        assert policy.rate_limit == 50
        assert policy.rate_window == 30

    def test_provenance_invalid_sets_injection_block(self) -> None:
        result = ScanResult(
            scan_id="test",
            findings=[
                Finding(
                    FindingType.PROVENANCE_INVALID, Severity.HIGH, "Bad provenance"
                ),
            ],
        )
        policy = MCPGuardPolicy.from_scan_result(result)
        assert policy.block_injection

    def test_anomaly_critical_sets_resource_scan(self) -> None:
        result = ScanResult(
            scan_id="test",
            findings=[
                Finding(
                    FindingType.ANOMALY_DETECTED, Severity.CRITICAL, "Critical anomaly"
                ),
            ],
        )
        policy = MCPGuardPolicy.from_scan_result(result)
        assert policy.block_resource_scan
