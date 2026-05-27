# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Memory protection policy generator for MCPGuard.

Generates MCPGuard-compatible YAML policies from MemMark scan findings
to automatically configure runtime protection for agent memory systems.
"""

from __future__ import annotations

from typing import Any

import yaml

from memmark.scanner import Finding, FindingType, ScanResult, Severity


class MCPGuardPolicy:
    """MCPGuard-compatible protection policy generated from scan findings."""

    def __init__(self) -> None:
        self.denied_tools: list[str] = []
        self.allowed_tools: list[str] = []
        self.block_injection: bool = False
        self.block_poisoning: bool = False
        self.block_resource_scan: bool = False
        self.rate_limit: int = 100
        self.rate_window: int = 60
        self.metadata: dict[str, Any] = {}

    @classmethod
    def from_scan_result(
        cls,
        result: ScanResult,
        rate_limit: int = 100,
        rate_window: int = 60,
    ) -> MCPGuardPolicy:
        """Generate a policy from a scan result.

        Args:
            result: ScanResult from memory analysis.
            rate_limit: Max requests per time window.
            rate_window: Rate limit window in seconds.

        Returns:
            MCPGuardPolicy with rules derived from findings.
        """
        policy = cls()
        policy.rate_limit = rate_limit
        policy.rate_window = rate_window

        for finding in result.findings:
            policy._apply_finding(finding)

        return policy

    def _apply_finding(self, finding: Finding) -> None:
        """Apply a single finding to the policy rules.

        Args:
            finding: Finding to translate into policy rules.
        """
        if finding.finding_type == FindingType.POISONING_DETECTED:
            self.block_poisoning = True
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                self.block_injection = True
                if finding.evidence:
                    tool_hint = finding.evidence.get("tool_name")
                    if tool_hint:
                        self.denied_tools.append(tool_hint)

        elif finding.finding_type == FindingType.INTEGRITY_MODIFIED:
            self.block_injection = True
            self.block_poisoning = True

        elif finding.finding_type == FindingType.ANOMALY_DETECTED:
            if finding.severity == Severity.CRITICAL:
                self.block_resource_scan = True

        elif finding.finding_type in (
            FindingType.WATERMARK_MISSING,
            FindingType.WATERMARK_DETECTED,
        ):
            if finding.severity in (Severity.CRITICAL, Severity.HIGH):
                self.block_poisoning = True

        elif finding.finding_type == FindingType.PROVENANCE_INVALID:
            self.block_injection = True

    def add_denied_tool(self, tool_name: str) -> None:
        """Add a tool to the deny list.

        Args:
            tool_name: Tool name or pattern to deny.
        """
        if tool_name not in self.denied_tools:
            self.denied_tools.append(tool_name)

    def add_allowed_tool(self, tool_name: str) -> None:
        """Add a tool to the allow list.

        Args:
            tool_name: Tool name or pattern to allow.
        """
        if tool_name not in self.allowed_tools:
            self.allowed_tools.append(tool_name)

    def to_yaml(self) -> str:
        """Serialize policy to YAML string.

        Returns:
            YAML-formatted policy string.
        """
        config: dict[str, Any] = {
            "mode": "http",
            "listen_host": "127.0.0.1",
            "listen_port": 8080,
        }

        if self.allowed_tools:
            config["allow"] = sorted(self.allowed_tools)
        if self.denied_tools:
            config["deny"] = sorted(self.denied_tools)

        if self.block_injection:
            config["block_on_injection"] = True
        if self.block_poisoning:
            config["block_on_poisoning"] = True
        if self.block_resource_scan:
            config["block_on_resource_scan"] = True

        config["rate_limit"] = self.rate_limit
        config["rate_window"] = self.rate_window

        config["log_dir"] = "./mcpguard_logs"

        if self.metadata:
            config["metadata"] = self.metadata

        return yaml.dump(config, default_flow_style=False, sort_keys=False)

    def save(self, path: str) -> None:
        """Save policy to a YAML file.

        Args:
            path: Output file path.
        """
        from pathlib import Path

        Path(path).write_text(self.to_yaml(), encoding="utf-8")

    @property
    def is_restrictive(self) -> bool:
        """Check if policy applies any blocking rules."""
        return self.block_injection or self.block_poisoning or self.block_resource_scan
