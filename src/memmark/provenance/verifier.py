# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Memory provenance verifier for AI agent memory systems.

Verifies the integrity and authenticity of provenance chains
to detect tampered or forged memory origins.
"""

from __future__ import annotations

from typing import Any

from memmark.provenance.tracker import ProvenanceRecord, ProvenanceTracker


class ProvenanceVerifier:
    """Verifies provenance chains for memory entries."""

    def __init__(self) -> None:
        """Initialize provenance verifier."""

    def verify_chain(self, tracker: ProvenanceTracker) -> dict[str, Any]:
        """Verify the integrity of the entire provenance chain.

        Args:
            tracker: ProvenanceTracker with records to verify.

        Returns:
            Verification result with validity and any issues found.
        """
        issues: list[str] = []
        records = list(tracker.records.values())

        if not records:
            return {
                "valid": True,
                "record_count": 0,
                "issues": [],
            }

        # Verify chain linkage
        previous_hash = ""
        for record in records:
            expected_hash = record.compute_chain_hash(previous_hash)
            if record.chain_hash != expected_hash:
                issues.append(
                    f"Chain hash mismatch for memory {record.memory_id}",
                )
            previous_hash = record.chain_hash

        # Verify chain head
        if records and tracker.chain_head != previous_hash:
            issues.append("Chain head does not match last record hash")

        return {
            "valid": len(issues) == 0,
            "record_count": len(records),
            "chain_head_valid": tracker.chain_head == previous_hash,
            "issues": issues,
        }

    def verify_entry(
        self,
        record: ProvenanceRecord,
        previous_hash: str = "",
    ) -> dict[str, Any]:
        """Verify a single provenance record.

        Args:
            record: ProvenanceRecord to verify.
            previous_hash: Expected previous chain hash.

        Returns:
            Verification result for the record.
        """
        expected_hash = record.compute_chain_hash(previous_hash)
        is_valid = record.chain_hash == expected_hash

        return {
            "memory_id": record.memory_id,
            "valid": is_valid,
            "expected_hash": expected_hash,
            "actual_hash": record.chain_hash,
            "source": record.source,
            "version": record.version,
        }

    def detect_forged_provenance(
        self,
        memories: list[dict[str, Any]],
        tracker: ProvenanceTracker,
    ) -> list[dict[str, Any]]:
        """Detect memory entries with forged or missing provenance.

        Args:
            memories: Current memory entries.
            tracker: ProvenanceTracker with known records.

        Returns:
            List of entries with provenance issues.
        """
        suspicious: list[dict[str, Any]] = []

        for entry in memories:
            memory_id: Any = entry.get("id", entry.get("memory_id"))
            if not isinstance(memory_id, str):
                continue
            record = tracker.get_record(memory_id)

            if not record:
                suspicious.append(
                    {
                        "memory_id": memory_id,
                        "issue": "no_provenance_record",
                        "severity": "high",
                    }
                )
                continue

            verification = self.verify_entry(record)
            if not verification["valid"]:
                suspicious.append(
                    {
                        "memory_id": memory_id,
                        "issue": "provenance_chain_invalid",
                        "severity": "critical",
                        "details": verification,
                    }
                )

        return suspicious
