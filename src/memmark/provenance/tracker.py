"""Memory provenance tracker for AI agent memory systems.

Tracks the origin and evolution of each memory entry
to enable verification of legitimate vs injected memories.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass
class ProvenanceRecord:
    """Provenance record for a single memory entry."""

    memory_id: str
    source: str
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    modified_at: str | None = None
    version: int = 1
    parent_id: str | None = None
    chain_hash: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def compute_chain_hash(self, previous_hash: str = "") -> str:
        """Compute chain hash linking to previous record.

        Args:
            previous_hash: Hash of previous record in chain.

        Returns:
            New chain hash.
        """
        data = f"{previous_hash}:{self.memory_id}:{self.source}:{self.created_at}"
        return hashlib.sha256(data.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "memory_id": self.memory_id,
            "source": self.source,
            "created_at": self.created_at,
            "modified_at": self.modified_at,
            "version": self.version,
            "parent_id": self.parent_id,
            "chain_hash": self.chain_hash,
            "metadata": self.metadata,
        }


class ProvenanceTracker:
    """Tracks provenance of memory entries over time."""

    def __init__(self) -> None:
        """Initialize provenance tracker."""
        self.records: dict[str, ProvenanceRecord] = {}
        self.chain_head: str = ""

    def register(
        self,
        memory_id: str,
        source: str,
        metadata: dict[str, Any] | None = None,
        parent_id: str | None = None,
    ) -> ProvenanceRecord:
        """Register a new memory entry with provenance.

        Args:
            memory_id: Unique identifier for the memory.
            source: Origin source of the memory.
            metadata: Additional provenance metadata.
            parent_id: ID of parent memory if derived.

        Returns:
            Created ProvenanceRecord.
        """
        record = ProvenanceRecord(
            memory_id=memory_id,
            source=source,
            parent_id=parent_id,
            metadata=metadata or {},
        )
        record.chain_hash = record.compute_chain_hash(self.chain_head)
        self.chain_head = record.chain_hash
        self.records[memory_id] = record
        return record

    def update(
        self,
        memory_id: str,
        metadata: dict[str, Any] | None = None,
    ) -> ProvenanceRecord | None:
        """Update provenance for an existing memory entry.

        Args:
            memory_id: Memory entry identifier.
            metadata: Updated metadata.

        Returns:
            Updated ProvenanceRecord or None if not found.
        """
        record = self.records.get(memory_id)
        if not record:
            return None

        record.version += 1
        record.modified_at = datetime.now(UTC).isoformat()
        if metadata:
            record.metadata.update(metadata)
        record.chain_hash = record.compute_chain_hash(self.chain_head)
        self.chain_head = record.chain_hash
        return record

    def get_record(self, memory_id: str) -> ProvenanceRecord | None:
        """Get provenance record for a memory entry.

        Args:
            memory_id: Memory entry identifier.

        Returns:
            ProvenanceRecord or None.
        """
        return self.records.get(memory_id)

    def get_chain(self, memory_id: str) -> list[ProvenanceRecord]:
        """Get the full provenance chain for a memory entry.

        Args:
            memory_id: Memory entry identifier.

        Returns:
            List of ProvenanceRecord from origin to current.
        """
        chain: list[ProvenanceRecord] = []
        current_id: str | None = memory_id

        while current_id:
            record = self.records.get(current_id)
            if not record:
                break
            chain.append(record)
            current_id = record.parent_id

        chain.reverse()
        return chain

    def export(self) -> dict[str, Any]:
        """Export all provenance records.

        Returns:
            Dictionary of all records.
        """
        return {
            "chain_head": self.chain_head,
            "records": {
                mid: rec.to_dict() for mid, rec in self.records.items()
            },
        }

    def load(self, data: dict[str, Any]) -> None:
        """Load provenance records from exported data.

        Args:
            data: Exported provenance data.
        """
        self.chain_head = data.get("chain_head", "")
        for mid, rec_data in data.get("records", {}).items():
            record = ProvenanceRecord(
                memory_id=rec_data["memory_id"],
                source=rec_data["source"],
                created_at=rec_data.get("created_at", ""),
                modified_at=rec_data.get("modified_at"),
                version=rec_data.get("version", 1),
                parent_id=rec_data.get("parent_id"),
                chain_hash=rec_data.get("chain_hash", ""),
                metadata=rec_data.get("metadata", {}),
            )
            self.records[mid] = record

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.export(), indent=indent)
