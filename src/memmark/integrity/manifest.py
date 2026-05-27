# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Memory integrity manifest for AI agent memory systems.

Generates and verifies SHA-256 manifests of memory state
for tamper detection and integrity verification.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from memmark.utils.crypto import hash_memory_entry, hash_memory_state


@dataclass
class EntryManifest:
    """Manifest entry for a single memory item."""

    memory_id: str
    hash: str
    size: int
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "memory_id": self.memory_id,
            "hash": self.hash,
            "size": self.size,
            "metadata": self.metadata,
        }


@dataclass
class IntegrityManifest:
    """Complete integrity manifest for a memory state."""

    manifest_id: str
    version: str = "1.0"
    created_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat())
    source: str = ""
    memory_hash: str = ""
    entry_count: int = 0
    entries: list[EntryManifest] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def create(
        cls,
        memories: list[dict[str, Any]],
        source: str = "",
        metadata: dict[str, Any] | None = None,
    ) -> IntegrityManifest:
        """Create a new integrity manifest from memory entries.

        Args:
            memories: List of memory entry dictionaries.
            source: Source identifier for the memory.
            metadata: Additional metadata.

        Returns:
            New IntegrityManifest instance.
        """
        entry_manifests = []
        for entry in memories:
            memory_id = entry.get("id", entry.get("memory_id", "unknown"))
            content = json.dumps(entry, sort_keys=True, separators=(",", ":"))
            entry_manifests.append(
                EntryManifest(
                    memory_id=memory_id,
                    hash=hash_memory_entry(entry),
                    size=len(content),
                ),
            )

        return cls(
            manifest_id=str(uuid.uuid4()),
            source=source,
            memory_hash=hash_memory_state(memories),
            entry_count=len(memories),
            entries=entry_manifests,
            metadata=metadata or {},
        )

    @classmethod
    def load(cls, path: str | Path) -> IntegrityManifest:
        """Load manifest from a JSON file.

        Args:
            path: Path to manifest JSON file.

        Returns:
            Loaded IntegrityManifest instance.
        """
        with open(path, encoding="utf-8") as f:
            data = json.load(f)

        entries = [
            EntryManifest(
                memory_id=e["memory_id"],
                hash=e["hash"],
                size=e["size"],
                metadata=e.get("metadata", {}),
            )
            for e in data.get("entries", [])
        ]

        return cls(
            manifest_id=data["manifest_id"],
            version=data.get("version", "1.0"),
            created_at=data.get("created_at", ""),
            source=data.get("source", ""),
            memory_hash=data["memory_hash"],
            entry_count=data.get("entry_count", 0),
            entries=entries,
            metadata=data.get("metadata", {}),
        )

    def save(self, path: str | Path) -> None:
        """Save manifest to a JSON file.

        Args:
            path: Output path for manifest JSON.
        """
        data = self.to_dict()
        Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def verify(self, current_hash: str) -> bool:
        """Verify memory state against this manifest.

        Args:
            current_hash: Current SHA-256 hash of memory state.

        Returns:
            True if hash matches manifest.
        """
        return self.memory_hash == current_hash

    def verify_entries(
        self,
        memories: list[dict[str, Any]],
    ) -> dict[str, Any]:
        """Verify individual memory entries against manifest.

        Args:
            memories: Current memory entries.

        Returns:
            Verification results per entry.
        """
        manifest_map = {e.memory_id: e for e in self.entries}
        results: dict[str, Any] = {
            "total": len(memories),
            "verified": 0,
            "modified": 0,
            "missing": 0,
            "new": 0,
            "details": [],
        }

        current_ids = set()
        for entry in memories:
            memory_id = entry.get("id", entry.get("memory_id", "unknown"))
            current_ids.add(memory_id)
            current_hash = hash_memory_entry(entry)

            manifest_entry = manifest_map.get(memory_id)
            if not manifest_entry:
                results["new"] += 1
                results["details"].append(
                    {
                        "memory_id": memory_id,
                        "status": "new",
                    }
                )
            elif manifest_entry.hash != current_hash:
                results["modified"] += 1
                results["details"].append(
                    {
                        "memory_id": memory_id,
                        "status": "modified",
                        "expected_hash": manifest_entry.hash,
                        "actual_hash": current_hash,
                    }
                )
            else:
                results["verified"] += 1
                results["details"].append(
                    {
                        "memory_id": memory_id,
                        "status": "verified",
                    }
                )

        # Check for missing entries
        for manifest_entry in self.entries:
            if manifest_entry.memory_id not in current_ids:
                results["missing"] += 1
                results["details"].append(
                    {
                        "memory_id": manifest_entry.memory_id,
                        "status": "missing",
                    }
                )

        return results

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "manifest_id": self.manifest_id,
            "version": self.version,
            "created_at": self.created_at,
            "source": self.source,
            "memory_hash": self.memory_hash,
            "entry_count": self.entry_count,
            "entries": [e.to_dict() for e in self.entries],
            "metadata": self.metadata,
        }

    def to_json(self, indent: int = 2) -> str:
        """Serialize to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)
