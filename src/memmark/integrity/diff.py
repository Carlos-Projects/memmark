# Copyright (c) 2025 Carlos Rocha
# SPDX-License-Identifier: MIT

"""Memory diff engine for AI agent memory systems.

Compares two memory states to detect unauthorized changes,
additions, deletions, and modifications.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from memmark.utils.crypto import hash_memory_entry


@dataclass
class MemoryDiff:
    """Result of comparing two memory states."""

    added: int = 0
    removed: int = 0
    modified: int = 0
    unchanged: int = 0
    added_entries: list[dict[str, Any]] = field(default_factory=list)
    removed_entries: list[dict[str, Any]] = field(default_factory=list)
    modified_entries: list[dict[str, Any]] = field(default_factory=list)
    before_hash: str = ""
    after_hash: str = ""

    @classmethod
    def compare(
        cls,
        before: list[dict[str, Any]],
        after: list[dict[str, Any]],
    ) -> MemoryDiff:
        """Compare two memory states.

        Args:
            before: Original memory entries.
            after: Modified memory entries.

        Returns:
            MemoryDiff with all changes.
        """
        before_map = cls._build_map(before)
        after_map = cls._build_map(after)

        before_ids = set(before_map.keys())
        after_ids = set(after_map.keys())

        added_ids = after_ids - before_ids
        removed_ids = before_ids - after_ids
        common_ids = before_ids & after_ids

        diff = cls(
            added=len(added_ids),
            removed=len(removed_ids),
            added_entries=[after_map[mid] for mid in added_ids],
            removed_entries=[before_map[mid] for mid in removed_ids],
        )

        # Check for modifications in common entries
        for mid in common_ids:
            before_hash = hash_memory_entry(before_map[mid])
            after_hash = hash_memory_entry(after_map[mid])

            if before_hash != after_hash:
                diff.modified += 1
                diff.modified_entries.append(
                    {
                        "memory_id": mid,
                        "before": before_map[mid],
                        "after": after_map[mid],
                        "before_hash": before_hash,
                        "after_hash": after_hash,
                    }
                )
            else:
                diff.unchanged += 1

        # Compute state hashes
        from memmark.utils.crypto import hash_memory_state

        diff.before_hash = hash_memory_state(before)
        diff.after_hash = hash_memory_state(after)

        return diff

    @staticmethod
    def _build_map(
        entries: list[dict[str, Any]],
    ) -> dict[str, dict[str, Any]]:
        """Build ID-to-entry map.

        Args:
            entries: List of memory entries.

        Returns:
            Dictionary mapping memory IDs to entries.
        """
        result: dict[str, dict[str, Any]] = {}
        for entry in entries:
            mid = entry.get("id", entry.get("memory_id"))
            if mid:
                result[mid] = entry
        return result

    @property
    def has_changes(self) -> bool:
        """Check if any changes were detected."""
        return self.added > 0 or self.removed > 0 or self.modified > 0

    @property
    def is_intact(self) -> bool:
        """Check if memory state is unchanged."""
        return not self.has_changes

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary."""
        return {
            "added": self.added,
            "removed": self.removed,
            "modified": self.modified,
            "unchanged": self.unchanged,
            "added_entries": [
                {"id": e.get("id", e.get("memory_id"))} for e in self.added_entries
            ],
            "removed_entries": [
                {"id": e.get("id", e.get("memory_id"))} for e in self.removed_entries
            ],
            "modified_entries": [
                {"memory_id": e["memory_id"]} for e in self.modified_entries
            ],
            "before_hash": self.before_hash,
            "after_hash": self.after_hash,
            "has_changes": self.has_changes,
        }
