# Copyright (c) 2025 Carlos-Projects
# SPDX-License-Identifier: MIT

"""Memory store abstraction for pluggable backends.

Provides a common interface for reading and writing
agent memory from different storage backends.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any


class MemoryStore(ABC):
    """Abstract base for memory storage backends.

    Implementations handle serialization, persistence,
    and retrieval of memory entry lists.
    """

    @abstractmethod
    def read(self) -> list[dict[str, Any]]:
        """Read all memory entries from the store.

        Returns:
            List of memory entry dictionaries.
        """

    @abstractmethod
    def write(self, memories: list[dict[str, Any]]) -> None:
        """Write memory entries to the store.

        Args:
            memories: List of memory entry dictionaries.
        """

    @abstractmethod
    def append(self, entry: dict[str, Any]) -> None:
        """Append a single memory entry to the store.

        Args:
            entry: Memory entry dictionary.
        """


class FileMemoryStore(MemoryStore):
    """Memory store backed by a local JSON file."""

    def __init__(self, path: str | Path) -> None:
        """Initialize file-backed store.

        Args:
            path: Path to JSON file.
        """
        self.path = Path(path)

    def read(self) -> list[dict[str, Any]]:
        with open(self.path, encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            data = data.get("memories", data.get("entries", [data]))
        return data  # type: ignore[no-any-return]

    def write(self, memories: list[dict[str, Any]]) -> None:
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(memories, f, indent=2)

    def append(self, entry: dict[str, Any]) -> None:
        memories = self.read()
        memories.append(entry)
        self.write(memories)


class InMemoryMemoryStore(MemoryStore):
    """Memory store backed by an in-memory list."""

    def __init__(self, memories: list[dict[str, Any]] | None = None) -> None:
        self._memories: list[dict[str, Any]] = memories or []

    def read(self) -> list[dict[str, Any]]:
        return list(self._memories)

    def write(self, memories: list[dict[str, Any]]) -> None:
        self._memories = list(memories)

    def append(self, entry: dict[str, Any]) -> None:
        self._memories.append(entry)
