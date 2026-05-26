"""Memory provenance graph for AI agent memory systems.

Builds and analyzes the graph of memory dependencies
to visualize and detect anomalous provenance patterns.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from memmark.provenance.tracker import ProvenanceTracker


@dataclass
class ProvenanceNode:
    """Node in the provenance graph."""

    memory_id: str
    source: str
    is_root: bool = False
    children: list[str] = field(default_factory=list)
    parent: str | None = None


class ProvenanceGraph:
    """Graph representation of memory provenance relationships."""

    def __init__(self) -> None:
        """Initialize provenance graph."""
        self.nodes: dict[str, ProvenanceNode] = {}

    @classmethod
    def from_tracker(cls, tracker: ProvenanceTracker) -> ProvenanceGraph:
        """Build provenance graph from a ProvenanceTracker.

        Args:
            tracker: ProvenanceTracker with records.

        Returns:
            Populated ProvenanceGraph.
        """
        graph = cls()

        for record in tracker.records.values():
            node = ProvenanceNode(
                memory_id=record.memory_id,
                source=record.source,
                parent=record.parent_id,
                is_root=record.parent_id is None,
            )
            graph.nodes[record.memory_id] = node

        # Build children relationships
        for node in graph.nodes.values():
            if node.parent and node.parent in graph.nodes:
                graph.nodes[node.parent].children.append(node.memory_id)

        return graph

    def get_roots(self) -> list[ProvenanceNode]:
        """Get all root nodes (entries with no parent).

        Returns:
            List of root ProvenanceNode objects.
        """
        return [n for n in self.nodes.values() if n.is_root]

    def get_children(self, memory_id: str) -> list[str]:
        """Get all direct children of a memory entry.

        Args:
            memory_id: Parent memory identifier.

        Returns:
            List of child memory IDs.
        """
        node = self.nodes.get(memory_id)
        return node.children if node else []

    def get_descendants(self, memory_id: str) -> list[str]:
        """Get all descendants of a memory entry (recursive).

        Args:
            memory_id: Root memory identifier.

        Returns:
            List of all descendant memory IDs.
        """
        descendants: list[str] = []
        queue = [memory_id]

        while queue:
            current = queue.pop(0)
            children = self.get_children(current)
            descendants.extend(children)
            queue.extend(children)

        return descendants

    def get_depth(self, memory_id: str) -> int:
        """Get the depth of a memory entry in the provenance tree.

        Args:
            memory_id: Memory identifier.

        Returns:
            Depth level (0 for root entries).
        """
        depth = 0
        current = self.nodes.get(memory_id)
        visited: set[str] = set()

        while current and current.parent:
            if current.memory_id in visited:
                break
            visited.add(current.memory_id)
            current = self.nodes.get(current.parent)
            depth += 1

        return depth

    def detect_anomalies(self) -> list[dict[str, Any]]:
        """Detect anomalous patterns in the provenance graph.

        Returns:
            List of detected anomalies.
        """
        anomalies: list[dict[str, Any]] = []

        # Detect orphan nodes (parent referenced but not found)
        for node in self.nodes.values():
            if node.parent and node.parent not in self.nodes:
                anomalies.append(
                    {
                        "type": "orphan_node",
                        "memory_id": node.memory_id,
                        "missing_parent": node.parent,
                        "severity": "high",
                    }
                )

        # Detect cycles (should not exist in provenance tree)
        visited: set[str] = set()
        for node_id in self.nodes:
            if node_id not in visited:
                cycle = self._detect_cycle(node_id, visited)
                if cycle:
                    anomalies.append(
                        {
                            "type": "provenance_cycle",
                            "cycle": cycle,
                            "severity": "critical",
                        }
                    )

        # Detect unusually deep chains
        for node_id in self.nodes:
            depth = self.get_depth(node_id)
            if depth > 10:
                anomalies.append(
                    {
                        "type": "deep_chain",
                        "memory_id": node_id,
                        "depth": depth,
                        "severity": "medium",
                    }
                )

        return anomalies

    def _detect_cycle(
        self,
        start_id: str,
        visited: set[str],
    ) -> list[str] | None:
        """Detect cycle starting from a node.

        Args:
            start_id: Starting node ID.
            visited: Set of already visited nodes.

        Returns:
            Cycle path if found, None otherwise.
        """
        path: list[str] = []
        current = start_id

        while current:
            if current in path:
                cycle_start = path.index(current)
                return path[cycle_start:]
            if current in visited:
                return None

            visited.add(current)
            path.append(current)
            node = self.nodes.get(current)
            current = node.parent if node else None

        return None

    def to_dict(self) -> dict[str, Any]:
        """Export graph as dictionary.

        Returns:
            Dictionary representation of the graph.
        """
        return {
            "nodes": {
                nid: {
                    "memory_id": n.memory_id,
                    "source": n.source,
                    "is_root": n.is_root,
                    "parent": n.parent,
                    "children": n.children,
                }
                for nid, n in self.nodes.items()
            },
            "root_count": len(self.get_roots()),
            "total_nodes": len(self.nodes),
        }
