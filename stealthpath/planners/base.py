"""
Shared types for all three planners.

The whole project is a *comparison* between three planners (shortest-path, A*,
PPO). If they return different shapes, the evaluation code turns into three
special cases and every comparison needs a translation layer. So: one `Path`
type, one `Planner` protocol, fixed now, in Stage 1, while it is cheap to fix.

The RL agent in Stage 4 will produce a trajectory rather than a search result.
That's fine — it still emits a node sequence and an edge sequence, so it still
fits `Path`. Keep it that way.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Protocol, Sequence, runtime_checkable

from ..graph import AttackGraph

__all__ = ["Path", "Planner", "CostFn", "unit_cost"]


@dataclass(frozen=True)
class Path:
    """A concrete route through the attack graph.

    Invariant: `len(edges) == len(nodes) - 1`, and edge i joins node i to
    node i+1. `validate()` enforces this; call it in tests and after any RL
    trajectory decode, because an off-by-one here scores the wrong edges and
    still looks like a perfectly valid answer.
    """

    nodes: tuple[int, ...]
    edges: tuple[int, ...]
    cost: float
    planner: str = ""
    meta: dict[str, Any] = field(default_factory=dict)

    @property
    def length(self) -> int:
        """Number of traversals (hops), not number of nodes."""
        return len(self.edges)

    def rel_types(self, graph: AttackGraph) -> list[str]:
        """The technique sequence, in order. Stage 3's history-dependent
        visibility model consumes exactly this."""
        return [graph.edges[ei].rel_type for ei in self.edges]

    def validate(self, graph: AttackGraph) -> None:
        if len(self.edges) != len(self.nodes) - 1:
            raise ValueError(
                f"malformed path: {len(self.nodes)} nodes but {len(self.edges)} edges"
            )
        for i, ei in enumerate(self.edges):
            e = graph.edges[ei]
            if e.source != self.nodes[i] or e.target != self.nodes[i + 1]:
                raise ValueError(
                    f"edge {i} ({e.rel_type}) joins {e.source}->{e.target}, "
                    f"but path expects {self.nodes[i]}->{self.nodes[i+1]}"
                )

    def describe(self, graph: AttackGraph) -> str:
        """Human-readable route. Used by the Stage 1 milestone check and by the
        Cyber Track when eyeballing Stage 4 trajectories."""
        if not self.nodes:
            return "(empty path)"
        lines = [f"  {graph.node(self.nodes[0]).name}"]
        for i, ei in enumerate(self.edges):
            e = graph.edges[ei]
            lines.append(f"    --[{e.rel_type}]-->  {graph.node(self.nodes[i+1]).name}")
        head = f"{self.planner or 'path'}: {self.length} hops, cost {self.cost:.4f}"
        return head + "\n" + "\n".join(lines)


CostFn = "callable(graph, edge_index, path_so_far) -> float"


def unit_cost(graph: AttackGraph, edge_index: int, path_so_far: Sequence[int]) -> float:
    """Every hop costs 1. This makes Dijkstra a pure hop-count shortest path —
    the baseline that ignores detection entirely."""
    return 1.0


@runtime_checkable
class Planner(Protocol):
    name: str

    def plan(self, graph: AttackGraph, sources: Sequence[int],
             targets: Sequence[int]) -> Path | None:
        """Return a route from any source to any target, or None if none exists."""
        ...
