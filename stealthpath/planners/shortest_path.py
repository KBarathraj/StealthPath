"""
Baseline planner #1: pure shortest path (Dijkstra).

This is the "attacker who ignores detection entirely" baseline the other two
planners get compared against. With `unit_cost` it degenerates to BFS over hop
count, which is exactly what
BloodHound's own `shortestPath` shows you — that equivalence is the Stage 1
milestone check.

Implementation notes:

* Multi-source, multi-target. Real environments have several footholds and
  several tier-0 targets; picking one arbitrarily would bias every comparison.
  Handled with a virtual super-source rather than N separate runs.
* The cost function receives the path so far. Dijkstra is only *correct* for
  history-independent costs, so this is a lie in general — but it is a useful
  one, because it lets the same code run a greedy history-dependent variant for
  Stage 3 sanity checks. `history_dependent=True` makes that explicit and drops
  the optimality claim. Do not report greedy results as optimal.
* Ties are broken deterministically by (cost, hops, edge index). Two runs on the
  same graph must return the same route, or nothing built on top compares.
"""

from __future__ import annotations

import heapq
from typing import Callable, Sequence

from ..ad_schema import DEFAULT_TRAVERSAL_SET
from ..graph import AttackGraph
from .base import Path, unit_cost

__all__ = ["ShortestPathPlanner", "dijkstra"]


def dijkstra(
    graph: AttackGraph,
    sources: Sequence[int],
    targets: Sequence[int],
    cost_fn: Callable[[AttackGraph, int, Sequence[int]], float] = unit_cost,
    *,
    allowed_rel_types: frozenset[str] | None = None,
    history_dependent: bool = False,
    max_hops: int | None = None,
) -> Path | None:
    """Least-cost route from any source to any target, or None."""
    if not sources or not targets:
        return None

    allowed = DEFAULT_TRAVERSAL_SET if allowed_rel_types is None else allowed_rel_types
    target_set = set(targets)

    # (cost, hops, tiebreak, node, node_path, edge_path)
    heap: list[tuple[float, int, int, int, tuple[int, ...], tuple[int, ...]]] = []
    counter = 0
    for s in sorted(set(sources)):
        if s in target_set:
            return Path((s,), (), 0.0, "shortest-path", {"trivial": True})
        heapq.heappush(heap, (0.0, 0, counter, s, (s,), ()))
        counter += 1

    # For history-independent costs a settled node never needs revisiting. For
    # history-dependent costs that guarantee is gone, so we cap by hop count
    # instead and accept a greedy answer.
    settled: set[int] = set()
    best_at: dict[int, float] = {}

    while heap:
        cost, hops, _, node, npath, epath = heapq.heappop(heap)

        if node in target_set:
            return Path(npath, epath, cost, "shortest-path",
                        {"hops": hops, "history_dependent": history_dependent})

        if history_dependent:
            if best_at.get(node, float("inf")) < cost:
                continue
            best_at[node] = cost
        else:
            if node in settled:
                continue
            settled.add(node)

        if max_hops is not None and hops >= max_hops:
            continue

        for ei in graph.out_edge_indices(node):
            edge = graph.edges[ei]
            if edge.rel_type not in allowed:
                continue
            nxt = edge.target
            if nxt in npath:
                continue  # no cycles: revisiting an owned object gains nothing
            step = cost_fn(graph, ei, epath)
            if step < 0:
                raise ValueError(
                    f"negative cost {step} on edge {ei} ({edge.rel_type}); "
                    "Dijkstra requires non-negative costs"
                )
            heapq.heappush(heap, (cost + step, hops + 1, counter, nxt,
                                  npath + (nxt,), epath + (ei,)))
            counter += 1

    return None


class ShortestPathPlanner:
    """Planner-protocol wrapper around `dijkstra` with unit costs."""

    name = "shortest-path"

    def __init__(self, allowed_rel_types: frozenset[str] | None = None,
                 max_hops: int | None = None):
        self.allowed_rel_types = allowed_rel_types
        self.max_hops = max_hops

    def plan(self, graph: AttackGraph, sources: Sequence[int],
             targets: Sequence[int]) -> Path | None:
        return dijkstra(graph, sources, targets, unit_cost,
                        allowed_rel_types=self.allowed_rel_types,
                        max_hops=self.max_hops)
