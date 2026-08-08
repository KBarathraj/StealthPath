"""
Planner #2: weighted A* — the attacker who knows which actions are loud.

Same search problem as `shortest_path.dijkstra`, same cost-function signature,
one difference: the cost of a hop is the risk weight of the relationship rather
than a flat 1. So the route it picks trades hops for quiet.

**A* vs Dijkstra is a speed difference, not a quality difference.** With an
admissible heuristic both return an optimal route for the same costs; A* just
expands fewer nodes getting there. The reason planner #2 finds a *different*
route than planner #1 is entirely the weights. If the weights ever stop
differentiating, no amount of search cleverness hides it — see
`test_weighted_route_differs_from_shortest_path`, which exists to catch exactly
that.

The heuristic is `min_edge_cost x (hops remaining)`, where hops-remaining comes
from a backward breadth-first sweep off the target set. It is admissible because
any route from a node to a target must cross at least that many edges and no
edge is cheaper than the minimum, and it is consistent because the hop estimate
drops by at most one per edge. Consistency is what lets the closed set be safe.

Nodes the backward sweep never reaches cannot reach a target at all, so they get
dropped before expansion. On a real AD graph that prunes a large amount of the
directory for free.

Static costs only. The heuristic assumes a hop's cost doesn't depend on what
came before it, which is true for Stage 2's weights and false for Stage 3's
history-dependent model. Feeding this a history-dependent cost function silently
breaks admissibility, so don't — `shortest_path.dijkstra(history_dependent=True)`
is the greedy escape hatch for that case.
"""

from __future__ import annotations

import heapq
from collections import deque
from typing import Callable, Sequence

from ..ad_schema import DEFAULT_TRAVERSAL_SET
from ..graph import AttackGraph
from ..risk import static_cost_fn
from .base import Path

__all__ = ["WeightedAStarPlanner", "astar", "hops_to_targets"]


def hops_to_targets(graph: AttackGraph, targets: Sequence[int],
                    allowed: frozenset[str]) -> dict[int, int]:
    """Minimum hop count from each node to the nearest target.

    Backward BFS over reversed edges. Nodes absent from the result cannot reach
    any target, which is useful on its own — it is the cheapest possible
    reachability filter.
    """
    dist: dict[int, int] = {t: 0 for t in sorted(set(targets))}
    queue: deque[int] = deque(dist)
    while queue:
        node = queue.popleft()
        for edge in graph.in_edges(node):
            if edge.rel_type not in allowed:
                continue
            if edge.source not in dist:
                dist[edge.source] = dist[node] + 1
                queue.append(edge.source)
    return dist


def _cheapest_edge(graph: AttackGraph,
                   cost_fn: Callable[[AttackGraph, int, Sequence[int]], float],
                   allowed: frozenset[str]) -> float:
    """Cheapest traversable hop anywhere in the graph, for the heuristic.

    Evaluated with an empty history, which is only meaningful for a static cost
    function — see the module docstring.
    """
    costs = [cost_fn(graph, ei, ()) for ei, e in enumerate(graph.edges)
             if e.rel_type in allowed]
    return min(costs) if costs else 0.0


def astar(
    graph: AttackGraph,
    sources: Sequence[int],
    targets: Sequence[int],
    cost_fn: Callable[[AttackGraph, int, Sequence[int]], float] | None = None,
    *,
    allowed_rel_types: frozenset[str] | None = None,
    max_hops: int | None = None,
) -> Path | None:
    """Least-risk route from any source to any target, or None."""
    if not sources or not targets:
        return None

    allowed = DEFAULT_TRAVERSAL_SET if allowed_rel_types is None else allowed_rel_types
    cost = cost_fn if cost_fn is not None else static_cost_fn()
    target_set = set(targets)

    remaining = hops_to_targets(graph, targets, allowed)
    unit = _cheapest_edge(graph, cost, allowed)

    def h(node: int) -> float:
        return unit * remaining[node]

    # (f, g, hops, tiebreak, node, node_path, edge_path). Ordering by f then g
    # then hops then a counter is total and reproducible — two runs on one graph
    # must return the same route or the comparison against planner #1 is noise.
    heap: list[tuple[float, float, int, int, int, tuple[int, ...], tuple[int, ...]]] = []
    counter = 0
    for s in sorted(set(sources)):
        if s in target_set:
            return Path((s,), (), 0.0, "weighted-astar", {"trivial": True})
        if s not in remaining:
            continue  # this foothold reaches nothing; another one may
        heapq.heappush(heap, (h(s), 0.0, 0, counter, s, (s,), ()))
        counter += 1

    settled: set[int] = set()

    while heap:
        _, g_cost, hops, _, node, npath, epath = heapq.heappop(heap)

        if node in target_set:
            return Path(npath, epath, g_cost, "weighted-astar",
                        {"hops": hops, "expanded": len(settled)})

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
            if nxt not in remaining:
                continue  # dead end with respect to every target
            if nxt in npath:
                continue  # no cycles: revisiting an owned object gains nothing
            step = cost(graph, ei, epath)
            if step < 0:
                raise ValueError(
                    f"negative cost {step} on edge {ei} ({edge.rel_type}); "
                    "A* requires non-negative costs"
                )
            g_next = g_cost + step
            heapq.heappush(heap, (g_next + h(nxt), g_next, hops + 1, counter,
                                  nxt, npath + (nxt,), epath + (ei,)))
            counter += 1

    return None


class WeightedAStarPlanner:
    """Planner-protocol wrapper around `astar` with the static risk weights."""

    name = "weighted-astar"

    def __init__(self, cost_fn: Callable[[AttackGraph, int, Sequence[int]], float] | None = None,
                 allowed_rel_types: frozenset[str] | None = None,
                 max_hops: int | None = None):
        self.cost_fn = cost_fn if cost_fn is not None else static_cost_fn()
        self.allowed_rel_types = allowed_rel_types
        self.max_hops = max_hops

    def plan(self, graph: AttackGraph, sources: Sequence[int],
             targets: Sequence[int]) -> Path | None:
        return astar(graph, sources, targets, self.cost_fn,
                     allowed_rel_types=self.allowed_rel_types,
                     max_hops=self.max_hops)
