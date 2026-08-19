"""
Tier 1: exact history-aware search — the optimal reference.

Uniform-cost search over the **augmented** state space `(node, set of technique
categories used)`. Deterministic, exhaustive, optimal.

## Why this exists, and why it is built before any learning

This is the reference the learned planner is scored against. Because Summary A's
state space is small enough to search exactly — 783 nodes x 2^9 categories =
400,896 states — the Q-learner can be reported as an **optimality gap against a
known optimum** rather than as a training curve. "Converged" tells a reader
nothing about solution quality; "within X% of optimal" does.

Building it first also means the learner is debugged against something. A
learning planner with no reference is indistinguishable from a broken one.

## It reuses the model, it does not reimplement it

The cost of every step comes from the cost function passed in — normally
`risk.history_cost_fn`. This module never recomputes a weight or reapplies the
repeat multiplier itself. That is deliberate and it is the same concern P6
encodes: two implementations of one model turn every comparison into a
measurement of the gap between them.

The one subtlety is `path_so_far`. The search keys states on a category *set*,
not on a route, so there is no single path to hand the cost function. It
synthesises one — a representative edge per category in the set — which is exact
because the model reads nothing from `path_so_far` except the categories it
implies. `test_exact_search_cost_equals_the_models_own_route_cost` checks that
end-to-end by re-scoring the returned route with `route_cost`, so an error in
this reasoning fails loudly rather than producing a plausible number.
"""

from __future__ import annotations

import heapq
from typing import Callable, Iterable, Sequence

from ..ad_schema import DEFAULT_TRAVERSAL_SET, category_of
from ..graph import AttackGraph
from .base import Path

__all__ = ["exact_history_search", "ExactHistoryPlanner", "state_space_size",
           "category_representatives"]

CostFn = Callable[[AttackGraph, int, Sequence[int]], float]


def state_space_size(graph: AttackGraph,
                     allowed_rel_types: Iterable[str] | None = None) -> int:
    """`|S|` for this graph under Summary A: nodes x 2^categories.

    Reported rather than assumed. The pre-registered 400,896 is 783 x 2^9, and
    the 9 is a *consequence of build rule 3* — structural edges are excluded from
    `DEFAULT_TRAVERSAL_SET`, leaving nine of the ten `EdgeCategory` values
    reachable. If the default traversal set ever changes, this number moves with
    it, which is exactly why it is computed here instead of hard-coded.
    """
    allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                  else allowed_rel_types)
    cats = {category_of(r) for r in allowed}
    return len(graph.nodes) * (2 ** len(cats))


def category_representatives(graph: AttackGraph,
                              allowed: set[str]) -> dict[str, int]:
    """One edge index per category, for synthesising a `path_so_far`.

    Lowest edge index wins, so the choice is deterministic and independent of
    traversal order — a requirement, not a convenience, since a cost that
    depended on *which* representative was picked would break P12.
    """
    reps: dict[str, int] = {}
    for i, e in enumerate(graph.edges):
        if e.rel_type not in allowed:
            continue
        cat = category_of(e.rel_type)
        if cat not in reps:
            reps[cat] = i
    return reps


def exact_history_search(graph: AttackGraph,
                         sources: Sequence[int],
                         targets: Sequence[int],
                         cost: CostFn,
                         allowed_rel_types: Iterable[str] | None = None,
                         max_hops: int = 20) -> Path | None:
    """Least-risk route under a history-dependent cost model, exactly.

    Uniform-cost search: states are popped in nondecreasing cost order, so the
    first goal state popped is optimal. Ties break on an insertion counter, which
    makes the result deterministic without depending on node indices.
    """
    allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                  else allowed_rel_types)
    target_set = set(targets)
    if not target_set or not sources:
        return None

    reps = category_representatives(graph, allowed)

    def synth(cats: frozenset[str]) -> tuple[int, ...]:
        # Sorted so the synthesised history is itself deterministic.
        return tuple(reps[c] for c in sorted(cats) if c in reps)

    counter = 0
    heap: list[tuple[float, int, int, frozenset[str]]] = []
    best: dict[tuple[int, frozenset[str]], float] = {}
    prev: dict[tuple[int, frozenset[str]], tuple[tuple[int, frozenset[str]], int]] = {}
    hops: dict[tuple[int, frozenset[str]], int] = {}

    empty: frozenset[str] = frozenset()
    for s in sorted(set(sources)):
        state = (s, empty)
        if state not in best:
            best[state] = 0.0
            hops[state] = 0
            heapq.heappush(heap, (0.0, counter, s, empty))
            counter += 1

    while heap:
        total, _, node, cats = heapq.heappop(heap)
        state = (node, cats)
        if total > best.get(state, float("inf")):
            continue
        if node in target_set and hops[state] > 0:
            return _reconstruct(graph, state, prev, total)
        if hops[state] >= max_hops:
            continue

        history = synth(cats)
        for ei in graph.out_edge_indices(node):
            edge = graph.edges[ei]
            if edge.rel_type not in allowed:
                continue
            step = cost(graph, ei, history)
            nxt = (edge.target, cats | {category_of(edge.rel_type)})
            new_total = total + step
            if new_total < best.get(nxt, float("inf")):
                best[nxt] = new_total
                prev[nxt] = (state, ei)
                hops[nxt] = hops[state] + 1
                heapq.heappush(heap, (new_total, counter, nxt[0], nxt[1]))
                counter += 1

    return None


def _reconstruct(graph: AttackGraph,
                 state: tuple[int, frozenset[str]],
                 prev: dict, total: float) -> Path:
    nodes: list[int] = [state[0]]
    edges: list[int] = []
    cur = state
    while cur in prev:
        parent, ei = prev[cur]
        edges.append(ei)
        nodes.append(parent[0])
        cur = parent
    nodes.reverse()
    edges.reverse()
    return Path(nodes=tuple(nodes), edges=tuple(edges), cost=total,
                planner="exact-history")


class ExactHistoryPlanner:
    """Planner-protocol wrapper. The optimal reference, not a contender."""

    name = "exact-history"

    def __init__(self, cost: CostFn,
                 allowed_rel_types: Iterable[str] | None = None,
                 max_hops: int = 20) -> None:
        self._cost = cost
        self._allowed = allowed_rel_types
        self._max_hops = max_hops

    def plan(self, graph: AttackGraph, sources: Sequence[int],
             targets: Sequence[int]) -> Path | None:
        return exact_history_search(graph, sources, targets, self._cost,
                                    self._allowed, self._max_hops)
