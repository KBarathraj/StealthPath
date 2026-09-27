"""Planning a route to Domain Admin on a directory nobody has measured.

`rl_view` covers the two frozen demo graphs, where the answer is already known
and `results/h5_h6.json` records it. None of that transfers to an upload: the
reachable component might be tiny or the whole directory, and the stored numbers
describe two specific graphs and must never be shown for a third.

## The ladder

1. **`exact_history_search`** -- optimal, provable, and the only rung that can
   say so. Always tried first, under a deadline.
2. **Approximate Q-learning** (`planners/linear_q.py`) -- hashed state-action
   features, bounded memory, runs on a directory of any size. Reported as a gap
   against rung 1 whenever rung 1 finished, and as an unverified candidate when
   it did not.
3. **Refusal.** Not a partial policy, not a truncated search, not a stored
   number from another graph.

**The tabular learner is deliberately not a rung here.** It is the pre-registered
Tier 2 planner and it keeps its reported 15/15 result on the frozen graphs via
`rl_view`, but for an upload it is strictly worse: its memory has no ceiling, and
on the random directories checked while building this it came in +9.3% on a start
where the approximator was exact. Offering a planner that is both less accurate
and unbounded, on the one code path where nobody knows the graph, would be the
wrong default.

## Why the learner runs even when the exact route is already in hand

Because the gap is the interesting number, and it is only obtainable where both
finish. The exact route is what the app *reports* in that case; the learned one
is shown beside it as a check on the learner, which is the only evidence anyone
has that rung 2 can be trusted on the graphs where rung 1 cannot run.

## Why a capped run is a refusal and not a result

`_epsilon` derives its decay schedule from `cfg.episodes`, so a run stopped at
episode 12,000 of 25,000 is **not** the first 12,000 episodes of a full run -- it
explored on a compressed schedule and its policy is not a prefix of anything.
Presenting it as "the learned route so far" would be presenting a different
experiment.
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph
from stealthpath.planners.exact_history import exact_history_search
from stealthpath.planners.linear_q import ApproxQConfig, train_approx
from stealthpath.risk import history_cost_fn

from .rl_view import BudgetExceeded, TrainingBudget

__all__ = ["UploadPlan", "LearnedRoute", "plan_upload",
           "EXACT", "LEARNED", "REFUSED"]

EXACT = "exact"
LEARNED = "approx-q"
REFUSED = "refused"

_ALLOWED = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)


@dataclass
class LearnedRoute:
    """What the learner produced, kept separate from what the app reports.

    Separate because they answer different questions. `UploadPlan` is "what is
    the route" and this is "can the learner be trusted here" -- merging them is
    how an unverified number ends up rendered as a verified one.
    """

    cost: float | None
    hops: int | None
    route: list[str]
    node_names: list[str]
    node_kinds: list[str]
    gap_vs_exact: float | None
    matches_exact: bool
    seconds: float
    episodes: int
    load_factor: float
    """Fraction of weight buckets touched. High means estimates are bleeding
    between unrelated state-actions and the route deserves less trust."""


@dataclass
class UploadPlan:
    """What was computed, by what, and how much it may be trusted."""

    tier: str
    verified: bool
    """True only when an exact search produced the reported route. A learned
    route is never verified, however close to the optimum it lands."""

    cost: float | None
    hops: int | None
    route: list[str]
    node_names: list[str]
    node_kinds: list[str] = field(default_factory=list)
    """Object kind per node on the route, parallel to `node_names`.

    Carried on the plan rather than looked up by the renderer, so the view
    layer never needs the graph in hand to draw a route.
    """

    node_indices: list[int] = field(default_factory=list)
    edge_indices: list[int] = field(default_factory=list)
    learned: LearnedRoute | None = None
    seconds: float = 0.0
    notes: list[str] = field(default_factory=list)

    @property
    def found_route(self) -> bool:
        return self.cost is not None

    def verdict(self) -> str:
        if self.tier == EXACT:
            return "Proved optimal: no cheaper route exists under this cost model."
        if self.tier == LEARNED:
            return ("Learned route. The exact search did not finish in budget, "
                    "so nothing proves this is the cheapest one.")
        return "No route reported."


def plan_upload(graph: AttackGraph,
                sources: Sequence[int],
                targets: Sequence[int],
                budget: TrainingBudget | None = None,
                max_hops: int = 20,
                episodes: int | None = None,
                seed: int = 0,
                run_learner: bool = True) -> UploadPlan:
    """Walk the ladder and return the strongest rung that finished in budget."""
    budget = budget or TrainingBudget()
    cost_fn = history_cost_fn()
    notes: list[str] = []
    started = time.perf_counter()

    if not sources:
        return _refusal(started, ["no start node was selected"])
    if not targets:
        return _refusal(started, [
            "no target could be derived for this directory. Targets come from "
            "well-known RIDs 512/519 and domain objects; pick a destination "
            "manually if yours are named or structured differently."
        ])

    exact_path = None
    exact_timed_out = False
    try:
        exact_path = _with_deadline(
            lambda: exact_history_search(graph, sources, targets, cost_fn,
                                         _ALLOWED, max_hops),
            budget.max_seconds)
    except TimeoutError:
        exact_timed_out = True
        notes.append(
            f"the exact search did not finish within {budget.max_seconds:g}s, "
            f"so there is no optimality reference for this graph")

    if not exact_timed_out and exact_path is None:
        notes.append("no route exists from this start to any derived target "
                     "under the traversal rules, so there is nothing to learn")
        return _refusal(started, notes)

    learned = None
    if run_learner:
        learned = _learn(graph, sources, targets, cost_fn, budget, max_hops,
                         episodes, seed, exact_path, notes)

    if exact_path is not None:
        return UploadPlan(
            tier=EXACT, verified=True, cost=exact_path.cost,
            hops=exact_path.length,
            route=exact_path.rel_types(graph),
            node_names=[graph.node(n).name for n in exact_path.nodes],
            node_kinds=[graph.node(n).kind for n in exact_path.nodes],
            node_indices=list(exact_path.nodes),
            edge_indices=list(exact_path.edges),
            learned=learned, seconds=time.perf_counter() - started, notes=notes)

    if learned is None or learned.cost is None:
        notes.append(
            "no planner finished inside the budget. Nothing partial is shown "
            "because a stopped run explores on a compressed schedule and is not "
            "the beginning of a finished one -- raise the budget and retry.")
        return _refusal(started, notes)

    return UploadPlan(
        tier=LEARNED, verified=False, cost=learned.cost, hops=learned.hops,
        route=learned.route, node_names=learned.node_names,
        node_kinds=learned.node_kinds,
        learned=learned, seconds=time.perf_counter() - started, notes=notes)


def _learn(graph, sources, targets, cost_fn, budget, max_hops, episodes, seed,
           exact_path, notes) -> LearnedRoute | None:
    """Train from **every** start node, and keep the best route.

    **The source set must match the one the exact search used.** It briefly did
    not: the exact search ran over all `sources` while the learner trained only
    on `sources[0]`, so the reported gap compared two different problems. It
    showed up as an apparently terrible learner -- +43% on a random directory --
    when the learner had in fact found the exact optimum from the node it was
    given, and the "optimum" it was being judged against belonged to a different
    start. Nothing in the frozen-graph tests could catch it, because every
    documented entry name there resolves to exactly one node.
    """
    cfg_episodes = episodes if episodes is not None else ApproxQConfig().episodes
    started = time.perf_counter()

    def watchdog(episode: int, _cost: float | None) -> None:
        elapsed = time.perf_counter() - started
        if elapsed > budget.max_seconds:
            raise BudgetExceeded(elapsed, episode, budget)

    best = None
    best_result = None
    try:
        for source in sorted(set(sources)):
            result = train_approx(
                graph, source, targets, cost_fn,
                ApproxQConfig(episodes=cfg_episodes, seed=seed, max_hops=max_hops),
                _ALLOWED, on_checkpoint=watchdog)
            if result.path and (best is None or result.path.cost < best.cost):
                best, best_result = result.path, result
    except BudgetExceeded as exc:
        notes.append(str(exc))
        return None

    elapsed = time.perf_counter() - started
    if best is None:
        notes.append("the learner did not reach a target under its greedy policy")
        return None

    gap = None
    matches = False
    if exact_path is not None and exact_path.cost:
        gap = (best.cost - exact_path.cost) / exact_path.cost
        matches = abs(best.cost - exact_path.cost) < 1e-9

    return LearnedRoute(
        cost=best.cost, hops=best.length,
        route=best.rel_types(graph),
        node_names=[graph.node(n).name for n in best.nodes],
        node_kinds=[graph.node(n).kind for n in best.nodes],
        gap_vs_exact=gap, matches_exact=matches, seconds=elapsed,
        episodes=cfg_episodes,
        load_factor=best_result.collision_report()["load_factor"],
    )


def _with_deadline(fn, seconds: float):
    """Run `fn`, and raise `TimeoutError` if it overran.

    **Checked after the fact, not a kill switch.** `exact_history_search` has no
    observer hook, and adding a wall-clock read to the inner loop of the one
    planner whose output is cited by hash would trade determinism there for a
    tighter bound here. The cost is that a very slow exact search still runs to
    completion before being discarded; the benefit is that the optimal planner
    did not change to support a web page.
    """
    started = time.perf_counter()
    result = fn()
    if time.perf_counter() - started > seconds:
        raise TimeoutError
    return result


def _refusal(started: float, notes: list[str]) -> UploadPlan:
    return UploadPlan(tier=REFUSED, verified=False, cost=None, hops=None,
                      route=[], node_names=[],
                      seconds=time.perf_counter() - started, notes=notes)
