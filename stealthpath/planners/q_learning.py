"""
Tier 2: tabular Q-learning over the augmented MDP.

Same state space as Tier 1, same cost model, same graph, same view. The only
thing that differs is how the policy is obtained — learned from experience rather
than searched exhaustively.

## How this gets reported

**As an optimality gap against `exact_history_search`, from the first run.** Not
as a training curve. The exact reference exists precisely so "converged" can be
replaced by "within X% of optimal", and a learner with no reference is
indistinguishable from a broken one.

Q-learning **cannot beat exact search** on this MDP. If it appears to, that is a
bug in one of them — most likely a cost model applied inconsistently between the
two — and not a result. The reportable content is how close it gets, how
reliably across seeds, and where it falls short.

## Hyperparameters are pre-registered

Defaults here match the pre-registration recorded in `docs/findings.md` before
the first run. Changing one is a decision to be recorded there, not a tuning
knob: in particular the failure penalty is a *termination condition*, not reward
shaping toward any route, and swapping it for a shaped reward would change what
is being learned.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from ..ad_schema import DEFAULT_TRAVERSAL_SET, category_of
from ..graph import AttackGraph
from .base import Path
from .exact_history import category_representatives

__all__ = ["QLearningConfig", "QLearningResult", "train", "greedy_path",
           "QLearningPlanner"]

CostFn = Callable[[AttackGraph, int, Sequence[int]], float]


@dataclass(frozen=True)
class QLearningConfig:
    """Pre-registered hyperparameters. See `docs/findings.md`, Tier 2 entry."""

    alpha: float = 0.1
    gamma: float = 1.0
    """Undiscounted on purpose: this is a minimum-cost path problem, not a
    discounted-return one. Episodes terminate via the goal or the hop cap, so
    returns stay finite without discounting."""

    episodes: int = 50_000
    max_hops: int = 20
    epsilon_start: float = 1.0
    epsilon_end: float = 0.05
    epsilon_decay_fraction: float = 0.8
    failure_penalty: float = -100.0
    """Applied when the hop cap is reached without a target.

    Why it must exist: with `gamma=1` and purely negative step rewards, an agent
    that cycles on cheap edges until the cap can out-score one that pays for an
    expensive route to a target. -100 exceeds any feasible route cost on this
    graph (TYWIN, the dearest, is 44.5), so reaching a target always dominates.
    A termination condition, not a nudge toward a particular route."""

    checkpoint_every: int = 1_000
    stable_checkpoints_for_convergence: int = 10
    seed: int = 0


@dataclass
class QLearningResult:
    path: Path | None
    converged: bool
    converged_at_episode: int | None
    episodes_run: int
    success_rate_first_5k: float
    """Fraction of the first 5,000 episodes that reached a target. The
    pre-registered exploration-failure guard trips below 1%."""
    goal_reached_total: int
    checkpoints: list[tuple[int, float | None]]
    q_size: int
    first_target_episode: int | None = None
    """Episode of the first target-reaching episode, or None if never reached.

    Reported because it is the shape of the TYWIN exploration finding: the guard
    fires on `success_rate_first_5k`, but *when* the first target is reached is
    what says whether a run was recovering or stuck. Tracked here rather than
    reconstructed by a caller, because reconstructing it from outside means
    wrapping the cost function and filtering out `greedy_path`'s own calls."""
    q: dict[tuple[int, int, int], float] | None = None
    """The learned table, kept so a policy can be evaluated on a *changed* graph
    without retraining. That is the H5 measurement: degradation of an existing
    policy under perturbation, which is meaningless if the agent is retrained."""


def _mask_bits(allowed: set[str]) -> dict[str, int]:
    """Category -> bit, assigned in sorted order so runs are comparable."""
    return {c: 1 << i for i, c in enumerate(sorted({category_of(r) for r in allowed}))}


def _epsilon(cfg: QLearningConfig, episode: int) -> float:
    span = max(1, int(cfg.episodes * cfg.epsilon_decay_fraction))
    if episode >= span:
        return cfg.epsilon_end
    frac = episode / span
    return cfg.epsilon_start + frac * (cfg.epsilon_end - cfg.epsilon_start)


def train(graph: AttackGraph,
          source: int,
          targets: Sequence[int],
          cost: CostFn,
          cfg: QLearningConfig = QLearningConfig(),
          allowed_rel_types: Iterable[str] | None = None,
          on_checkpoint: Callable[[int, float | None], None] | None = None,
          ) -> QLearningResult:
    """Learn a policy from `source`, then report it against the exact optimum.

    `on_checkpoint(episode, best_cost)` is an **observer**, called with the same
    pair already appended to `checkpoints`. It exists so a caller can watch a run
    without waiting for it to end; it is passed no mutable state, its return
    value is discarded, and it is called after the checkpoint is recorded, so it
    cannot influence convergence. Critically it touches nothing the RNG sees, so
    a run with an observer must produce byte-identical output to one without —
    `test_the_observer_cannot_change_the_run` proves that rather than assuming
    it, because a frozen artifact is cited by hash.
    """
    allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                  else allowed_rel_types)
    target_set = set(targets)
    bits = _mask_bits(allowed)
    reps = category_representatives(graph, allowed)
    rng = random.Random(cfg.seed)

    # Actions available per node, in index order so tie-breaks are deterministic.
    actions: dict[int, list[int]] = {}
    for n in range(len(graph.nodes)):
        actions[n] = [ei for ei in graph.out_edge_indices(n)
                      if graph.edges[ei].rel_type in allowed]

    def history_for(mask: int) -> tuple[int, ...]:
        return tuple(reps[c] for c, b in sorted(bits.items()) if mask & b and c in reps)

    q: dict[tuple[int, int, int], float] = {}

    def qval(node: int, mask: int, ei: int) -> float:
        return q.get((node, mask, ei), 0.0)

    def best_value(node: int, mask: int) -> float:
        acts = actions[node]
        if not acts:
            return 0.0
        return max(qval(node, mask, ei) for ei in acts)

    goal_reached = 0
    first_5k_success = 0
    first_target_episode: int | None = None
    checkpoints: list[tuple[int, float | None]] = []
    stable = 0
    last_route: tuple[int, ...] | None = None
    converged_at: int | None = None

    for ep in range(cfg.episodes):
        node, mask = source, 0
        eps = _epsilon(cfg, ep)
        reached = False
        for _ in range(cfg.max_hops):
            acts = actions[node]
            if not acts:
                break
            if rng.random() < eps:
                ei = acts[rng.randrange(len(acts))]
            else:
                best = max(qval(node, mask, a) for a in acts)
                # Deterministic tie-break by edge index, matching the planners.
                ei = next(a for a in acts if qval(node, mask, a) == best)

            step = cost(graph, ei, history_for(mask))
            edge = graph.edges[ei]
            nxt_node = edge.target
            nxt_mask = mask | bits[category_of(edge.rel_type)]
            reward = -step

            dead_end = False
            if nxt_node in target_set:
                target_q = 0.0
                reached = True
            elif not actions[nxt_node]:
                # **Non-goal terminal.** Without this branch `best_value` returns
                # 0.0 for a node with no actions — the same bootstrap a *goal*
                # gets — so dead-ending is free and the cheapest edge into one
                # beats any route to a target. On the real graph that is exactly
                # what was learned: `MemberOf` (0.1) into a zero-out-degree node
                # scored better than the 4.1 optimum. Every non-goal termination
                # must be penalised the same way the hop cap is; the alternative
                # is an MDP where giving up wins.
                target_q = cfg.failure_penalty
                dead_end = True
            else:
                target_q = best_value(nxt_node, nxt_mask)

            key = (node, mask, ei)
            old = q.get(key, 0.0)
            q[key] = old + cfg.alpha * (reward + cfg.gamma * target_q - old)

            node, mask = nxt_node, nxt_mask
            if reached or dead_end:
                break

        if reached:
            goal_reached += 1
            if first_target_episode is None:
                first_target_episode = ep
            if ep < 5_000:
                first_5k_success += 1
        else:
            # Terminal failure: bootstrap the last state-action toward the
            # penalty so cap-hitting is learned as bad rather than as neutral.
            acts = actions[node]
            if acts:
                best = max(qval(node, mask, a) for a in acts)
                ei = next(a for a in acts if qval(node, mask, a) == best)
                key = (node, mask, ei)
                old = q.get(key, 0.0)
                q[key] = old + cfg.alpha * (cfg.failure_penalty - old)

        if (ep + 1) % cfg.checkpoint_every == 0:
            path = greedy_path(graph, source, target_set, cost, q, bits, reps,
                               actions, cfg.max_hops)
            route = path.edges if path else None
            checkpoints.append((ep + 1, path.cost if path else None))
            if on_checkpoint is not None:
                on_checkpoint(*checkpoints[-1])
            if route is not None and route == last_route:
                stable += 1
                if (stable >= cfg.stable_checkpoints_for_convergence
                        and converged_at is None):
                    converged_at = ep + 1
            else:
                stable = 0
            last_route = route

    final = greedy_path(graph, source, target_set, cost, q, bits, reps,
                        actions, cfg.max_hops)
    return QLearningResult(
        path=final,
        converged=converged_at is not None,
        converged_at_episode=converged_at,
        episodes_run=cfg.episodes,
        success_rate_first_5k=first_5k_success / min(5_000, cfg.episodes),
        goal_reached_total=goal_reached,
        first_target_episode=first_target_episode,
        checkpoints=checkpoints,
        q_size=len(q),
        q=q,
    )


def greedy_path(graph: AttackGraph, source: int, targets: set[int],
                cost: CostFn, q: dict, bits: dict[str, int], reps: dict[str, int],
                actions: dict[int, list[int]], max_hops: int) -> Path | None:
    """The ε=0 policy, walked once. Returns None if it fails to reach a target.

    Scored with the same cost function the search uses, so the number is directly
    comparable to Tier 1's rather than being the learner's own estimate of
    itself.
    """
    node, mask = source, 0
    nodes, edges = [node], []
    total = 0.0
    seen_states: set[tuple[int, int]] = set()
    for _ in range(max_hops):
        if (node, mask) in seen_states:
            return None                     # cycling under the greedy policy
        seen_states.add((node, mask))
        # **Visited actions only.** Every reward here is negative, so every
        # learned Q value is <= 0 while an unvisited action defaults to 0.0 —
        # which makes "never tried" the highest-scoring option and sends the
        # greedy walk into unexplored states every time. That is correct during
        # training (it is what drives exploration under optimistic init) and
        # wrong at extraction: an action with no estimate is unknown, not good.
        # This changes how the policy is read off, not what was learned.
        acts = [a for a in actions[node] if (node, mask, a) in q]
        if not acts:
            return None
        best = max(q[(node, mask, a)] for a in acts)
        ei = next(a for a in acts if q[(node, mask, a)] == best)
        history = tuple(reps[c] for c, b in sorted(bits.items())
                        if mask & b and c in reps)
        total += cost(graph, ei, history)
        edge = graph.edges[ei]
        nodes.append(edge.target)
        edges.append(ei)
        node = edge.target
        mask |= bits[category_of(edge.rel_type)]
        if node in targets:
            return Path(nodes=tuple(nodes), edges=tuple(edges), cost=total,
                        planner="q-learning")
    return None


class QLearningPlanner:
    """Planner-protocol wrapper. Trains on demand, one source at a time."""

    name = "q-learning"

    def __init__(self, cost: CostFn, cfg: QLearningConfig = QLearningConfig(),
                 allowed_rel_types: Iterable[str] | None = None) -> None:
        self._cost = cost
        self._cfg = cfg
        self._allowed = allowed_rel_types

    def plan(self, graph: AttackGraph, sources: Sequence[int],
             targets: Sequence[int]) -> Path | None:
        best: Path | None = None
        for s in sorted(set(sources)):
            r = train(graph, s, targets, self._cost, self._cfg, self._allowed)
            if r.path and (best is None or r.path.cost < best.cost):
                best = r.path
        return best
