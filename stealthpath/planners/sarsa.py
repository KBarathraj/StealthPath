"""
Tier 2 (comparison): SARSA over the augmented MDP.

Same state space, cost model, graph, view and `Path` type as `q_learning.py`.
The *only* thing that differs is the temporal-difference target:

    Q-learning (off-policy): Q(s,a) += alpha * (r + gamma * max_a' Q(s',a') - Q(s,a))
    SARSA      (on-policy):  Q(s,a) += alpha * (r + gamma *       Q(s',a') - Q(s,a))

where in SARSA `a'` is the action the exploration policy *actually* takes in
`s'`, not the greedy maximiser. That one change is the whole point of running it:
SARSA learns the value of the policy it is following, epsilon-exploration
included, so it is the natural on-policy control baseline to put beside the
off-policy learner the project already reports.

## How this gets reported

Exactly like `q_learning`: **as an optimality gap against `exact_history_search`,
never as a training curve.** SARSA cannot beat the exact optimum on this MDP; if
it appears to, that is a bug in one of the two, most likely the cost model
applied inconsistently. The reportable content is how close it gets and how
reliably across seeds.

## It reuses the model and the extraction, it does not reimplement them

`_mask_bits`, `_epsilon` and `greedy_path` are imported from `q_learning`. The
greedy extraction in particular must be byte-identical to the off-policy
learner's or the comparison measures the extractor, not the algorithm. The two
share `QLearningConfig`, so the only free variable between the two runs is the
update rule.

## The terminal bookkeeping matches the off-policy learner deliberately

A goal bootstraps toward 0, a dead-end and a hop-cap toward `failure_penalty`.
That is not SARSA-specific; it is the MDP's definition (see the dead-end comment
in `q_learning.train`), and both learners must see the same MDP or H2/H3 compare
two different problems rather than two algorithms.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

from ..ad_schema import DEFAULT_TRAVERSAL_SET, category_of
from ..graph import AttackGraph
from .base import Path
from .exact_history import category_representatives
from .q_learning import QLearningConfig, _epsilon, _mask_bits, greedy_path

__all__ = ["SarsaConfig", "SarsaResult", "train", "SarsaPlanner"]

CostFn = Callable[[AttackGraph, int, Sequence[int]], float]

# SARSA shares the pre-registered hyperparameters of the off-policy learner so
# the update rule is the only thing that differs between the two runs. Aliased
# rather than re-declared, for the same "one source of truth" reason the helpers
# are imported.
SarsaConfig = QLearningConfig


@dataclass
class SarsaResult:
    path: Path | None
    converged: bool
    converged_at_episode: int | None
    episodes_run: int
    success_rate_first_5k: float
    goal_reached_total: int
    checkpoints: list[tuple[int, float | None]]
    q_size: int
    first_target_episode: int | None = None
    q: dict[tuple[int, int, int], float] | None = None


def train(graph: AttackGraph,
          source: int,
          targets: Sequence[int],
          cost: CostFn,
          cfg: SarsaConfig = SarsaConfig(),
          allowed_rel_types: Iterable[str] | None = None,
          on_checkpoint: Callable[[int, float | None], None] | None = None,
          ) -> SarsaResult:
    """Learn a policy from `source` with SARSA, then score it against the exact
    optimum.

    The structure mirrors `q_learning.train` line for line except for the TD
    target, so that a diff of the two is exactly the off-policy/on-policy
    difference and nothing else.
    """
    allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                  else allowed_rel_types)
    target_set = set(targets)
    bits = _mask_bits(allowed)
    reps = category_representatives(graph, allowed)
    rng = random.Random(cfg.seed)

    actions: dict[int, list[int]] = {}
    for n in range(len(graph.nodes)):
        actions[n] = [ei for ei in graph.out_edge_indices(n)
                      if graph.edges[ei].rel_type in allowed]

    def history_for(mask: int) -> tuple[int, ...]:
        return tuple(reps[c] for c, b in sorted(bits.items()) if mask & b and c in reps)

    q: dict[tuple[int, int, int], float] = {}

    def qval(node: int, mask: int, ei: int) -> float:
        return q.get((node, mask, ei), 0.0)

    def choose(node: int, mask: int, eps: float) -> int | None:
        """epsilon-greedy over the node's actions, deterministic tie-break by
        edge index. Returns None at a node with no actions."""
        acts = actions[node]
        if not acts:
            return None
        if rng.random() < eps:
            return acts[rng.randrange(len(acts))]
        best = max(qval(node, mask, a) for a in acts)
        return next(a for a in acts if qval(node, mask, a) == best)

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
        # On-policy: the next action is chosen *before* the update that uses it.
        ei = choose(node, mask, eps)
        for _ in range(cfg.max_hops):
            if ei is None:
                break
            step = cost(graph, ei, history_for(mask))
            edge = graph.edges[ei]
            nxt_node = edge.target
            nxt_mask = mask | bits[category_of(edge.rel_type)]
            reward = -step

            dead_end = False
            nxt_ei: int | None = None
            if nxt_node in target_set:
                target_q = 0.0
                reached = True
            elif not actions[nxt_node]:
                # Non-goal terminal. Same reasoning as q_learning.train: without
                # the penalty, dead-ending is free and the cheapest edge into a
                # zero-out-degree node beats any route to a target.
                target_q = cfg.failure_penalty
                dead_end = True
            else:
                # The on-policy target: value of the action actually selected
                # next, not the greedy maximiser.
                nxt_ei = choose(nxt_node, nxt_mask, eps)
                target_q = qval(nxt_node, nxt_mask, nxt_ei) if nxt_ei is not None else 0.0

            key = (node, mask, ei)
            old = q.get(key, 0.0)
            q[key] = old + cfg.alpha * (reward + cfg.gamma * target_q - old)

            node, mask, ei = nxt_node, nxt_mask, nxt_ei
            if reached or dead_end:
                break

        if reached:
            goal_reached += 1
            if first_target_episode is None:
                first_target_episode = ep
            if ep < 5_000:
                first_5k_success += 1
        else:
            # Terminal failure bootstrap, matching the off-policy learner: push
            # the last greedy state-action toward the penalty so hitting the cap
            # is learned as bad rather than neutral.
            acts = actions[node]
            if acts:
                best = max(qval(node, mask, a) for a in acts)
                last = next(a for a in acts if qval(node, mask, a) == best)
                key = (node, mask, last)
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
    if final is not None:
        final = Path(nodes=final.nodes, edges=final.edges, cost=final.cost,
                     planner="sarsa")
    return SarsaResult(
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


class SarsaPlanner:
    """Planner-protocol wrapper. Trains on demand, one source at a time."""

    name = "sarsa"

    def __init__(self, cost: CostFn, cfg: SarsaConfig = SarsaConfig(),
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
