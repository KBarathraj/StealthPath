"""
Tier 2b: Q-learning with hashed state-action features, for graphs of any size.

This is the learner the web app runs on an uploaded directory. It exists because
the tabular learner in `q_learning.py` allocates one cell per reachable
`(node, mask, action)` and has no ceiling: on a real directory that is not a
slow run, it is an unbounded one.

## What it actually is

Linear Q-learning, `Q(s,a) = w . phi(s,a)`, where `phi` is three hashed
indicator features rather than a handcrafted vector:

    (edge, mask)     the specific state-action -- precision
    (edge)           the same move regardless of history -- generalises across masks
    (target, mask)   arriving here having used these categories -- generalises
                     across the predecessors that can reach it

The state's node is not in any key because an edge index already determines its
own source, so including it would partition nothing further. `w` is a fixed-size
array: memory is `buckets`, not `|S|`, so a directory ten times larger costs the
same RAM and only more episodes. Collisions are real and are reported by
`collision_report()` rather than hidden.

## Why not a handcrafted feature vector

The first version of this module used ~20 named, readable features (step cost,
hops-to-target, category one-hots). It looked better and was much worse: on
random AD graphs of 2,900-8,200 nodes it came in **+32% to +80% above the exact
optimum and did not improve with more episodes**, because a global weight per
named feature cannot say "take MemberOf *here* but not *there*" -- it learns one
global edge preference. Adding the named block back on top of the hashed one
made things worse again (one case +65%, another failed to reach a target at
all), because the shared dense weights pull every state's estimate together.

Measured on the same six start/graph pairs: hashed reached the exact optimum on
**6 of 6**, handcrafted on 1 of 6. Widened afterwards to 14 start/graph pairs
spanning the reference collection and random directories of 2,902 to 20,502
nodes: **14 of 14 at +0.00%**, the largest in about 7 seconds.
`tests/test_targets_and_scaling.py` pins a subset that runs fast enough for the
suite.

The cost of the change is interpretability: there is no "weight for
step_cost" to print any more. That was a genuine property of the old design and
it is gone. `collision_report()` is what replaced it, and it answers a different
and smaller question -- how crowded the table is, not what the policy believes.

## What is still not guaranteed

**Nothing here is proved optimal.** Tier 1 (`exact_history.py`) is what lets
this project say a route *is* optimal, and `dashboard/rl_upload.py` always runs
it first and reports this learner against it when it finishes. When it does not,
a route from here is a **candidate**: `Path.meta["verified"]` is `False`, the
planner name says so, and the UI renders it differently. Reaching the optimum on
every case anyone has checked is evidence, not a proof, and the two must not be
confused in anything this prints.

## Determinism

`hash()` on a tuple of ints is stable within and across CPython runs, but
`PYTHONHASHSEED` does perturb `hash()` on str and bytes, and relying on the
distinction is the kind of subtlety that breaks a frozen result a year later.
`_mix()` is an explicit integer hash so the bucket for a given state-action is a
property of this file. Seeded RNG and index tie-breaking match the other
planners.
"""

from __future__ import annotations

import random
from array import array
from dataclasses import dataclass, field
from typing import Callable, Iterable, Sequence

from ..ad_schema import DEFAULT_TRAVERSAL_SET, category_of
from ..graph import AttackGraph
from .base import Path
from .exact_history import category_representatives

__all__ = [
    "ApproxQConfig", "ApproxQResult", "LinearQConfig", "LinearQResult",
    "train_approx", "train_linear", "greedy_path_approx", "ApproxQPlanner",
    "LinearQPlanner", "state_space_fits_table", "TABLE_STATE_LIMIT",
    "DEFAULT_BUCKETS",
]

CostFn = Callable[[AttackGraph, int, Sequence[int]], float]

DEFAULT_BUCKETS = 1 << 20
"""1,048,576 weights, 8 MB as a `double` array.

Chosen so the worst case is bounded and boring rather than tuned: a directory
big enough to collide heavily here is also big enough that the exact search has
already declined, so the alternative to a collision is not a better answer, it
is no answer.
"""

TABLE_STATE_LIMIT = 5_000_000
"""Nominal `(node, mask)` count above which the tabular learner is not offered.

**This is a statement about the table, not about difficulty.** It was briefly
used to decide which planner an upload should get, which was wrong twice over:
it called a 10,902-node graph too big while the exact search answered it in
under a second, and the nominal count ignores that the reachable component is
usually a tiny fraction of it. `dashboard/rl_upload.py` now decides by running
the exact search under a deadline and seeing what happens.
"""

_MASK64 = (1 << 64) - 1


def _mix(*values: int) -> int:
    """Stable integer hash. SplitMix64-style finaliser over the inputs.

    Written out rather than calling `hash()` so the bucket a state-action lands
    in is fixed by this file and not by the interpreter's hash randomisation.
    """
    h = 0x9E3779B97F4A7C15
    for v in values:
        h = (h ^ (v & _MASK64)) & _MASK64
        h = (h * 0xBF58476D1CE4E5B9) & _MASK64
        h ^= h >> 31
        h = (h * 0x94D049BB133111EB) & _MASK64
        h ^= h >> 29
    return h


@dataclass(frozen=True)
class ApproxQConfig:
    """Ordinary engineering defaults, and that differs from `QLearningConfig`.

    `q_learning.QLearningConfig` carries hyperparameters registered in
    `findings.md` before the first run, because its results are reported as a
    measurement. These are not: this learner's output is labelled unverified and
    changing a default here is not a finding.
    """

    alpha: float = 0.05
    gamma: float = 1.0
    episodes: int = 25_000
    """Measured, not guessed. At 10,000 one start on an 8,000-user random graph
    landed +7.3% on one seed of three; at 25,000 every seed reached the exact
    optimum, and the run still finishes in about a second. Raising it further
    bought nothing on any case checked."""

    max_hops: int = 20
    epsilon_start: float = 1.0
    epsilon_end: float = 0.05
    epsilon_decay_fraction: float = 0.8
    failure_penalty: float = -100.0
    """Same role as in the tabular learner: a termination condition, not reward
    shaping. Without it, dead-ending scores better than paying for a route."""

    checkpoint_every: int = 1_000
    stable_checkpoints_for_convergence: int = 10
    """Checkpoints of identical greedy route before `converged_at_episode` is set.

    **Reporting only -- the run does not stop.** Early stopping on this
    criterion was built and then removed: across 14 start/graph pairs it fired
    on **none of them**, so `converged_at_episode` stayed `None` and the flag
    changed nothing but the number of branches. The apparent 2.4s-vs-9.3s
    speedup that motivated it was run-to-run noise on identical work, not the
    flag. Do not re-add it expecting a win without first checking that this
    criterion actually fires on the graphs you care about.
    """

    buckets: int = DEFAULT_BUCKETS
    seed: int = 0

    def __post_init__(self) -> None:
        if self.buckets & (self.buckets - 1):
            raise ValueError(
                f"buckets must be a power of two, got {self.buckets}. The "
                f"bucket index is taken with a mask rather than a modulo, "
                f"which is only uniform for powers of two."
            )


@dataclass
class ApproxQResult:
    path: Path | None
    converged: bool
    converged_at_episode: int | None
    episodes_run: int
    goal_reached_total: int
    first_target_episode: int | None
    buckets_touched: int
    buckets: int
    checkpoints: list[tuple[int, float | None]] = field(default_factory=list)
    weights: array = field(default_factory=lambda: array("d"))

    @property
    def verified(self) -> bool:
        """Always False. A property rather than a flag the caller sets, so it
        cannot be forgotten on one code path."""
        return False

    def collision_report(self) -> dict[str, float | int]:
        """How crowded the weight array got.

        `load_factor` near 1 means buckets are being shared and estimates are
        bleeding between unrelated state-actions. It is a reason to distrust the
        route, and it is the honest replacement for the named feature weights
        the handcrafted version used to print.
        """
        return {
            "buckets": self.buckets,
            "touched": self.buckets_touched,
            "load_factor": self.buckets_touched / self.buckets,
        }

    def weights_digest(self) -> int:
        """Cheap fingerprint, for asserting two runs agree without holding two
        8 MB arrays side by side."""
        h = 0
        for i, value in enumerate(self.weights):
            if value:
                h = _mix(h, i, int(value * 1e9))
        return h


# Names kept so existing imports and tests do not churn. The basis changed, the
# interface did not.
LinearQConfig = ApproxQConfig
LinearQResult = ApproxQResult


def state_space_fits_table(graph: AttackGraph,
                           allowed_rel_types: Iterable[str] | None = None) -> bool:
    """Whether the tabular learner could hold this graph's nominal state space.

    Read the note on `TABLE_STATE_LIMIT`: this answers a memory question, not
    "which planner should run".
    """
    allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                  else allowed_rel_types)
    categories = {category_of(r) for r in allowed}
    return len(graph.nodes) * (2 ** len(categories)) <= TABLE_STATE_LIMIT


def _epsilon(cfg: ApproxQConfig, episode: int) -> float:
    span = max(1, int(cfg.episodes * cfg.epsilon_decay_fraction))
    if episode >= span:
        return cfg.epsilon_end
    return cfg.epsilon_start + (episode / span) * (cfg.epsilon_end - cfg.epsilon_start)


_MASK_SALT = 0xD6E8FEB86659FD93


class _Hasher:
    """The feature map: three buckets per state-action, no allocation per call.

    **`node` is not in any of the keys, because it is redundant** -- an edge
    index determines its own source, so `(node, mask, edge)` and `(mask, edge)`
    partition the state-action space identically. Dropping it is not an
    approximation.

    That leaves every key a function of `(edge, mask)` alone, so the expensive
    part is precomputed per edge at construction and the per-call work is one
    multiply and one xor. The full `_mix` was ~24s for 10k episodes on the
    reference graph under GPO expansion, where container nodes have very high
    out-degree and `best_value` hashes every action at every step.
    """

    def __init__(self, graph: AttackGraph, buckets: int):
        self._mask = buckets - 1
        # Per-edge bases, mixed once with the strong finaliser.
        self._edge_base = [_mix(1, ei) for ei in range(len(graph.edges))]
        self._edge_only = [_mix(2, ei) & self._mask for ei in range(len(graph.edges))]
        self._target_base = [_mix(3, e.target) for e in graph.edges]

    def __call__(self, node: int, mask: int, ei: int) -> tuple[int, int, int]:
        salted = (mask * _MASK_SALT) & _MASK64
        m = self._mask
        return ((self._edge_base[ei] ^ salted) & m,
                self._edge_only[ei],
                (self._target_base[ei] ^ salted) & m)


def train_approx(graph: AttackGraph,
                 source: int,
                 targets: Sequence[int],
                 cost: CostFn,
                 cfg: ApproxQConfig = ApproxQConfig(),
                 allowed_rel_types: Iterable[str] | None = None,
                 on_checkpoint: Callable[[int, float | None], None] | None = None,
                 ) -> ApproxQResult:
    """Learn a policy from `source` over the same MDP the tabular learner uses.

    `on_checkpoint(episode, best_cost)` is an observer with the same contract as
    `q_learning.train`'s: called after the checkpoint is recorded, return value
    discarded, and it touches nothing the RNG sees, so a run with an observer
    must produce identical output to one without.
    """
    allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                  else allowed_rel_types)
    target_set = set(targets)
    categories = sorted({category_of(r) for r in allowed})
    bits = {c: 1 << i for i, c in enumerate(categories)}
    reps = category_representatives(graph, allowed)
    rng = random.Random(cfg.seed)

    actions: dict[int, list[int]] = {
        n: [ei for ei in graph.out_edge_indices(n)
            if graph.edges[ei].rel_type in allowed]
        for n in range(len(graph.nodes))
    }

    w = array("d", bytes(8 * cfg.buckets))
    touched: set[int] = set()
    feats = _Hasher(graph, cfg.buckets)
    history_cache: dict[int, tuple[int, ...]] = {}

    def history_for(mask: int) -> tuple[int, ...]:
        cached = history_cache.get(mask)
        if cached is None:
            cached = tuple(reps[c] for c in categories
                           if mask & bits[c] and c in reps)
            history_cache[mask] = cached
        return cached

    def q(node: int, mask: int, ei: int) -> float:
        a, b, c = feats(node, mask, ei)
        return w[a] + w[b] + w[c]

    def best_value(node: int, mask: int) -> float:
        acts = actions[node]
        return max((q(node, mask, ei) for ei in acts), default=0.0)

    def update(node: int, mask: int, ei: int, target_value: float) -> None:
        a, b, c = feats(node, mask, ei)
        # Divided by the three active features, so the step size is the same
        # whether one bucket or three carry the estimate. Without it the
        # effective alpha is 3x the configured one and the updates oscillate.
        delta = cfg.alpha * (target_value - (w[a] + w[b] + w[c])) / 3.0
        w[a] += delta
        w[b] += delta
        w[c] += delta
        touched.add(a)
        touched.add(b)
        touched.add(c)

    goal_reached = 0
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
                values = [q(node, mask, a) for a in acts]
                ei = acts[values.index(max(values))]   # ties -> lowest edge index

            step = cost(graph, ei, history_for(mask))
            edge = graph.edges[ei]
            nxt_node = edge.target
            nxt_mask = mask | bits[category_of(edge.rel_type)]

            dead_end = False
            if nxt_node in target_set:
                bootstrap = 0.0
                reached = True
            elif not actions[nxt_node]:
                bootstrap = cfg.failure_penalty
                dead_end = True
            else:
                bootstrap = best_value(nxt_node, nxt_mask)

            update(node, mask, ei, -step + cfg.gamma * bootstrap)
            node, mask = nxt_node, nxt_mask
            if reached or dead_end:
                break

        if reached:
            goal_reached += 1
            if first_target_episode is None:
                first_target_episode = ep
        else:
            acts = actions[node]
            if acts:
                values = [q(node, mask, a) for a in acts]
                update(node, mask, acts[values.index(max(values))],
                       cfg.failure_penalty)

        if (ep + 1) % cfg.checkpoint_every == 0:
            path = greedy_path_approx(graph, source, target_set, cost, q,
                                      history_for, actions, bits, cfg.max_hops)
            checkpoints.append((ep + 1, path.cost if path else None))
            if on_checkpoint is not None:
                on_checkpoint(*checkpoints[-1])
            route = path.edges if path else None
            if route is not None and route == last_route:
                stable += 1
                if stable >= cfg.stable_checkpoints_for_convergence and converged_at is None:
                    converged_at = ep + 1
            else:
                stable = 0
            last_route = route

    final = greedy_path_approx(graph, source, target_set, cost, q, history_for,
                               actions, bits, cfg.max_hops)
    return ApproxQResult(
        path=final,
        converged=converged_at is not None,
        converged_at_episode=converged_at,
        episodes_run=cfg.episodes,
        goal_reached_total=goal_reached,
        first_target_episode=first_target_episode,
        buckets_touched=len(touched),
        buckets=cfg.buckets,
        checkpoints=checkpoints,
        weights=w,
    )


def greedy_path_approx(graph: AttackGraph, source: int, targets: set[int],
                       cost: CostFn, q, history_for, actions: dict[int, list[int]],
                       bits: dict[str, int], max_hops: int) -> Path | None:
    """The epsilon=0 policy, walked once and scored with the real cost function.

    **No "visited actions only" filter**, unlike `q_learning.greedy_path`. That
    filter exists because an unvisited table cell reads 0.0 and so outranks every
    learned negative value. There are no unvisited cells here: every action is
    scored by whatever its buckets hold, and an action this walk never took still
    has an estimate. Copying the filter across would be the natural thing to do
    and would be wrong.
    """
    node, mask = source, 0
    nodes, edges = [node], []
    total = 0.0
    seen: set[tuple[int, int]] = set()
    for _ in range(max_hops):
        if (node, mask) in seen:
            return None                     # cycling under the greedy policy
        seen.add((node, mask))
        acts = actions[node]
        if not acts:
            return None
        values = [q(node, mask, a) for a in acts]
        ei = acts[values.index(max(values))]
        total += cost(graph, ei, history_for(mask))
        edge = graph.edges[ei]
        nodes.append(edge.target)
        edges.append(ei)
        node = edge.target
        mask |= bits[category_of(edge.rel_type)]
        if node in targets:
            return Path(nodes=tuple(nodes), edges=tuple(edges), cost=total,
                        planner="approximate Q-learning (unverified)",
                        meta={"verified": False,
                              "why": "learned policy; not proved optimal"})
    return None


def train_linear(*args, **kwargs) -> ApproxQResult:
    """Previous name for `train_approx`, kept so callers do not churn."""
    return train_approx(*args, **kwargs)


class ApproxQPlanner:
    """Planner-protocol wrapper. Same `Path` type as the other planners, by
    build rule 5."""

    name = "approx-q"

    def __init__(self, cost: CostFn, cfg: ApproxQConfig = ApproxQConfig(),
                 allowed_rel_types: Iterable[str] | None = None) -> None:
        self._cost = cost
        self._cfg = cfg
        self._allowed = allowed_rel_types

    def plan(self, graph: AttackGraph, sources: Sequence[int],
             targets: Sequence[int]) -> Path | None:
        best: Path | None = None
        for s in sorted(set(sources)):
            r = train_approx(graph, s, targets, self._cost, self._cfg, self._allowed)
            if r.path and (best is None or r.path.cost < best.cost):
                best = r.path
        return best


LinearQPlanner = ApproxQPlanner
