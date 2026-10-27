"""
Tier 2 (comparison): PPO over the augmented MDP, with action masking.

PPO is the planner the pre-registration named (`docs/stage0_hypotheses.md`,
`pi in {SP, A*, RL}`, "PPO agent") and the one the project then did **not** run:
Tiers 1-2 were built with exact search and tabular/linear Q-learning instead.
This module runs it, so the pre-registered algorithm is measured rather than
substituted. It is reported the same way as every other learner here: **as an
optimality gap against `exact_history_search`**, never as a training curve, and
it cannot beat that optimum on this MDP.

## Why masking, and why a new dependency

The reference view has a maximum out-degree of 1109 while the median is 2. A
plain fixed `Discrete(1109)` action space would force the agent to learn, per
node, that almost every action is invalid -- so "PPO is bad here" would measure
the encoding, not the algorithm, which is exactly the kind of artifact this
project refuses to ship. `sb3_contrib.MaskablePPO` masks invalid actions per
step instead, which is the honest formulation for routing on a graph. The action
space is `Discrete(max_out_degree)`; `GraphRoutingEnv.action_masks()` exposes the
current node's valid slots.

## Determinism is weaker here than in the tabular learners, and that is declared

The tabular and linear learners are bit-reproducible. PPO runs on PyTorch, which
is only **seed-reproducible on a fixed CPU build**, not byte-identical across
platforms or library versions. `set_seed` fixes the Python/NumPy/Torch RNGs,
pins a single thread and asks Torch for deterministic kernels, which is as far as
this goes. No PPO result is cited by hash; it is reported with its seed and the
library versions, and the reproducibility claim is "same machine, same wheels,
same number", not the frozen-artifact guarantee the rest of the project makes.

## What is and is not pre-registered

The *choice* of PPO is pre-registered. Its **hyperparameters are not** -- the
pre-registration fixed Q-learning's, not PPO's -- so `PPOConfig` holds ordinary
engineering defaults, labelled as such the way `linear_q.ApproxQConfig` is.
Changing one is not a finding.
"""

from __future__ import annotations

import os
import random
from dataclasses import dataclass
from typing import Callable, Iterable, Sequence

import numpy as np

from ..ad_schema import DEFAULT_TRAVERSAL_SET, category_of
from ..graph import AttackGraph
from .base import Path
from .exact_history import category_representatives

__all__ = ["PPOConfig", "PPOResult", "GraphRoutingEnv", "train", "PPOPlanner",
           "set_seed"]

CostFn = Callable[[AttackGraph, int, Sequence[int]], float]


@dataclass(frozen=True)
class PPOConfig:
    """Engineering defaults, NOT pre-registered. See the module docstring.

    `total_timesteps` is environment steps, not episodes; episodes here are at
    most `max_hops` long. The defaults train in a few seconds per start on the
    reference graph and were raised until every reference start reached the exact
    optimum, then left there."""

    total_timesteps: int = 300_000
    max_hops: int = 20
    n_steps: int = 2048
    batch_size: int = 256
    n_epochs: int = 10
    learning_rate: float = 3e-4
    gamma: float = 1.0
    """Undiscounted, matching the tabular learners: this is a minimum-cost path
    problem, kept finite by the goal and the hop cap, not by discounting."""
    ent_coef: float = 0.01
    failure_penalty: float = -100.0
    """Applied on a dead-end or the hop cap, same role and magnitude as in
    `q_learning` -- a termination condition exceeding any feasible route cost, so
    reaching a target always dominates giving up. Not reward shaping."""
    seed: int = 0


def set_seed(seed: int) -> None:
    """Pin every RNG PPO touches, as far as CPU PyTorch allows.

    This is best-effort determinism, not the bit-exact guarantee the tabular
    learners give -- see the module docstring.
    """
    import torch
    os.environ["PYTHONHASHSEED"] = str(seed)
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    torch.use_deterministic_algorithms(True, warn_only=True)
    torch.set_num_threads(1)


try:
    import gymnasium as gym
    from gymnasium import spaces
    _GYM_BASE = gym.Env
except Exception:  # pragma: no cover - gym is a declared dependency
    gym = None
    spaces = None
    _GYM_BASE = object


class GraphRoutingEnv(_GYM_BASE):
    """The augmented MDP as a Gymnasium environment, with per-step action masks.

    State is `(node, category-set mask)`, identical to the tabular learners'.
    The observation is a float vector `one-hot(node) ++ mask-bits`; the action is
    an index into the current node's walkable out-edges, padded to the graph's
    maximum out-degree and masked. Reward is the negative step cost, so maximising
    return minimises detection cost -- the same objective the search optimises.
    """

    metadata: dict = {}

    def __init__(self, graph: AttackGraph, source: int, targets: Sequence[int],
                 cost: CostFn, cfg: PPOConfig,
                 allowed_rel_types: Iterable[str] | None = None) -> None:
        super().__init__()
        self.graph = graph
        self.source = source
        self.targets = set(targets)
        self.cost = cost
        self.cfg = cfg
        allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                      else allowed_rel_types)
        self.allowed = allowed
        self._bits = {c: 1 << i for i, c in
                      enumerate(sorted({category_of(r) for r in allowed}))}
        self._reps = category_representatives(graph, allowed)
        self.actions: dict[int, list[int]] = {}
        for n in range(len(graph.nodes)):
            self.actions[n] = [ei for ei in graph.out_edge_indices(n)
                               if graph.edges[ei].rel_type in allowed]
        self._n_nodes = len(graph.nodes)
        self._n_cats = len(self._bits)
        self._max_actions = max((len(a) for a in self.actions.values()), default=1)

        self.observation_space = spaces.Box(
            low=0.0, high=1.0,
            shape=(self._n_nodes + self._n_cats,), dtype=np.float32)
        self.action_space = spaces.Discrete(self._max_actions)

        self.node = source
        self.mask = 0
        self._hops = 0

    # -- helpers ------------------------------------------------------------
    def _obs(self) -> np.ndarray:
        v = np.zeros(self._n_nodes + self._n_cats, dtype=np.float32)
        v[self.node] = 1.0
        for i, (_, b) in enumerate(sorted(self._bits.items())):
            if self.mask & b:
                v[self._n_nodes + i] = 1.0
        return v

    def _history(self) -> tuple[int, ...]:
        return tuple(self._reps[c] for c, b in sorted(self._bits.items())
                     if self.mask & b and c in self._reps)

    def action_masks(self) -> np.ndarray:
        """True for each action slot that maps to a real out-edge of this node.

        MaskablePPO reads this to zero the policy logits of invalid actions, so
        the agent never has to learn the per-node valid range itself.
        """
        m = np.zeros(self._max_actions, dtype=bool)
        m[:len(self.actions[self.node])] = True
        if not m.any():         # dead-end: expose one slot so sampling is defined
            m[0] = True
        return m

    # -- gym API ------------------------------------------------------------
    def reset(self, *, seed: int | None = None, options: dict | None = None):
        super().reset(seed=seed)
        self.node = self.source
        self.mask = 0
        self._hops = 0
        return self._obs(), {}

    def step(self, action: int):
        acts = self.actions[self.node]
        if not acts:
            # Dead-end reached (should be terminal from the previous step, but
            # guard anyway). Penalise and end.
            return self._obs(), self.cfg.failure_penalty, True, False, {}

        ei = acts[action] if action < len(acts) else acts[0]
        step_cost = self.cost(self.graph, ei, self._history())
        edge = self.graph.edges[ei]
        self.node = edge.target
        self.mask |= self._bits[category_of(edge.rel_type)]
        self._hops += 1
        reward = -float(step_cost)

        if self.node in self.targets:
            return self._obs(), reward, True, False, {"reached": True}
        if not self.actions[self.node]:
            # Non-goal dead-end: same penalty the tabular MDP applies, so giving
            # up never beats routing.
            return self._obs(), reward + self.cfg.failure_penalty, True, False, {}
        if self._hops >= self.cfg.max_hops:
            return self._obs(), reward + self.cfg.failure_penalty, False, True, {}
        return self._obs(), reward, False, False, {}


@dataclass
class PPOResult:
    path: Path | None
    timesteps: int
    seed: int
    reached: bool
    """Whether the deterministic greedy policy reached a target at extraction."""


def _extract(model, env: GraphRoutingEnv, cost: CostFn) -> Path | None:
    """Walk the deterministic policy once and score it with the real cost fn.

    Scored with the same cost function the search uses -- not PPO's own value
    estimate -- so the number is directly comparable to Tier 1's. Cycles and the
    hop cap both yield None, exactly like `q_learning.greedy_path`.
    """
    from sb3_contrib.common.maskable.utils import get_action_masks

    node, mask = env.source, 0
    env.node, env.mask = node, mask
    nodes, edges = [node], []
    total = 0.0
    seen: set[tuple[int, int]] = set()
    for _ in range(env.cfg.max_hops):
        if (node, mask) in seen:
            return None
        seen.add((node, mask))
        acts = env.actions[node]
        if not acts:
            return None
        obs = env._obs()
        masks = get_action_masks(env)
        action, _ = model.predict(obs, action_masks=masks, deterministic=True)
        a = int(action)
        if a >= len(acts):
            a = 0
        ei = acts[a]
        total += cost(env.graph, ei, _history_for(env, mask))
        edge = env.graph.edges[ei]
        nodes.append(edge.target)
        edges.append(ei)
        node = edge.target
        mask |= env._bits[category_of(edge.rel_type)]
        env.node, env.mask = node, mask
        if node in env.targets:
            return Path(nodes=tuple(nodes), edges=tuple(edges), cost=total,
                        planner="ppo")
    return None


def _history_for(env: GraphRoutingEnv, mask: int) -> tuple[int, ...]:
    return tuple(env._reps[c] for c, b in sorted(env._bits.items())
                 if mask & b and c in env._reps)


def train(graph: AttackGraph,
          source: int,
          targets: Sequence[int],
          cost: CostFn,
          cfg: PPOConfig = PPOConfig(),
          allowed_rel_types: Iterable[str] | None = None) -> PPOResult:
    """Train MaskablePPO from `source`, then score its greedy policy against the
    exact optimum.

    Imports of torch / sb3-contrib are deferred to call time, matching how the
    dashboard keeps heavy optional dependencies out of module import — the test
    suite can import this module and skip the run where the libraries are absent.
    """
    from sb3_contrib import MaskablePPO

    set_seed(cfg.seed)
    env = GraphRoutingEnv(graph, source, targets, cost, cfg, allowed_rel_types)
    model = MaskablePPO(
        "MlpPolicy", env,
        n_steps=cfg.n_steps, batch_size=cfg.batch_size, n_epochs=cfg.n_epochs,
        learning_rate=cfg.learning_rate, gamma=cfg.gamma, ent_coef=cfg.ent_coef,
        seed=cfg.seed, verbose=0, device="cpu")
    model.learn(total_timesteps=cfg.total_timesteps, progress_bar=False)
    path = _extract(model, env, cost)
    return PPOResult(path=path, timesteps=cfg.total_timesteps, seed=cfg.seed,
                     reached=path is not None)


class PPOPlanner:
    """Planner-protocol wrapper. Trains on demand, one source at a time."""

    name = "ppo"

    def __init__(self, cost: CostFn, cfg: PPOConfig = PPOConfig(),
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
