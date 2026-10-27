"""Tier 2 comparison - PPO with action masking (the pre-registered algorithm).

PPO depends on torch and sb3-contrib. Those are declared in requirements but are
heavy, so the whole module **skips** where they are absent rather than failing -
the same "skip rather than fail" rule the project uses for gitignored artifacts,
so a clone without the deep-RL stack is still green and the skip count says so.

Full training is minutes per start and does not belong in the suite. What is
tested here is the parts that must be correct regardless of how well PPO learns:
the environment's action masking, the reward sign, and that a decoded trajectory
is a valid `Path` scored by the real cost function. Whether PPO reaches the
optimum is a *result*, measured by `tools/compare_rl_algorithms.py`, not a unit
test.
"""

from __future__ import annotations

import pytest

pytest.importorskip("torch")
pytest.importorskip("sb3_contrib")

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph, Edge, Node
from stealthpath.planners.ppo import GraphRoutingEnv, PPOConfig, train
from stealthpath.risk import RiskWeight, history_cost_fn

ALLOWED = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)


def _tiny_graph() -> tuple[AttackGraph, dict[str, RiskWeight]]:
    """Source -> middle -> target, plus a cheap dead-end branch."""
    nodes = [
        Node(id="s", name="SOURCE", kind="User"),
        Node(id="d", name="DEADEND", kind="Group"),
        Node(id="m", name="MIDDLE", kind="Computer"),
        Node(id="t", name="DOMAIN ADMINS@X", kind="Group"),
    ]
    edges = [
        Edge(0, 1, "MemberOf", {}),
        Edge(0, 2, "WriteOwner", {}),
        Edge(2, 3, "GenericWrite", {}),
    ]
    table = {
        "MemberOf": RiskWeight(weight=0.1, rationale="x", source="x"),
        "WriteOwner": RiskWeight(weight=4.0, rationale="x", source="x"),
        "GenericWrite": RiskWeight(weight=0.1, rationale="x", source="x"),
    }
    return AttackGraph(nodes, edges), table


def test_action_mask_marks_exactly_the_valid_out_edges():
    graph, table = _tiny_graph()
    allowed = {"MemberOf", "WriteOwner", "GenericWrite"}
    env = GraphRoutingEnv(graph, 0, [3], history_cost_fn(table),
                          PPOConfig(), allowed)
    env.reset()
    # SOURCE has two out-edges; the action space is padded to the max out-degree.
    mask = env.action_masks()
    assert mask[:2].all() and not mask[2:].any()
    assert env.action_space.n == 2  # max out-degree in this tiny graph


def test_reward_is_negative_step_cost_and_goal_terminates():
    graph, table = _tiny_graph()
    allowed = {"MemberOf", "WriteOwner", "GenericWrite"}
    env = GraphRoutingEnv(graph, 0, [3], history_cost_fn(table),
                          PPOConfig(), allowed)
    env.reset()
    # action 1 = WriteOwner (edge index 1 among SOURCE's out-edges), cost 4.0.
    obs, reward, terminated, truncated, info = env.step(1)
    assert reward == pytest.approx(-4.0)
    assert not terminated  # MIDDLE is not a target and has an out-edge
    # From MIDDLE, the only action leads to the target. GenericWrite repeats the
    # acl_abuse category WriteOwner already used, so the history model charges
    # 0.1 * k = 0.12 rather than 0.1 - confirming the env reads history.
    obs, reward, terminated, truncated, info = env.step(0)
    assert reward == pytest.approx(-0.12)
    assert terminated and info.get("reached")


def test_a_short_run_returns_a_valid_path_or_none():
    """Plumbing only: a brief train must yield a well-formed Path (or None), not
    raise. Not an optimality claim - that is the harness's job."""
    graph, table = _tiny_graph()
    allowed = {"MemberOf", "WriteOwner", "GenericWrite"}
    r = train(graph, 0, [3], history_cost_fn(table),
              PPOConfig(total_timesteps=1_500, n_steps=256, batch_size=64, seed=0),
              allowed)
    if r.path is not None:
        r.path.validate(graph)
        assert r.path.planner == "ppo"
        # Can never be cheaper than the exact optimum (4.12 here: 4.0 + 0.1*k).
        assert r.path.cost >= 4.12 - 1e-9
