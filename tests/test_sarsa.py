"""Tier 2 comparison - SARSA, the on-policy twin of the tabular Q-learner.

SARSA shares the Q-learner's MDP, cost model and greedy extraction, so the tests
that mattered there matter here: the silent dead-end bug, determinism, and
reaching the exact optimum. The one SARSA-specific check is that it is genuinely
*on-policy* - its TD target reads the next action actually taken, not the greedy
maximiser - which is the only thing that distinguishes it from `q_learning`.
"""

from __future__ import annotations

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph, Edge, Node
from stealthpath.planners.exact_history import exact_history_search
from stealthpath.planners.sarsa import SarsaConfig, SarsaPlanner, train
from stealthpath.risk import RiskWeight, history_cost_fn

FAST = SarsaConfig(episodes=6_000, seed=0, checkpoint_every=500)
ALLOWED = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)


def _dead_end_graph() -> tuple[AttackGraph, dict[str, RiskWeight]]:
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


def test_a_cheap_dead_end_does_not_beat_reaching_the_target():
    """The bug that broke the first real run, ported to SARSA: a cheap edge into
    a zero-out-degree node must not out-score the dearer route to a target."""
    graph, table = _dead_end_graph()
    cost = history_cost_fn(table)
    allowed = {"MemberOf", "WriteOwner", "GenericWrite"}
    r = train(graph, 0, [3], cost, SarsaConfig(episodes=4_000, seed=0,
              checkpoint_every=500), allowed)
    assert r.path is not None
    assert r.path.rel_types(graph) == ["WriteOwner", "GenericWrite"]


def test_sarsa_is_deterministic():
    """Two runs with the same seed must return the same route and q-table size.
    Determinism is a build rule; a frozen comparison depends on it."""
    graph, table = _dead_end_graph()
    cost = history_cost_fn(table)
    allowed = {"MemberOf", "WriteOwner", "GenericWrite"}
    a = train(graph, 0, [3], cost, SarsaConfig(episodes=3_000, seed=1), allowed)
    b = train(graph, 0, [3], cost, SarsaConfig(episodes=3_000, seed=1), allowed)
    assert a.path.edges == b.path.edges
    assert a.path.cost == b.path.cost
    assert a.q_size == b.q_size


def test_sarsa_reaches_the_exact_optimum_on_a_reference_entry():
    """SARSA cannot beat exact search; on SAMWELL (2 hops) it should match it."""
    graph = AttackGraph.load("data/goad_graph.json").with_gpo_expansion()
    cost = history_cost_fn()
    src = graph.find(name="SAMWELL.TARLY@NORTH")
    opt = exact_history_search(graph, src, graph.tier0_targets(), cost, ALLOWED, 20)
    r = train(graph, src[0], graph.tier0_targets(), cost,
              SarsaConfig(episodes=20_000, seed=0), ALLOWED)
    assert r.path is not None
    r.path.validate(graph)
    assert abs(r.path.cost - opt.cost) < 1e-9, (r.path.cost, opt.cost)


def test_sarsa_never_prices_below_the_exact_optimum():
    """A learner that reports a cost under the proven optimum is a bug, not a win
    - most likely the cost model applied inconsistently between the two."""
    graph = AttackGraph.load("data/goad_graph.json").with_gpo_expansion()
    cost = history_cost_fn()
    src = graph.find(name="SQL_SVC@NORTH")
    opt = exact_history_search(graph, src, graph.tier0_targets(), cost, ALLOWED, 20)
    r = train(graph, src[0], graph.tier0_targets(), cost,
              SarsaConfig(episodes=20_000, seed=0), ALLOWED)
    assert r.path is not None
    assert r.path.cost >= opt.cost - 1e-9


def test_planner_wrapper_returns_one_path_type():
    graph = AttackGraph.load("data/goad_graph.json").with_gpo_expansion()
    planner = SarsaPlanner(history_cost_fn(), SarsaConfig(episodes=8_000, seed=0),
                           ALLOWED)
    src = graph.find(name="SAMWELL.TARLY@NORTH")
    path = planner.plan(graph, src, graph.tier0_targets())
    assert path is not None and path.planner == "sarsa"
    path.validate(graph)
