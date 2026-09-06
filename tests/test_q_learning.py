"""Tier 2 — tabular Q-learning, scored against the exact optimum.

Both bugs this planner shipped with were **silent**: the agent trained happily,
reported plausible statistics, and returned a confidently wrong policy. Neither
would have been caught by "does it run". The two regression tests below are the
main content here.
"""

from __future__ import annotations

import pytest

from stealthpath.graph import AttackGraph, Edge, Node
from stealthpath.planners.exact_history import exact_history_search
from stealthpath.planners.q_learning import (
    QLearningConfig, QLearningPlanner, greedy_path, train,
)
from stealthpath.risk import RiskWeight, history_cost_fn
from stealthpath.synthetic import goad_like

FAST = QLearningConfig(episodes=4_000, seed=0, checkpoint_every=500)


@pytest.fixture
def goad():
    return goad_like()


def _dead_end_graph() -> tuple[AttackGraph, dict[str, RiskWeight]]:
    """Source with two choices: a cheap dead end, or a dearer route to a target.

    This is the shape that broke the real run. `MemberOf` (0.1) into a
    zero-out-degree node scored better than the 4.1 optimum, because a node with
    no actions bootstrapped to 0.0 — the same value a *goal* gets.
    """
    nodes = [
        Node(id="s", name="SOURCE", kind="User"),
        Node(id="d", name="DEADEND", kind="Group"),
        Node(id="m", name="MIDDLE", kind="Computer"),
        Node(id="t", name="DOMAIN ADMINS@X", kind="Group"),
    ]
    edges = [
        Edge(0, 1, "MemberOf", {}),       # cheap, goes nowhere
        Edge(0, 2, "WriteOwner", {}),     # dearer, but on the way
        Edge(2, 3, "GenericWrite", {}),
    ]
    table = {
        "MemberOf": RiskWeight(weight=0.1, rationale="x", source="x"),
        "WriteOwner": RiskWeight(weight=4.0, rationale="x", source="x"),
        "GenericWrite": RiskWeight(weight=0.1, rationale="x", source="x"),
    }
    return AttackGraph(nodes, edges), table


def test_a_cheap_dead_end_does_not_beat_reaching_the_target():
    """**Regression: dead ends were free.**

    A node with no actions returned `best_value` 0.0, identical to a goal's
    bootstrap, so the learned optimum was to take the cheapest edge into a dead
    end and stop. Every non-goal termination has to be penalised the way the hop
    cap is, or the MDP rewards giving up.
    """
    graph, table = _dead_end_graph()
    cost = history_cost_fn(table=table)
    allowed = {"MemberOf", "WriteOwner", "GenericWrite"}
    result = train(graph, 0, [3], cost, FAST, allowed_rel_types=allowed)

    assert result.path is not None, "learner failed to reach the target at all"
    assert result.path.nodes[-1] == 3
    assert result.path.rel_types(graph) == ["WriteOwner", "GenericWrite"]


def test_greedy_extraction_ignores_actions_it_never_tried():
    """**Regression: unvisited actions dominated the greedy policy.**

    Every reward is negative, so every learned Q value is <= 0 while an
    unvisited action defaults to 0.0 — the best possible score. Greedy therefore
    preferred whatever it had never tried and walked into unexplored states.
    Correct during training, where it drives exploration; fatal at extraction,
    where "no estimate" is not "good".

    Tested on `greedy_path` directly rather than through a training run, because
    the behavioural version of this depends on how far a short run happens to
    get and would be flaky for reasons unrelated to the fix.
    """
    graph, table = _dead_end_graph()
    cost = history_cost_fn(table=table)
    bits = {"group_membership": 1, "acl_abuse": 2}
    actions = {0: [0, 1], 1: [], 2: [2], 3: []}

    # Nothing visited at all: there is no policy to read off, so None — not a
    # walk into the highest-scoring unexplored action.
    assert greedy_path(graph, 0, {3}, cost, {}, bits, {}, actions, 20) is None

    # Only the route to the target has been visited, and every one of its Q
    # values is negative. Edge 0 (the dead end) is unvisited and would score
    # 0.0 — the best number on the table — under the old rule, sending greedy
    # into the dead end. Under the fix it is not a candidate at all.
    q = {(0, 0, 1): -4.1, (2, 2, 2): -0.1}
    walked = greedy_path(graph, 0, {3}, cost, q, bits, {}, actions, 20)
    assert walked is not None, "greedy chose an action it had never tried"
    assert walked.rel_types(graph) == ["WriteOwner", "GenericWrite"]


@pytest.mark.parametrize("seed", [0, 1, 2])
def test_never_beats_the_exact_optimum(goad, seed):
    """Q-learning cannot beat exact search on the same MDP. If it appears to,
    one of the two is applying the cost model differently — which would make
    every optimality gap meaningless, in the flattering direction."""
    cost = history_cost_fn()
    srcs, tgts = goad.entry_nodes(), goad.target_nodes()
    opt = exact_history_search(goad, srcs, tgts, cost)
    if opt is None:
        pytest.skip("no route")
    cfg = QLearningConfig(episodes=4_000, seed=seed, checkpoint_every=500)
    for s in srcs:
        r = train(goad, s, tgts, cost, cfg)
        if r.path is None:
            continue
        per_source = exact_history_search(goad, [s], tgts, cost)
        assert r.path.cost >= per_source.cost - 1e-9


def test_is_deterministic_for_a_seed(goad):
    cost = history_cost_fn()
    srcs, tgts = goad.entry_nodes(), goad.target_nodes()
    runs = [train(goad, srcs[0], tgts, cost, FAST) for _ in range(3)]
    assert len({(r.path.edges if r.path else None) for r in runs}) == 1


def test_different_seeds_are_actually_different_runs(goad):
    """Guards the opposite failure — a seed that is threaded but never used
    would make the five-seed reliability claim meaningless."""
    cost = history_cost_fn()
    srcs, tgts = goad.entry_nodes(), goad.target_nodes()
    a = train(goad, srcs[0], tgts, cost, QLearningConfig(episodes=300, seed=0))
    b = train(goad, srcs[0], tgts, cost, QLearningConfig(episodes=300, seed=99))
    assert a.goal_reached_total != b.goal_reached_total


def test_reports_the_exploration_guard(goad):
    """The pre-registered guard needs a number to trip on."""
    cost = history_cost_fn()
    srcs, tgts = goad.entry_nodes(), goad.target_nodes()
    r = train(goad, srcs[0], tgts, cost, FAST)
    assert 0.0 <= r.success_rate_first_5k <= 1.0
    assert r.goal_reached_total >= 0


def test_planner_protocol_wrapper_returns_a_valid_path(goad):
    planner = QLearningPlanner(history_cost_fn(), FAST)
    path = planner.plan(goad, goad.entry_nodes(), goad.target_nodes())
    if path is None:
        pytest.skip("no route learned in the fast config")
    path.validate(goad)
    assert path.planner == "q-learning"


def test_the_observer_cannot_change_the_run(goad):
    """`on_checkpoint` observes; it must not perturb a single byte of the result.

    The reason this is a test rather than a comment: `results/h5_h6.json` is
    cited by sha256 in `docs/findings.md`, so anything that could shift the RNG
    or the update order would silently invalidate a hash the write-up quotes.
    An observer that reads state is safe by inspection, but "safe by inspection"
    is what the two silent bugs above also looked like.
    """
    src = goad.find(name="SOURCE")[0] if goad.find(name="SOURCE") else 0
    targets = goad.tier0_targets()
    cost = history_cost_fn()

    seen: list[tuple[int, float | None]] = []
    quiet = train(goad, src, targets, cost, FAST)
    loud = train(goad, src, targets, cost, FAST,
                 on_checkpoint=lambda ep, c: seen.append((ep, c)))

    assert quiet.checkpoints == loud.checkpoints
    assert quiet.q == loud.q
    assert quiet.q_size == loud.q_size
    assert quiet.converged_at_episode == loud.converged_at_episode
    assert quiet.goal_reached_total == loud.goal_reached_total
    assert quiet.success_rate_first_5k == loud.success_rate_first_5k
    assert (quiet.path is None) == (loud.path is None)
    if quiet.path is not None:
        assert (quiet.path.edges, quiet.path.cost) == (loud.path.edges, loud.path.cost)

    # The observer saw exactly the recorded checkpoints, in order, and nothing else.
    assert seen == quiet.checkpoints


def test_the_observer_is_optional_and_defaults_to_off(goad):
    """Absent `on_checkpoint`, train() behaves as it did before the hook existed."""
    src = goad.find(name="SOURCE")[0] if goad.find(name="SOURCE") else 0
    r = train(goad, src, goad.tier0_targets(), history_cost_fn(), FAST)
    assert len(r.checkpoints) == FAST.episodes // FAST.checkpoint_every
    assert all(isinstance(ep, int) for ep, _ in r.checkpoints)
