"""Tier 1 — the exact history-aware search, the optimal reference.

The point of this planner is to be *right*, not fast: the learned planner in
Stage 4 gets reported as an optimality gap against it, so an error here silently
rescales every number that follows. These tests are therefore mostly about
agreement with things computed independently — the model's own route scorer, and
the static planner in the regime where the two must coincide.
"""

from __future__ import annotations

import pytest

from stealthpath.ad_schema import (
    DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES, category_of,
)
from stealthpath.planners.exact_history import (
    ExactHistoryPlanner, exact_history_search, state_space_size,
)
from stealthpath.planners.weighted_astar import astar
from stealthpath.risk import history_cost_fn, static_cost_fn
from stealthpath.risk_properties import route_cost
from stealthpath.synthetic import goad_like, random_ad

SEEDS = [0, 1, 2, 7, 17, 42]


@pytest.fixture
def goad():
    return goad_like()


def _endpoints(graph):
    return graph.entry_nodes(), graph.target_nodes()


@pytest.mark.parametrize("seed", SEEDS)
def test_cost_equals_the_models_own_route_cost(seed):
    """**The check that validates the whole state-keyed design.**

    The search keys states on a category *set*, so it synthesises a
    `path_so_far` rather than carrying a real route. That is exact only if the
    model reads nothing else from history. Re-scoring the returned route with
    `route_cost` — which walks the actual edge sequence — is the independent
    confirmation. If the synthesis were wrong these would drift apart and the
    planner would still return a plausible-looking number.
    """
    graph = random_ad(seed=seed)
    srcs, tgts = _endpoints(graph)
    cost = history_cost_fn()
    path = exact_history_search(graph, srcs, tgts, cost)
    if path is None:
        pytest.skip("no route on this graph")
    assert path.cost == pytest.approx(route_cost(cost, graph, path.edges))


@pytest.mark.parametrize("seed", SEEDS)
def test_is_at_least_as_good_as_the_static_planner_under_the_history_model(seed):
    """Optimality, stated as a comparison rather than asserted.

    The static planner minimises the *static* cost, so under the history model
    its route can only be as good as the exact search's or worse. A violation
    means the search is not finding the optimum — which would make every
    optimality gap reported against it meaningless, and in the flattering
    direction.
    """
    graph = random_ad(seed=seed)
    srcs, tgts = _endpoints(graph)
    hist = history_cost_fn()
    exact = exact_history_search(graph, srcs, tgts, hist)
    static_route = astar(graph, srcs, tgts, static_cost_fn())
    if exact is None or static_route is None:
        pytest.skip("no route on this graph")
    assert exact.cost <= route_cost(hist, graph, static_route.edges) + 1e-9


@pytest.mark.parametrize("seed", SEEDS)
def test_reduces_to_the_static_planner_when_history_is_disabled(seed):
    """P6's consequence at the planner level: with k=1.0 the two optimise the
    same objective, so their costs must match. Routes may differ on ties, which
    is why this compares cost and not the edge sequence."""
    graph = random_ad(seed=seed)
    srcs, tgts = _endpoints(graph)
    exact = exact_history_search(graph, srcs, tgts, history_cost_fn(k=1.0))
    static_route = astar(graph, srcs, tgts, static_cost_fn())
    if exact is None or static_route is None:
        pytest.skip("no route on this graph")
    assert exact.cost == pytest.approx(static_route.cost)


def test_is_deterministic(goad):
    srcs, tgts = _endpoints(goad)
    cost = history_cost_fn()
    runs = [exact_history_search(goad, srcs, tgts, cost) for _ in range(5)]
    assert all(r is not None for r in runs)
    assert len({(r.edges, r.nodes, r.cost) for r in runs}) == 1


@pytest.mark.parametrize("seed", SEEDS)
def test_returned_paths_are_well_formed(seed):
    graph = random_ad(seed=seed)
    srcs, tgts = _endpoints(graph)
    path = exact_history_search(graph, srcs, tgts, history_cost_fn())
    if path is None:
        pytest.skip("no route on this graph")
    path.validate(graph)
    assert path.planner == "exact-history"


def test_returns_none_when_target_unreachable(goad):
    assert exact_history_search(goad, goad.entry_nodes(), [], history_cost_fn()) is None


def test_planner_protocol_wrapper_agrees_with_the_function(goad):
    srcs, tgts = _endpoints(goad)
    cost = history_cost_fn()
    direct = exact_history_search(goad, srcs, tgts, cost)
    viaplanner = ExactHistoryPlanner(cost).plan(goad, srcs, tgts)
    assert direct is not None and viaplanner is not None
    assert direct.edges == viaplanner.edges


def test_state_space_matches_the_pre_registered_figure():
    """400,896 = 783 x 2^9, and the 9 is a *consequence of build rule 3*."""
    graph = random_ad(seed=0)
    n = len(graph.nodes)
    cats = {category_of(r) for r in DEFAULT_TRAVERSAL_SET}
    assert len(cats) == 9
    assert state_space_size(graph) == n * 2 ** 9


def test_the_gpo_expansion_view_doubles_the_state_space():
    """**A live coupling between a build rule and a pre-registered number.**

    `with_gpo_expansion()` re-admits `GPLink` and `Contains`, which are the
    `structural` category — so the augmented state space over that view is
    2^10, not 2^9. The pre-registered 400,896 describes `DEFAULT_TRAVERSAL_SET`;
    every route reported for the three documented entry points is computed on
    the expansion view, where it is 801,792.

    Both numbers are right for their own traversal set. Pinned here so the
    difference is impossible to discover by accident later.
    """
    graph = random_ad(seed=0)
    expanded = DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES
    assert len({category_of(r) for r in expanded}) == 10
    assert state_space_size(graph, expanded) == 2 * state_space_size(graph)


def test_the_adaptive_model_can_change_a_route_somewhere():
    """Guards the reporting frame for the headline Tier-1 result.

    No route changes on the frozen graph. That is only a *finding* if the model
    is capable of changing routes at all — otherwise it is a bug wearing a
    finding's clothes. Seed 17 is the existence proof, and it is pinned so the
    claim cannot quietly stop being true.
    """
    graph = random_ad(seed=17)
    srcs, tgts = _endpoints(graph)
    exact = exact_history_search(graph, srcs, tgts, history_cost_fn())
    static_route = astar(graph, srcs, tgts, static_cost_fn())
    assert exact is not None and static_route is not None
    assert exact.rel_types(graph) != static_route.rel_types(graph)
