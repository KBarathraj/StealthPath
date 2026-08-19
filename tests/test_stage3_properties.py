"""Stage 3 gate — the structural properties, exercised.

Two jobs, and the second is the one that matters:

1. Run every applicable property against the only risk model that currently
   exists (`risk.static_cost_fn`). It should pass all of them.
2. Prove each property actually *fires* — feed it a model that deliberately
   violates it and confirm the violation is caught.

Without (2) a property suite is decoration. A check that cannot fail tells you
nothing when it passes, and every one of these will spend most of its life
passing. The `*_catches_*` tests are the real content here.

Lab-independent and weight-independent: the properties constrain the model's
shape, not its numbers, so they hold for any weight table including the
provisional one.
"""

from __future__ import annotations

import pytest

from stealthpath.risk import (
    REPEAT_MULTIPLIER, history_cost_fn, max_repeat_step, static_cost_fn,
)
from stealthpath.risk_properties import (
    PropertyViolation, check_all, check_p1_repetition_never_reduces_risk,
    check_p2_first_repeat_is_strictly_louder, check_p4_subsequence_monotonicity,
    check_p5_target_sensitivity, check_p6_static_reduction,
    check_p7_static_ignores_history, check_p9_strict_positivity,
    check_p12_relabelling_invariance, check_p13_locality, check_p14_determinism,
    check_p15_bounded_step,
)
from stealthpath.synthetic import goad_like, random_ad


@pytest.fixture
def goad():
    return goad_like()


def test_static_model_satisfies_every_applicable_property(goad):
    ran = check_all(static_cost_fn(), goad, static=static_cost_fn())
    assert len(ran) == 9


def test_p5_is_not_vacuous():
    """A property that makes zero comparisons passes by doing nothing. `goad_like`
    has no walkable edge into Enterprise Admins at all, which is exactly how a
    fixture-driven P5 would have silently tested nothing."""
    assert check_p5_target_sensitivity(static_cost_fn()) > 0


@pytest.mark.parametrize("seed", [0, 1, 2, 7, 42])
def test_properties_hold_across_topologies(seed):
    """One graph passing could be luck. The properties are about the model, so
    they must hold on any graph it is handed."""
    check_all(static_cost_fn(), random_ad(seed=seed))


def test_static_model_is_its_own_static_reduction(goad):
    """P6 against itself — the trivial case, and a guard that the check isn't
    vacuously passing."""
    check_p6_static_reduction(static_cost_fn(), static_cost_fn(), goad)


def test_p4_catches_a_model_where_doing_more_is_cheaper(goad):
    """The failure P4 exists for: a model where padding a route with extra
    actions *lowers* its score, which a cost-minimising planner would find and
    exploit immediately."""
    static = static_cost_fn()

    def rewards_padding(graph, ei, history):
        # a "familiarity discount" — the more you have already done, the quieter
        # the next thing. Exactly backwards, and steep enough to actually invert
        # the ordering rather than merely dent it.
        return static(graph, ei, history) - 2.0 * len(history)

    with pytest.raises(PropertyViolation, match="cannot be quieter"):
        check_p4_subsequence_monotonicity(rewards_padding, goad)


def test_p5_catches_a_model_that_is_cheaper_against_a_bigger_prize(goad):
    static = static_cost_fn()

    def discounts_enterprise_admins(graph, ei, history):
        target = graph.node(graph.edges[ei].target)
        base = static(graph, ei, history)
        return base * 0.5 if "ENTERPRISE ADMINS" in target.name.upper() else base

    with pytest.raises(PropertyViolation, match="scored lower against it"):
        check_p5_target_sensitivity(discounts_enterprise_admins)


def test_target_severity_is_a_partial_order(goad):
    """Incomparable is a real answer, not a gap to be filled."""
    ea = goad.index_of("G-EA-SK")
    da_north, da_sk = goad.index_of("G-DA-NORTH"), goad.index_of("G-DA-SK")
    dom_north = goad.index_of("S-1-5-21-NORTH")

    assert goad.compare_target_severity(ea, da_north) == 1      # forest > domain
    assert goad.compare_target_severity(da_north, ea) == -1
    assert goad.compare_target_severity(da_north, dom_north) == 0   # tied
    assert goad.compare_target_severity(da_north, da_sk) is None    # incomparable
    assert goad.compare_target_severity(dom_north, da_sk) is None
    assert goad.compare_target_severity(goad.index_of("U-SAMWELL"), da_north) is None


def test_p6_catches_a_model_that_is_not_the_same_model(goad):
    """The failure P6 exists for: an adaptive model whose base weights drifted
    from the static one. A 1% offset is invisible in any eyeball check and
    silently poisons every regime comparison."""
    static = static_cost_fn()

    def drifted(graph, ei, history):
        return static(graph, ei, history) * 1.01

    with pytest.raises(PropertyViolation, match="not the same model"):
        check_p6_static_reduction(static, drifted, goad)


def test_p7_catches_history_leaking_into_the_static_regime(goad):
    static = static_cost_fn()

    def leaky(graph, ei, history):
        return static(graph, ei, history) + 0.5 * len(history)

    with pytest.raises(PropertyViolation, match="history-independent"):
        check_p7_static_ignores_history(leaky, goad)


def test_p9_catches_a_free_action(goad):
    static = static_cost_fn()

    def has_a_free_edge(graph, ei, history):
        return 0.0 if graph.edges[ei].rel_type == "MemberOf" else static(graph, ei, history)

    with pytest.raises(PropertyViolation, match="risk > 0"):
        check_p9_strict_positivity(has_a_free_edge, goad)


def test_p12_catches_dependence_on_edge_index(goad):
    """The exact artifact this property was written for: a score that moves
    with collection order rather than with the environment."""
    static = static_cost_fn()

    def index_dependent(graph, ei, history):
        return static(graph, ei, history) + ei * 0.001

    with pytest.raises(PropertyViolation, match="collection order"):
        check_p12_relabelling_invariance(index_dependent, goad)


def test_p13_catches_dependence_on_global_graph_statistics(goad):
    """A model normalised over the whole graph scores differently depending on
    how much of the estate was collected, which is not a property of any
    attacker action."""
    static = static_cost_fn()

    def normalised_over_graph(graph, ei, history):
        return static(graph, ei, history) / len(graph.edges)

    with pytest.raises(PropertyViolation, match="global graph statistics"):
        check_p13_locality(normalised_over_graph, goad)


def test_p14_catches_nondeterminism(goad):
    import random
    static = static_cost_fn()

    def jittery(graph, ei, history):
        return static(graph, ei, history) + random.random()

    with pytest.raises(PropertyViolation, match="across 5 calls"):
        check_p14_determinism(jittery, goad)


BOUND, OBSERVED = max_repeat_step()


def test_history_model_satisfies_every_applicable_property(goad):
    """The full gate against the real adaptive model.

    `cost` is the model with its history term disabled (k=1.0) so P6 and P7 can
    compare it to static; `adaptive` is the live one, which is what P2 and P15
    are handed.
    """
    ran = check_all(history_cost_fn(k=1.0), goad,
                    static=static_cost_fn(),
                    adaptive=history_cost_fn(),
                    max_step=BOUND)
    assert len(ran) == 11


def test_history_model_reduces_exactly_to_static_at_k_one(goad):
    """P6, stated the way it will actually be used. `weight * 1.0` is exact in
    IEEE 754, so this is equality rather than tolerance — which is the point of
    P6, since a tolerance would hide the systematic offset it exists to catch."""
    check_p6_static_reduction(static_cost_fn(), history_cost_fn(k=1.0), goad)


@pytest.mark.parametrize("seed", [0, 1, 2, 7, 42])
def test_history_properties_hold_across_topologies(seed):
    """Same reasoning as the static version — one graph passing could be luck."""
    graph = random_ad(seed=seed)
    check_all(history_cost_fn(k=1.0), graph,
              static=static_cost_fn(),
              adaptive=history_cost_fn(),
              max_step=BOUND)


def test_the_declared_bound_is_not_the_observed_step():
    """Guards a specific way of overstating the model.

    P15 is checked against the weight *ceiling* so it cannot break when an
    unrelated weight is sourced upward. That makes the bound (2.0) roughly twice
    today's actual maximum step (1.3, from `DCSync` at 6.5). Both numbers are
    real and they mean different things; asserting the gap here stops "holds with
    headroom" from being read as a measurement.
    """
    assert BOUND > OBSERVED
    assert OBSERVED == pytest.approx(6.5 * (REPEAT_MULTIPLIER - 1.0))


def test_p1_catches_a_model_where_history_makes_things_cheaper(goad):
    """A "familiarity discount" — the attacker gets quieter the more they do.
    A cost-minimising planner would pad routes to exploit it."""
    static = static_cost_fn()

    def discount_for_experience(graph, ei, history):
        return static(graph, ei, history) / (1.0 + len(history))

    with pytest.raises(PropertyViolation, match="got \\*cheaper\\*"):
        check_p1_repetition_never_reduces_risk(discount_for_experience, goad)


def test_p2_catches_a_model_that_ignores_history(goad):
    """**The static model is the violator here, and that is the point.** P2 is
    the property that separates adaptive from static, so a model that passes it
    while ignoring history would mean the property is measuring nothing."""
    with pytest.raises(PropertyViolation, match="degenerated into the static"):
        check_p2_first_repeat_is_strictly_louder(static_cost_fn(), goad)


def test_p2_catches_a_penalty_that_decays_after_the_first_repeat(goad):
    """The other half of P2 — non-decreasing *after* the first repeat. A model
    that spikes then relaxes would let a planner "wait out" a category, which
    Summary A's one-bit state cannot represent and must not imply."""
    static = static_cost_fn()

    def spikes_then_relaxes(graph, ei, history):
        base = static(graph, ei, history)
        uses = sum(1 for i in history if graph.edges[i].rel_type
                   == graph.edges[ei].rel_type)
        if uses == 0:
            return base
        return base * (1.0 + 1.0 / uses)      # 2x, then 1.5x, then 1.33x...

    with pytest.raises(PropertyViolation, match="non-decreasing"):
        check_p2_first_repeat_is_strictly_louder(spikes_then_relaxes, goad)


def test_p15_catches_a_cliff(goad):
    """The failure P15 exists for, and it is a threat to the project's own
    conclusion rather than to correctness: a steep enough penalty makes the
    adaptive planner beat the static one by avoiding a cliff placed by hand, and
    that looks exactly like a positive result for H3."""
    with pytest.raises(PropertyViolation, match="exceeding the declared bound"):
        check_p15_bounded_step(history_cost_fn(k=5.0), goad, max_step=BOUND)


def test_p15_accepts_the_declared_multiplier(goad):
    """The chosen k must actually clear its own bound — otherwise the bound was
    picked to fit the model rather than the model to fit the bound."""
    check_p15_bounded_step(history_cost_fn(), goad, max_step=BOUND)


@pytest.mark.skip(reason="P3/P4/P8/P10/P11 need a P_detect route scorer — Stage 3")
def test_route_level_properties():
    """Everything that scores a whole route rather than a step. Blocked on the
    combination rule; the current weights are costs, not probabilities."""


@pytest.mark.skip(reason="P5 needs a target severity ordering, which does not exist")
def test_p5_target_sensitivity_monotonicity():
    """`tier0_targets()` returns a set, not a ranking. Defining that ordering is
    Stage 3 work this property depends on."""
