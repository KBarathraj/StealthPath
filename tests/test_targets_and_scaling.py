"""Target derivation, the approximating learner, and the upload ladder.

Three properties carry the weight here:

- the generalised target set must return exactly what `tier0_targets()` returns
  on the frozen graph, or every route, gap and figure in `docs/findings.md` is
  measured against a different destination;
- the learner must reach the exact optimum on graphs far larger than the
  reference collection, because that is the whole reason it exists and the
  previous handcrafted-feature version silently did not;
- the learner and the exact search must be given the **same** start set, or the
  gap between them compares two different problems.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from dashboard.rl_upload import EXACT, LEARNED, REFUSED, UploadPlan, plan_upload
from dashboard.rl_view import TrainingBudget
from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph
from stealthpath.planners.exact_history import exact_history_search
from stealthpath.planners.linear_q import (
    ApproxQConfig, state_space_fits_table, train_approx,
)
from stealthpath.risk import history_cost_fn
from stealthpath.synthetic import random_ad
from stealthpath.targets import derive_sources, derive_targets, target_indices

ROOT = Path(__file__).resolve().parent.parent
FROZEN = ROOT / "data" / "goad_graph.json"
ALLOWED = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)

pytestmark = pytest.mark.skipif(not FROZEN.exists(),
                                reason="frozen graph is not present")


@pytest.fixture(scope="module")
def graph():
    return AttackGraph.load(FROZEN)


@pytest.fixture(scope="module")
def view(graph):
    return graph.with_gpo_expansion()


# --------------------------------------------------------------------------
# target derivation
# --------------------------------------------------------------------------

def test_derived_targets_match_tier0_on_the_frozen_graph(graph):
    """Generalising the target set must not move a published number.

    `tier0_targets()` matches the string `DOMAIN ADMINS`; the derivation keys on
    RID 512. They agree here, which is what makes it safe to swap one for the
    other in the dashboard -- and this test is what will notice if they stop.
    """
    assert target_indices(graph) == graph.tier0_targets()


def test_derivation_survives_a_renamed_domain_admins_group(graph):
    """The failure the derivation exists for.

    Rename the group -- a non-English install, or a directory that simply calls
    it something else -- and the name-matching target set loses it. The RID does
    not change.
    """
    renamed = AttackGraph(list(graph.nodes), list(graph.edges))
    hit = next(i for i, n in enumerate(renamed.nodes)
               if n.name.startswith("DOMAIN ADMINS@NORTH"))
    original = renamed.nodes[hit]
    renamed.nodes[hit] = type(original)(**{**original.__dict__,
                                           "name": "DOMÄNEN-ADMINS@NORTH"})

    assert hit not in renamed.tier0_targets()
    assert hit in target_indices(renamed)
    reason = next(c.reason for c in derive_targets(renamed) if c.index == hit)
    assert "512" in reason


def test_domain_controllers_stay_opt_in(graph):
    """Documented as belonging in the target set, and still off by default.

    Turning them on adds three targets to the reference graph, and every route
    in findings.md is measured without them. The blocker was that nothing marked
    a DC; `props.isdc` now does, so this is a decision rather than a limitation.
    """
    assert len(target_indices(graph, include_domain_controllers=True)) \
        == len(target_indices(graph)) + 3


def test_derived_sources_prefer_a_session_over_an_arbitrary_account(graph):
    """A start nobody would pick makes the default useless on an upload."""
    session_holders = [c for c in derive_sources(graph)
                       if c.confidence == "structure"]
    assert session_holders
    assert all("session" in c.reason for c in session_holders)


# --------------------------------------------------------------------------
# the approximating learner
# --------------------------------------------------------------------------

@pytest.mark.parametrize("entry", ["SAMWELL.TARLY@NORTH",
                                   "TYWIN.LANNISTER@SEVENKINGDOMS"])
def test_the_learner_reaches_the_exact_optimum_on_the_reference_graph(view, entry):
    sources = [i for i, n in enumerate(view.nodes) if n.name.startswith(entry)]
    targets = target_indices(view)
    optimum = exact_history_search(view, sources, targets, history_cost_fn(),
                                   ALLOWED, 20)
    result = train_approx(view, sources[0], targets, history_cost_fn(),
                          ApproxQConfig(), ALLOWED)
    assert result.path is not None
    assert result.path.cost == pytest.approx(optimum.cost)


def test_the_learner_reaches_the_optimum_on_a_graph_far_larger_than_the_reference():
    """The regression that matters, and the one the reference graph cannot catch.

    The previous handcrafted-feature learner hit the optimum on all three
    reference entry points and was **+32% to +80% on random directories of
    2,900-8,200 nodes**, without improving as episodes rose -- a global weight
    per named feature cannot say "take MemberOf here but not there". Only a
    graph with real branching exposes it, so one is built here rather than
    trusting the 783-node collection to stand in for a directory.
    """
    graph = random_ad(n_users=2000, n_computers=600, n_groups=300, seed=1)
    targets = target_indices(graph)
    assert len(graph.nodes) > 2_500

    for source in graph.entry_nodes():
        optimum = exact_history_search(graph, [source], targets,
                                       history_cost_fn(), ALLOWED, 20)
        if optimum is None:
            continue
        result = train_approx(graph, source, targets, history_cost_fn(),
                              ApproxQConfig(), ALLOWED)
        assert result.path is not None, f"no route learned from {source}"
        assert result.path.cost == pytest.approx(optimum.cost), (
            f"learner is {(result.path.cost - optimum.cost) / optimum.cost:+.1%} "
            f"off the optimum from node {source}")


def test_memory_is_bounded_by_buckets_not_by_state_count(view):
    """The property that makes this usable on a directory of any size.

    The tabular learner allocates per reachable state and has no ceiling. This
    one never exceeds its bucket count however much of the graph it visits.
    """
    sources = [i for i, n in enumerate(view.nodes)
               if n.name.startswith("SQL_SVC@NORTH")]
    cfg = ApproxQConfig(episodes=3_000, buckets=1 << 12)
    result = train_approx(view, sources[0], target_indices(view),
                          history_cost_fn(), cfg, ALLOWED)
    report = result.collision_report()
    assert report["buckets"] == 1 << 12
    assert report["touched"] <= report["buckets"]
    assert 0.0 <= report["load_factor"] <= 1.0


def test_a_non_power_of_two_bucket_count_is_refused():
    """The index is masked, not taken modulo, so anything else is non-uniform."""
    with pytest.raises(ValueError, match="power of two"):
        ApproxQConfig(buckets=1000)


def test_every_learned_route_is_labelled_unverified(view):
    """The label travels with the route, not with the caller's memory of it."""
    sources = [i for i, n in enumerate(view.nodes)
               if n.name.startswith("SAMWELL.TARLY@NORTH")]
    result = train_approx(view, sources[0], target_indices(view),
                          history_cost_fn(), ApproxQConfig(episodes=2_000),
                          ALLOWED)
    assert result.verified is False
    assert result.path.meta["verified"] is False
    assert "unverified" in result.path.planner


def test_the_learner_is_seeded_and_reproducible(view):
    """Determinism is a build rule, and hashing is where it usually breaks.

    The bucket for a state-action comes from `_mix`, written out in the module
    rather than from `hash()`, precisely so `PYTHONHASHSEED` cannot move it.
    """
    sources = [i for i, n in enumerate(view.nodes)
               if n.name.startswith("SAMWELL.TARLY@NORTH")]
    targets = target_indices(view)
    runs = [train_approx(view, sources[0], targets, history_cost_fn(),
                         ApproxQConfig(episodes=1_500, seed=3), ALLOWED)
            for _ in range(2)]
    assert runs[0].weights_digest() == runs[1].weights_digest()
    assert runs[0].path.edges == runs[1].path.edges


def test_the_observer_cannot_change_the_run(view):
    """Same contract as the tabular learner's: an observer must not perturb the
    RNG or the result, because the budget watchdog rides on it."""
    sources = [i for i, n in enumerate(view.nodes)
               if n.name.startswith("SAMWELL.TARLY@NORTH")]
    targets = target_indices(view)
    cfg = ApproxQConfig(episodes=2_000, seed=1)
    seen: list[tuple[int, float | None]] = []
    plain = train_approx(view, sources[0], targets, history_cost_fn(), cfg, ALLOWED)
    watched = train_approx(view, sources[0], targets, history_cost_fn(), cfg,
                           ALLOWED, on_checkpoint=lambda e, c: seen.append((e, c)))
    assert seen, "the observer was never called"
    assert plain.weights_digest() == watched.weights_digest()
    assert plain.path.edges == watched.path.edges


def test_the_frozen_graph_still_fits_the_table(view):
    """`state_space_fits_table` answers a memory question, not a routing one.

    It is no longer used to pick a planner -- it called a 10,902-node graph too
    big while the exact search answered it in under a second. Kept because the
    tabular learner's applicability is still a real fact worth asserting.
    """
    assert state_space_fits_table(view, ALLOWED)


# --------------------------------------------------------------------------
# the upload ladder
# --------------------------------------------------------------------------

def test_the_ladder_reports_the_exact_route_and_checks_it_against_the_learner(view):
    sources = [i for i, n in enumerate(view.nodes)
               if n.name.startswith("SQL_SVC@NORTH")]
    plan = plan_upload(view, sources, target_indices(view),
                       TrainingBudget(max_seconds=120))
    assert plan.tier == EXACT
    assert plan.verified
    assert plan.cost == pytest.approx(15.1)
    assert plan.learned is not None
    assert plan.learned.matches_exact
    assert plan.learned.gap_vs_exact == pytest.approx(0.0)


def test_the_learner_is_trained_from_every_start_the_exact_search_used():
    """The bug this exists for: exact over all sources, learner on sources[0].

    The gap then compares two different problems. It read as a badly broken
    learner -- +43% on a random directory -- when the learner had found the exact
    optimum from the node it was given and was being judged against a different
    start's optimum. Invisible on the frozen graph, where every documented entry
    name resolves to exactly one node.
    """
    graph = random_ad(n_users=2000, n_computers=600, n_groups=300, seed=1)
    sources = graph.entry_nodes()
    assert len(sources) > 1, "this test needs a start set with more than one node"

    per_source = [exact_history_search(graph, [s], target_indices(graph),
                                       history_cost_fn(), ALLOWED, 20)
                  for s in sources]
    costs = {p.cost for p in per_source if p is not None}
    assert len(costs) > 1, "the sources must not all have the same optimum"

    plan = plan_upload(graph, sources, target_indices(graph),
                       TrainingBudget(max_seconds=120))
    assert plan.learned is not None
    assert plan.learned.matches_exact, (
        f"learner {plan.learned.cost} vs exact {plan.cost}: the two were given "
        f"different start sets")


def test_no_targets_is_a_refusal_with_a_reason(view):
    """An empty target set must not read as "no route exists"."""
    plan = plan_upload(view, [0], [], TrainingBudget(max_seconds=5))
    assert plan.tier == REFUSED
    assert not plan.found_route
    assert any("target" in n for n in plan.notes)


def test_an_unreachable_target_is_refused_without_blaming_the_budget(view):
    """A start with no route must say so, not imply it ran out of time."""
    isolated = next(i for i, n in enumerate(view.nodes)
                    if not view.out_edge_indices(i))
    plan = plan_upload(view, [isolated], target_indices(view),
                       TrainingBudget(max_seconds=30))
    assert plan.tier == REFUSED
    assert any("no route exists" in n for n in plan.notes)


def test_an_exhausted_budget_never_returns_a_partial_policy(view):
    """A capped run explores on a compressed schedule, so it is not a prefix of
    a finished one. The floor is a refusal, never a truncated route shown as the
    learned one."""
    sources = [i for i, n in enumerate(view.nodes)
               if n.name.startswith("TYWIN.LANNISTER@SEVENKINGDOMS")]
    plan = plan_upload(view, sources, target_indices(view),
                       TrainingBudget(max_seconds=0.0))
    assert plan.tier == REFUSED
    assert plan.cost is None
    assert plan.notes


def test_a_learned_tier_never_claims_to_be_verified():
    plan = UploadPlan(tier=LEARNED, verified=False, cost=3.0, hops=2,
                      route=["MemberOf", "GenericAll"], node_names=["a", "b", "c"])
    assert not plan.verified
    assert "not" in plan.verdict().lower()
