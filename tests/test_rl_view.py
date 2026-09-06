"""Pins the RL view's behaviour, including the parts that are refusals.

Live training is affordable here (~0.3-1.5s per run), but the suite is not the
place to spend 13s reproducing all fifteen. Cheap entry points are trained for
real; the expensive assertions are made against the committed artifact, which is
the thing a live run is supposed to agree with anyway.
"""

from __future__ import annotations

import pytest

from dashboard import rl_view as R
from dashboard.compute import ENTRY_POINTS
from stealthpath.graph import AttackGraph
from tests.test_dashboard_numbers import BASE  # same frozen graph, one definition


@pytest.fixture(scope="module")
def base():
    return AttackGraph.load(BASE)


def test_the_reference_is_the_exact_tier1_optimum_and_needs_no_training(base):
    """4.1 / 15.1 / 44.5, matching findings.md and the H1 table.

    Computed before any training by construction — the learner is reported as an
    optimality gap, so the line it must reach cannot be read off its own run.
    """
    costs = {e: R.reference_optimum(base, e) for e in ENTRY_POINTS}
    assert costs["SAMWELL.TARLY@NORTH"]["cost"] == pytest.approx(4.1)
    assert costs["SQL_SVC@NORTH"]["cost"] == pytest.approx(15.1)
    assert costs["TYWIN.LANNISTER@SEVENKINGDOMS"]["cost"] == pytest.approx(44.5)
    assert [costs[e]["hops"] for e in ENTRY_POINTS] == [2, 4, 9]
    assert all(c["reachable"] for c in costs.values())


def test_a_live_run_lands_on_the_reference(base):
    """SAMWELL, seed 0, the full pre-registered 50,000 episodes (~0.3s).

    The +0.00% gap is the Tier 2 result. Asserting it on a live run is the point
    of allowing live training at all: the artifact says 15/15 optimal, and this
    re-derives one of those fifteen rather than reading it back.
    """
    run = R.training_run(base, "SAMWELL.TARLY@NORTH", 0)
    assert run["gap_vs_optimum"] == 0.0
    assert run["matches_optimum"] is True
    assert run["final_cost"] == pytest.approx(4.1)
    assert run["reference"]["cost"] == pytest.approx(4.1)
    assert len(run["trajectory"]) == 50          # 50,000 / checkpoint_every
    assert run["trajectory"][-1]["cost"] == pytest.approx(4.1)
    assert run["episodes_capped"] is False
    assert run["provenance"] == R.LIVE


def test_episodes_to_first_target_is_always_reported(base):
    """TYWIN seed 0 first reaches a target at episode 9,033 (~0.8s to re-derive).

    A reported finding about exploration difficulty, not an embarrassment: the
    guard fires because the first 5,000 episodes reach nothing, and the run
    still converges. See the 2026-09-06 correction entry in findings.md for why
    the per-seed figure matters rather than the rounded 0.0%.
    """
    run = R.training_run(base, "TYWIN.LANNISTER@SEVENKINGDOMS", 0)
    assert run["first_target_episode"] == 9033
    assert run["success_rate_first_5k"] == 0.0
    assert run["converged_at_episode"] == 22_000
    assert run["gap_vs_optimum"] == 0.0

    fast = R.training_run(base, "SAMWELL.TARLY@NORTH", 0)
    assert fast["first_target_episode"] == 3


def test_reproduce_reports_a_derived_count_not_a_claim(base):
    """A subset stands in for the 15-run button; the headline is recomputed.

    Recomputing means a regression shows up as 1/2 rather than as prose that
    still says 15/15.
    """
    out = R.reproduce_all(base, entries=["SAMWELL.TARLY@NORTH"], seeds=[0, 1])
    assert out["headline"] == "2/2 at +0.00%"
    assert out["all_optimal"] is True
    assert out["completed"] == out["total"] == 2
    assert out["budget_failures"] == []
    assert out["first_target_episodes"]["SAMWELL.TARLY@NORTH"] == [3, 0]


def test_a_blown_budget_refuses_rather_than_returning_a_partial_policy(base):
    """The upload guard. q_size 11/84/1076 bounds nothing about a stranger's graph.

    A truncated run that still reported a route would be the worst outcome —
    confident, cheap-looking, and wrong — so exceeding the budget raises.
    """
    with pytest.raises(R.BudgetExceeded) as exc:
        R.training_run(base, "SQL_SVC@NORTH", 0,
                       budget=R.TrainingBudget(max_seconds=0.001))
    assert "use the stored result instead" in str(exc.value)
    assert exc.value.episode > 0


def test_reproduce_records_budget_failures_instead_of_dropping_them(base):
    """A refused run is reported, not silently missing from the denominator."""
    out = R.reproduce_all(base, entries=["SQL_SVC@NORTH"], seeds=[0],
                          budget=R.TrainingBudget(max_seconds=0.001))
    assert out["completed"] == 0
    assert out["total"] == 1
    assert out["all_optimal"] is False
    assert len(out["budget_failures"]) == 1
    assert out["headline"] == "0/1 at +0.00%"


def test_an_episode_cap_is_flagged_because_it_changes_the_epsilon_schedule(base):
    """`_epsilon` derives its decay span from cfg.episodes.

    So a 5,000-episode run is *not* the first 5,000 episodes of a 50,000-episode
    one — it explores on a compressed schedule. Comparing a capped run against
    the stored numbers is invalid, and `episodes_capped` is what says so.
    """
    run = R.training_run(base, "SAMWELL.TARLY@NORTH", 0, episodes=50_000,
                         budget=R.TrainingBudget(max_episodes=5_000))
    assert run["episodes"] == 5_000
    assert run["episodes_requested"] == 50_000
    assert run["episodes_capped"] is True


def test_stored_and_live_are_tagged_and_never_merged(base):
    """A live run corroborates the record; it does not replace it."""
    stored = R.stored_run("TYWIN.LANNISTER@SEVENKINGDOMS")
    assert stored["provenance"] == R.STORED
    assert stored["provenance"] != R.LIVE
    assert stored["graph_sha256"].startswith("3c1bef97f75df7d2")
    assert stored["episodes"] == 50_000
    assert stored["seeds"] == [0, 1, 2, 3, 4]
    assert stored["success_rate_first_5k"] == [0.0, 0.0002, 0.0002, 0.0002, 0.0]
    assert stored["optimum_cost"] == pytest.approx(44.5)

    live = R.training_run(base, "SAMWELL.TARLY@NORTH", 0)
    assert live["provenance"] == R.LIVE
    assert "does not replace" in live["provenance"]


def test_stored_run_refuses_an_unknown_entry():
    with pytest.raises(KeyError, match="no stored result"):
        R.stored_run("ADMINISTRATOR@NORTH")
