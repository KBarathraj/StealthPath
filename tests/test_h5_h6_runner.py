"""Guards on the H5/H6 experiment runner and its committed artifact.

**The expected numbers live here, not in the runner and not in the artifact.**
That separation is the point: `tools/run_h5_h6.py` derives everything from the
two committed graphs, and this file asserts that what it derives matches what was
independently audited. Putting the expected values in the runner would let it
report them without computing them.

The 50,000-episode RL runs are far too slow for a test suite, so the expensive
part is covered two ways instead: the deterministic non-RL stages are exercised
directly, and the committed `results/h5_h6.json` — produced by a real full run —
is asserted against the audited figures.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph
from tools.run_h5_h6 import (
    BASE_GRAPH, ENTRY_POINTS, PERTURBED_GRAPH, affected_region, classify_entries,
    graph_diff, run_planners, sha256_of,
)

ROOT = Path(__file__).resolve().parent.parent
ARTIFACT = ROOT / "results" / "h5_h6.json"
ALLOWED = set(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)

BASE_SHA = "3c1bef97f75df7d224a1e35767cdb3bdf0cb3348b8dd8bbff0d777f924a65ba2"
PERT_SHA = "7f80e6dc02ba3aed4896a5f201fbccd447dfe893ba6f16de2dd5b99ab88ed172"


@pytest.fixture(scope="module")
def graphs():
    return AttackGraph.load(BASE_GRAPH), AttackGraph.load(PERTURBED_GRAPH)


def test_graph_hashes_match_the_cited_values():
    """Every H5/H6 figure is cited against these two hashes. If they move, the
    results describe a different substrate and must be regenerated."""
    assert sha256_of(BASE_GRAPH) == BASE_SHA
    assert sha256_of(PERTURBED_GRAPH) == PERT_SHA


def test_the_perturbation_is_exactly_two_added_edges(graphs):
    """The pre-registered perturbation: one permission, one membership, nothing
    removed. A third edge appearing here would invalidate the H5/H6 write-up."""
    base, pert = graphs
    diff = graph_diff(base, pert)
    assert diff["removed"] == []
    assert len(diff["added"]) == 2
    assert diff["edges_base"] == 5825
    assert diff["edges_perturbed"] == 5827
    assert diff["nodes_base"] == diff["nodes_perturbed"] == 783

    by_rel = {e["rel_type"]: e for e in diff["added"]}
    assert set(by_rel) == {"GenericAll", "MemberOf"}
    assert by_rel["GenericAll"]["source_name"].startswith("JORAH.MORMONT@ESSOS")
    assert by_rel["GenericAll"]["target_name"].startswith("ROBB.STARK@NORTH")
    assert by_rel["GenericAll"]["category"] == "acl_abuse"
    assert by_rel["MemberOf"]["source_name"].startswith("TYRON.LANNISTER@")
    assert by_rel["MemberOf"]["target_name"].startswith("KINGSGUARD@")
    assert by_rel["MemberOf"]["category"] == "group_membership"


def test_tywin_loses_two_hops_and_the_others_do_not_move(graphs):
    """The headline H5 route change: 9h/39.5 -> 7h/26.6 on TYWIN only."""
    base, pert = graphs
    before, after = run_planners(base, ALLOWED), run_planners(pert, ALLOWED)

    t = "TYWIN.LANNISTER@SEVENKINGDOMS"
    assert before[t]["weighted_astar"]["hops"] == 9
    assert after[t]["weighted_astar"]["hops"] == 7
    assert before[t]["weighted_astar"]["cost_display"] == 39.5
    assert after[t]["weighted_astar"]["cost_display"] == 26.6

    # Plain shortest path moves too, so this is a structural shortcut rather
    # than an artifact of the risk weights.
    assert before[t]["shortest_path"]["hops"] == 9
    assert after[t]["shortest_path"]["hops"] == 7

    for entry in ("SAMWELL.TARLY@NORTH", "SQL_SVC@NORTH"):
        for planner in ("shortest_path", "weighted_astar", "exact_history"):
            assert (before[entry][planner]["route"]
                    == after[entry][planner]["route"]), entry


def test_affected_region_counts_and_that_seeds_are_derived(graphs):
    """H6: 45,056 affected of 801,792, 1,467 reachable, 14 in both.

    Also pins that the reverse-BFS seeds come from the diff rather than from a
    constant — pass the derived sources and they must be the two changed nodes.
    """
    base, pert = graphs
    diff = graph_diff(base, pert)
    seeds = sorted({e["source_index"] for e in diff["added"]})
    assert len(seeds) == 2, "seeds must come from the diff, not a literal"

    region = affected_region(pert, ALLOWED, seeds)
    region.pop("_affected_set")
    region.pop("_reachable_set")

    assert region["state_space_size"] == 801_792
    assert region["categories_in_traversal_set"] == 10
    assert region["reverse_bfs_seed_nodes"] == seeds
    assert region["affected_states"] == 45_056
    assert region["reachable_states"] == 1_467
    assert region["affected_and_reachable"] == 14
    # Not vacuous - the whole point of reporting fractions.
    assert region["affected_fraction_of_state_space"] < 0.10
    assert region["affected_fraction_of_reachable"] < 0.02


def test_the_bound_classifies_all_three_entry_points_correctly(graphs):
    """TYWIN predicted, SAMWELL and SQL_SVC excluded. Nothing falsified."""
    base, pert = graphs
    diff = graph_diff(base, pert)
    seeds = sorted({e["source_index"] for e in diff["added"]})
    region = affected_region(pert, ALLOWED, seeds)
    cls = classify_entries(pert, region["_affected_set"],
                           run_planners(base, ALLOWED), run_planners(pert, ALLOWED))

    assert cls["TYWIN.LANNISTER@SEVENKINGDOMS"]["verdict"] == "correctly_predicted"
    assert cls["SAMWELL.TARLY@NORTH"]["verdict"] == "correctly_excluded"
    assert cls["SQL_SVC@NORTH"]["verdict"] == "correctly_excluded"
    assert all(v["verdict"] != "OUTSIDE_BOUND_FALSIFIED" for v in cls.values())


@pytest.fixture(scope="module")
def artifact():
    if not ARTIFACT.exists():
        pytest.skip("results/h5_h6.json not generated - run tools/run_h5_h6.py")
    return json.loads(ARTIFACT.read_text(encoding="utf-8"))


def test_artifact_records_the_provenance_needed_to_reproduce(artifact):
    assert artifact["graphs"]["base"]["sha256"] == BASE_SHA
    assert artifact["graphs"]["perturbed"]["sha256"] == PERT_SHA
    assert artifact["rl_config"]["seeds"] == [0, 1, 2, 3, 4]
    assert artifact["rl_config"]["episodes"] == 50_000
    assert artifact["rl_config"]["retrained_after_perturbation"] is False
    assert artifact["risk_model"]["repeat_multiplier_k"] == 1.2
    assert artifact["risk_model"]["weights_sourced_count"] == 21
    assert artifact["risk_model"]["weights_unsourced_count"] == 14
    assert artifact["planner_config"]["max_hops"] == 20


def test_artifact_h5_degradation_matches_the_audit(artifact):
    """+53.45% on TYWIN, +0.00% on the two entries the change did not reach,
    on every seed, with retraining off throughout."""
    h5 = artifact["results"]["h5_rl_no_retraining"]
    expected = {
        "SAMWELL.TARLY@NORTH": 0.0,
        "SQL_SVC@NORTH": 0.0,
        "TYWIN.LANNISTER@SEVENKINGDOMS": 0.53448276,
    }
    for entry, want in expected.items():
        rows = h5[entry]["seeds"]
        assert len(rows) == 5, entry
        for row in rows:
            assert row["retrained"] is False
            assert row["base_gap_vs_optimum"] == pytest.approx(0.0, abs=1e-9), entry
            assert row["perturbed_gap_vs_new_optimum"] == pytest.approx(
                want, abs=1e-6), f"{entry} seed {row['seed']}"


def test_artifact_contains_no_hand_written_expected_values(artifact):
    """The artifact must not carry an 'expected' block. If it does, it has
    stopped being a record of what was computed."""
    blob = json.dumps(artifact).lower()
    for banned in ('"expected"', '"claim"', '"asserted"', '"should_be"'):
        assert banned not in blob
