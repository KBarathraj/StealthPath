"""Pins every number `dashboard/compute.py` returns, for both frozen graphs.

Same convention as `test_reported_figures.py`: the expected values come from
`docs/findings.md`, and **a disagreement is a bug in the code, not in the test**.
The dashboard's whole claim to be trustworthy is that it displays the numbers
the paper reports; a dashboard that computes something findings.md does not say
is worse than no dashboard, because it looks authoritative while disagreeing
with the write-up.

Values are rounded here rather than in `compute.py`, matching how
`test_reported_figures.py` treats the same figures — the measurement is the
unrounded quantity and 79.4% is its presentation.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from dashboard import compute as C
from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph
from stealthpath.planners.shortest_path import dijkstra

ROOT = Path(__file__).resolve().parent.parent
BASE = ROOT / "data" / "goad_graph.json"
PERTURBED = ROOT / "data" / "goad_graph_perturbed.json"
RESULTS = ROOT / "results" / "h5_h6.json"


@pytest.fixture(scope="module")
def base():
    return AttackGraph.load(BASE)


@pytest.fixture(scope="module")
def perturbed():
    return AttackGraph.load(PERTURBED)


@pytest.fixture(scope="module")
def stored():
    return json.loads(RESULTS.read_text(encoding="utf-8"))


# --------------------------------------------------------------------------
# graph_profile — the four antecedent statistics
# --------------------------------------------------------------------------

def test_profile_matches_the_collapse_figures_on_the_base_graph(base):
    """findings.md:282 (79.4%, 3,965/4,991), :288 (0.654, 95.3%), :289 (0.909).

    These four are the antecedent of the paper's conditional. If the dashboard
    disagrees with findings.md here it is contradicting the claim it exists to
    illustrate.
    """
    p = C.graph_profile(base)
    assert (p["edges_total"], p["edges_walkable"]) == (5825, 4991)
    assert (p["modal_weight"], p["modal_weight_edges"]) == (4.0, 3965)
    assert round(p["modal_weight_share"] * 100, 1) == 79.4
    assert round(p["hhi_weights"], 3) == 0.654
    assert round(p["hhi_categories"], 3) == 0.909
    assert p["acl_abuse_edges"] == 4754
    assert round(p["acl_abuse_share"] * 100, 1) == 95.3
    assert p["nodes"] == 783


def test_profile_on_the_perturbed_graph_moves_only_where_the_diff_did(perturbed, stored):
    """+2 edges, one acl_abuse and one group_membership (h5_h6.json graph_diff).

    The share drops 95.3 -> 95.2 because the second added edge is `MemberOf`,
    not an ACL. Pinned so the perturbed graph is not quietly assumed to carry
    the base graph's figures — the two are cited by different hashes and a
    dashboard showing one graph's concentration for the other is exactly the
    "right number, wrong quantity" error findings.md:270 records.
    """
    p = C.graph_profile(perturbed)
    assert (p["edges_total"], p["edges_walkable"]) == (5827, 4993)
    assert (p["modal_weight"], p["modal_weight_edges"]) == (4.0, 3966)
    assert round(p["modal_weight_share"] * 100, 1) == 79.4
    assert round(p["hhi_weights"], 3) == 0.654
    assert round(p["hhi_categories"], 3) == 0.909
    assert p["acl_abuse_edges"] == 4755
    assert round(p["acl_abuse_share"] * 100, 1) == 95.2

    added = stored["graph_diff"]["added"]
    assert [a["category"] for a in added] == ["acl_abuse", "group_membership"]
    assert stored["graph_diff"]["edges_perturbed"] - stored["graph_diff"]["edges_base"] == 2


def test_dropped_types_are_pinned_and_absence_is_not_reported_as_zero(base, perturbed):
    """19 types / 2,443 edges on the base graph; *unrecorded* on the perturbed one.

    The second half is the point. The perturbed copy carries empty provenance,
    so "0 dropped types" would be a fabricated clean bill of health. `recorded`
    must distinguish the two, for the same reason `RiskWeight.channels` has
    NONE_FOUND values.
    """
    d = C.graph_profile(base)["dropped_edge_types"]
    assert d["recorded"] is True
    assert d["type_count"] == 19
    assert d["edge_count"] == 2443
    assert d["types"]["WriteOwnerRaw"] == 1316
    assert d["types"]["OwnsRaw"] == 722

    d2 = C.graph_profile(perturbed)["dropped_edge_types"]
    assert d2["recorded"] is False
    assert d2["types"] == {}
    assert d2["type_count"] == 0


def test_the_superseded_share_is_not_what_the_profile_reports(base):
    """80.4% is a different measurement and must not surface as the collapse figure.

    findings.md:270-282. `Owns` derives to 4.5 and never shared the signature,
    so a profile reporting 80.4 would be quoting the right number for the wrong
    quantity — the specific error that entry exists to record.
    """
    p = C.graph_profile(base)
    assert round(p["modal_weight_share"] * 100, 1) != 80.4
    assert p["weight_distribution"][4.0] == 3965
    assert 4.5 in p["weight_distribution"]


# --------------------------------------------------------------------------
# coverage — per edge and, crucially, per route
# --------------------------------------------------------------------------

def test_graph_level_coverage(base):
    """21 of 35 weights sourced (test_reported_figures.py:69-71).

    The four unpriced types have no RiskWeight at all, which is a different
    state from provisional: `weight_of` raises on them rather than guessing.
    None of them is walkable, so no route can reach one.
    """
    cov = C.coverage(base)
    assert (cov["weights_sourced"], cov["weights_total"]) == (21, 35)
    assert cov["all_edges"]["total"] == 5825
    assert cov["all_edges"]["unpriced"] == 76
    assert cov["walkable_edges"] == {
        "total": 4991, "sourced": 4200, "provisional": 791, "unpriced": 0,
        "sourced_share": 4200 / 4991,
    }
    unpriced = sorted(t for t, v in cov["by_edge_type"].items()
                      if v["status"] == "unpriced")
    assert unpriced == ["CrossForestTrust", "LocalToComputer",
                        "MemberOfLocalGroup", "SameForestTrust"]
    assert all(not cov["by_edge_type"][t]["walkable"] for t in unpriced)


def test_every_reported_route_is_fully_sourced_though_the_graph_is_not(base):
    """The reason per-route coverage is reported separately from per-edge.

    The graph is 84.2% sourced across walkable edges, but all nine reported
    routes are 100% sourced. That is not luck: CLAUDE.md defers 14 weights on
    the stated grounds that they "sit on no observed route", and this is the
    check that the claim still holds. If a deferred weight ever lands on a
    reported route, this fails and the deferral has to be revisited.
    """
    cov = C.coverage(base)
    for entry, planners in cov["routes"].items():
        for planner, route in planners.items():
            assert route["fully_sourced"], (
                f"{entry}/{planner} traverses a non-sourced edge: "
                f"{[h for h in route['per_hop'] if h['status'] != 'sourced']}")
            assert route["provisional"] == 0 and route["unpriced"] == 0

    assert round(cov["walkable_edges"]["sourced_share"] * 100, 1) == 84.2
    assert [cov["routes"][e]["exact_history"]["hops"] for e in C.ENTRY_POINTS] == [2, 4, 9]


def test_route_coverage_is_reported_per_planner_not_once_per_entry(base):
    """SQL_SVC is the entry where the planners disagree (weight_snapshot.json).

    Plain and weighted take different routes there, so their pricing provenance
    is separately derived even though both come out fully sourced here.
    """
    routes = C.coverage(base)["routes"]["SQL_SVC@NORTH"]
    plain = [h["rel_type"] for h in routes["shortest_path"]["per_hop"]]
    weighted = [h["rel_type"] for h in routes["weighted_astar"]["per_hop"]]
    assert plain == ["SQLAdmin", "HasSession", "AdminTo", "DCSync"]
    assert weighted == ["SQLAdmin", "HasSession", "MemberOf", "GenericWrite"]
    assert plain != weighted


# --------------------------------------------------------------------------
# structural_absences
# --------------------------------------------------------------------------

def test_structural_absences_on_both_graphs(base, perturbed):
    """5 HasSession, 0 delegation, AD CS present as nodes but absent as edges.

    handoff.md's "three structural holes". The AD CS shape is the subtle one:
    79 certificate objects were collected, so the absence is a modelling
    decision rather than a gap in the data, and a dashboard that showed only
    "ADCS: absent" would misattribute it to the collection.
    """
    for g in (base, perturbed):
        a = C.structural_absences(g)
        assert a["session_edges"] == 5
        assert a["delegation_edges"] == 0
        assert a["adcs"]["nodes_present"] == 79
        assert a["adcs"]["edges_modelled"] == 0
        assert a["adcs"]["node_kinds"] == {
            "AIACA": 2, "CertTemplate": 71, "EnterpriseCA": 2,
            "NTAuthStore": 2, "RootCA": 2,
        }

    assert C.structural_absences(base)["adcs"]["provenance_recorded"] is True
    assert C.structural_absences(perturbed)["adcs"]["provenance_recorded"] is False


def test_the_adcs_share_of_the_dropped_edges_partitions_the_documented_total(base):
    """289 of the 2,443 dropped edges are certificate abuse, across 14 of 19 types.

    **289 is not a findings.md figure** — findings.md and handoff.md pin only the
    totals (19 types, 2,443 edges). It is asserted here as an exact partition of
    those two rather than as a constant of its own, so it stays anchored to a
    number the write-up does pin: if the AD CS filter ever drifts, the remainder
    stops summing and this fails rather than silently reporting a new figure the
    paper has never seen.
    """
    dropped = C.graph_profile(base)["dropped_edge_types"]
    adcs = C.structural_absences(base)["adcs"]
    rest = {t: c for t, c in dropped["types"].items()
            if t not in adcs["dropped_edge_types"]}

    assert (dropped["type_count"], dropped["edge_count"]) == (19, 2443)
    assert (len(adcs["dropped_edge_types"]), adcs["dropped_edges"]) == (14, 289)
    assert len(rest) + len(adcs["dropped_edge_types"]) == dropped["type_count"]
    assert sum(rest.values()) + adcs["dropped_edges"] == dropped["edge_count"]
    # The five that remain are ACL and directory noise, not certificate abuse.
    assert sorted(rest) == ["AllExtendedRights", "ClaimSpecialIdentity", "DCFor",
                            "OwnsRaw", "WriteOwnerRaw"]


# --------------------------------------------------------------------------
# compare_entry_point — against findings.md and the committed artifact
# --------------------------------------------------------------------------

BASE_ROUTES = {
    # entry: (hops, plain cost, weighted cost, history cost, static risk plain/weighted)
    "SAMWELL.TARLY@NORTH": (2, 2.0, 4.1, 4.1, 4.1, 4.1),
    "SQL_SVC@NORTH": (4, 4.0, 15.1, 15.1, 20.0, 15.1),
    "TYWIN.LANNISTER@SEVENKINGDOMS": (9, 9.0, 39.5, 44.5, 39.5, 39.5),
}


@pytest.mark.parametrize("entry", list(BASE_ROUTES))
def test_compare_entry_point_matches_the_h1_table(base, entry):
    """findings.md:74-77 — hops identical across planners, static risk 4.10 /
    20.00 vs 15.10 / 39.50.

    The hop column is the H1 result: the weighted planner never pays an extra
    hop for quiet. If a dashboard ever shows differing hop counts here, H1's
    reported failure is wrong.
    """
    hops, plain, weighted, history, sr_plain, sr_weighted = BASE_ROUTES[entry]
    r = C.compare_entry_point(base, entry)

    assert r["shortest_path"]["hops"] == hops
    assert r["weighted_astar"]["hops"] == hops
    assert r["exact_history"]["hops"] == hops

    assert r["shortest_path"]["cost"] == pytest.approx(plain)
    assert r["weighted_astar"]["cost"] == pytest.approx(weighted)
    assert r["exact_history"]["cost"] == pytest.approx(history)

    assert r["shortest_path"]["static_risk"] == pytest.approx(sr_plain)
    assert r["weighted_astar"]["static_risk"] == pytest.approx(sr_weighted)


def test_tywin_is_the_only_entry_where_history_costs_more_than_static(base):
    """44.5 history vs 39.5 static — the repeat penalty firing on one entry.

    Two different scales that must never be shown as one column. The H1 table
    reports 39.50 for TYWIN (static risk); h5_h6.json reports 44.5 (history
    cost). Both are correct for their own cost model.
    """
    costs = {e: C.compare_entry_point(base, e) for e in C.ENTRY_POINTS}
    differs = [e for e, r in costs.items()
               if r["exact_history"]["cost"] != r["weighted_astar"]["cost"]]
    assert differs == ["TYWIN.LANNISTER@SEVENKINGDOMS"]
    assert costs["TYWIN.LANNISTER@SEVENKINGDOMS"]["exact_history"]["cost"] == pytest.approx(44.5)
    assert costs["TYWIN.LANNISTER@SEVENKINGDOMS"]["weighted_astar"]["static_risk"] == pytest.approx(39.5)


def test_compare_entry_point_reproduces_the_committed_artifact(base, perturbed, stored):
    """Field-for-field against results/h5_h6.json, for both graphs.

    The strongest available check: the artifact was produced by
    tools/run_h5_h6.py, so agreement here means the dashboard and the runner
    derive routes identically rather than merely landing on the same cost.
    """
    for graph, key in ((base, "planners_base"), (perturbed, "planners_perturbed")):
        for entry in C.ENTRY_POINTS:
            got = C.compare_entry_point(graph, entry)
            want = stored["results"][key][entry]
            for planner in ("shortest_path", "weighted_astar", "exact_history"):
                assert got[planner]["route"] == want[planner]["route"], (entry, planner)
                assert got[planner]["hops"] == want[planner]["hops"]
                assert got[planner]["cost"] == pytest.approx(want[planner]["cost"])
                assert got[planner]["categories"] == want[planner]["categories"]
                assert got[planner]["node_names"] == want[planner]["node_names"]


def test_the_perturbation_shortens_tywin_and_leaves_the_others_alone(base, perturbed):
    """9 hops -> 7, 44.5 -> 29.0. The other two entries do not move.

    This is H6's "3 of 3 entry points predicted correctly" seen from the route
    side rather than the reverse-BFS side.
    """
    for entry in ("SAMWELL.TARLY@NORTH", "SQL_SVC@NORTH"):
        b = C.compare_entry_point(base, entry)["exact_history"]
        p = C.compare_entry_point(perturbed, entry)["exact_history"]
        assert (b["hops"], b["route"]) == (p["hops"], p["route"])
        assert b["cost"] == pytest.approx(p["cost"])

    b = C.compare_entry_point(base, "TYWIN.LANNISTER@SEVENKINGDOMS")["exact_history"]
    p = C.compare_entry_point(perturbed, "TYWIN.LANNISTER@SEVENKINGDOMS")["exact_history"]
    assert (b["hops"], p["hops"]) == (9, 7)
    assert b["cost"] == pytest.approx(44.5)
    assert p["cost"] == pytest.approx(29.0)


def test_the_gpo_expansion_view_is_not_optional(base):
    """SAMWELL's two-hop route traverses GPLink, which the default set excludes.

    Pinned because it is the quiet failure mode for a reimplementation: running
    DEFAULT_TRAVERSAL_SET alone still returns *a* route and still looks correct.
    """
    r = C.compare_entry_point(base, "SAMWELL.TARLY@NORTH")
    assert r["exact_history"]["route"] == ["WriteOwner", "GPLink"]

    # Build rule 3: GPLink is directory structure, excluded from the default set
    # and re-admitted only by the GPO-expansion view.
    assert "GPLink" not in DEFAULT_TRAVERSAL_SET
    assert "GPLink" in GPO_EXPANSION_EDGES

    # Demonstrate the failure rather than asserting it abstractly: the same
    # query over the default set returns a *different* route, not an error.
    view = base.with_gpo_expansion()
    narrow = dijkstra(view, view.find(name="SAMWELL.TARLY@NORTH"),
                      sorted(view.tier0_targets()),
                      allowed_rel_types=frozenset(DEFAULT_TRAVERSAL_SET),
                      max_hops=C.MAX_HOPS)
    assert narrow is None or narrow.rel_types(view) != ["WriteOwner", "GPLink"]


# --------------------------------------------------------------------------
# qlearning_result — stored only, never trained
# --------------------------------------------------------------------------

def test_qlearning_numbers_match_findings(stored):
    """+0.00% on two entries, +53.45% on TYWIN; convergence 11k-37k.

    findings.md's H5 result. `gaps_vs_optimum` for the perturbed graph is the
    degradation figure quoted as +53.45%.
    """
    gaps = {e: C.qlearning_result("perturbed", e)["gaps_vs_optimum"]
            for e in C.ENTRY_POINTS}
    assert gaps["SAMWELL.TARLY@NORTH"] == [0.0] * 5
    assert gaps["SQL_SVC@NORTH"] == [0.0] * 5
    assert gaps["TYWIN.LANNISTER@SEVENKINGDOMS"] == [0.53448276] * 5

    for e in C.ENTRY_POINTS:
        assert C.qlearning_result("base", e)["gaps_vs_optimum"] == [0.0] * 5

    conv = [c for e in C.ENTRY_POINTS
            for c in C.qlearning_result("base", e)["converged_at_episode"]]
    assert (min(conv), max(conv)) == (11_000, 37_000)
    assert len(conv) == 15


def test_the_perturbed_result_is_labelled_a_replay_not_a_training_run():
    """Every seed is trained_on=base, retrained=false — including 'perturbed'.

    There is no independently trained perturbed policy anywhere in the artifact.
    A dashboard tab presenting this as "Q-learning on the perturbed graph" would
    be describing a replay as a training run, so the labelling is pinned rather
    than left to the presentation layer.
    """
    r = C.qlearning_result("perturbed", "TYWIN.LANNISTER@SEVENKINGDOMS")
    assert r["trained_on"] == "base"
    assert r["evaluated_on"] == "perturbed"
    assert r["retrained"] is False
    assert r["is_replay"] is True

    b = C.qlearning_result("base", "TYWIN.LANNISTER@SEVENKINGDOMS")
    assert b["is_replay"] is False
    # Same replayed policy, scored against two different optima: that is the
    # whole of H5. 44.5 was optimal on the base graph and is 53.45% over on the
    # perturbed one, without the policy changing at all.
    assert b["policy_costs"] == r["policy_costs"]
    assert b["optimum_cost"] != r["optimum_cost"]


def test_qlearning_result_cites_both_graph_hashes():
    """Every number carries its graph, per findings.md's opening rule."""
    r = C.qlearning_result("base", "SAMWELL.TARLY@NORTH")
    assert r["graphs"]["base"]["sha256"].startswith("3c1bef97f75df7d2")
    assert r["graphs"]["perturbed"]["sha256"].startswith("7f80e6dc02ba3aed")


def test_qlearning_result_refuses_unknown_inputs_rather_than_defaulting():
    """Build rule 4's habit applied to the dashboard boundary."""
    with pytest.raises(ValueError, match="expected 'base' or 'perturbed'"):
        C.qlearning_result("live", "SAMWELL.TARLY@NORTH")
    with pytest.raises(KeyError, match="no stored Q-learning result"):
        C.qlearning_result("base", "ADMINISTRATOR@NORTH")
