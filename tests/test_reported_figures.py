"""Figures quoted in prose, derived from their sources so they cannot drift.

Two different quantities got conflated once already and the stale value
propagated across three documents before anyone noticed:

  **19 dropped edge types** (2,443 edges) - what the *collection* discarded at
  freeze time, recorded by the loader in the graph's own provenance block.
  **14 deferred weights** (21 of 35 sourced) - what the *risk table* has not
  priced yet.

They are unrelated numbers about unrelated things, and prose is where that
distinction dies. Same pattern as the weight snapshot: derive it, assert the
documents agree, and let a failure name the file to edit rather than leaving a
reader to notice a number is out of date.

There is a second trap worth pinning, because an audit fell into it: the
provenance is **split across two files**. `data/collection_provenance.json`
carries the human narrative and only *mentions* `dropped_unknown_edge_types`;
the actual record lives inside `data/goad_graph.json` under `provenance`,
written by `loader_neo4j.py` at freeze time. Neither file says the other exists.
This test reads the authoritative one.
"""

from __future__ import annotations

import json
from pathlib import Path

from stealthpath.risk import PROVISIONAL_WEIGHTS, unsourced

ROOT = Path(__file__).resolve().parent.parent
GRAPH = ROOT / "data" / "goad_graph.json"
DOCS = ROOT / "docs"


def dropped_edge_types() -> dict[str, int]:
    """The authoritative record: the frozen graph's own provenance block."""
    provenance = json.loads(GRAPH.read_text(encoding="utf-8"))["provenance"]
    return provenance["dropped_unknown_edge_types"]


def test_dropped_edge_types_are_read_from_the_graphs_own_provenance():
    dropped = dropped_edge_types()
    assert len(dropped) == 19
    assert sum(dropped.values()) == 2443
    # The two largest are raw ACL variants, not ADCS - worth pinning, because
    # "ADCS dropped" is the shorthand and it understates what was discarded.
    assert dropped["WriteOwnerRaw"] == 1316
    assert dropped["OwnsRaw"] == 722


def test_the_narrative_provenance_file_only_points_at_the_record():
    """Pins the split that misled an audit on 2026-08-10.

    If `dropped_unknown_edge_types` ever becomes a real key in the narrative
    file, this fails and the pointer in `handoff.md` should be revisited.
    """
    narrative = json.loads(
        (ROOT / "data" / "collection_provenance.json").read_text(encoding="utf-8"))
    assert "dropped_unknown_edge_types" not in narrative
    assert "dropped_unknown_edge_types" in json.dumps(narrative), (
        "the narrative file should still mention where the record lives")


def test_deferred_weight_count_is_derived_from_the_risk_table():
    total = len(PROVISIONAL_WEIGHTS)
    missing = unsourced()
    sourced = total - len(missing)
    assert total == 35
    assert sourced == 21
    assert len(missing) == 14


def test_the_two_counts_are_different_quantities():
    """The conflation this file exists to prevent."""
    assert len(dropped_edge_types()) != len(unsourced())
    assert set(dropped_edge_types()) & set(unsourced()) == set(), (
        "a dropped edge type should never also appear as an unsourced weight - "
        "dropped types are not in the weight table at all")


# --------------------------------------------------- the docs must agree

def test_docs_quote_the_derived_figures():
    """Prose is checked against the sources, so a quoted number is guaranteed."""
    n_dropped = len(dropped_edge_types())
    n_edges = sum(dropped_edge_types().values())
    n_deferred = len(unsourced())

    handoff = (DOCS / "handoff.md").read_text(encoding="utf-8")
    assert f"{n_dropped} edge types" in handoff
    assert f"{n_edges:,} edges" in handoff

    stage3 = (DOCS / "stage3_risk_model_properties.md").read_text(encoding="utf-8")
    assert f"Deferred: {n_deferred} weights" in stage3


def test_superseded_figures_are_not_reintroduced():
    """17 was the deferred count before the replication components were sourced.

    Checked across every doc rather than the one that carried it, because the
    original drift was three documents deep.
    """
    for path in sorted(DOCS.glob("*.md")):
        text = path.read_text(encoding="utf-8")
        for stale in ("Deferred: 17 weights", "17 deferred weights"):
            assert stale not in text, f"{path.name} still says {stale!r}"


# ---------------------------------------------- widened sweep, 2026-08-10
#
# A deliberate sweep of every figure appearing in live claim text found the
# 80.4% misuse had survived in `abstract.md` — the document that matters most —
# and was caught by accident during unrelated work. Everything derivable is
# pinned below. The set that cannot be derived is listed in `handoff.md` under
# the decisions log, so the unpinned set is known rather than assumed empty.

from collections import Counter  # noqa: E402

from stealthpath.ad_schema import (  # noqa: E402
    DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES, category_of,
)
from stealthpath.graph import AttackGraph  # noqa: E402
from stealthpath.risk import REPEAT_MULTIPLIER  # noqa: E402

RESULTS = ROOT / "results" / "h5_h6.json"


def _walkable():
    g = AttackGraph.load(GRAPH)
    return g, [e for e in g.edges if e.rel_type in DEFAULT_TRAVERSAL_SET]


def test_concentration_figures_match_the_collection():
    """79.4% modal-weight share, 95.3% acl_abuse, HHI 0.654 and 0.909.

    These are the antecedent of the paper's conditional claim — the numbers a
    reader computes on their own collection to decide whether it applies to
    them — so they are the ones least tolerable as prose.
    """
    g, walk = _walkable()
    n = len(walk)
    assert (len(g.edges), n) == (5825, 4991)

    by_weight = Counter(PROVISIONAL_WEIGHTS[e.rel_type].weight for e in walk)
    modal_weight, modal_n = by_weight.most_common(1)[0]
    assert (modal_weight, modal_n) == (4.0, 3965)
    assert round(modal_n / n * 100, 1) == 79.4

    by_cat = Counter(category_of(e.rel_type) for e in walk)
    assert round(by_cat["acl_abuse"] / n * 100, 1) == 95.3

    assert round(sum((v / n) ** 2 for v in by_weight.values()), 3) == 0.654
    assert round(sum((v / n) ** 2 for v in by_cat.values()), 3) == 0.909


def test_the_superseded_share_is_a_different_measurement():
    """80.4% is five ACL types *including* Owns over all 5,825 edges, and Owns
    derives to 4.5 so it never shared the signature. Both numbers are real;
    pinning both is what stops one being reused for the other."""
    g, _ = _walkable()
    counts = Counter(e.rel_type for e in g.edges)
    five = ["WriteDacl", "WriteOwner", "GenericAll", "Owns", "GenericWrite"]
    assert sum(counts[t] for t in five) == 4686
    assert round(4686 / len(g.edges) * 100, 1) == 80.4
    assert PROVISIONAL_WEIGHTS["Owns"].weight != 4.0


def test_both_state_space_figures_and_their_traversal_sets():
    """400,896 is the pre-registered figure over DEFAULT_TRAVERSAL_SET; 801,792
    is what every reported route actually runs on. Neither replaces the other."""
    g, _ = _walkable()
    c_default = len({category_of(r) for r in DEFAULT_TRAVERSAL_SET})
    c_expanded = len({category_of(r) for r in DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES})
    assert (c_default, c_expanded) == (9, 10)
    assert len(g.nodes) * 2 ** c_default == 400_896
    assert len(g.nodes) * 2 ** c_expanded == 801_792


def test_k_is_the_declared_value():
    assert REPEAT_MULTIPLIER == 1.2


def test_h5_h6_figures_come_from_the_artifact():
    """45,056 / 1,467 / 14, +53.45% and +0.00%, convergence 11k-37k."""
    if not RESULTS.exists():
        import pytest
        pytest.skip("results/h5_h6.json not generated")
    res = json.loads(RESULTS.read_text(encoding="utf-8"))["results"]

    region = res["h6_affected_region"]
    assert region["state_space_size"] == 801_792
    assert region["affected_states"] == 45_056
    assert region["reachable_states"] == 1_467
    assert region["affected_and_reachable"] == 14

    rl = res["h5_rl_no_retraining"]
    gaps = {e.split("@")[0]: sorted({s["perturbed_gap_vs_new_optimum"]
                                     for s in v["seeds"]})
            for e, v in rl.items()}
    assert gaps["SAMWELL.TARLY"] == [0.0]
    assert gaps["SQL_SVC"] == [0.0]
    assert gaps["TYWIN.LANNISTER"] == [0.53448276]

    conv = [s["converged_at_episode"] for v in rl.values() for s in v["seeds"]]
    assert (min(conv), max(conv)) == (11_000, 37_000)
    assert all(s["base_gap_vs_optimum"] == 0.0
               for v in rl.values() for s in v["seeds"])


def test_docs_quote_the_concentration_figures():
    abstract = (DOCS / "abstract.md").read_text(encoding="utf-8")
    for figure in ("79.4%", "95.3%", "0.654", "0.909", "801,792", "400,896"):
        assert figure in abstract, f"abstract.md no longer quotes {figure}"


def test_modal_class_membership_is_five_types_but_four_share_the_signature():
    """The distinction the prose must keep, pinned so it cannot collapse back.

    The *modal-weight* class is five types — what a planner sees, since it reads
    weights and not derivations. The *shared-signature* class is four — what the
    mechanism is actually about. `ForceChangePassword` reaches 4.0 by an
    unrelated route and contributes a single edge, so the two shares differ only
    at the second decimal, which is exactly what makes them easy to conflate.
    """
    _, walk = _walkable()
    n = len(walk)
    counts = Counter(e.rel_type for e in walk)
    modal = {t for t in counts if PROVISIONAL_WEIGHTS[t].weight == 4.0}
    shape_d = {"WriteDacl", "WriteOwner", "GenericAll", "GenericWrite"}

    assert modal == shape_d | {"ForceChangePassword"}
    assert counts["ForceChangePassword"] == 1

    # Same number, different channels: convergence in the output of two
    # derivations, not a shared cause.
    fcp = set(PROVISIONAL_WEIGHTS["ForceChangePassword"].channels)
    for t in shape_d:
        assert set(PROVISIONAL_WEIGHTS[t].channels) != fcp

    assert sum(counts[t] for t in shape_d) == 3964
    assert sum(counts[t] for t in modal) == 3965
    assert round(sum(counts[t] for t in shape_d) / n * 100, 2) == 79.42
    assert round(sum(counts[t] for t in modal) / n * 100, 2) == 79.44
