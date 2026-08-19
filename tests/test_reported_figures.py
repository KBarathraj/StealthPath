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
