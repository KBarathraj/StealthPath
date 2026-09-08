"""Proof that the parser validator can fail.

A validator that has never failed is not known to work. Every test below feeds
the harness a *deliberately wrong* parse and asserts it is caught, by name —
because the point of the harness is not a pass/fail bit, it is saying which
relationship type is wrong.

The four corruptions are the four plausible ways to get this component wrong:

1. **A swapped mapping.** `WriteDacl` <-> `GenericAll`. Counts per type stay in
   the same ballpark and every route still resolves; only the prices change.
2. **The intuitive DCSync rule.** `GetChanges AND GetChangesAll` looks correct,
   is what the ACE data supports, and produces three of six edges — *none* of
   them the ones the reported routes traverse. This is the most important test
   here: it is not a typo, it is the implementation a careful person writes.
3. **A naive ACE reader.** CE emits both `WriteOwnerRaw` and `WriteOwner` (and
   `OwnsRaw`/`Owns`) for the same ACEs. Emitting both doubles the ACL classes
   that are 79.4% of walkable edges.
4. **A corrupt endpoint index.** `-1` wraps silently in `AttackGraph.__init__`
   rather than raising, so it must be caught before the graph is built.

Each test also asserts the harness *passes* on the uncorrupted parse, so a
failure here means the corruption was detected rather than the harness being
broken in general.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from stealthpath.graph import AttackGraph
from tools.validate_parser import (
    REFUSED_PREFIX, ROUTE_BEARING_TYPES, WrongCollectionError,
    assert_fixture_is_the_right_collection, reference_triples, validate,
)

ROOT = Path(__file__).resolve().parent.parent
GRAPH = ROOT / "data" / "goad_graph.json"
RAW = ROOT / "data" / "raw_collection"


@pytest.fixture(scope="module")
def perfect():
    """A parse that is exactly right, as node/edge dicts.

    Taken from the frozen graph itself: this stands in for a parser that has
    reproduced CE's ingest perfectly, and is the baseline every corruption below
    is applied to.
    """
    data = json.loads(GRAPH.read_text(encoding="utf-8"))
    return data["nodes"], data["edges"]


def test_the_harness_passes_on_a_perfect_parse(perfect):
    """The control. Without this, every failure below is uninformative."""
    nodes, edges = perfect
    report = validate(nodes, edges)
    assert report.ok
    assert report.route_failures == []
    assert report.index_problems == []
    assert all(d.ok for d in report.diffs)
    assert "VERDICT: PASS" in report.render()


def test_reference_is_triples_not_counts():
    """5,825 edges resolve to 5,825 distinct triples, so no duplicate hides."""
    assert len(reference_triples()) == 5825


# ---------------------------------------------------------------------------
# 1. A swapped mapping
# ---------------------------------------------------------------------------

def test_swapping_writedacl_and_genericall_is_caught(perfect):
    """Both are route-bearing, so this must fail loudly and name both.

    Counts alone would show 1317 and 1008 becoming 1008 and 1317 — visibly odd
    but only if someone is reading the numbers. The triples show which specific
    edges moved.
    """
    nodes, edges = perfect
    swap = {"WriteDacl": "GenericAll", "GenericAll": "WriteDacl"}
    corrupted = [{**e, "rel_type": swap.get(e["rel_type"], e["rel_type"])}
                 for e in edges]

    report = validate(nodes, corrupted)
    assert not report.ok

    failed = {d.rel_type for d in report.route_failures}
    assert {"WriteDacl", "GenericAll"} <= failed

    by_type = {d.rel_type: d for d in report.diffs}
    assert by_type["WriteDacl"].expected == 1317
    assert by_type["WriteDacl"].got == 1008
    assert by_type["GenericAll"].expected == 1008
    assert by_type["GenericAll"].got == 1317
    # Both directions of the swap are visible: each type is simultaneously
    # missing its own edges and carrying the other's.
    assert by_type["WriteDacl"].missing and by_type["WriteDacl"].extra
    assert by_type["WriteDacl"].status == "MISMATCH"

    rendered = report.render()
    assert "ROUTE-BEARING" in rendered
    assert "VERDICT: FAIL" in rendered


# ---------------------------------------------------------------------------
# 2. The intuitive DCSync rule — the one that matters
# ---------------------------------------------------------------------------

def _dcsync_from_replication_rights(nodes, edges):
    """Synthesise DCSync the way the ACE data suggests, and only that way.

    `DCSync = GetChanges AND GetChangesAll` between the same pair. This is the
    natural implementation: it is what the extended rights mean, and it is what
    a reader of the ACL data would write. It is also wrong, because CE grants
    DCSync to domain controllers directly — no ACE involved.
    """
    have = {}
    for e in edges:
        if e["rel_type"] in ("GetChanges", "GetChangesAll"):
            have.setdefault((e["source"], e["target"]), set()).add(e["rel_type"])
    synthesised = [
        {"source": s, "target": t, "rel_type": "DCSync", "props": {}}
        for (s, t), rights in sorted(have.items())
        if rights == {"GetChanges", "GetChangesAll"}
    ]
    kept = [e for e in edges if e["rel_type"] != "DCSync"]
    return nodes, kept + synthesised


def test_the_intuitive_dcsync_rule_is_caught_and_it_misses_every_route(perfect):
    """The invisible failure, made visible.

    Three of six DCSync edges, and the three produced are the `ADMINISTRATORS`
    ones that carry underlying replication ACEs. The three missed are
    `WINTERFELL`, `KINGSLANDING` and `MEEREEN` — the domain controllers — and
    those are the edges every reported route actually traverses. A parser with
    this bug re-costs `SQL_SVC` and `TYWIN` on both frozen graphs while
    reporting full coverage.
    """
    nodes, edges = _dcsync_from_replication_rights(*perfect)
    report = validate(nodes, edges)

    assert not report.ok
    assert "DCSync" in {d.rel_type for d in report.route_failures}

    dcsync = next(d for d in report.diffs if d.rel_type == "DCSync")
    assert (dcsync.expected, dcsync.got) == (6, 3)
    assert dcsync.status == "MISSING"
    assert dcsync.extra == [], "the rule under-produces; it invents nothing"
    assert len(dcsync.missing) == 3

    # Name the three that are missed, and prove they are the domain controllers
    # rather than an arbitrary three.
    graph = AttackGraph.load(GRAPH)
    by_id = {n.id: n for n in graph.nodes}
    missed = sorted(by_id[src].name for src, _, _ in dcsync.missing)
    assert missed == [
        "KINGSLANDING.SEVENKINGDOMS.LOCAL",
        "MEEREEN.ESSOS.LOCAL",
        "WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL",
    ]
    assert all(by_id[src].kind == "Computer" for src, _, _ in dcsync.missing)

    # And that they carry no replication ACE at all, which is why the rule
    # cannot reach them and why the fix has to key on the node being a DC.
    for src, dst, _ in dcsync.missing:
        siblings = {e.rel_type for e in graph.edges
                    if graph.nodes[e.source].id == src
                    and graph.nodes[e.target].id == dst}
        assert not siblings & {"GetChanges", "GetChangesAll"}

    assert "DCSync" in report.render()


def test_the_route_bearing_dcsync_edges_are_exactly_the_missed_ones():
    """Why the rule above is invisible rather than merely wrong.

    Every DCSync hop on every reported route starts at a domain controller. The
    three edges the intuitive rule *does* produce are on no reported route, so a
    coverage report would be clean and three published costs would be wrong.
    """
    from dashboard.compute import ENTRY_POINTS, compare_entry_point

    graph = AttackGraph.load(GRAPH)
    view = graph.with_gpo_expansion()
    sources = set()
    for entry in ENTRY_POINTS:
        for record in compare_entry_point(graph, entry).values():
            if "DCSync" in record["route"]:
                i = record["route"].index("DCSync")
                sources.add(record["node_names"][i])

    assert sources == {
        "WINTERFELL.NORTH.SEVENKINGDOMS.LOCAL",
        "KINGSLANDING.SEVENKINGDOMS.LOCAL",
    }
    assert not any(name.startswith("ADMINISTRATORS@") for name in sources)
    assert "DCSync" in ROUTE_BEARING_TYPES
    assert view is not None


# ---------------------------------------------------------------------------
# 3. A naive ACE reader emitting both Raw and processed edges
# ---------------------------------------------------------------------------

def test_emitting_both_raw_and_processed_acl_edges_is_caught(perfect):
    """`WriteOwnerRaw` alongside `WriteOwner`, `OwnsRaw` alongside `Owns`.

    CE post-processes raw ACEs into the edges the graph uses; the raw forms are
    dropped at load. A parser reading `Aces` directly produces the raw
    semantics, and emitting both doubles two ACL classes.

    `WriteOwner` is route-bearing so this fails; `Owns` is not, so it lands in
    the notes. Both must still be *named* — that split is the harness's whole
    reason for separating the two lists rather than counting failures.
    """
    nodes, edges = perfect
    doubled = list(edges)
    for e in edges:
        if e["rel_type"] == "WriteOwner":
            doubled.append({**e, "rel_type": "WriteOwnerRaw"})
        elif e["rel_type"] == "Owns":
            doubled.append({**e, "rel_type": "OwnsRaw"})
    # Same ACEs read twice under both names, as a naive reader would.
    doubled += [{**e, "rel_type": "WriteOwner"} for e in edges
                if e["rel_type"] == "WriteOwner"]

    report = validate(nodes, doubled)
    assert not report.ok

    by_type = {d.rel_type: d for d in report.diffs}

    # The duplicated WriteOwner edges collapse in the triple set, so the per-type
    # diff reports WriteOwner as a clean MATCH. That is not a gap being excused:
    # it is why the duplicate check exists as a separate signal, and asserting
    # the MATCH here keeps the division of labour explicit. An earlier draft of
    # this test asserted got == 2632 and was simply wrong about its own harness.
    assert by_type["WriteOwner"].status == "MATCH"
    assert by_type["WriteOwner"].got == 1316
    duplicates = [p for p in report.index_problems
                  if p.field_name == "duplicate_triples"]
    assert len(duplicates) == 1
    assert duplicates[0].value == 1316, "one extra copy of every WriteOwner edge"

    # The Raw types are pure EXTRA: they exist nowhere in the reference.
    assert by_type["WriteOwnerRaw"].status == "EXTRA"
    assert by_type["WriteOwnerRaw"].expected == 0
    assert by_type["WriteOwnerRaw"].got == 1316
    assert by_type["OwnsRaw"].status == "EXTRA"
    assert by_type["OwnsRaw"].got == 722

    # WriteOwnerRaw is not route-bearing, so it is a note; the failure that
    # stops the build is the duplication on WriteOwner itself.
    notes = {d.rel_type for d in report.other_failures}
    assert {"WriteOwnerRaw", "OwnsRaw"} <= notes
    assert "duplicate" in report.render()


# ---------------------------------------------------------------------------
# 4. A corrupt endpoint index
# ---------------------------------------------------------------------------

def test_a_negative_endpoint_index_is_caught(perfect):
    """-1 is the dangerous one: `from_dict` accepts it and wraps.

    Out-of-range raises IndexError when the graph is built, which is loud. A
    negative index silently attaches the edge to the last node, producing a
    valid-looking graph with one wrong edge, so the harness has to catch it
    before construction.
    """
    nodes, edges = perfect
    corrupted = [dict(e) for e in edges]
    corrupted[10]["source"] = -1

    report = validate(nodes, corrupted)
    assert not report.ok

    problems = [p for p in report.index_problems if p.field_name == "source"]
    assert len(problems) == 1
    assert problems[0].edge_index == 10
    assert problems[0].value == -1
    assert "wraps" in problems[0].reason
    assert "INDEX INTEGRITY" in report.render()

    # And confirm the premise: AttackGraph really does accept it silently.
    data = json.loads(GRAPH.read_text(encoding="utf-8"))
    data["edges"] = corrupted
    built = AttackGraph.from_dict(data)
    assert built.edges[10].source == -1, (
        "if this ever raises, from_dict has been hardened and this check can "
        "be relaxed to rely on it")


def test_an_out_of_range_endpoint_index_is_caught(perfect):
    nodes, edges = perfect
    corrupted = [dict(e) for e in edges]
    corrupted[3]["target"] = len(nodes)

    report = validate(nodes, corrupted)
    assert not report.ok
    assert any(p.value == len(nodes) and "out of range" in p.reason
               for p in report.index_problems)


# ---------------------------------------------------------------------------
# The fixture guard
# ---------------------------------------------------------------------------

def test_the_wrong_collection_is_refused_by_name():
    """Made impossible rather than documented.

    The bloodhound.py exports describe the same lab and would validate against
    the wrong ingest while reporting success.
    """
    with pytest.raises(WrongCollectionError, match="bloodhound.py"):
        assert_fixture_is_the_right_collection(
            Path(f"{REFUSED_PREFIX}north_20240411011008_bloodhound.zip"))

    for path in sorted(RAW.glob("*.zip")):
        assert_fixture_is_the_right_collection(path)


def test_the_vendored_fixtures_match_their_recorded_hashes():
    """Same treatment as the frozen graph: committed, and cited by hash."""
    import hashlib

    provenance = json.loads(
        (ROOT / "data" / "collection_provenance.json").read_text(encoding="utf-8"))
    recorded = provenance["raw_collection"]["sha256"]
    assert len(recorded) == 3

    for name, expected in sorted(recorded.items()):
        path = RAW / name
        assert path.exists(), f"{name} is recorded but not vendored"
        actual = hashlib.sha256(path.read_bytes()).hexdigest()
        assert actual == expected, f"{name} does not match its recorded sha256"

    # The three named here must be the three the graph's own provenance lists.
    assert set(recorded) == set(provenance["source_files"])
