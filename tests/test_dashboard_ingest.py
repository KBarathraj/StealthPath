"""Upload path: a StealthPath freeze or a collector export loads, nothing else.

The zip used to be refused by name, and that was right at the time: a
mis-mapped `WriteDacl` -> `GenericAll` still looks fully covered and nothing
downstream can catch it. `tools/validate_parser.py` answers that objection
directly -- it compares the parse against BloodHound CE's own ingest triple by
triple -- so the refusal moved rather than relaxed. A damaged or unrecognisable
file still stops here instead of being priced.
"""

from __future__ import annotations

import json

import pytest

from dashboard.compute import _TRAVERSAL_ALLOWED, starting_points, target_names
from dashboard.ingest import UnsupportedGraphError, load_uploaded, load_uploads
from stealthpath.graph import AttackGraph
from stealthpath.targets import derive_targets, reaching_set
from stealthpath.synthetic import goad_like
from tests.test_dashboard_numbers import BASE


def test_a_frozen_stealthpath_json_loads():
    raw = BASE.read_bytes()
    graph = load_uploaded(raw, "goad_graph.json")
    assert len(graph.nodes) == 783
    assert len(graph.edges) == 5825


def test_a_damaged_zip_is_refused_rather_than_crashing():
    """`zipfile` raises `BadZipFile`, which is not an `UnsupportedGraphError`.

    A truncated upload is ordinary. Letting the raw exception through takes the
    page down instead of naming the damaged file. Matched on "truncated" rather
    than on "zip", because the old refusal message also contained the word
    "zip" and would have kept this test green after the behaviour reversed.
    """
    with pytest.raises(UnsupportedGraphError, match="truncated"):
        load_uploaded(b"PK\x03\x04not-a-real-zip", "BloodHound.zip")


def test_a_real_collector_export_is_parsed_not_refused():
    """The behaviour change itself: a BloodHound zip is now a supported upload."""
    raw_dir = BASE.parent / "raw_collection"
    zips = sorted(raw_dir.glob("*.zip")) if raw_dir.exists() else []
    if not zips:
        pytest.skip("vendored collector exports are not present")
    loaded = load_uploads([(p.name, p.read_bytes()) for p in zips])
    assert loaded.is_reconstruction
    assert len(loaded.graph.edges) == 5825


def test_a_freeze_uploaded_with_anything_else_is_refused():
    """Collector exports merge; freezes do not.

    A multi-domain forest is collected one domain at a time, so the zips only
    resolve their cross-domain ACEs together. A freeze is already a whole graph,
    and concatenating it with anything else would describe a collection that
    never happened.
    """
    with pytest.raises(UnsupportedGraphError, match="on its own"):
        load_uploads([("frozen.json", BASE.read_bytes()),
                      ("other.zip", b"PK\x03\x04")])


def test_a_bloodhound_ce_fragment_is_refused():
    payload = json.dumps({
        "data": [],
        "meta": {"type": "users", "count": 0, "version": 5},
    }).encode("utf-8")
    with pytest.raises(UnsupportedGraphError, match="BloodHound CE"):
        load_uploaded(payload, "users.json")


def test_nodes_and_edges_without_format_are_refused():
    payload = json.dumps({"nodes": [], "edges": []}).encode("utf-8")
    with pytest.raises(UnsupportedGraphError, match="no \"format\" field"):
        load_uploaded(payload, "almost.json")


def test_a_synthetic_round_trip_loads_through_the_uploader():
    graph = goad_like()
    raw = json.dumps(graph.to_dict()).encode("utf-8")
    loaded = load_uploaded(raw, "fixture.json")
    assert len(loaded.nodes) == len(graph.nodes)
    assert len(loaded.edges) == len(graph.edges)


def test_starting_points_put_owned_and_documented_entries_first():
    g = goad_like()
    owned = [g.nodes[i].name for i in g.entry_nodes()]
    starts = starting_points(g)
    assert owned
    assert starts[: len(owned)] == owned
    assert target_names(g)


def test_starting_points_on_the_frozen_graph_surface_the_documented_entries():
    g = AttackGraph.load(BASE)
    starts = starting_points(g)
    assert any("SAMWELL.TARLY" in s for s in starts[:5])
    assert any("SQL_SVC" in s for s in starts[:5])
    assert any("TYWIN.LANNISTER" in s for s in starts[:5])
    names = target_names(g)
    assert names
    assert any("DOMAIN ADMINS" in n.upper() or n.endswith(".LOCAL") for n in names)


def test_the_default_start_is_not_an_already_privileged_account():
    """The first entry is the UI default, and it decides the first impression.

    Two separate near-misses produced a useless opening answer, and both are
    guarded here because each was invisible on the other's dataset:

    - an upload of the reference collection defaulted to `HODOR`, a session
      holder with *no route*, so the page opened on "No route reported";
    - the SpecterOps public sample defaulted to `ADMINISTRATOR`, which is
      already in Enterprise Admins, so the page opened on a one-hop `MemberOf`
      into the target.

    An account that is already tier-0 starts at the destination; a route from it
    demonstrates nothing.
    """
    g = AttackGraph.load(BASE)
    starts = starting_points(g)
    privileged = {n.name for n in g.nodes
                  if n.props.get("admincount") is True or n.high_value}
    assert starts[0] not in privileged, (
        f"default start {starts[0]!r} is already privileged")

    view = g.with_gpo_expansion()
    targets = {c.index for c in derive_targets(view)}
    assert targets, "no targets derived, so the ordering check proves nothing"
    reaching = reaching_set(view, sorted(targets), _TRAVERSAL_ALLOWED)
    assert starts[0] in {view.nodes[i].name for i in reaching}, (
        f"default start {starts[0]!r} cannot reach any target")
