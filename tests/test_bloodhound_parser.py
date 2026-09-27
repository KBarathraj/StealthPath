"""The BloodHound CE parser, checked against CE's own ingest.

The load-bearing test is `test_the_parse_reproduces_the_reference_ingest_exactly`.
Everything else in this file is a named regression for a bug that actually
happened while the parser was being written, and each one was invisible to every
other test in the suite: the graph still loaded, still priced every edge, still
reported full coverage and still printed a route.
"""

from __future__ import annotations

import io
import json
import zipfile
from pathlib import Path

import pytest

from dashboard.bloodhound_parser import (
    NotABloodHoundExport, parse_export_bytes, parse_export_dir, to_attack_graph,
)
from stealthpath.graph import AttackGraph

ROOT = Path(__file__).resolve().parent.parent
RAW = ROOT / "data" / "raw_collection"
FROZEN = ROOT / "data" / "goad_graph.json"

pytestmark = pytest.mark.skipif(
    not RAW.exists() or not any(RAW.glob("*.zip")),
    reason="vendored collector exports are not present",
)


@pytest.fixture(scope="module")
def parsed():
    return parse_export_dir(RAW)


@pytest.fixture(scope="module")
def reference():
    return AttackGraph.load(FROZEN)


def _triples(nodes, edges):
    ids = [n.id for n in nodes]
    return {(ids[e.source], ids[e.target], e.rel_type) for e in edges}


def test_the_parse_reproduces_the_reference_ingest_exactly(parsed, reference):
    """Every edge BloodHound CE created, and no others.

    `data/goad_graph.json` is CE's ingest of the exact zips in
    `data/raw_collection/`, so this is a decidable question rather than a
    judgement about whether the mapping looks right. Compared as triples because
    per-type counts pass a parser that emits the right number of `DCSync` edges
    between the wrong endpoints -- which is close to the real failure, since CE
    grants three of the six to domain controllers with no ACE behind them.
    """
    nodes, edges = parsed
    expected = {(reference.nodes[e.source].id, reference.nodes[e.target].id,
                 e.rel_type) for e in reference.edges}
    graph = to_attack_graph(to_parsed(nodes, edges))
    assert _triples(graph.nodes, graph.edges) == expected


def to_parsed(nodes, edges):
    """Rebuild the `ParsedExport` shape `to_attack_graph` takes."""
    from dashboard.bloodhound_parser import ParsedExport
    return ParsedExport(list(nodes), list(edges), set(), [], {})


def test_admitted_edge_count_matches_the_frozen_graph(parsed, reference):
    graph = to_attack_graph(to_parsed(*parsed))
    assert len(graph.edges) == len(reference.edges) == 5825


def test_duplicate_object_records_are_merged_not_overwritten():
    """SharpHound writes the same object twice, and the second copy is empty.

    Last-wins cost 81 `Owns` and 84 `Contains` edges when this parser was first
    written, and nothing downstream noticed. The placeholder must not erase the
    enumerated record.
    """
    full = {
        "meta": {"type": "groups", "count": 1, "version": 6},
        "data": [{
            "ObjectIdentifier": "S-1-5-21-1-2-3-1000",
            "Properties": {"name": "G@D", "domain": "D"},
            "Aces": [{"PrincipalSID": "S-1-5-21-1-2-3-500",
                      "PrincipalType": "User", "RightName": "GenericAll",
                      "IsInherited": False}],
            "Members": [{"ObjectIdentifier": "S-1-5-21-1-2-3-501",
                         "ObjectType": "User"}],
        }],
    }
    placeholder = {
        "meta": {"type": "groups", "count": 1, "version": 6},
        "data": [{"ObjectIdentifier": "S-1-5-21-1-2-3-1000",
                  "Properties": {}, "Aces": [], "Members": []}],
    }
    result = parse_export_bytes([
        ("full.json", json.dumps(full).encode()),
        ("placeholder.json", json.dumps(placeholder).encode()),
    ])
    rels = {e.rel_type for e in result.edges}
    assert "GenericAll" in rels, "the placeholder erased the enumerated ACEs"
    assert "MemberOf" in rels, "the placeholder erased the member list"


def test_self_referential_edges_are_dropped(parsed):
    """The reference ingest has none, and the collection really does contain
    three (`DOMAIN ADMINS -Owns-> DOMAIN ADMINS`)."""
    _nodes, edges = parsed
    assert not [e for e in edges if e.source == e.target]


def test_dcsync_includes_the_domain_controllers(parsed):
    """The half a rights-only rule silently omits.

    `GetChanges AND GetChangesAll` yields 3 of the 6 `DCSync` edges here. The
    other 3 belong to the DCs themselves, which CE grants with no underlying
    ACE -- and they are the ones a route traverses.
    """
    nodes, edges = parsed
    by_id = {n.id: n for n in nodes}
    sources = [nodes[e.source] for e in edges if e.rel_type == "DCSync"]
    assert len(sources) == 6
    assert sum(1 for n in sources if n.kind == "Computer") == 3
    assert all(by_id[n.id].props.get("isdc") for n in sources
               if n.kind == "Computer")


def test_primary_group_membership_is_reconstructed(parsed):
    """`PrimaryGroupSID` lives on the member, not in the group's member list.

    Without it Domain Users and Domain Computers are almost empty, and 62 of the
    reference's 199 `MemberOf` edges disappear.
    """
    nodes, edges = parsed
    member_of = [e for e in edges if e.rel_type == "MemberOf"]
    assert len(member_of) == 199
    names = {nodes[e.target].name for e in member_of}
    assert any("DOMAIN USERS" in n for n in names)


def test_local_admin_comes_from_rid_544_only(parsed):
    """CE emits no `CanRDP` here despite four local Remote Desktop Users.

    Emitting the other local-group RIDs would produce a graph that is provably
    not the one CE produced, and all three are traversable, so the difference
    would move routes.
    """
    _nodes, edges = parsed
    types = {e.rel_type for e in edges}
    assert "AdminTo" in types
    assert not types & {"CanRDP", "ExecuteDCOM", "CanPSRemote"}


def test_unknown_edge_types_are_dropped_and_recorded(parsed):
    """Rule 4 still owns admission; the parser does not pre-filter.

    An upload drops rather than raises -- it is somebody else's directory and an
    unknown type is expected -- but what was dropped travels with the graph.
    """
    graph = to_attack_graph(to_parsed(*parsed))
    dropped = graph.provenance["dropped_unknown_edge_types"]
    assert dropped["OwnsRaw"] == 722
    assert dropped["Enroll"] == 181
    assert "DCFor" in dropped


def test_a_zip_of_nothing_useful_is_refused():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("readme.json", json.dumps({"hello": "world"}))
    with pytest.raises(NotABloodHoundExport):
        parse_export_bytes([("x.zip", buf.getvalue())])


def test_a_stealthpath_freeze_is_not_mistaken_for_an_export():
    data = json.dumps({"format": "stealthpath.attackgraph/1",
                       "nodes": [], "edges": []}).encode()
    with pytest.raises(NotABloodHoundExport):
        parse_export_bytes([("g.json", data)])
