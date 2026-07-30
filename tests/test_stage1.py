"""Stage 1 test suite.

These tests are the actual Stage 1 exit criteria for the software half. They run
without a lab, a database, or a network.
"""

from __future__ import annotations

import json

import pytest

from stealthpath.ad_schema import (
    DEFAULT_TRAVERSAL_SET, EDGE_CATEGORIES, STRUCTURAL_EDGES, category_of,
)
from stealthpath.graph import AttackGraph, Node
from stealthpath.loader_neo4j import _is_high_value, _is_owned, _primary_kind
from stealthpath.planners.shortest_path import ShortestPathPlanner, dijkstra
from stealthpath.synthetic import goad_like, random_ad


# ------------------------------------------------------------------ fixtures

@pytest.fixture
def goad():
    return goad_like()


# --------------------------------------------------------------- graph tests

def test_graph_builds_with_expected_shape(goad):
    assert len(goad.nodes) > 15
    assert len(goad.edges) > 20
    assert goad.node_kind_counts()["User"] >= 8
    assert "Domain" in goad.node_kind_counts()


def test_objectid_lookup_is_stable(goad):
    idx = goad.index_of("U-SAMWELL")
    assert goad.nodes[idx].id == "U-SAMWELL"
    assert goad.node("U-SAMWELL") is goad.nodes[idx]
    with pytest.raises(KeyError):
        goad.index_of("does-not-exist")


def test_adjacency_is_consistent(goad):
    """Every edge must appear in exactly one out-list and one in-list."""
    for ei, e in enumerate(goad.edges):
        assert ei in goad.out_edge_indices(e.source)
        assert e in goad.in_edges(e.target)


def test_multigraph_keeps_parallel_edges():
    """Two different relationships between the same pair must not collapse —
    they have different detection profiles, which is the whole project."""
    g = AttackGraph()
    g.add_node(Node("a", "A", "User"))
    g.add_node(Node("b", "B", "Computer"))
    g.add_edge("a", "b", "AdminTo")
    g.add_edge("a", "b", "CanRDP")
    assert len(g.edges) == 2
    assert {e.rel_type for e in g.out_edges("a")} == {"AdminTo", "CanRDP"}


def test_entry_and_target_detection(goad):
    entries = goad.entry_nodes()
    assert entries, "fixture must have a foothold"
    assert goad.nodes[entries[0]].name.startswith("SAMWELL")
    assert goad.find(name="DOMAIN ADMINS", kind="Group")


def test_json_round_trip_preserves_everything(goad, tmp_path):
    path = tmp_path / "g.json"
    goad.save(path)
    back = AttackGraph.load(path)
    assert len(back.nodes) == len(goad.nodes)
    assert len(back.edges) == len(goad.edges)
    assert back.edge_type_counts() == goad.edge_type_counts()
    assert back.node("U-SAMWELL").owned is True
    assert back.node("C-CASTELBLACK").props["haslaps"] is True
    # adjacency must be rebuilt, not just the lists
    assert back.out_edge_indices(back.index_of("U-SAMWELL")) == \
           goad.out_edge_indices(goad.index_of("U-SAMWELL"))


def test_save_creates_missing_parent_directory(goad, tmp_path):
    """The runbook freezes to `data/goad_graph.json` on a fresh checkout where
    `data/` doesn't exist yet. Failing there costs a whole SharpHound re-run."""
    goad.save(tmp_path / "data" / "goad_graph.json")
    assert AttackGraph.load(tmp_path / "data" / "goad_graph.json").edge_type_counts() \
           == goad.edge_type_counts()


def test_rejects_unknown_serialisation_format(tmp_path):
    p = tmp_path / "bad.json"
    p.write_text(json.dumps({"format": "something/else", "nodes": [], "edges": []}))
    with pytest.raises(ValueError, match="unrecognised"):
        AttackGraph.load(p)


def test_filtered_view_drops_edges_not_nodes(goad):
    only_member = goad.filtered({"MemberOf"})
    assert len(only_member.nodes) == len(goad.nodes)
    assert all(e.rel_type == "MemberOf" for e in only_member.edges)


# -------------------------------------------------------------- schema tests

def test_every_fixture_edge_is_categorised(goad):
    for rel in goad.edge_type_counts():
        assert category_of(rel)


def test_structural_edges_excluded_from_traversal():
    assert "Contains" in STRUCTURAL_EDGES
    assert "Contains" not in DEFAULT_TRAVERSAL_SET
    assert "MemberOf" in DEFAULT_TRAVERSAL_SET


def test_unknown_relationship_fails_loudly():
    """Silently defaulting an unknown edge would skew Stage 3 costs."""
    with pytest.raises(KeyError, match="Unknown relationship"):
        category_of("TotallyMadeUpEdge")


# -------------------------------------------------------------- loader tests
# Only the pure helpers — no database, per the no-lab-required rule. These are
# the parts that differ between BloodHound generations, so they're the ones that
# would silently produce an empty target list after a whole lab build.

def test_primary_kind_ignores_base_label():
    """`Base` is on every node in BloodHound CE and would win a first-wins pick."""
    assert _primary_kind(["Base", "User"]) == "User"
    assert _primary_kind(["User"]) == "User"


def test_primary_kind_is_priority_not_first_wins():
    """Neo4j label order isn't stable across driver versions, so a Computer that
    also carries Group must resolve the same way every collection."""
    assert _primary_kind(["Group", "Computer"]) == "Computer"
    assert _primary_kind(["Computer", "Group"]) == "Computer"


def test_primary_kind_survives_labels_it_has_never_seen():
    assert _primary_kind(["SomethingNew"]) == "SomethingNew"
    assert _primary_kind(["Base"]) == "Unknown"
    assert _primary_kind([]) == "Unknown"


def test_high_value_detected_under_both_bloodhound_generations():
    assert _is_high_value({"highvalue": True})                       # legacy 4.x
    assert _is_high_value({"system_tags": ["admin_tier_0"]})         # CE, list
    assert _is_high_value({"system_tags": "admin_tier_0"})           # CE, string
    assert not _is_high_value({"highvalue": False})
    assert not _is_high_value({})


def test_owned_detected_under_both_bloodhound_generations():
    assert _is_owned({"owned": True})
    assert _is_owned({"user_tags": ["owned"]})
    assert not _is_owned({})


# ------------------------------------------------------------- planner tests

def test_finds_a_path_to_domain_admins(goad):
    planner = ShortestPathPlanner()
    targets = goad.find(name="DOMAIN ADMINS@NORTH", kind="Group")
    path = planner.plan(goad, goad.entry_nodes(), targets)
    assert path is not None
    path.validate(goad)
    assert path.nodes[0] == goad.index_of("U-SAMWELL")
    assert path.nodes[-1] in targets


def test_path_is_a_real_walk_in_the_graph(goad):
    """The invariant that everything downstream depends on."""
    planner = ShortestPathPlanner()
    path = planner.plan(goad, goad.entry_nodes(),
                        goad.find(name="DOMAIN ADMINS@NORTH", kind="Group"))
    for i, ei in enumerate(path.edges):
        edge = goad.edges[ei]
        assert edge.source == path.nodes[i]
        assert edge.target == path.nodes[i + 1]


def test_unit_cost_equals_hop_count(goad):
    planner = ShortestPathPlanner()
    path = planner.plan(goad, goad.entry_nodes(),
                        goad.find(name="DOMAIN ADMINS@NORTH", kind="Group"))
    assert path.cost == pytest.approx(float(path.length))


def test_agrees_with_networkx_on_shortest_length(goad):
    """Independent cross-check. If our Dijkstra and networkx disagree on
    length, ours is wrong."""
    import networkx as nx

    traversable = goad.filtered(DEFAULT_TRAVERSAL_SET)
    nxg = nx.DiGraph()
    nxg.add_nodes_from(range(len(traversable.nodes)))
    nxg.add_edges_from((e.source, e.target) for e in traversable.edges)

    src = goad.index_of("U-SAMWELL")
    dst = goad.find(name="DOMAIN ADMINS@NORTH", kind="Group")[0]
    expected = nx.shortest_path_length(nxg, src, dst)

    path = ShortestPathPlanner().plan(goad, [src], [dst])
    assert path.length == expected


def test_returns_none_when_target_unreachable(goad):
    isolated = goad.add_node(Node("ISOLATED", "ISOLATED", "User"))
    assert ShortestPathPlanner().plan(goad, goad.entry_nodes(), [isolated]) is None


def test_trivial_path_when_source_is_target(goad):
    src = goad.entry_nodes()[0]
    path = ShortestPathPlanner().plan(goad, [src], [src])
    assert path is not None and path.length == 0 and path.cost == 0.0


def test_multi_source_picks_the_closest(goad):
    """A far foothold must not beat a near one."""
    near = goad.index_of("U-EDDARD")     # one MemberOf hop from DA
    far = goad.index_of("U-SAMWELL")
    dst = goad.find(name="DOMAIN ADMINS@NORTH", kind="Group")
    path = ShortestPathPlanner().plan(goad, [far, near], dst)
    assert path.nodes[0] == near
    assert path.length == 1


def test_path_never_revisits_a_node(goad):
    path = ShortestPathPlanner().plan(goad, goad.entry_nodes(),
                                      goad.find(name="DOMAIN ADMINS@NORTH", kind="Group"))
    assert len(set(path.nodes)) == len(path.nodes)


def test_structural_edges_are_not_traversed(goad):
    """Contains would give a bogus 2-hop route Domain -> DA."""
    path = ShortestPathPlanner().plan(goad, goad.entry_nodes(),
                                      goad.find(name="DOMAIN ADMINS@NORTH", kind="Group"))
    assert "Contains" not in path.rel_types(goad)


def test_weighted_costs_change_the_route(goad):
    """Pre-flight for Stage 2. The plan warns: if weighted A* always returns the
    same path as Dijkstra, the weights aren't differentiating anything. This
    confirms the fixture has enough route diversity for weights to bite.

    Unit-cost shortest path here is the 3-hop delegation shortcut. Make
    delegation expensive and a genuinely different route must appear.
    """
    src = goad.entry_nodes()
    dst = goad.find(name="DOMAIN ADMINS@NORTH", kind="Group")

    cheap = dijkstra(goad, src, dst)
    assert "AllowedToDelegate" in cheap.rel_types(goad)

    def costly_delegation(graph, ei, history):
        return 100.0 if graph.edges[ei].rel_type == "AllowedToDelegate" else 1.0

    avoided = dijkstra(goad, src, dst, costly_delegation)
    assert avoided is not None
    assert "AllowedToDelegate" not in avoided.rel_types(goad)
    assert avoided.rel_types(goad) != cheap.rel_types(goad)
    # and it should be a longer walk, since it gave up the shortcut
    assert avoided.length > cheap.length


def test_negative_costs_rejected(goad):
    def bad(graph, ei, history):
        return -1.0
    with pytest.raises(ValueError, match="negative cost"):
        dijkstra(goad, goad.entry_nodes(),
                 goad.find(name="DOMAIN ADMINS@NORTH", kind="Group"), bad)


def test_max_hops_bounds_the_search(goad):
    path = dijkstra(goad, goad.entry_nodes(),
                    goad.find(name="DOMAIN ADMINS@NORTH", kind="Group"),
                    max_hops=1)
    assert path is None


def test_malformed_path_is_caught():
    from stealthpath.planners.base import Path
    g = AttackGraph()
    g.add_node(Node("a", "A", "User"))
    g.add_node(Node("b", "B", "User"))
    g.add_edge("a", "b", "MemberOf")
    with pytest.raises(ValueError, match="malformed"):
        Path((0, 1), (), 0.0).validate(g)


# ------------------------------------------------------- synthetic generator

@pytest.mark.parametrize("seed", [0, 1, 2, 7, 42])
def test_random_graphs_are_solvable(seed):
    g = random_ad(n_users=40, n_computers=12, n_groups=8, seed=seed)
    path = ShortestPathPlanner().plan(g, g.entry_nodes(), g.find(name="DOMAIN ADMINS"))
    assert path is not None
    path.validate(g)


def test_random_generation_is_deterministic():
    a, b = random_ad(seed=5), random_ad(seed=5)
    assert a.edge_type_counts() == b.edge_type_counts()
    assert [n.id for n in a.nodes] == [n.id for n in b.nodes]


def test_random_graphs_use_realistic_edge_types():
    g = random_ad(seed=3)
    present = set(g.edge_type_counts())
    assert {"MemberOf", "HasSession"} <= present
    for rel in present:
        assert rel in EDGE_CATEGORIES
