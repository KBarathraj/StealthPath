"""Stage 2 test suite: risk weights and the weighted A* planner.

Like Stage 1's, these run without a lab, a database, or a network.

The load-bearing test here is `test_weighted_route_differs_from_shortest_path`.
If the weighted planner always agrees with plain shortest path, the weights are
decorative and everything built on top of them is measuring nothing.
"""

from __future__ import annotations

import pytest

from stealthpath.ad_schema import (
    DEFAULT_TRAVERSAL_SET, PARTIAL_RIGHT_EDGES, STRUCTURAL_EDGES,
    TRAVERSABLE_EDGES, EdgeCategory, category_of,
)
from stealthpath.planners.shortest_path import dijkstra
from stealthpath.planners.weighted_astar import (
    WeightedAStarPlanner, astar, hops_to_targets,
)
from stealthpath.risk import (
    PROVISIONAL_WEIGHTS, WEIGHT_CEILING, WEIGHT_FLOOR, require_sourced,
    static_cost_fn, unsourced, weight_of,
)
from stealthpath.synthetic import goad_like, random_ad


@pytest.fixture
def goad():
    return goad_like()


@pytest.fixture
def da_north(goad):
    """One specific group. Tests that are about the *planner* pin an explicit
    endpoint so they don't move when the target policy does."""
    return goad.find(name="DOMAIN ADMINS@NORTH", kind="Group")


@pytest.fixture
def tier0(goad):
    """The real default target set: DA groups plus domain objects."""
    return goad.tier0_targets()


def test_every_traversable_edge_has_a_weight():
    """A new edge type in ad_schema must not be walkable until it is weighted.
    This test failing is the intended notification.

    Coverage, not equality: the table also still carries weights for
    `PARTIAL_RIGHT_EDGES` (GetChanges / GetChangesAll / GetChangesInFilteredSet),
    which are no longer traversable. Those three are now dead numbers. Leaving
    them is harmless — nothing reads them — and pruning them is a risk.py edit,
    which belongs with the sourcing pass.
    """
    assert set(TRAVERSABLE_EDGES) <= set(PROVISIONAL_WEIGHTS)


def test_only_the_gpo_chain_is_weighted_among_structural_edges():
    """Structural edges are normally unweighted — a weight on something the
    planners never walk is a dead number that later reads as an endorsement.

    `GPLink` and `Contains` are the deliberate exception. They *are* walkable
    inside `with_gpo_expansion()`, so they need costs or that view cannot be
    planned over with weights at all. Both sit at the floor precisely because
    they are propagation rather than action.
    """
    weighted_structural = set(PROVISIONAL_WEIGHTS) & STRUCTURAL_EDGES
    assert weighted_structural == {"GPLink", "Contains"}
    assert all(PROVISIONAL_WEIGHTS[r].weight == WEIGHT_FLOOR for r in weighted_structural)


def test_weights_are_inside_the_documented_scale():
    for rel, w in PROVISIONAL_WEIGHTS.items():
        assert WEIGHT_FLOOR <= w.weight <= WEIGHT_CEILING, rel


def test_no_weight_is_zero():
    """Zero would claim a technique is literally invisible."""
    assert all(w.weight > 0 for w in PROVISIONAL_WEIGHTS.values())


def test_every_weight_has_a_rationale():
    for rel, w in PROVISIONAL_WEIGHTS.items():
        assert w.rationale.strip(), rel


def test_replication_outranks_membership():
    """Sanity anchor on the ordering. DCSync is the canonical AD detection;
    using a group you already belong to is not an action at all. If these two
    ever invert, the table has been edited into nonsense."""
    assert weight_of("DCSync") > weight_of("AdminTo") > weight_of("MemberOf")


def test_unknown_relationship_has_no_default_weight():
    with pytest.raises(KeyError, match="No risk weight"):
        weight_of("TotallyMadeUpEdge")


def test_sourcing_pass_is_under_way_but_incomplete():
    """Tracks the sourcing pass rather than asserting it hasn't started.

    The first entries now carry real citations. Most do not, so
    `require_sourced` must still refuse — the gate exists to stop a *mixed*
    table backing a reported number, which is exactly the state we are in now
    and the easiest one to forget about.
    """
    sourced = set(PROVISIONAL_WEIGHTS) - set(unsourced())
    assert sourced, "no weight is sourced; the pass has not started"
    assert set(unsourced()), "all weights sourced — update this test and the docs"
    assert {"GPLink", "Contains", "SpoofSIDHistory"} <= sourced


def test_require_sourced_blocks_reporting_while_provisional():
    with pytest.raises(ValueError, match="no source"):
        require_sourced()


def test_require_sourced_passes_once_sources_exist():
    from dataclasses import replace
    sourced = {rel: replace(w, source="T0000 (placeholder for this test only)")
               for rel, w in PROVISIONAL_WEIGHTS.items()}
    require_sourced(sourced)          # must not raise
    assert unsourced(sourced) == []


def test_static_cost_ignores_history(goad):
    """That is what makes it static. Stage 3's version has the same signature
    and does read the history, so the planners never have to change."""
    cost = static_cost_fn()
    ei = next(i for i, e in enumerate(goad.edges) if e.rel_type == "HasSession")
    assert cost(goad, ei, ()) == cost(goad, ei, (0, 1, 2))


def test_cost_matches_the_table(goad):
    cost = static_cost_fn()
    for ei, edge in enumerate(goad.edges):
        if edge.rel_type in TRAVERSABLE_EDGES:
            assert cost(goad, ei, ()) == PROVISIONAL_WEIGHTS[edge.rel_type].weight


def test_hops_to_targets_is_a_real_hop_count(goad, da_north):
    dist = hops_to_targets(goad, da_north, TRAVERSABLE_EDGES)
    for t in da_north:
        assert dist[t] == 0
    sp = dijkstra(goad, goad.entry_nodes(), da_north)
    assert dist[sp.nodes[0]] == sp.length


def test_hops_to_targets_omits_unreachable_nodes(goad, da_north):
    dist = hops_to_targets(goad, da_north, TRAVERSABLE_EDGES)
    # STANNIS is the fixture's dead end: reachable from the foothold, reaches
    # nothing itself.
    assert goad.index_of("U-STANNIS") not in dist


def test_dcsync_route_reaches_the_domain_object(goad, tier0):
    """The DCSync route is a real endpoint, and the target set now says so.

    `SVC_BACKUP -DCSync-> NORTH domain` is full domain compromise: replication
    rights on the domain don't require Domain Admins membership. When the target
    set was DA-groups-only this route dead-ended and the whole quiet branch of
    the fixture was unreachable — the target set was wrong, not the fixture.

    Note what this does *not* do: the domain object is reached by traversing
    DCSync onto it, not by walking `Contains` down from it. `Contains` is still
    excluded, and the route below is checked for it explicitly.
    """
    dist = hops_to_targets(goad, tier0, TRAVERSABLE_EDGES)
    assert goad.index_of("S-1-5-21-NORTH") in dist
    assert goad.index_of("U-SVC-BACKUP") in dist

    quiet = astar(goad, goad.entry_nodes(), tier0, static_cost_fn())
    replication = astar(goad, goad.entry_nodes(),
                        [goad.index_of("S-1-5-21-NORTH")], static_cost_fn())
    assert replication is not None
    replication.validate(goad)
    assert "Contains" not in replication.rel_types(goad)

    # The last hop is a replication edge, but not necessarily DCSync itself: the
    # fixture carries GetChanges / GetChangesAll / DCSync as three parallel
    # edges onto the domain, and the planner takes the cheapest. Asserting the
    # category rather than the name is the honest check — see
    # test_replication_edges_are_priced_independently for why that matters.
    assert category_of(replication.rel_types(goad)[-1]) == EdgeCategory.DOMAIN_REPLICATION
    # ... and it is a legitimate route, just not the cheapest way to any target
    assert quiet.cost <= replication.cost


def test_half_a_replication_right_is_not_domain_compromise(goad, tier0):
    """Replicating secrets needs both rights together, so neither half may be
    walked on its own.

    The fixture gives SVC_BACKUP all three edges onto the NORTH domain:
    `GetChanges`, `GetChangesAll`, and the composite `DCSync`. Before this was
    fixed the planner arrived at the domain across a single `GetChanges` (8.0),
    which is both cheaper than `DCSync` (9.0) and not actually sufficient —
    it claimed a capability the attacker had only half of.

    Only the composite is traversable now. That is BloodHound's own convention:
    it marks the two halves non-traversable and post-processes them into DCSync
    precisely to keep half-privilege paths out of results.
    """
    assert goad.index_of("U-SVC-BACKUP") in hops_to_targets(
        goad, tier0, DEFAULT_TRAVERSAL_SET)

    # all three edges are still present in the graph — nothing was deleted
    parallel = {e.rel_type for e in goad.out_edges("U-SVC-BACKUP")
                if e.target == goad.index_of("S-1-5-21-NORTH")}
    assert parallel == {"GetChanges", "GetChangesAll", "DCSync"}

    # ... but only the composite is walkable
    assert PARTIAL_RIGHT_EDGES.isdisjoint(DEFAULT_TRAVERSAL_SET)
    assert "DCSync" in DEFAULT_TRAVERSAL_SET

    route = astar(goad, goad.entry_nodes(),
                  [goad.index_of("S-1-5-21-NORTH")], static_cost_fn())
    assert route.rel_types(goad)[-1] == "DCSync"
    assert PARTIAL_RIGHT_EDGES.isdisjoint(route.rel_types(goad))


def test_partial_rights_cannot_reach_a_domain_alone():
    """The narrow version of the above, on a graph that has *only* half the
    right. Before the fix this returned a path; now the domain is unreachable,
    which is the correct answer."""
    from stealthpath.graph import AttackGraph, Node
    g = AttackGraph()
    g.add_node(Node("u", "HALF@LAB.LOCAL", "User", owned=True))
    g.add_node(Node("d", "LAB.LOCAL", "Domain"))
    g.add_edge("u", "d", "GetChanges")          # one right, not both
    assert astar(g, g.entry_nodes(), g.tier0_targets(), static_cost_fn()) is None

    g.add_edge("u", "d", "DCSync")              # now the composite exists
    assert astar(g, g.entry_nodes(), g.tier0_targets(), static_cost_fn()) is not None


def test_gpo_content_control_reaches_objects_only_under_the_expansion():
    """Pins the scoped GPO exception, same pattern as the DCSync case.

    Controlling a GPO's content really does reach every object the GPO applies
    to, but the route runs GPO -> OU -> object across two edges excluded by
    default. `with_gpo_expansion()` re-admits them for that chain only.
    """
    from stealthpath.ad_schema import GPO_EXPANSION_EDGES
    from stealthpath.synthetic import gpo_abuse

    g = gpo_abuse()
    sansa, desk = g.find(name="SANSA"), [g.index_of("C-DESK01")]

    # default rules: the policy chain is not walkable, so the object is safe
    assert dijkstra(g, sansa, desk) is None

    view = g.with_gpo_expansion()
    route = dijkstra(view, sansa, desk,
                     allowed_rel_types=DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)
    assert route is not None
    route.validate(view)
    assert route.rel_types(view) == ["GenericWrite", "GPLink", "Contains"]


def test_writegplink_alone_reaches_nothing():
    """THEON can attach a policy to the OU but controls no policy worth
    attaching, so the link right on its own buys him nothing.

    Note *why* this passes now, because the reason changed: `WriteGPLink` is in
    `PARTIAL_RIGHT_EDGES`, so it is globally non-traversable and never enters
    any traversal set. It is no longer the view's drop doing the work — that
    drop is retained as defence in depth but is now redundant. The assertion
    below checks the view specifically; the global rule is pinned by
    `test_writegplink_is_globally_non_traversable`.
    """
    from stealthpath.ad_schema import GPO_EXPANSION_EDGES
    from stealthpath.synthetic import gpo_abuse

    raw = gpo_abuse()
    theon_raw = raw.find(name="THEON")[0]
    assert "WriteGPLink" in {e.rel_type for e in raw.out_edges(theon_raw)}

    g = raw.with_gpo_expansion()
    allowed = DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES
    theon, desk = g.find(name="THEON"), [g.index_of("C-DESK01")]
    assert dijkstra(g, theon, desk, allowed_rel_types=allowed) is None

    # Specifically: not by landing on the OU and descending. Re-admitting
    # Contains out of an OU lets *any* arrival there walk into its contents, and
    # a link right is not control of what is linked.
    assert "WriteGPLink" not in {e.rel_type for e in g.edges}


def test_writegplink_into_a_domain_is_not_a_route():
    """**The case that actually mattered.**

    BloodHound permits a domain object as a `WriteGPLink` target, and domain
    objects are tier-0. So a single `WriteGPLink` edge used to be a one-hop
    route to full domain compromise in the *default* traversal set — nothing to
    do with the GPO view — and at 6.0 it was cheaper than DCSync at 9.0, so a
    cost-minimising planner would actively prefer it over the real thing.

    Linking a policy you do not control achieves nothing. There must be no route.
    """
    from stealthpath.graph import AttackGraph, Node

    g = AttackGraph()
    g.add_node(Node("u", "ATTACKER@LAB.LOCAL", "User", domain="LAB.LOCAL", owned=True))
    g.add_node(Node("d", "LAB.LOCAL", "Domain", domain="LAB.LOCAL"))
    g.add_edge("u", "d", "WriteGPLink")

    assert g.tier0_targets() == [g.index_of("d")]
    assert dijkstra(g, g.entry_nodes(), g.tier0_targets()) is None
    assert astar(g, g.entry_nodes(), g.tier0_targets(), static_cost_fn()) is None


def test_writegplink_is_globally_non_traversable():
    """Not a GPO-view special case: it is out of the default traversal set
    entirely, because it is never sufficient alone regardless of context."""
    from stealthpath.ad_schema import PARTIAL_RIGHT_EDGES
    assert "WriteGPLink" in PARTIAL_RIGHT_EDGES
    assert "WriteGPLink" not in DEFAULT_TRAVERSAL_SET
    assert "WriteGPLink" not in TRAVERSABLE_EDGES


def test_gpo_chain_does_not_depend_on_writegplink():
    """Excluding it must not break the real GPO route, which runs onto an
    already-linked GPO and never uses the link right."""
    from stealthpath.ad_schema import GPO_EXPANSION_EDGES
    from stealthpath.synthetic import gpo_abuse

    view = gpo_abuse().with_gpo_expansion()
    route = dijkstra(view, view.find(name="SANSA"), [view.index_of("C-DESK01")],
                     allowed_rel_types=DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)
    assert route.rel_types(view) == ["GenericWrite", "GPLink", "Contains"]


def test_gpo_expansion_does_not_reopen_the_contains_shortcut():
    """The exception must widen one chain, not the rule. `Contains` from a
    *Domain* is what rule 3 blocks, and it stays blocked here."""
    from stealthpath.ad_schema import GPO_EXPANSION_EDGES
    from stealthpath.synthetic import gpo_abuse

    view = gpo_abuse().with_gpo_expansion()
    allowed = DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES
    domain, da = [view.index_of("S-1-5-21-LAB")], [view.index_of("G-DA")]
    assert dijkstra(view, domain, da, allowed_rel_types=allowed) is None

    # ... and the same holds on the main fixture, whose Domain -Contains-> DA
    # edge is the original motivating case
    goad_view = goad_like().with_gpo_expansion()
    path = dijkstra(goad_view, goad_view.entry_nodes(), goad_view.tier0_targets(),
                    allowed_rel_types=allowed)
    assert "Contains" not in path.rel_types(goad_view)


def test_gpo_route_can_now_be_costed():
    """This test used to assert the opposite — that the GPO route was walkable
    but not costable, because `GPLink`/`Contains` had no weights. The sourcing
    pass fixed that, so it flips to assert the capability rather than the
    limitation.

    Both are at the floor: the priced act is the GPO write on the ACL edge, and
    charging for propagation as well would double-count it.
    """
    from stealthpath.ad_schema import GPO_EXPANSION_EDGES
    from stealthpath.risk import weight_of
    from stealthpath.synthetic import gpo_abuse

    assert weight_of("GPLink") == WEIGHT_FLOOR
    assert weight_of("Contains") == WEIGHT_FLOOR

    view = gpo_abuse().with_gpo_expansion()
    route = astar(view, view.find(name="SANSA"), [view.index_of("C-DESK01")],
                  static_cost_fn(),
                  allowed_rel_types=DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)
    assert route is not None
    assert route.rel_types(view) == ["GenericWrite", "GPLink", "Contains"]
    # 4.0 for the write, 0.2 for the propagation. Moved twice: 4.7 while
    # GenericWrite was an unsourced guess, 1.7 when it was derived from native
    # AD auditing alone, 4.2 once the EDR half of the baseline was included.
    assert route.cost == pytest.approx(4.2)


def test_acl_write_ordering_after_the_full_baseline_derivation():
    """**The registered flip fired, then un-fired. Both are recorded here.**

    Sequence, because the intermediate state was wrong in an instructive way:

    1. Unsourced guesses put the ACL writes at 4.5-5.0.
    2. Deriving from native AD auditing alone gave 1.5 - no SACL on ordinary
       objects, so no 5136, so nothing recorded. That fired the flip registered
       in the audit doc's cross-check table: ACL writes became the quietest
       actions in the schema, below ticket forgery and delegation abuse.
    3. That derivation used **half the baseline.** The baseline also assumes
       EDR/Sysmon-class telemetry, which needs no SACL. A named shipped rule
       (posh_ps_powerview_malicious_commandlets.yml) fires on script-block
       logging for the PowerView cmdlets that perform these writes. Including
       that half puts the base back at 4.0 and **un-fires the flip.**

    The near-miss is the point. Step 2 would have produced a striking
    counterintuitive headline - "directory modification is quieter than ticket
    forgery" - that was an artifact of an incomplete derivation rather than a
    finding. It survived one review pass before being caught.

    The 1.5 figure is not discarded: it is preserved as the
    `tooling_is_native_ldap` conditional, because it is the correct answer for
    an attacker who avoids recognisable tooling.
    """
    from stealthpath.risk import PROVISIONAL_WEIGHTS, weight_of

    acl = ["WriteDacl", "WriteOwner", "GenericAll", "GenericWrite"]
    for rel in acl:
        # back above the forgery edge, as before step 2
        assert weight_of(rel) > weight_of("SpoofSIDHistory"), rel
        # the native-LDAP path is still the quietest thing in the table
        assert PROVISIONAL_WEIGHTS[rel].conditional["tooling_is_native_ldap"]             < weight_of("SpoofSIDHistory"), rel
        # tier-zero always outranks the base, since 5136 fires on top of EDR
        assert PROVISIONAL_WEIGHTS[rel].conditional["target_is_tier_zero"]             > weight_of(rel), rel

    # all four base weights are equal: the EDR signal is the same regardless of
    # which right is being written. This is why SAMWELL's result did not return.
    assert len({weight_of(r) for r in acl}) == 1

    # chain length separates them only where directory auditing exists
    tz = {r: PROVISIONAL_WEIGHTS[r].conditional["target_is_tier_zero"] for r in acl}
    assert tz["WriteOwner"] > tz["WriteDacl"] > tz["GenericWrite"]


def test_rbcd_needs_a_principal_that_can_actually_wield_it():
    """Shape B from the audit: the right is real, but abusing it needs an
    SPN-bearing account you control. Same right, three holders, different
    answers."""
    from stealthpath.synthetic import rbcd_abuse

    g = rbcd_abuse(machine_account_quota=0)
    assert len(g.edges) == 3                       # all three rights are present

    gated = g.with_preconditions()
    sources = {gated.node(e.source).name for e in gated.edges}
    assert not any(n.startswith("PLAIN") for n in sources)   # no SPN, no quota
    assert any(n.startswith("SVC_WEB") for n in sources)     # user with an SPN
    assert any(n.startswith("WKS01") for n in sources)       # computers have one


def test_machine_account_quota_makes_the_rbcd_precondition_moot():
    """Where anyone may create a computer account, everyone can obtain an SPN,
    so the precondition stops filtering anything."""
    from stealthpath.synthetic import rbcd_abuse

    gated = rbcd_abuse(machine_account_quota=10).with_preconditions()
    assert len(gated.edges) == 3


def test_preconditions_view_leaves_unrelated_edges_alone(goad):
    """The view must narrow one specific capability, not quietly prune the
    graph. `goad_like` has no RBCD edges, so nothing should change."""
    assert len(goad.with_preconditions().edges) == len(goad.edges)


def test_tier0_targets_covers_groups_and_domains(goad):
    """One canonical target set. Previously the CLI and each test decided this
    independently, which is how the DA-group-only gap survived as long as it
    did."""
    tier0 = goad.tier0_targets()
    kinds = {goad.nodes[i].kind for i in tier0}
    assert kinds == {"Group", "Domain"}
    assert goad.index_of("G-DA-NORTH") in tier0
    assert goad.index_of("S-1-5-21-NORTH") in tier0


def test_domain_object_is_a_target_not_a_containment_shortcut(goad, tier0):
    """The domain object being a target must not smuggle `Contains` back in.
    Domain -Contains-> DA group still isn't walkable; the domain is simply an
    endpoint of its own."""
    path = astar(goad, goad.entry_nodes(), tier0, static_cost_fn())
    assert "Contains" not in path.rel_types(goad)
    assert not (set(path.rel_types(goad)) & STRUCTURAL_EDGES)


def test_finds_a_path_to_domain_admins(goad, da_north):
    path = WeightedAStarPlanner().plan(goad, goad.entry_nodes(), da_north)
    assert path is not None
    assert path.nodes[-1] in da_north
    path.validate(goad)


def test_agrees_with_weighted_dijkstra_on_cost(goad, da_north):
    """The correctness cross-check. A* and Dijkstra optimise the same thing, so
    the *cost* must match exactly. The route may differ where costs tie, and
    that is fine."""
    cost = static_cost_fn()
    a = astar(goad, goad.entry_nodes(), da_north, cost)
    d = dijkstra(goad, goad.entry_nodes(), da_north, cost)
    assert a.cost == pytest.approx(d.cost)


@pytest.mark.parametrize("seed", [0, 1, 2, 7, 42])
def test_agrees_with_weighted_dijkstra_on_random_graphs(seed):
    """One fixture agreeing could be luck. Several topologies could not."""
    g = random_ad(seed=seed)
    cost = static_cost_fn()
    src, dst = g.entry_nodes(), g.find(name="DOMAIN ADMINS", kind="Group")
    a = astar(g, src, dst, cost)
    d = dijkstra(g, src, dst, cost)
    assert (a is None) == (d is None)
    if a is not None:
        a.validate(g)
        assert a.cost == pytest.approx(d.cost)


def test_weighted_route_differs_from_shortest_path(goad, da_north):
    """**The check the plan asks for by name.** If the weighted planner always
    returns plain shortest path's route, the weights are decorative and every
    comparison built on them is measuring nothing. Do not relax this.

    What actually changes on this fixture: plain shortest path opens with
    `CanRDP` (3.5) because it is one hop. The weighted planner pays two extra
    hops to open with `MemberOf, MemberOf, ReadLAPSPassword` (2.7 combined)
    instead. Both routes finish through the delegation shortcut — not because
    the weights failed to notice delegation is expensive, but because every
    delegation-free route to this target costs *more*. Optimal, not lazy;
    `test_weighted_route_is_actually_quieter` is what pins that down.
    """
    src = goad.entry_nodes()
    plain = dijkstra(goad, src, da_north)
    quiet = astar(goad, src, da_north, static_cost_fn())

    assert plain.rel_types(goad) != quiet.rel_types(goad)
    assert quiet.length > plain.length              # bought quiet with hops
    assert plain.rel_types(goad)[0] == "CanRDP"     # the loud one-hop opener
    assert quiet.rel_types(goad)[0] == "MemberOf"   # ... traded away


def test_random_graphs_offer_more_than_one_route_shape():
    """`random_ad` must not hand out the same route on every seed.

    It used to. `ensure_path=True` bolted a fixed
    `MemberOf -> AdminTo -> HasSession -> MemberOf` chain onto every graph, and
    because every `groups[1:]` slice excluded Domain Admins, that chain was the
    *only* route to the target — not merely the cheapest. Both planners returned
    it on 8 of 12 seeds and "agreed", which reads exactly like a result about
    the planners and was entirely an artifact of the generator.

    This asserts variety, not disagreement. Manufacturing planner disagreement
    by shaping the generator would be the same mistake in the other direction:
    where the shortest route genuinely is also the quietest, both planners
    *should* return it, and a generator tuned until they differ would be
    reporting its own tuning back at us.
    """
    shapes, costs = set(), set()
    for seed in range(12):
        g = random_ad(seed=seed)
        src, dst = g.entry_nodes(), g.find(name="DOMAIN ADMINS", kind="Group")
        route = astar(g, src, dst, static_cost_fn())
        assert route is not None, f"seed {seed} unreachable"
        shapes.add(tuple(route.rel_types(g)))
        costs.add(round(route.cost, 1))

    # was 2 and 2 before the fix
    assert len(shapes) >= 6, f"only {len(shapes)} distinct route shapes across 12 seeds"
    assert len(costs) >= 5, f"only {len(costs)} distinct route costs across 12 seeds"


def test_ensure_path_is_a_fallback_not_a_construction():
    """The guarantee must be "a route exists", not "here is the route". It only
    fires where the random structure genuinely failed to connect."""
    from stealthpath.synthetic import _reaches

    unreachable = []
    for seed in range(30):
        g = random_ad(seed=seed, ensure_path=False)
        if not _reaches(g, g.entry_nodes(), g.index_of("G-DA")):
            unreachable.append(seed)
    # some seeds connect naturally, some don't — if *every* seed needed the
    # fallback we would be back to a constructed route on every graph
    assert 0 < len(unreachable) < 30
    for s in unreachable[:5]:
        g = random_ad(seed=s)
        assert _reaches(g, g.entry_nodes(), g.index_of("G-DA")), "fallback failed to connect"


def test_plain_shortest_path_ties_are_broken_blind_to_risk(goad, tier0, da_north):
    """Pins a measurement artifact that would otherwise quietly inflate the
    headline gap. Read this before any number from `cli compare` gets written up.

    Plain shortest path has two routes of *identical* hop count to a tier-0
    target and no way to tell them apart, because it does not look at risk. It
    picks by tie-break (deterministic, by edge index) — and on this fixture the
    tie-break happens to land on the louder of the two.

    So part of the plain-vs-weighted gap is luck of tie ordering rather than the
    baseline being detection-blind. That is not wrong — a detection-blind
    planner genuinely has no basis to choose — but it means the gap is sensitive
    to edge insertion order, and a fixture edit that reorders edges could move
    the headline number without anything real changing.

    If a future change makes the baseline deterministic *on risk* as well, this
    test should fail and be removed deliberately.
    """
    from stealthpath.risk import weight_of

    def risk(p):
        return sum(weight_of(r) for r in p.rel_types(goad))

    src = goad.entry_nodes()
    chosen = dijkstra(goad, src, tier0)
    alternative = dijkstra(goad, src, da_north)

    assert chosen.length == alternative.length      # a genuine tie on hops
    assert risk(chosen) != risk(alternative)        # ... but not on risk
    assert chosen.nodes[-1] != alternative.nodes[-1]
    # the tie-break landed on the louder route, purely by edge ordering
    assert risk(chosen) > risk(alternative)


def test_weighted_route_is_actually_quieter(goad, da_north):
    """The other half of the previous test: different is not automatically
    better. Score both routes with the same weights and check the weighted one
    wins on its own objective."""
    cost = static_cost_fn()

    def total_risk(path):
        return sum(cost(goad, ei, ()) for ei in path.edges)

    src = goad.entry_nodes()
    plain = dijkstra(goad, src, da_north)
    quiet = astar(goad, src, da_north, cost)
    assert total_risk(quiet) < total_risk(plain)


def test_is_deterministic(goad, da_north):
    runs = {astar(goad, goad.entry_nodes(), da_north, static_cost_fn()).nodes
            for _ in range(5)}
    assert len(runs) == 1


def test_returns_none_when_target_unreachable(goad):
    stannis = goad.find(name="STANNIS")
    assert astar(goad, goad.entry_nodes(), stannis, static_cost_fn()) is not None
    # ... but nothing leads back out of the dead end
    assert astar(goad, stannis, goad.find(name="DOMAIN ADMINS@NORTH"),
                 static_cost_fn()) is None


def test_trivial_path_when_source_is_target(goad, da_north):
    path = astar(goad, da_north, da_north, static_cost_fn())
    assert path.length == 0
    assert path.cost == 0.0


def test_structural_edges_are_not_traversed(goad, da_north):
    path = astar(goad, goad.entry_nodes(), da_north, static_cost_fn())
    assert not (set(path.rel_types(goad)) & STRUCTURAL_EDGES)


def test_negative_costs_rejected(goad, da_north):
    def bad(graph, ei, history):
        return -1.0
    with pytest.raises(ValueError, match="negative cost"):
        astar(goad, goad.entry_nodes(), da_north, bad)


def test_max_hops_bounds_the_search(goad, da_north):
    assert astar(goad, goad.entry_nodes(), da_north, static_cost_fn(),
                 max_hops=1) is None


def test_shares_the_path_type_with_planner_one(goad, da_north):
    """One Path type for all planners — the evaluation code must not need to
    know which planner produced a route."""
    from stealthpath.planners.base import Path
    src = goad.entry_nodes()
    plain = dijkstra(goad, src, da_north)
    quiet = astar(goad, src, da_north, static_cost_fn())
    assert isinstance(plain, Path) and isinstance(quiet, Path)
    assert quiet.planner == "weighted-astar"


def test_reuses_the_shared_cost_function_signature(goad, da_north):
    """Both planners must accept the identical callable, or they are not
    comparable."""
    cost = static_cost_fn()
    assert dijkstra(goad, goad.entry_nodes(), da_north, cost) is not None
    assert astar(goad, goad.entry_nodes(), da_north, cost) is not None
