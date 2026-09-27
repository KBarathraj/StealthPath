"""The defender-side projections: exposure, detection posture, choke points.

These answer a SOC analyst's questions from the same graph and the same weight
table the attacker-side planners use. Nothing here introduces a new cost model
or a new traversal rule; if a test in this file starts asserting a weight, the
assertion belongs in `test_weight_invariants.py` instead.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from stealthpath.defend import (
    BLIND, CONDITIONAL, COVERED, UNVERIFIED, choke_points, detection_summary,
    exposure_report, route_detection,
)
from stealthpath.graph import AttackGraph
from stealthpath.risk import PROVISIONAL_WEIGHTS
from stealthpath.targets import derive_targets

ROOT = Path(__file__).resolve().parent.parent
FROZEN = ROOT / "data" / "goad_graph.json"

pytestmark = pytest.mark.skipif(not FROZEN.exists(),
                                reason="frozen graph is not present")


@pytest.fixture(scope="module")
def graph():
    return AttackGraph.load(FROZEN)


# --------------------------------------------------------------------------
# detection posture
# --------------------------------------------------------------------------

def test_unverified_is_not_collapsed_into_blind():
    """The distinction the whole sourcing discipline exists to preserve.

    `blind` means both telemetry halves were checked and neither found
    anything — a finding about the reader's coverage. `unverified` means nobody
    checked — a gap in this tool. An analyst acting on the first writes a rule;
    acting on a mislabelled second they write a rule for something a shipped
    Sigma rule may already catch.
    """
    unsourced = next((r for r, w in PROVISIONAL_WEIGHTS.items() if not w.sourced),
                     None)
    if unsourced is None:
        pytest.skip("every weight is sourced, so there is nothing to misreport")
    assert route_detection([unsourced])[0].visibility == UNVERIFIED


def test_a_hop_with_both_halves_empty_is_blind():
    """`MemberOf` is the honest example: using a group you already hold emits
    nothing in either half, and that is recorded rather than assumed."""
    hop = route_detection(["MemberOf"])[0]
    assert hop.sourced
    assert hop.visibility == BLIND
    assert hop.technique is None


def test_a_hop_with_a_named_endpoint_rule_is_covered():
    hop = route_detection(["HasSession"])[0]
    assert hop.visibility == COVERED
    assert hop.technique == "T1003.001"
    assert "sigma" in (hop.source or "").lower()


def test_sacl_only_hops_are_conditional_not_covered():
    """A weight resting on SACL auditing alone is silent on an ordinary object.

    The baseline grants SACLs on tier-zero objects only, so reporting these as
    `covered` would promise an event that a real directory may never emit.
    """
    conditional = [r for r in PROVISIONAL_WEIGHTS
                   if route_detection([r])[0].visibility == CONDITIONAL]
    for rel in conditional:
        hop = route_detection([rel])[0]
        assert hop.native == "native_ad_sacl"
        assert hop.endpoint == "endpoint_none_found"


def test_detection_summary_counts_every_hop_exactly_once():
    route = ["SQLAdmin", "HasSession", "MemberOf", "WriteDacl"]
    summary = detection_summary(route)
    assert summary["hops"] == len(route)
    assert sum(summary["counts"].values()) == len(route)
    assert summary["blind_hops"] == summary["counts"][BLIND]


def test_techniques_are_deduplicated_but_ordered():
    """A route using one technique twice is still one thing to hunt for."""
    summary = detection_summary(["HasSession", "SQLAdmin", "HasSession"])
    assert summary["techniques"] == ["T1003.001", "T1505.003"]


# --------------------------------------------------------------------------
# exposure
# --------------------------------------------------------------------------

def test_exposure_ranks_the_closest_account_first(graph):
    rows = exposure_report(graph)
    reachable = [e for e in rows if e.reachable]
    assert reachable
    costs = [e.static_cost for e in reachable]
    assert costs == sorted(costs), "exposure must be cheapest-first"
    assert reachable[0].hops is not None


def test_exposure_excludes_accounts_that_are_already_tier_zero(graph):
    """An account that *is* a Domain Admin is not an exposure finding.

    Left in, they fill the top of the list at zero cost and push the accounts
    somebody can act on off the screen.
    """
    rows = exposure_report(graph)
    for e in rows:
        node = graph.nodes[e.index]
        assert node.props.get("admincount") is not True
        assert not node.high_value


def test_exposure_reports_unreachable_accounts_rather_than_hiding_them(graph):
    """"This account cannot reach Domain Admin" is an answer, not an absence."""
    rows = exposure_report(graph)
    assert any(not e.reachable for e in rows)
    for e in rows:
        if not e.reachable:
            assert e.hops is None and e.static_cost is None and e.first_hop is None


def test_exposure_first_hop_is_a_real_outgoing_relationship(graph):
    """`first_step` is what an analyst looks for in the logs next, so it has to
    be an edge that actually leaves the account."""
    view = graph.with_gpo_expansion()
    for e in exposure_report(graph)[:10]:
        if not e.reachable:
            continue
        outgoing = {edge.rel_type for edge in view.out_edges(e.index)}
        assert e.first_hop in outgoing


def test_exposure_is_deterministic(graph):
    a = [(e.name, e.hops, e.static_cost, e.first_hop) for e in exposure_report(graph)]
    b = [(e.name, e.hops, e.static_cost, e.first_hop) for e in exposure_report(graph)]
    assert a == b


# --------------------------------------------------------------------------
# choke points
# --------------------------------------------------------------------------

def test_choke_points_are_ranked_with_actionable_rows_first(graph):
    """A domain controller's `DCSync` cuts the most accounts and cannot be
    revoked. Ranking it above a real misconfiguration would hand an analyst a
    work item that does not exist."""
    rows = choke_points(graph, top=10)
    assert rows
    actionable = [i for i, c in enumerate(rows) if c.actionable]
    structural = [i for i, c in enumerate(rows) if not c.actionable]
    if actionable and structural:
        assert max(actionable) < min(structural)


def test_a_domain_controller_replication_edge_carries_a_caveat(graph):
    """Measured on the reference collection: the DC's DCSync edge cuts 29% of
    accounts, which is true and is not a remediation."""
    rows = choke_points(graph, top=50)
    dcsync = [c for c in rows if c.rel_type == "DCSync"]
    for c in dcsync:
        assert not c.actionable
        assert "not revocable" in c.caveat


def test_removing_a_listed_choke_point_really_does_cut_that_many(graph):
    """The claim is falsifiable, so it is checked rather than trusted.

    Rebuilds reachability with the named edge dropped and counts the accounts
    that lose it, independently of the function that produced the ranking.
    """
    view = graph.with_gpo_expansion()
    targets = {c.index for c in derive_targets(view)}
    allowed = {e.rel_type for e in view.edges}

    def reaching(banned: int | None) -> set[int]:
        seen, frontier = set(targets), list(targets)
        while frontier:
            nxt = []
            for node in frontier:
                for ei in view._in[node]:            # noqa: SLF001
                    if ei == banned:
                        continue
                    edge = view.edges[ei]
                    if edge.rel_type not in allowed or edge.source in seen:
                        continue
                    seen.add(edge.source)
                    nxt.append(edge.source)
            frontier = nxt
        return seen

    top = choke_points(graph, top=1)[0]
    before = reaching(None) - targets
    after = reaching(top.edge_index) - targets
    cut = sum(1 for i in (before - after)
              if view.nodes[i].kind.lower() == "user")
    assert cut == top.accounts_cut


def test_choke_points_are_deterministic(graph):
    a = [(c.rel_type, c.source_name, c.accounts_cut) for c in choke_points(graph)]
    b = [(c.rel_type, c.source_name, c.accounts_cut) for c in choke_points(graph)]
    assert a == b
