"""Where a route starts and what counts as arriving, on a directory we have
never seen.

`AttackGraph.tier0_targets()` finds Domain Admins by looking for a group called
`DOMAIN ADMINS`. That is what makes the reference demo work and exactly what
fails on somebody else's directory: rename the group, run a non-English
install, or upload a forest whose privileged groups are nested custom ones, and
the target set comes back holding only the domain objects -- or nothing. A
planner handed an empty target set does not fail loudly. It reports "no route",
which reads like a finding.

## The rule, in priority order

**Well-known RIDs first, names last.** A RID is part of the SID and survives
renaming and localisation; `DOMAIN ADMINS` is a display string. The reference
collection happens to agree on both, which is what
`test_derivation_agrees_with_tier0_targets_on_the_frozen_graph` pins -- the
derivation must not move a published number while it is being made general.

Every candidate carries the `reason` it was selected and a `confidence`, and
both reach the UI. A target set is a claim about what "compromised" means, and
if the tool picked it rather than the user, the user needs to see the argument.

## Domain controllers are opt-in, and that is unchanged

`tier0_targets()` documents that DC computer objects belong in the target set --
admin on a DC is domain compromise -- and leaves them out because nothing in the
graph reliably marked one. `props.isdc` does mark one, on both the frozen graph
and anything `dashboard.bloodhound_parser` produces, so the blocker is gone.
They still default to **off**, because switching them on would add three targets
to the reference graph and every route, gap and figure quoted in
`docs/findings.md` is measured without them. Turning them on is a decision with
a re-measurement attached, not a default.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Sequence

from .ad_schema import DEFAULT_TRAVERSAL_SET
from .graph import AttackGraph

__all__ = [
    "Candidate", "derive_targets", "derive_sources", "target_indices",
    "reaching_set",
    "TIER_ZERO_GROUP_RIDS", "WELL_KNOWN_TARGET_NAMES",
]

# RID -> what the group is, for the reason string. Renaming a group does not
# change its RID, and a German or Japanese install has different names and the
# same numbers.
TIER_ZERO_GROUP_RIDS: dict[str, str] = {
    "512": "Domain Admins",
    "519": "Enterprise Admins",
    "518": "Schema Admins",
    "544": "Builtin Administrators",
    "516": "Domain Controllers",
    "498": "Enterprise Read-only Domain Controllers",
    "521": "Read-only Domain Controllers",
}

# Only the two that `tier0_targets()` already uses. This is the fallback for a
# directory whose privileged groups somehow carry no well-known RID, not a
# second opinion on the RID table.
WELL_KNOWN_TARGET_NAMES = ("DOMAIN ADMINS", "ENTERPRISE ADMINS")

# The subset that counts as *arriving*. Domain Controllers and Builtin
# Administrators are tier-0 memberships, but a route that ends at the group
# object has not yet done anything with it, and admitting them would make
# several two-hop routes look like full compromise.
_ARRIVAL_RIDS = ("512", "519")


@dataclass(frozen=True)
class Candidate:
    """One node the tool proposes, with the argument for proposing it."""

    index: int
    name: str
    kind: str
    reason: str
    """Human-readable: "well-known RID 512 (Domain Admins)"."""

    confidence: str
    """`rid` > `structure` > `name` > `marked`.

    Ordered by how hard the signal is to get wrong, not by how likely it is to
    be right. A well-known RID is a fact about the SID; a BloodHound high-value
    marking is whatever somebody last clicked in the UI.
    """


def _rid(object_id: str) -> str:
    return object_id.rsplit("-", 1)[-1]


def derive_targets(graph: AttackGraph, include_domain_controllers: bool = False,
                   ) -> list[Candidate]:
    """Nodes that count as full domain compromise on this graph.

    Deterministic and deduplicated: a node selected by two signals keeps the
    stronger one, so the reason shown is the best reason, and the order is by
    node index so two runs agree.
    """
    found: dict[int, Candidate] = {}

    def offer(index: int, reason: str, confidence: str) -> None:
        rank = ("rid", "structure", "name", "marked")
        existing = found.get(index)
        if existing is not None and rank.index(existing.confidence) <= rank.index(confidence):
            return
        node = graph.nodes[index]
        found[index] = Candidate(index, node.name, node.kind, reason, confidence)

    for i, node in enumerate(graph.nodes):
        if node.kind == "Domain":
            # The domain object is a target in its own right: replication
            # rights live on it, not in any group, so an attacker holding them
            # has won without ever touching Domain Admins.
            offer(i, "domain object (replication rights live here)", "structure")
            continue
        if node.kind == "Group":
            rid = _rid(node.id)
            if rid in _ARRIVAL_RIDS:
                offer(i, f"well-known RID {rid} ({TIER_ZERO_GROUP_RIDS[rid]})", "rid")
                continue
            upper = node.name.upper()
            if any(w in upper for w in WELL_KNOWN_TARGET_NAMES):
                offer(i, f"well-known name match ({node.name})", "name")
        if include_domain_controllers and node.kind == "Computer" \
                and node.props.get("isdc") is True:
            offer(i, "domain controller (props.isdc)", "structure")

    if not found:
        # Nothing structural matched. Fall back to whatever the collection
        # marked, and say so -- an empty target set would be reported as
        # "no route", which is indistinguishable from a hardened directory.
        for i in graph.find(high_value=True):
            offer(i, "marked high-value in the collection", "marked")

    return [found[i] for i in sorted(found)]


def reaching_set(graph: AttackGraph, targets: Sequence[int],
                 allowed_rel_types: Iterable[str] | None = None) -> set[int]:
    """Every node from which some target is reachable at all.

    A reverse BFS, ignoring cost and the hop cap, so it is an over-approximation
    of "a route exists from here" and never excludes a start that has one.

    It exists because the first thing a user sees on an upload is the default
    start, and on a real collection most accounts cannot reach Domain Admin. The
    reference collection is an honest example: the alphabetically-first session
    holder is `HODOR`, which has no route at all, so the page opened on "No route
    reported" for a graph containing two perfectly good ones.
    """
    allowed = set(DEFAULT_TRAVERSAL_SET if allowed_rel_types is None
                  else allowed_rel_types)
    seen = set(targets)
    frontier = list(seen)
    while frontier:
        nxt = []
        for node in frontier:
            for edge in graph.in_edges(node):
                if edge.rel_type in allowed and edge.source not in seen:
                    seen.add(edge.source)
                    nxt.append(edge.source)
        frontier = nxt
    return seen - set(targets)


def derive_sources(graph: AttackGraph, limit: int = 50) -> list[Candidate]:
    """Plausible entry points, best first.

    Owned nodes are the real answer when the collection has any; everything
    below that is a *suggestion list for a human to choose from*, not a claim
    that these accounts are compromised. Ordered so the useful ones are near the
    top of a dropdown: a session on a machine beats an ordinary enabled account.
    """
    found: dict[int, Candidate] = {}

    def offer(index: int, reason: str, confidence: str) -> None:
        if index not in found:
            node = graph.nodes[index]
            found[index] = Candidate(index, node.name, node.kind, reason, confidence)

    for i in graph.find(owned=True):
        offer(i, "marked owned in the collection", "marked")
    if found:
        return [found[i] for i in sorted(found)]

    # No owned marking, which is the normal case for a fresh export. Rank by
    # how much a foothold there would actually buy.
    has_session = {e.target for e in graph.edges if e.rel_type == "HasSession"}
    for i in sorted(has_session):
        offer(i, "has a session on a collected machine", "structure")

    for i, node in enumerate(graph.nodes):
        if len(found) >= limit:
            break
        if node.kind != "User" or node.props.get("enabled") is False:
            continue
        # An already-privileged account is a poor demonstration of a route: it
        # starts at the destination. Offered last rather than hidden.
        if node.props.get("admincount") is True:
            continue
        offer(i, "enabled, non-privileged user account", "name")

    return [found[i] for i in sorted(found)][:limit]


def target_indices(graph: AttackGraph, include_domain_controllers: bool = False,
                   ) -> list[int]:
    """`derive_targets` reduced to the index list the planners take."""
    return [c.index for c in derive_targets(graph, include_domain_controllers)]
