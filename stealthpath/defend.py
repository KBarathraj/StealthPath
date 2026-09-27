"""The defender's three questions, answered from the same graph and the same
weight table the attacker-side planners use.

The planners answer "what is the cheapest route to Domain Admin". That is a red
team's question. A SOC analyst holding an alert has three different ones, and
none of them is served by a single route:

1. **"We got an alert on account X. How bad is this?"** -> `exposure_report`
   ranks every account by how close it is to a tier-0 target.
2. **"What would we actually have seen?"** -> `route_detection` maps each hop to
   its ATT&CK technique, its named Sigma rule, and the telemetry it depends on.
3. **"What do we fix first?"** -> `choke_points` ranks single relationships by
   how many accounts lose all access to tier-0 when that one edge is removed.

## The detection data was already here and was not being shown

`RiskWeight` has carried `technique`, `source` and `channels` since Stage 2,
because the weights had to be sourced before they could back a number. Nothing
displayed them. Every hop on every route already knows its ATT&CK ID and the
SigmaHQ rule behind its price; this module is mostly the projection that makes
that visible.

## Blind, conditional, covered -- and the fourth one that matters most

`channels` records one answer per telemetry half: native AD auditing, and
endpoint/EDR. `*_NONE_FOUND` means the half was checked and nothing was found.
That makes a genuinely new defensive number computable: a hop where **both**
halves came back empty is one an attacker can take and you will not see.

    covered      a default-audit event or a named endpoint rule fires
    conditional  only native SACL auditing catches it, and the baseline assumes
                 SACLs on tier-zero objects only -- so on an ordinary object,
                 this is blind
    blind        both halves checked, neither found anything
    unverified   the weight is not sourced, so nobody checked

**`unverified` is not a quiet `blind`.** The whole point of the sourcing
discipline is that silence and absence are different, and collapsing them here
would undo it: `blind` is a finding about your telemetry, `unverified` is a gap
in ours. A SOC analyst acting on "blind" will go write a rule; acting on a
mislabelled "unverified" they would go write a rule for a technique that a
shipped Sigma rule may already cover.

## Why exposure uses the static model and the route panel does not

`exposure_report` runs one reverse Dijkstra over static weights and prices every
account in the directory at once. The route panel runs the exact history-aware
search for a single start. They will disagree slightly, because the history
model charges more for reusing a technique, and that is stated wherever the
number is shown rather than reconciled away.

The alternative -- running the exact history-aware search once per account -- is
correct and unusable: it is a separate search per start, and a triage list is
worthless if it takes an hour. Ranking is what this is for; the exact figure for
the one account that matters comes from the route panel.
"""

from __future__ import annotations

import heapq
from dataclasses import dataclass
from typing import Iterable, Sequence

from .ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES, category_of
from .graph import AttackGraph
from .risk import (
    ENDPOINT_NONE_FOUND, ENDPOINT_RULE, NATIVE_DEFAULT, NATIVE_NONE_FOUND,
    NATIVE_SACL, PROVISIONAL_WEIGHTS, weight_of,
)
from .targets import derive_targets

__all__ = [
    "HopDetection", "Exposure", "ChokePoint",
    "route_detection", "detection_summary", "exposure_report", "choke_points",
    "COVERED", "CONDITIONAL", "BLIND", "UNVERIFIED", "TRAVERSAL",
]

COVERED = "covered"
CONDITIONAL = "conditional"
BLIND = "blind"
UNVERIFIED = "unverified"

TRAVERSAL = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)
"""The view every reported route runs on, so exposure is measured on the same
edges a route could actually use."""


# --------------------------------------------------------------------------
# 2. what would we have seen
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class HopDetection:
    """One hop's detection posture."""

    rel_type: str
    weight: float | None
    technique: str | None
    """ATT&CK technique ID, where one describes this step. `None` is a real
    answer for `MemberOf` -- using a group you already hold is not a technique."""

    source: str | None
    visibility: str
    native: str
    endpoint: str
    sourced: bool

    @property
    def is_blind(self) -> bool:
        return self.visibility == BLIND

    def headline(self) -> str:
        """One line for a ticket."""
        tech = f"{self.technique} " if self.technique else ""
        return f"{self.rel_type} — {tech}{self.visibility}"


def _classify(channels: Sequence[str], sourced: bool) -> tuple[str, str, str]:
    """`(visibility, native, endpoint)` from a weight's declared channels."""
    if not sourced or not channels:
        return UNVERIFIED, "unchecked", "unchecked"

    native = next((c for c in channels if c.startswith("native_")), NATIVE_NONE_FOUND)
    endpoint = next((c for c in channels if c.startswith("endpoint_")),
                    ENDPOINT_NONE_FOUND)

    if endpoint == ENDPOINT_RULE or native == NATIVE_DEFAULT:
        visibility = COVERED
    elif native == NATIVE_SACL:
        # Only caught by object-level auditing, and this project's baseline
        # grants SACLs on tier-zero objects only. On an ordinary object this is
        # blind in practice, which is why it is not folded into `covered`.
        visibility = CONDITIONAL
    else:
        visibility = BLIND
    return visibility, native, endpoint


def route_detection(route: Sequence[str]) -> list[HopDetection]:
    """One `HopDetection` per hop, in route order."""
    out: list[HopDetection] = []
    for rel in route:
        w = PROVISIONAL_WEIGHTS.get(rel)
        sourced = bool(w and w.sourced)
        channels = tuple(w.channels) if w else ()
        visibility, native, endpoint = _classify(channels, sourced)
        out.append(HopDetection(
            rel_type=rel,
            weight=weight_of(rel) if w else None,
            technique=w.technique if w else None,
            source=w.source if w else None,
            visibility=visibility,
            native=native,
            endpoint=endpoint,
            sourced=sourced,
        ))
    return out


def detection_summary(route: Sequence[str]) -> dict[str, object]:
    """Route-level detection posture, for the panel and for export.

    `blind_hops` is the number a SOC analyst should act on: steps this route
    takes that no rule in the baseline catches.
    """
    hops = route_detection(route)
    counts = {k: sum(1 for h in hops if h.visibility == k)
              for k in (COVERED, CONDITIONAL, BLIND, UNVERIFIED)}
    techniques = [h.technique for h in hops if h.technique]
    return {
        "hops": len(hops),
        "counts": counts,
        "blind_hops": counts[BLIND],
        "conditional_hops": counts[CONDITIONAL],
        # Deduplicated, order preserved: a route that uses WriteDacl twice is
        # still one technique to hunt for.
        "techniques": list(dict.fromkeys(techniques)),
        "quietest_hop": min(hops, key=lambda h: h.weight if h.weight is not None
                            else float("inf")).rel_type if hops else None,
        "detail": hops,
    }


# --------------------------------------------------------------------------
# 1. how bad is this account
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class Exposure:
    """One principal's distance to tier-0."""

    index: int
    name: str
    kind: str
    hops: int | None
    static_cost: float | None
    """Cost under the **static** weight model -- see the module docstring. `None`
    when no route exists at all."""

    reachable: bool
    first_hop: str | None
    """The relationship the cheapest route leaves on. The single most useful
    field during triage: it says what to look for in the logs next."""

    target_name: str | None


def _reverse_dijkstra(graph: AttackGraph, targets: Sequence[int],
                      allowed: Iterable[str],
                      ) -> tuple[list[float], list[int], list[int | None]]:
    """Cheapest static cost from every node to the nearest target, in one pass.

    Reverse traversal: edges run source -> target, so reaching a target from a
    node means walking `in_edges` backwards from the target set. One run prices
    the whole directory, which is what makes a triage list possible at all.
    """
    allowed = set(allowed)
    n = len(graph.nodes)
    INF = float("inf")
    dist = [INF] * n
    hops = [0] * n
    goal: list[int | None] = [None] * n

    pq: list[tuple[float, int, int]] = []
    for t in targets:
        dist[t] = 0.0
        goal[t] = t
        heapq.heappush(pq, (0.0, 0, t))

    while pq:
        d, h, node = heapq.heappop(pq)
        if d > dist[node]:
            continue
        for edge in graph.in_edges(node):
            if edge.rel_type not in allowed:
                continue
            nd = d + weight_of(edge.rel_type)
            src = edge.source
            # Ties broken toward fewer hops, then by edge type name, so two runs
            # on the same graph produce the same first_hop rather than whichever
            # the heap happened to pop.
            if nd < dist[src] or (nd == dist[src] and h + 1 < hops[src]):
                dist[src] = nd
                hops[src] = h + 1
                goal[src] = goal[node]
                heapq.heappush(pq, (nd, h + 1, src))
    return dist, hops, goal


def _first_hop(graph: AttackGraph, node: int, dist: list[float],
               allowed: set[str]) -> str | None:
    """The relationship type the cheapest route leaves this node on.

    Recovered from the distance array rather than stored during the search,
    because storing it means keeping a predecessor edge per node and the tie
    handling gets subtle; reading it back is one pass over the node's out-edges
    and is deterministic by construction.
    """
    best: tuple[float, str] | None = None
    for edge in graph.out_edges(node):
        if edge.rel_type not in allowed:
            continue
        onward = dist[edge.target]
        if onward == float("inf"):
            continue
        total = weight_of(edge.rel_type) + onward
        if best is None or (total, edge.rel_type) < best:
            best = (total, edge.rel_type)
    return best[1] if best else None


def exposure_report(graph: AttackGraph, kinds: Sequence[str] = ("User",),
                    limit: int | None = None,
                    include_privileged: bool = False) -> list[Exposure]:
    """Every principal ranked by how close it is to tier-0, cheapest first.

    Runs on `with_gpo_expansion()` and `TRAVERSAL`, matching the view the route
    panel reports on, so an account ranked 1 hop away is 1 hop away under the
    same rules.

    `include_privileged=False` drops accounts that are already tier-0. They
    would otherwise fill the top of the list at zero cost and say nothing: an
    account that *is* a Domain Admin is not an exposure finding.
    """
    view = graph.with_gpo_expansion()
    targets = [c.index for c in derive_targets(view)]
    if not targets:
        return []

    allowed = set(TRAVERSAL)
    dist, hops, goal = _reverse_dijkstra(view, targets, allowed)
    target_set = set(targets)
    wanted = {k.lower() for k in kinds}

    rows: list[Exposure] = []
    for i, node in enumerate(view.nodes):
        if node.kind.lower() not in wanted or i in target_set:
            continue
        if not include_privileged and (node.props.get("admincount") is True
                                       or node.high_value):
            continue
        reachable = dist[i] != float("inf")
        rows.append(Exposure(
            index=i,
            name=node.name,
            kind=node.kind,
            hops=hops[i] if reachable else None,
            static_cost=dist[i] if reachable else None,
            reachable=reachable,
            first_hop=_first_hop(view, i, dist, allowed) if reachable else None,
            target_name=view.nodes[goal[i]].name
            if reachable and goal[i] is not None else None,
        ))

    # Unreachable last, then cheapest first, then by name so the order is total
    # and two runs agree.
    rows.sort(key=lambda e: (not e.reachable,
                             e.static_cost if e.static_cost is not None else 0.0,
                             e.hops if e.hops is not None else 0,
                             e.name))
    return rows[:limit] if limit else rows


# --------------------------------------------------------------------------
# 3. what do we fix first
# --------------------------------------------------------------------------

@dataclass(frozen=True)
class ChokePoint:
    """One relationship, and what removing it would buy."""

    edge_index: int
    rel_type: str
    source_name: str
    target_name: str
    accounts_cut: int
    """How many accounts lose *all* access to tier-0 if this one edge goes."""

    accounts_before: int
    category: str
    caveat: str = ""
    """Why this row is not a work item, when it is not one.

    **Cutting reachability and being revocable are different things**, and the
    ranking only measures the first. A domain controller holds `DCSync` because
    it is a domain controller; on the reference collection that edge tops the
    list at 29% of accounts cut, and "revoke it" is not an action anybody can
    take. Presenting a structural fact of the directory as a remediation is the
    fastest way to lose an analyst's trust, so it is labelled rather than
    silently ranked or silently dropped.
    """

    @property
    def share_cut(self) -> float:
        return self.accounts_cut / self.accounts_before if self.accounts_before else 0.0

    @property
    def actionable(self) -> bool:
        return not self.caveat


def _reaching(graph: AttackGraph, targets: set[int], allowed: set[str],
              banned_edge: int | None = None) -> set[int]:
    """Nodes that can reach a target, optionally with one edge index removed.

    Walks edge *indices* rather than `in_edges()` objects because the exclusion
    has to identify one specific parallel edge. `AttackGraph` is a multigraph by
    build rule 2, so two relationships can join the same pair and comparing edge
    objects would drop both.
    """
    seen = set(targets)
    frontier = list(seen)
    while frontier:
        nxt = []
        for node in frontier:
            for ei in graph._in[node]:          # noqa: SLF001 - indices, not objects
                if ei == banned_edge:
                    continue
                edge = graph.edges[ei]
                if edge.rel_type not in allowed or edge.source in seen:
                    continue
                seen.add(edge.source)
                nxt.append(edge.source)
        frontier = nxt
    return seen


def choke_points(graph: AttackGraph, top: int = 10,
                 candidate_limit: int = 400) -> list[ChokePoint]:
    """Single relationships whose removal cuts the most accounts off from tier-0.

    **This is the question BloodHound does not answer.** It shows paths; it does
    not rank what to revoke. Removing one ACL is a change a directory team can
    actually make on Monday, and the useful ordering is by how much reach it
    removes rather than by how alarming the edge sounds.

    Candidates are the edges that lie on some account's cheapest route, not
    every edge in the graph: an edge no cheapest route uses cannot be the reason
    an account reaches tier-0 along one. That is a heuristic and it is a real
    limitation -- an edge carrying only *second*-cheapest routes is invisible
    here, and removing a listed edge may simply push traffic onto another.
    What each row states is exactly what was measured: accounts that lose *all*
    reach when this edge alone is removed.
    """
    view = graph.with_gpo_expansion()
    targets = {c.index for c in derive_targets(view)}
    if not targets:
        return []
    allowed = set(TRAVERSAL)

    before = _reaching(view, targets, allowed) - targets
    accounts_before = sum(1 for i in before
                          if view.nodes[i].kind.lower() == "user")
    if not accounts_before:
        return []

    dist, _hops, _goal = _reverse_dijkstra(view, sorted(targets), allowed)

    # Edges that lie on some node's cheapest route: cost(edge) + dist[target]
    # equals dist[source]. Deterministic, and far smaller than the edge set.
    candidates: list[int] = []
    for ei, edge in enumerate(view.edges):
        if edge.rel_type not in allowed:
            continue
        if dist[edge.source] == float("inf") or dist[edge.target] == float("inf"):
            continue
        if abs(weight_of(edge.rel_type) + dist[edge.target] - dist[edge.source]) < 1e-9:
            candidates.append(ei)
    candidates = candidates[:candidate_limit]

    rows: list[ChokePoint] = []
    for ei in candidates:
        after = _reaching(view, targets, allowed, banned_edge=ei) - targets
        cut = sum(1 for i in (before - after)
                  if view.nodes[i].kind.lower() == "user")
        if cut <= 0:
            continue
        edge = view.edges[ei]
        rows.append(ChokePoint(
            edge_index=ei,
            rel_type=edge.rel_type,
            source_name=view.nodes[edge.source].name,
            target_name=view.nodes[edge.target].name,
            accounts_cut=cut,
            accounts_before=accounts_before,
            category=category_of(edge.rel_type),
            caveat=_caveat(view, edge),
        ))

    # Actionable rows first, then by how much they cut. A structural grant that
    # cuts more is still worth *showing* — it says where the concentration is —
    # but it must not sit above a change somebody could actually make.
    rows.sort(key=lambda c: (not c.actionable, -c.accounts_cut,
                             c.rel_type, c.source_name))
    return rows[:top]


def _caveat(graph: AttackGraph, edge) -> str:
    """Name the rows that are facts about the directory rather than mistakes."""
    source = graph.nodes[edge.source]
    if edge.rel_type in ("DCSync", "GetChanges", "GetChangesAll") \
            and source.props.get("isdc") is True:
        return ("a domain controller replicates by definition — this edge is "
                "not revocable; treat it as where the concentration is, not as "
                "a work item")
    if edge.rel_type == "MemberOf" and source.kind == "Computer" \
            and source.props.get("isdc") is True:
        return "built-in DC group membership; not revocable"
    return ""
