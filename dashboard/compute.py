"""Computation layer for the Stage 7 dashboard. Pure functions, no UI.

New transport, zero new semantics. Every categorisation, admission, pricing and
provenance decision here routes through the modules that already own it —
`ad_schema.category_of`, `loader_neo4j.admit_edge`, `risk.weight_of`, the three
planners, `AttackGraph.with_gpo_expansion`. Nothing in this file decides what an
edge *is*; it only counts and arranges what those functions return. If a change
here starts to look like a second opinion about edge admission or kind
resolution, it belongs upstream instead.

Everything returns plain JSON-serialisable dicts, because the consumer is a
presentation layer that has to hand them to a template or a wire format.

Shares and concentration indices are returned **unrounded**. `docs/findings.md`
quotes them rounded (79.4%, 0.654) and the caller does that rounding, exactly as
`tests/test_reported_figures.py` does. Rounding here would bake a display
decision into the measurement and make the two files disagree about what the
number is.
"""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path
from typing import Any, Iterable, Sequence

from stealthpath.ad_schema import (
    DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES, category_of,
)
from stealthpath.graph import AttackGraph
from stealthpath.loader_neo4j import admit_edge
from stealthpath.planners.exact_history import exact_history_search
from stealthpath.planners.shortest_path import dijkstra
from stealthpath.planners.weighted_astar import astar
from stealthpath.risk import PROVISIONAL_WEIGHTS, history_cost_fn, static_cost_fn, weight_of
from stealthpath.defend import (
    choke_points, detection_summary, exposure_report, route_detection,
)
from stealthpath.targets import (
    Candidate, derive_sources, derive_targets, reaching_set,
)

# Imported, not reimplemented. `_path_record` is the exact record shape and
# `static_risk` derivation that produced the committed artifact, and ENTRY_POINTS
# and MAX_HOPS are the parameters it ran under. Copying them here would put the
# same fact in two files, which is the drift this project has already been bitten
# by once — a dashboard whose record shape quietly diverges from the runner's
# would still look right field by field until someone diffed them.
#
# The leading underscore is honest about the coupling rather than hiding it: this
# is a deliberate dependency on the runner's definition, and if `_path_record`
# moves somewhere less private, this import should follow it rather than fork.
from tools.run_h5_h6 import ENTRY_POINTS, MAX_HOPS, _path_record

__all__ = [
    "graph_profile", "coverage", "structural_absences",
    "compare_entry_point", "qlearning_result", "route_static_risk_per_hop",
    "starting_points", "target_names", "target_candidates", "annotate_hops",
    "route_detection_rows", "exposure_rows", "choke_point_rows",
    "resolve_sources", "resolve_targets",
    "with_per_hop_weights",
    "split_comparison", "provenance_triple", "pricing_verdict", "routing_verdict",
    "ENTRY_POINTS", "MAX_HOPS", "ADCS_NODE_KINDS", "RESULTS_PATH",
]

ROOT = Path(__file__).resolve().parent.parent
RESULTS_PATH = ROOT / "results" / "h5_h6.json"

# AD CS object types. Their *edges* are dropped at load (see the deferral in
# stage2_joint_capability_audit.md), so the nodes are the only trace left in a
# frozen graph that certificate abuse was collectable and is not modelled.
ADCS_NODE_KINDS = frozenset({
    "EnterpriseCA", "RootCA", "AIACA", "NTAuthStore", "CertTemplate",
})

_TRAVERSAL_ALLOWED = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)


def _walkable(graph: AttackGraph) -> list:
    """Edges the default traversal set admits.

    `DEFAULT_TRAVERSAL_SET`, not the GPO-expansion union: the concentration
    figures in findings.md are measured over this set, and widening it here
    would silently move 79.4% and both HHIs onto a different denominator.
    """
    return [e for e in graph.edges if e.rel_type in DEFAULT_TRAVERSAL_SET]


def _hhi(counts: Iterable[int], total: int) -> float:
    """Herfindahl-Hirschman index over a partition. 1.0 = a single class."""
    if total == 0:
        return 0.0
    return sum((v / total) ** 2 for v in counts)


def _modal(by_weight: Counter) -> tuple[float, int]:
    """Most common derived weight, ties broken toward the lower weight.

    `Counter.most_common` breaks ties by insertion order, which depends on edge
    order in the file. Determinism is a build rule, so the tie-break is explicit
    even though the real collection has a clear modal weight.
    """
    return max(sorted(by_weight.items()), key=lambda kv: (kv[1], -kv[0]))


def graph_profile(graph: AttackGraph) -> dict[str, Any]:
    """The four antecedent statistics, plus the edge counts they rest on.

    This is the portable part of the finding. The paper's claim is a conditional
    — *where* a graph's dominant edge class collapses to one detection
    signature, risk-weighting loses discriminating power on that class — and
    these are the numbers another researcher computes on their own collection to
    decide whether the antecedent holds for them. That is why they are a
    first-class function rather than a figure caption.
    """
    walk = _walkable(graph)
    n = len(walk)

    by_weight = Counter(weight_of(e.rel_type) for e in walk)
    modal_weight, modal_count = _modal(by_weight) if n else (0.0, 0)
    by_category = Counter(category_of(e.rel_type) for e in walk)

    return {
        "edges_total": len(graph.edges),
        "edges_walkable": n,
        "nodes": len(graph.nodes),
        "modal_weight": modal_weight,
        "modal_weight_edges": modal_count,
        "modal_weight_share": (modal_count / n) if n else 0.0,
        "hhi_weights": _hhi(by_weight.values(), n),
        "hhi_categories": _hhi(by_category.values(), n),
        "acl_abuse_edges": by_category.get("acl_abuse", 0),
        "acl_abuse_share": (by_category.get("acl_abuse", 0) / n) if n else 0.0,
        "weight_distribution": dict(sorted(by_weight.items())),
        "category_distribution": dict(sorted(by_category.items())),
        "dropped_edge_types": _dropped_edge_types(graph),
    }


def _dropped_edge_types(graph: AttackGraph) -> dict[str, Any]:
    """What the loader discarded, or an explicit statement that nobody recorded it.

    `recorded` is the load-bearing field. The loader writes
    `dropped_unknown_edge_types` only when something was actually dropped, and a
    graph derived from another graph (the H5/H6 perturbed copy) carries no
    provenance at all. Both cases produce an empty mapping, and reporting either
    as "0 types dropped" would state a clean collection where the truth is that
    the question was never answered — the same silence-versus-absence distinction
    `RiskWeight.channels` exists to prevent.
    """
    dropped = graph.provenance.get("dropped_unknown_edge_types")
    if dropped is None:
        return {"recorded": False, "types": {}, "type_count": 0, "edge_count": 0}
    return {
        "recorded": True,
        "types": dict(sorted(dropped.items())),
        "type_count": len(dropped),
        "edge_count": sum(dropped.values()),
    }


def _price_status(rel_type: str) -> str:
    """One edge type's pricing provenance: sourced, provisional, or unpriced.

    `unpriced` is not a worse `provisional` — it means no `RiskWeight` exists at
    all, so `weight_of` would raise rather than return a guess. Keeping the two
    apart is what stops a dashboard reporting an unpriceable edge as merely
    weakly-evidenced.
    """
    w = PROVISIONAL_WEIGHTS.get(rel_type)
    if w is None:
        return "unpriced"
    return "sourced" if w.sourced else "provisional"


def coverage(graph: AttackGraph,
             entries: Sequence[str] | None = None,
             target: str | None = None) -> dict[str, Any]:
    """Pricing provenance per edge and per route.

    Both halves are reported because either alone misleads. A route can be fully
    sourced on a badly-covered graph, and entirely provisional on a well-covered
    one — the graph-level percentage hides both, and it is the route that a
    reader is actually being asked to believe.
    """
    entries = list(ENTRY_POINTS if entries is None else entries)

    by_type: dict[str, dict[str, Any]] = {}
    for rel_type, count in sorted(Counter(e.rel_type for e in graph.edges).items()):
        # admit_edge is rule 4 at the collection boundary: it answers "does
        # ad_schema know this type", which is a different question from whether
        # a weight exists for it. Reused rather than re-derived from the
        # category tables.
        known = admit_edge(rel_type, drop_unknown=True)
        by_type[rel_type] = {
            "edges": count,
            "status": _price_status(rel_type),
            "schema_known": known,
            "walkable": rel_type in DEFAULT_TRAVERSAL_SET,
            "category": category_of(rel_type) if known else None,
        }

    all_status = Counter(_price_status(e.rel_type) for e in graph.edges)
    walk_status = Counter(_price_status(e.rel_type) for e in _walkable(graph))

    return {
        "all_edges": _status_block(all_status, len(graph.edges)),
        "walkable_edges": _status_block(walk_status, len(_walkable(graph))),
        "by_edge_type": by_type,
        "weights_total": len(PROVISIONAL_WEIGHTS),
        "weights_sourced": sum(1 for w in PROVISIONAL_WEIGHTS.values() if w.sourced),
        "routes": {e: _route_coverage(graph, e, target) for e in entries},
    }


def _status_block(counts: Counter, total: int) -> dict[str, Any]:
    return {
        "total": total,
        "sourced": counts.get("sourced", 0),
        "provisional": counts.get("provisional", 0),
        "unpriced": counts.get("unpriced", 0),
        "sourced_share": (counts.get("sourced", 0) / total) if total else 0.0,
    }


def _route_coverage(graph: AttackGraph, entry: str,
                    target: str | None = None) -> dict[str, Any]:
    """Per-hop pricing provenance for each planner's route from `entry`."""
    out: dict[str, Any] = {}
    for planner, record in compare_entry_point(graph, entry, target).items():
        if record is None:
            out[planner] = None
            continue
        statuses = [_price_status(r) for r in record["route"]]
        counts = Counter(statuses)
        out[planner] = {
            "hops": len(statuses),
            "per_hop": [{"rel_type": r, "status": s}
                        for r, s in zip(record["route"], statuses)],
            "sourced": counts.get("sourced", 0),
            "provisional": counts.get("provisional", 0),
            "unpriced": counts.get("unpriced", 0),
            "fully_sourced": counts.get("sourced", 0) == len(statuses),
        }
    return out


def structural_absences(graph: AttackGraph) -> dict[str, Any]:
    """The three holes in the collection, reported without being asked.

    All three are properties of this collection rather than of AD, and every one
    of them bounds a result: absent sessions under-represent credential theft,
    absent delegation removes a whole route class, and dropped AD CS edges make
    every reported cost an upper bound on what a real attacker would pay.
    """
    walk = _walkable(graph)
    by_category = Counter(category_of(e.rel_type) for e in walk)
    adcs_nodes = Counter(n.kind for n in graph.nodes if n.kind in ADCS_NODE_KINDS)
    dropped = _dropped_edge_types(graph)
    adcs_dropped = {t: c for t, c in dropped["types"].items()
                    if t.startswith("ADCS") or t in {
                        "Enroll", "EnrollOnBehalfOf", "EnterpriseCAFor",
                        "GoldenCert", "HostsCAService", "ManageCA",
                        "ManageCertificates", "NTAuthStoreFor", "PublishedTo",
                        "RootCAFor", "TrustedForNTAuth",
                    }}
    return {
        "adcs": {
            "nodes_present": sum(adcs_nodes.values()),
            "node_kinds": dict(sorted(adcs_nodes.items())),
            "edges_modelled": 0,
            "dropped_edge_types": dict(sorted(adcs_dropped.items())),
            "dropped_edges": sum(adcs_dropped.values()),
            "provenance_recorded": dropped["recorded"],
        },
        "session_edges": by_category.get("session", 0),
        "delegation_edges": by_category.get("delegation", 0),
    }


def route_static_risk_per_hop(route: Sequence[str]) -> list[float]:
    """Static weight of each hop, in order, via `risk.weight_of`.

    Split out rather than added to `_path_record` on purpose: that record shape
    is shared with `tools/run_h5_h6.py` and reproduces the committed artifact
    byte for byte, so adding a field there would change `results/h5_h6.json` and
    break a hash the paper cites. Figure 3 needs the per-hop breakdown to show
    how 20.00 and 15.10 are reached; it gets it here instead.
    """
    return [weight_of(r) for r in route]


def annotate_hops(route: Sequence[str]) -> list[dict[str, Any]]:
    """One record per hop: technique, what it costs, and whether that cost is cited.

    This is the per-hop view the route panel renders. It exists so the page can
    show *which hop* is provisionally priced rather than only a route-level
    "not fully sourced" flag — a single unsourced hop in the middle of a route
    is the thing a reader needs to see, and a summary number hides exactly that.
    """
    out: list[dict[str, Any]] = []
    for rel in route:
        priced = rel in PROVISIONAL_WEIGHTS
        out.append({
            "rel_type": rel,
            "weight": weight_of(rel) if priced else None,
            "status": _price_status(rel),
            "category": category_of(rel),
        })
    return out


def route_detection_rows(route: Sequence[str]) -> dict[str, Any]:
    """Detection posture of one route, flattened for display and export.

    The SOC-facing projection of data the weight table has carried since
    Stage 2: every hop already knows its ATT&CK technique and the SigmaHQ rule
    its price was derived from, and nothing displayed either.
    """
    summary = detection_summary(route)
    return {
        "hops": summary["hops"],
        "counts": summary["counts"],
        "blind_hops": summary["blind_hops"],
        "conditional_hops": summary["conditional_hops"],
        "techniques": summary["techniques"],
        "detail": [
            {
                "rel_type": h.rel_type,
                "weight": h.weight,
                "technique": h.technique,
                "visibility": h.visibility,
                "native": h.native,
                "endpoint": h.endpoint,
                "source": h.source,
            }
            for h in route_detection(route)
        ],
    }


def exposure_rows(graph: AttackGraph, limit: int | None = None) -> list[dict[str, Any]]:
    """Every account ranked by how close it is to tier-0.

    `static_cost` is deliberately named: this is the static weight model over
    the whole directory in one pass, not the history-aware search the route
    panel runs for a single start. The two disagree slightly and the UI says so.
    """
    return [
        {
            "account": e.name,
            "kind": e.kind,
            "hops": e.hops,
            "static_cost": e.static_cost,
            "reaches": e.target_name,
            "first_step": e.first_hop,
            "reachable": e.reachable,
        }
        for e in exposure_report(graph, limit=limit)
    ]


def choke_point_rows(graph: AttackGraph, top: int = 10) -> list[dict[str, Any]]:
    """Relationships ranked by how many accounts lose tier-0 reach without them."""
    return [
        {
            "relationship": c.rel_type,
            "from": c.source_name,
            "to": c.target_name,
            "accounts_cut": c.accounts_cut,
            "of_accounts": c.accounts_before,
            "share_cut": c.share_cut,
            "actionable": c.actionable,
            "caveat": c.caveat,
        }
        for c in choke_points(graph, top=top)
    ]


def starting_points(graph: AttackGraph) -> list[str]:
    """Names a user can start from, in a useful order.

    Owned nodes first (BloodHound foothold marks), then documented provenance
    entries that resolve on this graph, then everything else **with accounts
    that can actually reach a target ahead of those that cannot**.
    Deduplicated, first occurrence wins.

    That last clause is the whole point of the ordering. The first entry is the
    UI default, and on a real collection most accounts cannot reach Domain Admin
    at all. Ordering only by "has a session on a collected machine" put `HODOR`
    at the top of an upload of the reference collection -- a session holder with
    no route -- so the page's first answer was "No route reported" for a graph
    that contains two good routes. Reachability is not a tiebreak here; it is
    the primary key below the two authored groups.
    """
    seen: set[str] = set()
    out: list[str] = []

    def add(name: str) -> None:
        if name not in seen:
            seen.add(name)
            out.append(name)

    for i in graph.entry_nodes():
        add(graph.nodes[i].name)
    documented = graph.provenance.get("entry_points") or {}
    if isinstance(documented, dict):
        for key in documented:
            if key in ("note",) or "NO unprivileged" in str(documented[key]).upper():
                continue
            if graph.find(name=key):
                add(key)

    reaching = _reaching_names(graph)
    privileged = _privileged_names(graph)
    sessioned = [c.name for c in derive_sources(graph)
                 if c.confidence == "structure"]
    ranked = _ranked_user_names(graph)

    # Two keys, applied in this order to every group below: can it reach a
    # target, and is it not already privileged. Both had to be applied
    # *uniformly*. Demoting privileged accounts only within the flat user list
    # left `ADMINISTRATOR@PHANTOM.CORP` at the top of the SpecterOps sample,
    # because it also holds a session and the session group ran first — so the
    # app's opening answer was a one-hop `MemberOf` into Enterprise Admins from
    # an account that was already there.
    def useful(name: str) -> bool:
        return name in reaching and name not in privileged

    for group in (sessioned, ranked):
        for name in group:
            if useful(name):
                add(name)
    for group in (sessioned, ranked):
        for name in group:
            if name in reaching:
                add(name)
    # Unreachable starts are listed, not hidden: "this account cannot reach
    # Domain Admin" is a real answer someone may want, and silently dropping it
    # would make the graph look smaller than it is.
    for group in (sessioned, ranked):
        for name in group:
            add(name)

    if not out:
        out = [n.name for n in graph.nodes]
    return out


def _privileged_names(graph: AttackGraph) -> set[str]:
    """Names of accounts that are already tier-0, by either available signal.

    `admincount` is AdminSDHolder protection, which a directory sets on
    privileged principals. The second signal exists because a name in this list
    may belong to more than one object — the SpecterOps sample has a
    `CertTemplate` and a `User` both called `ADMINISTRATOR@PHANTOM.CORP`, and
    `resolve_sources` matches on the name, so the flag has to be checked across
    every node that answers to it.
    """
    out: set[str] = set()
    for node in graph.nodes:
        if node.props.get("admincount") is True or node.high_value:
            out.add(node.name)
    return out


def _reaching_names(graph: AttackGraph) -> set[str]:
    """Names of nodes from which some derived target is reachable.

    Computed on the same view and traversal set the planners use, so "can
    reach" means there what it means here. Cost and the hop cap are ignored,
    which makes it an over-approximation: it can promote a start that turns out
    to be unreachable within 20 hops, and it never demotes one that has a route.
    """
    view = graph.with_gpo_expansion()
    targets = [c.index for c in derive_targets(view)]
    return {view.nodes[i].name
            for i in reaching_set(view, targets, _TRAVERSAL_ALLOWED)}


def _ranked_user_names(graph: AttackGraph) -> list[str]:
    """Every User account, ordinary accounts before already-privileged ones.

    Stable within each group (node-index order), so the list does not reshuffle
    between runs on the same graph. The reachable/unreachable split is applied
    by the caller, on top of this.

    **An account that is already tier-0 is a poor default.** It starts at the
    destination, so the route it produces is one `MemberOf` hop and tells the
    reader nothing. On the SpecterOps public sample the first reachable user in
    node order is `ADMINISTRATOR`, which made the app's opening answer a
    one-hop route into Enterprise Admins — true, and a bad demonstration.
    `derive_sources` already applied this rule; this list did not, and this list
    is the one that feeds the picker.
    """
    ordinary, privileged = [], []
    for node in graph.nodes:
        if node.kind.lower() != "user":
            continue
        (privileged if node.props.get("admincount") is True
         else ordinary).append(node.name)
    return ordinary + privileged


def target_candidates(graph: AttackGraph) -> list[Candidate]:
    """Destinations with the argument for each, for an upload the tool has never
    seen.

    `tier0_targets()` finds Domain Admins by that exact display name, which is
    what makes the reference demo work and what returns an empty set on a
    renamed or non-English directory -- reported to the user as "no route",
    which is indistinguishable from a hardened forest. `stealthpath.targets`
    keys on well-known RIDs instead and carries a reason per candidate.

    On the frozen graphs the two agree exactly, which
    `test_derived_targets_match_tier0_on_the_frozen_graph` pins: this generalises
    the target set without moving a published number.
    """
    return derive_targets(graph.with_gpo_expansion())


def target_names(graph: AttackGraph) -> list[str]:
    """Default destinations, derived rather than matched by well-known name."""
    view = graph.with_gpo_expansion()
    names = [c.name for c in derive_targets(view)]
    return names or [n.name for n in view.nodes if n.kind.lower() == "domain"]


def _exact_name_hits(view: AttackGraph, name: str) -> list[int]:
    needle = name.upper()
    return [i for i, n in enumerate(view.nodes) if n.name.upper() == needle]


def resolve_sources(view: AttackGraph, entry: str) -> list[int]:
    """Start nodes for a selected name.

    Exact match first. `AttackGraph.find` is a substring search, which is the
    right default when a test passes `SQL_SVC@NORTH`, and the wrong one when
    the UI passes a full UPN that is also a suffix of other names.
    """
    exact = _exact_name_hits(view, entry)
    if exact:
        return sorted(exact)
    return sorted(view.find(name=entry))


def resolve_targets(view: AttackGraph, target: str | None) -> list[int]:
    """Destinations for a selected name.

    Exact match first so choosing the domain object `NORTH.SEVENKINGDOMS.LOCAL`
    does not also select every `…@NORTH.SEVENKINGDOMS.LOCAL` account — those
    UPNs contain the domain string, and a substring hit on the start node
    reports a 0-hop route that is not a route.
    """
    if not target:
        # Derived, not name-matched -- see `target_candidates`. Identical to
        # tier0_targets() on the frozen graphs, and non-empty on a directory
        # whose privileged groups are renamed or localised.
        return sorted(c.index for c in derive_targets(view))             or sorted(view.target_nodes())
    exact = _exact_name_hits(view, target)
    if exact:
        return sorted(exact)
    pool = [c.index for c in derive_targets(view)] or view.target_nodes()
    needle = target.upper()
    hits = [i for i in pool if needle in view.nodes[i].name.upper()]
    if hits:
        return sorted(hits)
    return sorted(view.find(name=target))


def with_per_hop_weights(record: dict[str, Any] | None) -> dict[str, Any] | None:
    """Attach static per-hop weights for the route figure. Display only."""
    if record is None:
        return None
    return {**record, "static_risk_per_hop": route_static_risk_per_hop(record["route"])}


def provenance_triple(graph: AttackGraph, entry: str,
                      target: str | None = None
                      ) -> tuple[dict[str, Any] | None, dict[str, Any] | None,
                                 dict[str, Any] | None]:
    """Per-planner hop provenance for one start, unpacked for the UI."""
    block = coverage(graph, entries=[entry], target=target)["routes"].get(entry) or {}
    return (block.get("shortest_path"),
            block.get("weighted_astar"),
            block.get("exact_history"))


def split_comparison(comparison: dict[str, Any]
                     ) -> tuple[dict[str, Any] | None, dict[str, Any] | None,
                                dict[str, Any] | None]:
    """Unpack the three planner records so a UI layer never names the keys."""
    return (comparison["shortest_path"],
            comparison["weighted_astar"],
            comparison["exact_history"])


def pricing_verdict(graph: AttackGraph) -> dict[str, Any]:
    """GOOD only when every walkable edge is sourced and nothing was dropped.

    That is the coverage question the honesty panel exists to answer — not a
    concentration statistic, and not whether two planners disagree. A graph can
    be fully priced and still have identical shortest/weighted routes.
    """
    cov = coverage(graph, entries=())
    profile = graph_profile(graph)
    walk = cov["walkable_edges"]
    dropped = profile["dropped_edge_types"]
    dropped_count = dropped["edge_count"] if dropped["recorded"] else 0
    good = walk["unpriced"] == 0 and walk["sourced_share"] == 1.0 and dropped_count == 0
    return {
        "verdict": "GOOD" if good else "POOR",
        "walkable_sourced_share": walk["sourced_share"],
        "walkable_sourced": walk["sourced"],
        "walkable_total": walk["total"],
        "dropped_types": dropped["type_count"] if dropped["recorded"] else None,
        "dropped_edges": dropped_count if dropped["recorded"] else None,
        "dropped_recorded": dropped["recorded"],
        "weights_sourced": cov["weights_sourced"],
        "weights_total": cov["weights_total"],
    }


def routing_verdict(graph: AttackGraph, entry: str,
                    target: str | None = None) -> dict[str, Any]:
    """GOOD when detection-aware routing picks a different technique sequence.

    Same hop count with a different edge sequence still counts as GOOD — that is
    the SQL_SVC case. Identical sequences are POOR: the cost model has nothing
    to choose on that start.
    """
    shortest, weighted, _ = split_comparison(compare_entry_point(graph, entry, target))
    if shortest is None or weighted is None:
        return {"verdict": "POOR", "differs": False, "reachable": False}
    differs = shortest["route"] != weighted["route"]
    return {
        "verdict": "GOOD" if differs else "POOR",
        "differs": differs,
        "reachable": True,
        "shortest_route": shortest["route"],
        "weighted_route": weighted["route"],
    }


def compare_entry_point(graph: AttackGraph, entry: str,
                        target: str | None = None) -> dict[str, Any]:
    """All three planners from one entry point, on the GPO-expansion view.

    The view and the allowed set are not options. Every route in findings.md
    runs on `with_gpo_expansion()` over `DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES`;
    running the default set instead silently drops `GPLink` and changes
    SAMWELL's route, which is a two-hop route that traverses one.

    `target` is an exact node name when it matches one (the dashboard dropdown
    always does). Fragments such as `DOMAIN ADMINS` still match inside the
    tier-0 set. Omit it to use `tier0_targets()`, with high-value as fallback
    when that set is empty — the documented GOAD entries never hit the fallback.
    """
    view = graph.with_gpo_expansion()
    targets = resolve_targets(view, target)
    sources = resolve_sources(view, entry)
    return {
        "shortest_path": _path_record(view, dijkstra(
            view, sources, targets, allowed_rel_types=_TRAVERSAL_ALLOWED,
            max_hops=MAX_HOPS), "unit_cost"),
        "weighted_astar": _path_record(view, astar(
            view, sources, targets, static_cost_fn(),
            allowed_rel_types=_TRAVERSAL_ALLOWED, max_hops=MAX_HOPS), "static"),
        "exact_history": _path_record(view, exact_history_search(
            view, sources, targets, history_cost_fn(),
            _TRAVERSAL_ALLOWED, MAX_HOPS), "history"),
    }


def qlearning_result(graph_id: str, entry: str,
                     results_path: Path | None = None) -> dict[str, Any]:
    """Stored Q-learning numbers for one entry point. Never trains.

    There is no trained model to load — `train()` returns its Q-table in memory
    and nothing persists it — so "pre-trained" here means *stored result*, and
    the dashboard's numbers match findings.md by construction rather than by
    reproduction.

    `graph_id` selects which side of the H5 replay to report, and the two are
    not symmetric. Every seed was trained on the base graph and replayed on the
    perturbed one without retraining, so `perturbed` is a **replay of a base
    policy**, not an independently trained result. `trained_on`, `evaluated_on`
    and `retrained` are passed through unchanged so a caller cannot present it
    as one.
    """
    if graph_id not in ("base", "perturbed"):
        raise ValueError(
            f"unknown graph_id {graph_id!r}: expected 'base' or 'perturbed'. "
            f"Q-learning results exist only for the two frozen graphs."
        )
    data = json.loads((results_path or RESULTS_PATH).read_text(encoding="utf-8"))
    h5 = data["results"]["h5_rl_no_retraining"]
    if entry not in h5:
        raise KeyError(
            f"no stored Q-learning result for entry point {entry!r}. "
            f"Available: {', '.join(sorted(h5))}. Training live is not an "
            f"option here — see this function's docstring."
        )
    block = h5[entry]
    seeds = block["seeds"]
    optimum = block["optimum_base" if graph_id == "base" else "optimum_perturbed"]
    cost_key = "base_policy_cost" if graph_id == "base" else "replayed_cost"
    gap_key = ("base_gap_vs_optimum" if graph_id == "base"
               else "perturbed_gap_vs_new_optimum")

    return {
        "graph_id": graph_id,
        "entry": entry,
        "trained_on": seeds[0]["trained_on"],
        "evaluated_on": graph_id,
        "retrained": any(s["retrained"] for s in seeds),
        "is_replay": graph_id == "perturbed",
        "seeds": len(seeds),
        "optimum_cost": optimum["cost"],
        "optimum_hops": optimum["hops"],
        "optimum_route": optimum["route"],
        "policy_costs": [s[cost_key] for s in seeds],
        "gaps_vs_optimum": [s[gap_key] for s in seeds],
        "converged_at_episode": [s["converged_at_episode"] for s in seeds],
        "graphs": data["graphs"],
    }
