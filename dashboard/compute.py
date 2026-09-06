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
    "compare_entry_point", "qlearning_result",
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
             entries: Sequence[str] | None = None) -> dict[str, Any]:
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
        "routes": {e: _route_coverage(graph, e) for e in entries},
    }


def _status_block(counts: Counter, total: int) -> dict[str, Any]:
    return {
        "total": total,
        "sourced": counts.get("sourced", 0),
        "provisional": counts.get("provisional", 0),
        "unpriced": counts.get("unpriced", 0),
        "sourced_share": (counts.get("sourced", 0) / total) if total else 0.0,
    }


def _route_coverage(graph: AttackGraph, entry: str) -> dict[str, Any]:
    """Per-hop pricing provenance for each planner's route from `entry`."""
    out: dict[str, Any] = {}
    for planner, record in compare_entry_point(graph, entry).items():
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


def compare_entry_point(graph: AttackGraph, entry: str) -> dict[str, Any]:
    """All three planners from one entry point, on the GPO-expansion view.

    The view and the allowed set are not options. Every route in findings.md
    runs on `with_gpo_expansion()` over `DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES`;
    running the default set instead silently drops `GPLink` and changes
    SAMWELL's route, which is a two-hop route that traverses one.
    """
    view = graph.with_gpo_expansion()
    targets = sorted(view.tier0_targets())
    sources = view.find(name=entry)
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
