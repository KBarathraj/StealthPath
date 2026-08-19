"""Run the H5/H6 experiment and emit a machine-readable artifact.

    python tools/run_h5_h6.py                       # full run, writes results/h5_h6.json
    python tools/run_h5_h6.py --episodes 2000       # quick structural check
    python tools/run_h5_h6.py --seeds 0 1           # fewer RL seeds

**Why this file exists.** The H5/H6 numbers were originally produced by throwaway
scripts and hand-transcribed into `docs/findings.md`. The numbers were real — an
independent re-derivation reproduced every one of them — but the code that made
them was not in the repository, so a reader could not regenerate them. A result
citing an artifact nobody can obtain is not a result yet.

**Nothing here is hard-coded from the expected answer.** In particular the
perturbation is *discovered* by diffing the two committed graphs, and the
reverse-BFS seeds are the source nodes of whatever that diff turns up. Change the
perturbed graph and this runner reports the new perturbation rather than the old
one. The expected values live in `tests/test_h5_h6_runner.py`, which asserts
against this runner's output; they are deliberately not in the runner and not in
the artifact.

H5 is the degradation of an *existing* policy under graph change, so the learner
is trained on the base graph and its Q-table is replayed on the perturbed graph.
It is never retrained. `retrained: false` in the artifact records that.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import platform
import sys
from collections import Counter, deque
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stealthpath.ad_schema import (  # noqa: E402
    DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES, category_of,
)
from stealthpath.graph import AttackGraph  # noqa: E402
from stealthpath.planners.exact_history import (  # noqa: E402
    category_representatives, exact_history_search, state_space_size,
)
from stealthpath.planners.q_learning import (  # noqa: E402
    QLearningConfig, greedy_path, train,
)
from stealthpath.planners.shortest_path import dijkstra  # noqa: E402
from stealthpath.planners.weighted_astar import astar  # noqa: E402
from stealthpath.risk import (  # noqa: E402
    P15_DECLARED_FRACTION, PROVISIONAL_WEIGHTS, REPEAT_MULTIPLIER,
    WEIGHT_CEILING, WEIGHT_FLOOR, history_cost_fn, static_cost_fn, weight_of,
)

BASE_GRAPH = ROOT / "data" / "goad_graph.json"
PERTURBED_GRAPH = ROOT / "data" / "goad_graph_perturbed.json"
DEFAULT_OUT = ROOT / "results" / "h5_h6.json"

ENTRY_POINTS = [
    "SAMWELL.TARLY@NORTH",
    "SQL_SVC@NORTH",
    "TYWIN.LANNISTER@SEVENKINGDOMS",
]
MAX_HOPS = 20


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def graph_diff(base: AttackGraph, pert: AttackGraph) -> dict:
    """What actually differs between the two committed graphs.

    Counters rather than sets, because `AttackGraph` is a multigraph by design
    (build rule 2) and two identical-endpoint edges of the same type are two
    edges. Collapsing them here would under-report a perturbation.
    """
    def key(g):
        return Counter((e.source, e.target, e.rel_type) for e in g.edges)

    added = sorted((key(pert) - key(base)).elements())
    removed = sorted((key(base) - key(pert)).elements())

    def describe(g, items):
        return [{
            "source_index": s, "target_index": t, "rel_type": r,
            "source_name": g.node(s).name, "target_name": g.node(t).name,
            "category": category_of(r),
        } for s, t, r in items]

    return {
        "nodes_base": len(base.nodes), "nodes_perturbed": len(pert.nodes),
        "edges_base": len(base.edges), "edges_perturbed": len(pert.edges),
        "added": describe(pert, added),
        "removed": describe(base, removed),
    }


def _path_record(graph, path, cost_label: str) -> dict | None:
    if path is None:
        return None
    rels = path.rel_types(graph)
    return {
        "hops": path.length,
        "cost": path.cost,
        "cost_display": round(path.cost, 2),
        "static_risk": round(sum(weight_of(r) for r in rels), 6),
        "route": rels,
        "categories": [category_of(r) for r in rels],
        "node_names": [graph.node(n).name for n in path.nodes],
        "cost_model": cost_label,
    }


def run_planners(graph: AttackGraph, allowed: set[str]) -> dict:
    """Shortest path, weighted A*, and exact history-aware search."""
    view = graph.with_gpo_expansion()
    targets = sorted(view.tier0_targets())
    out = {}
    for entry in ENTRY_POINTS:
        src = view.find(name=entry)
        out[entry] = {
            "shortest_path": _path_record(view, dijkstra(
                view, src, targets, allowed_rel_types=allowed,
                max_hops=MAX_HOPS), "unit_cost"),
            "weighted_astar": _path_record(view, astar(
                view, src, targets, static_cost_fn(), allowed_rel_types=allowed,
                max_hops=MAX_HOPS), "static"),
            "exact_history": _path_record(view, exact_history_search(
                view, src, targets, history_cost_fn(), allowed_rel_types=allowed,
                max_hops=MAX_HOPS), "history"),
        }
    return out


def run_h5_rl(base: AttackGraph, pert: AttackGraph, allowed: set[str],
              seeds: list[int], episodes: int) -> dict:
    """Train on base, replay the frozen Q-table on perturbed. No retraining."""
    bv, pv = base.with_gpo_expansion(), pert.with_gpo_expansion()
    btg, ptg = sorted(bv.tier0_targets()), sorted(pv.tier0_targets())
    cost = history_cost_fn()

    cats = sorted({category_of(r) for r in allowed})
    bits = {c: 1 << i for i, c in enumerate(cats)}
    reps_p = category_representatives(pv, allowed)
    acts_p = {n: [ei for ei in pv.out_edge_indices(n)
                  if pv.edges[ei].rel_type in allowed]
              for n in range(len(pv.nodes))}

    results = {}
    for entry in ENTRY_POINTS:
        bs, ps = bv.find(name=entry)[0], pv.find(name=entry)[0]
        opt_base = exact_history_search(bv, [bs], btg, cost,
                                        allowed_rel_types=allowed, max_hops=MAX_HOPS)
        opt_pert = exact_history_search(pv, [ps], ptg, cost,
                                        allowed_rel_types=allowed, max_hops=MAX_HOPS)
        per_seed = []
        for seed in seeds:
            cfg = QLearningConfig(episodes=episodes, seed=seed)
            trained = train(bv, bs, btg, cost, cfg, allowed_rel_types=allowed)
            replayed = greedy_path(pv, ps, set(ptg), cost, trained.q, bits,
                                   reps_p, acts_p, MAX_HOPS)
            row = {
                "seed": seed,
                "trained_on": "base",
                "evaluated_on": "perturbed",
                "retrained": False,
                "converged": trained.converged,
                "converged_at_episode": trained.converged_at_episode,
                "goal_reached_episodes": trained.goal_reached_total,
                "success_rate_first_5k": round(trained.success_rate_first_5k, 6),
                "q_table_entries": trained.q_size,
                "base_policy_cost": trained.path.cost if trained.path else None,
                "base_gap_vs_optimum": (
                    None if trained.path is None or opt_base is None
                    else round((trained.path.cost - opt_base.cost) / opt_base.cost, 8)),
                "replayed_cost": replayed.cost if replayed else None,
                "replayed_hops": replayed.length if replayed else None,
                "replayed_route": replayed.rel_types(pv) if replayed else None,
                "perturbed_gap_vs_new_optimum": (
                    None if replayed is None or opt_pert is None
                    else round((replayed.cost - opt_pert.cost) / opt_pert.cost, 8)),
            }
            per_seed.append(row)
        results[entry] = {
            "optimum_base": _path_record(bv, opt_base, "history"),
            "optimum_perturbed": _path_record(pv, opt_pert, "history"),
            "seeds": per_seed,
        }
    return results


def affected_region(pert: AttackGraph, allowed: set[str],
                    changed_source_indices: list[int]) -> dict:
    """H6: reverse-BFS bound over the augmented state space.

    Seeds come from the *derived* diff, not from a constant. An added edge
    `u -> v` can only change the optimal cost of a state that can reach `u`, so
    the affected set is everything reaching a changed edge's source.

    Predecessors in the augmented graph: an edge `m -> n` of category `c` can
    precede `(n, mask)` only if `c` is already in `mask`, and the predecessor's
    mask is either `mask` or `mask` without `c`.
    """
    view = pert.with_gpo_expansion()
    cats = sorted({category_of(r) for r in allowed})
    bit = {c: 1 << i for i, c in enumerate(cats)}
    full = state_space_size(view, allowed)

    incoming: dict[int, list[tuple[int, int]]] = {}
    for e in view.edges:
        if e.rel_type in allowed:
            incoming.setdefault(e.target, []).append(
                (e.source, bit[category_of(e.rel_type)]))

    seen: set[tuple[int, int]] = set()
    frontier: deque[tuple[int, int]] = deque()
    for n in changed_source_indices:
        for mask in range(2 ** len(cats)):
            if (n, mask) not in seen:
                seen.add((n, mask))
                frontier.append((n, mask))
    while frontier:
        n, mask = frontier.popleft()
        for m, b in incoming.get(n, ()):
            if not (mask & b):
                continue
            for prev in (mask, mask & ~b):
                if (m, prev) not in seen:
                    seen.add((m, prev))
                    frontier.append((m, prev))

    outgoing = {n: [(view.edges[ei].target,
                     bit[category_of(view.edges[ei].rel_type)])
                    for ei in view.out_edge_indices(n)
                    if view.edges[ei].rel_type in allowed]
                for n in range(len(view.nodes))}
    reach: set[tuple[int, int]] = set()
    q: deque[tuple[int, int]] = deque()
    for entry in ENTRY_POINTS:
        for s in view.find(name=entry):
            if (s, 0) not in reach:
                reach.add((s, 0))
                q.append((s, 0))
    while q:
        n, mask = q.popleft()
        for t, b in outgoing[n]:
            if (t, mask | b) not in reach:
                reach.add((t, mask | b))
                q.append((t, mask | b))

    both = seen & reach
    return {
        "state_space_size": full,
        "categories_in_traversal_set": len(cats),
        "category_names": cats,
        "reverse_bfs_seed_nodes": sorted(changed_source_indices),
        "affected_states": len(seen),
        "affected_fraction_of_state_space": round(len(seen) / full, 8),
        "reachable_states": len(reach),
        "reachable_fraction_of_state_space": round(len(reach) / full, 8),
        "affected_and_reachable": len(both),
        "affected_fraction_of_reachable": (
            round(len(both) / len(reach), 8) if reach else None),
        "_affected_set": seen,          # stripped before serialisation
        "_reachable_set": reach,
    }


def classify_entries(pert: AttackGraph, affected: set[tuple[int, int]],
                     base_planners: dict, pert_planners: dict) -> dict:
    """Did the bound predict which entry point actually changed?"""
    view = pert.with_gpo_expansion()
    out = {}
    for entry in ENTRY_POINTS:
        src = view.find(name=entry)[0]
        predicted = (src, 0) in affected
        before = base_planners[entry]["exact_history"]
        after = pert_planners[entry]["exact_history"]
        observed = (before or {}).get("route") != (after or {}).get("route")
        if predicted and observed:
            verdict = "correctly_predicted"
        elif not predicted and not observed:
            verdict = "correctly_excluded"
        elif predicted and not observed:
            verdict = "over_inclusive_but_sound"
        else:
            verdict = "OUTSIDE_BOUND_FALSIFIED"
        out[entry] = {
            "entry_node_index": src,
            "predicted_affected": predicted,
            "observed_route_change": observed,
            "verdict": verdict,
        }
    return out


def risk_model_config() -> dict:
    sourced = sorted(r for r, w in PROVISIONAL_WEIGHTS.items() if w.sourced)
    unsourced = sorted(r for r, w in PROVISIONAL_WEIGHTS.items() if not w.sourced)
    return {
        "cost_unit": "unitless loudness per edge, floor..ceiling",
        "weight_floor": WEIGHT_FLOOR,
        "weight_ceiling": WEIGHT_CEILING,
        "repeat_multiplier_k": REPEAT_MULTIPLIER,
        "p15_declared_fraction": P15_DECLARED_FRACTION,
        "history_summary": "set of technique categories used (one bit each)",
        "weights_total": len(PROVISIONAL_WEIGHTS),
        "weights_sourced_count": len(sourced),
        "weights_unsourced_count": len(unsourced),
        "weights_sourced": sourced,
        "weights_unsourced": unsourced,
        "unknown_edge_type_behaviour": "raises; never defaults",
    }


def build(seeds: list[int], episodes: int) -> dict:
    base = AttackGraph.load(BASE_GRAPH)
    pert = AttackGraph.load(PERTURBED_GRAPH)
    allowed = set(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)

    diff = graph_diff(base, pert)
    if not diff["added"] and not diff["removed"]:
        raise SystemExit("the two graphs are identical - nothing to measure")

    base_planners = run_planners(base, allowed)
    pert_planners = run_planners(pert, allowed)

    changed_sources = sorted({e["source_index"] for e in diff["added"]}
                             | {e["source_index"] for e in diff["removed"]})
    region = affected_region(pert, allowed, changed_sources)
    affected_set = region.pop("_affected_set")
    region.pop("_reachable_set")

    return {
        "experiment": "H5/H6",
        "description": ("H5: degradation of an existing policy under graph "
                        "change, no retraining. H6: reverse-BFS affected-region "
                        "bound over the augmented state space."),
        "generated_by": "tools/run_h5_h6.py",
        "python": platform.python_version(),
        "graphs": {
            "base": {"path": "data/goad_graph.json",
                     "sha256": sha256_of(BASE_GRAPH)},
            "perturbed": {"path": "data/goad_graph_perturbed.json",
                          "sha256": sha256_of(PERTURBED_GRAPH)},
        },
        "graph_diff": diff,
        "planner_config": {
            "traversal_view": "with_gpo_expansion()",
            "allowed_rel_types": sorted(allowed),
            "max_hops": MAX_HOPS,
            "target_set": "tier0_targets()",
            "entry_points": ENTRY_POINTS,
            "tie_breaking": "lowest edge index, deterministic",
        },
        "risk_model": risk_model_config(),
        "rl_config": {
            **{k: v for k, v in vars(QLearningConfig(episodes=episodes)).items()},
            "seeds": seeds,
            "retrained_after_perturbation": False,
            "algorithm": "tabular Q-learning",
            "state": "(node index, category-set bitmask)",
            "action_space": "walkable out-edges of the current node",
        },
        "results": {
            "planners_base": base_planners,
            "planners_perturbed": pert_planners,
            "h5_rl_no_retraining": run_h5_rl(base, pert, allowed, seeds, episodes),
            "h6_affected_region": region,
            "h6_entry_classification": classify_entries(
                pert, affected_set, base_planners, pert_planners),
        },
    }


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, nargs="+", default=[0, 1, 2, 3, 4])
    ap.add_argument("--episodes", type=int, default=50_000)
    ap.add_argument("--out", type=Path, default=DEFAULT_OUT)
    args = ap.parse_args()

    artifact = build(args.seeds, args.episodes)
    args.out.parent.mkdir(parents=True, exist_ok=True)
    args.out.write_text(json.dumps(artifact, indent=2, sort_keys=True) + "\n",
                        encoding="utf-8", newline="\n")
    try:
        shown = args.out.resolve().relative_to(ROOT)
    except ValueError:
        shown = args.out          # --out may point outside the repo
    print(f"wrote {shown}")

    r = artifact["results"]
    for entry in ENTRY_POINTS:
        b = r["planners_base"][entry]["weighted_astar"]
        p = r["planners_perturbed"][entry]["weighted_astar"]
        cls = r["h6_entry_classification"][entry]
        print(f"  {entry:<34} weightedA* {b['hops']}h/{b['cost_display']} -> "
              f"{p['hops']}h/{p['cost_display']}   {cls['verdict']}")
    reg = r["h6_affected_region"]
    print(f"  affected {reg['affected_states']:,} "
          f"({reg['affected_fraction_of_state_space']:.4%} of |S|) | "
          f"reachable {reg['reachable_states']:,} | "
          f"both {reg['affected_and_reachable']}")


if __name__ == "__main__":
    main()
