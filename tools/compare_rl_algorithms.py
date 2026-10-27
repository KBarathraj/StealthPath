"""Compare the RL planners against the exact optimum on the reference graph.

Runs tabular Q-learning, SARSA and (optionally) PPO from each documented entry
point and reports every one **as an optimality gap against `exact_history_search`**
-- the only honest way to score a learner on an MDP whose optimum is known. None
of them can beat the exact route; the reportable content is how close each gets,
how reliably across seeds, and where it falls short.

    python tools/compare_rl_algorithms.py                 # Q-learning + SARSA, 3 seeds
    python tools/compare_rl_algorithms.py --seeds 5        # as pre-registered for RL
    python tools/compare_rl_algorithms.py --ppo            # include PPO (slow)
    python tools/compare_rl_algorithms.py --ppo --only SQL_SVC@NORTH

Writes `results/rl_comparison.json`. ASCII-only output: the default Windows
console codepage mangles anything else (a project convention).

PPO is the pre-registered algorithm the project substituted Q-learning for; this
is where it is actually measured. It is off by default because MaskablePPO on CPU
in deterministic mode takes minutes per start, against about a second for the
tabular learners.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
import sys
import time
from pathlib import Path as FsPath

# Repo root on sys.path so this runs as a plain script, matching run_h5_h6.py.
sys.path.insert(0, str(FsPath(__file__).resolve().parent.parent))

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph
from stealthpath.planners import q_learning, sarsa
from stealthpath.planners.exact_history import exact_history_search
from stealthpath.risk import PROVISIONAL_WEIGHTS, history_cost_fn, unsourced

ROOT = FsPath(__file__).resolve().parent.parent
GRAPH = ROOT / "data" / "goad_graph.json"
OUT = ROOT / "results" / "rl_comparison.json"

ENTRY_POINTS = [
    "SAMWELL.TARLY@NORTH",
    "SQL_SVC@NORTH",
    "TYWIN.LANNISTER@SEVENKINGDOMS",
]
MAX_HOPS = 20
ALLOWED = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)


def _gap(cost: float | None, optimum: float) -> float | None:
    if cost is None or not optimum:
        return None
    return (cost - optimum) / optimum


def _run_tabular(trainer, graph, source, cfg):
    t = time.perf_counter()
    r = trainer(graph, source, graph.tier0_targets(), history_cost_fn(), cfg, ALLOWED)
    dt = time.perf_counter() - t
    return r.path, dt, r.converged_at_episode


def _run_ppo(graph, source, cfg):
    from stealthpath.planners import ppo
    t = time.perf_counter()
    r = ppo.train(graph, source, graph.tier0_targets(), history_cost_fn(), cfg, ALLOWED)
    return r.path, time.perf_counter() - t, None


def _emit(payload: dict, results: dict) -> None:
    """Write the artifact after every entry, so a long or interrupted run leaves
    the entries it did finish on disk rather than all-or-nothing at the end."""
    payload["results"] = results
    OUT.parent.mkdir(exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2), encoding="utf-8")


def compare(seeds: list[int], include_ppo: bool, only: list[str] | None,
            ppo_seeds: list[int], ppo_timesteps: int, payload: dict) -> dict:
    graph = AttackGraph.load(str(GRAPH)).with_gpo_expansion()
    cost = history_cost_fn()
    entries = [e for e in ENTRY_POINTS if not only or e in only]

    algos = ["q_learning", "sarsa"] + (["ppo"] if include_ppo else [])
    results: dict[str, dict] = {}

    for entry in entries:
        source = graph.find(name=entry)
        opt = exact_history_search(graph, source, graph.tier0_targets(), cost,
                                   ALLOWED, MAX_HOPS)
        print(f"\n{entry}", flush=True)
        print(f"  exact optimum: cost {opt.cost:.2f}, {opt.length} hops, "
              f"route {' -> '.join(opt.rel_types(graph))}", flush=True)
        rec: dict = {
            "exact_cost": round(opt.cost, 6),
            "exact_hops": opt.length,
            "exact_route": opt.rel_types(graph),
            "algorithms": {},
        }
        for algo in algos:
            algo_seeds = ppo_seeds if algo == "ppo" else seeds
            runs = []
            for seed in algo_seeds:
                if algo == "q_learning":
                    path, dt, conv = _run_tabular(
                        q_learning.train, graph, source[0],
                        q_learning.QLearningConfig(seed=seed))
                elif algo == "sarsa":
                    path, dt, conv = _run_tabular(
                        sarsa.train, graph, source[0],
                        sarsa.SarsaConfig(seed=seed))
                else:
                    from stealthpath.planners import ppo as _ppo
                    path, dt, conv = _run_ppo(
                        graph, source[0],
                        _ppo.PPOConfig(seed=seed, total_timesteps=ppo_timesteps))
                gap = _gap(path.cost if path else None, opt.cost)
                runs.append({
                    "seed": seed,
                    "cost": round(path.cost, 6) if path else None,
                    "hops": path.length if path else None,
                    "route": path.rel_types(graph) if path else None,
                    "gap_vs_exact": gap,
                    "reached": path is not None,
                    "converged_at_episode": conv,
                    "seconds": round(dt, 2),
                })
                # PPO seeds are minutes apart; persist each one as it lands.
                if algo == "ppo":
                    rec["algorithms"][algo] = {"runs": list(runs)}
                    results[entry] = rec
                    _emit(payload, results)
            gaps = [r["gap_vs_exact"] for r in runs if r["gap_vs_exact"] is not None]
            reached = sum(1 for r in runs if r["reached"])
            summary = {
                "reached": f"{reached}/{len(algo_seeds)}",
                "best_gap": min(gaps) if gaps else None,
                "worst_gap": max(gaps) if gaps else None,
                "mean_gap": statistics.mean(gaps) if gaps else None,
                "all_optimal": bool(gaps) and all(abs(g) < 1e-9 for g in gaps),
                "timesteps": ppo_timesteps if algo == "ppo" else None,
            }
            rec["algorithms"][algo] = {"summary": summary, "runs": runs}
            bg = summary["best_gap"]
            wg = summary["worst_gap"]
            bg_s = "n/a" if bg is None else f"{bg:+.2%}"
            wg_s = "n/a" if wg is None else f"{wg:+.2%}"
            mean_s = runs and round(statistics.mean(r["seconds"] for r in runs), 1)
            print(f"  {algo:11s} reached {summary['reached']:>4}  "
                  f"gap best {bg_s:>8} worst {wg_s:>8}  "
                  f"{'ALL OPTIMAL' if summary['all_optimal'] else '':11s}  "
                  f"~{mean_s}s/seed", flush=True)
        results[entry] = rec
        _emit(payload, results)
    return results


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--seeds", type=int, default=3,
                    help="tabular seeds (0..n-1); pre-registration uses 5 for RL")
    ap.add_argument("--ppo", action="store_true", help="include PPO (slow)")
    ap.add_argument("--ppo-seeds", type=int, default=2,
                    help="PPO seeds (fewer, because each is minutes on CPU)")
    ap.add_argument("--ppo-timesteps", type=int, default=150_000,
                    help="PPO env steps per seed (fixed, fair budget across starts)")
    ap.add_argument("--only", nargs="*", help="restrict to these entry points")
    args = ap.parse_args()

    seeds = list(range(args.seeds))
    ppo_seeds = list(range(args.ppo_seeds))
    print("StealthPath - RL algorithm comparison", flush=True)
    print(f"graph {GRAPH.name} sha256 {hashlib.sha256(GRAPH.read_bytes()).hexdigest()[:16]}", flush=True)
    print(f"cost: history-dependent (k=1.2); tabular seeds {seeds}; "
          f"PPO {'ON' if args.ppo else 'off'}"
          + (f", {len(ppo_seeds)} seed(s) x {args.ppo_timesteps:,} steps" if args.ppo else ""),
          flush=True)
    n_unsourced = len(unsourced())
    print(f"NOTE: {n_unsourced} of {len(PROVISIONAL_WEIGHTS)} weights unsourced; "
          "these are development numbers, not a reportable result until sourced.",
          flush=True)

    payload = {
        "generated_by": "tools/compare_rl_algorithms.py",
        "graph_sha256": hashlib.sha256(GRAPH.read_bytes()).hexdigest(),
        "cost_model": "history-dependent, k=1.2",
        "tabular_seeds": seeds,
        "ppo_seeds": ppo_seeds if args.ppo else [],
        "ppo_timesteps": args.ppo_timesteps if args.ppo else None,
        "max_hops": MAX_HOPS,
        "traversal_view": "with_gpo_expansion",
        "reproducibility_note": (
            "Tabular Q-learning and SARSA are bit-reproducible. PPO is "
            "seed-reproducible on a fixed CPU torch build only, not byte-identical; "
            "it is reported with its seed and is never cited by hash."
        ),
        "results": {},
    }

    compare(seeds, args.ppo, args.only, ppo_seeds, args.ppo_timesteps, payload)

    print(f"\nwrote {OUT.relative_to(ROOT)}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
