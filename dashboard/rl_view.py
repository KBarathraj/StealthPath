"""View model for the RL panel. Data only — no rendering, no framework.

Live training is in scope because it was measured rather than assumed: the full
15-run reproduction is ~15s wall clock and the worst single run is under 2s on
the frozen graphs. See the 2026-09-06 timing entry in `docs/findings.md`.

**The design follows from that measurement.** At ~1s per run there is nothing to
watch, so this module builds *re-run*, not *progress*: the exact Tier 1 optimum
is computed first and stands as the reference, a run is executed, and its
checkpoint trajectory is reported as having landed on that reference or not. The
`on_checkpoint` observer is used for budget enforcement, not for a progress bar.

**Two provenances, never merged.** Every structure returned here carries a
`provenance` field that is either `STORED` or `LIVE`. A live run *corroborates*
the record; it does not replace it. `docs/findings.md` cites the artifact by
hash, and a number computed in a browser session is not that artifact.

**The frozen graphs bound nothing about an upload.** Training is fast here
because the reachable component is tiny — `q_size` of 11, 84 and 1,076 against a
nominal |S| of 801,792. An arbitrary BloodHound graph has no such guarantee, so
every entry point into live training takes a `TrainingBudget` and falls back to
stored results rather than running unbounded.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from typing import Any, Sequence

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET, GPO_EXPANSION_EDGES
from stealthpath.graph import AttackGraph
from stealthpath.planners.exact_history import exact_history_search
from stealthpath.planners.q_learning import QLearningConfig, train
from stealthpath.risk import history_cost_fn

from .compute import ENTRY_POINTS, MAX_HOPS, RESULTS_PATH

__all__ = [
    "STORED", "LIVE", "TrainingBudget", "BudgetExceeded",
    "reference_optimum", "training_run", "reproduce_all",
    "stored_run", "DEFAULT_SEEDS", "REPRO_EPISODES",
]

STORED = "stored (results/h5_h6.json, cited by hash in findings.md)"
LIVE = "live run (this session — corroborates the record, does not replace it)"

DEFAULT_SEEDS = [0, 1, 2, 3, 4]
REPRO_EPISODES = 50_000
"""The pre-registered count, and what `rl_config.episodes` in the artifact says."""

_ALLOWED = frozenset(DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES)


class BudgetExceeded(RuntimeError):
    """Raised when a live run passes its wall-clock cap.

    Carries `elapsed` and `episode` so the caller can say what it stopped and
    where, rather than reporting a bare failure. The intended handling is to fall
    back to the stored result, which is why this is an exception rather than a
    silently truncated run: a partial policy reported as a result would be a
    worse outcome than declining to run.
    """

    def __init__(self, elapsed: float, episode: int, budget: "TrainingBudget"):
        self.elapsed = elapsed
        self.episode = episode
        self.budget = budget
        super().__init__(
            f"training exceeded its {budget.max_seconds:g}s budget after "
            f"{episode:,} episodes ({elapsed:.1f}s). No partial policy is "
            f"reported; use the stored result instead."
        )


@dataclass(frozen=True)
class TrainingBudget:
    """Hard caps for live training on a graph nobody has measured.

    Defaults are sized from the frozen graphs with headroom — the worst measured
    single run is 1.87s, so 30s is roughly 16x the observed worst case. That is a
    guess about *unmeasured* graphs and is meant to be: the point is that there
    is a ceiling and a fallback, not that the ceiling is precisely right.
    """

    max_episodes: int = REPRO_EPISODES
    max_seconds: float = 30.0

    def capped_episodes(self, requested: int) -> int:
        return min(requested, self.max_episodes)

    def caps_episodes(self, requested: int) -> bool:
        return requested > self.max_episodes


def _view(graph: AttackGraph):
    v = graph.with_gpo_expansion()
    return v, sorted(v.tier0_targets())


def reference_optimum(graph: AttackGraph, entry: str) -> dict[str, Any]:
    """The exact Tier 1 optimum, computed **before** any training.

    This is the horizontal reference a trajectory is plotted against, and it is
    deliberately computed first: the learner is reported as an optimality gap,
    never as a training curve, so the line it must reach has to exist before the
    run starts rather than being read off the run's own best value.
    """
    view, targets = _view(graph)
    path = exact_history_search(view, view.find(name=entry), targets,
                                history_cost_fn(), _ALLOWED, MAX_HOPS)
    if path is None:
        return {"entry": entry, "reachable": False, "cost": None,
                "hops": None, "route": []}
    return {
        "entry": entry,
        "reachable": True,
        "cost": path.cost,
        "hops": path.length,
        "route": path.rel_types(view),
        "planner": "exact_history_search (Tier 1, optimal reference)",
    }


def training_run(graph: AttackGraph, entry: str, seed: int,
                 episodes: int = REPRO_EPISODES,
                 budget: TrainingBudget | None = None) -> dict[str, Any]:
    """One live run, reported against the reference as a landed trajectory.

    Raises `BudgetExceeded` rather than returning a partial policy. The wall-clock
    check runs inside `on_checkpoint`, so it fires at most once per 1,000
    episodes — precise enough for a 30s ceiling and free of any per-step cost.
    """
    budget = budget or TrainingBudget()
    reference = reference_optimum(graph, entry)
    view, targets = _view(graph)

    requested = episodes
    episodes = budget.capped_episodes(episodes)
    cfg = QLearningConfig(episodes=episodes, seed=seed)

    started = time.perf_counter()

    def watchdog(episode: int, _cost: float | None) -> None:
        elapsed = time.perf_counter() - started
        if elapsed > budget.max_seconds:
            raise BudgetExceeded(elapsed, episode, budget)

    result = train(view, view.find(name=entry)[0], targets, history_cost_fn(),
                   cfg, allowed_rel_types=_ALLOWED, on_checkpoint=watchdog)
    elapsed = time.perf_counter() - started

    cost = result.path.cost if result.path else None
    gap = None
    if cost is not None and reference["cost"]:
        gap = (cost - reference["cost"]) / reference["cost"]

    return {
        "provenance": LIVE,
        "entry": entry,
        "seed": seed,
        "episodes": episodes,
        "episodes_requested": requested,
        # Surfaced, not hidden: `_epsilon` derives its decay span from
        # cfg.episodes, so a capped run explores on a compressed schedule and is
        # NOT the first N episodes of a full run. Any comparison against the
        # stored numbers is invalid once this is True.
        "episodes_capped": budget.caps_episodes(requested),
        "seconds": elapsed,
        "reference": reference,
        "trajectory": [{"episode": ep, "cost": c} for ep, c in result.checkpoints],
        "final_cost": cost,
        "gap_vs_optimum": gap,
        "matches_optimum": gap == 0.0,
        "converged_at_episode": result.converged_at_episode,
        # Always displayed. TYWIN's [9033, 4206, 1735, 946, 6410] is a reported
        # finding about exploration difficulty, not an embarrassment to bury.
        "first_target_episode": result.first_target_episode,
        "success_rate_first_5k": result.success_rate_first_5k,
        "goal_reached_total": result.goal_reached_total,
        "q_size": result.q_size,
    }


def reproduce_all(graph: AttackGraph,
                  entries: Sequence[str] | None = None,
                  seeds: Sequence[int] | None = None,
                  episodes: int = REPRO_EPISODES,
                  budget: TrainingBudget | None = None) -> dict[str, Any]:
    """The "reproduce all 15 runs" action: 3 entry points x 5 seeds.

    Reports `15/15 at +0.00%` as a derived count rather than a claim — the
    headline is recomputed from the runs, so a regression shows up as 14/15
    instead of as prose that still says 15.
    """
    entries = list(entries if entries is not None else ENTRY_POINTS)
    seeds = list(seeds if seeds is not None else DEFAULT_SEEDS)

    started = time.perf_counter()
    runs, failures = [], []
    for entry in entries:
        for seed in seeds:
            try:
                runs.append(training_run(graph, entry, seed, episodes, budget))
            except BudgetExceeded as exc:
                failures.append({"entry": entry, "seed": seed, "reason": str(exc)})

    optimal = [r for r in runs if r["matches_optimum"]]
    return {
        "provenance": LIVE,
        "runs": runs,
        "budget_failures": failures,
        "total": len(entries) * len(seeds),
        "completed": len(runs),
        "at_optimum": len(optimal),
        "headline": f"{len(optimal)}/{len(entries) * len(seeds)} at +0.00%",
        "all_optimal": len(optimal) == len(entries) * len(seeds),
        "seconds": time.perf_counter() - started,
        "first_target_episodes": {
            e: [r["first_target_episode"] for r in runs if r["entry"] == e]
            for e in entries
        },
    }


def stored_run(entry: str, graph_id: str = "base",
               results_path=None) -> dict[str, Any]:
    """The recorded result for one entry point, tagged as the record.

    Rendered beside a live run, never merged into it. The stored numbers are what
    `findings.md` cites; the live ones are this session's corroboration.
    """
    data = json.loads((results_path or RESULTS_PATH).read_text(encoding="utf-8"))
    h5 = data["results"]["h5_rl_no_retraining"]
    if entry not in h5:
        raise KeyError(f"no stored result for {entry!r}. "
                       f"Available: {', '.join(sorted(h5))}")
    block = h5[entry]
    optimum = block["optimum_base" if graph_id == "base" else "optimum_perturbed"]
    return {
        "provenance": STORED,
        "entry": entry,
        "graph_id": graph_id,
        "episodes": data["rl_config"]["episodes"],
        "seeds": data["rl_config"]["seeds"],
        "optimum_cost": optimum["cost"],
        "optimum_hops": optimum["hops"],
        "policy_costs": [s["base_policy_cost" if graph_id == "base"
                           else "replayed_cost"] for s in block["seeds"]],
        "gaps": [s["base_gap_vs_optimum" if graph_id == "base"
                   else "perturbed_gap_vs_new_optimum"] for s in block["seeds"]],
        "success_rate_first_5k": [s["success_rate_first_5k"] for s in block["seeds"]],
        "converged_at_episode": [s["converged_at_episode"] for s in block["seeds"]],
        "graph_sha256": data["graphs"][graph_id]["sha256"],
    }
