"""Figures 4-6 — Q-learning trajectories against the exact optimum.

    python tools/figure_rl_trajectory.py

One figure per documented entry point, seed 0, at the pre-registered 50,000
episodes. Everything is derived by running the learner at render time; nothing is
typed in and no stored number is plotted.

**These are the same figures the dashboard draws.** `dashboard.figures` holds the
one implementation; this script only chooses which runs to render and where to
write them. A figure in the paper that a demo cannot reproduce is a figure nobody
can check.

Rendering takes ~3s in total: 0.3s, 1.5s and 0.8s of training for the three entry
points. The trajectories are deterministic given the seed, so re-running produces
identical bytes.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from dashboard.compute import ENTRY_POINTS  # noqa: E402
from dashboard.figures import rl_trajectory_figure, save_figure  # noqa: E402
from dashboard.rl_view import REPRO_EPISODES, training_run  # noqa: E402
from stealthpath.graph import AttackGraph  # noqa: E402

import matplotlib.pyplot as plt  # noqa: E402

OUT_DIR = ROOT / "results" / "figures"
SEED = 0
# Figure numbers follow the three entry points in the order findings.md reports
# them, so fig4 is the cheap route and fig6 the one that carries the H5 result.
STEMS = {
    "SAMWELL.TARLY@NORTH": "fig4_rl_trajectory_samwell",
    "SQL_SVC@NORTH": "fig5_rl_trajectory_sql_svc",
    "TYWIN.LANNISTER@SEVENKINGDOMS": "fig6_rl_trajectory_tywin",
}


def main() -> None:
    graph = AttackGraph.load(ROOT / "data" / "goad_graph.json")
    for entry in ENTRY_POINTS:
        run = training_run(graph, entry, SEED, episodes=REPRO_EPISODES)
        fig = rl_trajectory_figure(run)
        written = save_figure(fig, OUT_DIR / STEMS[entry])
        plt.close(fig)
        print(f"wrote {written[0].relative_to(ROOT)} / .svg")
        print(f"  optimum {run['reference']['cost']:.4g}  final {run['final_cost']:.4g}  "
              f"gap {run['gap_vs_optimum']:+.2%}  first target ep "
              f"{run['first_target_episode']:,}  converged ep "
              f"{run['converged_at_episode']:,}")


if __name__ == "__main__":
    main()
