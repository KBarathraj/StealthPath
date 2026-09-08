"""Figure 3 — SQL_SVC's route comparison, the H1 headline.

    python tools/figure_route_comparison.py

`SQL_SVC` is the one entry point where the plain and risk-weighted planners
disagree, and the shape of that disagreement is the H1 result: **the same four
hops at a lower price**, not a longer detour bought with extra steps. H1 as
pre-registered predicted a hops-versus-risk trade-off; there isn't one, and this
figure is what that looks like.

Everything is derived at render time through `dashboard.compute`, which routes
every number through `risk.weight_of` and `ad_schema.category_of`. Nothing is
typed in. The rendering lives in `dashboard.figures` alongside Figures 4-6, so
the paper and the dashboard draw this from one implementation.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import matplotlib.pyplot as plt  # noqa: E402

from dashboard.compute import (  # noqa: E402
    compare_entry_point, route_static_risk_per_hop,
)
from dashboard.figures import route_comparison_figure, save_figure  # noqa: E402
from stealthpath.graph import AttackGraph  # noqa: E402

OUT_DIR = ROOT / "results" / "figures"
STEM = "fig3_route_comparison_sql_svc"
ENTRY = "SQL_SVC@NORTH"


def main() -> None:
    graph = AttackGraph.load(ROOT / "data" / "goad_graph.json")
    comparison = compare_entry_point(graph, ENTRY)

    # The per-hop breakdown is attached here rather than inside
    # `compare_entry_point`, because that function's records reproduce
    # `results/h5_h6.json` field for field and the artifact is cited by hash.
    for record in comparison.values():
        record["static_risk_per_hop"] = route_static_risk_per_hop(record["route"])

    fig = route_comparison_figure(comparison, ENTRY)
    written = save_figure(fig, OUT_DIR / STEM)
    plt.close(fig)

    plain, weighted = comparison["shortest_path"], comparison["weighted_astar"]
    print(f"wrote {written[0].relative_to(ROOT)} / .svg")
    print(f"  plain    {plain['hops']}h  {plain['static_risk']:.2f}  "
          f"{' -> '.join(plain['route'])}")
    print(f"  weighted {weighted['hops']}h  {weighted['static_risk']:.2f}  "
          f"{' -> '.join(weighted['route'])}")
    print(f"  gap {plain['static_risk'] - weighted['static_risk']:.2f}, "
          f"same hop count: {plain['hops'] == weighted['hops']}")


if __name__ == "__main__":
    main()
