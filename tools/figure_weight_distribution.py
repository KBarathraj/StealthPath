"""Figure 1 — detection-signature concentration in the frozen collection.

    python tools/figure_weight_distribution.py

This is the figure a reader checks their own collection against, so it carries
the paper's conditional claim: the antecedent is a measurable property, and this
plot is how it is measured. Everything is derived from `data/goad_graph.json` at
render time; nothing is typed in.

**No synthetic data is plotted.** The contrast with independent per-edge cost
sampling is stated as arithmetic in the annotation — a continuous draw assigns
distinct costs with probability 1, so its HHI is 1/|E| — rather than simulated,
because a simulated distribution sitting beside real data in one figure is
exactly the ambiguity build rule 7 exists to prevent.
"""

from __future__ import annotations

import sys
from collections import Counter
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET  # noqa: E402
from stealthpath.graph import AttackGraph  # noqa: E402
from stealthpath.risk import PROVISIONAL_WEIGHTS  # noqa: E402

OUT = ROOT / "results" / "figures" / "fig1_weight_distribution"

INK = "#1a1a1a"
MUTED = "#b8b8b8"
MODAL = "#c1440e"


def main() -> None:
    graph = AttackGraph.load(ROOT / "data" / "goad_graph.json")
    walkable = [e for e in graph.edges if e.rel_type in DEFAULT_TRAVERSAL_SET]
    n = len(walkable)

    by_weight = Counter(PROVISIONAL_WEIGHTS[e.rel_type].weight for e in walkable)
    types_at = {w: sorted({e.rel_type for e in walkable
                           if PROVISIONAL_WEIGHTS[e.rel_type].weight == w})
                for w in by_weight}
    modal_w, modal_n = by_weight.most_common(1)[0]
    hhi = sum((c / n) ** 2 for c in by_weight.values())

    weights = sorted(by_weight)
    counts = [by_weight[w] for w in weights]
    labels = [f"{w:g}" for w in weights]
    colours = [MODAL if w == modal_w else MUTED for w in weights]

    fig, ax = plt.subplots(figsize=(10.5, 4.8))
    bars = ax.barh(labels, counts, color=colours, height=0.72,
                   edgecolor=INK, linewidth=0.6)

    for w, bar, count in zip(weights, bars, counts):
        share = count / n
        pct = f"{share:.1%}" if share >= 0.001 else "<0.1%"
        note = f"{count:,}  ({pct})"
        # The modal row always names its types: which rights collapse into one
        # signature is the whole point of the figure, and "5 edge types" hides it.
        if len(types_at[w]) <= 3 or w == modal_w:
            note += "   " + ", ".join(types_at[w])
        else:
            note += f"   {len(types_at[w])} edge types"
        # The modal label goes *inside* its bar. Extending the axis to fit it
        # outside would stretch the x-range well past n and visually shrink the
        # 79.4% bar - which is the one thing this figure exists to show.
        if w == modal_w:
            ax.text(bar.get_width() - n * 0.012, bar.get_y() + bar.get_height() / 2,
                    note, va="center", ha="right", fontsize=8.5,
                    color="white", weight="bold")
        else:
            ax.text(bar.get_width() + n * 0.012, bar.get_y() + bar.get_height() / 2,
                    note, va="center", ha="left", fontsize=8, color="#555555")

    ax.set_xlim(0, n * 1.02)
    ax.set_xlabel(f"walkable edges  (n = {n:,} of {len(graph.edges):,} collected)",
                  fontsize=9)
    ax.set_ylabel("derived detection weight", fontsize=9)
    ax.set_title("Detection-signature concentration, GOADv2 frozen collection",
                 fontsize=11, weight="bold", loc="left", color=INK)
    ax.invert_yaxis()
    ax.tick_params(labelsize=8)
    for side in ("top", "right"):
        ax.spines[side].set_visible(False)
    ax.grid(axis="x", color="#e6e6e6", linewidth=0.7)
    ax.set_axisbelow(True)

    annotation = (
        f"modal-weight share  {modal_n / n:.1%}   ({modal_n:,} edges at {modal_w:g})\n"
        f"HHI over derived weights  {hhi:.3f}\n"
        f"independent continuous draw would give  1/{n:,} ≈ {1 / n:.4f}"
    )
    ax.text(0.985, 0.06, annotation, transform=ax.transAxes, ha="right", va="bottom",
            fontsize=8.5, color=INK, linespacing=1.55,
            bbox=dict(boxstyle="round,pad=0.55", facecolor="#fbfbfb",
                      edgecolor="#cccccc", linewidth=0.8))

    fig.text(0.005, 0.005,
             "One derived weight per BloodHound relationship type, under the "
             "stated telemetry baseline. Real collection; no synthetic data.",
             fontsize=7, color="#777777")
    fig.tight_layout()
    OUT.parent.mkdir(parents=True, exist_ok=True)
    for ext in ("png", "svg"):
        fig.savefig(f"{OUT}.{ext}", dpi=400, bbox_inches="tight")
    plt.close(fig)

    print(f"wrote {OUT.relative_to(ROOT)}.png / .svg")
    print(f"  modal share {modal_n / n:.1%}  HHI {hhi:.3f}  "
          f"{len(by_weight)} distinct weights over {n:,} walkable edges")


if __name__ == "__main__":
    main()
