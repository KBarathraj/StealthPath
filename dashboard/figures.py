"""Matplotlib rendering for the RL view. One code path, two consumers.

The same function draws the dashboard's live plot and the paper's Figure 4-6.
That is deliberate: a figure in the write-up and a panel in the demo that are
produced by different code can disagree, and the one a reader sees is not the one
a reviewer checked.

**Rendering only.** Nothing here computes a cost, a route or a category. It draws
what `rl_view.training_run()` returns and nothing else, so the cost model has
exactly one implementation and this file cannot become a second opinion about it.

Determinism follows `tools/figure_*.py`: the Agg backend, a pinned SVG hash salt,
metadata timestamps dropped at save time and CRLF normalised, so re-rendering
identical data produces identical bytes.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib

matplotlib.use("Agg")
# Same salt as the existing figure scripts. matplotlib salts generated SVG
# element ids, so without pinning it two renders of identical data differ.
matplotlib.rcParams["svg.hashsalt"] = "stealthpath"
import matplotlib.pyplot as plt  # noqa: E402
from matplotlib.figure import Figure  # noqa: E402

__all__ = ["rl_trajectory_figure", "save_figure", "INK", "MUTED", "MODAL", "REFERENCE"]

# Shared with tools/figure_weight_distribution.py so the paper's figures read as
# one set rather than as two authors' defaults.
INK = "#1a1a1a"
MUTED = "#b8b8b8"
MODAL = "#c1440e"
REFERENCE = "#1f6f5c"


def rl_trajectory_figure(run: dict[str, Any], *, title: str | None = None) -> Figure:
    """Plot one run's checkpoint trajectory landing on the exact Tier 1 optimum.

    Takes a `rl_view.training_run()` result. The optimum is drawn as a horizontal
    reference because that is what the result *is* — an optimality gap against a
    reference computed before training, never a training curve read off its own
    best value.

    Checkpoints before the greedy policy first finds any route carry `cost=None`.
    Those are drawn as an explicit shaded "no route yet" span rather than dropped,
    because on TYWIN that span is 12,000 episodes and silently starting the line
    at 12k would hide the exploration finding the run exists to show.
    """
    traj = run["trajectory"]
    reference = run["reference"]["cost"]

    episodes = [p["episode"] for p in traj]
    costs = [p["cost"] for p in traj]
    found = [(e, c) for e, c in zip(episodes, costs) if c is not None]

    fig, ax = plt.subplots(figsize=(7.2, 4.0))

    # The reference first, so the trajectory is drawn over it.
    if reference is not None:
        ax.axhline(reference, color=REFERENCE, linewidth=1.6, zorder=2,
                   label=f"exact optimum (Tier 1) = {reference:.4g}")

    if found:
        first_found = found[0][0]
        if first_found > episodes[0]:
            ax.axvspan(episodes[0] - (episodes[1] - episodes[0] if len(episodes) > 1 else 0),
                       first_found, color=MUTED, alpha=0.25, zorder=1, linewidth=0)
            ax.text(first_found, ax.get_ylim()[1], " no route from the greedy policy yet",
                    ha="left", va="top", fontsize=8, color="#777777")
        ax.plot([e for e, _ in found], [c for _, c in found],
                color=MODAL, linewidth=1.4, marker="o", markersize=2.6,
                zorder=3, label="greedy policy cost at checkpoint")

    first_target = run.get("first_target_episode")
    if first_target is not None:
        ax.axvline(first_target, color=INK, linewidth=0.9, linestyle=":", zorder=2)
        ax.text(first_target, ax.get_ylim()[0], f" first target reached: ep {first_target:,}",
                rotation=90, ha="right", va="bottom", fontsize=7.5, color=INK)

    converged = run.get("converged_at_episode")
    if converged is not None:
        ax.axvline(converged, color=REFERENCE, linewidth=0.9, linestyle="--", zorder=2)
        ax.text(converged, ax.get_ylim()[1], f"converged: ep {converged:,} ",
                rotation=90, ha="right", va="top", fontsize=7.5, color=REFERENCE)

    ax.set_xlabel("training episode")
    ax.set_ylabel("route cost under the history-dependent model")
    ax.set_title(title or f"{run['entry']} — seed {run['seed']}", fontsize=11, color=INK)
    ax.spines[["top", "right"]].set_visible(False)
    ax.legend(frameon=False, fontsize=8.5, loc="upper right")

    gap = run.get("gap_vs_optimum")
    if gap is not None:
        # Wall-clock time is deliberately NOT drawn. It is a property of the
        # machine, not of the result, and putting it here made two renders of
        # identical data differ — the same defect as matplotlib's <dc:date>,
        # reintroduced by hand. The dashboard shows timing as page text instead.
        ax.text(0.985, 0.06,
                f"final {run['final_cost']:.4g}   gap {gap:+.2%}\n"
                f"{run['episodes']:,} episodes",
                transform=ax.transAxes, ha="right", va="bottom", fontsize=8.5,
                color=INK, linespacing=1.5,
                bbox=dict(boxstyle="round,pad=0.5", facecolor="#fbfbfb",
                          edgecolor="#cccccc", linewidth=0.8))

    fig.tight_layout()
    return fig


def save_figure(fig: Figure, stem: Path | str, dpi: int = 400) -> list[Path]:
    """Write PNG and SVG with the project's byte-stability treatment.

    Same handling as `tools/figure_*.py`: drop the metadata timestamp, whose key
    differs per backend, then normalise the SVG's newlines so committed bytes do
    not depend on which machine rendered them.
    """
    stem = Path(stem)
    stem.parent.mkdir(parents=True, exist_ok=True)
    written = []
    for ext in ("png", "svg"):
        meta = {"Date": None} if ext == "svg" else {"Software": None}
        out = stem.with_suffix(f".{ext}")
        fig.savefig(out, dpi=dpi, bbox_inches="tight", metadata=meta)
        written.append(out)
    svg = stem.with_suffix(".svg")
    svg.write_bytes(svg.read_bytes().replace(b"\r\n", b"\n"))
    return written


def route_comparison_figure(comparison: dict[str, Any], entry: str,
                            *, title: str | None = None) -> Figure:
    """Plot two planners' routes from one entry point side by side.

    Takes a `compute.compare_entry_point()` result. Like the trajectory figure
    this computes nothing: the routes, per-hop weights and totals all arrive
    already derived, so the figure cannot disagree with `findings.md` about a
    number it did not calculate.

    The design decision that matters is the **shared prefix**. Both routes open
    `SQLAdmin -> HasSession` and only diverge at hop 3, which is the whole point
    of the comparison — the weighted planner is not finding a longer way around,
    it is making a different choice at one node. Drawing the common hops in the
    muted colour and the divergence in full ink makes that readable in one look;
    two independently coloured tracks would not.
    """
    routes = [("shortest path", comparison["shortest_path"], MODAL),
              ("risk-weighted", comparison["weighted_astar"], REFERENCE)]

    # Where the two routes stop agreeing. Derived, not hard-coded, so the figure
    # stays correct if the graph or the weights move.
    a, b = routes[0][1]["route"], routes[1][1]["route"]
    split = next((i for i, (x, y) in enumerate(zip(a, b)) if x != y), min(len(a), len(b)))

    fig, ax = plt.subplots(figsize=(9.5, 4.2))
    fig.patch.set_facecolor("white")
    ax.set_facecolor("white")

    n_hops = max(len(a), len(b))
    for row, (label, rec, colour) in enumerate(routes):
        y = 1 - row
        rels = rec["route"]
        ax.plot([0, n_hops], [y, y], color=MUTED, linewidth=1.0, zorder=1)
        for i, rel in enumerate(rels):
            shared = i < split
            c = MUTED if shared else colour
            ax.plot([i, i + 1], [y, y], color=c,
                    linewidth=3.2 if not shared else 2.0, zorder=2,
                    solid_capstyle="round")
            ax.annotate("", xy=(i + 1, y), xytext=(i + 0.72, y), zorder=3,
                        arrowprops=dict(arrowstyle="-|>", color=c, linewidth=0))
            weight = rec["static_risk_per_hop"][i]
            ax.text(i + 0.5, y + 0.085, rel, ha="center", va="bottom",
                    fontsize=8.5, color=INK if not shared else "#777777",
                    fontweight="bold" if not shared else "normal")
            ax.text(i + 0.5, y - 0.10, f"{weight:g}", ha="center", va="top",
                    fontsize=8, color=c if not shared else "#999999")
        ax.text(-0.12, y, label, ha="right", va="center", fontsize=9.5,
                color=INK, fontweight="bold")
        ax.text(n_hops + 0.12, y,
                f"{rec['hops']} hops\n{rec['static_risk']:.2f}",
                ha="left", va="center", fontsize=9, color=colour,
                fontweight="bold", linespacing=1.4)

    # The divergence, called out once rather than left to the colour change.
    ax.axvline(split, color=INK, linestyle=(0, (2, 3)), linewidth=1.0, zorder=0)
    ax.text(split, 1.42, f"routes diverge at hop {split + 1}", ha="center",
            va="bottom", fontsize=8.5, color=INK)

    gap = routes[0][1]["static_risk"] - routes[1][1]["static_risk"]
    # The edge worth naming is the loudest one the weighted route drops, not the
    # first one it changes. Those differ here: divergence starts at `AdminTo`
    # (2.5) but the finding is that `DCSync` (6.5) is avoided, and taking the
    # first divergent hop instead of the dearest dropped one captioned this
    # figure wrongly on its first render.
    dropped = [(w, r) for r, w in zip(a, routes[0][1]["static_risk_per_hop"])
               if r not in set(b)]
    avoided = max(dropped)[1] if dropped else None
    ax.text(0.5, -0.62,
            f"identical hop count · {avoided} avoided · static-risk gap {gap:.2f}",
            transform=ax.get_yaxis_transform(), ha="center", va="center",
            fontsize=9.5, color=INK,
            bbox=dict(boxstyle="round,pad=0.55", facecolor="#fbfbfb",
                      edgecolor="#cccccc", linewidth=0.8))

    ax.set_xlim(-1.55, n_hops + 1.15)
    ax.set_ylim(-0.95, 1.75)
    ax.axis("off")
    ax.set_title(title or f"{entry} — same length, different price",
                 fontsize=11, color=INK)
    fig.tight_layout()
    return fig
