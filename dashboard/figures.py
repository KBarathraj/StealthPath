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
