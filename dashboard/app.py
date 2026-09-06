"""Streamlit page: coverage gate first, then the RL view.

    pip install -e ".[dashboard]"
    streamlit run dashboard/app.py

**Streamlit is imported at call time, not at module import.** The core suite must
pass on a machine that has never installed it, so nothing here may be reachable
from a plain `import dashboard`. `tests/test_dashboard_optional_dependency.py`
enforces that rather than trusting it.

**This file renders. It does not compute.** Every number shown comes from
`dashboard.compute` or `dashboard.rl_view`, and every plot from
`dashboard.figures`. There is no cost model, no traversal decision and no planner
call in this file — if a number needs deriving, it belongs upstream, because a
second derivation in a presentation layer is how a demo starts disagreeing with
the paper.

**The coverage gate comes first on purpose.** 19 dropped edge types, no AD CS,
14 deferred weights. A tool that prints three confident numbers without saying
what it could not price is worse than no tool, so the honesty panel is not behind
a tab.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# `streamlit run dashboard/app.py` executes this file as a top-level script, not
# as a package module, so relative imports raise "attempted relative import with
# no known parent package" and the repo root is not on sys.path. Absolute imports
# plus this insert make the file work both ways — as the streamlit entry point
# and as `import dashboard.app`. Found by running it; importing it as a module
# succeeds either way, so the module-level import test could not have caught it.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard import compute as C  # noqa: E402
from dashboard import rl_view as R  # noqa: E402
from dashboard.figures import rl_trajectory_figure  # noqa: E402
from stealthpath.graph import AttackGraph  # noqa: E402
GRAPHS = {
    "base — goad_graph.json (3c1bef97…)": ROOT / "data" / "goad_graph.json",
    "perturbed — goad_graph_perturbed.json (7f80e6dc…)": (
        ROOT / "data" / "goad_graph_perturbed.json"),
}


def _st():
    """Import streamlit lazily, with an actionable message if it is absent."""
    try:
        import streamlit as st
    except ModuleNotFoundError as exc:  # pragma: no cover - trivial branch
        raise ModuleNotFoundError(
            "The dashboard needs streamlit, which is deliberately not a core "
            "dependency: the test suite must run without it. Install with "
            "`pip install -e \".[dashboard]\"`."
        ) from exc
    return st


def render_coverage_gate(st, graph: AttackGraph) -> None:
    """What this graph cannot answer, before anything it can."""
    profile = C.graph_profile(graph)
    cov = C.coverage(graph)
    absences = C.structural_absences(graph)

    st.subheader("Coverage — what this graph cannot tell you")
    st.caption(
        "Shown first and never collapsed. The three planners below are only as "
        "good as this panel admits."
    )

    a, b, c, d = st.columns(4)
    a.metric("modal-weight share", f"{profile['modal_weight_share']:.1%}",
             help="Edges carrying the single most common derived weight. The "
                  "antecedent of the paper's conditional claim.")
    b.metric("HHI over weights", f"{profile['hhi_weights']:.3f}",
             help="1.0 would mean every walkable edge shares one signature.")
    c.metric("acl_abuse share", f"{profile['acl_abuse_share']:.1%}")
    d.metric("HHI over categories", f"{profile['hhi_categories']:.3f}")

    dropped = profile["dropped_edge_types"]
    if dropped["recorded"]:
        st.warning(
            f"**{dropped['type_count']} edge types dropped at load "
            f"({dropped['edge_count']:,} edges).** Certificate abuse accounts for "
            f"{absences['adcs']['dropped_edges']:,} of them across "
            f"{len(absences['adcs']['dropped_edge_types'])} types. Any route that "
            f"would have run through a dropped edge is missing, so every cost "
            f"here is an **upper bound**."
        )
    else:
        # Absence of the key is not evidence of a clean load.
        st.warning(
            "**Dropped edge types were never recorded for this graph.** Its "
            "provenance block is empty — this is not the same as nothing having "
            "been dropped, and it must not be read as a clean collection."
        )

    st.write(
        f"- **AD CS**: {absences['adcs']['nodes_present']} certificate objects "
        f"collected, **0 edges modelled** — a deferral, not a gap in the data.\n"
        f"- **Sessions**: {absences['session_edges']} `HasSession` edges — an idle "
        f"lab, so credential theft is under-represented.\n"
        f"- **Delegation**: {absences['delegation_edges']} edges — a whole route "
        f"class is absent.\n"
        f"- **Weights**: {cov['weights_sourced']} of {cov['weights_total']} sourced; "
        f"{cov['walkable_edges']['sourced_share']:.1%} of walkable edges priced "
        f"from a cited source."
    )

    fully = [f"{e.split('@')[0]}/{p}" for e, pl in cov["routes"].items()
             for p, r in pl.items() if r and not r["fully_sourced"]]
    if fully:
        st.error(f"Routes traversing a non-sourced edge: {', '.join(fully)}")
    else:
        st.success(
            "Every reported route is **100% sourced**, though the graph as a "
            f"whole is {cov['walkable_edges']['sourced_share']:.1%}. The deferred "
            "weights sit on no reported route — which is the stated reason they "
            "were deferred."
        )


def render_rl_view(st, graph: AttackGraph) -> None:
    """The RL panel: reference first, then a run, then the record beside it."""
    st.subheader("Q-learning against the exact optimum")

    entry = st.selectbox("Entry point", C.ENTRY_POINTS)
    seed = st.selectbox("Seed", R.DEFAULT_SEEDS)

    reference = R.reference_optimum(graph, entry)
    st.info(
        f"**Exact Tier 1 optimum: {reference['cost']:.4g}** over "
        f"{reference['hops']} hops — computed before training. The learner is "
        f"reported as a gap against this, never as a training curve."
    )

    if st.button(f"Train {entry.split('@')[0]}, seed {seed} "
                 f"({R.REPRO_EPISODES:,} episodes, ~1s)"):
        try:
            run = R.training_run(graph, entry, seed)
        except R.BudgetExceeded as exc:
            st.error(f"{exc} Showing the stored result instead.")
            run = None
        if run is not None:
            st.pyplot(rl_trajectory_figure(run))
            m1, m2, m3, m4 = st.columns(4)
            m1.metric("final cost", f"{run['final_cost']:.4g}")
            m2.metric("gap vs optimum", f"{run['gap_vs_optimum']:+.2%}")
            m3.metric("first target at episode",
                      f"{run['first_target_episode']:,}"
                      if run["first_target_episode"] is not None else "never")
            m4.metric("wall clock", f"{run['seconds']:.2f}s")
            if run["episodes_capped"]:
                st.warning(
                    "This run was capped, so it explored on a compressed "
                    "epsilon schedule. It is **not** the first "
                    f"{run['episodes']:,} episodes of a full run and must not be "
                    "compared against the stored numbers."
                )

    if st.button(f"Reproduce all 15 runs (3 entry points x 5 seeds, ~13s)"):
        with st.spinner("training 15 policies"):
            out = R.reproduce_all(graph)
        (st.success if out["all_optimal"] else st.error)(
            f"**{out['headline']}** in {out['seconds']:.1f}s")
        st.write("**Episodes to first target reached** — a reported finding:")
        for e, firsts in out["first_target_episodes"].items():
            st.write(f"- `{e}`: {firsts}")
        if out["budget_failures"]:
            st.error(f"{len(out['budget_failures'])} run(s) exceeded the budget "
                     f"and were not counted as optimal.")

    st.divider()
    st.caption("Stored result — the record, cited by hash in findings.md")
    stored = R.stored_run(entry)
    st.write(
        f"Graph `{stored['graph_sha256'][:16]}…` · {stored['episodes']:,} episodes "
        f"· seeds {stored['seeds']} · optimum **{stored['optimum_cost']:.4g}** · "
        f"gaps {stored['gaps']}"
    )
    st.caption(
        "A live run above corroborates this record; it does not replace it. "
        "The published numbers are the artifact's."
    )


def main() -> None:  # pragma: no cover - entry point, exercised by hand
    st = _st()
    st.set_page_config(page_title="StealthPath", layout="wide")
    st.title("StealthPath — attack-path planning under a detection-risk model")

    label = st.sidebar.selectbox("Frozen graph", list(GRAPHS))
    graph = AttackGraph.load(GRAPHS[label])
    st.sidebar.caption(
        f"{len(graph.nodes)} nodes · {len(graph.edges):,} edges. Frozen and "
        "committed; the dashboard never loads live data."
    )

    render_coverage_gate(st, graph)
    st.divider()
    render_rl_view(st, graph)


if __name__ == "__main__":  # pragma: no cover
    main()
