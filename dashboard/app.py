"""Streamlit page: upload an AD graph, get the route to Domain Admin.

    pip install streamlit
    streamlit run dashboard/app.py

**Streamlit is imported at call time, not at module import.** The core suite must
pass on a machine that has never installed it, so nothing here may be reachable
from a plain `import dashboard`. `tests/test_dashboard_optional_dependency.py`
enforces that rather than trusting it.

**This file renders. It does not compute.** Every number shown comes from
`dashboard.compute`, `dashboard.rl_upload`, `dashboard.rl_view` or
`dashboard.ingest`. There is no cost model, no traversal decision and no planner
call in this file.

## Layout, and the three things the previous version got wrong

The page answers one question -- *what is the cheapest route from this account to
Domain Admin, and can I believe it* -- so the route and its trustworthiness are
the whole first screen. Everything else is behind a disclosure. The coverage gate
did not move and must not: the part of it that is *about this route* stays above
the fold, and the collection-level distribution statistics sit one click away
under "Graph data quality".

Three specific faults drove this rewrite, all visible at 1440px:

1. **It ignored the width.** Content sat in one narrow column with most of the
   viewport empty. The route and the panel that qualifies it now sit side by
   side, which is also the order you read them in.
2. **The route was a text list.** For a tool about attack *paths* that is the
   wrong primitive — it read as log output. It is now a stepper: a node card
   per principal, a connector carrying the technique, its cost and its
   detection state.
3. **Detection was nine expanders.** One per hop on a nine-hop route, so the
   summary a reader needs was buried under nine identical closed rows. The
   per-hop state is now a dot on the connector, and the evidence is one table.

`_style` holds the whole visual system. Colours are stated explicitly rather
than inherited: the theme is pinned dark in `.streamlit/config.toml`, and an
earlier version used light cards, which put Streamlit's white heading text on a
pale green panel and made the word *proved* invisible.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

# `streamlit run dashboard/app.py` executes this file as a top-level script, not
# as a package module, so relative imports raise "attempted relative import with
# no known parent package" and the repo root is not on sys.path. Absolute imports
# plus this insert make the file work both ways — as the streamlit entry point
# and as `import dashboard.app`.
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dashboard import compute as C  # noqa: E402
from dashboard import rl_upload as U  # noqa: E402
from dashboard import rl_view as R  # noqa: E402
from dashboard.ingest import UnsupportedGraphError, load_uploads  # noqa: E402
from stealthpath.graph import AttackGraph  # noqa: E402

# Filtered to what is actually on disk. The perturbed graph is gitignored as of
# 2026-09-27 — kept locally, out of the repo — so a fresh clone has one demo,
# not two. Offering a picker entry whose file is absent would fail on select
# rather than at load, which is the worst moment to find out.
_DEMO_CANDIDATES = {
    "GOAD — published collection": (ROOT / "data" / "goad_graph.json", "base"),
    "GOAD — with one permission changed":
        (ROOT / "data" / "goad_graph_perturbed.json", "perturbed"),
}

DEMO_GRAPHS = {label: path for label, (path, _id) in _DEMO_CANDIDATES.items()
               if path.exists()}
DEMO_GRAPH_ID = {label: demo_id for label, (path, demo_id) in _DEMO_CANDIDATES.items()
                 if path.exists()}

# Category -> accent colour. Grouped by what the step *is*, so a reader can see
# "this route is four ACL abuses and a session theft" without reading the edge
# names one at a time.
CATEGORY_COLOUR = {
    "group_membership": "#5b8def",
    "acl_abuse": "#e08c3b",
    "credential_access": "#e05561",
    "session": "#a970d6",
    "remote_execution": "#2bb3a3",
    "local_admin": "#3d9e94",
    "domain_replication": "#d1495b",
    "delegation": "#9b7fd4",
    "trust": "#c9a227",
    "structural": "#7d8590",
}

# One-letter badge per object kind. Letters rather than emoji: emoji render at
# different sizes across platforms and broke the row rhythm on Windows.
KIND_BADGE = {
    "user": ("U", "#5b8def"),
    "computer": ("C", "#2bb3a3"),
    "group": ("G", "#e08c3b"),
    "domain": ("D", "#d1495b"),
    "gpo": ("P", "#a970d6"),
    "ou": ("O", "#7d8590"),
    "container": ("N", "#7d8590"),
}

VISIBILITY = {
    "covered": ("#3fb950", "a rule fires"),
    "conditional": ("#d29922", "only with object auditing (SACL) enabled"),
    "blind": ("#f85149", "nothing in the baseline catches this"),
    "unverified": ("#8b949e", "we have not sourced a detection for it"),
}


def _st():
    """Import streamlit lazily, with an actionable message if it is absent."""
    try:
        import streamlit as st
    except ModuleNotFoundError as exc:  # pragma: no cover - trivial branch
        raise ModuleNotFoundError(
            "The dashboard needs streamlit, which is deliberately not a core "
            "dependency: the test suite must run without it. Install with "
            "`pip install streamlit` then `streamlit run dashboard/app.py`."
        ) from exc
    return st


def _style(st) -> None:
    """The whole visual system. Presentation only — no value is derived here."""
    st.markdown(
        """
        <style>
          .block-container { padding-top: 2.2rem; max-width: 1500px; }
          section[data-testid="stSidebar"] { border-right: 1px solid #21262d; }

          .sp-top { display:flex; align-items:baseline; gap:.75rem;
                    border-bottom:1px solid #21262d; padding-bottom:.7rem;
                    margin-bottom:1.1rem; flex-wrap:wrap; }
          .sp-mark { font-size:1.45rem; font-weight:700; letter-spacing:-.02em;
                     color:#f0f3f6; }
          .sp-tag { color:#8b949e; font-size:.9rem; }
          .sp-badge { margin-left:auto; color:#8b949e; font-size:.8rem;
                      border:1px solid #30363d; border-radius:6px;
                      padding:.2rem .55rem; font-family:ui-monospace,monospace; }

          /* result tiles */
          .sp-tiles { display:grid; grid-template-columns:repeat(auto-fit,minmax(140px,1fr));
                      gap:.7rem; margin:.2rem 0 1.1rem 0; }
          .sp-tile { border:1px solid #21262d; border-radius:10px; padding:.7rem .9rem;
                     background:#0f141a; }
          .sp-tile .v { font-size:1.75rem; font-weight:650; line-height:1.15;
                        color:#f0f3f6; }
          .sp-tile .k { font-size:.75rem; color:#8b949e; text-transform:uppercase;
                        letter-spacing:.05em; margin-top:.15rem; }

          /* verdict */
          .sp-verdict { border-radius:10px; padding:.85rem 1.05rem; margin:0 0 1rem 0;
                        border:1px solid; display:flex; gap:.7rem; align-items:flex-start; }
          .sp-verdict .ico { font-size:1.05rem; line-height:1.4; }
          .sp-verdict .t { font-weight:650; font-size:1.02rem; }
          .sp-verdict .d { color:#c9d1d9; font-size:.9rem; margin-top:.15rem; }
          .v-proved  { background:rgba(63,185,80,.10);  border-color:rgba(63,185,80,.40); }
          .v-proved  .t { color:#56d364; }
          .v-learned { background:rgba(210,153,34,.10); border-color:rgba(210,153,34,.45); }
          .v-learned .t { color:#e3b341; }
          .v-none    { background:rgba(248,81,73,.10);  border-color:rgba(248,81,73,.40); }
          .v-none    .t { color:#ff7b72; }

          /* card */
          .sp-card { border:1px solid #21262d; border-radius:10px; padding:1rem 1.1rem;
                     background:#0f141a; margin-bottom:.9rem; }
          .sp-card h4 { margin:0 0 .6rem 0; font-size:.8rem; color:#8b949e;
                        text-transform:uppercase; letter-spacing:.06em; font-weight:600; }

          /* route stepper */
          .sp-node { display:flex; align-items:center; gap:.6rem; }
          .sp-kind { width:22px; height:22px; border-radius:6px; flex:0 0 22px;
                     display:inline-flex; align-items:center; justify-content:center;
                     font-size:.7rem; font-weight:700; color:#0d1117; }
          .sp-name { font-family:ui-monospace,SFMono-Regular,Menlo,monospace;
                     font-size:.85rem; color:#e6edf3; overflow-wrap:anywhere; }
          .sp-conn { display:flex; align-items:center; gap:.55rem;
                     margin:.1rem 0 .1rem 10px; padding:.28rem 0 .28rem 1.05rem;
                     border-left:2px solid #30363d; }
          .sp-tech { display:inline-block; color:#0d1117; border-radius:5px;
                     padding:.1rem .5rem; font-size:.74rem; font-weight:700; }
          .sp-w { color:#8b949e; font-size:.76rem; font-family:ui-monospace,monospace; }
          .sp-dot { width:8px; height:8px; border-radius:50%; display:inline-block; }
          .sp-start { color:#8b949e; font-size:.7rem; text-transform:uppercase;
                      letter-spacing:.06em; margin-bottom:.3rem; }

          /* misc */
          .sp-kv { display:flex; justify-content:space-between; gap:1rem;
                   padding:.32rem 0; border-bottom:1px solid #1c2128; font-size:.87rem; }
          .sp-kv:last-child { border-bottom:none; }
          .sp-kv .l { color:#8b949e; }
          .sp-kv .r { color:#e6edf3; text-align:right; }
          .sp-legend { color:#6e7681; font-size:.75rem; margin-top:.5rem; }
          .sp-note { color:#8b949e; font-size:.8rem; line-height:1.5; }

          /* fix list */
          .sp-fixhead { display:flex; align-items:center; gap:.7rem;
                        color:#6e7681; font-size:.7rem; text-transform:uppercase;
                        letter-spacing:.06em; padding-bottom:.45rem;
                        border-bottom:1px solid #21262d; margin-bottom:.15rem; }
          .sp-fixhead span:nth-child(1) { width:34px; text-align:right; }
          .sp-fixhead span:nth-child(2) { width:44px; text-align:right; }
          .sp-fix { display:flex; align-items:center; gap:.7rem; flex-wrap:wrap;
                    padding:.42rem 0; border-bottom:1px solid #1c2128; }
          .sp-fix:last-child { border-bottom:none; }
          .sp-cut { width:34px; text-align:right; font-weight:700;
                    color:#f0f3f6; font-size:.95rem; }
          .sp-share { width:44px; text-align:right; color:#8b949e;
                      font-size:.78rem; font-family:ui-monospace,monospace; }

          /* Streamlit columns do not stack on their own. Below this width the
             route/side-panel split leaves ~250px a side, which wrapped UPNs
             mid-token ("TYWIN.LANNISTER@SEV / ENKINGDOMS.LOCAL"). Stacking is
             the honest answer at that size. */
          @media (max-width: 1150px) {
            [data-testid="stHorizontalBlock"] { flex-wrap: wrap; }
            [data-testid="stHorizontalBlock"] > [data-testid="stColumn"] {
              min-width: 100% !important; flex: 1 1 100% !important;
            }
          }
        </style>
        """,
        unsafe_allow_html=True,
    )


def _kind_badge(kind: str) -> str:
    letter, colour = KIND_BADGE.get(kind.lower(), ("?", "#7d8590"))
    return (f'<span class="sp-kind" style="background:{colour}">{letter}</span>')


def _tiles(items: list[tuple[str, str]]) -> str:
    cells = "".join(f'<div class="sp-tile"><div class="v">{v}</div>'
                    f'<div class="k">{k}</div></div>' for v, k in items)
    return f'<div class="sp-tiles">{cells}</div>'


# --------------------------------------------------------------------------
# sidebar
# --------------------------------------------------------------------------

def _load_graph(st):
    """Sidebar: upload a collection, or pick a bundled demo. Returns (graph, demo_id)."""
    st.sidebar.markdown("### Graph")
    uploaded = st.sidebar.file_uploader(
        "BloodHound export (.zip) or StealthPath freeze (.json)",
        type=["zip", "json"],
        accept_multiple_files=True,
        help="Upload every domain's SharpHound zip together — cross-domain ACEs "
             "only resolve once all of them are in the same table. A frozen "
             "StealthPath graph goes in on its own.",
    )
    demo_label = st.sidebar.selectbox(
        "…or a demo graph", list(DEMO_GRAPHS) + ["(none — upload only)"])

    if uploaded:
        try:
            loaded = load_uploads([(f.name, f.getvalue()) for f in uploaded])
        except UnsupportedGraphError as exc:
            st.sidebar.error(str(exc))
            st.stop()
        graph = loaded.graph
        st.sidebar.success(
            f"{len(graph.nodes):,} objects · {len(graph.edges):,} relationships")
        if loaded.is_reconstruction:
            # A parsed export is this session's reconstruction of BloodHound's
            # ingest, and the only reason to believe it is the triple validator.
            st.sidebar.caption(
                "Reconstructed from collector output, checked triple-by-triple "
                "against BloodHound CE's own ingest. Session-scoped.")
            stubs = graph.provenance.get("referenced_but_not_collected")
            if stubs:
                st.sidebar.caption(
                    f"{stubs} object(s) referenced by an ACE or group but never "
                    "collected. Kept with no properties rather than dropped.")
        return graph, None

    if demo_label.startswith("(none"):
        st.sidebar.info("Upload a BloodHound export, or pick a demo graph.")
        st.stop()

    graph = AttackGraph.load(DEMO_GRAPHS[demo_label])
    st.sidebar.caption(
        f"{len(graph.nodes):,} objects · {len(graph.edges):,} relationships. "
        "Demo file, never written back.")
    return graph, DEMO_GRAPH_ID[demo_label]


def _query_controls(st, starts: list[str], targets: list[str], demo_id: str | None):
    st.sidebar.markdown("### Route")
    any_tier0 = "Any Domain Admin / domain"
    preferred = next((i for i, n in enumerate(starts) if "TYWIN" in n), 0)
    entry = st.sidebar.selectbox(
        "Start from", starts, index=preferred if demo_id else 0,
        help="Accounts that can actually reach a target are listed first.")
    target_choice = st.sidebar.selectbox("Reach", [any_tier0] + targets)
    target = None if target_choice == any_tier0 else target_choice

    seconds = st.sidebar.slider(
        "Time limit per planner (s)", 5, 180, 30, step=5,
        help="If the exact search overruns, the learned route is reported "
             "instead and marked unproved. A stopped training run is never "
             "shown as a finished one.")
    return entry, target, float(seconds)


# --------------------------------------------------------------------------
# route tab
# --------------------------------------------------------------------------

def render_verdict(st, plan) -> None:
    if not plan.found_route:
        reason = (plan.notes[0] if plan.notes
                  else "No route was found from this account.")
        st.markdown(
            '<div class="sp-verdict v-none"><div class="ico">✕</div><div>'
            '<div class="t">No route from this account</div>'
            f'<div class="d">{reason[:1].upper() + reason[1:]}</div></div></div>',
            unsafe_allow_html=True)
        return
    proved = plan.verified
    st.markdown(
        f'<div class="sp-verdict {"v-proved" if proved else "v-learned"}">'
        f'<div class="ico">{"✓" if proved else "≈"}</div><div>'
        f'<div class="t">{"Proved optimal" if proved else "Learned — not proved"}</div>'
        f'<div class="d">{plan.verdict()}</div></div></div>',
        unsafe_allow_html=True)


def render_tiles(st, plan, detection) -> None:
    if not plan.found_route:
        return
    blind = detection["blind_hops"]
    items = [
        (f"{plan.cost:.4g}", "detection cost"),
        (str(plan.hops), "hops"),
        (str(blind), "blind hops"),
        (f"{len(detection['techniques'])}", "ATT&CK techniques"),
        (f"{plan.seconds:.1f}s", "time to plan"),
    ]
    st.markdown(_tiles(items), unsafe_allow_html=True)


def render_route_diagram(st, plan, detection) -> None:
    """The route as a stepper: node card, connector, node card.

    Replaces a flat list of monospace names. The connector is where the
    information is — technique, what it costs, and a dot for whether anything
    would have logged it — because that is the part a reader is scanning for.
    """
    if not plan.found_route:
        return
    names = plan.node_names
    hops = C.annotate_hops(plan.route)
    det = {d["rel_type"]: d for d in detection["detail"]}
    kinds = plan.node_kinds or [""] * len(names)

    parts = ['<div class="sp-start">Start</div>']
    parts.append(f'<div class="sp-node">{_kind_badge(kinds[0])}'
                 f'<span class="sp-name">{names[0]}</span></div>')
    for i, (hop, nxt) in enumerate(zip(hops, names[1:])):
        colour = CATEGORY_COLOUR.get(hop["category"], "#7d8590")
        weight = "unpriced" if hop["weight"] is None else f'{hop["weight"]:g}'
        vis = det.get(hop["rel_type"], {}).get("visibility", "unverified")
        dot, meaning = VISIBILITY[vis]
        kind = kinds[i + 1] if i + 1 < len(kinds) else ""
        parts.append(
            f'<div class="sp-conn">'
            f'<span class="sp-tech" style="background:{colour}">{hop["rel_type"]}</span>'
            f'<span class="sp-w">{weight}</span>'
            f'<span class="sp-dot" style="background:{dot}" title="{vis}: {meaning}"></span>'
            f'</div>'
            f'<div class="sp-node">{_kind_badge(kind)}'
            f'<span class="sp-name">{nxt}</span></div>')
    parts.append(
        '<div class="sp-legend">Dot = would this step be logged? '
        '<span class="sp-dot" style="background:#3fb950"></span> covered · '
        '<span class="sp-dot" style="background:#d29922"></span> needs SACL · '
        '<span class="sp-dot" style="background:#f85149"></span> blind · '
        '<span class="sp-dot" style="background:#8b949e"></span> unverified</div>')

    st.markdown('<div class="sp-card"><h4>The route</h4>'
                + "".join(parts) + '</div>', unsafe_allow_html=True)


def render_side_panel(st, graph: AttackGraph, plan, detection) -> None:
    """Everything that qualifies the route, beside it rather than below it."""
    if not plan.found_route:
        for note in plan.notes[1:]:
            st.caption(f"· {note}")
        st.caption("Starts that can reach a target are listed first in the "
                   "sidebar, so an account further down may simply have no path.")
        return

    counts = detection["counts"]
    rows = "".join(
        f'<div class="sp-kv"><span class="l">'
        f'<span class="sp-dot" style="background:{VISIBILITY[k][0]}"></span> {k}'
        f'</span><span class="r">{counts[k]}</span></div>'
        for k in ("covered", "conditional", "blind", "unverified"))
    st.markdown(f'<div class="sp-card"><h4>Would you see it?</h4>{rows}</div>',
                unsafe_allow_html=True)

    if detection["blind_hops"]:
        st.error(f"**{detection['blind_hops']} of {detection['hops']} hops are "
                 "blind** — crossed without an event in either native AD "
                 "auditing or the endpoint rules this model accounts for.")
    elif detection["conditional_hops"]:
        st.warning(f"**{detection['conditional_hops']} hop(s) need object "
                   "auditing.** They emit 5136/4670 only where a SACL is "
                   "configured; on an ordinary object they are silent.")
    else:
        st.success("Every hop would generate an event.")

    if detection["techniques"]:
        st.markdown("**Hunt for:** "
                    + " ".join(f"`{t}`" for t in detection["techniques"]))

    # Trust, as key/value rather than paragraphs.
    hops = C.annotate_hops(plan.route)
    sourced = sum(1 for h in hops if h["status"] == "sourced")
    dropped = C.graph_profile(graph)["dropped_edge_types"]
    if dropped["recorded"]:
        drop_txt = (f"{dropped['type_count']} types, {dropped['edge_count']:,} edges"
                    if dropped["edge_count"] else "none")
    else:
        drop_txt = "not recorded"
    learned = plan.learned
    if learned is not None and learned.cost is not None:
        cross = ("agrees (+0.00%)" if learned.matches_exact
                 else f"{learned.gap_vs_exact:+.2%}")
    else:
        cross = "not run"
    st.markdown(
        '<div class="sp-card"><h4>Can you trust it?</h4>'
        f'<div class="sp-kv"><span class="l">hops with a cited price</span>'
        f'<span class="r">{sourced}/{len(hops)}</span></div>'
        f'<div class="sp-kv"><span class="l">optimality</span>'
        f'<span class="r">{"proved by exhaustive search" if plan.verified else "not proved"}</span></div>'
        f'<div class="sp-kv"><span class="l">independent learner</span>'
        f'<span class="r">{cross}</span></div>'
        f'<div class="sp-kv"><span class="l">dropped on ingest</span>'
        f'<span class="r">{drop_txt}</span></div>'
        '</div>', unsafe_allow_html=True)
    if dropped["recorded"] and dropped["edge_count"]:
        st.caption("A route using a dropped relationship would not appear here, "
                   "so this cost is an **upper bound**.")
    if learned is not None and learned.cost is not None and learned.load_factor > 0.5:
        st.caption(f"Learner weight table {learned.load_factor:.0%} occupied — "
                   "unrelated states are sharing buckets.")
    for note in plan.notes:
        st.caption(f"· {note}")


def render_evidence(st, detection) -> None:
    """One table, not one expander per hop.

    A nine-hop route produced nine identical closed rows, which buried the
    summary rather than supporting it.
    """
    with st.expander("Detection evidence — per hop"):
        st.dataframe(
            [{"step": d["rel_type"],
              "seen?": d["visibility"],
              "ATT&CK": d["technique"] or "—",
              "native": d["native"].replace("native_", ""),
              "endpoint": d["endpoint"].replace("endpoint_", ""),
              "evidence the price rests on": (d["source"] or "not sourced")}
             for d in detection["detail"]],
            use_container_width=True, hide_index=True)


# --------------------------------------------------------------------------
# defend tab
# --------------------------------------------------------------------------

def render_defend(st, graph: AttackGraph) -> None:
    """The three questions an analyst has that a single route does not answer."""
    rows = C.exposure_rows(graph)
    reachable = [r for r in rows if r["reachable"]]
    chokes = C.choke_point_rows(graph, top=10)
    one_hop = sum(1 for r in reachable if r["hops"] == 1)

    st.markdown(_tiles([
        (f"{len(rows):,}", "accounts assessed"),
        (f"{len(reachable):,}", "can reach tier-0"),
        (f"{one_hop:,}", "one hop away"),
        (f"{len(chokes)}", "choke points found"),
    ]), unsafe_allow_html=True)

    # **Stacked, not side by side.** Two half-width tables at 1440px truncated
    # every column that matters — a UPN alone needs ~300px, so the first step
    # read "GenericA" and the relationship "WriteDac". These are also sequential
    # questions (who is dangerous, then what to revoke), not a comparison.
    st.markdown('<div class="sp-card"><h4>Which accounts are dangerous?</h4>'
                '<div class="sp-note">Ranked by distance to a Domain Admins '
                'group, an Enterprise Admins group or a domain object. Use it '
                'for "we got an alert on this user — how bad is it?"</div>'
                '</div>', unsafe_allow_html=True)
    st.dataframe(
        [{"account": r["account"], "hops": r["hops"],
          "cost": None if r["static_cost"] is None else round(r["static_cost"], 2),
          "first step": r["first_step"], "reaches": r["reaches"]}
         for r in reachable],
        use_container_width=True, hide_index=True, height=340,
        # Names are long UPNs; without this the two widest columns clip and the
        # numeric ones get space they do not need.
        column_config={
            "account": st.column_config.TextColumn(width="large"),
            "reaches": st.column_config.TextColumn(width="medium"),
        })
    st.caption(
        "Cost is the **static** model over the whole directory in one pass. "
        "The route tab runs the history-aware search for one account and "
        "charges more for reusing a technique, so the two differ slightly — "
        "this list ranks, that one answers.")
    st.download_button("Download exposure (CSV)", _csv(reachable),
                       "stealthpath_exposure.csv", "text/csv")

    st.markdown('<div class="sp-card" style="margin-top:1.4rem">'
                '<h4>What should we fix first?</h4>'
                '<div class="sp-note">Single relationships ranked by how many '
                'accounts lose <b>all</b> access to tier-0 without them.</div>'
                '</div>', unsafe_allow_html=True)
    if not chokes:
        st.info("No single relationship changes reachability on this graph.")
        return
    # A list, not a dataframe. Each row is `FROM —Rel→ TO`, which runs to ~90
    # characters of UPN; every dataframe column width Streamlit offers clipped
    # it, and the two names are the whole point of the row. Ten rows is a list.
    rows = []
    for c in chokes:
        colour = CATEGORY_COLOUR.get(
            C.annotate_hops([c["relationship"]])[0]["category"], "#7d8590")
        flag = ("" if c["actionable"] else
                '<span class="sp-w" style="color:#d29922"> · not revocable</span>')
        rows.append(
            '<div class="sp-fix">'
            f'<span class="sp-cut">{c["accounts_cut"]}</span>'
            f'<span class="sp-share">{c["share_cut"]:.0%}</span>'
            f'<span class="sp-name">{c["from"]}</span>'
            f'<span class="sp-tech" style="background:{colour}">{c["relationship"]}</span>'
            f'<span class="sp-name">{c["to"]}</span>{flag}</div>')
    st.markdown(
        '<div class="sp-card"><div class="sp-fixhead">'
        '<span>cut</span><span>share</span><span>revoke this relationship</span>'
        '</div>' + "".join(rows) + '</div>', unsafe_allow_html=True)
    for c in chokes:
        if c["caveat"]:
            st.caption(f"· **{c['relationship']}** {c['from']} → {c['to']}: "
                       f"{c['caveat']}")
    st.caption(
        "Cutting reachability and being safe to revoke are different questions "
        "and only the first is measured. Rows are limited to edges on some "
        "account's cheapest route, so an edge carrying only second-cheapest "
        "routes will not appear — and removing one listed here may push "
        "traffic onto another.")
    st.download_button("Download fix list (CSV)", _csv(chokes),
                       "stealthpath_chokepoints.csv", "text/csv")


def _csv(rows: list[dict]) -> str:
    """Rows to CSV text. Rendering, not computation — no value is derived."""
    import csv
    import io
    if not rows:
        return ""
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return buf.getvalue()


# --------------------------------------------------------------------------
# disclosures
# --------------------------------------------------------------------------

def render_comparison(st, graph: AttackGraph, entry: str, target: str | None) -> None:
    """The project's actual claim: three planners, three answers."""
    with st.expander("Compare the three planners"):
        st.caption(
            "Shortest path ignores detection entirely. Risk-weighted A* prices "
            "each technique. History-aware also charges for reusing a technique "
            "the attacker has already used.")
        shortest, weighted, history = C.split_comparison(
            C.compare_entry_point(graph, entry, target))
        routing = C.routing_verdict(graph, entry, target)

        rows = []
        for label, rec in (("1 · Shortest path (fewest hops)", shortest),
                           ("2 · Risk-weighted A*", weighted),
                           ("3 · History-aware (reported above)", history)):
            if rec is None:
                rows.append({"planner": label, "hops": "—", "cost": "—",
                             "techniques": "no route"})
                continue
            rows.append({"planner": label, "hops": rec["hops"],
                         "cost": f'{rec["cost"]:.4g}',
                         "techniques": " → ".join(rec["route"])})
        st.dataframe(rows, use_container_width=True, hide_index=True)

        if routing.get("differs"):
            st.markdown("**Detection-aware routing changes the answer on this "
                        "start** — the priced route uses a different technique "
                        "sequence than fewest-hops.")
        else:
            st.markdown("**Detection-aware routing does not change the answer "
                        "on this start**: shortest and priced return the same "
                        "technique sequence. That is a property of this graph, "
                        "not a bug — see Graph data quality.")


def render_data_quality(st, graph: AttackGraph) -> None:
    """The collection-level statistics. Real, and not about any one route."""
    with st.expander("Graph data quality"):
        profile = C.graph_profile(graph)
        absences = C.structural_absences(graph)
        pricing = C.pricing_verdict(graph)

        st.markdown(
            f"**Pricing coverage: {pricing['verdict']}** — "
            f"{pricing['walkable_sourced']:,} of {pricing['walkable_total']:,} "
            f"walkable edges carry a cited weight "
            f"({pricing['walkable_sourced_share']:.1%}); weight table "
            f"{pricing['weights_sourced']}/{pricing['weights_total']}.")

        st.markdown(_tiles([
            (f"{profile['nodes']:,}", "objects"),
            (f"{profile['edges_walkable']:,}", "walkable relationships"),
            (f"{profile['modal_weight_share']:.1%}", "same-cost share"),
            (f"{absences['adcs']['nodes_present']:,}", "AD CS objects"),
            (f"{absences['session_edges']:,}", "session edges"),
            (f"{absences['delegation_edges']:,}", "delegation edges"),
        ]), unsafe_allow_html=True)
        st.caption(
            f"{profile['modal_weight_edges']:,} of {profile['edges_walkable']:,} "
            f"walkable edges price at {profile['modal_weight']:g}. When that "
            "share is high, detection-aware routing has little to choose "
            "between on this graph — a property of the directory, reported "
            "rather than tuned away. AD CS edges are not modelled, and few "
            "session edges means credential-theft routes are under-represented.")


def render_stored_record(st, entry: str, demo_id: str | None) -> None:
    """The recorded artifact for the demo graphs, never for an upload."""
    stored_key = next((e for e in C.ENTRY_POINTS if e in entry), None)
    if not (demo_id and stored_key):
        return
    with st.expander("Recorded result for this demo start"):
        stored = R.stored_run(stored_key, graph_id=demo_id)
        st.markdown(
            f"`results/h5_h6.json`, graph `{stored['graph_sha256'][:16]}…` · "
            f"{stored['episodes']:,} episodes · seeds {stored['seeds']}")
        st.markdown(f"Exact optimum **{stored['optimum_cost']:.4g}** over "
                    f"{stored['optimum_hops']} hops. Tabular Q-learning costs "
                    f"{stored['policy_costs']}, gaps {stored['gaps']}.")
        st.caption(stored["provenance"])


# --------------------------------------------------------------------------

def main() -> None:  # pragma: no cover - entry point, exercised by hand
    st = _st()
    st.set_page_config(page_title="StealthPath", layout="wide",
                       initial_sidebar_state="expanded")
    _style(st)

    graph, demo_id = _load_graph(st)
    starts = C.starting_points(graph)
    targets = C.target_names(graph)

    st.markdown(
        '<div class="sp-top"><span class="sp-mark">StealthPath</span>'
        '<span class="sp-tag">cheapest route to Domain Admin, priced by how '
        'likely each step is to be noticed</span>'
        f'<span class="sp-badge">{len(graph.nodes):,} objects · '
        f'{len(graph.edges):,} rels</span></div>',
        unsafe_allow_html=True)

    if not starts:
        st.error("This graph has no objects to start from.")
        st.stop()
    if not targets:
        st.error(
            "No Domain Admins group, Enterprise Admins group or domain object "
            "was found, so there is no destination to plan to. Targets are "
            "derived from well-known RIDs and domain structure; if this "
            "directory is shaped differently, the graph may be incomplete.")
        st.stop()

    entry, target, budget_seconds = _query_controls(st, starts, targets, demo_id)
    view = graph.with_gpo_expansion()
    key = (entry, target, budget_seconds, id(graph))

    route_tab, defend_tab = st.tabs(
        ["Attack route — one account", "Defend — whole directory"])

    with route_tab:
        if st.button("Find the route to Domain Admin", type="primary"):
            with st.spinner("Searching for the optimal route, then checking it "
                            "against a learned one…"):
                st.session_state["plan"] = (key, U.plan_upload(
                    view,
                    C.resolve_sources(view, entry),
                    C.resolve_targets(view, target),
                    budget=R.TrainingBudget(max_seconds=budget_seconds)))

        cached = st.session_state.get("plan")
        if cached and cached[0] == key:
            plan = cached[1]
            detection = C.route_detection_rows(plan.route)
            render_verdict(st, plan)
            render_tiles(st, plan, detection)
            left, right = st.columns([1.35, 1], gap="large")
            with left:
                render_route_diagram(st, plan, detection)
            with right:
                render_side_panel(st, graph, plan, detection)
            if plan.found_route:
                render_evidence(st, detection)
        else:
            st.info("Pick a start account in the sidebar, then press "
                    "**Find the route to Domain Admin**.")

        render_comparison(st, graph, entry, target)
        render_data_quality(st, graph)
        render_stored_record(st, entry, demo_id)

    with defend_tab:
        render_defend(st, graph)


if __name__ == "__main__":  # pragma: no cover
    main()
