# Handoff

**As of 2026-08-19.** `194 passed, 2 skipped`. Clean tree. Everything below runs with no network, no database, no lab.

Read `CLAUDE.md` first for the build rules, then this. To find your way around
the code without reading it all, use the graph index — see "Finding your way
around" below.

---

## What the project is

Compares three ways of planning a route through an Active Directory attack
graph: plain shortest path, a risk-weighted planner that avoids loud actions,
and a learning planner that adapts. The question is whether the learning planner
beats a well-tuned static one at staying quiet, and whether that depends on risk
changing based on what the attacker already did.

**All three planners are built and run on the real collected data**, plus a
fourth that exists to score the third: an exact history-aware search used as the
optimal reference, so the learner reports as an optimality gap rather than a
training curve.

**The headline result is negative and that is the finding.** Adaptive planning
changes no route on this graph, at any repeat penalty. See "The Shape D collapse"
in `abstract.md` — the claim is a conditional with a measured antecedent, not an
unconditional statement about AD.

---

## State

**Stage status lives in `CLAUDE.md`, in the Status block — read it there.** It
is deliberately not repeated here. This file used to carry its own copy, the two
drifted, and one of them ended up claiming Stage 3 had not started while the
other correctly reported most of its properties implemented. The Stage 3 exit
criteria are in the same file, immediately below Status.

**That file is local and deliberately untracked** — gitignored, absent from a
clone by design. If you are reading this from a fresh clone you do not have it;
ask for it rather than reconstructing its content here.

The short version, for orientation only: Stages 1-4 done, Stage 5's experiments
done with the write-ups outstanding, Stage 7 (dashboard) proposed and awaiting a
decision.

**Frozen graph:** `data/goad_graph.json`, sha256 `3c1bef97f75df7d2…`
783 nodes / 5825 edges. Published GOADv2 SharpHound 2.3.3 collection
(2024-04-10, Unlicense), ingested via BloodHound CE. **Not our own lab** — a
hypervisor conflict blocked the GOAD build. Full provenance including two
superseded hashes lives in `data/collection_provenance.json`.

**Three structural holes in the data**, all recorded, none fixable without our
own lab: sessions near-absent (5 `HasSession` edges), zero delegation edges,
ADCS dropped (19 edge types still discarded, 2,443 edges).

All three are checkable rather than asserted, and the 19 is easy to look for in
the wrong place: it lives in **`data/goad_graph.json` itself**, under
`provenance.dropped_unknown_edge_types`, written by the loader
(`loader_neo4j.py`) at freeze time — *not* in `data/collection_provenance.json`,
which only points at it. An audit on 2026-08-10 checked the separate provenance
file, did not find the key, and wrongly reported the figure as unverifiable. The
19 entries and the 2,443-edge total are correct.

---

## Immediate next steps, in order

**Everything experimental is done.** H1-H6 are measured, Stage 3's gate is
closed, both Stage 4 tiers are built, and every number is reproducible from
committed artifacts. What remains is writing, plus one scoping decision.

1. **Finish the writing.** In dependency order, roughly a day and a half:
   - **Figure 3** - `SQL_SVC`'s route comparison. The headline result currently
     exists only as prose. Plain `SQLAdmin -> HasSession -> AdminTo -> DCSync`
     (4h, 20.00) against weighted `SQLAdmin -> HasSession -> MemberOf ->
     GenericWrite` (4h, 15.10); same hop count, `DCSync` avoided, gap 4.9.
   - **Optimality-gap write-up.** State the reproducibility claim plainly: two
     independent 50,000-episode runs produced a byte-identical artifact
     (`7a5d92df`), and the +0.00% gap held across three entry points and five
     seeds. That answers "did you cherry-pick a seed" mechanically, and most RL
     work cannot make the first claim at all.
   - **Related work.** Three verified facts from arXiv:2406.19596, all confirmed
     against the primary source: it models **three** BloodHound edge types
     (`AdminTo`, `HasSession`, `MemberOf`) with no access-control edges at all;
     its graphs are DBCreator synthetics at **r500 (1,493/3,456), r1000
     (2,996/8,814), r2000 (5,997/18,795)**; and it states single-domain scope
     with one Domain Admin target, so the cross-forest axis is usable as a
     **scope difference, never a superiority claim**. Two corrections to make
     while there: that paper is Data61/CSCRC-led with Adelaide co-authorship, so
     "the Adelaide programme" is imprecise for it, and the r-graph sizes are
     r500/r1000/r2000 rather than the r1000/r2000/r4000 currently written.

2. **Decide the dashboard scope.** Stage 7 came back into scope on 2026-08-19:
   faculty expect an upload-a-graph demo showing all three planners, with a
   validation layer. A full proposal was delivered and is awaiting a decision -
   see "Dashboard - proposed, not started" below.

---

## Decisions that would be expensive to re-derive

- **The unpinned figure set is known, not assumed empty.** A deliberate sweep on
  2026-08-10 checked every number in live claim text against its source.
  Everything derivable is pinned by `tests/test_reported_figures.py`: the
  concentration figures (79.4% modal share, 95.3% `acl_abuse`, HHI 0.654 and
  0.909), the superseded 80.4% and why it is a different measurement, both |S|
  figures with their traversal sets, `k`, the 19 dropped types, the 14 deferred
  weights, and the H5/H6 artifact values.

  **Hand-maintained, and it is the pytest counts.** `194 passed, 2 skipped`
  appears in `README.md`, `CLAUDE.md`, `handoff.md` and
  `stage1_lab_runbook.md`. It is not statically derivable — pytest's collected
  count expands `parametrize` and so differs from the AST function count in
  `tests/test_inventory.json` (111 vs 123 when that gap was last measured), and
  running pytest inside pytest to obtain it is not acceptable. The sweep found
  all four stale, plus two stale claims in `README.md` (32 unsourced weights,
  and the learner described as PPO when it is tabular Q-learning). **Update
  these four by hand whenever the suite count changes.**

- **Provenance is split across two files and neither says so.** The human
  narrative — why the collection was chosen, what the known gaps are — lives in
  `data/collection_provenance.json`. The machine record of what the loader
  actually discarded lives *inside* `data/goad_graph.json`, under `provenance`,
  written by `loader_neo4j.py` at freeze time. On 2026-08-10 an audit looked for
  `dropped_unknown_edge_types` in the narrative file, did not find it, and
  reported the 19-dropped-types figure as unverifiable. The figure was correct;
  the audit read the wrong file. The narrative file does point at the record, but
  only in prose inside a `note` field, and the graph file says nothing about the
  narrative file existing. `tests/test_reported_figures.py` now pins the split so
  it is visible rather than folklore.

- **Target set** is `tier0_targets()`: DA groups, EA groups, domain objects, by
  well-known name, never by BloodHound's high-value marking. DC computer objects
  are deliberately absent — `isdc` is present in real SharpHound data and agrees
  with `DCFor`, but the decision was left open.
- **Three scoped traversal views**, each gating an edge that would otherwise
  claim a capability the attacker lacks: `with_gpo_expansion()`,
  `with_preconditions()` (RBCD needs an SPN), `with_local_admin_expansion()`
  (privileged local groups only, by RID).
- **Rights that are never sufficient alone are not traversable** —
  `PARTIAL_RIGHT_EDGES`. Build rule 8.
- **Static gate or history?** Build rule 9. If the missing piece is visible on an
  edge or property, gate it statically; if it is a fact about the path, it is
  Stage 3's and Stage 2 must not approximate it.
- **History summary is "set of categories used" + one step change on first
  repeat.** 400,896 states, ~23 MB sparse Q-table. The count-based alternative
  was costed at 11.8 GB and rejected. This weakens H3 to "risk depends on whether
  a category has been used before" — stated as a scope section in
  `abstract.md`, not a footnote.
- **`random_ad` cannot back distributional claims.** Its edge mix is inverted
  relative to real AD. Build rule 7, measured in
  `generator_vs_real_distribution.md`.

---

## Traps — things that have already bitten

**The telemetry baseline has two halves and it is easy to use one.** Native AD
auditing (5136/4670, SACL-dependent) *and* EDR/Sysmon endpoint telemetry (no
SACL). The Shape D edges were first derived at 1.5 from the native half alone,
which would have produced a striking counterintuitive headline that was an
artifact. It survived a full review pass. `RiskWeight.channels` now makes the
omission structural, and
`test_sourced_weight_accounts_for_both_baseline_halves` fails if a half is
unanswered — but it cannot catch a *wrong* answer, only an absent one.

**Do not edit an ordering test to agree with a weight.** Two were flipped and
flipped back in one session, so while the error was live the suite endorsed it.
Tests are now split: `test_weight_invariants.py` holds claims derived from the
baseline (hand-written, suspect the weight first when one fails);
`test_weight_snapshot.py` holds numbers (generated by
`tools/snapshot_weights.py` — regenerate and read the diff, never hand-edit).

**Price loudness, not impact.** Every weight revised so far moved *down*
because the original encoded how bad the technique is rather than how likely it
is to be noticed. `SpoofSIDHistory` 8.0 → 3.5, delegation trio 6.5/6.5/7.0 →
4.0/4.5/5.0.

**Never anchor a sourced weight to an unsourced one.** Derive bottom-up from
named detections, then record where it lands relative to neighbours as a
*prediction* in the cross-check table. If a derived number contradicts a
provisional neighbour, the neighbour is wrong.

**Watch for silently deleted tests.** A patch range once swallowed three
unrelated tests and the total went 110 → 107 with everything green.
`test_no_tests_were_silently_deleted` guards this now.

**The frozen graph hash must stay reproducible.** `save()` writes `newline="\n"`
explicitly and `.gitattributes` marks `data/*.json` as `-text`. Without both, a
cloner computes a hash matching nothing in the provenance.

---

## Commands

```bash
pytest -q
python -m stealthpath.cli compare --graph data/goad_graph.json
python tools/snapshot_weights.py          # after any weight change
```

Three documented entry points, all with verified routes:
`SAMWELL.TARLY@NORTH` (2 hops, needs `with_gpo_expansion()`),
`SQL_SVC@NORTH` (4 hops), `TYWIN.LANNISTER@SEVENKINGDOMS` (9 hops).

---

## Finding your way around

`graphify-out/` holds a queryable index of this repo — 560 nodes, 1,072 edges,
built from tree-sitter AST extraction plus a semantic pass over the docs. It
exists so a session can locate things without reading whole modules. It is
gitignored and regenerable; it is **not** a collection and never a citation.

```bash
graphify god-nodes                            # core abstractions
graphify explain "static_cost_fn()"           # what a symbol touches, file:line, direction
graphify affected "RiskWeight" --depth 2      # what breaks if I change this
graphify path "AttackGraph" "weight_of()" --undirected
graphify update .                             # rebuild after edits — nothing does this automatically
```

`affected` is the one that pays for itself here. Changing a weight reaches 55
nodes across `risk.py`, both planners, `cli.py`, `snapshot_weights.py` and three
test files — one call, versus a grep sweep and several file reads.

**Then open the file.** The index gives you a location; the content comes from
reading it. Three reasons that separation is not optional:

- **`data/collection_provenance.json` is not in the graph at all.** It extracted
  to zero nodes, as did `weight_snapshot.json` and `pyproject.toml`. Provenance
  and snapshot questions have to go to the file — the graph will return nothing
  rather than tell you it can't answer.
- **It collapses parallel edges.** Built undirected, so 34 same-endpoint edges
  became one. That is the deduplication build rule 2 forbids in `AttackGraph`;
  the index is not multigraph-faithful and its edge counts should not be quoted.
- **The doc half is model-generated.** 408 nodes are deterministic AST output;
  152 came from an LLM reading `docs/` and `README.md`, carry `INFERRED` edges
  below confidence 1.0, and would come out differently on a re-run. Nothing in
  this project's evidence chain may rest on that.

`graphify query "<question>"` exists but is weak — it returns a truncated
keyword-matched node list, not an answer. Prefer `explain` and `affected`.

## Dashboard — proposed, not started

Stage 7 came back into scope on 2026-08-19. Faculty expect an upload-a-graph demo
showing all three planners. A proposal was delivered and **awaits a decision**;
nothing is built.

**Why a validation layer is mandatory, not decoration.** 19 dropped edge types,
no ADCS, 14 unsourced weights. An arbitrary BloodHound export contains types we
drop and paths we cannot price, and without a validator the tool prints three
confident numbers that are wrong. Surfacing coverage turns the limitation into a
feature.

**The blocking finding — "reuse the existing loader" is not satisfiable as
stated.** `loader_neo4j.py` reads from a **live Neo4j driver** (Cypher `MATCH`,
`session.run`); it cannot read a file. `AttackGraph.from_dict` accepts **only**
our frozen format and raises on anything else. There is no BloodHound CE JSON
parser anywhere in the repo, and "reuse the loader" plus "no live Neo4j" cannot
both hold for an upload.

What *is* reusable is the part that matters, because the semantics are
module-level functions with no driver dependency: `admit_edge()` (rule 4 at the
boundary), `_primary_kind()`, `jsonable()`, `_is_owned()`, `_is_high_value()`,
and the `dropped_unknown_edge_types` provenance recording. So the honest form is
**new transport, zero new semantics** — an adapter that emits `(nodes, edges)`
and routes every categorisation and admission decision through those functions.

**The parser dominates the cost and carries the most risk.** A BloodHound CE
export is a zip of `users.json`, `groups.json`, `computers.json`, `domains.json`,
`gpos.json`, `ous.json`, `containers.json`, and the edges are not a flat list —
they are nested inside `Aces`, `Members`, `Sessions`, `LocalAdmins`,
`ChildObjects`, `Links` and `AllowedToDelegate` on each object. Reconstructing
the edge set is what BloodHound's own ingest does. **The validator cannot catch a
parser that mis-maps an edge type**: a wrong `WriteDacl` → `GenericAll` mapping
yields 100% coverage and confident wrong numbers.

**Recommended stack.** FastAPI plus one static page with Cytoscape.js. Python
does every computation; JS only draws, so the cost model never crosses the
language boundary. Roughly 7-9 days, over half of it the parser. Cheaper
fallback if writing is at risk: Streamlit, ~1.5 days, frozen-format upload only,
no BloodHound parser.

**Q-learning is never trained live** — 11k-37k episodes would hang the UI.
Convenient fact: the trained Q-table is not persisted anywhere (`train()` returns
it in memory and nothing saves it), but `results/h5_h6.json` already stores the
Q-learning *results* for both frozen graphs. So "pre-trained" means *stored
result*, not *stored model*, and the dashboard's numbers match `findings.md` by
construction.

**Constraints that hold.** Frozen graphs immutable; upload creates a
session-scoped graph and never re-freezes anything on disk. No live Neo4j. No
retraining. Every number shown for the frozen graphs must match `findings.md` —
if the dashboard computes something the paper does not report, that is a bug.
An honesty panel (dropped types, deferred weights, near-zero sessions, zero
delegation) is visible without being asked.

**Recommendation on record:** finish the writing first — it is roughly a day and
a half against the dashboard's seven to nine. If the demo date forces overlap,
take the Streamlit fallback and drop the parser. A dashboard that loads two
frozen graphs and reports them honestly demonstrates the research; one that
mis-parses an examiner's upload live demonstrates the opposite.

## Where things live

| | |
|---|---|
| `graphify-out/` | queryable code index (gitignored, regenerable, never a citation) |
| `docs/abstract.md` | merged framing, contributions, H3 scope statement |
| `docs/findings.md` | running results log, every entry tied to a graph hash |
| `docs/stage2_joint_capability_audit.md` | telemetry baseline, named failure modes, per-edge status |
| `docs/stage3_risk_model_properties.md` | 16 properties, reduced gate of 8 |
| `docs/generator_vs_real_distribution.md` | why `random_ad` can't back distributional claims |
| `docs/stage1_lab_runbook.md` | lab build, target-set policy |
| `docs/stage0_*.md` | **parked** — research phase, after Stage 5 |

`CLAUDE.md` is gitignored, so it is **not in the repo** — a fresh clone gets
neither the build rules nor the Status block. **This is deliberate and stays
that way (2026-09-04):** it is a local working file. Do not "fix" it by copying
its content into the tracked docs — duplicating the Status block is precisely
what caused the Stage 3 drift this file warns about above. Hand the file over
directly instead.
