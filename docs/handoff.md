# Handoff

**As of 2026-09-10.** The deliverable is the **working web app**, not a paper.
`311 collected, 2 skipped`. Launch: `streamlit run dashboard/app.py`.

Read `CLAUDE.md` first for the build rules and the Status block, then this for
what to build next. `docs/scope_minimum.md` is the floor: the app on the two
frozen graphs.

---

## What the project is

StealthPath is a web application that plans attack paths on an Active Directory
graph. It computes three routes to Domain Admin — shortest, detection-aware, and
history-aware — and reports which techniques each one uses and how confidently
each edge is priced. The learned planner is verified against an exactly computed
optimum, so the app can prove a route is optimal rather than assert it.

The coverage / honesty panel is a product feature. Most tools in this space give
three confident numbers with no statement of how much of the graph they could
price. This one shows dropped types, unsourced weights, and missing session or
delegation data first.

**Stage status lives in `CLAUDE.md`, in the Status block — read it there.** Do
not copy it into this file.

**That file is local and deliberately untracked** — gitignored, absent from a
clone by design. If you are reading this from a fresh clone you do not have it;
ask for it rather than reconstructing its content here.

The short version: Stages 1–5's software and measurements are done. The Streamlit
app is **built**. Remaining work is the three product gaps below. Writing is
second.

**Frozen graph:** `data/goad_graph.json`, sha256 `3c1bef97f75df7d2…`
783 nodes / 5825 edges. Published GOADv2 SharpHound 2.3.3 collection
(2024-04-10, Unlicense), ingested via BloodHound CE. **Not our own lab** — a
hypervisor conflict blocked the GOAD build. Full provenance including two
superseded hashes lives in `data/collection_provenance.json`.

**Three structural holes in the data**, all recorded, none fixable without our
own lab: sessions near-absent (5 `HasSession` edges), zero delegation edges,
ADCS dropped (19 edge types still discarded, 2,443 edges). The app surfaces
these on the coverage panel rather than hiding them.

All three are checkable rather than asserted, and the 19 is easy to look for in
the wrong place: it lives in **`data/goad_graph.json` itself**, under
`provenance.dropped_unknown_edge_types`, written by the loader
(`loader_neo4j.py`) at freeze time — *not* in `data/collection_provenance.json`,
which only points at it. An audit on 2026-08-10 checked the separate provenance
file, did not find the key, and wrongly reported the figure as unverifiable. The
19 entries and the 2,443-edge total are correct.

---

## Immediate next steps, in order

**The app is the priority.** Experimental measurement is done and stays in
`docs/findings.md`. Do not reopen a paper-first queue.

**All three product gaps closed 2026-09-19.** Kept below with what closed them,
because each records a constraint the next change has to respect.

1. **BloodHound CE ingest — DONE.** `dashboard/bloodhound_parser.py` reads a
   collector export (zip or loose per-class JSON) and `dashboard/ingest.py`
   accepts it. `tools/validate_parser.py` passes: **all 13 route-bearing
   relationship types reproduce CE's ingest triple for triple**, and the parsed
   graph's 5,825 edge triples are identical to `data/goad_graph.json`. The 7
   remaining diffs are types `admit_edge` drops (`OwnsRaw`, `WriteOwnerRaw`,
   `Enroll`, `AllExtendedRights`, `DCFor`, `ManageCA`, `ManageCertificates`) and
   their counts match the frozen graph's own `dropped_unknown_edge_types`.

   Four derivations are CE post-processing and were read off the reference
   rather than assumed — see the parser's docstring. The one worth repeating:
   **`DCSync` is not "holds GetChanges and GetChangesAll"**. That rule yields 3
   of the 6 edges; the other 3 are the DCs themselves, with no ACE behind them,
   and they are the ones a route traverses. The validator's warning about this
   was exactly right.

   Two bugs the triple check caught that nothing else would have: SharpHound
   writes the same object twice inside one zip, once enumerated and once as an
   empty placeholder (last-wins silently cost 81 `Owns` and 84 `Contains`
   edges), and `PrimaryGroupSID` carries 62 of the 199 `MemberOf` edges. Both
   graphs still loaded, priced and routed. Both are now named regression tests.

   **The parser deliberately does less than CE in one place**: local-group RIDs
   555/562/580 would emit `CanRDP`/`ExecuteDCOM`/`CanPSRemote`, the reference
   ingest emits none despite four candidate principals, and all three are
   traversable — so emitting them would move routes away from the graph CE
   actually produced. `LOCAL_GROUP_RIDS` keeps the full map with only 544 live.

2. **Start/target derivation — DONE.** `stealthpath/targets.py` keys on
   well-known RIDs (512/519) and domain structure, not on the string
   `DOMAIN ADMINS`, and every candidate carries the reason it was selected.
   `target_indices()` returns **exactly** `tier0_targets()` on the frozen graph,
   pinned by `test_derived_targets_match_tier0_on_the_frozen_graph` — that is
   what makes it safe to swap in without moving a published number.

   **DC computer objects are now derivable** (`props.isdc`, normalised by the
   parser) and stay **opt-in**: switching them on adds 3 targets to the
   reference graph, and every route in `findings.md` is measured without them.
   The open decision recorded below is therefore resolved as "possible, still
   off", not as "blocked".

3. **Capped runs — DONE, and the ladder is the answer.** `dashboard/rl_upload.py`
   tries exact → approximate Q-learning → refusal, and reports *which* rung
   answered. A capped run is still never a result: `_epsilon` schedules
   exploration from the full episode count, so a stopped run is not a prefix of
   a finished one.

   **The tabular learner is deliberately not a rung.** It keeps its reported
   15/15 result on the frozen graphs through `rl_view`, but for an upload it is
   both unbounded in memory and measurably less accurate — on the random
   directories checked it came in +9.3% on a start where the approximator was
   exact. When both planners finish, the learned route is reported *as a gap
   against the exact one*, which is the only evidence available that the learner
   can be trusted on graphs where the exact search cannot run.

   **A bug worth not reintroducing:** the exact search ran over all `sources`
   while the learner trained on `sources[0]` only, so the reported gap compared
   two different problems. It read as a badly broken learner (+43% on a random
   directory) when the learner had found the exact optimum from the node it was
   given. Invisible on the frozen graph, where every documented entry name
   resolves to exactly one node. Pinned by
   `test_the_learner_is_trained_from_every_start_the_exact_search_used`.

   **New, and it is a real loss of guarantee:** `stealthpath/planners/linear_q.py`
   is Q-learning with hashed state-action features, for graphs too large for the
   table. On such a graph the exact search does not finish either, so there is
   no optimum to measure it against and **nothing it produces is verified** —
   `Path.meta["verified"]` is `False`, the planner name says so, and the UI
   renders it amber rather than green.

   **The first version of this learner was not good enough, and the reference
   graph could not show it.** It used ~20 named handcrafted features, reached
   the exact optimum on all three reference entry points, and was **+32% to
   +80% above optimum on random directories of 2,900–8,200 nodes** — and did not
   improve with more episodes, because one global weight per named feature
   cannot say "take `MemberOf` here but not there". Replacing the basis with
   three hashed `(edge, mask)` indicators fixed it: **14 of 14 start/graph pairs
   at +0.00%**, spanning the reference collection and random directories up to
   20,502 nodes. Memory is the bucket count, not `|S|`, so it does not grow with
   the directory.

   Two things to not undo: the bucket index is masked rather than taken modulo
   (so `buckets` must be a power of two), and `_mix` is written out in the
   module instead of calling `hash()`, because `PYTHONHASHSEED` perturbs
   `hash()` on str/bytes and determinism is a build rule.

**Writing is next** (Figure 3 / `SQL_SVC` route drawing, optimality-gap
reproducibility claim, related-work corrections).

---

## Decisions that would be expensive to re-derive

- **The unpinned figure set is known, not assumed empty.** A deliberate sweep on
  2026-08-10 checked every number in live claim text against its source.
  Everything derivable is pinned by `tests/test_reported_figures.py`: the
  concentration figures (79.4% modal share, 95.3% `acl_abuse`, HHI 0.654 and
  0.909), the superseded 80.4% and why it is a different measurement, both |S|
  figures with their traversal sets, `k`, the 19 dropped types, the 14 deferred
  weights, and the H5/H6 artifact values.

  **Hand-maintained, and it is the pytest counts.** `311 collected, 2 skipped`
  appears in `README.md`, `CLAUDE.md`, `handoff.md` and
  `stage1_lab_runbook.md`. It is not statically derivable — pytest's collected
  count expands `parametrize` and so differs from the AST function count in
  `tests/test_inventory.json`, and running pytest inside pytest to obtain it is
  not acceptable. The live claim is always the *collected* count; the inventory
  total is generated, is never quoted in prose. **Update these four by hand
  whenever the suite count changes.**

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

- **Target set** is now `stealthpath.targets.derive_targets()`: well-known RIDs
  512/519 plus domain objects, each with a stated reason.
  `AttackGraph.tier0_targets()` still matches by name and is unchanged — the two
  agree exactly on the frozen graph and that agreement is a test. **DC computer
  objects are derivable and deliberately off**; see next-step (2) above.
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
streamlit run dashboard/app.py
python -m stealthpath.cli compare --graph data/goad_graph.json
python tools/snapshot_weights.py          # after any weight change
```

Reference-collection starts the demo uses, all with verified routes:
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

## Web app — built; three gaps remain

The Streamlit app in `dashboard/` is running software, not a proposal. It loads
the two frozen graphs or an uploaded StealthPath freeze, shows the coverage
gate first, then three planners, then optional live Q-learning under a budget.

**Why the coverage gate is the differentiator, not decoration.** 19 dropped edge
types, no AD CS, 14 unsourced weights. An arbitrary BloodHound export contains
types we drop and paths we cannot price, and without a validator the tool prints
three confident numbers that are wrong. Surfacing coverage is the product.

**CE ingest is built.** `dashboard/bloodhound_parser.py` reconstructs a
collector export — a zip of per-class JSON with edges nested on the objects
(`Aces`, `Members`, `Sessions`, …) — into `(nodes, edges)`. `loader_neo4j.py` is
unchanged and still the freeze path from a live database; the parser reuses its
`admit_edge()`, `jsonable()` and `dropped_unknown_edge_types` recording rather
than re-deciding any of it.

**The coverage panel cannot catch a parser that mis-maps an edge type**, which
is why `tools/validate_parser.py` compares triples and not counts, and why it
must keep passing. Run it after any parser change:

```bash
python tools/validate_parser.py        # VERDICT: PASS
```

**Constraints that hold.** Frozen graphs on disk are immutable; upload is
session-scoped and never re-freezes anything. No live Neo4j in the UI. Every
number shown for the frozen graphs must match the pinned tests / `findings.md`
— if the UI computes something that record does not report, that is a bug. The
honesty panel is visible without being asked.

**Q-learning:** on the reference graphs, live training is cheap (~1s). On an
unknown upload it is not, so `dashboard/rl_upload.py` walks exact → tabular →
linear approximation → refusal and names the rung that answered. A capped run is
still a refusal plus the exact-search route, never a finished-looking partial
policy. `results/h5_h6.json`
is stored *results* for the two frozen graphs, not a stored model to replay on
someone else's directory.

## Where things live

| | |
|---|---|
| `dashboard/` | Streamlit app — the deliverable |
| `docs/scope_minimum.md` | what ships if nothing else lands |
| `docs/screenshots/` | UI capture placeholder |
| `graphify-out/` | queryable code index (gitignored, regenerable, never a citation) |
| `docs/abstract.md` | engine write-up (not the homepage) |
| `docs/findings.md` | dated results log, every entry tied to a graph hash |
| `docs/stage2_joint_capability_audit.md` | telemetry baseline, named failure modes, per-edge status |
| `docs/stage3_risk_model_properties.md` | 16 properties, reduced gate of 8 |
| `docs/generator_vs_real_distribution.md` | why `random_ad` can't back distributional claims |
| `docs/stage1_lab_runbook.md` | how to freeze your own lab collection |
| `docs/stage0_*.md` | **frozen** — do not edit hypothesis statements |

`CLAUDE.md` is gitignored, so it is **not in the repo** — a fresh clone gets
neither the build rules nor the Status block. **This is deliberate and stays
that way (2026-09-04):** it is a local working file. Do not "fix" it by copying
its content into the tracked docs — duplicating the Status block is precisely
what caused the Stage 3 drift this file warns about above. Hand the file over
directly instead.
