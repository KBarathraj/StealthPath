# Handoff

**As of 2026-08-05.** `120 passed, 3 skipped`. Branch `main`, 13 commits, clean
tree. Everything below runs with no network, no database, no lab.

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

Planners 1 and 2 are built and run on real collected data. Planner 3 is not
started and is correctly paused.

---

## State

**Stage status lives in `CLAUDE.md`, in the Status block — read it there.** It
is deliberately not repeated here. This file used to carry its own copy, the two
drifted, and one of them ended up claiming Stage 3 had not started while the
other correctly reported most of its properties implemented. The Stage 3 exit
criteria are in the same file, immediately below Status.

The short version, for orientation only: Stage 1 done, Stage 2 software done,
Stage 2 sourcing and Stage 3 both in progress, Stages 4–5 not started.

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

1. **Price `DCSync`, alone, and stop.** Report before touching anything else. It
   anchors the headline and it is the single most consequential number left in
   the table. The 1.5 error happened because the last item in a long pass got
   the least scrutiny — so `DCSync` does not go in a pass with six other edges.

   **Answer the weight-sensitivity question in the same pass**, while the
   machinery is loaded: *at what `DCSync` weight does `SQL_SVC`'s avoidance stop
   being preferred?* That threshold is reportable either way and it turns the
   result's weight-sensitivity into a measurement rather than a caveat.

2. **Then the remaining seven, in a pass of their own**: `AdminTo`, `SQLAdmin`,
   `HasSession`, `ForceChangePassword`, `AddMember`, `MemberOf`, `AddSelf`. Both
   baseline halves checked per edge. `MemberOf` and `AddSelf` stay trivial.
3. **Build the Stage 3 history-dependent model**, then the three remaining gate
   properties (P1, P2, P15) which need it to exist first.
4. Planner #3 after that, not before.

Prerequisite for step 1 is **done**: the Shape D collapse and the `SQL_SVC`
magnitude-sensitivity are both written up in `findings.md` (2026-08-09), which
is what had to land before `DCSync` was priced.

---

## Decisions that would be expensive to re-derive

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

`CLAUDE.md` is gitignored, so it is **not in the repo** — a fresh clone gets none
of the build rules. Worth fixing if a second person joins.
