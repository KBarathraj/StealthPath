# Handoff

**As of 2026-08-05.** `120 passed, 3 skipped`. Branch `main`, 13 commits, clean
tree. Everything below runs with no network, no database, no lab.

Read `CLAUDE.md` first for the build rules, then this.

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

| | |
|---|---|
| Stage 1 (graph, loader, Dijkstra, CLI) | done |
| Stage 2 software | done |
| Stage 2 sourcing | **10 of 35 weights**, 5 of the 13 that gate Stage 3 |
| Stage 3 | spec written, **model not built**; 6 of 8 gate properties implemented |
| Stages 4–5 | not started |

**Frozen graph:** `data/goad_graph.json`, sha256 `3c1bef97f75df7d2…`
783 nodes / 5825 edges. Published GOADv2 SharpHound 2.3.3 collection
(2024-04-10, Unlicense), ingested via BloodHound CE. **Not our own lab** — a
hypervisor conflict blocked the GOAD build. Full provenance including two
superseded hashes lives in `data/collection_provenance.json`.

**Three structural holes in the data**, all recorded, none fixable without our
own lab: sessions near-absent (5 `HasSession` edges), zero delegation edges,
ADCS dropped (19 edge types still discarded).

---

## Immediate next steps, in order

1. **Write up two findings** that are decided but not yet documented — see
   "In flight" below. Item (b) must land *before* `DCSync` is priced.
2. **Source the remaining eight gate weights**, `DCSync` first because
   everything else compares against it and the headline result rests on it:
   `DCSync`, `AdminTo`, `SQLAdmin`, `HasSession`, `ForceChangePassword`,
   `AddMember`, `MemberOf`, `AddSelf`. `MemberOf` and `AddSelf` are near-trivial.
3. **Build the Stage 3 history-dependent model**, then the three remaining gate
   properties (P1, P2, P15) which need it to exist first.
4. Planner #3 after that, not before.

---

## In flight — decided, not yet written up

**(a) The Shape D collapse is a finding, not an implementation detail.** All
four ACL-write edges derive to the same 4.0 base because the EDR signal does not
distinguish *which* right is being written. That means 80.4% of the graph carries
one weight. The claim: under an EDR-dominated posture the graph's dominant edge
distinction is invisible to the defender, so cost models assigning different
constants to `WriteDacl`/`WriteOwner`/`GenericAll`/`GenericWrite` are encoding
**authority, not observability**. Falls straight out of the impact-vs-loudness
check. Honest consequence: it reduces the static planner's discriminating power
here, which raises the stakes for whether the history-dependent planner finds
anything the static one cannot.

**(b) `SQL_SVC`'s gap is direction-robust and magnitude-sensitive.** It has been
7.4, then 10.4, then 7.9 across three derivations in one session. The
*qualitative* result is the claim — identical hop count, `DCSync` avoided
entirely. The number is not. **Record this before `DCSync` is priced** so it
cannot read as a retrofit if the gap narrows. If sourcing `DCSync` moves it
substantially that is itself reportable, and feeds the robustness analysis
directly: *at what `DCSync` weight does the avoidance stop being preferred?*

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

## Where things live

| | |
|---|---|
| `docs/abstract.md` | merged framing, contributions, H3 scope statement |
| `docs/findings.md` | running results log, every entry tied to a graph hash |
| `docs/stage2_joint_capability_audit.md` | telemetry baseline, named failure modes, per-edge status |
| `docs/stage3_risk_model_properties.md` | 16 properties, reduced gate of 8 |
| `docs/generator_vs_real_distribution.md` | why `random_ad` can't back distributional claims |
| `docs/stage1_lab_runbook.md` | lab build, target-set policy |
| `docs/stage0_*.md` | **parked** — research phase, after Stage 5 |

`CLAUDE.md` is gitignored, so it is **not in the repo** — a fresh clone gets none
of the build rules. Worth fixing if a second person joins.
