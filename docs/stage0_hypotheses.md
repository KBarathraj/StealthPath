> **PARKED — research phase.** Do not read this for build work and do not act
> on it. The project is in the build phase until Stage 5 is functionally done;
> see `CLAUDE.md`. Nothing here is cancelled and **nothing here gets edited** —
> the statements below are frozen, in this phase and the next. The plain-English
> summary of H1–H4 lives at the bottom of `CLAUDE.md`.

# Stage 0 Deliverable — Hypotheses H1–H4 (Pre-Registered)

**Freeze this before Stage 4 training starts.** Once you have seen the PPO
results, you cannot honestly rewrite the hypotheses to match them. Commit this
file, note the commit hash in the paper's reproducibility section, and don't
touch the hypothesis statements afterwards — only the "outcome" column.

The plan said these were "already drafted, just confirm wording." They needed
more than wording: each one needed an operational metric, a null hypothesis, and
a decision rule, or Stage 5 becomes an argument about what counts as winning.

---

## Common definitions

| Symbol | Definition |
|---|---|
| `G` | The frozen AD attack graph from the GOAD collection. One file, one hash, cited in the paper. |
| `S` | Set of entry nodes (documented explicitly, not inferred from `owned` markings). |
| `T` | Set of tier-0 target nodes (Domain Admins group and/or DC computer objects). |
| `π ∈ {SP, A*, RL}` | The three planners: unweighted shortest path, static weighted A*, PPO agent. |
| `path(π)` | Node/edge sequence produced by planner π on one episode. |
| `V(e, h, c)` | Visibility model — probability the defender alerts on traversing edge `e`, given attacker history `h` and context `c`. Built in Stage 3. |

### Primary metric — cumulative detection probability

For a path with edges `e₁…eₙ` and history prefix `hᵢ`:

```
P_detect(path) = 1 − Π (1 − V(eᵢ, hᵢ, c))
```

Report `P_detect` as the headline number. It is bounded in [0,1], interpretable,
and independent of path length, which a summed cost is not.

**Secondary metrics** (report all three, always — a planner that halves
`P_detect` by taking a 40-hop path has not achieved anything an attacker wants):

- `L` — path length in hops
- `max_step_risk` — `max V(eᵢ, hᵢ, c)`, the loudest single action
- `success` — whether any target in `T` was reached within the episode limit

### Two risk regimes

- **STATIC**: `V` ignores `h`. Detection risk is a per-edge constant. This is
  the regime all prior work assumes (see related-work note §2).
- **ADAPTIVE**: `V` depends on `h` — repetition, escalation, prior near-misses.
  This is our contribution.

`STATIC` is not a strawman: it must use the *same* base weights as `ADAPTIVE`
with the history term disabled. Otherwise H3 is comparing two different models,
not two regimes.

---

## H1 — Detection-aware planning reduces detection

> **H1:** Under the ADAPTIVE regime, both detection-aware planners (A*, RL)
> achieve lower `P_detect` than unweighted shortest path.
>
> **H1₀:** `P_detect(SP) ≤ min(P_detect(A*), P_detect(RL))`.

- **Test:** paired comparison across N episodes; 95% bootstrap CI on the
  difference in means. Reject H1₀ if the CI excludes 0 for both comparisons.
- **Expected:** confirmed, comfortably. If H1 fails, something is broken in
  Stage 3 — a detection-blind planner should not beat detection-aware ones.
  **Treat H1 failure as a bug hunt, not a finding.**
- **Why include a hypothesis we expect to confirm:** it is the sanity anchor for
  the whole experimental apparatus, and reviewers expect the trivial baseline to
  be present.

---

## H2 — Under static risk, A* is not beaten

> **H2:** Under the STATIC regime, weighted A* achieves `P_detect` statistically
> indistinguishable from, or better than, the trained RL agent.
>
> **H2₀:** RL achieves strictly lower `P_detect` than A* under STATIC.

- **Test:** equivalence test (TOST) with a pre-declared margin of **δ = 0.02
  absolute `P_detect`**. Pick δ now, not after seeing results.
- **Rationale:** with history-independent costs, minimum-cost path is exactly
  what Dijkstra/A* solves optimally. RL should at best tie. If RL *wins* under
  STATIC, the most likely explanation is that A* and the RL environment are not
  solving the same problem — mismatched cost function, mismatched action set, or
  a bug. **Check that before writing it up as a result.**
- **This is the honest-methodology hypothesis.** It says out loud that our own
  proposed method should not win here. Reviewers reward that.

---

## H3 — Adaptive planning wins only when risk is history-dependent

> **H3:** The RL agent's advantage over A* is significantly greater under
> ADAPTIVE than under STATIC.
>
> **H3₀:** `Δ_ADAPTIVE ≤ Δ_STATIC`, where `Δ = P_detect(A*) − P_detect(RL)`.

- **Test:** interaction effect — difference-in-differences on `Δ` between
  regimes, 95% bootstrap CI. Reject H3₀ if the CI on `(Δ_ADAPTIVE − Δ_STATIC)`
  excludes 0.
- **This is the paper's actual contribution.** H1 and H2 exist to make H3
  interpretable.
- **If H3 is not supported:** that is a *real, reportable finding* — "history-
  dependent risk is not sufficient to justify adaptive planning at this scale."
  The plan already anticipates this at the Stage 4 milestone check. Say it
  plainly in the abstract rather than hedging; a clean negative result on a
  well-posed question is publishable at workshop level, a hedged one is not.
- **Failure mode to watch:** if the ADAPTIVE penalty is tuned so steeply that
  *any* repetition is catastrophic, H3 confirms trivially and meaninglessly.
  The Stage 3 manual validation must check that the history term is a gradient,
  not a cliff.

---

## H4 — Conclusions are robust to visibility-model uncertainty

> **H4:** The H1–H3 conclusions hold when the visibility model's parameters are
> perturbed within plausible bounds.
>
> **H4₀:** At least one of H1–H3 flips sign or loses significance under
> perturbation.

- **Test:** resample every weight `wᵢ → wᵢ · (1 + ε)`, `ε ~ Uniform(−0.5, +0.5)`,
  independently per weight, ≥ 200 draws. Re-run all comparisons per draw. Report
  the **fraction of draws in which each conclusion holds** — that fraction is
  the actual result, not a footnote.
- **Also report:** a one-at-a-time sensitivity ranking, so the paper can say
  *which* parameters the conclusions actually hinge on. If one weight dominates,
  that weight needs the strongest citation in the paper.
- **Why this exists:** our weights are hand-calibrated. This is the objection a
  reviewer will raise. H4 is how we answer it with numbers instead of prose.

---

## Pre-registered decisions (fix these now)

| Decision | Value | Why now |
|---|---|---|
| Episodes per condition, `N` | **500** | Fixing N prevents stopping when results look good. Revise only with a documented power justification. |
| Equivalence margin, `δ` | **0.02** absolute `P_detect` | Post-hoc δ is p-hacking. |
| CI method | Bootstrap percentile, 10,000 resamples | Distribution of `P_detect` is bounded and skewed; don't assume normality. |
| Multiple comparisons | Holm–Bonferroni across H1–H3 | Three families of tests on one dataset. |
| Episode hop limit | **20** | Prevents degenerate infinite-avoidance policies. Confirm against observed path lengths in Stage 1 and adjust *once*, before training. |
| RL seeds | **5** independent training seeds, all reported | A single-seed RL result is not a result. |
| Graph | One frozen JSON snapshot, hash in paper | Re-collection would silently change the substrate. |

---

## Added 2026-08-05 with the merged framing — H1–H4 above are untouched

Nothing above this line was edited. H1–H4 are byte-identical to the
pre-registered versions; the merged abstract did not require changing any of
them, which is itself worth recording.

> ⚠️ **Provenance note on H5.** H5 is referenced as pre-existing but does not
> appear in this file, which has only ever held H1–H4. It presumably lives in the
> project plan, which is not in the repository. The statement below is a
> reconstruction from the instruction "H5 stays but gains the affected-region
> measurement" — **check it against the original before relying on it**, and if
> the wording differs, the original wins.

### H5 — incremental retraining after graph change *(reconstructed, plus the new measurement)*

> **H5:** After a permission change, retraining restricted to the affected region
> recovers the same solution quality as full retraining, at lower cost.
>
> **Added:** the affected region is identified by graph diff plus reverse BFS
> from the changed edges, and its size is *measured* rather than assumed.

- **Test:** apply a change, compute the BFS-predicted affected region, retrain
  only within it, compare final optimality gap against full retraining.
- **Note the efficiency caveat from the abstract:** on 783 nodes, full retraining
  is cheap enough that a saving here is not by itself a result. H5's value is the
  measurement in H6, not the speedup.

### H6 — the invalidated region exceeds the graph neighbourhood *(new)*

> **H6:** Under a history-dependent cost model, the region whose optimal routes
> are invalidated by a single realistic permission change is **larger** than the
> graph neighbourhood of that change.
>
> **H6₀:** The invalidated region is contained within the BFS-predicted
> neighbourhood.

- **Rationale:** with history-independent costs, a change can only affect routes
  passing through it, so reverse BFS bounds the damage exactly. Once cost depends
  on what the attacker has already done, a change can alter the *relative* cost
  of routes that never touch the changed edge — because it changes which history
  a cheaper route arrives with. If that happens, selective retraining scoped by
  BFS is unsound, and the BFS bound is a heuristic rather than a guarantee.
- **Test:** for each of N sampled realistic permission changes, compute the
  BFS-predicted region and the observed set of nodes whose optimal route changed.
  Report the fraction of observed changes falling outside the prediction, and the
  size ratio.
- **This is falsifiable in a useful direction either way.** If the two regions
  coincide, that is also a result: it says BFS-scoped retraining is sound under
  history-dependent cost, which is a licence for the engineering in H5. A
  hypothesis whose negative outcome is equally publishable is the right shape.
- **Failure mode to watch:** "realistic permission change" must be fixed before
  measuring. Cherry-picking changes that maximise spillover would confirm H6
  trivially. Draw them from the actual ACL distribution of the frozen graph.

## Outcome log (fill in during Stage 5 — nothing above this line changes)

| Hypothesis | Supported? | Effect size | CI | Notes |
|---|---|---|---|---|
| H1 | | | | |
| H2 | | | | |
| H3 | | | | |
| H4 | | | | |
