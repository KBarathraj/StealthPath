# Findings — running log

Results that mean something, recorded when they happen. Chat history is not a
record; this file is.

**Every number here comes from a frozen graph, named by hash.** If a finding
cannot name its graph it does not belong here.

**Weights are still provisional.** `require_sourced()` blocks reporting for good
reason — 32 of 35 weights carry a rationale but no citation. Nothing below is a
publishable number. What *is* meaningful is the **direction and shape** of the
differences, which are structural and survive reasonable changes to the numbers.
Re-check anything marked as sensitive to weights once the sourcing pass lands.

---

## 2026-09-06 — correction: `TYWIN`'s first-5k figure is 0.0% on two seeds, not five

Found while timing training for the Stage 7 live-run decision, not while
re-reading the claim. **findings.md:348 says "not one of the first 5,000 episodes
reached a target."** That holds for **seeds 0 and 4**. Seeds 1, 2 and 3 each
reached a target **exactly once** inside the first 5,000.

The artifact already recorded this and the prose did not follow it:

| seed | `success_rate_first_5k` | goals in first 5k | first target at episode |
|---|---|---|---|
| 0 | 0.0 | 0 | 9,033 |
| 1 | **0.0002** | **1** | 4,206 |
| 2 | **0.0002** | **1** | 1,735 |
| 3 | **0.0002** | **1** | 946 |
| 4 | 0.0 | 0 | 6,410 |

**The table's "0.0%" is fair rounding — 0.02% displays as 0.0% at one decimal —
and it stands. The sentence beneath it does not.** Recorded rather than silently
reworded, because this is the fourth instance of the same class in this project:
a correct number carried into a sentence that claims slightly more than it.

**Nothing downstream moves.** The guard's threshold is 1%; 0.02% trips it just as
0.0% does, so `TYWIN` still trips on all five seeds, the remedy is still "none
applied", and the recovery narrative is unchanged. What changes is only how
absolutely the zero may be stated.

**The recovery is gradual, and worth having measured.** Goals per 5,000-episode
window, seed 0:

| episodes | goals | rate |
|---|---|---|
| 0–5,000 | 0 | 0.00% |
| 5,000–10,000 | 1 | 0.02% |
| 10,000–15,000 | 14 | 0.28% |
| 15,000–20,000 | 122 | 2.44% |
| 20,000–25,000 | 305 | 6.10% |
| 25,000–30,000 | 711 | 14.22% |
| 30,000–35,000 | 1,494 | 29.88% |
| 35,000–40,000 | 2,902 | 58.04% |
| 40,000–45,000 | 3,874 | 77.48% |
| 45,000–50,000 | 3,964 | 79.28% |

Across seeds the first 1,000-episode window above 1% success is **13,000–16,000**,
and convergence follows at 22,000–27,000 — so **the greedy route stabilises while
the exploration success rate is still only ~6%**. The policy is right long before
the random walk that trained it looks healthy, which is the substantive reason
the guard fired on a run that needed no rescuing.

---

## 2026-09-04 — history rewrite, and the round trip verified for the first time

**Graphs:** `3c1bef97…` and `7f80e6dc…`, both unchanged — and re-hashed from a
**fresh clone of the remote** rather than from the working tree, which is the
whole point of this entry.

Branch `h5h6-perturbed-graph` had author and committer normalised to
`KBarathraj <barathrajkannan2006@gmail.com>` and 15 `Co-Authored-By` trailers
stripped. Content did not move: all 28 tree hashes are identical before and
after, `git diff` across the rewrite is empty, and author and committer
timestamps match to the second, timezone offsets included.

**Two corrections to the record.**

1. The branch is **28 commits, not 13**.
2. It had **already been pushed** to `origin/h5h6-perturbed-graph` at `151e54b`,
   so the rewrite required a force-push rather than a first push. The
   pre-rewrite commits stay reachable on the remote by hash, so the stripped
   trailers are not retracted from GitHub — only from the branch history.

**One new result, not a correction: the round trip had never been run.** The
`b427ef8a…` → `3c1bef97…` supersession was made to fix exactly this — `save()`
wrote platform-default line endings and `core.autocrlf` meant the blob git
stored could differ from the file on disk — but the fix had only ever been
checked in place. Clone-and-rehash closes that:

| Check, from `git clone` on Windows | Result |
|---|---|
| `sha256 data/goad_graph.json` | `3c1bef97f75df7d2…` — matches |
| `sha256 data/goad_graph_perturbed.json` | `7f80e6dc02ba3aed…` — matches |
| `git hash-object` vs `rev-parse HEAD:<path>`, all 5 chain files | identical |
| `pytest -q` | **194 passed, 2 skipped** |

The five files in the hash-citation chain are the two graph artifacts plus
`data/collection_provenance.json`, `results/h5_h6.json` and
`tests/test_h5_h6_runner.py`. Only the first two have their *own* hash cited;
the other three cite or pin. Worth stating because "five hash-cited artifacts"
is the natural miscount.

**ESORICS citation checked, and it was correct — recorded because
checked-and-clean must read differently from never-considered.** Goel et al.,
*Optimizing Cyber Defense in Dynamic Active Directories through Reinforcement
Learning*, verified against arXiv:2406.19596: title verbatim and the author
order (Goel, Moore, Guo, Wang, Kim, Camtepe) both match `abstract.md` and
`stage0_related_work.md`. No change made. Same convention as `NONE_FOUND` in
`channels`.

---

## 2026-08-09 — **H1 fails**, and it fails in shape rather than magnitude

**Graph:** `3c1bef97…`, expansion view. No new computation — this is a tabulation
of routes already in the snapshot.

H1 as pre-registered: *"plain shortest path minimizes hops but maximizes
detection risk."* **It stands as registered and it is reported as failing.**

| Entry | hops plain / weighted | static risk plain / weighted | loudest edge |
|---|---|---|---|
| `SAMWELL` | **2 / 2** | 4.10 / 4.10 — equal | 4.0 / 4.0 |
| `SQL_SVC` | **4 / 4** | 20.00 / 15.10 — plain **+4.90** | 6.5 / 6.0 |
| `TYWIN` | **9 / 9** | 39.50 / 39.50 — equal | 6.5 / 6.5 |

**Both halves fail, and the first is the interesting one.** The hop counts are
*identical on all three entry points*. The weighted planner never pays an extra
hop for quiet — so there is no hops-versus-risk trade-off to measure. The risk
half holds on one of three.

**This is the first pre-registered hypothesis to be wrong about the structure of
the problem rather than the size of an effect**, and that makes it the strongest
single piece of evidence that the concentration finding is real rather than an
artifact of planner construction. An implementation can fail to find a trade-off
that exists; it cannot manufacture the absence of one. At 79.4% modal-weight
concentration a minimum-risk route is usually also a minimum-hop route.

Folded into "The Shape D collapse" in `abstract.md` as consequence 2 of five,
rather than reported as an independent result — it is the same mechanism, and the
one entry where H1 shows anything (`SQL_SVC`) is the one decided by a
minority-class edge, which is where the boundary clause says discrimination
should survive.

**Related-work consequence.** Goel et al. (ESORICS 2024, arXiv:2406.19596)
critique shortest-path attackers as simplistic and easy to predict. That critique
is made analytically and evaluated on synthetic DBCreator graphs
(r1000–r4000, 2,996–12,001 nodes, single domain, per-edge detection
probabilities drawn uniformly on [0, 0.2]); they name validation against real AD
data as future work. H1's failure is that validation, and it is written up as a
**boundary condition, not a refutation**: uniform random per-edge costs give
every edge a distinct price by construction, which is exactly the condition under
which shortest path *is* trivially worse. Whether real directories resemble that
draw or this collection is open, and one collection cannot settle it.

---

## 2026-08-09 — H5/H6 result: **the registered prediction was wrong, on both counts**

**Graphs.** Base `data/goad_graph.json`, sha256 `3c1bef97f75df7d2…`, **unmodified**
— verified by re-hashing after the run. Perturbed copy
`data/goad_graph_perturbed.json`, sha256 `7f80e6dc02ba3aed…`, 783 nodes / 5,827
edges (+2). Perturbation exactly as pre-registered below; nothing was reselected.

### The prediction failed, and the failure is the finding

I registered that (1) a single added ACL edge was unlikely to re-rank anything
and (2) the affected set would cover most of the state space. **Neither held.**

But the *first* failure is more precise than it looks, and it sharpens the
collapse claim rather than contradicting it:

- **P1, the `GenericAll` ACL edge, changed nothing.** Exactly as the collapse
  predicts — it joined the 95.3% dominant class at the modal weight, competing
  against thousands of interchangeable alternatives.
- **P2, the `MemberOf` group membership, changed everything it touched.**
  `MemberOf` is in the 4.0% *minority* class at the floor weight (0.1) — the one
  edge type with a distinctive derived cost.

So the collapse does not predict insensitivity to *all* perturbation. It predicts
insensitivity to perturbation **within the dominant class**, and the experiment
separated the two cleanly by accident of having registered one of each. That is a
better-specified claim than the one I registered.

### H5 — graceful degradation, measured

| Entry | plain | weighted | exact-history | Q-learning, **no retraining** |
|---|---|---|---|---|
| `SAMWELL` | unchanged | unchanged | unchanged | 4.10 → 4.10, **+0.00%** |
| `SQL_SVC` | unchanged | unchanged | unchanged | 15.10 → 15.10, **+0.00%** |
| `TYWIN` | 9h → **7h** | 39.50 → **26.60** | 44.50 → **29.00** | 44.50 held, **+53.45% gap** |

`TYWIN`'s route loses three hops: `AddSelf → AddMember → WriteOwner` collapses
into the single new `MemberOf`. Plain shortest path moves too (9h → 7h), so this
is a genuine structural shortcut and not an artifact of the risk model.

**The H5 number is +53.45%.** A policy trained on the base graph, replayed on the
perturbed one without retraining, keeps returning its old 44.50 route while the
new optimum is 29.00. Degradation is exactly zero where the graph did not change
and substantial where it did — which is what "graceful" should mean, and it is
now measured rather than asserted.

### H6 — the bound is sound, discriminating, and **not vacuous**

| | states | fraction |
|---|---|---|
| Augmented state space \|S\| | 801,792 | — |
| Reverse-BFS affected set | 45,056 | **5.6% of \|S\|** |
| Reachable from the three entries | 1,467 | 0.2% of \|S\| |
| Affected **and** reachable | 14 | **1.0% of the reachable space** |

Reported as fractions, as required, so vacuity would have been visible. It is not
vacuous: **5.6%**, and **1.0%** of the operationally reachable space.

And it discriminated perfectly:

| Entry | in affected set | observed change | verdict |
|---|---|---|---|
| `SAMWELL` | no | no | correctly excluded |
| `SQL_SVC` | no | no | correctly excluded |
| `TYWIN` | yes | yes | correctly predicted |

**3 of 3.** No degradation fell outside the bound, and the bound did not
over-include either entry that was unaffected. Of the three pre-registered
outcomes this is the first — *sound and useful* — and it is the one I predicted
against.

**Consequence for the retraining idea:** selective retraining over the affected
region is worth building on a graph like this. Touching 1.0% of the reachable
state space instead of all of it is a real saving, and the bound was tight enough
to identify the single affected entry point out of three.

**Attribution.** P1 alone yields 45,056 affected states and P2 alone 20,480 —
so the *bound* is dominated by the ACL edge while the *observed change* came
entirely from the membership edge. The bound is conservative in exactly the
direction it should be: it over-covers the class that turns out not to matter,
and still excludes the two entries that did not move.

---

## 2026-08-09 — H5/H6 pre-registration (written **before** the graph is touched)

Prediction, perturbation and outcome definitions all fixed here before the
perturbed graph exists. Last opportunity in the project to register a predicted
null, which is worth more than an explained one.

### Registered prediction

**I expect H5/H6 to be weakly informative on this graph, for the same reason
everything else has been.** With `acl_abuse` at 95.3% of walkable edges and 79.4%
of them on one derived weight:

1. A single added ACL edge is **unlikely to re-rank any route**. It joins the
   dominant class at the modal weight, so it competes against thousands of
   interchangeable alternatives.
2. The reverse-BFS affected set is likely to **cover most of the augmented state
   space**, because a graph this concentrated is densely interconnected through
   one edge class.

If both land, that is the fifth manifestation of the same collapse and will be
reported as such, not as five independent results.

### The three H6 outcomes, defined in advance

Reported as a **fraction of the augmented state space**, not a node count, so
vacuity is visible rather than implied.

| Outcome | Meaning |
|---|---|
| degradation **inside** the predicted region | bound is sound and useful |
| degradation **outside** | bound falsified — **selective retraining is unsound**; the most interesting result |
| predicted region covers **most of the state space** | bound sound but **VACUOUS** — selective retraining buys nothing at this concentration |

The third is what the prediction points at, and it is the direct answer to
whether the BFS incremental-retraining idea is worth building at all.

### The perturbation, named before execution

Both selected on realism criteria from the **base** graph only. **Neither was
checked against any planner beforehand**, and no modified graph has been planned
on at the time of writing. Inspecting an effect and then reselecting would be
choosing for effect and would make the result worthless.

**P1 — one risky permission.**
`JORAH.MORMONT@ESSOS.LOCAL` (node 260) —`GenericAll`→
`ROBB.STARK@NORTH.SEVENKINGDOMS.LOCAL` (node 381).

*Realism:* an ordinary domain user granted full control over a user object is the
single most common ACL misconfiguration BloodHound surfaces. Placing it across
the ESSOS → NORTH trust reflects delegated administration spanning a forest,
which GOAD models with real trusts. Neither endpoint is tier-0. The target sits
on an existing route, which is where a permission change is *capable* of
mattering — chosen so the experiment can be informative, not because its effect
is known.

**P2 — one group membership.**
`TYRON.LANNISTER@SEVENKINGDOMS.LOCAL` (node 336) —`MemberOf`→
`KINGSGUARD@SEVENKINGDOMS.LOCAL` (node 701).

*Realism:* adding an existing user to an existing non-privileged group in the
same domain is the most routine change any directory receives. Both objects
already exist; the group is not tier-0.

### Constraints on the run

- **Build rule 6 holds.** `data/goad_graph.json` is not modified. The
  perturbation is applied to a **copy**, re-frozen under its own hash, and the
  hash is recorded below with the results.
- **All three planners re-run without retraining.** That is the H5 measurement.
- **If the perturbation changes nothing, that is the result and it stands.** No
  second, larger perturbation will be applied to produce movement. Testing
  sensitivity to perturbation *size* would be a separate pre-registered
  experiment with its own justification — not a retry.

---

## 2026-08-09 — correction: the collapse figure is 79.4%, not 80.4%

Caught while measuring the antecedent of the generalisation claim rather than
restating it. Entries below that say "80.4% of the graph carries one weight" are
**using the right number for the wrong quantity**.

- **80.4%** is five ACL types *including* `Owns`, over all 5,825 edges — the
  measurement in `generator_vs_real_distribution.md`, where it is correct and
  stands.
- `Owns` derives to **4.5**, not 4.0, so it is not part of the collapsed
  signature and never was.
- The figure the collapse claim needs is the **modal-weight share: 3,965 of
  4,991 walkable edges (79.4%) carry weight 4.0** — measured on the *derived
  weight* rather than on edge type, which is what "one detection signature"
  actually means.

Two further concentration figures, now reported as named properties of the graph
so the claim's antecedent is measurable elsewhere: **HHI over derived weights
0.654** (1.0 = a single signature), and **`acl_abuse` at 95.3% of walkable
edges, HHI over categories 0.909**. The second is the direct explanation for the
flat `k` sweep — almost every route repeats `acl_abuse` immediately, so scaling
the repeat penalty rescales the alternatives together.

The direction and the mechanism are unaffected; the number attached to them was
imported from a neighbouring measurement and not re-derived. Recorded rather than
silently corrected, because it is the same class of error the sourcing method
exists to catch — a figure that was true somewhere else.

---

## 2026-08-09 — Tier 2 result: **15/15 runs optimal, 0.00% gap** — after two silent bugs

**Graph:** unchanged, sha256 `3c1bef97…`, `with_gpo_expansion()` view,
|S| = 801,792. Cost model `history_cost_fn`, `k = 1.2`. Hyperparameters exactly
as pre-registered in the entry below.

### Two changes to the pre-registered setup, both reported

Neither was a tuning change and neither was made to improve a number. Both were
defects that produced confidently wrong policies while every reported statistic
looked healthy.

**(1) Policy extraction preferred actions it had never tried.** Every reward is
negative, so every learned Q value is ≤ 0, while an unvisited action defaults to
0.0 — the best score available. Greedy extraction therefore walked into
unexplored states on principle. This is correct *during training*, where it is
what optimistic initialisation is for, and fatal at extraction, where "no
estimate" is not "good". Fixed by restricting the greedy walk to visited
actions. **This changes how the policy is read off, not what is learned.**

**(2) Dead ends were free — an MDP misspecification.** The pre-registered failure
penalty applied only at the hop cap. A node with no out-edges returned a
bootstrap value of 0.0, *identical to a goal's*, so terminating in a dead end
cost nothing. On the real graph the learner correctly concluded that `MemberOf`
(0.1) into a zero-out-degree node beats the 4.1 optimal route. It was not failing
to learn; it was learning that giving up wins.

Fixed by penalising every non-goal termination the way the hop cap already was.
**This is a change to the environment definition and is recorded as one** — but
it is not reward shaping toward any particular route: it makes all non-goal
terminations uniformly bad, which is what the pre-registered hop-cap penalty
already asserted for the other half of the same case.

Both are pinned by regression tests in `tests/test_q_learning.py`. The diagnosis
came from `|Q| = 11` after 50,000 episodes — the table was the right size for
`SAMWELL`'s 4-state reachable component, which is what pointed at the MDP rather
than at exploration.

### The exploration guard tripped, and no remedy was applied

Pre-registered threshold: under 1% goal-reaching in the first 5,000 episodes.

| Entry | first-5k success | goals / 50k |
|---|---|---|
| `SAMWELL` | 60.7–62.9% | ~41,400 |
| `SQL_SVC` | 1.4–1.9% | ~20,100 |
| `TYWIN` | **0.0%** | ~13,300 |

`TYWIN` trips it: not one of the first 5,000 episodes reached a target. Reported
rather than fixed, because the run recovered on its own — as ε decayed and Q
values began steering, it reached a target ~13,300 times and converged by episode
22,000–27,000. **No initialisation change, no reward shaping, no episode
seeding.** The guard was worth having and the honest outcome is that it fired on
a run that did not need rescuing.

### Result — optimality gap against Tier 1

| Entry | Tier 1 optimum | Q-learning (5 seeds) | gap | converged at |
|---|---|---|---|---|
| `SAMWELL` | 2h / 4.10 | 2h / 4.10, all seeds | **+0.00%** | 11k–12k |
| `SQL_SVC` | 4h / 15.10 | 4h / 15.10, all seeds | **+0.00%** | 36k–37k |
| `TYWIN` | 9h / 44.50 | 9h / 44.50, all seeds | **+0.00%** | 22k–27k |

**15 of 15 runs reach the exact optimum and return the identical route.** Q-table
sizes are small — 11, ~1,090, 84 — because the reachable augmented state space
from a single entry point is a tiny fraction of the 801,792 total.

As registered, the reportable content is speed and reliability, not discovery:
perfect reliability across seeds, convergence in 11k–37k episodes, seconds of
wall time. Q-learning found nothing the exact search did not, which is the
expected and correct outcome — it cannot beat exact search, and
`test_never_beats_the_exact_optimum` asserts it does not.

### The `k` sweep — flat everywhere, the fourth manifestation

Registered before running: conclusions flat in `k` would be a fourth appearance
of the Shape D collapse rather than an independent result. **It landed that way.**

| `k` | 1.0 | 1.2 | 1.5 | 2.0 | 3.0 | 5.0 | 10.0 |
|---|---|---|---|---|---|---|---|
| any route differs from static | no | no | no | no | no | no | no |
| `SQL_SVC` avoids `DCSync` | yes | yes | yes | yes | yes | yes | yes |

No route changes at any `k` tested, up to a **ten-fold** repeat penalty — roughly
forty times beyond the P15 bound, which `k` exceeds above 1.2475. `TYWIN`'s cost
climbs 39.5 → 264.5 across that range and its route never moves.

That is the mechanism stated three times already, now measured across the
parameter: when the alternatives repeat the same categories, scaling the repeat
penalty rescales them together and re-ranks nothing. **The conclusions do not
depend on `k` on this graph**, which retires the last free parameter as a source
of doubt — and does so by measurement rather than by defending the value.

---

## 2026-08-09 — Tier 2 pre-registration (written **before** the first run)

Recorded ahead of any result so "converged" is not decided after seeing a curve.
Same discipline as `k`. Nothing below was chosen with a result in view.

**Setup.** Tabular Q-learning over the same augmented MDP as Tier 1 — state
`(node, set of categories used)`, actions the walkable out-edges — with the same
cost model (`history_cost_fn`, `k = 1.2`) on the same frozen graph and the same
`with_gpo_expansion()` view.

| | |
|---|---|
| learning rate α | 0.1 |
| discount γ | 1.0 — undiscounted; this is min-cost path, not a discounted-return problem |
| exploration | ε-greedy, ε linear 1.0 → 0.05 over the first 80% of episodes, 0.05 thereafter |
| episodes | 50,000 per seed per entry point |
| hop cap | 20 (the pre-registered limit) |
| step reward | `−cost(edge)` from `history_cost_fn` |
| failure penalty | `−100` if the cap is hit without reaching a target |
| Q init | 0.0 |
| seeds | 0, 1, 2, 3, 4 |
| episode start | the entry point under evaluation, not a random node |

**Why the failure penalty exists, stated in advance.** With `γ = 1` and purely
negative step rewards, an agent that cycles on cheap edges until the cap can
out-score one that pays for an expensive route to a target. −100 exceeds any
feasible route cost on this graph (`TYWIN`, the most expensive, is 44.5), so
reaching a target always dominates. It is a termination condition, not reward
shaping toward a particular route.

**Definitions, fixed now.**

- **Converged** — the greedy (ε = 0) route is unchanged across 10 consecutive
  checkpoints, taken every 1,000 episodes. Convergence says nothing about
  quality.
- **Optimal** — the greedy route's cost equals Tier 1's exact optimum to within
  1e-9.
- **Optimality gap** — `(Q_cost − Tier1_cost) / Tier1_cost`, reported per seed.
  This is the headline number. **Q-learning cannot beat exact search**; the
  result is how close it gets, how reliably, and at what cost.

**Expected result, registered.** It converges to the same routes Tier 1 found.
If so the reportable content is speed, reliability across seeds, and where it
falls short of optimal — not discovery.

**Registered failure mode.** A tabular agent on a 783-node graph with sparse
terminal reward may never reach a target under random exploration. If the
baseline reaches a target in fewer than 1% of the first 5,000 episodes, that is
reported as an **exploration problem**, and any remedy — initialisation, reward
shaping, episode seeding — is named explicitly with what it changes about what is
being learned. Reward shaping cannot be an undocumented fix.

**Nothing will be tuned to make Q-learning beat Tier 1.** If it produces a
different route on the real graph, that is a discrepancy to investigate as a
possible Q-learning error, not a vindication.

---

## 2026-08-09 — **STAGE 3 GATE CLOSED**

Recorded as an event, not left to be inferred. All six exit criteria from
`CLAUDE.md` hold simultaneously as of this entry.

| # | Criterion | |
|---|---|---|
| 1 | All 13 gate weights sourced | ✅ verified programmatically |
| 2 | Both baseline halves on every sourced gate weight | ✅ enforced by `test_sourced_weight_accounts_for_both_baseline_halves` |
| 3 | All 8 gate properties implemented | ✅ **P1, P2, P15 landed with the model** |
| 4 | `test_weight_invariants.py` green, nothing asserting a weight | ✅ |
| 5 | Snapshot and inventory regenerated | ✅ |
| 6 | `compare` re-run, `findings.md` updated | ✅ this log |

`164 passed, 2 skipped`. The two skips are the route-level properties
(P3/P4/P8/P10/P11 need `P_detect`) and P5's severity ordering — both in the
deferred class, neither gating.

**Work now moves to Tier 1 and then the learner. The 14 deferred weights stay
deferred permanently** and any new weight question gets logged rather than
answered.

*The count was written as 17 here and corrected to 14 on 2026-08-10.* It was
stale rather than wrong at the time: sourcing `DCSync` also sourced its three
replication components, and this line was not updated. Verified position: **35
weights, 21 sourced, 14 unsourced.** Recorded in `results/h5_h6.json` under
`risk_model` so it is derived on every run rather than transcribed.

### The history-dependent model

`risk.history_cost_fn`. Summary A: state is `(node, set of technique categories
used)`. An action costs its static weight the first time its category appears on
the route and `weight × k` on every appearance after, `k = 1.2`.

**Proportional rather than uniform, and the reason came out of the sourcing
pass.** A uniform additive step would charge the same increment for repeating
`MemberOf` as for repeating `DCSync` — but `MemberOf` is sourced at the floor
with *both* halves recorded `NONE_FOUND`, meaning the pass established there is
no detection at all. A fixed step manufactures loudness there, silently
overturning a sourced negative result on the exact hop that decides the
`SQL_SVC` route. It also assumes a defender who notices category repetition
independently of severity, which is the correlation capability the baseline
explicitly excludes.

**`k` is a declared parameter and the defence is the sweep, not the value.**
Written into the model's docstring and `abstract.md` *before* any result exists,
so it cannot later read as a response to an inconvenient number. Nothing in the
baseline fixes `k`: the sourcing pass priced first occurrences and is silent on
second sightings. Conclusions get reported as the range of `k` over which they
hold, using the machinery H4 already has.

**P15's two numbers, which are not the same number.** The declared bound is 25%
of range, checked against `WEIGHT_CEILING` so it cannot break when an unrelated
weight is sourced upward — max step 2.0. Today's *actual* maximum step is 1.3
(`DCSync` at 6.5 × 0.2), about 13%. "Holds with headroom" describes the bound,
not a measurement, and `test_the_declared_bound_is_not_the_observed_step` pins
the gap so the two cannot be conflated.

### |S| is 801,792 on the graph the results actually use

The pre-registered figure is 400,896 = 783 × 2⁹, and the 9 follows from build
rule 3 excluding structural edges from `DEFAULT_TRAVERSAL_SET`. That coupling was
flagged as live before the model was built. **It has already fired.**

Every route reported for the three documented entry points is computed on
`with_gpo_expansion()`, which re-admits `GPLink` and `Contains` — the
`structural` category. Ten categories, so 783 × 2¹⁰ = **801,792**.

Neither number is wrong; they describe different traversal sets. But the
pre-registered figure is **not** the state space the reported results live in,
and saying "400,896" about a `SAMWELL` or `TYWIN` route would be false. Pinned by
`test_the_gpo_expansion_view_doubles_the_state_space`. Still tractable — roughly
46 MB by the earlier scaling — so this changes a number to report, not a
feasibility argument.

### Tier 1 — exact history-aware search: **no route changed**

Uniform-cost search over the augmented state space, deterministic, optimal.
Sub-millisecond on all three entry points.

| Entry | exact (history) | static weighted | route differs |
|---|---|---|---|
| `SAMWELL` | 2h / 4.10 | 2h / 4.10 | **no** |
| `SQL_SVC` | 4h / 15.10 | 4h / 15.10 | **no** |
| `TYWIN` | 9h / **44.50** | 9h / 39.50 | **no** |

**This is a finding, and it is reported as one.** H3 was pre-registered as
conditional — adaptivity earns its complexity only when risk depends on history —
and "adaptive planning changes no route on a real graph of this size and shape"
is a legitimate answer to the question the project exists to ask. No parameter
was tuned to avoid it. `k`, the categories and the entry points are all as
decided before the run.

`TYWIN`'s cost rises 39.5 → 44.5 under the history model, because its route
repeats `acl_abuse` seven times. **The cost moves; the route does not** — the
alternatives repeat the same categories, so the penalty applies roughly evenly
and re-ranks nothing. That is the mechanism behind the null result, and it is the
Shape D collapse again in a third form: when 80.4% of the graph is one category
carrying one weight, a category-repeat penalty has little to discriminate with.

**It is a finding rather than a bug**, and that distinction was checked rather
than asserted. The model *can* change routes: on `random_ad(seed=17)` the exact
search returns a different route from the static planner. Pinned by
`test_the_adaptive_model_can_change_a_route_somewhere` so the claim cannot
quietly stop being true. Correctness is separately guarded — the returned cost is
re-scored with the model's own `route_cost`, and the exact search is asserted no
worse than the static planner under the history model, which is the property that
makes an optimality gap meaningful.

### Three method results from this pass

Recorded together, because they are the available evidence that the process is
not just confirming a prior.

**A weight moved up.** `SQLAdmin` 3.5 → 5.0. Every previous revision moved down,
and "sourcing always lowers weights" was becoming an unstated assumption. It is
false: 3.5 was not pricing impact, it was pricing the wrong channel.

**A registered prediction failed and is recorded as failed.** The triage
predicted `AddMember` would be "likely the loudest of these eight after
`DCSync`". It landed mid-table at 4.5, because the shipped rule is stable but
level `low` with unknown false positives and matches any global-group addition.
The prediction reasoned from event reliability; loudness needed the rule's
severity and scope.

**A citation was refused.** A search returned a "Tier-0 Password Reset (4724)"
rule with no SigmaHQ path, a malformed id and a future date. Not cited.
`ForceChangePassword` rests on Microsoft's 4724 documentation and T1098 instead,
with the refusal recorded in the weight's `source` field. This pass had already
produced two bad citations — a filename that 404'd and an `AccessMask` term
absent from the rule body — which is why the third was checked rather than used.

---

## 2026-08-09 (last) — the seven, the composite inversion, and the gate weights closed

**Graph:** unchanged, sha256 `3c1bef97…`. **All 13 gate weights are now
sourced.** 21 of 35 overall; the remaining 14 sit on no observed route and stay
deferred.

### A weight nothing reads is a weight nothing checks

`GetChanges`, `GetChangesAll` and `GetChangesInFilteredSet` sat at 8.0 while
`DCSync` — the composite they combine into — was sourced down to 6.5. **The
halves were louder than the whole.** Exercising the composite means exercising
the components, so this is not stale pricing; it is incoherent.

**How it survived is the finding.** All three are in `PARTIAL_RIGHT_EDGES` and
non-traversable. No route reaches them, so no `compare` run can produce a number
that contradicts them, so no amount of running the system would ever have
surfaced it. Every other weight in the table is checked continuously and
implicitly by the routes it participates in. These three had no such check, and
went inconsistent silently.

This is the **second independent failure at the same edge triple.** The first
was the joint-capability bug that started the audit — walking one replication
half claims a capability the attacker lacks, and prices it cheaper than the real
thing. That was a *traversal* error; this is a *pricing* error; they share a
site and nothing else. The common factor is that replication is the one place in
the schema where a capability is split across edges, and split things drift.

**Fixed as one unit with the composite: all three re-derived to 6.5, equal to
`DCSync`, not merely below it.** The reason is in the rule body — the Sigma
selection matches `Properties|contains` **any one** of the four replication
GUIDs, so a request carrying only `DS-Replication-Get-Changes` produces the same
4662 and trips the same rule as a full DCSync. The detection keys on the
replication request, not on how many rights the principal holds. Equal is the
derived answer.

**Guarded now, because only a static check can catch this class.**
`ad_schema.COMPOSITE_RIGHTS` makes the composite→component relationship
machine-readable — it was already asserted in the `PARTIAL_RIGHT_EDGES`
docstring, so this encodes an existing claim rather than adding one — and
`test_no_composite_is_quieter_than_a_component_it_subsumes` enforces it.

It already has something to say about the future: **`SyncLAPSPassword` is the
other composite** (`GetChanges` + `GetChangesInFilteredSet`) and sits unsourced
at **2.5**, far below its own components. The invariant skips it only because
comparing against an unsourced guess is the anchoring trap. Source it below 6.5
and the test fails — correctly, because the same rule fires.

### The seven

| Edge | was | now | why it moved |
|---|---|---|---|
| `MemberOf` | 0.1 | **0.1** | floor confirmed; both halves genuinely empty |
| `AdminTo` | 3.0 | **2.5** | visibility without suspicion — recorded by default, no rule alerts |
| `SQLAdmin` | 3.5 | **5.0** | wrong channel assumed; EDR rule is level *high* |
| `HasSession` | 6.0 | **6.0** | unchanged; named rule found, derivation held |
| `ForceChangePassword` | 5.0 | **4.0** | "users notice" is not telemetry |
| `AddMember` | 4.0 | **4.5** | stable rule, but level *low* |
| `AddSelf` | 4.0 | **4.5** | identical to `AddMember`; nothing shipped distinguishes them |

**`SQLAdmin` is the first weight in the project to move *up*.** Every previous
revision moved down because the original priced impact. This one was wrong in a
different way — 3.5 assumed detection depended on SQL Server auditing, which the
audit doc had already ruled outside the baseline. Pricing the correct channel
(`sqlservr.exe` spawning a shell, a level-**high** shipped rule) raised it. Worth
recording because "sourcing always lowers weights" was becoming an unstated
assumption, and it is false.

**A registered prediction failed.** The triage predicted `AddMember` would be
"likely the loudest of these eight after `DCSync`". It is not — it lands at 4.5,
mid-table. The rule body is why: the shipped rule is **stable but level `low`**
with false positives "Unknown", and it matches *any* addition to *any*
security-enabled global group. It is an audit-trail rule, not an alert. The
prediction was reasoning from event reliability; loudness needed the severity
and the scope of the rule, which only reading it gives.

**`ForceChangePassword` is the cleanest impact leak of the seven.** Its 5.0 was
partly "the user is locked out and complains" — a real consequence, and not
telemetry. That is the named non-telemetry limitation from the audit doc, and it
had been folded into a detection weight anyway.

**`AddSelf` exposed a detection-engineering gap rather than a modelling one.**
The triage asked whether anything in the log distinguishes it from `AddMember`.
4728 records `Subject` and `Member` as separate fields, so self-addition *is*
expressible and is genuinely suspicious — administrators rarely add themselves.
No shipped rule compares the two fields. The signal exists and is unused, so
both price identically at 4.5.

**`HasSession` did not move.** A sourcing pass that only ever changes numbers
would itself be suspicious; this one confirmed a value.

### Routes after the full gate set

| | plain | weighted | |
|---|---|---|---|
| `SAMWELL` | 2h / 4.1 | 2h / 4.1 | identical |
| `SQL_SVC` | 4h / **20.0** | 4h / **15.1** | gap **4.9** |
| `TYWIN` | 9h / 39.5 | 9h / 39.5 | identical |

The `SQL_SVC` result survives the whole gate set: same hop count, `DCSync`
avoided entirely, gap 4.9. It has now been 7.4 → 10.4 → 7.9 → 5.4 → 4.9 across
five derivations. **The direction has never changed and the magnitude has never
stopped moving** — which is exactly what the sensitivity note above this entry
predicted, and the reason it was written before `DCSync` was priced.

`TYWIN` at 39.5 is unchanged by coincidence, not by stability:
`ForceChangePassword` −1.0 against `AddSelf` +0.5 and `AddMember` +0.5 happens to
net to zero on that route.

---

## 2026-08-09 (later) — `DCSync` sourced 9.0 → 6.5, and the threshold that tests it

**Graph:** unchanged, sha256 `3c1bef97…`. **What changed:** `DCSync` only, from
an unsourced 9.0 to a sourced **6.5**. Sourcing now 11 of 35 overall, **6 of the
13 gate weights**.

**Source:** SigmaHQ
`rules/windows/builtin/security/win_security_ad_replication_non_machine_account.yml`
— "Active Directory Replication from Non Machine Account - DcSync Indicator",
id `17d619c1-e020-4347-957e-1d1207455c93`, ATT&CK **T1003.006**. Event 4662 with
the replication extended-right GUIDs.

### The impact leak was here, and it was the biggest one in the table

`DCSync` is the highest-impact edge in the schema — every hash in the domain,
krbtgt included. 9.0 on a 10-point scale was pricing *that*. Near-ceiling is a
claim that the action is almost maximally **noticeable**, which is a different
statement and one the evidence does not support.

Every weight revised so far has moved down for this reason. This is the purest
case of it: the edge where impact and loudness are furthest apart, and the one
where the confusion was hardest to see precisely because the number *felt*
right.

### The SACL dependency survives — confirmed, not assumed

The audit doc flagged `DCSync` as "the one edge whose SACL dependency probably
survives" and asked for confirmation. Confirmed. 4662 needs a SACL on the domain
root plus the Directory Service Access audit subcategory. The baseline grants
SACLs on tier-zero objects, and **the domain root is tier-zero** — so unlike the
Shape D edges, where the native channel is silent on ordinary objects, here it
genuinely fires.

That makes `DCSync` the **structural mirror of Shape D**. Those four rest
entirely on the endpoint half and are defeated by renaming a cmdlet. This one
rests entirely on the native half and cannot be defeated that way at all: the
replication GUIDs are protocol constants, so you cannot request replication
without asking for them. Neither has both halves.

**What pulled it down from a higher number:** the rule is `test` status, its
documented false-positive rate is *medium* rather than low, and it filters
principals ending in `$` — so `DCSync` from a computer account is not matched.
That bypass is cheap wherever a route already yields a machine account.

### Routes after the change

| | plain | weighted | |
|---|---|---|---|
| `SAMWELL` | 2h / 4.1 | 2h / 4.1 | identical, unchanged |
| `SQL_SVC` | 4h / **19.0** | 4h / 13.6 | gap **5.4** (was 7.9) |
| `TYWIN` | 9h / **39.5** | 9h / 39.5 | identical; moved 42.0 → 39.5 |

### H4 — the threshold marks where avoidance stops, not where weighting stops mattering

*At what `DCSync` weight does `SQL_SVC`'s avoidance stop being preferred?*

**The primary result is structural, and the number is a consequence of it.**

Below the flip the planners **do not converge**. The route becomes
`SQLAdmin → HasSession → MemberOf → DCSync` — still not the plain route, which
is `SQLAdmin → HasSession → AdminTo → DCSync`, because `MemberOf` (0.1)
undercuts `AdminTo` (2.5). Risk-weighting keeps changing the answer below the
threshold; it just stops changing it *about `DCSync`* and starts changing it
about the third hop instead.

So the threshold marks where **`DCSync`-avoidance** stops being preferred. It is
not the point where the weighted planner degenerates into the plain one, and
reporting it as such would overclaim in the project's own favour.

**The threshold is 3.9, and it is set by `GenericWrite`, not by `DCSync`.** Both
candidate routes share `SQLAdmin → HasSession → MemberOf`; the choice is
`GenericWrite` (4.0) against `DCSync` (w), so the flip happens the moment
`DCSync` drops below the ACL-write base. Confirmed by re-running the sweep after
`AdminTo` moved 3.0 → 2.5 in the sourcing pass below: **the threshold did not
move.** Nothing on the plain route affects it.

That connects the two findings in this log. The ACL-write base *is* the Shape D
collapse value — one number carried by 80.4% of the graph — so the
weight-sensitivity of the headline result is pinned to the collapsed weight
rather than to `DCSync` itself. Re-derive Shape D and this threshold moves with
it.

At the sourced 6.5 the avoidance holds with **2.6 of headroom** above the flip.

**`MemberOf` is doing real work here and is worth naming.** At 0.1 it decides
the third hop in both the avoidance route and the flipped route. It was in the
gate set and has since been sourced (below) — the floor survived the check, and
both halves came back genuinely empty, so the cheapness is derived rather than
assumed. Had it moved, this threshold analysis would have needed redoing.

---

## 2026-08-09 — two results promoted out of the handoff, before `DCSync` is priced

**Graph:** unchanged, sha256 `3c1bef97…`. No weight moved. Both entries below
were decided earlier and were sitting in `handoff.md` as "decided, not yet
written up". They are recorded here **before** the `DCSync` sourcing pass so
neither can read as a retrofit if that pass moves the numbers.

### The Shape D collapse is a finding, not an implementation detail

All four ACL-write edges — `WriteDacl`, `WriteOwner`, `GenericAll`,
`GenericWrite` — derive to the **same 4.0 base**. Not a modelling shortcut: the
EDR signal does not distinguish *which* right is being written. Script-block
logging and Sysmon Event 1 capture the cmdlet and its command line, and
`Add-DomainObjectAcl` looks the same to both whether the DACL, the owner, or a
generic right is the thing being changed.

Those four types are **80.4% of the collected graph**. So the dominant edge
distinction in an AD attack graph is, under an EDR-dominated posture, *invisible
to the defender*.

The claim: **cost models that assign different constants to these four are
encoding authority, not observability.** They are pricing how much power the
right confers, which is a real property and the wrong one — it is the impact-
versus-loudness failure mode, appearing in the one place where it affects most
of the graph. This falls straight out of the check the sourcing method already
applies; what is new is noticing that it lands on four fifths of the edges.

Honest consequence, and it cuts against us: it **reduces the static planner's
discriminating power** on this graph. Where a route is ACL-dominated the
weighted planner has almost nothing to choose between, which is exactly what
`SAMWELL` showed when its result evaporated. That raises the stakes on whether
the history-dependent planner finds anything the static one cannot — the
remaining discrimination has to come from somewhere, and if it is not in the
static weights it has to be in the history.

The distributional half of this was already noted as a consequence in the
2026-08-05 entry ("80.4% of edges just became near-free"). This entry promotes
it from an observation about the graph to a claim about cost models generally.

### `SQL_SVC`'s gap is direction-robust and magnitude-sensitive

The gap has been **7.4, then 10.4, then 7.9** across three derivations in a
single session. Every derivation was honest; each moved because the ACL-write
base underneath it moved.

**The qualitative result is the claim. The number is not.** What has held
through all three: identical hop count, and `DCSync` avoided entirely —
`SQLAdmin → HasSession → MemberOf → GenericWrite` against the plain
`SQLAdmin → HasSession → AdminTo → DCSync`. What has not held: the magnitude,
which has moved by more than a third of its own value without anything being
wrong.

This is recorded now, before `DCSync` is priced, for a specific reason. `DCSync`
is the number the plain route's cost mostly consists of, so sourcing it will move
this gap again. Writing the sensitivity down first means a narrower gap reads as
the measurement it is, rather than as a result quietly walked back.

**If sourcing `DCSync` moves it substantially, that is itself reportable.** It
feeds the weight-robustness question directly, and the machinery to answer it
already exists: *at what `DCSync` weight does `SQL_SVC`'s avoidance stop being
preferred?* That threshold is a finding either way — it converts the result's
weight-sensitivity from a caveat into a measurement. Answer it in the same pass
that prices `DCSync`.

---

## 2026-08-05 (later) — the flip fired on half a baseline, then un-fired

**Correction to the entry below.** The 1.5 floor was derived from native AD
auditing only: 5136/4670 need a SACL, the baseline grants SACLs on tier-zero
objects only, so an ACL write on an ordinary object emits nothing. Sound, and
incomplete — **the baseline also assumes EDR/Sysmon-class telemetry, which needs
no SACL.**

SigmaHQ `posh_ps_powerview_malicious_commandlets.yml` fires on script-block
logging (4104) for the PowerView cmdlets that perform these writes
(`Add-DomainObjectAcl`, `Set-DomainObjectOwner`), and Sysmon Event 1 carries the
command line. Both in-baseline, named shipped rule, distinctive low-false-positive
strings. **The write is observed.** Base re-derived 1.5 → **4.0**.

| | plain | weighted | |
|---|---|---|---|
| `SAMWELL` | 2h / 4.1 | 2h / 4.1 | **still identical** |
| `SQL_SVC` | 4h / 21.5 | 4h / **13.6** | gap **7.9** |
| `TYWIN` | 9h / 42.0 | 9h / 42.0 | identical |

### The near-miss is the finding

The intermediate 1.5 would have produced a striking headline — *directory
modification is quieter than ticket forgery* — and it was an artifact of
deriving from half the stated baseline. **It survived a full review pass before
being caught.** Recorded because the sourcing method is itself a contribution,
and this is the clearest example of it failing and then working.

The 1.5 is not discarded. It is preserved as the `tooling_is_native_ldap`
conditional, because it is the right answer for an attacker using
`.NET DirectoryServices`, SharpView, or Impacket `dacledit` from Linux. **The
detection is tooling-dependent, not technique-dependent, and evasion is cheap** —
renaming a function defeats it. That assumption is recorded on every one of the
four weights.

### `SAMWELL`'s loss is robust to the correction

It did not come back. All four ACL writes derive to the **same** base — the EDR
signal is identical regardless of which right is written — so `GenericWrite` and
`WriteOwner` tie at any floor level. The original 0.5 gap was an artifact of two
arbitrary guesses, and no honest derivation reproduces it. Pinned by
`test_acl_write_ordering_after_the_full_baseline_derivation`.

### Registered flip: fired, then un-fired

`SpoofSIDHistory` (3.5) is back below the ACL writes (4.0), where it started. The
cross-check prediction was right after all — but only once the derivation was
complete. **A prediction that fails against an incomplete derivation has not
actually failed.**

---

## 2026-08-05 — Shape D sourced: one finding survived, one evaporated

**Graph:** unchanged, sha256 `3c1bef97…`. **What changed:** `GenericWrite`,
`WriteDacl`, `WriteOwner`, `GenericAll` moved from unsourced 4.5–5.0 to sourced
**1.5** (non-tier-zero), with tier-zero conditionals of 4.5–6.0.

| Entry | | before | after |
|---|---|---|---|
| `SAMWELL` | plain | 2h / 5.1 `WriteOwner → GPLink` | 2h / **1.6** `WriteOwner → GPLink` |
| | weighted | 2h / 4.6 `GenericWrite → GPLink` | 2h / **1.6** *identical to plain* |
| `SQL_SVC` | plain | 4h / 21.5 | 4h / **21.5** unchanged |
| | weighted | 4h / 14.1 | 4h / **11.1** |
| `TYWIN` | both | 9h / 46.5 | 9h / **29.5** |

### `SQL_SVC` survived and strengthened — gap 7.4 → 10.4

Still `SQLAdmin → HasSession → MemberOf → GenericWrite` against the plain
`SQLAdmin → HasSession → AdminTo → DCSync`, still the same hop count, still
avoiding `DCSync` entirely. The gap widened because the ACL write it uses got
cheaper. **This result did not depend on the guesses** — it turns on `DCSync`
(9.0) versus an ACL write, and sourcing moved them further apart, not closer.

### `SAMWELL`'s result evaporated — and that is the honest outcome

Both planners now return `WriteOwner → GPLink` at 1.6. **The weighted planner no
longer differs from plain shortest path for this entry point.**

The previous 0.5 improvement was `GenericWrite` (4.5) versus `WriteOwner` (5.0) —
two unsourced guesses, flagged in the process note below as exactly that. Sourced
honestly, both are 1.5 on an unaudited target: no SACL, no 5136, nothing
recorded. There is no longer anything to choose between them, so the planners
tie and the tie-break picks `WriteOwner`.

**A finding was removed by doing the work properly.** Recorded rather than
quietly dropped, because it is the clearest evidence available that the caveat on
unsourced weights was load-bearing and not boilerplate.

### The registered flip fired

The audit doc's cross-check table predicted that Shape D sourcing might push
these five below 3.5 and invert four predictions. It did. Under the stated
baseline, **ACL writes on ordinary objects are now the quietest meaningful
actions in the schema** — below ticket forgery (3.5) and below delegation abuse
(4.0–5.0) — because 5136 needs a SACL and the baseline grants SACLs only on
tier-zero objects. An action nobody records is quieter than one producing
ordinary-looking Kerberos traffic.

`test_acl_writes_price_below_the_forgery_and_delegation_edges` was rewritten from
asserting the old ordering to asserting the new one, with the reasoning.

**Consequence for the graph:** 80.4% of edges just became near-free. Expect the
weighted planner to become *less* distinguishable from plain shortest path on
ACL-dominated routes, and more distinguishable where a route can avoid a
genuinely loud action (`DCSync`, `HasSession`). `SQL_SVC` versus `SAMWELL` is
that contrast in miniature.

## 2026-08-04 — First real routes on collected data

**Graph:** `data/goad_graph.json`, sha256 `3c1bef97…` (supersedes `b427ef8a…`, `ff5a00f5…`)
**Collection:** published GOADv2 SharpHound 2.3.3, 2024-04-10 — see
`data/collection_provenance.json`
**Planners:** Dijkstra (unit cost) vs weighted A\* (`static_cost_fn`)
**View:** `with_gpo_expansion()`, traversal set
`DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES`

The first comparison run on real collected data rather than the synthetic
fixture. Three documented entry points, all with verified routes to a tier-0
target.

| Entry | Planner | Hops | Risk | Route |
|---|---|---|---|---|
| `SAMWELL.TARLY@NORTH` | plain | 2 | **5.1** | `WriteOwner → GPLink` |
| | weighted | 2 | **4.6** | `GenericWrite → GPLink` |
| `SQL_SVC@NORTH` | plain | 4 | **21.5** | `SQLAdmin → HasSession → AdminTo → DCSync` |
| | weighted | 4 | **14.1** | `SQLAdmin → HasSession → MemberOf → GenericWrite` |
| `TYWIN.LANNISTER@SEVENKINGDOMS` | plain | 9 | **46.5** | `ForceChangePassword → GenericWrite → WriteDacl → AddSelf → AddMember → WriteOwner → GenericAll → GenericAll → DCSync` |
| | weighted | 9 | **46.5** | *identical* |

### The `SQL_SVC` result is the significant one

**Same hop count, 7.4 lower risk, `DCSync` avoided entirely.**

This is the first evidence on real data that the two planners genuinely differ,
and it is the cleanest possible shape of that difference: the risk-aware planner
did **not** trade hops for quiet — it found a route of *identical length* that
skips the single loudest action in the schema. Plain shortest path has no basis
to prefer either, because both are four hops, so it takes whichever the
tie-break hands it.

That matters more than a longer-but-quieter route would. A quieter route costing
extra hops is a trade someone might reject; a quieter route costing nothing is
strictly better, and a hop-counting planner cannot see it. It is a concrete
instance of the plain baseline minimising hops while being indifferent to
detection.

**Caveat:** the size of the gap (7.4) is weight-dependent — it is essentially
the price of `DCSync` (9.0) minus what replaced it. The *existence* of the gap is
structural and will survive re-sourcing; the magnitude will move.

### `SAMWELL` — small difference, same shape

Both planners take the GPO chain; the weighted one swaps `WriteOwner` (5.0) for
`GenericWrite` (4.5) onto the same GPO. A 0.5 improvement, and a good check that
the planner picks the cheaper of two equivalent rights rather than the first one
it finds.

### `TYWIN` — identical, and that is fine

Nine hops through five technique categories, and both planners return exactly
the same route. Where the shortest route genuinely is also the quietest, they
*should* agree. Worth recording precisely because a comparison that always
differs would be more suspicious than one that sometimes doesn't.

### Checked and found empty — delegation weights change nothing here

Recorded so the absence is on the record as *checked*, not forgotten.

After sourcing `AllowedToDelegate` (4.0), `AllowedToAct` (4.5) and
`AddAllowedToAct` (5.0 / 6.0 tier-zero), **no `cli compare` re-run was done,
because there is nothing to re-run.** This graph contains **zero** delegation
edges of any kind — not dropped, simply absent. The three routes above are
unaffected and the numbers in the table stand unchanged.

Two consequences worth carrying forward:

- The delegation weights are **sourced but unexercised by real data.** They are
  the first weights in the table with citations and the least load-bearing on
  anything measured so far.
- **`synthetic.random_ad()` does generate `AllowedToDelegate`** (24 edges across
  12 seeds), so that weight *does* feed any statistic computed over generated
  graphs. A number produced that way is not grounded in the real collection, and
  should not be described as if it were.

### Process note — triage order needs re-checking

The delegation trio took several passes and produced weights that move nothing
in the only real graph we have. Meanwhile `WriteDacl`/`WriteOwner`/`Owns`/
`GenericAll`/`GenericWrite` are ~4,500 of ~6,700 real ACEs and **already changed
this round's routes** — `SAMWELL`'s weighted route turns on `GenericWrite` vs
`WriteOwner`, a 4.5-vs-5.0 comparison between two unsourced guesses.

The work was worth doing and the cost is sunk; the trio is finished rather than
abandoned. But the ordering was wrong: it was picked by "what came up in
conversation" rather than by edge count or by influence on observed routes.

**Re-check the triage order before starting the edge after Shape D**, using
those two criteria explicitly.

### Conditions

- `SAMWELL`'s route exists only under `with_gpo_expansion()`; under the default
  traversal set it has none.
- `SQL_SVC` uses one of only **5** surviving `HasSession` edges in the whole
  collection. Session data is thin (idle lab at collection time) — see the
  provenance `known_gaps`. A collection with realistic session volume would
  likely produce more routes of this shape, not fewer.
- ADCS edges are dropped from this graph, so any route that would have run
  through certificate abuse is absent. Path costs here are an upper bound on
  what a real attacker would pay.
