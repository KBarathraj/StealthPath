# Abstract — merged framing

**Status: draft for review.** Supersedes the "Q-Learning + BFS incremental
retraining for efficiency on dynamic AD graphs" framing. Q-learning and BFS both
survive; what changes is what they are *for*.

---

## Why the efficiency framing was dropped

The earlier draft made incremental-retraining efficiency the headline. Two
problems, and the second is fatal to it as a *research* claim.

**It deletes the contribution.** Detection risk is the only thing that makes this
project different from the existing literature. A framing that optimises for
convergence speed on a dynamic graph has no detection model in it, and without
one the work is a graph-algorithms paper that happens to use AD as a substrate.

**The baseline is too easy to beat, so beating it proves nothing.** Tabular
Q-learning over 783 nodes converges in seconds. A speedup measured against that
is not a result — it is a statement about how small the graph is. Efficiency
becomes reportable **only if** the tractability crossover experiment shows exact
history-aware search failing at a scale where the learner still works. Until that
measurement exists, efficiency is a secondary, conditional claim and must not
lead.

It also **collides directly with the Adelaide program.** Goel, Guo, Neumann and
Nguyen have an established line on dynamic AD graphs and RL. Racing them on
their own axis, with a smaller graph and no detection model, is a losing
position. The differentiation is stated below and it is not about efficiency.

---

## Contributions, in order

**(a) A detection-cost model for AD edges, sourced rather than asserted.**
Per-relationship loudness weights, each traced to an ATT&CK technique, a named
SigmaHQ rule, or a documented detection strategy, under an explicitly stated
telemetry baseline (standard Windows logs plus SIEM, EDR/Sysmon-class endpoint
telemetry, native AD auditing; custom correlation and UEBA excluded). The
baseline is the load-bearing part: "is this loud?" is meaningless without it, and
published weights that do not state one are not reproducible.

Two failure modes are named and guarded against in the sourcing method: pricing
*impact* rather than *likelihood of notice*, and deriving a sourced weight by
anchoring to an unsourced neighbour.

**(b) A three-planner comparison under that cost model.** Unweighted shortest
path (what BloodHound does today), risk-weighted A\*, and Q-learning over a
history-augmented state. All three emit the same `Path` type so the comparison is
not three special cases.

**(c) Exact history-aware search as an optimal reference.** The novel piece
methodologically. Because the state space is small enough to admit exact search
over history-augmented states, the learner can be scored by **optimality gap
against a known optimum** rather than by a training curve. Reporting "converged"
tells a reader nothing about solution quality; reporting "within X% of optimal"
does.

**(d) Affected-region analysis under graph change.** Given a permission change,
diff the graph and reverse-BFS to bound the region whose optimal routes could
have changed. This supports two things: a *measurement* — how far the effect of
one change actually propagates under a history-dependent cost model — and an
*engineering* use, selective retraining of only the affected region.

**(e) Real collected data and an open benchmark.** Routes, weights and results
come from a frozen SharpHound collection in BloodHound's own schema, cited by
hash, with full provenance including what was dropped and why. Released with the
weight table and its citations so the cost model can be criticised rather than
taken on faith.

---

## Differentiation from the Adelaide program

Stated explicitly, because the earlier framing collided with it.

| | Goel / Guo / Neumann / Nguyen | This work |
|---|---|---|
| Whose policy is optimised | **Defender** — edge blocking, hardening | **Attacker** — the object of study, never a scoring device |
| What the attacker is for | A device for scoring defender policies | The thing being compared |
| Detection model | Per-edge constant failure/detection rate | Sourced per-edge cost, and history-dependent in the adaptive regime |
| Graph provenance | Modelled / synthetic (R500, R1000 style) | Real SharpHound collection, BloodHound schema, cited by hash |
| Question | How should a defender harden? | Does adaptive planning beat a tuned static heuristic at staying quiet, and does that depend on history? |

The honest weakness is scale — a teaching-lab collection is small next to a
generated R1000. That is stated up front rather than left for a reader to find.
The trade is realism of schema and edge semantics against size, and the
detection-model axis is where the actual novelty sits.

---

## Scope statement on H3 — history dependence is tested in a weakened form

**This is a scope statement, not a footnote, and H3 itself is unchanged.**

H3 asks whether the learner's advantage depends on risk being history-dependent.
The learner's state is `(current node, history summary)`, and the chosen summary
is **the set of technique categories used so far** — nine categories, one bit
each.

So "risk depends on the attacker's own history" is operationalised as **"risk
depends on whether a category has been used before."** One bit per category, a
single step change on first repeat, no escalation with count. A third
Kerberoast costs exactly what the second did.

**Why this summary and not a richer one.** Two reasons, and the first is the
substantive one.

*It is what the telemetry baseline supports.* Unbounded escalation with
repetition implies a defender accumulating evidence across occurrences and
raising suspicion as a count grows. That is precisely the correlation and
baselining the stated baseline excludes. What a default-logging posture actually
supports is a qualitative shift when a category **first appears** — a technique
the environment has not seen before. A step change models that; a growing
gradient models a capability we explicitly do not assume the defender has.

*It is also the tractable one, and that was costed rather than assumed.* The
set-of-categories summary gives 400,896 states and a sparse Q-table of ~2.87 M
entries (≈23 MB). The count-based alternative — per-category counts capped at
three — gives 205 M states and ~1.47 × 10⁹ entries, **≈11.8 GB**, which is where
tabular learning stops being reasonable. The cheaper representation was chosen
because the evidence supports it, and it happens to also be the affordable one.

**The consequence for reading H3.** A confirmed H3 under this summary says
history-dependence *of the first-use kind* is what the learner exploits. It does
**not** establish that count-based escalation would produce the same result, and
a reviewer asking that question is asking something the experiment does not
answer. The answer is: not tested, at 11.8 GB for the representation that would
test it, and the step form is what the baseline licences.

**Two properties change shape under this summary**, both recorded in
`stage3_risk_model_properties.md`: P2 is restated as *strictly louder on first
repeat of a category, non-decreasing thereafter* (the original strict-increase-
on-every-repeat is unsatisfiable when the summary cannot count), and P15 is
renamed *bounded step* from *gradient, not cliff* — there is no gradient
available to a one-bit summary, so the old name would mislead.

## What is deliberately *not* claimed

- **Not** generalisation across environments. One frozen graph, stated as such.
- **Not** a better attacker. The question is comparative: does the extra
  machinery buy anything.
- **Not** efficiency, unless (c)'s crossover measurement supports it.
- **Not** distributional claims from the generator. `random_ad`'s edge mix is
  measurably inverted relative to real AD, so statistics over it describe the
  generator. See `generator_vs_real_distribution.md`.

A negative result is publishable here and the design accommodates it: "adaptive
planning is unnecessary under static risk" is a finding.
