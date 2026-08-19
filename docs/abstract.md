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

**The weight table is a result, not a parameter.** This is the methodological
claim behind (a), and two independent observations from the sourcing pass
support it from opposite directions.

*The ordering is not derivable from the baseline.* When the hand-written
invariants were separated from the recorded numbers, only the **structural**
assertions survived as things provable from the telemetry baseline alone —
monotonicity (a tier-zero conditional is never quieter than its base; a
conditional modelling absent tooling is never louder), bounds (no weight is free,
none exceeds the scale), and completeness (every walkable edge is priced, every
sourced weight answers both baseline halves). Every assertion carrying **domain
content** failed to survive: `SpoofSIDHistory` below `WriteDacl`, ACL writes
below delegation abuse, the four ACL bases being equal. Each of those turned out
to be an *empirical output* of sourcing — a measurement that could have come out
otherwise — rather than a claim derivable from the stated baseline. They are
recorded in the snapshot, not asserted in the invariants.

*And the derivation can fail in a way that looks like success.* The same pass
produced an intermediate value that yielded a striking, publishable-sounding
headline — *directory modification is quieter than ticket forgery* — from a
derivation that used half the stated baseline. It was internally consistent and
**survived a full review pass** before being caught. Written up in
`findings.md` (2026-08-05, "The near-miss is the finding").

Together these say the same thing twice: if the ordering were derivable, the
domain assertions would have held and an incomplete derivation would have been
visibly inconsistent. Neither happened. That is why the *method* is the
contribution and the table is one of its outputs — a table published without its
derivation is not reproducible even when every number in it is right.

**The sensitivity chain — one modelling choice, traced to one reported number.**
This is the strongest methods argument the project has, and it is a single causal
chain rather than a set of caveats. The headline `SQL_SVC` result is that the
risk-weighted planner avoids `DCSync` at equal hop count. Its weight-sensitivity
threshold — the point at which avoidance stops being preferred — is set not by
`DCSync` but by `GenericWrite`, because both candidate routes share their first
three hops and the choice is between those two edges; sweeping `DCSync` while
`AdminTo` moved underneath it left the threshold unmoved, which is how this was
established rather than assumed. `GenericWrite`'s weight is the **Shape D
collapse value**: one number carried by all four ACL-write edges because the EDR
signal cannot distinguish which right is written, and therefore by **79.4% of
walkable edges** (the modal-weight share). That value comes from the *endpoint* half of the telemetry baseline —
the half that was omitted in the first derivation, produced a striking and wrong
headline, and survived a full review pass before being caught. And it rests on a
Sigma rule matching PowerView function names, which renaming a cmdlet defeats. So
the reported finding's robustness traces back through a threshold, to a
collapsed weight, to a baseline half that was once missed, to a rule that is
cheap to evade. Every link is documented in `findings.md`; the chain is what a
sourcing method buys, and no published weight table without one can be
interrogated this way.

The honest form of the result belongs with it: `SQL_SVC`'s gap has been **7.4 →
10.4 → 7.9 → 5.4 → 4.9** across five derivations. **The direction has never
changed and the magnitude has never stopped moving.** The qualitative claim —
same hop count, `DCSync` avoided entirely — is what survives; the number is not
the finding.

A limitation belongs next to this claim and should reach the paper close to
verbatim from the `RiskWeight.channels` docstring: recording which detection
channels a weight rests on **forces the question and catches an unanswered one;
it cannot catch a confidently wrong answer.** A weight declaring that no
endpoint rule exists looks identical to one where none does. That residual gap
is a literature-search failure, and only review closes it.

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

**(e) Real collected data and an open benchmark, released with its
distribution.** Routes, weights and results come from a frozen SharpHound
collection in BloodHound's own schema, cited by hash, with full provenance
including what was dropped and why. The release carries **both graphs by hash**
(base and the H5/H6 perturbed copy), the weight table with its citations and
`channels`, the executable property suite, the provenance record, and the
**edge-type distribution with HHI figures**.

The distribution is part of the artifact, not an appendix to it. No published
base rates for ACE or edge-type distribution across real domains could be found,
and the nearest comparators evaluate on synthetic graphs and report no real
distribution at all — so a collection released *with* its concentration measured
is what makes the conditional claim in (f) checkable by anyone else. That is what
turns releasing a collection from a courtesy into a contribution.

**(f) Identification of when detection-aware planning pays, and that the cost
model decides it.** Independent per-edge cost sampling — the standard
construction in this literature — makes ties impossible with probability 1, which
guarantees the hops-versus-risk frontier that makes a naive attacker easy to
beat. A sourced cost model produces a genuine mode instead, because detection
channels are shared across edge types and shared causes are what independence
assumes away. Reaching this required a real collection *and* a sourced cost model
together; neither alone can show it. See the named section below.

---

## Methods note — one pre-registered hypothesis could not have failed

H2 asks whether the risk-weighted planner gives the best tradeoff under static
risk. It does, and it could not have done otherwise: minimum-cost path over
non-negative edge weights is solved by A\* with an admissible heuristic, and the
heuristic used here is admissible by construction. Confirming H2 is therefore a
**correctness check on the implementation**, not evidence about Active Directory.

Reported here rather than left in the log, because the distinction is what makes
the other results credible. A hypothesis set in which every entry is winnable
tells a reader nothing when the entries are confirmed. This one contains a
hypothesis that could only pass (H2), one that failed on the structure of the
problem rather than the size of an effect (H1), one answered in the negative
(H3), and two whose registered prediction was wrong in a way that sharpened the
claim (H5/H6). Saying which is which is part of the evidence.

## Methods note — a correct number used in the wrong place

A recurring failure class, named because it has now happened more than once and
neither instance was caught by review.

**It is not a wrong number.** In every case the figure was correctly measured
*somewhere*, and became false only when imported into a claim with a different
measurement scope. That is what makes it survive review: checking the arithmetic
finds nothing, and the number has a real derivation behind it.

**Instance 1 — the 1.5 near-miss.** The Shape D ACL writes were first derived at
1.5 from native AD auditing alone. Correct for that half of the telemetry
baseline; false as a statement about the baseline, which also assumes
EDR/Sysmon-class telemetry that needs no SACL. It produced a striking,
publishable-sounding headline and survived a full review pass.

**Instance 2 — the 80.4%.** Correct in
`generator_vs_real_distribution.md` as five ACL types *including* `Owns` over all
5,825 edges. False in the collapse claim, which is about edges sharing one
*derived weight* — and `Owns` derives to 4.5, not 4.0. The right figure is the
**79.4% modal-weight share**. Caught only by measuring the antecedent properly
for the generalisation claim, not by anyone re-reading the sentence.

**A third instance was reported in review and has been retired as
unrecoverable.** An error in an ACE-count denominator was described as belonging
to this pattern: a figure of 4,486 said to cover `WriteDacl` + `WriteOwner` +
`Owns` only, measured against 6,506 raw ACEs, then carried forward as though it
spanned five edge types. It was checked against the frozen graph rather than
accepted:

| Grouping | Count |
|---|---|
| `WriteDacl` + `WriteOwner` + `Owns` | **3,355** |
| + `GenericAll` | 4,363 |
| + `GenericWrite` (all five) | **4,686** — matches the corrected figure |

The corrected side reconciles exactly. The erroneous side does not: no grouping
of these types yields 4,486. The raw-ACE denominators (6,506 / 6,043) appear
nowhere in `collection_provenance.json` and the source SharpHound archives are
not in the repository, so that half cannot be checked at all.

Retired rather than reconstructed, on the principle that two verified instances
are worth more than three with one rebuilt from memory. And the retirement makes
the section's own argument: **an attempt to document a "correct number used in
the wrong place" produced a figure that does not reconcile with the graph.** That
is the case for attaching measurement scope at the point of recording, made by
the pattern's own third instance failing to be verifiable.

**The generalisation, and it is the argument for two mechanisms already in the
codebase.** Every reported figure needs its **measurement scope attached to it**,
not implied by its surroundings. `RiskWeight.channels` does this for weights — it
forces "which baseline halves?" to be a structural field rather than prose — and
`collection_provenance.json` does it for the graph. Both were built in response
to instance 1. Instance 2 shows the same discipline is needed for *derived
statistics* about the graph, which currently carry their scope only in the
sentence around them.

**Hence the concentration figures are reported as named properties with explicit
denominators**, and HHI is given alongside the share. HHI over categories
(**0.909**) is the portable form: a single scale-free number another researcher
can compute on their own collection to check whether this paper's conditional
claim applies to them. A percentage needs its denominator explained; an HHI does
not.

## Methods note — the agent learned that giving up wins

A transferable failure, recorded because it is cheap to reproduce and hard to
see.

The Q-learning environment pre-registered a failure penalty for episodes that hit
the hop cap without reaching a target. It did **not** penalise absorbing dead
ends — nodes with no outgoing walkable edge. Such a node has no actions, so its
bootstrap value is 0.0: **numerically identical to the value a goal state gets.**
Terminating in a dead end therefore scored the same as succeeding.

The learner behaved correctly given that specification. On the real graph it
preferred a `MemberOf` edge costing 0.1 into a zero-out-degree node over the 4.1
optimal route to a target. It was not failing to learn; it had learned that
giving up wins.

**Nothing in the reported statistics showed it.** Goal-reaching rates were
healthy — 62.9% in the first 5,000 episodes on the affected entry point,
41,430 successful episodes out of 50,000 — and training completed without
warning. Optimality gap was the only diagnostic that exposed anything, which is
the argument for building the exact reference *before* the learner rather than
after.

**The signal that discriminated the diagnosis was `|Q| = 11`.** A Q-table with
eleven entries after 50,000 episodes looks like catastrophic
under-exploration — but it is exactly the right size for that entry point's
four-state reachable component. Recognising the table as *complete* rather than
*starved* is what separated "MDP misspecification" from "exploration failure",
which are indistinguishable from the success-rate curve alone and have opposite
remedies. An exploration fix here would have changed nothing and would have been
reported as a tuning improvement.

**The distinction that matters for review:** the fix changed the *environment
definition* — every non-goal termination is now penalised the way the hop cap
already was — and not the reward function toward any particular route. Reward
shaping alters what is being learned and would have to be defended as such. This
made the specification internally consistent: it had asserted that failing to
reach a target is bad, and then priced one of the two ways of failing at zero.

A second, smaller defect in the same component is recorded alongside it: greedy
policy extraction preferred actions it had never tried, because with uniformly
negative rewards an unvisited action's default of 0.0 outranks every learned
value. Correct during training, where it drives exploration; wrong at extraction,
where "no estimate" is not "good".

## Contribution — the conditions under which detection-aware planning pays are a property of the cost model, and synthetic sampling chooses them implicitly

Stated as identification, not as a correction to anyone. It is the most
transferable result here, and it could not have been reached from either half of
the setup alone.

**Independent per-edge sampling makes ties impossible.** The standard construction
in this literature draws a detection or failure probability independently for each
edge from a continuous distribution — in the closest comparator, uniformly on
[0, 0.2]. Any independent continuous draw assigns distinct costs to distinct edges
**with probability 1**. There is no mode, no plateau, and no two edges that a
cost-minimising planner cannot tell apart.

That is precisely the condition under which a shortest-path attacker is trivially
worse than a cost-aware one. A graph whose costs are drawn this way always has a
hops-versus-risk frontier, because it always has a strict ordering to exploit.
**So "the naive attacker is easy to beat" is, under this construction, a property
of the cost generator rather than a finding about Active Directory** — and it
holds for any graph structure whatever, since the draw is independent of topology.

**A sourced cost model produces a mode, and independence is exactly what forbids
it.** In this collection 79.4% of walkable edges carry one derived weight. That
is not a coincidence of rounding: the four ACL-write rights share a *detection
channel*. One alert fires for all of them, because script-block logging records
the cmdlet and not which right it altered. Cost is a deterministic function of
the channel, and the map from edge types to channels is many-to-one.

No independent per-edge draw can reproduce that, and the reason is structural
rather than a matter of tuning the distribution: the mode arises from a **shared
cause across edge types**, and shared causes are what independence assumes away.
A generator could be given a discrete distribution with atoms and would still be
choosing the concentration by hand; here it was measured.

**Why this was not previously observable.** It requires a real collection *and* a
sourced cost model, together — and neither alone is enough:

- Synthetic costs on any graph cannot show it, because the sampling forbids the
  mode before the graph is seen.
- Hand-assigned weights on a real graph would not show it either. Weights chosen
  by judgement come out distinct, because a human assigning numbers to four
  different rights naturally gives four different numbers — which is exactly what
  this project did before sourcing, and exactly the artifact the sourcing pass
  deleted. Our own earlier `SAMWELL` result was that artifact.

**This is the argument for the sourcing method being a contribution rather than a
chore**, and it is now supported by an external comparison rather than by our own
process notes. Deriving each weight bottom-up from named detections is what
allowed the mode to appear at all; assigning plausible numbers would have hidden
it, and generating them would have made it impossible.

The practical consequence for anyone modelling attack paths: **the choice of cost
model silently determines whether detection-aware planning can pay.** That choice
deserves to be stated and measured — the concentration figures and HHI in this
paper exist so it can be — rather than inherited from a generator's defaults.

## The Shape D collapse — one mechanism, five consequences, one boundary

The project's central result. One modelling fact, established by sourcing,
produces five separate outcomes across four hypotheses — and two of them fall on
the *other* side of a boundary the mechanism itself predicts.

**The mechanism, stated once.** All four ACL-write edges — `WriteDacl`,
`WriteOwner`, `GenericAll`, `GenericWrite` — derive to the *same* base weight,
because the EDR signal does not distinguish which right is being written:
script-block logging and Sysmon capture the cmdlet and its command line, and
those look identical whether the DACL, the owner, or a generic right is changed.
**79.4% of walkable edges carry that one derived weight** and 95.3% fall in the
single `acl_abuse` category.

**Two classes are easy to conflate here and the paper keeps them apart.** The
*shared-signature* class is those four types: one detection, one derivation, one
cause. The *modal-weight* class is **five** types — the same four plus
`ForceChangePassword`, which reaches 4.0 by an unrelated route (default-channel
4724, no endpoint rule, after the "users notice" impact leak was removed from
its derivation). A planner cannot tell those five apart, because it sees weights
and not derivations, so the modal-weight class is the right one for every claim
about *planning*.

It is the wrong one for claims about the detection surface, and the difference is
small enough to be tempting: `ForceChangePassword` contributes **1 edge of the
3,965** (0.02%). So the two figures are 79.42% and 79.44%, and the fifth type
carries essentially none of the mass. Recorded because the near-identical numbers
would otherwise let a claim about five types stand on evidence about four —
convergence in the output of two independent derivations is a property of a
coarse weight scale, not evidence of a shared cause.

**The two shares differ by 0.02 points, so a five-type claim could have rested on
four-type evidence indefinitely without ever producing a contradiction.** That is
the argument for pinning *membership* rather than share:
`test_modal_class_membership_is_five_types_but_four_share_the_signature` asserts
the exact set at the modal weight, that `ForceChangePassword` contributes one
edge, and that its channels differ from the other four. A share can agree to two
decimals while the claim behind it is wrong; a membership set cannot.

Concentration on one derived weight **removes what a risk-aware planner has to
trade against**. Where every alternative costs the same, there is no cheaper
route to find and no ordering to exploit — not because the planner is weak, but
because the environment has no gradient to climb.

Each consequence below is a prediction that mechanism makes.

**1 — Risk-weighting has nothing to choose (`SAMWELL`). Majority class.** Both
planners return `WriteOwner → GPLink` at identical cost. An earlier apparent
improvement here was the difference between two *unsourced guesses*; sourcing
removed it. A finding was deleted by doing the work properly.

**2 — H1 fails in shape, not magnitude. Majority class.** H1 was pre-registered
as *"plain shortest path minimizes hops but maximizes detection risk"*. Measured
across all three entry points, **the hop counts are identical** — 2/2, 4/4, 9/9.
The weighted planner never pays a single extra hop for quiet, and the risk half
holds on only one of three.

This is the strongest evidence in the project that the concentration finding is
real rather than an artifact of how the planners were built. **H1 presumes a
hops-versus-risk frontier and this graph has none.** It is the first
pre-registered hypothesis to be wrong about the *structure* of the problem rather
than the size of an effect — a planner implementation cannot manufacture the
absence of a trade-off, only fail to find one that exists. When 79.4% of edges
cost the same, a minimum-risk route is usually also a minimum-hop route.

**3 — History-dependence has nothing to re-rank (`TYWIN`). Majority class.**
Under the history-dependent model `TYWIN`'s cost rises 39.5 → 44.5 because its
route repeats `acl_abuse` seven times. **The cost moves and the route does not.**
Every alternative repeats the same category, so the penalty rescales them
together. The `k` sweep is flat to `k = 10.0` for the same reason, and this is
the mechanism behind the Tier-1 null: exact history-aware search changes no route
on any entry point.

**4 — Sensitivity is pinned to the collapsed value, via a minority edge
(`SQL_SVC`). BOUNDARY CASE.** The threshold at which `DCSync`-avoidance stops
being preferred is set by `GenericWrite`, not by `DCSync` — both candidate routes
share their first three hops, so the decision is between those two edges.
Established rather than assumed: sweeping `DCSync` while `AdminTo` moved
underneath left the threshold unmoved. `SQL_SVC` is also the *only* entry where
H1 shows anything, and the only one whose route turns on `DCSync` — a
**minority-class** edge. Discrimination survives exactly where the collapse does
not reach.

**5 — Perturbation re-ranks only outside the dominant class. BOUNDARY, MEASURED
DIRECTLY.** Two changes were pre-registered, one of each kind, and they
separated cleanly:

| | class | share | effect |
|---|---|---|---|
| P1 `GenericAll` ACE | majority `acl_abuse` | 95.3% | **no route changed** |
| P2 `MemberOf` membership | minority, floor weight | 4.0% | **`TYWIN` re-ranked, 9h → 7h** |

This is the boundary drawn by experiment rather than argument. **It was a
property of the design, not foresight** — the registered prediction was that
*neither* would matter, and having happened to register one perturbation of each
kind is what made the separation visible. Recorded as luck because it was.

**The claim, stated as a conditional with a measurable antecedent.**

> **Where** a real AD graph's dominant edge class collapses to a single detection
> signature under a stated telemetry baseline, **risk-weighting and
> history-dependence lose discriminating power WITHIN that class. Discrimination
> survives in the minority classes, and perturbations landing there re-rank
> normally.**

**The boundary clause is not a hedge — it is the result of the experiment that
tried to falsify the claim.** An earlier form asserted the loss of discriminating
power without qualification. That form was too broad: it predicts that nothing
re-ranks, and P2 re-ranked. The corrected form is both narrower and more useful,
because it says where to look — and it makes the earlier results legible rather
than merely consistent. `SQL_SVC` turns on `DCSync`, a minority edge, which is
why it is the one entry where anything is visible at all; `TYWIN`'s sweep is flat
because its route is almost entirely `acl_abuse`.

Deliberately not "AD graphs behave like this". One collection cannot establish
that, and softening the wording would not fix it. Stated as a conditional, the
claim is testable by anyone with a collection: measure the concentration, predict
the effect. It travels without pretending to have been verified elsewhere.

**The antecedent, measured on this graph.** Reported as a named property so the
condition is a number rather than a description. Over the 4,991 walkable edges of
the frozen collection:

| Property | Value |
|---|---|
| **Modal-weight share** — edges carrying the single most common derived weight (4.0) | **79.4%** (3,965) |
| Distinct derived weights present | 9 |
| HHI over derived weights | **0.654** (1.0 = one signature; 0.111 = uniform over 9) |
| Largest category (`acl_abuse`) share | **95.3%** |
| HHI over categories | **0.909** |

Modal-weight share is the antecedent for the risk-weighting half; category
concentration is the antecedent for the history-dependence half, and at 95.3%
it explains why the `k` sweep is flat — nearly every route repeats `acl_abuse`
immediately, so scaling the repeat penalty rescales all alternatives together.

**Correction to a figure used earlier.** The Shape D collapse was previously
described as "80.4% of the graph carries one weight". That number is real but is
a different measurement: five ACL types *including* `Owns`, over all 5,825 edges,
from `generator_vs_real_distribution.md`. `Owns` derives to 4.5, not 4.0, so it
does not share the signature. The correct figure for *this* claim is the
**79.4% modal-weight share**, which is measured on the derived weight rather than
on edge type and is therefore the thing the claim is actually about. The 80.4%
figure stands where it was originally used.

**Is the antecedent common? We could not establish it.** ACL dominance in
production directories is widely asserted in practitioner material, but we found
**no published base rates** for ACE or edge-type distribution across real
domains — nothing citable giving the proportion of ACL edges in a typical
enterprise directory. The nearest comparators in the literature, the Adelaide
line of work, evaluate on *synthetic* graphs (R500-style), so they supply no
real-world distribution to compare against either. That absence is itself worth
reporting: the antecedent of this claim is currently unmeasurable outside one's
own collection, which is an argument for releasing collections with their
distributions attached.

**What would falsify it.** Named as the obvious next experiment rather than left
implicit. A graph with a flatter category distribution, or one where ACL writes
split across detection shapes — different SACL coverage, an endpoint posture
where `WriteDacl` and `WriteOwner` produce distinguishable telemetry — should
show risk-weighting and history-dependence recovering discriminating power. If
such a graph showed the same null, the claim is wrong and the cause lies with
the planners after all.

The honest second data point is **a second real collection**, and that is out of
scope here. `random_ad` cannot serve: build rule 7 forbids distributional claims
from it, and its edge mix is *measured* as inverted relative to real AD, so it
would argue the opposite of whatever it was pointed at.

This is more defensible than the positive result would have been. It is derived
from sourced evidence — a named rule, a measured edge distribution, an explicit
telemetry baseline — rather than from a tuned parameter, and it was reached by a
method that has twice deleted its own findings. A positive H3 on this graph would
have required believing that the adaptive machinery found signal in the 79.4% of
walkable edges the defender cannot tell apart.

**Registered prediction.** If the `k` sweep shows conclusions flat across `k` on
this graph, that is a fourth manifestation of the same collapse rather than an
independent result, and will be reported as such. Recorded before the sweep is
run.

## Results — H2 and H3

Both read off the Shape D section above, which is why they are written together:
one mechanism answers them in opposite directions.

### H2 — under static risk, the weighted planner is not beaten. It is optimal.

*Registered form: the smarter static planner gives the best tradeoff when risk
does not change with history.*

**Supported, and more strongly than registered — but the strength is the
uninteresting kind and should be reported as such.** Weighted A\* does not merely
give the best observed tradeoff; it returns the exact optimum. This is checked
mechanically rather than argued: the Tier 1 exact history-aware search, run with
its history term disabled (`k = 1.0`), returns the same cost as weighted A\* on
every graph tested, pinned by
`test_reduces_to_the_static_planner_when_history_is_disabled`.

That is a statement about the problem class, not about tuning. Minimum-cost path
over non-negative edge weights is solved by A\* with an admissible heuristic, and
the heuristic here — the cheapest walkable edge times the hop distance to the
nearest target — is admissible by construction. **H2 could not have failed
without one of the two being wrong**, so confirming it is a correctness check on
the implementation rather than evidence about Active Directory.

Reporting it that way matters, because H2 is the hypothesis most easily
overstated. "Our risk-weighted planner achieved the best risk/hops tradeoff" is
true and nearly vacuous. The non-vacuous part is what H1 measured and is recorded
as consequence 2 of the Shape D section: **on this graph there is no tradeoff at
all.** The hop counts are identical across all three entry points, so the
weighted planner never pays a hop for quiet and the frontier H2 presumes does not
exist here.

### H3 — answered negatively, with a mechanism and a boundary

*Registered form: the learning planner meaningfully beats the smarter static one
only when risk depends on the attacker's own past actions.*

**H3 is answered in the negative on this graph, and the negative is the
project's central result.** Three independent measurements, none of which
required tuning:

| Measurement | Result |
|---|---|
| Tier 1 exact history-aware search vs. static weighted | **no route changes** on any of the three entry points |
| Tier 2 Q-learning, 5 seeds × 3 entries | reaches the exact optimum, **+0.00% gap**, 15/15 |
| `k` sweep, 1.0 → 10.0 | **flat** — no route change at any value |

The registered antecedent is not merely unmet; **it is unmeetable on this
substrate**, and that is a stronger and more useful finding than a failed
comparison would have been. History-dependence has nothing to discriminate with
when 95.3% of walkable edges fall in one category: every alternative route
repeats the same category, so a repeat penalty rescales them together and
re-ranks nothing. `TYWIN` shows this cleanly — its cost rises 39.5 → 44.5 under
the history model while its route does not move, and it still does not move at
`k = 10.0`, where the cost has reached 264.5.

**The negative is bounded, not universal, and the bound was measured rather than
argued.** The H5/H6 perturbation registered one change inside the dominant class
and one outside it. The `GenericAll` ACE, joining the 95.3% majority, changed
nothing. The `MemberOf` membership, in the 4.0% minority at the floor weight,
re-ranked `TYWIN` from nine hops to seven. So history-dependence is not inert in
principle — it is inert *within a collapsed class*, and it recovers exactly where
the collapse does not reach.

**What H3 does not say.** It does not say adaptive planning is useless in
Active Directory; one collection cannot support that. It says the conditions
under which adaptivity can pay are a measurable property of the graph, and this
graph does not have them. The conditional form and its measurable antecedent are
in the Shape D section; the reason synthetic evaluation would not have surfaced
this is contribution (f).

Both results also carry the scope statement below: H3 is tested in a weakened
form, with history summarised as a set of category bits and no escalation with
count. A confirmed H3 under that summary would have said less than the registered
hypothesis implies.

**What a richer summary would have done is a bound, not a measurement, and is
labelled as one.** Summary B distinguishes *counts* within a category. On a graph
where 95.3% of walkable edges fall in one category, that gains resolution
**inside the class that collapsed and none outside it** — it would let the model
tell a third `WriteDacl` from a second, which is a distinction among edges that
already price identically, and would add nothing to the minority classes where
discrimination survives. It could not have created discrimination the substrate
does not contain.

That is reasoning about what a representation could express, not a result from
running one. **It is untestable here by a decision already on the record**:
Summary B was costed at 205 M states and ≈11.8 GB and rejected before any of
this was measured, so the bound stands on the earlier decision rather than on new
evidence. Stated this way so it cannot be read as a measured comparison between
two history summaries, which is not what was done.

## Differentiation from the Adelaide program

Stated explicitly, because the earlier framing collided with it.

**Reading is deliberately asymmetric.** Goel et al., *Optimizing Cyber Defense in
Dynamic Active Directories through Reinforcement Learning* (ESORICS 2024,
arXiv:2406.19596) is engaged with in full, because it is the closest work and
because it critiques shortest-path attacker models directly — which is the exact
claim our H1 result bears on. The rest of the program (GECCO '22, GECCO '23,
AAAI '23, IJCAI '25, ACM TELO '25) is cited and positioned from abstracts to
establish the program's shape: defender-side optimisation over modelled graphs.

| | Goel et al. (ESORICS 2024) | This work |
|---|---|---|
| Whose policy is optimised | **Defender** — edge blocking, hardening, via a Stackelberg game | **Attacker** — the object of study, never a scoring device |
| What the attacker is for | A device for scoring defender policies | The thing being compared |
| Detection model | Per-edge constant probabilities, drawn uniformly on [0, 0.2] | Sourced per-edge cost tied to named rules, history-dependent in the adaptive regime |
| Graph provenance | **Synthetic only** — DBCreator r1000/r2000/r4000 (2,996–12,001 nodes) | Real SharpHound collection, BloodHound schema, cited by hash, distribution reported |
| Graph scope | **Single domain**, one Domain Admin target, no trusts | Multi-domain: three domains, a forest trust, cross-forest edges recorded in provenance |
| Question | How should a defender harden? | Does adaptive planning beat a tuned static heuristic at staying quiet, and does that depend on history? |

Scale runs the other way and is stated up front: their r4000 is an order of
magnitude larger than our 783-node collection. The trade is realism of schema,
edge semantics and provenance against size.

### An empirical boundary condition on their critique of shortest-path attackers

Their critique is explicit — a shortest-path attacker is, in their words,
**"simplistic"**, with a policy that is easy for a defender to predict — and the
argument is sound as motivation for a richer attacker model. But it is made
*analytically* and evaluated on synthetic graphs, and they say plainly that
validation against real AD data remains future work.

**Our H1 result is that validation, and it is a boundary condition rather than a
refutation.** On this collection, across the three documented entry points,
shortest path is not trivially worse than a risk-aware planner: the hop counts
are identical on all three, the risk is identical on two, and the two differ only
on `SQL_SVC` — the single entry whose route is decided by a minority-class edge.
The reason is measurable and is the subject of the section above: at 79.4%
modal-weight concentration there is no hops-versus-risk frontier for a
sophisticated attacker to exploit.

**Scoped, deliberately, and offered as a contribution to their programme.** This
does not show their critique is wrong. They identified the question and named
real-data validation as the missing piece; we supply the first real-data
measurement bearing on it, and what it shows is that the critique is
**conditional on a graph property their generator supplies by construction**.
Their per-edge probabilities drawn uniformly on [0, 0.2] give every edge a
distinct cost with probability 1, which is precisely the condition under which a
shortest-path attacker *is* trivially worse — the general form of that argument
is contribution (f) above and is not repeated here.

**Both readings remain open.** Real directories may resemble the uniform draw, in
which case their critique holds broadly and this collection is unusual; or they
may resemble this collection, in which case the gap between naive and
sophisticated attackers is narrower in practice than synthetic evaluation
suggests. **One collection cannot settle which**, and nothing here should be read
as claiming it does. What can be said is that the question is now answerable — it
needs collections released with their concentration measured, which is why HHI is
reported here at all.

Nothing in this comparison is a claim to be better. The differences are of
**scope and object of study**: they optimise a defender over larger modelled
single-domain graphs; we compare attacker strategies over a smaller real
multi-domain collection with a sourced cost model. Each buys something the other
gives up.

The honest weakness is scale — a teaching-lab collection is small next to a
generated R1000. That is stated up front rather than left for a reader to find.
The trade is realism of schema and edge semantics against size, and the
detection-model axis is where the actual novelty sits.

---

## Scope statement on H3 — history dependence is tested in a weakened form

**This is a scope statement, not a footnote, and H3 itself is unchanged.**

H3 asks whether the learner's advantage depends on risk being history-dependent.
The learner's state is `(current node, history summary)`, and the chosen summary
is **the set of technique categories used so far** — one bit each, no escalation
with count.

**The category count depends on the traversal set, and both figures are
reported.** Over `DEFAULT_TRAVERSAL_SET` there are **nine** categories; over
`with_gpo_expansion()` — the view all three reported entry points use — there are
**ten**, because `GPLink` and `Contains` re-enter and bring the `structural`
category with them. The substantive claim is unchanged either way: one bit per
category, a single step on first repeat, no accumulation. See "State space" below
for the two |S| figures and why neither replaces the other.

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

### State space — two figures, each labelled with its traversal set

**Both are reported and neither replaces the other.** Overwriting the
pre-registered figure would erase the trail.

| Traversal set | Categories | \|S\| |
|---|---|---|
| `DEFAULT_TRAVERSAL_SET` (pre-registered) | 9 | 783 × 2⁹ = **400,896** |
| `with_gpo_expansion()` (all reported routes) | 10 | 783 × 2¹⁰ = **801,792** |

The pre-registered 400,896 stands as pre-registered. But every `SAMWELL`,
`SQL_SVC` and `TYWIN` result is computed on the expansion view, so **801,792 is
the figure that must accompany any of those results**. Quoting the pre-registered
number about a reported route would be false. Doubling leaves it tractable
(~46 MB), so this changes a number to report, not a feasibility argument.

**The methods point is how this was found.** The nine follows from build rule 3
excluding structural edges from the default traversal set. That coupling — a
build rule silently determining a pre-registered figure — was written down as a
live risk, and **it fired within one session of being documented**, on the first
run of the exact search over the augmented space. It is now computed by
`state_space_size()` rather than hard-coded anywhere, and pinned by
`test_the_gpo_expansion_view_doubles_the_state_space`.

That sequence is better evidence than a single clean figure would have been: the
coupling note was load-bearing rather than decorative, and a documented risk that
never materialises is indistinguishable from an imagined one.

**The consequence for reading H3.** A confirmed H3 under this summary says
history-dependence *of the first-use kind* is what the learner exploits. It does
**not** establish that count-based escalation would produce the same result, and
a reviewer asking that question is asking something the experiment does not
answer. The answer is: not tested, at 11.8 GB for the representation that would
test it, and the step form is what the baseline licences.

**The step's magnitude, `k`, is a declared parameter and the defence is the
sweep.** Stated here before any result exists, deliberately, so it cannot later
read as a response to an inconvenient number. The step is **proportional** —
repeating a technique costs `weight × k`, `k = 1.2` — rather than a uniform
additive increment, because a fixed step would manufacture loudness on
`MemberOf`, which is sourced at the floor with *both* baseline halves recorded as
empty, and would model a defender tracking repetition independently of severity,
which is the correlation capability this baseline excludes. Nothing in the
baseline fixes `k`: the sourcing pass priced first occurrences and is silent on
second sightings. **Conclusions will therefore be reported as the range of `k`
over which they hold, plus the value at which any conclusion flips** — the same
treatment the `DCSync` threshold received, using the same machinery.

**A known limitation of the nine-category grouping**, demonstrated rather than
hypothesised: `acl_abuse` contains both the Shape D writes (SACL + a script-block
rule) and `AddMember`/`AddSelf` (default channel, no endpoint rule) — different
events, different baseline halves, different severities, no shared rule. A repeat
across that boundary asserts a transfer the baseline does not support. Splitting
it would give ten categories and |S| = 801,792, which is tractable, but |S| here
is pre-registered; the split is logged as future work and the proportional step
bounds how far the error travels. Two of the nine categories are *uncheckable*
for coherence, because the permanent deferral of 14 weights leaves them with one
sourced member each.

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

---

## Future work — index detection cost to evasion difficulty, not rule existence

**Logged, not built.** Recorded here because the current model already contains
one instance of it and the reason is otherwise invisible.

Every weight in the table currently answers "does a named detection exist for
this, under the stated baseline?" That treats all named rules as equally
durable, and they are not. Two examples from the sourcing pass, at opposite ends:

- **A string-matching rule is cheap to evade.** SigmaHQ
  `posh_ps_powerview_malicious_commandlets.yml` fires on script-block logging for
  specific PowerView function names. Renaming the function defeats it. The
  technique is unchanged and the detection is gone.
- **A spawned child process cannot be hidden.** Where the detection rests on
  process creation itself rather than on a string inside it, there is nothing to
  rename — executing the technique produces the artifact.

Both are "a named rule exists", and the model prices them identically. It should
not: the second is a structural consequence of doing the thing, the first is a
naming coincidence that survives only until an attacker types `Rename-Item`.

**`tooling_is_native_ldap` is already a first instance of this**, and this is the
paragraph that explains why it exists. That conditional drops the four ACL-write
edges to 1.5 for an attacker using `.NET DirectoryServices`, SharpView, or
Impacket `dacledit` — not because the technique is quieter, but because the
detection was keyed to tooling the attacker simply did not use. It is an
evasion-difficulty adjustment wearing a tooling label. Generalising it means
scoring each weight's *evasion cost* alongside its detection channels, which is
a second axis on the weight table rather than a change to any number in it.

**The completed sourcing pass produced a measured instance of the axis, at both
ends, in one table.** This is the clearest illustration available and it should
be the worked example if this is ever written up:

- **The four Shape D ACL writes (`WriteDacl`, `WriteOwner`, `GenericAll`,
  `GenericWrite`, 4.0)** rest *entirely on the endpoint half*. Their native
  channel is silent on ordinary objects — 5136 needs a SACL the baseline grants
  only on tier-zero — so the whole weight comes from a Sigma rule matching
  PowerView function names in script-block logging. **Renaming the function
  defeats it**, and the technique is unchanged.
- **`DCSync` (6.5)** rests *entirely on the native half*. Its rule matches
  Event 4662 carrying the replication extended-right GUIDs, and those GUIDs are
  **protocol constants** — you cannot request replication without asking for
  them. There is nothing to rename.

Neither edge has both halves. They are mirror images: same structural shape,
opposite channel, and opposite evasion cost. Under a model that scores only
"does a named rule exist", the two are indistinguishable in kind. Under one that
scores evasion difficulty they are at opposite ends, and the current table
cannot express that difference.

A third data point from the same pass, arrived at independently:
**`SQLAdmin` (5.0)** prices above the ACL writes partly because command
execution through SQL requires `sqlservr.exe` to spawn a child, and process
lineage is not renameable either. The axis keeps appearing in the derivations
without a place to be recorded.

**State the bypass honestly alongside it, because the two are easily conflated.**
`DCSync`'s rule filters principals whose name ends in `$`, so DCSync performed
from a computer account is not matched by it. Protocol constants make the
*technique* unrenameable; they do not make the *rule* unbypassable. Evasion
difficulty is a property of the detection as written, not of the technique
alone — which is precisely why it needs measuring per rule rather than inferring
from the mechanism.

Deliberately out of scope for this work: the sourcing pass is already the
load-bearing contribution, and adding an axis to it before the first one is
complete would put both at risk.
