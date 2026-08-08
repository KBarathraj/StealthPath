# Stage 3 Gate — structural properties the risk model must satisfy

**Draft, first pass.** Written before the risk model exists, deliberately: these
are the spec, not a description. Most can be encoded as tests today and will
fail until there is something to test.

## Why this instead of hand-picked sequences

The plan says the risk model gets manually checked against hand-picked attack
sequences. That check is necessary but it is not sufficient, and we already know
its failure mode from this project.

The fixture's docstring claimed it contained a long quiet route to Domain
Admins. It didn't — the route it described reached the wrong node and was the
second-loudest path in the graph. That claim survived because it was *plausible*
and nobody re-derived it. Three separate test assertions were then written
against the same kind of plausible-but-unverified expectation and all three were
wrong.

Hand-checking a sequence asks "does this look right?" — which is exactly the
question that failed. A property asks "is this true for every input?", which
can't be satisfied by something that merely looks reasonable. Use both: the
properties catch the class of error, the hand-checks catch the ones nobody
thought to write a property for.

**These properties do not need the lab or sourced weights.** They constrain the
*shape* of the model, not its numbers, so they hold for any weight table
including the provisional one. That makes them the cheapest available progress
on Stage 3.

---

## The motivating case, measured in real data

Stage 2's static model prices each edge independently and decides
traversability per edge type. Here is one measured situation, from the frozen
GOADv2 collection, where **both** of those break — and they break for the same
underlying reason, which is why it is one example rather than two.

### The one question

`SpoofSIDHistory` requires **krbtgt of the source domain**: you forge a ticket,
so you need the key that signs it. Everything below turns on a single question:

> **Did the path into the source Domain node actually grant krbtgt?**

The tempting shortcut was to assume yes — you cannot traverse *out* of a Domain
node without first reaching it, and reaching a Domain node sounds like domain
compromise. **The data says no.** 23 enabled users reach a domain object with
zero replication edges on the path, across ten distinct route shapes and three
different final hops:

```
20 users   ... -> WriteDacl       onto the Domain object
 2 users   ... -> GPLink          the GPO chain
 1 user    ... -> GenericAll

e.g.  MemberOf -> WriteDacl                                            (2 hops)
      Owns     -> GPLink                                               (2 hops)
      MemberOf -> MemberOfLocalGroup -> LocalToComputer
                -> HasSession -> MemberOfLocalGroup -> WriteDacl       (6 hops)
```

Writing the DACL on a domain object is how you *grant yourself* replication
rights. Arriving there means you **could** replicate, not that you have. So the
answer to the question is genuinely "it depends on the route."

### Consequence 1 — cost

* **Low marginal cost** if the route already went through `DCSync`: krbtgt is in
  hand and the forging is nearly free.
* **Full cost** if it arrived via `WriteDacl`, `GenericAll`, or the GPO chain:
  krbtgt still has to be obtained and nothing on the path has paid for it.

Stage 2 prices the undiscounted figure (3.5), which overstates the DCSync-first
route. The discount belongs here, not there.

### Consequence 2 — reachability

Worse than mispricing: under the static model a route that arrives via
`WriteDacl` can then *walk* `SpoofSIDHistory` while holding no krbtgt at all —
claiming a capability it does not have. That is the same shape as
`GetChanges`-without-`GetChangesAll` and RBCD-without-an-SPN, catalogued as
Shape B in `docs/stage2_joint_capability_audit.md`.

The difference is that those two can be gated statically — the missing piece is
visible on an edge or a node property. This one cannot: whether krbtgt was
obtained is a fact about the **path**, not about the graph. `with_preconditions()`
has nowhere to look.

So Stage 2 knowingly overstates reachability here, and the frozen graph's
provenance says so. Do not paper over it with a static approximation; a
history-aware model is the only thing that can answer the question correctly.

### Use it as a validation case

A history-dependent model that does not make this edge **cheaper after a
`DCSync`**, and does not make it **unavailable without one**, is not reading
history in the way this example requires. Both halves, or it has only half
solved it.

## Notation

`V(e, h, c)` — risk of traversing edge `e` given attacker history `h` and
context `c`. `S(route)` — the route's combined score.

---

## Group 1 — monotonicity (the core of the adaptive claim)

**P1 — Repetition never reduces risk.**
`V(e, h + [a], c) >= V(e, h, c)` for any prior action `a`.
Doing more things can only make the next thing as loud or louder. If this fails,
the model can be gamed by padding a route with noise, which inverts the whole
point.

**P2 — Repeating *the same* technique is strictly louder.**
`V(e, h + [e], c) > V(e, h, c)`.
Stronger than P1 and the actual substance of "adaptive". Strictness matters: if
the increase can be zero, the adaptive model can silently degenerate into the
static one for some inputs and nobody would see it.

**P3 — Path extension never reduces the score.**
`S(route + step) >= S(route)`.
Follows automatically from `1 - Π(1-vᵢ)` when every `vᵢ >= 0`, so this is really
a check that the implementation matches the stated formula. Cheap, and it
catches sign errors and stray normalisation.

**P4 — Order-preserving sub-route monotonicity.** *(settled and encoded)*
If A's actions appear in B in the same relative order — B may have extra actions
anywhere around them — then `S(A) <= S(B)`.

Subsequence, **not** multiset. Under a history-dependent model the order of
shared actions changes their risk, so a same-multiset statement would be false
the moment history matters. This form survives it: every action in A sees a
history in B that is a superset of what it saw in A, so given P1 and P9, B
cannot come out cheaper. It also holds trivially under the static model, which
is what makes it safe to enforce before the adaptive model exists.

**P5 — Target-sensitivity monotonicity.** *(settled and encoded)*
The same technique against a more sensitive target never scores lower than
against a less sensitive one, all else equal.

Severity is a **partial order**, and the gaps in it are deliberate:

| | |
|---|---|
| Enterprise Admins | outranks everything — forest-wide |
| DA@X vs domain object@X | **tied.** Both domain-wide; neither dominates |
| anything@X vs anything@Y | **incomparable.** No ranking between domains |

Ties and incomparable pairs constrain nothing, which is the point — inventing an
order between DA@NORTH and DA@SEVENKINGDOMS would put a number on a question
nobody asked. `AttackGraph.compare_target_severity` returns `None` for
incomparable, and that is a real answer callers must handle rather than coerce.

Because no fixture happens to contain a strictly-ordered pair reached by the
same relationship type, the check builds its own probe graph and reports how
many comparisons it made. A property that silently compares nothing passes by
doing nothing.

---

## Group 2 — the two regimes must be the same model

**P6 — Exact static reduction.**
With the history term disabled, the adaptive model must reproduce the static
model's scores **exactly**, not approximately, on the same base weights.

This is the single most important property here. If the two regimes are
secretly different models — different base weights, different normalisation,
different action set — then any comparison between them measures the difference
between two implementations rather than the effect of history. That failure is
invisible in results and fatal to conclusions.

**P7 — History-independence implies path-independence.**
Under the static regime, `V` must not vary with `h` at all. Score a route, then
score it again with an arbitrary fake history prepended: identical.

---

## Group 3 — well-formedness

**P8 — Boundedness.** `0 <= S(route) <= 1`. Never NaN, never negative, never
above 1 through accumulated float error on long routes.

**P9 — Strict positivity.** Every action carries risk `> 0`. Nothing is
invisible. Matches the floor already documented in `risk.py`.

**P10 — Saturation, not overflow.** A route that repeats a loud action many
times must approach a bound, not exceed it or wrap.

**P11 — Empty route scores zero.** `S([]) == 0`. Trivial, and the kind of thing
that breaks silently when a formula is refactored.

---

## Group 4 — the model must not depend on things that aren't real

**P12 — Relabelling invariance.**
Permute the graph's node indices and every score must be unchanged.

Directly motivated by a bug already in this repo's history: plain shortest path
picks between equal-cost routes by edge index, so the headline comparison number
is sensitive to edge *insertion order*. That is defensible for a tie-break in a
planner. It would not be defensible in the risk model, where it would mean the
score depends on the order SharpHound happened to return rows.

**P13 — Locality.**
Adding a node or edge that is not on the route must not change the route's
score. Catches accidental dependence on global graph statistics.

**P14 — Determinism.**
Same route, same graph, same seed, same score — across runs and across
processes. Already a project-wide rule; state it here so the risk model is
covered by it explicitly.

---

## Group 5 — the adaptive term must be a gradient, not a cliff

**P15 — Bounded per-step increase.**
No single repetition may move the score by more than a declared fraction of the
total range.

If the history penalty is tuned so steeply that any repetition is catastrophic,
then the adaptive planner beats the static one trivially — it wins by avoiding a
cliff that was placed there by hand, not by learning anything about detection.
The result would be real-looking and meaningless. Pick the fraction before
tuning, not after.

**P16 — Monotone in the penalty parameter.**
Increasing the history-penalty parameter must not decrease any route's score.
A knob that moves scores in both directions is a knob nobody can reason about.

---

## How to test these

Property-based, over generated graphs — `random_ad(seed=...)` already provides
seeded topology variation, and `hypothesis` would give shrinking counterexamples
if it's worth the dependency. The point is to run each property over many
inputs rather than one hand-chosen one.

Two caveats before relying on generated graphs:

- **`random_ad` currently bolts a fixed dominant route onto every graph**
  (`ensure_path=True`), which makes 8 of 12 seeds behave near-identically. Fix
  that before using it as a property-testing substrate, or the properties will
  be exercised over one topology wearing twelve hats. See
  `test_random_generator_route_dominates_its_own_graphs`.
- **`goad_like()` covers 16 of 29 walkable edge types.** Properties that need a
  specific technique present must assert it, not assume it.

## Suggested order

P6 and P7 first — they are the ones whose failure invalidates everything
downstream, and they can be written the day the static and adaptive models both
exist. Then Group 3 (cheap, mechanical). Then P1–P3. P4, P5, and Group 5 need
decisions made first and should wait for them rather than be guessed at.
