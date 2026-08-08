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
