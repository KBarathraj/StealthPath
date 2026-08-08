# `random_ad()` vs the real collection — edge-type distribution

**Measured 2026-08-04.** Real graph: `data/goad_graph.json`, sha256 `3c1bef97…`,
783 nodes / 5825 edges. Generator: `synthetic.random_ad(seed=0..11)` aggregated,
2570 edges. Percentages are of each population's own edge total.

Produced to answer a specific question — is the generator's edge-type
distribution comparable to real collected AD? — because a project claim rests on
it. **The answer is no, and not marginally.**

## The table

| Edge type | real | real % | synth | synth % | |
|---|---:|---:|---:|---:|---|
| `MemberOf` | 199 | 3.4% | 1475 | **57.4%** | synth 16.8× over |
| `WriteDacl` | 1317 | **22.6%** | 47 | 1.8% | synth 12.4× under |
| `WriteOwner` | 1316 | **22.6%** | 37 | 1.4% | synth 15.7× under |
| `GenericAll` | 1008 | **17.3%** | 43 | 1.7% | synth 10.3× under |
| `HasSession` | 5 | 0.1% | 370 | **14.4%** | synth 167.7× over |
| `Contains` | 729 | 12.5% | 12 | 0.5% | synth 26.8× under |
| `Owns` | 722 | 12.4% | 36 | 1.4% | synth 8.8× under |
| `GenericWrite` | 323 | 5.5% | 41 | 1.6% | synth 3.5× under |
| `CanPSRemote` | 0 | — | 92 | 3.6% | **absent from real** |
| `AdminTo` | 19 | 0.3% | 81 | 3.2% | synth 9.7× over |
| `CanRDP` | 0 | — | 71 | 2.8% | **absent from real** |
| `AddMember` | 1 | 0.0% | 58 | 2.3% | synth 131.5× over |
| `ReadLAPSPassword` | 0 | — | 50 | 1.9% | **absent from real** |
| `ForceChangePassword` | 1 | 0.0% | 48 | 1.9% | synth 108.8× over |
| `AddKeyCredentialLink` | 66 | 1.1% | 37 | 1.4% | comparable |
| `DCSync` | 6 | 0.1% | 24 | 0.9% | synth 9.1× over |
| `GetChanges` | 9 | 0.2% | 24 | 0.9% | synth 6.0× over |
| `AllowedToDelegate` | 0 | — | 24 | 0.9% | **absent from real** |
| `MemberOfLocalGroup` | 50 | 0.9% | 0 | — | **absent from generator** |
| `LocalToComputer` | 22 | 0.4% | 0 | — | **absent from generator** |
| `GPLink` | 8 | 0.1% | 0 | — | **absent from generator** |
| `GetChangesInFilteredSet` | 6 | 0.1% | 0 | — | **absent from generator** |
| `GetChangesAll` | 6 | 0.1% | 0 | — | **absent from generator** |
| `SpoofSIDHistory` | 2 | 0.0% | 0 | — | **absent from generator** |
| `SQLAdmin` | 2 | 0.0% | 0 | — | **absent from generator** |
| `SameForestTrust` | 2 | 0.0% | 0 | — | **absent from generator** |
| `SyncLAPSPassword` | 2 | 0.0% | 0 | — | **absent from generator** |
| `CrossForestTrust` | 2 | 0.0% | 0 | — | **absent from generator** |
| `AddSelf` | 1 | 0.0% | 0 | — | **absent from generator** |
| `ReadGMSAPassword` | 1 | 0.0% | 0 | — | **absent from generator** |

Only **one** edge type (`AddKeyCredentialLink`) has comparable share in both.

## What it says

**The distributions are inverted, not merely different.** Real collected AD is
**ACL-dominated**: `WriteDacl`, `WriteOwner`, `GenericAll`, `Owns` and
`GenericWrite` are **80.4%** of all edges. The generator is
**membership-dominated**: `MemberOf` alone is 57.4%, while those same five ACL
types are ~7.9%.

**Coverage is asymmetric in both directions.** Four types the generator produces
do not occur in the real collection at all; **twelve** types the real collection
contains are produced by nothing in the generator — including every trust type,
the whole local-group chain, `GPLink`, `SQLAdmin`, and two of the three
replication halves.

**Two outliers deserve naming.** `HasSession` is 167× over-represented, which
inverts the real collection's most serious gap: sessions are nearly absent in
real data and abundant in generated data. `AddMember` and `ForceChangePassword`
are ~100× over, and both appear exactly once in the real graph.

## Consequence for what may be reported

A distributional claim computed over `random_ad` is a claim about **the
generator**, not about Active Directory. The shape it would be measuring is one
we wrote.

That does not make the generator useless — it makes its legitimate uses narrow
and specific:

- **Property-based testing.** `docs/stage3_risk_model_properties.md` uses it to
  check structural invariants that must hold on *any* graph. Valid precisely
  because those checks are distribution-independent — that is the whole point of
  a property.
- **Robustness and determinism checks.** Does the code handle varied topology
  without crashing, and give the same answer twice.
- **Unreachability and edge-case coverage** that a single fixture cannot supply.

What it cannot support is any statement of the form "across N graphs, the
weighted planner saves X" presented as a finding about AD.

See build rule 7 in `CLAUDE.md`, which this measurement caused to be rewritten.
