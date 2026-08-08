# StealthPath

A tool for comparing route-planning strategies on an Active Directory attack
graph.

Three planners, same graph, same start and end points:

1. **Plain shortest path** — fewest hops, ignores how noisy each step is. This
   is what BloodHound's own pathfinding does.
2. **Smarter static planner (A\*)** — weights each relationship by how likely it
   is to get noticed, then finds the cheapest route under those weights.
3. **Learning planner (PPO)** — learns to avoid loud actions and adapts as it
   goes, so it can react to the fact that repeating a technique gets louder.

The question the tool answers: does the learning planner actually beat a
well-tuned static one at staying quiet, and does that depend on risk changing
based on what the attacker has already done?

**Stages 0 and 1 are complete**, except for the lab deployment and SharpHound
collection, which need your hardware — see `docs/stage1_lab_runbook.md`. That's
the next thing to do.

## Quick start (no lab required)

```bash
python -m venv .venv && .venv/Scripts/activate     # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
pytest -q                                    # 110 pass + 3 skipped, no network, no database
```

```bash
python -m stealthpath.cli inspect --synthetic
```

```bash
python -m stealthpath.cli path --synthetic --verify --to "DOMAIN ADMINS@NORTH"
```

Run both planners on the same endpoints and see what the risk weights buy:

```bash
python -m stealthpath.cli compare --synthetic --to "DOMAIN ADMINS@NORTH"
```

The synthetic fixture is a development substrate so software work isn't blocked
on the lab. It is not data — any number you actually report comes from the real
collection.

## Layout

```
docs/
  stage1_lab_runbook.md     GOAD + SharpHound checklist and the milestone gate
  stage2_joint_capability_audit.md   Edges that overstate what an attacker holds
  stage3_risk_model_properties.md    Properties the risk model must satisfy
  handoff.md                Start here if picking the project up
  findings.md               Running log of real results, each tied to a graph hash
  generator_vs_real_distribution.md  Why random_ad cannot back distributional claims
  stage0_related_work.md    PARKED — research phase, after Stage 5
  stage0_hypotheses.md      PARKED — research phase, after Stage 5
stealthpath/
  graph.py                  AttackGraph / Node / Edge — the shared substrate
  ad_schema.py              BloodHound edge taxonomy + ATT&CK candidate worksheet
  risk.py                   Static per-edge risk weights + the static cost function
  risk_properties.py        Stage 3 gate — structural properties, as runnable checks
  loader_neo4j.py           BloodHound Neo4j → AttackGraph (legacy + CE)
  synthetic.py              GOAD-shaped fixture, seeded generator, GPO/RBCD fixtures
  planners/base.py          Path type and Planner protocol — all three planners share it
  planners/shortest_path.py Dijkstra baseline (planner #1 of 3)
  planners/weighted_astar.py Weighted A* (planner #2 of 3)
  cli.py                    inspect / path / compare / freeze
tests/test_stage1.py        Stage 1 exit criteria
tests/test_stage2.py        Stage 2 exit criteria
tests/test_stage3_properties.py  Risk-model properties, incl. that each one bites
```

## Why the code is built this way

Each of these is load-bearing. Reversing one is a real decision, not a cleanup.

- **The graph is integer-indexed and Neo4j-free at runtime.** The learning
  planner needs a fixed action space with stable indices, and nothing downstream
  should need a database running to work.
- **It's a multigraph.** Two objects can be joined by several relationships with
  very different risk profiles. Collapsing them by endpoint pair would throw
  away exactly the signal the tool is measuring.
- **`Contains` and `GPLink` are not traversed by default.** They're directory
  structure, not attacker actions. Including them yields shorter paths that
  don't correspond to anything an attacker does. Documented in `ad_schema.py`.
- **Unknown relationship types raise rather than defaulting.** An edge nobody
  categorised would silently pick up a made-up cost and skew every number built
  on top of it.
- **Freeze the graph to JSON and commit it.** Re-collecting mid-project changes
  the ground truth underneath results you already generated.
- **One `Path` type for all three planners.** Fixed early, while it was cheap,
  so the evaluation code doesn't turn into three special cases.
- **Determinism throughout.** Seeded RNG, deterministic tie-breaking. Two runs
  on the same input must give the same answer or comparisons mean nothing.

## Next

1. Stand up GOAD and collect with SharpHound — `docs/stage1_lab_runbook.md`.
2. Source the risk weights. All 32 entries in `risk.PROVISIONAL_WEIGHTS` carry a
   rationale but no citation, and `risk.require_sourced()` refuses to let an
   unsourced weight back a reported number. Each one needs an ATT&CK technique
   ID, a specific Sigma rule, or a named detection writeup.

Neither step blocks the other, and step 2 needs no lab and no code.

## Scope

This tool operates on graph abstractions. It computes routes; it does not
execute techniques. Intended for an isolated lab only.
