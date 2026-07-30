> **PARKED — research phase.** Do not read this for build work and do not act
> on it. The project is in the build phase until Stage 5 is functionally done;
> see `CLAUDE.md`. Nothing here is cancelled — it's saved for later.

# Stage 0 Deliverable — Related-Work Positioning Note

**Status:** draft for joint review. This is the backbone the paper's related-work
section gets expanded from, not the section itself.

All citations below were verified against the publisher or DBLP record. Two
entries flagged **[UNVERIFIED]** need one of you to check personally before they
go in the paper.

---

## 1. The one-sentence claim

> Existing work either (a) uses RL on AD graphs to *harden* them from the
> defender's side, or (b) uses RL for attack-path discovery on abstract network
> topologies with static or absent detection modelling. We ask a narrower
> question neither answers: **on a real AD identity graph, does an adaptive
> planner beat a well-tuned static heuristic at evading detection — and if so,
> only when detection risk depends on attacker history?**

The load-bearing word is *comparative*. We are not claiming a better attacker.
We are testing whether the added machinery of RL buys anything over A* with good
weights. That framing matters because it makes a negative result publishable:
"adaptive planning is unnecessary under static risk" is a finding, not a failure.

---

## 2. Cluster A — RL on Active Directory attack graphs (defender-side)

The Adelaide group (Goel, Guo, Neumann, Nguyen, Ward, et al.) owns this space.

| Work | Venue | What it does |
|---|---|---|
| Goel, Ward-Graham, Neumann, Neumann, Nguyen, Guo — *Defending Active Directory by Combining Neural Network based Dynamic Program and Evolutionary Diversity Optimisation* | GECCO 2022, pp. 1191–1199 | Stackelberg game on an AD attack graph; every edge carries a detection rate and failure rate; defender blocks *k* edges. Proves both sides' problems #P-hard. |
| Goel, Neumann, Neumann, Nguyen, Guo — *Evolving Reinforcement Learning Environment to Minimize Learner's Achievable Reward* | GECCO 2023, pp. 1348–1356 | Defender picks an environment configuration; attacker trains RL against it; EDO evolves configurations that minimise attacker reward. |
| Guo et al. — *A Scalable Double Oracle Algorithm for Hardening Large Active Directory Systems* | AsiaCCS 2023 | Double-oracle for the same Stackelberg formulation at scale. |
| Goel, Moore, Guo, Wang, Kim, Camtepe — *Optimizing Cyber Defense in Dynamic Active Directories Through Reinforcement Learning* | ESORICS 2024, pp. 332–352 | Extends edge-blocking to AD systems treated as **dynamic** rather than static. |
| Goel, Ward, Neumann, Neumann, Nguyen, Guo — *Hardening Active Directory Graphs via Evolutionary Diversity Optimization-based Policies* | ACM TELO 5(3), 2025 | Journal consolidation of the above. |

**Our delta, stated defensively (expect a reviewer to push on exactly this):**

1. **Objective is inverted.** Their attacker exists to score defender policies.
   Ours is the object of study; we never optimise a defence.
2. **Their detection model is a per-edge constant.** A fixed `p_d(e)` per edge is
   precisely the *static* condition of our H2/H3. Our contribution is the
   history-dependent regime — repeating a technique gets louder — which their
   formulation cannot express, and which is where we predict adaptive planning
   earns its keep. **This is the single strongest sentence available to us.
   Lead the related-work section with it.**
3. **Graph provenance.** They evaluate on synthetic AD graphs (R500/R1000 style
   generators). We collect from a live lab via SharpHound, in BloodHound's own
   schema. Weaker on scale, stronger on realism — say so plainly rather than
   letting a reviewer say it for us.

> ⚠️ **Do not oversell (3).** GOAD is a *small teaching lab*. "Real collection"
> means real schema and real edge semantics, not enterprise scale. Any claim
> beyond that will get us rejected, and deservedly.

---

## 3. Cluster B — RL frameworks for attack-path discovery / pentesting

| Work | Venue | Environment |
|---|---|---|
| Microsoft Defender Research Team — **CyberBattleSim** | Open source, 2021 | Abstract network graph, parameterised vulnerabilities. |
| Schwartz & Kurniawati — **NASim** | arXiv 1905.05965, 2019 | Host/service/exploit abstraction. |
| Janisch, Pevný, Lisý — **NASimEmu** | SECAI @ ESORICS 2023, LNCS 14399, pp. 589–608 | Simulator **and** emulator with a shared interface, so simulation-trained agents deploy into emulation; explicitly targets generalisation to unseen scenarios. |
| Terranova, Lahmadi, Chrisment — *Leveraging Deep RL for Cyber-Attack Paths Prediction* | RAID 2024 | Formulation, generalisation, evaluation on CyberBattleSim-derived scenarios. |
| Terranova, Lahmadi, Chrisment — *Scalable and Generalizable RL Agents for Attack Path Discovery via Continuous Invariant Spaces* | **RAID 2025, pp. 440–457**, DOI 10.1109/RAID67961.2025.00029 | Continuous, invariant input/output spaces so policies transfer across topologies and vulnerability sets, instead of retraining per environment. Artefact: C-CyberBattleSim. |
| Li et al. — **EPPTA** | *Engineering Reports* 7(1):e12818, 2025 | POMDP framing; implicit belief module; asynchronous RL (Sample Factory) for ~20× convergence speedup. |

**Our delta:**

1. **Substrate.** All of the above operate on *host/vulnerability* graphs —
   chain CVEs across subnets. AD attack paths are an *identity/ACL* graph:
   `MemberOf`, `GenericAll`, `ReadLAPSPassword`, `DCSync`. Different edge
   semantics, different detection surface. Nothing in Cluster B ingests a
   BloodHound graph.
2. **Detection as the objective, not a constraint.** These frameworks optimise
   for reaching the goal (sometimes with a cost term). Detection probability is
   our primary optimisation target and our primary reported metric.
3. **Generalisation is explicitly *not* our claim.** Terranova et al. 2025 is
   about transfer across environments. We train and evaluate on one lab graph
   and say so. Trying to compete on their axis would be a losing fight and is
   not our question. **Cite them as the transfer benchmark we are not attempting
   — that pre-empts "why didn't you generalise?"**

---

## 4. Cluster C — AD attack-path tooling (the practitioner baseline)

- **BloodHound / SharpHound** (SpecterOps) — the graph model we adopt wholesale.
  Its own pathfinding is unweighted shortest path, which is *literally our
  Dijkstra baseline*. Worth stating outright: the tool the entire industry uses
  is the weakest of our three planners under a detection objective. That is a
  clean, honest motivating sentence for the introduction.
- **PingCastle**, **Purple Knight** — rule-based AD posture scoring. No path
  planning, no detection modelling. Mention once as evidence that the
  practitioner state of the art is static scoring, then move on.

**[UNVERIFIED]** If you want to cite BloodHound formally, find a citable
reference (SpecterOps whitepaper or the original DerbyCon presentation) — I did
not confirm one. A bare GitHub URL is acceptable at most venues but weak.

---

## 5. The gap, in the form the paper will state it

> Detection risk in AD is treated as a per-edge constant across the literature.
> In practice, defender visibility is *history-dependent*: the third
> Kerberoasting request from the same principal is not as quiet as the first.
> No published work isolates whether that history-dependence is what makes
> adaptive planning necessary, or whether a static weighted heuristic captures
> the achievable gain. We answer that question directly, with an explicit
> null-result-tolerant design and a sensitivity analysis over the detection
> model's own parameters.

The last clause is deliberate. Our detection model is hand-calibrated, so its
parameters are the obvious attack surface in review. H4 exists to defuse that
before a reviewer raises it. **Do not bury H4 — put the sensitivity analysis in
the main body, not an appendix.**

---

## 6. Known weaknesses, and where we pre-empt them

| Reviewer objection | Where we handle it |
|---|---|
| "Your detection model is invented." | Stage 3 per-parameter sourcing; H4 sensitivity sweep. **The single biggest risk to acceptance.** |
| "One small lab graph." | Limitations section, stated up front; `synthetic.random_ad()` gives supplementary topology variation, clearly labelled as synthetic. |
| "Goel et al. already did AD + RL." | §2 delta 2 — static vs. history-dependent risk. |
| "RL didn't beat A*." | That is H3's hypothesis, pre-registered before we ran anything. Design already accommodates it. |
| "No real defender in the loop." | Threat model: we model *visibility*, not response. Say it in the threat model, not the discussion. |

---

## 7. Reading assignments (Stage 0 closure)

**Cyber Track:** Goel GECCO 2022 + ESORICS 2024 (skim TELO 2025 — it consolidates
both); BloodHound edge documentation end to end; PingCastle methodology page.

**Non-Cyber Track:** NASimEmu paper + repo; Terranova RAID 2025 (§ on invariant
spaces); CyberBattleSim README and env definitions; skim EPPTA for POMDP framing
only — we are **not** doing partial observability in v1, and adding it would
blow the timeline.

**Closure criterion:** both tracks can state, in one sentence each, why Goel et
al. and why Terranova et al. do not already answer H3. If either of you can't,
Stage 0 isn't done.
