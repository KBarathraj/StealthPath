# Stage 1 Runbook — Lab, Collection, and the Milestone Gate

This is the part I can't do for you: deploying GOAD and running SharpHound needs
your hardware and your lab. Everything else in Stage 1 is done — the loader,
the graph model, the Dijkstra baseline, and the milestone-check tooling all
exist and are tested against a synthetic fixture.

So the order below is deliberately inverted from the project plan. **The software
is already unblocked. Do the lab work in parallel, not first.**

---

## 0. Before anything — a boundary that must hold

GOAD is intentionally vulnerable. It exists to be attacked and it will be
trivially compromised by anything that reaches it.

- Host-only or NAT-isolated networking. **No bridged adapter, no port forwards.**
- Never joined to, routed to, or credential-shared with any real domain.
- Snapshot every VM once the build completes and before you touch anything.
  You will break it, and rebuilding from scratch costs hours.
- Everything in this project stays inside that lab. The planners here operate on
  a graph abstraction — they compute routes, they do not execute anything — and
  it should stay that way. If Stage 4 ever tempts you toward "let's have the
  agent actually run the technique," that is a different project with a
  different ethics review.

Write down how you isolated it — provider, network mode, snapshot points. You
will want that record later, and reconstructing it from memory never works.

---

## 1. Deploy GOAD

Follow the upstream documentation (`github.com/Orange-Cyberdefense/GOAD`) rather
than any command list I could write here — it changes, and a stale command list
is worse than none. Notes from the usual failure modes:

- **Provider choice.** VirtualBox + Vagrant is the least painful on a single
  workstation. Proxmox if you have a server. VMware needs the paid Vagrant
  plugin.
- **Resources.** Full GOAD is 5 VMs and wants ~24 GB RAM. If you're short,
  `GOAD-Light` (3 VMs) still produces a usable multi-domain graph and is a
  perfectly fine choice — just record which variant you used, because the graph
  it produces is different.
- **The Ansible provisioning stage is where it breaks**, not the Vagrant stage.
  It's long, it's chatty, and it is re-runnable. Re-run the failed role rather
  than destroying the lab.
- **Time drift between VMs breaks Kerberos**, which breaks collection in ways
  that look like unrelated errors. If things behave strangely after a suspend,
  check clock sync first.

**Done when:** all DCs are up, domains resolve, and a domain-joined machine can
authenticate.

---

## 2. Collect with SharpHound

Run from a domain-joined host in the lab with a normal domain user context.

- Use **all collection methods** (`All` plus session/ACL/trust collection).
  Partial collection is the number-one cause of a graph missing the edge types
  Stage 2 depends on.
- If sessions look sparse, log a few users into a few machines first and
  re-collect. `HasSession` edges are the ones GOAD produces least reliably, and
  they matter — they're a whole category in the visibility model.
- Collect **once, properly**, then freeze it. Re-collecting mid-project silently
  changes the substrate under your results.

**Ingest into Neo4j via the BloodHound UI**, then confirm in the UI that you can
see a path to Domain Admins. If BloodHound itself can't find one, our code
certainly won't.

---

## 3. Document entry and target nodes

The plan calls for this and it is easy to skip. Don't.

Fill this in and commit it. This becomes the fixed start/end list every run
uses, so it has to be stable and written down rather than re-decided each time:

| Role | objectid | Name | Justification |
|---|---|---|---|
| Entry | | | Why an attacker plausibly starts here |
| Entry | | | |
| Target | | | Why this is tier-0 |
| Target | | | |

Prefer naming these explicitly over relying on BloodHound's `owned`/high-value
markings. Markings drift as people click around the UI; a documented list
doesn't. The CLI takes `--from` / `--to` for exactly this reason.

---

## 4. Run the milestone check

```bash
pip install -r requirements.txt

# 1. What's actually in the graph?
python -m stealthpath.cli inspect --uri bolt://localhost:7687 --password YOURPW

# 2. Freeze it. Do this before any analysis.
python -m stealthpath.cli freeze --uri bolt://localhost:7687 --password YOURPW \
    --out data/goad_graph.json

# 3. The gate itself.
python -m stealthpath.cli path --graph data/goad_graph.json --verify \
    --from "SAMWELL" --to "DOMAIN ADMINS@NORTH.SEVENKINGDOMS.LOCAL"
```

`inspect` will flag two things you must resolve before Stage 2:

- **Expected-but-absent edge types** → your collection is incomplete. Go back to
  step 2. This is a lab problem, not a code problem.
- **Uncategorised relationship types** → your BloodHound version emits edges
  `ad_schema.EDGE_CATEGORIES` doesn't know. Add them, with a category. Don't let
  them default silently; in Stage 3 they'd get a default cost and quietly skew
  every downstream number.

`path --verify` prints the equivalent Cypher. Paste it into the BloodHound /
Neo4j browser and compare.

### Passing the gate

**Compare hop count, not the exact path.** When several routes tie, BloodHound's
tie-breaking isn't ours, and a different path of the same length is fine.

- **Same length** → gate passed. Proceed to Stage 2.
- **Different length** → the traversal sets differ. Almost always
  `Contains`/`GPLink`: we exclude them by default because they're directory
  structure, not attacker actions, and including them produces shorter paths
  that don't correspond to anything an attacker does. Decide which convention
  you want, set `DEFAULT_TRAVERSAL_SET` accordingly, and **write the choice
  down** — every path length the tool produces depends on it.
- **We find a path, BloodHound doesn't** (or vice versa) → real bug. Stop and
  find it. Don't carry it into Stage 3.

---

## 5. What's already done

| Stage 1 task | Status |
|---|---|
| Deploy GOAD, verify domains | **Yours** — steps 1 above |
| SharpHound collection → Neo4j | **Yours** — step 2 |
| Sanity-check AD edge types present | Automated: `cli inspect` |
| Document entry / DA target nodes | Template above, step 3 |
| Neo4j → internal graph loader | Done: `loader_neo4j.py` |
| Shortest-path (Dijkstra) baseline | Done: `planners/shortest_path.py` |
| Milestone check vs. BloodHound | Done: `cli path --verify` |

Run `pytest` now, before the lab exists — 37 tests pass against the synthetic
fixture. That means when the real graph lands, any failure is about *your data*,
not the code, which makes debugging enormously faster.

One of those tests cross-checks our Dijkstra against networkx and will error out
with `ModuleNotFoundError` if you skipped `pip install -r requirements.txt`.
That's a missing dependency, not a code failure.

---

## 6. Where the schedule risk actually is

You said time is short. The honest read on this plan:

- **Stage 3 is the real deadline risk**, not Stage 1. It's 2–3 weeks, it's the
  hard gate, and everything built afterwards sits on top of it. Every day
  Stage 1 slips comes out of Stage 3.
- **Stage 1's lab work and its software work are now independent.** Whoever has
  the hardware should start the GOAD build today; the other person can start
  Stage 2's technique-to-risk-weight mapping immediately against
  `synthetic.goad_like()`.
- **That mapping needs no lab and no code.** It's the highest-value thing to
  parallelise, and `ad_schema.ATTACK_MAPPING_STUB` is the worksheet for it.
  Starting it now buys back most of a week.
- **The plan's own escape hatches are good.** After Stage 2 you have a working
  two-planner tool that answers the plain-vs-smarter comparison with no learning
  planner at all. Keep that stopping point genuinely available rather than
  treating it as failure — a working two-planner tool beats a half-finished
  three-planner one.
- **Stage 7 (dashboard) is optional and cuttable.** It gates nothing, nothing
  else depends on it, and it can be skipped entirely if time is short. Treat it
  as the first thing to drop, not as scope you owe anyone. Deciding that now
  means nobody quietly spends a weekend on it.
- **The build phase ends at Stage 5**, not Stage 7 — lab, baselines, risk model,
  learning planner, evaluation. Everything after that is a bonus.
