# StealthPath

A web app that plans attack paths through an Active Directory graph and
**says how much of that graph it could actually price.**

Drop in a SharpHound / BloodHound CE collector export (or use the bundled
reference collection). StealthPath computes three routes to Domain Admin —
**shortest**, **detection-aware**, and **history-aware** — and shows which
techniques each one uses, what each hop costs, and how confidently each edge is
priced. The learned planner is checked against an exactly computed optimum, so
the app can prove a route is optimal rather than assert it.

Most tools in this space print three confident numbers with no statement of
coverage. This one refuses to. **Beside every route** it states how many hops
carry a cited price, whether optimality was proved, and what was dropped on
ingest — which makes the cost an upper bound. The directory-wide gaps
(unsourced weights, missing session or delegation data, how concentrated the
costs are) sit one click below, under *Graph data quality*.

## For a SOC analyst

A route is a red team's answer. The **Defend** tab answers the three questions
somebody holding an alert actually has:

| Question | Where |
|---|---|
| "We got an alert on this account — how bad is it?" | **Exposure**: every account ranked by hops and cost to a Domain Admins group, an Enterprise Admins group, or a domain object |
| "What would we actually have seen?" | **Detection**: per hop, the ATT&CK technique and the named SigmaHQ rule the price was derived from — plus `blind` hops, where *both* telemetry halves were checked and neither found anything |
| "What do we fix first?" | **Choke points**: single relationships ranked by how many accounts lose all tier-0 reach if that one edge is removed |

Both tables export to CSV, and the same report runs headless for a playbook:

```bash
python -m stealthpath.cli triage --graph data/goad_graph.json --json
```

Two distinctions the output keeps, because collapsing either would mislead:
**`blind` is not `unverified`** — the first means nothing in the baseline
catches that step, the second means we never sourced a detection for it — and
**cutting reachability is not the same as being revocable**, so a domain
controller's `DCSync` is labelled rather than offered as a work item.

On the bundled GOADv2 demo, starting from `TYWIN.LANNISTER@SEVENKINGDOMS.LOCAL`:
a **9-hop route at cost 44.5, proved optimal**, every hop carrying a cited
price, one hop that only logs where a SACL is configured, and an independently
trained learner arriving at the same cost.

This tool operates on graph abstractions. It computes routes; it does not
execute techniques. Intended for an isolated lab only.

## Run the app

```bash
python -m venv .venv && .venv/Scripts/activate     # Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt -r requirements-dashboard.txt
pytest -q                                          # 327 collected, 2 skipped; no network, no database
streamlit run dashboard/app.py
```

1. **Install** the venv and dependencies. Streamlit lives in
   `requirements-dashboard.txt`, pinned, and is deliberately optional: the test
   suite runs without it.
2. **Launch** `streamlit run dashboard/app.py`.
3. **Load a graph** in the sidebar, one of:
   - a **SharpHound / BloodHound CE collector export** — the `.zip`, or its
     per-class `.json` files. Upload every domain's zip together: cross-domain
     ACEs only resolve once all of them are in the same table. The parser is
     checked triple by triple against CE's own ingest
     (`python tools/validate_parser.py`); an upload is session-scoped and never
     written to `data/`.
   - a **StealthPath freeze** (JSON with `"format": "stealthpath.attackgraph/1"`),
     e.g. from a live BloodHound database:

     ```bash
     python -m stealthpath.cli freeze --uri bolt://localhost:7687 --password X --out my_graph.json
     ```

   - the **bundled demo** (the reference collection).
4. **Pick a start account and press *Find the route*.** Accounts that can
   actually reach a target are listed first.

## What you are looking at

The **Attack route** tab, top to bottom:

| Panel | What it does |
|---|---|
| Verdict and tiles | *Proved optimal* or *Learned — not proved*; cost, hops, blind hops, ATT&CK techniques |
| The route | A stepper: each principal, and between them the technique, its price, and a dot for whether anything would log it |
| Would you see it? | Hops that are covered, need a SACL, are blind, or are unverified |
| Can you trust it? | Hops with a cited price, whether optimality was proved, the independent learner's gap, what was dropped on ingest |
| Detection evidence | Per hop: ATT&CK ID, the named SigmaHQ rule the price came from, telemetry dependency |
| Compare the three planners | Shortest path (fewest hops) · risk-weighted A\* · exact history-aware search |
| Graph data quality | Pricing coverage, same-cost share, AD CS / session / delegation counts — whether detection-aware routing can help **on this graph** |
| Recorded result | For the demo starts only: the stored Q-learning run from `results/h5_h6.json` |

**Where a route comes from.** The exact history-aware search runs first, under
a deadline, and is the only planner that can say *proved*. A learner
(Q-learning over hashed state-action features) runs beside it as a check and is
reported as a gap against it. On a directory too large for the exact search to
finish, the learned route is shown as an **unverified candidate**, in amber. If
neither finishes, the app refuses rather than showing a partial policy.

The **Defend** tab is described above.

The engine behind those numbers — sourced weights, frozen graphs, property
tests — is why a demo on the reference collection is trustworthy. It is not
the product headline. See `docs/scope_minimum.md` for what “ships if nothing
else lands.”

## CLI (same engine, no browser)

```bash
python -m stealthpath.cli inspect --synthetic
python -m stealthpath.cli path --synthetic --verify --to "DOMAIN ADMINS@NORTH"
python -m stealthpath.cli compare --synthetic --to "DOMAIN ADMINS@NORTH"
python -m stealthpath.cli compare --graph data/goad_graph.json
```

`--synthetic` is a development fixture so the software runs without a lab. It
is not Active Directory. Numbers about AD come from the frozen collection in
`data/`, cited by hash.

## Layout

```
dashboard/                  Streamlit app (upload, route, defend, planners)
  bloodhound_parser.py      SharpHound / BloodHound CE export -> (nodes, edges)
  ingest.py                 Upload: collector export or StealthPath freeze
  rl_upload.py              Planner ladder: exact -> learned -> refusal
data/raw_collection/        The collector export the reference graph was ingested
                            from; ground truth for tools/validate_parser.py
docs/
  handoff.md                Current priorities and what was decided
  scope_minimum.md          What ships if nothing else lands
stealthpath/                Graph, risk model, planners, targets, defend, CLI
  planners/                 shortest_path, weighted_astar, exact_history,
                            q_learning (tabular), linear_q (hashed features)
  defend.py                 Exposure, detection posture, choke points
  targets.py                Where a route starts and what counts as arriving
data/goad_graph.json        Reference collection (published GOADv2 SharpHound)
tests/                      No network, no database, no lab
```

### Navigating the code

`graphify-out/` is a graph index of this repo, for finding where things live
without reading every module:

```bash
graphify explain "static_cost_fn()"           # what a symbol touches, with file:line
graphify affected "RiskWeight" --depth 2      # what a change would reach
graphify update .                             # rebuild after edits
```

It's a map, not the territory. Use it to locate code, then read the file.
Nothing the app displays cites it.

## Why the numbers can be trusted

Each of these is load-bearing. Reversing one is a real decision, not a cleanup.

- **The graph is integer-indexed and Neo4j-free at runtime.** Planners do not
  need a database. Uploads stay in the session; frozen files on disk are never
  overwritten.
- **It's a multigraph.** Two objects can be joined by several relationships with
  very different risk profiles. Collapsing them by endpoint pair would throw
  away the signal the cost model is using.
- **`Contains` and `GPLink` are not traversed by default.** They're directory
  structure, not attacker actions. `with_gpo_expansion()` re-admits them only
  for the GPO → OU → object chain.
- **Unknown relationship types raise rather than defaulting.** An uncategorised
  edge would pick up a made-up cost and quietly skew every route.
- **Freeze the graph to JSON and commit it.** Re-collecting mid-project changes
  the ground truth underneath numbers you already showed.
- **One `Path` type for all planners**, including the learner.
- **Determinism throughout.** Seeded RNG, deterministic tie-breaking.
- **ASCII only in console output.** The default Windows console codepage
  mangles anything else.

## Research record (below the fold)

The planners and the weight table were measured on a frozen GOADv2 SharpHound
collection (`data/goad_graph.json`, sha256 `3c1bef97…`), which ships here
because every reported number cites it.

**The write-up itself is not in this repo.** The dated findings log, the
pre-registered hypotheses, the telemetry-baseline audit and the risk-model
property list are kept outside version control — this repository is the
running tool. What remains of that record in-tree is `docs/handoff.md`, which
carries the decisions a later change has to respect.

Two research artifacts are also kept out for weight: the perturbed graph used
by the H5/H6 experiment, and the rendered paper figures. Tests that need one of
them **skip** rather than fail, so a clone is green and the skip count says how
many checks did not run.
