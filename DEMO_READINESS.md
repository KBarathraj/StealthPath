# StealthPath — Demo Readiness

**Verdict: Ready with limitations.** The app launches, the bundled demo graph
works end to end, and error paths fail gracefully. The limits below are about
*what to claim*, not about stability. Audited 2026-10-27 on Windows 11,
Python 3.12.10, Streamlit 1.63.0 (pinned — do not upgrade before the demo).

## What it is (say this, not more)
A local web app that, for one starting account in an Active Directory graph,
finds the cheapest route to Domain Admin under a **relative detection-cost model**,
shows the evidence behind each step, and ranks exposed accounts for a defender.
It analyzes *modeled graph relationships*. It does **not** prove a route is
exploitable, and the cost is a **relative loudness score, not a probability**.

## Launch (run before the presentation)
```bash
cd C:\Users\barat\Projects\StealthPath
.venv\Scripts\activate
streamlit run dashboard/app.py          # opens http://localhost:8501
```
The bundled demo (GOADv2, 783 objects / 5,825 relationships) loads by default.
No network, database or lab is needed.

## Demo sequence (about 4 minutes; each value below was observed)
1. **Default start `TYWIN.LANNISTER@SEVENKINGDOMS`** → press *Find the route to
   Domain Admin*. Expect: **Proved optimal, cost 44.5, 9 hops, 0 blind hops**,
   "hops with a cited price 9/9", "independent learner agrees (+0.00%)".
2. Open **Compare the three planners** → for this start shortest and priced
   routes are the same sequence. The app says so ("a property of this graph").
3. **Start `SQL_SVC@NORTH.SEVENKINGDOMS.LOCAL`** (not `SQL_SVC@ESSOS`) → **cost
   15.1, 4 hops, proved optimal, 1 of 4 hops blind**. In *Compare the three
   planners* the shortest-path row has the same 4 hops but its cost column shows
   **4** (that is its own objective, the hop count) and its technique list ends in
   `DCSync`; the priced routes cost 15.1. **The UI never prints 20.0.** Priced with
   the same weights the shortest route costs **20.0**: show it with
   `python -m stealthpath.cli compare --graph data/goad_graph.json --from "SQL_SVC@NORTH"`
   ("total risk 20.0" vs 15.1) or say it aloud. This is the one start where
   detection-aware routing changes the answer.
4. **Defend tab** → **28 accounts assessed, 11 can reach tier-0, 1 one hop away,
   10 choke points**. Top choke point cuts 7 of 24 accounts (29%).
5. Open **Graph data quality** → "Pricing coverage: POOR — 4,922 of 4,991 walkable
   edges (98.6%) carry a cited weight; weight table 22/35"; 19 relationship types
   (2,443 edges) dropped. Show this deliberately: it is the honesty feature.

## Verified results
| # | Check | Result | Evidence |
|---|---|---|---|
| 1 | App starts | PASS | Server up on :8501, page rendered, 0 console errors |
| 2 | Sample graph loads | PASS | 783 objects / 5,825 rels shown |
| 3 | Select start / target | PASS | Start dropdown and *Reach* dropdown present; start changed and routed in UI |
| 4 | Route is valid and understandable | PASS | TYWIN 44.5/9 hops and SQL_SVC 15.1/4 hops in UI match `cli compare` and compute layer |
| 5 | Planners compared on same inputs | PASS | UI table + `cli compare`: SQL_SVC 20.0 vs 15.1 |
| 6 | Costs/explanations match code | PASS | Panels agree with `graph_profile`, `pricing_verdict`, tests |
| 7 | Defend view | PASS | 28 / 11 / 1 / 10 in UI; 11 of 28 in `cli triage` |
| 8 | Invalid input handling | PASS | Garbage zip, empty file, wrong JSON, no file → clean `UnsupportedGraphError` messages; custom-type form rejects empty name and existing types |
| 9 | No path / unparseable input does not crash | PASS | `SQL_SVC@ESSOS` → "No route from this account"; 0 exceptions (UI, then headless harness) |
| 10 | README launch works | PARTIAL | Launch command verified in the existing venv; creating a fresh venv and `pip install` NOT TESTED |
| — | Automated tests | PASS | `pytest`: **325 passed, 2 skipped** (327 collected); skips are the intentional Stage-3 deferrals |
| — | Parser validator | PASS | `tools/validate_parser.py` → PASS (0 route-bearing failures) |

## Fixed during this audit
- **Misleading tagline.** The header said steps are priced by "how *likely* each
  step is to be noticed", which reads as a probability. Now: "how loud each step
  is (a relative score, not a probability)". Text only; no results changed.
- **Stale test count** (319 → 327) in README and handoff.

## Known limitations — do not claim otherwise
- **One small lab graph.** GOADv2 is a teaching lab, not a sample of enterprise AD.
- **Cost = relative score.** Weights come from ATT&CK / SigmaHQ detection rules
  under a stated telemetry baseline. **22 of 35 are sourced; 13 are not.** Nothing
  here is a measured detection rate.
- **Costs are upper bounds.** 19 relationship types (2,443 edges, mostly AD CS)
  are dropped; sessions are near-absent (5) and delegation edges are zero.
- **"Proved optimal" means optimal under this model on this graph**, via
  exhaustive search. On graphs too large for the search it is shown as an
  unverified learned candidate (amber).
- **Defend ≠ remediation plan.** A choke point shows where reachability depends on
  one relationship. The UI's own footnote says cutting reachability and being safe
  to revoke are different questions. The list header reads "revoke this
  relationship": present it as *investigate first*.
- **Detection-aware routing rarely differs here.** ~94% of walkable edges share one
  weight, so on most starts the routes match. Say that; do not oversell SQL_SVC.
- Don't claim RL beats classical search; the exact search is the reference.

## Not tested
- **Uploading a file through the browser.** The headless harness cannot upload;
  upload parsing is covered by unit tests and the parser validator, and bad-input
  handling was exercised at module level.
- Fresh-venv install, Linux/macOS, and any Streamlit version other than 1.63.0
  (the code uses a parameter Streamlit has deprecated; the pin keeps it working).
- The *Add a relationship we drop* feature was only exercised end to end at module
  level and via form validation, not with a real zip through the UI. Avoid it in the demo.
- `SAMWELL.TARLY@NORTH` (2 hops, cost 4.1) was verified in the compute layer, not clicked.
- `cli path` with a missing file prints a Python traceback (CLI only; the web UI is unaffected).
- On a fresh clone only one demo graph appears (the perturbed copy is gitignored).

## If something fails during the demo
| Symptom | Fix |
|---|---|
| Page won't load | Stop the server (Ctrl+C), rerun the launch command; try `--server.port 8502` |
| `streamlit` not found | Use `.venv\Scripts\python.exe -m streamlit run dashboard/app.py` |
| Route takes long / "no planner finished" | Raise *Time limit per planner* in the sidebar; observed planning times were 2.3 s (TYWIN) and ~9.5 s (SQL_SVC) |
| Blank/odd state after clicks | Reload the browser tab (session state resets; nothing is saved to disk) |
| Need an offline fallback | `python -m stealthpath.cli compare --graph data/goad_graph.json --from "SQL_SVC@NORTH"` and `python -m stealthpath.cli triage --graph data/goad_graph.json` print the same numbers |
