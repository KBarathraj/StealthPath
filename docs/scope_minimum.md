# Minimum that ships

**If nothing else lands, the deliverable is the working web application on the
frozen reference graph.**

That bar is already the app's job, not a future milestone.

## In

- `streamlit run dashboard/app.py` launches without a lab or a live Neo4j.
- The committed graph loads: `data/goad_graph.json`. The perturbed copy used by
  the H5/H6 experiment (`data/goad_graph_perturbed.json`) is gitignored since
  2026-09-27; the demo picker offers it only where the file is on disk, so a
  fresh clone has one demo, not two.
- The coverage / honesty panel is visible without being asked: beside the route
  (cited prices, proof, dropped-on-ingest), and one click below it for the
  directory-wide gaps (unsourced weights, sessions, delegation, AD CS).
- Three routes for a chosen start: shortest path, risk-weighted A\*, exact
  history-aware search.
- Q-learning on the frozen graph, reported as a gap against the exact optimum —
  prove the route, do not assert it.
- Every number shown for the frozen graph matches the pinned tests / the dated
  record in `findings.md`. If the UI computes something that record does not
  report, that is a bug.

## Beyond the minimum — shipped 2026-09-19

These were the three product gaps. All three closed; `docs/handoff.md` records
what closed each and the constraints a later change has to respect.

- **BloodHound CE ingest.** A collector export (zip, or per-class JSON) is
  accepted and reconstructed by `dashboard/bloodhound_parser.py`.
  `tools/validate_parser.py` is the gate: it must keep passing.
- **Start and target selection on a directory with no GOAD names.**
  `stealthpath/targets.py` keys on well-known RIDs and domain structure, and
  returns exactly `tier0_targets()` on the frozen graph.
- **Q-learning on an unknown upload.** `dashboard/rl_upload.py` walks exact
  search → approximate Q-learning → refusal and names the rung that answered.
  A capped or unfinished run is never presented as a finished policy, and an
  approximate route with no exact optimum to check it against is labelled
  unverified.

## Why this is enough to show

The research engine (sourced weights, property tests, frozen hashes) is what
makes the numbers on the reference graph trustworthy. The app is how a reviewer
sees that engine. Coverage-first is the differentiator: the demo is honest
about what it could not price.
