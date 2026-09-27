# Minimum that ships

**If nothing else lands, the deliverable is the working web application on the
two frozen graphs.**

That bar is already the app's job, not a future milestone.

## In

- `streamlit run dashboard/app.py` launches without a lab or a live Neo4j.
- The two committed graphs load: `data/goad_graph.json` and
  `data/goad_graph_perturbed.json`.
- The coverage / honesty panel is visible without being asked (dropped types,
  unsourced weights, sessions, delegation, AD CS).
- Three routes for a chosen start: shortest path, risk-weighted A\*, exact
  history-aware search.
- Q-learning on those graphs, reported as a gap against the exact optimum —
  prove the route, do not assert it.
- Every number shown for those frozen graphs matches the pinned tests / the
  dated record in `findings.md`. If the UI computes something that record does
  not report, that is a bug.

## Out of the minimum (product gaps, not blockers for a demo)

- BloodHound CE zip ingest. Today the upload path accepts a StealthPath freeze
  only. A zip is refused rather than guessed.
- Start and target selection that works on a directory with no GOAD names.
  Today `tier0_targets()` keys on well-known Domain Admins / domain objects;
  a foreign collection needs `_is_high_value` / `_is_owned` and actual domain
  structure.
- Unbounded Q-learning on an unknown upload. A capped or unfinished run must
  never be presented as a finished policy.

## Why this is enough to show

The research engine (sourced weights, property tests, frozen hashes) is what
makes the numbers on those two graphs trustworthy. The app is how a reviewer
sees that engine. Coverage-first is the differentiator: the demo is honest
about what it could not price.

See `docs/handoff.md` for the three gaps above, in priority order.
