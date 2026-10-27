# StealthPath — Demo Script (3–5 minutes)

Everything below was reproduced on the bundled demo graph (see `DEMO_READINESS.md`).
Launch first: `.venv\Scripts\activate` then `streamlit run dashboard/app.py`.

## 1. The problem (30 s)
"In Active Directory, accounts, groups and computers are linked by privileges. If
one account is compromised, an attacker can chain those links to reach Domain
Admin. Existing tools show the *shortest* path, but a short path can be loud and a
longer one quiet, and tools rarely say how much of the picture is missing.
StealthPath compares routes by an estimated detection cost and tells you how far to
trust the answer."

## 2. Loading data (20 s)
"On the left I can upload a BloodHound/SharpHound export or a saved graph. For the
demo I'm using the bundled GOAD lab graph: 783 objects, 5,825 relationships. It runs
locally and nothing I upload is written back."

## 3. Pick a start and find a route (60 s)
- In **Start from**, keep `TYWIN.LANNISTER@SEVENKINGDOMS`; **Reach** stays on *Any
  Domain Admin / domain*. Press **Find the route to Domain Admin**.
- "It returns a nine-step route with a total cost of 44.5, marked **Proved
  optimal**: an exhaustive search found nothing cheaper under this model. Each step
  shows its technique and cost, and a dot says whether it would be logged. On the
  right, *Can you trust it?* says all nine steps have a cited price, and that the
  route is an **upper bound**, because some relationship types were dropped."

## 4. Compare routes (60 s)
- Switch **Start from** to `SQL_SVC@NORTH.SEVENKINGDOMS.LOCAL` and run again.
  (Choose the NORTH one; the ESSOS account has no route.)
- "Cost 15.1, four steps, proved optimal. Open **Compare the three planners**: the
  shortest route is also four steps and ends in **DCSync**, a loud step. The
  priced route takes a quieter final step instead." (Note: the table's cost column
  shows the shortest row as **4**, its hop count. If asked for its detection cost,
  it is **20.0** under the same weights; the UI doesn't print that, but
  `python -m stealthpath.cli compare --graph data/goad_graph.json --from "SQL_SVC@NORTH"`
  does, as "total risk 20.0" vs 15.1.)
- "The score is a relative loudness measure, **not a probability of detection**. And
  honestly, for most starts here the two routes match; this graph is dominated by one
  kind of relationship. That is something the tool reports rather than hides."

## 5. The defender's view (60 s)
- Click **Defend — whole directory**.
- "Same model, defender's question. Of 28 accounts assessed, 11 can reach tier-0.
  The list ranks them by distance, so 'we got an alert on this user: how bad is it?'
  is a lookup. *What should we fix first?* ranks single relationships by how many
  accounts lose all tier-0 access without them; the top one cuts 7 of 24, about 29%."
- "Caution: breaking a path doesn't make a relationship safe to remove. The tool
  says that itself. I'd use this list to decide what to investigate first, not to
  delete things."

## 6. Honesty panel and close (40 s)
- Back on **Attack route**, open **Graph data quality**: "Pricing coverage is rated
  POOR on purpose: 98.6% of walkable edges have a cited weight, 22 of 35 weights are
  sourced, and 19 relationship types are dropped. I'd rather show that than print
  confident numbers."
- **Close:** "StealthPath turns an AD attack graph into an evidence-aware decision:
  understand the path, inspect the evidence behind its cost, and prioritize what to
  investigate. Its limits: one lab graph, some unsourced weights, relative scores
  rather than measured detection rates, and it models relationships without proving
  exploitability. Next steps are better coverage, more validated weights, and testing
  on more authorized collections."

## Likely questions (answers grounded in the code)
- *Is the cost a detection probability?* No. It is a relative score; weights are
  sourced to ATT&CK / SigmaHQ rules under a stated telemetry baseline.
- *Can it run on our network?* It analyzes an exported graph; it executes nothing
  against hosts. Results on other collections are untested.
- *Why is the learner mentioned?* An independent learner cross-checks the exact
  search; where they agree, the app shows it. The exact search is the reference.
