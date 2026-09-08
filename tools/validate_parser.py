"""Validate a parsed (nodes, edges) result against BloodHound CE's own ingest.

    python tools/validate_parser.py            # once a parser exists

The BloodHound CE export parser has one failure mode nothing else in this repo
can catch: a **mis-mapped relationship type**. It yields full pricing coverage,
plausible routes and confidently wrong costs, and every existing test still
passes because every existing test asks whether the *graph* is self-consistent,
not whether it is the right graph.

What makes the check possible is that `data/goad_graph.json` is CE's ingest of
the exact collector output now vendored in `data/raw_collection/`. Reproducing
that ingest is therefore a decidable question, and this module is the decision
procedure.

**Triples, not counts.** The comparison is over
`(source_objectid, target_objectid, rel_type)`, resolved back from the frozen
graph's integer indices. Per-type counts would pass a parser that emits six
`DCSync` edges between the wrong endpoints — which is close to the real failure,
because CE grants `DCSync` to domain controllers with no underlying ACE at all
and the intuitive `GetChanges AND GetChangesAll` rule produces three edges, none
of them the ones the reported routes traverse.

**Route-bearing types fail; everything else is a note.** A drift in `Enroll`
changes nothing anyone has published. A drift in `DCSync` or `GenericWrite`
re-costs a route quoted in `findings.md`.
"""

from __future__ import annotations

import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from stealthpath.graph import AttackGraph  # noqa: E402

__all__ = [
    "Triple", "TypeDiff", "ValidationReport", "IndexProblem",
    "reference_triples", "triples_from_parsed", "validate",
    "check_index_integrity", "ROUTE_BEARING_TYPES", "REFUSED_PREFIX",
    "assert_fixture_is_the_right_collection",
]

FROZEN_GRAPH = ROOT / "data" / "goad_graph.json"
RAW_COLLECTION = ROOT / "data" / "raw_collection"

# Derived in reconnaissance: the union of relationship types appearing on any
# reported route, across both frozen graphs and all three planners. A mapping
# error confined to a type outside this set cannot move a number in findings.md;
# an error inside it invalidates one.
ROUTE_BEARING_TYPES = frozenset({
    "AddMember", "AddSelf", "AdminTo", "DCSync", "ForceChangePassword",
    "GPLink", "GenericAll", "GenericWrite", "HasSession", "MemberOf",
    "SQLAdmin", "WriteDacl", "WriteOwner",
})

# The upstream repository also publishes exports collected a day later by
# bloodhound.py. They describe the same lab, they are not the same collection,
# and they did not produce the frozen graph. Refused by name, because a
# validation run against the wrong ground truth still reports success.
REFUSED_PREFIX = "ce_branch_bloodhoundpy_"

Triple = tuple[str, str, str]


class WrongCollectionError(Exception):
    """Raised when a fixture is not the collection the frozen graph came from."""


def assert_fixture_is_the_right_collection(path: Path) -> None:
    """Refuse a collector export that cannot be ground truth for this graph.

    Documented-only guards get ignored under deadline. This one raises.
    """
    if path.name.startswith(REFUSED_PREFIX):
        raise WrongCollectionError(
            f"{path.name} is a bloodhound.py export collected 2024-04-11, not "
            f"the SharpHound 2.3.3 collection that produced data/goad_graph.json "
            f"(sha256 3c1bef97...). Validating against it would compare the "
            f"parser to a different ingest and still report success. Use the "
            f"files listed under `raw_collection.sha256` in "
            f"data/collection_provenance.json."
        )


@dataclass
class TypeDiff:
    """One relationship type's agreement with the reference ingest."""

    rel_type: str
    expected: int
    got: int
    missing: list[Triple] = field(default_factory=list)
    extra: list[Triple] = field(default_factory=list)
    route_bearing: bool = False

    @property
    def status(self) -> str:
        if not self.missing and not self.extra:
            return "MATCH"
        if self.missing and self.extra:
            return "MISMATCH"
        return "MISSING" if self.missing else "EXTRA"

    @property
    def ok(self) -> bool:
        return self.status == "MATCH"


@dataclass
class IndexProblem:
    """An edge whose endpoints cannot be trusted.

    `AttackGraph.__init__` indexes `self._out[e.source]`, so a negative index
    silently wraps to the end of the node list and builds a wrong graph without
    raising. Out-of-range raises IndexError, which is loud; -1 does not, which is
    why this check exists separately from "did it load".
    """

    edge_index: int
    field_name: str
    value: int
    reason: str


@dataclass
class ValidationReport:
    diffs: list[TypeDiff]
    index_problems: list[IndexProblem] = field(default_factory=list)
    names: dict[str, str] = field(default_factory=dict)
    """objectid -> display name, from the reference graph.

    A diff whose purpose is to say *which* edge is wrong is not doing that if it
    prints only SIDs. Populated for reference nodes; an objectid a parser
    invented has no name and is shown as-is, which is itself informative.
    """

    @property
    def route_failures(self) -> list[TypeDiff]:
        return [d for d in self.diffs if d.route_bearing and not d.ok]

    @property
    def other_failures(self) -> list[TypeDiff]:
        return [d for d in self.diffs if not d.route_bearing and not d.ok]

    @property
    def ok(self) -> bool:
        """Route-bearing agreement and index integrity. Not total agreement.

        Deliberately not "every type matches": the parser is scoped to what the
        risk table prices, so types outside that scope are expected to be
        missing and are reported as notes rather than failures.
        """
        return not self.route_failures and not self.index_problems

    def name_of(self, objectid: str) -> str:
        name = self.names.get(objectid)
        return f"{name}" if name else f"<{objectid}>"

    def render(self, show_all: bool = False, max_examples: int = 4) -> str:
        lines: list[str] = []
        w = max((len(d.rel_type) for d in self.diffs), default=10)

        def block(title: str, diffs: list[TypeDiff]) -> None:
            if not diffs:
                return
            lines.append(title)
            lines.append("-" * len(title))
            for d in diffs:
                lines.append(f"  {d.rel_type:<{w}}  expected {d.expected:>5}  "
                             f"got {d.got:>5}  delta {d.got - d.expected:+5}  "
                             f"{d.status}")
                for label, triples in (("missing", d.missing), ("extra", d.extra)):
                    for s, t, r in triples[:max_examples]:
                        lines.append(f"      {label}: {self.name_of(s)} "
                                     f"-{r}-> {self.name_of(t)}")
                    if len(triples) > max_examples:
                        lines.append(f"      ... {len(triples) - max_examples} "
                                     f"more {label}")
            lines.append("")

        block("ROUTE-BEARING TYPES — a discrepancy here invalidates a published number",
              self.route_failures)
        block("OTHER TYPES — note only, outside what the risk table prices",
              self.other_failures)
        if show_all:
            block("AGREEING", [d for d in self.diffs if d.ok])

        if self.index_problems:
            lines.append("INDEX INTEGRITY")
            lines.append("-" * len("INDEX INTEGRITY"))
            for p in self.index_problems:
                lines.append(f"  edge {p.edge_index}: {p.field_name}={p.value} "
                             f"— {p.reason}")
            lines.append("")

        matched = sum(1 for d in self.diffs if d.ok)
        lines.append(f"{matched}/{len(self.diffs)} types agree; "
                     f"{len(self.route_failures)} route-bearing failure(s); "
                     f"{len(self.index_problems)} index problem(s)")
        lines.append("VERDICT: " + ("PASS" if self.ok else "FAIL"))
        return "\n".join(lines)


def reference_triples(graph_path: Path | None = None) -> set[Triple]:
    """The frozen graph as `(source_objectid, target_objectid, rel_type)`.

    Indices are resolved back to objectids so the comparison does not depend on
    node ordering, which a parser has no reason to reproduce.
    """
    graph = AttackGraph.load(graph_path or FROZEN_GRAPH)
    nodes = graph.nodes
    return {(nodes[e.source].id, nodes[e.target].id, e.rel_type)
            for e in graph.edges}


def triples_from_parsed(nodes: list, edges: list) -> set[Triple]:
    """Same projection over a parser's output.

    Accepts either dataclass instances or the plain dicts `from_dict` takes, so
    a parser can be validated before it is wired to anything.
    """
    def node_id(n: object) -> str:
        return n["id"] if isinstance(n, dict) else n.id

    ids = [node_id(n) for n in nodes]
    out: set[Triple] = set()
    for e in edges:
        if isinstance(e, dict):
            s, t, r = e["source"], e["target"], e["rel_type"]
        else:
            s, t, r = e.source, e.target, e.rel_type
        # Endpoints outside the node list are skipped rather than indexed. A
        # broken index is reported by `check_index_integrity`, and raising here
        # would replace that named diagnosis with an IndexError traceback —
        # turning the one report that says *which* edge is wrong into a crash.
        if not isinstance(s, int) or not isinstance(t, int):
            continue
        if not (0 <= s < len(ids)) or not (0 <= t < len(ids)):
            continue
        out.add((ids[s], ids[t], r))
    return out


def check_index_integrity(nodes: list, edges: list) -> list[IndexProblem]:
    """Catch endpoints `from_dict` would accept and misinterpret."""
    n = len(nodes)
    problems: list[IndexProblem] = []
    for i, e in enumerate(edges):
        pair = ((e["source"], e["target"]) if isinstance(e, dict)
                else (e.source, e.target))
        for name, value in zip(("source", "target"), pair):
            if not isinstance(value, int) or isinstance(value, bool):
                problems.append(IndexProblem(
                    i, name, value, "endpoint is not an integer index"))
            elif value < 0:
                problems.append(IndexProblem(
                    i, name, value,
                    f"negative index wraps to node {n + value} instead of "
                    f"raising — from_dict will accept this silently"))
            elif value >= n:
                problems.append(IndexProblem(
                    i, name, value, f"out of range for {n} nodes"))
    return problems


def validate(nodes: list, edges: list,
             graph_path: Path | None = None) -> ValidationReport:
    """Compare a parsed result against the reference ingest."""
    expected = reference_triples(graph_path)
    got = triples_from_parsed(nodes, edges)
    reference = AttackGraph.load(graph_path or FROZEN_GRAPH)
    names = {n.id: n.name for n in reference.nodes}

    diffs: list[TypeDiff] = []
    for rel_type in sorted({t[2] for t in expected} | {t[2] for t in got}):
        exp = {t for t in expected if t[2] == rel_type}
        act = {t for t in got if t[2] == rel_type}
        diffs.append(TypeDiff(
            rel_type=rel_type,
            expected=len(exp),
            got=len(act),
            missing=sorted(exp - act),
            extra=sorted(act - exp),
            route_bearing=rel_type in ROUTE_BEARING_TYPES,
        ))

    problems = check_index_integrity(nodes, edges)

    # A set comparison cannot see a duplicated edge, and build rule 2 makes
    # AttackGraph a multigraph precisely so duplicates are meaningful. The
    # reference happens to contain no repeated triple (5,825 edges, 5,825
    # triples), so any duplication on the parsed side is the parser's, and it
    # would otherwise be invisible in every diff above.
    # Counted over edges with usable endpoints only: edges skipped for a broken
    # index are already reported above, and counting them here would report the
    # same fault twice under the wrong name.
    countable = len(edges) - len({p.edge_index for p in problems if p.edge_index >= 0})
    if countable != len(got):
        problems.append(IndexProblem(
            -1, "duplicate_triples", countable - len(got),
            f"{countable} well-formed edges collapse to {len(got)} distinct "
            f"triples; the reference has no repeated triple, so these are "
            f"duplicates the per-type diff cannot show"))

    return ValidationReport(diffs, problems, names)


def main() -> int:
    try:
        from dashboard.bloodhound_parser import parse_export_dir
    except ImportError:
        print("No parser yet — dashboard/bloodhound_parser.py does not exist.")
        print("The harness is built first on purpose; see this module's docstring.")
        print(f"\nReference ingest: {len(reference_triples()):,} edge triples "
              f"from {FROZEN_GRAPH.relative_to(ROOT)}")
        print(f"Route-bearing types: {len(ROUTE_BEARING_TYPES)}")
        zips = sorted(RAW_COLLECTION.glob("*.zip"))
        print(f"Vendored collector exports: {len(zips)}")
        for z in zips:
            assert_fixture_is_the_right_collection(z)
            print(f"  {z.name}")
        return 0

    nodes, edges = parse_export_dir(RAW_COLLECTION)
    report = validate(nodes, edges)
    print(report.render())
    return 0 if report.ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
