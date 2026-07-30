"""
StealthPath CLI — Stage 1 milestone tooling.

The Stage 1 gate is: *can we query the graph programmatically and get a shortest
path to DA that matches what BloodHound's UI shows?* This gives you both halves
of that — our answer, and the Cypher to paste into BloodHound to check it.

    # against the live lab
    python -m stealthpath.cli inspect --uri bolt://localhost:7687 --password X
    python -m stealthpath.cli freeze  --uri bolt://localhost:7687 --password X \
        --out data/goad_graph.json

    # against a frozen snapshot (no database needed)
    python -m stealthpath.cli inspect --graph data/goad_graph.json
    python -m stealthpath.cli path    --graph data/goad_graph.json

    # against the synthetic fixture (no lab needed at all)
    python -m stealthpath.cli inspect --synthetic
    python -m stealthpath.cli path    --synthetic --verify
"""

from __future__ import annotations

import argparse
import logging
import sys
from typing import Sequence

from .ad_schema import DEFAULT_TRAVERSAL_SET, EDGE_CATEGORIES, category_of
from .graph import AttackGraph
from .planners.shortest_path import ShortestPathPlanner

# Edge types SharpHound should produce in any non-trivial AD environment. If
# these are missing after collection, the collection is incomplete — that is a
# lab problem, not a code problem, and it must be fixed before Stage 2.
EXPECTED_EDGE_TYPES = (
    "MemberOf", "AdminTo", "HasSession", "GenericAll", "GenericWrite",
    "WriteDacl", "Owns", "Contains",
)


def _load(args: argparse.Namespace) -> AttackGraph:
    if args.synthetic:
        from .synthetic import goad_like
        return goad_like()
    if args.graph:
        return AttackGraph.load(args.graph)
    from .loader_neo4j import Neo4jLoader
    with Neo4jLoader(args.uri, args.user, args.password, args.database) as loader:
        return loader.load()


def _resolve_endpoints(graph: AttackGraph, args: argparse.Namespace
                       ) -> tuple[list[int], list[int]]:
    """Entry and target nodes, by explicit flag or by BloodHound marking.

    Stage 1 asks you to *document* these. Prefer --from/--to with real names in
    anything you report: BloodHound's owned/high-value markings drift as people
    click around the UI, and a run whose start points changed underneath it is
    not comparable to the one before it.
    """
    if args.source:
        sources = [i for s in args.source for i in graph.find(name=s)]
    else:
        sources = graph.entry_nodes()
    if args.target:
        targets = [i for t in args.target for i in graph.find(name=t)]
    else:
        targets = [i for i in graph.find(name="DOMAIN ADMINS", kind="Group")] \
                  or graph.target_nodes()
    return sources, targets


def cmd_inspect(args: argparse.Namespace) -> int:
    g = _load(args)
    print(f"\nGraph: {len(g.nodes)} nodes, {len(g.edges)} edges\n")

    print("Node kinds:")
    for kind, count in g.node_kind_counts().items():
        print(f"  {count:>7}  {kind}")

    print("\nRelationship types:")
    by_cat: dict[str, list[tuple[str, int]]] = {}
    for rel, count in g.edge_type_counts().items():
        try:
            cat = category_of(rel)
        except KeyError:
            cat = "UNKNOWN"
        by_cat.setdefault(cat, []).append((rel, count))
    for cat in sorted(by_cat):
        print(f"  [{cat}]")
        for rel, count in by_cat[cat]:
            flag = "" if rel in DEFAULT_TRAVERSAL_SET else "   (not traversed)"
            print(f"    {count:>7}  {rel}{flag}")

    missing = [r for r in EXPECTED_EDGE_TYPES if r not in g.edge_type_counts()]
    if missing:
        print(f"\n  !! Expected but absent: {', '.join(missing)}")
        print("     Check SharpHound collection method coverage before Stage 2.")

    unknown = [r for r in g.edge_type_counts() if r not in EDGE_CATEGORIES]
    if unknown:
        print(f"\n  !! Uncategorised relationship types: {', '.join(unknown)}")
        print("     Add them to ad_schema.EDGE_CATEGORIES before Stage 2.")

    sources, targets = _resolve_endpoints(g, args)
    print(f"\nEntry nodes ({len(sources)}):")
    for i in sources[:10]:
        print(f"  {g.nodes[i].name}")
    print(f"\nTarget nodes ({len(targets)}):")
    for i in targets[:10]:
        print(f"  {g.nodes[i].name}")
    if not sources:
        print("\n  !! No entry nodes. Mark a foothold as owned in BloodHound, "
              "or pass --from.")
    if not targets:
        print("\n  !! No target nodes. Pass --to, or mark tier-0 in BloodHound.")
    print()
    return 0


def cmd_path(args: argparse.Namespace) -> int:
    g = _load(args)
    sources, targets = _resolve_endpoints(g, args)
    if not sources or not targets:
        print("Cannot plan: missing entry or target nodes. Run `inspect` first.",
              file=sys.stderr)
        return 2

    planner = ShortestPathPlanner(max_hops=args.max_hops)
    path = planner.plan(g, sources, targets)
    if path is None:
        print("No path found from any entry node to any target.")
        print("That is a legitimate result, not necessarily a bug — but confirm "
              "it against BloodHound before believing it.")
        return 1

    path.validate(g)
    print("\n" + path.describe(g) + "\n")

    if args.verify:
        _print_verification(g, path, sources, targets)
    return 0


def _print_verification(graph: AttackGraph, path, sources: Sequence[int],
                        targets: Sequence[int]) -> None:
    """Emit the Cypher to run in BloodHound so the two answers can be compared.

    Matching *hop count* is the real check. The specific path may legitimately
    differ when several routes tie, because BloodHound's tie-breaking is not
    ours. A different length, though, means one of the two is traversing an edge
    set the other isn't — usually Contains/GPLink. Chase that down.
    """
    src = graph.node(path.nodes[0])
    dst = graph.node(path.nodes[-1])
    rels = "|".join(sorted(DEFAULT_TRAVERSAL_SET))
    print("--- Stage 1 milestone check " + "-" * 47)
    print(f"Ours: {path.length} hops.")
    print("Run this in the BloodHound / Neo4j browser and compare the length:\n")
    print(f"  MATCH p = shortestPath(")
    print(f"    (a {{objectid: '{src.id}'}})-[:{rels}*1..]->(b {{objectid: '{dst.id}'}})")
    print(f"  ) RETURN length(p), p")
    print("\nIf the lengths differ, the traversal sets differ. Check")
    print("ad_schema.DEFAULT_TRAVERSAL_SET against the edges BloodHound used.")
    print("-" * 75 + "\n")


def cmd_freeze(args: argparse.Namespace) -> int:
    g = _load(args)
    g.save(args.out)
    print(f"Wrote {len(g.nodes)} nodes / {len(g.edges)} edges to {args.out}")
    print("Commit this file. Every run must go against a frozen graph, not a "
          "live database.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="stealthpath", description=__doc__,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("-v", "--verbose", action="store_true")
    sub = p.add_subparsers(dest="command", required=True)

    def add_source_args(sp: argparse.ArgumentParser) -> None:
        grp = sp.add_argument_group("graph source")
        grp.add_argument("--graph", help="load a frozen graph JSON file")
        grp.add_argument("--synthetic", action="store_true",
                         help="use the built-in GOAD-shaped fixture (no lab needed)")
        grp.add_argument("--uri", default="bolt://localhost:7687")
        grp.add_argument("--user", default="neo4j")
        grp.add_argument("--password", default="neo4j")
        grp.add_argument("--database", default=None)
        sp.add_argument("--from", dest="source", action="append",
                        help="entry node name substring (repeatable)")
        sp.add_argument("--to", dest="target", action="append",
                        help="target node name substring (repeatable)")

    sp = sub.add_parser("inspect", help="graph statistics and sanity checks")
    add_source_args(sp)
    sp.set_defaults(func=cmd_inspect)

    sp = sub.add_parser("path", help="shortest path from entry to target")
    add_source_args(sp)
    sp.add_argument("--max-hops", type=int, default=None)
    sp.add_argument("--verify", action="store_true",
                    help="print the equivalent BloodHound Cypher for comparison")
    sp.set_defaults(func=cmd_path)

    sp = sub.add_parser("freeze", help="snapshot the graph to JSON")
    add_source_args(sp)
    sp.add_argument("--out", required=True)
    sp.set_defaults(func=cmd_freeze)
    return p


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(levelname)s %(name)s: %(message)s")
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
