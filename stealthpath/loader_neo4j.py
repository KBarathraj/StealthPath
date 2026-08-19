"""
Neo4j -> AttackGraph loader.

Reads a SharpHound-ingested BloodHound database and produces an `AttackGraph`.
Handles both legacy BloodHound (4.x, `highvalue` boolean property) and
BloodHound CE (5.x+, `system_tags` containing `admin_tier_0`).

The `neo4j` package is imported lazily so the rest of StealthPath — planners,
tests, the Stage 4 environment — runs on machines that never touch a database.

Usage:
    from stealthpath.loader_neo4j import Neo4jLoader
    with Neo4jLoader("bolt://localhost:7687", "neo4j", "password") as ld:
        g = ld.load()
    g.save("data/goad_graph.json")   # freeze it, commit it, cite it
"""

from __future__ import annotations

import logging
from typing import Any, Iterator

from .graph import AttackGraph, Node

log = logging.getLogger(__name__)

__all__ = ["Neo4jLoader", "admit_edge", "jsonable", "NODE_QUERY", "EDGE_QUERY"]


NODE_QUERY = """
MATCH (n)
WHERE n.objectid IS NOT NULL
RETURN n.objectid            AS objectid,
       coalesce(n.name, n.objectid) AS name,
       labels(n)             AS labels,
       coalesce(n.domain, '') AS domain,
       properties(n)         AS props
SKIP $skip LIMIT $limit
"""

EDGE_QUERY = """
MATCH (a)-[r]->(b)
WHERE a.objectid IS NOT NULL AND b.objectid IS NOT NULL
RETURN a.objectid AS source,
       b.objectid AS target,
       type(r)    AS rel_type,
       properties(r) AS props
SKIP $skip LIMIT $limit
"""

# Labels that are structural rather than object-kind markers. `Base` appears on
# everything in BloodHound CE and would otherwise win the kind election.
_NON_KIND_LABELS = {"Base", "AZBase"}

_KIND_PRIORITY = ("Domain", "Computer", "User", "Group", "GPO", "OU", "Container")


def _primary_kind(labels: list[str]) -> str:
    """Pick one label as *the* kind. Priority order, not first-wins: BloodHound
    frequently attaches several labels and the ordering from Neo4j is not
    guaranteed stable across driver versions."""
    candidates = [l for l in labels if l not in _NON_KIND_LABELS]
    for kind in _KIND_PRIORITY:
        if kind in candidates:
            return kind
    return candidates[0] if candidates else "Unknown"


def _is_high_value(props: dict[str, Any]) -> bool:
    """True for tier-0 objects under either BloodHound generation."""
    if props.get("highvalue") is True:          # legacy BloodHound 4.x
        return True
    tags = props.get("system_tags") or props.get("user_tags") or ""
    if isinstance(tags, (list, tuple)):
        tags = " ".join(str(t) for t in tags)
    return "admin_tier_0" in str(tags)


def jsonable(value: Any) -> Any:
    """Coerce a Neo4j property value into something `json.dumps` accepts.

    BloodHound stores temporals — `lastseen`, `whencreated`, `lastlogon` — as
    Neo4j `DateTime` objects, and the driver hands them back as such. They
    survive in memory and blow up at `graph.save()`, which is the worst possible
    place to find out: after a collection, at the exact moment rule 6 says to
    freeze. The synthetic fixture has no temporals, so nothing caught this until
    the first real graph.

    ISO strings rather than epoch numbers, because the value is only ever read
    by a human checking provenance.
    """
    if isinstance(value, (str, int, float, bool, type(None))):
        return value
    if isinstance(value, (list, tuple)):
        return [jsonable(v) for v in value]
    if isinstance(value, dict):
        return {str(k): jsonable(v) for k, v in value.items()}
    iso = getattr(value, "isoformat", None)
    return iso() if callable(iso) else str(value)


def admit_edge(rel_type: str, drop_unknown: bool = False) -> bool:
    """Rule 4 at the collection boundary: True to keep, False to drop, or raise.

    A free function so the rule is testable with no database — the loader class
    can't be constructed without a live driver, which is precisely how this
    check went unexercised long enough for the `DCFor` gap to exist.
    """
    from .ad_schema import category_of

    try:
        category_of(rel_type)
        return True
    except KeyError:
        if drop_unknown:
            return False
        raise KeyError(
            f"Collection contains relationship type {rel_type!r}, which "
            f"ad_schema.EDGE_CATEGORIES does not know. Categorise it before "
            f"loading — an uncategorised edge would take a made-up cost later "
            f"and skew every number downstream. To triage the collection "
            f"first, load with drop_unknown_edges=True; what it discards is "
            f"recorded in graph.provenance and travels with the frozen graph."
        ) from None


def _is_owned(props: dict[str, Any]) -> bool:
    if props.get("owned") is True:
        return True
    tags = props.get("system_tags") or props.get("user_tags") or ""
    if isinstance(tags, (list, tuple)):
        tags = " ".join(str(t) for t in tags)
    return "owned" in str(tags)


class Neo4jLoader:
    """Pulls nodes and relationships out of a BloodHound Neo4j instance.

    Paginated because a full GOAD collection is small but a real collection is
    not, and you want the same code path in both cases.
    """

    def __init__(self, uri: str = "bolt://localhost:7687",
                 user: str = "neo4j", password: str = "neo4j",
                 database: str | None = None, page_size: int = 5000):
        try:
            from neo4j import GraphDatabase
        except ImportError as exc:  # pragma: no cover - depends on environment
            raise ImportError(
                "The 'neo4j' package is required to load from a live database. "
                "Install it with `pip install neo4j`, or work against a frozen "
                "graph via AttackGraph.load(), or against "
                "stealthpath.synthetic.goad_like()."
            ) from exc
        self._driver = GraphDatabase.driver(uri, auth=(user, password))
        self._database = database
        self._page_size = page_size

    def __enter__(self) -> "Neo4jLoader":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._driver.close()

    def _paged(self, query: str) -> Iterator[dict[str, Any]]:
        skip = 0
        with self._driver.session(database=self._database) as session:
            while True:
                batch = list(session.run(query, skip=skip, limit=self._page_size))
                if not batch:
                    return
                for record in batch:
                    yield dict(record)
                skip += self._page_size

    def load(self, drop_unknown_edges: bool = False) -> AttackGraph:
        """Build the full graph.

        **Unknown relationship types raise.** Every type is put through
        `category_of()`, which throws on anything the schema doesn't know. That
        is the project's rule, and it used to be enforced everywhere *except*
        here: this loader ran its own membership test and quietly `continue`d,
        so the one code path where an unexpected type actually shows up — a real
        collection — was the one path that didn't raise. `DCFor` is the concrete
        example; it exists in BloodHound CE, the schema has never known about
        it, and it was being discarded without ever reaching `category_of`.

        Worse, `cli inspect`'s uncategorised-type check reads the *loaded*
        graph, so it could only ever see types that survived this filter. The
        detector sat downstream of the thing destroying the evidence.

        `drop_unknown_edges=True` is the deliberate escape hatch for triaging a
        collection you cannot yet fix. It records what it discarded in
        `graph.provenance`, which is serialised with the frozen graph — a
        dropped edge must not be knowable only from a log line that scrolled
        past six weeks ago.
        """
        graph = AttackGraph()

        n_nodes = 0
        for rec in self._paged(NODE_QUERY):
            props = {k: jsonable(v) for k, v in (rec.get("props") or {}).items()}
            labels = list(rec.get("labels") or [])
            graph.add_node(Node(
                id=rec["objectid"],
                name=rec.get("name") or rec["objectid"],
                kind=_primary_kind(labels),
                labels=tuple(labels),
                domain=rec.get("domain") or props.get("domain") or "",
                high_value=_is_high_value(props),
                owned=_is_owned(props),
                props=props,
            ))
            n_nodes += 1
        log.info("loaded %d nodes", n_nodes)

        kept = 0
        dropped: dict[str, int] = {}
        missing_endpoint = 0
        for rec in self._paged(EDGE_QUERY):
            rel = rec["rel_type"]
            if not admit_edge(rel, drop_unknown_edges):
                dropped[rel] = dropped.get(rel, 0) + 1
                continue
            try:
                graph.add_edge(rec["source"], rec["target"], rel,
                               {k: jsonable(v)
                                for k, v in (rec.get("props") or {}).items()})
                kept += 1
            except KeyError:
                # Endpoint outside the node query (e.g. objectid-less node).
                missing_endpoint += 1

        log.info("loaded %d edges", kept)
        if dropped:
            log.warning("dropped unknown relationship types: %s", dropped)
        if missing_endpoint:
            log.warning("dropped %d edges with unresolvable endpoints", missing_endpoint)

        # Travels with the graph, not just the log. Only recorded when something
        # was actually discarded, so a clean collection freezes to a clean file.
        if dropped:
            graph.provenance["dropped_unknown_edge_types"] = dict(sorted(dropped.items()))
        if missing_endpoint:
            graph.provenance["dropped_edges_missing_endpoint"] = missing_endpoint
        return graph
