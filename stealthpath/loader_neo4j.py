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

__all__ = ["Neo4jLoader", "NODE_QUERY", "EDGE_QUERY"]


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

    # ------------------------------------------------------------------ ctx
    def __enter__(self) -> "Neo4jLoader":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self._driver.close()

    # ----------------------------------------------------------------- fetch
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

    def load(self, drop_unknown_edges: bool = True) -> AttackGraph:
        """Build the full graph.

        `drop_unknown_edges`: relationship types not present in
        `ad_schema.EDGE_CATEGORIES` are dropped with a warning rather than
        silently admitted. If you see warnings here, that is a real finding —
        either your BloodHound version has edges the schema module doesn't know
        about, or the collection picked up something unexpected. Resolve it
        before Stage 2 rather than after.
        """
        from .ad_schema import EDGE_CATEGORIES

        graph = AttackGraph()

        n_nodes = 0
        for rec in self._paged(NODE_QUERY):
            props = dict(rec.get("props") or {})
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
            if drop_unknown_edges and rel not in EDGE_CATEGORIES:
                dropped[rel] = dropped.get(rel, 0) + 1
                continue
            try:
                graph.add_edge(rec["source"], rec["target"], rel,
                               dict(rec.get("props") or {}))
                kept += 1
            except KeyError:
                # Endpoint outside the node query (e.g. objectid-less node).
                missing_endpoint += 1

        log.info("loaded %d edges", kept)
        if dropped:
            log.warning("dropped unknown relationship types: %s", dropped)
        if missing_endpoint:
            log.warning("dropped %d edges with unresolvable endpoints", missing_endpoint)
        return graph
