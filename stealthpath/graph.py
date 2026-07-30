"""
Internal attack-graph representation for StealthPath.

Design goals (these matter for Stages 3-5, so they are deliberate):

1. **Integer-indexed.** Nodes and edges have stable integer indices. The RL
   environment in Stage 4 needs a fixed action space and action masking over
   outgoing edges; string keys would force a lookup on every step.
2. **Neo4j-free at runtime.** The loader populates this structure once. Nothing
   downstream (planners, visibility model, Gym env) imports the Neo4j driver.
   This means the whole pipeline can be developed and tested against a
   synthetic graph before GOAD is standing.
3. **Round-trippable to JSON.** A collected graph can be snapshotted to disk and
   committed. Every run must be repeatable against a *frozen* graph; re-running
   SharpHound would silently change the ground truth under results you already
   have.
4. **Edges carry their raw BloodHound relationship type.** Stage 2 maps those to
   ATT&CK techniques and Stage 3 maps them to detection cost. Neither of those
   mappings is baked in here.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable, Iterator, Sequence

__all__ = ["Node", "Edge", "AttackGraph"]


@dataclass(frozen=True)
class Node:
    """A single AD object (user, computer, group, domain, GPO, OU, container)."""

    id: str
    """BloodHound `objectid`. Stable across collections; use this as the key."""

    name: str
    """Display name, usually UPPER@DOMAIN.LOCAL. Human-facing only."""

    kind: str
    """Primary label: User / Computer / Group / Domain / GPO / OU / Container."""

    labels: tuple[str, ...] = ()
    """All Neo4j labels, in case something carries more than one."""

    domain: str = ""
    high_value: bool = False
    """Tier-0 / marked-high-value. Used to identify DA targets."""

    owned: bool = False
    """Marked as attacker-controlled. Used to identify entry nodes."""

    props: dict[str, Any] = field(default_factory=dict)
    """Everything else from the collection, kept for Stage 3 context features
    (e.g. `enabled`, `hasspn`, `operatingsystem`, `admincount`)."""

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        flags = "".join(c for c, on in (("H", self.high_value), ("O", self.owned)) if on)
        return f"<{self.kind} {self.name}{'!' + flags if flags else ''}>"


@dataclass(frozen=True)
class Edge:
    """A directed relationship the attacker may be able to traverse."""

    source: int
    """Index into AttackGraph.nodes."""

    target: int
    rel_type: str
    """Raw BloodHound relationship type, e.g. 'MemberOf', 'GenericAll'."""

    props: dict[str, Any] = field(default_factory=dict)
    """Edge properties, e.g. `isacl`, `isinherited`."""


class AttackGraph:
    """A directed multigraph over AD objects.

    Multigraph, not simple graph: two objects can be joined by several distinct
    relationships (e.g. both `GenericAll` and `AdminTo`), and those have very
    different detection profiles. Collapsing them would destroy the signal the
    whole project is about.
    """

    def __init__(self, nodes: Sequence[Node] | None = None, edges: Sequence[Edge] | None = None):
        self.nodes: list[Node] = list(nodes or [])
        self.edges: list[Edge] = list(edges or [])
        self._index_of: dict[str, int] = {n.id: i for i, n in enumerate(self.nodes)}
        self._out: list[list[int]] = [[] for _ in self.nodes]
        self._in: list[list[int]] = [[] for _ in self.nodes]
        for ei, e in enumerate(self.edges):
            self._out[e.source].append(ei)
            self._in[e.target].append(ei)

    # ------------------------------------------------------------------ build

    def add_node(self, node: Node) -> int:
        """Add a node, or return the existing index if `node.id` is already known."""
        existing = self._index_of.get(node.id)
        if existing is not None:
            return existing
        idx = len(self.nodes)
        self.nodes.append(node)
        self._index_of[node.id] = idx
        self._out.append([])
        self._in.append([])
        return idx

    def add_edge(self, source: str | int, target: str | int, rel_type: str,
                 props: dict[str, Any] | None = None) -> int:
        """Add an edge by node id or index. Raises KeyError on unknown endpoints."""
        s = self.index_of(source) if isinstance(source, str) else source
        t = self.index_of(target) if isinstance(target, str) else target
        ei = len(self.edges)
        self.edges.append(Edge(s, t, rel_type, dict(props or {})))
        self._out[s].append(ei)
        self._in[t].append(ei)
        return ei

    # ------------------------------------------------------------------ query

    def index_of(self, object_id: str) -> int:
        try:
            return self._index_of[object_id]
        except KeyError:
            raise KeyError(f"unknown objectid: {object_id!r}") from None

    def node(self, ref: str | int) -> Node:
        return self.nodes[self.index_of(ref) if isinstance(ref, str) else ref]

    def out_edges(self, node: str | int) -> list[Edge]:
        i = self.index_of(node) if isinstance(node, str) else node
        return [self.edges[ei] for ei in self._out[i]]

    def out_edge_indices(self, node: str | int) -> list[int]:
        """Indices rather than objects — this is what action masking will use."""
        i = self.index_of(node) if isinstance(node, str) else node
        return list(self._out[i])

    def in_edges(self, node: str | int) -> list[Edge]:
        i = self.index_of(node) if isinstance(node, str) else node
        return [self.edges[ei] for ei in self._in[i]]

    def find(self, *, name: str | None = None, kind: str | None = None,
             high_value: bool | None = None, owned: bool | None = None) -> list[int]:
        """Find node indices by any combination of filters. `name` is a
        case-insensitive substring match, which is what you want when hunting
        for 'DOMAIN ADMINS' without knowing the exact SID."""
        out = []
        needle = name.upper() if name else None
        for i, n in enumerate(self.nodes):
            if needle is not None and needle not in n.name.upper():
                continue
            if kind is not None and n.kind.lower() != kind.lower():
                continue
            if high_value is not None and n.high_value != high_value:
                continue
            if owned is not None and n.owned != owned:
                continue
            out.append(i)
        return out

    def entry_nodes(self) -> list[int]:
        """Attacker-controlled starting points (BloodHound `owned` marking)."""
        return self.find(owned=True)

    def target_nodes(self) -> list[int]:
        """Tier-0 / high-value objects. Stage 1 asks you to *document* these
        explicitly rather than trusting the marking — see docs/stage1_lab_runbook.md."""
        return self.find(high_value=True)

    def edge_type_counts(self) -> dict[str, int]:
        """Sanity-check helper: are the AD edge types you expect actually present?"""
        counts: dict[str, int] = {}
        for e in self.edges:
            counts[e.rel_type] = counts.get(e.rel_type, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    def node_kind_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {}
        for n in self.nodes:
            counts[n.kind] = counts.get(n.kind, 0) + 1
        return dict(sorted(counts.items(), key=lambda kv: -kv[1]))

    # ------------------------------------------------------------------ views

    def filtered(self, rel_types: Iterable[str]) -> "AttackGraph":
        """A copy keeping only the given relationship types, all nodes retained.

        Used to reproduce BloodHound's own path queries, which traverse a
        specific edge set — and for testing what happens when a whole class of
        edges is taken off the table.
        """
        keep = set(rel_types)
        return AttackGraph(self.nodes, [e for e in self.edges if e.rel_type in keep])

    def to_networkx(self):
        """Escape hatch for plotting and for cross-checking our Dijkstra against
        networkx's. Not used on any hot path."""
        import networkx as nx

        g = nx.MultiDiGraph()
        for i, n in enumerate(self.nodes):
            g.add_node(i, **asdict(n))
        for e in self.edges:
            g.add_edge(e.source, e.target, key=e.rel_type, rel_type=e.rel_type, **e.props)
        return g

    # ------------------------------------------------------------- (de)serial

    def to_dict(self) -> dict[str, Any]:
        return {
            "format": "stealthpath.attackgraph/1",
            "nodes": [asdict(n) for n in self.nodes],
            "edges": [asdict(e) for e in self.edges],
        }

    def save(self, path: str | Path) -> None:
        # Create the parent directory: the runbook freezes to `data/` immediately
        # after collection, and failing there would mean re-running SharpHound.
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(self.to_dict(), indent=1), encoding="utf-8")

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "AttackGraph":
        fmt = data.get("format", "")
        if not fmt.startswith("stealthpath.attackgraph/"):
            raise ValueError(f"unrecognised graph format: {fmt!r}")
        nodes = [Node(**{**n, "labels": tuple(n.get("labels", ()))}) for n in data["nodes"]]
        return cls(nodes, [Edge(**e) for e in data["edges"]])

    @classmethod
    def load(cls, path: str | Path) -> "AttackGraph":
        return cls.from_dict(json.loads(Path(path).read_text(encoding="utf-8")))

    # ------------------------------------------------------------------ dunder

    def __len__(self) -> int:
        return len(self.nodes)

    def __iter__(self) -> Iterator[Node]:
        return iter(self.nodes)

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return f"<AttackGraph {len(self.nodes)} nodes, {len(self.edges)} edges>"
