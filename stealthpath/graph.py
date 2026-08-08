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

    def __init__(self, nodes: Sequence[Node] | None = None, edges: Sequence[Edge] | None = None,
                 provenance: dict[str, Any] | None = None):
        self.nodes: list[Node] = list(nodes or [])
        self.edges: list[Edge] = list(edges or [])
        self.provenance: dict[str, Any] = dict(provenance or {})
        """How this graph came to be, travelling *with* the graph.

        Anything the loader discarded or transformed belongs here, because a
        frozen JSON file is the ground truth for every later run and its reader
        has no access to the log lines emitted when it was built. A drop that
        exists only in a transient log is a drop nobody will ever find.

        Deliberately holds no timestamp: freezing identical data twice must
        produce an identical file, or committed graphs churn on every re-freeze.
        """
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
        """Whatever BloodHound has *marked* high-value. Drifts as people click
        around the UI, so prefer `tier0_targets()` or an explicit --to list —
        see docs/stage1_lab_runbook.md."""
        return self.find(high_value=True)

    def tier0_targets(self) -> list[int]:
        """Endpoints that count as full domain compromise.

        Domain Admins groups, Enterprise Admins groups, and domain objects.

        The domain object belongs here because replication rights live on the
        domain, not in any group. An attacker who holds them has won without
        ever touching Domain Admins, so a DA-group-only target set silently
        drops that whole class of route — one of the most common real endpoints,
        not an edge case. Enterprise Admins belongs here because it is
        forest-wide admin, which is strictly more than Domain Admins.

        These are endpoints in their own right, *not* things reached by walking
        `Contains` down from a container. `Contains` stays out of
        DEFAULT_TRAVERSAL_SET; this changes what counts as arriving, never what
        counts as a step.

        Identified by well-known name rather than by BloodHound's high-value
        marking, which drifts as people click around the UI.

        **Domain controller computer objects are missing from this list**, and
        should be here by the same argument — admin on a DC is domain
        compromise. They are absent because the graph carries no reliable DC
        marker yet: BloodHound's signal is the `DCFor` edge, which
        `EDGE_CATEGORIES` does not know about and the loader therefore drops.
        See the note on PARTIAL_RIGHT_EDGES's neighbour in ad_schema, and the
        target-set section of docs/stage1_lab_runbook.md.

        Defined here, in one place, because the target set was previously
        re-decided independently by the CLI and by every test that needed one.
        """
        targets = set(self.find(name="DOMAIN ADMINS", kind="Group"))
        targets.update(self.find(name="ENTERPRISE ADMINS", kind="Group"))
        targets.update(self.find(kind="Domain"))
        return sorted(targets)

    def target_severity(self, ref: str | int) -> tuple[str, str] | None:
        """Classify a tier-0 target as `(scope, domain)`, or None if not one.

        `scope` is `"forest"` for Enterprise Admins and `"domain"` for a Domain
        Admins group or a domain object. Used by `compare_target_severity`.
        """
        node = self.node(ref)
        upper = node.name.upper()
        if node.kind == "Group" and "ENTERPRISE ADMINS" in upper:
            return ("forest", node.domain)
        if node.kind == "Group" and "DOMAIN ADMINS" in upper:
            return ("domain", node.domain)
        if node.kind == "Domain":
            return ("domain", node.domain or node.name)
        return None

    def compare_target_severity(self, a: str | int, b: str | int) -> int | None:
        """Partial order over tier-0 targets. +1 if `a` outranks `b`, -1 if `b`
        outranks `a`, 0 if equal, **None if incomparable**.

        The order, deliberately partial:

        * Enterprise Admins outranks everything — it is forest-wide.
        * Within one domain, the Domain Admins group and the domain object are
          **tied**. Replication rights on the domain and DA membership are both
          domain-wide; neither dominates the other.
        * Across domains, targets are **incomparable**. There is no defensible
          ranking between DA@NORTH and DA@SEVENKINGDOMS, and inventing one would
          put a number on a question nobody asked.

        None is a real answer here, not a failure. Callers must handle it rather
        than coercing it to an ordering.
        """
        sa, sb = self.target_severity(a), self.target_severity(b)
        if sa is None or sb is None:
            return None
        if sa[0] == "forest" and sb[0] == "forest":
            return 0
        if sa[0] == "forest":
            return 1
        if sb[0] == "forest":
            return -1
        return 0 if sa[1] == sb[1] else None

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

    def with_gpo_expansion(self) -> "AttackGraph":
        """A view where `GPLink` and `Contains` are walkable, but only downward
        from the object kind that makes them an attack rather than an accident.

        `GPLink` is kept only when its source is a GPO, and `Contains` only when
        its source is an OU or Container. That is the whole exception: an
        attacker who controls a GPO's content genuinely does reach every object
        the GPO applies to, and the route there runs GPO -> OU -> object.

        What it deliberately does **not** re-admit is the general case. The
        `Domain -Contains-> Domain Admins` shortcut that rule 3 exists to block
        has a Domain as its source, so it stays excluded here too — the whole
        point is that this widens one specific chain rather than the rule.

        `WriteGPLink` is dropped from this view. That is now **redundant** — it
        lives in `PARTIAL_RIGHT_EDGES`, so it is already outside
        `DEFAULT_TRAVERSAL_SET` and could never arrive here. Kept deliberately as
        defence in depth: this method's entire job is re-admitting edges the
        default rules exclude, so it is the one place where a future widening
        could let a partial right back in by accident. The cost of the redundant
        check is one comparison; the cost of removing it is that the failure it
        guards against becomes silent.

        The failure, for the record: re-admitting `Contains` out of an OU means
        *any* arrival at that OU can descend into its contents — including
        arrival across `WriteGPLink`, which is the right to attach a policy, not
        control of one. Without the drop a planner walks
        `WriteGPLink -> OU -> Contains -> object` and claims the estate for a
        right that alone does nothing.

        Plan over the result with `DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES`.
        Note that `GPLink` and `Contains` have no risk weights, so the weighted
        planner cannot cost this route yet.
        """
        from .ad_schema import DEFAULT_TRAVERSAL_SET

        sources_allowed = {"GPLink": {"GPO"}, "Contains": {"OU", "Container"}}
        kept = []
        for edge in self.edges:
            if edge.rel_type == "WriteGPLink":
                continue
            if edge.rel_type in DEFAULT_TRAVERSAL_SET:
                kept.append(edge)
                continue
            allowed = sources_allowed.get(edge.rel_type)
            if allowed and self.nodes[edge.source].kind in allowed:
                kept.append(edge)
        return AttackGraph(self.nodes, kept, provenance=dict(self.provenance))

    def with_local_admin_expansion(self) -> "AttackGraph":
        """A view where the local-group chain is walkable, but only out of a
        local group whose membership actually confers access.

        `Principal -MemberOfLocalGroup-> LocalGroup -LocalToComputer-> Computer`
        is BloodHound CE's local-admin model, and where the group is
        Administrators it means exactly what `AdminTo` means. The catch is that
        `LocalToComputer` runs out of *every* local group — Users, Guests,
        IIS_IUSRS — so admitting it wholesale would let membership in local
        `Users` reach the machine. Effectively every domain account is in local
        Users on every machine, so every principal would reach every DC.

        Gated on `PRIVILEGED_LOCAL_GROUP_RIDS`, matched against the objectid's
        RID suffix rather than the group name, because names are localised and
        `S-1-5-32-544` is not.

        Plan over the result with
        `DEFAULT_TRAVERSAL_SET | LOCAL_ADMIN_EXPANSION_EDGES`. Neither edge has
        a risk weight yet, so the weighted planner cannot cost this view.
        """
        from .ad_schema import DEFAULT_TRAVERSAL_SET, PRIVILEGED_LOCAL_GROUP_RIDS

        def privileged(index: int) -> bool:
            oid = self.nodes[index].id or ""
            return oid.rsplit("-", 1)[-1] in PRIVILEGED_LOCAL_GROUP_RIDS

        kept = []
        for edge in self.edges:
            if edge.rel_type == "MemberOfLocalGroup":
                if privileged(edge.target):
                    kept.append(edge)
            elif edge.rel_type == "LocalToComputer":
                if privileged(edge.source):
                    kept.append(edge)
            elif edge.rel_type in DEFAULT_TRAVERSAL_SET:
                kept.append(edge)
        return AttackGraph(self.nodes, kept, provenance=dict(self.provenance))

    def with_preconditions(self) -> "AttackGraph":
        """A view with statically-checkable capability preconditions enforced.

        Some edges represent a right the holder cannot actually use. Where the
        missing piece is visible in the graph, drop the edge rather than let a
        planner claim a capability nobody has.

        **Resource-based constrained delegation** (`AllowedToAct`,
        `AddAllowedToAct`) is the first case. Abusing RBCD needs a principal you
        control that has an SPN, because S4U2Proxy is requested *as* a service.
        That holds when the source is a Computer (computers always have one), or
        a User with `hasspn`, or when the domain's `ms-DS-MachineAccountQuota`
        is above zero so you can create a computer account yourself.

        What this deliberately does not cover: acquiring an SPN-bearing account
        *partway along a route* also satisfies the precondition, and whether you
        have done so depends on the path taken. That is history-dependent and
        belongs to Stage 3's model, not to a static view. So this view is
        conservative — it can drop an edge a longer route could legitimately
        use. Being conservative in that direction understates the attacker,
        which is the safe way to be wrong here.
        """
        rbcd = {"AllowedToAct", "AddAllowedToAct"}
        quota = 0
        for node in self.nodes:
            if node.kind == "Domain":
                try:
                    quota = max(quota, int(node.props.get("machineaccountquota") or 0))
                except (TypeError, ValueError):
                    pass

        kept = []
        for edge in self.edges:
            if edge.rel_type in rbcd and quota <= 0:
                source = self.nodes[edge.source]
                has_spn = source.kind == "Computer" or bool(source.props.get("hasspn"))
                if not has_spn:
                    continue
            kept.append(edge)
        return AttackGraph(self.nodes, kept, provenance=dict(self.provenance))

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
            "provenance": self.provenance,
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
        # .get: graphs frozen before provenance existed are still readable.
        return cls(nodes, [Edge(**e) for e in data["edges"]],
                   provenance=data.get("provenance") or {})

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
