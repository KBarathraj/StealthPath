"""BloodHound CE / SharpHound export -> `(nodes, edges)`.

**New transport, zero new semantics.** Everything this module decides about an
edge is a decision BloodHound CE already makes at ingest time; nothing here
invents a relationship type, and admission stays with
`loader_neo4j.admit_edge()` / `ad_schema.category_of()` where it always was.
What is new is only *where the bytes come from*: a zip of per-class JSON rather
than a live Neo4j session.

## Why a parser needs a harness and not a code review

A mis-mapped relationship type is invisible downstream. Rewrite `WriteDacl` to
`GenericAll` and the graph still loads, still prices every edge, still reports
full coverage, and still prints a route -- a wrong one, confidently. No existing
test catches it, because every existing test asks whether the graph is
self-consistent rather than whether it is the *right* graph.

`tools/validate_parser.py` is the decision procedure: `data/goad_graph.json` is
CE's own ingest of the exact collector output vendored in `data/raw_collection/`,
so "did this reproduce CE" is decidable over
`(source_objectid, target_objectid, rel_type)` triples. This module is written
against that check and must keep passing it.

## The derivations that are not one-to-one

Four edge types in the reference ingest exist nowhere in the collector output.
They are CE post-processing, and each was read off the reference rather than
assumed:

- **`DCSync`** is *not* just "holds GetChanges and GetChangesAll". That rule
  yields 3 edges here; the reference has 6. The other 3 are the domain
  controllers themselves, which CE grants `DCSync` with no underlying ACE at
  all. Both halves are needed, and the naive half is the one that omits exactly
  the edges a route would traverse.
- **`SyncLAPSPassword`** is `GetChanges` + `GetChangesInFilteredSet` on a
  domain, fanned out to each LAPS-enabled computer in it -- not an ACE.
- **`AdminTo`** comes from local group membership, restricted to RID 544.
- **`SpoofSIDHistory`** follows a cross-forest trust with SID filtering off.

## One place this deliberately does less than CE

CE's local-group model can also emit `CanRDP`, `ExecuteDCOM` and `CanPSRemote`
from RIDs 555, 562 and 580. **The reference ingest emits none of them**, though
this collection has four principals in local Remote Desktop Users -- so emitting
them would produce a graph that demonstrably is not the one CE produced, and
they are all traversable, so the difference would move routes. `LOCAL_GROUP_RIDS`
carries the full map with only 544 enabled, so the gap is visible rather than
absent. Turning the others on is a decision to be validated, not a default.

ADCS post-processing (`ADCSESC*`, `GoldenCert`) is not reproduced: those edge
types are dropped by `admit_edge` anyway, so reproducing them would add a
mapping this repo cannot price and cannot check.
"""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from pathlib import Path
from typing import Any, Iterable, Iterator

from stealthpath.graph import AttackGraph, Edge, Node
from stealthpath.loader_neo4j import admit_edge, jsonable

__all__ = [
    "parse_export_dir", "parse_export_files", "parse_export_bytes",
    "to_attack_graph", "ParsedExport", "NotABloodHoundExport",
    "OBJECT_KINDS", "LOCAL_GROUP_RIDS", "TIER_ZERO_RIDS",
]


class NotABloodHoundExport(ValueError):
    """The bytes are not a SharpHound/BloodHound CE collector export."""


# meta.type -> the node kind BloodHound CE labels the object with.
OBJECT_KINDS: dict[str, str] = {
    "users": "User",
    "computers": "Computer",
    "groups": "Group",
    "domains": "Domain",
    "gpos": "GPO",
    "ous": "OU",
    "containers": "Container",
    "certtemplates": "CertTemplate",
    "rootcas": "RootCA",
    "aiacas": "AIACA",
    "enterprisecas": "EnterpriseCA",
    "ntauthstores": "NTAuthStore",
}

# Local group RID -> the edge CE derives from membership in it.
#
# Only 544 is enabled; see this module's docstring. The other three are recorded
# rather than deleted so that "we do not emit CanRDP" reads as a decision with a
# reason attached, instead of as a mapping somebody forgot.
LOCAL_GROUP_RIDS: dict[int, str | None] = {
    544: "AdminTo",
    555: None,   # Remote Desktop Users -> CanRDP in some CE versions
    562: None,   # Distributed COM Users -> ExecuteDCOM
    580: None,   # Remote Management Users -> CanPSRemote
}

# Well-known tier-0 RIDs. Used only to set `Node.high_value`, which the triple
# validator does not check -- CE's own tagging pass is not reproduced here, and
# `stealthpath.targets` treats this as one signal among several rather than as
# ground truth.
TIER_ZERO_RIDS = frozenset({
    "512", "516", "517", "518", "519", "520", "521", "526", "527", "498",
    "500", "502", "544", "548", "549", "550", "551", "557", "559", "562",
    "569", "9",
})

_RAW_TWIN = {"Owns": "OwnsRaw", "WriteOwner": "WriteOwnerRaw"}
"""ACE rights CE emits twice: once post-processed, once as the unfiltered fact.

Both are emitted here because both are in the reference ingest's provenance, and
a parser that emitted only one would disagree with it. `admit_edge` drops the
raw twin as an unknown type, which is where that decision belongs.
"""


class ParsedExport:
    """What a collector export reconstructs to, before admission.

    Carries `nodes` and `edges` in the shape `tools/validate_parser.py` takes,
    plus the counts the coverage panel needs. Not an `AttackGraph`: admission
    happens in `to_attack_graph`, so the parse can be validated on its own.
    """

    def __init__(self, nodes: list[Node], edges: list[Edge],
                 stub_ids: set[str], sources: list[str],
                 object_classes: dict[str, int]):
        self.nodes = nodes
        self.edges = edges
        self.stub_ids = stub_ids
        """Objectids referenced by an edge but never collected as an object.

        Real and expected -- a cross-domain ACE names a principal the collector
        never enumerated. They become nodes with no properties, and that is
        worth showing rather than silently dropping the edge.
        """
        self.sources = sources
        self.object_classes = object_classes
        """meta.type -> objects kept, including classes this parser does not know.

        An unrecognised class counts as 0 rather than being absent, so the
        coverage panel can say "this export had 104 certtemplates we did not
        model" instead of leaving the reader to infer it from a node count.
        """

    def __repr__(self) -> str:  # pragma: no cover - cosmetic
        return (f"<ParsedExport {len(self.nodes)} nodes, {len(self.edges)} edges, "
                f"{len(self.stub_ids)} stubs>")


# --------------------------------------------------------------------------
# reading the container
# --------------------------------------------------------------------------

def _iter_json_documents(raw: bytes, name: str) -> Iterator[tuple[str, dict[str, Any]]]:
    """Yield `(member_name, document)` for a zip or a single JSON file."""
    if raw[:2] == b"PK":
        try:
            archive = zipfile.ZipFile(BytesIO(raw))
        except zipfile.BadZipFile as exc:
            # A truncated or half-uploaded zip. Without this the BadZipFile
            # escapes as an unhandled exception and takes the page down, which
            # is a worse answer than "that file is damaged".
            raise NotABloodHoundExport(
                f"{name} starts like a zip but could not be opened ({exc}). "
                f"It is most likely truncated -- try the upload again."
            ) from exc
        with archive as zf:
            for member in zf.namelist():
                if not member.lower().endswith(".json"):
                    continue
                try:
                    yield member, json.loads(zf.read(member).decode("utf-8-sig"))
                except (json.JSONDecodeError, UnicodeDecodeError) as exc:
                    raise NotABloodHoundExport(
                        f"{name}:{member} is not readable JSON ({exc})") from exc
        return
    try:
        yield name, json.loads(raw.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise NotABloodHoundExport(f"{name} is not readable JSON ({exc})") from exc


def _collect_objects(
    documents: Iterable[tuple[str, dict[str, Any]]],
) -> tuple[dict[str, tuple[str, dict]], dict[str, int]]:
    """Merge every document into one objectid -> (kind, object) table.

    **Deduplicated by objectid, and that is not an optimisation.** A three-domain
    collection re-describes the same forest-wide containers and groups in each
    zip: 1,063 object entries here collapse to 755 distinct objects, and
    reproducing the reference ingest requires exactly that collapse. Keeping
    duplicates would multiply every ACE on a shared object.
    """
    objects: dict[str, tuple[str, dict]] = {}
    classes: dict[str, int] = {}
    for member, doc in documents:
        if not isinstance(doc, dict) or "meta" not in doc:
            raise NotABloodHoundExport(
                f"{member} has no `meta` block, so it is not a collector "
                f"output file. A BloodHound CE export is a zip of per-class "
                f"JSON, each with meta.type and a data array."
            )
        kind_key = str((doc.get("meta") or {}).get("type", ""))
        kind = OBJECT_KINDS.get(kind_key)
        if kind is None:
            # Unknown object class: counted, not guessed. CE adds classes over
            # time, and that is not an error -- but inventing a kind for one
            # would put it in front of a planner under a false label.
            classes.setdefault(kind_key, 0)
            continue
        for obj in doc.get("data") or []:
            oid = obj.get("ObjectIdentifier")
            if not oid:
                continue
            previous = objects.get(oid)
            if previous is None:
                classes[kind_key] = classes.get(kind_key, 0) + 1
                objects[oid] = (kind, obj)
            else:
                objects[oid] = (previous[0] or kind,
                                _merge_objects(previous[1], obj))
    return objects, classes


def _merge_objects(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Combine two descriptions of the same objectid, richer field wins.

    **Last-wins loses data, and it loses it silently.** SharpHound writes the
    same object twice inside a *single* zip: once fully enumerated and once as a
    bare placeholder carrying only its identifier. Overwriting the first with the
    second cost 81 `Owns` edges and 84 `Contains` edges here, and the graph still
    loaded, still priced and still routed -- exactly the failure mode the triple
    validator exists to catch. CE upserts; so does this.

    "Richer" is deliberately crude -- a populated list beats an empty one, a
    value beats None -- because the two records are the same object and the only
    real difference between them is how much of it was filled in.
    """
    merged = dict(a)
    for key, value in b.items():
        if key not in merged:
            merged[key] = value
            continue
        current = merged[key]
        if isinstance(current, dict) and isinstance(value, dict):
            merged[key] = _merge_objects(current, value)
        elif isinstance(current, (list, tuple)) and isinstance(value, (list, tuple)):
            if len(value) > len(current):
                merged[key] = value
        elif current in (None, "", [], {}, False) and value not in (None, "", [], {}):
            merged[key] = value
    return merged


# --------------------------------------------------------------------------
# edge derivation
# --------------------------------------------------------------------------

def _rid(objectid: str) -> str:
    return objectid.rsplit("-", 1)[-1]


def _as_int(text: str) -> int:
    try:
        return int(text)
    except ValueError:
        return -1


def _tier_zero(kind: str, oid: str, props: dict[str, Any]) -> bool:
    """Our tier-0 marking, which is *not* CE's post-processing pass.

    CE writes `system_tags: admin_tier_0` after ingest using rules this repo
    does not reproduce. Rather than leave every uploaded graph with no
    high-value node at all -- which would make target derivation silently
    return nothing -- this applies the two signals present in the collector
    output itself: AdminSDHolder protection (`admincount`) and well-known
    tier-0 RIDs. `stealthpath.targets` says so where a user can see it.
    """
    if kind == "Domain":
        return True
    if props.get("admincount") is True:
        return True
    return _rid(oid) in TIER_ZERO_RIDS


def _derive_edges(objects: dict[str, tuple[str, dict]]) -> list[tuple[str, str, str, dict]]:
    """Every `(source_id, target_id, rel_type, props)` CE's ingest would create."""
    out: list[tuple[str, str, str, dict]] = []

    def emit(src: str | None, dst: str | None, rel: str,
             props: dict | None = None) -> None:
        # Self-referential edges are discarded: the reference ingest contains
        # none at all, and the collection really does carry three of them
        # (`DOMAIN ADMINS -Owns-> DOMAIN ADMINS`). A planner cannot use a
        # self-loop for anything except padding a route, so keeping them would
        # add cost without adding reach.
        if src and dst and src != dst:
            out.append((src, dst, rel, props or {}))

    # Per-domain indexes the composite derivations need.
    domain_rights: dict[str, dict[str, set[str]]] = {}   # domain -> principal -> rights
    laps_computers: dict[str, list[str]] = {}            # domain sid -> computer ids
    dc_of: list[tuple[str, str]] = []                    # (computer id, domain sid)

    for oid, (kind, obj) in objects.items():
        props = obj.get("Properties") or {}

        # --- ACEs: principal -RightName-> this object ------------------------
        for ace in obj.get("Aces") or []:
            principal = ace.get("PrincipalSID")
            right = ace.get("RightName")
            if not principal or not right:
                continue
            ace_props = {"isacl": True, "isinherited": bool(ace.get("IsInherited"))}
            emit(principal, oid, right, ace_props)
            twin = _RAW_TWIN.get(right)
            if twin:
                emit(principal, oid, twin, ace_props)
            if kind == "Domain":
                domain_rights.setdefault(oid, {}).setdefault(principal, set()).add(right)

        # --- containment ------------------------------------------------------
        for child in obj.get("ChildObjects") or []:
            emit(oid, child.get("ObjectIdentifier"), "Contains")
        contained_by = obj.get("ContainedBy")
        if isinstance(contained_by, dict):
            emit(contained_by.get("ObjectIdentifier"), oid, "Contains")

        # --- GPO links: the GPO is the source, the linked container the target -
        for link in obj.get("Links") or []:
            emit(link.get("GUID"), oid, "GPLink",
                 {"enforced": bool(link.get("IsEnforced"))})

        # --- group membership -------------------------------------------------
        for member in obj.get("Members") or []:
            emit(member.get("ObjectIdentifier"), oid, "MemberOf")
        # Primary group membership is stored on the member, not in the group's
        # member list -- Domain Users and Domain Computers are almost entirely
        # invisible without it. 62 of the reference's 199 MemberOf edges are
        # only reachable this way.
        emit(oid, obj.get("PrimaryGroupSID"), "MemberOf")

        # --- delegation and SID history --------------------------------------
        for t in obj.get("AllowedToDelegate") or []:
            emit(oid, t.get("ObjectIdentifier"), "AllowedToDelegate")
        for t in obj.get("HasSIDHistory") or []:
            emit(oid, t.get("ObjectIdentifier"), "HasSIDHistory")
        for t in obj.get("AllowedToAct") or []:
            emit(t.get("ObjectIdentifier"), oid, "AllowedToAct")
        for t in obj.get("DumpSMSAPassword") or []:
            emit(oid, t.get("ObjectIdentifier"), "DumpSMSAPassword")

        # --- SQL service principals ------------------------------------------
        for spn in obj.get("SPNTargets") or []:
            if str(spn.get("Service", "")).lower() == "sqladmin":
                emit(oid, spn.get("ComputerSID"), "SQLAdmin")

        if kind == "Computer":
            # Sessions arrive from three collection methods that overlap; the
            # union is deduplicated later, which is what leaves the reference
            # with 5 HasSession edges from 10 raw observations.
            for block in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                for s in ((obj.get(block) or {}).get("Results") or []):
                    emit(s.get("ComputerSID") or oid, s.get("UserSID"), "HasSession")

            for lg in obj.get("LocalGroups") or []:
                lg_id = lg.get("ObjectIdentifier")
                results = lg.get("Results") or []
                if not lg_id or not results:
                    continue
                emit(lg_id, oid, "LocalToComputer")
                derived = LOCAL_GROUP_RIDS.get(_as_int(_rid(lg_id)))
                for m in results:
                    emit(m.get("ObjectIdentifier"), lg_id, "MemberOfLocalGroup")
                    if derived:
                        emit(m.get("ObjectIdentifier"), oid, derived)

            domain_sid = obj.get("DomainSID") or props.get("domainsid")
            if obj.get("IsDC") and domain_sid:
                dc_of.append((oid, domain_sid))
            if props.get("haslaps") is True and domain_sid:
                laps_computers.setdefault(domain_sid, []).append(oid)

        # --- GPO-applied local admin -----------------------------------------
        changes = obj.get("GPOChanges") or {}
        affected = [c.get("ObjectIdentifier")
                    for c in (changes.get("AffectedComputers") or [])]
        for key, rel in (("LocalAdmins", "AdminTo"), ("RemoteDesktopUsers", "CanRDP"),
                         ("DcomUsers", "ExecuteDCOM"), ("PSRemoteUsers", "CanPSRemote")):
            for principal in changes.get(key) or []:
                for computer in affected:
                    emit(principal.get("ObjectIdentifier"), computer, rel)

        # --- trusts ------------------------------------------------------------
        if kind == "Domain":
            for trust in obj.get("Trusts") or []:
                other = trust.get("TargetDomainSid")
                if not other:
                    continue
                cross_forest = str(trust.get("TrustType", "")) == "Forest"
                rel = "CrossForestTrust" if cross_forest else "SameForestTrust"
                direction = str(trust.get("TrustDirection", ""))
                pairs = [(oid, other), (other, oid)]
                if direction == "Inbound":
                    pairs = [(other, oid)]
                elif direction == "Outbound":
                    pairs = [(oid, other)]
                for a, b in pairs:
                    emit(a, b, rel, {"transitive": bool(trust.get("IsTransitive"))})
                    # SID filtering off across a forest boundary is what makes
                    # the history injection reachable; same-forest trusts never
                    # filter, and CE does not emit the edge for them.
                    if cross_forest and trust.get("SidFilteringEnabled") is False:
                        emit(a, b, "SpoofSIDHistory")

    # --- well-known memberships nothing in the export states -----------------
    #
    # CE synthesises these at ingest. They are not in any Members list and not
    # in any ACE, and they matter: Domain Users -> Authenticated Users is how
    # every ordinary account inherits whatever Authenticated Users can do, so a
    # graph without it under-reports reach from exactly the entry points a user
    # is most likely to pick.
    domains = {oid: (obj.get("Properties") or {})
               for oid, (kind, obj) in objects.items() if kind == "Domain"}
    domain_names = {str(p.get("name") or "").upper(): oid
                    for oid, p in domains.items() if p.get("name")}
    for domain_sid, props in domains.items():
        dname = str(props.get("name") or "").upper()
        if not dname:
            continue
        everyone = f"{dname}-S-1-1-0"
        authenticated = f"{dname}-S-1-5-11"
        emit(f"{domain_sid}-513", authenticated, "MemberOf")   # Domain Users
        emit(f"{domain_sid}-515", authenticated, "MemberOf")   # Domain Computers
        emit(f"{domain_sid}-501", everyone, "MemberOf")        # Guest
        emit(authenticated, everyone, "MemberOf")

    # A domain controller belongs to Enterprise Domain Controllers of its
    # *forest root*, not of its own domain -- which is why WINTERFELL, in the
    # NORTH child domain, lands in the SEVENKINGDOMS group. The root is the
    # shortest collected domain name that the DC's domain is a suffix of.
    for computer, domain_sid in dc_of:
        props = (objects.get(computer) or ("", {}))[1].get("Properties") or {}
        dname = str(props.get("domain") or "").upper()
        roots = sorted((n for n in domain_names if dname.endswith(n)), key=len)
        if roots:
            emit(computer, f"{roots[0]}-S-1-5-9", "MemberOf")

    # --- composites, which no single object carries --------------------------
    for domain_sid, principals in domain_rights.items():
        for principal, rights in principals.items():
            if {"GetChanges", "GetChangesAll"} <= rights:
                emit(principal, domain_sid, "DCSync")
            if {"GetChanges", "GetChangesInFilteredSet"} <= rights:
                for computer in laps_computers.get(domain_sid, []):
                    emit(principal, computer, "SyncLAPSPassword")

    # A domain controller replicates by definition, with no ACE behind it. This
    # is the half of DCSync that a rights-only rule silently omits -- and on this
    # collection it is 3 of the 6 edges.
    for computer, domain_sid in dc_of:
        emit(computer, domain_sid, "DCFor")
        emit(computer, domain_sid, "DCSync")

    return out


# --------------------------------------------------------------------------
# assembly
# --------------------------------------------------------------------------

def _build(objects: dict[str, tuple[str, dict]], sources: list[str],
           classes: dict[str, int]) -> ParsedExport:
    nodes: list[Node] = []
    index: dict[str, int] = {}

    def add(oid: str, kind: str, obj: dict | None) -> int:
        existing = index.get(oid)
        if existing is not None:
            return existing
        props = {k: jsonable(v) for k, v in ((obj or {}).get("Properties") or {}).items()}
        # `IsDC` sits beside Properties in the collector output but inside them
        # after a CE ingest, and the frozen graph carries it as `props.isdc`.
        # Normalising here is what lets `stealthpath.targets` ask one question
        # of an uploaded graph and a frozen one.
        if obj is not None and "IsDC" in obj and "isdc" not in props:
            props["isdc"] = bool(obj["IsDC"])
        index[oid] = len(nodes)
        nodes.append(Node(
            id=oid,
            name=str(props.get("name") or oid),
            kind=kind,
            labels=(kind,),
            domain=str(props.get("domain") or ""),
            high_value=_tier_zero(kind, oid, props),
            owned=False,
            props=props,
        ))
        return index[oid]

    for oid, (kind, obj) in objects.items():
        add(oid, kind, obj)

    raw_edges = _derive_edges(objects)

    stub_ids: set[str] = set()
    for src, dst, _rel, _props in raw_edges:
        for endpoint in (src, dst):
            if endpoint not in index:
                stub_ids.add(endpoint)
                # Kind "Unknown" rather than a guess: this objectid was named by
                # an ACE or a membership list and never collected, so nothing in
                # the export says what it is.
                add(endpoint, "Unknown", None)

    # Deduplicated on the triple, not on the endpoint pair. Build rule 2 keeps
    # AttackGraph a multigraph, so two *different* relationships between the
    # same objects both survive; what collapses here is the same relationship
    # described twice -- a container appearing in three zips, or a session seen
    # by two collection methods.
    seen: set[tuple[int, int, str]] = set()
    edges: list[Edge] = []
    for src, dst, rel, props in raw_edges:
        key = (index[src], index[dst], rel)
        if key in seen:
            continue
        seen.add(key)
        edges.append(Edge(index[src], index[dst], rel, props))

    return ParsedExport(nodes, edges, stub_ids, sources, classes)


def parse_export_bytes(items: Iterable[tuple[str, bytes]]) -> ParsedExport:
    """Parse named byte blobs -- zips or loose collector JSON -- as one collection.

    Several zips are merged deliberately: a multi-domain forest is collected one
    domain at a time, and the cross-domain ACEs only resolve once all of them
    are in the same table.
    """
    documents: list[tuple[str, dict[str, Any]]] = []
    names: list[str] = []
    for name, raw in items:
        names.append(name)
        documents.extend(_iter_json_documents(raw, name))
    if not documents:
        raise NotABloodHoundExport("no JSON documents found in the upload")
    objects, classes = _collect_objects(documents)
    if not objects:
        raise NotABloodHoundExport(
            "the export contains no recognisable AD objects. Expected per-class "
            "files with meta.type in " + ", ".join(sorted(OBJECT_KINDS)) + "."
        )
    return _build(objects, names, classes)


def parse_export_files(paths: Iterable[Path]) -> ParsedExport:
    return parse_export_bytes((p.name, p.read_bytes()) for p in list(paths))


def parse_export_dir(directory: Path | str) -> tuple[list[Node], list[Edge]]:
    """Parse every collector export in a directory.

    Returns the bare `(nodes, edges)` pair because that is the signature
    `tools/validate_parser.py` calls -- the harness predates the parser on
    purpose, and this keeps it the gate rather than a formality.
    """
    d = Path(directory)
    paths = sorted(p for p in d.iterdir() if p.suffix.lower() in (".zip", ".json"))
    parsed = parse_export_files(paths)
    return parsed.nodes, parsed.edges


def to_attack_graph(parsed: ParsedExport, drop_unknown_edges: bool = True) -> AttackGraph:
    """Apply the existing admission rules and build the graph.

    `drop_unknown_edges` defaults to True here and False in `Neo4jLoader`, and
    that asymmetry is intended: a freeze is an authored artifact where an
    unknown type must stop the run, while an upload is someone else's directory
    where an unknown type is expected and the honest response is to drop it and
    say so on the coverage panel.
    """
    graph = AttackGraph()
    for node in parsed.nodes:
        graph.add_node(node)

    dropped: dict[str, int] = {}
    for edge in parsed.edges:
        if not admit_edge(edge.rel_type, drop_unknown_edges):
            dropped[edge.rel_type] = dropped.get(edge.rel_type, 0) + 1
            continue
        graph.add_edge(edge.source, edge.target, edge.rel_type, edge.props)

    graph.provenance["ingest"] = "bloodhound_parser (collector export, session-scoped)"
    graph.provenance["source_files"] = list(parsed.sources)
    graph.provenance["object_classes"] = dict(sorted(parsed.object_classes.items()))
    if dropped:
        graph.provenance["dropped_unknown_edge_types"] = dict(sorted(dropped.items()))
    if parsed.stub_ids:
        graph.provenance["referenced_but_not_collected"] = len(parsed.stub_ids)
    return graph
