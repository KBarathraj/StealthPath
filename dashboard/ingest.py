"""Load a user-supplied graph into `AttackGraph`. No UI, no planners.

Two shapes are accepted, and the difference between them is worth stating
because it is the difference between a citation and a session.

**A StealthPath freeze** (`format: stealthpath.attackgraph/1`) is what
`AttackGraph.save` / `cli freeze` write. It is an authored artifact: hashable,
citable, and already past admission.

**A BloodHound CE / SharpHound collector export** -- the zip a user actually
has -- is reconstructed by `dashboard.bloodhound_parser`. That parser is not a
guess: `data/goad_graph.json` is CE's own ingest of the collection vendored in
`data/raw_collection/`, and `tools/validate_parser.py` checks the parse against
it triple by triple. Every route-bearing relationship type agrees exactly.

This module used to refuse the zip, for a reason that was right at the time: a
mis-mapped `WriteDacl` -> `GenericAll` still looks fully covered and prints
confident, wrong costs, and nothing downstream can catch it. That reason is
answered by the validator rather than by the refusal, so the refusal is gone and
the validator is now the thing that must not be removed.

**An uploaded graph is session-scoped and is never frozen.** Nothing here writes
to `data/`, and build rule 6 is unaffected: the frozen graphs on disk stay the
ground truth for every reported number.
"""

from __future__ import annotations

import json
from typing import Any, Sequence

from stealthpath.graph import AttackGraph

from .bloodhound_parser import (
    NotABloodHoundExport, ParsedExport, parse_export_bytes, to_attack_graph,
)

__all__ = ["UnsupportedGraphError", "load_uploaded", "load_uploads", "LoadedGraph"]

_FORMAT_PREFIX = "stealthpath.attackgraph/"


class UnsupportedGraphError(ValueError):
    """The bytes are a graph, just not one this loader can price honestly."""


class LoadedGraph:
    """An `AttackGraph` plus how it got here.

    The route matters downstream: a freeze carries its own provenance and can be
    cited, while a parsed export carries only what the parser recorded and must
    be labelled as this session's reconstruction.
    """

    def __init__(self, graph: AttackGraph, origin: str,
                 parsed: ParsedExport | None = None):
        self.graph = graph
        self.origin = origin
        """`"freeze"` or `"collector-export"`."""
        self.parsed = parsed

    @property
    def is_reconstruction(self) -> bool:
        return self.origin == "collector-export"


def load_uploads(items: Sequence[tuple[str, bytes]]) -> LoadedGraph:
    """Load one or more uploaded files as a single graph.

    Several files are merged only for collector exports, and that is deliberate:
    a multi-domain forest is collected one domain at a time, and the cross-domain
    ACEs do not resolve until every zip is in the same table. Two *freezes* are
    two separate graphs and merging them would invent a forest that was never
    collected, so that combination is refused rather than concatenated.
    """
    if not items:
        raise UnsupportedGraphError("nothing uploaded")

    freezes = [(n, b) for n, b in items if _looks_like_freeze(b)]
    if freezes and len(items) > 1:
        raise UnsupportedGraphError(
            "a StealthPath freeze was uploaded alongside other files. A freeze "
            "is a complete graph on its own; merging it with anything else "
            "would produce a forest that was never collected. Upload the freeze "
            "by itself, or upload only collector exports."
        )
    if freezes:
        name, raw = freezes[0]
        return LoadedGraph(_load_freeze(raw, name), "freeze")

    try:
        parsed = parse_export_bytes(items)
    except NotABloodHoundExport as exc:
        raise UnsupportedGraphError(_refusal(items, str(exc))) from exc
    return LoadedGraph(to_attack_graph(parsed), "collector-export", parsed)


def load_uploaded(raw: bytes, filename: str = "") -> AttackGraph:
    """Single-file convenience wrapper, kept for callers that have one blob."""
    return load_uploads([(filename or "(upload)", raw)]).graph


def _looks_like_freeze(raw: bytes) -> bool:
    if raw[:2] == b"PK":
        return False
    try:
        data = json.loads(raw.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return (isinstance(data, dict)
            and str(data.get("format", "")).startswith(_FORMAT_PREFIX))


def _load_freeze(raw: bytes, name: str) -> AttackGraph:
    data = json.loads(raw.decode("utf-8-sig"))
    try:
        return AttackGraph.from_dict(data)
    except (TypeError, KeyError, ValueError) as exc:
        raise UnsupportedGraphError(
            f"{name} declares {data.get('format')!r} but could not be loaded: {exc}"
        ) from exc


def _refusal(items: Sequence[tuple[str, bytes]], detail: str) -> str:
    """Say what was uploaded and what would work, not just that it failed."""
    name = items[0][0] if len(items) == 1 else f"{len(items)} files"
    hint = ""
    raw = items[0][1]
    if raw[:1] not in (b"P", b"{", b"["):
        hint = (" The file does not start like JSON or a zip, so it may be the "
                "wrong file entirely.")
    else:
        data = _try_json(raw)
        if isinstance(data, dict) and "nodes" in data and "edges" in data:
            hint = (" It has nodes and edges but no \"format\" field, so it is "
                    "not a StealthPath freeze -- accepting it would price a "
                    "graph that never passed admission.")
    return (
        f"{name} could not be read as either supported format ({detail}).{hint}\n\n"
        "This page takes either:\n"
        "  - a SharpHound / BloodHound CE collector export (.zip, or the "
        "per-class .json files) -- upload every domain's zip together; or\n"
        "  - a StealthPath freeze, a JSON object with "
        "\"format\": \"stealthpath.attackgraph/1\", as written by "
        "`python -m stealthpath.cli freeze`."
    )


def _try_json(raw: bytes) -> Any:
    try:
        return json.loads(raw.decode("utf-8-sig"))
    except (json.JSONDecodeError, UnicodeDecodeError):
        return None
