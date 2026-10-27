"""Session-scoped custom relationship types, for a SOC analyst's own directory.

The default schema and weight table are the frozen, sourced ground truth behind
every reported number (cited by hash). This module lets an analyst **add** a
relationship type the default schema drops -- an AD CS edge, an org-specific
right -- for THEIR uploaded directory, in-session only, without touching that
ground truth.

Everything a custom type touches is **unverified by construction**: its weight is
analyst-supplied, not sourced, so any route that traverses it is reported as
custom/unverified, never "proved" against the sourced model. This is the amber
treatment the approximate learner already gets, applied to the weight table.

## How it works, and why a context manager

`category_of` reads the module-level dict `ad_schema.EDGE_CATEGORIES`, and
`weight_of` reads `risk.PROVISIONAL_WEIGHTS`; both dicts are shared by reference
across the whole codebase -- the parser's admission rule, the cost model, the
planners, the coverage panel. Rather than thread a custom schema through the
dozen functions that read them, `overlay()` adds the custom types to those two
dicts **in place** for the duration of a `with` block and removes them again in a
`finally`. Inside the block every existing function is custom-aware with no
signature change; outside it the frozen state is exactly restored.
`tests/test_custom_schema.py` proves the restoration, including on exception.

This is global mutation, which the project otherwise avoids (determinism is a
build rule). It is acceptable here for three specific reasons, and only these:

1. **Additive only.** `overlay` refuses a type that already exists in the default
   schema -- it never changes a sourced weight or an existing category. Adding a
   key that was absent cannot alter any number the frozen table produces.
2. **Strictly scoped and reversed**, including on exception, and asserted so.
3. **Confined to a local single-user tool** computing one route synchronously.

Re-weighting an *existing* sourced type is a different feature and is deliberately
not offered here; `overlay` raises if a spec names a type already in the table.

**Traversability is not part of the global mutation.** It is already a per-call
parameter of every planner (`allowed_rel_types=`), so the caller passes
`walkable_types(specs)` explicitly. Keeping it out keeps the frozen
`DEFAULT_TRAVERSAL_SET` a frozenset that nothing can quietly widen.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
from typing import Iterator, Sequence

from . import ad_schema, risk

__all__ = ["CustomRelationship", "CATEGORY_NAMES", "validate", "overlay",
           "walkable_types", "custom_weight"]

# The ten categories a custom type may be filed under, taken from the categories
# actually in use. A custom type must reuse an existing category rather than
# invent one: a new category would need its own bit in the history model's state,
# which is a core change, not a per-session one. (`EdgeCategory` is a plain
# constants class, not an iterable enum, so we read the values off the schema.)
CATEGORY_NAMES: tuple[str, ...] = tuple(sorted(set(ad_schema.EDGE_CATEGORIES.values())))


@dataclass(frozen=True)
class CustomRelationship:
    """One analyst-defined relationship type, for this session only."""

    rel_type: str
    category: str
    """One of `CATEGORY_NAMES`. Decides how the history model buckets it."""
    weight: float
    """Detection loudness, 0.1-10. Analyst-supplied, so UNSOURCED by definition."""
    walkable: bool = True
    """Whether a planner may traverse it. False keeps it priced but off-route
    (the right may not be sufficient alone -- build rule 8 -- but the analyst
    owns that call for their own environment)."""
    note: str = ""
    """The analyst's own rationale. Recorded, but it is never a citation and
    never lets the type pass the sourcing gate."""


def validate(spec: CustomRelationship) -> None:
    """Raise if a spec cannot be admitted. Called by `overlay` on every spec."""
    if not spec.rel_type or not spec.rel_type.strip():
        raise ValueError("a relationship type name is required")
    if spec.rel_type in ad_schema.EDGE_CATEGORIES:
        raise ValueError(
            f"{spec.rel_type!r} is already in the default schema. This feature "
            "ADDS types the schema drops; it does not re-weight a sourced one.")
    if spec.category not in CATEGORY_NAMES:
        raise ValueError(
            f"unknown category {spec.category!r}; choose one of {CATEGORY_NAMES}")
    if not (risk.WEIGHT_FLOOR <= spec.weight <= risk.WEIGHT_CEILING):
        raise ValueError(
            f"weight must be in [{risk.WEIGHT_FLOOR}, {risk.WEIGHT_CEILING}]")


def custom_weight(spec: CustomRelationship) -> risk.RiskWeight:
    """A `RiskWeight` for a custom type: a value, a rationale, and **no source**.

    `source=None` is the whole point -- it is what makes `RiskWeight.sourced`
    False, so the coverage panel and the route badge mark anything using it as
    unverified rather than letting an analyst's number wear the sourced model's
    authority.
    """
    rationale = spec.note.strip() or "Analyst-supplied for a custom relationship type."
    return risk.RiskWeight(
        weight=spec.weight,
        rationale=rationale + "  [CUSTOM: analyst-supplied, did not pass the "
                              "sourcing gate.]",
        source=None,
    )


def walkable_types(specs: Sequence[CustomRelationship]) -> frozenset[str]:
    """The custom types a planner may traverse -- pass to `allowed_rel_types=`."""
    return frozenset(s.rel_type for s in specs if s.walkable)


@contextmanager
def overlay(specs: Sequence[CustomRelationship]) -> Iterator[None]:
    """Register `specs` in the shared schema/weight dicts for this block only.

    Validates every spec first (so a bad spec aborts before any mutation), adds
    the types, yields, and removes them in a `finally` that runs on normal exit
    and on exception alike. An empty `specs` is a no-op.
    """
    specs = list(specs)
    for s in specs:
        validate(s)
    # Reject duplicate names within the batch too: the restore loop pops by name
    # and two specs with one name would leave one half-registered.
    names = [s.rel_type for s in specs]
    if len(names) != len(set(names)):
        raise ValueError("two custom relationships share a name")

    cat = ad_schema.EDGE_CATEGORIES
    wt = risk.PROVISIONAL_WEIGHTS
    try:
        for s in specs:
            cat[s.rel_type] = s.category
            wt[s.rel_type] = custom_weight(s)
        yield
    finally:
        for s in specs:
            cat.pop(s.rel_type, None)
            wt.pop(s.rel_type, None)
