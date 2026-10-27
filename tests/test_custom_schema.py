"""Session-scoped custom relationship types.

The load-bearing property is **restoration**: the overlay mutates the shared
schema and weight dicts in place, so if it ever failed to put them back, every
later reported number would be computed against a polluted table. These tests
prove it restores on normal exit and on exception, and that a custom type is
unverified by construction.
"""

from __future__ import annotations

import pytest

from stealthpath import ad_schema, risk
from stealthpath.custom_schema import (
    CATEGORY_NAMES, CustomRelationship, overlay, validate, walkable_types,
)

ESC = CustomRelationship(rel_type="ADCSESC1", category="domain_replication",
                         weight=6.0, walkable=True, note="cert abuse in our CA")


def _snapshot():
    return dict(ad_schema.EDGE_CATEGORIES), dict(risk.PROVISIONAL_WEIGHTS)


def test_overlay_restores_both_dicts_on_normal_exit():
    cats, weights = _snapshot()
    with overlay([ESC]):
        assert ad_schema.category_of("ADCSESC1") == "domain_replication"
        assert risk.weight_of("ADCSESC1") == 6.0
    assert dict(ad_schema.EDGE_CATEGORIES) == cats
    assert dict(risk.PROVISIONAL_WEIGHTS) == weights
    assert "ADCSESC1" not in ad_schema.EDGE_CATEGORIES


def test_overlay_restores_on_exception():
    cats, weights = _snapshot()
    with pytest.raises(RuntimeError):
        with overlay([ESC]):
            raise RuntimeError("boom")
    assert dict(ad_schema.EDGE_CATEGORIES) == cats
    assert dict(risk.PROVISIONAL_WEIGHTS) == weights


def test_a_custom_type_is_unsourced_so_the_coverage_gate_marks_it():
    with overlay([ESC]):
        w = risk.PROVISIONAL_WEIGHTS["ADCSESC1"]
        assert w.sourced is False
        assert w.source is None
        assert "ADCSESC1" in risk.unsourced()


def test_validate_refuses_to_reweight_an_existing_sourced_type():
    with pytest.raises(ValueError, match="already in the default schema"):
        validate(CustomRelationship("Owns", "acl_abuse", 1.0))


def test_validate_rejects_unknown_category_and_out_of_range_weight():
    with pytest.raises(ValueError, match="unknown category"):
        validate(CustomRelationship("Foo", "not_a_category", 4.0))
    with pytest.raises(ValueError, match="weight must be"):
        validate(CustomRelationship("Foo", "acl_abuse", 99.0))
    with pytest.raises(ValueError, match="name is required"):
        validate(CustomRelationship("  ", "acl_abuse", 4.0))


def test_duplicate_names_in_one_batch_are_refused():
    with pytest.raises(ValueError, match="share a name"):
        with overlay([ESC, CustomRelationship("ADCSESC1", "acl_abuse", 2.0)]):
            pass
    assert "ADCSESC1" not in ad_schema.EDGE_CATEGORIES   # aborted before mutating


def test_a_custom_edge_becomes_traversable_and_priced_end_to_end():
    """The actual use: a graph carrying a dropped type routes through it only
    inside the overlay, and only when the analyst marks it walkable."""
    from stealthpath.graph import AttackGraph, Edge, Node
    from stealthpath.planners.weighted_astar import astar
    from stealthpath.risk import static_cost_fn

    nodes = [Node(id="s", name="FOOTHOLD", kind="User"),
             Node(id="t", name="DOMAIN ADMINS@X", kind="Group")]
    g = AttackGraph(nodes, [Edge(0, 1, "ADCSESC1", {})])

    # Without the overlay the type is unknown: pricing it raises (build rule 4).
    with pytest.raises(KeyError):
        static_cost_fn()(g, 0, [])

    allowed = frozenset({"ADCSESC1"}) | walkable_types([ESC])
    with overlay([ESC]):
        path = astar(g, [0], [1], static_cost_fn(), allowed_rel_types=allowed,
                     max_hops=5)
        assert path is not None
        assert path.rel_types(g) == ["ADCSESC1"]
        assert path.cost == 6.0


def test_category_names_are_the_ten_real_categories():
    assert "acl_abuse" in CATEGORY_NAMES and "domain_replication" in CATEGORY_NAMES
    assert len(CATEGORY_NAMES) == 10
