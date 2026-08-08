"""Category (a): baseline-derived invariants.

**These are hand-written and must never be edited to agree with a weight.**
Every assertion here follows from the telemetry baseline in
`docs/stage2_joint_capability_audit.md` rather than from any particular number.
When one fails, **suspect the weight first.**

That rule exists because of what happened during the Shape D pass. Two ordering
tests were rewritten to match new weights, then rewritten back when the weights
were corrected — so at the moment the 1.5 error was live, the suite agreed with
it. A test updated to match the thing it is checking has stopped being a test.

Current numeric values live in `test_weight_snapshot.py`, generated from
`risk.py`. Nothing in *this* file may assert a specific weight.

What these catch, honestly: internal inconsistency and unanswered questions.
What they cannot catch: a confidently wrong answer. The 1.5 error was an
incomplete literature search that was internally consistent throughout, and no
invariant would have flagged it — only review did. `channels` narrows that gap
by making the omission structural rather than prose, but does not close it.
"""

from __future__ import annotations

import pytest

from stealthpath.ad_schema import DEFAULT_TRAVERSAL_SET
from stealthpath.risk import (
    ENDPOINT_HALF, NATIVE_HALF, NATIVE_SACL, PROVISIONAL_WEIGHTS,
    WEIGHT_CEILING, WEIGHT_FLOOR, unsourced,
)

SOURCED = {r: w for r, w in PROVISIONAL_WEIGHTS.items() if w.sourced}


# --------------------------------------------------- structural completeness

def test_sourced_weight_accounts_for_both_baseline_halves():
    """**The invariant written in response to the 1.5 error.**

    The baseline has two halves — native AD auditing and EDR/Sysmon-class
    endpoint telemetry. A weight derived from one half is not derived. Each
    sourced weight must name a channel in each half, using the NONE_FOUND values
    to record a half that was checked and came back empty.

    It forces the question to be answered. It cannot verify the answer.
    """
    for rel, w in SOURCED.items():
        assert set(w.channels) & NATIVE_HALF, (
            f"{rel} names no native-AD channel: was that half checked?")
        assert set(w.channels) & ENDPOINT_HALF, (
            f"{rel} names no endpoint channel — this is exactly the omission "
            f"that produced the 1.5 error on the Shape D edges.")


def test_sourced_weight_has_both_a_rationale_and_a_citation():
    """A rationale is reasoning; a source is evidence. Neither substitutes."""
    for rel, w in SOURCED.items():
        assert w.rationale.strip(), rel
        assert w.source and w.source.strip(), rel


# ------------------------------------------------- ordering that must hold

def test_a_sacl_only_weight_declares_a_tier_conditional():
    """If the only native channel needs a SACL, then on a non-tier-zero target
    that channel is silent — so the weight *must* split by tier, or it is
    asserting the same loudness for an audited and an unaudited object."""
    for rel, w in SOURCED.items():
        if NATIVE_SACL in w.channels:
            assert w.conditional and "target_is_tier_zero" in w.conditional, (
                f"{rel} rests on SACL-dependent auditing but has no tier "
                f"conditional")


def test_tier_zero_is_never_quieter_than_the_base():
    """Adding a detection channel cannot reduce loudness. The tier-zero branch
    is the base plus 5136, so it can only be louder or equal — never less."""
    for rel, w in SOURCED.items():
        if w.conditional and "target_is_tier_zero" in w.conditional:
            assert w.conditional["target_is_tier_zero"] >= w.weight, rel


def test_a_tooling_conditional_modelling_absence_is_never_louder():
    """`tooling_is_native_ldap` models an attacker who emits no endpoint
    artifact. Removing a signal cannot make an action louder."""
    for rel, w in SOURCED.items():
        if w.conditional and "tooling_is_native_ldap" in w.conditional:
            assert w.conditional["tooling_is_native_ldap"] <= w.weight, rel


def test_no_weight_is_free_and_none_exceeds_the_scale():
    """Zero would claim literal invisibility; the ceiling keeps the scale
    interpretable. Applies to conditionals too, which are easy to forget."""
    for rel, w in PROVISIONAL_WEIGHTS.items():
        values = [w.weight, *(w.conditional or {}).values()]
        for v in values:
            assert WEIGHT_FLOOR <= v <= WEIGHT_CEILING, f"{rel}: {v}"


def test_every_walkable_edge_is_priced():
    """A walkable edge with no weight raises at plan time, on real data, which
    is the worst place to discover it."""
    assert set(DEFAULT_TRAVERSAL_SET) <= set(PROVISIONAL_WEIGHTS)


# ------------------------------------------------------------- the gate

def test_require_sourced_still_blocks_a_mixed_table():
    """The dangerous state is *partial* sourcing, where a reported number mixes
    cited and invented weights. That is where the table is now."""
    from stealthpath.risk import require_sourced
    assert SOURCED, "no weight is sourced; the pass has not started"
    assert unsourced(), "all weights sourced — update this test and the docs"
    with pytest.raises(ValueError, match="no source"):
        require_sourced()
