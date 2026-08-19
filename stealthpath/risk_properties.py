"""
Executable form of the Stage 3 gate: `docs/stage3_risk_model_properties.md`.

These are the spec, written before the risk model exists. Each property is a
function that takes a cost function and a graph and either returns cleanly or
raises `PropertyViolation` naming what broke.

## Why functions rather than tests

Whoever builds the history-dependent model in Stage 3 needs to run these against
work in progress, repeatedly, without going through pytest. `tests/` wires them
up; this module is what you call from a scratch script at 2am.

## What they take

A **cost function** in the planners' shared signature —
`(graph, edge_index, path_so_far) -> float`. That is already the contract both
planners use and the one Stage 3's model is documented to adopt, so no new
abstraction is introduced here. `path_so_far` is a tuple of edge indices: the
attacker's history.

## What is deliberately not here yet

Properties over *route scores* (P3, P4, P8, P10, P11) need `P_detect`, a
combination rule that turns per-step risk into one number for a route. That does
not exist — the current weights are costs, not probabilities. Those properties
are stated in the doc and will land with the scorer.

P5 (target sensitivity) needs a severity ordering over targets. `tier0_targets()`
returns a set, not a ranking, so there is nothing to compare against yet.
"""

from __future__ import annotations

from typing import Callable, Sequence

from .ad_schema import DEFAULT_TRAVERSAL_SET
from .graph import AttackGraph, Edge, Node

__all__ = [
    "PropertyViolation",
    "CostFn",
    "route_cost",
    "check_p1_repetition_never_reduces_risk",
    "check_p2_first_repeat_is_strictly_louder",
    "check_p15_bounded_step",
    "check_p4_subsequence_monotonicity",
    "check_p5_target_sensitivity",
    "check_p6_static_reduction",
    "check_p7_static_ignores_history",
    "check_p9_strict_positivity",
    "check_p12_relabelling_invariance",
    "check_p13_locality",
    "check_p14_determinism",
    "check_all",
]

CostFn = Callable[[AttackGraph, int, Sequence[int]], float]


class PropertyViolation(AssertionError):
    """A structural property of the risk model does not hold.

    AssertionError subclass so a bare `assert check(...)` in a scratch script
    and a pytest run report the same way.
    """


def _walkable(graph: AttackGraph) -> list[int]:
    return [i for i, e in enumerate(graph.edges)
            if e.rel_type in DEFAULT_TRAVERSAL_SET]


def _histories(graph: AttackGraph, edge_index: int) -> list[tuple[int, ...]]:
    """A spread of plausible histories to probe a cost function with.

    Includes the empty history, an unrelated prior action, and the edge itself
    repeated — the last is what any history term should react to.
    """
    walkable = _walkable(graph)
    other = next((i for i in walkable if i != edge_index), edge_index)
    return [
        (),
        (other,),
        (edge_index,),
        (edge_index, edge_index),
        (other, edge_index, other),
    ]


def route_cost(cost: CostFn, graph: AttackGraph, route: Sequence[int]) -> float:
    """Total cost of a sequence of actions, each scored against what preceded it.

    This is what the planners accumulate into `Path.cost`. It is not `P_detect`
    — the combination rule that turns per-step risk into one bounded number does
    not exist yet — but the route-ordering properties (P4) only need a total, so
    they can be stated and enforced now rather than waiting for it.
    """
    total = 0.0
    for i, edge_index in enumerate(route):
        total += cost(graph, edge_index, tuple(route[:i]))
    return total


# -------------------------------------------------------------------- P4

def _subsequence_pairs(graph: AttackGraph) -> list[tuple[tuple[int, ...], tuple[int, ...]]]:
    """`(shorter, longer)` pairs where `shorter` is an order-preserving
    subsequence of `longer`.

    Built by deleting elements from a base sequence, which guarantees the
    subsequence relation by construction rather than by search. The sequences
    are histories, not walks: the model is a function of (edge, prior actions),
    and a history is just a list of what was done before.
    """
    walkable = _walkable(graph)[:6]
    if len(walkable) < 3:
        return []
    base = tuple(walkable)
    pairs = [(base[:i] + base[i + 1:], base) for i in range(len(base))]
    pairs.append((base[::2], base))
    pairs.append(((base[0],), base))
    pairs.append(((), base))
    # a repeated action, so history-dependent models are actually exercised
    doubled = base + base
    pairs.append((base, doubled))
    return pairs


def check_p4_subsequence_monotonicity(cost: CostFn, graph: AttackGraph) -> None:
    """**P4 — order-preserving sub-route monotonicity.**

    If A's actions appear in B in the same relative order — B may have extra
    actions anywhere around them — then `S(A) <= S(B)`.

    Stated over subsequences rather than multisets on purpose. Under a
    history-dependent model the order of shared actions changes their risk, so a
    same-multiset statement would be false the moment history matters. This form
    survives that: every action in A sees a history in B that is a superset of
    what it saw in A, so if history never *reduces* risk (P1) and no action is
    free (P9), B cannot come out cheaper.

    It also holds trivially under the static model, which is what makes it safe
    to enforce now: P6 guarantees the adaptive model reduces to the static one,
    so a violation here is a real defect in either regime rather than an
    artifact of testing the wrong one.
    """
    for shorter, longer in _subsequence_pairs(graph):
        a = route_cost(cost, graph, shorter)
        b = route_cost(cost, graph, longer)
        if a > b:
            raise PropertyViolation(
                f"P4: route {shorter} is an order-preserving subsequence of "
                f"{longer} but scored higher ({a!r} > {b!r}). Doing strictly "
                f"more, in the same order, cannot be quieter."
            )


# -------------------------------------------------------------------- P5

def _severity_probe() -> AttackGraph:
    """A minimal graph carrying one of each tier-0 target kind, reached by the
    *same* relationship type, so P5 compares like with like.

    Built here rather than taken from a fixture because no fixture happens to
    contain a comparable pair — `goad_like` has no walkable edge into Enterprise
    Admins at all, so a fixture-driven P5 would silently make zero comparisons
    and pass by doing nothing.
    """
    g = AttackGraph()
    g.add_node(Node("u", "ATTACKER@NORTH.LOCAL", "User", domain="NORTH.LOCAL", owned=True))
    g.add_node(Node("ea", "ENTERPRISE ADMINS@ROOT.LOCAL", "Group", domain="ROOT.LOCAL"))
    g.add_node(Node("da", "DOMAIN ADMINS@NORTH.LOCAL", "Group", domain="NORTH.LOCAL"))
    g.add_node(Node("dom", "NORTH.LOCAL", "Domain", domain="NORTH.LOCAL"))
    g.add_node(Node("da2", "DOMAIN ADMINS@OTHER.LOCAL", "Group", domain="OTHER.LOCAL"))
    for target in ("ea", "da", "dom", "da2"):
        g.add_edge("u", target, "MemberOf")
    return g


def check_p5_target_sensitivity(cost: CostFn) -> int:
    """**P5 — the same technique against a more sensitive target never scores
    lower.**

    Severity is `AttackGraph.compare_target_severity`, a deliberate *partial*
    order: Enterprise Admins outranks everything; within a domain the DA group
    and the domain object are tied; across domains targets are incomparable.
    Only strictly-ordered pairs constrain anything — ties and incomparable pairs
    impose nothing, which is the point of not inventing an ordering for them.

    Returns the number of comparisons actually made, so callers can assert the
    check wasn't vacuous.
    """
    graph = _severity_probe()
    compared = 0
    for i, ei in enumerate(range(len(graph.edges))):
        for ej in range(len(graph.edges)):
            if ei == ej:
                continue
            order = graph.compare_target_severity(graph.edges[ei].target,
                                                  graph.edges[ej].target)
            if order != 1:
                continue
            compared += 1
            more = cost(graph, ei, ())
            less = cost(graph, ej, ())
            if more < less:
                raise PropertyViolation(
                    f"P5: {graph.node(graph.edges[ei].target).name} outranks "
                    f"{graph.node(graph.edges[ej].target).name}, but the same "
                    f"{graph.edges[ei].rel_type} scored lower against it "
                    f"({more!r} < {less!r})."
                )
    if compared == 0:
        raise PropertyViolation(
            "P5 made no comparisons — the probe graph no longer contains a "
            "strictly-ordered target pair, so this check is passing by doing "
            "nothing. Fix the probe, don't trust the pass."
        )
    return compared


# ---------------------------------------------------------------- P6 and P7

def check_p6_static_reduction(static: CostFn, adaptive_history_disabled: CostFn,
                              graph: AttackGraph) -> None:
    """**P6 — exact static reduction.**

    With its history term disabled, the adaptive model must reproduce the static
    model *exactly* on the same base weights. Not approximately.

    This is the property whose failure is worst, because it is invisible in
    results. If the two regimes are secretly different models — different base
    weights, a stray normalisation, a different action set — then every
    comparison between them measures the gap between two implementations rather
    than the effect of history, and the output looks entirely reasonable either
    way.

    Exact equality is deliberate. A tolerance here would hide precisely the
    small systematic offset this is meant to catch.
    """
    for ei in _walkable(graph):
        for history in _histories(graph, ei):
            a = static(graph, ei, history)
            b = adaptive_history_disabled(graph, ei, history)
            if a != b:
                raise PropertyViolation(
                    f"P6: adaptive-with-history-disabled disagrees with static on "
                    f"edge {ei} ({graph.edges[ei].rel_type}, history={history}): "
                    f"static={a!r} adaptive={b!r}. The two regimes are not the "
                    f"same model, so any comparison between them measures the "
                    f"implementation difference, not the effect of history."
                )


def check_p7_static_ignores_history(static: CostFn, graph: AttackGraph) -> None:
    """**P7 — under the static regime, history must not matter at all.**

    Score each edge against a spread of histories; every answer must be
    identical. Catches a history term that is nominally disabled but still
    leaking through a shared code path.
    """
    for ei in _walkable(graph):
        baseline = static(graph, ei, ())
        for history in _histories(graph, ei):
            got = static(graph, ei, history)
            if got != baseline:
                raise PropertyViolation(
                    f"P7: static cost for edge {ei} ({graph.edges[ei].rel_type}) "
                    f"changed with history {history}: {baseline!r} -> {got!r}. "
                    f"The static regime must be history-independent by "
                    f"construction, not by convention."
                )


# -------------------------------------------------------------------- P9

def check_p9_strict_positivity(cost: CostFn, graph: AttackGraph) -> None:
    """**P9 — every action carries risk > 0.**

    Zero would claim a technique is literally invisible, which is a stronger
    claim than anything in the schema can support. Also guards the planners:
    a genuine zero lets a route accumulate unlimited free hops.
    """
    for ei in _walkable(graph):
        for history in _histories(graph, ei):
            value = cost(graph, ei, history)
            if not value > 0:
                raise PropertyViolation(
                    f"P9: edge {ei} ({graph.edges[ei].rel_type}) scored {value!r} "
                    f"with history {history}; every action must carry risk > 0."
                )


# -------------------------------------------------------------------- P12

def _relabelled(graph: AttackGraph) -> tuple[AttackGraph, dict[int, int]]:
    """The same graph with node and edge order reversed.

    A permutation is enough to expose index dependence, and reversal is a
    permutation that needs no RNG — so this property stays deterministic.
    """
    n = len(graph.nodes)
    remap = {old: n - 1 - old for old in range(n)}
    nodes = list(reversed(graph.nodes))
    edges = [Edge(remap[e.source], remap[e.target], e.rel_type, dict(e.props))
             for e in reversed(graph.edges)]
    return AttackGraph(nodes, edges), remap


def check_p12_relabelling_invariance(cost: CostFn, graph: AttackGraph) -> None:
    """**P12 — permuting node indices must not change any score.**

    Motivated directly by a real artifact in this repo: plain shortest path
    breaks equal-cost ties by edge index, so the headline planner comparison is
    sensitive to edge *insertion order*. That is defensible in a planner's
    tie-break. In the risk model it would mean scores depend on the order
    SharpHound happened to return rows — which is not a property of the
    environment being modelled.
    """
    flipped, _ = _relabelled(graph)
    n_edges = len(graph.edges)
    for ei in _walkable(graph):
        mirrored = n_edges - 1 - ei
        before = cost(graph, ei, ())
        after = cost(flipped, mirrored, ())
        if before != after:
            raise PropertyViolation(
                f"P12: edge {ei} ({graph.edges[ei].rel_type}) scored {before!r} "
                f"but {after!r} after relabelling. The model depends on node or "
                f"edge index, which is an artifact of collection order rather "
                f"than anything about the environment."
            )


# -------------------------------------------------------------------- P13

def check_p13_locality(cost: CostFn, graph: AttackGraph) -> None:
    """**P13 — an unrelated edge elsewhere must not change a route's score.**

    Adds an isolated pair of nodes joined by a walkable edge, then re-scores
    every original edge. Catches dependence on global graph statistics — an
    average, a count, a normalisation over all edges — which would make every
    score a function of collection scope rather than of the action.
    """
    extended = AttackGraph(list(graph.nodes), list(graph.edges),
                           provenance=dict(graph.provenance))
    a = extended.add_node(Node("p13-isolated-a", "P13-A", "User"))
    b = extended.add_node(Node("p13-isolated-b", "P13-B", "Group"))
    extended.add_edge(a, b, "MemberOf")

    for ei in _walkable(graph):
        before = cost(graph, ei, ())
        after = cost(extended, ei, ())
        if before != after:
            raise PropertyViolation(
                f"P13: edge {ei} ({graph.edges[ei].rel_type}) scored {before!r}, "
                f"then {after!r} after an unrelated node pair was added "
                f"elsewhere. The model depends on global graph statistics, so "
                f"every score is a function of how much was collected."
            )


# -------------------------------------------------------------------- P14

def check_p14_determinism(cost: CostFn, graph: AttackGraph, repeats: int = 5) -> None:
    """**P14 — same input, same score, every time.**

    Project-wide rule; stated here so the risk model is explicitly covered by it
    rather than covered by assumption.
    """
    for ei in _walkable(graph):
        for history in _histories(graph, ei):
            seen = {cost(graph, ei, history) for _ in range(repeats)}
            if len(seen) != 1:
                raise PropertyViolation(
                    f"P14: edge {ei} ({graph.edges[ei].rel_type}) with history "
                    f"{history} produced {sorted(seen)!r} across {repeats} calls."
                )


# ------------------------------------------------------------ P1, P2, P15
#
# The three that needed the history-dependent model to exist. They are written
# here in the same form as the other six — a function over a cost function —
# rather than as tests, so the model can be probed from a scratch script.

def _extensions(graph: AttackGraph, edge_index: int
                ) -> list[tuple[tuple[int, ...], int]]:
    """`(history, one_more_action)` pairs for probing single-step changes.

    P1 and P15 both ask what happens when *one* action is appended, so they
    share the probe rather than each inventing histories.
    """
    walkable = _walkable(graph)
    other = next((i for i in walkable if i != edge_index), edge_index)
    return [
        ((), edge_index),
        ((), other),
        ((other,), edge_index),
        ((edge_index,), edge_index),
        ((edge_index,), other),
        ((other, edge_index), edge_index),
    ]


def check_p1_repetition_never_reduces_risk(cost: CostFn, graph: AttackGraph) -> None:
    """**P1 — doing more can never make the next action cheaper.**

    `V(e, h + [a]) >= V(e, h)` for any prior action `a`.

    Without it the model can be gamed by padding: a planner would insert extra
    actions to *reduce* the cost of the one it actually wants, which inverts the
    objective the whole project is measuring. Note this is the property a
    normalisation bug produces most easily — dividing by route length looks
    reasonable and violates this immediately.
    """
    for ei in _walkable(graph):
        for history, extra in _extensions(graph, ei):
            before = cost(graph, ei, history)
            after = cost(graph, ei, tuple(history) + (extra,))
            if after < before:
                raise PropertyViolation(
                    f"P1: edge {ei} ({graph.edges[ei].rel_type}) got *cheaper* "
                    f"when action {extra} was appended to history {history}: "
                    f"{before!r} -> {after!r}. A model that rewards padding "
                    f"inverts the objective."
                )


def check_p2_first_repeat_is_strictly_louder(cost: CostFn,
                                             graph: AttackGraph) -> int:
    """**P2 — repeating a technique category for the first time is strictly louder.**

    `V(e, h + [e]) > V(e, h)` when `h` holds nothing of `e`'s category, and
    non-decreasing thereafter.

    *Restated form.* The original demanded a strict increase on **every** repeat,
    which is unsatisfiable under Summary A: the state carries one bit per
    category, so the second and third uses are indistinguishable and must score
    equal. What the property is for survives — the adaptive model must not
    silently degenerate into the static one.

    **This is the one property a static model must fail.** Do not run it against
    the static regime expecting a pass; `check_all` only applies it to a model
    passed as `adaptive`.

    Returns the number of edges compared, and raises if that is zero — a probe
    graph with nothing walkable would otherwise pass by doing nothing.
    """
    compared = 0
    for ei in _walkable(graph):
        first = cost(graph, ei, ())
        second = cost(graph, ei, (ei,))
        third = cost(graph, ei, (ei, ei))
        compared += 1
        if not second > first:
            raise PropertyViolation(
                f"P2: edge {ei} ({graph.edges[ei].rel_type}) cost {second!r} on "
                f"the first repeat of its category against {first!r} fresh — not "
                f"strictly louder. The adaptive model has degenerated into the "
                f"static one for this edge."
            )
        if third < second:
            raise PropertyViolation(
                f"P2: edge {ei} ({graph.edges[ei].rel_type}) fell from {second!r} "
                f"to {third!r} on a later repeat; the term must be "
                f"non-decreasing after the first."
            )
    if compared == 0:
        raise PropertyViolation(
            "P2 made no comparisons — no walkable edges in the probe graph, so "
            "this check is passing by doing nothing. Fix the probe."
        )
    return compared


def check_p15_bounded_step(cost: CostFn, graph: AttackGraph, *,
                           max_step: float) -> None:
    """**P15 — no single repetition may move the score by more than `max_step`.**

    *Renamed from "gradient, not cliff".* Under Summary A there is no gradient
    available — one bit per category can only produce a step — so the old name
    described a shape the model cannot have. What survives is that the step be
    bounded.

    The reason is a threat to the project's own conclusion. If the history
    penalty is tuned steeply enough, the adaptive planner beats the static one
    trivially by avoiding a cliff that was placed there by hand. That would look
    exactly like a positive result for H3 and would be an artifact of tuning.

    `max_step` is supplied by the caller rather than read from the risk model, so
    this module stays a spec over cost functions and does not import the thing it
    checks. See `risk.max_repeat_step` for how it is derived, and note it is a
    bound against the weight ceiling, not a measurement of today's model.
    """
    for ei in _walkable(graph):
        for history, extra in _extensions(graph, ei):
            before = cost(graph, ei, history)
            after = cost(graph, ei, tuple(history) + (extra,))
            if abs(after - before) > max_step:
                raise PropertyViolation(
                    f"P15: edge {ei} ({graph.edges[ei].rel_type}) moved "
                    f"{before!r} -> {after!r} on one appended action "
                    f"(|Δ| = {abs(after - before)!r}), exceeding the declared "
                    f"bound of {max_step!r}. A step this size lets the adaptive "
                    f"planner win by avoiding a hand-placed cliff."
                )


# -------------------------------------------------------------------- runner

def check_all(cost: CostFn, graph: AttackGraph, *,
              static: CostFn | None = None,
              adaptive: CostFn | None = None,
              max_step: float | None = None) -> list[str]:
    """Run every property that applies to a single cost function.

    Returns the names of the properties that passed. Three of them need more
    than one model or an extra number, so they are opt-in:

    - `static` — enables P6 and P7. Pass the static cost function and make
      `cost` the adaptive one *with its history term disabled*.
    - `adaptive` — enables P2, which a static model must fail by definition. Pass
      the genuinely history-dependent model here, not the disabled one.
    - `max_step` — enables P15, which needs a declared bound. See
      `risk.max_repeat_step`.

    Raises on the first violation rather than collecting them: a model that
    fails one of these is not in a state where the remaining answers mean
    anything.
    """
    ran = []
    check_p5_target_sensitivity(cost)
    ran.append("P5 target sensitivity")
    for name, check in (
        ("P1 repetition never reduces risk", check_p1_repetition_never_reduces_risk),
        ("P4 subsequence monotonicity", check_p4_subsequence_monotonicity),
        ("P9 strict positivity", check_p9_strict_positivity),
        ("P12 relabelling invariance", check_p12_relabelling_invariance),
        ("P13 locality", check_p13_locality),
        ("P14 determinism", check_p14_determinism),
    ):
        check(cost, graph)
        ran.append(name)

    if static is not None:
        check_p6_static_reduction(static, cost, graph)
        ran.append("P6 exact static reduction")
        check_p7_static_ignores_history(static, graph)
        ran.append("P7 static ignores history")
    if adaptive is not None:
        check_p1_repetition_never_reduces_risk(adaptive, graph)
        check_p2_first_repeat_is_strictly_louder(adaptive, graph)
        ran.append("P2 first repeat strictly louder")
    if max_step is not None:
        check_p15_bounded_step(adaptive or cost, graph, max_step=max_step)
        ran.append("P15 bounded step")
    return ran
