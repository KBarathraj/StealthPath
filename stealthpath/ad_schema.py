"""
BloodHound/SharpHound schema constants: node kinds, relationship types, and
which relationships an attacker can actually *traverse*.

Scope note: this module is descriptive only. It records which relationship
types exist and groups them into coarse categories. It deliberately does **not**
assign risk weights or ATT&CK technique IDs — that is Stage 2 (Cyber Track), and
every one of those needs a real source behind it rather than a plausible guess.
The `ATTACK_MAPPING_STUB` at the bottom is a worksheet for that, not an answer.

Reference for relationship semantics: BloodHound's own edge documentation
(SpecterOps). Verify against the BloodHound version you actually collect with —
CE and legacy differ in a few edge names and in how high-value is marked.
"""

from __future__ import annotations

__all__ = [
    "NODE_KINDS",
    "EdgeCategory",
    "EDGE_CATEGORIES",
    "TRAVERSABLE_EDGES",
    "STRUCTURAL_EDGES",
    "PARTIAL_RIGHT_EDGES",
    "COMPOSITE_RIGHTS",
    "GPO_EXPANSION_EDGES",
    "LOCAL_ADMIN_EXPANSION_EDGES",
    "PRIVILEGED_LOCAL_GROUP_RIDS",
    "DEFAULT_TRAVERSAL_SET",
    "category_of",
    "ATTACK_MAPPING_STUB",
]

NODE_KINDS = (
    "User", "Computer", "Group", "Domain", "GPO", "OU", "Container",
)


class EdgeCategory:
    """Coarse buckets. Stage 3's visibility model will almost certainly want to
    reason at this granularity for some features (e.g. "how many *distinct*
    credential-access techniques has the attacker used?") even though the cost
    function is keyed on the specific relationship type."""

    GROUP_MEMBERSHIP = "group_membership"
    ACL_ABUSE = "acl_abuse"
    CREDENTIAL_ACCESS = "credential_access"
    REMOTE_EXECUTION = "remote_execution"
    SESSION = "session"
    DELEGATION = "delegation"
    DOMAIN_REPLICATION = "domain_replication"
    LOCAL_ADMIN = "local_admin"
    STRUCTURAL = "structural"
    TRUST = "trust"


_C = EdgeCategory

EDGE_CATEGORIES: dict[str, str] = {
    # Free to traverse and essentially free to *observe*: membership is a
    # property of the directory, not an action. Expect near-zero detection cost
    # in Stage 3 — this is the main reason A* and Dijkstra may agree.
    "MemberOf": _C.GROUP_MEMBERSHIP,

    "AdminTo": _C.LOCAL_ADMIN,
    "CanRDP": _C.REMOTE_EXECUTION,
    "CanPSRemote": _C.REMOTE_EXECUTION,
    "ExecuteDCOM": _C.REMOTE_EXECUTION,
    "SQLAdmin": _C.REMOTE_EXECUTION,

    # Traversal here means credential theft from a logged-on session.
    "HasSession": _C.SESSION,

    "GenericAll": _C.ACL_ABUSE,
    "GenericWrite": _C.ACL_ABUSE,
    "WriteDacl": _C.ACL_ABUSE,
    "WriteOwner": _C.ACL_ABUSE,
    "Owns": _C.ACL_ABUSE,
    "AddMember": _C.ACL_ABUSE,
    "AddSelf": _C.ACL_ABUSE,
    "WriteSPN": _C.ACL_ABUSE,
    "AddKeyCredentialLink": _C.ACL_ABUSE,
    "WriteAccountRestrictions": _C.ACL_ABUSE,
    "WriteGPLink": _C.ACL_ABUSE,

    "ForceChangePassword": _C.CREDENTIAL_ACCESS,
    "ReadLAPSPassword": _C.CREDENTIAL_ACCESS,
    "SyncLAPSPassword": _C.CREDENTIAL_ACCESS,
    "ReadGMSAPassword": _C.CREDENTIAL_ACCESS,
    "DumpSMSAPassword": _C.CREDENTIAL_ACCESS,
    "HasSIDHistory": _C.CREDENTIAL_ACCESS,

    "AllowedToDelegate": _C.DELEGATION,
    "AllowedToAct": _C.DELEGATION,
    "AddAllowedToAct": _C.DELEGATION,

    "DCSync": _C.DOMAIN_REPLICATION,
    "GetChanges": _C.DOMAIN_REPLICATION,
    "GetChangesAll": _C.DOMAIN_REPLICATION,
    "GetChangesInFilteredSet": _C.DOMAIN_REPLICATION,

    # These are directory structure, not attacker actions. Including them in a
    # path makes the path shorter but not meaningful, unless paired with a
    # GPO-abuse edge. Excluded from DEFAULT_TRAVERSAL_SET on purpose.
    "Contains": _C.STRUCTURAL,
    "GPLink": _C.STRUCTURAL,

    # `TrustedBy` was retired: current BloodHound does not emit it. SpecterOps
    # replaced the single catch-all with a set that separates the *existence* of
    # a trust from the *abuse* of one — SameForestTrust / CrossForestTrust carry
    # the relationship and its metadata, while AbuseTGTDelegation and
    # SpoofSIDHistory are the actual attacks across it.
    #
    # The first two are structural for the same reason Contains and GPLink are:
    # a trust existing is a fact about the directory, not a step an attacker
    # takes. Traversing one would let a planner cross a forest boundary for free
    # when the real crossing costs a specific, expensive technique.
    "SameForestTrust": _C.STRUCTURAL,
    "CrossForestTrust": _C.STRUCTURAL,

    # Traversable, unlike the two above: this is the attack *across* a trust
    # rather than the trust itself. Domain -> Domain, landing on a node already
    # in tier0_targets(). See the audit doc for what it understates, and
    # docs/stage3_risk_model_properties.md for the krbtgt precondition that a
    # static model cannot express.
    "SpoofSIDHistory": _C.TRUST,

    # BloodHound CE's local-admin model: Principal -MemberOfLocalGroup->
    # LocalGroup -LocalToComputer-> Computer. Where the local group is
    # Administrators, that chain is semantically `AdminTo`.
    #
    # Both are structural by default, and that is a safety decision rather than
    # a semantic one. `LocalToComputer` runs out of *every* local group on a
    # machine — Users, Guests, IIS_IUSRS, Pre-Windows 2000 Compatible Access —
    # not just the privileged ones. Admitting it wholesale would mean membership
    # in local `Users` reaches the computer, and since effectively every domain
    # account is in local Users on every machine, every principal would "reach"
    # every DC. Same failure as WriteGPLink, different door.
    #
    # `AttackGraph.with_local_admin_expansion()` re-admits the chain for the
    # privileged local groups only.
    "MemberOfLocalGroup": _C.STRUCTURAL,
    "LocalToComputer": _C.STRUCTURAL,
}
"""Note: `EdgeCategory.TRUST` currently has no members. It is kept for
`SpoofSIDHistory`, which is a genuine attacker action across a trust and is
pending a risk weight before it can be admitted — see the round report."""

STRUCTURAL_EDGES = frozenset(
    r for r, c in EDGE_CATEGORIES.items() if c == _C.STRUCTURAL
)

PARTIAL_RIGHT_EDGES = frozenset({
    "GetChanges", "GetChangesAll", "GetChangesInFilteredSet",
    "WriteGPLink",
})
"""Rights that are never sufficient on their own, so a planner must not walk them.

Traversing a half-right lets a planner claim a capability the attacker does not
have — and price it *cheaper* than the real thing, because one right costs less
than two. That combination, wrong and cheap, is what makes these actively
attractive to a cost-minimising search: it will seek them out.

Two different shapes end up here.

**Replication — two rights, one composite.** `GetChanges` + `GetChangesAll` is
DCSync; `GetChanges` + `GetChangesInFilteredSet` is the LAPS replication read.
Both halves run between the same two nodes, and BloodHound already emits the
sufficient combination as its own edge (`DCSync`, `SyncLAPSPassword`) for exactly
this reason. Excluding the halves loses nothing: the composite remains, walkable
and correctly priced.

**WriteGPLink — two rights, no composite.** Linking a GPO to an OU or domain
does nothing unless you separately control a GPO worth linking, and that control
is a different edge onto a *different node of a different kind* (an ACL right
onto a GPO). There is no `GPOAppliesTo`-style composite in BloodHound to fall
back on, so excluding this removes a capability rather than replacing it.

That is acceptable because the capability was never expressible anyway: holding
two rights out of one node simultaneously is not something a path can represent.
The only thing traversing `WriteGPLink` ever contributed was false routes — and
the worst was not the GPO chain but a *single hop*, since BloodHound permits a
domain object as a `WriteGPLink` target and domain objects are tier-0. One edge,
straight to full domain compromise, cheaper than DCSync. See
`test_writegplink_into_a_domain_is_not_a_route`.

The real GPO chain is unaffected: it runs `GenericWrite -> GPLink -> Contains`
onto an already-linked GPO and never touches `WriteGPLink`. See
`AttackGraph.with_gpo_expansion`.
"""

COMPOSITE_RIGHTS: dict[str, frozenset[str]] = {
    "DCSync": frozenset({"GetChanges", "GetChangesAll"}),
    "SyncLAPSPassword": frozenset({"GetChanges", "GetChangesInFilteredSet"}),
}
"""Composite edges, mapped to the component rights they subsume.

This is the prose in `PARTIAL_RIGHT_EDGES` above made machine-readable, not a
new claim — that docstring already states both pairings. It exists so an
invariant can check what the prose asserts: **a composite cannot be quieter than
a component it subsumes**, because exercising the composite means exercising the
component. See `test_no_composite_is_quieter_than_a_component_it_subsumes`.

It was written after that exact inversion went unnoticed. `GetChanges` and
`GetChangesAll` sat at 8.0 while `DCSync` was sourced down to 6.5 — halves
louder than the whole. Nothing caught it, and nothing *could* have: all three
components are non-traversable, so no route reads their weights and no `compare`
run can surface the contradiction. A weight nothing reads is a weight nothing
checks, which is what makes a static invariant the only available guard.

`WriteGPLink` is deliberately absent. It is in `PARTIAL_RIGHT_EDGES` for the
other reason documented above — there is no composite in BloodHound to map it
to — so it has no entry here and the invariant has nothing to say about it.
"""

TRAVERSABLE_EDGES = (frozenset(EDGE_CATEGORIES)
                     - STRUCTURAL_EDGES - PARTIAL_RIGHT_EDGES)
"""Relationship types a planner may actually walk.

Two exclusions, for two different reasons. `STRUCTURAL_EDGES` are directory
layout rather than actions. `PARTIAL_RIGHT_EDGES` are real rights that simply
are not sufficient alone, and have a composite edge representing the sufficient
combination.
"""

GPO_EXPANSION_EDGES = frozenset({"GPLink", "Contains"})
"""Structural edges re-admitted *only* for the GPO -> OU -> object expansion.

This is the scoped exception the note below anticipated. Controlling a GPO's
content is a real attack, but the effect only reaches actual objects by
following `GPLink` down to an OU and `Contains` down to what the OU holds — two
edges excluded by default precisely because, used generally, they invent
connectivity no attacker action corresponds to.

The exception is *contextual*, not a set membership change, and cannot be
expressed by widening a traversal set: `GPLink` is walkable only from a GPO, and
`Contains` only from an OU or Container. `AttackGraph.with_gpo_expansion()`
builds the view that enforces it. The general Domain -Contains-> group shortcut,
which is what rule 3 exists to block, stays blocked because its source is a
Domain rather than an OU.

Use `DEFAULT_TRAVERSAL_SET | GPO_EXPANSION_EDGES` as the traversal set when
planning over that view, never against a raw graph.
"""

LOCAL_ADMIN_EXPANSION_EDGES = frozenset({"MemberOfLocalGroup", "LocalToComputer"})
"""The local-group chain, re-admitted only for privileged local groups.

Paired with `PRIVILEGED_LOCAL_GROUP_RIDS` and
`AttackGraph.with_local_admin_expansion()`. Same shape as the GPO exception:
the edge types are fine, it is the *source* that decides whether walking them
means anything.
"""

PRIVILEGED_LOCAL_GROUP_RIDS = {
    "544": "Administrators",        # local admin -> price as AdminTo
    "555": "Remote Desktop Users",  # interactive logon -> price as CanRDP
}
"""Local groups whose membership actually confers access, by well-known RID.

Keyed on RID rather than name on purpose: BloodHound names these
`ADMINISTRATORS@DOMAIN`, but group names are localised in non-English
installations while `S-1-5-32-544` is not. The objectids in a real collection
look like `NORTH.SEVENKINGDOMS.LOCAL-S-1-5-32-544`.

Deliberately short. `Distributed COM Users` (562) is the obvious next candidate
and maps to ExecuteDCOM, but it is not present in the current collection so it
is left out rather than added speculatively.

**Sourcing note:** when the weights pass reaches these, membership of 544 prices
as `AdminTo` and 555 as `CanRDP` — the chain is those techniques, reached a
different way, not a new technique.
"""

DEFAULT_TRAVERSAL_SET = TRAVERSABLE_EDGES
"""What the planners traverse unless told otherwise.

Rationale for excluding Contains/GPLink by default: they inflate connectivity
without corresponding to an attacker action, which would make shortest-path
results look dramatically better than they are. If you later add explicit GPO
abuse, model it as a WriteGPLink/GenericWrite edge onto the GPO and re-include
GPLink only for the GPO->OU->object expansion. Write down whichever you choose —
every path length the tool produces depends on it.
"""


def category_of(rel_type: str) -> str:
    """Category for a relationship type; unknown types fall back to acl_abuse
    only if they look like ACLs, otherwise raise. Failing loudly is right here:
    a silently-uncategorised edge in Stage 3 would get a default cost and skew
    every result downstream."""
    try:
        return EDGE_CATEGORIES[rel_type]
    except KeyError:
        raise KeyError(
            f"Unknown relationship type {rel_type!r}. Add it to EDGE_CATEGORIES "
            f"before using it in a planner — do not let it default silently."
        ) from None


# STAGE 2 WORKSHEET — Cyber Track fills this in, with a citation per row.
#
# The weights themselves now live in `risk.py`, which is also where the verified
# `technique=` and `source=` fields belong once you have confirmed them. This
# table stays as the candidate-hint worksheet: it is where the guessing happens,
# risk.py is where the answers land.
#
# Every weight needs to trace to an ATT&CK technique ID, a specific Sigma rule,
# or a named detection writeup. Candidate techniques are noted below as
# *starting points for verification only* — several BloodHound edges map to more
# than one technique, or to none cleanly, and a few of these guesses will be
# wrong. Don't ship them unverified; a wrong weight here quietly changes every
# route the planners pick.
#
# Fill: rel_type -> (attack_technique_id, sigma_rule_or_source, static_weight)

ATTACK_MAPPING_STUB: dict[str, dict[str, str | None]] = {
    rel: {"technique": None, "source": None, "candidate_hint": hint}
    for rel, hint in {
        "MemberOf": "no action taken; likely weight ~0",
        "AdminTo": "T1078.002 Valid Accounts: Domain Accounts (verify)",
        "HasSession": "T1003 OS Credential Dumping (verify sub-technique)",
        "CanRDP": "T1021.001 Remote Services: RDP (verify)",
        "CanPSRemote": "T1021.006 Remote Services: WinRM (verify)",
        "ExecuteDCOM": "T1021.003 Remote Services: DCOM (verify)",
        "ForceChangePassword": "T1098 Account Manipulation (verify)",
        "AddMember": "T1098.007 Account Manipulation: Group Modification (verify)",
        "GenericAll": "multiple; depends on target object kind",
        "GenericWrite": "multiple; depends on target object kind",
        "WriteDacl": "T1222 File and Directory Permissions Modification? (weak fit)",
        "WriteOwner": "weak ATT&CK fit; may need a Sigma-only citation",
        "WriteSPN": "targeted Kerberoasting; see T1558.003 (verify)",
        "AddKeyCredentialLink": "Shadow Credentials; ATT&CK fit is poor, cite writeup",
        "ReadLAPSPassword": "T1555 Credentials from Password Stores (verify)",
        "ReadGMSAPassword": "T1555 (verify)",
        "AllowedToDelegate": "T1558.003 / constrained delegation abuse (verify)",
        "AllowedToAct": "RBCD abuse; likely needs a detection-writeup citation",
        "DCSync": "T1003.006 OS Credential Dumping: DCSync (high confidence)",
        "GetChanges": "component of DCSync",
        "GetChangesAll": "component of DCSync",
        "SQLAdmin": "T1078 Valid Accounts (verify)",
        "HasSIDHistory": "T1134.005 Access Token Manipulation: SID-History (verify)",
    }.items()
}
