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
    # --- group membership -------------------------------------------------
    # Free to traverse and essentially free to *observe*: membership is a
    # property of the directory, not an action. Expect near-zero detection cost
    # in Stage 3 — this is the main reason A* and Dijkstra may agree.
    "MemberOf": _C.GROUP_MEMBERSHIP,

    # --- local admin / remote execution -----------------------------------
    "AdminTo": _C.LOCAL_ADMIN,
    "CanRDP": _C.REMOTE_EXECUTION,
    "CanPSRemote": _C.REMOTE_EXECUTION,
    "ExecuteDCOM": _C.REMOTE_EXECUTION,
    "SQLAdmin": _C.REMOTE_EXECUTION,

    # --- sessions ---------------------------------------------------------
    # Traversal here means credential theft from a logged-on session.
    "HasSession": _C.SESSION,

    # --- ACL abuse --------------------------------------------------------
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

    # --- credential access ------------------------------------------------
    "ForceChangePassword": _C.CREDENTIAL_ACCESS,
    "ReadLAPSPassword": _C.CREDENTIAL_ACCESS,
    "SyncLAPSPassword": _C.CREDENTIAL_ACCESS,
    "ReadGMSAPassword": _C.CREDENTIAL_ACCESS,
    "DumpSMSAPassword": _C.CREDENTIAL_ACCESS,
    "HasSIDHistory": _C.CREDENTIAL_ACCESS,

    # --- delegation -------------------------------------------------------
    "AllowedToDelegate": _C.DELEGATION,
    "AllowedToAct": _C.DELEGATION,
    "AddAllowedToAct": _C.DELEGATION,

    # --- replication ------------------------------------------------------
    "DCSync": _C.DOMAIN_REPLICATION,
    "GetChanges": _C.DOMAIN_REPLICATION,
    "GetChangesAll": _C.DOMAIN_REPLICATION,
    "GetChangesInFilteredSet": _C.DOMAIN_REPLICATION,

    # --- structural / containment ----------------------------------------
    # These are directory structure, not attacker actions. Including them in a
    # path makes the path shorter but not meaningful, unless paired with a
    # GPO-abuse edge. Excluded from DEFAULT_TRAVERSAL_SET on purpose.
    "Contains": _C.STRUCTURAL,
    "GPLink": _C.STRUCTURAL,

    # --- trusts -----------------------------------------------------------
    "TrustedBy": _C.TRUST,
}

STRUCTURAL_EDGES = frozenset(
    r for r, c in EDGE_CATEGORIES.items() if c == _C.STRUCTURAL
)

TRAVERSABLE_EDGES = frozenset(EDGE_CATEGORIES) - STRUCTURAL_EDGES

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


# ---------------------------------------------------------------------------
# STAGE 2 WORKSHEET — Cyber Track fills this in, with a citation per row.
# ---------------------------------------------------------------------------
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
