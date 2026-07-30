"""
Synthetic AD attack graphs.

Why this exists: Stage 1's lab deployment is the slowest, most failure-prone
task in the project and it blocks everything. This module removes that
dependency for the software work. Everything downstream — A*, the visibility
model, the Gym environment, the statistics harness — can be built and tested
against a synthetic graph today and re-pointed at the real GOAD collection with
a one-line change, because both produce the same `AttackGraph` type.

What this is NOT: a substitute for real data. Any number that gets reported
anywhere must come from the real SharpHound collection. The synthetic graph is a
development fixture and a unit-test substrate. It is deliberately shaped like an
AD environment (tiered groups, delegation, ACL chains, cross-domain trust) but
its topology is invented — it tells you the code runs, never what the answer is.
Keep that distinction explicit anywhere results are recorded.

Two generators:
  * `goad_like()`     — small, hand-authored, deterministic. Use in tests.
  * `random_ad()`     — parameterised and seeded. Use for scaling experiments
                        and for checking planners don't overfit one topology.
"""

from __future__ import annotations

import random
from typing import Sequence

from .graph import AttackGraph, Node

__all__ = ["goad_like", "random_ad"]


def _n(graph: AttackGraph, oid: str, name: str, kind: str, domain: str,
       *, high_value: bool = False, owned: bool = False, **props) -> int:
    return graph.add_node(Node(id=oid, name=name, kind=kind, labels=(kind,),
                               domain=domain, high_value=high_value,
                               owned=owned, props=dict(props)))


def goad_like() -> AttackGraph:
    """A small three-domain environment loosely shaped like GOAD.

    Two domains in one forest plus a second forest reachable over a trust.
    Contains, by construction:
      * a long "quiet" route (group membership + LAPS read) to DA
      * a short "loud" route (session credential theft -> DCSync)
      * a delegation shortcut that only pays off if used once
      * one dead end, so planners have something to reject

    That structure is the point: if every route were equally noisy, Stages 2-4
    would have nothing to differentiate and the three planners would all return
    the same answer for the wrong reason.
    """
    g = AttackGraph()
    SK, NORTH, ESSOS = "SEVENKINGDOMS.LOCAL", "NORTH.SEVENKINGDOMS.LOCAL", "ESSOS.LOCAL"

    # --- domains -----------------------------------------------------------
    _n(g, "S-1-5-21-SK", SK, "Domain", SK)
    _n(g, "S-1-5-21-NORTH", NORTH, "Domain", NORTH)
    _n(g, "S-1-5-21-ESSOS", ESSOS, "Domain", ESSOS)

    # --- computers ---------------------------------------------------------
    _n(g, "C-KINGSLANDING", f"KINGSLANDING.{SK}", "Computer", SK,
       high_value=True, operatingsystem="Windows Server 2019", is_dc=True)
    _n(g, "C-WINTERFELL", f"WINTERFELL.{NORTH}", "Computer", NORTH,
       high_value=True, operatingsystem="Windows Server 2019", is_dc=True)
    _n(g, "C-MEEREEN", f"MEEREEN.{ESSOS}", "Computer", ESSOS,
       high_value=True, operatingsystem="Windows Server 2019", is_dc=True)
    _n(g, "C-CASTELBLACK", f"CASTELBLACK.{NORTH}", "Computer", NORTH,
       operatingsystem="Windows Server 2019", haslaps=True)
    _n(g, "C-BRAAVOS", f"BRAAVOS.{ESSOS}", "Computer", ESSOS,
       operatingsystem="Windows Server 2016")

    # --- groups ------------------------------------------------------------
    _n(g, "G-DA-SK", f"DOMAIN ADMINS@{SK}", "Group", SK, high_value=True, admincount=True)
    _n(g, "G-DA-NORTH", f"DOMAIN ADMINS@{NORTH}", "Group", NORTH, high_value=True, admincount=True)
    _n(g, "G-EA-SK", f"ENTERPRISE ADMINS@{SK}", "Group", SK, high_value=True, admincount=True)
    _n(g, "G-STARK", f"STARK@{NORTH}", "Group", NORTH)
    _n(g, "G-NIGHTWATCH", f"NIGHT WATCH@{NORTH}", "Group", NORTH)
    _n(g, "G-SUPPORT", f"HELPDESK@{NORTH}", "Group", NORTH)
    _n(g, "G-DRAGONS", f"DRAGONS@{ESSOS}", "Group", ESSOS)

    # --- users -------------------------------------------------------------
    _n(g, "U-SAMWELL", f"SAMWELL.TARLY@{NORTH}", "User", NORTH,
       owned=True, enabled=True)                     # <- the foothold
    _n(g, "U-JON", f"JON.SNOW@{NORTH}", "User", NORTH, enabled=True, hasspn=True)
    _n(g, "U-ARYA", f"ARYA.STARK@{NORTH}", "User", NORTH, enabled=True)
    _n(g, "U-EDDARD", f"EDDARD.STARK@{NORTH}", "User", NORTH, enabled=True, admincount=True)
    _n(g, "U-ROBERT", f"ROBERT.BARATHEON@{SK}", "User", SK, enabled=True, admincount=True)
    _n(g, "U-TYWIN", f"TYWIN.LANNISTER@{SK}", "User", SK, enabled=True)
    _n(g, "U-JORAH", f"JORAH.MORMONT@{ESSOS}", "User", ESSOS, enabled=True)
    _n(g, "U-SVC-BACKUP", f"SVC_BACKUP@{NORTH}", "User", NORTH, enabled=True, hasspn=True)
    _n(g, "U-STANNIS", f"STANNIS.BARATHEON@{SK}", "User", SK, enabled=False)  # dead end

    E = g.add_edge

    # --- route A: quiet. membership -> helpdesk -> LAPS -> admin -> DCSync --
    E("U-SAMWELL", "G-NIGHTWATCH", "MemberOf")
    E("G-NIGHTWATCH", "G-SUPPORT", "MemberOf")
    E("G-SUPPORT", "C-CASTELBLACK", "ReadLAPSPassword")
    E("C-CASTELBLACK", "U-SVC-BACKUP", "HasSession")
    E("U-SVC-BACKUP", "S-1-5-21-NORTH", "GetChanges")
    E("U-SVC-BACKUP", "S-1-5-21-NORTH", "GetChangesAll")
    E("U-SVC-BACKUP", "S-1-5-21-NORTH", "DCSync")
    E("S-1-5-21-NORTH", "G-DA-NORTH", "Contains")

    # --- route B: short but loud -------------------------------------------
    E("U-SAMWELL", "C-CASTELBLACK", "CanRDP")
    E("C-CASTELBLACK", "U-JON", "HasSession")
    E("U-JON", "G-STARK", "MemberOf")
    E("G-STARK", "U-EDDARD", "GenericAll")
    E("U-EDDARD", "G-DA-NORTH", "MemberOf")

    # --- route C: ACL chain, medium ----------------------------------------
    E("U-SAMWELL", "U-ARYA", "ForceChangePassword")
    E("U-ARYA", "G-STARK", "AddMember")
    E("U-ARYA", "U-JON", "AddKeyCredentialLink")

    # --- delegation shortcut -----------------------------------------------
    E("C-CASTELBLACK", "C-WINTERFELL", "AllowedToDelegate")
    E("C-WINTERFELL", "G-DA-NORTH", "AdminTo")

    # --- cross-forest / cross-domain ---------------------------------------
    E("G-DA-NORTH", "S-1-5-21-SK", "TrustedBy")
    E("S-1-5-21-SK", "G-EA-SK", "Contains")
    E("G-DA-NORTH", "G-DA-SK", "MemberOf")
    E("U-ROBERT", "G-DA-SK", "MemberOf")
    E("U-TYWIN", "C-KINGSLANDING", "AdminTo")
    E("U-JORAH", "G-DRAGONS", "MemberOf")
    E("G-DRAGONS", "C-MEEREEN", "CanPSRemote")
    E("C-BRAAVOS", "U-JORAH", "HasSession")

    # --- dead end -----------------------------------------------------------
    E("U-SAMWELL", "U-STANNIS", "GenericWrite")

    return g


_FIRST = ("jon", "arya", "sansa", "bran", "robb", "catelyn", "theon", "davos",
          "jaime", "cersei", "tyrion", "sandor", "brienne", "podrick", "gendry",
          "missandei", "grey", "varys", "petyr", "olenna", "margaery", "loras")
_ROLE = ("workstation", "server", "fileshare", "sql", "web", "jump", "print")


def random_ad(
    n_users: int = 60,
    n_computers: int = 20,
    n_groups: int = 12,
    *,
    domain: str = "LAB.LOCAL",
    seed: int = 0,
    n_owned: int = 2,
    ensure_path: bool = True,
) -> AttackGraph:
    """Generate a seeded pseudo-random AD graph.

    `ensure_path=True` guarantees at least one route from an owned user to
    Domain Admins, so planner tests can't fail spuriously on an unlucky seed.
    Set it False when you specifically want to test unreachable-target handling.
    """
    rng = random.Random(seed)
    g = AttackGraph()

    _n(g, "S-1-5-21-DOM", domain, "Domain", domain)
    _n(g, "G-DA", f"DOMAIN ADMINS@{domain}", "Group", domain,
       high_value=True, admincount=True)

    users = []
    for i in range(n_users):
        oid = f"U-{i:04d}"
        name = f"{rng.choice(_FIRST)}{i}@{domain}".upper()
        _n(g, oid, name, "User", domain, enabled=rng.random() > 0.08,
           hasspn=rng.random() < 0.15)
        users.append(oid)

    computers = []
    for i in range(n_computers):
        oid = f"C-{i:04d}"
        _n(g, oid, f"{rng.choice(_ROLE)}{i}.{domain}".upper(), "Computer", domain,
           haslaps=rng.random() < 0.5)
        computers.append(oid)

    groups = ["G-DA"]
    for i in range(n_groups):
        oid = f"G-{i:04d}"
        _n(g, oid, f"GROUP{i}@{domain}", "Group", domain)
        groups.append(oid)

    for oid in rng.sample(users, min(n_owned, len(users))):
        idx = g.index_of(oid)
        g.nodes[idx] = Node(**{**g.nodes[idx].__dict__, "owned": True})

    # membership: users -> groups, and a shallow group nesting tree
    for u in users:
        for grp in rng.sample(groups[1:], rng.randint(1, 3)):
            g.add_edge(u, grp, "MemberOf")
    for grp in groups[1:]:
        if rng.random() < 0.35:
            parent = rng.choice(groups[1:])
            if parent != grp:
                g.add_edge(grp, parent, "MemberOf")

    # access / execution
    for c in computers:
        for grp in rng.sample(groups[1:], rng.randint(0, 2)):
            g.add_edge(grp, c, rng.choice(["AdminTo", "CanRDP", "CanPSRemote"]))
        for u in rng.sample(users, rng.randint(0, 3)):
            g.add_edge(c, u, "HasSession")
        if g.node(c).props.get("haslaps") and rng.random() < 0.4:
            g.add_edge(rng.choice(groups[1:]), c, "ReadLAPSPassword")

    # ACL abuse
    acl = ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
           "ForceChangePassword", "AddMember", "AddKeyCredentialLink"]
    for _ in range(int(0.4 * (n_users + n_groups))):
        src = rng.choice(users + groups[1:])
        dst = rng.choice(users + groups[1:] + computers)
        if src != dst:
            g.add_edge(src, dst, rng.choice(acl))

    # delegation + replication
    for c in rng.sample(computers, max(1, n_computers // 8)):
        g.add_edge(c, rng.choice(computers), "AllowedToDelegate")
    for u in rng.sample(users, max(1, n_users // 25)):
        g.add_edge(u, "S-1-5-21-DOM", "GetChanges")
        g.add_edge(u, "S-1-5-21-DOM", "DCSync")
    g.add_edge("S-1-5-21-DOM", "G-DA", "Contains")

    if ensure_path:
        owned = g.entry_nodes()
        if owned:
            start = g.nodes[owned[0]].id
            mid_g, mid_c = rng.choice(groups[1:]), rng.choice(computers)
            g.add_edge(start, mid_g, "MemberOf")
            g.add_edge(mid_g, mid_c, "AdminTo")
            victim = rng.choice(users)
            g.add_edge(mid_c, victim, "HasSession")
            g.add_edge(victim, "G-DA", "MemberOf")

    return g
