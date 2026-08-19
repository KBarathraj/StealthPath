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

__all__ = ["goad_like", "random_ad", "gpo_abuse", "rbcd_abuse"]


def _n(graph: AttackGraph, oid: str, name: str, kind: str, domain: str,
       *, high_value: bool = False, owned: bool = False, **props) -> int:
    return graph.add_node(Node(id=oid, name=name, kind=kind, labels=(kind,),
                               domain=domain, high_value=high_value,
                               owned=owned, props=dict(props)))


def goad_like() -> AttackGraph:
    """A small three-domain environment loosely shaped like GOAD.

    Two domains in one forest, plus a third in a separate forest.

    **The ESSOS forest is unreachable from the foothold**, and that is correct
    rather than an oversight. Trust edges are structural — a trust existing is a
    fact about the directory, not a step — so crossing a forest boundary needs a
    real technique (`SpoofSIDHistory`, `AbuseTGTDelegation`), none of which this
    fixture has. ESSOS is there as an unreachable component, which is a useful
    thing for a planner to have to reject. `DOMAIN ADMINS@SEVENKINGDOMS` *is*
    reachable, via cross-domain group nesting rather than via the trust.

    What it actually contains:

      * a quiet **opening** — group membership x2 then a LAPS read (2.7 combined
        under the current weights) — which lands on CASTELBLACK
      * a delegation shortcut off CASTELBLACK (AllowedToDelegate -> AdminTo)
        that reaches the DA group in two more hops
      * a short **loud** route: CanRDP straight onto CASTELBLACK, then session
        credential theft, then replication onto the domain object
      * a mid-cost ACL chain (ForceChangePassword -> AddMember / shadow creds)
      * one dead end (STANNIS, disabled), so planners have something to reject

    The quiet opening and the loud opening converge on the same host, which is
    what makes the fixture discriminating: both planners can reach a target,
    and they disagree about how to get in.

    **There is no route that is quiet the whole way.** Every route to a tier-0
    target pays at least one expensive action — delegation, session theft, or
    replication. In particular the membership+LAPS chain does *not* continue
    quietly: its own continuation (HasSession -> DCSync onto the domain) is the
    loudest tail here. An earlier version of this docstring claimed a "long
    quiet route to DA"; no such route exists, and it never did.

    That is arguably realistic — real tier-0 usually costs something — but it is
    a property of this fixture, not a law, and anything that assumes a
    free-and-quiet route exists will be wrong on it.

    Known gap: the fixture exercises 16 of the 29 walkable relationship types.
    Absent are most of the delegation-write, SPN-write and less common
    credential-read edges (AddAllowedToAct, AllowedToAct, WriteSPN, WriteOwner,
    WriteGPLink, ReadGMSAPassword, SyncLAPSPassword, DumpSMSAPassword, AddSelf,
    HasSIDHistory, ExecuteDCOM, SQLAdmin, WriteAccountRestrictions). It is a
    development substrate, not a coverage matrix. Anything that needs a specific
    edge type present should assert that rather than assume it.

    The shape is the point: if every route were equally noisy, Stages 2-4 would
    have nothing to differentiate and the three planners would all return the
    same answer for the wrong reason.
    """
    g = AttackGraph()
    SK, NORTH, ESSOS = "SEVENKINGDOMS.LOCAL", "NORTH.SEVENKINGDOMS.LOCAL", "ESSOS.LOCAL"

    _n(g, "S-1-5-21-SK", SK, "Domain", SK)
    _n(g, "S-1-5-21-NORTH", NORTH, "Domain", NORTH)
    _n(g, "S-1-5-21-ESSOS", ESSOS, "Domain", ESSOS)

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

    _n(g, "G-DA-SK", f"DOMAIN ADMINS@{SK}", "Group", SK, high_value=True, admincount=True)
    _n(g, "G-DA-NORTH", f"DOMAIN ADMINS@{NORTH}", "Group", NORTH, high_value=True, admincount=True)
    _n(g, "G-EA-SK", f"ENTERPRISE ADMINS@{SK}", "Group", SK, high_value=True, admincount=True)
    _n(g, "G-STARK", f"STARK@{NORTH}", "Group", NORTH)
    _n(g, "G-NIGHTWATCH", f"NIGHT WATCH@{NORTH}", "Group", NORTH)
    _n(g, "G-SUPPORT", f"HELPDESK@{NORTH}", "Group", NORTH)
    _n(g, "G-DRAGONS", f"DRAGONS@{ESSOS}", "Group", ESSOS)

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

    # route A: quiet. membership -> helpdesk -> LAPS -> admin -> DCSync
    E("U-SAMWELL", "G-NIGHTWATCH", "MemberOf")
    E("G-NIGHTWATCH", "G-SUPPORT", "MemberOf")
    E("G-SUPPORT", "C-CASTELBLACK", "ReadLAPSPassword")
    E("C-CASTELBLACK", "U-SVC-BACKUP", "HasSession")
    E("U-SVC-BACKUP", "S-1-5-21-NORTH", "GetChanges")
    E("U-SVC-BACKUP", "S-1-5-21-NORTH", "GetChangesAll")
    E("U-SVC-BACKUP", "S-1-5-21-NORTH", "DCSync")
    E("S-1-5-21-NORTH", "G-DA-NORTH", "Contains")

    # route B: short but loud
    E("U-SAMWELL", "C-CASTELBLACK", "CanRDP")
    E("C-CASTELBLACK", "U-JON", "HasSession")
    E("U-JON", "G-STARK", "MemberOf")
    E("G-STARK", "U-EDDARD", "GenericAll")
    E("U-EDDARD", "G-DA-NORTH", "MemberOf")

    # route C: ACL chain, medium
    E("U-SAMWELL", "U-ARYA", "ForceChangePassword")
    E("U-ARYA", "G-STARK", "AddMember")
    E("U-ARYA", "U-JON", "AddKeyCredentialLink")

    # delegation shortcut
    E("C-CASTELBLACK", "C-WINTERFELL", "AllowedToDelegate")
    E("C-WINTERFELL", "G-DA-NORTH", "AdminTo")

    # Domain -> Domain, matching what BloodHound actually emits. The previous
    # `G-DA-NORTH -TrustedBy-> SEVENKINGDOMS` edge was wrong twice over: the
    # type was retired from BloodHound's model, and a trust runs between domains
    # rather than out of a group. Both directions, because the real GOADv2
    # collection has them bidirectional.
    E("S-1-5-21-SK", "S-1-5-21-NORTH", "SameForestTrust")     # parent -> child
    E("S-1-5-21-NORTH", "S-1-5-21-SK", "SameForestTrust")
    E("S-1-5-21-SK", "S-1-5-21-ESSOS", "CrossForestTrust")    # separate forest
    E("S-1-5-21-ESSOS", "S-1-5-21-SK", "CrossForestTrust")

    E("S-1-5-21-SK", "G-EA-SK", "Contains")
    E("G-DA-NORTH", "G-DA-SK", "MemberOf")
    E("U-ROBERT", "G-DA-SK", "MemberOf")
    E("U-TYWIN", "C-KINGSLANDING", "AdminTo")
    E("U-JORAH", "G-DRAGONS", "MemberOf")
    E("G-DRAGONS", "C-MEEREEN", "CanPSRemote")
    E("C-BRAAVOS", "U-JORAH", "HasSession")
    # Owns / WriteDacl exist so the fixture covers the ACL edge types the CLI's
    # collection-completeness check looks for. Placed inside ESSOS, which no
    # route from the NORTH foothold enters, so they add edge-type coverage
    # without changing any planner result. Deliberate: the fixture's topology
    # should be shaped by AD realism, never by what makes a number come out.
    E("U-JORAH", "C-BRAAVOS", "Owns")
    E("G-DRAGONS", "U-JORAH", "WriteDacl")

    # dead end
    E("U-SAMWELL", "U-STANNIS", "GenericWrite")

    return g


def gpo_abuse() -> AttackGraph:
    """A deliberately tiny graph for one thing: the GPO -> OU -> object chain.

    Separate from `goad_like()` on purpose. Retrofitting GPO structure into the
    main fixture would move every existing route and re-open questions that are
    already settled; a six-node graph that exists to pin one behaviour cannot.

    Two principals, so the joint-capability point is testable rather than
    asserted:

      * `SANSA` controls the GPO's **content** (`GenericWrite` onto the GPO),
        and the GPO is already linked to the OU. She reaches the workstation.
      * `THEON` holds `WriteGPLink` on the OU and nothing else. He can attach a
        policy but controls none worth attaching, so he reaches nothing — the
        same shape as holding `GetChanges` without `GetChangesAll`.

    Both edges are present in the graph either way. The difference is entirely
    in what the traversal rules will walk.
    """
    g = AttackGraph()
    DOM = "LAB.LOCAL"

    _n(g, "U-SANSA", f"SANSA.STARK@{DOM}", "User", DOM, owned=True, enabled=True)
    _n(g, "U-THEON", f"THEON.GREYJOY@{DOM}", "User", DOM, owned=True, enabled=True)
    _n(g, "GPO-BASELINE", f"WORKSTATION BASELINE@{DOM}", "GPO", DOM)
    _n(g, "OU-WORKSTATIONS", f"OU=WORKSTATIONS,DC=LAB,DC=LOCAL", "OU", DOM)
    _n(g, "C-DESK01", f"DESK01.{DOM}", "Computer", DOM, high_value=True)
    _n(g, "S-1-5-21-LAB", DOM, "Domain", DOM)
    _n(g, "G-DA", f"DOMAIN ADMINS@{DOM}", "Group", DOM, high_value=True)

    E = g.add_edge
    E("U-SANSA", "GPO-BASELINE", "GenericWrite")   # controls the policy content
    E("U-THEON", "OU-WORKSTATIONS", "WriteGPLink")  # can link, controls nothing
    E("GPO-BASELINE", "OU-WORKSTATIONS", "GPLink")  # policy already applies here
    E("OU-WORKSTATIONS", "C-DESK01", "Contains")

    # The shortcut rule 3 exists to block, present so the scoped exception can
    # be shown *not* to re-open it: this Contains has a Domain as its source.
    E("S-1-5-21-LAB", "G-DA", "Contains")

    return g


def rbcd_abuse(machine_account_quota: int = 0) -> AttackGraph:
    """A tiny graph for the RBCD precondition, separate for the same reason
    `gpo_abuse` is: neither main fixture contains a single RBCD edge, and no
    fixture carries `machineaccountquota` at all.

    Three principals holding the identical `AddAllowedToAct` right, differing
    only in whether they can wield it:

      * `PLAIN` — a user with no SPN. Cannot request S4U2Proxy.
      * `SVC`   — a user with an SPN. Can.
      * `WKS01` — a computer, so it has an SPN by definition. Can.

    Pass a non-zero `machine_account_quota` to model a domain where anyone can
    create a computer account, which makes the precondition moot and should
    re-admit `PLAIN`.
    """
    g = AttackGraph()
    DOM = "LAB.LOCAL"

    _n(g, "S-1-5-21-LAB", DOM, "Domain", DOM, machineaccountquota=machine_account_quota)
    _n(g, "U-PLAIN", f"PLAIN.USER@{DOM}", "User", DOM, owned=True, enabled=True)
    _n(g, "U-SVC", f"SVC_WEB@{DOM}", "User", DOM, owned=True, enabled=True, hasspn=True)
    _n(g, "C-WKS01", f"WKS01.{DOM}", "Computer", DOM)
    _n(g, "C-TARGET", f"TARGET.{DOM}", "Computer", DOM, high_value=True)

    for source in ("U-PLAIN", "U-SVC", "C-WKS01"):
        g.add_edge(source, "C-TARGET", "AddAllowedToAct")
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

    for c in computers:
        for grp in rng.sample(groups[1:], rng.randint(0, 2)):
            g.add_edge(grp, c, rng.choice(["AdminTo", "CanRDP", "CanPSRemote"]))
        for u in rng.sample(users, rng.randint(0, 3)):
            g.add_edge(c, u, "HasSession")
        if g.node(c).props.get("haslaps") and rng.random() < 0.4:
            g.add_edge(rng.choice(groups[1:]), c, "ReadLAPSPassword")

    # Domain Admins must be reachable by the same mechanisms as any other group.
    # Every `groups[1:]` slice above excludes it (it is index 0), so nothing
    # ever pointed at it and the only route to DA was whatever `ensure_path`
    # bolted on below. That gave every generated graph exactly one path to the
    # target, which made both planners return it and "agree" — an artifact of
    # the generator that reads exactly like a result about the planners.
    # Kept rare deliberately. A group nested *inside* Domain Admins is a serious
    # real-world misconfiguration, not the normal case — and because MemberOf is
    # near-free, one of these creates a short route that is also the cheapest,
    # which flattens any difference between the planners. Rare here means the
    # common route to DA is an ACL right over the group (AddMember, GenericAll,
    # WriteDacl), which is both more realistic and actually costs something.
    for grp in groups[1:]:
        if rng.random() < 0.03:
            g.add_edge(grp, "G-DA", "MemberOf")

    acl = ["GenericAll", "GenericWrite", "WriteDacl", "WriteOwner", "Owns",
           "ForceChangePassword", "AddMember", "AddKeyCredentialLink"]
    for _ in range(int(0.4 * (n_users + n_groups))):
        src = rng.choice(users + groups[1:])
        dst = rng.choice(users + groups + computers)   # `groups`, so DA included
        if src != dst:
            g.add_edge(src, dst, rng.choice(acl))

    for c in rng.sample(computers, max(1, n_computers // 8)):
        g.add_edge(c, rng.choice(computers), "AllowedToDelegate")
    for u in rng.sample(users, max(1, n_users // 25)):
        g.add_edge(u, "S-1-5-21-DOM", "GetChanges")
        g.add_edge(u, "S-1-5-21-DOM", "DCSync")
    g.add_edge("S-1-5-21-DOM", "G-DA", "Contains")

    if ensure_path:
        owned = g.entry_nodes()
        if owned and not _reaches(g, owned, g.index_of("G-DA")):
            # Fallback only, and only when the random structure genuinely failed
            # to connect. Composition is randomised so that when it does fire it
            # does not always cost the same, which is what let the old fixed
            # MemberOf/AdminTo/HasSession/MemberOf chain dominate every graph.
            start = g.nodes[owned[0]].id
            mid_g, mid_c = rng.choice(groups[1:]), rng.choice(computers)
            g.add_edge(start, mid_g, rng.choice(["MemberOf", "AddMember", "GenericWrite"]))
            g.add_edge(mid_g, mid_c, rng.choice(["AdminTo", "CanRDP", "CanPSRemote"]))
            victim = rng.choice(users)
            g.add_edge(mid_c, victim, "HasSession")
            g.add_edge(victim, "G-DA", rng.choice(["MemberOf", "AddMember", "GenericAll"]))

    return g


def _reaches(graph: AttackGraph, sources: Sequence[int], target: int) -> bool:
    """Plain forward BFS over walkable edges.

    Local rather than reusing a planner's helper: a fixture module importing a
    planner to build the fixture the planner is tested on is a loop nobody wants
    to debug later.
    """
    from .ad_schema import DEFAULT_TRAVERSAL_SET

    seen, queue = set(sources), list(sources)
    while queue:
        node = queue.pop()
        if node == target:
            return True
        for edge in graph.out_edges(node):
            if edge.rel_type in DEFAULT_TRAVERSAL_SET and edge.target not in seen:
                seen.add(edge.target)
                queue.append(edge.target)
    return False
