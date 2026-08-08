"""
Static per-edge risk weights: how loud is each AD technique?

This is the Stage 2 half of the risk model. One number per relationship type,
independent of what the attacker did before. Stage 3 adds the history-dependent
part on top (the third Kerberoast is louder than the first); nothing here knows
about history, and `static_cost_fn` ignores its `path_so_far` argument on
purpose.

## The scale

`weight` is a *relative loudness cost*, not a probability. Range 0.1 to 10:

    0.1 - 1     no attacker action; the only trace is ordinary authentication
    2   - 4     an action, but one that looks like normal administration
    5   - 7     a directory or credential operation with a distinctive signature
    8   - 10    loud enough that a shop with any detection at all should catch it

Nothing is zero. A zero would claim a technique is *literally invisible*, which
is a stronger claim than any of these can support — every one of them produces
at least an authentication event somewhere.

## Every weight needs a source, and none of these have one yet

`PROVISIONAL_WEIGHTS` is a **starting point, not an answer**. The `rationale`
field says why the number is roughly where it is; that is reasoning, not a
citation. Each entry needs a real source in the `source` field — an ATT&CK
technique ID, a specific Sigma rule, or a named detection writeup — before any
number computed from this table gets reported anywhere.

`require_sourced()` is the gate. Call it before generating any result you intend
to keep. It fails loudly while the table is still provisional, which is the
entire point: a plausible-looking number with nothing behind it is worse than no
number, because it doesn't announce itself.

The candidate ATT&CK hints in `ad_schema.ATTACK_MAPPING_STUB` are the other half
of the worksheet. Several of them are weak fits and are flagged as such there.
Verify, then fill in `technique=` and `source=` here.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable, Sequence

from .ad_schema import TRAVERSABLE_EDGES
from .graph import AttackGraph

__all__ = [
    "RiskWeight",
    "PROVISIONAL_WEIGHTS",
    "weight_of",
    "static_cost_fn",
    "unsourced",
    "require_sourced",
    "WEIGHT_FLOOR",
    "WEIGHT_CEILING",
]

WEIGHT_FLOOR = 0.1
WEIGHT_CEILING = 10.0


@dataclass(frozen=True)
class RiskWeight:
    """One relationship type's static loudness, plus where the number came from."""

    weight: float
    rationale: str
    """Why the number sits roughly where it does. Reasoning, *not* a citation —
    this field never satisfies `require_sourced`."""

    technique: str | None = None
    """ATT&CK technique ID, once verified. See ad_schema.ATTACK_MAPPING_STUB."""

    source: str | None = None
    """The actual citation: ATT&CK ID, Sigma rule name, or detection writeup.
    While this is None the weight is a guess and must not back any reported
    number."""

    conditional: dict[str, float] | None = None
    """Weights that apply only under a named condition, keyed by condition name.

    `weight` always holds the value that applies **today**, with no conditional
    machinery — deliberately the conservative one, so a model that ignores this
    field is wrong in the safe direction rather than the flattering one.

    Exists because several detections depend on the *target*, not the edge:
    5136 only fires where a SACL exists, and this project's baseline assumes
    SACLs on tier-zero objects only. Collapsing that into one number either
    overstates detection on ordinary objects or understates it on tier-zero
    ones. `AddAllowedToAct` is the first entry to use it, as a working prototype
    of what the Shape D edges will need at ~4,500-edge scale.
    """

    @property
    def sourced(self) -> bool:
        return self.source is not None


def _w(weight: float, rationale: str) -> RiskWeight:
    return RiskWeight(weight=weight, rationale=rationale)


# ---------------------------------------------------------------------------
# PROVISIONAL. Every `source` below is None. That is not an oversight.
# ---------------------------------------------------------------------------

PROVISIONAL_WEIGHTS: dict[str, RiskWeight] = {
    # --- no action taken --------------------------------------------------
    "MemberOf": _w(0.1, "Using a membership you already hold is not an action. "
                        "The only trace is the authentication that would have "
                        "happened anyway."),
    "HasSIDHistory": _w(0.3, "Also passive — the SID is already in the token. "
                             "Categorised as credential_access in ad_schema, "
                             "which overstates it; worth revisiting."),
    "TrustedBy": _w(1.0, "Crossing a trust is authentication, not exploitation, "
                         "though cross-domain auth stands out more than local."),

    # --- looks like normal administration ---------------------------------
    "AdminTo": _w(3.0, "Admin logon to a host. Generates a logon event, but so "
                       "does every legitimate admin, every day."),
    "CanRDP": _w(3.5, "Interactive logon. Extremely visible in logs and "
                      "extremely common; visibility without suspicion."),
    "SQLAdmin": _w(3.5, "Command execution via SQL. Visible where SQL auditing "
                        "exists, which is inconsistently deployed."),
    "CanPSRemote": _w(4.0, "WinRM. Less common in ordinary user activity than "
                           "RDP, so it stands out more against a baseline."),
    "ExecuteDCOM": _w(5.5, "Rare in normal operations and specifically hunted "
                           "for; low volume makes it easy to alert on."),

    # --- directory modification -------------------------------------------
    # These write to AD, so they land in directory-service auditing *if* it is
    # switched on. That conditional is doing a lot of work and is exactly the
    # kind of assumption the sourcing pass needs to pin down.
    "AddMember": _w(4.0, "Group modification. Well-known event IDs and a common "
                         "alert, especially on privileged groups."),
    "AddSelf": _w(4.0, "Same modification, same events, attacker as the target."),
    # --- Shape D: ACL writes -----------------------------------------------
    # SOURCED. All four collapse to near-silence on unaudited objects, because
    # every detection here runs through 5136 / 4670, and both need a SACL on the
    # target. The baseline grants SACLs on tier-zero objects only. Chain length
    # therefore matters *only where auditing exists* - zero events times three
    # actions is still zero events.
    "GenericWrite": RiskWeight(
        weight=1.5,
        conditional={"target_is_tier_zero": 4.5, "target_is_gpo": 5.0},
        rationale=(
            "Chain: write a non-protected attribute -> use the capability that "
            "creates (write an SPN then roast it, write scriptPath then wait for "
            "a logon). Two actions.\n"
            "  IMPACT-VS-LOUDNESS: broad write authority is impact. The only "
            "question here is whether the attribute write is recorded. On an "
            "object with no SACL it is not recorded at all, and 4.5 was pricing "
            "the authority rather than the noise.\n"
            "  non-tier-zero (1.5, applies today): no SACL, no 5136. The write "
            "is invisible; what the attacker later does with it is priced on "
            "that edge, not this one.\n"
            "  tier-zero (4.5): 5136 fires and names the modified attribute.\n"
            "  GPO target (5.0): the SYSVOL route is NOT tier-dependent - "
            "win_security_gpo_scheduledtasks.yml fires on 5145 share access to "
            "ScheduledTasks.xml as well as on 5136, and SYSVOL file-share "
            "auditing is a different channel from AD-object SACLs. A GPO write "
            "is the best-covered case in this group."
        ),
        source=(
            "SigmaHQ win_security_gpo_scheduledtasks.yml (GPO branch): event "
            "codes 5136 and 5145, gPCMachineExtensionNames / "
            "gPCUserExtensionNames modification, and SYSVOL ScheduledTasks.xml "
            "access. Cited specifically rather than via a generic ACL-write "
            "rule, which would not cover this technique. "
            "Generic branch: 5136 (Directory Service Changes) - NOT enabled by "
            "default, requires DS Access audit policy AND a SACL on the object. "
            "ATT&CK fit is weak: T1222 is file/directory permissions, not "
            "directory-object attributes, so no technique ID is claimed."
        ),
    ),
    "Owns": _w(4.5, "Ownership implies the ability to rewrite the DACL; the "
                    "noise comes from what follows."),
    "WriteAccountRestrictions": _w(4.5, "Narrow, unusual attribute write."),
    "GenericAll": RiskWeight(
        weight=1.5,
        conditional={"target_is_tier_zero": 5.0},
        rationale=(
            "Chain: full control, so the chain is whichever of the others you "
            "actually exercise - reset the password, rewrite the DACL, write an "
            "attribute. The static model cannot see which, so it is priced as "
            "the common case (a DACL write or password reset).\n"
            "  IMPACT-VS-LOUDNESS: 'full control' is the purest impact framing "
            "in the whole table and 5.0 was mostly that. Holding the right emits "
            "nothing; only using it can, and only if the object is audited.\n"
            "  Sourcing this matters even though its weight moves no route. "
            "GenericAll shows no route change under +/-1.5 perturbation on any "
            "of the three entry points, and that inertness is a reported "
            "finding - but 'the weight does not matter here' is only a finding "
            "if the weight is defensible. An inert unsourced guess is not "
            "evidence of anything."
        ),
        source=(
            "Same 5136 / 4670 dependency as WriteDacl, since the observable act "
            "is whichever right is exercised. TrustedSec, 'A Hitch-hacker's "
            "Guide to DACL-Based Detections' (parts 1a/1b/3) for the detection "
            "engineering and its preconditions."
        ),
    ),
    "WriteDacl": RiskWeight(
        weight=1.5,
        conditional={"target_is_tier_zero": 5.0},
        rationale=(
            "Chain: write the DACL -> use the granted right. Two actions.\n"
            "  IMPACT-VS-LOUDNESS: 'rarely legitimate outside a change window' "
            "was the old rationale, and that is a claim about *suspiciousness "
            "once seen*, not about whether it is seen. On an unaudited object "
            "it is never seen.\n"
            "  tier-zero (5.0): 4670 carries the old and new SDDL, which makes "
            "triage cheap, plus 5136 on nTSecurityDescriptor. Slightly above "
            "GenericWrite's tier-zero because a DACL change is more distinctive "
            "than an arbitrary attribute write."
        ),
        source=(
            "Event 4670 (permissions on an object were changed; old/new SDDL) "
            "and 5136 on nTSecurityDescriptor. Both require auditing configured "
            "AND a SACL on the target. TrustedSec, 'A Hitch-hacker's Guide to "
            "DACL-Based Detections', which is explicit that the SACL is the "
            "precondition. ATT&CK T1222 is a weak fit (file/directory, not "
            "directory objects); not claimed."
        ),
    ),
    "WriteOwner": RiskWeight(
        weight=1.5,
        conditional={"target_is_tier_zero": 6.0},
        rationale=(
            "Chain: take ownership -> write the DACL -> use the right. THREE "
            "actions, one more than WriteDacl, and the extra one is separately "
            "logged where auditing exists.\n"
            "  This is where the Shape D chain-length guidance actually bites, "
            "and it bites asymmetrically: on a tier-zero target the longer chain "
            "means two audited modifications rather than one, so 6.0 - the "
            "highest of this group. On an unaudited target the longer chain "
            "produces exactly as many events as the shorter one, namely none, "
            "so it collapses to the same 1.5. Chain length is only loud where "
            "something is listening.\n"
            "  Caveat carried from the OWNER RIGHTS finding: SharpHound emits "
            "Owns unconditionally with no OWNER RIGHTS check, so the "
            "take-ownership leg can be blocked in ways the graph cannot show."
        ),
        source=(
            "nTSecurityDescriptor owner change and the subsequent DACL write, "
            "both via 5136 / 4670, both SACL-dependent. TrustedSec DACL-based "
            "detections series. MS-ADTS 6.1.3.4 for the OWNER RIGHTS caveat."
        ),
    ),
    "WriteSPN": _w(5.5, "Targeted Kerberoasting: write an SPN, request the "
                        "ticket, remove it. The write and the ticket request "
                        "are two separate signals."),
    "AddKeyCredentialLink": _w(5.5, "Shadow Credentials. The key-credential "
                                    "attribute write is a strong indicator and "
                                    "the technique is well documented."),
    "WriteGPLink": _w(6.0, "Linking a GPO affects every object under the OU. "
                           "High impact, and GPO changes are usually watched."),

    # --- credential access -------------------------------------------------
    "ReadLAPSPassword": _w(2.5, "A directory attribute read. Quiet unless LAPS "
                                "read auditing is deliberately configured, "
                                "which it often isn't."),
    "SyncLAPSPassword": _w(2.5, "Same read, replication path."),
    "ReadGMSAPassword": _w(2.5, "Same shape as the LAPS read."),
    "DumpSMSAPassword": _w(4.0, "Requires host access first, so it rides on "
                                "whatever noise got you there."),
    "ForceChangePassword": _w(5.0, "A password reset the user did not request. "
                                   "Distinctive event, and users notice."),
    "HasSession": _w(6.0, "Credential theft from a live session means touching "
                          "LSASS. This is the single most heavily instrumented "
                          "action on a modern endpoint."),

    # --- delegation --------------------------------------------------------
    # SOURCED. All three share one detection — 4769 with a non-blank Transited
    # Services field, which is what an S4U2Proxy request looks like. Verified:
    # RBCD and classic constrained delegation populate that field *identically*,
    # so the field does not separate them. What separates them is local base
    # rate, and that is a difference of degree, not kind.
    "AllowedToDelegate": RiskWeight(
        weight=4.0,
        rationale=(
            "The discriminator is real but conditionally cancelled. 4769 with "
            "Transited Services populated is a genuine structural marker in a "
            "default channel — unlike SpoofSIDHistory, where the tickets are "
            "cryptographically indistinguishable and there is no marker at all. "
            "But on a host where classic constrained delegation is legitimately "
            "configured and used, that same marker fires all day for the same "
            "service account, and the abuse arrives inside a legitimate stream. "
            "Priced above SpoofSIDHistory (3.5) because a cancelled "
            "discriminator is not an absent one: the configured-delegation set "
            "is small and directly enumerable, so a defender who checks which "
            "hosts should be producing S4U2Proxy recovers part of the signal "
            "for no tooling investment. Below the RBCD pair only because "
            "legitimate classic delegation is common enough that the "
            "cancellation usually applies."
        ),
        source=(
            "Event 4769, Transited Services field non-blank = S4U2Proxy. "
            "Microsoft's own event-4769 guidance recommends monitoring S4U from "
            "devices not configured for delegation. NO SHIPPED NAMED RULE fires "
            "on this — the support is documented hunting strategy (see also "
            "swolfsec, 'Detecting Resource-Based Constrained Delegation "
            "Abuse', 2023-11-29), which is the same strategy-not-default-rule "
            "situation that brought SpoofSIDHistory down from 8.0. "
            "No ATT&CK technique fits delegation *abuse*; T1098 covers "
            "configuring it, not using it, so no technique ID is claimed here. "
            "CAVEAT: assumes configured delegation is actively used. Dormant "
            "delegation — stale service accounts, decommissioned apps, "
            "over-provisioned setups — is NOT cancelled and is louder than this. "
            "No published base-rate evidence on active-vs-dormant prevalence "
            "was found; priced for the active case, which understates the "
            "attacker's noise and is therefore the safe direction."
        ),
    ),
    "AllowedToAct": RiskWeight(
        weight=4.5,
        rationale=(
            "Same edge semantics as AllowedToDelegate — the right already "
            "exists on the target — so the same cancellation applies: an "
            "AllowedToAct edge exists precisely because RBCD is already "
            "configured there, and if an admin configured it for a real purpose "
            "the path carries routine S4U2Proxy traffic. The only separator is "
            "that legitimate RBCD is rarer than legitimate classic delegation, "
            "so the cancellation applies less often. That is a difference of "
            "degree, hence +0.5 rather than a band change. (Attacker-configured "
            "RBCD is AddAllowedToAct, a different edge.)"
        ),
        source=(
            "Same as AllowedToDelegate: 4769 Transited Services, no shipped "
            "rule, documented hunting strategy only. Same dormant-delegation "
            "caveat. Verified that RBCD's S4U2Proxy populates Transited "
            "Services identically to classic constrained delegation, so the "
            "field itself provides no separation between the two."
        ),
    ),
    "AddAllowedToAct": RiskWeight(
        weight=5.0,
        conditional={"target_is_tier_zero": 6.0},
        rationale=(
            "Adds the attribute *write* to AllowedToAct's use, and the write is "
            "the only part of this trio covered by a shipped named rule. The "
            "premium is therefore entirely target-dependent, because that rule "
            "needs 5136, and 5136 needs a SACL.\n"
            "  non-tier-zero (5.0, applies today): no SACL, no 5136, no rule. "
            "The write still happens and is one more action with some residual "
            "chance of notice, hence +0.5 over AllowedToAct, not more.\n"
            "  tier-zero (6.0): 5136 fires and a shipped rule matches it, "
            "which is a real second signal, hence +1.5.\n"
            "Encoded as two values rather than asserting a modal case. The "
            "canonical writeup is RBCD onto a DC, but the canonical writeup is "
            "not the modal edge — in a real graph these point at whatever "
            "computers a principal can write to, mostly workstations and member "
            "servers. This collection has zero such edges, so the claim is "
            "untestable here and does not get to carry a premium by assertion."
        ),
        technique="T1098",
        source=(
            "SigmaHQ win_security_alert_ad_user_backdoors.yml, id "
            "300bac00-e041-4ee2-9c36-e262656a6ecc (status: test), "
            "selection_5136_3: EventID 5136 with AttributeLDAPDisplayName "
            "'msDS-AllowedToActOnBehalfOfOtherIdentity'. Tagged attack.t1098. "
            "INHERITS THE SACL/TIER DEPENDENCY: 5136 only fires where a SACL "
            "exists, and the project baseline assumes SACLs on tier-zero "
            "objects only — which is what the conditional above encodes. "
            "Abuse-side reference: Elad Shamir, 'Wagging the Dog' (2019). "
            "Use-side signal is AllowedToAct's, with its caveats."
        ),
    ),

    # --- trusts ------------------------------------------------------------
    # SOURCED. Priced at its own undiscounted marginal cost — the forging and
    # use of the ticket, not the krbtgt compromise that precedes it.
    "SpoofSIDHistory": RiskWeight(
        weight=3.5,
        rationale=(
            "Forged TGTs carrying spoofed SID history produce ordinary-looking "
            "4768/4769 events. The tickets are cryptographically valid, so "
            "nothing structurally distinguishes them from legitimate "
            "cross-forest authentication. A 4672 does fire when the privileged "
            "token is used, which is standard logging — but 4672 is high-volume "
            "noise from legitimate admin activity, so it is visibility without "
            "suspicion. Sits with AdminTo (3.0) and CanRDP (3.5) for that "
            "reason, slightly above AdminTo because cross-forest authentication "
            "is rarer than intra-domain admin logon and because the impersonated "
            "identity holds privileges the real account does not."
        ),
        technique="T1134.005",
        source=(
            "ATT&CK T1134.005 (Access Token Manipulation: SID-History "
            "Injection). Detection: MITRE ATT&CK DET0144 — note this is a "
            "behaviour-chain *correlation strategy*, not a default-log "
            "detection, and is therefore excluded by the defender baseline in "
            "docs/stage2_joint_capability_audit.md. Deliberately NOT sourced to "
            "SigmaHQ 2632954e-db1c-49cb-9936-67d1ef1d17d2 ('Addition of SID "
            "History to Active Directory Object'): that rule fires on 4765/4766 "
            "when SID history is written to a real directory object, whereas "
            "this edge forges it inside a ticket and never touches the "
            "directory. Citing it would look rigorous and be wrong."
        ),
    ),

    # --- policy propagation -------------------------------------------------
    # SOURCED. Not attacker actions: the action is writing the GPO, priced on
    # the ACL edge onto it. These two are Group Policy applying, which the OS
    # does by itself. Weighted only so the GPO expansion view can be costed.
    "GPLink": RiskWeight(
        weight=0.1,
        rationale=(
            "Policy application, not an action. Charging for it would "
            "double-count the GPO write already priced on the ACL edge. An "
            "earlier draft put this above the floor on the theory that "
            "policy-pushed payloads generate endpoint telemetry when they run; "
            "that does not hold — GPO-pushed execution goes through the "
            "legitimate Group Policy Client service with a legitimate parent "
            "process, so there is no additional signal to charge for."
        ),
        technique="T1484.001",
        source=(
            "ATT&CK T1484.001 (Domain or Tenant Policy Modification: Group "
            "Policy Modification) covers the abuse; the detectable act is the "
            "GPO write, not the link. When GenericWrite/GenericAll are sourced, "
            "cite SigmaHQ win_gpo_scheduledtasks.yml specifically for the "
            "write-side signal — a generic ACL-write rule does not cover this "
            "technique."
        ),
    ),
    "Contains": RiskWeight(
        weight=0.1,
        rationale=(
            "Pure containment. Nothing happens when an OU holds an object; "
            "walking it is not an act. Weighted at the floor rather than zero "
            "for the same reason everything else is: zero would claim "
            "invisibility we cannot support."
        ),
        technique="T1484.001",
        source=(
            "Same as GPLink — reachable only inside "
            "AttackGraph.with_gpo_expansion(), where the priced act is the GPO "
            "write. ATT&CK T1484.001."
        ),
    ),

    # --- replication -------------------------------------------------------
    # The loudest category. If a shop has one AD detection, it is this one.
    "GetChanges": _w(8.0, "Replication right. On its own it is a precondition, "
                          "but requesting it is already anomalous."),
    "GetChangesAll": _w(8.0, "Second half of the same precondition."),
    "GetChangesInFilteredSet": _w(8.0, "Narrower variant, same signal."),
    "DCSync": _w(9.0, "Replication from a non-DC. The canonical AD detection; "
                      "assume any shop with monitoring catches this."),
}


def weight_of(rel_type: str,
              table: dict[str, RiskWeight] = PROVISIONAL_WEIGHTS) -> float:
    """Static loudness for a relationship type.

    Raises on unknown types rather than defaulting, for the same reason
    `ad_schema.category_of` does: an edge that quietly picks up a made-up cost
    changes every route the planner returns and never says so.
    """
    try:
        return table[rel_type].weight
    except KeyError:
        raise KeyError(
            f"No risk weight for relationship type {rel_type!r}. Add it to "
            f"PROVISIONAL_WEIGHTS with a rationale — do not let it default."
        ) from None


def static_cost_fn(table: dict[str, RiskWeight] = PROVISIONAL_WEIGHTS
                   ) -> Callable[[AttackGraph, int, Sequence[int]], float]:
    """Cost function in the planners' shared signature.

    `path_so_far` is accepted and ignored. That ignoring *is* the static model —
    Stage 3's history-dependent version has the same signature and actually
    reads it, so the two are drop-in swappable and the planners never change.
    """
    def cost(graph: AttackGraph, edge_index: int,
             path_so_far: Sequence[int]) -> float:
        return weight_of(graph.edges[edge_index].rel_type, table)

    return cost


def unsourced(table: dict[str, RiskWeight] = PROVISIONAL_WEIGHTS) -> list[str]:
    """Relationship types whose weight is still an unbacked guess."""
    return sorted(rel for rel, w in table.items() if not w.sourced)


def require_sourced(table: dict[str, RiskWeight] = PROVISIONAL_WEIGHTS) -> None:
    """Refuse to proceed while any weight is unsourced.

    Call this before generating a number you intend to keep. Planning and
    testing against provisional weights is fine and expected — reporting one is
    not, and the difference between the two is easy to forget at 2am.
    """
    missing = unsourced(table)
    if missing:
        raise ValueError(
            f"{len(missing)} of {len(table)} risk weights have no source: "
            f"{', '.join(missing)}. Fill in RiskWeight.source (ATT&CK ID, Sigma "
            f"rule, or named detection writeup) before reporting any number "
            f"derived from these weights."
        )
