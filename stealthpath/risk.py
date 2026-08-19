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

from .ad_schema import TRAVERSABLE_EDGES, category_of
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
    "REPEAT_MULTIPLIER",
    "P15_DECLARED_FRACTION",
    "history_cost_fn",
    "max_repeat_step",
]

WEIGHT_FLOOR = 0.1
WEIGHT_CEILING = 10.0

# Detection channels, split by baseline half. Every sourced weight must name at
# least one from each half, using the NONE_FOUND value where a half was checked
# and came back empty.
NATIVE_SACL = "native_ad_sacl"            # 5136 / 4670 / 4662 - needs a SACL
NATIVE_DEFAULT = "native_default_channel"  # 4624/4672/4724/4728/4769 - no SACL
NATIVE_NONE_FOUND = "native_none_found"
ENDPOINT_RULE = "endpoint_named_rule"      # shipped Sigma on Sysmon/4104/EDR
ENDPOINT_NONE_FOUND = "endpoint_none_found"

NATIVE_HALF = {NATIVE_SACL, NATIVE_DEFAULT, NATIVE_NONE_FOUND}
ENDPOINT_HALF = {ENDPOINT_RULE, ENDPOINT_NONE_FOUND}


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

    channels: tuple[str, ...] = ()
    """Which detection channels this weight rests on, one per baseline half.

    Exists because of a specific failure. The Shape D edges were first derived
    at 1.5 from native AD auditing alone — 5136/4670 need a SACL, so an ACL
    write on an ordinary object emits nothing — while the baseline *also*
    assumes EDR/Sysmon telemetry, which needs no SACL and does catch it. The
    derivation was internally consistent and simply omitted half the evidence.
    Nothing in prose made that omission visible.

    Recording the channels makes "which halves were considered?" a structural
    field rather than something buried in a paragraph, so
    `test_sourced_weight_accounts_for_both_baseline_halves` can require an
    answer for each. Use `NATIVE_NONE_FOUND` / `ENDPOINT_NONE_FOUND` to record a
    half that was checked and came back empty — silence and absence must be
    distinguishable.

    Note honestly what this does and does not catch: it forces the question, and
    it catches an unanswered one. It cannot catch a *wrong* answer — a weight
    that declares `ENDPOINT_NONE_FOUND` when a rule does in fact exist looks
    identical to one where none does. That failure is a literature-search
    failure and only review catches it.
    """

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

    tier_conditional_not_applicable: str = ""
    """Why this SACL-dependent weight has no tier split, when it genuinely has none.

    A weight resting on `NATIVE_SACL` normally *must* declare a
    `target_is_tier_zero` conditional, because the baseline grants SACLs on
    tier-zero objects only and one number for both cases is asserting the
    audited and unaudited object are equally loud.

    A few edges have no non-tier-zero case at all. `DCSync` is the example:
    replication rights apply only to a naming context, so every target is a
    domain object and every domain object is tier-zero. The first attempt at
    this recorded `{"target_is_tier_zero": 6.5}` against a base of 6.5 — a
    conditional equal to its base, which is a no-op written to satisfy a test.
    That is the same anti-pattern as editing the test, wearing a different
    disguise: it encodes a fake number where a fact belongs.

    So the exemption is a **required reason string**, not a flag. An empty
    string is not an exemption, and
    `test_a_sacl_only_weight_declares_a_tier_conditional` accepts a real
    conditional or a stated reason and rejects both-absent.
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
    "MemberOf": RiskWeight(
        weight=0.1,
        channels=(NATIVE_NONE_FOUND, ENDPOINT_NONE_FOUND),
        rationale=(
            "No action is taken. `MemberOf` is a fact about the token the "
            "attacker already holds, not something they do, so there is no "
            "operation for a defender to observe.\n"
            "  IMPACT-VS-LOUDNESS: the temptation is to price group membership "
            "by what the group can do. That is authority, and it belongs on "
            "whichever edge exercises it.\n"
            "  Native half: nothing. The membership is evaluated during "
            "authentication and appears in 4768/4769/4624 as group SIDs in a "
            "token - but that authentication would have happened anyway, and "
            "no event marks the traversal. There is no 'a membership was used' "
            "record in Windows.\n"
            "  Endpoint half: nothing. No process, no handle, no artifact.\n"
            "  FLOOR, NOT ZERO, and the distinction matters: 0.0 would claim "
            "literal invisibility and let a planner chain unlimited free hops "
            "through group structure.\n"
            "  This weight decides a real route and was checked accordingly. "
            "`SQL_SVC`'s least-risk route runs ...HasSession -> MemberOf -> "
            "GenericWrite, and below the DCSync threshold the flipped route "
            "still prefers MemberOf (0.1) over AdminTo. So the floor is doing "
            "load-bearing work in the headline result. It survives the check: "
            "there genuinely is no observable action here, and the cheapness "
            "is the correct answer rather than a convenient one."
        ),
        source=(
            "Negative result, recorded as such. No ATT&CK technique describes "
            "using a group membership one already holds - T1078 Valid Accounts "
            "is the closest and concerns the *credential*, not the group. No "
            "SigmaHQ rule fires on membership use, only on membership *change* "
            "(4728/4732/4756, which is AddMember/AddSelf, priced separately). "
            "Both halves searched and empty; that is the finding."
        ),
    ),
    "HasSIDHistory": _w(0.3, "Also passive — the SID is already in the token. "
                             "Categorised as credential_access in ad_schema, "
                             "which overstates it; worth revisiting."),
    "TrustedBy": _w(1.0, "Crossing a trust is authentication, not exploitation, "
                         "though cross-domain auth stands out more than local."),

    # --- looks like normal administration ---------------------------------
    "AdminTo": RiskWeight(
        weight=2.5,
        channels=(NATIVE_DEFAULT, ENDPOINT_NONE_FOUND),
        rationale=(
            "Administrative logon to a host.\n"
            "  IMPACT-VS-LOUDNESS: local admin on a machine is a large "
            "capability, and 3.0 was partly pricing that. The question is only "
            "whether the logon stands out.\n"
            "  Native half: 4624 (logon) and 4672 (special privileges assigned "
            "to new logon) both fire by default with no SACL. So the event is "
            "definitely recorded.\n"
            "  Endpoint half: nothing for the logon itself. Whatever the "
            "attacker runs afterwards is priced on that edge.\n"
            "  The reason this lands LOW despite guaranteed recording is base "
            "rate. 4672 fires for every legitimate administrator on every "
            "logon, all day, across the estate. No shipped rule alerts on it "
            "because alerting on it would be unusable. This is the clearest "
            "case in the table of **visibility without suspicion** - perfect "
            "recall, no signal - and it must price below anything that trips a "
            "named rule. Below the ACL writes (4.0), which do.\n"
            "  Retrievable in an investigation, invisible in a queue. Those are "
            "different things and the weight models the second."
        ),
        source=(
            "Microsoft Learn, event 4672 'Special privileges assigned to new "
            "logon' and 4624 'An account was successfully logged on' - both in "
            "default audit policy, neither SACL-dependent. NO named SigmaHQ "
            "rule for administrative logon as such: searched, and the absence "
            "is the point rather than a gap in the search. ATT&CK T1078.002 "
            "(Valid Accounts: Domain Accounts) describes the technique but "
            "carries no detection that distinguishes it from ordinary "
            "administration."
        ),
    ),
    "CanRDP": _w(3.5, "Interactive logon. Extremely visible in logs and "
                      "extremely common; visibility without suspicion."),
    "SQLAdmin": RiskWeight(
        weight=5.0,
        technique="T1505.003",
        channels=(NATIVE_NONE_FOUND, ENDPOINT_RULE),
        rationale=(
            "Command execution as the SQL service account, in practice via "
            "`xp_cmdshell`.\n"
            "  IMPACT-VS-LOUDNESS: this one moved UP, which is unusual. 3.5 was "
            "not pricing impact - it was pricing the wrong channel, assuming "
            "detection depended on SQL Server auditing.\n"
            "  Native half: nothing. The audit doc already decided SQL Server "
            "auditing does not clear the bar - it is off by default and is "
            "per-application configuration, while the baseline covers native "
            "*AD* auditing plus EDR. Recorded as NONE_FOUND rather than "
            "silently leaned on.\n"
            "  Endpoint half: strong, and this is the whole number. Executing "
            "a command through SQL means `sqlservr.exe` spawns a child - and "
            "the shipped rule is level **high**, matching cmd.exe, "
            "powershell.exe, pwsh.exe and eleven others under a sqlservr.exe "
            "parent.\n"
            "  Prices ABOVE the ACL-write base (4.0), as the triage predicted. "
            "Two reasons: the rule is level high where the ACL-write rule is "
            "not, and **process lineage cannot be renamed away**. The ACL "
            "writes die to renaming a cmdlet; here the child process is the "
            "signal and command execution requires one. Same non-evadability "
            "argument as DCSync's protocol GUIDs, arrived at independently.\n"
            "  Held below DCSync (6.5) and HasSession (6.0) because it rests "
            "on one half with nothing on the other."
        ),
        source=(
            "SigmaHQ rules/windows/process_creation/"
            "proc_creation_win_mssql_susp_child_process.yml - 'Suspicious "
            "Child Process Of SQL Server', id "
            "869b9ca7-9ea2-4a5a-8325-e80e62f75445, status test, **level "
            "high**. ParentImage endswith '\\sqlservr.exe'; Image endswith any "
            "of bash.exe, bitsadmin.exe, cmd.exe, netstat.exe, nltest.exe, "
            "ping.exe, powershell.exe, pwsh.exe, regsvr32.exe, rundll32.exe, "
            "sh.exe, systeminfo.exe, tasklist.exe, wsl.exe. Carries a DATEV "
            "filter. Tags attack.t1505.003, attack.t1190. Read from the rule "
            "body, not a summary."
        ),
    ),
    "CanPSRemote": _w(4.0, "WinRM. Less common in ordinary user activity than "
                           "RDP, so it stands out more against a baseline."),
    "ExecuteDCOM": _w(5.5, "Rare in normal operations and specifically hunted "
                           "for; low volume makes it easy to alert on."),

    # --- directory modification -------------------------------------------
    # These write to AD, so they land in directory-service auditing *if* it is
    # switched on. That conditional is doing a lot of work and is exactly the
    # kind of assumption the sourcing pass needs to pin down.
    "AddMember": RiskWeight(
        weight=4.5,
        technique="T1098",
        channels=(NATIVE_DEFAULT, ENDPOINT_NONE_FOUND),
        rationale=(
            "Adding a principal to a group.\n"
            "  IMPACT-VS-LOUDNESS: adding yourself to Domain Admins is "
            "enormous impact. The events fire identically for adding someone "
            "to a distribution group.\n"
            "  Native half: 4728 (global), 4732 (local), 4756 (universal) all "
            "fire by default, no SACL, and there is a **stable** shipped rule "
            "on 4728.\n"
            "  Endpoint half: nothing. The change can be made over LDAP or "
            "SAMR from a host nobody is watching.\n"
            "  The triage predicted 'likely the loudest of these eight after "
            "DCSync'. **That prediction is wrong, and the rule body is why.** "
            "The shipped rule is level **low** with false positives 'Unknown', "
            "and it matches *any* addition to *any* security-enabled global "
            "group - not privileged ones. It is an audit-trail rule, not an "
            "alert. Helpdesk group changes fire it all day.\n"
            "  So: reliably recorded, named and stable, but low-severity and "
            "high-volume. 4.5 - above ForceChangePassword (4.0), which has no "
            "named rule at all, and above the ACL writes (4.0) whose native "
            "half needs a SACL this one does not. Below the edges carrying a "
            "high-severity or technique-specific rule.\n"
            "  A privileged-group-specific conditional is the obvious "
            "refinement and is NOT added here: it needs target-kind-aware "
            "costing, which the audit doc already lists as blocked on the "
            "schema rather than the weights."
        ),
        source=(
            "SigmaHQ rules/windows/builtin/security/account_management/"
            "win_security_member_added_security_enabled_global_group.yml - 'A "
            "Member Was Added to a Security-Enabled Global Group', id "
            "c43c26be-2e87-46c7-8661-284588c5a53e, **status stable, level "
            "low**, falsepositives Unknown. Detection: EventID 4728 or 632, "
            "condition `selection` with no filtering. Tags "
            "attack.privilege-escalation, attack.persistence, attack.t1098. "
            "A more targeted sibling exists for the local-administrators case "
            "(win_security_user_added_to_local_administrators.yml, keyed on "
            "S-1-5-32-544); not cited as primary because BloodHound's "
            "`AddMember` is domain group membership."
        ),
    ),
    "AddSelf": RiskWeight(
        weight=4.5,
        technique="T1098",
        channels=(NATIVE_DEFAULT, ENDPOINT_NONE_FOUND),
        rationale=(
            "The same modification with the attacker as the member added.\n"
            "  The triage asked whether anything distinguishes this from "
            "AddMember in the log. **Answer: nothing shipped does.** 4728 "
            "records Subject (who performed it) and Member (who was added) as "
            "separate fields, so the self-addition case *is* expressible - "
            "Subject equals Member is a genuinely suspicious pattern, since "
            "administrators rarely add themselves. But the shipped rule "
            "conditions on EventID alone and does not compare the two fields, "
            "and no other rule was found that does.\n"
            "  Pricing what exists rather than what could exist: identical to "
            "AddMember at 4.5. Recorded as an asymmetry between what the log "
            "*contains* and what any rule *reads* - a detection-engineering "
            "gap, not a modelling one, and a natural instance of the "
            "evasion-difficulty axis in reverse: the signal is present and "
            "simply unused."
        ),
        source=(
            "Same rule and citation as `AddMember` above - EventID 4728, "
            "condition `selection`, no Subject/Member comparison. The absence "
            "of a self-addition rule was searched for specifically and none "
            "was found; recorded as a negative result."
        ),
    ),
    # --- Shape D: ACL writes -----------------------------------------------
    # SOURCED, and re-derived once. The first derivation used only the native-AD
    # half of the baseline: 5136 / 4670 both need a SACL, the baseline grants
    # SACLs on tier-zero objects only, therefore an ACL write on an ordinary
    # object emits nothing and the floor is 1.5. That reasoning is sound but
    # incomplete - the baseline also assumes EDR/Sysmon-class telemetry, which
    # does NOT depend on a SACL.
    #
    # SigmaHQ posh_ps_powerview_malicious_commandlets.yml fires on PowerShell
    # Script Block Logging (4104) for PowerView cmdlet names including
    # Add-DomainObjectAcl and Set-DomainObjectOwner, and Sysmon Event 1 carries
    # the command line. Both are in-baseline. So the write IS observed - a named
    # shipped rule on assumed telemetry, distinctive low-false-positive strings.
    #
    # The catch, and it is the whole reason for the tooling condition: that
    # signal is TOOLING-dependent, not TECHNIQUE-dependent. Rename the function,
    # use SharpView, use .NET DirectoryServices from a compiled binary, or run
    # Impacket dacledit from Linux, and none of it appears. Evasion is cheap.
    #
    # Base weight prices the OBSERVABLE case. tooling_is_native_ldap preserves
    # the 1.5 derivation for a path that emits no endpoint artifact. Chain
    # length still only matters where directory auditing exists, which is why
    # WriteOwner's three legs separate from WriteDacl's two only on tier-zero.
    #
    # LIMITATION of the conditional field: these keys are flat and do not
    # compose. Native-LDAP tooling against a TIER-ZERO target still fires 5136,
    # so the tier-zero value holds there regardless of tooling; the 1.5 applies
    # to the non-tier-zero case only. A cross-product encoding is Stage 3 work.
    "GenericWrite": RiskWeight(
        weight=4.0,
        channels=(NATIVE_SACL, ENDPOINT_RULE),
        conditional={"target_is_tier_zero": 5.0, "target_is_gpo": 5.5,
                     "tooling_is_native_ldap": 1.5},
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
        weight=4.0,
        channels=(NATIVE_SACL, ENDPOINT_RULE),
        conditional={"target_is_tier_zero": 5.5, "tooling_is_native_ldap": 1.5},
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
        weight=4.0,
        channels=(NATIVE_SACL, ENDPOINT_RULE),
        conditional={"target_is_tier_zero": 5.5, "tooling_is_native_ldap": 1.5},
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
        weight=4.0,
        channels=(NATIVE_SACL, ENDPOINT_RULE),
        conditional={"target_is_tier_zero": 6.0, "tooling_is_native_ldap": 1.5},
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
    # PENDING INVERSION - the invariant skip below is deliberate, not an oversight.
    # This is the second composite in COMPOSITE_RIGHTS (GetChanges +
    # GetChangesInFilteredSet), and both components are sourced at 6.5 while this
    # sits at an unsourced 2.5 - i.e. the halves are already louder than the
    # whole. test_no_composite_is_quieter_than_a_component_it_subsumes does not
    # fire, because it only checks *sourced* composites: comparing a derived
    # number against a guess is the anchoring trap the method forbids.
    # Consequence to expect: sourcing this below 6.5 will fail that test, and
    # should. The same 4662 rule fires on GetChangesInFilteredSet's GUID, so the
    # honest answer is very likely 6.5.
    "SyncLAPSPassword": _w(2.5, "Same read, replication path."),
    "ReadGMSAPassword": _w(2.5, "Same shape as the LAPS read."),
    "DumpSMSAPassword": _w(4.0, "Requires host access first, so it rides on "
                                "whatever noise got you there."),
    "ForceChangePassword": RiskWeight(
        weight=4.0,
        technique="T1098",
        channels=(NATIVE_DEFAULT, ENDPOINT_NONE_FOUND),
        rationale=(
            "Resetting another principal's password without knowing the old "
            "one.\n"
            "  IMPACT-VS-LOUDNESS, and the leak here is subtle. 5.0 was partly "
            "priced on 'users notice' - the victim is locked out and "
            "complains. That is a real consequence and it is **not "
            "telemetry**. It is the named non-telemetry limitation from the "
            "audit doc, and folding it into a detection weight is exactly the "
            "error the method exists to catch. Removed; the number drops.\n"
            "  Native half: 4724 'An attempt was made to reset an account's "
            "password' fires by default, no SACL. Recorded reliably.\n"
            "  Endpoint half: nothing. The reset goes over SAMR or LDAP and "
            "needs no process on any monitored host.\n"
            "  No named SigmaHQ rule found for 4724 - see the source note, "
            "which matters. So: default-channel recording, no shipped alert, "
            "but a genuinely uncommon operation. That puts it above AdminTo "
            "(2.5), which is recorded-but-ubiquitous, and at the ACL-write "
            "level (4.0) rather than above it."
        ),
        source=(
            "Microsoft Learn, event 4724 'An attempt was made to reset an "
            "account's password' - default audit policy, not SACL-dependent. "
            "ATT&CK T1098 Account Manipulation.\n"
            "NO named SigmaHQ rule cited, deliberately. A search returned a "
            "'Tier-0 Password Reset (4724)' rule with no SigmaHQ path, an id "
            "that does not match the repository's format, and a future "
            "modification date. It was NOT cited and should not be - this pass "
            "had already produced two bad citations (a 404'd filename and an "
            "AccessMask term absent from the rule body), and an unverifiable "
            "third is how a confidently wrong answer enters. If a real 4724 "
            "rule exists, finding it would raise this weight."
        ),
    ),
    "HasSession": RiskWeight(
        weight=6.0,
        technique="T1003.001",
        channels=(NATIVE_NONE_FOUND, ENDPOINT_RULE),
        rationale=(
            "Harvesting the credentials of a user with a live session on a "
            "host the attacker controls, which means reading LSASS.\n"
            "  IMPACT-VS-LOUDNESS: held at 6.0 across the revised baseline "
            "already. The triage said it needed a named rule to finish, not a "
            "re-derivation. It now has one and the number is unchanged - worth "
            "recording, because a sourcing pass that only ever moves numbers "
            "would be suspicious in its own way.\n"
            "  Native half: nothing. LSASS access is not an AD operation and "
            "produces no directory event.\n"
            "  Endpoint half: the most heavily instrumented behaviour on a "
            "modern endpoint. The shipped rule keys on ProcessAccess to "
            "lsass.exe with specific GrantedAccess masks and on CallTrace "
            "entries through dbgcore.dll / dbghelp.dll, i.e. "
            "MiniDumpWriteDump.\n"
            "  Highest of the seven, and second only to DCSync overall. Not "
            "raised further because the GrantedAccess/CallTrace signature is "
            "genuinely evadable - direct syscalls or handle duplication move "
            "an attacker off the matched masks - which is a real difference "
            "from DCSync's protocol constants."
        ),
        source=(
            "SigmaHQ rules/windows/process_access/"
            "proc_access_win_lsass_memdump.yml - 'Potential Credential "
            "Dumping Activity Via LSASS'. TargetImage endswith '\\lsass.exe'; "
            "GrantedAccess in 0x1038, 0x1438, 0x143a, 0x1fffff; CallTrace "
            "contains dbgcore.dll / dbghelp.dll among others. Tags "
            "attack.credential-access, attack.t1003.001. Authors Samir "
            "Bousseaden and Michael Haag. Sysmon Event 10 (ProcessAccess) is "
            "the log source and is EDR/Sysmon-class, in baseline, no SACL."
        ),
    ),

    # --- delegation --------------------------------------------------------
    # SOURCED. All three share one detection — 4769 with a non-blank Transited
    # Services field, which is what an S4U2Proxy request looks like. Verified:
    # RBCD and classic constrained delegation populate that field *identically*,
    # so the field does not separate them. What separates them is local base
    # rate, and that is a difference of degree, not kind.
    "AllowedToDelegate": RiskWeight(
        weight=4.0,
        channels=(NATIVE_DEFAULT, ENDPOINT_NONE_FOUND),
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
        channels=(NATIVE_DEFAULT, ENDPOINT_NONE_FOUND),
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
        channels=(NATIVE_SACL, ENDPOINT_NONE_FOUND),
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
        channels=(NATIVE_DEFAULT, ENDPOINT_NONE_FOUND),
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
        # NONE_FOUND, not SACL: the *link* emits nothing. What
        # win_security_gpo_scheduledtasks.yml fires on is the GPO content write,
        # and that is priced on the ACL edge onto the GPO. Mislabelling this as
        # SACL-dependent was caught by
        # test_a_sacl_only_weight_declares_a_tier_conditional - a SACL-only
        # weight must split by tier, and this one has nothing to split.
        channels=(NATIVE_NONE_FOUND, ENDPOINT_NONE_FOUND),
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
        channels=(NATIVE_NONE_FOUND, ENDPOINT_NONE_FOUND),
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
    # The three components below are priced as ONE UNIT with the composite
    # above. They sat at 8.0 while `DCSync` was 9.0 and stayed there when it
    # was sourced to 6.5, leaving the halves louder than the whole - which is
    # incoherent, because exercising the composite means exercising them.
    #
    # Why they land EQUAL to the composite rather than below it: the Sigma
    # rule's selection matches `Properties|contains` **any one** of the four
    # replication GUIDs. A request carrying only DS-Replication-Get-Changes
    # produces the same 4662 and trips the same rule as a full DCSync. The
    # detection keys on the replication request, not on how many rights the
    # principal holds, so there is no signal difference to price. Equal is the
    # derived answer, not a rounding convenience.
    #
    # All three are in PARTIAL_RIGHT_EDGES and non-traversable, so no route
    # reads these numbers. That is exactly how the inversion survived - see
    # `docs/findings.md` 2026-08-09.
    "GetChanges": RiskWeight(
        weight=6.5,
        technique="T1003.006",
        channels=(NATIVE_SACL, ENDPOINT_NONE_FOUND),
        tier_conditional_not_applicable=(
            "Replication rights apply only to a naming context, so the target "
            "is always a domain object and always tier-zero."
        ),
        rationale=(
            "Component of DCSync (with GetChangesAll) and of SyncLAPSPassword "
            "(with GetChangesInFilteredSet). Non-traversable.\n"
            "  IMPACT-VS-LOUDNESS: 8.0 priced it as 'requesting replication is "
            "already anomalous', which is a statement about how suspicious the "
            "request looks rather than about what records it. What records it "
            "is one 4662, the same one the composite produces.\n"
            "  Equal to the composite by derivation - the rule fires on this "
            "GUID alone. See the block comment above."
        ),
        source="Same rule and selection as `DCSync` above; this GUID is "
               "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 "
               "(DS-Replication-Get-Changes), listed in the rule's own "
               "selection as an independent match.",
    ),
    "GetChangesAll": RiskWeight(
        weight=6.5,
        technique="T1003.006",
        channels=(NATIVE_SACL, ENDPOINT_NONE_FOUND),
        tier_conditional_not_applicable=(
            "Replication rights apply only to a naming context, so the target "
            "is always a domain object and always tier-zero."
        ),
        rationale="Second half of the DCSync pair. Same 4662, same rule, same "
                  "number as its sibling and its composite.",
        source="Same rule and selection as `DCSync` above; this GUID is "
               "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 "
               "(DS-Replication-Get-Changes-All).",
    ),
    "GetChangesInFilteredSet": RiskWeight(
        weight=6.5,
        technique="T1003.006",
        channels=(NATIVE_SACL, ENDPOINT_NONE_FOUND),
        tier_conditional_not_applicable=(
            "Replication rights apply only to a naming context, so the target "
            "is always a domain object and always tier-zero."
        ),
        rationale=(
            "Pairs with GetChanges to make SyncLAPSPassword. Same 4662 and the "
            "same rule.\n"
            "  NOTE for the next pass: `SyncLAPSPassword` is the composite of "
            "this and GetChanges and currently sits UNSOURCED at 2.5, far below "
            "its own components. The composite invariant skips it only because "
            "it is unsourced; sourcing it at anything below 6.5 will fail "
            "`test_no_composite_is_quieter_than_a_component_it_subsumes`, and "
            "should - the same rule fires."
        ),
        source="Same rule and selection as `DCSync` above; this GUID is "
               "89e95b76-444d-4c62-991a-0facbeda640c "
               "(DS-Replication-Get-Changes-In-Filtered-Set).",
    ),
    "DCSync": RiskWeight(
        weight=6.5,
        technique="T1003.006",
        channels=(NATIVE_SACL, ENDPOINT_NONE_FOUND),
        tier_conditional_not_applicable=(
            "Replication rights apply only to a naming context, so every "
            "DCSync target is a domain object and every domain object is "
            "tier-zero. There is no non-tier-zero case to split."
        ),
        rationale=(
            "One action, not a chain: request DsGetNCChanges over DRSUAPI. The "
            "attacker already holds both replication rights or the composite "
            "edge would not exist.\n"
            "  IMPACT-VS-LOUDNESS: this is where that confusion hides best. "
            "DCSync is the highest-impact edge in the schema - every hash in "
            "the domain, krbtgt included - and 9.0 was pricing exactly that. "
            "Near-ceiling on a 10-point scale is a statement that the action is "
            "almost maximally *noticeable*, which is a different claim and one "
            "the evidence does not support. The narrow question is whether the "
            "replication request is recorded.\n"
            "  Native half, and it is the whole of the number: 4662 carrying "
            "the replication extended-right GUIDs. SACL-dependent - it needs a "
            "SACL on the domain root plus the Directory Service Access audit "
            "subcategory. **The baseline grants SACLs on tier-zero objects, and "
            "the domain root is tier-zero, so unlike the Shape D edges this "
            "channel is genuinely present.** The audit doc asked for this to be "
            "confirmed rather than assumed; it is confirmed.\n"
            "  Endpoint half: nothing found. The call is remote RPC against the "
            "DC. `secretsdump.py` from Linux leaves no process artifact on the "
            "DC at all, and Mimikatz leaves one on the attacker's host, which is "
            "not the DC and is often unmonitored.\n"
            "  So DCSync is the structural mirror of Shape D. Those edges rest "
            "entirely on the endpoint half; this one rests entirely on the "
            "native half. Neither has both.\n"
            "  Placement at 6.5: a clear step above AddAllowedToAct (5.0), which "
            "has the same channel shape - SACL plus nothing on the endpoint - "
            "but no named rule. DCSync adds two real things: a shipped rule "
            "written for this exact technique, and a SACL that is present by "
            "construction rather than by luck of which object was targeted. "
            "Discounted well below the ceiling for three reasons: the rule is "
            "`test` status, its documented false-positive rate is *medium* "
            "rather than low, and it filters principals ending in `$` - so "
            "DCSync from a computer account is not matched by it. That last one "
            "is cheap wherever a route already yields a machine account (RBCD, "
            "MachineAccountQuota).\n"
            "  What it is NOT evadable by: renaming tooling. The replication "
            "GUIDs are protocol constants - you cannot request replication "
            "without asking for them. That is the opposite of the Shape D case, "
            "where renaming a cmdlet defeats the rule, and it is a first "
            "concrete instance of the evasion-difficulty axis logged as future "
            "work in `docs/abstract.md`.\n"
            "  No tier split: see `tier_conditional_not_applicable`. Every "
            "target is a domain object, so the base *is* the tier-zero case."
        ),
        source=(
            "SigmaHQ rules/windows/builtin/security/"
            "win_security_ad_replication_non_machine_account.yml - 'Active "
            "Directory Replication from Non Machine Account - DcSync "
            "Indicator', id 17d619c1-e020-4347-957e-1d1207455c93, author "
            "Roberto Rodriguez (@Cyb3rWard0g). Status: test. Documented "
            "false-positive rate: medium. Requires a SACL on the domain root "
            "and the Directory Service Access audit subcategory. ATT&CK "
            "T1003.006 (OS Credential Dumping: DCSync), from the rule's tags.\n"
            "SELECTION, read from the rule body rather than a summary - "
            "EventID 4662 and Properties|contains any of FOUR GUIDs, all now "
            "resolved: 1131f6ad-9c07-11d1-f79f-00c04fc2dcd2 "
            "DS-Replication-Get-Changes-All; 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2 "
            "DS-Replication-Get-Changes; 9923a32a-3607-11d2-b9be-0000f87a36b2 "
            "DS-Replication-Synchronize; 89e95b76-444d-4c62-991a-0facbeda640c "
            "DS-Replication-Get-Changes-In-Filtered-Set.\n"
            "FILTERS: SubjectUserName endswith '$'; SubjectDomainName 'Window "
            "Manager'; SubjectUserName startswith 'NT AUT' or 'MSOL_'. "
            "Condition: selection and not 1 of filter_main_* and not 1 of "
            "filter_optional_*.\n"
            "The selection carries NO AccessMask term. A secondary summary "
            "claimed 0x100 (Control Access); the rule body does not contain it. "
            "Recorded because it would have been an invented detail.\n"
            "FILENAME TRAP: an earlier search returned "
            "'win_security_dcsync.yml' for this rule. That file does not "
            "exist; the path above is the real one. Recorded so the wrong "
            "citation is not re-derived."
        ),
    ),
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


# ---------------------------------------------------------------------------
# Stage 3: the history-dependent model
# ---------------------------------------------------------------------------

REPEAT_MULTIPLIER = 1.2
"""`k` in the proportional repeat step. **A declared parameter, not a derived one.**

Nothing in the telemetry baseline fixes this value, and saying so plainly is part
of the model rather than a caveat on it. The sourcing pass priced *first*
occurrences — it found named rules, event IDs and severities for an action
happening once. No evidence in it speaks to what a defender does on the second
sighting, because the baseline excludes the correlation and UEBA capability that
would notice.

**So the defence of `k` is the sweep, not the point value.** This is written
before any result exists, deliberately, so it cannot read later as a response to
an inconvenient number: conclusions are to be reported as the *range of `k` over
which they hold*, plus the value at which any conclusion flips — exactly the
treatment `DCSync` got in the H4 threshold analysis, using the same machinery.
P16 (monotone in the penalty parameter, deferred) is the property that covers
this axis.

1.2 is the working default, chosen to satisfy P15 against the weight ceiling
with margin. See `max_repeat_step`.
"""

P15_DECLARED_FRACTION = 0.25
"""P15's "declared fraction of the total range" — the bound a single repetition
may not exceed.

Stated against `WEIGHT_CEILING`, not against the largest weight actually in the
table. That decoupling is deliberate: bounding against the observed maximum would
make P15 fail later when some unrelated weight is sourced upward, which is the
hidden-dependency pattern that caused documented drift earlier in this project.

Read `max_repeat_step` for the two numbers that matter and do not confuse them —
the bound is 2.0 (25.3% of range, and only reachable if a weight reaches the
ceiling of 10.0), while today's *actual* maximum step is 1.3, about 13% of range,
because the highest sourced weight is `DCSync` at 6.5. "Holds with headroom" is a
statement about the bound, not a measurement of the model.
"""


def max_repeat_step(k: float = REPEAT_MULTIPLIER,
                    table: dict[str, RiskWeight] = PROVISIONAL_WEIGHTS
                    ) -> tuple[float, float]:
    """`(bound_at_ceiling, observed_max)` for the repeat step, in weight units.

    Two numbers on purpose. The first is what P15 is checked against and is
    stable under any weight change; the second is what the model does today.
    Reporting only the first overstates the step; only the second makes P15
    brittle.
    """
    heaviest = max((w.weight for w in table.values()), default=WEIGHT_FLOOR)
    return WEIGHT_CEILING * (k - 1.0), heaviest * (k - 1.0)


def history_cost_fn(table: dict[str, RiskWeight] = PROVISIONAL_WEIGHTS,
                    k: float = REPEAT_MULTIPLIER
                    ) -> Callable[[AttackGraph, int, Sequence[int]], float]:
    """Cost function in the planners' shared signature, reading `path_so_far`.

    Summary A: the attacker's history is summarised as **the set of technique
    categories used so far** — nine categories, one bit each. An action costs its
    static weight the first time its category appears on the route, and
    `weight * k` on every appearance after that.

    **Proportional, not uniform**, and the reason is a result rather than a
    preference. A uniform additive step would charge the same increment for
    repeating `MemberOf` as for repeating `DCSync` — but `MemberOf` is sourced at
    the floor with *both* baseline halves recorded as `NONE_FOUND`, meaning the
    sourcing pass established there is no detection at all. A fixed step would
    manufacture loudness there, silently overturning a sourced negative result on
    the exact hop that decides the `SQL_SVC` route. Scaling by the edge's own
    weight leaves it at the floor.

    The second reason is the baseline. A uniform step models a defender who
    notices "this category has appeared before" independently of severity;
    nothing in a default-logging posture does that, because what reaches a human
    is gated by rule severity. Proportional models repetition as *amplifying
    existing signal* rather than creating new signal, which is what a severity-
    gated queue actually does.

    **Non-decreasing after the first repeat, by construction.** The state carries
    one bit per category, so the second and third uses are indistinguishable and
    must cost the same. That is P2 in its restated form, and it is a consequence
    of Summary A rather than a modelling choice made here.

    `k=1.0` disables the history term exactly — `weight * 1.0` is exact in IEEE
    754 — which is what P6 checks against `static_cost_fn`.

    Known limitation, demonstrated rather than hypothetical: the nine categories
    do not all group edges that share a detection rule. `acl_abuse` holds both
    the Shape D writes (SACL + a script-block rule) and `AddMember`/`AddSelf`
    (default channel, no endpoint rule) — different events, different baseline
    halves, different severities, no shared rule. Repeating across that boundary
    asserts a transfer the baseline does not support. The proportional form
    bounds how far that error travels, since the step is computed from the edge
    actually being taken. See `docs/stage3_risk_model_properties.md`.
    """
    def cost(graph: AttackGraph, edge_index: int,
             path_so_far: Sequence[int]) -> float:
        edge = graph.edges[edge_index]
        base = weight_of(edge.rel_type, table)
        # category_of raises on unknown types (build rule 4). Left to propagate:
        # an uncategorised edge must not quietly take the first-use branch.
        seen = {category_of(graph.edges[i].rel_type) for i in path_so_far}
        return base * k if category_of(edge.rel_type) in seen else base

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
