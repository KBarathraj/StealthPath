# Joint-Capability Audit — where one edge overstates what an attacker holds

**Status: review output, not a change.** Nothing in `risk.py` or
`ATTACK_MAPPING_STUB` was touched to produce this. Every row is a *candidate*
that needs verifying against BloodHound's edge documentation and the version you
actually collect with — the same standard the weights themselves are held to.

## Check this first — where does the missing piece live?

Standing principle, stated as build rule 9 in `CLAUDE.md`. For any edge that
claims a capability the attacker might not hold:

| Missing piece is… | Then… |
|---|---|
| visible on a sibling edge or a node property | **gate it statically** — `PARTIAL_RIGHT_EDGES`, `with_preconditions()`, or a scoped expansion view |
| a fact about the route taken | **it is Stage 3's** — no static view can see it, and approximating it here is silently wrong |

Every entry below is one or the other. Sort a new case into the right column
before designing a fix.

## The pattern we're looking for

`GetChanges` and `GetChangesAll` each look like they grant replication. Neither
does alone; only both together do. A planner that walks one of them claims a
capability the attacker does not have — and prices it *cheaper* than the real
thing, because one right costs less than two. That combination (wrong **and**
cheap) is what makes this class of bug attractive to a cost-minimising planner:
it will actively seek these edges out.

BloodHound solved the replication case by marking both halves non-traversable
and post-processing them into the composite `DCSync` edge. We now match that.
The question this audit answers is: **where else does the same shape occur?**

Five distinct shapes turned up. Only Shape A is the exact `GetChanges` pattern;
the rest are near-relatives that fail the same way — an edge that reads as a
complete capability but isn't.

---

## Shape A — two edges, both genuinely required

The exact pattern. An edge is insufficient alone and there is a real second edge
that completes it.

| Rows | Needs, jointly | Status |
|---|---|---|
| `GetChanges` + `GetChangesAll` | → `DCSync` | **Handled.** Both non-traversable, composite walkable. |
| `GetChanges` + `GetChangesInFilteredSet` | → `SyncLAPSPassword` | **Handled**, same fix. |
| `WriteGPLink` | control of a GPO worth linking | **Open — highest priority.** |

**`WriteGPLink` is the strongest unhandled candidate.** Linking a GPO to an OU
does nothing unless you also control a GPO containing something malicious —
which means a separate `GenericWrite`/`GenericAll`/`Owns` edge onto a GPO
object, or the right to create one. `WriteGPLink` alone is the right to link a
*benign* policy. It is currently walkable and weighted 6.0, so a planner can
"reach" GPO abuse across one edge for a capability that needs two.

Note this interacts with the `GPLink` traversal exclusion. `GPLink` (the
structural edge) is already excluded; `WriteGPLink` (the ACL edge) is not, and
they are easy to confuse when reading the schema quickly.

---

## Shape B — edge plus a node property that isn't checked

The second requirement is a property on a node, not an edge, so no amount of
edge filtering catches it.

- **`AllowedToAct` / `AddAllowedToAct` (RBCD).** Abusing resource-based
  constrained delegation needs a principal you control that has an SPN. The
  usual route is creating a computer account, which needs the domain's
  `ms-DS-MachineAccountQuota` to be non-zero — a domain-object property. Where
  quota is 0 and you control no SPN-bearing account, the edge is not actionable.
  **Strong candidate.**
- **`AllowedToDelegate` (constrained delegation).** With protocol transition
  (`TRUSTED_TO_AUTH_FOR_DELEGATION` in the account's UAC), S4U2Self works
  standalone. Without it, you need an existing forwardable ticket from a victim,
  which is a materially harder and louder precondition. **One edge, two very
  different capabilities, one weight.**
- **`DumpSMSAPassword`.** Requires admin on the host where the sMSA is
  installed — i.e. jointly with an `AdminTo`. Lower priority: routes reaching
  the sMSA usually pass through the host anyway, so the path may already imply
  it. Worth confirming rather than assuming.

---

## Shape C — edge plus an environment precondition the graph can't express

The second requirement isn't in the graph at all, so it can never be checked.

- **`AddKeyCredentialLink` (Shadow Credentials).** Depends on PKINIT working,
  which requires an enterprise CA issuing KDC certificates. No AD CS, no shadow
  credentials — the edge is inert. `NODE_KINDS` has no ADCS concept, so the
  graph cannot represent the difference between a domain where this works and
  one where it doesn't. **Strong candidate, and the hardest to fix.**
- **`ReadLAPSPassword` / `SyncLAPSPassword`.** Derived from the ACL, but an ACL
  granting read on the LAPS attribute yields nothing on a host where LAPS was
  never deployed or the attribute is unpopulated. The fixture carries a `haslaps`
  property; real collections expose the attribute's presence. Also confirm which
  LAPS your environment runs — legacy and Windows LAPS use different attributes
  and BloodHound models them differently.

---

## Shape D — one edge standing in for a multi-step sequence

Not jointness, but the same failure: the edge understates both the hop count and
the total noise, because using it is several actions rather than one.

| Edge | What it actually takes |
|---|---|
| `WriteOwner` | take ownership → write the DACL → use the new right (3 actions) |
| `Owns` | ownership is not a capability; it is the right to grant yourself one |
| `WriteDacl` | write the DACL → use the granted right (2 actions) |
| `ForceChangePassword` | reset → authenticate as the victim. Also *destructive* — it locks the real user out, which is its own detection channel and isn't captured by a single quiet-vs-loud number |
| `WriteSPN` | write SPN → request ticket → crack offline → clean up. And the payoff is **probabilistic**: a strong password means the whole chain yields nothing |

`WriteSPN` is the interesting one, because it's the only edge here whose success
isn't guaranteed. Every other edge in the schema either works or doesn't; this
one works with some probability. That may deserve modelling rather than a flat
weight.

---

## Shape E — one edge whose meaning depends on the target's type

### `AllExtendedRights` — confirmed Shape E, not a new category

**Status: dropped via `drop_unknown_edges` for now; folds into the planned
kind-aware costing fix rather than needing its own treatment.**

Turned up in the real collection (**88 edges**) as an unknown type. It is not a
new shape — it behaves exactly like `GenericAll`/`GenericWrite`, meaning
different things by target kind:

| Target | What the right actually grants |
|---|---|
| Domain | the replication rights — DCSync-equivalent |
| User | password reset — `ForceChangePassword`-equivalent |
| Computer with LAPS | LAPS password read — `ReadLAPSPassword`-equivalent |

So when target-kind-aware costing lands, this rides along with the same
mechanism. Weighting it as a single flat number would repeat the exact problem
Shape E already documents, and here it would be worse: the Domain case is
DCSync-grade while the User case is a password reset.

> ⚠️ **Do not model `AllExtendedRights` as granting RBCD.** BloodHound's own
> historical documentation linked it to resource-based constrained delegation.
> That association is wrong and should not be carried into the weights or the
> schema, however plausible it looks in older references.

### `GenericAll` / `GenericWrite`

`GenericAll` and `GenericWrite` mean materially different things depending on
what they point at:

| Target | Actual abuse |
|---|---|
| User | password reset, or shadow credentials |
| Group | add member |
| Computer | RBCD, or shadow credentials |
| GPO | modify policy — affects everything linked |

One weight covers all four. `risk.py`'s rationale for these already half-admits
it ("loudness depends on what you actually write, which this static model cannot
see"). The graph *does* know the target's `kind`, so this is the most tractable
item on the list: the cost function has the information, it just doesn't use it.

---

## Also worth a second pair of eyes (different failure, same silence)

- **`TrustedBy` direction.** Trust relationships are a classic source of
  inverted-arrow bugs, and an inverted trust edge produces confident, wrong,
  entirely plausible-looking paths. Verify against a known two-domain case
  before trusting any cross-domain route.
- **`HasSIDHistory` categorisation.** Sits under `credential_access`, but
  traversing it is passive — the SID is already in the token. `risk.py`'s
  rationale flags this too. Miscategorised edges will matter more in Stage 3,
  where the model is expected to reason per-category.

---

## Defender-sophistication baseline — assume this, and only this

**Every weight is priced against a reasonably instrumented defender.** Assumed
present:

- standard Windows security logs ingested into a SIEM;
- **EDR / Sysmon-class endpoint telemetry** (process creation, LSASS access,
  image loads);
- **well-known native AD auditing that a competent shop enables** — Directory
  Service Changes (5136), SACL auditing on tier-zero objects.

Assumed **absent**: custom-built correlation, UEBA, and bespoke environmental
baselining. In other words, the defender has bought and switched on the standard
tooling; they have not built anything themselves.

This has to be stated because "is this loud?" is meaningless without it. The same
technique is invisible to one shop and trivially caught by another, and a scale
that silently mixes assumptions produces numbers nobody can reason about.

Practical test when sourcing a weight: *would a named rule shipped with standard
tooling, or a default-enabled audit channel, catch this?* A MITRE detection
**strategy** describing a correlation approach the defender would have to build
does not clear the bar.

### Never derive a sourced weight by anchoring to an unsourced one

Second named failure mode, and subtler than the first.

Most of this table is still provisional guesses. Picking a number for a weight
you are sourcing by reasoning *"it should sit just above `ExecuteDCOM`"* imports
that guess into the sourced value. Two things then break: the new number is only
as good as the old guess, and the before/after comparison across the sourcing
pass becomes circular, because the "after" table is a function of the "before"
one.

**Method:** derive each weight bottom-up from named detections and default log
sources alone. Only *then* look at where it lands relative to its neighbours,
and record that ordering as a **prediction** in the cross-check list below —
to be re-tested when each neighbour is itself sourced.

**If a derived number contradicts a provisional neighbour, the neighbour is what
is wrong.** That is the expected outcome, not a problem with the derivation.

#### Cross-check when sourced

Predictions to re-test as each neighbour gets its own citation. A failed
prediction means the neighbour needs re-deriving, not the sourced value.

| Sourced weight | Predicted relationship | Re-test when |
|---|---|---|
| `AllowedToDelegate` 4.0 | sits **below** `GenericAll`/`WriteDacl`/`WriteOwner` (5.0) | Shape D is sourced |
| `AllowedToAct` 4.5 | sits **below** the same three | Shape D is sourced |
| `AddAllowedToAct` 5.0 | **equal to** those three on non-tier-zero targets | Shape D is sourced |
| `SpoofSIDHistory` 3.5 | sits **below** all ACL writes | Shape D is sourced |
| all four | sit **above** `AdminTo` (3.0) | `AdminTo` is sourced |
| `AllowedToDelegate` 4.0 | sits **above** `CanRDP` (3.5) | `CanRDP` is sourced |

> **Specific thing to re-test, not a general note:** the Shape D SACL/tier pass
> may push `WriteDacl`/`WriteOwner`/`Owns`/`GenericAll`/`GenericWrite` **below
> 3.5** on non-tier-zero targets, since without a SACL there is no 5136 and
> therefore no detection at all for the majority of those ~4,500 edges. That
> would **flip every prediction in the first four rows** — the delegation trio
> and `SpoofSIDHistory` would end up *louder* than the ACL writes rather than
> quieter.
>
> That is not a hypothetical: it follows directly from the baseline as written.
> When it happens, the flip is the correct result and these predictions are what
> was wrong.

### The scale measures likelihood of notice, not severity of impact

**Re-run this check on every weight before finalising it.** These two get
conflated constantly, and the conflation always pushes the same direction — a
technique that would be catastrophic if it succeeded drifts upward on a scale
that is supposed to be about whether anyone *sees* it.

They are independent. `DCSync` is both high-impact and loud, which makes the
confusion invisible there. `SpoofSIDHistory` is catastrophic and quiet.
`MemberOf` is trivial and silent. Only the second axis belongs in this table.

This was caught concretely: the delegation trio's original 6.5/6.5/7.0 was
partly encoding "sophisticated, high-impact technique" rather than measured
loudness, and the clause carrying that weight (`"no benign analogue"`) turned
out to be factually wrong.

**Where the leak is most tempting next:** the Shape D edges — `WriteDacl`,
`WriteOwner`, `Owns`, `GenericAll`, `GenericWrite`, `AddKeyCredentialLink`. Each
grants sweeping control, so the instinct is to price them high. Control is
impact. The question here is only whether 5136 fires and whether anyone is
watching that object. Ask it separately, in those words, for each one.

### Retroactive check under the revised line

| Weight | Rationale as written | Verdict |
|---|---|---|
| `HasSession` 6.0 | "the single most heavily instrumented action on a modern endpoint" | **Holds.** LSASS access is exactly what EDR/Sysmon Event 10 is for, and that tier is now assumed present. |
| `WriteDacl` / `WriteOwner` / `GenericAll` / `AddKeyCredentialLink` | directory-service auditing | **Holds.** Event 5136 is a native audit channel a competent shop enables, now in scope. The hedging in those rationales ("that conditional is doing a lot of work") can be dropped when each is formally sourced. |
| `DCSync` 9.0 | "the canonical AD detection" | **Holds.** 4662 with the replication GUIDs, via SACL auditing on the domain object — native, well-known, and in scope. |
| `AllowedToDelegate` 6.5 | "S4U2Proxy leaves a distinctive Kerberos ticket pattern that has no benign analogue" | **Weight holds, wording does not** — see below. |
| `AllowedToAct` 6.5 / `AddAllowedToAct` 7.0 | "same ticket-level signal" / "two signals, one edge" | **Hold**, same reasoning. |
| `SpoofSIDHistory` 3.5 | forged TGTs are cryptographically valid | **Still excluded, correctly.** DET0144 is a behaviour-chain correlation strategy — the defender would have to build it. This is the one case the revised baseline does *not* rescue, which is why it prices low. |

> ⚠️ **Open, deliberately not acted on: the delegation trio's adjacency to
> `GenericAll` is coincidental.** Wherever the trio lands after revision, it will
> sit at or near `GenericAll`/`WriteDacl`/`WriteOwner` — and that proximity is an
> artifact of two independent revisions happening at different times, not a
> considered judgement that Kerberos delegation abuse and a DACL write are
> equally loud. **Re-check explicitly once Shape D sourcing lands**, since those
> five are about to move and may cross the trio. If they end up adjacent again
> after both are sourced, that should be because someone compared them directly.

**The delegation trio survives, but one clause in it is factually wrong.**
S4U2Proxy is visible in a standard field: 4769 events carry a populated
*Transited Services* field on constrained-delegation requests, and that is
native Windows logging, not correlation. So the weights stand.

What does not stand is *"has no benign analogue."* Constrained delegation is a
legitimate, widely-used feature, and S4U2Proxy fires constantly in environments
that use it. Telling malicious from legitimate means knowing which delegations
are expected — that is configuration knowledge a defender can enumerate, so it
stays inside the baseline, but it is emphatically not "no benign analogue."
**Correct that clause when the trio is formally sourced; do not carry it into a
citation.**

## Sourcing guidance for Shape D — price the chain, not the edge

> ### ⚠️ Read before pricing any Shape D edge: the SACL/tier problem
>
> Every Shape D rationale leans on **5136** as the detection. **5136 only fires
> where a SACL exists**, and this project's baseline assumes SACLs on
> **tier-zero objects only**.
>
> These five edges are ~4,500 of ~6,700 real ACEs in the collection, and the
> overwhelming majority target objects that are **not** tier-zero — ordinary
> users, ordinary computers, ordinary groups. Pricing them as though 5136
> catches all of them assumes an auditing posture the baseline explicitly does
> not grant.
>
> This is not a rounding error. It is the difference between "a directory-change
> event fires and someone is watching" and "nothing is recorded at all", applied
> to two thirds of the graph.
>
> **Do not average it away into a single number.** The honest options are the
> same two offered for `AddAllowedToAct`: price the unconditional (no-SACL) case
> and record the tier-zero premium as a documented conditional, or hold the
> premium and make these an explicit dependency on **target-kind *and* tier**
> aware costing. Whichever is chosen, state it per edge before assigning a
> figure.

**Applies to `WriteOwner`, `WriteDacl`, `Owns`, `ForceChangePassword`.** When
these reach the sourcing pass, the weight must reflect the **full real action
sequence**, not one atomic action. Each of these edges is several operations
wearing one label, and a weight sized as though it were a single step understates
both the hop count and the noise.

| Edge | Sequence the weight must cover |
|---|---|
| `WriteOwner` | change the owner → write the DACL → use the granted right |
| `Owns` | (already owner) → write the DACL → use the granted right |
| `WriteDacl` | write the DACL → use the granted right |
| `ForceChangePassword` | reset the password → authenticate as the victim |

Note this cuts against the instinct to source these from a single ATT&CK
technique: the technique ID will describe one operation, and the weight has to
cover the chain.

### `Owns` is not simply a shorter `WriteOwner` — verify before equating them

The assumption behind treating ownership as control is that **Active Directory
implicitly grants the owner `WRITE_DAC` and `READ_CONTROL`**, so an owner can
always rewrite the object's DACL and grant themselves anything. That is correct
by default and is the documented basis for BloodHound's `Owns` edge.

**It is not unconditional.** Microsoft's own specification has a section titled
*Blocking Implicit Owner Rights*: when an ACE carrying the **OWNER RIGHTS** SID
(`S-1-3-4`) is present on an object, the system **ignores** the implicit
`READ_CONTROL` and `WRITE_DAC` the owner would otherwise hold. Where that ACE is
deployed, `Owns` grants no DACL-rewrite capability at all and the edge is inert.

Three consequences for the sourcing pass:

1. `Owns` and `WriteOwner` should **not** be given the same weight by default —
   `WriteOwner` includes an extra operation (changing the owner) that `Owns`
   does not.
2. Both are **conditional** on OWNER RIGHTS not being set, and the graph does not
   carry whether it is. Same shape as the AD CS gap below: a precondition the
   collection does not express.
3. ~~Check whether the BloodHound version you collect with accounts for OWNER
   RIGHTS when emitting `Owns`.~~ **Checked: it does not.** Confirmed against
   SpecterOps' current `SharpHoundCommon` source (`ACLProcessor.cs`) — `Owns` is
   emitted unconditionally, with no OWNER RIGHTS SID check. So the
   conditionality is **real and unaddressed in collected data**, not handled
   upstream. Every `Owns` edge in the graph asserts a capability that an OWNER
   RIGHTS ACE would negate, and nothing downstream can tell the difference.

Sources to cite: [MS-ADTS 6.1.3.4, Blocking Implicit Owner
Rights](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-adts/fb7c101d-ec8b-4fbf-bca8-7d7c2d747d0c)
for the implicit-rights mechanism and its suppression; [*An ACE Up the Sleeve*
(Robbins/Schroeder, Black Hat US
2017)](https://specterops.io/wp-content/uploads/sites/3/2022/06/an_ace_up_the_sleeve.pdf)
for the abuse and detection framing.

---

## Known limitations — accepted, not oversights

### ForceChangePassword's destructive effect is outside the model

Separate from the chain-length point above, and **not** something to fold into
the existing weight scale.

Resetting a user's password locks the real user out. They notice, and they call
the service desk. That is a detection channel — often a fast one — but it is not
the kind of detection this model represents. The risk scale measures
**technical/telemetry** visibility: what lands in event logs, what EDR sees, what
a Sigma rule fires on. A human noticing their password stopped working and
reporting it is a different mechanism with a different timeline, and it does not
belong on the same axis.

Folding it in by inflating the weight would be wrong twice over: it would make
the number mean two incommensurable things at once, and it would be invisible to
anyone reading the scale later.

So `ForceChangePassword` is weighted for its telemetry footprint only, and this
limitation is named rather than absorbed. Anything reporting results involving
this edge should say so — the model understates how quickly this technique gets
noticed in practice.

**Revisit when:** the model gains a second axis for non-telemetry detection.
Not before; a single number cannot carry both.

### Citation found while sourcing the delegation trio — affects two parked items

`win_security_alert_ad_user_backdoors.yml` (`300bac00-e041-4ee2-9c36-e262656a6ecc`)
matches **three** 5136 attribute writes, not one. Pulled in full while sourcing
`AddAllowedToAct`:

| Selection | Attribute | Relevance |
|---|---|---|
| `selection_5136_1` | `msDS-AllowedToDelegateTo` | configuring classic delegation — no BloodHound edge maps to it (our `AllowedToDelegate` is pre-existing config, not a write) |
| `selection_5136_2` | `servicePrincipalName` on `ObjectClass: user` | **live citation for `WriteSPN`** |
| `selection_5136_3` | `msDS-AllowedToActOnBehalfOfOtherIdentity` | cited for `AddAllowedToAct` |

Plus `selection1`: EventID 4738 with `AllowedToDelegateTo` populated.

**`WriteSPN` now has a shipped named rule** — writing an SPN onto a user account
is exactly targeted Kerberoasting, and this fires on it. It is still parked, but
it is no longer citation-less: use `selection_5136_2` when its turn comes. Note
this covers only the SPN *write*; the offline crack remains unmodellable, so the
"overstated certainty" limitation below is unaffected.

**`AddKeyCredentialLink` is NOT covered.** `msDS-KeyCredentialLink` does not
appear in this rule. Checked specifically; it still needs its own citation.

**`SpoofSIDHistory` is not covered either** — no `sIDHistory` selection here. Its
"deliberately not cited" note names SigmaHQ `2632954e…`, which is the correct
rule to decline. This rule was also checked and also does not apply, for the
same underlying reason: **forgery never touches the directory, so no 5136-based
rule can see it.**

All of these inherit the SACL/tier dependency — 5136 only fires where a SACL
exists.

### WriteSPN / targeted Kerberoasting — flat weight, certainty overstated

**Decision: parked, same pattern as AddKeyCredentialLink.** When sourcing reaches
it, give it a flat weight and move on.

`WriteSPN` is the only edge in the schema whose success is **probabilistic**.
Writing the SPN and requesting the ticket always work; what follows is an offline
crack, and against a strong service-account password it yields nothing. Every
other edge either works or does not.

A flat weight treats the whole chain as though it always succeeds, which
**overstates attacker certainty**. Password strength is not in the graph and
SharpHound has no way to collect it, so the model cannot do better without
inventing a crack-probability parameter — a number with nothing behind it, which
is precisely what `require_sourced` exists to prevent.

Note the direction differs from AD CS below: that one overstates the attacker
where infrastructure is absent, this one overstates the attacker where passwords
are strong. Both are safe directions for a defensive tool; both should be stated
wherever numbers are reported.

**Revisit when:** the model represents outcome probability rather than only
cost — which is a Stage 3 modelling change, not a weight.

### AddKeyCredentialLink / Shadow Credentials — REVISIT TRIGGER HAS FIRED

**Status: scheduled, pending the ADCS categorisation pass.** Not solved, not
still deferred-indefinitely — the condition this was waiting on has been met.

The trigger was *"a real collection actually surfaces AD CS objects."* The
GOADv2 collection ingested on 2026-08-03 does, in volume:

| | |
|---|---|
| `AddKeyCredentialLink` edges | **66** |
| EnterpriseCA / RootCA / AIACA / NTAuthStore | 2 each |
| CertTemplate nodes | 71 |
| `Enroll` edges | 181 |
| ADCS escalation edges | `ADCSESC1` (5), `ADCSESC3` (8), `ADCSESC4` (5), `GoldenCert` (2) |

So the infrastructure PKINIT needs is present and BloodHound has already
computed concrete escalation paths over it. The "we cannot tell whether this
edge works" objection no longer applies to this graph — we now know it does.

What still blocks it: the ADCS node and edge kinds are **dropped at load** in the
current freeze, so certificate-abuse paths are absent from the graph entirely.
Un-deferring means categorising ~14 ADCS relationship types and 4 node kinds
first. Until that happens the 66 `AddKeyCredentialLink` edges remain weighted as
though they always work, which in *this* environment is now known to be roughly
right rather than merely assumed.

**Original reasoning, retained for context:** abusing this needs PKINIT, which
needs an enterprise CA issuing KDC certificates. Where AD CS is absent the edge
is inert, and where it is present the attack is straightforward — so the edge's
true cost swings entirely on infrastructure the graph cannot see.

`NODE_KINDS` has no AD CS concept: no CA, no certificate template, no
enrolment-right edges. Representing this properly is a schema expansion, not a
weight, and it would need collection to cover AD CS in the first place.

So `AddKeyCredentialLink` stays traversable and weighted as if it always works.
That **overstates** the attacker in environments without AD CS — the safe
direction to be wrong for a defensive tool, but state it wherever numbers get
reported.

**Revisit when:** a real collection actually surfaces AD CS objects. Check the
first SharpHound ingest for certificate-template or CA nodes; if they are there,
this becomes worth doing and the dropped-edge-type warning in `graph.provenance`
will say so.

### SpoofSIDHistory understates what it wins — stated limitation, not open

**Settled: traversal is correct, the prize is understated.**

The edge is `Domain -> Domain` and represents a cross-forest trust with weak SID
filtering. Traversing it lands on the target **domain object**, which is already
in `tier0_targets()`, so the destination is right and no new target modelling is
needed.

What the edge does *not* carry is which privileged group you end up in. SID
filtering blocks RIDs below 1000, so Domain Admins (512) and Enterprise Admins
(519) **cannot** be spoofed cross-forest; the viable targets are custom groups at
RID >= 1000. In this collection that is concretely `DRAGONRIDER@SEVENKINGDOMS`
(RID 1111, BloodHound-tagged Tier Zero), which in turn holds
`MemberOfLocalGroup -> ADMINISTRATORS@SEVENKINGDOMS -> KINGSLANDING` — local
admin on the SEVENKINGDOMS DC.

So the real capability is "become a member of a specific RID >= 1000 privileged
group in the target domain," and the edge compresses that to "reach the domain."
That is a **stated simplification, not an open schema question**: the graph
arrives at a genuine tier-0 target either way, and modelling the specific group
would need per-edge target selection the edge type does not carry.

### ClaimSpecialIdentity — safe to admit, but worthless

Checked rather than assumed, because the worry was that admitting it would let
every principal reach everything through `EVERYONE`:

- Real principals **are** `MemberOf` the special identities (`EVERYONE`,
  `AUTHENTICATED USERS`), so the entry into that cluster exists.
- The special-identity groups hold **zero outbound rights** — none at all.
- Every `ClaimSpecialIdentity` edge runs from `EVERYONE` to another
  special-identity pseudo-group, and those are terminal.

So the cluster is a dead end. Admitting the edge would create no new attack path
and no new risk of a spurious one. It stays dropped on the grounds that it adds
nothing, not on the grounds that it is dangerous.

### Local-group chain — admitted, but gated

`MemberOfLocalGroup` + `LocalToComputer` are BloodHound CE's local-admin model
and are now known to the schema as **structural**, with
`AttackGraph.with_local_admin_expansion()` re-admitting the chain for privileged
local groups only.

The gate is not optional. `LocalToComputer` runs out of *every* local group on a
machine — in this collection that includes `USERS`, `GUESTS`, `IIS_IUSRS`,
`PRE-WINDOWS 2000 COMPATIBLE ACCESS` and `WINDOWS AUTHORIZATION ACCESS GROUP`.
Admitting it wholesale would mean membership in local `Users` reaches the
machine, and effectively every domain account is in local Users on every
machine, so every principal would reach every DC. Third instance of the same
failure shape, after `GetChanges` and `WriteGPLink`.

Matched on the objectid's RID suffix rather than the group name, because names
are localised and `S-1-5-32-544` is not. On this collection the gate cuts the
chain from 72 edges to 18.

**Sourcing note:** membership of `544` (Administrators) prices as `AdminTo`,
`555` (Remote Desktop Users) as `CanRDP`. These are those techniques reached a
different way, not new techniques.

### GPLink / Contains carry no risk weight

The GPO expansion route is walkable but cannot be *costed* — the weighted
planner raises on it. Pinned by `test_gpo_route_cannot_be_costed_yet`. Weighting
them is a `risk.py` change and belongs with the sourcing pass.

**Agreed direction: both near the floor.** Neither is an attacker action. The
action is writing the GPO, already priced on the ACL edge onto it; `GPLink` and
`Contains` are Group Policy applying, which the OS does by itself. Pricing them
meaningfully would double-count the write.

An earlier draft argued `GPLink` should sit slightly above the floor because
policy-pushed payloads generate endpoint telemetry on execution. **That argument
does not hold** — GPO-pushed execution runs through the legitimate Group Policy
Client service with a legitimate parent process, so it is largely invisible
without GPO-specific monitoring. Under the defender baseline above, there is no
extra signal to charge for.

> **Refinement to apply when `GenericWrite` / `GenericAll` are sourced:** the
> write-side detection for GPO abuse should cite SigmaHQ's
> `win_gpo_scheduledtasks.yml` specifically, not a generic ACL-write rule. The
> generic citation would not actually cover this technique.

---

## One-line triage for the remaining eight gate weights

No pricing, no derivation — the shape of the problem only, so the next pass
starts from something rather than nothing. All eight sit on a chosen or rejected
route for the three documented entry points.

| Edge | Shape of the problem |
|---|---|
| `MemberOf` | No action taken; the only trace is authentication that would have happened anyway. Should be at or near the floor and is the one weight unlikely to move. |
| `AdminTo` | Admin logon to a host — 4624/4672 fire by default, no SACL needed, but the volume is enormous. Visibility without suspicion; the base-rate argument from `CanRDP` applies directly. |
| `SQLAdmin` | Command execution via SQL. Detection depends on SQL Server auditing, which is **not** in the baseline's assumed set — needs deciding whether that counts as standard tooling. |
| `HasSession` | Already re-checked under the revised baseline and held at 6.0 (Sysmon Event 10, EDR-visible, no SACL dependency). Needs a named rule to finish, not a re-derivation. |
| `DCSync` | 4662 with the replication GUIDs. **The one edge whose SACL dependency probably survives** — it is the canonical AD detection and shops enable it *because* of this attack. Confirm rather than assume. |
| `ForceChangePassword` | 4724 fires by default with no SACL. Also destructive — the user is locked out and notices — but that is the named non-telemetry limitation and must not be folded into the number. |
| `AddMember` | 4728/4732/4756 fire by default, no SACL, and privileged-group modification is among the most widely alerted events in AD. Likely the loudest of these eight after `DCSync`. |
| `AddSelf` | Same events as `AddMember`, attacker as the subject. Expect the same number; check whether anything distinguishes them in the log. |

**Pattern worth noting before pricing:** most of these fire on **default-enabled
channels with no SACL requirement**, unlike the Shape D five. That is likely to
put several of them *above* the freshly-sourced ACL writes, which would sharpen
the contrast the `SQL_SVC` result depends on rather than flatten it.

## Triage status

1. ~~`WriteGPLink`~~ — **done.** Two parts.

   `AttackGraph.with_gpo_expansion()` re-admits `GPLink`/`Contains` for the
   GPO -> OU -> object chain only, pinned by the `gpo_abuse()` fixture.

   `WriteGPLink` itself is now in `PARTIAL_RIGHT_EDGES` — **globally**
   non-traversable, not a GPO-view special case. It is never sufficient alone:
   linking a policy requires separately controlling a policy worth linking, via
   an ACL edge onto a different node of a different kind, and BloodHound has no
   composite covering the pair. The decisive case was not the GPO chain but a
   single hop — BloodHound permits a domain object as a `WriteGPLink` target,
   domain objects are tier-0, so one edge reached full domain compromise at 6.0,
   cheaper than DCSync at 9.0. Pinned by
   `test_writegplink_into_a_domain_is_not_a_route`.

   Nothing real was lost: holding two rights out of one node simultaneously was
   never expressible as a path, so the only thing traversal contributed was
   false routes.
2. ~~`AllowedToAct` / `AddAllowedToAct`~~ — **done, partially.**
   `AttackGraph.with_preconditions()` drops RBCD edges whose source cannot wield
   them (not a Computer, no `hasspn`, domain quota zero), pinned by
   `rbcd_abuse()`. Deliberately conservative: acquiring an SPN-bearing account
   *partway along a route* also satisfies the precondition, and that is
   history-dependent, so it belongs to Stage 3 rather than a static view.
3. `GenericAll` / `GenericWrite` by target kind — **blocked on the weights.**
   The graph already carries the target's `kind`, and the cost function already
   receives the graph, so nothing structural is missing. Making cost vary by
   target kind means changing the cost function in `risk.py` and choosing
   per-kind numbers — which is the sourcing pass, not a schema change. Nothing
   to do here until those numbers exist.
4. `AddKeyCredentialLink` — see Known Limitations above. Not modelled.
5. Shape D — **settled, three different treatments, no schema change.**
   `WriteOwner` / `WriteDacl` / `Owns` and `ForceChangePassword` get the
   chain-length sourcing rule above (with the OWNER RIGHTS caveat for `Owns`);
   `ForceChangePassword` additionally has its human-detection channel named as
   an accepted limitation rather than absorbed into the scale; `WriteSPN` is
   parked with a flat weight and its overstated certainty documented.
