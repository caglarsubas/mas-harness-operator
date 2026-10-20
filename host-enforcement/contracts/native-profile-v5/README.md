# Native qualification captures v5 — the host fields become record-only (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-19. Status: **CONTRACT_CANDIDATE_ROUND4_AWAITING_INDEPENDENT_REVIEW** (candidate 4).

Contract review round 1 (of candidate 1, generator sha256 `9eed3c45…`) returned CHANGES_REQUIRED with 6 MINOR (E1-1 to
E1-6) and 4 NOTE (E1-7 to E1-10) findings. Round 2 (of candidate 2, generator sha256 `d8c23d0b…`) found E1-2 to E1-10
resolved and E1-1 open by design (it waits for owner question Q-NPE-9), and returned CHANGES_REQUIRED with 1 MINOR
(E2-1) and 2 NOTE (E2-2, E2-3) findings. Round 3 (of candidate 3, generator sha256 `33cf3f06…`) returned
PASS_FOR_ADOPTION with one NOTE (E3-1). Candidate 4 then applies the decisions on Q-NPE-9, Q-HE4D2-3 and Q-NPE-10
(below) and E3-1. The "Contract review round N findings and dispositions" sections at the end answer each finding. The
review records are kept outside the repository with the coordinator and are added with the status record at adoption.

v5 is the capture-only successor of the adopted native-profile v4 (`../native-profile-v4/`, ADOPTED, MET-ENFORCE-033),
owner decision Q-NPE-1 (c). It moves the three capture variants (the P1 role captures, the P5 lifecycle capture and the
backend captures) to v5 and drops from them the seven fields that v4 classes OUT_OF_SCOPE_HOST (v4 `README.md:134-136`):
`host`, `selinuxBefore`, `selinuxAfter`, `kernelPolicyDigest`, `booleansObserved`, `hardeningObserved` and
`bootEntryObserved`. v4 keeps "v3's equalities on them", but no reader role observes them, so HE-004D1 fills them from
the record (owner decision Q-HE4D1-1 (a), below) and those equalities hold by construction. v5 is the follow-up that
decision names, and it discharges W03-PLAN-AMEND-3's residual
(`architecture/w03-obligation-amendment-3/amendment.json:151`) and dependency name (`:282`).

The record contract stays native-profile v4's: the record `planeon.internal.native-qualification/v4`, its schema,
`check_record`, `check_migration`, and v4's record and migration vectors. Native-profile v1 to v4, I06 v3 and edge
records v1 to v6 are byte-identical; v5 never reinterprets earlier data, and a v4 capture is not a v5 capture. Nothing
here is a native result, installed profile, kernel observation or grant. Every vector and model result is
DATA_CHECK_ONLY, and all E01-E12 stay OPEN_UNPROVEN.

Base: main `f560209d04b7e0f07b2480219718a8a6dbdb21ef` (MET-ENFORCE-037, 250 packets). Slot 252; the packet id is
assigned when the contract is adopted. Scope: the slot-252 scope document (sha256 prefix `e9e66c08`), kept with the
coordinator outside the repository.

## Decisions (verbatim)

The owner's slot-252 decisions, relayed by the lane monitor (2026-10-19):

> Monitor relay, owner decisions on the slot-252 scope (SCOPE.md e9e66c08), 2026-10-19:
> - Q-NPE-1 (c): a capture-only native-profile v5. The record stays planeon.internal.native-qualification/v4, and v4 and I06 v3 stay frozen.
> - Q-NPE-2 (a): all seven host fields become record-only and are dropped from the captures, with the record unchanged. Observed booleans stay a later candidate; off-host attestation is carried to HE-008/T04.
> - Q-NPE-3 (b): keep OUT_OF_SCOPE_HOST "absent" with four named T04 proofs (T04-HOST-BOOT, T04-POLICY-STABLE, T04-HOST-LOCKS, T04-BOOT-ENTRY).
> - Q-NPE-4 (a): re-derive the 7 affected vectors in place (ids kept, v4 refusal recorded), add 18 negatives, and replay only the capture and qualification cases.
> - Q-NPE-5 (a): the ClusterRole I06 successor gets its own slot after 252 and before HE-008.
> - Q-NPE-6 (a): edge v7 (v8 if 251 publishes one first; it doesn't, so v7) with 3 rows labelled HE-004D2. Switch to (b) only if the D2 dossier advises a re-vendor first; bring that back to me.
> - Q-NPE-7 (a): architecture/native-profile-v5/ and scripts/native_qualification_v5.py.
> - Q-NPE-8 (a): keep the retained-capture rule minus the 7 fields.
> Record these verbatim and dated. GO for the contract draft and the contract review rounds (light). Mechanics wait for 251's merge and my word.

The decisions on the history rows, Q03 and the work item (2026-10-19, relayed by the lane monitor):

> Monitor relay, owner decisions, 2026-10-19:
> - Q-HE4D2-3 = (a): widen edge v7 by 3 rows for the v1–v3 history vectors (62 rows), for the exact 413-check replay.
> Monitor decisions (contract details, owner-delegated; I'll tell the owner):
> - Q-NPE-9 (a): re-derive Q03 as an eighth case with its refusal unchanged, using the v5 SERVER capture. Record the scope miscount; this amends Q-NPE-4's "7" to 8.
> - Q-NPE-10: NATIVE-PROFILE-V5.

The track that opened this contract (2026-10-19):

> Monitor relay, owner decision Q-NEXT-D2 = (a), 2026-10-19: two light tracks now, nothing heavy:
> (i) scope and draft the NATIVE-PROFILE-V4 host-field errata/successor contract for harness-onion slot 252, with contract review rounds; mechanics on my word after 251 merges;

The decision this contract follows up (2026-10-18):

> - Q-HE4D1-1 = (a): fill the host fields from the record's declared values, marked R10-side as not observed (a MODEL_DEFINED row); HE-008 and T04 keep the real reads. The owner accepts that those equalities are vacuous until a follow-up successor or errata drops them from captures.

## Text in force

- v4's README is in force for every rule v5 keeps: the record and its rules, the capture routes and the capturer, the
  evidence classes other than OUT_OF_SCOPE_HOST, the inspector obligation, the reader duties, and v4's T04 proofs,
  residuals and obligations. The sections below replace the v4 statements they name.
- For v5 captures, "The host facts", "The four T04 proofs" and "Evidence classes" below replace, narrow or make moot
  these v4 statements (v4 `README.md`):
  - **Replaced:** the OUT_OF_SCOPE_HOST bullet (`:134-136`); the seal marker "in `hardeningObserved`" in the
    declared-label row (`:158`), since v5 captures carry no `hardeningObserved`; the "host, policy and boot fields" row
    (`:159`); the P5 clause "booleans and the boot entry are OUT_OF_SCOPE_HOST" (`:183-184`); representation choice 5,
    "the rest of `hardeningObserved` keeps v3's equality" (`:471-472`); the K1 row's last sentence, "Every role and
    lifecycle capture reports the boot entry it observed ..., which must be the enrolled one" (`:505`), by "The host
    facts" and T04-BOOT-ENTRY; and "The observed `hardening.lockdown` value, pinned to `integrity`, remains the evidence
    of the lockdown state itself" (`:538`), by T04-HOST-LOCKS.
  - **Narrowed:** "host-policy reads ..., whose capture fields carry the class OUT_OF_SCOPE_HOST" (`:19-20`): the class
    stays, and its cells read "absent"; and the K1 statement "The recorded boot entries tell an honest maintenance boot
    apart" (`:511-513`): v4's captures did that at the data level (V39, V40), but v5's report no boot entry, so only
    T04-BOOT-ENTRY tells a maintenance boot apart. The record's entries and the limits listed under the K1 statement
    (`:514-536`) stay.
  - **Moot:** the seal marker label "in `hardeningObserved`" among the fields that leave the captures (`:264`), and
    decision 2's first sentence, "Boot-entry observation is loader-reported, not measured" (`:581`), since no v5 capture
    observes a boot entry.
- The W02 notes errata and HS43's replacement clause stay as v4 adopts them.

## Files

- `qualification.schema.json`: JSON Schema 2020-12, `$id` `urn:planeon:internal:native-qualification-capture:v5`, with
  the variants `capture`, `lifecycleCapture` and `backendCapture` only. Its definitions are v4's, in v4's order,
  restricted to the three variants and the 18 definitions they reach once the seven fields are gone (`host`,
  `observedBooleans`, `observedBootEntry`, `observedHardening`, `status` leave), plus the `evidenceClasses` constant.
  Every kept definition equals v4's as data, except the three variants and `evidenceClasses` (below): the dropped fields
  leave the variants' `properties` and `required`, and `schemaVersion` names v5. There is no record variant: the record
  is v4's. The schema holds no `/opt/planeon/`, `/run/planeon` or `/sys/fs` text.
- `vectors.json`: 5 positives (v4's five, records, profiles and endpoints unchanged, captures moved to v5); 266
  negatives (v4's 199 capture, 25 lifecycle, 5 backend and 19 qualification negatives, 8 of them re-derived, and
  H01-H18); 7 accepted cases (v4's capture-family accepted cases); 6 cross-version cases (X09-X14). `inputs` pins, by
  SHA-256, the v1 to v4 schemas and vectors that the replay reads.
- `../../scripts/native_qualification_v5.py`: the reference data model. It imports native-profile v4's model and binds
  v4's helpers and constants by name. `_shape`, `check_capture`, `check_lifecycle_capture`, `check_backend_capture`,
  `check_qualification`, `validate_capture` and `validate_qualification` are v4's functions with the changes below, so
  each function's v4-to-v5 diff is the review surface. `check_vectors` replays every v5 vector, checks every replayed v4
  case against its v4 form, and returns the number of checks (284).
- `status.json`: the candidate's status, its supersession record, the decisions and the four proofs.
  `source-index.json`: the subject and input digests; its subject leaves out `status.json` and edge record v7, which
  adoption rewrites.
- `../artifact-edges/operator-harness-engineering-v7.json` and `../artifact-edges/README-v7.md`: edge record v7, edge
  v6's 56 rows plus 6 new.

Caller obligations: v4's obligations 1 to 4 (v4 `README.md`, "Files"), unchanged. That `record_schema` is native-profile
v4's schema is checked, not a caller obligation: v4's `_shape` refuses any other schema ("unreviewed v4 qualification
schema").

## What v5 changes

| Item | v5 rule | Vectors |
|---|---|---|
| Capture shapes | P1 captures drop the seven fields, the P5 lifecycle capture drops `host`, `booleansObserved` and `bootEntryObserved`, and backend captures drop `host`. Each variant's `schemaVersion` names v5. | positives; H01-H18 |
| Capture rules removed | v4's "wrong boot/kernel" (v4 model `:518`), "active policy changed" (`:519-521`), "host lock state differs" (`:522-524`, `:670`), the boot-entry rule (`:525`, `:671`; `_boot_entry` `:647-652`), and the `host` half of "lifecycle capture binding" (`:660-661`) and "backend capture binding" (`:697-698`). | C10, C11, L08, N134, N135, V39, V40 re-derived |
| Retained-capture rule | kept, with the seven fields removed from its list (`:629-639`; Q-NPE-8 (a)) | none, as in v4 |
| Evidence classes | the OUT_OF_SCOPE_HOST cells read "absent" and name four T04 proofs (Q-NPE-3 (b)) | H01-H18 |
| Record | unchanged: native-profile v4's | v4's vectors |

Every function v5 shares with v4 is v4's except for these changes, which are its whole v4-to-v5 diff:

| Function | Change from v4 |
|---|---|
| `_shape` | pins the v5 capture schema's canonical digest (`SCHEMA_SHA256`); its refusal is "unreviewed v5 capture schema" (v4: "unreviewed v4 qualification schema") |
| `check_capture` | signature `check_capture(record, capture, role, record_schema, schema, previous=None)`; the docstring adds that the record is v4's; the discriminator is `planeon.internal.native-qualification-capture/v5` and its refusal "not a v5 capture"; the record's shape step is v4's `_shape(record, "record", record_schema)`; v4's host rules (`:518-525`) become a comment; the retained-capture list loses the seven fields and its recursive call passes `record_schema` |
| `check_lifecycle_capture` | signature `check_lifecycle_capture(record, capture, record_schema, schema)`; the discriminator is `planeon.internal.native-qualification-lifecycle/v5` and its refusal "not a v5 lifecycle capture"; the record's shape step is v4's `_shape`; "lifecycle capture binding" checks `qualificationDigest` only; v4's booleans and boot-entry rules (`:670-671`) become a comment |
| `check_backend_capture` | signature `check_backend_capture(record, capture, record_schema, schema)`; the discriminator is `planeon.internal.native-qualification-backend/v5` and its refusal "not a v5 backend capture"; the record's shape step is v4's `_shape`; "backend capture binding" checks `qualificationDigest` only |
| `check_qualification` | `record_schema` (v4's schema) comes before `schema` (v5's); the docstring adds the split; it calls `v4.check_record(..., record_schema)`, the three v5 capture checks with `record_schema`, and `v4.check_migration(..., record_schema, no_earlier_history)`; v4's cross-capture rules are unchanged and in v4's order |
| `validate_capture` | signature `validate_capture(record, capture, role, record_schema, schema, previous=None)`; message "invalid DATA_CHECK_ONLY v5 capture; no native authority" |
| `validate_qualification` | message "invalid DATA_CHECK_ONLY v5 qualification; no native authority (caller must also have validated the profile with the pinned proxy contract)" |

New in v5: `SCHEMA_SHA256`, `V5_CAPTURE`, `V5_LIFECYCLE`, `V5_BACKEND` and `HOST_FIELDS`; `derive_capture`,
`derive_positive`, `_subject` and `check_vectors` with their constants. v5 binds 24 of v4's helpers and constants by
name (`require`, `digest`, `canonical`, `parse`, `explain`, `schema_errors`, `_bounded`, `_path`, `_within`,
`_same_set`, `_result`, `_apply`, `capture_class`, `_member_sets`, `ROLES`, `SINGLE_PROCESS_ROLES`, `SECCOMP_FILTERS`,
`HOOKS`, `CENSUS_ATTACH_TYPES`, `DELEGATED_CHILDREN`, `SLICE`, `BROKER_SERVICE`, `ROLE_DOMAINS`, `MAX_BYTES`). The
record functions (`check_record`, `check_migration`, `validate_record` and every record rule) stay v4's and are called
through `v4.`.

## The host facts

| Field | In v4's captures | Record counterpart (unchanged) | Record rules that stay | Proof |
|---|---|---|---|---|
| `host` | P1, P5, backend | `host` | the seal digest binds `bootId` (v4 model `:231-239`, `:399-400`); migration (`:732`) | T04-HOST-BOOT |
| `selinuxBefore`, `selinuxAfter` | P1 | `selinux.status` | the even sequence (`:306`); the schema's constants | T04-POLICY-STABLE |
| `kernelPolicyDigest` | P1 | `selinux.policyDigest` | the seal digest (`:231-239`); T04-ENTRYPOINT's premise | T04-POLICY-STABLE |
| `booleansObserved` | P1, P5 | `selinux.booleans` | the schema's constants (vectors R12-R14) | T04-HOST-LOCKS |
| `hardeningObserved` | P1 | `hardening` | the schema's constants and the seal marker (vectors R15-R22) | T04-HOST-LOCKS |
| `bootEntryObserved` | P1, P5 | `bootEntries` | the closed grammar and the binding (`:272-284`) | T04-BOOT-ENTRY |

- **The even sequence.** v4's `check_capture` also tested the record's even policy sequence, inside "active policy
  changed". That test is a record rule: `check_record` keeps it ("unstable policy epoch", `:306`), and
  `check_qualification` runs `check_record` first. A standalone v5 `check_capture` no longer repeats it.
- **What stays observed.** The P5 lifecycle capture observes the seal marker's path, digest, uid and mode and
  `runFsType` (`:664-666`). The marker's digest must equal the record's, which `check_record` binds to the record's
  `bootId` and policy digest (`expected_seal_digest`, `:231-239`; `:399-400`). P1's `hardeningObserved` held the
  declared hardening settings, which were never observed (OUT_OF_SCOPE_HOST), and copies of the marker and `runFsType`
  that P5 observes, so P1 loses nothing observed.
- **Who reads them.** As in v4, "How they are read is HE-008's and T04's" (v4 `README.md:134-136`). An off-host
  attestation of these facts is carried to HE-008 and T04, and observed booleans stay a later candidate (Q-NPE-2 (a)).

## The four T04 proofs

| Proof | What it must show |
|---|---|
| T04-HOST-BOOT | the running boot and kernel equal the record's `host` (`bootId`, `machine`, `kernelRelease`, `kernelNotesDigest`) for every capture of the record's window |
| T04-POLICY-STABLE | from the seal until the enrolled boot ends (so at every capture of the record's window), the active SELinux policy is the record's `selinux.policyDigest`, with the record's status: no policy load after the seal (the bracket that `selinuxBefore` and `selinuxAfter` stood for) |
| T04-HOST-LOCKS | from the seal until the enrolled boot ends (so at every capture of the record's window), the SELinux booleans and the kernel hardening settings equal the record's `selinux.booleans` and `hardening` |
| T04-BOOT-ENTRY | the boot ran from the record's enrolled boot entry, measured rather than loader-reported (v4's decision 2 leaves the measurement to T04) |

They extend v4's ten (v4 `README.md:313`). The v4 record's `t04Proofs` is a schema constant and does not list them,
because the record is unchanged: a v5 qualification relies on the record's ten proofs and on these four, which v5's
class table names in its `proofs` arrays (Q-NPE-3 (b)).

## Evidence classes (the changed rows)

| Table | Fields | Cell | Proofs |
|---|---|---|---|
| capture | `host` | OUT_OF_SCOPE_HOST (absent) | T04-HOST-BOOT |
| capture | `selinuxBefore`, `selinuxAfter`, `kernelPolicyDigest` | OUT_OF_SCOPE_HOST (absent) | T04-POLICY-STABLE |
| capture | `booleansObserved`, `hardeningObserved` | OUT_OF_SCOPE_HOST (absent) | T04-HOST-LOCKS |
| capture | `bootEntryObserved` | OUT_OF_SCOPE_HOST (absent) | T04-BOOT-ENTRY |
| lifecycleCapture | `host` | OUT_OF_SCOPE_HOST (absent) | T04-HOST-BOOT |
| lifecycleCapture | `booleansObserved` | OUT_OF_SCOPE_HOST (absent) | T04-HOST-LOCKS |
| lifecycleCapture | `bootEntryObserved` | OUT_OF_SCOPE_HOST (absent) | T04-BOOT-ENTRY |
| backendCapture | `host` | OUT_OF_SCOPE_HOST (absent) | T04-HOST-BOOT |

In the P1 table each of the three columns holds the cell. The DECLARED_T04 label row drops
`hardeningObserved.sealMarker.selinuxLabel`, since the whole of `hardeningObserved` is absent; the lifecycle row for
`sealMarker.selinuxLabel` is unchanged. Every other row, the class list, the capture targets and the capturer text are
v4's.

## Replayed v4 cases

Every v4 negative and accepted case of the capture, lifecycle, backend and qualification targets is replayed under v5
against the derived positives, with its id. A replayed row other than Q03 (below) equals v4's row as data, v4's
`v3Refusal`, `reason` and `rederived` annotations included (they record v3-to-v4 changes); the qualification cases keep
v4's refusal texts, since the record checks and the cross-capture rules are v4's. Seven cases are re-derived, because
their operation edits a member of a dropped field: the operation sets the whole field to the v4 positive's value with
the same edit, and the row records `rederived`, its `v4Refusal` and a `reason`:

| Case | Target | v4 operation path | v4 refusal | v5 refusal | Reason |
|---|---|---|---|---|---|
| C10 | capture, OBSERVER | `hardeningObserved.modulesDisabled` | host lock state differs | `schema $ additionalProperties` | the hardening settings are record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-HOST-LOCKS) |
| C11 | capture, OBSERVER | `hardeningObserved.unprivilegedBpfDisabled` | host lock state differs | `schema $ additionalProperties` | the hardening settings are record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-HOST-LOCKS) |
| L08 | lifecycle | `booleansObserved.planeon_containment_enabled` | host lock state differs | `schema $ additionalProperties` | the SELinux booleans are record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-HOST-LOCKS) |
| N134 | capture, BROKER | `hardeningObserved.sealMarker.selinuxLabel` | schema $.hardeningObserved.sealMarker additionalProperties | `schema $ additionalProperties` | the hardening settings are record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-HOST-LOCKS) |
| N135 | capture, WORKER | `hardeningObserved.sealMarker.selinuxLabel` | schema $.hardeningObserved.sealMarker additionalProperties | `schema $ additionalProperties` | the hardening settings are record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-HOST-LOCKS) |
| V39 | capture, BROKER | `bootEntryObserved.entryId` | observed on a boot entry other than the enrolled one | `schema $ additionalProperties` | the boot entry is record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-BOOT-ENTRY) |
| V40 | lifecycle | `bootEntryObserved.cmdlineSha256` | observed on a boot entry other than the enrolled one | `schema $ additionalProperties` | the boot entry is record-only in v5 (OUT_OF_SCOPE_HOST, absent; T04-BOOT-ENTRY) |

Q03 is re-derived too (decision Q-NPE-9 (a), the lane monitor's, owner-delegated), as an eighth, refusal-preserving
case: v4's operation sets `captures[1]` to the v4 positive's SERVER capture, which carries the v4 discriminator and the
seven dropped fields, and v5's sets it to the v5 positive's SERVER capture. Its refusal, "one capture per resident
role", is unchanged, and its `rederived` records why. The scope's count of host-touching replayed cases (seven) missed
Q03; Q-NPE-9 (a) amends Q-NPE-4 (a)'s "7" to 8.

Not replayed: v4's 196 record negatives and 11 record accepted cases, its 22 migration cases, and X01-X08 and X15. Their
checks (v4's `check_record`, `check_migration` and the record cross-version kinds) are unchanged, so v4's vectors keep
pinning them.

## v5 cases

| Case | Target | Role or component | Field | Intent |
|---|---|---|---|---|
| H01 | capture | SERVER | `host` | server capture carrying the record's host block (T04-HOST-BOOT) |
| H02 | capture | SERVER | `host` | server capture reporting another boot ID |
| H03 | capture | OBSERVER | `selinuxBefore` | observer's own capture carrying the record's SELinux status as selinuxBefore (T04-POLICY-STABLE) |
| H04 | capture | OBSERVER | `selinuxBefore` | observer's own capture reporting another policy sequence before the inspection |
| H05 | capture | BROKER | `selinuxAfter` | broker capture carrying the record's SELinux status as selinuxAfter (T04-POLICY-STABLE) |
| H06 | capture | BROKER | `selinuxAfter` | broker capture reporting another policy sequence after the inspection |
| H07 | capture | WORKER | `kernelPolicyDigest` | worker capture carrying the record's policy digest (T04-POLICY-STABLE) |
| H08 | capture | WORKER | `kernelPolicyDigest` | worker capture reporting another loaded policy digest |
| H09 | capture | EFFECT_GATE | `booleansObserved` | gate capture carrying the record's SELinux booleans (T04-HOST-LOCKS) |
| H10 | capture | EFFECT_GATE | `booleansObserved` | gate capture reporting secure_mode_policyload off |
| H11 | capture | SERVER | `hardeningObserved` | server capture carrying the record's hardening settings, seal label removed (T04-HOST-LOCKS) |
| H12 | capture | OBSERVER | `bootEntryObserved` | observer's own capture carrying the enrolled boot entry (T04-BOOT-ENTRY) |
| H13 | lifecycle | - | `host` | lifecycle capture carrying the record's host block (T04-HOST-BOOT) |
| H14 | lifecycle | - | `host` | lifecycle capture reporting another boot ID |
| H15 | lifecycle | - | `booleansObserved` | lifecycle capture carrying the record's SELinux booleans (T04-HOST-LOCKS) |
| H16 | lifecycle | - | `bootEntryObserved` | lifecycle capture carrying the enrolled boot entry (T04-BOOT-ENTRY) |
| H17 | backend | APISERVER | `host` | apiserver observation carrying the record's host block (T04-HOST-BOOT) |
| H18 | backend | KUBELET | `host` | kubelet observation reporting another kernel release |

Each sets one dropped field and is refused by the schema (`schema $ additionalProperties`). With the re-derived C10,
C11, N134, N135, V39, L08 and V40, every dropped (variant, field) pair is refused at least once with the v4 positive's
value (the record's declared value) and at least once with another value; `check_vectors` requires this closed set, the
ids H01-H18 in order (none of them a v4 id), and each re-derived row's operation, value and texts.

## Cross-version

X09-X14 are v4's capture-family cross-version cases moved one version up: v4 captures, lifecycle captures and backend
captures under the v5 model ("not a v5 …"), and v5 ones under the v4 schema, which must include the discriminator error
and, new in v5, `$ required` (the dropped fields are required in v4).

## Counts

- `check_vectors`: 284 checks (5 positives, 266 negatives, 7 accepted, 6 cross-version).
- The capture family: 247 negatives (148 schema refusals, 99 model refusals with 35 distinct texts, from v4's 37) and 7
  accepted cases.
- A capture-family replay such as HE-004D1's: 70 positive captures + 7 accepted + 247 negatives + 6 cross-version = 330
  checks (HE-004D1's replay of v4 runs 312).

## Consumers

- **HE-004D2** vendors v5's schema, vectors and README (edge v7, Q-NPE-6 (a)) and the native-profile v1, v2 and v3
  vectors that the replay reads as histories (edge v7, Q-HE4D2-3 (a)), and composes v5's `check_qualification` with I06
  v3 for I06-2 (`architecture/w03-plan-v2/plan.json:405`). HE-004D1's captures move to v5 in a re-vendor (the capture
  fields, the checks, the schema load and pins, and the replay).
- **I06 v3** is unchanged: it binds the v4 record through v4's `check_record`, which v5 keeps.
- **HE-004-I01**: the declared-host-field mark on the wire, which HE-004D1 hands it, has nothing left to mark once
  captures are v5.

## Residuals and carried items

- **T04**: T04-HOST-BOOT, T04-POLICY-STABLE, T04-HOST-LOCKS and T04-BOOT-ENTRY, with v4's ten proofs.
- **HE-008 and T04**: the real reads of the seven facts, and an off-host attestation of them if one is wanted (Q-NPE-2
  (a)).
- **A later candidate**: observed booleans (Q-NPE-2 (a)).
- **The ClusterRole I06 successor** (OBS-RBAC-1): its own slot after 252 and before HE-008 (Q-NPE-5 (a)).
- Every residual and obligation v4 carries, unchanged.

## Not claimed

No real kernel, SELinux policy, bpffs, cgroup, boot loader or TPM was observed, and no capture route was exercised on a
host. Dropping the fields from captures proves none of the host facts: they are declared by the record and stay T04's
and HE-008's. Native, installation and tenant acceptance remain separate.

## Open items

- Edge record v7's 3 native-profile v5 rows carry `providerPacket` `TBD`; the packet id is assigned with the slot at
  adoption.
- The status record gains the review rounds and the adoption at adoption.
- v5's layer validator (packet mechanics) checks that native-profile v1 to v4 (models included), I06 v3 (its model
  included) and edge records v1 to v6 stay byte-identical, freezing `scripts/native_qualification_v4.py` (sha256
  `f7c71807…`) and `scripts/i06_backend_profile_v3.py` (`dfb00e90…`) by exact path and digest, since v5 binds v4's model
  by name; that the packet adds new files only; and that `evidenceClasses` agrees with the model as v4's layer does
  (each host field present in a capture is refused), its eight host rows naming exactly the four proofs of `status.json`
  `hostProofs`.
- The mechanics re-verify, at the merged base, every bound and pinned input digest (the twelve adopted native-profile v4
  and I06 v3 files, edge v6, W03-PLAN-AMEND-3, plan v2 and the v1 to v3 schemas and vectors) and that v7 is still the
  next free edge version, so the line citations here (at `f560209`, kept as the review base) stay valid.
- Edge v7 also registers the native-profile v1, v2 and v3 vectors for HE-004D2 (Q-HE4D2-3 (a)); those three rows carry
  their files' last-change commits, so adoption changes only the native-profile v5 rows' `providerPacket`.

## Contract review round 1 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| E1-1 Q03 carries a whole v4 capture | MINOR | Q-NPE-9 (a): Q03 is re-derived as an eighth, refusal-preserving case ("Replayed v4 cases"), with its own re-derivation rule in `check_vectors`; the scope's miss is recorded. |
| E1-2 the re-derivations and added ids are not pinned | MINOR | `check_vectors` now requires, for each re-derived row, that v4's operation is one `set` inside the row's field, that the v5 operation sets the whole field to that edit applied to the v4 positive's value, and that `rederived` and `reason` are the field's pinned texts (`REDERIVED_WHY`, `REDERIVED_REASONS`); and that the added rows are exactly H01-H18 in order, none of them a v4 id. The reviewer's three probes (another different C10 value, replaced texts, H01 renamed R12) and candidate 1's five are refused (the generator's self-tests). |
| E1-3 the change set omits per-function changes | MINOR | "What v5 changes" now lists every per-function change; that list is the whole v4-to-v5 diff. |
| E1-4 Text in force misses contradicting v4 statements | MINOR | "Text in force" names v4 `README.md:134-136`, `:158`, `:159`, `:183-184` and `:471-472` (and `:264`, moot); the bullet is cited as `:134-136` throughout. Candidate 3 adds (round 2, E2-1, and the author's search of v4's README): `:505` (the K1 row's last sentence) and `:538` (the observed lockdown value), replaced; `:19-20` (the class of the capture fields) and `:511-513` (the K1 statement), narrowed; and `:581` (decision 2's first sentence), moot. |
| E1-5 two proofs' windows cannot be closed | MINOR | T04-POLICY-STABLE and T04-HOST-LOCKS hold from the seal until the enrolled boot ends (so at every capture of the record's window); "no policy load after the seal" stays T04-POLICY-STABLE's content. `status.json` `hostProofs` carries the four texts. |
| E1-6 source-index pins files rewritten at adoption | MINOR | `source-index.json`'s subject drops `status.json` and edge v7 (both rewritten at adoption) and keeps README-v7; `predecessorInputs` gains `architecture/w03-plan-v2/plan.json`. |
| E1-7 nothing pins the v4 model's bytes | NOTE | "Open items": the layer freezes both scripts by exact path and digest, "native-profile v1 to v4 (models included)", and the mechanics re-verify every pinned input at the merged base. |
| E1-8 five wording fixes | NOTE | (a) "its residual (`:151`) and dependency name (`:282`)"; (b) "and `evidenceClasses` (below)"; (c) the `record_schema` check is stated as v4's `_shape` check, not a caller obligation (README and model docstring); (d) what P1's `hardeningObserved` held is stated; (e) "at least once". |
| E1-9 the Q-HE4D2-3 switch's quoting and labels | NOTE | The Q-HE4D2-3 line must sit inside a dated `## ` section, and its edge v7 label carries that date; with the switch on, README-v7's list reads "Q-NPE-1 (c), Q-NPE-6 (a), Q-NPE-7 (a) and Q-HE4D2-3". |
| E1-10 status.json omits the Q-NEXT-D2 lines | NOTE | `status.json` quotes the two Q-NEXT-D2 lines. The workItem name and the adoption-time fields (reviewBase, adoptionEdit, recordPaths) are the monitor's and the adoption's. |

## Contract review round 2 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| E2-1 four more v4 statements on captures | MINOR | "Text in force" adds `:505` and `:538` (replaced, by T04-BOOT-ENTRY and T04-HOST-LOCKS), `:511-513` (narrowed: only T04-BOOT-ENTRY tells a maintenance boot apart) and `:581`'s first sentence (moot), all computed from the pinned README. The author's search of v4's README for every statement on the seven fields or on what captures report also found `:19-20` (the class of the capture fields), narrowed. The E1-4 row is extended. |
| E2-2 the v5 cases' content is not pinned | NOTE | `NEW_CASES` declares each v5 case's id, target, role or component, field and kind of value (the v4 positive's or another), and `check_vectors` requires each added row to match ("v5 case as declared"). The reviewer's probes (H01's and H02's operations swapped; H18's component changed to APISERVER) are refused (the generator's self-tests). |
| E2-3 Q03 wording under the switch | NOTE | Prepared in candidate 3 (switch off). Candidate 4 sets `Q03_MODE` "a" (Q-NPE-9 (a)): the decisions' heading is neutral ("relayed by the lane monitor"), and the replayed-rows sentence reads "A replayed row other than Q03 (below) equals v4's row as data" (round 3, E3-1). |

## Contract review round 3 findings and dispositions

| Finding | Severity | Disposition |
|---|---|---|
| E3-1 Q03 wording at the switch-on regeneration | NOTE | Applied: under (a) the sentence reads "A replayed row other than Q03 (below) equals v4's row as data, ...", and the E2-3 row names the mode now set. |
