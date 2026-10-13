# I07 policy writer channel v2 — W02c-F contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-08. Status: **CONTRACT_CANDIDATE_ROUND1_AWAITING_INDEPENDENT_REVIEW**.

v2 is the W02c-F successor of the adopted I07 contract `../i07-policy-write/` (`planeon.internal.policy-write-frame/v1`,
MET-ENFORCE-008, review round 1 PASS_FOR_SOURCE_PUBLICATION with R1-R8 carried). Later layers pin the v1 bytes, so v1 stays
byte-identical and v2 is published beside it. v2 changes three things and answers R1-R8:
- it extends the **I05 v2 gate** (`scripts/i05_gate_channel_v2.py`, W02b-F) instead of the frozen v1 gate, so the drain
  answer, the reported denies and the restart rule after an unrecorded failure come from I05 v2;
- it applies the **W02f** decision: admission policies and bindings live only in the sealed static admission manifest
  directory, and a static guard denies every API write of them, so the writer's grants for those two kinds are inert;
- a write's **upstream outcome is its own event**, so writer EOF, a writer peer deviation, I05 events, storage failures and
  restarts can arrive while a write is outstanding.

Nothing here opens a socket, forwards a request or installs anything; all E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `c1a678480263e0513585647f5cc748f11beb54f0` (MET-ENFORCE-013, 212 packets).

## Files

| File | Content |
|---|---|
| `channel.schema.json` | Draft 2020-12 schema `planeon.internal.policy-write-frame/v2`: eight frame variants (four requests, four responses) |
| `policy-kinds.json` | `planeon.internal.i07-policy-kinds/v2`: seven writable kinds derived from the W02g closure, two sealed admission kinds, the non-writable and effect kinds |
| `vectors.json` | 79 kind checks (v1 K01-K77 under their IDs, K78-K79 new), 7 render checks, 22 outcome checks, 38 frame checks (G21-G38 new), 9 byte checks, 58 transcripts (v1 T01-T45 under their IDs, T46-T58 new) |
| `../../scripts/i07_policy_write_v2.py` | Reference model: `check_write`, `render_write`, `request_digest`, `write_outcome_is_final`, `PolicyGate` (extends `i05_gate_channel_v2.Gate`), `replay` |

The v2 model is the v1 model with the changes below, so the v1-to-v2 diff of `scripts/i07_policy_write.py` and
`scripts/i07_policy_write_v2.py` is the review surface.

## What v2 changes

| Item | v2 rule | Vectors |
|---|---|---|
| Base gate | `PolicyGate` extends `i05_gate_channel_v2.Gate`. The A3 fence is the base `fence()`; maintenance is PENDING, OPEN or HELD by it after every event, I05 or I07. A pending I05 drain also settles after writer events (a writer peer deviation can hold the generation while it is pending). | T04-T06, T17 |
| R1 restart | A generation the gate rebuilt after a restart never opens a maintenance: a maintenance the restart interrupted never resumes, and none begins (`maintenanceReason` GENERATION_REBUILT). With I05 v2's failure marker, probe PA (a writer peer deviation whose INVALIDATED and STORAGE_FAILURE records both fail after a clean close) restarts HELD as well; I05 v2's double-fault residual remains, but no maintenance follows it. | T46, T47, T14, T15, T38 |
| R2 and W02f | ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding move from the writable rows to `notWritable` with disposition SEALED_STATIC_MANIFEST and are refused ADMISSION_OBJECT_SEALED at any version. The W02g closure still grants them (it is frozen data); the grant is inert because the W02f guard denies every API write of admission objects. No name is writable, which closes the W02g name obligation. | K13-K18, K49, K63, K78, K79, T48 |
| R3 schema | Conditional constraints: maintenance OPEN implies gateState CLOSED or INVALIDATED (and, in MAINTENANCE_STATUS, no in-flight action and no ambiguous write); maintenance HELD implies gateState HELD; maintenance PENDING implies DRAINING or INVALIDATED; an ambiguous write implies HELD; a delivered write's status is 200, 201, 202 or 4xx other than 408; WRITE_END never reports ACTIVE or INSPECTING. | G21-G34 |
| R4 outstanding write | WRITE_OBJECT records WRITE_FORWARDED and forwards; its response follows the separate upstream event (W_UPSTREAM). While it is outstanding: a writer frame breaks lockstep (fatal LOCKSTEP); writer EOF, a fatal frame or a writer peer deviation first records the write WRITE_TERMINAL IO_AMBIGUOUS (the exchange is aborted, the generation HELD) and only then WRITER_SESSION_ENDED and MAINT_ENDED; an outcome after the abort is journalled WRITE_LATE_UPSTREAM and never relayed; I05 events (a close, RECONCILIATION_REQUIRED, a drain) and storage failures proceed, and the outcome is still recorded and relayed; a restart rebuilds the write IO_AMBIGUOUS and HELD. No successor generation is enrolled while a WRITE_FORWARDED lacks WRITE_TERMINAL or an ambiguous write is unreconciled: the restart and HELD rules give the gate's side; enrollment itself is W03. | T49-T53, T58, T14 |
| R5 observations | requestDigest is the SHA-256 of the canonical JSON object `{"bodyDigest": ..., "head": ...}` of the rendered request (`request_digest`). observedUid and observedResourceVersion come only from a success response; a rejection (a v1 Status body) reports null. T11 and T40 now report null. | T54, T55, G24, G25 |
| R6 wording | Decision 2: the generation never returns to ACTIVE; WRITE_END reports DRAINING, CLOSED, INVALIDATED or HELD. INVALIDATED after the fence counts as closed for maintenance (W01 §2.3, M2). | G34 |
| R7 denies | WRITE_BEGIN reports every I05 action its drain denied, also when the DRAIN_STARTED record failed and the storage-failure path denied it (I05 v2 P3). | T56, T07 |
| R8 key bound | A member name may have 317 characters (a maximal qualified key: 253-character DNS prefix, `/`, 63-character name). | G35, G36 |
| W02b-F V2 | OPEN is a point-in-time answer: after OPEN the gate keeps evaluating the fence, and a later HELD (an I05 channel loss, RECONCILIATION_REQUIRED, a storage failure, an ambiguous write) holds the maintenance, so no further write is forwarded. | T57, T30, T51 |

## Channel

As v1 (`../i07-policy-write/README.md`, "Channel"), with the v2 frame version: one writer session at a time on
`/run/planeon/maintenance/policy-write.sock`; custody on every frame (a deviation is fatal and an urgent invalidation,
WRITER_PEER_DEVIATION); MAINTENANCE_STATUS opens each session; strict lockstep (a writer frame before the response to its
previous request is fatal, LOCKSTEP); the I05 byte rules with printable-ASCII strings and member names of at most 317
characters; fatal versus refused as in v1. WRITE_OBJECT is answered after its upstream exchange, which the gate bounds to
10 seconds (on expiry the gate aborts it: IO_AMBIGUOUS).

## Operations

| Operation | Request | OK response | Refusal reasons |
|---|---|---|---|
| MAINTENANCE_STATUS | `{}` | generation, gate state, maintenance state, in-flight I05 action, write count, ambiguous write IDs, journal digest | none |
| WRITE_BEGIN | expectedGeneration | maintenance (PENDING, OPEN or HELD), gate state, every I05 action this request denied | GENERATION_MISMATCH, MAINTENANCE_ENDED, STORAGE_FAILURE |
| WRITE_OBJECT | writeId, operation, resource, namespace, name, object, prior | writeId, classification, requestDigest, and for a delivered result the HTTP status, result digest and (success only) observed UID and resourceVersion | MAINTENANCE_NOT_OPEN, MAINTENANCE_HELD, WRITE_ID_OUT_OF_ORDER, EFFECT_KIND, POLICY_KIND_NOT_WRITABLE, ADMISSION_OBJECT_SEALED, KIND_OUTSIDE_TABLE, VERB_NOT_ALLOWED, SCOPE_MISMATCH, PRIOR_RULE, OBJECT_RULE, STORAGE_FAILURE |
| WRITE_END | `{}` | maintenance ENDED, gate state (DRAINING, CLOSED, INVALIDATED or HELD), write count, ambiguous write IDs | MAINTENANCE_NOT_BEGUN, MAINTENANCE_ENDED, STORAGE_FAILURE |

The value sources are v1's ("Where each request value comes from").

## Closed policy-kind table

`policy-kinds.json` is derived: the W02g closure's POLICY_WRITE grants of `planeon:policy-writer` give nine rows; the two
admission kinds are moved to `notWritable` by the W02f decision (`sealedBy`). Writable:

| Kind | Resource | Scope | Operations |
|---|---|---|---|
| LimitRange | `v1 limitranges` | qualification namespace | CREATE, UPDATE, DELETE |
| Namespace | `v1 namespaces` | the qualification namespace object only | UPDATE |
| ResourceQuota | `v1 resourcequotas` | qualification namespace | CREATE, UPDATE, DELETE |
| ServiceAccount | `v1 serviceaccounts` | qualification namespace | CREATE, UPDATE, DELETE |
| NetworkPolicy | `networking.k8s.io/v1 networkpolicies` | qualification namespace | CREATE, UPDATE, DELETE |
| Role | `rbac.authorization.k8s.io/v1 roles` | qualification namespace | CREATE, UPDATE, DELETE |
| RoleBinding | `rbac.authorization.k8s.io/v1 rolebindings` | qualification namespace | CREATE, UPDATE, DELETE |

Effect kinds (EFFECT_KIND), the v1 non-writable policy kinds (POLICY_KIND_NOT_WRITABLE) and everything else
(KIND_OUTSIDE_TABLE) are as v1. ValidatingAdmissionPolicy and ValidatingAdmissionPolicyBinding are ADMISSION_OBJECT_SEALED
at any version. No writable kind is cluster-scoped any more.

## Decisions

0. **Maintenance follows the A3 fence.** WRITE_BEGIN asks for the I05 v2 drain. Maintenance is OPEN only while the base
   `fence()` is OPEN (CLOSED or INVALIDATED, no consumed action without a terminal record), HELD while the generation is
   HELD, and PENDING otherwise, evaluated after every event. MAINT_OPEN is recorded before the first write. OPEN can become
   HELD; it never becomes OPEN again after HELD.
1. **One maintenance per generation, owned by one session, never in a rebuilt generation.** As v1, and a generation the
   gate rebuilt after a restart never opens one (R1).
2. **The generation never returns to ACTIVE.** WRITE_END reports DRAINING, CLOSED, INVALIDATED or HELD; a new generation
   needs fresh observation and enrollment (R6).
3. **Writer identity only for the closed table, only while OPEN** (v1 order; sealed admission kinds refused at the kind
   step).
4. **Exact rendering and preconditions** as v1; the response carries `request_digest` of the rendering (R5).
5. **Write outcomes** as v1; observed object metadata only from success responses (R5).
6. **Durable before the effect, and before the end.** WRITE_FORWARDED before the first upstream byte; WRITE_TERMINAL before
   the response, and before WRITER_SESSION_ENDED and MAINT_ENDED when the session ends while a write is outstanding (R4).
7. **A3 versus A4** as v1, with the I05 v2 drain answer.
8. **What the gate does not judge** as v1. Admission objects are not written through I07 at all (W02f).

## Durable journal

The v1 records (MAINT_REQUESTED, MAINT_OPEN, MAINT_HELD, WRITE_FORWARDED, WRITE_TERMINAL, MAINT_ENDED, WRITER_SESSION_ENDED)
plus:

| Record | When | Restart meaning |
|---|---|---|
| WRITE_TERMINAL(writeId, IO_AMBIGUOUS, {aborted: reason}) | The gate aborts an outstanding write (writer EOF, fatal frame, writer peer deviation), before the session and maintenance records | The write is ambiguous; the gate is HELD |
| WRITE_LATE_UPSTREAM(writeId) | An upstream outcome after the abort | Reconciliation only |

and the I05 v2 records (RESTARTED, the failure marker, torn-record detection). On restart the gate rebuilds the I05 v2 way,
every write forwarded without a terminal record becomes IO_AMBIGUOUS (HELD), no writer session survives, and the
maintenance is ENDED: GATE_RESTART if one had begun, GENERATION_REBUILT otherwise.

`STORAGE_FAIL_AFTER` is a test injection of the model only (the record after the given number of successful records fails),
used by T56; it is not a gate event.

## v1 review findings and dispositions

| Finding | Disposition in v2 |
|---|---|
| R1 MINOR, maintenance after an unrecorded failure | No maintenance in a rebuilt generation; I05 v2 failure marker (T46, T47) |
| R2 MINOR, VAP names | W02f seals admission objects; ADMISSION_OBJECT_SEALED; no name is writable (K13-K18, K49, K63, K78, K79, T48) |
| R3 MINOR, response combinations | Conditional schema constraints (G21-G34) |
| R4 MINOR, events during an outstanding write | Upstream outcome as its own event; abort recorded before the session and maintenance end; lockstep; late outcome not relayed (T49-T53, T58) |
| R5 NOTE, requestDigest and observed fields | Defined; null on rejections; T11 and T40 corrected (T54, T55) |
| R6 NOTE, Decision 2 wording | Reworded; WRITE_END gateState closed set (G34) |
| R7 NOTE, WRITE_BEGIN denies after a storage failure | I05 v2 P3 reporting (T56) |
| R8 NOTE, 316 versus 317 | 317 (G35, G36) |

## Still open

- All E01-E12 and T01-T08.
- Enrollment refusing a successor generation while a write is unterminated or an ambiguous write is unreconciled (W03).
- The writer artifact, the socket and the HTTP/TLS substrate (W03); the journal and marker storage formats.
- I05 v2's double-fault residual (both failure domains failing at once) still applies to the gate's own HELD.
