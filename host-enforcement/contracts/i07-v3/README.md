# I07 policy writer channel v3 — W02-ADM-F contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-09. Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (one combined W02-ADM-F review
with `../i05-gate-channel-v3/` and `../admission-semantics-v3/`; brief and source index in `../w02-adm-f/`).

v3 is the W02-ADM-F successor of the adopted I07 v2 contract `../i07-policy-write-v2/`
(`planeon.internal.policy-write-frame/v2`, MET-ENFORCE-014, review round 1 PASS_FOR_SOURCE_PUBLICATION with W1-W4
carried). Later layers pin the v2 bytes, so v2 stays byte-identical and v3 is published beside it. v3 extends the **I05 v3
gate** (`scripts/i05_gate_channel_v3.py`) and answers W1-W4; the v2 design is otherwise unchanged. Nothing here opens a
socket, forwards a request or installs anything; all E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `f88e7f7` (MET-ENFORCE-014, 213 packets). The packet that publishes v3 is claimed only after
MET-PERF-035 merges (owner decision, 2026-10-08).

## Files

| File | Content |
|---|---|
| `channel.schema.json` | Draft 2020-12 schema `planeon.internal.policy-write-frame/v3`: eight frame variants (four requests, four responses) |
| `policy-kinds.json` | `planeon.internal.i07-policy-kinds/v2`, unchanged from v2: seven writable kinds derived from the W02g closure, two sealed admission kinds, the non-writable and effect kinds |
| `vectors.json` | 79 kind checks, 7 render checks, 22 outcome checks, 48 frame checks (G39-G48 new), 9 byte checks, 62 transcripts (T59-T62 new); every v2 vector is carried under its ID |
| `../../scripts/i07_policy_write_v3.py` | Reference model: `check_write`, `render_write`, `request_digest`, `write_outcome_is_final`, `PolicyGate` (extends `i05_gate_channel_v3.Gate`), `replay` |

The v3 model is the v2 model with the changes below, so the v2-to-v3 diff of `scripts/i07_policy_write_v2.py` and
`scripts/i07_policy_write_v3.py` is the review surface. Carried vectors keep their v2 events and expected outputs; they
differ only in the frame version strings and the digests and bytes that follow from them. G38's intent now says "not v3".

## What v3 changes

| Item | v3 rule | Vectors |
|---|---|---|
| Base gate | `PolicyGate` extends `i05_gate_channel_v3.Gate`. The `STORAGE_FAIL_AFTER` test injection now lives in the base gate (I05 v3, V1); `PolicyGate` no longer overrides `_record`. | T56 (carried) |
| W1 schema | Four more conditional constraints, so the schema refuses exactly the combinations the gate never reports: in MAINTENANCE_STATUS, maintenance ENDED implies a gate state other than ACTIVE or INSPECTING, maintenance PENDING implies an integer inFlightActionId, and gateState CLOSED implies a null inFlightActionId; in WRITE_END, a non-empty ambiguousWriteIds implies gateState HELD. One rule stays outside JSON Schema: ambiguousWriteIds is a subset of 1..writes; the gate's own state guarantees it, and a writer-side check must test it itself. | G39-G47 |
| W2 restart reason and upstream bound | On restart the maintenance is ENDED with the recorded MAINT_ENDED reason if the maintenance had ended, GATE_RESTART if it had begun and not ended, GENERATION_REBUILT otherwise. The gate bounds a write's upstream exchange to 10 seconds; on expiry (model event W_UPSTREAM with upstream TIMEOUT) it aborts the exchange: WRITE_TERMINAL IO_AMBIGUOUS `{aborted: UPSTREAM_TIMEOUT}`, the generation and the maintenance HELD, and that IO_AMBIGUOUS outcome is the writer's response. A later upstream outcome is WRITE_LATE_UPSTREAM, never relayed. This differs from LOST only in the journal qualifier. | T59, T61, T62; T15, T14, T38 (carried) |
| W3 WRITE_BEGIN storage failure | A WRITE_BEGIN refused STORAGE_FAILURE (its MAINT_REQUESTED record failed) may already have denied an armed I05 action through the storage-failure path; the refusal has no deniedActionIds, and the deny is reported only through I05 ACTION_OUTCOME (NOT_FORWARDED). | T60 |
| W4 predecessors and scope | `architecture/i06-backend-profile/README.md` (the W02g name obligation, lines 239-240) is a pinned predecessor input in the source index. The CLUSTER scope is removed from `SCOPES`, `check_write` and `render_write`; no writable row is cluster-scoped (the builder asserts it). | K01-K79 (carried) |

The v2 changes (R1-R8 of the v1 review, the I05 v2 base, the W02f sealing) stay as stated in
`../i07-policy-write-v2/README.md` ("What v2 changes").

## Channel

As v1 (`../i07-policy-write/README.md`, "Channel"), with the v3 frame version (round-1 AF-I07-1): one writer session at a time on
`/run/planeon/maintenance/policy-write.sock`; custody on every frame (a deviation is fatal and an urgent invalidation,
WRITER_PEER_DEVIATION); MAINTENANCE_STATUS opens each session; strict lockstep (a writer frame before the response to its
previous request is fatal, LOCKSTEP); the I05 byte rules with printable-ASCII strings and member names of at most 317
characters; fatal versus refused as in v1. WRITE_OBJECT is answered after its upstream exchange, which the gate bounds to
10 seconds. On expiry the gate aborts the exchange and records WRITE_TERMINAL IO_AMBIGUOUS `{aborted: UPSTREAM_TIMEOUT}`
before the response; the writer is answered IO_AMBIGUOUS and the maintenance is HELD (v3, W2).

## Operations

| Operation | Request | OK response | Refusal reasons |
|---|---|---|---|
| MAINTENANCE_STATUS | `{}` | generation, gate state, maintenance state, in-flight I05 action, write count, ambiguous write IDs, journal digest | none |
| WRITE_BEGIN | expectedGeneration | maintenance (PENDING, OPEN or HELD), gate state, every I05 action this request denied | GENERATION_MISMATCH, MAINTENANCE_ENDED, STORAGE_FAILURE (a refusal after a failed MAINT_REQUESTED record may already have denied an armed I05 action, reported only through ACTION_OUTCOME; v3, W3) |
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
at any version. No writable kind is cluster-scoped, and the model has no cluster scope any more (v3, W4).

## Decisions

0. **Maintenance follows the A3 fence.** WRITE_BEGIN asks for the I05 v3 drain. Maintenance is OPEN only while the base
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
7. **A3 versus A4** as v1, with the I05 v3 drain answer.
8. **What the gate does not judge** as v1. Admission objects are not written through I07 at all (W02f).

## Durable journal

The v1 records (MAINT_REQUESTED, MAINT_OPEN, MAINT_HELD, WRITE_FORWARDED, WRITE_TERMINAL, MAINT_ENDED, WRITER_SESSION_ENDED)
plus:

| Record | When | Restart meaning |
|---|---|---|
| WRITE_TERMINAL(writeId, IO_AMBIGUOUS, {aborted: reason}) | The gate aborts an outstanding write (writer EOF, fatal frame, writer peer deviation), before the session and maintenance records | The write is ambiguous; the gate is HELD |
| WRITE_TERMINAL(writeId, IO_AMBIGUOUS, {aborted: UPSTREAM_TIMEOUT}) | The 10-second upstream bound expires; before the writer's response (v3, W2) | The write is ambiguous; the gate is HELD |
| WRITE_LATE_UPSTREAM(writeId) | An upstream outcome after the abort | Reconciliation only |

and the I05 v3 records (RESTARTED, the failure marker, torn-record detection). On restart the gate rebuilds the I05 v3 way,
every write forwarded without a terminal record becomes IO_AMBIGUOUS (HELD), no writer session survives, and the
maintenance is ENDED with the recorded MAINT_ENDED reason if the maintenance had ended, GATE_RESTART if it had begun and
not ended, and GENERATION_REBUILT otherwise (v3, W2).

`STORAGE_FAIL_AFTER` is a test injection of the I05 v3 model (the (k+1)-th record attempted from then on fails; failed
attempts count, and one injection is pending at a time), used by T56; it is not a gate event.

## v2 review findings and dispositions in v3

| Finding | Disposition in v3 |
|---|---|
| W1 MINOR, response combinations the gate never sends | Four conditional constraints (G39-G47); the ambiguousWriteIds/writes bound stated as outside JSON Schema |
| W2 NOTE, restart reason and upstream expiry | Restart sentence reworded; TIMEOUT is an abort `{aborted: UPSTREAM_TIMEOUT}`, answered IO_AMBIGUOUS (T59, T61, T62) |
| W3 NOTE, WRITE_BEGIN STORAGE_FAILURE denies | Stated in the Operations table (T60) |
| W4 NOTE, W02g README and CLUSTER branches | README pinned as a predecessor input; CLUSTER scope removed |

## v1 review findings and dispositions (in v2, unchanged)

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
- I05 v3's double-fault residual (its exact precondition is in `../i05-gate-channel-v3/README.md`) still applies to the
  gate's own HELD; no maintenance opens in the rebuilt generation.
