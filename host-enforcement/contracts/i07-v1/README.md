# I07 policy writer channel — W02c (MET-ENFORCE-008), round 1

Status: **CONTRACT_CANDIDATE**, awaiting the round-1 independent review. DATA_CHECK_ONLY: no socket is opened, no write is
forwarded, nothing is installed, and all E01-E12 stay OPEN_UNPROVEN.

This part formalizes I07, the private channel from the enrolled policy-writer artifact to the effect gate, as the
reviewed W01 design left it for W02 (HOST-INTERFACE-DRAFT-002 §2.3, §2.4, §3.2 A3/A4, §4.3, §5.3, §5.5 M2/M4,
counterexamples 18 and 23):

- the frame envelope, which reuses the I05 rules (W02b) with its own writer challenge and chain;
- the closed schema for MAINTENANCE_STATUS, WRITE_BEGIN, WRITE_OBJECT and WRITE_END;
- the closed policy-kind table: exactly the kinds, scopes and operations the writer identity may change, derived from
  the reviewed W02g identity closure, with the refusal of effect kinds, of policy kinds outside the closure and of every
  other kind;
- the gate's decisions as an executable model that extends the reviewed W02b gate model without changing it:
  maintenance opens only when the A3 drain fence holds, and every write is journalled durably;
- kind-table, rendering, outcome, frame, byte-level and transcript vectors, including counterexamples 18 and 23 and
  the W02b round-3 probes for finding P1.

## Files

| File | Content |
|---|---|
| `channel.schema.json` | Draft 2020-12 schema `planeon.internal.policy-write-frame/v1`: eight frame variants (four requests, four responses) |
| `policy-kinds.json` | The closed policy-kind table: nine writable kinds derived from W02g, three effect kinds, nine policy kinds outside the writer closure |
| `vectors.json` | 77 kind-table checks, 7 exact renderings, 22 outcome checks, 20 frame checks, 9 byte-level checks and 45 transcripts, each with its exact expected output |
| `scripts/i07_policy_write.py` | Reference model: `classify_resource`, `check_write`, `render_write`, `write_outcome_is_final`, `PolicyGate` (a subclass of the W02b `Gate`), `replay` |

The W02b model `scripts/i05_gate_channel.py` is imported unchanged; its reviewed bytes are an input, not a subject.

## Channel

1. **Socket and sessions.** The gate listens on the candidate path `/run/planeon/maintenance/policy-write.sock`
   (AF_UNIX/SOCK_SEQPACKET, root:root 0600; only `planeon_policy_writer_t` may `connectto`, W01 §2.4, §5.3). One writer
   session at a time: a second connection while one is open is refused (`SESSION_EXISTS`). Sessions may follow one another
   while no maintenance has begun, so an operator can read status and leave.
2. **Custody on every frame.** On every received frame the gate qualifies the writer peer the way it qualifies the broker
   on I05 (W01 §4.3): SO_PEERCRED and the frame's SCM_CREDENTIALS, the retained pidfd and PID/start identity, the enrolled
   writer artifact `/opt/planeon/bin/harness-policy-write` (fs-verity digest under its signed manifest, §4.2), the label
   `planeon_policy_writer_t` (§5.3). A deviation means something other than the enrolled writer holds the session. That is
   an enforcement breach, so it is fatal for the session and an urgent invalidation of the generation (HELD,
   `WRITER_PEER_DEVIATION`).
3. **Opening and lockstep.** The first writer frame of each session is MAINTENANCE_STATUS with sequence 1, an all-zero
   previous digest and a fresh 256-bit writer challenge; every later frame of the session carries that challenge. Odd
   sequences are writer requests, even sequences gate responses, one response per request. The envelope carries no
   generation. The writer learns it from the MAINTENANCE_STATUS response and must name it in WRITE_BEGIN.
4. **Bytes.** As I05 (W02b channel item 4): at most 16 KiB, UTF-8, duplicate-free canonical JSON, exact builtins, no
   control character, depth at most 16, the closed schema. A write object is free-form JSON inside the same bounds, with two
   extra schema rules so that the canonical form stays RFC 8785: every string and member name is printable ASCII, and every
   integer is within ±(2^53−1). MAINTENANCE_STATUS, WRITE_BEGIN and WRITE_END are answered within 2 seconds. WRITE_OBJECT is
   answered after its upstream exchange (Decision 4). No descriptor passing, command, URL, path or program selector.
5. **Fatal versus refused.** A frame that fails item 4, breaks the chain, claims the gate's direction (an even sequence or a
   response shape), changes the challenge, or does not open with MAINTENANCE_STATUS ends the session without a response.
   A well-formed request the gate will not honour gets REFUSED with a closed reason and changes no state, except that a
   storage failure holds the generation.
6. **Session end.** EOF or loss ends the session and is journalled. If the session owns the maintenance (Decision 1), the
   maintenance ends with it.

## Operations

| Operation | Request | OK response | Refusal reasons |
|---|---|---|---|
| MAINTENANCE_STATUS | `{}` | generation, gate state, maintenance state, in-flight I05 action, write count, ambiguous write IDs, journal digest | none |
| WRITE_BEGIN | expectedGeneration | maintenance (PENDING, OPEN or HELD), gate state, the I05 actions this drain denied | GENERATION_MISMATCH, MAINTENANCE_ENDED, STORAGE_FAILURE |
| WRITE_OBJECT | writeId, operation (CREATE, UPDATE, DELETE), resource (group, version, resource), namespace, name, object, prior (uid, resourceVersion, projectionDigest) | writeId, classification (DELIVERED_RESULT or IO_AMBIGUOUS), the digest of the rendered request, and for a delivered result the HTTP status, result digest, observed UID and resourceVersion | MAINTENANCE_NOT_OPEN, MAINTENANCE_HELD, WRITE_ID_OUT_OF_ORDER, EFFECT_KIND, POLICY_KIND_NOT_WRITABLE, KIND_OUTSIDE_TABLE, VERB_NOT_ALLOWED, SCOPE_MISMATCH, PRIOR_RULE, OBJECT_RULE, STORAGE_FAILURE |
| WRITE_END | `{}` | maintenance ENDED, gate state, write count, ambiguous write IDs | MAINTENANCE_NOT_BEGUN, MAINTENANCE_ENDED, STORAGE_FAILURE |

### Where each request value comes from

| Value | Source at the gate | Effect |
|---|---|---|
| expectedGeneration | GATE: its own generation | Must equal it (GENERATION_MISMATCH); journalled in MAINT_REQUESTED |
| resource, operation, namespace, name | TABLE: `policy-kinds.json` and the qualification namespace | Must be inside the closed table (Decision 3) |
| object | TABLE: the kind's object shape | apiVersion, kind, metadata name and namespace must agree with the request; only the kind's own top-level keys; metadata limited to name, namespace, labels, annotations, uid and resourceVersion (OBJECT_RULE) |
| prior.uid, prior.resourceVersion | APISERVER: rendered as preconditions | The apiserver refuses a stale or replaced object itself (409); the gate holds no read grant |
| prior.projectionDigest | LABEL | The writer's statement of the observer projection it acted on; journalled, confers nothing |
| writeId | LABEL | Contiguous from 1 within the maintenance (1-256); refusals do not consume an ID |

## Closed policy-kind table

`policy-kinds.json` is derived, not chosen: its writable rows are exactly the POLICY_WRITE grants of `planeon:policy-writer`
in the reviewed W02g identity closure (`architecture/i06-backend-profile/identity-closure.json`, digest pinned in the file).
The validator recomputes the derivation.

| Kind | Resource | Scope | Operations |
|---|---|---|---|
| LimitRange | `v1 limitranges` | qualification namespace | CREATE, UPDATE, DELETE |
| Namespace | `v1 namespaces` | the qualification namespace object only | UPDATE |
| ResourceQuota | `v1 resourcequotas` | qualification namespace | CREATE, UPDATE, DELETE |
| ServiceAccount | `v1 serviceaccounts` | qualification namespace | CREATE, UPDATE, DELETE |
| NetworkPolicy | `networking.k8s.io/v1 networkpolicies` | qualification namespace | CREATE, UPDATE, DELETE |
| Role | `rbac.authorization.k8s.io/v1 roles` | qualification namespace | CREATE, UPDATE, DELETE |
| RoleBinding | `rbac.authorization.k8s.io/v1 rolebindings` | qualification namespace | CREATE, UPDATE, DELETE |
| ValidatingAdmissionPolicy | `admissionregistration.k8s.io/v1 validatingadmissionpolicies` | cluster | CREATE, UPDATE, DELETE |
| ValidatingAdmissionPolicyBinding | `admissionregistration.k8s.io/v1 validatingadmissionpolicybindings` | cluster | CREATE, UPDATE, DELETE |

- **Narrower than the grants.** The identity also holds `patch` on every row. I07 never sends PATCH, so the gate cannot
  forward a merge it did not render. W02g grants Namespace only `update` and `patch`, so creating or deleting a Namespace
  is refused (VERB_NOT_ALLOWED).
- **bind and escalate.** The identity holds them only on the two named Roles `planeon-gate-effect` and
  `planeon-policy-observer`. They are not I07 operations: the apiserver's own RBAC escalation check uses them when a Role
  or RoleBinding write references those Roles. The gate adds no name rule of its own.
- **Effect kinds.** Pod, ConfigMap and Service, the gate effect identity's kinds (W02b), are never forwarded with the
  writer identity at any version: EFFECT_KIND (counterexample 23).
- **Policy kinds outside the writer closure.** ClusterRole, ClusterRoleBinding and CertificateSigningRequest are reboot
  maintenance only (W01 §5.5, P4). Validating and mutating webhook configurations, MutatingAdmissionPolicy and its binding,
  APIService and CustomResourceDefinition must stay absent (P6, P7). All are refused at any version:
  POLICY_KIND_NOT_WRITABLE.
- **Everything else** is outside the table, including Secrets, workloads, nodes and a writable kind at an unlisted
  version: KIND_OUTSIDE_TABLE. Subresources (`status`, `token`, `approval`, ...) and the `impersonate` verb cannot be
  expressed: the resource name admits no `/`, and the operation set is closed.

## Decisions

0. **Maintenance opens only on the A3 fence (W02b finding P1).** WRITE_BEGIN asks for the gate's normal drain. The answer is
   not a grant. Maintenance is OPEN only while the generation is CLOSED or INVALIDATED and no action admitted under it lacks
   a durable terminal classification. It is HELD while the generation is HELD, which includes any IO_AMBIGUOUS action, and
   PENDING otherwise. The model computes this fence from the gate's own state after every event (`PolicyGate._fence`). It
   never uses the W02b drain reply, which after an urgent close can come back INVALIDATED while an admitted action is
   still in flight (P1 probes, T04-T06). MAINT_OPEN is recorded before the first write.
1. **One maintenance per generation, owned by one session.** The session whose WRITE_BEGIN starts the maintenance owns it.
   WRITE_END ends it; so does the owning session's end, loss or fatal frame. After that, WRITE_BEGIN is refused
   (MAINTENANCE_ENDED) in every later session of the generation. A maintenance interrupted by a gate restart never resumes
   (W01 base §5: the gate restarts denied). A repeated WRITE_BEGIN in the owning session reports the current state without
   a second drain or record, so it doubles as a poll.
2. **The gate stays CLOSED.** WRITE_END leaves the gate CLOSED or INVALIDATED. The old generation never resumes; a new one
   needs fresh observation and enrollment (W01 §2.4, base §5). During maintenance the broker may still read status and
   seal actions on I05, but BIND, ARM and A1 stay refused, because the generation is not ACTIVE.
3. **Writer identity only for the closed table, only while OPEN.** WRITE_OBJECT is checked in this order: maintenance OPEN,
   writeId, kind table, operation, scope, prior rule, object rule. Only then does the gate render the request and forward it
   with the writer identity. A refused write changes no state and forwards nothing.
4. **Exact rendering and preconditions.** From the table row and the request the gate renders the one Kubernetes request a
   write permits (`render_write`). That is `POST` to the collection with the canonical object (CREATE), or `PUT` to the item
   with the canonical object carrying the prior uid and resourceVersion (UPDATE). For DELETE it is `DELETE` to the item
   with exactly
   `{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"resourceVersion":"<rv>","uid":"<uid>"}}`. The headers are
   `Host: <apiserver loopback authority>`, `Accept: application/json`, `Content-Type: application/json` and
   `Content-Length`. The apiserver enforces the expected prior state: an existing name refuses a CREATE, and a stale uid
   or resourceVersion refuses an UPDATE or DELETE (409). The writer identity has no read grant (W02g), so the gate does not
   read first. The response carries the digest of the rendered request. The gate bounds the upstream exchange to
   10 seconds and answers within 12. On expiry it aborts the exchange and the write is IO_AMBIGUOUS.
5. **Write outcomes.** The same ambiguity rule as W02b Decision 0. A delivered response settles a write only with its
   success status (CREATE 201; UPDATE 200 or 201; DELETE 200 or 202) or a rejection (4xx other than 408, which includes 409
   and a DELETE's 404). Any other status, a lost exchange or a failed terminal record makes the write IO_AMBIGUOUS. It then
   holds the generation HELD, which holds the maintenance, so no further write is possible. The status and digest of an
   ambiguous response stay in its journal record for reconciliation only.
6. **Durable before the effect.** WRITE_FORWARDED is written with fsync and read back before the first upstream byte, like
   A1's consumption record. WRITE_TERMINAL is written before the response. A failed write record is the W02b urgent
   STORAGE_FAILURE: the generation is HELD, and a write whose forward record failed is not forwarded.
7. **A3 versus A4.** An urgent close does not wait for A3 (W02b Decision 8). Maintenance after one still waits for the fence.
   Actions admitted before the invalidation finish and are recorded `admittedBeforeInvalidation` before any write
   commits (T04, T05). So the W01 guarantee holds for I07 writes in every state: no mediated policy write commits while an
   admitted action lacks a durable terminal classification.
8. **What the gate does not judge.** Beyond kind, scope and object shape, the gate does not check a write's content: rule
   breadth, binding subjects, quota values, network-policy semantics or a ValidatingAdmissionPolicy's CEL. The apiserver
   applies RBAC escalation prevention. Fresh observation of the complete effective RBAC and policy closure (W01 §2.3,
   W02g IC00-IC05) decides whether any new generation can enroll. ValidatingAdmissionPolicy names are not restricted until
   the A2 objects are pinned (W02f); their digests are pinned by the observer's admissionPolicy check (W01 §3.2 A2). An
   object larger than the 16 KiB frame cannot be written through I07 v1.

## Durable journal

I07 adds these records to the gate's one journal. Each is written with fsync and read back before the effect named. A
failed record is the urgent STORAGE_FAILURE (W02b durable journal).

| Record | When | Restart meaning |
|---|---|---|
| MAINT_REQUESTED(generation) | WRITE_BEGIN starts a maintenance, before the drain | A maintenance began; after a restart it is ENDED (GATE_RESTART) unless MAINT_ENDED follows |
| MAINT_OPEN(state) | The fence holds | Writes were permitted |
| MAINT_HELD(state) | The generation is HELD during the maintenance | — |
| WRITE_FORWARDED(writeId, operation, apiVersion, kind, namespace, name, requestDigest, prior) | Before the first upstream byte | Without WRITE_TERMINAL: IO_AMBIGUOUS, and the gate restarts HELD |
| WRITE_TERMINAL(writeId, classification, details) | Before the response | The write's classification |
| MAINT_ENDED(reason, writes, ambiguousWriteIds) | WRITE_END or the owning session's end | Maintenance ENDED |
| WRITER_SESSION_ENDED(how) | Session EOF, loss or fatal frame | — |

On restart the gate rebuilds I05 actions as W02b does. Every write forwarded without a terminal record becomes
IO_AMBIGUOUS, and the gate then restarts HELD. No writer session survives the restart, and an unfinished maintenance is
ENDED (T14, T15, T38).

## W02b finding P1 and the I05 side

P1 found that after an urgent close the W02b gate-side drain does not follow the A3 fence. A pending drain never settles
in INVALIDATED. A WRITE_BEGIN in INVALIDATED is answered at once while an admitted action is still in flight. A failed seal
record leaves `drainPending` set. The round-3 review asked W02c to treat such an answer as "no write" unless the fence
holds. Decision 0 does that for every write, and the three probes are vectors: PA as T05, PA3 as T04, Q3 as T06.

The I05-side bookkeeping stays W02b's, unchanged and carried to W02b-F: `drainPending` staying set in INVALIDATED (T05
pins it), no DRAINED record in that case, and ARM's refusal reason there. Findings P2-P8 are untouched by this part.

## Counterexamples

| Counterexample | Vector |
|---|---|
| 18: a policy write while an admitted CREATE is in flight | T02 (the write waits for the terminal record), T03 (an ambiguous outcome blocks every write), T04 and T05 (after an urgent close) |
| 23: a WRITE_OBJECT carrying a Pod or an unknown kind | T08; K-checks for every effect kind, every non-writable policy kind and kinds outside the table |
| W02b P1 probes PA, PA3, Q3 | T05, T04, T06 |

## Spec mapping

| Design text | Here |
|---|---|
| §2.3 writer identity: policy kinds only, qualification namespace plus named cluster objects, only while CLOSED for maintenance | Closed table; Decisions 0 and 3 |
| §2.4 WRITE_BEGIN: normal drain, reply after the A3 fence, HELD if ambiguous | Decision 0 (the grant is MAINT_OPEN, never the drain reply), T02-T06, T28 |
| §2.4 WRITE_OBJECT: one create/update/delete of one policy kind with the expected prior projection digest; non-policy and effect kinds refused | Decisions 3-5; prior uid and resourceVersion as apiserver preconditions, projectionDigest journalled |
| §2.4 WRITE_END: gate stays CLOSED, the old generation never resumes | Decisions 1 and 2 |
| §2.4 the writer never holds an apiserver credential | Only the gate holds the writer credential; the writer reaches nothing but I07 |
| §3.2 A3 and A4 | Decisions 0 and 7 |
| §4.3 the gate qualifies the writer on every I07 frame | Channel item 2 |
| §5.5 M2 and M4 | WRITE_BEGIN before a maintenance reboot; Kubernetes policy changes through I07 with the fence |
| Counterexamples 18 and 23 | See above |

## Still open

All E01-E12 and T01-T08. The writer's per-frame custody under load (native). The gate's HTTP/TLS client to the apiserver
and the journal storage format (W03). The names and field allowlists of the A2 ValidatingAdmissionPolicy objects (W02f).
The I05-side drain bookkeeping and findings P2-P8 (W02b-F). W03-W07 remain gated. Alpha2 remains open; model-effort
transition NOT_DUE.
