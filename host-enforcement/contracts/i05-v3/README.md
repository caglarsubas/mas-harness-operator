# I05 broker-gate channel v3 — W02-ADM-F contract (DATA_CHECK_ONLY)

Alpha 2A; 2026-10-09. Status: **CONTRACT_CANDIDATE_ROUND2_AWAITING_INDEPENDENT_REVIEW** (one combined W02-ADM-F review
with `../admission-semantics-v3/` and `../i07-policy-write-v3/`; brief and source index in `../w02-adm-f/`).

v3 is the W02-ADM-F successor of the adopted I05 v2 contract `../i05-gate-channel-v2/`
(`planeon.internal.effect-gate-frame/v2`, ADOPTED_DATA_CONTRACT, MET-ENFORCE-011). Later layers pin the v2 bytes (the I07
v2 contract extends the v2 model unchanged and its validator lists them as frozen), so v2 stays byte-identical and v3 is
published beside it. v3 keeps the v2 design and changes only what the v2 review (`../i05-gate-channel-v2/review-round1.json`,
PASS_FOR_SOURCE_PUBLICATION) carried: V1 and V3-V6, plus the Decision 8 wording of V2 (the I07 side of V2 was closed in
I07 v2, T57). Nothing here opens a socket, forwards a request or installs a gate; all E01-E12 stay OPEN_UNPROVEN.

Accepted base: main `f88e7f7` (MET-ENFORCE-014, 213 packets). The packet that publishes v3 is claimed only after
MET-PERF-035 merges (owner decision, 2026-10-08).

## Files

| File | Content |
|---|---|
| `channel.schema.json` | Draft 2020-12 schema `planeon.internal.effect-gate-frame/v3`: the v2 frame variants under the v3 version (no other schema change) |
| `outcome-mapping.json` | `planeon.internal.effect-gate-outcome-mapping/v2`, unchanged from v2 |
| `vectors.json` | 120 transcripts (T01-T106 carried from v2 under their IDs, T107-T120 new), 42 agreement cases, 34 frame checks (G34 new), 14 byte-level checks (listed B01-B14 in order), 5 configuration refusals (K04, K05 new), each with its exact expected output |
| `../../scripts/i05_gate_channel_v3.py` | Reference model: `decode_frame`, `check_frame`, `render_request`, `template_digest`, `identity_of`, `Gate` (with `fence`), `replay`, `check_agreement` |

The v3 model is a copy of the v2 model with the changes below, so the v2-to-v3 diff of `scripts/i05_gate_channel_v2.py`
and `scripts/i05_gate_channel_v3.py` is the review surface. Every carried vector keeps its v2 events and expected
outputs; they differ from v2 only in the frame version string and the digests and frame bytes that follow from it, and in
the K02 refusal text (V6). G10's intent now says "not a v3 frame".

## What v3 changes

| Finding | v3 rule | Vectors |
|---|---|---|
| V1 unpinned rules | Three v2 rules get vectors: a restart drops a pending drain without an answer; a second drain request while one is pending records DRAIN_STARTED once (each request is answered PENDING); a DELETE armed with a UID this execution created for another manifest is refused UID_NOT_CREATED. The model gains a finer test injection, `STORAGE_FAIL_AFTER {after: k}`: the (k+1)-th record attempted from then on fails (STORAGE_FAIL_NEXT always fails the next record). It counts attempts, failed ones and those inside the storage-failure path included, and one such injection is pending at a time (a second replaces the first). With it the DRAINED-failure and DENIED-after-record cases are pinned. It is a model event only, never a channel frame. | T107-T113, T120 |
| V2 Decision 8 wording | A HELD generation answers a drain HELD at once, even while a consumed action has no terminal record (fails safe). OPEN is a point-in-time answer: the generation can become HELD afterwards (RECONCILIATION_REQUIRED, a non-orderly channel loss with an unsealed action, a storage failure), and the I07 writer keeps evaluating the fence after OPEN (I07 v2 and v3: MAINT_HELD). | T66, T71 (carried); I07 T57 |
| V3 residual precondition | Stated exactly under Durable journal and failure marker: two consecutive failed journal writes, one failed marker write, no torn record, and no later state record before the restart. It covers the gate's own storage-failure HELD as well as RECONCILIATION_REQUIRED, and a drain after such a restart is answered OPEN. | T103 (carried); T116-T118 |
| V4 upstream bound | The gate bounds a forwarded exchange by the 900-second limit, counted from its consumption. The end of the signed lifetime does not abort it: as Decision 9 says, an action in flight at expiry completes and is reported admitted before invalidation. On expiry of the bound (model event UPSTREAM_TIMEOUT) it aborts the exchange and closes the server connection: the action is TERMINAL IO_AMBIGUOUS with `{aborted: UPSTREAM_TIMEOUT}`, nothing is relayed, the generation is HELD, a pending drain settles HELD, and a later upstream response is a late response. | T114, T115, T119 |
| V5 dropped v1 clauses | Restored: Decision 1's durability-before-relay sentence, Decision 4's fail-closed stock client, the conservative outcomes paragraph with the `flushClosures` definition, why NOT_FORWARDED agrees with both DENIED and AMBIGUOUS, that object content beyond the identity match is not verified, and that an execution with an action admitted before invalidation never ends COMPLETED. | — |
| V6 hygiene | The identity refusal reads "a manifest identity resolves to more than one manifest", and it also applies within one run (K05). A `priorBindings` record without all four lists (the v1 shape) is refused "an incomplete priorBindings record" (K04) instead of raising KeyError. The byte checks are listed B11, B12, B13, B14. G34 refuses a v2 frame. | K02, K04, K05, G34, B11-B14 |

The v2 changes (P1-P8 of the v1 round-3 review) stay as stated in `../i05-gate-channel-v2/README.md` ("What v2
changes"); the sections below restate the rules they produced.

## Channel

1. **One channel per gate generation.** The broker connects to the candidate path
   `/run/planeon/live-proxy/effect-admission.sock` (AF_UNIX/SOCK_SEQPACKET, root:root 0600) after it has qualified the gate
   as a peer (§4.3). The gate refuses a second connection while the channel is open and any connection after it closed:
   there is no reconnect.
2. **Custody on every frame.** On every received frame the gate verifies the broker's kernel peer identity: SO_PEERCRED and
   the frame's SCM_CREDENTIALS, the retained pidfd and PID/start identity, executable, label and cgroup (base §3, §4.3). Any
   deviation is fatal. The BIND_EXECUTION peer-qualification digest adds a cross-check of the mutual qualification record;
   it does not replace the per-frame checks.
3. **Opening and lockstep.** The first broker frame is GENERATION_STATUS with sequence 1, an all-zero previous digest, the
   gate's generation and a fresh 256-bit broker challenge; every later frame carries the same generation and challenge. Odd
   sequences are broker requests, even sequences gate responses, one response per request, no unsolicited gate frames.
   `previousDigest` is the SHA-256 of the exact bytes of the frame before it.
4. **Bytes.** A received datagram is a byte string (F07 otherwise) of at most 16 KiB, UTF-8, duplicate-free JSON without
   NaN or Infinity, and exactly the canonical encoding (sorted keys, no whitespace), so the bytes digested are the bytes
   received (`decode_frame`; for this schema, with ASCII strings and integers only, that canonical form coincides with RFC
   8785; any other decode failure, such as an over-long integer or a lone surrogate, is F06). Then: depth at most 16 (checked
   first), exact builtins (no floats; booleans are not integers), no control character in any string (the schema patterns
   are ECMA-262 patterns; a trailing newline is refused), the closed schema. Each request is answered within 2 seconds,
   inside the execution's signed lifetime and the 900-second limit. No descriptor passing, no command, URL, path or program
   selector.
5. **Fatal versus refused.** A frame that fails any of item 4, breaks the chain, claims the gate's direction (a response
   shape or an even sequence), carries another generation or challenge, or does not open with GENERATION_STATUS closes the
   channel without a response; so does a peer deviation or a BIND whose peer-qualification digest differs. A well-formed
   request the gate will not honour gets REFUSED with a closed reason and changes no gate state, except that a storage
   failure holds the generation.
6. **Channel end.** Broker EOF when the generation is CLOSED or INVALIDATED, every action sealed and none in flight, is an
   orderly end: the state stays, and the end is journalled. Any other loss is peer failure: unsealed actions are denied and
   the generation is HELD. A connection that ends before its first frame also uses the generation's one channel. W01 §2.4
   WRITE_END therefore leaves the gate CLOSED.

The broker verifies the gate's frames the same way and treats any deviation as peer failure.

## Operations

| Operation | Request | OK response | Refusal reasons |
|---|---|---|---|
| GENERATION_STATUS | `{}` | state, drainPending, bound execution, armed and in-flight action, counters, journal digest | none |
| BIND_EXECUTION | executionId, bindingDigest, reservationDigest, runNonce, caseId, requestDigest, dispatchGeneration, serverCertificateDigest, worker PID and start ticks, peerQualificationDigest | executionId and the gate-resolved case manifest-set digest | NOT_ACTIVE, ACTION_OUTSTANDING, EXECUTION_REPLAY, GENERATION_MISMATCH, UNKNOWN_BINDING, CERTIFICATE_MISMATCH, MANIFEST_REUSED, WORKER_NOT_OBSERVED, STORAGE_FAILURE |
| ARM_ACTION | executionId, actionId, verb, manifestDigest, requestTemplateDigest, recordedUid | actionId and the number of connections the C2 flush closed | NOT_ACTIVE, DRAIN_PENDING, EXECUTION_NOT_BOUND, EXECUTION_EXPIRED, ACTION_OUTSTANDING, ACTION_ID_OUT_OF_ORDER, MANIFEST_OUTSIDE_CASE, UID_RULE, UID_NOT_CREATED, TEMPLATE_MISMATCH, MUTATION_KEY_REUSED, STORAGE_FAILURE |
| ACTION_OUTCOME | executionId, actionId | classification, admittedBeforeInvalidation, HTTP status, result digest, observed UID and resourceVersion | EXECUTION_NOT_BOUND, UNKNOWN_ACTION, STORAGE_FAILURE |
| CLOSE_GENERATION | reason (NORMAL_DRAIN, REVOCATION, EXPIRY, PEER_FAILURE, STORAGE_FAILURE, OBSERVATION_FAILURE, RECONCILIATION_REQUIRED) | resulting state and every action this close denied | ACTION_IN_FLIGHT (normal drain only) |

GENERATION_STATUS is constrained in the schema: at most one outstanding action, none without a bound execution, an armed
action only while ACTIVE, nothing bound while INSPECTING, no in-flight action while CLOSED, a pending drain while DRAINING,
and (v2) a pending drain only in DRAINING or INVALIDATED and only while an action is in flight.

### Where each request value comes from

| Value | Source at the gate | Effect |
|---|---|---|
| runNonce, bindingDigest, caseId, requestDigest | RESOLVED: the gate's own copy of the signed release and capacity inputs for this run nonce; the gate refuses inputs in which a manifest digest or a manifest identity (kind, namespace, name) belongs to more than one run, or a run lists a digest the signed profile lacks | Must equal the resolution (UNKNOWN_BINDING) |
| serverCertificateDigest | RESOLVED: the run certificate the gate enrolled for this run | Must equal it; A1 requires the same certificate (CERTIFICATE_MISMATCH) |
| case manifest set, manifest identity, request rendering | RESOLVED: the signed profile and exact kubernetesApiRules | Bounds every ARM_ACTION; no manifest digest or identity of an earlier generation's run (MANIFEST_REUSED) |
| workerPid, workerStartTicks | KERNEL: a live member of the broker's probe-worker cgroup with that PID and start time | Must be observed (WORKER_NOT_OBSERVED) |
| peerQualificationDigest | KERNEL: the gate's own mutual qualification record | Must equal it (fatal) |
| dispatchGeneration | GATE: its own generation | Must equal it (GENERATION_MISMATCH) |
| recordedUid (DELETE) | GATE: a UID the gate itself recorded from this execution's own delivered CREATE 201 for the same manifest | Must be one of them (UID_NOT_CREATED) |
| executionId, reservationDigest | LABEL: broker-assigned; no independent source | Confers no authority; journalled; an executionId or run nonce binds once, ever: earlier generations' BIND records stay in the durable journal (EXECUTION_REPLAY) |
| actionId, verb, manifestDigest, requestTemplateDigest | LABEL checked against RESOLVED data | A request to arm; the gate re-derives the template and refuses any mismatch |

## Decisions

0. **Unknown mutation outcomes are ambiguous.** A delivered response settles a CREATE only with 201 or a rejection (4xx
   other than 408), and a DELETE only with 200, 202, 404 or such a rejection. Any other status (every 5xx, 408, 1xx, 3xx,
   another 2xx) leaves the outcome unknown, so the gate classifies the action IO_AMBIGUOUS, keeps the status and digest in
   its TERMINAL record for reconciliation, relays the response, and holds the generation: the A3 fence, the drain and the
   normal close never treat it as settled. A GET never mutates, so every GET status is DELIVERED_RESULT.
1. **ACTION_OUTCOME seals.** After its response the action can never be consumed and its classification never changes. An
   armed, unconsumed action becomes NOT_FORWARDED and its stamped connections close. A terminal action returns its record.
   An action still in flight is aborted: the gate closes the upstream exchange and the consumed server connection, records
   IO_AMBIGUOUS and holds the generation (A3). A late upstream response after a seal is never relayed and never changes the
   seal; it is journalled as a reconciliation note. The broker asks after the server's RESOURCE_RESULT, and the gate
   records every terminal classification durably before relaying any response byte, so a normal result is recorded by
   then (restored from v1, V5).
2. **One outstanding action, sealed before the next.** ARM_ACTION and the next BIND_EXECUTION are refused until every action
   of the bound execution is terminal and sealed. One execution is bound at a time (one worker). The broker's I02
   transcript advances only after it holds both the gate's ACTION_OUTCOME and the server's RESOURCE_RESULT and they agree.
3. **Action identifiers.** actionId is the I02 RESOURCE_ACTION actionId, contiguous from 1 within the execution (1-256). The
   broker emits RESOURCE_ACTION only after ARM_ACTION returned OK. A connection stamp is (executionId, actionId).
4. **Exact request bytes.** From the armed template and the signed profile the gate renders the one I04 request the action
   permits (`render_request`, unchanged from v1). The head bytes are
   `<METHOD> /api/v1/namespaces/<ns>/<plural>[/<name>] HTTP/1.1` CRLF, `Host: <signed endpoint authority>` CRLF,
   `Accept: application/json` CRLF and, with a body, `Content-Type: application/json` CRLF and `Content-Length: <n>` CRLF,
   then an empty line. The body is the signed manifest bytes for CREATE, none for GET, and for DELETE exactly
   `{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"uid":"<recorded UID>"}}`. At A1 the received head and body
   must equal these bytes, and the gate forwards these rendered bytes upstream. Byte equality refuses, as REQUEST_MISMATCH,
   any other method, target form, query parameter, protocol version, header field (User-Agent and Transfer-Encoding
   included), name case, order, duplicate, folding, DeleteOptions field or body byte. HTTP/2, CONNECT, upgrade, redirect and
   generic proxying stay refused (base §4). The exact head is a requirement on the existing I04 client that no current I04
   rule states; it stays carried to the I04 owner (R01) and CONF-LIVE-003, and until then a stock client that adds fields
   is refused (fail-closed; restored from v1, V5).
5. **C2 flush and C3 stamp.** In the ARM_ACTION transaction, under the generation lock and before the ARM record, the gate
   closes every accepted connection that has not consumed an action and accepts and closes every connection in its listen
   backlog. A connection accepted later is stamped with the armed action, or with none. ACCEPT, ARM_ACTION, A1, sealing and
   closing serialize on the generation lock.
6. **A1.** A request passes only when the generation is ACTIVE with no pending drain, the execution is bound and not
   expired, the connection's stamp equals the armed, unconsumed action of the bound execution, its client certificate equals
   the bound run certificate and the request equals the rendering. The gate records the consumption (fsync and read back),
   then sends the first byte upstream. One request per connection (C1); the gate closes the connection after relaying its
   one response. After the consumption every other connection stamped with that action closes (C5). STAMP_MISMATCH and
   ALREADY_CONSUMED are checked but unreachable in the model (defence in depth).
7. **C7 by construction.** At ARM the gate refuses a CREATE whose manifest it already armed in this execution and a DELETE
   whose recorded UID it already armed, even if the earlier action was never forwarded. GETs may repeat.
8. **Closing and draining (v2, P1).** Normal close is refused while an action is in flight; otherwise it records the close,
   denies an armed action and ends CLOSED, or HELD if any action of the generation is IO_AMBIGUOUS. Urgent reasons
   (revocation, expiry, peer, storage or observation failure) close A1 at once in memory, independent of storage, record the
   invalidation, deny an armed action and end INVALIDATED (HELD if the record fails); an action already admitted may still
   complete and is recorded with `admittedBeforeInvalidation` (A4). RECONCILIATION_REQUIRED lets the broker carry its own
   disagreement or missing outcome to the gate: it closes A1, denies an armed action and ends HELD. An I07 WRITE_BEGIN is a
   drain request in every state, answered from the A3 fence (`fence()`, v2 P1). A HELD generation answers HELD at once,
   even while a consumed action has no terminal record (v3, V2). Otherwise the answer is PENDING until no consumed action
   lacks a terminal record, then OPEN (the generation is CLOSED or INVALIDATED) or HELD. OPEN is a point-in-time answer:
   the generation can become HELD afterwards (RECONCILIATION_REQUIRED, a non-orderly channel loss with an unsealed action,
   a storage failure), so the I07 writer keeps evaluating the fence after OPEN. A second request while one is pending
   records nothing new and is answered PENDING; a restart drops a pending drain without an answer (the I07 session does not
   survive a restart either). While DRAINING, ARM is refused DRAIN_PENDING and BIND NOT_ACTIVE.
9. **Execution expiry.** When the bound execution's signed lifetime ends, the gate records the expiry, denies an armed
   action, refuses ARM and A1 (EXECUTION_EXPIRED), and an action already in flight completes but is reported
   `admittedBeforeInvalidation`, as under the EXPIRY close.
10. **Cleanup admission (v2, P2).** Every I04 request, cleanup and absence confirmation included, must be a broker-armed
    RESOURCE_ACTION of the bound execution, or it is refused (STAMP_NONE). Absence is confirmed by GET (repeatable). A
    DELETE needs a UID that this execution's own CREATE 201 delivered for that manifest and is armed once per UID (C7). An
    INVALIDATED or HELD gate forwards nothing, cleanup included: resources stay CLEANUP_PENDING until externally authorized
    reconciliation. A later generation cannot re-bind an earlier run (EXECUTION_REPLAY), cannot bind a run that re-uses an
    earlier run's manifest digest or identity (MANIFEST_REUSED), and can delete only what its own execution created, so
    cleanup of an earlier run's resources is not done through I05; it stays with the external reconciliation path.
11. **States.** INSPECTING, ACTIVE, DRAINING, CLOSED, INVALIDATED and HELD are the base conceptual states, carried only on
    this private channel.
12. **Upstream bound (v3, V4).** A forwarded exchange is bounded by the 900-second limit, counted from its consumption
    (A1). The end of the bound execution's signed lifetime does not abort it (Decision 9: it completes and is reported
    `admittedBeforeInvalidation`). On expiry of the bound the gate aborts the exchange and closes the consumed server
    connection, records TERMINAL IO_AMBIGUOUS `{aborted: UPSTREAM_TIMEOUT}` and holds the generation. Nothing is relayed;
    a later upstream response is journalled LATE_UPSTREAM and never relayed. A pending drain settles HELD. So a hanging
    upstream cannot keep a WRITE_BEGIN PENDING forever. The broker's ACTION_OUTCOME then reports IO_AMBIGUOUS, which agrees
    only with AMBIGUOUS.

## Durable journal and failure marker (v2, P4)

The gate relies after a restart only on these records. Each is written with fsync and read back before the effect named.
A failed write is an urgent STORAGE_FAILURE at every record point: the failure marker is written first, A1 closes, the
generation is HELD, an armed action is denied and its connections close, an in-flight action is marked admitted before
invalidation, and the gate tries to record the invalidation; the operation then refuses or reports what it did.

| Record | Content | Durable before |
|---|---|---|
| BIND | executionId, runNonce, reservationDigest, the run's manifest digests and identities; kept across generations | the BIND_EXECUTION response |
| ARM | actionId, verb, manifestDigest, recordedUid, template digest | the ARM_ACTION response (after the C2 flush) |
| CONSUMED | actionId | the first byte sent upstream (A1) |
| TERMINAL | actionId, classification, admittedBeforeInvalidation, status, result digest, observed UID and resourceVersion (for an unknown mutation outcome: IO_AMBIGUOUS with the status and digest as reconciliation data; for an expired exchange: IO_AMBIGUOUS `{aborted: UPSTREAM_TIMEOUT}`) | the first response byte relayed to the server |
| SEALED | actionId, classification, admittedBeforeInvalidation | the ACTION_OUTCOME response |
| DENIED | actionId | the response or event that denied it |
| INVALIDATED | reason, resulting state | the CLOSE_GENERATION response (A1 closes first, in memory) |
| CLOSED, DRAINED | reason or resulting state | the response, or the drain answer to I07 |
| DRAIN_STARTED | — | the drain's denies |
| CHANNEL_ENDED | orderly, or before the first frame | reconciliation only |
| EXPIRED | executionId | any later decision for that execution |
| LATE_UPSTREAM | actionId | reconciliation only |
| RESTARTED | the restart state | the first decision after a restart |
| failure marker (separate store) | generation, reason | anything after a failed journal write |

Every journal record is self-delimiting and carries its own digest, so a torn record is detected wherever it is. A restart
starts denied, with no channel, stamps, connections or pending drain, and rebuilds the actions and the state from the
marker and the journal alone. A consumed action without a terminal record is IO_AMBIGUOUS and admitted before the
restart; an armed one without a terminal record is NOT_FORWARDED; the A4 qualifier otherwise comes from the TERMINAL and
SEALED records. The gate restarts HELD when the marker is present or a record is torn. Otherwise it restarts in the last
recorded CLOSED, INVALIDATED, DRAINED or RESTARTED state when every action is sealed and terminal and none is ambiguous,
and HELD in every other case. It then writes RESTARTED; if that write fails, the restart is HELD. The storage format of
both stores stays open; the marker store must not share a device or file system with the journal.

**Residual (disclosed against base §5; exact precondition, v3 V3).** The restart trusts the last clean record only when
all of these hold: two consecutive journal writes fail (the failing record and the INVALIDATED STORAGE_FAILURE record
written after the marker attempt), the one marker write fails, neither failure leaves a torn record, and no later state
record (CLOSED, INVALIDATED, DRAINED, RESTARTED) is written before the restart. One journal failure is not enough: the
INVALIDATED HELD record is then durable and the restart is HELD (T118). The residual covers RECONCILIATION_REQUIRED (T103,
where the broker keeps the generation HELD in its own journal and never advances its I02 transcript) and also the gate's
own storage-failure HELD, for example an orderly channel end whose records both fail (T117): there no broker holds
anything, and the restart comes back CLOSED. After such a restart a drain is answered OPEN (T116); I07 v3 still never
opens a maintenance in a rebuilt generation (I07 R1), so no policy write follows from it. It takes two independent
failure domains failing at once.

**Model test injections.** `STORAGE_FAIL_NEXT` (optionally torn) fails the next journal record, `STORAGE_FAIL_AFTER
{after: k}` fails the (k+1)-th record attempted from then on (v3, V1), and `MARKER_FAIL_NEXT` fails the next marker
write. STORAGE_FAIL_AFTER counts record attempts, including failed ones and the records written inside the
storage-failure path, and only one is pending at a time: a second replaces the first (T120). They are model events for
the vectors, never channel frames.

## Outcome mapping

`outcome-mapping.json` maps each gate classification to the I02 RESOURCE_RESULT outcomes that agree with it; an exact HTTP
status row takes precedence over a status-class row (minus its `excludeStatus`), and only an OK ACTION_OUTCOME is usable.

| Verb | Gate classification | HTTP status | RESOURCE_RESULT | Object |
|---|---|---|---|---|
| CREATE | DELIVERED_RESULT | 201 | CREATED | identity match required |
| CREATE | DELIVERED_RESULT | 4xx except 408 | DENIED | not compared |
| GET | DELIVERED_RESULT | 200 | PRESENT | identity match required |
| GET | DELIVERED_RESULT | 404 / other 4xx / 5xx | ABSENT / DENIED / AMBIGUOUS | not compared |
| DELETE | DELIVERED_RESULT | 200, 202 (202 unreachable with the pinned DeleteOptions) | DELETED | the kind's DELETE body when present |
| DELETE | DELIVERED_RESULT | 404 / 4xx except 408 (incl. 409) | ABSENT / DENIED | not compared |
| any | NOT_FORWARDED | none | DENIED or AMBIGUOUS | none |
| any | IO_AMBIGUOUS (incl. a CREATE or DELETE with an unknown outcome) | none | AMBIGUOUS | none |

DELETE bodies differ by kind (`deleteResponseBody`, sources pinned in `upstreamSource` and `deleteResponseBodySources`):
Pod and Service return the deleted object (identity match; the gate observes its UID and resourceVersion); ConfigMap
returns a v1 Status with status Success whose details carry name, kind (the resource, `configmaps`) and UID, so the gate
observes details.uid and no resourceVersion. A deletion that is not immediate returns the updated object instead
(`deleteNotImmediate`); for a ConfigMap that is refused (M05) and the broker holds. The identity match decodes objectBase64
strictly (valid base64, duplicate-free JSON, no NaN, depth at most 16) and requires apiVersion, kind, metadata.namespace
and metadata.name equal to the armed template and metadata.uid and metadata.resourceVersion equal to the gate's
observation. Object content beyond that is not verified (restored from v1, round-1 AF-I05-3). Disagreement, a missing or refused ACTION_OUTCOME or a missing RESOURCE_RESULT is sticky failure: the broker
holds the generation HELD and never advances its I02 transcript past the action. `admittedBeforeInvalidation` keeps the mapped outcome, but such an execution
never ends COMPLETED (restored from v1, round-1 AF-I05-3). NOT_FORWARDED agrees with both DENIED and
AMBIGUOUS, because a server that saw its connection closed cannot tell a refusal from a lost send (restored from v1, V5).
I02 is unchanged and no outcome enum is overloaded.

Conservative outcomes, stated rather than hidden (restored from v1, V5): a server whose I04 timeout is shorter than the
gate's upstream wait reports AMBIGUOUS, the seal or the upstream bound (Decision 12) then aborts the exchange
(IO_AMBIGUOUS) and the generation is HELD; a DELIVERED_RESULT whose relay the server lost disagrees with its AMBIGUOUS and
is HELD as well. `flushClosures` counts every gate-initiated closure of an unconsumed connection: the C2 flush, C5, seals
and denies.

## Counterexamples

| Counterexample | Vector |
|---|---|
| 17: a byte-identical duplicate of completed GET A buffered before ARM(B) | T02, T03 |
| 18: a policy write while an admitted CREATE is in flight | T30, T31; after an urgent close T87-T90 (v2) |
| 21: gate restart mid-execution | T25, T27; after unrecorded failures T100-T104 (v2) |
| 22: a connection opened while A was armed, used after B is armed | T08, T64 |

The §6.3 residual stays as stated there: a server that opens a new connection after ARM(B) and sends exactly B's request
gets B forwarded once; misattribution shows as disagreement (HELD), not as an unarmed effect.

## v2 review findings and dispositions in v3

| Finding | Disposition in v3 |
|---|---|
| V1 NOTE, four unpinned rules | Three vectors (T107-T109); `STORAGE_FAIL_AFTER` pins the DRAINED and DENIED-after-record failures (T110-T113); its counting is stated (T120) |
| V2 NOTE, drain-answer wording | Decision 8 reworded: HELD answers at once; OPEN is point-in-time and the writer keeps evaluating the fence |
| V3 NOTE, residual precision | Exact precondition, the gate's own storage-failure HELD, and a drain OPEN after the restart (T116-T118) |
| V4 NOTE, unbounded upstream exchange | Decision 12: 900 seconds from consumption (expiry does not abort, Decision 9), then abort IO_AMBIGUOUS `{aborted: UPSTREAM_TIMEOUT}`, HELD (T114, T115, T119) |
| V5 NOTE, dropped v1 clauses | Restored in Decisions 1 and 4 and under Outcome mapping, including the two further sentences the W02-ADM-F round-1 review named |
| V6 NOTE, hygiene | Refusal wording (K02, K05), incomplete priorBindings refused (K04), B11-B14 in order, G34 |

W02-ADM-F review round 1 (`../w02-adm-f/review-round1.json`, PASS_FOR_SOURCE_PUBLICATION) found AF-I05-1 (Decisions 9
and 12 disagreed on the signed lifetime: the bound is now the 900-second limit, T119), AF-I05-2 (injection counting
stated, T120) and AF-I05-3 (two more v1 sentences restored); round 2 answers all three.

## v1 round-3 findings and dispositions (in v2, unchanged)

| Finding | Disposition in v2 |
|---|---|
| P1 MINOR, drain after an urgent close | Drain accepted in every state, settled after every event from `fence()`, answer PENDING / OPEN / HELD on the settling event; ARM NOT_ACTIVE outside DRAINING (T87-T94; probes PA, PA3, Q3 are T87, T90, T91) |
| P2 MINOR, GET-observed DELETE across runs | DELETE UID only from this execution's own CREATE 201 (UID_NOT_CREATED); identity uniqueness across runs (K02, probe PD); MANIFEST_REUSED across generations from durable BIND records (T95, probe PE); T47 and T96 |
| P3 MINOR, deniedActionIds after storage failure | Reports every action armed before and denied during the operation (T58 restored, T97-T99; probes PB, PB2, PB3) |
| P4 NOTE, restart after two write failures | Failure marker on a separate failure domain, torn-record detection, RESTARTED record; residual disclosed and pinned (T100-T104; probe PC) |
| P5 NOTE, 408 in the 4xx rows | `excludeStatus` [408] on the CREATE and DELETE 4xx rows (A40-A42); 202 row unreachable, stated |
| P6 NOTE, unpinned sources and finalizers | Tag, commit and file digests pinned, distribution re-check obligation, `deleteNotImmediate` as a known HELD cause (A39; probe PH) |
| P7 NOTE, RecursionError and wrong type | Depth first with iterative helpers, F07 for a non-bytes input, RecursionError mapped to F01 (B11-B14, G33) |
| P8 NOTE, T74 and T81 intents | Narrowed; T105 and T106 add the missing cases |

The v1 round-1 and round-2 dispositions stay in `../i05-gate-channel/README.md`.

## Spec mapping

| Spec | Encoded by |
|---|---|
| Base §3 I05 rules (custody, bounds, no selectors) | Channel 1-5, schema, `decode_frame` |
| Base §4 step 4 (gate derives route and body) | Decision 4 |
| Base §5 (partial write, readback mismatch, full disk or lost history starts denied and HELD) | Durable journal and failure marker; residual stated |
| §2.4 WRITE_BEGIN (replies only after the A3 drain fence) | Decision 8, `fence()`, the drain answer, Decision 12 (bounded wait) |
| §7 BIND_EXECUTION, ARM_ACTION, ACTION_OUTCOME, CLOSE_GENERATION, GENERATION_STATUS additions | Operations, Decisions 1-9, durable journal |
| §3.2 A1, A3, A4 | Decisions 6, 8 and 9 |
| §6 C1-C7 | Decisions 3-7, T02-T10, T64 |
| I02 cleanup ownership (server-recorded created UIDs; a digest belongs to one case) | Decision 10 |

## Still open

- All E01-E12 and T01-T08; C2/C3 behaviour under load and restart is native T02/T03 work.
- How the gate's substrate enforces the 900-second upstream bound (W03).
- The exact I04 request head as a requirement on the I04 client (R01, CONF-LIVE-003), and the external reconciliation path
  for resources of earlier runs.
- The re-check of the mapping rows and DELETE bodies against the selected Kubernetes distribution (W02/W03).
- The gate's HTTP/TLS substrate and how it implements stamping and exact rendering (the Envoy candidate stays unselected).
- The storage formats of the journal and of the failure marker store.
