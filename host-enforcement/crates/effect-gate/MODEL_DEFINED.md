# HE-002, HE-002B and HE-002C: model-defined and R10-defined behaviour

HE-002 implements the I05 v3 contract (harness-onion `a2eab93`, copied under `host-enforcement/contracts/`) from its
READMEs, schemas, tables and vectors (owner decision B (a)). Where the READMEs are silent, the pinned reference model
`scripts/i05_gate_channel_v3.py` (sha256 `2c7985b539c0ce8eb79eaabfa1f1ab7d43bdca7515defc590a76ecb1697ca959`) and the
validator `scripts/validate_admission_channel_v3.py` (sha256
`7bd762d3069ad6add891063c5b5cd16c75534adb88b1afa245f050b5856dc247`) were read as specification and never copied: the
two crates `i05-protocol` and `effect-gate` share no code or comment text with them (checked with an 8-word span search,
HE-002 PR review round 1, R1-1; the one shared span R10 had, a two-line hashing helper in `tools/gate.py` that HE-001
merged, was outside these crates, as `contracts/PROVENANCE.md` states, and HE-002C's rename of its parameter removed
it). Each such point is listed below with its file and lines at `a2eab93` ("model" and "validator" below), followed by
the behaviour R10 defines itself. The vectors decide every disagreement; all I05 v3 vectors pass.

HE-002B adds the I07 v3 PolicyGate (`effect-gate`: `policy`, `policy_gate`) the same way, from the I07 v1-v3 READMEs,
the I07 v3 schema, `policy-kinds.json` and vectors, with the pinned I07 v3 model `scripts/i07_policy_write_v3.py` (sha256
`6cc7ea0d3df0c7f2966184bb6d322189de3b49b5b02dfe2429911121973afe08`, "I07 model" below) read as specification where the
READMEs are silent and never copied; its points are N1-N19 and its R10-defined behaviour R13-R18 below. All I07 v3
vectors pass (79 kind, 7 render, 22 outcome checks and 62 transcripts on both frame paths).

HE-002C adds the durable stores (`effect-gate`: `frame`, `store`, `file_store`; the new crate `gate-sys`). The pinned
models keep their journal and marker in memory and define no byte format, so nothing in HE-002C is model-defined: its
rules are the R10-defined R19-R30 and the disclosures in the HE-002C section at the end, each with the owner decision
that settled it (HE-002C design revision 4, §18).

Correspondence (HE-002 PR review round 1, R1-2): `i05-protocol` has no counterpart in the model, which relies on CPython's
`json`, `jsonschema`, `base64` and `hashlib`. `effect-gate`'s `Gate` does follow the model's `Gate` class in its
decomposition into operations (BIND, ARM, ACTION_OUTCOME, CLOSE, GENERATION_STATUS, A1, the upstream, expiry, drain and
restart handlers, and the helpers for recording, denying and urgent closes) and in the order of the checks inside each
operation, because M17-M31 make refusal order, journal tuples and the restart rebuild normative and the vectors pin
them. The Rust types and data structures (typed events, requests, outcomes and journal records, the split of A1 into
admission and consumption) and the R10-defined paths (R1-R12) are R10's own. Owner decision Q-HE2-R1 (a), 2026-10-13
(via the lane monitor), verbatim: "Disclose and accept": MODEL_DEFINED.md and the packet text state that
effect-gate's Gate follows the pinned model's operation decomposition and per-operation order (normative under
M17-M31); the Rust stays independently written with no shared comment or code text once R1-1 is fixed.

The same holds for the PolicyGate (HE-002B). It follows the I07 model's decomposition into the four operations, the
writer, upstream and restart handlers, the maintenance settle, the abort and the session end, and the order of the checks
inside each, because the I07 v3 vectors make the `check_write` order, the WRITE_BEGIN and WRITE_OBJECT refusal orders,
the abort-before-end rule and the settle after every event normative. It differs from the model in three ways. It
**composes** rather than inherits: `PolicyGate` owns a `Gate` and reaches the journal, fence, drain, deny, urgent-close
and state steps through crate-private methods, so the I05 public API and `Config` are unchanged (the additive public
changes are the `Invalidation::WriterPeerDeviation` variant and the I07 `Record` variants). It replaces the model's
overridden rebuild with a **restart floor**: the I07 rebuild is a function of the journal alone (N10), and the base
restart takes `restart_with(Some(HELD))` when it finds an ambiguous write, while the public GATE_RESTART passes `None`.
And it has **its own output type**, `PolicyOutput`, so the I05 `Output` stays as it is (the I07 TIMEOUT answer has no
`aborted` member, unlike I05's). Owner decision Q-HE2B-1 (a), 2026-10-13 (via the lane monitor), verbatim:
"Disclosure covers it": PolicyGate follows the pinned I07 v3 model's operation decomposition and per-operation order, is
written independently in Rust with no shared comment or code text (the span check runs before the PR), and
MODEL_DEFINED.md gets an I07 section with every model-defined point and its model line.

## Wire codec and canonical form (`i05-protocol`: `json`, `frame`, `base64`)

| # | Behaviour | Source |
|---|---|---|
| M1 | The canonical encoding is Python `json.dumps(sort_keys=True, ensure_ascii=False, separators=(",", ":"), allow_nan=False)` then UTF-8: keys in code-point order (not RFC 8785's UTF-16 order), `\" \\ \b \f \n \r \t` and other C0 characters as lowercase `\u00xx`, DEL and non-ASCII raw, integers in decimal, floats as Python `repr` (shortest round-trip digits, an exact tie between two shortest candidates to the even digit, fixed notation for exponents -4 to 15 with at least one fractional digit, otherwise `d[.ddd]e±XX`); a lone surrogate or a non-finite float has no encoding | model :58-59 |
| M2 | Digests are `"sha256:" + lowercase hex`; the all-zero previous digest is `"sha256:"` followed by 64 zeros | model :50, :62-67 |
| M3 | `decode_frame` order: not a byte string F07; more than 16384 bytes F02; UTF-8 over the whole datagram, then parse, then encode, any failure F06 except a refused constant (`NaN`, `Infinity`, `-Infinity`, F03 at its token) and a duplicate key (F05, found when its object closes), the first error in document order winning; then byte equality with the canonical encoding (F06); then `check_frame` | model :119-128, :174-194 |
| M4 | The parser accepts what CPython 3.12 `json.loads` accepts: whitespace (space, tab, LF, CR) around tokens, `-0` as the integer 0, at most 4300 integer digits (more is a decode error, F06), floats correctly rounded (`1e400` is infinite), raw control characters refused inside strings, escaped surrogate pairs joined and lone surrogates kept, a byte-order mark refused | model :180 (`json.loads`), :184-189 |
| M5 | `check_frame` order and codes: depth above 16 (a scalar is 0, an empty container 1) F01; any float F03; any string or member name with a character below U+0020 or DEL F04; the closed schema F00; canonical length above 16384 F02 | model :131-171 |
| M6 | A RecursionError from the decoder maps to F01; with CPython 3.12 no frame within 16 KiB reaches it, so R10's iterative parser has no such path (R6) | model :182-183, I05 v2 README P7 |
| M7 | The I05 frame checks compare the exact refusal text (`"F00 frame outside the closed schema"`, ...); the I07 frame and byte checks compare only the code (`F00` to `F07`) | validator :459-464, :571-576 |
| M8 | Byte-check inputs: base64 decoded strictly and required canonical (re-encoding gives the same text); `inputType` `bytes` stays bytes, `bytearray` and `str` (ASCII-decoded) are not byte strings, mapped to `Datagram::NotBytes` | validator :164-171, :417, :463 |
| M9 | Agreement mode (`objectBase64`): Python `base64.b64decode(data, validate=True)` (ASCII text only, standard alphabet, padding required, at most two `=` and only at the end, nothing after the padding, non-zero trailing bits accepted), then UTF-8, then the same parser (whitespace and floats allowed, duplicates and constants refused, the digit limit applies, lone surrogates accepted), an object at the top, depth at most 16; any failure means no object | model :209-219 |

## Schema subset (`i05-protocol`: `schema`, `regex`)

| # | Behaviour | Source |
|---|---|---|
| M10 | The schema is applied with Python `jsonschema` Draft 2020-12 semantics: each keyword only for its own instance type; booleans are neither integers nor numbers; `const`, `enum` and `uniqueItems` use `jsonschema`'s equality (`true` is not `1`, `1` equals `1.0`); `minimum`/`maximum` compare exactly; lengths count code points; `pattern` is a search (`re.search`) | model :170 (`jsonschema.Draft202012Validator`) |

## Outcome mapping (`i05-protocol`: `mapping`)

| # | Behaviour | Source |
|---|---|---|
| M11 | Row selection: rows of the verb or `*` with the outcome's classification; an exact `httpStatus` row first, otherwise status-class rows (`4xx`, `5xx`) minus `excludeStatus`; a null status only matches a null row; exactly one row or M02 | model :199-206, :230-235 |
| M12 | `check_agreement` order and wording M00 to M07, with Python `==` on the decoded values (a missing member reads as `None`, `True == 1`, `404.0 == 404`); the STATUS rule for DELETE bodies (`kind` `Status`, `status` `Success`, `details.name` and `details.kind` the resource plural, `details.uid` the observed UID, no observed resourceVersion) | model :222-264 |
| M13 | The plural table: Pod `pods`, ConfigMap `configmaps`, Service `services` | model :46 |

## Request rendering (`i05-protocol`: `render`)

| # | Behaviour | Source |
|---|---|---|
| M14 | The action template `planeon.internal.effect-gate-template/v1`: the canonical object `{schemaVersion, verb, apiVersion, kind, namespace, name, uid, manifestDigest}` (uid null except for DELETE), digested; ARM_ACTION's `requestTemplateDigest` must equal it, computed with the request's manifest digest | model :35, :75-79, :799-802 |
| M15 | `render_request` yields the head bytes and a body digest: CREATE posts with the manifest's signed digest and size as body digest and Content-Length; DELETE's body is the canonical DeleteOptions (`uid` null when absent) and its digest; GET has no body. A1 compares the request's head and body digest with this pair | model :82-103, :616-618 |
| M16 | `identity_of` is `kind/namespace/name` | model :70-72 |

## Gate (`effect-gate`: `gate`, `journal`, `config`)

| # | Behaviour | Source |
|---|---|---|
| M17 | Configuration refusals, in order and wording: a run manifest outside the signed profile; a manifest digest in more than one run; a manifest identity resolving to more than one manifest (within one run too); then `priorBindings` must be an object with exactly `executionIds`, `runNonces`, `manifestDigests`, `manifestIdentities`, each a list ("an incomplete priorBindings record"). The refusal vectors are applied as `dict(ACTIVE, **override)` | model :280-293; validator :466-469 |
| M18 | The journal tuples: `["BIND", executionId, runNonce, reservationDigest, sortedDigests, sortedIdentities]`, `["ARM", actionId, verb, manifestDigest, recordedUid, templateDigest]`, `["CONSUMED", id]`, `["TERMINAL", id, classification, afterInvalidation, details]` (details `{httpStatus, resultDigest, observedUid, observedResourceVersion}` delivered, `{httpStatus, resultDigest}` for an unknown mutation outcome, `{}` for a lost exchange or a failed TERMINAL write, `{aborted: "UPSTREAM_TIMEOUT"}`), `["SEALED", id, classification, afterInvalidation]` (the unmasked qualifier), `["DENIED", id]`, `["INVALIDATED", reason, state]`, `["CLOSED", reason, state]`, `["DRAINED", state]`, `["DRAIN_STARTED"]`, `["CHANNEL_ENDED", "ORDERLY" or "BEFORE_FIRST_FRAME"]`, `["EXPIRED", executionId]`, `["LATE_UPSTREAM", id]`, `["RESTARTED", state]`, and `["TORN"]` for a torn write; the marker record is `[generation, "STORAGE_FAILURE"]`; `journalDigest` is the digest of the canonical journal list | model :313-314, :330-345, :649, :671, :747, :772, :814 |
| M19 | Test injections: `STORAGE_FAIL_NEXT` queues one failure (torn only when `torn` is exactly true); `STORAGE_FAIL_AFTER {after: k}` counts down on every record attempt (failed ones and those inside the storage-failure path included) and, at zero, joins its failure to the back of the queue behind pending NEXT failures (R10-L02, R10-L02b; supplement S05, S06); a second AFTER replaces the first (R10-L01; supplement S01-S04); `MARKER_FAIL_NEXT` fails the next marker write, and a present marker is never rewritten | model :317-346, :514-524 |
| M20 | The storage-failure path: re-entry suppressed; the generation HELD; an in-flight action marked admitted before invalidation; the marker written (its result ignored); `["INVALIDATED", "STORAGE_FAILURE", "HELD"]` attempted; armed actions denied | model :348-359 |
| M21 | Deny order for each armed action: close its stamped, unconsumed connections (counted as flush closures), set it TERMINAL NOT_FORWARDED, then record DENIED; `deniedActionIds` and `denied` report the actions armed when the operation began that are TERMINAL when it ends | model :416-444 |
| M22 | Urgent close: the state becomes the target unless already HELD; an in-flight action is marked; INVALIDATED records the resulting state; armed actions are denied. A fatal channel failure closes the channel, closes urgently toward HELD and leaves HELD; its output is `{"fatal": reason}` with reasons `Fxx_INVALID_FRAME`, `DIRECTION`, `CHAIN_BROKEN`, `GENERATION_MISMATCH`, `OPENING_FRAME_REQUIRED`, `CHALLENGE_MISMATCH`, `PEER_QUALIFICATION_MISMATCH`, `PEER_LOST`, `PEER_CHANGED` | model :446-461, :540, :545, :714-726, :751 |
| M23 | Frame handling order: a closed channel answers `{"refusedChannel": "GENERATION_CHANNEL_USED"}` before any check; then `check_frame`; direction and odd sequence (DIRECTION); sequence and previous digest (CHAIN_BROKEN); generation; the opening frame (GENERATION_STATUS) records the challenge, later frames must carry it. The response envelope is `GATE_TO_BROKER` with sequence + 1 and the received frame's digest; the next broker frame must carry sequence + 2 and the response's digest | model :708-736 |
| M24 | Operation refusal order: BIND (peer digest fatal, NOT_ACTIVE, ACTION_OUTSTANDING, EXECUTION_REPLAY over this generation's and prior bindings, GENERATION_MISMATCH, UNKNOWN_BINDING, CERTIFICATE_MISMATCH, MANIFEST_REUSED, WORKER_NOT_OBSERVED, STORAGE_FAILURE); ARM (DRAIN_PENDING only while DRAINING else NOT_ACTIVE, EXECUTION_NOT_BOUND, EXECUTION_EXPIRED, ACTION_OUTSTANDING, ACTION_ID_OUT_OF_ORDER against the number of actions plus one, MANIFEST_OUTSIDE_CASE, UID_RULE, UID_NOT_CREATED, TEMPLATE_MISMATCH, MUTATION_KEY_REUSED, then the C2 flush, then STORAGE_FAILURE); ACTION_OUTCOME (EXECUTION_NOT_BOUND, UNKNOWN_ACTION, the seal, STORAGE_FAILURE); CLOSE (in CLOSED, INVALIDATED or HELD: RECONCILIATION_REQUIRED alone moves to HELD with an INVALIDATED record, then denies; NORMAL_DRAIN refused ACTION_IN_FLIGHT, otherwise CLOSED or HELD with a CLOSED record; other reasons urgent) | model :749-870 |
| M25 | The C2 flush counts every open unconsumed connection and every listen-backlog entry (each becomes a closed, unstamped connection) as flushed connections and flush closures; the caseManifestSetDigest is the digest of the canonical sorted digest list | model :766-778, :807-813 |
| M26 | A1 order: CONNECTION_CLOSED, PROTOCOL_VIOLATION (a second request), NOT_ACTIVE (not ACTIVE, a pending drain, no open channel or nothing bound), EXECUTION_EXPIRED, STAMP_NONE, STAMP_MISMATCH, ALREADY_CONSUMED, CERTIFICATE_MISMATCH, REQUEST_MISMATCH, then the CONSUMED record (STORAGE_FAILURE); correlationRefusals counts STAMP_NONE, CERTIFICATE_MISMATCH, REQUEST_MISMATCH, STAMP_MISMATCH and ALREADY_CONSUMED; a consumption closes the action's other stamped connections | model :583-627 |
| M27 | Upstream events: a response for a sealed action is LATE_UPSTREAM, never relayed; otherwise the TERMINAL record decides (a failed write leaves the action IO_AMBIGUOUS with no details and nothing relayed); IO_AMBIGUOUS holds the generation; a delivered CREATE 201 with a UID records a created UID for its manifest; the connection closes; the output is `{classification, relayed}`, plus `aborted` for the 900-second bound | model :629-675 |
| M28 | The drain: from ACTIVE or INSPECTING it is the gate's own normal drain (DRAINING); DRAIN_STARTED once; armed actions denied; the answer settled at once or PENDING. After every event a pending drain settles: DRAINING with nothing in flight becomes CLOSED or HELD (an ambiguous action), then a decided fence writes DRAINED and the settling event carries `drain` | model :488-495, :677-705 |
| M29 | Expiry: with nothing bound or already expired, `{"denied": []}`; otherwise EXPIRED, the in-flight qualifier and the deny. Channel end: before the first frame `{"channelEnd": "UNUSED"}`; orderly when CLOSED or INVALIDATED with every action sealed and none in flight; otherwise PEER_LOST. A second channel answers CHANNEL_EXISTS or GENERATION_CHANNEL_USED | model :529-545, :559-571 |
| M30 | The replay restart: actions rebuilt from the journal since the last BIND (state from the last INVALIDATED, CLOSED, DRAINED or RESTARTED record; clean only if every action is TERMINAL, sealed and not ambiguous; a consumed action without TERMINAL becomes IO_AMBIGUOUS admitted before the restart, an armed one NOT_FORWARDED); HELD with a marker or a torn record; connections closed without counting; backlog, channel and pending drain dropped; RESTARTED recorded; in-memory execution data (bound execution, expiry, counters, bound identifiers, created UIDs, mutation keys) kept | model :361-404, :546-557 |
| M31 | The snapshot shape: `state`, `drainPending`, `channel` (UNOPENED, OPEN, CLOSED), `boundExecutionId`, `actions` by id (`status`, `classification`, `admittedBeforeInvalidation` unmasked, `sealed`), `connections` by name (OPEN, CLOSED), `counters`, `journal`, `failureMarker`; outputs and snapshots compare exactly | model :476-485; validator :452-453 |
| M32 | Replay frames: the envelope a correct broker sends next (`schemaVersion`, the config's `generation` and `brokerChallenge`, the gate's next sequence and last digest, `BROKER_TO_GATE`, the event's operation and payload), then the event's `mutate` operations (`set`, `delete` at a path). Vector files are parsed duplicate-free without constants, so `201.0` (G07) and `1.0` (T24) stay floats | model :873-904; validator :56-67 |

## I07 PolicyGate (`effect-gate`: `policy`, `policy_gate`, the I07 records in `journal`; HE-002B)

Lines are the I07 model's (`scripts/i07_policy_write_v3.py` at `a2eab93`) unless the validator is named.

| # | Behaviour | Source |
|---|---|---|
| N1 | Classification: a writable row needs an equal group, version and resource; an effect-kind or non-writable row is recognised from group and resource alone, whatever the version; effect kinds are checked before non-writable kinds, and the first matching non-writable row's disposition gives ADMISSION_OBJECT_SEALED (SEALED_STATIC_MANIFEST) or POLICY_KIND_NOT_WRITABLE; anything else is KIND_OUTSIDE_TABLE. The api version is `<version>` for the core group and `<group>/<version>` otherwise | I07 model :50-51, :54-70 |
| N2 | `check_write` order: kind (N1), operation (VERB_NOT_ALLOWED), scope (SCOPE_MISMATCH: the request namespace equals the qualification namespace, or for the Namespace object a null namespace and the name equal to it), CREATE exactly when there is no prior (PRIOR_RULE), DELETE exactly when there is no object (OBJECT_RULE). A CREATE or UPDATE object then needs (all OBJECT_RULE): members only `apiVersion`, `kind`, `metadata` and the row's top-level keys; the row's api version and kind; a metadata object with members among `annotations`, `labels`, `name`, `namespace`, `resourceVersion`, `uid` and the request's name; the qualification namespace as metadata namespace, or no metadata namespace member at all for the Namespace object; labels and annotations, when present, objects of strings only; for CREATE no metadata uid or resourceVersion, for UPDATE exactly the prior's uid and resourceVersion. Comparisons are exact (a member of another type never equals text) | I07 model :40, :73-117 |
| N3 | `render_write`: root `/api/<version>` for the core group, else `/apis/<group>/<version>`; the collection `<root>/namespaces/<namespace>/<resource>`, or `<root>/<resource>` for the Namespace object; CREATE is `POST` of the canonical object to the collection, UPDATE `PUT` of it to `<collection>/<name>`, DELETE `DELETE` of `<collection>/<name>` with the canonical `{"apiVersion":"v1","kind":"DeleteOptions","preconditions":{"resourceVersion":…,"uid":…}}` from the prior; the head is the request line `HTTP/1.1`, then `Host: <authority>`, `Accept: application/json`, `Content-Type: application/json`, `Content-Length: <body bytes>`, each ending CRLF, and an empty line; the body digest is the SHA-256 of the body | I07 model :120-141 |
| N4 | `requestDigest` is the digest of the canonical `{"bodyDigest": …, "head": …}`; a delivered status settles a write when it is the operation's success (CREATE 201, UPDATE 200 or 201, DELETE 200 or 202) or a 4xx other than 408 | I07 model :39, :144-154 |
| N5 | The kind and render checks use the validator's fixed qualification namespace `planeon-qual` and authority `127.0.0.1:6443`; the validator compares head and body digest (R10 compares the vectors' body bytes too); outcome checks compare `final` | validator :553, :556-566 |
| N6 | The maintenance settle after every event: PENDING becomes OPEN only when the fence is OPEN and the MAINT_OPEN record is durable; PENDING or OPEN becomes HELD when the fence is HELD, whatever the MAINT_HELD record's result; a failed MAINT_OPEN holds the generation, so the same settle then holds the maintenance and records MAINT_HELD | I07 model :177-185 |
| N7 | Event handling: a writer event is handled, then a pending I05 drain settles and its answer is attached as `drain`; an I05 event goes through the base gate, which settles its own drain; GATE_RESTART drops the outstanding write first and drops the session and adds `maintenance` to the output after; the maintenance settle (N6) follows every event. An event refused as invalid (R3, R14, R15) changes nothing, the settle included | I07 model :241-256 |
| N8 | The operations. MAINTENANCE_STATUS answers generation, gate state, maintenance, the in-flight I05 action, the write count, the sorted ambiguous write IDs and the digest of the one journal (I05 and I07 records). WRITE_BEGIN: GENERATION_MISMATCH, MAINTENANCE_ENDED; a first one notes the armed I05 actions, records MAINT_REQUESTED (STORAGE_FAILURE when it fails, with no `deniedActionIds`), makes the session the owner, sets PENDING, runs the I05 drain and drops the drain entry's own answer (so no `drain` member comes from it), and reports the noted actions now TERMINAL; every WRITE_BEGIN settles the maintenance (N6) before answering, so a repeat polls. WRITE_OBJECT: MAINTENANCE_HELD (maintenance HELD) or MAINTENANCE_NOT_OPEN (not OPEN), WRITE_ID_OUT_OF_ORDER (not the write count plus one), the table (N2), then WRITE_FORWARDED (STORAGE_FAILURE forwards nothing), the write FORWARDED and outstanding, output `{"forwarded": writeId}`. WRITE_END: MAINTENANCE_NOT_BEGUN, MAINTENANCE_ENDED, then MAINT_ENDED `WRITE_END`; when that record fails it answers STORAGE_FAILURE and the maintenance stays as it was | I07 model :187-188, :378-433 (:391, :395, :398, :428-430) |
| N9 | Sessions: a second W_CONNECT while one is connected is `{"refusedSession": "SESSION_EXISTS"}`; an accepted one starts UNOPENED at sequence 1 and the zero digest; a loss or a peer change without a session outputs `{}`. A session end records WRITER_SESSION_ENDED (`ENDED` or `FATAL`) first; only the owning session then ends a maintenance that is not ENDED, with MAINT_ENDED `SESSION_ENDED` or `SESSION_FATAL`, and the maintenance is ENDED whatever that record's result; the output is `{"sessionEnd": how, "maintenance": state}`. A writer loss or a fatal frame leaves the generation untouched unless a write is outstanding (N11) | I07 model :190-192, :258-275, :285-291 |
| N10 | The restart: the outstanding write is dropped before the base restart. The writes are rebuilt from the whole journal (WRITE_FORWARDED makes a write FORWARDED, WRITE_TERMINAL makes it TERMINAL with its classification, torn entries are skipped, a BIND resets nothing; a write still FORWARDED becomes IO_AMBIGUOUS) and replace the in-memory map; the maintenance is ENDED with the last MAINT_ENDED reason, else GATE_RESTART, when a MAINT_REQUESTED exists, and GENERATION_REBUILT otherwise; an ambiguous write makes the restart HELD (R10: the restart floor); no WRITER_SESSION_ENDED or MAINT_ENDED is written, the write counters (sessions included) survive, and no session survives. The rebuild reads the journal alone, so HE-002C's process restart can reuse it | I07 model :206-229, :249-254 |
| N11 | The abort of the outstanding write: WRITE_TERMINAL IO_AMBIGUOUS `{"aborted": reason}` is attempted first (its result changes nothing), then the write is TERMINAL IO_AMBIGUOUS and the generation HELD by a direct state change, with no INVALIDATED record of its own; reasons WRITER_CHANNEL_LOST (a loss), WRITER_PEER_DEVIATION (a peer change), WRITER_PROTOCOL_FAILURE (a fatal frame) | I07 model :194-204, :274, :278, :294 |
| N12 | A writer peer change with a session: the abort (N11), then the base urgent close toward HELD with WRITER_PEER_DEVIATION (`["INVALIDATED", "WRITER_PEER_DEVIATION", "HELD"]`, armed I05 actions denied), the generation HELD, the session end FATAL (N9), output `fatal: PEER_CHANGED`. Only this path records INVALIDATED for the writer side | I07 model :276-283 |
| N13 | W_FRAME checks in order: LOCKSTEP while a write is outstanding (before any frame check); the frame checks with the I07 v3 schema (`<code>_INVALID_FRAME`); DIRECTION (not `WRITER_TO_GATE`, or an even sequence); CHAIN_BROKEN (not the session's next sequence and last digest); OPENING_FRAME_REQUIRED (an unopened session's first frame must be MAINTENANCE_STATUS, which opens it and fixes its challenge); CHALLENGE_MISMATCH. Every one is fatal: the abort with WRITER_PROTOCOL_FAILURE, then the session end FATAL with `fatal: reason` | I07 model :293-297, :308-325 |
| N14 | The response envelope: the I07 v3 version, the session challenge, the request's sequence + 1, the request frame's digest as `previousDigest` (on the byte path the received datagram's, which is canonical), `GATE_TO_WRITER`, the request's operation and the payload; the next writer frame then carries sequence + 2 and the response's digest. A forwarded WRITE_OBJECT keeps its frame's sequence and digest and is answered by its upstream event | I07 model :299-306, :326-330 |
| N15 | Upstream outcomes: for a write that is not the outstanding one, WRITE_LATE_UPSTREAM if the gate forwarded it (`{"lateUpstream": "NOT_RELAYED"}`, never relayed), an invalid event otherwise (R14). For the outstanding one: LOST is IO_AMBIGUOUS with `{}`; TIMEOUT (the logical expiry of the 10-second bound; the real timer and the apiserver client are HE-003's by owner decision Q-HE2B-2 (a)) is IO_AMBIGUOUS `{"aborted": "UPSTREAM_TIMEOUT"}`; a status that does not settle the write (N4) is IO_AMBIGUOUS `{httpStatus, resultDigest}`; a settling one is DELIVERED_RESULT with `{httpStatus, resultDigest, observedUid, observedResourceVersion}`, the observed members null unless the status is the success (a rejection observes nothing). The WRITE_TERMINAL record comes first; when it fails the write is IO_AMBIGUOUS and the answer carries no details. IO_AMBIGUOUS holds the generation. The answer's `httpStatus`, `resultDigest` and observed members are null unless DELIVERED_RESULT; the output is `{classification, relayed: true, response}`, and with no session `{classification, relayed: false}` (R18) | I07 model :332-373 |
| N16 | Counters: `sessions` counts accepted W_CONNECTs; `writesForwarded` counts durable WRITE_FORWARDED records; `writesRefused` counts the maintenance, write-ID and table refusals of WRITE_OBJECT only (not STORAGE_FAILURE) | I07 model :174, :264, :402-411, :419 |
| N17 | The snapshot adds to the base snapshot (M31) `maintenance`, `maintenanceReason` (null until ENDED), `writerSession` (`UNOPENED`, `OPEN` or null), `pendingWriteId`, `writes` by ID (`status` FORWARDED or TERMINAL, `classification`) and `writeCounters` | I07 model :231-238 |
| N18 | Replay of W_FRAME events: the I07 v3 envelope with the challenge of the latest W_CONNECT event (refused or not), the current session's next sequence and last digest whether it opened or not (else 1 and the zero digest), `WRITER_TO_GATE`, the event's operation and payload, then its `mutate` operations; FRAME events as M32 with the base gate's chain | I07 model :436-459 |
| N19 | The I07 journal tuples, in the one journal: `["MAINT_REQUESTED", generation]`, `["MAINT_OPEN", state]`, `["MAINT_HELD", state]`, `["WRITE_FORWARDED", writeId, operation, apiVersion, kind, namespace or null, name, requestDigest, prior or null]` (the prior as received: `projectionDigest`, `resourceVersion`, `uid`), `["WRITE_TERMINAL", writeId, classification, details]` (details per N15 and N11), `["MAINT_ENDED", reason, writes, ambiguousWriteIds]`, `["WRITER_SESSION_ENDED", how]`, `["WRITE_LATE_UPSTREAM", writeId]`. A failed record takes the base storage-failure path (M20) | I07 model :179, :185, :192, :202, :288, :339, :358, :392, :415-416, :428 |

## R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R1 | A response that would leave the schema (a sequence past 2147483647 after a broker frame at the maximum, a counter past 2147483647, or any other response schema failure) closes the channel fatally with `RESPONSE_OUT_OF_BOUNDS`: HELD, journalled `["INVALIDATED", "RESPONSE_OUT_OF_BOUNDS", "HELD"]`, armed actions denied | DESIGN §10; the model raises there (:733) |
| R2 | Counters saturate at `u64::MAX` instead of overflowing; anything past 2147483647 is already refused by R1. No arithmetic can panic (`panic = "abort"`) | DESIGN §10 |
| R3 | An event outside the model's preconditions (ACCEPT outside the backlog, a request on an unaccepted connection, an upstream event or a timeout without a forwarded exchange, a second channel before the first) returns `EventError` and changes nothing; the model raises before any change (:542, :574, :585, :631, :669) | no panics on any input |
| R4 | A rebuild that meets a record for an action no ARM record introduced restarts HELD (the model would raise KeyError; unreachable from the gate's own journal) | fail closed for HE-002C's durable journal |
| R5 | Lookups of data validated earlier (the bound run, an armed action's manifest) fail closed with a refusal if they ever failed (unreachable) | no panics |
| R6 | The JSON parser, encoder, depth and equality walks and `Value`'s drop never recurse, so nesting costs heap only; the RecursionError clause (M6) has no counterpart | no stack overflow on any input |
| R7 | Production frames enter as bytes: a decode failure closes the channel fatally with `<code>_INVALID_FRAME`, the code from `decode_frame` (F02, F05, F06, F07 become reachable there); `Output` also carries the response frame's canonical bytes. The replay suite runs every transcript through both entries (DESIGN §13 E12) | the model's `_frame` takes values only |
| R8 | A schema-valid value without a canonical encoding is refused F06 in `check_frame` (unreachable: schema-valid strings are ASCII and floats are refused first) | the model would report a UnicodeEncodeError message |
| R9 | `check_agreement` with a non-numeric `httpStatus` where only status-class rows remain finds no row (M02); the model raises TypeError | no panics |
| R10 | Typed inputs: the agreement identity's kind and every configured manifest kind must be Pod, ConfigMap or Service; the mapping must name every kind's DELETE body; configuration fields of the wrong type, unknown fields (other than `brokerChallenge`, which the gate ignores), observed workers that are not integer pairs and prior-binding entries that are not text are refused before the model's checks | fail closed at load |
| R11 | The schema subset refuses any other keyword, a nested `$schema`, `$id` or `$defs`, a non-local `$ref` and any pattern outside the twelve-pattern subset at load; validation gives up after 512 nested evaluations and refuses the instance (never inverted by `not`); `$` is ECMA-262's (end of input only), a difference unreachable behind F04 | DESIGN §6 |
| R12 | Upstream responses are typed: an integer status, a body digest, an optional UID and resourceVersion | the substrate (HE-003) supplies them |
| R13 | Response bound (PolicyGate): a writer frame whose sequence + 1 would pass the I07 v3 schema's maximum (2147483647) ends the session fatally with `RESPONSE_OUT_OF_BOUNDS` after the chain and challenge checks and before its operation runs, so only WRITER_SESSION_ENDED (and the owning session's MAINT_ENDED) is recorded and a WRITE_OBJECT is never forwarded without a response that can be framed. Any other response outside the schema (unreachable: the v3 W1 constraints describe answers the gate never gives, and R15 keeps the upstream answer inside the patterns) ends the session the same way after the operation, and a deferred WRITE_OBJECT answer is then not relayed | HE-002B DESIGN §13; the I07 model forwards, records the outcome and then raises (:304) |
| R14 | Invalid events (PolicyGate): a W_FRAME without a session and a W_UPSTREAM naming a write the gate never forwarded return `EventError` with no state change; W_CONNECT, W_CHANNEL_LOST and W_PEER_CHANGED are always valid | the I07 model raises there (:269, :338) |
| R15 | Typed upstream outcomes (PolicyGate): `Lost`, `Timeout`, or a `Response` with an integer status 100-599, a body digest matching `^sha256:[0-9a-f]{64}$`, a uid null or matching `^[A-Za-z0-9-]{1,128}$` and a resourceVersion null or matching `^[A-Za-z0-9]{1,64}$` (the I07 v3 WRITE_OBJECT answer's patterns). Anything else is `EventError` before any state change: the write stays outstanding and nothing is recorded. Carried to HE-003: the substrate reports an apiserver response outside these patterns as LOST (IO_AMBIGUOUS), never as a Response | HE-002B DESIGN §13 (review C1); a relayed answer always stays inside the schema |
| R16 | Configuration (PolicyGate): `policyWriter` is required and parsed by PolicyGate itself: exactly `qualificationNamespace` (a DNS-1123 label of at most 63 characters) and `apiserverAuthority` (printable ASCII without space, CR or LF, 1 to 255 characters); a missing, unknown, mistyped or out-of-rule member refuses the configuration, and the rest goes to the unchanged I05 `Config`, which still refuses `policyWriter` itself. The policy-kind table is read into closed types: version `planeon.internal.i07-policy-kinds/v2`, writable rows with scope QUALIFICATION_NAMESPACE or QUALIFICATION_NAMESPACE_OBJECT (the retired CLUSTER scope is refused), operations among CREATE, UPDATE, DELETE, the three known dispositions; members the gate does not use are ignored | HE-002B DESIGN §13, B4; the I07 model reads both with dictionary lookups |
| R17 | Counters (PolicyGate) saturate at `u64::MAX` instead of overflowing; the writes map is bounded by the schema's write ID (1-256), so it never holds more than 256 writes | no panics |
| R18 | The upstream answer with no session (I07 model :370-371) is unreachable, because every session end aborts the outstanding write first (N9, N11) and GATE_RESTART drops it; it is kept as no-panic code (`{classification, relayed: false}`) and unit-tested on a constructed state. The other unreachable fallbacks fail closed the same way: a WRITE_OBJECT payload the schema passed but the gate cannot type is a fatal F00 frame, and a checked write that does not render is refused OBJECT_RULE | no panics (as R4, R5) |

## HE-002C: durable stores (`frame`, `store`, `file_store`, crate `gate-sys`)

The gate's one journal (I05 and I07 records) and its failure marker are files: `<generation>.journal` in the journal
directory, `<generation>.marker` in a marker directory on another device, and the generation index `generations` beside
the journals. Each record, marker and index entry is one frame, `FF 00 "HEJ1"`, the payload length in 8 lowercase hex
digits, the payload's SHA-256, the SHA-256 of the 80 header bytes before it, LF, the canonical tuple (the bytes
`journalDigest` covers), a status byte (`P`, `C` or `R`) and LF. Files are opened only by `openat` in
`gate-sys/src/openat.rs`, the one module of the workspace that holds `unsafe` code (the gate's lexical tripwire below);
the other system calls are std on the returned `File` (`pwrite64`, `pread64`, `fstat`, `fsync`, `flock`, `close`).
`Gate::new` and `PolicyGate::new` keep HE-002's in-memory stores and their behaviour; the injection queue moved
unchanged into `store::FaultPlan`. The in-process view of a file journal is its mirror, which every append changes
exactly as the in-memory journal does (a durable record added, a torn failure one TORN, a clean failure nothing), so
`journalDigest`, the snapshot and every replay restart are the in-memory gate's; the file is scanned only when the
stores open. The test suites run every I05 and I07 transcript through files with a fresh scan compared after every
event, and every transcript with a GATE_RESTART, as it is and extended by EXPIRE and by DRAIN_REQUEST, as a process
restart.

The source check in `tools/gate.py` is a lexical tripwire over the workspace's `.rs` files (`target/` excluded): it
matches text and does not parse Rust (HE-002C PR review rounds 1 and 2, R1-1 and R2-1). It refuses a list of std
modules and items; it is not an allowlist of std modules, so other std paths (`std::thread`, `std::sync`, `std::time`,
and so on) pass and are code review's. In the non-test sources of the crates
EFFECT_GATE will link (`effect-gate`, `gate-sys`, `i05-protocol`), read with the whitespace around every `::` removed,
it refuses `std::process`, `std::env`, `std::net` and `std::path`; the names `Path`, `PathBuf`, `DirBuilder`,
`OpenOptions`, `File::open`, `File::create`, `File::options`, `TryLockError` and `Metadata`; a `std::os::fd` item outside
`openat.rs`; any std `fs` item but `std::fs::File` and, where allowed, `std::os::unix::fs::FileExt` and `MetadataExt`;
any other `std::os` path (for example `std::os::unix::net`); a `use` of std that renames, and `std as` anywhere; a
top-level grouped or glob std import (`std::{`, `std::*`) and a nested std glob (`std::io::prelude::*`); a std path a
macro completes (`std::$`); and `extern crate`. In every workspace source, tests and binaries included, it refuses the
word `unsafe` outside `gate-sys/src/openat.rs`, a `path` attribute (also under `cfg_attr`), the word `include` (the
macro `include!` under any spelling; `include_str!` and `include_bytes!` are other words), a raw identifier (`r#process`)
and inline assembly (`asm!`, `global_asm!`, `naked_asm!`). It refuses any file under a crate's `src/` that is not a `.rs`
file, any symlink under `crates/`, and a crate manifest whose `[package]` names a `build` script or whose `lib`, `bin`,
`test`, `bench` or `example` target names a `path`. It also requires `#![forbid(unsafe_code)]` on the `effect-gate` and `i05-protocol` roots and
`#![deny(unsafe_code)]` on `gate-sys`'s (whose `openat` module allows it); for the first two crates the compiler, through
that attribute, enforces the rule against unsafe code, and the tripwire only checks the attribute is there. Anything
beyond the tripwire's forms, for example a comment between a path's tokens or inside an attribute, a `]` inside a
string in `cfg_attr`, or a macro that assembles a std path or an attribute from its arguments, is code review's.

| # | Behaviour | Why |
|---|---|---|
| R19 | A generation on file stores matches `^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$` and is not `generations`; any other name refuses `FileStores::open` before anything is created | store file names derive from it |
| R20 | A payload holds at most 1 MiB and a store file at most 64 MiB: a larger payload, or an append that would pass 64 MiB, fails clean (no bytes); a scan reads in 64 KiB chunks, holds at most one frame, and stops at 64 MiB with one TORN for the rest | bounded memory and work on any file |
| R21 | A committed frame whose digests match but whose payload is not UTF-8 JSON in canonical form, or not exactly one of the record tuples (checked by re-encoding the decoded record), is TORN; an index or marker frame is held to its own tuple the same way | only the gate's own bytes are records |
| R22 | Marker bytes other than one committed `["MARKER", generation, "STORAGE_FAILURE"]` of this generation count as a present marker, shown as `[[generation, "UNREADABLE"]]`; a failed marker write that left bytes is such a marker (stricter than the model, whose failed write leaves none; `MARKER_FAIL_NEXT` is clean, so no vector reaches it) | fail closed; owner decision Q-HE2C-4 (a), below |
| R23 | Every TORN or undecodable index entry is ignored; a committed earlier generation whose journal is missing refuses the open. An index or earlier journal that cannot be read whole (a read error, or past R20's bound) refuses the open too | an entry is appended only after its journal exists (R26); owner decision Q-HE2C-4 (a), below |
| R24 | The open refuses when the journal and marker directories report the same device (`fstat`'s `st_dev`; tests pass their own probe, E15). Necessary, not sufficient: the failure-domain proof is HE-008's and T04's | the marker's separate failure domain (I05 v2 P4) |
| R25 | The journal is `flock`ed (non-blocking) for the stores' life; a journal another holder has locked refuses the open | one writer per generation |
| R26 | Durability order: the index is created if new and the journal directory synced before the index's first append; a new journal is created and the journal directory synced before the generation's index entry, which comes before the first record; the marker file is created at the first marker write, then the marker directory is synced, then the frame is written. The syncs do not depend on which opening created a file (HE-002C PR review round 1, R1-3): every opening syncs the journal directory once the index is open, and once more when it created the journal or will append the generation's index entry (so a journal an earlier, failed opening created is synced before its entry), and the first marker write syncs the marker directory also when the marker file was already there. Per opening: one journal-directory sync for an indexed generation; two, plus the index append's two file syncs, for a new or unindexed one, and two for a committed generation whose own journal is missing and is recreated empty (design §7; unlike R23's missing earlier journal, which refuses); the first marker write adds one marker-directory sync and its frame's two. `FileStores::directory_syncs()` is a read-only count of these syncs, public for the tests that assert them | a crash never leaves an index entry without its journal, or a marker frame in an unsynced entry |
| R27 | Every I/O error and scan outcome is a value: a failed append is `Appended::Failed { torn }`, an unreadable rest of a journal is one TORN (the restart is then HELD), and no store code unwraps, indexes or does unchecked arithmetic on file-derived data | no panics (`panic = "abort"`) |
| R28 | A generation that is a committed index entry but not the last committed one cannot be opened | an older generation never runs beside a newer one |
| R29 | Two phases per append: the frame with status `P`, synced and read back; then the status byte `C`, synced and read back. A failure that left the file's length unchanged is clean; any other failure (or an unreadable length) is torn, and a frame whose `C` byte was written is rewritten to `R`, synced and read back. The mirror holds TORN either way | owner decision Q-HE2C-1 (a), below |
| R30 | The open refuses while an earlier generation's journal is locked by a live holder, so generations never overlap, also within one process (HE-003 drops a generation's stores before it opens the next) | that generation could still write BINDs this open cannot see |

Opening (`FileStores::open`) runs every check before anything is appended and appends the generation's index entry
last, all under a blocking `flock` on the index: R19 and R24, the index (R23), R28, every earlier generation's journal
(R23, R30, its committed BIND records), the marker, the journal (created if new, R25, scanned into the mirror), then the
index entry; a failed index append fails the open. `Gate::create` and `PolicyGate::create` accept only stores whose
opening created the journal file and appended the index entry, with an empty journal and no marker file, and stores of
the configured generation (`GateError::NotFresh`, `GateError::GenerationMismatch`); everything else is reopened with
`open`, the process restart. A generation whose open failed after its journal was created is therefore restart-only
(HELD); the broker uses a new generation.

The process restart (`Gate::open`, `PolicyGate::open`) builds the gate from the files without a restart, then restarts
once: the bound execution is this journal's last BIND, its expiry an EXPIRED record for it after that BIND, the bound
execution IDs and run nonces this journal's BIND records, and the prior bindings the configuration's united with the
earlier generations' (Q-HE2C-2 (a)); PolicyGate then takes GATE_RESTART's I07 path (writes and maintenance rebuilt from
the journal, a HELD floor for an ambiguous write, RESTARTED appended once, no session), and the I05 gate alone takes the
same floor. Not kept, and unobservable after a restart because the generation's one channel never reopens and the
data-plane connections die with the process: the I05 counters, the connection table, the challenge and chain position,
the mutation keys and created UIDs, and the I07 write counters (zero after a process restart).

Notes from HE-002C PR review round 1. R1-5, carried to HE-008/T04 (which own the store directory and the failure-domain
proof): `Dir::file` opens without `O_NOCTTY` and checks for a regular file only after the open succeeds, so a device
node or FIFO planted at a store name (which needs write access to the store directory, and `mknod` for a device) is
opened before it is refused. R1-7 (1): `GateError` is not `#[non_exhaustive]`; its new variants `NotFresh` and
`GenerationMismatch` are additive (`Gate::new` never returns them) and no match in the workspace is exhaustive over it,
but an exhaustive match outside the workspace would need the two arms.

Owner decisions (2026-10-13, relayed by the lane monitor; quoted from HE-002C design revision 4, §18):

- **Q-HE2C-1 (a), the append protocol and its disclosed residual.** "two-phase append plus revocation (frame pending,
  sync and read-back; commit status byte, sync and read-back; revoke on failure). The residual window extends the
  disclosed I05 v2 P4 / v3 V3 residual by one case." The case: a record whose `C` byte was written but whose commit
  sync or read-back failed, after the frame's own sync and read-back had succeeded, is answered as a storage failure
  (HELD), and its revocation fails too. Without a reboot the scan then reads the page cache's `C`; after a reboot the
  medium may hold `C` without the `R`. Either way a process restart can read as durable a record the gate reported as
  failed, so a CLOSED record answered HELD can come back CLOSED. The read-back checks the kernel's view, not the medium.
  A torn status rewrite can also corrupt earlier short frames sharing its sector; they read as TORN (fail closed). The
  append-point tests assert this window as such (mirror TORN, scan a record).
- **Q-HE2C-2 (a), earlier bindings.** "the union of the configuration's priorBindings and the journal-derived earlier
  bindings." A BIND torn at write time was never granted and contributes nothing; a granted BIND corrupted later loses
  its derived bindings, which the configured priorBindings still cover.
- **Q-HE2C-3 (a), the E14 divergence.** "accept and disclose. Keep the model's order (expired set before the EXPIRED
  write) and amend HE-002 design §7's identical-journal claim for this case." `Gate::expire` sets `expired` before it
  attempts the EXPIRED record and keeps it when the write fails (R10-L02, R10-L02b); the process restart sees only
  durable records, so after such a failure a later EXPIRE journals `["EXPIRED", id]` again where the replay restart
  answers without a record. Outputs (`{"denied": []}`) and the generation's state are equal; the journal and its digest
  differ by that one record. The process-restart tests assert exactly this for R10-L02 and R10-L02b extended by EXPIRE,
  and journal equality for every other case.
- **Q-HE2C-4 (a), two points stricter than the design** (2026-10-13, relayed by the lane monitor). "Accept both, fail
  closed": R22 (a committed marker counts only with reason STORAGE_FAILURE, otherwise UNREADABLE) and R23 (an index or
  earlier-generation journal that can't be read whole refuses FileStores::open) stand as built and disclosed. Design
  revision 4 asked only for one committed marker of this generation (R22), and its R27 would have read the unread rest of
  an index or earlier journal as one ignored TORN entry (R23), which could hide a committed earlier BIND.
