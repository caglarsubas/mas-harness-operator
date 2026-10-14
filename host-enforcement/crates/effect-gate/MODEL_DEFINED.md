# HE-002, HE-002B, HE-002C, HE-002S and HE-003A: model-defined and R10-defined behaviour

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
rules are the R10-defined R19-R30 and the disclosures in the HE-002C section, each with the owner decision
that settled it (HE-002C design revision 4, §18).

HE-002S adds the EFFECT_GATE process seal (`effect-gate`: `seal`; `gate-sys`: `seal.rs` and `Dir::file_ro`). No pinned
model defines a seal, so nothing in it is model-defined: its sequence, accepted start states and checks are R10's, from
HE-002S design revision 4 with §18 and the owner decisions quoted in the HE-002S section at the end, which also records
the Rust 1.99.0 and musl 1.2.5 re-check (owner decision Q-HE2S-3 (a)).

HE-003A adds the effect gate's channel substrate (`effect-gate`: `substrate`, `peers`, `linux_os`; `gate-sys`:
`channel.rs`, `peer_wire.rs`, `Dir::sub`) and two R10-defined events (`Event::AnswerLate`, `PolicyEvent::WAnswerLate`).
No pinned model defines sockets, peer custody, the expiry clock or the answer bound, so nothing in HE-003A is
model-defined: its rules are R31-R42 in the HE-003A section at the end, from HE-003A design revision 3 with its §16
build amendment and the owner decisions quoted there. No existing event's answer changes.

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

## HE-002S: the EFFECT_GATE process seal (`seal`, crate `gate-sys`: `seal.rs`, `Dir::file_ro`)

The seal implements HI-7's EFFECT_GATE row and SEC-4 for that role (HE-002S design revision 4, §2 as amended by §18's
consequence of owner decision Q-HE2S-9 (a)): uid and gid 0, no capability left, permitted = effective = inheritable =
bounding = ambient = {}, `no_new_privs` 1 before the filter, `RLIMIT_CORE` 0/0, and exactly the published EFFECT_GATE
program installed in mode 2. It is a library: `seal_stage1() -> Result<Stage1, SealError>` and
`seal_stage2(Stage1) -> Result<Sealed, SealError>`, Linux only, concrete over the Linux implementation of the
crate-private `SealOps` trait; the generic engine (`run_stage1`, `run_stage2`, `plan`) is crate-private, and `Stage1`
and `Sealed` have private fields and no `Clone`, `Copy` or `Default`, so no crate can obtain a token from a fake
(design review round 3, D6). HE-003's `main` calls stage 1 first, reads and checks only the signed configuration,
calls stage 2, and exits with a distinct status on any `SealError` (the library cannot exit). On other targets the two
public functions are absent; the engine, the plan and the portable helpers compile and are host-tested everywhere.

### The sequence, as built

| Step | Calls (each read-back compared with its target) | `SealStep` on failure |
|---|---|---|
| precondition | the `Threads:` line of the process's status file is 1 (`Dir::at("/proc/self")`, `file_ro("status")`, at most 64 KiB) | `Threads(One)` |
| precondition | `getresuid` and `getresgid`: all three ids 0 (`getuid` is killed by the filter, so this runs first) | `UserIds`, `GroupIds` |
| start sets | `capget` (version 3, pid 0); `PR_CAPBSET_READ` 0..=40, then `PR_CAPBSET_READ(41)`, which must fail with EINVAL | `StartCapabilities`, `StartBounding` |
| plan | the running architecture's program is 1 to 4096 whole instructions (checked before any change) | `Program` |
| 1 | `prlimit(0, RLIMIT_CORE, {0, 0}, &old)` (musl issues `prlimit64`); read back with a null new limit: 0/0 | `CoreLimit`, `CoreLimitReadBack` |
| 2 | `PR_CAP_AMBIENT_CLEAR_ALL`; read back with `PR_CAP_AMBIENT_IS_SET` 0..=40: empty | `AmbientClear`, `AmbientReadBack` |
| 3 | `PR_CAPBSET_DROP` of every present capability but CAP_SETPCAP, ascending; read back 0..=41: {CAP_SETPCAP} ∩ start bounding | `BoundingDrop(One, n)`, `BoundingReadBack(One)` |
| 4 | `capset` permitted = effective = {CAP_SETPCAP} ∩ start permitted, inheritable empty; `capget` read-back | `Capabilities(One)`, `CapabilitiesReadBack(One)` |
| 5 | `PR_SET_NO_NEW_PRIVS` 1; `PR_GET_NO_NEW_PRIVS` reads 1 | `NoNewPrivs`, `NoNewPrivsReadBack` |
| between | HE-003: only the signed configuration's read and check | |
| 6 | the `Threads:` line is 1 again | `Threads(Two)` |
| 7 | `PR_CAPBSET_DROP(CAP_SETPCAP)` if stage 1 left it in the bounding set; read back 0..=41: empty | `BoundingDrop(Two, 8)`, `BoundingReadBack(Two)` |
| 8 | `capset` all three sets empty; `capget` read-back | `Capabilities(Two)`, `CapabilitiesReadBack(Two)` |
| final state | `capget` (all empty), `PR_CAPBSET_READ` 0..=41 (empty), `PR_CAP_AMBIENT_IS_SET` 0..=40 (empty), `PR_GET_NO_NEW_PRIVS` (1), the core limit (0/0): the last reads, since the filter kills all of them (D4) | `FinalCapabilities` ... `FinalCoreLimit` |
| 9 | `syscall(SYS_seccomp, SECCOMP_SET_MODE_FILTER, SECCOMP_FILTER_FLAG_TSYNC, &prog)` (317 on x86_64, 277 on aarch64; musl has no `seccomp` wrapper) with the running architecture's program; any return but 0 fails (a positive return is TSYNC's thread id, nothing installed) | `Filter` |

Every failure is a `SealError { step, failure }`: the OS error of a failed call, `InvalidCapability(n)` for EINVAL from
a capability read within 0..=40 (C9), `LastCapability` when `PR_CAPBSET_READ(41)` does not fail with EINVAL,
`NotABoolean` for a read that is neither 0 nor 1, `SetMismatch`, `CapabilitiesMismatch`, `CoreLimitMismatch` and
`NoNewPrivsUnset` for read-backs, `NotRoot`, `Threads(n)` and `StatusFormat` for the preconditions, `ProgramLength`,
and `TsyncThread(id)` or `Returned(value)` for the filter. The seal stops at the first one. With a full root start the
seal makes 309 calls (176 in stage 1, 133 in stage 2).

Accepted start states (§18): the full root set, or any superset of {CAP_SETPCAP}; or a start already within
{CAP_SETPCAP}, with nothing left to drop when CAP_SETPCAP is absent (HE-008's unit starts the gate in one of them).
Every target derives from the start sets, so the kernel itself refuses the others: `PR_CAPBSET_DROP` needs CAP_SETPCAP
effective even for an absent capability (EPERM at `BoundingDrop`), and `capset` can only shrink the permitted set.
The host tests run each start through a fake kernel that models both rules: full root (also with an inheritable and an
ambient capability), a superset of {CAP_SETPCAP}, {CAP_SETPCAP} only, {CAP_NET_BIND_SERVICE, CAP_SETPCAP}, empty, and
CAP_SETPCAP permitted and effective but not bounding all seal; CAP_NET_BIND_SERVICE without CAP_SETPCAP, a full
bounding set without capabilities, CAP_SETPCAP permitted but not effective, and CAP_SETPCAP only in the bounding set
fail at `BoundingDrop` with EPERM. Two starts outside the list's wording also seal, because nothing is left to drop from
their bounding sets and `capset` lowers the permitted set without a capability: a permitted set beyond the bounding set
(D4's example) and another permitted capability with an empty bounding set and no CAP_SETPCAP. Both end with every set
empty, which the final-state assertion checks, so HI-7's "bounding equal" holds for every start that seals.

### Code and audit

- `gate-sys/src/seal.rs` (Linux only; with `openat.rs` the only places of the workspace that may hold `unsafe`): one
  `unsafe extern "C"` block declaring exactly `prlimit`, `prctl`, `capget`, `capset`, `getresuid`, `getresgid` and
  `syscall`, private; each call in its own `unsafe` block with its own `// SAFETY:` argument, behind safe functions
  (`own_status`, `user_ids`, `group_ids`, `read_capabilities`, `write_capabilities`, `process_control`, `core_limit`,
  `install_filter`). `process_control` accepts only options 23, 24, 38, 39 and 47 with sub-option 1 or 4 (none of which
  takes a pointer) and always passes exactly four `c_ulong` arguments; `install_filter` checks that the stated
  instruction count is 1 to 4096 and exactly the program's size before the call, passes the program as a byte pointer
  in `sock_fprog` (never cast to a typed slice) and gives `syscall` six `c_long` or pointer arguments (D5).
  `read_capabilities` also refuses a header the kernel changed. Compile-time size, alignment and offset asserts cover
  `CapHeader` (8/4), `CapData` (12/4; two words 24), `Rlimit` (16/8) and `SockFprog` (16/8, pointer at 8), checked by
  both musl release builds.
- `Dir::file_ro(name)`: `O_RDONLY|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK`, the store-name check before the call and the
  regular-file check (`fstat`) after it, as `Dir::file`; a missing name is `NotFound`. `O_NONBLOCK` (owner decision
  Q-HE2S-11 (a), 2026-10-13, via the lane monitor, verbatim: "add O_NONBLOCK to Dir::file_ro in HE-002S (no effect on
  regular files; a FIFO open returns at once and the fstat check refuses it), plus one host test that a FIFO is refused
  without blocking; §6 gains the flag. Dir::file's R1-5 stays carried to HE-003.") is 0o4000 on both Linux targets
  (musl's `pipe2` passes 2048 to `fcntl(F_SETFL)` in the pinned `libc.a`) and 0x4 on macOS. `Dir::at("/proc/self")` follows the `self`
  link, and `O_NOFOLLOW` applies to `status` (D3).
- `effect-gate/src/seal.rs` (safe; the root forbids `unsafe_code`): the plan, the engine, the typestate API, and the
  portable helpers `capability_words` and `capability_sets` (the two version-3 words, capabilities 32-40 in the second),
  `filter_length` (the `sock_fprog` length), `Prctl::arguments` (the option and its four arguments) and `status_threads`
  (exactly one line starting `Threads:`, optional tabs or spaces, decimal digits, nothing else, no overflow). Both
  programs are embedded with `include_bytes!` as `PROGRAM_X86_64` and `PROGRAM_AARCH64` on every target;
  `RUNNING_ARCH` (`cfg(target_arch)`) selects the one installed.
- `tools/gate.py`: the two programs among the contract files (15), pinned at the published digests; the word `unsafe`
  also allowed in `gate-sys/src/seal.rs`; the start-up lint's one exception, one occurrence of the expression
  `Dir::at("/proc/self")?.file_ro("status")` in that file (whitespace between its tokens ignored), removed before the
  scan, so a second occurrence, the bare literal `"/proc/self"`, a raw string, `concat!("/proc/self", ..)`, another
  name such as `file_ro("environ")`, `"/proc/self/status"`, a `/proc` in a comment or the expression in any other
  file still refuses (HE-002S PR review round 1, R1-5). The lint matches text: a `concat!` split so that no part spells
  `/proc` (for example `concat!("/pro", "c/self")`) passes it in any file, as it did before HE-002S; that form is code
  review's (PR review round 2, R2-2). The per-file foreign-item allowlist over the linked crates'
  sources (D8): `openat.rs` exactly `openat`, `seal.rs` exactly the seven symbols above, no other source an extern
  block with an item, no `pub` or `safe` item in one, no `link_name`. It reads each source with its comments removed
  and the contents of its string, raw-string and character literals emptied, so neither a comment nor a literal can
  hide a block or end one early; every `extern` must be an extern block, `extern crate` or a function's ABI
  (`extern "C" fn`); a block's body is read strictly (items ending in `;`, each a `fn`, `static` or `type` with its
  name; a `!`, `$`, `#`, `=` or brace in a body refuses); and `openat.rs` and `seal.rs` define no macro (the word
  `macro_rules`, or any `$` outside string and character literals). Anything the reader cannot lex or follow refuses,
  so "exactly" holds for every extern block in the linked sources: a block behind a comment between the ABI and the
  brace is read, a `}` in a comment or a literal does not end a block early, and a block a macro would generate is
  refused (R1-1). The post-seal tripwire covers
  `effect-gate`, `gate-sys` and `i05-protocol`, whose code also runs after the seal (no `i05-protocol` source named a
  listed API when it was added; R1-2), and refuses `set_nonblocking`, `read_dir`, `current_exe`, `uname`,
  `membarrier`, `set_len`, `set_permissions`, `set_times`, `set_modified`, `io::copy`, `is_terminal` and
  `IsTerminal` (the std openers stay LINKED_FORBIDDEN's). That is its whole scope: the refused list of HE-002S DESIGN
  §5 plus `set_modified` and `is_terminal`, over those three crates. A std API the list does not name (for example
  `Debug` of a `File`, in the table below) is code review's and T04's, whose steady-state trace is the proof. The
  linked-source tripwire also refuses, read with comments and literal contents removed, a `use` that renames (`as`)
  a path any of whose segments is `std` or a name some linked source imports from std (R1-2): the union over the
  three crates' sources, in any order, so `use std::io; use io as z;`, `use self::io as z;`, `use {std::io as z};`
  and a `crate::` or `super::` path through a re-exported std name refuse, and a `use` tree the reader cannot follow
  (a macro's `$crate`) refuses too. It is a rule over names, not over what a path resolves to: a crate-local item that
  shares a std-imported name cannot be renamed either. A glob (`*`) whose path goes through `std` or such a name
  refuses as well (PR review round 2, R2-1: `use std::io::{*};`, `use std::io; use io::*;`, `use std::io::{self, *};`
  and `pub use super::io::*;` would name std's items without spelling them). No source used any of those names or
  forms before the checks were added. HE-002C's carried R3-1 is closed for these forms (R1-4): in every workspace source the words
  `global_asm` and `naked_asm`, `asm!`, the word `asm` after `arch::` (also inside a group, as in
  `use core::arch::{asm as a};`) and before ` as` (`use core::arch::asm as a;`); and in the linked sources the word
  `asm` itself, so no macro or renaming import there can assemble a call to it. R3-4 (the duplicate `import tomllib`;
  the "allowlist" comment in `tools/test_gate.py`) is fixed; R3-2 and R3-3 stay HE-003's. Like the other tripwires
  these match text, not Rust, and any other form is code review's.

### The Rust 1.99.0 and musl 1.2.5 re-check (owner decision Q-HE2S-3 (a))

Sources. Rust: HE-001's evidence copy `tools/w03/he001/closure/evidence/rust-src-1.99.0.tar.xz` (owner decision C7),
sha256 `3f1f9b7ed48f4596fc87889b7b3c61747336a55c9c22db1ab0c697e0aadb77aa` re-hashed before use, read from a scratch
extraction of `library/std/src` and `library/backtrace/src`; paths below are relative to `library/std/src` unless they
name another directory. musl: the pinned toolchain's self-contained `libc.a`, sha256
`e699c64b0c6b427d89ad5bf767bf78beb30c19930c5dedff635951636e8f9f70` (x86_64, 6406314 bytes) and
`b03473b6f1efb72f700f561b4407a88885b37e0edb5cdb2a64de0df5499e813f` (aarch64, 6455370 bytes), both rows of the closure
table: the archive symbol index (2002 entries over 1347 members on each), the members' ELF symbol tables, and the
disassembly (llvm-objdump of the Command Line Tools) of the members named below. System call numbers are the
immediates loaded into the number register (`eax`, `x8`) or into the first argument of `__syscall_cp` (`edi`, `x0`).
The "After the seal" column is the vendored programs' own answer: each named call (with the argument that decides it,
such as `FIONBIO`, `F_DUPFD_CLOEXEC`, the clone flags, `mremap`'s flags or the socket type) was run through a
classic-BPF interpreter over `host-enforcement/contracts/seccomp-v3/`; "killed" is `SECCOMP_RET_KILL_PROCESS` and
`clone3` gets `ERRNO(ENOSYS)`. After the filter the seal's own calls are all killed (`capget`, `capset`, `getresuid`,
`getresgid`, `seccomp` and `prctl` options 23, 24, 38, 39 and 47, as are `getuid`, `setrlimit` and `getrlimit`) except
`prlimit64`, which is allowed for this process and for another (§2: bounded by the hard limit 0 and by SELinux).

Symbols (C5). Both archives define `prlimit` (prlimit.lo), `prctl` (prctl.lo), `capset` and `capget` (cap.lo),
`getresuid` (getresuid.lo), `getresgid` (getresgid.lo) and `syscall` (syscall.lo), each referencing only
`__syscall_ret`, and neither has `prlimit64`, `seccomp` or `clone3`. The wrappers issue: `prlimit` 302 (`prlimit64`) on
x86_64 and 261 on aarch64; `prctl` 157 and 167; `capget` 125 and 90, `capset` 126 and 91; `getresuid` 118 and 148;
`getresgid` 120 and 150.

| §5 item | Rust 1.99.0 | musl 1.2.5 (`libc.a`, x86_64 / aarch64) | After the seal |
|---|---|---|---|
| thread naming | `sys/thread/unix.rs:434-451`: Linux `set_name` is `pthread_setname_np(pthread_self(), name)`, truncated to 16 bytes; `thread/lifecycle.rs:144-146`: a spawned thread names itself before its closure runs; `sys/pal/unix/mod.rs:42-49`: the main thread is renamed only on Apple targets | `pthread_setname_np.lo` calls `prctl` with option 15 (`PR_SET_NAME`) for the calling thread; for another thread it opens and writes its `comm` file (it references `open` and `write`), which std never does | `prctl(PR_SET_NAME)` allowed; a thread names only itself |
| thread creation | `sys/thread/unix.rs:103`: `pthread_create`; no `clone3` anywhere in `library/std/src` | `pthread_create.lo` calls `__clone`; `clone.lo` issues `clone` (56 / 220) and `exit` (60 / 93); no member loads 435 (`clone3`) | `clone` with `CLONE_THREAD` allowed; no `clone3` issued |
| abort, raise | `sys/pal/unix/mod.rs:299-301`: `abort_internal` is `libc::abort()` | `abort.lo` calls `raise`; `raise.lo` issues `tkill` (200 / 130) | allowed |
| allocation | `sys/alloc/unix.rs:31`, `:53`, `:71`, `:99`: `malloc`, `calloc`, `realloc`, `posix_memalign` | mallocng's `realloc.lo` calls `__mremap` with flags 1 (`MREMAP_MAYMOVE`) on both; `mmap`, `munmap`, `brk` | allowed (`mremap` with flags 0 is killed: see `pthread_getattr_np` below) |
| stdio, time, randomness | `sys/fd/unix.rs:376`, `:393`: `write`, `writev`; `sys/pal/unix/time.rs:107`: `clock_gettime`; `sys/random/linux.rs:72-122` (`:113`, `:119`, `:122`): `getrandom` by raw system call, falling back to `/dev/urandom` (opened at `:157` with `File::open`) only on ENOSYS or EPERM, or on EAGAIN after EINVAL for GRND_INSECURE (a kernel before 5.6, which the seal's `PR_CAPBSET_READ(40)` check refuses) | | allowed; `getrandom` is allowed, so the fallback's open (killed on x86_64) is not reached |
| no `pthread_getattr_np` on the main thread | `sys/pal/unix/stack_overflow.rs:400-410` and `:447-452`: on musl the main-thread guard is `None`, without a call; `:246-253` and `:568-580`: a spawned thread calls `pthread_getattr_np(pthread_self())` on itself | `pthread_getattr_np.lo` calls `mremap` with flags 0 (the main-thread stack probe) | the probe is killed, but only the main thread would reach it and std never calls it there |
| `available_parallelism` | `sys/thread/unix.rs:152` | | refused in every workspace source by the start-up lint |
| `set_nonblocking` | `sys/fd/unix.rs:628-634` and `sys/net/connection/socket/unix.rs:591-595`: `ioctl(FIONBIO)` | `ioctl.lo`: 16 / 29 | killed; refused by the post-seal tripwire |
| std path openers | `sys/fs/unix.rs:30-39`: on musl std uses `open`, `stat`, `lstat`, `fstat` and `ftruncate`; `:1241` (`open64` is `open`), `:1914` (`readlink`), `:1977` (`stat`), `:1994` (`lstat`); `statx` is glibc only (`:9`, `:63`) | `open.lo`: `__syscall_cp(2)` / `__syscall_cp(56)` (`openat`); `stat.lo` and `lstat.lo` call `fstatat.lo`: 4, 6, 5 and 262 / 79 and 80; `readlink.lo`: 89 / 78 | opens killed on x86_64 only (aarch64's `openat` is allowed); `stat`, `lstat` and `readlink` killed on both; LINKED_FORBIDDEN refuses `File::open`, `OpenOptions` and `std::path` |
| `read_dir` | `sys/fs/unix.rs:1847`: `opendir`; `:868`: `readdir` | `getdents.lo`: 217 / 61 (`getdents64`) | killed; refused |
| `current_exe` | `sys/paths/unix.rs:275-276`: `read_link("/proc/self/exe")` | `readlink.lo`: 89 / 78 | killed; refused |
| `uname`, `membarrier` | no caller in `library/std/src` | `uname.lo`: 63 / 160; `membarrier.lo` is the only member loading 324 / 283 | killed; refused by name |
| `File::set_len`, `set_permissions`, `set_times`, `set_modified` | `fs.rs:1115`, `:1215`, `:1262`, `:1271`; `sys/fs/unix.rs:1463-1466` (`ftruncate`), `:1553-1555` (`fchmod`), `:1617` (`futimens`) | `ftruncate.lo`: 77 / 46; `fchmod.lo`: 91 / 52; `utimensat.lo`: 280 / 88 | killed; refused |
| `io::copy` between descriptors | `io/mod.rs:314` (re-exported from `alloc`'s io); `sys/io/kernel_copy/linux.rs:72-77` (the `File` specialization), `:295-332` (`copy_file_range`, then `sendfile` or `splice`), `:696-733` | `copy_file_range.lo`, `sendfile.lo`, `splice.lo` | killed; refused |
| `is_terminal` (`IsTerminal`) | `io/stdio.rs:1250` (the trait), `:1265` (`File`, the std streams and their locks), `os/fd/owned.rs:254` (`BorrowedFd`, `OwnedFd`); `sys/io/is_terminal/isatty.rs:5`: `libc::isatty` | `isatty.lo`: `ioctl` (16 / 29) with `TIOCGWINSZ` (0x5413) | killed; refused by the post-seal tripwire (HE-002S PR review round 1, R1-2) |
| `Debug` of a `File` | `fs.rs:1300` (std's `File` formats its inner file); `sys/fs/unix.rs:1771-1777`: `debug_path_fd` (`:286-315`), whose `get_path_from_fd` (`:317-322`) reads the link `/proc/self/fd/N` with `readlink` (`:1914`) | `readlink.lo`: 89 / 78 | killed. `gate-sys`'s `Dir` (`openat.rs:105`) and `effect-gate`'s `FileStores` (`file_store.rs:105`) derive `Debug` over a `File`; no non-test source formats one today. Not on the post-seal list: carried to HE-003 (no `{:?}` of either after the seal, or a `Debug` impl that does not format the `File`; R1-2) |
| `try_clone` | `fs.rs:1177`; `sys/fd/unix.rs:654-656`; `os/fd/owned.rs:113-118`: `fcntl(F_DUPFD_CLOEXEC)` | | allowed |
| HE-003: `connect_timeout`, AF_UNIX streams, `socketpair` | `sys/net/connection/socket/unix.rs:167-173` (`set_nonblocking` around `connect`, then `poll` at `:207`); `os/unix/net/stream.rs:112`, `:147`, `os/unix/net/listener.rs:75`, `:141` (`AF_UNIX`, `SOCK_STREAM`); `os/unix/net/stream.rs:177` and `sys/net/connection/socket/unix.rs:131`, `:135` (`socketpair`) | | killed (only AF_UNIX `SOCK_SEQPACKET` is granted); carried to HE-003 |
| link hazard | | `pthread_create.lo` defines `__membarrier_init` WEAK; `membarrier.lo` defines it GLOBAL with `__membarrier` and a WEAK `membarrier`; no member references `membarrier` or `__membarrier` | absent unless something linked references them; HE-003's link check of the gate binary confirms it (HE-002S links no binary) |
| `RUST_BACKTRACE` | `panic.rs:509-522` reads it; `panicking.rs:287-292` prints a backtrace through `backtrace_rs`; `library/backtrace/src/symbolize/gimli/parse_running_mmaps_unix.rs:48` opens `/proc/self/maps`, `libs_dl_iterate_phdr.rs:48`, `:77` call `current_exe`, `gimli.rs:193` opens the object | | a panic with it set dies by SIGSYS; HE-008's unit leaves it unset, T04 records the death signal |

The post-seal tripwire refuses the rows marked refused above and nothing else: HE-002S DESIGN §5's list plus
`set_modified` and `is_terminal`, over `effect-gate`, `gate-sys` and `i05-protocol`. Anything that list does not name
is code review's and T04's; the Linux trace of the seal and of the steady state stays T04's.

### Carried

- HE-002C's R1-5 (a FIFO planted at a store name blocks `Dir::file`'s open until a writer appears) stays carried to
  HE-003; `Dir::file_ro` sets `O_NONBLOCK` (Q-HE2S-11 (a)), so the signed configuration's read cannot wait on one.
- HE-003: the call site (stage 1 first, only the configuration between the stages, stage 2, a distinct exit status on
  any `SealError`), a source check that no socket or thread is created before `Sealed`, an allowance or another
  mechanism for the exit if the binary crate joins the linked-source tripwire (D9), the refusal of a signed I04 port
  below 1024 (Q-HE2S-9 (a)), the socket items above, the gate binary's link check for `__membarrier`, the
  qualification of the broker without a ptrace-mode read (Q-HE2S-10 (a)), and `Debug` of a `File` (HE-002S PR review
  round 1, R1-2): no `{:?}` of a `gate-sys` `Dir` or an `effect-gate` `FileStores` (or of anything holding one) after
  the seal, or a `Debug` impl that does not format the `File`.
- HE-008: the uid, an accepted start state, the SELinux self permissions (`capability { setpcap }`,
  `process { setcap getcap setrlimit }`, and the status-file reads: `dir { search }` on `/proc` and the gate's own
  directory, `lnk_file { read }` on the `self` link, `dir { open read }` on the directory and `file { open read
  getattr }` on `status`; D2), no `process { setrlimit getrlimit }` on other domains, a `core_pattern` that is not a
  pipe or a helper that honours `RLIMIT_CORE` 0, the gate kept dumpable, no systemd seccomp option and `RUST_BACKTRACE`
  unset.
- T04: for every thread `CapInh`, `CapPrm`, `CapEff`, `CapBnd` and `CapAmb` 0, `NoNewPrivs: 1`, `Seccomp: 2` and
  `Seccomp_filters: 1`; the core limit 0/0; the installed filter equal to the published digest; SIGSYS on a refused
  call, and no core from a seccomp kill or a panic; the broker's and the inspector's reads of the gate; only the
  configuration's reads between the stages; the unit's start state; no AVC denial from the seal; the steady-state trace
  inside the program; and the cross-process `prlimit64` reach denied by SELinux. Two host-test gaps are T04's too
  (HE-002S PR review round 1, R1-7): gate-sys `seal.rs`'s own refusals (the `prctl` option allowlist, the filter length
  check, the `capget` header check) are Linux-only and exercised only on Linux, since the host `cargo test` does not
  compile the module; and `SealStep::Program` cannot be reached with the embedded programs, whose lengths are tested on
  their own (`filter_length`), so no engine test reaches it.

### Owner decisions (2026-10-13, via the lane monitor; quoted from HE-002S design revision 4, §11, §14, §15 and §18)

- **Q-HE2S-1 = (a):** a harness-onion meta packet publishes the compiled seccomp programs as data files; its layer recompiles them with the pinned v3 compiler and checks them against the published digests; R10 vendors EFFECT_GATE's two files byte-identically, gate.py pins their sha256, and the seal embeds them.
- **Q-HE2S-2 = (a), all 14:** a new small primary-lane meta packet publishes all 7 roles × 2 architectures plus edge registry record v2. It ALSO carries EDGE-2 (the R12 conformance-labs → harness-engineering edge record that rides the next registry-touching packet, owner A13) and W03-PLAN-AMEND-1 (the obligation-register amendment, owner Q-HE2B-2). HE-002S merges after it.
- **Q-HE2S-3 = (a):** HE-002S does the source re-check of the Rust 1.99.0 std paths the gate uses after the seal, recorded in MODEL_DEFINED with source lines; the Linux trace stays with T04.
- **Q-HE2S-4 = (a):** two-stage seal. Stage 1 before any input: core limit 0/0 with read-back, PR_SET_DUMPABLE 0, ambient cleared, bounding set and capset down to {CAP_SETPCAP, CAP_NET_BIND_SERVICE}. Between stages, only the signed configuration's read and check. Stage 2: drop to {kept}, no_new_privs, then the filter.
- **Q-HE2S-5 = (a):** the seal checks "Threads: 1" in /proc/self/status before stage 1, with a reviewed start-up-lint exception limited to gate-sys's seal.rs and that one path; HE-003's source check and T04's per-thread checks stay.
- **Q-HE2S-6 = (a):** download the official rust-src 1.99.0 component from static.rust-lang.org into the operator state dir and check it against the sha256 in the signed 1.99.0 channel manifest; operator-side evidence only, nothing enters R10. Conditions: unauthenticated HTTPS, a generic User-Agent, no personal data in any URL, header or UA, no token; record the URL, size, sha256 and manifest digest in a small manifest. Run it yourself, not via an agent, or with the PAUSE prefix if an agent runs it.
- **Amendment scope = yes:** add SEC-4 and HI-7 (+HE-003 call site, +HE-008 uid, unit start state and SELinux self-permissions) and SEC-QW4 (+HE-002S steady-state re-check) to W03-PLAN-AMEND-1 in slot 232, then one more light contract review round before adoption.
- **Q-HE2S-7 = (a) "Keep gate dumpable":** drop the PR_SET_DUMPABLE 0 step (amends Q-HE2S-4 (a)); keep the core limit at 0/0 with read-back. Carry to HE-008: core_pattern is not a pipe, or its helper honours RLIMIT_CORE 0. Carry to T04: a seccomp kill and a panic leave no core anywhere, and the broker's and inspector's reads of the gate succeed.
- **Q-HE2S-8 = (a):** move no_new_privs into stage 1, and repeat the "Threads: 1" check at the start of stage 2; HE-003's source check also covers the code between the stages.
- **C7 = use the existing copy:** skip the Q-HE2S-6 download and use HE-001's evidence copy tools/w03/he001/closure/evidence/rust-src-1.99.0.tar.xz (sha256 3f1f9b7e…, matching HE-001's evidence manifest; I re-checked it). Nothing is downloaded.
- **Q-HE2S-9 = (a):** require a signed I04 port ≥ 1024, so `kept` is always empty and the gate holds no capability after the seal; HE-003's configuration check refuses a lower port. Reflect it in the slot-232 carry list and the HE-003 carry.
- **Q-HE2S-10 = (a):** amend §4.3 so the gate qualifies the broker by label, cgroup, pidfd/start time and SO_PEERCRED; the broker's artifact identity comes from the observer's native-profile record (HE-004), not the gate's own /proc read. Carried to the HE-003 and HE-005 designs and to the §4.3 owner; the amendment vehicle is named later. Note: `architecture/host-interface-amendment*` is a parallel-lane ownedPath, so that packet needs my coordination. Don't create files there.
- **D2 = carried note** in slot 232's status.json (an adoption-metadata edit, no round 5); HE-008 completes the /proc/self list.

As built, Q-HE2S-7 (a) removed `PR_SET_DUMPABLE` from Q-HE2S-4 (a)'s stage 1, Q-HE2S-8 (a) moved `no_new_privs` into
it, C7 replaced Q-HE2S-6 (a)'s download, and Q-HE2S-9 (a) narrowed stage 1's set; the design's consequence for §2,
verbatim: "Stage 1 therefore reduces the bounding and permitted sets to {CAP_SETPCAP} ∩ start, stage 2 drops
CAP_SETPCAP and leaves every set empty, and the API takes no `kept` value."

## HE-003A: the channel substrate (`substrate`, `peers`, `linux_os`; crate `gate-sys`: `channel.rs`, `peer_wire.rs`)

HE-003A (design revision 3 (sha256 `bc20dacc…`) with its §16 build amendment (sha256 `60e8d7da…`); design review
round 2 PASS_FOR_BUILD) builds I05-6 (the AF_UNIX SOCK_SEQPACKET listener, one channel per generation, per-frame kernel
custody, the 2-second answer bound), I07-5 (one writer session at a time on the maintenance socket, per-frame custody;
I07 v1 Channel 4's 2-second bound on MAINTENANCE_STATUS, WRITE_BEGIN and WRITE_END), SEL-5 (setsockcreate) and the
expiry clock (I05 Decision 9). It is a library: `Substrate<O: Os, I: I04Port, U: UpstreamPort>` over one `PolicyGate`,
generic over the `Os` (the system calls and the two clocks) and over two ports through which HE-003B's I04 events and
HE-003C's upstream events enter the same loop; `linux_os::LinuxOs` (Linux only) is the `Os` over gate-sys's `channel`
module, and its constructor takes `&Sealed`. No binary links it yet (HE-003D), so the ten binaries and SBOMs are
HE-002S's.

### The loop, as built

- **State** (§5.1). The substrate keeps only the connections it holds; the channel's state (`channel_state()`), the
  bound execution and its expiry (`bound_run()`), whether a writer session exists (`session_held()`), the I04
  connections' state (`connection_open()`) and the forwarded write (`pending_write()`) are read-only accessors of the
  model. After every event a held connection the model no longer holds is closed.
- **I05 connections** (§5.2): UNOPENED and none held: qualified (§4.2) and held, or a deviation before the first frame
  (R31); UNOPENED and one pending: the new one is closed unfed; OPEN: `SecondChannel` (CHANNEL_EXISTS); CLOSED (also
  after `PolicyGate::open`): `SecondChannel` (GENERATION_CHANNEL_USED). Each datagram: custody (§4.3), then the
  expiry check and the I04 port's backlog drain, then `Frame(Bytes(..))` (a truncated datagram as its first 16,385
  bytes; a zero-length one is a frame). `Eof` and any receive error are `ChannelLost`.
- **Peers** (§4.1-§4.3, `peers.rs`, owner decision Q-HE3A-3 (a)): the broker is `system_u:system_r:planeon_broker_t:s0`
  (selinux-matrix-v2 `domains[]`), uid 0 (spec §5.3), gid 0 (native-profile-v3's BROKER `gid` constant) and the cgroup
  v2 line `0::/planeon.slice/planeon-capacity-broker.service/broker` (native-profile-v3's BROKER `cgroup.path` constant
  without the cgroup filesystem's mount point; valid in the root cgroup namespace, HE-008); the writer is
  `system_u:system_r:planeon_policy_writer_t:s0`, uid 0, its gid and cgroup recorded at accept. Qualification at
  accept: SO_PEERCRED, SO_PEERSEC and SO_PEERPIDFD, then the peer's `/proc/<pid>` directory opened and read (`stat`
  field 22, the whole `cgroup` file, `attr/current`), then the pidfd must not have fired; then the process label and
  the socket label equal the expected label (one trailing NUL stripped), the uid, and for the broker the gid and the
  cgroup line set. On every frame: exactly one SCM_CREDENTIALS and one SCM_SECURITY (no MSG_CTRUNC, nothing else), its
  pid, uid and gid the qualified ones, its SCM_SECURITY byte-equal to the accept-time SO_PEERSEC bytes, the retained
  directory's start time, cgroup (expected for the broker, recorded for the writer) and process label unchanged, and
  the pidfd not fired. The control buffer is exactly `CMSG_SPACE(12) + CMSG_SPACE(L)` for the accept-time label length
  L, so a descriptor-passing message after the two is never installed (MSG_CTRUNC, a deviation).
- **The wake** (§5.6): the expiry, then the ports' due deadlines (the earlier port first); the I05 connection's
  datagrams until it would block; the I07 connection's; the pidfds (I05 then I07: the connection's datagrams are read
  first, and a connection still held whose process exited is a deviation); the ports' ready descriptors (I04 then
  upstream); the listeners (I05 then I07); then the ports register. The wait's timeout is the earliest deadline, rounded
  up to milliseconds, at most 1 second while an expiry is pending; EINTR is an empty wake.
- **Expiry** (§5.6, owner decision Q-HE3A-5 (a)): the bound run's lifetime end (`Lifetimes`, run nonce to seconds
  since the epoch) by the realtime clock, read at every check: at the start of every wake and right before any I05
  frame or I04 request is fed, `Expire` first when the clock has reached it. After `Expire` the model's `expired` is
  set and the deadline is gone (no spin); after `PolicyGate::open` the bound run and its expiry come from the journal's
  rebuild, so an expiry that passed while the gate was down is fed at the first wake.
- **Output tables** (§5.4): implemented as a `match` naming every `OutputKind` and `PolicyOutputKind` variant, so a new
  variant fails the build; every output goes to the I04 port's `apply`, then the upstream port's, then both ports'
  `sync` (with the `GateView` accessors). `RestartState` and `Restart` inside the loop stop it
  (`LoopExit::UnexpectedOutput`).
- **Exits** (§5.5): an `EventError` (the connection concerned closed first), a failed `accept4` other than EAGAIN or
  ECONNABORTED, a failed poller call or registration, an unregistered token, and a port token past 56 bits return a
  `LoopExit`; HE-003D exits the process with a distinct status, and the restart is deny-first.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R31 | A deviation before the first frame (at accept, or on the first datagram's custody, with the model's channel UNOPENED): the substrate feeds `PeerChanged`, which the model answers with nothing and which does not hold the generation, then `ChannelLost`, so `["CHANNEL_ENDED", "BEFORE_FIRST_FRAME"]` is journalled (output `{"channelEnd": "UNUSED"}`), the channel is CLOSED, the generation's state is kept and no later connection is accepted (the generation's one channel is used, as for a connection that ends before its first frame, T86) | DESIGN §5.3; owner decision Q-HE3A-4 (a) |
| R32 | An I07 writer connection that fails qualification at accept is closed without feeding the model (no `WConnect`, no session, nothing journalled). Sessions are one at a time, not one per generation, so a qualified writer may connect later | DESIGN §5.3, §5.8; Q-HE3A-4 (a) |
| R33 | ANSWER_LATE (I05): an answer is measured on the monotonic clock from the `recvmsg` that returned its request to its send and is never sent once 2 seconds have passed; the substrate feeds `Event::AnswerLate`, which on an OPEN channel closes it fatally with `ANSWER_LATE`: HELD in every state (an orderly CLOSED or INVALIDATED generation too, never the broker's orderly end), journalled `["INVALIDATED", "ANSWER_LATE", "HELD"]`, armed actions denied (as R1). On a channel that is not OPEN it is an `EventError` (R3's rule), which the substrate never feeds. Residual (not closed): the time a datagram waits in the socket queue before `recvmsg` is not counted; T04 measures the bound under load | DESIGN §5.7; owner decision Q-HE3A-2 (b) |
| R34 | ANSWER_LATE (I07): the answers to MAINTENANCE_STATUS, WRITE_BEGIN and WRITE_END (read from the response frame's `operation`; a frame the substrate cannot read is bounded too) carry the bound; a WRITE_OBJECT answer (a refusal, or the deferred outcome) does not (the write bound is the upstream port's). A late one is never sent; `PolicyEvent::WAnswerLate` then, in N12's order: the outstanding write aborted (none on these answers; with `WRITER_PROTOCOL_FAILURE`, as every other fatal session end aborts it), `INVALIDATED` with the gate's own reason (`["INVALIDATED", "ANSWER_LATE", "HELD"]`, not WRITER_PEER_DEVIATION), the generation HELD, `["WRITER_SESSION_ENDED", "FATAL"]` and, for an owning session whose maintenance has not ended, `MAINT_ENDED` `SESSION_FATAL`; output `{"sessionEnd": "FATAL", "maintenance": .., "fatal": "ANSWER_LATE"}` (`WriterFatal::AnswerLate`). Without a session it answers `{}` (as W_PEER_CHANGED) | DESIGN §5.7, B4; Q-HE3A-2 (b) |
| R35 | A failed send (B1): EAGAIN (under lockstep a full buffer means the peer stopped reading), EPIPE, ECONNRESET or any other errno is a peer failure; the answer is never retried: the connection is closed and `ChannelLost` (PEER_LOST and HELD outside an orderly state, `CHANNEL_ENDED ORDERLY` in one) or `WChannelLost` (the session ENDED) is fed. `MSG_NOSIGNAL` is set (std already ignores SIGPIPE) | DESIGN §3, §12 B1 |
| R36 | The liveness argument (A6): SO_PEERPIDFD gives a pidfd for the struct pid the kernel recorded at `connect`, with no window between the credentials and the pidfd; the `/proc/<pid>` directory opened by number names whatever process held that number at the open; the pidfd not having fired after the open proves the recorded process was still alive then, so the directory is that process's, and it stays bound to it (after the process is reaped, reads through it fail and never reach a process that reused the number). A frame read after its sender exited therefore fails the retained directory's reads (once the sender is reaped) or the pidfd probe (the pidfd fires at the exit), whatever pid its credentials carry, even the qualified number reused by another process (the argument does not rely on the pid the kernel reports for an exited sender; T04 may confirm the reported value): a broker that exits with a frame unread ends the channel fatally, never orderly (under lockstep it never does). A pidfd `ppoll` error, POLLERR or POLLNVAL counts as an exit (a deviation) | DESIGN §3, §4.2, §4.3 |
| R37 | The I07 custody gap: until the writer's executable check lands (owner decisions Q-HE3A-1 (c) and Q-HE3A-1b (a), below; decided, open), the writer is bound by the per-frame process label, cgroup, pidfd and start time, SO_PEERCRED and the per-frame credentials, while I07 v1 Channel 2 names the enrolled artefact. No HE-003A code reads a peer's executable | DESIGN §1, §4.3 |
| R38 | `Debug` and descriptors: `gate-sys`'s `Dir` and `effect-gate`'s `FileStores` have manual `Debug` impls (the type name; for `FileStores` also the generation), and `Listener`, `Conn`, `PidFd`, `Poller`, `ProcDir` and `SockCreate` print their type name only. `tools/gate.py` refuses `derive(Debug)` (also under `cfg_attr`) on a struct or enum of the linked crates whose field types mention `File`, `Dir`, `FileStores`, `Conn`, `Listener`, `Poller`, `PidFd` or `ProcDir` (field and variant names are not types); manual impls, direct formatting (`{:?}`, `expect_err`, `assert_eq!`) and a derived generic type instantiated with a hazard type (`#[derive(Debug)] struct Wrap<T> { inner: T }` used as `Wrap<File>`) are code review's | DESIGN §8, A10 |
| R39 | Refused by the linked-source tripwire: a top-level std group or glob (`std::{..}`, `std::*`) and a nested std glob (`std::…::*`, as `std::io::prelude::*`), with the renames and the globs through a name imported from std (HE-002S PR review R1-2 and R2-1). Left to code review, besides the forms listed in the HE-002C and HE-002S sections: type aliases (`type F = File;`, for the `Debug` rule too) and qualified paths such as `<T>::f` (HE-002C PR review round 3, R3-3) | DESIGN §8 |
| R40 | musl's `accept4` falls back to the killed `accept` on EINVAL or ENOSYS (`accept4.lo`), so the gate issues `accept4` through `syscall` (288 on x86_64, 242 on aarch64) and never calls musl's `accept4`; musl's `socket` retries without the flags and then uses `fcntl` (allowed), and `epoll_pwait` falls back to `epoll_wait` only on ENOSYS (A14) | DESIGN §2, §3 |
| R41 | A bound run with no lifetime in the `Lifetimes` input, and a realtime clock that cannot be read, expire at once (`Expire` at the next check; fail closed). A backward step of the realtime clock never fires the expiry early, a forward step is acted on within the 1-second cap and before the next frame or request | DESIGN §5.6 |
| R42 | The journal file's decoder (`frame.rs`) knows `ANSWER_LATE` among the fatal reasons, so `["INVALIDATED", "ANSWER_LATE", "HELD"]` reads back as written after a process restart (not TORN), the restart is HELD, the state the record names, and the reopened journal's digest equals the one before the restart. `frame.rs` joined HE-003A's paths for this (the design's path list was amended after the build) | DESIGN §10 (amended) |

### Code and audit

- `gate-sys/src/channel.rs` (Linux only; with `openat.rs` and `seal.rs` the only places of the workspace that may hold
  `unsafe`): one private `unsafe extern "C"` block declaring exactly `socket`, `bind`, `listen`, `setsockopt`,
  `getsockopt`, `recvmsg`, `sendmsg`, `epoll_create1`, `epoll_ctl`, `epoll_pwait`, `ppoll` and `syscall`; each call in
  its own `unsafe` block with its own `// SAFETY:` argument behind the safe functions `SockCreate::set` and `clear`,
  `listen_seqpacket`, `accept`, `peer`, `ProcDir::open` and `read`, `PidFd::exited`, `recv`, `send` and `Poller`'s
  `new`, `add`, `modify`, `delete` and `wait`. The sockcreate context is written with its trailing NUL in one `write`
  and cleared by one zero-length `File::write` (a guard clears on drop; an explicit `clear` reports a failure, which
  fails the listener). Compile-time size, alignment and offset asserts cover `sockaddr_un` (110/2), `ucred` (12/4),
  `iovec` (16/8), musl's `msghdr` (56/8; `msg_iovlen` at 24 and `msg_controllen` at 40, each 32-bit with padding),
  `epoll_event` (12/1 packed, data at 4, on x86_64; 16/8, data at 8, on aarch64), `pollfd` (8/4) and `timespec`
  (16/8), checked by both musl release builds. `gate-sys/src/peer_wire.rs` (portable, no `unsafe`) holds the control
  parser, the label rule, the `stat` and cgroup parsers and the buffer sizes, host-tested with fixed byte vectors.
- `Dir::file` opens `O_RDWR|O_CLOEXEC|O_NOFOLLOW|O_NONBLOCK|O_NOCTTY` (owner decision Q-HE3-4 (a); HE-002C's R1-5 is
  closed): `O_NOCTTY` keeps the gate, a session leader under systemd, from acquiring a controlling terminal through a
  terminal node planted at a store name, and `O_NONBLOCK` keeps an open of a device node from waiting; neither changes
  `pread`, `pwrite`, `fsync` or `flock` on a regular file, and the regular-file check refuses anything else. The host
  tests pin the values and bits; the behaviour is T04's. `Dir::sub(name)` opens one directory component
  (`O_RDONLY|O_DIRECTORY|O_CLOEXEC|O_NOFOLLOW`) with the store-name check.
- `tools/gate.py`: `channel.rs` joins the files allowed `unsafe` and has its foreign-symbol allowlist (the twelve
  above); the `std::os::fd` items are allowed in `openat.rs` and `channel.rs` only (effect-gate holds gate-sys's opaque
  types and names no descriptor); the start-up lint's exceptions are a per-file list of exact expressions, each removed
  once (`seal.rs`: the status read; `channel.rs`: `Dir::at("/proc/thread-self/attr")` and
  `Dir::at(&format!("/proc/{}", pid))`), so every other new file and its tests say "the proc filesystem" or "the cgroup
  filesystem"; the `derive(Debug)` rule of R38; and HE-002C PR review round 3's R3-2 (1)-(4): every workspace member is
  `crates/<name>`, `crates` is not a symlink, the crates effect-gate links (its path dependencies, transitively, with
  itself) are exactly effect-gate, gate-sys and i05-protocol, and the workspace edition is 2024 and every member
  inherits it (the unsafe tripwire relies on edition 2024's `unsafe extern` and `#[unsafe(no_mangle)]`), with no
  target table of a member manifest (`[lib]`, `[[bin]]`, `[[test]]`, `[[bench]]`, `[[example]]`) giving its own
  edition (HE-003A PR review round 1, R1-1). The contract table stays at 15 files.
- Departures from the design, besides R42: the `Os` trait has no random source (DESIGN §5 lists `getrandom` among what
  it wraps, but no substrate decision needs randomness: `WConnect`'s challenge is unused by the model); and a port
  registers its descriptors through `SourceId`s its `Os` gives it, since HE-003A's ports are the tests' fakes (the
  Linux `Os` refuses every port registration until HE-003B and HE-003C add their sources).

### Constants and their evidence (for T04)

From the pinned musl 1.2.5 `libc.a` (x86_64 sha256 `e699c64b…`, aarch64 `b03473b6…`), where its code shows the value
(llvm-objdump of the named members):

| Constant | x86_64 / aarch64 | Evidence |
|---|---|---|
| `accept4` system call | 288 / 242 | `accept4.lo` passes it to `__syscall_cp`, and falls back to `accept` on EINVAL or ENOSYS |
| `AF_UNIX` | 1 | `syslog.lo` (`__openlog`) calls `socket(1, 0x80002, 0)` |
| `SOCK_CLOEXEC`, `SOCK_NONBLOCK` (= `EPOLL_CLOEXEC`, `O_NONBLOCK`) | 0x80000, 0x800 | `socket.lo` and `accept4.lo` test exactly these bits (mask 0x80800) before their `fcntl(F_SETFD, FD_CLOEXEC)` and `fcntl(F_SETFL, 2048)` fallbacks |
| `MSG_NOSIGNAL` | 0x4000 | `res_msend.lo` passes 16384 to `sendto` and `sendmsg` |
| `MSG_DONTWAIT` | 0x40 | `netlink.lo` passes 64 to `recv` |
| `POLLNVAL` | 0x20 | `__libc_start_main.lo` (`__init_libc`) tests bit 5 of `revents` at offset 6 of `struct pollfd` |
| `O_NOCTTY` (`Dir::file`) | 0o400 (macOS 0x20000, SDK `sys/fcntl.h`) | `openpty.lo` opens the multiplexer with `O_RDWR|O_NOCTTY` = 0x102 |
| `struct msghdr` padding | offsets 28 and 44 | `recvmsg.lo` and `sendmsg.lo` zero them in their copy (and `sendmsg.lo` each `cmsghdr`'s padding at offset 4) |
| other system calls | `socket` 41 / 198, `bind` 49 / 200, `listen` 50 / 201, `setsockopt` 54 / 208, `getsockopt` 55 / 209, `recvmsg` 47 / 212, `sendmsg` 46 / 211, `epoll_create1` 291 / 20, `epoll_ctl` 233 / 21, `epoll_pwait` 281 / 22, `ppoll` 271 / 73 | the wrappers' immediates (for T04 and the EFFECT_GATE filter; the code names none of them) |

From the kernel UAPI (the code shows none of them; T04 confirms): `SOCK_SEQPACKET` 5 (`linux/net.h`); `SOL_SOCKET` 1,
`SO_PASSCRED` 16, `SO_PEERCRED` 17, `SO_PEERSEC` 31, `SO_PASSSEC` 34, `SO_PEERPIDFD` 77 (asm-generic `socket.h`, used by
both architectures; SO_PEERPIDFD needs Linux 6.5); `SCM_RIGHTS` 1, `SCM_CREDENTIALS` 2, `SCM_SECURITY` 3, `MSG_CTRUNC`
0x8, `MSG_TRUNC` 0x20, `MSG_CMSG_CLOEXEC` 0x40000000 (`linux/socket.h`); `EPOLL_CLOEXEC` 0x80000 (`linux/eventpoll.h`,
`O_CLOEXEC`), `EPOLL_CTL_ADD` 1, `EPOLL_CTL_DEL` 2, `EPOLL_CTL_MOD` 3, `EPOLLIN` 0x1, `EPOLLOUT` 0x4, `EPOLLERR` 0x8,
`EPOLLHUP` 0x10 (`linux/eventpoll.h`); `POLLIN` 0x1, `POLLERR` 0x8 (asm-generic `poll.h`). `struct epoll_event` is
packed on x86_64 only (the kernel's `EPOLL_PACKED`, musl's `__packed__`). `AT_FDCWD` is not used by `channel.rs`. The
socket contexts are `system_u:object_r:planeon_i05_socket_t:s0` and `system_u:object_r:planeon_i07_socket_t:s0`, the
paths `/run/planeon/live-proxy/effect-admission.sock` and `/run/planeon/maintenance/policy-write.sock` (contract
candidates).

### Carried

- HE-003D: one `PolicyGate` per process and a new generation only in a new process (R30's precondition); the production
  journal and marker directories; the process exit on a `LoopExit`; the mutual qualification record and how
  `peerQualificationDigest` relates to the identity the substrate keeps (`QualifiedIdentity`, §4.4); the `Lifetimes`
  input from the gate's own copy of the signed capacity inputs, with a configuration refused when a run has none. A
  standing duty (R42, built here): every later `FatalReason` joins `frame.rs`'s fatal-reason table (`FATAL_REASONS`).
- The writer's executable check (Q-HE3A-1 (c), Q-HE3A-1b (a); decided, open), after the chain the owner set: (1) a
  seccomp allowlist amendment adding the call to EFFECT_GATE with a first argument other than `AT_FDCWD` only (parallel
  lane, with or after the slot-234 §4.3 amendment); (2) republished EFFECT_GATE programs and edge record v3 (primary
  lane); (3) the R10 re-vendor and the check itself (HE-003D or HE-003A2). HE-007's obligations for it: (a) the writer's
  real, effective and saved uid and gid are 0; (b) it stays dumpable at every frame; (c) its permitted capability set is
  empty before it connects.
- HE-008: empty runtime directories at every start (`RuntimeDirectory=planeon/live-proxy planeon/maintenance`,
  `RuntimeDirectoryMode=0700`, `RuntimeDirectoryPreserve=no`, both `planeon_run_t`), `UMask=0177`, no private cgroup
  namespace for the gate's unit; the gate's own proc entries for its sockcreate attribute and `process setsockcreate`;
  the socket permissions on `planeon_i05_socket_t` and `planeon_i07_socket_t` and the two socket files' types; the
  peer reads (`process getattr` on `planeon_broker_t` and `planeon_policy_writer_t`, `attr/current` included) and
  whether the ignored ptrace-mode read check on that open is audited.
- T04: the listeners' labels as seen through SO_PEERSEC from a client and their 0600 mode; the real broker's and
  writer's custody; SCM_CREDENTIALS and SCM_SECURITY on every datagram (a zero-length one too); SO_PEERPIDFD;
  reading `attr/current` of the broker and the writer (no ptrace-mode check blocks it); an exec'd holder detected by
  the process label; the pidfd on exit; a refused second connection; the 2-second bound under load; a restart after a
  crash (empty runtime directories); the constants above; and that no killed call is reached (the steady-state trace).

### Owner decisions (2026-10-14, owner via the lane monitor; quoted from HE-003A design revision 3, §13)

- Q-HE3A-1 = (c) "readlink exe": the gate checks the I07 writer's executable by readlink of /proc/<pid>/exe. This was NOT your recommendation, and it needs a seccomp amendment: EFFECT_GATE's v3 program kills readlink, `architecture/seccomp*` is a parallel-lane path, and the compiled EFFECT_GATE programs from slot 232 would have to be recompiled, republished and re-vendored. Before folding it in, please check feasibility and send me: (1) the exact amendment chain (which packets, which lane, in what order, and whether it gates HE-003A's merge); (2) whether the readlink can succeed at all under the ptrace capability-subset rule (HE-002S D1). The sealed gate holds no capability (Q-HE2S-9), so if harness-policy-write's permitted set is non-empty, /proc/<pid>/exe is unreadable whatever seccomp allows. If (2) makes (c) infeasible, I'll take that back to the owner with the facts. Don't switch options on your own.
- Q-HE3A-2 = (b): new R10-defined fatal ANSWER_LATE; never sent late; the generation is HELD in every state; journalled as the gate's own failure.
- Q-HE3A-3 = (a): cited R10 constants (matrix-v2 labels, native-profile-v3 broker-leaf constant, spec §5.3 uids), passed as an argument so a signed or HE-004 source can replace them; T04 confirms them.
- Q-HE3A-4 = (a): a pre-first-frame deviation uses the one channel: PeerChanged then ChannelLost, CHANNEL_ENDED UNUSED, no reconnect, disclosed in MODEL_DEFINED; an I07 writer failing qualification at accept is closed without a session.
- Q-HE3A-5 = (a): a separate substrate input (run nonce → signed lifetime end) built by HE-003D from the signed capacity inputs, with one per run required.

"Fold Q-HE3A-2..5 into rev 2 now; hold Q-HE3A-1's part until (1) and (2) are answered."

- Q-HE3A-1b = (a) "No, merge HE-003A first". HE-003A merges with the writer bound by the per-frame process label, cgroup, pidfd and start time, SO_PEERCRED and per-frame credentials. The Q-HE3A-1 (c) exe check (readlinkat on the retained /proc/<pid> dir fd, "exe") is recorded as decided but open, and lands in the R10 packet after the chain. No readlinkat code goes into HE-003A. Record it verbatim and dated, and carry: the chain: (1) a seccomp allowlist amendment adding readlinkat to EFFECT_GATE (parallel lane, with or after the slot-234 §4.3 amendment that states the duty); (2) republished EFFECT_GATE programs plus edge record v3 (your lane); (3) the R10 re-vendor plus the writer exe check (HE-003D or HE-003A2); HE-007 obligations a-c: writer real/effective/saved uid and gid all 0; dumpable kept; permitted set empty before connect. T04 confirms. (2026-10-14, owner via the lane monitor.)
