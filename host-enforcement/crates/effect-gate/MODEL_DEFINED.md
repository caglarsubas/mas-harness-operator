# HE-002, HE-002B, HE-002C, HE-002S, HE-003A, HE-003B, HE-003C, HE-003D, HE-003A2, HE-004A, HE-003A3 and HE-004B1: model-defined and R10-defined behaviour

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

HE-003B adds the effect gate's I04 server (the new crate `gate-tls`; `effect-gate`: `net`, `linux_net`,
`Event::Disconnect`, `Port::failure`, `LoopExit::Port`; `gate-sys`: `tcp.rs`, `inet.rs`) and vendors the TLS stack. No
pinned model defines TLS, HTTP framing or sockets, so nothing in HE-003B is model-defined: its rules are R43-R58 in the
HE-003B section at the end, from HE-003B's design (revision 3 with its build amendments §17-§20) and the owner decisions
quoted there. No existing event's answer changes.

HE-003C adds the effect gate's upstream apiserver client (`gate-tls`: `upstream`, `tls_client`, `http1`'s client side,
`exchange::write_response`; `effect-gate`: `net::ConnectNet`, `linux_net::LinuxConnector`, `GateView::forwarded_write`,
R16's loopback parse; `gate-sys`: `connect_tcp`, `connect_result`). No pinned model defines sockets, TLS or HTTP
framing, so nothing in HE-003C is model-defined: its rules are R59-R68 in the HE-003C section at the end and the R16
rewording below, from HE-003C design revision 2.1 and the owner decisions quoted there. No existing event's answer
changes.

HE-003D adds the effect gate binary (`planeon-gate`'s `main`; `effect-gate`: `gate_config`, `status`,
`FileStores::open_bound`; `gate-tls`: `signed_config`, `credentials`; `i05-protocol`: the embedded policy-kind table)
and the host-path solution for the vendored crates. No pinned model defines a binary, a configuration file, exit
statuses or a store binding, so nothing in HE-003D is model-defined: its rules are R69-R78 in the HE-003D section at
the end, with the R65 and R67 rewording below and the amendment of R19-R30 (Q-HE3D-13 (b)), from HE-003D design
revision 2.2 and the owner decisions quoted there. No existing event's answer changes.

HE-003A2 re-vendors the EFFECT_GATE seccomp programs from allowlists v4 (harness-onion MET-ENFORCE-029,
`contracts/seccomp-v4/`, which the seal now embeds) and adds the gate's writer executable check (`gate-sys`:
`Dir::read_link`, `ProcDir::exe`; `effect-gate`: `peers::writer_exe_buffer_len` and `writer_exe_matches`,
`Os::writer_exe_ok`, the required `LinuxOs` argument, configuration format v2's `enrolledWriter`). No pinned model defines
the executable read or the configuration, so nothing in HE-003A2 is model-defined: its rules are R79-R85 in the HE-003A2
section at the end, with the R36, R37, R38, R40, R69, R70, R72 and R77 amendments, from HE-003A2 design revision 2.1 and
the owner decisions quoted there. No event, answer, record, vector, schema, journal format or `FatalReason` changes.

HE-004A adds the policy observer's substrate: the OBSERVER process seal and the observer binary (the crate
`planeon-observer`, now a library, `seal` and `status`, and a binary), the vendored OBSERVER seccomp programs and the
gate rules for a second linked binary. No pinned model defines a seal or a binary, so nothing in HE-004A is
model-defined: its rules are R86-R90 in the HE-004A section at the end, from HE-004A design revision 2.1 and the owner
decisions quoted there; it records the open item OBSERVER-WRAPPER-INVENTORY. The effect gate's crates, binary and
behaviour do not change.

HE-004B1 adds the policy observer's data logic (the crate `planeon-observer`'s modules `inputs`, `rbac`, `snapshot`,
`operational`, `admission` and `contracts`): the observer's list inputs and their completeness, the effective-RBAC
producer with the R1-7 refusal (I06-3), the I06 RBAC snapshot check, the observer-checked operational rules OR02, OR05
and OR06, and ADM-4's directory hash, comparison and pre-ACTIVE record. The snapshot check and the directory hash follow
the pinned I06 v1/v2 and admission v3 models where the contracts are silent (points P1-P10); the inputs, the producer,
the OR predicates and the record are R10-defined. Its rules are R98-R105 in the HE-004B1 section at the end, from
HE-004B design revision 2.2 and the owner decisions quoted there. Nothing in `main` calls the new logic, so no binary's
behaviour changes; the effect gate's crates and binary do not change.

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
| R16 | Configuration (PolicyGate): `policyWriter` is required and parsed by PolicyGate itself: exactly `qualificationNamespace` (a DNS-1123 label of at most 63 characters) and `apiserverAuthority` (HE-003C, HE-002B R1-4, Q-HE3C-1 (a) amended: an IP literal with port as gate-sys's `parse_authority` reads it, at most 64 bytes and no name, and loopback: an IPv4 address in 127.0.0.0/8 or the IPv6 address ::1 exactly, IPv4-mapped forms such as `::ffff:127.0.0.1` refused; no valid literal reaches 64 bytes, the longest loopback literals being 47 and 21 bytes; parsed once and kept by PolicyGate, whose `apiserver_address()` gives the upstream port of both channels its one address, while the string itself stays the I07 requests' `Host`); a missing, unknown, mistyped or out-of-rule member refuses the configuration, and the rest goes to the unchanged I05 `Config`, which still refuses `policyWriter` itself. The policy-kind table is read into closed types: version `planeon.internal.i07-policy-kinds/v2`, writable rows with scope QUALIFICATION_NAMESPACE or QUALIFICATION_NAMESPACE_OBJECT (the retired CLUSTER scope is refused), operations among CREATE, UPDATE, DELETE, the three known dispositions; members the gate does not use are ignored | HE-002B DESIGN §13, B4; the I07 model reads both with dictionary lookups |
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

HE-003D amends these rules (owner decision Q-HE3D-13 (b), R75): the gate binary opens its stores with
`FileStores::open_bound`, which also binds the generation to the signed configuration that started it, through a
`<generation>.document` file in the journal directory holding exactly one committed frame
`["DOCUMENT", generation, digest]`, written after the marker read and before the journal's creation (so R26's
directory syncs and their counts are unchanged) and compared at every later opening. `FileStores::open`, without the
binding, stays as HE-002C built it for its tests.

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
`clone3` gets `ERRNO(ENOSYS)`. HE-003A2 re-ran it over `contracts/seccomp-v4/` (the programs the seal embeds since then;
allowlists v4 = v3 plus `readlinkat` with a non-negative dirfd): every row keeps its answer, and only `readlinkat`
changes, so aarch64's `readlink`, which musl issues as `readlinkat(AT_FDCWD, ..)`, is now killed by its argument rather
than unconditionally (the rows that say so below, and the `readlinkat` row). After the filter the seal's own calls are all killed (`capget`, `capset`, `getresuid`,
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
| std path openers | `sys/fs/unix.rs:30-39`: on musl std uses `open`, `stat`, `lstat`, `fstat` and `ftruncate`; `:1241` (`open64` is `open`), `:1914` (`readlink`), `:1977` (`stat`), `:1994` (`lstat`); `statx` is glibc only (`:9`, `:63`) | `open.lo`: `__syscall_cp(2)` / `__syscall_cp(56)` (`openat`); `stat.lo` and `lstat.lo` call `fstatat.lo`: 4, 6, 5 and 262 / 79 and 80; `readlink.lo`: 89 / 78 | opens killed on x86_64 only (aarch64's `openat` is allowed); `stat`, `lstat` and `readlink` killed on both (under v4 aarch64's `readlink`, 78 with `AT_FDCWD`, by its argument); LINKED_FORBIDDEN refuses `File::open`, `OpenOptions` and `std::path` |
| `read_dir` | `sys/fs/unix.rs:1847`: `opendir`; `:868`: `readdir` | `getdents.lo`: 217 / 61 (`getdents64`) | killed; refused |
| `current_exe` | `sys/paths/unix.rs:275-276`: `read_link("/proc/self/exe")` | `readlink.lo`: 89 / 78 | killed (under v4 on aarch64 by the `AT_FDCWD` argument); refused |
| HE-003A2: `readlinkat` on a directory descriptor | std's `fs::read_link`, `current_exe` and `canonicalize` reach `readlink` or musl's `realpath` (`sys/fs/unix.rs:1914`), never `readlinkat` with a descriptor | `readlinkat.lo`: 267 / 78, the dirfd sign-extended and otherwise unchanged, no fallback (the evidence next to R40) | under v4 allowed when the dirfd's low 32 bits are non-negative, killed for `AT_FDCWD` (both encodings) and every negative descriptor; the gate's one call is `Dir::read_link` on its retained peer process directory (R79) |
| `uname`, `membarrier` | no caller in `library/std/src` | `uname.lo`: 63 / 160; `membarrier.lo` is the only member loading 324 / 283 | killed; refused by name |
| `File::set_len`, `set_permissions`, `set_times`, `set_modified` | `fs.rs:1115`, `:1215`, `:1262`, `:1271`; `sys/fs/unix.rs:1463-1466` (`ftruncate`), `:1553-1555` (`fchmod`), `:1617` (`futimens`) | `ftruncate.lo`: 77 / 46; `fchmod.lo`: 91 / 52; `utimensat.lo`: 280 / 88 | killed; refused |
| `io::copy` between descriptors | `io/mod.rs:314` (re-exported from `alloc`'s io); `sys/io/kernel_copy/linux.rs:72-77` (the `File` specialization), `:295-332` (`copy_file_range`, then `sendfile` or `splice`), `:696-733` | `copy_file_range.lo`, `sendfile.lo`, `splice.lo` | killed; refused |
| `is_terminal` (`IsTerminal`) | `io/stdio.rs:1250` (the trait), `:1265` (`File`, the std streams and their locks), `os/fd/owned.rs:254` (`BorrowedFd`, `OwnedFd`); `sys/io/is_terminal/isatty.rs:5`: `libc::isatty` | `isatty.lo`: `ioctl` (16 / 29) with `TIOCGWINSZ` (0x5413) | killed; refused by the post-seal tripwire (HE-002S PR review round 1, R1-2) |
| `Debug` of a `File` | `fs.rs:1300` (std's `File` formats its inner file); `sys/fs/unix.rs:1771-1777`: `debug_path_fd` (`:286-315`), whose `get_path_from_fd` (`:317-322`) reads the link `/proc/self/fd/N` with `readlink` (`:1914`) | `readlink.lo`: 89 / 78 | killed (under v4 on aarch64 by the `AT_FDCWD` argument). `gate-sys`'s `Dir` (`openat.rs:105`) and `effect-gate`'s `FileStores` (`file_store.rs:105`) derive `Debug` over a `File`; no non-test source formats one today. Not on the post-seal list: carried to HE-003 (no `{:?}` of either after the seal, or a `Debug` impl that does not format the `File`; R1-2). Since HE-003A: both have manual impls, and `derive(Debug)` over a `File`-holding type is refused by the gate; direct formatting stays code review's (R38) |
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

Note (HE-003A3, Q-HE4-13 (a), 2026-10-16): Q-HE2S-10 (a)'s source for the broker's artifact identity, the observer's
native-profile record (HE-004), was superseded by HS43 §4.3: the broker's identity follows from its label, and HE-004
provides none. The quote above stays as given; `substrate.rs`'s module text says so now (`peers.rs`'s replaceable
expected-peer constants concern Q-HE3A-3, not the broker's identity, and are unchanged).

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
| R36 | The liveness argument (A6): SO_PEERPIDFD gives a pidfd for the struct pid the kernel recorded at `connect`, with no window between the credentials and the pidfd; the `/proc/<pid>` directory opened by number names whatever process held that number at the open; the pidfd not having fired after the open proves the recorded process was still alive then, so the directory is that process's, and it stays bound to it (after the process is reaped, reads through it fail and never reach a process that reused the number). A frame read after its sender exited therefore fails the retained directory's reads (once the sender is reaped) or the pidfd probe (the pidfd fires at the exit), whatever pid its credentials carry, even the qualified number reused by another process (the argument does not rely on the pid the kernel reports for an exited sender; T04 may confirm the reported value): a broker that exits with a frame unread ends the channel fatally, never orderly (under lockstep it never does). A pidfd `ppoll` error, POLLERR or POLLNVAL counts as an exit (a deviation). HE-003A2 (R79, D1-11): the writer's `exe` link is read at check time through the same bound directory, after the label and uid comparison and before the probe, on accept and on every I07 frame, so the argument covers that read too. An exec by the holder keeps the pid and changes the link (and, on a domain transition, the label): caught on that frame. A zombie or reaped writer gives an error or an empty link (refused), and the pidfd then reports the exit. An exec away and back between a frame's send and its check is not seen by the check: it is bounded by matrix v5's `execute_no_trans` closure for `planeon_policy_writer_t` and the writer's no-exec duty (O-W03-WRITER-EXE). Replacing the binary under the same path is caught only through the kernel's rendering of the link (`" (deleted)"` or the new name): R37's residual | DESIGN §3, §4.2, §4.3 |
| R37 | The I07 custody gap: until the writer's executable check lands (owner decisions Q-HE3A-1 (c) and Q-HE3A-1b (a), below; decided, open), the writer is bound by the per-frame process label, cgroup, pidfd and start time, SO_PEERCRED and the per-frame credentials, while I07 v1 Channel 2 names the enrolled artefact. No HE-003A code reads a peer's executable. **Closed by HE-003A2** (R79-R83): the gate reads the writer's `exe` link with `readlinkat` on the retained process directory, on accept and on every I07 frame, and requires byte-exact equality with the enrolled path of the signed configuration (format v2); a failure at accept closes the connection unfed (R32), during a session it is N12. Residual: the check binds the path name the kernel renders for the running image (relative to the gate's root, through the writer's mount tree, symbolic links resolved, `" (deleted)"` after an unlink), not the file's contents; the fs-verity digest is enforced at enrollment (HS43 §4.3, `HOST_INTERFACE_SPEC.md:321-324`), and the conditions under which the enrolled path renders as itself are HE-007's and HE-008's (carried in the HE-003A2 section) | DESIGN §1, §4.3 |
| R38 | `Debug` and descriptors: `gate-sys`'s `Dir` and `effect-gate`'s `FileStores` have manual `Debug` impls (the type name; for `FileStores` also the generation), and `Listener`, `Conn`, `PidFd`, `Poller`, `ProcDir` and `SockCreate` print their type name only. `tools/gate.py` refuses `derive(Debug)` (also under `cfg_attr`) on a struct or enum of the linked crates whose field types mention `File`, `Dir`, `FileStores`, `Conn`, `Listener`, `Poller`, `PidFd` or `ProcDir` (field and variant names are not types); manual impls, direct formatting (`{:?}`, `expect_err`, `assert_eq!`) and a derived generic type instantiated with a hazard type (`#[derive(Debug)] struct Wrap<T> { inner: T }` used as `Wrap<File>`) are code review's. HE-003A2 (D1-10): for `Debug` of a std `File` this means the derive over a `File`-holding type is refused by the gate, and direct formatting stays code review's | DESIGN §8, A10 |
| R39 | Refused by the linked-source tripwire: a top-level std group or glob (`std::{..}`, `std::*`) and a nested std glob (`std::…::*`, as `std::io::prelude::*`), with the renames and the globs through a name imported from std (HE-002S PR review R1-2 and R2-1). Left to code review, besides the forms listed in the HE-002C and HE-002S sections: type aliases (`type F = File;`, for the `Debug` rule too) and qualified paths such as `<T>::f` (HE-002C PR review round 3, R3-3) | DESIGN §8 |
| R40 | musl's `accept4` falls back to the killed `accept` on EINVAL or ENOSYS (`accept4.lo`), so the gate issues `accept4` through `syscall` (288 on x86_64, 242 on aarch64) and never calls musl's `accept4`; musl's `socket` retries without the flags and then uses `fcntl` (allowed), and `epoll_pwait` falls back to `epoll_wait` only on ENOSYS (A14). HE-003A2 (D1-6): musl's `readlinkat` has no fallback, so `Dir::read_link` calls the wrapper itself (no `syscall` branch, so no new FOREIGN_ITEMS symbol beyond `readlinkat` and no Linux-only constant). Evidence, from the pinned `libc.a` read-only (members extracted with a stdlib `ar` reader, disassembled with the Command Line Tools' `llvm-objdump -dr`): `readlinkat.lo` (x86_64 member sha256 `e1da195a75319090…`, 3744 bytes; aarch64 `32cee367bb6a4383…`, 3784 bytes) sign-extends the dirfd and passes it otherwise unchanged (`movslq %edi,%rdi` / `sxtw x0, w0`), issues 267 (`movl $267,%eax; syscall`) / 78 (`mov x8, #78; svc #0`) and returns through `__syscall_ret`: no `AT_FDCWD` substitution, no call of `readlink`, not a cancellation point; a size of 0 is replaced by a 1-byte stack buffer whose positive count is returned as 0, a path `read_link` never takes (it refuses an empty buffer before the call). `readlink.lo` issues 89 on x86_64 and, on aarch64, 78 with `x0 = -100` (`AT_FDCWD`), which v4 kills by its argument | DESIGN §2, §3 |
| R41 | A bound run with no lifetime in the `Lifetimes` input, and a realtime clock that cannot be read, expire at once (`Expire` at the next check; fail closed). A backward step of the realtime clock never fires the expiry early, a forward step is acted on within the 1-second cap and before the next frame or request | DESIGN §5.6 |
| R42 | The journal file's decoder (`frame.rs`) knows `ANSWER_LATE` among the fatal reasons, so `["INVALIDATED", "ANSWER_LATE", "HELD"]` reads back as written after a process restart (not TORN), the restart is HELD, the state the record names, and the reopened journal's digest, over the records before the restart's own RESTARTED record, equals the digest before the restart (reworded by HE-003B: HE-003A PR review round 3, R3-1; `tests/answer_late.rs` digests the records before RESTARTED). `frame.rs` joined HE-003A's paths for this (the design's path list was amended after the build) | DESIGN §10 (amended) |

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
- **Closed by HE-003A2** (R79-R85; HE-007's obligations (a)-(c) below stay carried, with the rest of the HE-003A2
  section's carried list). The writer's executable check (Q-HE3A-1 (c), Q-HE3A-1b (a); decided, open), after the chain the owner set: (1) a
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
- Refinement of the HE-008 item above, which stays as history (HE-004B1, from the owner's decision "systemd cleans" and the lane monitor's Q-SOL-7 (a), both 2026-10-17):
  `RuntimeDirectory=` removal is per unit and not reference-counted, so a listener unit with
  `RuntimeDirectoryPreserve=no` would remove the other roles' live sockets in the shared directory. Instead a
  separate directory unit, ordered before the listeners and pulled in by each (`After=` and `Requires=` on it; ordering
  alone does not start it), owns `/run/planeon/live-proxy` (`RuntimeDirectory=`, `RuntimeDirectoryPreserve=yes`,
  mode 0700) and the gate's, broker's and observer's units do not list it; each
  listener unit removes only its own socket path in `ExecStartPre=` (`rm -f`), running as `init_t` under the grant
  the owner put into the matrix successor ("Into matrix v6"); `/run/planeon/maintenance` (I07, the gate only)
  follows the same pattern or is owned by the gate's unit alone; file contexts label `/run/planeon` and both
  subdirectories `planeon_run_t`. Every role still binds after its seal and never unlinks. T04's restart after a
  crash then checks the pre-start removal (as `init_t`, no transition) instead of empty runtime directories.
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

## HE-003B: the I04 TLS 1.3 mutual server (crate `gate-tls`; `effect-gate`: `net`, `linux_net`; `gate-sys`: `tcp.rs`, `inet.rs`)

HE-003B (design revision 3, sha256 `4274603c…`, with its build amendments §17 (Q-HE3B-26 (a)), §18 (Q-HE3B-27 (a)), §19
and §20; design review round 2 PASS_FOR_BUILD) builds the I04 server half of I05-3 and HI-10's connection stamping
C1-C7: the gate's KUBERNETES_API_PROXY listener (TLS 1.3 with mandatory client certificates), HTTP/1.1 framing that
hands the model the exact head, the body digest and the client certificate digest, and the exact rendering of the
response the I04 client receives. It is a library: `gate_tls::I04Server<N: StreamNet>` is the substrate's `I04Port`; no
binary links it yet (HE-003D), so the ten binaries and SBOMs are unchanged. HE-003C builds the upstream half.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R43 | Stamp at accept: every `accept4` on the I04 listener (at most 64 per readiness, and in the drain before every I05 frame) feeds `Backlog` and then `Accept` for the new connection before any TLS byte is read, so its stamp is the action armed when the kernel connection was accepted. The drain accepts until the queue is empty; if it cannot (an accept error other than EAGAIN, EINTR, ECONNABORTED and the TCP network errors, or more than 1,024 accepts in one drain), the loop stops with `LoopExit::Port` before the frame is fed. Over-cap connections drained before a frame are closed unfed. Residual: a connection that completes its TCP handshake after the drain and before the ARM record is accepted later with the new stamp; it cannot carry a buffered stale request, because with TLS 1.3, no early data, no resumption and no server-side TCP Fast Open (the listener sets none; HE-008 keeps the kernel's off) no request byte precedes the gate's handshake flight, which follows the accept. A request on it is a new send by the server, the resolved spec's §6.3 residual. A sustained connect flood during a pre-frame drain ends the generation: the loop stops, HE-003D exits, the restart is deny-first and the generation's single I05 channel is spent (fail closed; under the loopback-or-firewall assumption, HE-008; T04 measures it). Connection names are `i04-<n>`, never reused within a process | C2, C3; DESIGN §4.2, §6.3, §7.1 |
| R44 | `Event::Disconnect { conn }` (R10-defined): fed only when the I04 port closes, on its own, a model-held connection on which it fed no request (TLS refused, a deadline, an oversize head or a truncated request, EOF or reset, no client certificate). The model removes that connection's entry; no counter changes and nothing is journalled; output nothing. A connection the model closed itself (a flush, a deny) is closed by the port without a `Disconnect` and stays as a CLOSED entry, at most the 16-connection cap per flushing event; the model rule still accepts a closed entry with no request (a defensive branch the port never reaches). An unknown connection, or one with a request, is `EventError` (R3) | DESIGN §4.3; Q-HE3B-14 |
| R45 | At most 16 I04 connections are held; one accepted beyond that is closed at once and never fed: it has no stamp and never reaches TLS. Network exposure: the listener is meant for a loopback address or a firewalled one (HE-008); on a routable address mTLS, the cap, the accept bounds and the deadlines are its only protection. Under either assumption a sustained connect flood during a pre-frame drain ends the generation (fail closed, R43), which T04 measures | DESIGN §7.1, §7.4; Q-HE3B-21 |
| R46 | The TLS profile: TLS 1.3 only (no other version compiled in: gate-tls's registry lines are pinned and the gate refuses any member's `[features]` table, PR review R1-3); client authentication mandatory against the configured DER trust anchors, no CRLs; no session storage, no tickets, so no resumption; no early data and no half-RTT data; ALPN `http/1.1` only (a client offering none proceeds); the three TLS 1.3 suites and X25519, P-256, P-384 of the ring provider, set explicitly; no key log, no secret extraction; the server key PKCS#8 DER only. One builder serves production and the tests: `ServerConfig::builder_with_details(provider, time)` takes the time provider as an argument (§20) | C1; owner decisions Q-HE3B-5 (a), Q-HE3B-6 (a); Q-HE3B-20 |
| R47 | The certificate digest fed with a request is `sha256:` and the lowercase hex SHA-256 of the client's leaf certificate DER, as presented in the handshake that verified it; the model compares it with the run's `serverCertificateDigest` | C4; Q-HE3B-15 |
| R48 | Request framing: the head is the bytes through the first CRLF CRLF, at most 16,384; the body length comes from exactly one `Content-Length: <canonical decimal ≤ 16384>` line, or is zero with no length line (then the body digest is absent); any other length or Transfer-Encoding line makes the head unframeable, and it is fed at once without a body digest, so the model refuses and counts it. A head that is not UTF-8 is fed lossily. An oversize head, and a framed head whose body is truncated by the deadline, EOF or a reset, are refused as `Disconnect` and not counted (no request reached A1). This is the gate-side reading of MET-REPAIR-009's refusal of surplus and truncated data (:157-161). A manifest larger than 16,384 bytes can never be forwarded (HE-003D refuses one in the configuration) | I05 v3 Decision 4; MET-REPAIR-009 :157-162; Q-HE3B-25 |
| R49 | One request per connection: after the request is fed the port never gives the connection's bytes to rustls again; bytes after the request's end are discarded unparsed, and the connection closes after its one response (MET-REPAIR-009 :157-161, surplus data, read on the gate's side) | C1; Q-HE3B-17 |
| R50 | Deadlines on the monotonic clock: the handshake within 10 s of accept, the whole request within 10 s of the handshake, the relay and its linger within 10 s of the relay's start. A missed deadline closes the connection (`Disconnect` before a request; nothing after it). The upstream bound is HE-003C's | MET-REPAIR-009 :162-166; Q-HE3B-16, Q-HE3B-19 |
| R51 | Closing: a refused request gets TLS `close_notify` and no HTTP byte; a connection the model holds closed closes at the next sync, exactly once, except one relaying or lingering after its response; an upstream outcome that is not relayed (lost, timed out, aborted, late) closes the consumed connection without a byte; a client gone while its request is in flight is closed and its relay skipped. After a relayed response the gate sends `close_notify`, shuts its write side once rustls has nothing left to write (at the deadline it closes without), and reads and discards until EOF or the deadline within the per-wake read budget, so a client's unread surplus cannot turn the close into a reset that destroys the response | I05 v3 Decisions 1, 6, 12; HE-002B R1-1's I04 analogue; Q-HE3B-17, Q-HE3B-18 |
| R52 | The response rendering: `HTTP/1.1 <status> <reason>`, `Content-Type: application/json`, `Content-Length` (none for 204 and 304, which need an empty body), `Connection: close`, then the body unchanged; status 200-599; reason from a closed table of RFC 9110 §15's registered phrases, else empty; body at most 4,194,304 bytes; no upstream header is relayed; a status or size outside these closes without a byte | MET-REPAIR-009 :157-162; DESIGN §6.2 |
| R53 | The exchange board: the request staged when it is fed (an occupied slot is a port failure), confirmed by `Forward`, dropped by `Close`. The response is staged only through `stage_response`, which computes the body digest and builds the `UpstreamResponse` event from the staged status, digest, UID and resourceVersion, so the values the model journals are those of the bytes relayed. The I04 port relays it only on `Upstream { relayed: true }`, after checking that it names the connection in flight and that the body hashes to the staged digest; every `Upstream` output and `LateUpstream` remove it; at most one of each at a time | I05 v3 Decisions 1, 2; DESIGN §7.5 |
| R54 | Vendored crates (rustls 0.23.46, ring 0.17.14 and their closure) are outside the lexical tripwires and pinned file by file by the vendor table. gate-tls's own sources pass the TLS deny-list, matched case-sensitively and tolerant of whitespace around `=`, `(` and `::`, over the raw text (no `KeyLogFile`, `SSLKEYLOGFILE`, `KeyLog`, `key_log`, PEM reader, process-default provider or default-provider builder (`::builder(` and `builder_with_protocol_versions`; PR review R1-2), `danger` module, unauthenticated or no client authentication, session cache, `Ticketer`, secret extraction) and, read with comments removed, set `max_early_data_size = 0`, `send_tls13_tickets = 0`, `send_half_rtt_data = false` and `NoServerSessionStorage` exactly once, and `tls.rs` names `with_cert_resolver(` and `SingleCertAndKey::from(` exactly once each (§20). The build's inventory of the std paths and libc calls the 11 linked crates name, with each occurrence's reachability from gate-tls judged by hand from its rustls entry points, is recorded below; it is a review record, and T04's trace is the proof. Their run-time system calls on the gate's paths are `getrandom` and `clock_gettime` beside memory allocation. HE-003D adds a symbol inventory of the binary with justified exceptions | DESIGN §2.6, §2.9; G4, G10 |
| R55 | getrandom's file fallback is compiled out (`linux_disable_fallback`); the gate's randomness is the `getrandom` system call only, flags 0 | Q-HE3B-12 |
| R56 | Port failures: a port's `failure()` stops the loop with `LoopExit::Port(owner, reason)` after the event, call or wake step that set it: checked after every event's output has been applied, wired and synced, after every port call, and before every wait; before a drained I05 frame is fed. HE-003D exits the process, and the restart is deny-first | DESIGN §4.2; Q-HE3B-13 |
| R57 | Model-held connections: an accepted I04 connection counts as held by the model from the first sync that sees it open (the sync right after its `Accept`); the port's sync never closes a connection before that, and a wake that ends with one unconfirmed stops the loop. A `Fed` connection the model closes before its request is processed (an expiry fed first) is closed once and its request is refused CONNECTION_CLOSED | DESIGN §7.2; Q-HE3B-24 |
| R58 | The server key: `TlsServerInputs` holds it in `Zeroizing`, so every drop path clears it; the key is consumed first, moved (not copied) into rustls, whose ring provider zeroizes its own parsing copy; `TlsServerInputs` prints lengths only, and `derive(Debug)` is refused on it and on rustls's key and configuration types; gate-tls never formats them. Residual: ring's parsed key pair keeps the key for the process's life without zeroization; the gate dumps no core (RLIMIT_CORE 0/0) though it stays dumpable by design (Q-HE2S-7 (a)), and selinux-matrix-v2 assertion A34 (no domain ptraces `planeon_gate_t`) bounds live-memory reads | DESIGN §5.1, §20; D1-4 |

### Code and audit

- `gate-sys/src/tcp.rs` (Linux only; with `openat.rs`, `seal.rs` and `channel.rs` the only places of the workspace that
  may hold `unsafe`): one private `unsafe extern "C"` block declaring exactly `socket`, `setsockopt`, `bind`, `listen`,
  `recv`, `send`, `shutdown` and `syscall`, each call in its own `unsafe` block with its own `// SAFETY:` argument behind
  `listen_tcp` (port ≥ 1024 checked before any call; `SO_REUSEADDR`; `IPV6_V6ONLY` for IPv6; the exact address length;
  no other TCP option), `accept_tcp` (`accept4` through `syscall`, no peer address; EAGAIN empty, EINTR retried,
  ECONNABORTED and accept(2)'s network errors skipped, anything else a failure), `TcpConn::recv` (an empty buffer
  refused before the call), `send` (`MSG_DONTWAIT|MSG_NOSIGNAL`) and `shutdown_write`. `TcpListener` and `TcpConn` hold
  an `OwnedFd`, print their type name only, and give `channel.rs`'s poller the descriptor through a crate-private
  accessor (`Watched::TcpListener`, `Watched::TcpConn`: the only change to `channel.rs`). Compile-time asserts cover
  `sockaddr_in` (16/4; port at 2, address at 4) and `sockaddr_in6` (28/4; flowinfo 4, address 8, scope 24), checked by
  both musl release builds. `gate-sys/src/inet.rs` (portable, no `unsafe`) parses the literal authority (`a.b.c.d:port`
  or `[v6]:port`, RFC 4291 text forms, no zone, port 1-65535, at most 64 characters), host-tested.
- `effect-gate`: `net.rs` (portable) defines `StreamNet` (listener, accept, recv, send, `shutdown_write`, close,
  monotonic). `linux_net.rs` (Linux only) is the single-threaded stream table (`NetTable`, `SharedNet`) with source
  numbers never reused, `NetTable::listen_i04(&net, &Sealed, &address)` (backlog 16) and `LinuxStreams`; every
  `RefCell` borrow is a `try_borrow`. `LinuxOs::with_net` resolves a port's `SourceId` through the table and refuses one
  another owner holds; `LinuxOs::new` still refuses every port request. `Event::Disconnect` (R44), the provided
  `Port::failure` and `LoopExit::Port` (R56).
- `gate-tls`: `tls.rs` (`TlsServerInputs`, `server_config`, `certificate_digest`), `http1.rs` (`frame`,
  `render_response`), `exchange.rs` (the board) and `i04.rs` (`I04Server`). The root forbids `unsafe_code`.
- `tools/gate.py`: `check_cargo_config` (formerly `check_linker`: exactly `[net]`, `[target]`, `[source]` and `[env]`,
  `[env]` derived from `toolchain.json`'s `cToolchain`); the Command Line Tools' clang version and SDK, the pinned
  compiler and archiver, `xcode-select -p` and the first `cc` and `ar` on `PATH` as failing checks; `check_vendor`
  against the vendor table (`VENDOR_TABLE_SHA256`); `check_workspace` admitting gate-tls's three exact registry lines
  only and a lock whose registry packages are exactly the table's rows with their checksums and dependency lists, no
  `[patch]` or `[replace]`; `check_workspace_shape` over effect-gate's and gate-tls's closures; `tcp.rs` among the files
  allowed `unsafe` and `std::os::fd` items, with its eight foreign items; `TcpListener`, `TcpConn`, `NetTable` and the
  secret types in the `Debug` rule; `check_tls` (the deny-list and the exactly-once settings); `vendor/` skipped by the
  source scans; the SBOM rule for vendored components (none until HE-003D links gate-tls). `tools/test_gate.py` has a
  case per rule.
- Departures from the design, each within its intent: `StreamNet` gains `shutdown_write` (§7.1 needs it; §4.1 listed
  the other six methods); `NetTable::listen_i04` returns the listener's source; the substrate checks `failure()` after a
  `due` or `ready` call before feeding that call's events (as it does for the drain); the early-data test leg uses a
  test configuration with stateful tickets, because rustls 0.23.46 offers early data only with stateful tickets
  (`server/tls13.rs:669-671`); the port-failure tests reuse HE-003A's unchanged `substrate_support` module rather than
  a copy; the restart case of `i04_substrate.rs` uses the in-memory `GATE_RESTART` (deny-first) rather than a file-store
  `PolicyGate::open`.

### Vendored crates

The vendor table `host-enforcement/licenses/vendor-crates.json` (schema `planeon.internal.he-vendor-table/v1`, sha256
`32a6dc79a8bf47e04032b245cf2c6364e328074f3e81a2e2a3ee76f4fc19602e`) has 25 rows: 11 LINKED (cfg-if, getrandom, libc,
once_cell, ring, rustls, rustls-pki-types, rustls-webpki, subtle, untrusted, zeroize), 3 BUILD_HOST (cc, find-msvc-tools,
shlex), 11 LOCK_ONLY stubs (windows-sys, windows-targets, eight `windows_*`, wasi); 1,297 files. Each row records the
approved sha256, size and URL, the licence and its classification, the licence files, whether a build script exists,
the non-UTF-8 files (ring 32, rustls-pki-types 17, rustls-webpki 3; found by decoding), the suffix inventory, the
C-family, assembly and perl files (ring 176; cc's two compiler probes, §19), the file count, the tree digest and the
lock dependency list; ring's row also records the files its build script compiles (30 on x86_64, 24 on aarch64) and
the files they reach. Build scripts: libc, ring, rustls among the linked and build-host crates; the eight `windows_*`
stubs keep their `build.rs` (named by their manifests, never compiled for our targets). The stub rule (Q-HE3B-8 (a)):
`Cargo.toml`, the licence files and every file the manifest names kept byte-identical (45 files: the eight `build.rs`,
windows-sys's and windows-targets' `readme.md`, wasi's `README.md`, the manifests and licences), the library file empty,
284 files dropped; the rows list kept and dropped paths with their sha256. Five vendored crates ship a `.gitignore`
that hides five vendored files from `git add` (the `Cargo.lock` of cc, cfg-if, once_cell and shlex, untrusted's
`Cargo.toml.orig`); they are committed and pinned like every other file (§19). The first, full-form zero-bill scan's
hits (`(?i)LoadBalancer`, three files of windows-sys) are only in files the stub rule drops (§17); command 4 passes over
the committed tree. Custody is `UPSTREAM_PINNED` keyed by the crate sha256 (§2.8); `PORTING.yaml` stays the sentinel.
The C toolchain is the Command Line Tools' clang 14.0.3 and `ar` (`toolchain.json` `cToolchain`, a failing pin).

### Build confirmations (B6) and the inventory (B7)

- getrandom 0.2.17: `linux_disable_fallback` selects `linux_android.rs`, not the fallback (`src/lib.rs:261-305`); the
  call is `syscall(SYS_getrandom, buf, len, 0)` (`src/util_libc.rs:151-160`).
- rustls 0.23.46's ring provider: the three TLS 1.3 suites and X25519, P-256, P-384 (`src/crypto/ring/mod.rs:72-76,
  180-181`). `ServerConfig`'s defaults (`src/server/builder.rs:106-130`): an in-memory session cache under `std` and
  two tickets, both overridden; the never-producing ticketer, no early data, no half-RTT data, `NoKeyLog`, no secret
  extraction, no certificate compression without its features (`src/compress.rs:50-82`).
- The key is checked against the leaf by rustls itself (`CertifiedKey::from_der` → `keys_match`,
  `src/crypto/signer.rs:159-200`); ring's RSA, ECDSA and Ed25519 signing keys give their public key
  (`src/crypto/ring/sign.rs:130, 296, 392`), and the seed-only Ed25519 PKCS#8 form is accepted (`:364-377`), so the ring
  dev-dependency fallback of §9 was not needed.
- ALPN without overlap: a fatal `NoApplicationProtocol` alert; no ALPN offered: the handshake proceeds
  (`src/server/hs.rs:98-119`). `handshake_kind()` (`src/common_state.rs:188, 856`).
- pki-types 1.15.1 has no drop-zeroize (an explicit `Zeroize` only, `src/lib.rs:138, 331, 398, 466, 1050`); §20 holds
  the key in `Zeroizing` and hands it to rustls first. ring's key pairs do not zeroize. rustls's `Debug` impls print no
  key bytes (`ServerConnection` its name only; the ring signers their algorithm).
- Host-test outcomes: a serverAuth-only client leaf is refused `InvalidPurposeContext { required: ClientAuth, presented:
  [ServerAuth] }`; a `cA=true` client leaf `CaUsedAsEndEntity`; a TLS 1.2-only ClientHello
  `PeerIncompatible(SupportedVersionsExtensionRequired)` with an alert; a PSK offer gets a full handshake; offered early
  data is skipped and the handshake is full (none accepted or delivered).
- The R54 inventory (50 occurrences in the 11 linked crates' `src/`): only getrandom's `syscall(SYS_getrandom, .., 0)`
  is reached. Not reached: getrandom's `libc::open` (`use_file`, not compiled) and its `getrandom.rs`/`solaris.rs`;
  libc's Apple-only `spawn` re-exports; once_cell's test-only `spawn` (rustls uses `race::OnceBox` only);
  rustls's `key_log_file.rs` (`KeyLogFile`, refused by the deny-list), `stream.rs` and `message_test.rs` (tests) and
  the aws-lc-rs `hpke.rs` (not compiled); pki-types' PEM file reader (refused) and its `std::net` server-name
  conversions (a server builds none); webpki's test-only `ip_address.rs:678`.

### Constants and their evidence (for T04)

From the pinned musl 1.2.5 `libc.a` (x86_64 sha256 `e699c64b…`, aarch64 `b03473b6…`; llvm-objdump with relocations):

| Constant | x86_64 / aarch64 | Evidence |
|---|---|---|
| `recv` | `recvfrom` 45 / 207 | `recv.lo` zeroes the address arguments and jumps to `recvfrom`, which passes 45 / 207 |
| `send` | `sendto` 44 / 206 | `send.lo` likewise to `sendto` |
| `shutdown` | 48 / 210 | a direct system call |
| `AF_INET` | 2 | `res_msend.lo` (`__res_msend_rc`) calls `socket(2, 0x80802, 0)` with a 16-byte address |
| `AF_INET6` | 10 | `res_msend.lo` sets family 10 with a 28-byte address |
| `SOCK_STREAM` | 1 | `res_msend.lo`'s TCP fallback calls `socket(family, 0x80801, ..)` |
| `IPPROTO_TCP` | 6 | `res_msend.lo` calls `setsockopt(fd, 6, 30, ..)` |
| `IPPROTO_IPV6`, `IPV6_V6ONLY` | 41, 26 | `res_msend.lo` calls `setsockopt(fd, 41, 26, ..)` |

From the kernel UAPI (T04 confirms): `SOL_SOCKET` 1, `SO_REUSEADDR` 2 (the generic `socket.h`); `SHUT_WR` 1
(`linux/net.h`); errno (the generic `errno.h`): EINTR 4, EAGAIN 11, EINVAL 22, ENONET 64, EPROTO 71, ENOPROTOOPT 92,
EOPNOTSUPP 95, ENETDOWN 100, ENETUNREACH 101, ECONNABORTED 103, EHOSTDOWN 112, EHOSTUNREACH 113. Already recorded by
HE-003A: `socket` 41 / 198, `setsockopt` 54 / 208, `bind` 49 / 200, `listen` 50 / 201, `accept4` 288 / 242,
`SOCK_NONBLOCK` 0x800, `SOCK_CLOEXEC` 0x80000, `MSG_DONTWAIT` 0x40, `MSG_NOSIGNAL` 0x4000.

### Carried

- HE-003C: the upstream TLS client and its port; Decision 12's 900-second bound and I07's 10-second write bound as real
  deadlines; typed upstream responses (R12, R15, HE003-REQ-1); R1-4 (`gate_sys::inet` is there for it); `connect` on
  the stream table; the board's upstream side (take a staged request only when confirmed with the `Forward`'s action
  ID; build `UpstreamResponse` only through `stage_response`, which a lexical rule can keep to `exchange.rs`); the TLS
  deny-list's scope for client code (`danger`, `with_no_client_auth`; D2-2).
- HE-003D: `planeon-gate`'s `main`, the seal call site and the composition (`NetTable::new`, `listen_i04`,
  `LinuxOs::with_net`, `I04Server::new`); the configuration items (the I04 authority, the server chain and PKCS#8 key,
  the client CAs, all DER) and a manifest larger than 16,384 bytes refused; the key file's read-buffer hygiene; the
  deny-list and the secret-type rule over the gate binary's sources, with rustls's default time provider passed there;
  the symbol inventory of the binary; the vendored components in `planeon-gate`'s SBOM (§13.1 (ii)); and the
  vendored-source-path residual (§18, Q-HE3B-27 (a)): after `strip = "debuginfo"` the panic locations of the vendored
  crates keep their absolute source paths, so `check_binary` would refuse `planeon-gate` once it links `gate-tls`
  (choices: workspace path dependencies, `--remap-path-prefix`, or a reviewed gate exception).
- T04: the listener under the installed EFFECT_GATE filter (`socket`, `setsockopt`, `bind`, `listen`, `accept4`,
  `recvfrom`, `sendto`, `shutdown`, `close`), IPv4 and IPv6, `SO_REUSEADDR` after a crash; the real I04 client
  completing TLS 1.3 with its run certificate (ECDSA or RSA) and reading the rendered response, also after surplus bytes
  (no reset); the deadlines in real time; `getrandom` and `clock_gettime` under the filter and no blocking at start; C2
  and C3 under load and restart with the kernel's server-side TCP Fast Open off; the I05 answer bound with I04 traffic
  and under a connect flood; the constants above; the steady-state trace (no killed call reached by vendored code).
- HE-008: `planeon_gate_t`'s `tcp_socket` permissions, `name_bind` on `planeon_i04_port_t` and `node_bind` on the
  signed address's node type; `planeon_server_t`'s `name_connect` as the only local connector; the I04 port outside
  `net.ipv4.ip_local_port_range`; a loopback I04 address or a host firewall admitting only the server; the kernel's
  server-side TCP Fast Open bits off; `LimitNOFILE` headroom; the I04 server credential's files (root, 0400) and their
  SELinux type (the matrix names none: `planeon_gate_effect_cred_t` or a matrix amendment; §13.2).

### Owner decisions (verbatim as relayed, dated)

- 2026-10-14 (APPROVAL.md §4): Q-HE3B-1 = (a): download all 25 crates (11,430,251 bytes: the 14 used plus the 11 Windows/wasi ones never compiled) from static.crates.io/crates/<name>/<name>-<version>.crate, each verified against its sha256 in APPROVAL.md. Unauthenticated, generic UA, no personal data, no token; abort on any size or sha mismatch. The design decides vendored-as-is versus stubs for the 11. Q-HE3B-2 = (a): rustls 0.23.46. Q-HE3B-3 = (a): Command Line Tools clang 14.0.3 plus ar through the repository's [env], with a failing version pin in toolchain.json and the gate; no download, no root change. Q-HE3B-4 = (a): the x86_64 no-libc-headers flag line. Q-HE3B-5 = (a): TLS 1.3 only for HE-003B and HE-003C. Q-HE3B-6 = (a): DER-only CA input.
- 2026-10-14, on design revision 2 (sha256 `8bf0acb6…`): "Accept all recommended": Q-HE3B-7..Q-HE3B-25 = (a), including the reviewer-amended Q8, Q13, Q14, Q17, Q21 and Q22 and the new Q24 and Q25, and §13 (i) = yes (the sysroot closure table stays byte-identical and the crates get a separate vendor table); (ii) noted (SBOM evidence for the crates comes with HE-003D).
- 2026-10-14: "Q-HE3B-26 = (a): B1 is judged on the tree as it will be committed. GO to resume phase 1 in this order: 1. B3: build the stubs. 2. Re-run command 4 (ci/zero_bill_scan.py) over that exact committed tree. It must pass with zero hits. Any hit stops the build and comes back to me. 3. B2: the ring probe. Then stop and report. No ci/ change."
- 2026-10-15: "Q-HE3B-27 = (a): carry the host-path choice to HE-003D's design, and keep DESIGN §18 as written."
- Build amendments 3 and 4 (§19, §20) are the author's design-level amendments (cc's two compiler probes and ring's
  polyfill licences; who zeroizes the server key); they narrow nothing the owner decided.

## HE-003C: the upstream apiserver client (crate `gate-tls`: `upstream`, `tls_client`, `http1`'s client side, `exchange`; `effect-gate`: `net`, `linux_net`, `substrate`, `policy_gate`; `gate-sys`: `tcp.rs`)

HE-003C (design revision 2.1, sha256 `184922d6…`; design review round 2 PASS_FOR_BUILD with D2-1..D2-3 applied; owner
decisions Q-HE3C-1..7, quoted at the end) builds the upstream half of I05-3 and I07-6: the effect gate's apiserver
client over TLS 1.3 with the gate's two client identities, the real I05 upstream bound (I05-2, Decision 12's 900
seconds) and the real I07 write timer (v3 W2's 10 seconds, N15), typed upstream responses (R12, R15, HE003-REQ-1: an
answer outside the I07 v3 patterns reaches the model as LOST), `apiserverAuthority` parsed as a loopback address (HE-002B
R1-4) and the board's upstream side (HE-003B D2-4). It is a library: `gate_tls::UpstreamClient<C: ConnectNet>` is the
substrate's `UpstreamPort`; no binary links it yet (HE-003D), so the ten binaries and SBOMs are unchanged. No pinned
model defines sockets, TLS or HTTP framing, so nothing in HE-003C is model-defined: its rules are R59-R68 below and the
R16 rewording above. No answer, record or vector changes; the only existing test touched is R16's unit test.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R59 | The exchange (one port for both channels, at most one exchange open): `apply` and `sync` return no events, so a start only arms. I05: on `Forward { action_id }` the board's staged request is taken only when it was confirmed with that action ID; verb, kind and name come from the staged head's method, resource plural and path, which the model already matched against the consumed action (Decision 4). I07: in `sync`, when `pending_write()` names a write the port has not started, from the provided `GateView::forwarded_write()` (None by default, so HE-003A's and HE-003B's fakes are unchanged; `PolicyGate`'s outstanding write keeps its `RenderedWrite`); operation, resource plural and name come from the rendered head. A missing or unconfirmed request, a head outside the rendered forms, a pending write without its rendered request, or a start while an exchange is open is a port failure (`LoopExit::Port`, R56). The bound is anchored at the arming call on the connector's monotonic clock: 900 s for I05, 10 s for I07. The anchor follows the CONSUMED or WRITE_FORWARDED record of the same delivery, so the bound runs at least 900 s (10 s) from consumption, never less (the excess is the apply latency, the millisecond rounding of the wait and the wake's work). A start deadline at the anchor makes the next wait zero; that `due` connects | DESIGN §2.1; D1-1, D1-11, D2-4 |
| R60 | Connect and I/O: `socket(AF_INET or AF_INET6, SOCK_STREAM|SOCK_NONBLOCK|SOCK_CLOEXEC, IPPROTO_TCP)` and one `connect` to the one loopback apiserver address (R16). EINPROGRESS waits for writability, then SO_ERROR must be 0; a return of 0 proceeds as connected; any other errno (ECONNREFUSED, EMFILE, EINTR: no retry), an error or hang-up readiness during the connect, or a non-zero SO_ERROR is exactly one LOST, fed from that `due` or `ready`. I05 has a connect and a handshake phase deadline of 10 s each (R10-defined, from the I04 phase limits); I07 has none (its 10-second bound covers them). The interest follows rustls's `wants_read` and `wants_write` (writable only while connecting), so level-triggered epoll never spins; at most 64 KiB is read per wake. After an outcome every deadline is cleared and the descriptor is only closed: closing removes it from epoll, and a closed source is never deleted from the poller (an explicit delete would fail on Linux and stop the loop). A readiness for a closed exchange's token, or another token, feeds nothing | §2.2, §2.4, §2.6; D1-9, D2-1 |
| R61 | Deadlines (R1-9): `due` checks the bound first; when it has fallen due, `UpstreamTimeout { conn }` or `WUpstream { Timeout }` is fed and the exchange closed, whatever phase deadline is due too (so a tie is a TIMEOUT); a phase deadline gives LOST only when it is strictly earlier than the bound. Deadlines are fed before reads in a wake; an answer completed later in the same wake (or in any wake past the bound) first re-checks the bound on the connector's clock: past it nothing is fed, the descriptor closes and the TIMEOUT follows at the next (zero) wait. HE-003A's ordering of the two ports' due events suits this port: its deadlines concern one exchange | §2.5, §2.8; D1-2 |
| R62 | Outcomes, exactly one per exchange: Response; LOST (a refused or failed connect, a reset, EOF before a complete answer, a handshake failure including a protocol other than TLS 1.3, a refused answer (R63), a final answer whose identity cannot be read where the model journals it (R65), a board Status or Size refusal); or TIMEOUT. Seal and session end: when the model no longer holds the I05 connection open (it sealed the consumed action, Decision 1) or the I07 write pending (session end), `sync` closes the exchange at once, clears its deadlines and feeds nothing (a TIMEOUT fed then would be an `EventError`). Because the port closes the exchange at its outcome or the seal (Decisions 1 and 12 and I07 v3 W2 require it), it never receives a later response: the model's LATE_UPSTREAM and WRITE_LATE_UPSTREAM records are unreachable from R10's port, consistent with the contracts | §2.6, §2.7, §2.9; D1-11 |
| R63 | The answer's framing (`http1::ResponseReader`, incremental): the status line exactly `HTTP/1.1 SP 3DIGIT SP reason CRLF`, status 100-599, the reason holding tabs, spaces, visible bytes and obs-text only; 100, 102 and 103 skipped (at most four), 101 and 104-199 LOST; all heads together (interim and final) at most 16,384 bytes; field lines `token ":" value`, names case-insensitive, no obs-fold, bare CR or LF, or control byte other than a tab; one `Content-Length` of 1-7 ASCII digits at most 4 MiB, or one `Transfer-Encoding: chunked` (case-insensitive), never both and never duplicated; `Content-Encoding` only `identity`; 204 and 304 without a body (a `Transfer-Encoding` or a non-zero length LOST); every other status needs a length or `chunked` (no body delimited by the close; Q-HE3C-4 (a)). Chunked strictly: sizes of 1-7 hex digits without extensions or whitespace, CRLF after each chunk, the zero chunk then CRLF (no trailers), decoded at most 4 MiB and raw (framing included) at most 4 MiB + 64 KiB, which assumes chunks of about 0.5 KiB or more for a body near 4 MiB (T04 confirms the selected apiserver's chunk sizes). Surplus: any byte after the complete answer in the same read is LOST; "the same read" is the plaintext drained after the one `process_new_packets` that completed the answer. The rule is best-effort: bytes after the answer's last read are never read, since the exchange closes at once; a server `close_notify` after the answer is not surplus, nor are TLS post-handshake messages. The I04 answer is always re-rendered by `render_response` (exact, `Content-Length`), so I04 never sees chunked bytes; non-2xx and non-JSON bodies are relayed and digested byte-exact whatever their media type (the mapping's non-2xx rows use object ANY); the digest is over the decoded body | §4; Q-HE3C-4 (a); D1-5, D1-13, D2-4 |
| R64 | The TLS client profile (`tls_client.rs`): one builder `client_config(identity, roots, time)`, called once per identity: the gate effect identity (`planeon:effect-gate`) for I05 and the gate writer identity (`planeon:policy-writer`) for I07 (resolved spec §2.3, :405); `ClientConfig::builder_with_details(provider, time)` with `tls.rs`'s `provider()` (now `pub(crate)`: the three TLS 1.3 suites, X25519, P-256, P-384), TLS 1.3 only; `with_webpki_verifier(WebPkiServerVerifier::builder_with_provider(roots, provider))` over the configured apiserver serving CA (DER; Q-HE3C-2 (a): no custom verifier and no `danger` API); `with_client_auth_cert` with the identity's DER chain and its PKCS#8 DER key, held in `Zeroizing` until it is moved into rustls, which runs `CertifiedKey::from_der` and checks the key against the leaf; no session store (`Resumption::disabled()`), no early data, no SNI (rustls sends SNI only for a DNS name, `client/hs.rs:280-282`; set explicitly), ALPN `http/1.1`. The server name is the apiserver's literal IP: pki-types' own `Ipv4Addr` from the four octets or `Ipv6Addr` from the sixteen bytes read as eight big-endian pairs; the certificate must carry that IP SAN. `TlsClientIdentity` prints lengths only. Residual (as R58): each identity's ring key pair lives for the process | §3; Q-HE3C-2 (a), Q-HE3C-3 (a); D1-8, D1-12 |
| R65 | Identity fields, read only where the model journals them (Q-HE3C-6 (a) as amended): I05 GET 200, CREATE 201 and DELETE 200/202 (the mapping's IDENTITY_MATCH and DELETE_BODY_IF_PRESENT rows; other GET 2xx carry none), I07 `operation.is_success(status)`. There the body is pre-scanned for depth at most 16 (brackets outside strings, before any value is built), must be UTF-8, and is parsed by the agreement-mode decoder (whitespace and floats allowed, duplicates and NaN refused), an object at the top. Forms: the object (`metadata.uid` and `metadata.resourceVersion`; a body whose `kind` is `Status` is not an object); a v1 `Status` (`apiVersion` v1, `kind` Status, `status` Success, `details.name` equal to the request's name, `details.kind` equal to the resource plural, `details.uid`; resourceVersion None; `details.group` is not compared, the plural and name being the request's). I05 GET 200 and CREATE 201 take the object only; I05 DELETE the form `deleteResponseBody` names (Pod and Service: OBJECT; ConfigMap: STATUS; the other form, such as a ConfigMap answered by the object of a deletion that is not immediate, is LOST); I07 CREATE and UPDATE successes the object; an I07 DELETE success either form (Q-HE3C-7 (a), re-checked on the selected distribution in W03). Patterns: uid `^[A-Za-z0-9-]{1,128}$`, resourceVersion `^[A-Za-z0-9]{1,64}$` (I05 v3 ACTION_OUTCOME, identical to R15). A body that does not parse or whose fields fail is LOST (fail closed); every other status passes uid and resourceVersion None, so Decision 0's reconciliation path runs (status and digest kept, the response relayed). HE-003D (HE-003C PR R1-2, Q-HE3D-12 (a)): an I05 DELETE 200 or 202 without a body is LOST too, although the mapping's DELETE_BODY_IF_PRESENT row would accept it: fail closed, a liveness cost only, and the W03 distribution check confirms that the selected distribution sends a body | §4; Q-HE3C-6 (a), Q-HE3C-7 (a); D1-3, D1-4, D2-2; HE-003D §6 |
| R66 | The outcome events: an I05 answer goes through the board's `stage_response` and the port feeds exactly the event it returns (`BoardError::Status` or `Size` LOST, `Occupied` a port failure); an I07 answer goes through the free function `exchange::write_response(write_id, status, body, uid, resourceVersion)`, which computes the digest and checks R15's patterns (status 100-599, uid, resourceVersion) and returns `WUpstream { Lost }` when they fail (HE003-REQ-1); it never touches the board's request or response slots (I07 answers are not relayed through I04). Among gate-tls's non-test sources only `exchange.rs` constructs `UpstreamResponse {` (a gate rule; effect-gate's constructions are test-only). Then `close_notify` and the close | §2.5, §5; D1-13, HE-003B D2-4 |
| R67 | The gate (`tools/gate.py`): the TLS deny-list stays one global list over gate-tls's sources (Q-HE3C-5 (b)), kept whole and amended with the client hazards `in_memory_sessions`, `Resumption::store`, `ClientSessionMemoryCache`, `tls12_resumption`, `with_ech`, `EchMode` (ECH sends an outer SNI whatever `enable_sni` says), `with_client_cert_resolver` and `send_ticket_request`; the exactly-once settings gain `resumption = Resumption::disabled()`, `enable_early_data = false` and `enable_sni = false`; `tls_client.rs` names `with_client_auth_cert(` and `with_webpki_verifier(` exactly once each (HE-003D, HE-003C PR R1-1: the rule proves only what it counts, any mention of each in gate-tls's and the binary's sources read without comments, exactly once, in `tls_client.rs`; it does not see what a value handed out of a function can do); the secret types gain `ClientConfig`, `ClientConnection` and `TlsClientIdentity`, the Debug hazards `LinuxConnector`; `tcp.rs` declares exactly ten foreign items (with `connect` and `getsockopt`). Text, not Rust: a type alias, a renamed import or a macro could evade it, and code review stays. HE-003D (R1-1) narrows that gap for UpstreamResponse (outside `exchange.rs` no gate-tls or binary source names it at all, and neither crate defines a `macro_rules` macro) and adds `with_root_certificates` to the deny-list; the values `exchange.rs` hands out remain code review's | §5; D1-8; HE-003D §5 |
| R68 | The I04 port's side of the outcome (PR review R1-7, D1-11): an `Upstream` output takes the connection in flight (the relay or the not-relayed close clears it at once), and an `Upstream` output with no connection in flight is a port failure (fail closed) instead of being ignored | §6 |

### Code and audit

- `gate-sys/src/tcp.rs`: `connect_tcp(&InetAddress) -> Result<(TcpConn, Connecting), errno>` (the listener's `socket`
  call, then one `connect` with the exact `sockaddr_in` or `sockaddr_in6` length; 0 is `Connected`, EINPROGRESS
  `InProgress`, any other errno returned with the socket closed) and `connect_result(&TcpConn) -> Result<(), errno>`
  (`getsockopt(SOL_SOCKET, SO_ERROR)` into an `int`, its length checked), each call in its own `unsafe` block with its
  own `// SAFETY:` argument; `connect` and `getsockopt` join the private extern block (whose
  `#[allow(clashing_extern_declarations)]` covers it), `getsockopt` declared identically to `channel.rs:252`. The layouts
  were already asserted; the listener-only port rule does not apply to connect.
- `effect-gate`: `net.rs` gains the second trait `ConnectNet` (`connect`, `connect_result`, `recv`, `send`,
  `shutdown_write`, `close`, `monotonic`) and the portable `Connecting`, and re-exports gate-sys's `InetAddress` and
  `IpLiteral` for gate-tls (which depends on no new crate); `StreamNet` is unchanged. `linux_net.rs` gains
  `NetTable::connect(&net, &Sealed, &address)` and `LinuxConnector::new(&Sealed, net)` (no socket before the seal, as
  `listen_i04`), whose sources are owned by `Owner::Upstream`, so `LinuxOs::with_net` resolves them for the upstream port
  only. `substrate.rs`: the provided `GateView::forwarded_write` and its `PolicyGate` impl. `policy_gate.rs`: the
  outstanding write keeps its `RenderedWrite` (`PolicyGate::forwarded_write`), and R16's parse
  (`PolicyGate::apiserver_address`).
- `gate-tls`: `upstream.rs` (`UpstreamClient`, `UPSTREAM_BOUND`, `WRITE_BOUND`, `CONNECT_DEADLINE`,
  `HANDSHAKE_DEADLINE`), `tls_client.rs` (`TlsClientIdentity`, `client_config`, `server_name`), `http1.rs`
  (`ResponseReader`, `ResponseProgress`, `ResponseRefusal`, `INTERIM_LIMIT`, `CHUNKED_RAW_LIMIT`), `exchange.rs`
  (`write_response`, `is_uid`, `is_resource_version`), `i04.rs` (R68), `tls.rs` (`provider()` `pub(crate)`). The root
  forbids `unsafe_code`.
- Tests (host): `gate-tls/tests/upstream_port.rs`, `upstream_framing.rs`, `upstream_identity.rs`, `upstream_client.rs`,
  `upstream_substrate.rs`, `i04_outcome.rs` and the shared `upstream_support/mod.rs` (a fake `ConnectNet` on
  `tls_support`'s fake clock, a scripted rustls apiserver that verifies the client certificate, Ed25519 test PKI from
  fixed seeds); R16's unit test in `policy_gate.rs`; the gate's self-test cases for every new rule.
- Departures from the design, each within its intent: `client_config` takes the time provider as a third argument (as
  `server_config` does, §20 of HE-003B), and the serving CAs as a slice; the identity's key is moved into rustls at
  `with_client_auth_cert` (the last builder step, since the design's deny-list refuses `with_client_cert_resolver`), so
  every earlier refusal drops it inside its `Zeroizing`; `effect_gate::net` re-exports `InetAddress` and `IpLiteral` so
  gate-tls needs no new dependency; the I07 operation, plural and name are read from the rendered head (the design's
  `forwarded_write` returns the rendered write only); a v1 `Status` also needs `apiVersion` v1 and `kind` Status, and
  the object form refuses a body of kind Status; an error readiness during the handshake or the exchange is LOST after
  the reads (so a complete answer read in that wake still counts).

### Constants and their evidence (for T04)

From the pinned musl 1.2.5 `libc.a` (llvm-objdump with relocations; `tools/w03/he003c/CONSTANTS_EVIDENCE.md`):

| Constant | x86_64 / aarch64 | Evidence |
|---|---|---|
| `connect` | 42 / 203 | `connect.lo` passes it to `__syscall_cp` (a cancellation point; the gate is single-threaded and never cancelled, so it is the plain system call) |
| `getsockopt` | 55 / 209 | `getsockopt.lo` |
| `EINPROGRESS` | 115 | `res_msend.lo` compares errno with 115 right after its `connect` call |

From the kernel UAPI (T04 confirms): `SOL_SOCKET` 1 and `SO_ERROR` 4 (the generic `socket.h`, read by no musl object).

### Carried

- T04 (Linux under load): the client's calls under the installed EFFECT_GATE filter (`socket`, `connect`, `getsockopt`,
  `sendto`, `recvfrom`, `shutdown`, `close`) in the steady-state trace; Linux's immediate loopback connect results (0
  or ECONNREFUSED from a non-blocking connect); ECDSA and RSA apiserver certificates (the host tests use Ed25519); the
  selected apiserver's chunk sizes against the raw cap (R63) and its real chunked answers; the bounds in real time; the
  constants above.
- HE-008 (credentials and policy): the apiserver serving certificate carries the loopback IP SAN of
  `apiserverAuthority`, issued by a CA that issues no other certificate with that SAN (ideally a dedicated serving CA),
  since webpki accepts any certificate the configured CA issued for that IP; `planeon_gate_t`'s `name_connect` to
  `planeon_kubeapi_port_t` and the `tcp_socket` connect permissions; the two client credential files (root, 0400) and
  their SELinux type (matrix amendment, owner decision 2026-10-15 item 3); the clientAuth EKU and the RBAC of the two
  identities.
- W03 distribution check: real chunked answers and DELETE success bodies of the selected distribution (I05's
  `deleteResponseBody`, R65's I07 DELETE forms, `details.kind` the plural); DELETE success without a body (R65, fail
  closed: LOST; HE-003D, Q-HE3D-12 (a)); that the apiserver does not route on the
  forwarded I05 head's `Host` (the I04 endpoint).
- HE-003D (built; see its section): the composition (`LinuxConnector::new(&sealed, net)`, `UpstreamClient::new` with
  `PolicyGate::apiserver_address()` and the two `client_config` results, rustls's default time provider), the signed
  configuration's items (the apiserver serving CA and the two identities' DER chains and PKCS#8 keys), the key files'
  read-buffer hygiene, and the deny-list and secret-type rules over the binary's sources.

### Owner decisions (verbatim as relayed, 2026-10-15)

The lane monitor (owner-delegated, "reasonable logic"; the owner may override), recorded against DESIGN rev 2.1
(184922d6…):

- Q-HE3C-1 = (a), amended: one apiserverAuthority from HE-003D's signed config, parsed once as an IP:port literal and refused unless loopback (127.0.0.0/8 or exactly ::1; IPv4-mapped refused).
- Q-HE3C-2 = (a): standard webpki against the configured serving CA with an IP SAN; no custom verifier, no `danger` API. Carried to HE-008: a dedicated serving CA that issues no other certificate with the apiserver's loopback IP SAN.
- Q-HE3C-3 = (a): two identities (effect-gate for I05, policy-writer for I07), with the per-channel identity test.
- Q-HE3C-4 = (a): strict chunked on the gate→apiserver leg only, bounded at 4 MiB decoded plus the raw cap, re-rendered with Content-Length toward I04. T04 confirms it.
- Q-HE3C-5 = (b): one global deny-list, kept whole and amended with the client hazards and the exactly-once settings.
- Q-HE3C-6 = (a), amended: LOST only where the model journals the identity; None elsewhere, so I05 Decision 0's reconciliation still runs.
- Q-HE3C-7 = (a): accept the deleted object, or the v1 Status form I05 already pins, checked by name, plural and uid. It's re-checked on the selected distribution in W03.

## HE-003D: the gate binary (crate `planeon-gate`; `effect-gate`: `gate_config`, `status`, `FileStores::open_bound`; `gate-tls`: `signed_config`, `credentials`; `i05-protocol`: `contracts`)

HE-003D (design revision 2.2, sha256 `343a04dc…`; design reviews round 1 CHANGES_REQUIRED, round 2 CHANGES_REQUIRED with
text fixes, round 2 confirmation PASS_FOR_BUILD with N1-N3; phase 1 host-path probe PASS; owner decisions
Q-HE3D-1..13, quoted at the end) builds the effect gate binary: the EFFECT_GATE seal's call site (SEC-4 and HI-7,
HE-003's share), the source check that no socket or thread comes before `Sealed`, the `__membarrier` link check and the
symbol inventory, the binary's crate among the linked crates with one exit import, the R10-defined signed
configuration and its checks, the composition of HE-003A/B/C's parts and the event loop, a distinct exit status for
every failure point, and the host-path solution (the vendored crates as path packages). Its rules are R69-R78 below.
No answer, record or vector changes; no earlier test file changes.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R69 | The signed configuration (Q-HE3D-1 (a), R10-defined): `/etc/planeon/effect-gate/config.json` (1 byte to 1 MiB) and `config.json.sig` (exactly 64 raw bytes), fixed paths, no argv (Q-HE3D-5 (a)). Each is opened through gate-sys's `Dir::at` and `Dir::file_ro`, sized by `fstat` and read with a plain `read` loop into one buffer of size + 1 (a total other than the size, the file grew or shrank, is refused). The signer's Ed25519 public key is compiled in from `crates/gate-tls/config-signer.pub`, 0 or 32 bytes (a gate rule); empty means not yet set and every document is refused (status 12) until HE-008 generates the key and an R10 packet sets it (Q-HE3D-7 (d)); `load()` passes the key through `core::hint::black_box` before `check_key` (Q-HE3D-B1 (a)), an identity at run time, so that while the key is empty the optimiser cannot prove every document refused and drop the composition after the call: the shipped `planeon-gate` holds the composed gate, and its binary, host-path and inventory evidence (R76, R77) describe the real gate; a key of small order is refused at test time and at run time by libsodium's method (the sign bit cleared, compared with the seven small-order y values: 14 encodings, the non-canonical ones ring's decoder accepts included). The payload is `UTF8("planeon.effect-gate-config/v1") \|\| 0x00 \|\| document`, verified with ring's `UnparsedPublicKey::new(&ED25519, key).verify` (Q-HE3D-6 (a), one registry line `ring = "=0.17.14"` in gate-tls); verification comes first, so an unsigned or invalid document is never parsed. The format string is effect-gate's `gate_config::FORMAT` and the domain prefix is built from it, so they change together (`…/v2` for HE-003A2's writer path); a binary accepts exactly one version. What the signature protects under (d): a writer of `/etc/planeon/effect-gate/` (only `planeon_maint_t`, in maintenance) can deny service (status 12) or replay an older signed document (the generation binding, R75, stops replay within a generation; a signed document that was never deployed still starts a new generation, bounded only by its own lifetimes, a residual), but cannot forge one. Under option (a) (a key file beside the document, same label) the signature would only equal the label: one file written, status 12; document and signature, status 12 or replay; all three, full control (state, runs, manifests, lifetimes, endpoint, the I04 client CA, the serving CA, every credential pin). HE-003A2 (R83): the format is `planeon.effect-gate-config/v2`, so the payload's domain is `UTF8("planeon.effect-gate-config/v2")`; a v1 document or a signature over the v1 prefix is refused | §3.1; Q-HE3D-1/5/6/7; D1-1, D2-4, D2-7 |
| R70 | The document and its checks (`GateConfig::parse`, before stage 2, status 13). Canonical form: RFC 8785 JCS restricted to a subset on which it equals `i05_protocol::json::canonical`: ASCII only, strict JSON (no duplicate key, no NaN), depth at most 16, no float, integers 0..=2^53-1, and byte-equal to its canonical encoding (no whitespace, sorted keys, only the escapes JCS emits, no trailing newline); any standard JCS library can sign it (HO-D4). Schema, closed objects with unknown members refused: `format`, `gate` (the I05 `Config` members and `policyWriter`, passed unchanged to `PolicyGate`), `lifetimes` (run nonce to lifetime end, seconds since the epoch), `stores` (`journalDirectory`, `markerDirectory`) and `credentials` (`i04Server` and the two identities `{chain: 1 to 4 files, leaf first, key}`, `i04ClientCa`, `apiserverServingCa`; a file is `{path, sha256}`). Checks: `PolicyGate::new` on `gate` (the I05 `Config` and R16's loopback `apiserverAuthority`; an in-memory instance dropped at once); R19's generation form; the I04 `endpoint` a literal authority whose address is neither unspecified nor multicast (also in the IPv4-mapped form) and whose port is at least 1024 (O5, Q-HE2S-9 (a)); `observedWorkers` empty (Q-HE3D-2 (a): BIND is refused WORKER_NOT_OBSERVED until an I05 successor and a matrix grant let the gate observe the probe workers; HE-003A3 removed the rule: format v3's `gate` carries no `observedWorkers`, refused with I05 v4's C01 text, and the gate observes the probe worker at every BIND, R91-R94); `lifetimes` exactly the nonces of `gate.runs`, each 1..=2^53-1; at most 32 manifests, each keyed by its own R47 digest and at most 16,384 bytes (R48); every `serverCertificateDigest` in R47 form, distinct across runs, and not the pin of the gate's own leaf certificates (`i04Server`, `effectIdentity`, `writerIdentity` chain[0]); exactly one I04 client CA and one apiserver serving CA (R1-3, Q-HE3D-8 (a): Q-HE3C-2's condition, a dedicated serving CA that issues no other certificate with the apiserver's loopback IP SAN, holds for that one root); every path absolute and normalised (no empty, `.` or `..` component, no trailing `/`, no NUL), at most 255 bytes; every pin `sha256:` and 64 lowercase hex digits; the two store directories different. No pseudo-file-system prefix list: every file is pinned and must be a regular file of 1 to 65,536 bytes (R73), so a proc or sys entry cannot pass, and the gate's proc access is its own status, its two peers' and (HE-003A3, R94) the probe worker's `stat`; it reads the probe-worker leaf's `cgroup.procs` (matrix v5: READ on the leaf, search on its two parents, `/proc` access to the worker). The initial `state` may be any state the I05 model accepts on create (Q-HE3D-10 (a)); HE-008 records the production state it signs; a restart ignores it (`PolicyGate::open`, deny-first). `peerQualificationDigest` stays a signed configured value checked at BIND (Q-HE3D-9 (a)). HE-003A2 (R83): format v2 adds the top-level closed object `enrolledWriter` (`executable`, checked as R83 says) | §3.2, §3.3; Q-HE3D-2/8/9/10; D1-4, D1-5, D1-12, D2-3, N3 |
| R71 | Exit statuses (`effect_gate::status`, O7), distinct, never 0 (the loop has no normal end): 2 the non-Linux stub; 11 the configuration read; 12 the signature or the key; 13 the document's checks; 20 a credential or CA file; 21 the TLS configurations; 22 the stores (the generation binding included); 23 `PolicyGate::create` or `open`; 24 the socket setup (the I04 listener, the Linux `Os`); 25 `Substrate::new`; 26 the observation's two kernel roots (`KernelRoots::open_after_seal`, after the socket setup and before the stores; HE-003A3, R94); 30-35 the loop's exits (ModelPrecondition, UnexpectedOutput, Accept, Poll, PortToken, Port); 40-55 stage 1's steps (Threads(One) 40, UserIds 41, GroupIds 42, StartCapabilities 43, StartBounding 44, Program 45, CoreLimit 46, CoreLimitReadBack 47, AmbientClear 48, AmbientReadBack 49, BoundingDrop(One) 50, BoundingReadBack(One) 51, Capabilities(One) 52, CapabilitiesReadBack(One) 53, NoNewPrivs 54, NoNewPrivsReadBack 55); 60-70 stage 2's (Threads(Two) 60, BoundingDrop(Two) 61, BoundingReadBack(Two) 62, Capabilities(Two) 63, CapabilitiesReadBack(Two) 64, FinalCapabilities 65, FinalBounding 66, FinalAmbient 67, FinalNoNewPrivs 68, FinalCoreLimit 69, Filter 70). `status::seal_step` is one exhaustive match over both stages (a new `SealStep` variant fails the build; BoundingDrop's capability number is ignored). Nothing is printed (R78); a panic message (abort) may still reach fd 2, a residual | §4; O7; D1-13, D2-2 |
| R72 | The seal order and its source rules (O2): `main` (exactly one `#[cfg(target_os = "linux")]` one, plus a stub returning 2 elsewhere) starts with `let <name> = match seal_stage1() {`; between that call and the stage-2 statement the gate's grammar admits only `signed_config::load(`, `GateConfig::parse(`, `ExitCode::from(`, `status::seal(` (as `ExitCode::from`'s argument), the patterns `Ok(`, `Err(` and tuple-variant patterns, identifiers, paths, literals and `let`, `match`, `return`: no method call, closure, macro, `?` or other call. The second stage is exactly `let <n> = match seal_stage2(<the stage-1 binding>) { Ok(<x>) => <x>, Err(<e>) => return ExitCode::from(status::seal(&<e>)), };` (comments and whitespace tolerated), so nothing runs in its argument, before the second stage, or in either arm (PR review round 1, R1-1). `main.rs` imports exactly the pinned set (the top level's `ExitCode`, `status`, `seal_stage1`, `seal_stage2`, `GateConfig`, `Sealed`, `signed_config::{self, LoadError}`, and `serve`'s), with no rename or glob; it defines no item but the two `fn main` and `fn serve` (no mod, struct, enum, union, trait, type, impl, const, static, macro or extern); its only attributes are the crate's `forbid(unsafe_code)` and the two cfgs, and nothing but its cfg precedes the Linux main: so no code defined in `main.rs` runs between the stages under an allowed name (R1-2). Through the end of the stage-2 statement in `main.rs`, and anywhere in `gate_config.rs` and `signed_config.rs` (read without comments), none of `gate_sys` (except exactly one statement `use gate_sys::Dir;` at the start of a line in `signed_config.rs`, the read-only opener R69 needs, removed once before the scan; a second one, `pub use`, a group, a rename, another gate-sys path or a qualified `gate_sys::` expression refuses; departure A2, accepted 2026-10-15), `Poller`, `listen_`, `connect_`, `NetTable`, `LinuxOs`, `LinuxConnector`, `std::net`, `std::thread`, `thread::`; everything after the seal is in `serve`, below `main`. gate-sys's `channel` and `tcp` modules are reached (by use tree, groups, globs and renames included, or by qualified path) only from `linux_os.rs` and `linux_net.rs`, whose public constructors take `&Sealed` and which re-export nothing, and from gate-sys; a glob or rename of `gate_sys` elsewhere refuses. In those two files a text tripwire over names (comments removed; PR review rounds 1 and 2, R1-3 and R2-1): no `pub` (or `pub(..)`) type alias, const, static or fn signature, and no `pub` struct field, names a channel or tcp item, through an import, a module import or a qualified path, except the data types `ListenError`, `TcpListenError` and `Watched`, which create nothing (today's `listen_i04` and `watched` return them); no private type alias exists (so no alias chain hides an item); and no `pub` const, static or struct field has a fn-pointer type (so no pointer to a private fn is handed out). No linked source defines a macro (R78), so none can complete a socket path the reading does not see. Residual (code review's): the rule reads names, not types, so a wrapper type whose body or `impl` creates a socket item (for example a pub fn returning a struct built from `Poller::new`, or a trait impl's default) passes; so do what the functions called between the stages call in turn, and the bodies of the public functions of `linux_os.rs` and `linux_net.rs` (a new constructor without `&Sealed`, for example). HE-003A2 (HE-003D PR N1 and N2; Q-A2-9 (a), D1-3, D2-1; PR review round 1, R1-1, R1-2 and R1-4, Q-A2-R1 (a)): the parenthetical now holds for the forms the rule reads. No `pub` type alias, `pub` const or static type, or `pub` struct field (braced or tuple) has a fn-pointer type or an Fn-trait type, and no variant of a `pub` (or `pub(..)`) enum, tuple or named-field, has field types that name a channel or tcp item (the data types exempt) or are a fn pointer or an Fn-trait type. An Fn-trait type is any `Fn(`, `FnMut(` or `FnOnce(` (or `<`) in the typed text, however it is reached: after `dyn` or `impl`, path-qualified (`std::ops::Fn`, `core::ops::FnMut`, `::core::ops::FnOnce`), parenthesised (`dyn (Fn())`), higher-ranked (`for<'a>`), after other bounds, lifetimes or nested generic bounds. Only field types are read, never variant or field names; variants are split at commas outside parentheses, brackets and braces, so a discriminant such as `1 << 2` cannot merge the next variant, an explicit discriminant after a data variant is skipped, and field types with unbalanced angle brackets are refused; a private enum (`linux_net.rs`'s `Stream`) stays outside, like a private struct. N2: an associated type in a trait impl in these two files is refused as a private type alias (none exists; keeping the refusal keeps R2-1's alias closure). Residual, still code review's: trait-impl associated consts and items; the bodies and return types of pub fns; the generic parameters of pub structs, enums and aliases (default types such as `<T = Poller>`, bounds such as `<F: Fn()>` and where-clauses); and subtraits of Fn named by another trait (`trait Cbk: Fn(u8) {}` with `Box<dyn Cbk>`) | §5; O2; D1-3, D2-2, D2-6 |
| R73 | Credentials, after `Sealed` (`gate_tls::credentials`): each file the configuration names is opened with `Dir::file_ro` in its parent directory, sized by `fstat` (1 to 65,536 bytes), read with a plain `read` loop into one buffer of size + 1 allocated once (for a key a `Zeroizing<Vec<u8>>`, `KeyBytes`), never a growing one; a total other than the size is refused; the length is cut to the size without reallocation (zeroize 1.9.1 clears the spare capacity on drop); the bytes' sha256 must be the pin (status 20); then they move into `TlsServerInputs`, `TlsClientIdentity` or the one-root list with no other copy. `CredentialFile` and `KeyBytes` are secret types (no derived Debug). Residual (next to R58): the hasher's state over a key keeps its last block uncleared. gate-tls returns rustls's default time provider (`DefaultTimeProvider`) as `Arc<dyn TimeProvider>`, so `crates/gate` has no registry line (Q-HE3D-11 (a)) | §3.4; D1-7; Q-HE3D-11 |
| R74 | The I07 policy-kind table: `i05_protocol::contracts::I07_V3_POLICY_KINDS` embeds `contracts/i07-v3/policy-kinds.json` byte for byte (a unit test pins sha256 `4e427204…`, the value `tools/gate.py` registers); `GateConfig` parses it and `main` hands it to `PolicyGate` | §3.6; G3 |
| R75 | The generation binding (Q-HE3D-13 (b); amends R19-R30): `FileStores::open_bound(journal, marker, generation, document_digest, probe, plan)`, under the index lock, after the marker read and before the journal is created: for an indexed generation `<generation>.document` must hold exactly one committed R29 frame `["DOCUMENT", generation, digest]` with this digest; for an unindexed one the file is created and that frame appended (two-phase), or a file an earlier failed opening left is reused only when it already holds exactly that frame. Missing (indexed), empty, torn, uncommitted, revoked, extended or different is `OpenError::Document` (status 22), also for a new generation, since a torn file cannot be repaired after the seal (truncation is killed); a new generation is then needed. The name cannot collide with `<g>.journal`, `<g>.marker` or `generations`; R26's syncs and their counts are unchanged (the existing journal-directory sync covers the file); every I/O error is a value (R27); `StoreFile::Document` arms the file's fault points. `FileStores::open` (HE-002C, unbound) is unchanged, so no earlier test changes (departure A1, accepted 2026-10-15); a gate rule holds the binary to the bound opening: `crates/gate`'s sources (read without comments) call `FileStores::open_bound(` exactly once, name `::open` only as `PolicyGate::open`, and neither rename nor alias `FileStores` or `PolicyGate`; and no non-test source of a linked crate (`file_store.rs` included, whose `pub fn open` is the definition) spells a call of `FileStores::open` or, in `file_store.rs`, `Self::open` (PR review round 1, R1-4). Both are text tripwires over spellings (PR review round 2, R2-2): outside `crates/gate`, an import that renames `FileStores`, a type alias for it, or a new pub fn in `file_store.rs` that calls the private opener `FileStores::opening` without a digest would hand the binary an unbound opening and is code review's. Operational consequence (R1-5, carried to HE-008): an empty or torn `<generation>.document`, from a crash between the file's creation and its first write or a failed first write such as a full disk, wedges its generation for good (status 22 at every start); recovery is a re-signed configuration with a new generation | §3.3; Q-HE3D-13; D1-9, D2-5, N1, N2 |
| R76 | Host paths (Q-HE3B-27 (a), Q-HE3D-4 (a), phase 1): the workspace manifest maps the 11 LINKED vendored crates through `[patch.crates-io]` to `{ path = "vendor/<name>-<version>" }` (vendored bytes unchanged; the directory `[source]` stays for the build-host crates and the stubs), so cargo passes rustc workspace-relative source paths and `planeon-gate` carries no build-host path (vendored panic locations read `vendor/<crate>/src/…`). In `Cargo.lock` the patched packages have no `source` or `checksum`; the gate admits exactly that table and holds their names, versions and edges to the vendor rows, and the other 14 rows stay registry packages with their checksums. Cargo still loads every `.cargo-checksum.json` but no longer verifies a patched package's file digests, so `check_vendor` is their only file-level pin and the checksum files stay. The now-local vendored crates' lints run uncapped: ring's 11 (x86_64) or 9 (aarch64) `mismatched_lifetime_syntaxes` warnings, rustc's BSD-archive warning for ring's two static libraries and two `ranlib` build-script warnings per target, no error; a future toolchain could turn ring's live `deny`/`forbid` lints into errors (fallback: the `ci/` `--remap-path-prefix` wrapper, the owner's per-head approval) | §2, §5; phase 1 |
| R77 | `planeon-gate`'s symbol table (O3, C8; `tools/gate.py`), on both targets: symbols of gate-tls and rustls (a Rust path whose crate root is that crate, v0 or legacy mangling) and of ring's C and assembly core (`ring_core_0_17_14_…`) are present, so the binary holds the composed gate (Q-HE3D-B1 (a)); no `membarrier` or `__membarrier`; and every musl wrapper of `KILLED_WRAPPERS` it holds is in `WRAPPER_JUSTIFICATIONS`, the reviewed list below (an unlisted one fails). `KILLED_WRAPPERS` are the wrappers whose primary system call the pinned EFFECT_GATE programs kill on at least one target for every one of 147 argument vectors (a classic-BPF interpreter over `contracts/seccomp-v3/`); argument-filtered calls (`socket`, `prctl`, `mremap`, `fcntl`, …) are T04's trace. HE-003A2 (D1-13) re-derived the list over `contracts/seccomp-v4/` with a kept classifier, `tools/w03/he003a2/classify_wrappers.py` in the operator's state directory (sha256 `97cb5f2b90aa68ae73dd87cab4c67f89055aebb4dc4c736b3fcc9927d4c71ca0`; 90 argument vectors, sha256 `694dfd2daf4bc10083b71a242bb51c4ef0fa843f28a776f0f400b4fed2ed966c`, built from base values and one witness per feasible path of every argument-filtered body; every call number 0..1099, the x32 range and 0xffffffff swept on both versions): v3 and v4 decide differently only for 267 (x86_64) and 78 (aarch64), `readlinkat`, so `readlinkat` left (98 names) and nothing joined; `readlink` stays (x86_64's 89 is killed unconditionally) | §5; O3, C8; HE-003A2 §2, D1-13 |
| R78 | Other gate rules over the linked crates and the binary: `crates/gate` joins `LINKED_CRATES` and `POST_SEAL_CRATES`, its root forbids `unsafe_code`, and `std::process::ExitCode` is allowed only as the one `use std::process::ExitCode;` of `main.rs` (no `std::env`, no argv); no linked source (read without comments) defines a `macro_rules` macro or a `macro` item or carries `#[macro_export]` (PR review round 1, R1-3; none exists), names `std::thread` or `thread::` (the gate is single-threaded), `link_section`, `#[used]`, `init_array`, `no_mangle` or `export_name` (no code before `main`), `print!`, `println!`, `eprint!`, `eprintln!`, `dbg!`, or stdout or stderr in any case (nothing printed); the TLS deny-list and the exactly-once settings cover the binary's sources, `with_root_certificates` joins the list, and outside `exchange.rs` no gate-tls or binary source names `UpstreamResponse` or defines a `macro_rules` macro (R67); `CredentialFile` and `KeyBytes` join the secret types; `config-signer.pub` is 0 or 32 bytes | §4, §5; O4; D1-2, D1-10, D2-6 |

### The symbol inventory (R77)

Built from phase 2's actual set on the shipped binaries (the compiled-in key empty, `black_box` in `load()`: the
composed gate, 2,589,808 bytes on x86_64 and 2,297,624 on aarch64). Before `black_box`, LTO had proved that
`signed_config::load()` never succeeds with an empty key and dropped everything after it (about 478 KB, no rustls or
socket code); a scratch build with a 32-byte stand-in key held the composition and the same twelve wrappers as the
shipped binaries now do. No `membarrier` or `__membarrier`; no build-host path.

| Wrapper | Why it is present and unreachable on the gate's paths after the seal |
|---|---|
| `capget`, `capset` | the seal's own calls (gate-sys `seal.rs`), made only in stages 1 and 2 before the filter (step 9) |
| `getresuid`, `getresgid` | the seal's preconditions, before stage 1's first change |
| `open` | std's start-up before `main` (a closed fd 0-2 is reopened on `/dev/null`); on aarch64 musl's `open` is `openat` (allowed); no direct call in the composed text; the linked crates name no std opener |
| `readlink`, `getcwd` | called only by `realpath` (and std's `current_exe` and `current_dir`, refused by the start-up lint; std's `Debug` of a `File`, which no linked source formats after the seal) |
| `realpath`, `stat` | std's canonicalize, path metadata and backtrace paths; no direct call or jump in the composed text; `std::path` and `Path` are refused in the linked crates; a panic with `RUST_BACKTRACE` set dies by SIGSYS (HE-008 leaves it unset) |
| `dup` | std's runtime; no direct call or jump in the composed text; the gate duplicates no descriptor (`try_clone` is `fcntl(F_DUPFD_CLOEXEC)`, allowed) |
| `pause` | musl's or std's; no direct call or jump in the composed text; on aarch64 it is `ppoll` (allowed) |
| `sysinfo` | called only by musl's `sysconf` for the physical page counts; std asks `sysconf` only for the page size (from the auxiliary vector, no system call) |

### Code and audit

- `crates/gate/src/main.rs`: `main` (stage 1, `signed_config::load`, `GateConfig::parse`, stage 2), then `serve`:
  the credentials (all read, then `server_config` and the two `client_config`), `NetTable::new`, `listen_i04` with the
  configuration's parsed endpoint, `LinuxOs::with_net`, `FileStores::open_bound` with `fstat_device`, `PolicyGate::create`
  on a fresh journal (`journal_created && indexed_now && entries empty && no marker file`) or `PolicyGate::open` (its
  restart output dropped before the loop), `Exchange::shared`, `I04Server::new`, `LinuxConnector::new`,
  `UpstreamClient::new` with `gate.apiserver_address()` (R16 stays the single parser), `Substrate::new` and `run`. C1:
  the one `PolicyGate` on file stores in the process. `host-common` is no longer a dependency.
- `effect-gate`: `gate_config.rs` (`GateConfig::parse`, `FileRef`, `IdentityFiles`, `CredentialFiles`, `is_digest`,
  `is_normal_path`, `policy_kinds`), `status.rs`, `file_store.rs` (`open_bound`, `document_name`, `OpenError::Document`),
  `store.rs` (`StoreFile::Document`), and the root re-exports `gate_sys::inet::parse_authority` (so `gate_config.rs`
  names no gate-sys path). `gate-tls`: `signed_config.rs` (`verify`, `load_from(dir, key)`, `load`, `check_key`,
  `payload`, `fill`, `COMPILED_KEY`), `credentials.rs` (`CredentialFile`, `KeyBytes`, `read_certificate`, `read_key`,
  `server_inputs`, `client_identity`, `serving_roots`, `time_provider`), a path dependency on gate-sys and the ring line.
- Tests (host): `effect-gate/tests/gate_config.rs` (14), `gate_status.rs` (3), `stores_document.rs` (6);
  `gate-tls/tests/signed_config.rs` (7, a fixed-seed key from `Ed25519KeyPair::from_seed_unchecked`, test only) and
  `credentials.rs` (6); `i05-protocol`'s policy-kinds digest unit test; the gate's self-test cases for every new rule
  and bypass form. `main` itself runs on Linux only (T04); the host build compiles the stub.
- Accepted departures (2026-10-15, below): A1, the binding is `FileStores::open_bound` and `FileStores::open` keeps
  its signature, since changing it would change three earlier test files (the brief keeps them byte-identical), with
  the store opening rule of R75; A2, the `gate_sys` refusal in `signed_config.rs` excepts exactly one
  `use gate_sys::Dir;`, which the design's own read requires (R72). B1: `black_box` on the compiled-in key (R69, R77).
- Other departures, each within its intent:
  `parse_authority` is re-exported from effect-gate's root; the IPv4-mapped unspecified and multicast endpoints are
  refused too; a signature file other than 64 bytes is a read refusal (status 11); the credential helper's constructor
  is `CredentialFile::at` (the linked-source tripwire refuses the text `File::open`); `GateConfig` also carries the
  generation and the parsed kind table; the print rule ignores case; the TLS exactly-once counts include the binary.

### Carried

- T04 (Linux): `main` under the installed filter, with the key set (until then every start ends at status 12); the configuration's reads
  between the stages and nothing else; the symbol inventory on Linux and the steady-state trace (no killed call
  reached, the argument-filtered ones included); the immediate failures of the socket setup (a stale socket path, a
  busy port: status 24, the generation left fresh); every exit status as observed.
- HE-008: the off-host enrollment signer and its Ed25519 key; the R10 packet that sets `config-signer.pub` (T04 needs
  it set); the configuration and credential files (root, 0400) and their labels and SELinux types (the I04 key/cert
  type from SELINUX-MATRIX-I04-KEYCERT); the unit, `RUST_BACKTRACE` unset, core dumps, fds 0-2 open; the production
  initial `state` it signs; never two documents for one generation (R75 enforces it; a never-deployed signed document
  is the residual of R69); an empty or torn `<generation>.document` (a crash or a full disk at the first start) wedges
  that generation (status 22 at every start), and recovery is re-signing the configuration with a new generation (R75,
  PR review round 1, R1-5); every start gets empty runtime directories, also after exits 22-25, since the AF_UNIX
  socket paths then exist and the gate cannot unlink them.
- Refinement of the runtime-directory clause above, which stays as history (HE-004B1, from the owner's decision "systemd cleans" and the lane monitor's Q-SOL-7 (a), both 2026-10-17):
  after exits 22-25 or a crash, each listener unit's own `ExecStartPre=` removes its stale socket path as
  `init_t`; the shared directory itself is kept (the HE-003A section's refinement note gives the pattern).
- HE-003A2: the writer's executable check, its enrolled path in the configuration's next format (`…/v2`). **Closed by
  HE-003A2** (R79-R85).
- The I05 successor and the matrix grant (gate READ on the worker cgroup, procAccess to `planeon_worker_t`), then a
  later R10 packet, for `observedWorkers` (R70).
- A contract successor and HE-005: the mutual qualification record's canonical form (`peerQualificationDigest`).
- The next W03-plan meta packet: the W03-PLAN-AMEND-1 HE-003 share text ("kept … below 1024").
- Standing (R42): every later `FatalReason` joins `FATAL_REASONS`.

### Owner decisions (verbatim as relayed, 2026-10-15)

The lane monitor's first message, against the dossier:

> Owner:
> - Q-HE3D-1 = (a): an R10-defined signed configuration. One canonical JSON document with a detached Ed25519 signature (ring, already vendored) over a domain-separated payload, produced by HE-008's off-host enrollment signer and recorded in MODEL_DEFINED as R10-defined (Q-HE3A-3/-5 precedent).
> - Q-HE3D-2 = (a): fail closed now. The configured observedWorkers list is empty in production, so BIND is refused WORKER_NOT_OBSERVED. The real fix is an I05 successor plus a matrix grant (gate READ on the worker cgroup, procAccess to planeon_worker_t), then a later R10 packet. I'm routing the grant to the parallel lane's SELINUX-MATRIX-I04-KEYCERT and the I05 successor to the queue (parallel-owned paths).
> Monitor (owner-delegated):
> - Q-HE3D-3 = (a): the writer exe check isn't in HE-003D. It goes in HE-003A2 after the seccomp and programs chain merges; the enrolled path comes from the configuration (G4).
> - Q-HE3D-4 = (a): a two-phase build. Phase 1 is the scratch [patch] path-dependency probe (host paths, lint caps, OUT_DIR), stopping before any other code. Only if it fails does the ci/ wrapper come to the owner.

The second, against design revision 2.2 (343a04dc…):

> Owner:
> - Q-HE3D-7 = (d): the public key is compiled into the binary from crates/gate-tls/config-signer.pub. It's EMPTY until HE-008, so every document is refused until then (fail closed). Small-order keys are refused; rotation needs an R10 packet plus re-enrollment.
> - Q-HE3D-13 = (b): the store pins one document per generation (`<generation>.document` frame, compared on open; missing, torn or different → status 22). This explicitly amends HE-002C's owner-decided store rules R19-R30.
> Monitor (owner-delegated), all (a): Q-HE3D-5 fixed /etc/planeon/effect-gate/ paths; Q-HE3D-6 ring ED25519 via the one registry line; Q-HE3D-8 exactly one serving CA and one I04 client CA; Q-HE3D-9 signed peerQualificationDigest; Q-HE3D-10 any I05-accepted initial state; Q-HE3D-11 no registry lines in the binary; Q-HE3D-12 wording plus the W03 distribution check.

The third, on the build points B1, A1 and A2:

> Monitor (owner-delegated), 2026-10-15. Record verbatim.
> - Q-HE3D-B1 = (a): `core::hint::black_box` on the compiled key before check_key, so the shipped planeon-gate holds the composed gate, plus a gate rule that its .symtab contains gate_tls, rustls and ring symbols, with self-tests. Runtime behaviour is unchanged: every document is still refused until HE-008. The binary, host-path and inventory evidence must then describe the real gate.
> - A1 accepted: FileStores::open_bound carries §3.3, with a text rule that crates/gate names open_bound and never `FileStores::open(`.
> - A2 accepted: exactly one `use gate_sys::Dir;` is removed from signed_config.rs before the scan. Make the gate refuse any second or different gate_sys use there.

## HE-003A2: the v4 re-vendor and the writer executable check (`seal`, `peers`, `substrate`, `linux_os`, `gate_config`; crate `gate-sys`: `Dir::read_link`, `ProcDir::exe`)

HE-003A2 (design revision 2.1, sha256 `b4af83af…`; design reviews round 1 CHANGES_REQUIRED (D1-1..D1-13), round 2
PASS_FOR_BUILD with D2-1 applied in revision 2.1 and D2-2..D2-4 followed; owner decisions Q-A2-1, -2, -5, -6, -9, -10 and
-13, quoted at the end) is the third step of the chain the owner set for Q-HE3A-1 (c) with Q-HE3A-1b (a): seccomp
allowlists v4 (harness-onion MET-ENFORCE-027, `e7516160`), the republished EFFECT_GATE programs with edge record v3
(MET-ENFORCE-029, harness-onion `d2ef7083`, tree `611553ec`), then this packet (Q-HE3D-3 (a)). It re-vendors the v4
programs, which the seal now embeds, and adds the gate side of O-W03-WRITER-EXE (HS43 §4.2, §4.3, §5.3): the writer's
`exe` link, read with `readlinkat` on the retained process directory, must equal the enrolled writer path of the signed
configuration exactly, on accept and on every I07 frame. Its rules are R79-R85. No event, answer, record, vector,
schema, journal format or `FatalReason` changes (C5 is not triggered); the earlier test files change only on the
lines the design's §8 lists (R85).

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R79 | The writer executable check (`Os::writer_exe_ok`): for I07 connections only (the substrate decides; an erroneous call on an I05 connection fails closed, since the gate cannot read the broker's link, D2-4). At accept, in `qualify`: SO_PEERCRED, SO_PEERSEC and SO_PEERPIDFD, the process directory opened and read, the expected label and uid compared, **then the executable**, and the pidfd probe last (D1-8: no exe read is attempted for a peer that is not the writer domain); a failure closes the connection without feeding the model (R32). On every I07 frame, in `custody`: the control rules, the credentials, the socket label, the process directory's start time, cgroup and label, **then the executable**, and the pidfd probe last; a failure is `deviation(I07)`, `WPeerChanged`, so N12: the outstanding write aborted, `["INVALIDATED", "WRITER_PEER_DEVIATION", "HELD"]`, the session FATAL, `fatal: PEER_CHANGED`. The probe stays last, so R36's liveness argument covers the read (R36's HE-003A2 extension). The comparison is byte-exact on the count read: a `" (deleted)"` suffix, a prefix, a longer or truncated link and an empty one all fail. A replaced writer binary during a live session HELDs the generation (Q-A2-13 (a)): the writer session ends before any writer upgrade (carried) | DESIGN §4; HS43 §4.3; Q-HE3A-1 (c), Q-A2-13 (a); D1-8, D1-11, D2-4 |
| R80 | The read (`gate-sys`, owner decision Q-A2-2 (a)): `Dir::read_link(&self, name, buffer)` in `openat.rs`, the module that owns the descriptor, through musl's `readlinkat` wrapper (D1-6; the evidence is next to R40), on the `Dir`'s own descriptor, which is non-negative by construction (it comes only from a successful `openat`), so `AT_FDCWD` is never passed; the name passes the store-name check (1 to 255 bytes, one component, no `/`, `.`, `..` or NUL), so it is never absolute and the descriptor is never ignored. Refused: an empty buffer (before the call), any error, a count of 0 and a count equal to the buffer's length (the kernel truncates a longer link without an error). `ProcDir::exe(&self, buffer)` in `channel.rs` is `self.dir.read_link("exe", buffer)`, with no new `unsafe` there. `read_link` is `pub` for gate-sys's host tests (D1-9), so a gate rule pins its callers (R85). The std and musl routes that would kill the gate under v4 (`current_exe`, `fs::read_link`, `canonicalize`, `realpath`) stay refused by the existing rules (the start-up lint and the post-seal list, the fs-items rule, the exact FOREIGN_ITEMS); `Debug` of a `File` as R38 says (D1-10) | DESIGN §3; Q-A2-2 (a); D1-6, D1-9, D1-10, D2-2 |
| R81 | The sizing and the comparison are portable pure functions (D1-2), host-tested: `peers::writer_exe_buffer_len(expected)` is the enrolled path's length + 1 (HS43: a buffer longer than the enrolled path), and `peers::writer_exe_matches(link, expected)` is exact equality of two non-empty byte strings. `LinuxOs::writer_exe_ok` composes them with `ProcDir::exe` (a buffer of that size, the read, the comparison over the count read); no connection, no kept process directory or a refused read is false. Every mis-composition (a wrong size, the whole buffer compared) fails closed | DESIGN §3; D1-2 |
| R82 | The expected value is a **required** constructor argument (owner decision Q-A2-6 (a)): `LinuxOs::new(&Sealed, i05, i07, writer_executable)` and `LinuxOs::with_net(&Sealed, i05, i07, net, writer_executable)`, held privately; there is no `None` and no default, so the compiler forbids a production `Os` without it, and no test-only path exists in production code (`LinuxOs` is Linux-only and no test constructs it). `ExpectedPeers` and `r10()` are unchanged. `Os::writer_exe_ok` is a required trait method: `LinuxOs` implements it as R81 says; the substrate's own test `Os` (`Quiet`) and gate-tls's `LoopOs` (it accepts only I05) return false; effect-gate's `FakeOs` returns a per-peer `FakePeer::exe_ok` (true in `broker_peer` and `writer_peer`) and records `exe #N` in its trace, so the tests check the order. `main.rs` passes `config.writer_executable` to `LinuxOs::with_net` in `serve`, after the seal; its pinned imports and the seal-order grammar are unchanged | DESIGN §4; Q-A2-6 (a); D1-5, D2-3 |
| R83 | Configuration format v2 (`gate_config::FORMAT` = `planeon.effect-gate-config/v2`; the signing domain changes with it, and a binary accepts exactly one version: a v1 document, or a signature over the v1 prefix, is refused; nothing is deployed yet, the signer key is empty until HE-008). A new top-level closed object `enrolledWriter: { "executable": "<path>" }` (owner decision Q-A2-5 (a); named apart from `gate.policyWriter` and `credentials.writerIdentity`; JCS order `credentials` < `enrolledWriter` < `format`), parsed by `GateConfig` only (`gate`, R16 and `PolicyGate` unchanged), checked after the credentials: an absolute normalised path of at most 255 bytes (`is_normal_path`, which also refuses NUL), printable ASCII, and not ending in `" (deleted)"`. The canonical subset already refuses non-ASCII in any form (the canonical encoding writes non-ASCII raw, so an escaped character is not the canonical form, and a raw one is not ASCII); the ASCII test on the decoded string is defence in depth. The canonical form escapes the control characters 0x01-0x1f and writes 0x7f raw, so in those spellings they reach the path check, which refuses them (PR review round 1, R1-5); the other spellings (raw 0x01-0x1f, which is not even JSON, and escaped 0x7f) are refused by the canonical subset (an unlinked file at the enrolled path would otherwise match its own link); status 13 on any refusal. `GateConfig::writer_executable` carries its bytes. The production value `/opt/planeon/bin/harness-policy-write` is data in the signed document (a `HOST_PATHS` needle cannot be a binary constant) | DESIGN §5; Q-A2-5 (a); D1-1 |
| R84 | The re-vendor (owner decision Q-A2-1 (a)): `contracts/seccomp-v4/EFFECT_GATE.{aarch64,x86_64}.bpf` are edge record v3's two rows byte for byte (1512 B, 189 instructions, sha256 `8de80a2b…`; 1600 B, 200 instructions, sha256 `4e516f16…`; mode 100644; consumer packet `HE-003A2`), each MET-ENFORCE-025's v3 program with one 6-instruction block inserted (x86_64 at index 173 for 267, aarch64 at 34 for 78: `JEQ nr`, `LD arg0 low`, `AND 0x80000000`, `JEQ 0`, `RET ALLOW`, `RET KILL`); the seal embeds them (`include_bytes!`, length pins 200/189), the tests pin their digests, sizes and decode counts. The v3 files stay pinned but are no longer embedded (`CONTRACTS` 15 → 17), so edge record v3's carried HE-002S rows stay true. `readlinkat` left `KILLED_WRAPPERS` (98 names), re-derived by the kept classifier (R77); the "After the seal" column was re-run over v4 | DESIGN §2; Q-A2-1 (a); D1-7, D1-13 |
| R85 | Gate rules (`tools/gate.py`): `FOREIGN_ITEMS[openat.rs]` = {`openat`, `readlinkat`} (refused in any other linked source); `CONTRACTS` 17; `KILLED_WRAPPERS` without `readlinkat`; the `read_link` rule (D2-2): over the linked crates' non-test sources and the binary, read without comments and with literals kept, the word `read_link` occurs exactly twice, as its definition `fn read_link(` in `openat.rs` and as the one call `read_link("exe", ..)` in `channel.rs`, so a second call, a call elsewhere, another name and a reference without a call (a fn item) refuse; and the word `readlinkat` occurs exactly twice in `openat.rs` (read without comments, with literals kept and emptied alike), as its declaration inside the extern block and as the one call inside `read_link`'s body, and in no other linked source, so no second wrapper under another name can read a link (PR review round 1, R1-3); HE-003D PR N1 and N2 as R72 now says (D2-1's scope, widened by R1-1 and R1-2). The earlier test files change only on the §8 lines (Q-A2-10 (a)): `effect-gate/tests/seal.rs` :3, :60-61, :107-108, :121; `gate-tls/tests/signed_config.rs` :9, :68, :83 (the cross-version case v2 → v1), :84; `effect-gate/tests/gate_config.rs` the builder's `enrolledWriter` line and :275 (now :276, the other-version case v2 → v1); `effect-gate/tests/substrate_support/mod.rs` the `FakePeer::exe_ok` field, its `true` in `broker_peer` and `writer_peer`, and `FakeOs::writer_exe_ok`; `gate-tls/tests/tls_support/mod.rs` `LoopOs::writer_exe_ok`. New config tests are in `effect-gate/tests/gate_config_v2.rs` with their own builder | DESIGN §6, §8; Q-A2-9 (a), Q-A2-10 (a); D1-1, D1-3, D2-1, D2-2, D2-3 |

### Evidence

- The killed-wrapper classifier (D1-13), kept in the operator's state directory as `tools/w03/he003a2/classify_wrappers.py`
  (sha256 `97cb5f2b90aa68ae73dd87cab4c67f89055aebb4dc4c736b3fcc9927d4c71ca0`), with its vector set
  `classify_wrappers.vectors.json` (90 vectors, sha256 `694dfd2daf4bc10083b71a242bb51c4ef0fa843f28a776f0f400b4fed2ed966c`)
  and output `classify_wrappers.out.txt`: a classic-BPF interpreter (seccomp's subset) over the two v3 and the two v4
  programs. Vectors: the zero vector; for each argument position, 0, 1, 2, 3, 0x7fffffff, 0x80000000, `AT_FDCWD` in
  both encodings, -1 and three 64-bit values whose low word decides; the same values in every position; and one witness
  per feasible path of every argument-filtered body (each path's word constraints solved from its compared constants).
  A wrapper's primary call per target is its own name's call where the target defines it (the vendored libc crate's
  musl `SYS_` table), otherwise the call musl's wrapper issues (a recorded alias table: `open` → `openat` on aarch64,
  `readlink` and `realpath` → `readlinkat` on aarch64, `stat` → `newfstatat`, the spawning wrappers → `execve`, …);
  name-based where possible keeps the list conservative. Result: the v4 programs are v3 plus exactly the one block;
  over every call number 0..1099, the x32 range and 0xffffffff on both targets, v3 and v4 differ only for 267 (x86_64)
  and 78 (aarch64), 80 of 90 vectors from KILL to ALLOW (the 10 whose first argument's low word has bit 31 set stay KILL); the derived
  v3 list equals R10 `7743e55`'s 99 names, the derived v4 list the 98 of `KILLED_WRAPPERS` now; `readlinkat` left,
  nothing joined. aarch64's `readlink` and `realpath` are argument-filtered under v4 (78) but stay listed through
  x86_64 (89, unconditional).
- musl's `readlinkat.lo` on both targets: next to R40.
- The shipped `planeon-gate` links musl's `readlinkat` and `LinuxOs::writer_exe_ok` on both targets (2,592,824 bytes on
  x86_64, 2,300,888 on aarch64); its killed-call wrappers are the same twelve as HE-003D's (R77's table); no membarrier,
  no build-host path. The other eight binaries and their SBOMs are byte-identical to HE-003D's.

### Code and audit

- `gate-sys/src/openat.rs`: the `readlinkat` declaration in the one extern block, `Dir::read_link` (one `unsafe` block
  with its `// SAFETY:` argument; the module's third place of `unsafe`). `channel.rs`: `ProcDir::exe`.
- `effect-gate`: `peers.rs` (`writer_exe_buffer_len`, `writer_exe_matches`); `substrate.rs` (`Os::writer_exe_ok`, the
  order in `qualify` and `custody`, `Quiet`); `linux_os.rs` (the private `writer_executable`, both constructors,
  `writer_exe_ok`); `gate_config.rs` (`FORMAT` v2, `enrolledWriter`, `DELETED_SUFFIX`, `GateConfig::writer_executable`);
  `seal.rs` (the v4 `include_bytes!` and pins). `crates/gate/src/main.rs`: the argument to `LinuxOs::with_net`.
  `gate-tls/src/signed_config.rs`: its module documentation names the v2 payload (no code change).
- Tests (host): `gate-sys/tests/read_link_he003a2.rs` (4: real symbolic links; exact count with a byte to spare, a link
  filling the buffer, the `" (deleted)"` rendering against the enrolled buffer, an empty buffer, a missing name, a
  regular file and a directory, every refused name including an absolute one); `effect-gate/tests/writer_exe.rs` (3:
  the pure functions' exact, longer, truncated, `" (deleted)"`, empty, prefix and one-byte-off cases, and their
  composition with `Dir::read_link` on real links); `effect-gate/tests/substrate_writer_exe.rs` (6: accept match and
  mismatch closed unfed, the order with the probe after the read at accept and on every frame, no read for an
  unqualified peer, a per-frame mismatch to N12, broker peers never checked); `effect-gate/tests/gate_config_v2.rs` (6:
  valid, missing and extra members, relative, `.`, `..`, trailing `/`, NUL, `" (deleted)"`, 255 and 256 bytes,
  non-ASCII raw and escaped, control characters escaped and raw, a v1 document). The gate's self-test gains cases for
  every new rule and each N1 form (the reviewer's Q25-Q30, D2-1's three, and PR review round 1's path-qualified,
  parenthesised and higher-ranked Fn forms, shift and comparison discriminants, unbalanced angle brackets and a second
  `readlinkat` wrapper).
- Departures, each within the design's intent: `Dir::read_link` refuses an empty buffer before the call (the design's
  "buffer of length 0" case; musl would substitute a 1-byte buffer); `writer_exe_matches` also refuses an empty enrolled
  value; the ASCII test on the decoded `executable` (defence in depth) and the refusal of control characters (R1-5); `enrolledWriter` is checked after the credentials;
  `main.rs` binds the two listener plans to locals before the call; `FakeOs` records an `exe #N` trace entry; `Quiet`
  and `LoopOs` return false; `signed_config.rs`'s documentation (a stale v1 payload line) is updated, its code is not.

### Carried

- HE-007 (the writer side of O-W03-WRITER-EXE): the writer's real, effective and saved uid and gid 0; dumpable at every
  frame; its permitted capability set empty before its filter (the capset drop), with the host policy granting the
  writer `process setcap` on itself; the writer started by the enrolled canonical path, which holds no symbolic link in
  any component, in the host mount and user namespace (no `RootDirectory=`/chroot, bind mount or remap in either unit,
  no `PrivateUsers=`), so its `exe` link renders as the enrolled path; no exec away from the enrolled binary.
- HE-008: `/opt/planeon/bin` root-only, with no rename into place; a writer upgrade ends the writer session first
  (replacing the binary during a live session HELDs the generation, Q-A2-13 (a)); `/proc` with `hidepid=0` and no
  `ProtectProc=` that hides the writer from the gate; the gate's fsuid and fsgid 0 at start; the signed configuration's
  `enrolledWriter.executable` (`/opt/planeon/bin/harness-policy-write`) and the fs-verity digest at enrollment.
- T04: `readlinkat` on the writer's `exe` through the retained directory on the real kernel (the ptrace access-mode
  check under the conditions above, SELinux `lnk_file read` through matrix v5's `procAccess`), its errno set and its
  truncation without an error; the check on the real writer at accept and on every frame; a replaced binary HELDs the
  generation; the steady-state trace with `readlinkat` allowed for a non-negative dirfd and aarch64's `readlink` killed
  by its argument; the installed filter equal to the v4 digest.
- A later W03-plan meta packet registers HE-003A2 by name (MET-ENFORCE-029 R1-3); harness-onion's R1-2 is moot, since
  the v3 files stay (Q-A2-1 (a)).
- Standing (R42): every later `FatalReason` joins `FATAL_REASONS` (none added here).

### Owner decisions (verbatim as relayed, 2026-10-16)

> [lane monitor] HE-003A2: Q-A2-1, 2, 5, 6, 9, 10 and 13 = (a), as recommended and with the reviewer's agreement. Monitor (owner-delegated), 2026-10-16, against DESIGN rev 2.1 (b4af83af…). Record verbatim.
> - Q-A2-1: keep the seccomp-v3 EFFECT_GATE pinned but not embedded.
> - Q-A2-2: Dir::read_link via musl's wrapper, caller-pinned, plus ProcDir::exe.
> - Q-A2-5: a top-level enrolledWriter object.
> - Q-A2-6: a REQUIRED LinuxOs constructor argument, with no None.
> - Q-A2-9: extend N1 to Fn traits, fn pointers and enum variant fields.
> - Q-A2-10: the declared earlier-test departures.
> - Q-A2-13: a live writer replacement HELDs the generation; carried to HE-007/HE-008 as "end the writer session before any writer upgrade".
> The carried host preconditions and the path-not-content residual (fs-verity at enrollment) are noted.
> GO for the build under capped.zsh. It waits on HOLD_CARGO until PERF-040's measurements end; I'll lift it then. The sim and push go on my word.

## HE-004A: the observer substrate (crate `planeon-observer`: `seal`, `status`, the binary; `contracts/seccomp-v3/OBSERVER.*`)

HE-004A (design revision 2.1, sha256 `bc8d076e…`; design reviews round 1 CHANGES_REQUIRED (D1-1..D1-10), round 2
PASS_FOR_BUILD with D2-1 and D2-2 applied in revision 2.1 and D2-3..D2-5 followed; PR review round 1
CHANGES_REQUIRED (R1-1, R1-2 MINOR, R1-3..R1-5 NOTE), each applied; owner decisions Q-HE4A-1..7, Q-HE4A-B1
and Q-HE4A-B2, quoted at the end) is the first part of HE-004 under the owner's split (Q-HE4-2 (a): A substrate, then B
the I06/ADM-4 logic, C the apiserver client, D captures and NP-3). It holds SEC-4 and HI-7 for OBSERVER: the observer
installs exactly the published OBSERVER programs, and seals to uid/gid 0, exactly CAP_NET_ADMIN and CAP_BPF in permitted
= effective = bounding, ambient and inheritable empty, no_new_privs, RLIMIT_CORE 0/0 and seccomp mode 2 with TSYNC. No
configuration is read (Q-HE4A-1 (b): DESIGN-A rev 2.1 §10 option (b), which the monitor's "(a), as recommended" below
decided; the monitor confirmed that reading on 2026-10-16, quoted in the HE-003A3 section, which records it under D1-1);
nothing serves after the seal (Q-HE4A-2 (a)). Its rules are R86-R90. The effect
gate's crates and binary do not change; the earlier test files do not change.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R86 | The observer binary (`crates/observer/src/main.rs`) and its exit statuses (`status.rs`): on Linux `main` runs seal stage 1 as its first statement, seal stage 2 as the next statement with nothing between them, and then exits with `status::NOT_YET_SERVING` (10), the pinned tail; on other targets a stub exits with `status::NOT_LINUX` (2). No argv, no environment, nothing printed. Each failure point has its own status, distinct, non-zero and below 200 (systemd reserves 200-243): stage 1 in 40-54 (`Threads(One)` 40, `UserIds` 41, `GroupIds` 42, `StartCapabilities` 43, `StartBounding` 44, `StartAmbient` 45, `StartState` 46, `Program` 47, `CoreLimit` 48, `CoreLimitReadBack` 49, `Ambient` 50, `Capabilities` 51, `CapabilitiesReadBack` 52, `NoNewPrivs` 53, `NoNewPrivsReadBack` 54), stage 2 in 60-66 (`Threads(Two)` 60, `FinalCapabilities` 61, `FinalBounding` 62, `FinalAmbient` 63, `FinalNoNewPrivs` 64, `FinalCoreLimit` 65, `Filter` 66), one total mapping per `SealStep` variant. After a successful seal only the not-yet-serving exit runs under the filter: return from `main`, the runtime's cleanup and musl's exit (exit_group, munmap, sigaltstack, rt_sigprocmask, lseek, close and write on that path, each allowed by both OBSERVER programs per the design review's probes; T04 traces it). HE-008 must not deploy the unit with `Restart=` before HE-004B and HE-004C | DESIGN §5; Q-HE4A-2 (a); D1-10, D2-3 |
| R87 | The observer's seal (`crates/observer/src/seal.rs`, safe Rust over `gate_sys::seal`, unchanged and role-neutral). Preconditions: one thread (the `Threads:` line of the process's own status file) and real, effective and saved uid and gid 0. Start state: `capget`, `PR_CAPBSET_READ` 0..=40 with `PR_CAPBSET_READ(41)` failing with EINVAL, and `PR_CAP_AMBIENT_IS_SET` 0..=40; accepted only when the bounding set already equals {CAP_NET_ADMIN, CAP_BPF}, the permitted set holds both and the ambient set is empty, checked in that order before any write (`planeon_observer_t` has no `setpcap` in matrix v5, so a bounding drop is impossible and `PR_CAPBSET_DROP` is never called; a refused start makes no write). Stage 1: the core limit 0/0 read back (dumpability kept: nothing calls `PR_SET_DUMPABLE`, which gate-sys's `process_control` cannot reach); the ambient set asserted empty (not cleared); `capset` to permitted = effective = the two with inheritable empty, read back; no_new_privs 1, read back. Stage 2: one thread again; the final-state assertion (`capget`, the bounding and ambient sets, no_new_privs, the core limit), the last reads before the running architecture's OBSERVER program, installed with `SECCOMP_FILTER_FLAG_TSYNC` (a positive return is the id of a thread that could not be synchronised; any return but 0 fails). Nothing follows the install. Every step's failure and read-back mismatch is a typed `SealError`; the library never exits. The engine over the crate-private `SealOps` is crate-private and `seal_stage1`/`seal_stage2` are public only on Linux and concrete over gate-sys, so `Stage1` and `Sealed` are constructible only by the real stages (effect-gate's D6). The private helpers are copied from effect-gate's seal with its test cases (owner decision Q-HE4A-6 (a)); the observer's `Prctl` has no `BoundingDrop` and no `AmbientClearAll` variant (a departure accepted by the monitor, owner-delegated, 2026-10-16), so the seal engine cannot make either call; gate-sys's public `process_control` still accepts `PR_CAPBSET_DROP`, and the kernel refuses a bounding drop without CAP_SETPCAP, which `planeon_observer_t` lacks (PR review round 1, R1-5), and `PR_CAP_AMBIENT` with `PR_CAP_AMBIENT_CLEAR_ALL`, a no-op on the ambient set the seal asserts empty (HE-003A3, D1-2) | DESIGN §4; Q-HE4A-6 (a); D1-9, D2-4, D2-5; PR R1-5 |
| R88 | The programs (owner decision Q-HE4A-4 (a)): `contracts/seccomp-v3/OBSERVER.{aarch64,x86_64}.bpf` are edge records v2's and v3's two HE-004 rows byte for byte (harness-onion MET-ENFORCE-025, `5da1265`; read at `d2ef7083`; 1816 B, 227 instructions, sha256 `d31c8410…`; 1904 B, 238 instructions, sha256 `e793aae5…`; mode 100644), pinned in `CONTRACTS` (17 → 19) with their provenance in `contracts/PROVENANCE.md`. The seal embeds both on every target with `include_bytes!` into statics typed `&[u8; 1904]` and `&[u8; 1816]` (the length is pinned at compile time) and instruction counts 238 and 227 asserted at compile time and checked by `plan`; the tests pin their sha256, lengths and classic-BPF shape (five opcodes, argument low words only, one ERRNO(ENOSYS) return for clone3). `RUNNING_ARCH` selects the installed one | DESIGN §2, §4; Q-HE4A-4 (a); D1-10 |
| R89 | The crate's shape (owner decision Q-HE4A-7 (a)): `planeon-observer` has a library target (`src/lib.rs`: `seal`, `status`, both roots `#![forbid(unsafe_code)]`) and its binary; it depends on `gate-sys` by path and drops `host-common`; its SBOM's workspace set is {planeon-observer, gate-sys}. Its tests pin the programs' sha256 with i05-protocol's CAVP-tested SHA-256 through a test-only `[dev-dependencies]` path edge, not linked into the binary and not in its closure; `Cargo.lock`'s `planeon-observer` package therefore lists `gate-sys` and `i05-protocol` (a departure accepted by the monitor, owner-delegated, 2026-10-16) | DESIGN §3; Q-HE4A-7 (a); D1-5, D2-4 |
| R90 | Gate rules (`tools/gate.py`): `OBSERVER_LINKED_CRATES` = {crates/observer, crates/gate-sys} is exactly planeon-observer's closure (a path dependency outside it, effect-gate's crates included, refuses); crates/observer joins every linked-crate scan (`SCANNED_CRATES`: the linked-source tripwire, foreign items, Debug, socket modules, read_link, macros, code before main, prints, and the store-opening rule's unbound-open scan), and `CRATE_ROOTS` gains its `lib.rs` and `main.rs` with `#![forbid(unsafe_code)]`; its `main.rs` has the binary's one exit import (`use std::process::ExitCode;`, removed once before the refused-path scan); the seal-order grammar and the main.rs shape rules are parameterised by a site (main.rs, the files read before the seal, the calls allowed between the stages, the pinned imports and functions): the gate's is unchanged and the observer's (D2-3) has no configuration file, allows between the stages only `Ok`, `Err`, `ExitCode::from` and `status::seal` (the stage-1 statement's own arms), pins its four imports and two `fn main`, and requires the stage-1 statement exact, the exact stage-2 statement right after it (nothing between) and then exactly `ExitCode::from(status::NOT_YET_SERVING)` closing `main`; crates/observer (only it: gate-sys's own `Dir::file` and `Dir::sync` definitions stay) names none of `POST_SEAL_FORBIDDEN` and, in its code with comments and literal contents removed, none of the words `file`, `FileMode`, `sync`, `sync_all`, `sync_data`, `lock_shared`, `try_lock`/`try_lock_shared`, `unlock`, `lock` (Mutex::lock too, in the single-threaded observer), `write_at` and `write_all_at` (D2-2) in any form: method call, path call, function item, turbofish, type path or import, only `sync` followed by `::` passing as a module path segment (`std::sync::atomic`) (PR review round 1, R1-1), nor `Drop`, so no destructor defined in crates/observer runs under the filter (R1-4; gate-sys's one Drop impl, SockCreate's, is in the channel module, which the socket-module rule keeps from the observer); and each built `planeon-observer` has no `membarrier` or `__membarrier` symbol (D1-1: musl's wrapper passes no zero third argument, which the OBSERVER row's exact-argument rule kills; HE-004D, if it needs a fence, calls `SYS_membarrier` directly with all six arguments, and musl's `membarrier.lo` stays unlinked in every native binary) and holds its architecture's OBSERVER program bytes exactly once (D1-10, D2-5; SEC-4 evidence: stage 1 also names the program, so a dropped stage 2 is the seal-order grammar's to catch, PR review round 1, R1-3). No observer wrapper inventory (owner decision Q-HE4A-B2 (a); see below). The gate's own rules, lists and inventory (R77) are unchanged | DESIGN §6; D1-1..D1-3, D1-10, D2-2..D2-5; Q-HE4A-B2 (a); PR R1-1, R1-3, R1-4 |

### SEC-4 for OBSERVER, and the open item OBSERVER-WRAPPER-INVENTORY

SEC-4 for OBSERVER rests on: the digest- and length-pinned OBSERVER programs (R88), present exactly once in each built
`planeon-observer` (R90); the post-seal and linked-source rules over the observer's crates (R90), with the pinned tail
that leaves only the not-yet-serving exit under the filter (R86); and T04's proof on the real kernel that the installed
filter equals the OBSERVER digest.

OBSERVER-WRAPPER-INVENTORY (open): the design's symbol inventory for `planeon-observer` (DESIGN §6, D1-2, D2-1: musl
wrappers whose system call the OBSERVER filter kills for some argument vector, each present one with a reviewed
justification) is not part of HE-004A. It was dropped by owner decision Q-HE4A-B2 (a) after both classifier attempts
were stopped before any file was written; its later route is the owner's call (for example a human-curated list or a
T04 trace), with no agent tooling. Until it lands, `planeon-observer`'s symbol table is checked only for membarrier.

### Evidence

- Host tests, `planeon-observer`: 15 unit tests over a fake kernel in `src/seal.rs` (the planned calls in order, 222 for
  a seal; stage 1 alone; six accepted start states; eleven refused start states, each making only the 87 start reads and
  no write; uid/gid refusals; a second thread at either stage; every call failure at its own step; capset EPERM; C9's
  EINVAL for capabilities 0..=40 in five reads and capability 41 answered; every read-back mismatch; prctl values other
  than 0 and 1; TSYNC and other non-zero returns; the final-state assertion last before the filter and every ignored
  write caught by its read-back; and D2-5's three assertions, checked after every run and over 1346 runs: no
  `PR_CAPBSET_DROP`, no write for a refused start, nothing after the filter); `tests/observer_seal.rs` (6: the copied
  helpers against effect-gate's cases, the programs' sha256, lengths, counts and decode); `tests/observer_status.rs` (2:
  the table distinct, non-zero, below 200, in its ranges, `NOT_YET_SERVING` apart from every seal status).
- The gate's self-test gains cases for every new rule: the observer's seal grammar (nothing between the stages, the
  exact first stage, the pinned tail, imports, items, the gate's site unchanged), every linked-crate scan over
  crates/observer, the exit import, the post-seal list (each form, gate-sys's definitions allowed), the closure, the
  binary check (no membarrier, the program exactly once, not zero or more times, not truncated).
- Both musl builds of `planeon-observer` hold their own OBSERVER program exactly once; the x86_64 build does not hold the
  aarch64 bytes, the aarch64 build holds the x86_64 bytes once as well (both are compiled in; the rule is about each
  binary's own program).

### Code and audit

- `crates/observer/src/seal.rs`: no `unsafe`; the raw calls are gate-sys's `seal.rs`, unchanged (its module comment
  still names effect-gate as the only plan, now out of date by one; left unedited so planeon-gate stays byte-identical,
  D1-9). `status.rs`, `lib.rs`, `main.rs`: sequencing and tables only.
- `crates/observer/Cargo.toml` and `Cargo.lock` (only planeon-observer's edges); `contracts/seccomp-v3/OBSERVER.*` and
  `contracts/PROVENANCE.md`; `tools/gate.py` and `tools/test_gate.py`.
- Departures, each accepted (monitor, owner-delegated, 2026-10-16): the test-only `i05-protocol` dev-dependency (R89) and
  the smaller `Prctl` enum (R87). The wrapper inventory is not built (Q-HE4A-B2 (a)).

### Carried

- HE-008 (the observer's unit and host policy; G5-G7): uid and gid 0; the final bounding set {CAP_NET_ADMIN, CAP_BPF} at
  start (matrix v5 grants no `setpcap`); no `AmbientCapabilities=`; `RUST_BACKTRACE` unset; fds 0-2 open at start; no
  systemd seccomp option; `core_pattern`; the self-permissions `process setcap getcap setrlimit` and the reads of its own
  `/proc/self/status`; no `setrlimit`/`getrlimit` on other domains (`prlimit64` is unconditional in the OBSERVER row);
  dumpability kept; the RBAC grants; no `Restart=` before HE-004B and HE-004C (R86).
- T04: the installed filter equals the OBSERVER digest; `Seccomp_filters: 1`; the trace of the exit path after the seal;
  `PR_CAPBSET_READ(41)` returns EINVAL on the target kernel (CAP_LAST_CAP 40); TSYNC and dumpability at exec.
- HE-005..HE-007: a shared, role-neutral seal module extracted before they add their seals (Q-HE4A-6 (a)), so the
  observer's copied helpers do not become one of four copies.
- HE-004D: any membarrier fence as a direct six-argument system call (R90); captures, inspector policy and NP-3.
- The I05-v4 adoption packet takes STRUCT-ANGLE with both fixes (Q-HE4A-5 (a)): struct fields split at commas only where
  the depths of `(`, `[`, `{` and of generic angle brackets are all zero (`<`/`>` counted only as a generic argument list
  after a type path; shift and comparison operators inside brackets never affect the split), and the struct body found
  after the generic parameter list and any where-clause.
- OBSERVER-WRAPPER-INVENTORY (above): the owner's call.
- Out of HE-004A: I01 (after the OBSERVER listener seccomp successor, Q-HE4-1 (a)), the I06/ADM-4 logic (HE-004B), the
  apiserver client and the observer's signed configuration (HE-004C).

### Owner decisions (as relayed, 2026-10-16: Q-HE4A-1..7 and Q-HE4A-B2 verbatim, Q-HE4A-B1 in excerpt)

> [lane monitor] HE-004A: Q-HE4A-1 to Q-HE4A-7 = (a), as recommended and agreed by the reviewer. Monitor (owner-delegated), 2026-10-16, against DESIGN-A rev 2.1 (bc8d076e…). Record verbatim. The HE-008/T04 carried items are noted.

> [lane monitor] Owner decision Q-HE4A-B1 = (a), 2026-10-16: the table method with no disassembly automation, the same method HE-003A2's v1 used.
> […]
> Monitor (owner-delegated): both build departures accepted. i05-protocol is a dev-dependency for the digest-pin tests only (not linked; record the lock edge), and the Prctl enum has no BoundingDrop/AmbientClearAll variants.

> [lane monitor] Owner decision Q-HE4A-B2 = (a), 2026-10-16. Record verbatim, with both classifier stops.
> - Build the non-dependent parts of steps 5-7 now.
> - Drop the observer wrapper inventory from HE-004A and carry it as the explicit open item OBSERVER-WRAPPER-INVENTORY in MODEL_DEFINED.
> - SEC-4 for OBSERVER rests on: the digest- and length-pinned programs, present exactly once per binary; the post-seal and linked-source rules; and T04's installed-filter proof.
> - The inventory's later route is the owner's call (e.g. a human-curated list or a T04 trace). No agent attempts at any classifier or inventory tooling, by any route.
> Continue. The sim goes on my word.

Q-HE4A-B1's omitted lines describe the table method, which was not built (Q-HE4A-B2 (a)). The complete messages, with
their context (both classifier attempts stopped before any file was written, neither retried), are recorded in the
operator's `tools/w03/he004/OWNER_DECISIONS.md`.

## HE-003A3: the I05 gate channel v4, the gate's worker observation (`observation`, `fake_kernel`, `config`, `gate_config`, `gate`, `policy_gate`, `linux_os`, `status`; crate `gate-sys`: `KernelRoot`, `FixedPath`, `read_bounded`, `PidFd::open`, `PidFd::poll_zero`; the binary's `serve`)

HE-003A3 (design revision 2.2, sha256 `f487b168…`; design reviews round 1 CHANGES_REQUIRED (D1-1 MAJOR, D1-2..D1-10),
round 2 CHANGES_REQUIRED (D2-1..D2-8), round 3 PASS_FOR_BUILD with D3-1..D3-5 applied in revision 2.2; owner and
monitor decisions Q-A3-1..15 (a) and Q-HE4-13 (a), quoted at the end) adopts harness-onion's I05 gate channel v4
(MET-ENFORCE-030, merged as `fd362f9e`): the gate no longer looks the BIND's worker up in a static `observedWorkers` list
but observes the kernel at every BIND (v4's B1-B6), so R70's empty-list rule (Q-HE3D-2 (a)) is gone. The wire does not
change: frames stay `planeon.internal.effect-gate-frame/v3` and `i05-protocol` is byte-identical. The v4 README and
vectors are copied byte for byte (`contracts/i05-v4/`, registered for HE-003A3 by edge record v4, `c69e55f8`; provenance
in `contracts/PROVENANCE.md`); the v4 model `scripts/i05_gate_channel_v4.py` (sha256 `95c690cd…`, "v4 model" below) is
pinned by digest, read as specification only where the README is silent, and never copied. It also carries STRUCT-ANGLE
and the struct-body defect (Q-HE4A-5 (a)), HE-004A's D1-1 and D1-2, and Q-HE4-13's stale comment. Its rules are
R91-R97.

### Points taken from the v4 model (the README is silent; lines at `fd362f9e`)

| # | Point | v4 model |
|---|---|---|
| K1 | A configuration that holds `observedWorkers` is refused, whatever else it holds, before the kernel table is read; the refusal text is vector C01's | `:315-316` |
| K2 | The kernel table's closed shapes and their texts: exactly `{"processes": [..]}`, each process exactly `{pid, startTicks, cgroup}`, a positive integer pid not already live, a start time of at least 0, a cgroup path starting with `/` (C02-C09) | `:317-326`, `:365-369` |
| K3 | The model-only events: KERNEL_SPAWN, KERNEL_EXIT and KERNEL_MOVE with closed shapes and their refusals (M01-M05); OBSERVATION_FAIL_NEXT `{type, step}` with a step of the five, OBSERVATION_RACE_NEXT `{type, after, event}` with `after` one of the first four steps and a closed kernel event (M06-M09); each output `{}` | `:371-382`, `:663-678` |
| K4 | Where the injections land: a failure fails the read of its step before it is made; a race applies its kernel event right after its step's read (step 1) or after its step passed (steps 2-4); several races for one step apply in order; a pending injection waits for the next observation that reaches its step | `:385-396`, `:398-432` |
| K5 | KERNEL_EXIT is exit and reap together: after it the pid is gone for `pidfd_open` and `stat`, and a pid spawned again is another process (the held pidfd's poll reports the exit) | `:398-432` (README rule 1 states the real-kernel difference) |
| K6 | One log entry for every BIND that reaches the observation, written before the answer, kept when the BIND record then fails (O20); GATE_RESTART does not clear the log | `:903-912`, `:679-690` |
| K7 | v4's conversion of a v3 configuration: `observedWorkers` removed and each pair a live process in the probe-worker leaf; v3's configuration refusals are checked as the conversion of `dict(ACTIVE, **override)` | `:1025-1031`, `:1177-1180` |

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R91 | Configuration (owner decision Q-A3-1 (a)). The I05 `Config` lists no worker: `observed_workers` is gone, `FIELDS` holds eight members, and a document holding `observedWorkers` is refused with C01's text (`config::STATIC_WORKERS_REFUSED`, contract text) as the first check, before the unknown-field check, so the C01 vector answers C01 (D1-6). The signed configuration is format v3 (`planeon.effect-gate-config/v3`): its `gate` member carries no `observedWorkers` (one that does is refused by `PolicyGate::new`'s `Config`, a `GateConfigError::Gate` with C01's text), every other member is unchanged, gate-tls's signing domain is `FORMAT` and follows (R83), and v2 is refused as another format. No signed document exists to migrate (the signer key is empty until HE-008) | DESIGN §3; Q-A3-1 (a); D1-6 |
| R92 | The gate's seam (Q-A3-3, Q-A3-4 (a)). `observation::WorkerObserver::observe(pid, start_ticks) -> Observation` (`Observed`, or `NotObserved { step, cause }` with R10's own `Step` and `Cause`, never the vectors' labels, IR5-1). Every gate starts with `Unobserved`, which reads nothing and answers step 1 unreadable, so a gate built without an observer refuses every BIND (HE-003D's production behaviour); `Gate::with_observer` and `PolicyGate::with_observer` replace it; constructors keep their signatures. `Gate::bind` asks the observer once, at the place of HE-003D's list check: after every check through MANIFEST_REUSED and before the BIND record, and only for a BIND that passed them all (OB01-OB18; no earlier liveness check, IR5-1). `NotObserved` is the existing non-fatal, retryable `WORKER_NOT_OBSERVED`: the channel stays open, nothing durable is written and the snapshot is unchanged. The PolicyGate's BINDs reach the same `Gate::bind` and are observed identically (R10-defined; v4 is silent on I07). The local diagnostic log (Q-A3-7 (a)): `Gate::observation_log()`, the last 64 `(pid, start ticks, observation)` entries, oldest first, and a saturating count of the entries dropped to keep that bound; in memory only: not durable, not in the snapshot, not on the wire, never printed; not cleared by GATE_RESTART (K6), empty after a process restart. `Gate` and `PolicyGate` are not `Send`: the observer field is a `Box<dyn WorkerObserver>` without a `Send` bound, so `store.rs`'s `Stores: Send` bound no longer makes `Gate` `Send`; nothing needs it, since the gate is single-threaded (`tools/gate.py` refuses `std::thread` and `thread::` in the linked sources) and every test builds and drives its gate on one thread (a departure accepted by the monitor, recorded in `task-packets/HE-003A3.yaml`; PR review round 1, R1-6, carried to HE-004B1) | DESIGN §4; Q-A3-3, Q-A3-4, Q-A3-7 (a); IR5-1; PR R1-6 |
| R93 | The driver (Q-A3-13 (a), D1-1): `KernelObserver<K: KernelReads>` is the five-step observation, portable, host-tested and run by every replay; `KernelReads` is the four kernel calls only (`read_leaf_procs`, `pidfd_open(pid)`, `read_stat(pid)`, `poll_zero(&pidfd)` with the closed `PidState::{Alive, Exited}`), each failure a `KernelFail::{Os(errno), TooLong, NoErrno}` (D3-4: a failure without an errno maps to its step's cause, never a panic). Step 1: the member file read and parsed, `workerPid` listed; an unreadable, over-long (the driver re-checks 65,536 bytes) or malformed file is `Unreadable`, an unlisted pid `NotListed`; a `workerPid` that is not a `pid_t` of at least 1 is never listed (compared at full width; a `0` line never matches). Step 2: `pidfd_open`; ESRCH `Gone`, any other failure `OpenFailed`. Step 3: the `stat` file read and parsed (the driver re-checks 4,096 bytes); ENOENT or ESRCH `Gone`, any other failure or a refused parse `Unreadable`, a start time other than `workerStartTicks` `StartDiffers` (a negative `workerStartTicks` included; compared as `u64`). Step 4: the member file read afresh, with step 1's causes. Step 5: the zero-timeout poll; a failure `PollFailed`, any event `Exited`. The pidfd is a local of the observation and closes on every path when it is dropped. The parsers: `parse_leaf_procs` (each line newline-terminated ASCII digits, no sign, no leading zero, `0` itself allowed, duplicates and any order accepted, an empty file lists nothing, a number past `i32` refused) and `parse_stat_start`, a new strict parser beside HE-003A's (Q-A3-10 (a)): the fields after the last `)`, which a `(` precedes, each after exactly one space, holding no space or newline, the file ending in exactly one newline, the twentieth field ASCII digits within `u64`; HE-003A's `stat_start_time` and its peer qualification are unchanged | DESIGN §4; Q-A3-10, Q-A3-13 (a); D1-1, D1-7, D2-6, D3-4 |
| R94 | The Linux side (Q-A3-5, Q-A3-6, Q-A3-9, Q-A3-14, Q-A3-15 (a)). gate-sys `openat.rs`: `KernelRoot` (Linux only, a type of its own whose `Debug` prints its name) opened by `KernelRoot::open_kernel_root(absolute)` with `O_PATH\|O_DIRECTORY\|O_CLOEXEC` (no `open` or `read` of the directory, which matrix v5 does not grant); its only method `open_fixed(&FixedPath)` opens relative to it with `O_RDONLY\|O_CLOEXEC\|O_NOFOLLOW`. `O_PATH` is 0o10000000 on both Linux targets: the vendored libc 0.2.190's musl module (`src/unix/linux_like/linux/musl/mod.rs:522`, no architecture override), asserted at compile time; gate-sys gains no dependency (D2-7). `FixedPath` is 1-4 components of `[A-Za-z0-9._-]+`, none `.` or `..`, from a constant (`FixedPath::from_constant`) or `<pid>/stat` for a pid of at least 1 (`FixedPath::pid_stat`); its refusals are `InvalidInput` without an errno (`NoErrno` to the driver). `read_bounded(file, limit)`: plain `read` calls until one returns 0 into a buffer of `limit + 1` bytes, `None` for a longer file, nothing sized from metadata (I05 v4 rule 5); `file_ro` is unchanged (Q-A3-9 (a)). gate-sys `channel.rs`: `PidFd::open(pid)` is `pidfd_open(pid, 0)` through the existing `syscall` (no new foreign symbol; number 434 on both targets, the kernel's unified table, as the vendored libc 0.2.190's musl modules give it), its errno kept; `PidFd::poll_zero` is a zero-timeout `ppoll` for POLLIN that tells a poll error from an event (EINTR retries). effect-gate `linux_os.rs`: `KernelRoots::open_after_seal(&Sealed)` opens the cgroup2 mount's root and the proc filesystem's, the two exact calls of the start-up lint's exceptions; `LinuxKernelReads` holds exactly those two roots, opens each file afresh, caches nothing (no static or thread-local state in the file) and maps every failure to its errno or marker; its associated `Pidfd` is gate-sys's `PidFd` (D3-1: it creates no socket, and a `LinuxKernelReads` exists only after `open_after_seal(&Sealed)`). The binary's `serve`: right after `LinuxOs::with_net` and before `FileStores::open_bound`, `let Ok(kernel) = KernelRoots::open_after_seal(sealed) else { return status::OBSERVER_ROOTS };` (status 26, R71: nothing durable exists yet, so a failure leaves the generation fresh); right after the PolicyGate's create or open, `let gate = gate.with_observer(Box::new(KernelObserver::new(LinuxKernelReads::new(kernel))));`, before `Substrate::new`. Neither the substrate nor the `Os` trait is involved, so no test `Os` changes. R70's proc access gains the worker's `stat` and the leaf's `cgroup.procs` | DESIGN §5; Q-A3-5, Q-A3-6, Q-A3-9, Q-A3-14, Q-A3-15 (a); D1-3, D1-4, D2-2, D2-5, D2-7, D3-1, D3-4 |
| R95 | The fake kernel and v4's conversion (Q-A3-2 (a)): effect-gate's public, pure module `fake_kernel`, test support shared by effect-gate's and gate-tls's tests, kept out of production code by R96. `FakeKernel` implements `KernelReads` over the vectors' process table (pid -> start ticks, cgroup path and a counter value unique to each process), rendering the leaf's member file (one line per member, by pid) and a `stat` file as the kernel prints it (the start time field 22), so the replays run R93's steps and parsers; a clone shares the kernel, so the replay feeds K3's events to the one the gate observes through. It answers ESRCH for `pidfd_open` and ENOENT for `stat` of a pid it does not hold, and an injected failure with EIO (member file), EMFILE (`pidfd_open`), EACCES (`stat`) or ENOMEM (the poll); the member file's two reads are told apart by the pidfd (the second comes while the driver still holds the one last handed out); a race applies right after the next successful call at its step (K4; for steps 3 and 4 the fake cannot see the driver's comparison or recheck, so it applies right after the read, even when the pid is no longer listed at step 4, where the model applies it only after the recheck passed (v4 model `:421-426`): a difference no vector shows, since every replay consumes every injection; PR review round 1, R1-5, carried to HE-004B1). `fail_next` and `reply_next` let host tests inject any failure or content. Its refusal texts are the vectors' (K2, K3). `convert_v3_config` returns the configuration without `observedWorkers` and a fake kernel holding each pair in the leaf (K7). R10-defined: a pid is a `pid_t` of at least 1 (the model takes any positive integer) | DESIGN §3, §5; Q-A3-2 (a); D2-1; PR R1-5 |
| R96 | Gate rules (`tools/gate.py`). `CONTRACTS` 19 -> 21 (the v4 README and vectors). `STARTUP_EXCEPTIONS`: `KernelRoot::open_kernel_root("/sys/fs/cgroup")` and `KernelRoot::open_kernel_root("/proc")`, exact, once each, in `linux_os.rs`. The linked-source tripwire's `fs`-word rule has the single matching exception: that same exact `KernelRoot::open_kernel_root("/sys/fs/cgroup")` expression, removed once and only in `linux_os.rs` before the `fs` scan (`check_linked_sources`), so its path segment passes while any other `fs` word, a second such call, the call in another file or in a comment still refuses (PR review round 1, R1-7, carried to HE-004B1). The observation rules (`check_observation`, over the linked non-test sources): the words `open_kernel_root`, `open_after_seal`, `from_constant`, `pid_stat` and `open_fixed` occur only as their one definition and their exact calls (the two root opens inside `KernelRoots::open_after_seal`'s body; `KernelRoots::open_after_seal(sealed)` once in `main.rs`; `FixedPath::from_constant` with the probe-worker leaf's literal exactly once and `FixedPath::pid_stat(` once in `linux_os.rs`; `open_fixed` only as a method call there); every item-level impl header naming `WorkerObserver` or `KernelReads` is one of `impl WorkerObserver for Unobserved`, `impl<K: KernelReads> WorkerObserver for KernelObserver<K>` and `impl<K: KernelReads> KernelObserver<K>` (observation.rs), `impl KernelReads for LinuxKernelReads` (linux_os.rs) and `impl KernelReads for FakeKernel` (fake_kernel.rs), each exactly once (no other, blanket, generic, primitive or path-qualified impl; test-only observers live in integration tests, D3-2); `fake_kernel`, `FakeKernel` and `convert_v3_config` occur (comments removed, literal contents emptied) only in `fake_kernel.rs`, as `lib.rs`'s one `pub mod fake_kernel;` and inside strict in-source test modules (`#[cfg(test)]` alone on its line, directly above `mod tests {`, with no other attribute, D3-2); `fake_kernel.rs` re-exports nothing, defines no struct but `FakeKernel`, no enum, union or trait, no impl but its two, no type item but the one `type Pidfd` in its `KernelReads` impl (D3-1), and names neither observer (no wrapper); no linked source renames or aliases `WorkerObserver`, `KernelReads`, `KernelObserver`, `FakeKernel`, `KernelRoot`, `KernelRoots`, `FixedPath` or `LinuxKernelReads`; `LinuxKernelReads`'s fields are exactly two private `KernelRoot`s and `linux_os.rs` names no `static`, `thread_local!` or once or lazy cell (D3-4). The socket-module rule's private-alias refusal exempts exactly one `type Pidfd = PidFd;` inside `impl KernelReads for LinuxKernelReads` (D3-1). The wiring (`check_observer_wiring`): serve's two statements exactly once each, in the order `LinuxOs::with_net`, the roots, `FileStores::open_bound`, the observer, `Substrate::new(gate, ..)`; `with_observer`, `KernelRoots`, `LinuxKernelReads` and `KernelObserver` nowhere else in `main.rs` but its imports; exactly two `let gate` bindings, the second the observer's. `MAIN_USES` gains `effect_gate::linux_os::{KernelRoots, LinuxKernelReads}` and `effect_gate::KernelObserver`; `BEFORE_SEAL_REFUSED` gains `KernelRoots`; `DEBUG_HAZARDS` gains `KernelRoot`. `FOREIGN_ITEMS` is unchanged (a declared `pidfd_open` stays refused). STRUCT-ANGLE and the struct-body defect (Q-HE4A-5 (a), D1-5, D2-3, D3-3): `struct_fields` skips the generic parameter list and any where-clause with a context-aware bracket scanner (`bracket_scan`): in type position every `<` opens and every `>` closes an angle level (`>>` two, `->` none), so generic arguments, qualified paths and `for<'a>` nest; an array length after its `;` up to its matching `]` and every `{ }` block are expressions, where angles are operators; a `(` after the generics opens a tuple body (then only a where-clause and `;`), else the body is the `{` at depth 0 of all four kinds, or a unit struct ends at its `;`; fields split at commas at depth 0; a `=` at the body's depth 0 (a field default) refuses, as does anything the scanner cannot delimit. HE-004B1 hardens two of these rules (PR review round 1, R1-2 and R1-3; R104) | DESIGN §6; D1-5, D2-1, D2-2, D2-3, D2-5, D3-1..D3-4; PR R1-7 |
| R97 | Tests. The declared earlier-test departures (D1-2, D2-4): only the lines that build a configuration change, to v4's conversion and its fake kernel: `tests/support/mod.rs`, `replay_i05.rs` (the five v3 refusals checked through the conversion, K7), `robustness.rs`, `stores_restart.rs`, `stores_durable.rs`, `substrate_support/mod.rs`, `policy_support/mod.rs`, gate-tls `i04_substrate.rs` and `upstream_substrate.rs`, and, by amendment A1 (owner decision Q-A3-A1 (a), 2026-10-17: the design's list missed them), `file_support/mod.rs` (the gate-building lines of `Driven::memory`, `create` and `open`), `robustness_i07.rs`, `answer_late.rs` and `substrate.rs` (`replay_supplement.rs`, `local_vectors.rs`, `local_vectors_i07.rs`, `replay_i07.rs` and `stores_suites.rs` build through the support modules and need no change); the format tests `gate_config.rs` (the member removed; the removed-rule test now expects C01 for a list or an empty list), `gate_config_v2.rs` (the member removed; FORMAT v3; v2 refused as another version) and gate-tls `signed_config.rs:68` (the v3 domain); `gate_status.rs` (`STAGES` gains 26); the in-source test modules of `gate.rs`, `policy_gate.rs` and `substrate.rs`. Every other expectation is unchanged; every v3, supplement and I07 v3 replay keeps its expectations through the conversion. The v4 replay compares each observation as R10's `(pid, start ticks, observation)` through a test-side table from the vectors' labels (`tests/observation_support`), never as effect-gate text (IR5-1, D1-9) | DESIGN §3, §9; D1-2, D1-9, D2-4 |

### Evidence

- Host tests: `cargo test` runs 65 binaries and 452 tests, all passing (base `dcaf26f`: 62 and 427). The changes are
  exactly the new ones: effect-gate's unit tests 58 -> 60 (`observation.rs`: the log's bound and drop counter,
  `Unobserved`), and the new binaries `tests/observation.rs` (14), `tests/replay_i05_v4.rs` (6) and gate-sys's
  `tests/observation_reads.rs` (3); every earlier binary keeps its count. Every v3 replay keeps its expectations
  through v4's conversion and the fake kernel: the 120 transcripts on both frame paths (503 frames), the five
  configuration refusals (K7), S01-S06, the R10-local vectors, the 62 I07 v3 transcripts (21 BINDs) and the file-store,
  restart and robustness suites. `git diff --name-status dcaf26f -- '*/tests/*'` lists only R97's files as modified
  and the four new files as added.
- The v4 vectors (56 checks): O01-O20 on both frame paths, each with every output, the final snapshot and the local
  log equal to the vectors (each entry through the test-side table), every injection consumed, no race refused, and
  each of the 16 refused observations leaving the whole snapshot unchanged; together they give all 11 (step, cause)
  pairs and OBSERVED. OB01-OB18: the nine answers before the observation, each with both workers, nothing observed
  for the last BIND. C01 through `Config` and C02-C09 through `FakeKernel::from_table`, and M01-M09 through
  `FakeKernel::event`, each with the vectors' exact text. The vectors' pins of the four v3 files equal R10's bytes, and
  their three configurations are v3's converted plus the kernel table.
- IR5-1 (D1-9): for each of the nine answers before the observation, a BIND naming a worker that does not exist (pid
  9999) gets that answer and a counting observer records no call for it.
- Host tests of the driver and the Linux side's portable parts: every step and cause with each errno or marker the
  reads can return (ESRCH and ENOENT where they mean gone, others, `TooLong`, `NoErrno`), the bounds re-checked on
  over-long content, the numeric edges (a `0` line, pid 0, negative and past `i32`, a negative start, full-width
  comparison), a fresh read at every call, the pidfd closed on every path (the fake's step-4 test sees no pidfd left
  held), both parsers' grammar edges and overflows, `Unobserved` through a gate, and the gate's log (66 refused BINDs:
  64 kept, 2 dropped, the snapshot unchanged, then the named member binds); gate-sys: every `FixedPath` refusal (no
  errno) and the bounded read on host files (empty, exactly the bound, one byte past it, EISDIR).
- The gate's self-test: 183 tests (base 169), the new ones covering every R96 rule and its bypass forms (exact call
  forms, function items, renamed paths, second calls, calls elsewhere; blanket, generic, primitive, path-qualified,
  where-clause and nested impls and a test-module observer; the fake kernel named outside strict test blocks, the
  lenient attribute forms, a second `pub mod`, re-exports, wrappers, other items and a second `type Pidfd`; aliases;
  a cache field, a pub field, statics and lazy cells; serve's statements missing, doubled, reordered, with another
  observer or status, a rebinding; the start-up and `fs`-word exceptions once each and nowhere else; `KernelRoots`
  before the seal; the pinned imports; every STRUCT-ANGLE form of DESIGN §6 and D3-3, read field by field and with a
  private first field before a `pub p: Poller`, and the unreadable and field-default refusals).
- `gate.py` (both musl release builds): `he-gate: passed`; 21 contract files. planeon-broker, planeon-containment and
  planeon-writer are byte-identical to HE-004A's (`a34a429`) on both targets, binaries and SBOMs. planeon-gate changes
  (x86_64 sha256 `f534bd63…`, aarch64 `2d62ef0a…`) with the same twelve reviewed wrappers of killed calls and no
  membarrier; planeon-observer changes (x86_64 `997f01b4…`, aarch64 `d9dc2216…`: gate-sys's new code and the D1-1
  comment lines) and still holds its OBSERVER program exactly once.
- The 8-word span search (the files HE-003A3 adds or changes against the I05/I07 models and validators at `a2eab93`
  and the v4 model and its validator at `fd362f9e`, contract text excluded): 0 spans over 40 files.
- `crates/i05-protocol` is byte-identical (no wire change).

### Code and audit

- `crates/effect-gate/src/observation.rs` (new): the seam, the driver, the parsers, the log; no `unsafe` (the root
  forbids it). `fake_kernel.rs` (new): test support only, confined by R96. `config.rs`, `gate_config.rs`, `gate.rs`,
  `policy_gate.rs`, `status.rs`, `lib.rs`: R91, R92, R71. `linux_os.rs`: R94 (no new `unsafe`; gate-sys's calls only).
  `substrate.rs`: its in-source test module (R97) and Q-HE4-13's comment.
- `crates/gate-sys/src/openat.rs`: `KernelRoot`, `FixedPath`, `read_bounded` through the module's existing `openat` call
  and descriptor conversion (no new `unsafe` block); `channel.rs`: `PidFd::open` (one new `unsafe` block, the
  `syscall` call, with its `// SAFETY:` argument) and `PidFd::poll_zero` (one, the `ppoll` call).
- `crates/gate/src/main.rs`: serve's two statements and their imports (R94, R96).
- `crates/observer/src/seal.rs`, `lib.rs`: comments only (D1-1).
- `contracts/i05-v4/`, `contracts/PROVENANCE.md`; `tools/gate.py`, `tools/test_gate.py`; the tests of R97 and the new
  test files `tests/replay_i05_v4.rs`, `tests/observation.rs`, `tests/observation_support/mod.rs` (effect-gate) and
  `tests/observation_reads.rs` (gate-sys).

### Carried

- D1-1 (HE-004A's label citation): Q-HE4A-1 is DESIGN-A rev 2.1 §10 option (b), which the monitor's "(a), as
  recommended" decided; the monitor confirmed that reading on 2026-10-16 ("As recommended" governs, quoted in full in
  HE-004A's decision record). The HE-004A section text and the two crate comments now say so; the quote above and
  `task-packets/HE-004A.yaml` stay as history. D1-2: R87 names `PR_CAP_AMBIENT_CLEAR_ALL` beside `PR_CAPBSET_DROP`.
  Q-HE4-13: `substrate.rs`'s module text; `peers.rs` unchanged (D3-5); a note beside the Q-HE2S-10 quote.
- T04 (native): the observation on a real kernel (the pidfd and `stat` behaviour, rule 5's bounds, an exited but unreaped
  worker's real-kernel cause, README rule 1); the `O_PATH` open of the cgroup2 root needs dir search on `/`, `/sys` and
  `/sys/fs` (outside matrix v5) and the cgroup2 root's own type (host policy); cgroup2 is mounted at `/sys/fs/cgroup` and
  is the host's (rule 7: another root fails closed); the probe-worker leaf stays a domain cgroup with no threaded
  descendants (rule 2, the broker's obligation); one pid namespace and one time namespace or boottime offset; the
  gate's proc fd is that namespace's procfs; `hidepid=0` and the gate outside the mount's `gid=` group (rule 8).
- HE-005 (the broker): the probe worker runs in the leaf before its BIND and is a thread-group leader; the leaf's type.
- HE-008 (the unit and host policy): I05-8's preconditions above that are deployment (mounts, namespaces, `hidepid`,
  `ProtectProc=` unset for the gate), the signed v3 configuration, and the signer key.
- A later packet: the diagnostic log's durable storage, rotation and access control (README "Still open").
- Not in this packet's paths, left as found: gate-tls `src/signed_config.rs`'s module text still gives the v2 domain as
  its example (the code uses `FORMAT`); `tests/gate_config.rs:1-3` and `:34` still describe the document with an
  empty `observedWorkers`, and `tests/gate_config_v2.rs` keeps its v2 test name.

### Amendment A1 (owner decision Q-A3-A1 (a), 2026-10-17)

The build found that DESIGN §3's declared earlier-test departures missed four test files that build gates from
configurations carrying `observedWorkers`: `tests/file_support/mod.rs` (where `stores_suites.rs`, `stores_durable.rs` and
`stores_restart.rs` build their file-store gates), `tests/robustness_i07.rs`, `tests/answer_late.rs` and
`tests/substrate.rs`; without them 18 tests in 6 targets failed (the C01 refusal, or a BIND refused by the default
`Unobserved`). The owner approved recommendation (a): the four files join the declared departures under the same rule,
so only their gate-building lines change, to v4's conversion and its fake kernel (R97).

### Owner decisions (verbatim as relayed, 2026-10-16)

> [lane monitor] … 2. HE-003A3 rev 2.2 PASS_FOR_BUILD is noted. Monitor decisions (owner-delegated), all as recommended and agreed by the reviewer:
>    - Q-A3-1 to Q-A3-15 = (a);
>    - Q-HE4-13 (a): fix the substrate.rs:39 broker-identity comment in this packet; peers.rs is unchanged per D3-5.
>    Record them verbatim. The build waits for slot 245's merge and my GO.

> [lane monitor] Q-HE4A-1 confirmed, monitor decision (owner-delegated):
> - "As recommended" governs. Q-HE4A-1 = DESIGN-A rev 2.1 §10 option (b): no observer configuration in HE-004A; it arrives with HE-004C.
> - That is the substance your own question listed as the recommendation, and my "(a)" referred to that recommendation, not to DESIGN-A's (a) label.

## HE-004B1: the observer's RBAC snapshot, OR predicates and ADM-4 logic (crate `planeon-observer`: `inputs`, `rbac`, `snapshot`, `operational`, `admission`, `contracts`; `contracts/i06-v2/`, `contracts/i06-v1/`, `contracts/admission-v3/`)

HE-004B1 (HE-004B design revision 2.2, sha256 `b86b5c2d…`; design reviews round 1 CHANGES_REQUIRED (D1-1, D1-2 MAJOR,
D1-3..D1-18), round 2 CHANGES_REQUIRED (D2-1 MAJOR, D2-2..D2-7), round 3 PASS_FOR_BUILD with D3-1 and D3-2 applied in
revision 2.2; monitor and owner decisions Q-HE4B-0..12, quoted at the end) is the second part of HE-004 under the
owner's split (Q-HE4-2 (a)) and the first half of HE-004B (Q-HE4B-0 (a)); its other half, the I06 evidence composition
(I06-2), is folded into HE-004D (Q-HE4B-11 (b)). It carries the logic of I06-3 (R1-7: a non-resource-URL rule bound to
the loopback user refuses the snapshot) and of ADM-4 (the loaded manifest hash checked before ACTIVE; HE-008 binds the
record, Q-HE4-9 (a)). Everything is pure logic over parsed values and byte strings, exercised by host tests over the
vendored vectors and R10-local cases: nothing in `main` calls it (stage 1, stage 2, then `NOT_YET_SERVING`, unchanged),
so planeon-observer's behaviour does not change, while its bytes do (the new modules and the linked i05-protocol). The
ten contract files are copied byte for byte (edge record v4, rows 34-43; provenance in `contracts/PROVENANCE.md`); the
models `scripts/i06_backend_profile.py` (v1, sha256 `bea3c953…`), `scripts/i06_backend_profile_v2.py` (`58ceb7a6…`) and
`scripts/admission_semantics_v3.py` (`3db8f51a…`) are pinned by digest, read as specification only where the READMEs are
silent, and never copied. It also carries HE-003A3's PR review round 1 items R1-2 and R1-3 (gate rules, R104), R1-5,
R1-6 and R1-7 (the R95, R92 and R96 text above) and records R1-4 as a T04/HE-008 residual (below). Its rules are
R98-R105.

### Points taken from the pinned models (the READMEs are silent; lines at harness-onion `75669de`, the same bytes as at `3cba1171`)

| # | Point | Model |
|---|---|---|
| P1 | The snapshot check's order: the qualification namespace (a DNS label outside the system namespaces), the closed snapshot and its version; then, subject by subject in list order, the closed subject, its kind (User, Group, ServiceAccount), a text name, a boolean `exists` and a list of rules, the service-account prefix exactly for kind ServiceAccount, absence only for service accounts, no repeat, each rule closed; the policy-relevant grants (none: the next subject); a controller account marked absent is judged against its bootstrap grants and its closure entry (IC02); otherwise IC01 (not in the closure), IC02 (marked absent), IC03 (the first grant in sorted order outside the entry), IC04 (escalate and bind need named roles within the entry's); after every subject, IC05 over the closure entries in sorted order | `i06_backend_profile.py:598-647` |
| P2 | v2 adds, after v1's check, that the loopback user holds no rule at all | `i06_backend_profile_v2.py:39, 88-96` |
| P3 | The grant classification: `*` matches every resource, `*/x` any `<r>/x`, a `userextras/*` target any of its keys; verb `*` and `impersonate:<mode>`/`impersonate-on:<..>` count as special; a write verb is POLICY_WRITE on a policy pair, else STATUS_WRITE on a status pair; a workload verb counts only at CLUSTER or in a protected namespace | `:220-256` |
| P4 | An allowed row: ALL allows everything; otherwise category, resource and verb equal, and the row's scope (QUALIFICATION_NAMESPACE read as the namespace) equal to the grant's or CLUSTER | `:276-285` |
| P5 | A text: a non-empty string equal to its Python `strip()` (CPython 3.12's whitespace) | `:204-205` |
| P6 | The controller accounts: each inventory controller's non-empty `serviceAccount`, in kube-system | `:334-340` |
| P7 | The bootstrap baseline: each bootstrap subject's rules without their `binding`, by (kind, name) | `:343-364` |
| P8 | The nine tables (R100 pins their digests) | `:98-152` |
| P9 | The directory hash: names sorted; a lower-cased name ending in `.yaml`, `.yml` or `.json` with non-empty content is read; each read content and one NUL into SHA-256; `"sha256:"` and lowercase hex, or `""` | `admission_semantics_v3.py:481-490` |
| P10 | The A2 comparison: C21 when the loaded hash is not the pinned one (claims Q06, Q07) | `:528-579`, `:555` |

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R98 | The inputs (`inputs`; Q-HE4B-9 (a); D1-1, D2-1, D2-4, D3-1). The closed request specs are `Resource`'s 20 entries; `Resource::spec` is the request the apiserver client (HE-004C) must issue, exactly: the eighteen I07 v3 policy kinds, LimitRanges, Namespaces, ResourceQuotas and ServiceAccounts (core `v1`), NetworkPolicies (`networking.k8s.io/v1`), Roles, RoleBindings, ClusterRoles and ClusterRoleBindings (`rbac.authorization.k8s.io/v1`), the validating and mutating webhook configurations, MutatingAdmissionPolicies and their bindings, ValidatingAdmissionPolicies and their bindings (`admissionregistration.k8s.io/v1`), APIServices (`apiregistration.k8s.io/v1`), CustomResourceDefinitions (`apiextensions.k8s.io/v1`) and CertificateSigningRequests (`certificates.k8s.io/v1`), the namespaced ones over all namespaces and the others cluster-scoped, never with a label selector; and OR05's two Secret lists (core `v1` secrets over all namespaces, field selectors exactly `type=kubernetes.io/service-account-token` and `type=bootstrap.kubernetes.io/token`, answered as `PartialObjectMetadataList` of `meta.k8s.io/v1`). The I07 table gives versions only for its seven writable kinds; the other eleven are R10's choice, each kind's `v1`; an apiserver that serves the MutatingAdmissionPolicy kinds at another version only cannot answer the spec, so their pairs are missing and OR02 and OR06 refuse (fail closed). An input is a pair of a stated spec and a body (the list value, or NotServed: no version of the resource is served, attested by HE-004C's discovery over every served version of its group). `Inputs::new` refuses, pair by pair: a spec outside the set (another version, group or scope, a namespace, any label selector, any other field selector), a second pair for one entry, NotServed outside {MutatingAdmissionPolicies, MutatingAdmissionPolicyBindings}, and in a served answer: not an object; `kind` and `apiVersion` other than the entry's list kind (a list paired with another spec); `metadata` present but not an object, a `continue` present and not exactly `""` (any non-string included), any `remainingItemCount`; `items` not an array; an item without an object `metadata` holding a non-empty text `name`; a namespaced kind's item without a non-empty text namespace, a cluster-scoped kind's item with a `namespace` member; a repeated (namespace, name). A function's missing pair refuses (`InputError::Missing`), never an empty default, and NotServed never stands for a list a function needs served (the RBAC lists, OR05's). A name or namespace holding a lone surrogate is refused as malformed (an apiserver's JSON is UTF-8). HE-004C keeps: issuing exactly these requests (the pairing is its statement), watch continuity, one resourceVersion across the lists, restart invalidation (the readiness doc's completeness and continuity proof) | DESIGN-B §4.1; Q-HE4B-9 (a); D1-1, D2-1, D2-4, D3-1 |
| R99 | The effective-RBAC producer (`rbac::produce_snapshot`; Q-HE4B-3 (a) "Direct grants only"; D1-3, D1-18), no model. It reads the five RBAC lists (each refusal of R98 first), then every ClusterRole and every Role, bound or not: `rules` absent or null holds none, each rule's five lists absent or null are empty and otherwise lists of texts, and a rule with non-empty `nonResourceURLs` beside non-empty `resources` is Malformed (refusal 4). The bindings follow in a fixed order, the ClusterRoleBindings by name and then the RoleBindings by namespace and name, whatever the list order, each checked in turn: its `roleRef` (`apiGroup` `rbac.authorization.k8s.io`, `kind` ClusterRole, or Role in a RoleBinding only, a non-empty name; else Malformed); its subjects (absent or null: none; each an object with a non-empty text name and kind User, Group or ServiceAccount, else Malformed; a service account without a namespace, absent or empty, is in the RoleBinding's namespace and is Malformed in a ClusterRoleBinding); the role (a Role by the binding's namespace and name, a ClusterRole by name; none: DanglingRoleRef, refusal 3); OR03 (a ClusterRole with an `aggregationRule` key, of any value, bound by any ClusterRoleBinding or by a RoleBinding in the qualification namespace: AggregatedRole, refusal 2); R1-7 (a role holding a non-resource-URL rule bound by a binding whose subjects directly name {User, system:apiserver}: LoopbackNonResource, refusal 1; group membership is not reaching, so the stock bootstrap's non-resource roles bound to system:masters and system:authenticated are dropped). Each subject entry is one per (kind, name): a service account is `system:serviceaccount:<namespace>:<name>`, a User so named stays a User (IC00 judges it, S21), Groups are not expanded; it takes each binding's resource rules as `{apiGroups, resources, verbs, resourceNames, scope}` (`CLUSTER` for a ClusterRoleBinding, the binding's namespace for a RoleBinding) in binding and then rule order, duplicates kept; its non-resource-URL rules are dropped and counted once per (subject, rule) in `Produced::dropped_non_resource_rules`, which is not part of the snapshot. `exists` is true for Users and Groups and, for a service account, whether the ServiceAccount list holds it. The subjects come out sorted by (kind, name); a subject whose every rule was dropped is listed with none. Impersonation (D1-18): `impersonate`, `impersonate:<mode>`, `impersonate-on:<..>` and `serviceaccounts/token` create are ordinary rules with no path expansion, since the closure allows impersonation only to system:masters (ALL) and token creation only to system:kube-controller-manager, so any other holder refuses at IC01 or IC03. The texts are R10's (`ProduceError`'s Display) | DESIGN-B §4.2; Q-HE4B-3 (a); D1-3, D1-18, D2-6 |
| R100 | The snapshot check (`snapshot`; Q-HE4B-4 (a); D1-11, D2-2). `check_rbac_snapshot(snapshot, namespace)` reads the embedded closure, inventory and bootstrap (`Closure::embedded`, no caller-supplied closure) and runs v1 (P1) and then v2 (P2); `Closure::check_v1` is v1 alone. Disclosed (the Q-HE2-R1 precedent): it follows the models' decomposition and check order, which the vectors pin, and is written independently. The refusal texts the I06 v2 vectors pin are contract text and compared exactly; the unpinned ones (the closed snapshot, its version or subject list, a closed subject, a subject's fields, a closed rule, a present closure identity marked absent) are R10's texts with the models' codes, and the embedded data's own refusals (unreachable: the bytes are pinned) start with `IC`. R10-defined: a subject's kind or name, or a text of a rule, holding a lone surrogate is refused at IC00 where the model reads a text (no apiserver JSON holds one, and an R10 refusal text cannot carry it). With the embedded data the IC02 refusal of a present closure identity marked absent is unreachable: all 13 closure service accounts are inventory controller accounts, so a marked-absent one takes the bootstrap branch. The tables (P8) are transcribed as data, with group-name constants and R10's comments, and each table's canonical digest (the sha256 of the canonical JSON of the sorted `[group, resource]` pairs, of `[group, resource, [verbs in model order]]` for SPECIAL_TARGETS, or of the list in model order) is pinned: POLICY_RESOURCES 22 rows `00d07f87…`, STATUS_RESOURCES 7 `77441220…`, WORKLOAD_RESOURCES 9 `26981eea…`, SPECIAL_TARGETS 20 `ead65df5…`, KUBELET_VERBS 5 `b906f85c…`, WRITE_VERBS 5 `f862c1c7…`, WORKLOAD_VERBS 3 `a841aba1…`, PROTECTED_NAMESPACES 1 `93e8c6f8…`, SYSTEM_NAMESPACES 4 `df490723…` (the design's values, recomputed from the model at build) | DESIGN-B §4.3; Q-HE4B-4 (a); D1-11, D2-2 |
| R101 | The operational rules (`operational`; D1-5, D2-4, D3-1, D3-2), no model and no vector. OR02: `policy_kinds` re-checks i05-protocol's embedded `policy-kinds.json` against its registered digest (`4e427204…`) and reads the writable and then the not-writable kinds in table order, each mapped to its closed spec; every kind's pair must exist; a NotServed pair holds no object; an item's `metadata.ownerReferences` absent, null or an empty list passes and anything else refuses. OR05: both metadata-only Secret lists served and empty; no Secret data or `type` is read. OR06: the validating and mutating webhook configurations, MutatingAdmissionPolicies and their bindings, each a complete empty list or (the last two only) NotServed; OR02 and OR06 read the same pairs, so they cannot disagree about a kind. Each refusal names its rule | DESIGN-B §4.4; D1-5, D2-4, D3-1, D3-2 |
| R102 | ADM-4 (`admission`; Q-HE4-9 (a), Q-HE4B-8 (a), Q-HE4B-12 (a); D1-4, D1-16, D2-3). `manifest_directory_hash(entries)` is the reference derivation for HE-008's enrollment and the tests (P9): duplicate names refuse; names in byte order (Python's code-point order); a name is read when its ASCII-lower-cased form ends in `.yaml`, `.yml` or `.json` (no non-ASCII character lower-cases to one of those letters, so this equals the model's `str.lower()`) and its content is non-empty. `check_loaded_manifest(input)`: the caller supplies the pinned hash (from the signed configuration), the expected `plugin` label value (a caller input until HE-004C confirms the label), every sample it parsed of `apiserver_manifest_admission_config_controller_last_config_info` (`plugin`, `apiserver_id_hash`, `hash`), the Kubernetes version and the observation binding (`recordDigest` `sha256:` and 64 lowercase hex digits, or `nonce` of 32 to 64 lowercase hex digits; `windowStart` and `windowEnd` canonical UTC `YYYY-MM-DDTHH:MM:SSZ`, real calendar instants of years 0001-9999 without leap seconds, start before end), a malformed binding being an input error before any record. Verdicts: UNAVAILABLE unless the version is the accepted constant `v1.37.1` (the ALPHA-metric residual, changed only by a reviewed packet at each upgrade), for an empty expected plugin (R10 detail: an empty label value is an absent label), for any sample of another plugin, for zero or several samples of the expected plugin, and for a malformed or empty loaded or pinned hash (the model's empty-equals-empty is refused); otherwise MATCH when the one sample's hash equals the pinned hash and MISMATCH when it differs (Q06, Q07). The record `planeon.internal.observer-adm4/v1` (R10-defined): `{schemaVersion, metricName, plugin, apiserverIdHash, kubernetesVersion, observationBinding {recordDigest or nonce, windowStart, windowEnd}, pinnedHash, loadedHash, verdict}`, each hash (the apiserver id hash included, R10 detail) copied only when it is `sha256:` and 64 lowercase hex digits and otherwise null, the loaded hash and apiserver id hash taken from the one expected-plugin sample when exactly one exists; its canonical bytes are i05-protocol's encoding (sorted keys, no whitespace, UTF-8) and its digest `"sha256:" + hex`. The binding makes each record specific to one observation; the record alone does not prevent replay, so HE-008 checks the binding against the enrollment it signs and the window's freshness | DESIGN-B §4.5; Q-HE4-9 (a), Q-HE4B-8 (a), Q-HE4B-12 (a); D1-4, D1-16, D2-3 |
| R103 | The crate and its link (Q-HE4B-6 (a) "crates/observer"; D1-7, D1-14). The modules live in `crates/observer/src` under the crate root's `#![forbid(unsafe_code)]`; `i05-protocol` moves from `[dev-dependencies]` to `[dependencies]` for its strict parser, canonical encoder, `py_eq` and SHA-256 (`Cargo.lock` is byte-identical: it already listed the edge), so planeon-observer's closure and SBOM workspace set are {planeon-observer, gate-sys, i05-protocol}. `contracts.rs` is the observer's one module of embedded contract bytes: the identity closure, the writer inventory and the bootstrap RBAC, with their registered digests and the policy-kind table's. Maps and sets are `BTreeMap`/`BTreeSet`. The residual (accepted with Q-HE4B-6 (a)): once HE-004C calls this logic after the seal, i05-protocol's code runs under the OBSERVER filter: its `impl Drop for Value` (iterative, memory only: munmap and brk, in the OBSERVER row), its embedded I05/I07 contract data, and its parser's duplicate-key check through std's `HashSet` with the default hasher, whose first use per thread asks `getrandom` (in the OBSERVER row); so "no system call beyond memory allocation" holds for the logic modules' own code, while parsing through i05-protocol may add that one `getrandom` (T04's trace covers it). Re-checked at the build base `930fdc6`: i05-protocol's only observer-list word is `impl Drop for Value` (`json.rs:253`) and it names no std fs, io, time, thread or sync | DESIGN-B §3; Q-HE4B-6 (a); D1-7, D1-14 |
| R104 | Gate rules (`tools/gate.py`). `CONTRACTS` 21 -> 31 (edge record v4's ten HE-004 rows). `OBSERVER_LINKED_CRATES` gains `crates/i05-protocol` (the closure check, the linked-crate scans, which already read it, and the SBOM follow). The observer post-seal rule reads i05-protocol's sources too (`OBSERVER_POST_SEAL_CRATES`), with json.rs's one `impl Drop for Value` removed once from its code first; gate-sys stays outside. The logic modules (`check_observer_logic`, each required), read with comments removed, literal contents emptied and the whitespace around `::` removed: every use path and every crate-rooted code path (a leading `::`, or a first segment std, core, alloc, crate, self, super, i05_protocol, gate_sys or planeon_observer) starts with `crate::{inputs, rbac, snapshot, operational, admission, contracts}`, `self::` one of the five, `i05_protocol::{json, sha256, contracts}`, `std::collections::{BTreeMap, BTreeSet, VecDeque}` or `std::{cmp, fmt, string, vec, iter, ops, str, borrow, convert, option, result}`, so `crate::seal`, `crate::status`, gate-sys, `super::` and other `self::` paths refuse; globs and renaming imports refuse (`as` in a use declaration only, D3-2); the words HashMap, HashSet and RandomState and the include macros refuse; and outside strict `#[cfg(test)]` `mod tests` blocks `unwrap(`, `expect(`, `panic!`, `unreachable!`, `todo!`, `unimplemented!`, `assert!`, `assert_eq!`, `assert_ne!` and the `debug_assert` family refuse (indexing and overflow are code review's: every index guarded, saturating or checked arithmetic). The contracts module (`check_observer_includes`): `contracts.rs` exists, and every `include_bytes!`/`include_str!` of crates/observer is one plain literal naming a registered `CONTRACTS` file relative to its own file, only in `contracts.rs` and `seal.rs`, `seal.rs`'s only its two OBSERVER programs. Carried from HE-003A3's PR review round 1: R1-2, `check_observer_wiring` refuses any let pattern holding `gate` other than plain `gate` (`let (gate, ..)`, `let mut gate`, `let Some(gate)`, `let ref gate`), any assignment to `gate`, and after the observer's attach any `gate` other than `gate.apiserver_address()` and `Substrate::new(gate, ..)` (a shadowing `let gate` also fails the count of two); R1-3, `check_observation` refuses a module item in `observation.rs` outside its strict test module, requires `Unobserved` and `KernelObserver` defined exactly once each at its top level, and its pinned impls at its top level. `main.rs`'s grammar and tail and the program-bytes-once and no-membarrier checks are unchanged | DESIGN-B §6; D1-7, D2-5, D3-2; HE-003A3 PR R1-2, R1-3 |
| R105 | Tests. New files only (every earlier test file byte-identical): `tests/observer_contracts.rs` (the embedded and test-only contract bytes, the policy-kind table at this base), `observer_inputs.rs` (the closed set against the I07 table, every input refusal, the namespace-scoped RoleBinding list and selector-filtered ServiceAccount list, a paged ServiceAccount list missing a controller account refused rather than read as absent, NotServed for the two kinds only), `observer_rbac.rs` (every producer rule and refusal, the drop count, the order, and the model-derived consistency test over the bootstrap file: 57 rebuilt bindings, every subject's rules reproduced as a multiset, a subject without rules matching absence), `observer_snapshot.rs` (the nine digests, the positive, B01-B05, S01-S35 and H01-H03 with exact texts, X05 and X06 as v2 refusals the v1 check accepts, every table row wired), `observer_round_trip.rs` (the positive rebuilt as RBAC objects reproduces itself and is accepted; every IC refusal the producer's output can reach), `observer_operational.rs`, `observer_admission.rs` (H01-H04, the R10-local hash cases, every verdict, Q06 and Q07, the binding checks, the record's bytes and digest, the binding-only digest difference) and `observer_vector_loader.rs`, with the shared `tests/b1_support` (the I06 v2 loader: `set`, `delete`, `append`, the list-element selector under `py_eq`) and `tests/b1_rbac_support` | DESIGN-B §8 |

### Evidence

- Host tests: `cargo test` runs 73 binaries and 514 tests, all passing (base `930fdc6`: 65 and 452); every earlier
  binary keeps its count, and the eight new ones are planeon-observer's `observer_inputs` (13), `observer_rbac` (13),
  `observer_snapshot` (8), `observer_round_trip` (2), `observer_operational` (8), `observer_admission` (11),
  `observer_contracts` (3) and `observer_vector_loader` (4). `git diff --name-status 930fdc6 -- '*/tests/*'` lists only
  added files (the eight and the two support modules).
- The I06 v2 replays: the positive (61 subjects) is accepted by v1 and v2; B01-B05 are accepted; S01-S35 and H01-H03
  are each refused with the vectors' exact text; for X05 and X06 the v1 check accepts and v2 refuses with the exact text.
  The nine table digests equal the design's values, recomputed from the model at build; the wiring test makes 415 checks
  (every row of every table with each of its verbs and `*`, the constrained impersonation forms, every workload row at
  cluster scope, in kube-system and, accepted, in the qualification namespace, the non-policy reads accepted, and each
  system namespace refused as the qualification namespace).
- The producer: every rule and refusal of R99 by R10-local vectors; the bootstrap-derived consistency test rebuilds 57
  bindings (50 ClusterRoleBindings, 7 RoleBindings) from the file's 259 rules and reproduces the rules of all 55
  subjects that hold any, as multisets, with Group system:unauthenticated (no rule) absent. The round trips: the I06 v2
  positive rebuilt as RBAC objects reproduces itself exactly and is accepted; eleven refusals (IC00 four ways, IC01 two,
  IC02, IC03, IC04, IC05, and v2's IC03) are reached from RBAC objects.
- ADM-4: H01-H04 replay and the vendored manifest gives the pinned `sha256:5aa2cdec…`; Q06 gives MATCH and Q07 (C21)
  MISMATCH through the comparison; the record's canonical bytes and digests (`sha256:f9927afa…` for a MATCH,
  `sha256:6cdd65b2…` for an UNAVAILABLE with nulls) equal an independent computation with Python's `json.dumps(sort_keys,
  separators, ensure_ascii=False)` and `hashlib`.
- The gate's self-test: 193 tests (base 183), the new ones covering every R104 rule and its bypass forms (i05-protocol
  in the post-seal rule with the one exception; every refused import and code path, spaced and `::`-rooted, globs,
  renames, the words and the include macros; each panicking form and the lenient test-module forms; the include rule's
  unregistered, escaping, `concat!`, raw-string and escaped paths and other files; R1-2's binding, assignment and use
  forms; R1-3's nested module, second definition, non-top-level definition and impl).
- `gate.py` (both musl release builds): `he-gate: passed`; 31 contract files. planeon-gate (binary, symbols and SBOM),
  planeon-broker, planeon-containment and planeon-writer are byte-identical to HE-003A3's (`faa5cb18`, tree `c3d876c8`,
  this base) on both targets. planeon-observer changes (x86_64 sha256 `56f3fc20…`, SBOM `c7b80f9b…`; aarch64 `6386d7e5…`,
  SBOM `6b03bb88…`: its closure and SBOM gain i05-protocol) and still holds its OBSERVER program exactly once and no
  membarrier.
- The 8-word span search (the files HE-004B1 adds or changes against the I05/I07 models and validators at `a2eab93`, the
  I05 v4 model and validator at `fd362f9e`, and the I06 v1 and v2 models and validators and the admission v3 model and
  validator at `75669de`; contract text excluded): 0 spans over 22 files.
- `crates/i05-protocol`, `crates/effect-gate/src`, `crates/gate-sys`, `crates/gate`, `crates/gate-tls` and `Cargo.lock`
  are byte-identical to `930fdc6`.

### Code and audit

- `crates/observer/src/inputs.rs`, `rbac.rs`, `snapshot.rs`, `operational.rs`, `admission.rs` (new): R98-R102, pure logic,
  no `unsafe` (the root forbids it), held to R104's whitelist and no-panic rules. `contracts.rs` (new): R103. `lib.rs`:
  the six module declarations. `Cargo.toml`: the i05-protocol edge (R103).
- `contracts/i06-v2/`, `contracts/i06-v1/`, `contracts/admission-v3/` (ten files) and `contracts/PROVENANCE.md`;
  `tools/gate.py` and `tools/test_gate.py` (R104); this file (R92, R95 and R96's carried text, this section).
- The new test files of R105. No other crate changes: `crates/i05-protocol`, `crates/effect-gate/src`, `crates/gate-sys`,
  `crates/gate` and `crates/gate-tls` are byte-identical, and `Cargo.lock` too.

### Carried

- HE-004C (the apiserver client): the live inputs issued exactly per R98's request specs, each list paired with its
  spec, and the NotServed attestation by discovery over every served version; watch continuity, one resourceVersion
  across the lists and restart invalidation (the readiness doc's completeness and continuity proof); the expected
  `plugin` label value's confirmation and the metric's exposition parsing; the pinned hash from the observer's signed
  configuration; OR01 and OR07 (the apiserver's restart, `/readyz`); quota headroom; Q-HE4-5 (the client crate) and
  Q-HE4-6 (the read grants, which follow R98's specs exactly: all-namespace Roles, RoleBindings and ServiceAccounts,
  ClusterRoles and ClusterRoleBindings, the policy-kind lists, the four OR06 kinds and API discovery, OR05's two
  field-selected metadata-only Secret lists, the non-resource URLs `/metrics` and `/readyz`); the served versions of the
  two MutatingAdmissionPolicy kinds on v1.37.1 (R98's `v1` specs).
- HE-004D: `check_qualification` and the acceptance token (Q-HE4B-1 (a)); the I06 evidence half, B2 (Q-HE4B-11 (b)),
  with the design constraints of DESIGN-B §5; W02a caller obligations 2 (complete v1/v2 histories) and 3 (inspector
  rules, the plan's "inspector policy").
- HE-008 (enrollment and host policy): binding the ADM-4 record by digest and checking its `observationBinding` against
  the enrollment it signs and the window's freshness; the production pinned hash and the manifest enrollment; I06-4 / R2-4
  (distinct backend `verityDigest` values, or reliance on the captures); the OBSERVER-WRAPPER-INVENTORY obligation, a T04
  trace with seccomp audit records (owner decision 2026-10-16); the observer's RBAC read grants (G5-G7).
- T04/HE-008 residual from HE-003A3's PR review round 1, R1-4 (lane monitor, 2026-10-17): `KernelRoot::open_fixed` opens
  with `O_RDONLY|O_CLOEXEC|O_NOFOLLOW` only, without `O_NONBLOCK` or a regular-file check; on the host's cgroup2 and proc
  mounts that is harmless, but under I05 v4 rule 7's non-host root (a writable file system mounted at the cgroup2 path)
  a FIFO planted at the leaf would block the single-threaded gate instead of failing closed; it needs root-equivalent
  write access there. T04 and HE-008 keep cgroup2 mounted at its path as the host's, or a later packet adds `O_NONBLOCK`
  to the fixed flags.
- HE-008 (units), from the owner's decision "systemd cleans" and the lane monitor's Q-SOL-7 (a), both 2026-10-17: the directory unit owning `/run/planeon/live-proxy`
  (`RuntimeDirectoryPreserve=yes`, 0700), which every listener unit pulls in with `After=` and `Requires=`, and `/run/planeon/maintenance` (the same pattern, or the gate's unit alone);
  each listener unit's `ExecStartPre=` removal of its own socket path as `init_t`, the observer's I01 socket included;
  the `planeon_run_t` file contexts for `/run/planeon` and its subdirectories; the `init_t` grant comes from the matrix
  successor. T04: the pre-start step runs as `init_t` (no transition), the file contexts, and no unit's stop removes
  another role's live socket. The refinement notes beside the HE-003A and HE-003D carried items supersede their
  `RuntimeDirectoryPreserve=no` text.
- The I06 writer-name rule: moot for admission objects under admission v3 (none is writable); policy kinds are written
  only through I07's closed WRITE_OBJECT set.
- The ALPHA metric on v1.37.1 (Q-HE4-9 (a)): re-checked at every Kubernetes upgrade, with `ACCEPTED_KUBERNETES_VERSION`
  changed only by a reviewed packet.

### Owner decisions (verbatim as relayed, 2026-10-16 and 2026-10-17)

> [lane monitor] HE-004B rev 2.2 PASS_FOR_BUILD is noted. Monitor decisions (owner-delegated, 2026-10-16), all as recommended and agreed by the reviewer:
> - Q-HE4B-0 (a): HE-004B1 first; B2 per Q-HE4B-11.
> - Q-HE4B-1 (a): check_qualification and the acceptance token in HE-004D, bound to the record digest.
> - Q-HE4B-2 (c): test-side localisation with the existing is_valid, plus the listed prefix fallback.
> - Q-HE4B-4 (a): embedded digest-pinned bytes only.
> - Q-HE4B-5 (a): two private literals as exact expressions.
> - Q-HE4B-7 (a): the next operator edge record supersedes the current one by sha256, carries B1's 10 rows with full commits, and is published by W03-PLAN-AMEND-2. Include the I05-v4 rows in the same record if they are ready by then.
> - Q-HE4B-8 (a): B compares and defines the record; C parses and supplies the pinned hash; HE-008 binds by digest.
> - Q-HE4B-9 (a): closed request specs with completeness checks; the shared NotServed input (MutatingAdmissionPolicy kinds only); metadata-only OR05 lists; quota headroom goes to C.
> - Q-HE4B-10 (a)+(c): production returns Unavailable without touching the fixture path; the v2 halves of X02–X04 are replayed.
> - Q-HE4B-11 (b): fold B2 into HE-004D after native-profile v4 and the I06 successor, and split D so its v4-only captures aren't held.
> - Q-HE4-5 and Q-HE4-6 are decided with C; Q-HE4-7 and Q-HE4-8 go through Q-HE4B-10/11 and Q-HE4B-7 as listed.

> [lane monitor] OWNER DECISIONS 2026-10-16 (typed by the owner in the monitor chat), all as recommended. Record them verbatim:
> - Q-HE4B-3 (a) "Direct grants only":
>   - R1-7 on direct User system:apiserver bindings only;
>   - refuse OR03 and dangling role refs;
>   - drop and count other subjects' non-resource rules;
>   - no group expansion.
> - Q-HE4B-6 (a) "crates/observer":
>   - the modules go in crates/observer, linking i05-protocol (closure +1);
>   - the residual (i05-protocol Value's memory-only Drop) is accepted and recorded;
>   - the gate stays byte-identical.
> - Q-HE4B-12 (a) "Fields as proposed":
>   - the fields are metric name, plugin, apiserver_id_hash, Kubernetes version, observation binding (record digest or nonce, plus window), pinned and loaded hash, verdict;
>   - UNAVAILABLE unless the version is v1.37.1 and exactly one sample comes from the expected plugin;
>   - HE-008 checks the binding and freshness.

> [lane monitor] HE-003A3 PR review r1 PASS_FOR_PUSH is noted. Your carry is accepted: R1-2/3/5/6/7 go to HE-004B1, R1-4 to the T04/HE-008 residuals, and R1-1 is a process note.

The complete messages, with the sequencing parts not quoted here, are recorded in the operator's
`tools/w03/he004/OWNER_DECISIONS.md` and `tools/w03/i05v4/OWNER_DECISIONS.md`.

## HE-004C: the observer's apiserver client and live wiring (crate `planeon-observer`: `signed_config`, `config`, `credentials`, `tls`, `client`, `linux_net`, `http`, `exposition`, `watch`, `requests`, `quota`, `utc`, `observe`, `status` and the binary's `serve`)

HE-004C (DESIGN-C revision 4, sha256 `b8a580ec…`; owner decisions of 2026-10-18: Q-HE4-5 (a), Q-HE4-6 (a) with the
`list secrets` residual accepted, Q-HE4C-1..14 all (a)) gives the policy observer its apiserver read client and wires
the observation: after the seal, `serve` reads the observer's own signed configuration, its credentials and TLS
profile, opens its Linux wire and runs the observation epoch, which has no normal end. It answers HE-004B1's carried
list (the requests exactly per R98's specs, NotServed attested by discovery, watch continuity, one resourceVersion
across the lists, restart invalidation, the plugin label and the exposition, the pinned hash, OR01, OR07, quota
headroom, Q-HE4-5, Q-HE4-6, departure 1 and PR review R1-3). No pinned model defines sockets, TLS, HTTP, watches,
`/readyz`, the exposition or quota quantities, so all of it is R10-defined (the HE-003C precedent); the code copied from
gate-tls is R10's own (Q-HE4-5 (a)), and parity tests hold the copies to gate-tls. planeon-gate, planeon-broker,
planeon-containment and planeon-writer are byte-identical; B1's five logic modules and `contracts.rs` are unchanged. No
contract file is added or changed. Its rules are R106-R119.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R106 | The epoch and the binary (Q-HE4C-1, Q-HE4C-5). One observation epoch is the process's lifetime and keeps no durable state. `main` keeps HE-004A's grammar up to the stage-2 statement and ends with exactly `ExitCode::from(serve(&sealed))`. `serve` runs, in this order: `signed_config::load` (11, 12), `ObserverConfig::parse` (13), `config::check_lifetime` (14; 97 for an unusable wall clock), `credentials::observer_inputs` (20), `client_config` (21), `LinuxWire::new(sealed)` (24), `Closure::embedded()` once (22), then `observe::run`. The epoch: `S0` and OR07 (R112), then snapshots and watching (R111, R114) until an exit. The statuses are `status::SERVING` (11-14, 20-22, 24, 80-99), each distinct, non-zero, below 200 and outside 40-79, 2 and 10; `STAGES` keeps `[2, 10]` and `NOT_YET_SERVING` stays in the table, no longer reached; `status::observation` is one exhaustive match. Per snapshot the first refusal names the exit, in this order: `Inputs::new` (86), the weighted expansion guard (99), `produce_snapshot` and `Closure::check` (87; a `ProduceError::Input` is 86), OR02, OR05, OR06 (88; an `OperationalRefusal::Input` is 86), quota (89), ADM-4 (96, then 90 or 91). There is no status 0 and no normal end; HE-008 keeps the unit without `Restart=` until HE-004-I01 | DESIGN-C §2, §14; Q-HE4C-1 (a), Q-HE4C-5 (a); D1-1, D1-2 |
| R107 | The signed configuration (`signed_config`, `config`; Q-HE4C-3 (a) with (i), Q-HE4C-12 (a)). `/etc/planeon/policy-observer/config.json` (1 B to 1 MiB) and `config.json.sig` (64 raw bytes), fixed paths, read after the seal through gate-sys's read-only `Dir`, sized by `fstat` into size + 1 (the EOF probe). Ed25519 over `UTF8("planeon.observer-config/v1") || 0x00 || document`, the signature first; the observer's own key from `crates/observer/config-signer.pub`, 0 or 32 bytes and empty until HE-008 (every document refused, 12), small-order keys refused, the key passed through `core::hint::black_box` so the shipped binary holds the composed observer. The canonical subset is R70's (ASCII, strict JSON, depth at most 16, no float, integers 0 to 2^53-1, byte-equal to i05-protocol's canonical encoding); the closed schema `{format, generation, validity {notBefore, notAfter}, apiserverAuthority, qualificationNamespace, credentials {apiserverServingCa, observerIdentity {chain (1-4), key}}, admission {pinnedManifestHash, expectedPlugin}, enrollment {nonce}}`; the checks: R19's generation form, `0 < notBefore < notAfter <= 2^53-1`, the authority's address exactly `127.0.0.1` or `::1` (Q-HE4C-13 (a), native-profile v4's values) with a port, the namespace a DNS label outside B1's system namespaces, absolute normalised paths of at most 255 bytes and `sha256:` pins, the pinned hash a pin, the plugin 1-63 of `[A-Za-z0-9._-]`, the nonce 32-64 lowercase hex (13). The lifetime runs right after the parse: `notBefore <= now < notAfter` (14), a clock before the epoch or past 9999 is 97; reaching `notAfter` while running exits 94. The generation is kept for HE-004-I01's generation-equality rule | DESIGN-C §11; D1-1 |
| R108 | Credentials and the TLS client (`credentials`, `tls`; §4.3, HE-003C's R64). R73's reader: each named file opened in its parent directory, 1-65,536 B, one buffer allocated once (`Zeroizing` for the key, `ObserverKeyBytes`), pinned by sha256 (20); the copied identifier `file` renamed (the observer's post-seal word rule); exactly one serving CA. The profile is gate-tls's, copied: TLS 1.3 only through the ring provider's three suites and X25519, P-256, P-384; `WebPkiServerVerifier` over the one serving CA; the server name the authority's IP literal (its certificate needs that IP SAN); `with_client_auth_cert` with the `planeon:policy-observer` chain and PKCS#8 key; `Resumption::disabled()`, no early data, no SNI, ALPN `http/1.1`; one configuration for the process, one connection per TCP connection, `close_notify` and the close after each exchange. The ClientHello parity test compares the first flight with gate-tls's (versions, suites, groups, signature algorithms, ALPN; no `pre_shared_key`, `early_data` or `server_name`) | DESIGN-C §4.3, §11; D1-15 |
| R109 | Transport (`client`, `linux_net`; D1-14 (a), (d)). `client.rs`'s portable `Wire` (connect, connect_result, recv, send, shutdown_write, close, wait, now, wall_seconds) with its own types; `linux_net.rs`, the observer's one socket module, maps gate-sys's existing `tcp::connect_tcp`, `tcp::connect_result`, `TcpConn` transfers and `channel::Poller` (no new `unsafe`, foreign item or file). One exchange per connection: connect 10 s, handshake 10 s, 30 s from the request to the complete answer (or a watch's head); a watch stream with no byte for 300 s has ended. Interest follows rustls's `wants_read`/`wants_write`, 64 KiB read per connection per wake, a connection only closed (never deleted from the poller explicitly), readiness handled before deadlines; a `wait` failure other than an interrupted call is 95. That `LinuxWire::new` is the only constructor and takes `&Sealed` is code review's, as for the gate | DESIGN-C §4.4; D1-2, D1-14 |
| R110 | HTTP (`http`, `exposition`, `watch`; Q-HE4C-2 (a)). The request is `GET <target> HTTP/1.1` then exactly `Host: <authority>`, `User-Agent: planeon-observer`, `Accept` and `Connection: close`; no body, `Authorization` or `Accept-Encoding`. The Accept values: lists `application/json` (OR05's two `application/json;as=PartialObjectMetadataList;g=meta.k8s.io;v=v1`), watches `application/json` (OR05's two `…;as=PartialObjectMetadata;…`), discovery, `/version` and the progress read `application/json`, `/readyz` `text/plain`, `/metrics` `text/plain;version=0.0.4`. The readers keep gate-tls's R63 rules (heads at most 16 KiB, interim answers, field forms, one length or chunked, no coding but identity, strict chunking, surplus refused) with the bounds as parameters: 4 MiB per list and 64 KiB per small document (chunked raw at most the bound + 64 KiB), 16 MiB for one snapshot's list bodies together; `/metrics` streamed, raw at most 64 MiB, lines LF-terminated and at most 16 KiB, only the ADM-4 metric and `process_start_time_seconds` kept, at most 16 kept samples; a watch stream unbounded in total, one event per line, a line over 64 KiB a change. The `Content-Length` digit bound is max(7, the bound's digits). Media types compare the type and subtype only (`/metrics` also needs `version=0.0.4`); a 200 with another media type is a framing refusal; a `/metrics` or watch answer other than 200 ends at its head. Status mapping: §5.3 and §7.3 (R112, R114) | DESIGN-C §5; Q-HE4C-2 (a); D1-7, D1-15 |
| R111 | Requests (`requests`; departure 1, Q-HE4C-10 (a)). Each target is built only from `Resource::spec()`, so its list input is paired with that spec by construction (the round-trip test parses every rendered target back for all 20 entries in every mode): `/api/v1/<resource>` or `/apis/<group>/<version>/<resource>`, OR05's field selectors percent-encoded by RFC 3986, never a label selector, `limit` or `continue`. Outside the pairing, as "when" and not "which objects", after the field selector: none for the fresh list, `resourceVersion=<R>&resourceVersionMatch=Exact` for the others, `watch=true&allowWatchBookmarks=true&resourceVersion=<RV>` for watches, `limit=1` for the per-spec probes. One resourceVersion: the first served spec in `Resource::ALL` order is read fresh and its `metadata.resourceVersion` is `R` (decimal, 1-20 digits, at most 2^64-1, else 85); every other served spec is read `Exact` at `R` and must answer exactly `R` (85); `R` must be at least every earlier mark of the epoch (85); a 410 or 504 on an `Exact` list restarts the snapshot. This relies on one storage revision counter for the listed kinds and decimal resourceVersions (W03 distribution check and T04). Discovery runs first in each snapshot: the `APIGroup` of `admissionregistration.k8s.io` (its `groupVersion` values distinct and of the group, at most 16) and each version's `APIResourceList`; for the two MutatingAdmissionPolicy kinds `v1` listing the exact name gives the spec, no version listing it gives `ListBody::NotServed`, and only another version listing it gives no pair (B1's `Missing`, 86). Upstream data says both kinds are served at `admissionregistration.k8s.io/v1` on v1.37.1, GA since 1.36 and on by default (harness-onion `architecture/i06-backend-profile/upstream-facts-v1.37.1.json:2519-2521`, cited, not vendored), so R98's `v1` specs match and NotServed arises only with the feature gate off. Order per snapshot: discovery, the lists, `/version`, `/metrics`, sequential, one connection each, no watch open | DESIGN-C §6; Q-HE4C-10 (a); D2-3, D2-5 |
| R112 | OR07 and OR01 (§7; Q-HE4C-6 (a), Q-HE4C-11 (a)). The restart marker `S0` is the exact text of the single unlabelled `process_start_time_seconds` sample, read first; then `/readyz/poststarthook/rbac/bootstrap-roles` is polled every 1 s within 300 s until it answers 200 with `text/plain` and a body of exactly `ok` (another body 84, a 404 80 at once: RBAC is not an authorizer). Until the epoch's first 200 (from `/readyz` or the `S0` scrape) a 401 or 403 means "poll again"; at the end a last 401/403 exits 82, otherwise 80; after the first 200, 401 and 403 exit 82 at once everywhere. 429 and 5xx poll again; 410 and other statuses exit 84. The marker is read before OR07, at the end of every snapshot, by the restart check after every stream end, and in every 60 s cycle; another text exits 81, zero, several or malformed samples 84. The residual window from a snapshot's final scrape to its watches is closed within 60 s. `apiserver_id_hash` is not used (upstream derives it from the host name). §7.3's outcomes for the cycle and the end check: a valid answer carries on; 81, 82, 84 (malformed marker, a progress answer not a `NamespaceList` of `v1`), 85 (a progress resourceVersion missing or not decimal, an `F` or new `R` below an earlier mark), 90, 91, 96, 97 directly; any other status, a framing refusal, a transport failure or the 30 s deadline makes the view unavailable and runs a full snapshot | DESIGN-C §7; D1-4, D1-12, D2-3, D2-4 |
| R113 | ADM-4 inputs (§8; Q-HE4C-4 (a), Q-HE4C-8 (a)). The exposition rules of R110; each kept ADM-4 sample has exactly the labels {`plugin`, `apiserver_id_hash`, `hash`}, each once and in any order, values decoded for `\\`, `\"` and `\n` and valid UTF-8, the value exactly `1`, no timestamp; a repeated label set, more than 16 samples or a final line without LF exits 84; every sample goes to B1 unfiltered (a foreign plugin's sample gives UNAVAILABLE; one sample per configured plugin would make every verdict UNAVAILABLE, a distribution check item). `expectedPlugin` and the per-enrollment nonce come from the signed configuration, the version from `/version`'s `gitVersion` (1-64 printable ASCII; a distribution suffix gives UNAVAILABLE). The binding is `BindingId::Nonce`; `windowStart` is the floored wall second at the scrape's request start, `windowEnd` `max(end, start) + 1` from the floored second at its completion, formatted by `utc.rs` (a clock before the epoch or past 9999 exits 97; `Adm4InputError` 96). MATCH is required (MISMATCH 90, UNAVAILABLE 91), at every snapshot and on every 60 s cycle scrape, after the marker, with a fresh `Adm4Input` (the same pins, the scrape's samples, the snapshot's `gitVersion`, a new window); the newest record and its digest replace the previous ones. The nonce is not secret and does not prove where a record came from: the record's origin is authenticated by HE-004-I01's channel (carried) | DESIGN-C §8; D1-5, D1-11 |
| R114 | Watch continuity and the progress rule (§9; Q-HE4C-1 (a), Q-HE4C-14 (a)). One watch per served spec from `R` (20, or 18 with both MutatingAdmissionPolicy kinds NotServed), no `timeoutSeconds`. A line: exactly `type` and `object`, `object` of the stream's kind (`PartialObjectMetadata` for OR05's); `ADDED`, `MODIFIED`, `DELETED` or a line over 64 KiB is a change: every watch closes and a snapshot runs no sooner than 1 s after the last snapshot started; `BOOKMARK` with a decimal resourceVersion is the stream's mark when above it and is otherwise ignored (it neither lowers the resume point nor counts as progress); `ERROR`, another type or a malformed line is a gap (92). A stream that ends (final chunk, EOF, reset, TLS error, 300 s idle) makes the view unavailable, gets the restart check (a scrape, the marker `S0`) and is reopened from its mark; one check covers every stream that ended before it started. A reopen answered 410 is a gap (92); 429, 503, 504 and transport failures are failed opens, retried 1 s apart: the fourth in a row, or one more than 60 s after the first, exits 83. The first open after a snapshot answered 410 or 504 restarts the snapshot within that snapshot's deadline; 429, 503 and transport failures there count as failed opens. The cycle: each starts 60 s after the previous start (the first 60 s after the first snapshot's fresh-list stamp), or as soon as the previous ends if later; first the progress read `F` (`GET /api/v1/namespaces?limit=1`, never paired or fed to B1), stamped at its request start, then (behind `PER_SPEC_PROGRESS`, off) one consistent `limit=1` probe per served spec whose marks must be at least `F` (85), then the scrape. Marks never go backwards: `F` at least the previous `F` and the snapshot's `R`, a new `R` at least every `R`, `F` and passed bookmark of the epoch (85). Progress: within 150 s of `F`'s stamp every stream must deliver a bookmark at or beyond `F`, else the view is unavailable and a fresh snapshot runs; the third such staleness in a row with no `F` passed by every stream between them exits 98. `fresh_as_of` is the latest mark every stream has passed and its stamp (the snapshot's `R` with its fresh-list stamp first). The view is available only while every stream is established and `now - stamp(fresh_as_of) <= 210 s`, so while available it reflects every change up to a resourceVersion current at most 210 s earlier, whatever the cycle spacing or exchange time. Whether idle resources' bookmarks reach `F` within 150 s depends on each resource's watch cache reaching the current revision (etcd's watch-progress notifications, ConsistentListFromCache): T04 measures it, and if it fails a reviewed packet flips `PER_SPEC_PROGRESS` (about 21 reads a minute, OR05's Secret lists included), which goes to the owner through the lane monitor as an operations change under Q-HE4C-14 (a) | DESIGN-C §9; D1-3, D1-13, D2-2, D2-3, D2-5, D2-6, D3-2, D3-4 |
| R115 | Quota headroom (`quota`; Q-HE4C-7 (a)). Over the ResourceQuotas in the qualification namespace: settled (`status.hard` equals `spec.hard`, the same keys and exact values; otherwise the snapshot restarts, 89 at its deadline); `status.used` holds every key of `status.hard` and `used <= hard` for every key, exact integers at the 10^-9 scale in i128, no rounding (89); each of I01's six units bounded by at least one key of its R10-defined mapping (`pods`/`count/pods`, `configmaps`/`count/configmaps`, `services`/`count/services`, `requests.cpu`/`cpu`, `requests.memory`/`memory`, `requests.ephemeral-storage`/`ephemeral-storage`); per unit the minimum over the covering keys of `max(0, floor(hard) - ceil(used))` in the unit (whole counts, CPU millicores, bytes), the conservative rounding only there, each figure in 0 to 2^53-1 (89). Quantities: digits with an optional fraction, then `n`, `u`, `m`, `k`, `M`, `G`, `T`, `P`, `E`, `Ki`-`Ei` or a signed exponent (`E` alone is exa), exact at 10^-9; finer than `1n`, above 2^63 base units, a sign or a fraction of a count refuse. Requests versus limits is a W03 distribution check item; `limits.*` keys are still held to `used <= hard` | DESIGN-C §10; D1-8 |
| R116 | The read grants (Q-HE4-6 (a)). One ClusterRole and one ClusterRoleBinding to User `planeon:policy-observer`, named by the next I06 successor and provisioned by HE-008: `list` and `watch` on core `limitranges`, `namespaces`, `resourcequotas`, `serviceaccounts`, `secrets`; `networking.k8s.io` `networkpolicies`; `rbac.authorization.k8s.io` `roles`, `rolebindings`, `clusterroles`, `clusterrolebindings`; `admissionregistration.k8s.io` R98's six kinds; in `apiregistration.k8s.io` `apiservices`, in `apiextensions.k8s.io` `customresourcedefinitions` and in `certificates.k8s.io` `certificatesigningrequests`; and, in its own rule (B1's producer refuses a rule with both), `get` on `/metrics`, `/readyz/poststarthook/rbac/bootstrap-roles`, `/version`, `/apis/admissionregistration.k8s.io` and `/apis/admissionregistration.k8s.io/*`. No `get` on any resource and no `*`. `/version` counts under API discovery (OBS-RBAC-1 names B1's specs, API discovery, `/metrics` and `/readyz`; the stock `system:discovery` role groups it with the discovery URLs). The progress read uses `list namespaces`. A test binds this ClusterRole to the observer in B1's positive and `produce_snapshot` and the snapshot check accept it (list, watch and non-resource get are not policy-relevant; `secrets` is no special target). The Secret residual, accepted by the owner: RBAC has no metadata-only verb, so `list`/`watch secrets` also allow full Secret reads with this credential; C requests only field-selected metadata-only lists and watches, the custody is root 0400 (`planeon_observer_cred_t`) and before HE-004-I01 the process has no way out (no write, no listener, outbound only to the apiserver). Until the grants exist every read is refused and the epoch exits 82 at the end of OR07's cold start window | DESIGN-C §12; D1-9, D1-10 |
| R117 | Memory (Q-HE4C-2 (a), refined). The stated resident bound in the snapshot phase is about 172 MiB against the OBSERVER cgroup limit (native-profile v4's fixture 256 MiB): at most 1,000,000 parsed nodes at about 128 B (~122 MiB), the string payload once more (16 MiB), one in-flight body (4 MiB decoded + 4 MiB + 64 KiB raw), the produced snapshot (at most 40,000 weight units x 512 B, ~19.5 MiB), the embedded closure (a few MiB) and rustls buffers (under 1 MiB); in the watch phase 20 x 64 KiB line buffers and one 16 KiB exposition line; bodies are dropped once parsed, the inputs and the produced snapshot after the checks. The node-count cap: before a list body is parsed, one pass counts the structural tokens `{`, `[`, `:` and `,` outside string literals; one snapshot's lists together at most 1,000,000, else 84. The byte-aware weighted expansion guard (after `Inputs::new`, before `produce_snapshot`, in `observe.rs`, so B1 is unchanged): a rule weighs 1 + the sum over the elements of its `apiGroups`, `resources`, `verbs`, `resourceNames` and `nonResourceURLs` of (1 + its UTF-8 bytes / 64, rounded up); a binding contributes |subjects| x (1 + its role's weight, the role resolved as B1 resolves it); a missing or malformed piece counts 0 (B1 refuses it next); the sum over every ClusterRoleBinding and RoleBinding, checked, at most 40,000, else 99. Stock v1.37.1 bootstrap RBAC weighs 2,852 units (7.1%). The figures are estimates T04 measures (with managedFields-heavy maximal lists); an OOM kill is the residual | DESIGN-C §16 R117; D1-7, D2-1, D2-7, D3-1, D3-3 |
| R118 | Gate rules (`tools/gate.py`, §15). G1: `REGISTRY_LINES` gains `crates/observer`, each of its four lines equal to gate-tls's. G2: `OBSERVER_LINKED_CRATES` unchanged (the gate-tls dev-dependency is outside the closure, which reads `[dependencies]`). G3: `check_tls` reads two groups, gate-tls with the binary unchanged and crates/observer (the deny-list and a server-side list on raw text, `resumption`, `enable_early_data` and `enable_sni` once each, `with_client_auth_cert` and `with_webpki_verifier` once each in its `tls.rs`, no `macro_rules`), the counts per group. G4: the observer's `linux_net.rs` joins `SOCKET_FILES`. G5: the observer's tail `ExitCode::from(serve(&<the stage-2 binding>))`, functions main, main and serve, the pinned imports with `Sealed` and serve's in-body ones, and serve's eight calls once each in order. G6: the only extra include is `include_bytes!("../config-signer.pub")` in the observer's `signed_config.rs`; both signer key files are 0 or 32 bytes. G7 (B1's PR review R1-3): `contracts.rs` holds only `pub const NAME: &[u8] = include_bytes!("<registered file>");` and `pub const NAME: &str = "<registered pin>";`. G8: the no-panic tripwire covers the thirteen HE-004C modules, `main.rs` and `status.rs`. G9: each built planeon-observer holds a rustls `ClientConnection` symbol or, when LTO inlines it, the recorded substitute, and a `planeon_observer` client, http, watch or observe symbol. Recorded: on both musl builds LTO leaves no `ClientConnection` symbol, so the substitute applies, a symbol of rustls's client handshake modules `rustls::client::hs` or `rustls::client::tls13` (only the connection path keeps them; for example `rustls::client::hs::emit_client_hello_for_retry`). A symbol counts by its own path, the item path its v0 (or legacy) mangling names outside generic arguments, read by `symbol_path`: a `core` or `alloc` instantiation over a rustls or observer type does not count (the counts found are in the evidence below). G10: `SECRET_TYPES` gains `ObserverIdentity`, `ObserverKeyBytes`, `ObserverCredential`; `DEBUG_HAZARDS` gains `LinuxWire`. G11: the report lines. The SBOM's test-only lock path: `lock_closure` reads `Cargo.lock`, which records the gate-tls dev edge, so planeon-observer's lock closure also reaches gate-tls and effect-gate; its vendored set is still exactly the 11 LINKED crates it links directly, and its workspace set comes from `[dependencies]` only. What stays code review's: what a function serve calls in turn, new public functions in the socket modules (R72's residual) and the `&Sealed` constructor | DESIGN-C §3, §15; D1-6, D1-14, D2-8 |
| R119 | Tests. New files only (every earlier test file byte-identical except `tools/test_gate.py`, whose earlier cases change only where the observer's site, the TLS groups and the socket files change): `tests/c_support/mod.rs` (the test PKI from fixed seeds with the `127.0.0.1` and `::1` SANs, a fake `Wire` with fake monotonic and wall clocks, a scripted apiserver over a rustls server that verifies the client certificate) and `observer_config.rs`, `observer_signed_config.rs`, `observer_tls.rs`, `observer_http.rs`, `observer_parity.rs`, `observer_requests.rs`, `observer_exposition.rs`, `observer_watch.rs`, `observer_quota.rs`, `observer_observe.rs`, `observer_status_c.rs` (counts in the evidence below) | DESIGN-C §17 |

### Points settled at build (inside DESIGN-C's intent)

- A `/metrics` or watch answer whose status is not 200 is read only to its head; a 200 `/metrics` head without
  `text/plain` and `version=0.0.4`, or a 200 watch head without `application/json`, is a framing refusal, and so is a
  framing refusal on an established stream (84, as on the head).
- The watch phase is one event-driven poll loop: every stream, plus at most one cycle or end-check exchange in flight.
  The snapshot and OR07 issue their requests one after another with no watch open.
- At the 120 s snapshot deadline the exit follows the last restart's cause: 83 for a transport failure, 89 for an
  unsettled quota, otherwise 93. An initial-open 410 or 504 restarts within the deadline of the snapshot just ended,
  which is cleared once every stream is established, so a cache that never reaches `R` ends in 93.
- B1's `check_loaded_manifest` runs again on each 60 s cycle's scrape; a stream-end check reads only the marker. The
  staleness count of the progress rule resets only when every stream passes a cycle's `F` by bookmarks; a new snapshot's
  `R` does not reset it. The first cycle falls due 60 s after the first snapshot's fresh-list stamp, and the schedule
  carries across snapshots.
- A discovery `APIGroup` may list at most 16 versions; a per-spec probe may read up to the 4 MiB list bound, outside the
  16 MiB snapshot total. With `PER_SPEC_PROGRESS` on, the Namespaces probe repeats the progress read's request (21 reads a
  cycle, two of them the same); both are consistent reads held to `F`.
- Statuses 22 and 24 cannot occur on a development host (the closure's bytes are pinned; `linux_net` is Linux-only); the
  tests check their constants. Status 96 is reached with a configuration built directly, since a parsed configuration
  and the rendered window cannot make `check_loaded_manifest` refuse.

### Evidence

- Host tests: `cargo test` runs 84 binaries and 591 tests, all passing (base `ffa18d3`: 73 and 514); every earlier
  binary keeps its count, and the eleven new ones are planeon-observer's `observer_config` (6), `observer_signed_config`
  (8), `observer_tls` (5), `observer_http` (5), `observer_parity` (2), `observer_requests` (6), `observer_exposition` (8),
  `observer_watch` (9), `observer_quota` (5), `observer_observe` (21) and `observer_status_c` (2). `git diff
  --name-status ffa18d3 -- '*/tests/*'` lists only added files (the eleven and `c_support/mod.rs`).
- The epoch end to end, over the fake `Wire` and the scripted rustls apiserver on fake clocks: a MATCH snapshot, then
  watching until `notAfter` (94); every epoch status 80-99 reached; OR07's cold start (401 and 403 polled until the first
  200, then 82; `/readyz` absent 80 at once, never ready 80 at 300 s); the marker changed at each read point (81); an
  `Exact` answer at another resourceVersion, a non-decimal `R` and a new `R` below the highest mark (85); snapshot
  restarts within the deadline; a change re-snapshots no sooner than 1 s after the last start; each row of §7.3 for the
  cycle and for the stream-end check; the progress rule (a stuck stream re-snapshotted, 98 at the third); the view
  unavailable while a stream reopens and past 210 s after a slipped cycle, then available again; the per-spec probes
  with `PER_SPEC_PROGRESS`'s setting on in the test; the weighted guard at 40,000 and 40,001 (99), the node cap at
  1,000,000 and one over and one snapshot's list bodies at 16 MiB (84); R116's grants bound to the observer accepted by
  B1's producer and snapshot check; the ADM-4 window. Statuses 11-14, 20 and 21 are reached by their library calls; 22
  (the pinned closure) and 24 (the Linux-only poller) cannot be reached on the host, so the tests show their constants and
  that the embedded closure loads.
- The parts: gate-tls parity (the answer reader on the framing cases; the ClientHello's versions, suites, groups,
  signature algorithms and ALPN, without `pre_shared_key`, `early_data` or `server_name`); the TLS profile (the observer's
  identity seen by the server, `close_notify`, the `::1` literal, a wrong CA, a missing IP SAN and a TLS 1.2 ServerHello
  as transport failures); the request bytes of every kind, the bounds, codings, media types and the stream reader at
  every chunk boundary; the exposition (the kept metrics, the ADM-4 label set, the three escapes, the value `1`, 16
  samples, 16 KiB lines, the final LF, 64 MiB); the watch lines (each event type, 64 KiB, a lower bookmark ignored and not
  progress, the 300 s idle end, the reopen bound 83, an initial-open 410 or 504); every rendered target parsed back to its
  spec in every mode; the quantity parser and headroom; the configuration (canonical subset, every schema and check
  refusal, the authority, the lifetime) and the signed configuration (the empty compiled key refuses every document,
  small-order keys, the gate's domain, the size bounds, the EOF probe, no parse before verification).
- The gate's self-test: 221 tests (base 193); 28 new ones in ten classes cover G1-G10 and their bypass forms (G5's
  missing, swapped and doubled calls; G9 with real v0 names, each symbol missing and a `core`/`alloc` instantiation that
  only mentions a rustls or observer type); the earlier cases change only as R119 says.
- `gate.py` (both musl release builds): `he-gate: passed`; 31 contract files. planeon-gate (binary, symbols and SBOM),
  planeon-broker, planeon-containment and planeon-writer are byte-identical to the base's (`ffa18d3`, tree `330ed0fa`) on
  both targets. planeon-observer changes (x86_64 sha256 `240a9285…`, SBOM `e735ab8c…`; aarch64 `3a10d247…`, SBOM
  `732625c2…`; at the base `56f3fc20…`, `c7b80f9b…`, `6386d7e5…`, `6b03bb88…`), holds its OBSERVER program exactly once
  and no membarrier; its SBOM's vendored set is the 11 LINKED crates and its workspace set gate-sys, i05-protocol and
  planeon-observer.
- G9 on the built binaries: no `ClientConnection` symbol on either target; 51 substitute symbols on each (own paths in
  `rustls::client::hs` and `rustls::client::tls13`); 24 (x86_64) and 23 (aarch64) symbols whose own path is in the
  observer's client, http, watch or observe module (the gate reports `planeon_observer::client::flush` over `LinuxWire`).
- The 8-word span search (the files HE-004C adds or changes against the earlier packets' model and validator sets,
  every `scripts/*.py` at harness-onion `887cbe7` and the readiness document and two READMEs DOSSIER-C names; contract
  text, `vendor/`, `.json`, `.rsp` and `Cargo.lock` excluded) finds 0 spans in HE-004C's text over 35 files. It
  reports 19 spans in text unchanged from `ffa18d3` (earlier sections of this file, gate.py's import lines and helpers,
  two contract paths and quoted owner decisions that later harness-onion scripts also hold); each is present at the
  base. Three first-run spans of HE-004C were reworded: R116's group list, a loop variable in `check_observer_tls` and
  the manifest path in `c_support` (which now takes B1's pinned value, derived from the vendored bytes by
  `observer_admission.rs`).
- `crates/i05-protocol`, `crates/effect-gate/src`, `crates/gate-sys`, `crates/gate`, `crates/gate-tls`, `contracts/`,
  B1's five logic modules, `contracts.rs`, `seal.rs` and every earlier test file are byte-identical to `ffa18d3`;
  `Cargo.lock` gains only planeon-observer's five edges.

### Code and audit

- `crates/observer/src/signed_config.rs`, `config.rs`, `credentials.rs`, `utc.rs`, `tls.rs`, `client.rs`, `linux_net.rs`
  (Linux only), `http.rs`, `exposition.rs`, `watch.rs`, `requests.rs`, `quota.rs`, `observe.rs` (new): R106-R117, no
  `unsafe` (the root forbids it; `linux_net.rs` maps gate-sys's existing safe API), held to the observer post-seal word
  rule and G8's no-panic rule. `status.rs`: `SERVING` and the three mappings. `main.rs`: the serve tail and `serve`.
  `lib.rs`: the module declarations. `Cargo.toml`: the four registry lines and the gate-tls dev edge;
  `config-signer.pub` (new, empty).
- `tools/gate.py` and `tools/test_gate.py` (R118); this file (this section); `README.md` (the observer's row) and
  `NOTICE` (planeon-observer links the vendored crates).
- The new test files of R119. No contract file and no other crate changes.

### Carried

- HE-004-I01: the observation's wire form; the seven policy digests; the whole-run requested-headroom comparison; the
  generation-equality rule; the I01 clock rules (rollback refusals); a per-request fresh mark (the progress rule bounds
  staleness at 210 s, and I01's observation validity is at most 5 s); re-assessing the Secret residual when its AF_UNIX
  listener opens a channel; the ADM-4 record's origin authenticated by I01's peer custody, not by the nonce; revisiting
  the snapshot and scrape rate with a cache or a rate limit before the view is consumed.
- HE-004D2: cross-check `apiserverAuthority` against the enrolled record's `i06-apiserver` endpoint.
- The next I06 successor after v3: name R116's role, with `/version` under API discovery; a W03 meta packet records that
  packet's OBS-RBAC-1 share (C3-2).
- HE-008: the observer's signer key and its R10 packet (whether it equals the gate's is HE-008's call); the configuration
  with a per-enrollment nonce and generation; the credentials, with the subject exactly `CN=planeon:policy-observer`, no
  `O` values, and the clientAuth EKU, root 0400 of type `planeon_observer_cred_t`; a dedicated serving CA that issues no
  other certificate with that IP SAN (ECDSA/RSA apiserver certificates are T04's); the grants; the `tcp_socket` host
  policy; the unit, without `Restart=` until HE-004-I01; binding the ADM-4 record after HE-004-I01, its origin
  authenticated by that channel; the OBS-INV-1 host; signing the `expectedPlugin` the distribution check confirms;
  optionally an audit check flagging non-metadata Secret reads by the user.
- T04 and the W03 distribution check: the client's calls under the installed OBSERVER filter (OBS-INV-1's trace and
  coverage report; the open item OBSERVER-WRAPPER-INVENTORY stays the owner's trace route, with no classifier, table or
  inventory built by any route); the plugin label and one sample per apiserver; the exposition's content type and line
  forms; `process_start_time_seconds` changing on a restart and staying unchanged across a wall-clock step without one
  (fallback: the apiserver identity Lease, a further grant and a design delta); `apiserver_id_hash`'s stability; the
  `/readyz` body; 401/403 for the observer during apiserver start-up and whether a 429 can come before authorization;
  `Exact` lists and their resourceVersion, and a 504 `ResourceVersionTooLarge` on an `Exact` list or a first watch open;
  the one-revision-counter condition and decimal resourceVersions; watch framing and bookmark frequency; bookmark progress
  on idle resources within 150 s, with the etcd watch-progress interval and whether ConsistentListFromCache is on (if it
  fails, the per-spec probes through the owner); whether a watch cache sends a bookmark below the stream's opening
  resourceVersion; list and `/metrics` sizes against the bounds; the resident memory peak against the enrolled limit,
  with managedFields-heavy maximal lists, the bytes per node and per guard unit; chunk sizes; the `gitVersion` form; 403
  on reads outside the role; the port range; the IP SAN; requests versus limits in the quota mapping; the snapshot,
  handshake and scrape rates, with the acceptance bound of no exit 83 or 93 over the run and the CPU inside its cgroup
  quota without throttling-driven deadline misses.

### Owner decisions (verbatim as relayed, 2026-10-18)

> - Q-HE4-6 = (a): one closed ClusterRole, named by the next I06 successor and provisioned by HE-008; the client certificate is exactly CN=planeon:policy-observer with no O groups and the clientAuth EKU; a refused read exits 82. The owner ACCEPTS the residual that `list secrets` returns Secret data, to be re-assessed at HE-004-I01, with the optional audit check carried.
> - Q-HE4C-14 = (a): the progress rule (a fresh resourceVersion every 60 s; every stream must pass it within 150 s; exit 98 after 3 stale snapshots; a stated bound of 210 s; per-request freshness carried to I01).
> - Q-HE4-5 = (a): modules in crates/observer, with parity tests; planeon-gate stays byte-identical.
> - Q-HE4C-1..13 (except 14) = all (a), as recommended in rev 2.
> If design review r2 changes any recommendation, bring only that one back. Record all of these verbatim and dated. After an r2 PASS_FOR_BUILD, ask me for the build GO.

The subject was DESIGN-C revision 2 (sha256 `df6b0e19…`); design review rounds 2-4 changed no recommendation, and round 4
gave PASS_FOR_BUILD on revision 4. The complete messages are recorded in the operator's
`tools/w03/he004/OWNER_DECISIONS.md`.

## HE-004D1: the observer's kernel captures and NP-3 (crate `observer-sys`; `capture_schema`, `capture_check`, `kernel_text`, `enrolled`, `capture`, `linux_capture`; `contracts/native-profile-v4/`, `contracts/native-profile-v3/qualification.schema.json`)

The packet (DESIGN-D1 revision 4, sha256 `f8189354…`; dossier questions Q-HE4D1-1..12 all (a), and Q-HE4D1-D1 (c),
Q-HE4D1-D2 (a) and Q-HE4D1-D3 (a), quoted at the end) gives the sealed policy observer its kernel captures: once per
observation cycle, right after the cycle's scrape, it takes the five P1 role captures (WORKER first, inside the broker's
frozen bracket), the P5 lifecycle capture and one ENTRY_BOUND capture per backend component, checks each with R10's port
of native-profile v4's capture checks against the enrolled qualification record, and keeps the latest set in memory.
The kernel reads go through a new std-only crate, observer-sys, whose one foreign item is `syscall` with six calls
(`openat`, `getdents64`, `readlinkat`, `fstatfs`, the verity ioctl and three `bpf` commands); every open is read-only
(NP-3). A capture failure is a slot state and never ends the epoch. The four contract files are copied byte for byte
(edge record v5; provenance in `contracts/PROVENANCE.md`); the model `scripts/native_qualification_v4.py` (sha256
`f7c71807…`, harness-onion `887cbe7`) is pinned by digest, read as specification only where the README is silent, and
never copied. planeon-gate, planeon-broker, planeon-containment and planeon-writer are byte-identical; gate-sys,
effect-gate's sources, gate-tls, i05-protocol, `crates/gate`, B1's five logic modules, `seal.rs` and HE-004C's modules
other than `lib.rs`, `main.rs`, `status.rs`, `config.rs`, `contracts.rs` and `observe.rs` are unchanged. Its rules are
R120-R135.

### Points taken from the pinned model (the README is silent; lines of `native_qualification_v4.py` at `887cbe7`)

| # | Point | Model |
|---|---|---|
| P1 | The P1 check's order: version, the record's and capture's shapes, the role, the host, the even SELinux sequence with before equal to after, the booleans, the policy digest, hardening and boot entry, the binding, the window `a <= b < d`, `b - a <= 2000`, `d - a <= 900000`; the class's route fields; the custody fields; the cgroup without its hidden keys; uniform threads; the capability sets; the members; the task count; seccomp and the frozen bracket; no descendants; the broker's delegated children; the files; the image and maps; the hook programs; the empty census | `:510-628` |
| P2 | `capture_class`: OBSERVER is DECLARED_T04; BROKER, WORKER and a role holding CAP_NET_BIND_SERVICE are LABEL_BOUND; the others OBSERVED | `:482-489` |
| P3 | The member sets: each member keyed by (pid, start ticks) with its threads keyed by (tid, start ticks), no repeat; the set read first equal to the set read last (refusal: "member or thread set changed during the inspection"); the reported members exactly that set | `:491-508` |
| P4 | The hidden cgroup keys: `selinuxLabel` always, and `path` too in the observer's own capture | `:544-546` |
| P5 | The WORKER's capability sets (owner decision D5): a bounding set of distinct names, all among those the broker enrolled; its other four sets empty | `:548-556` |
| P6 | The task count: `pids.current` equals the members' thread total (the declared bound alone for the observer's own leaf) and is at most `pidsMax` | `:580-584` |
| P7 | The hooks and the census: the seven hooks in `HOOKS` order with their pinned programs (`pinLabel` declared), and the 22 `CENSUS_ATTACH_TYPES` in the model's order, each effective list empty | `:56-57`, `:98-104`, `:621-628` |
| P8 | The files (each enrolled path once, its entry and measurement, the set complete), the OBSERVED image (`exe` path, device and inode of the measured file) and the executable maps (equal, as sorted lists, to the enrolled executable segments) | `:603-620` |
| P9 | The lifecycle capture: the marker without its label, `runFsType`, the containment cgroup ABSENT or EMPTY, the booleans, no slice member, the census well formed and complete (every parent, every enrolled cgroup and the broker service), the containment subject not resident, no unenrolled populated cgroup, `nr_descendants` equal to the census less one | `:655-688` |
| P10 | The backend binding: the component recorded, its process label and cgroup path, the executable's path, content digest and verity digest equal to the record's | `:691-706` |

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R120 | Scope and the capture view (Q-HE4D1-6, -7, -10 (a)). One set per observation cycle, in memory only (`CaptureView`: a sequence, the record's digest, the five role slots in the model's order, the lifecycle slot, the backend slots in component order, the set's start in Unix milliseconds), replaced wholesale by each set. A slot is `Taken` (the canonical capture, its digest and its `observedAt`), `NotFrozen`, `Unavailable(reason)`, `Pending` (before `validFrom`) or `Expired` (from `expiresAt - 3 s`). No capture failure ends the epoch; no `ObserverExit` variant is added. **The declared host fields (Q-HE4D1-1 (a), owner-accepted vacuous equalities):** `host`, `selinuxBefore`, `selinuxAfter`, `kernelPolicyDigest`, `booleansObserved`, `hardeningObserved` and `bootEntryObserved` are copied from the record, never read; the view carries `DECLARED_HOST_FIELDS` and `HOST_FIELDS_OBSERVED = false`, so the model's equalities on them hold by construction until HE-008 and T04 supply real reads or a follow-up contract drops them. The capturer (§13.5): R10 states only that the observer builds each capture from its own reads and the record's declared host fields (D1-12); capturer authentication is HE-004-I01's | DESIGN-D1 §13; Q-HE4D1-1, -6, -7, -10 (a); D1-12 |
| R121 | Configuration v2 and the record's source (Q-HE4D1-2 (a)). `planeon.observer-config/v2` is v1's closed schema plus a ninth member, `qualificationRecord {path, sha256}`; the path must be in `/etc/planeon/policy-observer` (the configuration's own directory, `planeon_etc_t`), not the configuration or its signature, otherwise 13 (D1-3). The signature domain stays `planeon.observer-config/v1` (unchanged); v1 documents still parse as a library call and `serve` uses `parse_with_record`, which refuses them (13). `enrolled::load_record` opens the record read-only in that directory, sizes it by `fstat` (at most 262,144 bytes, `MAX_BYTES`), reads size + 1, checks the sha256 pin (26) and requires the canonical form, so the pin equals `qualificationDigest` (27) | DESIGN-D1 §5; Q-HE4D1-2 (a); D1-3 |
| R122 | The schema load and rewrite (Q-HE4D1-3 (a)). `CaptureSchema::embedded` takes the one embedded copy of the v4 schema (`NATIVE_PROFILE_V4_SCHEMA`, G-D1-9), checks the sha256 of its canonical encoding against the model's pin `3bf244b2…`, rewrites its closed set of `if`/`then`/`else` conditionals (exactly `$defs/capture/allOf/0` and `/3`) as `allOf` + `[{if, then}, {anyOf: [if, else]}]` (i05-protocol refuses `else`), and loads four validators (capture, lifecycle, backend and the record, the last dropped after enrollment); any refusal is 25. Evidence: the replay (R130) localises all 125 schema refusals with no prefix fallback | DESIGN-D1 §6; Q-HE4D1-3 (a) |
| R123 | The enrolled record (§7). `Enrolled::new`: the v4 identity, the data bound and the `record` variant (27); R10's read-path preconditions (28): every enrolled path in the read grammar (absolute and normalised), each `files` row at most 64 MiB and each `backendFiles` row at most 1 GiB (S1), at most 512 MiB of Planeon code and 4 GiB of backend code; the five role cgroups under the planeon slice with `pidsMax` at most 4,096, each `filePaths` entry a `files` row, the hook pins under the pin root; the containment cgroup and each backend component's cgroup under the cgroup2 root, each executable a `backendFiles` row; the seal marker's path; the window (29): `validFrom < expiresAt`, both canonical UTC, `expiresAt > now`; an unusable clock is 97. `CheckedRecord` holds the record value and its digest once, discharging the model's per-call record shape check | DESIGN-D1 §7; S1 |
| R124 | observer-sys (Q-HE4D1-4, -5 (a)). A std-only workspace crate without dependencies; its root denies `unsafe_code`; only `kernel.rs` (Linux) allows it, with one `// SAFETY:` block per call. The one foreign item `syscall`, six calls by number with six further `long` arguments: x86_64 `openat` 257, `getdents64` 217, `readlinkat` 267, `fstatfs` 138, `ioctl` 16, `bpf` 321; aarch64 56, 61, 78, 44, 29, 280 (the vendored libc 0.2.190's musl modules). Four named flag sets of `O_RDONLY`, `O_PATH`, `O_DIRECTORY`, `O_NOFOLLOW`, `O_CLOEXEC` and `O_NONBLOCK`, each asserted at compile time against the OBSERVER row's mask 0x400643; `struct statfs` (120 bytes), the verity reply (`FS_IOC_MEASURE_VERITY` 0xC0046686, capacity 32, algorithm 1), procfs, cgroup2 and tmpfs magic. **Under owner Q-HE4D1-D1 (c), cited by name from v6.12 `linux/bpf.h` and `linux/capability.h`, no fetch or vendoring:** `BPF_OBJ_GET` 7, `BPF_OBJ_GET_INFO_BY_FD` 15, `BPF_PROG_QUERY` 16, `BPF_F_RDONLY`, `BPF_F_ALLOW_OVERRIDE`, `BPF_F_ALLOW_MULTI`, `BPF_F_QUERY_EFFECTIVE`, the three attribute layouts (24, 16 and 64 bytes), `struct bpf_prog_info` (232 bytes and seven offsets), the 29 attach-type numbers and the 41 capability bits; compile-time asserts check what can be checked without the headers (29 distinct attach types, 41 distinct names over 0..=40, single-bit and distinct flags). Any query error makes the slot unavailable, never an empty list; every cited constant is a T04 check item; **the residual:** a value that is wrong but distinct and accepted by the kernel stays undetected until T04. No bpffs magic: the pin mount is not checked (D1-3). Bounds refuse and never truncate: listings (65,536 processes, 64 children, a 32 KiB buffer, each listing a fresh descriptor so no seek), reads past their limit, a translated program over 64 KiB, more than 16 map ids or 64 query ids | DESIGN-D1 §4; Q-HE4D1-4, -5 (a), -D1 (c); D1-4, D1-6 |
| R125 | The P1 capture (§8, §9). The window: the wall clock `a` and the monotonic start, the role cgroup held, the members before (`cgroup.procs`, each pid's directory held, `stat`, the task listing, each task's `stat`), the process reads through the held directories (`status`, `attr/current`, `cgroup`, each thread's `status` and `attr/current`; OBSERVED roles `maps`, `exe` and the four namespace links), the descriptor checks (each enrolled file's open, facts, verity and memo digest; the cgroup's inode, limits, `pids.current`, children and `cgroup.stat`; the broker's service directory; the seven hook programs with local and effective queries and the 22-type census), the OBSERVED role's second `maps`, the members after, and `b = a + elapsed`; over 2,000 ms is "inspection window exceeded". "Observe faithfully, let the port decide": the engine refuses early only for read failures, R10's bounds, the window, the bracket's start and the record's window. Each member's `cgroup` must name the role's cgroup (D1-12). The OBSERVER's own capture holds cgroup facts only, and its one member must be its own pid, read from the proc root's `self` link (R2-6; not `std::process::id()`, which the linked-source rule refuses); the link read is held by HE-002S-D2 and AMEND-3 OBS-HOSTPOL-1, and SAFETY item 3's six link names (R3-4). The mode is `%04o` of `st_mode & 0o7777` (D1-5); the call count counts `0x85` calls with source register 0 or 2 (D1-10). NP-3 is discharged structurally: no open can write (R124, G-D1-4) and no source names `cgroup.freeze`; the plan text is unchanged | DESIGN-D1 §8-§9; D1-5, D1-10, D1-12; R2-6, R3-4 |
| R126 | The WORKER frozen bracket (Q-HE4D1-9 (a), Q-HE4D1-D2 (a)). **WORKER-FIRST, D1's own obligation (C4-3):** the WORKER attempt is the set's first action, right after the scrape, before any hashing read or other capture (tested: the set's first access is the leaf's `cgroup.events`). It runs only when every WORKER file's digest is in the memo (else "content digest pending", with no read of the leaf) and only within 5 s of its cycle's scheduled start ("cycle late" past it). `cgroup.events` must read `frozen 1` at the start (else `NotFrozen`, nothing else read) and again after. **R10's NP-9 number: 70 s = 60 s cycle + 5 s scrape-to-set bound + 2 s window + 3 s margin, each term worst-case (C4-2).** The guarantee holds only within a running epoch, from the first set after the fill has covered the WORKER's files (the first set's attempt is never usable, R2-3; a restart costs availability, not safety); flipping `PER_SPEC_PROGRESS` re-checks the 5 s bound at T04 (R2-6); a shorter hold gives about `(H - 2)/60` attempts per freeze; how often is HE-005's | DESIGN-D1 §10; Q-HE4D1-9 (a), -D2 (a); C4-2, C4-3; R2-3, R2-6 |
| R127 | The lifecycle capture (§11). The seal marker read through its absolute path (mode `& 0o7777`, the run filesystem's type from `fstatfs`: `tmpfs` only); the containment cgroup's state (ABSENT, EMPTY or populated); the census walk under `planeon.slice` (breadth first, at most 1,024 cgroups and depth 8, emitted in path order); the domain scan: each set a fresh listing of the proc root, at most 65,536 entries and a 5 s deadline, each refusing and never truncating, with the lifecycle and every backend slot then unavailable ("process scan bound"); a process counts toward a Planeon domain by its `attr/current` type (P-a completeness), and the observer counts its own domain too. A `dontaudit` for the denials the scan meets is HE-008's recommendation, not a grant (D1-3, D1-4) | DESIGN-D1 §11; D1-3, D1-4 |
| R128 | Backend captures (§12). The candidates for a component are the scanned processes whose label is its `processLabel` and whose `cgroup` is its `cgroupPath`; over 4,096 refuses; the earliest by start ticks is captured (its executable path, content digest and verity from the memo and a fresh open), ENTRY_BOUND | DESIGN-D1 §12 |
| R129 | File measurement (Q-HE4D1-12 (a)). A per-epoch memo by path and (device, inode, size, ctime) holds the SHA-256 of exactly `size` bytes read through one no-follow read-only descriptor and then EOF, streamed in 64 KiB reads (i05-protocol's `Sha256`); every window opens the path afresh, checks its facts against the memo's key (another key drops the entry: "content digest stale") and measures verity, and the record's verity digest binds the content the memo hashed, which keeps the memo sound across inode reuse. Before any byte is read, the fresh open's size must equal the record row's: a file of another size is marked as differing and never read, and its capture refuses it ("file differs from its record row"), so the 512 MiB and 4 GiB totals bound the hashing (PR review round 1, R1-3). The budgeted fill runs after WORKER-FIRST: the WORKER's files first, then the other roles' and the backends' executables; a file the budget cuts keeps its one held descriptor and its partial hash, bound to its key, and resumes next set on that descriptor (no seek anywhere), restarting from byte 0 through a fresh open if the key changed (R2-3, R3-3). The page-cache charge and its stalls are T04 items (D1-9) | DESIGN-D1 §14; Q-HE4D1-12 (a); D1-9; R2-3, R3-3 |
| R130 | The port and the replay (Q-HE4D1-11 (a)). `capture_check.rs` ports `check_capture`, `check_lifecycle_capture` and `check_backend_capture` in the model's order with its refusal kinds; the 37 texts the vectors pin are compared exactly (contract text), the unpinned ones are R10's; equality is the model's (`py_eq`). The replay runs 312 checks: 70 positives, 7 accepted, 229 negatives (each the pinned text or a localised schema refusal: 125, of which 79 additionalProperties, 31 not, 11 required, 3 const, 1 uniqueItems; 119 capture, 4 lifecycle, 2 backend) and 6 cross-version cases (X09-X14, X12-X14 under the v3 schema's registered bytes); D§3.2's counts (229, 104) corrected | DESIGN-D1 §15; Q-HE4D1-11 (a) |
| R131 | Cadence and timing (Q-HE4D1-6 (a)). The set runs synchronously inside the cycle scrape's answer, after the marker check and the ADM-4 record, scheduled at the cycle's scheduled start (the previous cycle's start + 60 s); a cycle whose scrape escalates takes no set. Its order: WORKER-FIRST, the fill, the other four roles, the scan and the lifecycle capture, the backends. The budget ends at the scheduled start + 25 s; a capture not started by then is "set budget", every limit is checked between reads and each read has its size bound (R2-2). **The drain (R2-2, R3-2):** the set only marks the wire; `watch_loop` finishes the current poll's batch in order, then runs zero-timeout polls, each poll's events in order, until one returns no stream event, at most 8, before the next progress check; the mark is cleared when the watch phase ends (and again when one starts), so a trigger from the batch runs no drain poll and none carries over (R4-2). **The record window:** `Pending` before `validFrom`; the loop wakes at `expiresAt - 3 s` (the engine's wall clock) and turns every slot `Expired` at once, with no set after; `capture_view()` derives `Expired` at read time in every phase (R2-4) and latches the first observation, so a wall clock stepped back cannot revive the view (R3-6); each window first checks `a + 2,000 + 1,000 < expiresAt - 3 s` (D1-8). Times are Unix milliseconds | DESIGN-D1 §16; Q-HE4D1-6 (a); D1-8; R2-2, R2-4, R3-2, R3-6, R4-2 |
| R132 | Statuses and `serve` (Q-HE4D1-7 (a)). `status::CAPTURE_SETUP`, a table of its own: 25 the capture schema, 26 the record's read, 27 its form, 28 the read-path preconditions, 29 the window, 30 the capture roots; distinct, inside 25-39, apart from `SERVING`, `STAGES` and every seal status; `capture_setup` is one exhaustive match (an unusable clock stays 97); 31-39 stay free. `serve`'s twelve steps: `signed_config::load` (11, 12), `ObserverConfig::parse_with_record` (13), `config::check_lifetime` (14; 97), `credentials::observer_inputs` (20), `client_config` (21), `CaptureSchema::embedded` (25), `enrolled::load_record` (26, 27), `Enrolled::new` (27-29), `LinuxWire::new(sealed)` (24), `LinuxCapture::new(sealed)` (30), `Closure::embedded` (22), `observe::run` with the capture engine (80-99). The constructor is named `LinuxCapture::new`, mirroring `LinuxWire::new` (rev 2's `open_after_seal` is a word gate.py's `OBSERVATION_CALLERS` reserves, R2-1); it takes `&Sealed`, which is code review's, and is called once | DESIGN-D1 §17; Q-HE4D1-7 (a); R2-1 |
| R133 | Memory (§18). Resident for the epoch: three validators (about 3.6 MiB), the record (bytes and value, at most about 4.3 MiB), the memo, at most one held descriptor with its partial hash and one 64 KiB buffer, the view (at most 14 x 256 KiB); transient inside a set: one capture's value, two 1 MiB `maps` reads, the 32 KiB listing buffer and the 64 KiB program buffer; the parsed and rewritten schema values and the record validator are dropped before `observe::run`. At most about 19 MiB of the 84 MiB headroom. The page cache the hash pass charges to the cgroup is reclaimable; T04 measures both (D1-9) | DESIGN-D1 §18; D1-9 |
| R134 | Gate rules G-D1-1..16 (`tools/gate.py`, §19). G-D1-1: observer-sys in planeon-observer's closure and `SCANNED_CRATES`, its root `#![deny(unsafe_code)]`, no dependency. G-D1-2: `kernel.rs` in `UNSAFE_FILES` and `FD_FILES`, its foreign items exactly `{syscall}`, `MetadataExt` allowed in observer-sys. G-D1-3 (D1-6): one declaration, plain calls only (no path, rename, import or function pointer), seven arguments, the six numbers pinned per target with no shadow, openat's flags, ioctl's request and bpf's command single named constants, the request `FS_IOC_MEASURE_VERITY`, the commands 7, 15 and 16. G-D1-4: four read-only sets with their asserts, exactly seven cgroup file names, no `freeze`, no `write` in observer-sys. G-D1-5 (R3-1, R4-1): five exact private root constants excepted once each from the start-up lint and the `fs` scan (`FS_SCAN_EXCEPTIONS`). G-D1-6 (D1-12, R2-1): `observer_sys` only in `linux_capture.rs`, no `pub use`, no observer-sys type in a public item, `LinuxCapture::new(sealed)` once in `serve`, `BEFORE_SEAL_REFUSED` gains `observer_sys` and `LinuxCapture`, and a self-test that the existing `OBSERVATION_CALLERS` rule passes over D1's real sources and fails when one names `open_after_seal`. G-D1-7: `link_text` and `own_pid` pinned and called only in `linux_capture.rs`. G-D1-8: twelve wiring calls. G-D1-9 (R2-5): 35 contracts, one use site of `NATIVE_PROFILE_V4_SCHEMA` (its `pub static` fallback was not needed). G-D1-10: B1's logic rule for `capture_schema`, `capture_check` and `kernel_text`, `CRATE_PATH_ROOTS` gains `observer_sys`. G-D1-11: the no-panic rule over `enrolled`, `capture`, `linux_capture` and observer-sys's three sources (S8; a brace-free compile-time assert only, R1-1). **R1-2 (G-D1-3, G-D1-4, G-D1-7):** in `kernel.rs` no use declaration renames and no function body holds an item (fn, const, static, use, impl, mod, struct, enum, union, trait, type, extern or a macro); each flag set occurs exactly in its definition, its assert and the openat calls passing it, the verity request and each BPF command exactly in its definition and the calls passing it (as the `SYS_` names are counted); and `link_text`, `own_pid` and `link_at` name the free fn `name` and `link_at` only as pinned and bind no name `kernel.rs` defines at its top level, so neither a rename nor a shadow can rebind the flag words, a BPF command or the link-read path. G-D1-12: observer-sys joins the post-seal rule. G-D1-13: `Roots`, `CgroupDir`, `Opened`, `ProgFd` and `LinuxCapture` join the Debug hazards (`ProcDir` already was). **G-D1-14 (D1-7): planeon-observer's `.symtab` holds `observer_sys::kernel::Roots::open` and `planeon_observer::linux_capture::LinuxCapture::new`, both `#[inline(never)]`, each read by its whole item path (legacy, or v0 through the inherent impl's self type).** G-D1-15: the report lines. **G-D1-16 (owner Q-HE4D1-D3 (a)): for planeon-observer only, the pinned v4 schema bytes occur exactly once and the host-path scan runs on a copy with that one span blanked; a second copy, a changed byte or any needle outside the span fails; `HOST_PATHS` is unchanged for every binary; both targets pass, with the span recorded below (D1-1).** The rule inventory at `a602770` (57 rules) and the word lists are DESIGN-D1 §19's (R3-5). What stays code review's: that `LinuxCapture::new` takes `&Sealed`, what each `KernelView` method calls in turn, and the SAFETY arguments; and the qualified-path form `<LinuxCapture>::new(sealed)`, which G-D1-6's and G-D1-8's patterns do not match, as HE-004C's `<LinuxWire>::new` (PR review round 1, R1-5; carried below) | DESIGN-D1 §19; Q-HE4D1-D3 (a); D1-1, D1-6, D1-7, D1-12; R2-1, R2-5, R3-1, R3-5, R4-1, R4-2 |
| R135 | Tests (§20). New files only: observer-sys's `tests/dirent.rs`, and in `crates/observer/tests/` `d1_support/mod.rs` (`FakeHost`, a `KernelView` built from a native-profile v4 positive, every access logged, scripted hooks, delays and refusals, on its own clock or HE-004C's rig clock) and the nine files `observer_d1_contracts.rs`, `observer_config_v2.rs`, `observer_enrolled.rs`, `observer_capture_schema.rs`, `observer_kernel_text.rs`, `observer_capture_replay.rs`, `observer_capture.rs`, `observer_capture_epoch.rs` and `observer_status_d1.rs`. Every earlier test file is byte-identical except `tools/test_gate.py`, whose earlier cases change only where the observer's closure, the scanned and unsafe file lists, the foreign items, the start-up exceptions, the wiring order, the contracts count and the binary host-path check's one exempt span for planeon-observer (G-D1-16) change (R1-2; the list is in the PR body) | DESIGN-D1 §20, §23; R1-2 |

### Points settled at build (inside DESIGN-D1's intent)

- **S1.** §7's per-row bound reads "each file's `size` is at most 64 MiB", but the vectors' positives enroll backend
  executables larger than that, within the schema's own `backendFiles` maximum of 1 GiB: the bound is 64 MiB per
  `files` row and 1 GiB per `backendFiles` row, the totals (512 MiB and 4 GiB) unchanged, and the totals bound the
  hashing (R129, R1-3). Recorded in DESIGN-D1 §31.
- **S2.** The 41 capability names decode `status` masks in the portable engine (`kernel_text.rs`), with a compile-time
  proof that they are distinct; observer-sys holds no capability table.
- **S3.** `BPF_F_QUERY_EFFECTIVE` (a query flag) and `BPF_F_ALLOW_OVERRIDE` (an attach flag) are both bit 0, by the
  kernel's definition in different words; only the two attach flags are asserted distinct.
- **S4.** A directory entry's name that is not UTF-8 refuses the whole listing.
- **S5.** `CaptureSchema::embedded()` returns the capture validators and the record validator separately, so `serve`
  drops the latter after enrollment.
- **S6.** An unusable wall clock at the window check is `SetupError::Clock`, which `capture_setup` maps to 97.
- **S7.** A local query's flag word other than exactly `BPF_F_ALLOW_OVERRIDE` or `BPF_F_ALLOW_MULTI` (0 included) makes
  the capture unavailable ("foreign attach flag").
- **S8 (G-D1-11; DESIGN-D1 §31, accepted narrowly).** observer-sys's no-panic list removes each item-level
  compile-time assert, exactly `const _: () = assert!(..);` at brace depth 0 whose argument holds no `{` or `}`, before
  the scan: §4.2 and G-D1-4 require those asserts, and the compiler, not the running process, evaluates them. A form
  whose argument holds a block stays and is scanned, so its `assert!` refuses (PR review round 1, R1-1: a block can hold
  an item, an impl's runtime methods among them). Every other `assert!` still refuses, and crates/observer has no such
  exception. kernel.rs's 28 forms are all brace-free.
- The engine's own-pid method is `KernelView::observer_pid` (the word `own_pid` stays with `Roots::own_pid` and its one
  call, G-D1-7); attach types and the run filesystem's name travel by name, so every kernel ABI value stays in
  `kernel.rs`. The fill hashes the roles' files and the backends' executables (the files the captures report). A
  thread replaced before its per-thread reads gives "member gone"; the pinned "member or thread set changed during the
  inspection" arises when the change falls after the process reads. `sliceCgroups` are emitted in path order.
- The epoch's drain is cleared when a watch phase ends as well as when one starts (R4-2). The rig answers a wait's ready
  connections in handle order, so the "drain's place and order" test reopens a stream after the cycle scrape's link to
  put a stream event after the probe's in one batch. §20's blocked read of 40 s is placed after the budget's end inside
  a capture that started before it, the only place a 40 s block makes the next cycle late.
- G-D1 readings, each at least as strict as the text: observer-sys's manifest holds no dependency table of any kind;
  `SYS_` values in decimal; no `syscall` or `SYS_` name in other observer sources (R4-2); `freeze` and `observer_sys`
  matched in the raw text; `LinuxCapture` renamed or aliased nowhere; a small v0 path reader for G-D1-14.

### Evidence

- Host tests: `cargo test` runs 96 binaries and 662 tests, all passing (base `a602770`: 84 and 591); every earlier
  binary keeps its count, and the twelve new ones are observer-sys's library (0), `dirent` (5) and doc tests (0) and
  planeon-observer's `observer_d1_contracts` (2), `observer_config_v2` (5), `observer_enrolled` (11),
  `observer_capture_schema` (5), `observer_kernel_text` (10), `observer_capture_replay` (1 test, 312 checks),
  `observer_capture` (15), `observer_capture_epoch` (14) and `observer_status_d1` (2); `observer_enrolled` (12) pins both
  inventory totals, `observer_capture` that a file larger than its row is never read (R1-3, R1-4). `git diff --name-status a602770 --
  '*/tests/*'` lists only added files.
- The engine over the fake host: every capture of the five positives round-trips (14 per positive, the timing fields and
  the derived digests aside); the window's steps and refusals (a member gone, threads replaced, the 2 s window, bounds,
  the observer's own capture, NotFrozen, a pending or stale digest, a held descriptor resumed across sets, a replaced
  file). Inside HE-004C's epoch, on its unchanged rig: one set per cycle right after the scrape, WORKER-FIRST, "cycle
  late", the first set and the fill's order, no set after an escalated scrape, a 70 s freeze at every 5 s phase offset
  containing a WORKER window (a 30 s one between attempts not), no exit on capture failure (81 and 92 still reached), the
  budget from the scheduled start (an on-time set ends at +25 s, a set 12 s late gets 13 s, a 40 s read blocked after the
  budget's end makes the next cycle late), Pending before `validFrom`, the wake at `expiresAt - 3 s`, read-time Expired
  inside a snapshot phase and the latch (a wall clock stepped back in a watch phase and in a snapshot phase), the drain
  (a bookmark sent during a long set credited before its deadline is judged, `Stale(1)` without it; at most 8 polls; a
  trigger from the batch or from a drain poll ends the phase with the mark cleared, a scratch mutant without the clears
  fails). The replay: 70 positives, 7 accepted, 229 negatives (125 schema refusals localised with no prefix fallback),
  6 cross-version cases, the 37 pinned texts verbatim.
- The gate's self-test: 264 tests (base 221); 43 new ones in 18 classes cover G-D1-1..16 with their bypass forms (R4-1's
  cases, R2-1's `OBSERVATION_CALLERS` check over D1's real sources, one refusing fixture per word list, PR review round
  1's three R1-2 probes and its R1-1 block arguments); 69 earlier items change as R135 says, 56 of them only in the
  source counts their assertions expect.
- `gate.py` (both musl release builds): `he-gate: passed`; 35 contract files. planeon-gate (binary, symbols and SBOM),
  planeon-broker, planeon-containment and planeon-writer are byte-identical to the base's on both targets (x86_64
  `f534bd63…`, `3ae4f143…`, `77886c4b…`, `684149d7…`; aarch64 `2d62ef0a…`, `5508d7d5…`, `8fd74ad0…`, `cfb11b59…`; their
  SBOMs too). planeon-observer changes (x86_64 sha256 `b21d814a…`, SBOM `86c5c3ab…`; aarch64 `e9f7b439…`, SBOM
  `93f468da…`; at the base `240a9285…`, `e735ab8c…`, `3a10d247…`, `732625c2…`), holds its OBSERVER program exactly once
  and no membarrier, keeps G9's substitute and module symbols, and its SBOM's workspace set is gate-sys, i05-protocol,
  observer-sys and planeon-observer (the vendored set the 11 LINKED crates).
- G-D1-14 on the built binaries: `observer_sys::kernel::Roots::open` and
  `planeon_observer::linux_capture::LinuxCapture::new` are present on both targets (v0 names, read through the inherent
  impl's self type).
- G-D1-16 on the built binaries: the 93,041 bytes of the v4 schema occur exactly once, at offset 298,398 (x86_64) and
  237,704 (aarch64); with that span blanked no host path (`HOST_PATHS`, the build root, the home directory) is found.
- The 8-word span search (the files HE-004D1 adds or changes against the earlier packets' model and validator sets,
  every `scripts/*.py` at harness-onion `887cbe7` and the documents DOSSIER-C names; contract text, `vendor/`, `.json`
  and `.rsp` excluded) finds one span in HE-004D1's text, the edge record v5's file path in PROVENANCE (an identifier; the
  base cites v4's the same way), and 46 in text unchanged from `a602770`. First-run spans in new text were reworded: nine
  pinned texts in `capture_check.rs` are named constants (verbatim), a key list is in sorted order, and doc comments,
  a test loop variable, two gate.py patterns and three lines here were rephrased.
- `crates/i05-protocol`, `crates/effect-gate/src`, `crates/gate-sys`, `crates/gate`, `crates/gate-tls`, `vendor/`,
  `licenses/`, B1's five logic modules, `seal.rs` and every earlier test file are byte-identical to `a602770`;
  `Cargo.lock` gains observer-sys as a path package and planeon-observer's one edge to it.

### Code and audit

- `crates/observer-sys/` (new): `lib.rs` (the root, `#![deny(unsafe_code)]`), `dirent.rs` (the portable record parser),
  `kernel.rs` (Linux; the one foreign item, the four flag sets, the layouts and the safe API: `Roots`, `RelPath`,
  `ProcDir`, `CgroupDir`, `ProgFd`, `Opened`), each manual `Debug` printing the type name only.
- `crates/observer/src/`: `capture_schema.rs`, `capture_check.rs`, `kernel_text.rs` (logic modules, G-D1-10),
  `enrolled.rs`, `capture.rs` (the portable engine over `KernelView`) and `linux_capture.rs` (Linux; the only module that
  names observer-sys) are new; `config.rs` (v2), `contracts.rs` (the schema's two items), `observe.rs` (the set, the
  drain, the expiry wake and latch), `status.rs` (`CAPTURE_SETUP`), `main.rs` (`serve`'s twelve steps) and `lib.rs`
  change. No `unsafe` outside `kernel.rs`.
- `contracts/` (four files and PROVENANCE's section), `tools/gate.py`, `tools/test_gate.py` (R134), this section and
  `README.md`'s observer row; the workspace manifest and lock gain observer-sys as a path package and its one edge.

### Carried

- **T04 and the W03 distribution check:** OBS-INV-1 over every capture entry point (the six calls, the three BPF
  commands, the verity ioctl, std's reads and metadata, the `/proc/self` link read), with the coverage report and no
  inventory; OBS-HOSTPOL-1's five accesses (AMEND-3; "exactly"); the gate and the server without NBS dumpable, `/proc`
  without `hidepid`; a held `/proc/<pid>` descriptor failing once its process exits; **every constant cited by name under
  Q-HE4D1-D1 (c)** (the BPF flags, commands, layouts and offsets, the 7 hook and 22 census attach-type numbers, the 41
  capability bits) and the behaviours they rest on (a non-cgroup attach type refused by the query, `BPF_OBJ_GET` refusing
  a non-bpffs path, unredacted translated instructions with CAP_BPF, map-free programs, the helper and kfunc reading,
  query counts within 16 and 64; `BPF_OBJ_GET` with `BPF_F_RDONLY` on each hook's program pin returns a descriptor
  that `BPF_OBJ_GET_INFO_BY_FD` accepts, PR review round 1, R1-7), with R124's residual until then; the `maps` device equal to `fstat`'s `st_dev` on the
  enrolled filesystems (the rule itself to a later W03 plan amendment, AMEND-3 `carried[1]`); verity (algorithm 1) on
  every enrolled and backend file; the seal marker on tmpfs; one process per backend component or the earliest right;
  the content pass's duration, the set's duration against the loop (no 83, 93 or 98 caused), whether a pause in reading
  watch sockets ends a slow consumer's watch, how often cycles meet the 5 s scrape-to-set bound, the 5 s scan deadline on
  the enrolled host's process count, the longest single kernel read under load and how often the drain credits a
  bookmark after its deadline (D1-9, R2-2); the `PER_SPEC_PROGRESS` flip re-checking the 5 s bound and NP-9's 70 s
  (R2-6); the anonymous peak with D1's share and the page cache the hash pass charges, with reclaim stalls (D1-9); NP-9's
  T04 share (the broker's quiescent freeze holds `frozen 1` for at least 70 s, the WORKER capture inside it, no thaw of a
  leaf W1-W4 or W6 holds, no `cgroup.freeze` written by the observer); the vacuous host equalities until real reads.
- **HE-008:** sign `planeon.observer-config/v2` under the existing domain with `qualificationRecord`; install the record
  in `/etc/planeon/policy-observer` (recommended `qualification-record.json`, root, 0444, `planeon_etc_t`); keep the
  configuration's `notAfter` consistent with the record's `expiresAt`, or re-enroll; the observer's host-policy share
  (OBS-HOSTPOL-1); the `dontaudit` recommendation for the scan's denials (not a grant); the real reads of the seven host
  fields with the follow-up contract; the off-host measurement of the observer's own file (T04-OBSERVER-IDENTITY).
- **HE-004-I01:** the capture view's wire form, the declared-host-field mark on the wire, capturer authentication
  through its peer custody (Q-HE4D1-10 (a)), the per-request freshness of captures.
- **HE-004D2:** `check_record` on the same record before composing; `check_qualification` and the token, reusing
  `capture_schema.rs` and `capture_check.rs`; the cross-capture rules; retaining a capture across cycles (`previous`).
- **W03-PLAN-AMEND-3 and later amendments:** OBS-HOSTPOL-1 and NP-9 as adopted in candidate 5; WORKER-FIRST in HE-004D1's
  own NP-9 share and packet scope (C4-3); native-profile v4's other unregistered W03 items, the same-device rule for
  `maps` and `stat`, HE-008's and I01's hand-offs and the I06 successor for OBS-RBAC-1.
- **The follow-up contract (owner-accepted, Q-HE4D1-1):** a native-profile successor or errata that drops the seven host
  fields from captures.
- **S1 and S8:** recorded in DESIGN-D1 §31 (monitor, owner-delegated, 2026-10-19), S8 narrowed by PR review round 1's
  R1-1.
- **The qualified-path constructor form (PR review round 1, R1-5):** `<LinuxCapture>::new(sealed)`, like HE-004C's
  `<LinuxWire>::new(sealed)`, is not matched by the wiring and caller patterns; a later gate change matches
  `LinuxCapture\s*>?\s*::\s*new` (and `LinuxWire`'s) or counts every `LinuxCapture` token in `main.rs`. The `&Sealed`
  parameter keeps any extra call after the seal.

### Amendment A2 (HE-004D2 unit B1: native-profile v5)

HE-004D2's unit B1 (owner decision Q-HE4D2-2 (a); DESIGN-D2 §4) moves D1's captures onto native-profile v5 (edge v7,
harness-onion slot 252, MET-ENFORCE-038), whose captures no longer carry the seven host fields. The record contract,
its schema, its loader and its preconditions stay v4's. The rows above stay as history; this amendment states what
changed:

- **R120:** the declared host fields are gone. `DECLARED_HOST_FIELDS`, `HOST_FIELDS_OBSERVED`,
  `CaptureView.declared_host_fields` and the `Declared` copy are removed, and no capture carries `host`,
  `selinuxBefore`, `selinuxAfter`, `kernelPolicyDigest`, `booleansObserved`, `hardeningObserved` or
  `bootEntryObserved`. The rest of the row stands.
- **R122:** the load is split. `CaptureSchema::embedded` stays `serve`'s one call (any refusal is still 25) and names
  each embedded schema once (G-D2-3): `RecordSchema::from_bytes(NATIVE_PROFILE_V4_SCHEMA)` (the pin
  `RECORD_CANONICAL_PIN`, `3bf244b2…`; the closed rewrite, still needed for v4's two `else` objects; the record
  validator, dropped after enrollment) and `CaptureSchema::from_bytes(NATIVE_PROFILE_V5_SCHEMA)` (the pin
  `CAPTURE_CANONICAL_PIN`, `5f6703ca…`; the same closed rewrite of `$defs/capture/allOf/0` and `/3`; the capture,
  lifecycle and backend validators over v5's definitions). The v5 schema enters through `contracts.rs`
  (`NATIVE_PROFILE_V5_SCHEMA`, sha256 `70bda124…`); G-D1-16's one exempt span stays the v4 schema's, which the record
  validator still embeds.
- **R130:** the port follows the v5 model. The three type checks refuse with "not a v5 capture", "not a v5 lifecycle
  capture" and "not a v5 backend capture". The replay runs 330 checks: 70 positive captures, 7 accepted, 247 negatives
  (148 schema refusals, each localised: 102 additionalProperties, 31 not, 11 required, 3 const and 1 uniqueItems; 134
  capture, 10 lifecycle and 4 backend; and 99 pinned model texts) and 6 cross-version cases (X09-X11: v4's positive
  captures under the v5 checks; X12-X14: v5's positive captures under the registered v4 schema, both `mustInclude` pairs
  of each localised). The pinned texts are 35 (were 37). The localisation helpers moved to the shared
  `tests/schema_support/mod.rs`.
- **P1's order:** `check_capture` keeps v4's order (type, shape, binding, window, deadline, then the rest) without the
  host rules ("wrong boot/kernel", "active policy changed", "host lock state differs" and the boot entry; `boot_entry`
  has no caller left and is removed). The lifecycle and backend bindings check `qualificationDigest` only; the lifecycle
  check's booleans and boot-entry rules are gone. Under v4, "active policy changed" also refused a record whose SELinux
  status sequence was odd, its one part not copied from the record itself. That condition now lives only in
  `check_record` ("unstable policy epoch"), and `serve` does not run `check_record` until W02-PROD and HE-008 wire the
  composition, so until then nothing on the deployed observer's path refuses an odd sequence (PR review round 1, R1-3;
  carried below).
- **R134 (G-D1-9):** 46 contracts; the use-site rule counts `NATIVE_PROFILE_V4_SCHEMA` and `NATIVE_PROFILE_V5_SCHEMA`,
  each named once in `capture_schema.rs` and once in `contracts.rs` (G-D2-3).
- **R135:** four D1 test files change, and only for v5 (DESIGN-D2 §4.4, D2-6): `tests/d1_support/mod.rs` (the v5
  positives, no seal digest written into a capture's `hardeningObserved`), `tests/observer_capture.rs` (the
  `declared_host_fields` assertion goes), `tests/observer_capture_replay.rs` (above) and
  `tests/observer_capture_schema.rs` (the pin and rewrite tests once per schema, with each loader refusing the other's
  schema). `tests/observer_d1_contracts.rs` and every other earlier test file are byte-identical.
- **Carried, closed:** the vacuous host equalities are in no capture any more; what they stood for is T04's four host
  proofs under Q-NPE-3 (b), T04-HOST-BOOT, T04-POLICY-STABLE, T04-HOST-LOCKS and T04-BOOT-ENTRY. The follow-up contract
  (Q-HE4D1-1) is discharged by native-profile v5 (slot 252). HE-004-I01's declared-host-field mark on the wire is moot.

### Owner decisions (verbatim as relayed, 2026-10-18)

The dossier questions (subject DOSSIER-D1, sha256 prefix `ff9ace8e`):

> - Q-HE4D1-1 = (a): fill the host fields from the record's declared values, marked R10-side as not observed (a MODEL_DEFINED row); HE-008 and T04 keep the real reads. The owner accepts that those equalities are vacuous until a follow-up successor or errata drops them from captures.
> - Q-HE4D1-4 = (a): a new observer-sys crate; planeon-gate untouched.
> - Q-HE4D1-8 and -9 = (a): the next W03 plan amendment, a harness-onion meta packet, adds the observer's HE-008 host-policy share plus a T04 check, and the HE-005 quiescent-freeze obligation. D1 is designed alongside it, with the freeze bracket tested with fakes.
> - Q-HE4D1-2, 3, 5, 6, 7, 10, 11 and 12 = all (a), as in the dossier.
> Record all of these verbatim and dated. GO for the D1 design (light work), then independent review rounds.

Q-HE4D1-D1:

> 1. Owner Q-HE4D1-D1 = (c): cite linux/bpf.h and linux/capability.h (v6.12) by name and leave the value check to T04, following the gate-sys channel.rs precedent. No fetch, no vendoring. Record it verbatim and dated, and list the cited constants as a T04 check item.

Q-HE4D1-D2 and Q-HE4D1-D3:

> - Q-HE4D1-D2 = (a): keep the 60 s cadence (Q-HE4D1-6 (a)); the WORKER attempt goes first in each set, right after the scrape. NP-9's minimum becomes "one observer cycle plus the scrape-to-set bound plus one 2 s window, plus margin". R10 states the number, and HE-005 keeps how often. The owner accepts the longer probe-worker freeze.
> - Q-HE4D1-D3 = (a): the new gate rule G-D1-16, for planeon-observer only, with self-tests. The pinned v4 schema bytes occur exactly once; the host-path scan runs with that one span blanked; any /opt/planeon/ elsewhere, a second copy or a changed byte still fails. The host-path list stays unchanged for every binary.
> - Q-HE4D1-D1: (c) stands, with the no-fetch mitigations folded.

The complete messages are recorded in the operator's `tools/w03/he004/OWNER_DECISIONS.md`.

## HE-004D2: the I06 evidence composition, check_qualification and the acceptance token (`record_check`, `qualification`, `i06_evidence`, `composition`; `contracts/native-profile-v1/`, `-v2/`, `-v5/`, the v3 vectors, `contracts/i06-v3/`)

The packet (DESIGN-D2 revision 2, sha256 `8be61d58…`; owner decisions Q-HE4D2-1..11 all (a) and the monitor's Q-NPE-9 (a)
and Q-NPE-10, quoted at the end) adds the observer's qualification and acceptance logic as four pure modules that the
binary never reaches: R10's ports of native-profile v4's `check_record` and `check_migration`, native-profile v5's
`check_qualification`, and I06 v3's evidence check around I06 v1's SC00-SC15, each ending in an acceptance token, and the
composition of the two tokens, whose production entry answers unavailable until W02-PROD. Its first v5 unit (B1) moves
HE-004D1's captures onto native-profile v5; that change is the HE-004D1 section's Amendment A2. Eleven contract files
are copied byte for byte (edge records v6 and v7; provenance in `contracts/PROVENANCE.md`). The models are pinned by
digest, read as specification only where the READMEs are silent, and never copied: `native_qualification_v4.py`
(`f7c71807…`, harness-onion `887cbe7`, "NQ4"), `native_qualification_v5.py` (`d9926f4d…`, `27c54605`, "NQ5"),
`i06_backend_profile_v3.py` (`dfb00e90…`, `35b733b`, "I3M") and `i06_backend_profile.py` (`bea3c953…`, "I1M").
planeon-gate, planeon-broker, planeon-containment and planeon-writer are byte-identical; observer-sys, gate-sys,
i05-protocol, effect-gate's sources, gate-tls, `crates/gate`, B1's five logic modules, `seal.rs`, `main.rs`, `status.rs`,
`observe.rs`, `enrolled.rs`, `kernel_text.rs`, `linux_capture.rs` and HE-004C's modules are unchanged. Its rules are
R136-R147.

### Points taken from the pinned models (the READMEs are silent)

| # | Point | Model |
|---|---|---|
| Q1 | `check_record`'s order: the v4 identity; the shape step (data bound, canonical length, `record` variant); the profile binding; the boot entries; the scope and the window; the resource labels; the signed endpoints, their tuple, kinds and loopback; the policy epoch; the two inventories; per role ownership, cgroup inode, endpoints, capabilities and hook programs; executables and closures; the lifecycle subjects and the seal digest; the static closures and labels; the backend components, executables and the in-set census | NQ4 `:266-479` |
| Q2 | `check_migration`'s order: the shape step, the profile binding, the inputs' types, the attested-empty and retained-records rules, each predecessor in v1, v2, v3 order (version and validity, reboot, nonces), nonce reuse, then the nonce scan over every key and string of the profile and the record | NQ4 `:709-737` |
| Q3 | `check_qualification`'s order: `check_record`, the test-only rule, the role set, each role capture, the lifecycle capture, the backend set and each backend capture, the cross rules (process identity, inode and path identity, the worker's parent, the domain counts, the census against the role cgroups, the delegated service's two leaves, the populated flags), then `check_migration` | NQ5 `:243-298` |
| Q4 | I06 v3's wrapper: the fixture flag's type, the closed v2 record and its version, the closed W02a reference and its version, `check_record` (refusals prefixed), the reference digest, test-only agreement, the fixture gate, then I06 v1 on the projection with production meaning "not a fixture call" | I3M `:68-88` |
| Q5 | I06 v1's `check_evidence` order, SC00 to SC12's sealed set | I1M `:425-593` |
| Q6 | Python's readings the models rely on: `ipaddress.ip_address` and `str()` for endpoint and SC02 addresses (CPython 3.12.14); `str.split(" ")` for boot entries (empty words kept); `str.strip()`'s whitespace; `re.fullmatch` for the kernel-parameter and I06 v1 patterns | NQ4 `:73-76, 211-214`; I1M `:37, 183-184` |

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R136 | Scope and isolation (Q-HE4D2-4 (a), -5 (a)). No runtime wiring: no `serve` step, epoch hook, status, kernel read or system call. The four modules are unreachable from `serve` by construction (G-D2-5: their names occur outside them only as `lib.rs`'s four `pub mod` lines; the type names they define, derived at gate time, occur in no other observer source; every impl is `impl <own type> {`; no re-export; and, since PR review round 1 (R1-6), no child module: the crate's `src/` holds no directory and no logic module declares a module outside a strict test block, so nothing reaches a D2 module's items through `super::` from another file), with G-D2-7 (no planeon-observer symbol in a D2 module) and G-D1-16 as build-time corroboration (D2-4) | DESIGN-D2 §1, §9; Q-HE4D2-4, -5 (a); D2-4 |
| R137 | Contracts: 46 (edge record v6's five rows at A1, edge record v7's six at B1, three of them the v1-v3 history vectors, Q-HE4D2-3 (a)); `contracts.rs` embeds exactly five files (I06 v1's three, the v4 and v5 schemas; G-D2-2); every other registered file is read by the tests only | DESIGN-D2 §2; Q-HE4D2-3 (a) |
| R138 | Unit B1, native-profile v5 (Q-HE4D2-2 (a)): the schema load split (v4 for the record, v5 for the captures, each with its canonical pin), the v5 capture checks without the host rules, the producer without the seven host members; recorded as the HE-004D1 section's Amendment A2, D1's rows kept as history | DESIGN-D2 §4; Q-HE4D2-2 (a) |
| R139 | `check_record` (Q1): the schema's canonical pin is checked once, when `RecordSchema` is built, not per call; Python's `KeyError`, `TypeError` and `AttributeError` are `Refusal::Missing`; the IP text (`ip_text`, CPython 3.12.14's reading of the forms these contracts admit: four decimal octets without leading zeros, IPv6 groups with one `::` at most, a trailing dotted IPv4, a zone parsed then refused; RFC 5952's canonical text), the eleven kernel-parameter matchers (the `initrd=` class: letters, digits and `_ . / \ + -`, the backslash included) and the string walk are R10's own code; the in-set census's eight backend exec types are the table `BACKEND_EXEC_TYPES`, which a test holds equal to the vendored schema's constants (the model reads them from the schema; the check takes validators only); the three root literals (`CGROUP_ROOT`, `PIN_ROOT`, `INTERPRETER_TREE`) are private and exact (G-D2-6, G-D2-9). Times before 1970 refuse (D1's `utc_seconds`); a profile with no canonical encoding is `Missing`; an endpoint address given as a JSON number or boolean is "fixed canonical numeric endpoint", any other non-text R10's "not an IP address" | DESIGN-D2 §5; NQ4 `:463-464` |
| R140 | `PredecessorSchemas::from_bytes(v1, v2, v3)` checks the three canonical pins ("unreviewed vN schema") once, at construction, so the order differs from the model's only when a pin and an earlier rule fail together, which no vector does; `Histories` holds the three lists as JSON values, so "migration inputs" stays reachable; a pinned schema whose `record` variant does not load is R10's "predecessor schema does not load" | DESIGN-D2 §6.1-6.2 |
| R141 | `check_qualification(&QualificationInput, &CaptureSchema, &RecordSchema, &PredecessorSchemas, test_fixture)` in Q3's order, D1's three capture checks taking the `CheckedRecord` that `check_record` mints; on success only `QualificationAccepted { record_digest, valid_from, expires_at, fixture }`, the window in Unix seconds (parsed by the parser `check_record`'s window rule already applied). Settled at build: the test-only rule reads `testOnly` only without the fixture flag, with Python's truth value; in the two set rules a capture that is not an object is `Missing`, and a name that is not text is `Missing` when two or more captures meet the sort and the set rule's text when it is alone (Python sorts an all-numeric name list and then refuses with the text: both refuse); the backend names are `backendComponents`' keys; process, inode and path identity are compared with `py_eq` pairwise, `by_role` takes a role's last capture and the census lets a later row override, as Python's dicts do; the populated check's order cannot matter, since D1's lifecycle check already requires every cgroup it reads. The retained-capture rule (`previous`) is not ported (Q-HE4D2-8 (a)) | DESIGN-D2 §6.3-6.4; Q-HE4D2-8 (a) |
| R142 | `check_evidence` in Q4's then Q5's order, on the projection (the record without `w02aRecord`, at I06 v1's version), production meaning "not a fixture call"; `check_record`'s refusal wrapped with the prefix "SC00 W02a v4 refuses the backend record: "; I06 v1's two production-only rules ported though W02a v4 never reaches them (Q-HE4D2-10 (a)); SC02's loopback through `ip_text`, an IPv4-mapped loopback **not** loopback (stricter than CPython); `str.strip()` as R10's own copy of CPython 3.12's 29 whitespace code points; the implementation, path and digest patterns as hand-written matchers; the fixture flag's type rule is the boundary `fixture_flag(&Value)`, called before the check, which takes a `bool` (so G13, `testFixture: 1`, is replayed through R10 code); on success only `EvidenceAccepted { record_digest, evidence_digest, fixture }`. Five unpinned texts are R10's own words (DESIGN-D2 §21 counted four; the fifth, "SC00 the fixture implementation must be test-only", is seven words by spaces but nine by the span checker's tokens) | DESIGN-D2 §7, §21; Q-HE4D2-10 (a) |
| R143 | The composition (Q-HE4D2-6 (a)): `compose_fixture(EvidenceAccepted, QualificationAccepted)` consumes both tokens, refuses a token minted without the fixture flag (`ProductionTokenInFixture`) and two records (`RecordMismatch`), and makes `Composed { record_digest, evidence_digest, valid_from, expires_at }`; `compose_production(&, &)` refuses a fixture token (`FixtureTokenInProduction`) and otherwise answers `Production::Unavailable("W02-PROD")`. No production token can be made today: v4's schema admits only the test-only backend, so `check_qualification` without the flag refuses and I06 v3 refuses every production evidence record. Both entries decide through private helpers on booleans, which the module's own test drives through every branch without a token | DESIGN-D2 §8; Q-HE4D2-6 (a) |
| R144 | Caller obligations (Q-HE4D2-7 (a)): (1) a profile that the pinned proxy profile contract accepts and (2) complete v1-v3 histories are carried to W02-PROD and HE-008, D2 taking both only as test inputs; (3) the inspector obligation is D1's (NP-3); (4) the fixture flag is enforced by the tokens' flags and the two entries | DESIGN-D2 §8.3; Q-HE4D2-7 (a) |
| R145 | The replay: 413 checks. Native 262: `observer_record_replay` 216 (196 record negatives, 127 pinned texts over 44 and 69 schema refusals over 56; 11 accepted; X05-X08 and X15 under the registered v3 schema; X01-X04, the v3 vectors' positive records under `check_record`, "not a v4 record") and `observer_qualification_replay` 46 (the five v5 positives, accepted with the v1-v3 positives' records as histories, each token's digest, window and flag asserted; 19 qualification cases over 13 texts; native-profile v4's 22 migration cases). I06 151 (`observer_evidence_replay`). X01-X04 use the registered v3 positives, not R10-built values, because Q-HE4D2-3 (a) registers them (D2-2); I06 X01's v1 subject is built from the v3 positive; the v1 halves stay out. The 80 best-match refusals are localised by D1's rule, shared as `tests/schema_support`; twelve need its branch walk, because the v4 schema's `backendProfile` is a one-branch `oneOf` of constants that jsonschema's best match descends into: record R58, R59, V25, V28 and evidence E60, E61, E70, E71, G09, G10, X03, X04, each pinned by its replay | DESIGN-D2 §11; Q-HE4D2-3 (a), -10 (a); D2-2 |
| R146 | Gate rules G-D2-1..12 (`tools/gate.py`): 46 contracts (G-D2-1); the five embedded files (G-D2-2); both schema constants defined once in `contracts.rs` and named once in `CaptureSchema::embedded` (G-D2-3, G-D1-9 generalised); the four modules under B1's logic rule with D1's whitelist plus the four (G-D2-4); isolation (G-D2-5, R136); `/opt/planeon/` only in `INTERPRETER_TREE` (G-D2-6); no D2 symbol on either target (G-D2-7, item path and first crate root); the tokens (G-D2-8: one literal, in the minting function; private fields of `String`, `bool`, `u64`, `i64` or `&'static str`; no `Clone`, `Copy`, `Default`, `Hash` or serde derive, `cfg_attr` included; one impl of `&self` getters returning neither the token nor `Self`, each with the body `self.<name>` or `&self.<name>` of its own field; the token named in its file only by its struct, impl header, minting signature and literal; outside that impl, a token field reached only by its getter call (`.<field>(`), so no assignment, compound assignment, parenthesised place, `&mut`, method call or rebinding of a field (PR review round 1, R1-1); no `Self {` or `Self(` in the three token files (child modules are R136's rule, `check_observer_child_modules`); `compose_production`'s body naming none of `compose_fixture`, `Composed`, `check_qualification`, `check_evidence`; D2-1, R2-1); the two record_check roots among G-D1-5's exceptions (G-D2-9); observer-sys's `lib.rs`, `dirent.rs` and `Cargo.toml` pinned beside `kernel.rs` (G-D2-10, R4-1); the qualified constructor forms counted, empty generic arguments and a parenthesised type included, and each of `LinuxWire` and `LinuxCapture` named once in `serve`, renamed with `as` nowhere, named by no `type` item, and named in code only in its own file and inside `serve` (G-D2-11, R1-5; PR review round 1, R1-7; round 2, R2-1; round 3, R3-1); each type item read to its `;` at bracket depth 0 (round 4, R4-1); and the two home files, `linux_capture.rs` and `linux_net.rs`, pinned whole by sha256 beside the observer-sys pins (owner decision Q-D2-END), so no added associated fn, trait impl, alias, default or projection gives a second construction route (R2-2, R3-1, R4-2); these rules are textual, and `serve`'s own control flow around its one counted construction (a loop, or a closure or iterator calling it more than once) stays code review's (round 5, R5-1), beside R118's residual; the report lines (G-D2-12). `D2_LOGIC_BUILT` and `D2_TOKENS_BUILT` grew unit by unit, and G-D2-5 refuses a D2 file present before its unit builds it | DESIGN-D2 §12; D2-1, R2-1, R4-1, R1-5 |
| R147 | Tests (§15): new `d2_support`, `schema_support`, `observer_d2_contracts`, `observer_record_replay`, `observer_record_text`, `observer_evidence_replay`, `observer_qualification_replay`, `observer_composition` and `composition.rs`'s unit test. Every earlier test file is byte-identical except tools/test_gate.py and the four HE-004D1 test files that the native-profile v5 re-vendor changes (tests/d1_support/mod.rs, tests/observer_capture.rs, tests/observer_capture_replay.rs, tests/observer_capture_schema.rs) (the R1-2 wording; Amendment A2 says how each still exercises its intent) | DESIGN-D2 §15, §22 |

### Points settled at build (inside DESIGN-D2's intent)

- **The exec-type table (R139):** above; `observer_record_text` holds it equal to the vendored schema.
- **`tests/schema_support` (R145):** the localisation helpers became a shared test module in phase A for D2's replays,
  D1's rule unchanged as `localised`; B1 moved D1's capture replay onto it.
- **The twelve branch-walk localisations (R145):** listed above; each replay pins its list.
- **The fixture flag's boundary (R142):** `fixture_flag`, so G13 is replayed and counted in the 151.
- **The own-words texts (R142):** "SC00 test-only evidence refused in production" (I1M `:446`), "SC00 fixture identity
  refused in production" (`:447-448`), "SC08 W02a component keys out of range" (`:459`), "SC08 component executable not
  a canonical path: " and the name (`:469`), and "SC00 the fixture implementation must be test-only" (`:441`).
- **planeon-observer's change.** In phase A (no D2 code reachable) it changed on both targets only through link-time
  optimisation: no D2 symbol and no D2 word in any symbol; none of the D2 modules' string literals in the binary unless
  the base holds it too; the symbol differences are std and i05-protocol generic instances (`BTreeSet<String>`
  iteration emitted out of line, x86_64's `Vec<u8>::push_mut` inlined) and renumbered local suffixes and aarch64
  exception labels; `.rodata` keeps its size, `.text` -512 B (x86_64) and -128 B (aarch64). Unit B1 then changed it
  for D1's v5 re-vendor: the v5 schema's 46,190 bytes occur once, the v4 schema's still once (G-D1-16's span), the
  three "not a v5 …" texts replace v4's, the removed host texts are gone, and outside the two schema spans none of the
  seven host member names occurs. B2 and B3 left it byte-identical to B1's build.
- **B2 and B3:** `QualificationInput` holds owned values with public fields and no impl; the composition's two entries
  decide through private helpers on booleans; the logic rule's ban on `super::` and globs makes the module test import
  through `crate::composition::…`.
- **Readings of the gate rules, each at least as strict as the text:** G-D2-5's present-files rule; G-D2-7 also reads
  a symbol's first crate root; G-D2-8's field types are a closed list and `compose_production` must exist exactly once.

### Evidence

- Host tests: `cargo test` runs 102 binaries and 688 tests, all passing (base `1a0c529`: 96 and 662); the new binaries
  are `observer_d2_contracts` (5), `observer_record_replay` (2; 216 checks), `observer_record_text` (6),
  `observer_evidence_replay` (2; 151 checks), `observer_qualification_replay` (5; 46 checks) and `observer_composition`
  (4); planeon-observer's library tests go 15 → 17 (`composition`'s two). Every earlier binary keeps its count,
  `observer_capture_replay`'s one test now making 330 checks (Amendment A2).
- The gate's self-test: 317 tests (base 276; 307 before PR review round 1, whose fixes add five: R1-1's token forms,
  R1-6's three child-module cases and R1-7's spellings; round 2 adds R2-1's alias case, round 3 R3-1's forms and round 4
  R4-1's type items and Q-D2-END's two home-pin tests). Earlier items change only as the R1-2 wording says (the contracts count,
  the logic-module set and the fixtures that hold its files, the observer-sys pins, the schema constants, the root
  exceptions, the qualified constructor forms, the report lines).
- `gate.py` (both musl release builds): `he-gate: passed`; 46 contract files; 12 logic modules; 13 derived D2 type
  names; 3 tokens; G-D2-7: none of planeon-observer's 2,677 (x86_64) and 2,759 (aarch64) symbols is in a D2 module;
  G-D1-16: the v4 schema's 93,041 bytes once, at offset 298,407 (x86_64) and 237,769 (aarch64), no host path outside
  the span. planeon-gate, planeon-broker, planeon-containment and planeon-writer and their SBOMs are byte-identical to
  the base's; planeon-observer x86_64 `6300391b…` (SBOM `2a0e04ce…`), aarch64 `a2aa1000…` (SBOM `c0cd835d…`).
- The 8-word span search (every file the packet adds or changes, against the earlier packets' model and validator
  sets, every `scripts/*.py` at harness-onion `887cbe7`, `35b733b` and `27c54605`, and the documents DOSSIER-C names;
  spans also in the contracts' JSON or BPF data, `vendor/`, `.json` and `.rsp` excluded) finds, in added lines, only
  identifiers: I06 v1's ordered tables in `i06_evidence.rs`, the role-domain table in `qualification.rs`, the four T04
  proof names, contract or edge-record file paths, the packet's field names and one run of regex escapes in `gate.py`.
  Since PR review round 1 (R1-2) the contracts' README prose is no longer exempt; that exemption had hidden one comment in `record_check.rs` restating
  native-profile v4's README, now reworded with R144's phrase.
  First-run prose spans were reworded (doc comments in `record_check.rs` and `qualification.rs`, two comments in
  `capture_check.rs`); the refusal helper is `refuse_unless` and pinned texts whose neighbours matched are named
  constants.
- The §14 word list over every added or changed `.rs` line: no hit.

### Code and audit

- `crates/observer/src/`: `record_check.rs`, `i06_evidence.rs`, `qualification.rs` and `composition.rs` (logic modules,
  G-D2-4) are new; `lib.rs` (four `pub mod` lines), `contracts.rs` (the v5 schema), `capture_schema.rs`,
  `capture_check.rs` and `capture.rs` (unit B1) change. No `unsafe`, no `std::net`, no network or file access.
- `contracts/` (eleven files and PROVENANCE's section), `tools/gate.py`, `tools/test_gate.py` (R146), this section,
  Amendment A2 and `README.md`'s observer row. No manifest, lock, `vendor/`, `licenses/` or `ci/` change.

### Carried

- **HE-008 / W02-PROD:** the live composition and its inputs (the profile under the proxy profile contract; the signed
  endpoints; the complete v1-v3 histories and NP-2's ledger; the I06 evidence record), the production backend profile
  and the I06 successor bound to it, and the change to G-D2-7 when the composition is wired. Wiring it also puts
  `check_record`, and with it the record's even status sequence, on `serve`'s path (Amendment A2, R1-3).
- **HE-004-I01:** retaining a capture across cycles (the rule not ported) and per-request freshness; the capture view's
  wire form, now without a declared-field mark.
- **T04:** the four host proofs of Q-NPE-3 (b) (T04-HOST-BOOT, T04-POLICY-STABLE, T04-HOST-LOCKS, T04-BOOT-ENTRY); every
  earlier HE-004D1 T04 item stands.
- **The ClusterRole I06 successor** (its own slot, Q-NPE-5 (a)): if it re-binds the evidence, a later packet re-vendors
  D2's I06 files; if it only names the observer's grants, it changes B1's embedded closure.
- **What stays code review's:** every index guarded and every arithmetic step checked; the IP and grammar matchers equal
  to Python on inputs the vectors do not reach (their table tests are the evidence); the tokens' getters exposing nothing
  mutable.

### Owner decisions (verbatim as relayed, 2026-10-19)

> Monitor relay, owner decisions, 2026-10-19:
> - Q-HE4D2-3 = (a): widen edge v7 by 3 rows for the v1–v3 history vectors (62 rows), for the exact 413-check replay.
> - Q-HE4D2-1, 2 and 4–11 = all (a) as in DOSSIER-D2.md (b3e14e9b): build on v5, with the independent units on edge v6 now and a fallback to v4 if 252 slips; D2 carries D1's re-vendor as unit 1; no runtime wiring, and D2 stays unreachable from serve; the DESIGN-B token; caller obligations carried; the retained-capture rule not ported; I06 v3; the 413-check scope; fold in R4-1 and R1-5.
> Monitor decisions (contract details, owner-delegated; I'll tell the owner):
> - Q-NPE-9 (a): re-derive Q03 as an eighth case with its refusal unchanged, using the v5 SERVER capture. Record the scope miscount; this amends Q-NPE-4's "7" to 8.
> - Q-NPE-10: NATIVE-PROFILE-V5.

The complete messages are recorded in the operator's `tools/w03/he004/OWNER_DECISIONS.md`.

## HE-004-I01a: the observer's I01 listener, custody, request checks, quota pair and role pin (`client`, `linux_listen`, `linux_net`, `i01_service`, `i01_request`, `observer_rbac`, `enrolled`, `quota`, `observe`, `status`; gate-sys `listen_seqpacket_plain`; `contracts/seccomp-v5/`, `contracts/i06-v4/`)

The packet (DESIGN-I01A revision 6, sha256 `2d976d19…`; owner decisions Q-HE4I1-1..13 and Q-I01A-1..9, "Accept all",
recorded in the operator's `tools/w03/he004/OWNER_DECISIONS.md`, 2026-10-21) gives the observer its I01 listener and
everything that judges a peer and a request, and sends nothing: every request closes at the binding gate, which has no
binding until HE-008. Units U1-U6 also re-seal the observer with seccomp v5, keep a quota pair beside the headroom and
pin the observer's own role with I06 v4 on every snapshot. U7 (the `PV` replay) waits for edge v9. Four contract files
are copied byte for byte from edge record v8 (provenance in `contracts/PROVENANCE.md`). The I06 v4 model,
`scripts/i06_backend_profile_v4.py` (`7f97acfe…`, harness-onion `29c84b36`, "I4M"), is pinned by digest and read as
specification only. planeon-gate, planeon-broker, planeon-containment and planeon-writer are byte-identical;
observer-sys, i05-protocol, effect-gate's sources, gate-tls, `crates/gate`, B1's five logic modules and the D2 modules
are unchanged, and so are the D1 modules except `enrolled.rs`, which gains `server_identity()` (R152). Its rules are
R148-R160.

### Points taken from the pinned model (I06 v4; the design and the vectors are silent)

| # | Point | Model |
|---|---|---|
| P1 | The acceptance order: v3's IC00-IC05 on the snapshot, then RB05 on it, then RB01-RB04, RB06 and RB07 on the three lists of the same read | I4M `:248-277` |
| P2 | RB01's list reading: an object with exactly the three lists; every item an object whose metadata is an object with a plain-text name (all three lists read before the role is looked up) | I4M `:143-148`, `:188-193` |
| P3 | The shape reading shared by RB01 and RB03: unknown members (sorted, comma-joined) before `kind`/`apiVersion` (each checked only when present) before metadata beyond the name and the five server fields | I4M `:151-157` |
| P4 | RB02's reading: an absent or null `rules` is none; the count first; then rule by rule, its own reading (object, no unknown member, each list absent, null or an array of strings) and its five lists compared in the order apiGroups, resources, nonResourceURLs, verbs, resourceNames | I4M `:160-171`, `:203-212` |
| P5 | RB06 and RB07 walk the ClusterRoleBindings (the contract's skipped) and then the RoleBindings; per binding the subjects' reading, the observer named, the roleRef's reading, the contract role referenced; a RoleBinding's place carries its namespace only when that is a string | I4M `:220-236` |
| P6 | The aggregation reading: a null rule or a missing or null selector list is none; a selector matches an unlabelled object when it has no labels and every expression is NotIn or DoesNotExist; an unreadable selector refuses before a later one is read | I4M `:174-186`, `:237-246` |

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R148 | Scope. The observer listens on `/run/planeon/live-proxy/policy-observer.sock`, authenticates each peer, reads and checks each request, and closes every session: nothing is ever sent (`PeerOps` has no send; G-I01-5). New statuses 31-35 only (§14); every other I01 condition closes a session. Contracts: 50 (U1's two seccomp-v5 programs, U6's I06 v4 criteria and vectors) | DESIGN-I01A §0, §1, §14 |
| R149 | The listener. gate-sys `listen_seqpacket_plain` is `listen_seqpacket` without the sockcreate guard (the observer's socket is labelled by its own domain); no new foreign symbol. `I01Socket` (Linux, `linux_listen.rs`, pinned whole) is opened only inside `LinuxWire::new(&Sealed)` after the poller (24), its setup refusals mapped by one function to 31 (socket, address, options), 32 (bind), 33 (listen) and 34 (register). The observer never unlinks or renames a path (G-I01-1); a stale path makes `bind` refuse (32) until `ExecStartPre=` clears it as `init_t` | DESIGN-I01A §4; Q-HE4I1-5 (a) |
| R150 | The one wait. Every wire wait is `Client::wait_serving`'s (G-I01-2): it watches the service's plan (the listener only while no session is open and no backoff runs; else the session's peer), shortens the timeout to the plan's deadline, calls `serve_peer_step` once per ready I01 descriptor and `serve_peer_deadlines` once per wake. The service is attached to the client (`Option<Box<dyn PeerService>>`) and is handed the peer operations per call. One session at a time; the kernel backlog holds one more. I01 is not served during a capture set or a snapshot's CPU-bound tail | DESIGN-I01A §5; Q-HE4I1-6, Q-I01A-5 (a) |
| R151 | Listener faults: an accept error other than EAGAIN or ECONNABORTED, EPOLLERR or EPOLLHUP on the listener, or a failed re-add or removal. A fault takes the listener out of the wait for 5 s (the re-add is a deadline of the wait); an accept clears the count; the twelfth fault in a row ends the wait, the client names it, and the epoch exits 35 instead of the poller's 95. HE-008 must pair any `Restart=` with a start-rate limit | DESIGN-I01A §4, §14 |
| R152 | Custody, at accept, in HS43's order: SO_PEERCRED's uid and gid equal the record's SERVER row and SO_PEERSEC matches its `processLabel` (gate-sys `label_matches`, kernel bytes with their NUL); the pidfd is kept; `/proc/<pid>` is opened and kept, reading nothing; the pidfd is alive; through the kept directory, `stat`'s start time (the session's reference), `cgroup` equal to the line `0::/<cgroup_rel>\n` (gate-sys `same_lines`) and `attr/current` matching the record's label; an OBSERVED server's `exe` equal to `interpreterPath` exactly, and no `exe` read at all for a LABEL_BOUND one. Each message: SCM_CREDENTIALS the same pid, uid and gid, SCM_SECURITY byte-equal to SO_PEERSEC, exactly one of each control message (gate-sys `parse_control`), no truncation and no passed descriptor. Before and after each read the pidfd is alive and the start time, cgroup and label are unchanged. Every failure closes the session; none raises a status | DESIGN-I01A §6; Q-HE4I1-11, -12 (a) |
| R153 | The window. The clock is the wall second the client passes from `Wire::wall_seconds`; the interval is `[validFrom, expiresAt - 3 s)` (the capture engine's margin). Checked at accept and before each read: before `validFrom` the session closes with no latch; from `expiresAt - 3 s` any session is cut and the service stays closed until restart (a clock stepped back does not reopen it); no clock (`None`) closes without a latch. An open session is cut at the next read or deadline call, within the 2 s idle bound | DESIGN-I01A §6 |
| R154 | Not re-checked, and why: the listener's inode (no primitive; each peer is authenticated per connection, and only `init_t` can in practice unlink the path); the executable per message (SERVER's filter denies `execve` and `execveat`); the v1 inode-or-digest duty (path equality plus enrollment's fs-verity, the HS43 writer precedent) | DESIGN-I01A §6 |
| R155 | The request, in order (`i01_request`, a logic module): framing (one datagram of 1-16,384 bytes, not cut short; printable ASCII; one strict JSON value; depth at most 16 with the root at 0; no float; integers within 2^53 - 1; decoded strings printable ASCII; the bytes equal to their canonical encoding), the schema (exactly the seven members of `policy-observation-request/v1`, each in its form, `sequence` 1 to 2^53 - 1), the chain (a session's first request is sequence 1 after the all-zero digest; since nothing is answered, no later request can pass), then the binding gate, which refuses while no binding exists (I01a: always). Sessions: 2 s idle from the accept, 900 s outer. The refusal texts are R10's | DESIGN-I01A §7, §8; Q-I01A-3 (a) |
| R156 | The quota pair (`quota::quota`): per unit, the covering key with the least headroom (ties by the quota object's name, then the key's name), recorded as `floor(hard)` and `min(ceil(used), floor(hard))` in the unit's scale, so the pair never overstates the headroom and never shows `used > hard`; the chosen key's recorded values above 2^53 - 1 refuse the snapshot (89, "a recorded quota figure is above 2^53-1"), an unchosen key is never bound-checked; kept in `Observation.quota` beside `headroom` | DESIGN-I01A §9 |
| R157 | The role pin (`observer_rbac`, a logic module): in `check_snapshot`, right after `Closure::check` with only the three list bindings between and before `let dropped` and `drop(produced)` (G-I01-3), so before OR02, OR05 and OR06; a refusal is status 87 ("I06 v4's role pin refused"). The rule data is compiled in (the eight rules, the role and binding names, the API version, the roleRef, the one User subject, the five server metadata fields) and held to the vectors' `objectsPositive` by `tools/gate.py`. Pinned refusals are the vectors' texts; R10's words for the two no vector pins: "RB02 the observer ClusterRole's rules member is no array" and "RB02 the observer ClusterRole's rule N is not an object of text lists". Python's `==` on a constant text is an exact string match; the model's `_same` against the constants is exact JSON equality; `str.strip()` is R10's copy of CPython 3.12's whitespace; a lone surrogate in a name shows as U+FFFD in a refusal. RB05 on a snapshot `Closure::check` would refuse (unreachable in `observe.rs`) answers "absent" | DESIGN-I01A §10; Q-RBAC-4, Q-HE4I1-9, Q-I01A-4 (a) |
| R158 | Residuals (accepted). R116's "no way out" premise ends: a compromised observer now has a path to `planeon_server_t` (SELinux `connectto`, that domain only), although I01a sends nothing on it. A LABEL_BOUND server's executable is not checked (Q-HE4I1-11 (b), keeping the server without CAP_NET_BIND_SERVICE, is carried to HE-008 and T04). Per-connection containment rests on the cgroup line and the label; the cgroup's inode, limits, members, seccomp mode, `no_new_privs` and capabilities come from the last capture set (up to one cycle old). The pidfd and start time pin a process, not an identity. The Secret residual stays accepted; HE-008 seals an SC12 audit policy that flags an observer Secret request outside the two field-selected metadata forms, and T04 reads it (an audit event cannot see `Accept`); the `system:authenticated` limit is I06 v4's, carried to T04 | DESIGN-I01A §6, §11; Q-HE4I1-8, -13 (a) |
| R159 | Gate rules (`tools/gate.py`): 50 contracts; `OBSERVER_PROGRAMS` on seccomp v5; `linux_listen.rs` among the socket files and the whole-file pins (`linux_net.rs` re-pinned); `I01Socket` a Debug hazard; the no-panic list adds `linux_listen`, `i01_service`, `i01_request` and `observer_rbac`; `i01_request` and `observer_rbac` take B1's logic rule (`I01_LOGIC_PATHS`); `serve`'s wiring has thirteen calls (`enrolled.server_identity()` after `Enrolled::new`); G-I01-1 (no unlink, remove or rename spelling), G-I01-2 (the one wire wait and the one step call), G-I01-3 (the role pin's one call and its place), G-I01-4 (the I01 path only in `linux_listen.rs`'s constant), G-I01-5 (nothing leaves I01a), G-I01-6 (`I01Socket`'s two homes and one construction), and the role pin's constants against `objectsPositive`; each reported | DESIGN-I01A §12 |
| R160 | Tests (§15): `observer_status_i01`, `observer_i01_wait`, `observer_i01_request`, `observer_i01_service` (custody with a fake `PeerOps` and kernel-shaped labels), `observer_i01_quota`, `observer_i01_role_pin` (the 139-case I06 v4 replay: 96 of v4's own and v3's 43 snapshot cases on the v4 positive; the frozen inputs and constants; R10's texts; the rig's 87) and gate-sys's Linux-only `listen_plain`. Earlier test files change only where the design reaches them: the seal digests and counts, the fake wire's new `wait` and `PeerOps`, the quota edge of R156, and the rig's RBAC fixture (the observer's grants are now the contract role's alone) | DESIGN-I01A §15 |

### Points settled at build (inside DESIGN-I01A's intent)

- **The service's attachment (R150):** owned by the client (`serve_peers`) rather than lent per call; it still holds
  session state only. Deadlines are a second method, so `serve_peer_step` is spelled once and called once per ready
  descriptor.
- **Status 35's path (R151):** a listener failure reaches the epoch as a poll error that the client names
  (`listener_failed()`), read before the 95 mapping; a failed removal of the listener is a fault too, and any watch
  fault makes that wait zero-timeout.
- **The server identity (R152):** `Enrolled::server_identity()` refuses through `status::capture_setup` (27) for a row a
  schema-valid record cannot lack, so no new status.
- **The binding (R155):** never a service field; the gate is exercised with a test binding through `i01_request`
  directly. The idle bound runs from the accept only, since every first request closes the session.
- **The quota edge (R156):** HE-004C's `tests/observer_quota.rs` passed a pods hard of 2^53 + 2 whose headroom was
  exactly 2^53 - 1; under the chosen key's bound it now refuses with R156's text, and a hard of 2^53 - 1 passes beside
  it.
- **The role pin's object form (R157):** `object_lists` reads the vectors' (and HE-008's manifest's) three-list object;
  `observe.rs` passes the read's own lists, so that reading cannot refuse there. The composed replay reads the object
  form after the closure check and before RB05; no composed case has an unreadable form.
- **The rig's RBAC fixture (R160):** `tests/c_support`'s `positive_rbac` leaves out the observer's I06 v2 entry, so its
  grants come only from the contract role and binding the rig already adds; otherwise RB05 and RB06 refuse the rig's
  read.
- **G-I01-2 (R159):** every `wait` word counts, definitions aside (stricter than the call forms alone).
- **`ListenerSetup::Socket` (R149):** it also stands for gate-sys's two sockcreate steps, which the plain listener never
  reaches, so 31 covers every socket-stage refusal.
- **The quota tie-break (R156):** a quota object without a name sorts as the empty name.
- **`listen_plain` (R160), a departure from §15:** the test cannot accept a real peer, since a SEQPACKET client needs a
  raw `socket` call, which no test may hold; it binds, listens, sees no queued peer and EADDRINUSE on a second bind. It
  is Linux-only, and every run so far (the build host's `cargo test`, the sim and the verifier) is on macOS, where it
  holds 0 tests: the plain listener's bind, listen and EADDRINUSE behaviour has run nowhere yet. Both are carried to
  T04.

### Evidence

The heavy checkpoints ran in order under HOLD_CARGO sequencing, each on the lane monitor's word, on macOS:
- `cargo test`: 724 passed, 0 failed, in 109 test binaries. The new binaries: `observer_status_i01` 2,
  `observer_i01_wait` 7, `observer_i01_request` 4, `observer_i01_service` 11, `observer_i01_quota` 3,
  `observer_i01_role_pin` 9, and `listen_plain` 0 (Linux-only; see the settled points).
- Both musl release builds: rc 0.
- `gate.py`: the first run failed its self-test with 27 errors, all from one cause: U6's literal-aware bracket helper
  was a second module-level `bracket_end`, which replaced D1's two-argument helper. It was renamed `literal_bracket_end`
  (two lines; no other name is bound twice). After that: "he-gate: passed", self-test 332 OK, 50 contract files,
  G-I01-1..6 (G-I01-3 with 3 `let`s), the role constants (14), G-D1-16 and G-D2-7 on both targets.
- The sim (`./ci/verify-offline.sh` over the packet): rc 0, nine argv, the zero-bill scan passing, tracked files
  unchanged. planeon-gate, planeon-broker, planeon-containment and planeon-writer and their SBOMs are byte-identical to
  HE-004D2's; planeon-observer changes, by the I01a code and the seccomp-v5 programs.
- The 8-word span check against the three model files: shared spans only inside contract text (the vectors' pinned
  refusal texts and the rule data), byte-exact.

At build only `python3 -I -B` text checks ran: the contract digests and sizes, the seal constants and the BPF decode
shape, the gate-sys foreign symbols, independent mirrors of G-I01-1..6 and of the constants check over the real sources,
the serve wiring order, a python model of the request checks (56 cases), the quota choice, a python reading of
`observer_rbac.rs` over the vectors (67 object cases, 65 snapshot cases after the vectors' v3 results, 7 composed), the
8-word span check and the privacy scan.

### Code and audit

- `crates/observer/src/`: `linux_listen.rs`, `i01_service.rs`, `i01_request.rs` and `observer_rbac.rs` are new;
  `client.rs`, `linux_net.rs`, `status.rs`, `observe.rs`, `main.rs`, `lib.rs`, `enrolled.rs`, `quota.rs` and `seal.rs`
  change. gate-sys gains `listen_seqpacket_plain` in `channel.rs`. No new crate, no manifest or lock change, no
  `vendor/`, `licenses/` or `ci/` change.
- `contracts/` (four files and PROVENANCE's section), `tools/gate.py`, `tools/test_gate.py` (R159) and this section.

### Carried

- **I01b:** the response side (the answer, `observedAt` and the clock rules), generation equality across a reservation
  (HE-008's signed generation), the snapshot and scrape rate and the probe slot shared with per-request reads, the
  reuse window from the read's stamp, whether the latest SERVER capture slot feeds availability, and the idle bound's
  renewal on a request's receipt.
- **I01 successor or HE-008:** capturer authentication; per-request capture freshness and retention across cycles; the
  ADM-4 origin through I01 custody; the unavailable variant.
- **HE-008:** the binding (signed config successor); `Restart=` with a start-rate limit (status 35); `ExecStartPre=`
  clearing the socket path as `init_t`; `UMask=0177`; the I06 v4 role document and manifest check (RB00), whose objects
  carry no annotations; the SC12 audit policy; Q-HE4I1-11 (b).
- **W03 / T04:** the type transition labelling `policy-observer.sock` (without it `bind` refuses, 32); T04's checks of
  the residuals above, of the listener accepting a real peer, and a Linux run of `listen_plain` (bind, listen,
  EADDRINUSE), which no macOS run reaches.
- **The next re-pin or gate revision (PR review round 1's notes):** G-I01-5 and `check_socket_items` do not follow a
  crate alias (`use gate_sys as gs`), which only the two socket files' whole-file pins close today; the rules' textual
  limits (a split or escaped path literal, `serve_peer_deadlines` unpinned, no `unlinkat`/`renameat` words, a condition
  such as `cfg!(debug_assertions)` around the role pin's call); nothing pins that `serve` maps the wire's setup errors
  through `status::wire_setup` (31-34); the no-panic report line does not name the four I01 sources (its count, 25, is
  right).
- **What stays code review's:** every index guarded and every arithmetic step checked; the custody order inside
  `serve_peer_step`'s control flow beyond what the fake `PeerOps` records; `I01Socket`'s methods matching their
  `PeerOps` operations one to one.

## HE-004-I01A2: the I01 wire's request replay and four of HE-004-I01A's review notes (`contracts/i01-v1/`; `tests/observer_i01_pv_replay.rs`; `tools/gate.py`)

The packet is HE-004-I01a's unit U7 (DESIGN-I01A revision 6, sha256 `2d976d19…`, sections 3, 7 and 15; owner
decisions Q-HE4I1-10 (a) and Q-I01A-1; the lane monitor's Q-U7-1..3 (a) under owner delegation, 2026-10-22, recorded
in the operator's `tools/w03/he004/OWNER_DECISIONS.md`). It vendors the I01 wire's channel schema (`CS`) and vectors
(`PV`), which edge record v9 registers (harness-onion MET-ENFORCE-040), and replays `PV`'s request cases against
HE-004-I01A's request checks; with it come the cheap notes of HE-004-I01A's PR review rounds 1 and 2: R1-3, R1-5, R1-6
and R2-N5. No source under `crates/` changes: one test file is new, and `tools/gate.py`, `tools/test_gate.py`,
`contracts/` and this file change. Every binary, planeon-observer included, is expected byte-identical to
HE-004-I01A's. The validators `scripts/validate_policy_observation.py` (`ed0008be…`, "VPO") and
`scripts/validate_proxy_contract.py` (`13019446…`, "VPC") at harness-onion `6835a6ed` are pinned by digest and read as
specification only. Its rules are R161-R166.

### Points taken from the pinned validators (the design and the vectors are silent)

| # | Point | Validator |
|---|---|---|
| P1 | The binding a request names: its `bindingDigest` is `sha256:` and the SHA-256 of the binding document's canonical encoding, and its `runNonce` is the binding scope's `runNonce`. The replay's test binding is built from `PV`'s positive binding document this way | VPO `:110-111` |
| P2 | The canonical encoding: sorted keys, `,` and `:` separators and no whitespace, non-ASCII text unescaped (`ensure_ascii=False`), no non-finite number. R10's is i05-protocol's encoder, and the replay holds the two equal on the positive's binding document (the digest P1 names) | VPC `:29-30` |
| P3 | The request's own bounds beside the schema: its canonical encoding at most 16,384 bytes, depth at most 16 with the root at 0 (a member name counted one level below its object), integers within 2^53 - 1 in magnitude, only data values, and every text and member name printable ASCII. These are R155's framing rules, and on these bounds neither side is stricter for any request (an object at depth 16 with a member refuses on both); R10 also holds the bytes to their canonical encoding, which the validator, reading decoded values, does not see | VPO `:60-71`, `:87`; VPC `:104-114` |

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R161 | Scope. `contracts/i01-v1/channel.schema.json` (41,771 bytes) and `vectors.json` (14,486 bytes) are edge record v9's rows 67 and 68, byte for byte, mode 100644, at providerCommit `108e6195`, copied with `git show 6835a6ed:<providerPath>`; contracts: 52. `docs/alpha-2/POLICY_OBSERVATION_READINESS.md` is cited, not vendored (Q-EV9-1b (a)). Both files are read by the tests only: nothing in `crates/observer/src/` embeds them, and the I01 request checks (R155) are unchanged | DESIGN-I01A §3, §7; Q-HE4I1-10 (a), Q-I01A-1 |
| R162 | The replay (`observer_i01_pv_replay`, at unit level). The vendored bytes are the rows' sha256 and sizes, and `PV` holds 27 negatives: 5 on the request, 17 on the observation, 5 on the binding. `CS`'s `$defs.request` is the definition `i01_request` implements: exactly the seven members, `additionalProperties` false, the two constants, the three text forms and lengths, `sequence` from 1 to 2^53 - 1. The positive's request, encoded canonically, passes framing, the schema, a fresh session's chain and the binding gate with the test binding, and closes at the gate without one. Each request negative refuses at its own step, compared exactly: negative 1 (operation) at the schema, "another operation"; negatives 2 (`runNonce`) and 3 (`bindingDigest`) pass framing, the schema and the chain and refuse only at the gate, where a binding naming the changed member would pass them; negatives 4 (sequence 2) and 5 (a previous digest other than zero) at the chain, "a session's first request is sequence 1 after the zero digest", with the gate alone passing them. The whole check gives the same refusal with the test binding and without one. The positive's request in the vectors file's member order, with whitespace or with a line end refuses at framing (canonical form, printable bytes) | DESIGN-I01A §7, §15; review r2 I2-8, r3 I3-11 |
| R163 | The test binding's reach. `test_binding` is a function of the test binary only (`#[cfg(test)]` in `tests/observer_i01_pv_replay.rs`): it builds an `I01Binding` from `PV`'s positive binding document (P1, P2). Nothing in `crates/observer/src/` builds an `I01Binding`; the I01 service passes no binding (`i01_service.rs` calls `check_request(.., None)`) and `ObserverConfig` has no binding member, so through `serve` every request still closes at the gate (Q-I01A-3 (a)). `i01_request.rs` stays a child-free logic module (no test module is added to it) | DESIGN-I01A §7, §8; owner safety rule (2026-10-21) |
| R164 | Not replayed: `PV`'s 17 observation and 5 binding negatives, and the positive's observation and binding as documents. They also read the proxy profile, harness-onion `architecture/proxy-contract-inputs/vectors.json`, which no edge record registers (edge record v9's replay-scope note), and the observation side is I01b's. R10's own framing negatives (§15) were all built by HE-004-I01A: `observer_i01_request` (size, bytes, strict JSON, depth, floats, integers, decoded text, the non-canonical encodings, extra and missing members), `observer_i01_wait` (a datagram over 16,384 bytes cut short, other ancillary data, a passed descriptor) and `observer_i01_service` (each receive outcome closing the session); none is added | DESIGN-I01A §15; Q-EV9-1b (a) |
| R165 | Gate rules (`tools/gate.py`). Contracts: 52. R1-3: `resolved_uses` follows a source's own aliases (a rename of gate_sys itself, plain or braced, and a module or item bound under it, in chains); G-I01-5 reads the two observer socket files' use paths through it, so an import of `send` and a rename of the channel module through a crate alias refuse as their direct forms do, a `name::send` path through a name bound to the channel module refuses as `channel::send` does, and the two files hold no rename or glob of gate_sys and no `extern crate`; the socket-item rule (`check_socket_items`, all four socket files) reads its imports through `resolved_uses` and a gate_sys rename's qualified paths as gate_sys's. R1-5: `serve`'s wire construction is exactly `let wire = match LinuxWire::new(sealed) { Ok(wire) => wire, Err(error) => return status::wire_setup(&error), };` (`WIRE_SETUP_MATCH`), so its refusal keeps 24 and 31-34. R1-6: the no-panic rule's docstring and report line name the four I01 sources (`I01_NO_PANIC_BUILT`); its count is unchanged (25). Each reported | HE-004-I01A PR review r1 R1-3, R1-5, R1-6; Q-U7-2 (a) |
| R166 | Tests: the new binary `observer_i01_pv_replay` (5 tests). Self-tests: the contract table, D2's count and its missing, changed and unregistered files cover the two I01 files (52; the readiness document refuses if held); `test_g_i01_5_the_alias_forms_refuse` (the reviewer's probe and 17 kin, in both observer socket files), `test_items_through_a_crate_or_module_alias_refuse` (7 forms and a glob, in all four socket files) and `test_the_wire_s_refusal_maps_through_wire_setup` (7 departures and a spaced form); `GOOD_OBSERVER_MAIN` and `SERVE_STEPS` follow `main.rs`'s `match` form (R1-5). No earlier test binary changes | DESIGN-I01A §15 |

### Points settled at build (inside DESIGN-I01A's intent)

- **The test binding's source (R163):** it is built from the binding document rather than copied from the request, so
  the replay also checks that i05-protocol's canonical encoding is the one `PV` was written with (P2); the digest is
  `sha256:e10d89fd…`.
- **"Each negative's own refusal" (R162):** `PV` writes no refusal text, so each negative is held to the step and R10
  text of the request rule it changes, and to that step alone (the steps before it pass).
- **The validator's order (P1, R162):** VPO checks the request's binding, then the response's echo of the request, then
  the initial chain. Negatives 4 and 5 change only the request, so VPO's first failing check for them is the echo, while
  R10, which answers nothing in I01a, refuses them at the chain, the rule they target; both refuse. R10 runs its chain
  before the binding gate (DESIGN-I01A §0 item 2); no vector breaks both, so the order between the two is not replayed.
- **`#[cfg(test)]` (R163):** every `tests/` binary is built with `cfg(test)`, so the attribute only marks the test
  binding as test code; `i01_request.rs` has no test module because its logic rule keeps it child-free.
- **R1-3's form (R165):** both of the reviewer's options are taken for the observer's two socket files (aliases
  followed, and a gate_sys rename refused); effect-gate's two socket files keep their reading, with aliases followed and
  no new refusal, as no rule there named the alias forms. The real files hold no alias, so every count is unchanged.
- **R1-5's check (R165):** the optional textual check is added; it reads the whole `match` statement, so another status,
  another variable name or a changed arm refuses.
- **R2-N5:** six prose lines of the HE-004-I01a section were over 120 columns; they are reflowed with their words
  unchanged. Table rows and headings are not wrapped.

### Evidence

The heavy checkpoint (on the lane monitor's word, 2026-10-22, each step through `heavy.zsh`):
- `cargo test`: 110 binaries, 729 tests passing, 0 failing (HE-004-I01A: 109 and 724); `observer_i01_pv_replay` adds 5,
  and every earlier binary's count is unchanged.
- Both musl release builds pass. planeon-gate, planeon-broker, planeon-containment, planeon-writer and
  planeon-observer are byte-identical to HE-004-I01A's (binaries, symbols and SBOMs), as no crate source changed.
- `gate.py`: `he-gate: passed`, with 52 contract files matching the registered harness-onion bytes. Its self-test runs
  335 tests, all passing (HE-004-I01A's 332 and the three above).
- The sim: run on the packet head before the PR review (the lane monitor's word).
- The 8-word span check against VPO and VPC at `6835a6ed`, contract text excluded: 7 files, 7,517 words, no shared span.

At build only `python3 -I -B` text checks ran: the two files' sha256, sizes and modes against edge record v9's rows;
the binding document's canonical digest with the validators' encoding (`e10d89fd…`, the positive's `bindingDigest`); a
python model of the request checks over `PV`'s six request cases (the positive passing with the test binding and each
negative at the step R162 names); `CS`'s request definition against `i01_request`'s constants; `gate.py` and
`test_gate.py` parsed (335 test methods, no name bound twice); the new `WIRE_SETUP_MATCH` pattern on `main.rs`, the old
`let Ok(wire) = .. else` form and a spaced form, and `resolved_uses` and `gate_sys_aliases` on hand-made use paths; line
widths and the privacy scan.

### Code and audit

- `contracts/i01-v1/` (two files) and PROVENANCE's section; `crates/observer/tests/observer_i01_pv_replay.rs` (new);
  `tools/gate.py` and `tools/test_gate.py` (R165, R166); this section and the HE-004-I01a section's reflow. No source
  under `crates/`, no manifest or lock, no `vendor/`, `licenses/` or `ci/` change.

### Carried

- **HE-004-I01A's other review notes (Q-U7-2 (a)):** R1-4, the G-I01 rules' textual limits (a split or escaped path
  literal outside `linux_listen.rs`, a struct-literal `I01Socket` inside it, a type alias of `ConnId` or `Client` in
  `lib.rs` and a response module not named `i01_*`, `serve_peer_deadlines`' call sites, no `unlinkat`/`renameat`
  words, an `if false && ..` or `cfg!(debug_assertions)` condition around the role pin's call); R2-N2, the
  `listen_plain` point's "the verifier" among the runs so far; R2-N3, the operator's `BUILD-I01A.md` against
  MODEL_DEFINED; R2-N4, HE-004-I01A's evidence naming no commit.
- **A later edge record:** the binding and observation replays, which need `architecture/proxy-contract-inputs/` (the
  profile) registered first.
- **I01b, HE-008, W03 / T04:** unchanged from the HE-004-I01a section.
- **What stays code review's:** that no non-test source builds an `I01Binding` (no gate rule pins it; `i01_service.rs`
  passes `None`); aliases reached through another module (`crate::`, `super::` paths) are not followed, and stay closed
  by the socket-module rule, which refuses a gate_sys rename and any path to the socket modules outside the socket
  files, and by the socket files re-exporting nothing.

### Owner decisions (verbatim as relayed, 2026-10-22)

> [lane monitor] U7, monitor under owner delegation 2026-10-22, all (a):
> - Q-U7-1 (a): **HE-004-I01A2**, branch codex/he-004-i01a2-pv-replay.
> - Q-U7-2 (a): U7 as designed, plus the cheap NOTEs:
>   - R1-3, hardening G-I01 against the alias form, with self-tests;
>   - R1-5 and R1-6 docstrings;
>   - R2-N5 wraps.
>   R1-4 and R2-N2..N4 stay carried.
> - Q-U7-3 (a): the worktree on R10 main 12939ef3 via the standing ref-only R10 fetch from your own R10 worktree (log it). Write the build brief now, as light work.

The complete messages are recorded in the operator's `tools/w03/he004/OWNER_DECISIONS.md`.

## HE-004-I01B1: the I01 digest port (`contracts/i01-digests-v1/`, `contracts/i01-v1/proxy-contract-vectors.json`; `i01_digest`, `i01_admission_render`, `i01_gate`; three replays; `tools/gate.py`)

The packet is HE-004-I01b's first (DESIGN-I01B revision 3, sha256 `97bdefa6…`, sections 2, 6, 7.5 and 8; its I01B1
design section DESIGN-I01B1 revision 2, the section review's I1D-1 to I1D-12 binding; owner decision Q-HE4I1-2, the lane
monitor's Q-I01B-7..27 (a), the closure of DESIGN-I01B under Q-I01B-CAP with R-B3-A, R-B3-PIN and R-TEXT, the
HE-004-I01B1 build GO and MON-I01B1-A (a) and MON-I01B1-B (a), recorded in the operator's
`tools/w03/he004/OWNER_DECISIONS.md`). It vendors edge record v10's four rows (the I01 digest contract's definitions,
vectors and README, and the proxy-contract vectors; 56 contracts) and re-pins VPO, and it adds the contract's port as
three pure logic modules that nothing in `serve` reaches, three replays, and the I01B1 gate rules. The observer's
reachable code is unchanged, and neither musl build links the three modules (G-I01B-1's symbol check). The contract's
reference model `scripts/policy_observation_digests.py` (`01298fb5…`) and VPO (`3ac03636…`) at harness-onion `2043cc27`
are pinned by digest in PROVENANCE and read as specification only, never imported or run; VPC is not re-pinned (its
packet list changes with every packet, and the contract pins its helpers' behaviour by the helper vectors instead). Its
rules are R167-R175.

### Points taken from the pinned model (the contract's README and vectors are silent)

| # | Point | Model |
|---|---|---|
| P1 | A value holding a lone surrogate (an object's name or namespace, a member name or any document text) has no canonical encoding; the model refuses it as the key's malformed input when its canonical bytes are taken. R10 refuses it with that same text, earlier: at the first read of the value as text (`object_name`, `nonempty`) or at the digest | `projection`, `enforcement` (their `ValueError` arm) |
| P2 | The exactness walk: a float anywhere refuses first; then VPC's `_bounded` in its own order (depth first, each member's name before its value, members in document order), stopping at its first fault: a node deeper than 16, the 262,144 budget spent (a string or member name costs its code points, any other node one), or an integer past 2^53 - 1 in magnitude, checked after the node's cost. The first fault names the text | `document_bound`; VPC `_bounded` |
| P3 | Neither RBAC document can hold a number (B1 has checked every string and boolean), so the contract pins no float or integer text for `rbac` or `rbacClosureDigest`. R10 maps a float or an oversized integer there, which cannot occur, to the key's bound text | `refusal_texts`, `UNREACHABLE` |
| P4 | The model's "rbacClosureDigest: malformed input" for a missing or ill-shaped `i06` argument is unreachable in R10: the closure is I06 v1's typed, embedded closure (`Closure::embedded`), never an input | `_frozen_i06` |
| P5 | A render that yields nothing (the handed-in function returns `None`) is the key's malformed input, as an exception inside the model's render is | `projection`, `enforcement` |
| P6 | The capture gate's order: an unknown key, malformed capture data, no completed set, a required slot not `TAKEN` (for `hostPreflightDigest`, a record without a non-empty `backendComponents` object is malformed only once a completed set exists), then either age outside 0..90,000 ms | `capture_gate`, `required_slots`, `_capture` |
| P7 | The answer's composition: each projection and digest derived, the three gated values gated after they derive, each refusal or "<key>: differs from the signed value" (a projection's identity without its resourceVersion, a digest against `enforcementPins`), each text once, in key order | `observed`, `check_observation_digests` |

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R167 | Scope. `contracts/i01-digests-v1/{definitions.json, vectors.json, README.md}` and `contracts/i01-v1/proxy-contract-vectors.json` are edge record v10's rows 69-72, byte for byte, mode 100644; contracts: 56; none is embedded (`OBSERVER_EMBEDDED_CONTRACTS` stays at five). VPO is re-pinned at `2043cc27` (`3ac03636…`, replacing `ed0008be…`). Three logic modules are added, `i01_digest`, `i01_admission_render` and `i01_gate`, each a `pub mod` line in lib.rs and nothing else: no source of the observer names them or their types (G-I01B-1), so `serve` reaches none of them | DESIGN-I01B §2; Q-I01B-26 (a), Q-I01B-27 (a) |
| R168 | `i01_digest` (the contract's README sections 3-5): the seven projections and four enforcement digests from one snapshot (B1's checked lists, the read's resourceVersion, the configuration's values, ADM-4's loaded hash, the enrolled record) and the signed binding (read only for the bound names and the service-account subject). B1's producer runs first, so its refusals come first, in its order; the two RBAC documents are a second derivation over the same lists that keeps the non-resource rules B1 drops. The A2 render is handed in as a function (`&dyn Fn(&SealedAdmission) -> Option<Rendered>`), after the sealed values' checks and before the two hash equalities. Every refusal is one of the contract's 90 pinned texts, a `&'static str` written out in the module (P1-P5) | DESIGN-I01B §2; Q-I01B-16 (a); MON-I01B1-B (a) |
| R169 | `i01_gate`, the capture gate over plain data (README section 3.3, `captureGate`): the latest completed set (`LatestSet`: each slot with whether it is `TAKEN`, `scheduled_after_now`, `mono_age_ms: u64`, `wall_age_ms: i64`) or none. The required slots are `role/BROKER` (`mutationBroker`), `backend/NETWORK_POLICY_AGENT` (the network digest) and, for `hostPreflightDigest`, the five role slots, `lifecycle` and `backend/<component>` for each member of the record's `backendComponents`. A slot passes only if the set holds it and every entry of that name is taken; a component name with a lone surrogate never matches a slot. Both ages must lie in 0..=`GATE_BOUND_MS` (90,000); a start after the answer is `scheduled_after_now` and refuses. A key that is not capture-gated is its malformed input (the model's "unknown gated key" is no contract text). The texts are `i01_digest`'s (P6). The module also holds G-I01B-8's three literal pins: `ANSWER_LIMIT` 65,536 (VPO `:86-88`), `FRESHNESS_WINDOW_SECONDS` 5 (VPO `:128`) and `EXCHANGE_DEADLINE_SECONDS` 2 (Q-I01B-21 (a)); `CYCLE`, `SCRAPE_TO_SET` and `SET_BUDGET` stay in `observe.rs` and `capture.rs`. Building the facts from the capture view and the clocks is HE-004-I01B3's | DESIGN-I01B §2, §6 (G-I01B-8); F2.13; Q-I01B-13 (a), Q-I01B-21 (a) |
| R170 | `i01_admission_render`, the A2 render (Q-I01B-15 (a)): admission v3's `a2_objects` (one policy per qualification kind, the guard, one Deny binding each, in the model's order, the sealed values entering only the namespace selector, the Service allocation rule and the Pod tolerations rule), `manifest_file_bytes` (a v1 List, canonical JSON through i05-protocol's encoder) and the directory's hash over that one file named `planeon-a2.json`, reusing `admission::manifest_directory_hash`. No file is read: the observer renders | DESIGN-I01B §2; README §4.1, §5.1 |
| R171 | The replays. `observer_i01_digest_replay` (3 tests): the 16 helper vectors, the definitions pin and the 152 vectors with `i01_admission_render::render` handed in; the gate's 69 verdicts with the vectors' ms values as the ages (the replay's adapter checks the contract's capture data shape first; data of another shape, which R10's typed capture view cannot hold, is the key's malformed input, so G-20's three checks hold the adapter, not `i01_gate`); the 12 answer refusal lists and the complete I01 positive's 5 checks as the model composes them (P7), the comparison with the signed binding written in the test; 51 relations. Of the model's 320 checks, 318 are compared and 2 are refused earlier (R172). `observer_i01_render_replay` (4 tests): the render of admission v3's sealed values is the vendored `planeon-a2.json` byte for byte, with H01's and the pinned hash, and its items; each of the 9 `objects` vectors differs from it; the contract's 2 fence digests (P-UNIT, AF-01) and 3 `sealedObjects` documents (P-UNIT, AP-09, AP-11). `observer_i01_pv_replay` gains `PV_CASES`, PV's 22 binding and observation negatives as data (case, VPO rule, checker, packet), and a test holding its labels to negatives 6-27, each once; no row is replayed in I01B1 | DESIGN-I01B §2, §8.1; R-B1-13 (a); MON-I01B1-B (a) |
| R172 | RB-17's lists refuse earlier (MON-I01B1-A (a)). RB-17 deletes a ClusterRole's name; B1's `Inputs::new` refuses the lists (`ItemShape`, ClusterRoles item 1) before either RBAC value is derived, so R10 never reaches the producer's "rbac: malformed metadata", which the vector pins for `rbac` and `rbacClosureDigest`. Both are refusals and nothing is derived. The replay asserts the earlier refusal for those 2 checks | MON-I01B1-A (a) |
| R173 | Gate rules (`tools/gate.py`). G-I01B-2 (the four files' rows, PROVENANCE lines, mode and no embedding). G-I01B-1's I01B1 form: G-D2-5's construction, now one function over a module list (`module_isolation`, which G-D2-5 also calls with its own list and messages), over the three modules, with the symbol-table corroboration in G-D2-7's style (`check_i01b1_absent`). G-I01B-7: the `src/**/i01_*.rs` files are the five `I01_FILES_BUILT`, lib.rs declares exactly `OBSERVER_LIB_MODULES` (38: HE-004-I01A2's 35 and the three), each once and in file form, no other source declares a module, and the three take the logic and no-panic rules. G-I01B-8: `GATE_BOUND_MS` against `captureGate.boundMs` (the sum of its three parts), `CYCLE`, `SCRAPE_TO_SET` and `SET_BUDGET` read in place against those parts, the three literal pins with their citations, and the three modules' key-prefixed refusal texts exactly `refusalTexts`. R-B3-PIN: `check_i01b_guarded_pins` (R174). B3-1: `check_socket_module_aliases`, G-I01B-6 (e) as I1D-1 and I1D-2 state it: in every non-test source of effect-gate and the observer, a use path that is a socket module of its crate (renamed or not, its trailing `self` read as the module) or a glob through one refuses, a pub use naming one refuses, a use of a scope root alone refuses, a glob of a scope root refuses everywhere but at the top level of a crate's lib.rs (PR review round 1, R1-2), and an item import passes (today's three: effect-gate `linux_os.rs:39`, observer `linux_net.rs:35`, `main.rs:63`). The new checks run right after `check_observer_home_pins`, each printing its count | DESIGN-I01B §6; DESIGN-I01B1 §1, §2, §4; I1D-1..I1D-5, I1D-10, I1D-11 |
| R174 | R-B3-PIN in I01B1 (`I01B_GUARDED_PINS`): effect-gate's `linux_os.rs` (`88e70bf5…`) and `linux_net.rs` (`d452aa50…`) and the observer's `config.rs` (`bef5143c…`), `i01_request.rs` (`aee536e5…`), `i01_service.rs` (`b94f6daf…`) and `client.rs` (`2987e41d…`) are pinned whole at their `dd7422ed` bytes (each `cmp`-equal to `dd7422ed`, unchanged by I01B1); `linux_listen.rs` and `linux_net.rs` stay in `OBSERVER_HOME_PINS`, unchanged; `i01_answer.rs` has no directory entry (a file, a directory or a dangling symlink refuses). No entry of a guarded file's directory casefolds to a guarded name (pinned, absent or home-pinned) other than that name (`casefold_siblings`, read over each directory's listing, so its self-test runs on any file system: PR review round 1, R1-4). Each guarded module is declared once, in file form, in its crate's lib.rs (`pub mod config;`, `pub mod i01_request;`, `pub mod i01_service;`, `pub mod client;`, `pub mod linux_listen;`, `pub mod linux_net;`; effect-gate's `pub mod linux_os;`, `pub mod linux_net;`), and no source of either crate holds an inline `mod <one of them> {` (I1D-3) | R-B3-PIN; DESIGN-I01B1 §1; I1D-3, I1D-10 |
| R175 | The zero-bill allowlist (owner decision Q-I01B1-ZB, "Two exact allowlist entries"). `ci/zero_bill_scan.py`'s `CONTRACT_ALLOWLIST` gains, by exact path and sha256, `host-enforcement/contracts/i01-digests-v1/vectors.json` (`bd9f04bd…`, the vendored contract vectors, which carry the admission policy's rendered objects) and `host-enforcement/crates/observer/src/i01_admission_render.rs` (`2e23e488…`, the render, which writes the same rule text). Each is exempt from the scan's two service-type patterns only: every other pattern still applies, and a changed byte, or the same bytes at another path, fails as before. Any later edit of the render changes its bytes and must re-pin its entry in the same packet; the comment above the allowlist says so, beside Q-HE4B1-ZB's. It is the packet's one `ci/` change, and its transport and merge take the owner's approvals | Q-I01B1-ZB; MON-I01B1-FIX (iii) |

### Points settled at build (inside DESIGN-I01B's intent)

- **The closure digest re-runs the closure check and the role pin (R168):** `rbacClosureDigest` exists only after I06's
  closure check and I06 v4's role pin pass on B1's snapshot of the same lists, so `i01_digest` runs `Closure::check` and
  `observer_rbac::check_observer_snapshot` itself, as `observe.rs` runs them; the epoch's own calls are unchanged.
- **`crate::observer_rbac` under the I01 whitelist (R168):** the role pin is an I01 logic module, so `I01_LOGIC_PATHS`
  admits `crate::observer_rbac` in `i01_digest` without widening the whitelist.
- **`&'static str` refusals (R168, R169):** every refusal is a contract text written out once in `i01_digest`, including
  the capture gate's and "differs from the signed value" texts (`DigestKey::capture_not_passed`, `capture_too_old`,
  `differs`), which `i01_gate` and HE-004-I01B3 use rather than write again; G-I01B-8 holds the set to `refusalTexts`.
- **The pins (R167):** the contract's reference model is pinned in PROVENANCE (`01298fb5…`) and read as text; VPC is not
  re-pinned.
- **The capture gate's plain data (R169):** the design's `mono_age_ms: u64` cannot hold a start after the answer, so
  `scheduled_after_now` carries it (DESIGN-I01B §4.1's `CaptureFacts` field of that name); no completed set is `None`,
  and an Expired view is a set whose slots are all not taken (README section 3.3).
- **The literal pins' home (R169):** DESIGN-I01B places none of `ANSWER_LIMIT`, the freshness window and the exchange
  deadline, so all three are in `i01_gate.rs`, which G-I01B-8 reads.
- **The answer lists in the replay (R171):** the model's `check_observation_digests` is a composition (derive, gate,
  compare), so the replay writes the comparison itself over the port's values; HE-004-I01B3's `i01_answer` (windows,
  rollback, self-check, assembly, the bound) is not built, and its comparison must agree with these 12 lists and the
  complete positive.
- **G-I01B-6 (e)'s spellings (R173):** a glob through a socket module refuses beside the module itself (an item import
  is a path that continues to an item, not `self` or `*`); a `pub(crate)` use is a `pub` use; in main.rs the library's
  name is read as a scope root, so `use planeon_observer as po;` refuses. A glob of a scope root refuses everywhere but
  at the top level of a crate's lib.rs, beyond I1D-1's list of scope-root renames (PR review round 1, R1-2). The I1D-11
  matrix holds 128 cases, the unrenamed module import among its spellings (R1-7).
- **The BROKER lists' order (MON-I01B1-SPAN-2 (a); PR review round 1, R1-5):** BROKER_MEMBERS (i01_digest.rs:61) and
  BROKER_DOCUMENT (:69) list the v4 record's 20 BROKER row members and the mutationBroker document's 14 members in
  code-point order, the canonical encoding's order, not README section 4.6's (MON-I01B1-SPAN-2 (a)). Only membership
  counts: the row is checked as a closed set, and the document's members are encoded with sorted keys, so the order
  changes no refusal, no byte and no digest; CGROUP_MEMBERS keeps the README's order for the same reason.
- **G-I01B-7 (b) in file form (R173):** both of I1D-3's readings are taken: lib.rs's declarations are read only in file
  form, and `check_i01b_guarded_pins` holds the eight guarded declarations to the line-anchored form.
- **The casefold clause (R174):** it reads the pinned, the absent and the two home-pinned observer socket files' names,
  so all nine guarded names are covered.
- **`I01_FILES` (R173):** it lists the five sources and `I01_FILES_BUILT` equals it, as in HE-004-I01a; G-I01-5 reads
  the five, and its base self-test's refusal of `src/i01_digest.rs` becomes a pass, with `src/i01_answer.rs` refused in
  its place.

### Evidence

At build only `python3 -I -B` text checks ran: the four files and the guarded files against their rows and pins (each
guarded file `cmp`-equal to `dd7422ed`); the render's 17 CEL validation texts, decoded from the Rust literals and
formatted for admission v3's sealed values, against the vendored `planeon-a2.json`; the vector selections the replays
count (the 9 `objects` vectors, the 2 fence digests and 3 documents, the 22 PV labels); the new gate rules re-stated as
text and applied to the real sources (the socket-module alias rule over 60 sources with the three item imports, the five
i01_ sources and 38 lib.rs modules, the guarded pins, the 7 constants, the 90 refusal texts, the 11 type names of the
I01B1 isolation) and to the alias matrix's 120 cases; `gate.py` and `test_gate.py` parsed (361 test methods, no name
bound twice; HE-004-I01A2's 335, part 1's 6 in `I01bContractFileTests` and 20 new, in `I01b1IsolationTests` 5,
`I01b1SymbolTests` 1, `I01SourceRuleTests` 3, `I01bConstantTests` 3, `I01bGuardedPinTests` 5 and
`SocketModuleAliasTests` 3); line widths and the privacy scan.

The heavy checkpoint, on the lane monitor's word (Q-I01B1-RERUN), at `99c014ca`: `cargo test` 737 passed, 0 failed, in
112 binaries, with only the vendored ring warnings; the gate's self-test, 361 tests, OK; both musl release builds;
`he-gate: passed`, with 56 contracts and no symbol of the three I01B1 modules among planeon-observer's 2740 (x86_64) and
2822 (aarch64) symbols; the span check, 0 shared spans outside contract text and 207 in contract text. The packet commit
`6d579782` changes only the YAML. The fix for PR review round 1 (MON-I01B1-FIX) adds two self-tests,
`test_the_casefold_clause_on_a_listing` and `test_scope_root_globs_refuse_outside_a_crate_root` (363 in all, B3-11 (e)'s
count), grows the I1D-11 matrix to 128 cases and adds R175's allowlist entries. The sim and zero-bill evidence of the
final head is recorded in the PR body.

The span check's limits (PR review round 1, R1-3): three of its eight baselines are byte-identical to vendored contract
files (the digest contract's README.md and definitions.json, and admission v3's README.md), so every span they share is
contract text and they can never report one; its 0 is meaningful against VPO, the reference model, RD,
`admission_semantics_v3.py` and VPC. It reads only `host-enforcement/`, so `task-packets/` is not scanned.

### Code and audit

- `crates/observer/src/i01_digest.rs`, `i01_admission_render.rs` and `i01_gate.rs` (new) and lib.rs's three `pub mod`
  lines; `crates/observer/tests/observer_i01_digest_replay.rs` and `observer_i01_render_replay.rs` (new) and
  `observer_i01_pv_replay.rs` (the PV table); `contracts/i01-digests-v1/` and
  `contracts/i01-v1/proxy-contract-vectors.json` with PROVENANCE's section; `tools/gate.py` and `tools/test_gate.py`
  (R173, R174); `ci/zero_bill_scan.py`'s `CONTRACT_ALLOWLIST` and the comment above it (R175); the packet YAML; this
  section. No other source under `crates/`, no guarded file, no manifest or lock, no `vendor/` or `licenses/` change,
  and no other `ci/` change.

### Stated residuals

- **R-TEXT** (the monitor, verbatim): "accepted as the stated residual, in R5-1's class, recorded in MODEL_DEFINED.
  Every PR review of a pinned file must read the whole re-pinned file, not just the diff." The textual rules are
  tripwires; the pinned bytes and the PR review of the exact bytes are the guarantee. The pinned files from I01B1 on:
  effect-gate's `linux_os.rs` and `linux_net.rs`, the observer's `config.rs`, `i01_request.rs`, `i01_service.rs` and
  `client.rs` (`I01B_GUARDED_PINS`), `linux_listen.rs` and `linux_net.rs` (`OBSERVER_HOME_PINS`), and `i01_answer.rs`
  absent until HE-004-I01B3 pins it.
- **B3-12, beside R1-3's tripwire residual (R165).** Design review round 3 of DESIGN-I01B
  (`reviews/design-review-I01B-round3.json`, `f6508f2a…`), verbatim: "Not counted against the bar: these are not
  own-scope forms and lie outside G-I01B-6 (a)-(d). In effect-gate's unpinned socket files, two pre-existing R1-3
  tripwire limits pass check_socket_items. One is `pub trait Leak { fn leak(&self) -> &Conn; }`: trait items carry no
  `pub`, so PUB_ITEM never reads them. The other is `pub struct Holder<T = Conn> { pub inner: T }`: a generic default is
  not field text. The rule's docstring keeps 'a wrapper type' as code review's." Its required change: "For the monitor's
  awareness: carry them to the next gate change, or record them beside R1-3's tripwire residual. No change to I01b is
  required." Both forms stay outside `check_socket_items`; from I01B1 on each needs a change to a pinned effect-gate
  file (R174), so the whole-file pins close them, and `I01bGuardedPinTests` plants both.

### Carried

- **HE-004-I01A's PR review round 1, R1-4** (`reviews/pr-review-I01A-round1.json`, `b27fc75f…`; the monitor: "R1-4 and
  R2-N2..N4 stay carried", Q-U7-2 (a)), verbatim: "Textual limits, each closed elsewhere or harmless: G-I01-4 passes a
  split (concat!) or escaped (\x2e) socket path outside linux_listen.rs (no file but the socket files may reach
  gate_sys::channel); G-I01-6 counts only open calls, so a struct-literal I01Socket construction inside linux_listen.rs
  passes (pinned whole); G-I01-5's name rules pass a lib.rs type alias for ConnId/Client used by an i01_ file and a
  response module not named i01_*; G-I01-2 does not pin serve_peer_deadlines' call sites (it neither waits nor sends);
  G-I01-1's list omits unlinkat/renameat words (no std or gate-sys API by those names; seccomp v5 refuses the calls);
  G-I01-3 passes `if false && ..` and `if cfg!(debug_assertions) && ..` around the call. The first is caught by the
  rig's 87 tests; the debug_assertions form would pass debug-built tests and drop the pin from release binaries, a
  general class no gate rule refuses in observer sources." From I01B1 on, "a response module not named i01_*" refuses
  (G-I01B-7 (b): lib.rs's modules are exactly `OBSERVER_LIB_MODULES`), and `linux_listen.rs` stays pinned whole; the
  rest stands as stated, `serve_peer_deadlines`' call sites going to HE-004-I01B3 (G-I01B-5 (h)).
- **HE-004-I01A's PR review round 2, R2-N2..R2-N4** (`reviews/pr-review-I01A-round2.json`, `57a51248…`), verbatim:
  - R2-N2: "'every run so far (the build host's cargo test, the sim and the verifier) is on macOS' lists the verifier
    among runs so far, but this head is unpushed and the verifier has not run it. The packet's form ('which every macOS
    run, the verifier's included, skips') is exact. It understates nothing and overstates no coverage."
  - R2-N3: "R1-2's required change also asked for the accept part to be recorded as a departure in the build record. The
    in-tree record (MODEL_DEFINED) now does; BUILD-I01A.md (sha256 62cc4b70.., last written before round 1) still says
    U2 'No departure' and that the Linux-only listen_plain test runs in the sim."
  - R2-N4: "No sim has run on 574a1e2: the simmed packet is 94daf57's (sha256 e1f8212a.., the sim's packet= line), the
    new one is 63fa7b17... The delta is text only: MODEL_DEFINED.md is read by no gate rule, cargo target or
    zero_bill_scan (.md is outside its suffix set); the packet's one changed line passes zero_bill_scan's patterns
    statically and the other 15 fields are byte-identical. So the recorded results carry. Also, the Evidence names no
    commit: cargo test and both builds ran on 83272dd, gate.py's pass and the sim on 94daf57. Between those heads only
    the packet file and the two-line gate.py rename changed."
- **R2-N2..R2-N4's standing:** none asks for a change; each is recorded here as carried, and this section's evidence
  names its heads.
- **HE-004-I01A2's PR review round 1, R1-4** (`reviews/pr-review-I01A2-round1.json`, `e9859871…`; the monitor: "R1-4 →
  I01b's MODEL_DEFINED"), a different item from HE-004-I01A's R1-4, so both are carried; verbatim: "The packet YAML
  names both I01b carries: the gate rule pinning I01Binding construction to #[cfg(test)] or the production path, marked
  required (the monitor's ruling (3)), and the chain-versus-binding refusal order. In MODEL_DEFINED's HE-004-I01A2
  section, the I01Binding pin appears only under 'What stays code review's' ('no gate rule pins it'), and the refusal
  order appears only as a settled point. The in-tree record of carried items therefore does not show the ruling that the
  rule is required for I01b. Today nothing in crates/observer/src builds an I01Binding (git grep), and i01_service.rs
  passes None." Its required change: "None for the push, since the YAML and the PR body (the monitor's ruling) name it.
  I01b's packet and its MODEL_DEFINED section should record the rule as the required item." Recorded: the I01Binding pin
  is a **required** I01b item, bound as gate rules G-I01B-3 and G-I01B-4 (Q-I01B-19, binding) in HE-004-I01B2, and
  `i01_request.rs` is pinned whole from I01B1 on (R174); the chain-versus-binding order becomes unobservable in
  HE-004-I01B3, where the chain advances only after a successful send and every refusal closes (Q-I01B-20 (a)).
- **The other B3 rules** bind HE-004-I01B2 (B3-2, B3-3, B3-8, B3-9 (a), B3-11 (a) and (c)) and HE-004-I01B3 (B3-4, B3-5,
  B3-6, B3-7, B3-9 (b) and (c), B3-10, B3-11 (b) and (d)), each with round 3's `requiredChange` text as its binding
  wording (DESIGN-I01B1 section 2).
- **PR review round 1, R1-6** (`reviews/pr-review-I01B1-round1.json`, `cd8c8e9b…`), carried to HE-004-I01B3: its design
  section requires the replay to drive these 12 answer lists and the complete positive through `i01_answer` itself, not
  through the test's composition (R171).
- **Not here:** SR-1, the capture.rs entry and the SERVER-slot statement belong to HE-004-I01B3; the cfg(test)
  correction belongs to HE-004-I01B2.
- **I01B2, I01B3, HE-008, T04:** unchanged from DESIGN-I01B sections 3, 4, 5 and 8.

### Owner and monitor decisions (verbatim as relayed, 2026-10-22 and 2026-10-23)

> **2. HE-004-I01b design r3 (f6508f2a), my decision as monitor under owner delegation 2026-10-22: closed under Q-I01B-CAP, with the structural closure.**
> - **R-B3-A:** accepted. B3-1 to B3-12 are binding build rules, as proposed.
> - **B3-3:** accepted, the stricter form: `serve` occurs exactly twice in main.rs.
> - **R-B3-PIN:** accepted and binding. Each I01B packet pins by sha256, whole, every guarded file: effect-gate's linux_os.rs and linux_net.rs, and the observer's config.rs, i01_request.rs, i01_service.rs, client.rs and i01_answer.rs, beside linux_listen.rs and linux_net.rs. The textual rules become tripwires, and the pinned bytes plus PR review of the exact bytes are the guarantee.
> - **R-TEXT:** accepted as the stated residual, in R5-1's class, recorded in MODEL_DEFINED. Every PR review of a pinned file must read the whole re-pinned file, not just the diff.
> - **No r4.** I01B1's design-section review checks every B3 fix and the pins.

> [lane monitor] HE-004-I01A2 PR review r1 PASS_FOR_PUSH (e9859871) is noted. The carries are accepted, monitor under owner delegation 2026-10-22:
> - R1-4 → I01b's MODEL_DEFINED.

> - **HE-004-I01B1 build: GO**, at -j 2 with memory caps. It is cargo-heavy, so it waits for any HOLD_CARGO and runs one heavy job at a time.

> Monitor on HE-004-I01B1 part 1 (WIP a210af75, tree 6fec4209), under the owner's delegation:
> - **A, MON-I01B1-A (a):** B1's earlier `Inputs::new` refusal of RB-17's lists is accepted as R10-defined behaviour. Record it in part 2's MODEL_DEFINED, and the replay asserts it for those 2 checks.
> - **B, MON-I01B1-B (a):** the replay scope is split. Part 1 asserts the 110 checks as deferred, part 2 compares them, and the render comes in as a function.

The complete messages are recorded in the operator's `tools/w03/he004/OWNER_DECISIONS.md`.

## HE-004-I01B4: the I01 digest contract v2 re-vendor (`contracts/i01-digests-v2/`, `contracts/admission-v4/`, `contracts/i01-v2/proxy-profile-v2-vectors.json`; `i01_admission_render` on admission v4, `i01_digest` on v2; three replays; `tools/gate.py`; `ci/zero_bill_scan.py`)

The packet is LPK-1's step S3 with W3 (DESIGN-I01B4 revision 2, sha256 `3324993c…`, its section review's I4D-1 to I4D-14
binding; the lane monitor's Q-I01B4-1..12, MON-I01B4-FAMILY, Q-I01B4D-1 (a) and Q-I01B4D-2 (a), the owner's Q-I01B4-ZB
and the HE-004-I01B4 build GO, recorded in the operator's `tools/w03/he004/OWNER_DECISIONS.md`). It vendors edge record
v11's seven rows 73-79 (the I01 digest contract v2's definitions, vectors and README, admission v4's README, vectors and
sealed `planeon-a2.json`, and profile v2's vectors; 63 contracts) and re-pins VPO; it moves the A2 render to admission v4
and the digest port's schema version to v2, both in place; it moves the digest and render replays to v2 and v4, which
retires v1's, and derives W3's wire cases in the PV replay; and it adds G-I01B4-1. The three I01 modules stay unreachable
from `serve` and absent from both binaries (G-I01B-1), so no reachable code changes. The v2 model
`scripts/policy_observation_digests_v2.py` (`e1ba63d9…`, at harness-onion `f9882c1a`) and admission v4's model
`scripts/admission_semantics_v4.py` (`4da5a71d…`, at `675daccb`) are pinned by digest in PROVENANCE beside VPO
(`bbd1048a…`), read as specification only, never imported or run. Its rules are R176-R183.

### Points taken from the pinned model (P1-P7 against the v2 model)

P1-P7 (the HE-004-I01B1 section) hold against the v2 model at `e1ba63d9…` [I4D-12]: the functions they cite
(`projection`, `enforcement`, `document_bound` with VPC's `_bounded`, `refusal_texts`, `UNREACHABLE`, `_frozen_i06`,
`_capture`, `required_slots`, `capture_gate`, `observed`, `check_observation_digests`) are each defined in it under the
same name (checked as text), and the v2 model is v1's edited in eight places outside them (the contract v2's README
section 0; DOSSIER-I01B4 F2.1-F2.2). None moved, so none is re-cited. The model's three new `_check_complete` checks are
R179's.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R176 | Scope. `contracts/i01-digests-v2/{definitions.json, vectors.json, README.md}`, `contracts/admission-v4/{README.md, vectors.json, admission-manifests/planeon-a2.json}` and `contracts/i01-v2/proxy-profile-v2-vectors.json` are edge record v11's rows 73-79 (sha256 `9188980f…`, read by exact path at `f9882c1a`; its first 72 rows equal edge record v10's), byte for byte, mode 100644, each row compared key by key before any byte was copied (I4D-5); all seven were copied with `git show f9882c1a:<providerPath>`, and rows 76-79's bytes equal `675daccb`'s, their `providerCommit`. Contracts: 63; none is embedded (`OBSERVER_EMBEDDED_CONTRACTS` stays at five). VPO is re-pinned at `f9882c1a` (`bbd1048a…`, replacing `3ac03636…`, whose PROVENANCE line stays as written): only the packet list changed (against `675daccb`, as against `2043cc27`, only line 147 and the summary print at line 187 differ, and `:86-88` and `:128` read the same), and VPO stays pinned by digest (Q-I01B4-8). The held files and their readers [I4D-14]: v1's three digest files (rows 69-71), no crate test (v1's replays are retired, Q-I01B4-2), held by G-I01B-2 and the gate self-tests, and `vectors.json` also by the zero-bill test (Q-I01B4D-2 (a)); the proxy-contract vectors (row 72), no crate test, held by G-I01B-2 and the gate self-tests; admission v3's `vectors.json` (edge row 41), ADM-4's tests, the contract-bytes test and the zero-bill test; its `README.md` (row 42), the contract-bytes test; its `planeon-a2.json` (row 43), ADM-4's tests, the contract-bytes test, the zero-bill test and the render replay's v3 → v4 diff (R180). Profile v1 stays the wire's profile until W1-W4 land (profile v2's README; Q-LPK1-R2-1). R-B3-PIN in I01B4 [I4D-12]: no guarded file changes; the pins are R174's, each of the six `I01B_GUARDED_PINS` files and the two `OBSERVER_HOME_PINS` socket files `cmp`-equal to `a5d07979`, and `i01_answer.rs` has no directory entry | DESIGN-I01B4 §1, §6; Q-I01B4-2, Q-I01B4-8; I4D-5, I4D-6, I4D-12, I4D-14 |
| R177 | The render on admission v4 (§2.1; Q-I01B4-11: in place, no second module). `validations`' Pod arm changes in exactly two places: A2-POD-PULL-POLICY's two `'Always'` read `'Never'`, and a last row is appended to the Pod arm, every emptyDir bounded, `!has(object.spec.volumes) \|\| object.spec.volumes.all(v, !has(v.emptyDir) \|\| (has(v.emptyDir.sizeLimit) && !has(v.emptyDir.medium)))` (A2-POD-EMPTYDIR), each `{expression, message, reason: "Forbidden"}` as admission v4's model writes them (`:463-466`): 18 CEL rows, the Pod policy 10. The doc comments that named admission v3, its model or `2043cc27` as the rendering's source name admission v4, its model at `675daccb` and the v2 README. `render`, `manifest_file_bytes`, `a2_objects`, `SealedAdmission`, `sealed_admission` and the constants are unchanged, as are G-I01B-1's form and G-I01B-7's set. The file is re-pinned in the zero-bill allowlist (R183), so R-TEXT applies: the PR review reads it whole | DESIGN-I01B4 §2.1; Q-I01B4-11 |
| R178 | The v2 port (§3). `SCHEMA_VERSION` is `planeon.internal.policy-observation-digests/v2`; `CLOSURE_VERSION` stays `planeon.internal.policy-observation-rbac-closure/v1`, as v2's model keeps it. `i01_digest.rs`'s doc comments name the v2 README (harness-onion `f9882c1a`, edge record v11's row 75), the v2 model by digest, and admission v4's render and sealed values; "the I01 v1 answer" stays, since the wire is still I01 v1. No projection, digest, gate rule, refusal text or vector id changes: the module's diff is the constant and comment lines. `i01_gate.rs` changes in comments only, exactly I4D-11's three: the README path at :3 (`contracts/i01-digests-v2/README.md`, whose section 3.3 is still the capture gate) and "at `2043cc27`" → "at `f9882c1a`" at :30 and :34, each citation on one line and once in the file; G-I01B-8's citation strings and `I01B_LITERAL_PINS` are unchanged | DESIGN-I01B4 §3; I4D-11 |
| R179 | The digest replay on v2 (`observer_i01_digest_replay`, 4 tests; §4.1). Its inputs are rows 73-75 and 79 (`ROWS`, each sha256 and size), and its header and pin test say edge record v11's rows 73-75 and 79 [I4D-8]. The vectors' `schemaVersion` is `planeon.internal.policy-observation-digests-vectors/v2`, their `contract.path` is `architecture/policy-observation-digests-v2/definitions.json` and `contract.canonicalSha256` is `5f170f30…`, the definitions' canonical digest; the port's `SCHEMA_VERSION` is the definitions' `schemaVersion`; 90 refusal texts. The 16 helper vectors and 152 vectors replay with the v4 render handed in. The complete positive is on `qual` with 6 checks, v1's five and the sealed-namespace equality (the snapshot's `qualificationNamespace` is `planeon-qual`, the v2 model's `SEALED_NAMESPACE`, `:63`); its `binding.profileDigest` is `sha256:c212b038…` and its `request.bindingDigest` and `observation.bindingDigest` are `sha256:6e745318…`. The tally (Q-I01B4-5): (projections, enforcements, relations) = (119, 45, 51), (gates, answers, complete) = (69, 12, 6), B1's earlier refusals 2 (R172, unchanged in v2), (compared, refused earlier) = (319, 2), and 321 = 16 + 1 + 298 + 6. Outside the 321, R10-defined: profile v2's positive (row 79) equals the complete positive's profile in every member but exactly ten, the seven `policy.*Digest` and the three `capacityEntries.preexistingResourceRefs[0..2].observedDigest`, each present on both sides and differing, the members the positive's `replaced` list names for the profile; that gives row 79 its one reader (row 72 had only a pin table). Not run in R10 (the contract v2's README section 11, MON-I01S-C2-1-WORDING): the profile-schema load (`_profile_schema`), profile v2's `validate` and `precondition`, and the frozen-model file pins (`_frozen`'s FROZEN_MODELS loop, `scripts/proxy_profile_v2.py` included); so of the model's 323 checks R10's replay counts 321, and of `_check_complete`'s eight it runs six. Also not mirrored, as under v1: the model's uncounted FROZEN_INPUTS digest loop and I06 identity check (R10 embeds those bytes, G-D2-2) and its DESIGN_TEXTS coverage check; the v2 layer test's W1 assertions (VPO, profile v2 validate and precondition, P10) are harness-side (HO README section 10) | DESIGN-I01B4 §4.1; Q-I01B4-2, Q-I01B4-5; I4D-1, I4D-8 |
| R180 | The render replay on v4 (`observer_i01_render_replay`, 5 tests; §4.2). Every assertion of I01B1's v3 replay is kept with v4's values [I4D-9]: the pins (rows 77, 78 and 74, and the held v3 sealed file, `1096b3cc…`, 8,126 bytes); the render fits `i01_digest`'s render argument; the render of admission v4's sealed values {`planeon-qual`, IPv4, `10.96.0.0/12`, 300} is the vendored `planeon-a2.json` byte for byte, its hash is the pinned `manifestDirectoryHash`, H01's and H02's (`sha256:9b1ddc10…`), and its 8 objects are the file's items, 4 policies and 4 bindings; another sealed value renders other bytes and another hash; each of v4's 11 `objects` vectors (S01, S02, S03, S03b, S03c, S04, S05, S06, S06b, S06c, S06d) differs from the render; the contract v2's 2 fence digests (P-UNIT, AF-01) and 3 `sealedObjects` documents (P-UNIT, AP-09, AP-11) hold the render; the `unit` fixture's `pinnedManifestHash` and `adm4LoadedHash` are the render at `unit-namespace` (`sha256:8004085f…`), and, new, the `qual` fixture's are the render at `planeon-qual` (`9b1ddc10…`). The head layer's analogue: v4's `sealed.namespace` and `pinned.namespace` are both `planeon-qual`, the literal R179's sixth check uses. Test 5, the edit's extent: the v4 render differs from the held v3 file only in the Pod policy's validations (every other item, and every other member of the Pod policy, equal; its first 9 rows v3's, except that A2-POD-PULL-POLICY's two `'Always'` read `'Never'`; its tenth A2-POD-EMPTYDIR). Test 5 documents §2.1's extent against pinned data; it is not an independent check of the render [I4D-9] | DESIGN-I01B4 §4.2; I4D-9 |
| R181 | W3 (`observer_i01_pv_replay`, 8 tests; §4.3; Q-I01B4-4): R10-defined, with no harness-onion vector set and no edge record v12. The source is S1's complete triple (`complete` in row 74's file, pinned by its sha256 and size; HO vectors.json:23910-24559), whose `now`, `previous` (null), scope window, nonces and challenge are PV's. The derivation rule: for each of PV's negatives 6-27 (`document` observation or binding), the derived case is the triple with exactly that negative's one change, its `value` at its `path` in its `document`; nothing is recomputed, as PV's own negatives are the positive with one change and as `request_negatives` builds the request cases; the label stays PV's, and the rule label, checker and packet stay `PV_CASES`' row. The 22 derived cases are the table below. Structure checks only in I01B4 (one test): the derived cases are exactly `PV_CASES`' 22 labels, in order; each path exists in the triple's document; each value differs from the triple's value there; each derived document equals the triple's but at that one path. That each derived case still breaks the same VPO rule, and only it, is not shown: that would be harness-onion's VPO proof (Q-I01B4-4's (a), not chosen). No derived case runs against a checker in I01B4, because none exists yet. Carried [I4D-3]: W3's derived cases (R181): negative-27 is replayed against the load-time check (status 13) in HE-004-I01B2, and the 18 rows whose packet is HE-004-I01B3 against their checkers in HE-004-I01B3, each as the derived case on S1's v2 triple (row 74), with the derivation rule unchanged; each packet's design section states it and whether PV's v1 cases are also replayed. The request side (Q-I01B4D-1 (a), with I4D-4's rationale): the triple's request equals PV's positive request except at `bindingDigest` (`6e745318…` against PV's `e10d89fd…`); it passes framing, the schema, a fresh chain and `binding_gate` with the test binding built from the triple's binding (its canonical digest `6e745318…`, and the scope's `runNonce`), and PV's own test binding refuses it at the gate; PV's five request negatives, applied to the triple by the same rule, each have a value other than the triple's, and each refuses at its own step: the operation at the schema, `runNonce` and `bindingDigest` at `binding_gate`, the sequence and the previous digest at the chain. R10's canonical digest of the v2 binding is already asserted by R179's check 5; this adds framing, the schema, the chain and `binding_gate` on the triple's request | DESIGN-I01B4 §4.3, §8; Q-I01B4-4, Q-I01B4D-1 (a); I4D-3, I4D-4, I4D-13 |
| R182 | Gate rules (`tools/gate.py`). G-I01B-2's I01B4 set: `I01B_EDGE_V11_ROWS` (rows 73-79, in `I01B_EDGE_V10_ROWS`' tuple form); `check_i01b_contracts` holds both tables' files, each refusal naming its record (v10 or v11) and row, the embedding refusal covering both, and returns 11; its say line names both records; `CONTRACTS` holds 63. `I01B_DEFINITIONS` is `contracts/i01-digests-v2/definitions.json`: the section's own choice, which the rulings do not name, so that G-I01B-8 reads the file the port now reads; it changes no outcome, since v2's `refusalTexts`, `captureGate` and eleven keys equal v1's (checked), so G-I01B-8's counts stay 90 and 90,000 [I4D-10]. G-I01B4-1, the absence clause (Q-I01B4-5; I4D-1, I4D-2), `check_i01b4_replay_scope`, run right after `check_i01b_contracts` and printing its count: (a) no CONTRACTS path and no file or directory under `contracts/` has the basename `profile.schema.json` (casefolded), and no CONTRACTS digest and no file under `contracts/` is profile v2's schema by its sha256 (`e5ef3c3d…`, the v2 model's `PROFILE_SCHEMA`, `:150-151`); every `.rs` file under `crates/*/src` and `crates/*/tests` is read without comments, literals kept, and one the reader cannot lex refuses; (b) its `include_bytes!`/`include_str!` literals resolve as `check_i01b_contracts` resolves them (`posixpath.normpath` against the source's directory): exactly one, in `crates/observer/tests/observer_i01_digest_replay.rs`, resolves to row 79's file, and none in another source; row 79's file name occurs in the digest replay only in that literal, and in no other source (a `concat!` form or a runtime read included); (c) no `fn` or `mod` is named `validate_profile` or `precondition`, or has `profile_v2` in its name; (c1) no `fn`, `mod`, `struct`, `enum`, `trait`, `type`, `const`, `static` or `macro_rules` identifier, a leading `r#` stripped, casefolded with underscores removed, is `validateprofile`, `precondition` or `preconditions`, or contains `proxyprofilev2`; in (c) and (c1) a `const` followed by `fn`, `unsafe`, `extern` or `async` is a qualifier, so `[pub] const [unsafe|extern ".."] fn NAME` is read as the `fn` NAME (PR review round 1, R1-1, with a self-test for `const fn validate_profile`, `pub const fn precondition`, `pub const unsafe fn validate_profile` and `const fn preconditions`); (c2) no part of a source's path below its crate (each directory, and the file's stem), read the same way with hyphens also removed, contains `profilev2` unless it also contains `nativeprofile`; (c3) no source but the digest replay holds one of row 79's 28 distinct negative `expect` texts (read from the vendored file) or the schema's sha256. The real tree passes all of (a), (b), (c) and (c1)-(c3), and section 4.1's new test names hold no `profile_v2`. Self-tests: `I01bContractFileTests` over the eleven files (its seven `== 4` read 11; the row-number and provider-path assertions gain v11's; its docstring); the six 56 → 63 assertions with their comments; `I01B_V11_CONTRACTS`; `D2ContractCountTests` over the seven, with the v2 model as the unregistered file beside the contract v2's own; the three new prefix dicts; and `I01b4ReplayScopeTests`, 6 tests (the tree and the real files pass; the schema by name, by a CONTRACTS digest and by bytes; row 79's one reader, the include removed, doubled or beside a runtime read, and a `concat!` form; clause (c) in a src and a tests file and I4D-1's forms (1)-(5); a const fn read as its fn (the four forms in a src and a tests file) and a const still read as a const (PR review round 1, R1-1); clause (c3)). gate.py's module docstring gains an HE-004-I01B4 paragraph [I4D-10] | DESIGN-I01B4 §5; Q-I01B4-5; I4D-1, I4D-2, I4D-10 |
| R183 | The zero-bill allowlist (owner decision Q-I01B4-ZB, "Exact entries (Recommended)"), in Q-I01B1-ZB's form. `ci/zero_bill_scan.py`'s `CONTRACT_ALLOWLIST` gains, by exact path and sha256, `host-enforcement/contracts/i01-digests-v2/vectors.json` (`68eab470…`), `host-enforcement/contracts/admission-v4/vectors.json` (`5706b1a8…`) and `host-enforcement/contracts/admission-v4/admission-manifests/planeon-a2.json` (`92c21612…`), and the render's entry is re-pinned to its edited bytes (`fe856578…`, was `2e23e488…`). v1's and admission v3's entries stay while those files are held: seven entries. Each is exempt from the scan's two service-type patterns only (each of the three new files names both; v2's definitions and row 79's file name neither, and READMEs are not scanned): every other pattern still applies, and a changed byte, or the same bytes at another path, fails as before. The comment above the allowlist cites Q-I01B4-ZB beside Q-HE4B1-ZB and Q-I01B1-ZB and keeps the rule that any later edit of the render re-pins its entry in the same packet. Its test, `tests/verify/test_zero_bill_scan.py` (Q-I01B4D-2 (a)): `CONTRACTS` lists all seven files (admission v3's two first, so `CONTRACTS[1]` stays the file the exemption test rewrites; then v1's vectors, the render at its re-pinned bytes and the three new files), each passing at its pinned bytes and refusing a changed byte with both patterns; the `admission-v4/vectors.json` path with v3's bytes stays as a cross-entry case, beside the new `admission-v5/vectors.json` path no entry names [I4D-14]. It is the packet's one `ci/` change, and its transport and merge take the owner's approvals | Q-I01B4-ZB; Q-I01B4D-2 (a); I4D-14 |

### W3's derived cases (R181)

Each derived case is S1's triple with PV's one change. Digests are shortened to their first eight hex digits; `"x"×64`
is a text of 64 letters x.

| # | Label | Document: path | PV's value | The triple's value | PV_CASES' rule label (not a VPO result) | Checker | Packet |
|---|---|---|---|---|---|---|---|
| 6 | negative-6-observation-challenge | observation: challenge | `"c"×64` | `"a"×64` | response substitution | R10: i01_answer's self-check | HE-004-I01B3 |
| 7 | negative-7-observation-runNonce | observation: runNonce | `"other-run"` | `"unit-nonce"` | response substitution | R10: i01_answer's self-check | HE-004-I01B3 |
| 8 | negative-8-observation-bindingDigest | observation: bindingDigest | `"sha256:"` + `"0"×64` | `"sha256:6e745318…"` | response substitution | R10: i01_answer's self-check | HE-004-I01B3 |
| 9 | negative-9-observation-sequence | observation: sequence | `2` | `1` | response substitution | R10: i01_answer's self-check | HE-004-I01B3 |
| 10 | negative-10-observation-previousObservationDigest | observation: previousObservationDigest | `"sha256:"` + `"1"×64` | `"sha256:"` + `"0"×64` | response substitution | R10: i01_answer's self-check | HE-004-I01B3 |
| 11 | negative-11-observation-observedAt | observation: observedAt | `"2026-09-08T00:00:03Z"` | `"2026-09-08T00:00:01Z"` | stale or future | R10: self-check window | HE-004-I01B3 |
| 12 | negative-12-observation-expiresAt | observation: expiresAt | `"2026-09-08T00:00:02Z"` | `"2026-09-08T00:00:05Z"` | stale or future | R10: self-check window | HE-004-I01B3 |
| 13 | negative-13-observation-expiresAt | observation: expiresAt | `"2026-09-08T00:00:07Z"` | `"2026-09-08T00:00:05Z"` | freshness window | R10: self-check window | HE-004-I01B3 |
| 14 | negative-14-observation-namespace.uid | observation: namespace.uid | `"other-uid"` | `"unit-namespace-uid"` | observed namespace | R10: snapshot comparison and self-check | HE-004-I01B3 |
| 15 | negative-15-observation-projections.resourceQuota.projectionDigest | observation: projections.resourceQuota.projectionDigest | `"sha256:"` + `"0"×64` | `"sha256:7be2919c…"` | observed identity or digest | R10: snapshot comparison and self-check | HE-004-I01B3 |
| 16 | negative-16-observation-projections.rbac.uid | observation: projections.rbac.uid | `"other"` | `"0510ce35…"` | observed identity or digest | R10: snapshot comparison and self-check | HE-004-I01B3 |
| 17 | negative-17-observation-quota.used.configMaps | observation: quota.used.configMaps | `3` | `0` | used <= hard | R10: self-check | HE-004-I01B3 |
| 18 | negative-18-observation-quota.hard.configMaps | observation: quota.hard.configMaps | `0` | `1` | requested <= hard - used | HE-008, profile-side | `-` |
| 19 | negative-19-observation-quota.used.cpuMillis | observation: quota.used.cpuMillis | `true` | `0` | shape | R10: self-check shape | HE-004-I01B3 |
| 20 | negative-20-observation-quota.hard.cpuMillis | observation: quota.hard.cpuMillis | `9007199254740992` | `500` | shape | R10: self-check shape | HE-004-I01B3 |
| 21 | negative-21-observation-enforcement.policyGeneration | observation: enforcement.policyGeneration | `"c"×64` | `"b"×64` | enforcement proof mismatch | R10: self-check | HE-004-I01B3 |
| 22 | negative-22-observation-enforcement.hostPreflightDigest | observation: enforcement.hostPreflightDigest | `"sha256:"` + `"0"×64` | `"sha256:7d39e768…"` | enforcement proof mismatch | R10: self-check, and the snapshot comparison | HE-004-I01B3 |
| 23 | negative-23-binding-scope.tenantId | binding: scope.tenantId | `"other-tenant"` | `"unit-tenant"` | profile scope | HE-008, profile-side | `-` |
| 24 | negative-24-binding-profileDigest | binding: profileDigest | `"sha256:"` + `"0"×64` | `"sha256:c212b038…"` | profile digest | HE-008, profile-side | `-` |
| 25 | negative-25-binding-namespace.uid | binding: namespace.uid | `"other"` | `"unit-namespace-uid"` | namespace binding | R10: the snapshot comparison; HE-008 holds the profile-side half | HE-004-I01B3 |
| 26 | negative-26-binding-projections.serviceAccount.uid | binding: projections.serviceAccount.uid | `"other"` | `"unit-service-account-uid"` | policy identity | R10: the snapshot comparison; HE-008 holds the profile-side half | HE-004-I01B3 |
| 27 | negative-27-binding-scope.namespace | binding: scope.namespace | `"other"` | `"planeon-qual"` | namespace binding | R10: load-time check (status 13) | HE-004-I01B2 |

Cases 18, 23 and 24 have packet column `-` (checker: HE-008, profile-side) and are never replayed in R10 [I4D-13]. The
rule column is `PV_CASES`' label, not a VPO result. For negative-27, VPO's first failing check is the scope rule at
VPO:92 (`binding["scope"] == scope`, "independent profile scope"), in PV and in the derived case alike. As for PV's own
cases 23-27, a derived binding case changes the binding's digest, so a request naming the triple's digest fails the
gate; that is not counted as the case's checker.

### Points settled at build (inside DESIGN-I01B4's intent)

- **G-I01B4-1's readings (R182), each stricter than I4D-1's and I4D-2's text, never looser:** the schema's basename is
  casefolded; a path part drops hyphens as well as underscores, and each directory below the crate counts beside the
  file's stem (a `tests/<name>/main.rs` test root); the digest replay holds row 79's file name only in its one include
  literal, so its pin table names that file `i01-v2/, row 79`; test sources are lexed by `rust_code` as src sources are.
- **I4D-1's five forms (R182):** the self-tests plant, for form (1), `tests/profile_v2_check.rs` holding
  `fn validate(profile: &Value) -> Vec<String>` (clause (c2)), and the same under `tests/proxy-profile-v2/main.rs` and
  `src/ProfileV2.rs`; for form (2), `fn preconditions` (c1); for form (3), `fn r#precondition` (clause (c), the `r#`
  stripped); for form (4), `struct ProxyProfileV2` with `impl ProxyProfileV2 { fn validate(..) }` (c1); for form (5),
  `macro_rules! validate_profile` (c1); and `enum PRE_CONDITIONS` (c1). Not refused, as I4D-1 words the clause
  (equality for the precondition names, `proxyprofilev2` for the substring), and so stated as tripwire limits in
  R-TEXT's class: `fn check_precondition`, `fn validate_proxy_profile`, a bare `struct ProfileV2`, and a
  `let validate_profile = |..| ..;` closure, which is no item; and, among others, as (c1)-(c3), I4D-2 and the source
  glob read them, `type ProfileV2`, trait and impl names of that form, `fn check_preconditions_v2`, a negative text or
  the file name split across `concat!` pieces, and sources outside `crates/*/src` and `crates/*/tests` such as
  `build.rs` or `benches/` (PR review round 1, R1-3: the list is partial; round 2, R2-3). The review chose equality so
  that today's `LOOP_MODEL_PRECONDITION` and `events_outside_the_preconditions_change_nothing` pass; the fixture
  holds both.
- **The schema-bytes self-test (R182):** R10 holds no copy of profile v2's schema (it is not registered), so the test
  patches `PROFILE_V2_SCHEMA_SHA256` to a planted file's digest and refuses that file.
- **The render replay's pins (R180):** `PINS` holds the held v3 sealed file beside rows 77, 78 and 74, for test 5.
- **The PV replay's request steps (R181):** one function, `refuses_at_its_own_step`, holds a request negative to its own
  step, with the same assertions PV's test made inline; PV's and the triple's request negatives both call it, and
  `request_negatives_on` applies PV's request negatives to either request.
- **W3's structure test (R181)** also asserts that the triple's `now`, `previous`, scope window (`validFrom`,
  `expiresAt`), nonces (`runNonce`, `capacityNonce`) and the request's and observation's `challenge` are PV's
  (DOSSIER-I01B4 F5.6).
- **`check_i01b_contracts`' count (R182)** is the number of distinct files in its two tables, 11.

### Evidence

At build, `python3 -I -B` text checks: the base check (edge record v11's sha256 `9188980f…` and size, rows 73-79 key
by key against DESIGN-I01B4 section 1.1, each size against README-v11's table and the bytes, the first 72 rows equal
to v10's), before any byte was copied; the seven files' sha256, sizes and modes after, and rows 76-79's bytes equal at
`675daccb`; the two models' and VPO's digests and VPO's line diff; v1's and v2's definitions (`refusalTexts`,
`captureGate` and the eleven keys equal); the v3 and v4 sealed files (R180's extent); the v2 vectors (the complete
positive's digests and `replaced` list, row 79's ten differing members and 28 negative texts); W3's 22 paths and values
and the request side; each allowlisted file against both service-type patterns; and the word check (no email address,
absolute local path or legacy term in any added line outside the vendored contract files).

The heavy evidence, through `capped.zsh` at `-j 2`, one step at a time, on U5's tree (U4's head `dba40dbb` with U5's
edits), before the round-1 fix: `cargo test` 741 passed, 0 failed, in 112 binaries (the base: 737 in 112; the digest
replay 3 → 4 tests, the render replay 4 → 5, the PV replay 6 → 8), with only the vendored ring warnings; both musl
release builds (planeon-observer `d3b07259…` on x86_64 and `e61b7f02…` on aarch64, planeon-gate `f534bd63…` and
`2d62ef0a…`); `he-gate: passed`, with 63 contracts, G-I01B4-1 over 202 crate sources, and no symbol of the three I01
modules among planeon-observer's 2740 (x86_64) and 2822 (aarch64) symbols, the counts I01B1 recorded; the gate's
self-test, 368 tests (the base's 363 and `I01b4ReplayScopeTests`' 5), OK; the zero-bill scan passed; `tests/verify`, 13
tests, OK. The first gate run refused the word `include` in a digest-replay comment (`check_included_code`, which reads
comments too); the comment now names `include_bytes!`, and the sequence was re-run from `cargo test`. The span check
reads commits, so it runs on the head that holds U5; its first run, on U4's head, found three 8-word spans in the render
replay (A2-POD-EMPTYDIR's rule id written next to its CEL text, as admission v4's model writes the row), and the two are
now separate constants. On the round-1 fix's files (`f2aec1cf`): the gate's self-test, 369 tests (the base's 363 and
`I01b4ReplayScopeTests`' 6), OK; `he-gate: passed`, with 63 contracts and G-I01B4-1 over 202 crate sources; the
zero-bill scan passed; `tests/verify`, 13 tests, OK; the span check found no shared span; the sim: rc 0, 741 passed in
112 binaries, 187 s. The sim, the verify and their timings are the author's.

### Code and audit

- `contracts/i01-digests-v2/`, `contracts/admission-v4/` and `contracts/i01-v2/proxy-profile-v2-vectors.json` (seven
  files, new) with PROVENANCE's section; `crates/observer/src/i01_admission_render.rs` (R177),
  `i01_digest.rs` (`SCHEMA_VERSION` and comments, R178) and `i01_gate.rs` (three comment edits, R178);
  `crates/observer/tests/observer_i01_digest_replay.rs`, `observer_i01_render_replay.rs` and
  `observer_i01_pv_replay.rs` (R179-R181); `tools/gate.py` and `tools/test_gate.py` (R182); `ci/zero_bill_scan.py` and
  `tests/verify/test_zero_bill_scan.py` (R183); this section; the packet YAML (the author's). No guarded file, no
  `lib.rs`, `main.rs`, `observe.rs` or `capture.rs`, no `observer_admission.rs`, `observer_contracts.rs` or `c_support/`,
  no held v1 or admission v3 file, no manifest or lock, no `vendor/` or `licenses/` change, and no other `ci/` change.

### Stated residuals

- **R-TEXT** applies to the one re-pinned file I01B4 has, the render (R177, R183): the PR review reads
  `i01_admission_render.rs` whole, not only its diff. The guarded files keep R174's pins (R176).
- **G-I01B4-1's textual limits (R182):** the names and forms the clause does not read (above) stay code review's; the
  guarantee that R10 runs no profile v2 validator is the replay scope itself, R179's tally and the PR review.

### Carried

- **ADM-4's loaded hash.** It stays admission v3's (`5aa2cdec…`) in `observer_admission.rs` and `c_support`. Once
  HE-004-I01B3 makes the render live, `admissionPolicy` refuses "rendered hash differs" against a directory still loaded
  at v3 until M1 or M3 (DOSSIER-I01B4 F3.9). HE-004-I01B3's section and HE-008 carry the activation.
- **The three HE-008 cases** (18, 23 and 24) and HE-008's profile-side checks.
- **W3's derived cases [I4D-3]:** W3's derived cases (R181): negative-27 is replayed against the load-time check (status
  13) in HE-004-I01B2, and the 18 rows whose packet is HE-004-I01B3 against their checkers in HE-004-I01B3, each as the
  derived case on S1's v2 triple (row 74), with the derivation rule unchanged; each packet's design section states it
  and whether PV's v1 cases are also replayed.
- **R1-6 now reads v2 [I4D-12]:** HE-004-I01B3 drives the 12 answer lists and the complete positive (on `qual`, six
  checks) through `i01_answer`.
- **The contract v2's README section 12, carried items [I4D-12]**, quoted from
  HO:architecture/policy-observation-digests-v2/README.md:657-661:
  - "D3-1 and C1-7 (the capture gate's inputs) and Q-CB-11 (a) (no record digest in the capture verdicts) go to the
    HE-004-I01B family (R10), whose v2-file consumer is HE-004-I01B4, unchanged in substance, since the capture gate is
    v1's." They go to HE-004-I01B3, with the capture gate's inputs, unchanged in substance.
  - "Section 6's configuration successor goes to HE-004-I01B and HE-008, with HE-008 computing the three sealed
    admission values with this (v2) model at enrollment." It goes to HE-004-I01B2 and HE-008 (MON-I01B4-FAMILY).
- **W4:** its own step (Q-I01B4-10).
- **C1 and C2** gate ACTIVE, not the sealed bytes (DOSSIER-I01B4 F7.4).
- **MON-I01B4-FAMILY:** HE-004-I01B2 and HE-004-I01B3 keep the live parts, against v2's files; where DESIGN-I01B's text
  names v1 or admission v3 for them (DIB:182, DIB:716), their own sections read v2 and v4.
- **The vendored status lines:** the three vendored READMEs' status lines lag their `status.json` (DOSSIER-I01B4 F2.15,
  F9.6); they are vendored as they are, since the edge binds bytes.

### Owner and monitor decisions (verbatim as relayed, 2026-10-25)

> - **Q-1:** I01B4 next, before I01B3.
> - **Q-2:** keep v1's files held and pinned, and retire the v1 digest and render replays. Admission v3 stays for ADM-4.
> - **Q-3:** one packet.
> - **Q-4:** R10 derives W3's cases in test code from S1's triple, records them R10-defined in MODEL_DEFINED, and replays each in the packet that builds its checker. No harness-onion vector set or edge v12 for now.
> - **Q-5:** the tally assertion (compared, refused earlier) = (319, 2), plus the absence clause for profile.schema.json and any profile v2 validator.
> - **Q-6:** measure at the heavy checkpoint against I01B1's 737/112 and 201 s.
> - **Q-7, OWNER:** "Exact entries (Recommended)". ci/zero_bill_scan.py gains exact-bytes entries for contracts/i01-digests-v2/vectors.json, contracts/admission-v4/vectors.json and contracts/admission-v4/admission-manifests/planeon-a2.json, plus the render's re-pin, in Q-I01B1-ZB's form. Each is exempt from the two service-type patterns only, and the v1 and v3 entries stay while those files are held. Ref Q-I01B4-ZB. Record it verbatim.
> - **Q-8:** (a) re-pin VPO at f9882c1a (bbd1048a…), stating that only the packet list changed. The standing rule is unchanged: keep pinning VPO by digest. Stopping is a policy change I won't make in passing.
> - **Q-9:** the family reading. Record it as monitor note MON-I01B4-FAMILY.
> - **Q-10:** W4 is out of I01B4. MON-I01S-D3's note now reads "S3 with W3".
> - **Q-11:** edit the Pod rows in place, with no second module.
> - **Q-12:** a DESIGN-I01B4 section in DESIGN-I01B1's form, with its own design review through me.
> - **Every brief from now on** carries MON-I01B-DOSSIER-LIST's "no `git grep -l -e ''` listing" rule.
> - **I01B4 is gate material in R10,** because ci/zero_bill_scan.py is touched, so the owner's per-PR merge applies.

**MON-I01B4-FAMILY (monitor note, Q-9):** README section 11's live-port duties (`HO:architecture/policy-observation-digests-v2/README.md`)
are the I01B family's as a whole, as v1's README was read: I01B4 takes the v2 files, the v4 render and the replays;
I01B2 (configuration v3 and the binding) and I01B3 (the answer and the send) keep the live parts.

> - Q-I01B4D-1: (a). Also replay, now, the v2 triple's request and PV's 5 request negatives against I01A's existing checks.
> - Q-I01B4D-2: (a). The zero-bill test covers all 7 allowlist entries, including I01B1's two.

> - Q-I01B4D-1 stands as (a) with I4D-4's corrected rationale. The digest replay's complete check 5 already asserts R10's canonical digest of the v2 binding. What (a) adds is framing, the schema, the chain and binding_gate on a request that differs from PV's positive only in bindingDigest. It carries both extra assertions: (1) the triple's request equals PV's positive request except bindingDigest; (2) each of the 5 derived values differs from the triple's.
> - Q-I01B4D-2 (a) is unchanged.

> Note for later: i01_gate.rs is gate material even for comment-only edits, so the merge stays the owner's head-bound approval.

The complete messages, and the section review's I4D-1 to I4D-14 (`reviews/design-review-I01B4-round1.json`,
`e2d0c558…`), are recorded in the operator's `tools/w03/he004/` files.

## HE-004-I01B2: configuration v3 and the binding (`config.rs`, `i01_request.rs`, `i01_service.rs`, `observe.rs`, `main.rs`; five test binaries and `c_support`; `tools/gate.py`)

The packet is DESIGN-I01B rev 3's section 1 item 2 and section 3 (`97bdefa6…`, closed under Q-I01B-CAP), built as
DESIGN-I01B2 revision 3 states it (sha256 `020727f2…`): its section 2 carries round 3's B3-2, B3-3, B3-8, B3-9 (a) and
B3-11 (a) and (c) verbatim, and its sections 13 and 14 carry the two section reviews' I2D-1 to I2D-14
(`reviews/design-review-I01B2-round1.json`, `a9377d99…`) and I2E-1 to I2E-7 (`-round2.json`, `d7232e80…`) as binding
build rules, with the monitor's Q-I01B2D-1..4, its rulings on both rounds and the build GO (the operator's
`tools/w03/he004/OWNER_DECISIONS.md`, 2026-10-25). It is the first I01B packet that changes planeon-observer's reachable
code, in five places: `serve` (the v3 parse and the one `from_config` statement), `config.rs` (configuration v3, its
load-time checks and the private binding with its accessor), `i01_request.rs` (the closed binding), `i01_service.rs`
(the service holding it, `NotAnswered`) and `observe::run` (its seventh argument). planeon-gate's sources are untouched,
as are the I01 logic modules of I01B1 (G-I01B-1 keeps its I01B1 form). Every request still closes, and nothing is sent.
Its rules are R184-R196.

### R10-defined behaviour

| # | Behaviour | Why |
|---|---|---|
| R184 | Configuration v3 (`planeon.observer-config/v3`, `config::FORMAT_V3`), the observer configuration successor: v2's nine members and `sealedAdmission` and `binding`, eleven, closed; signed under the unchanged domain `planeon.observer-config/v1`. v2's members keep v2's checks (`fn members`, the record's reference as `parse_with_record` checks it), with `generation` narrowed to 64 lowercase hex (`is_generation_v3`, inside R19's store-name form). `binding` is the release-listed binding document inline; since the whole configuration must be its own canonical encoding, the member is byte for byte its canonical form. `ObserverConfig::parse_v3(document: &[u8]) -> Result<(ObserverConfig, FileRef), ConfigError>` (B3-11 (c)) is the only parse `serve` calls; v1 and v2 documents refuse there (Schema, status 13: their member sets and formats differ), and a v3 document refuses in `parse` and `parse_with_record`, which stay unchanged for their tests and leave the binding `Value::Null` and `sealed` `None`. HE-008 signs v3 with the binding's expected values and the three sealed admission values, which it computes with the v2 model at enrollment; R10 parses and checks them, and compares the values from HE-004-I01B3 on | DESIGN-I01B2 §3; DIB §3.1; B3-11 (c) |
| R185 | The load-time checks, each status 13 with its own `ConfigError::Check` text (a pub constant, so a test attributes each refusal), in `parse_v3` after v2's checks and in this order, the namespaces first [I2D-8]: (1) `binding.scope.namespace` and `binding.namespace.name` both equal `qualificationNamespace` (a missing or non-text one refuses here too); (2) the binding against CS's `$defs.binding` (`contracts/i01-v1/channel.schema.json`): `config::BINDING_FORM`, a typed table written from CS's text (every object closed with each member required, the one constant `planeon.internal.policy-observation-binding/v1`, each text's code-point bounds and pattern, each projection's `namespace` a label text or null), the patterns written by hand (`TextPattern::matches`, `$` only at the end as in ECMA-262), the refusal naming the member; (3) `binding.scope.serviceAccountSubject` is `system:serviceaccount:<qualificationNamespace>:<name>`, the name of CS's class `[a-z0-9.-]+`; (4) the sealed values' forms [I2D-10], `sealedAdmission` closed: `ipFamily` exactly `IPv4` or `IPv6` (the two `ipFamilies` values the Service API has and A2-SVC-ALLOCATION compares, admission v4's model at `f9882c1a`, `:444-447`); `serviceCIDR` a network of that family in canonical text, `/` and a decimal prefix without a leading zero, every host bit zero (the v4 model's strict `ip_network`, `:346`): IPv4 as gate-sys's `parse_ipv4` reads four decimal octets without leading zeros, prefix 0..32; IPv6 in RFC 5952's lowercase compressed form, prefix 0..128, the text equal to the address's own rendering (no dotted tail); `defaultTolerationSeconds` an integer in 0..2^53-1 (the canonical subset already holds every integer there). R10-defined: the v2 model (`:282-283`, types only) and admission v4 state no form. The check names no `i01_digest` item (G-I01B-1) | DESIGN-I01B2 §4; Q-I01B2D-1 (a); I2D-8, I2D-10 |
| R186 | The binding's provenance in config.rs [B2-11 (f), B3-2, I2D-1..3, I2D-13, I2E-3, I2E-7]: a private field `binding: Value` and `pub fn binding(&self) -> &Value`, whose body is exactly `&self.binding`; the one `ObserverConfig {` literal, in `fn members`, sets `binding: Value::Null` and `sealed: None`; in `parse_v3` the local `binding` is bound once, `let binding = match root.get("binding") { .. }`, from the checked member after every load-time check, and assigned once, `config.binding = binding;`, as statements of its outermost block; config.rs names no other field or method `binding`, the checks read the member, never `config.binding()`, and config.rs names no `Self`. `ObserverConfig` derives exactly `Clone, Debug` (I2D-2; i05-protocol's `Value` derives only those), and nothing compares whole configurations (the build compiled every test so). `pub sealed: Option<SealedValues>` (Q-I01B2D-2 (a)), `SealedValues { ip_family, service_cidr, default_toleration_seconds }` deriving `Clone, Debug, PartialEq, Eq` and never `Default`, set after the checks. `c_support::config_for` builds its configuration with `ObserverConfig::parse` over a v1 test document carrying the same values and lifetime | DESIGN-I01B2 §3; Q-I01B2D-2 (a) |
| R187 | The closed binding (G-I01B-3): `#[derive(Debug, PartialEq, Eq)] pub struct I01Binding { signed_digest: String, signed_nonce: String }`, renamed from `binding_digest`/`run_nonce` (neither new word occurred in the observer before); one `impl I01Binding {` with `pub fn from_config(binding: &Value) -> Option<I01Binding>` (B3-11 (a)) and the getters `signed_digest()` and `signed_nonce()`. `from_config` gives `sha256:` and the hex SHA-256 of i05-protocol's canonical encoding of the member and its `scope.runNonce`, and `None` when the encoding fails or `scope.runNonce` is not text (status 13 in `serve`; it does not occur after R185, which requires that member). `binding_gate(request: &I01Request, binding: Option<&I01Binding>) -> Result<(), RequestRefusal>` and `check_request(bytes: &[u8], truncated: bool, chain: &mut Chain, binding: Option<&I01Binding>) -> Result<I01Request, RequestRefusal>` keep their signatures (B3-8; the `None` tests stay) and compare through the getters. `i01_request.rs` stays a logic module with its whitelist unchanged (`i05_protocol::sha256` was on it) | DESIGN-I01B2 §6; DIB §3.4; B3-8, B3-11 (a) |
| R188 | The service: `I01Service` holds a private `binding: I01Binding`, `pub fn new(server: ServerIdentity, binding: I01Binding) -> I01Service`; the gate arm calls `check_request(bytes, false, &mut session.chain, Some(&self.binding))`: a refusal closes as `Closed::Request(refusal)`, as before, and a request that passes closes as the new `Closed::NotAnswered`. Nothing is answered or sent (no send path exists until HE-004-I01B3; G-I01-5 stands). `observe::run` takes `binding: I01Binding` seventh and hands it to `I01Service::new(server, binding)`. Q-I01A-3 (a)'s comment is replaced | DESIGN-I01B2 §6; B3-9 (a) |
| R189 | `serve`'s wiring, fourteen calls in order: `signed_config::load(`, `ObserverConfig::parse_v3(`, `config::check_lifetime(`, `I01Binding::from_config(`, `credentials::observer_inputs(`, `client_config(`, `CaptureSchema::embedded(`, `enrolled::load_record(`, `Enrolled::new(`, `enrolled.server_identity(`, `LinuxWire::new(`, `LinuxCapture::new(`, `Closure::embedded(`, `observe::run(`. Call 1 is the statement `let document = match signed_config::load() { Ok(document) => document, Err(error) => return status::config_load(&error), };`, call 2 `let Ok((config, record_ref)) = ObserverConfig::parse_v3(&document) else { return status::CONFIG_CHECK };`, followed by `drop(document);`, and call 4 `let Some(binding) = I01Binding::from_config(config.binding()) else { return status::CONFIG_CHECK };`, each a statement of `serve`'s outermost block; `observe::run(wire, config, tls, closure, captures, server, binding)`; `serve` imports `planeon_observer::i01_request::I01Binding` | DESIGN-I01B2 §5; DIB §3.3; I2D-4 (1), I2E-1, I2E-2 |
| R190 | Gate rule G-I01B-3, `check_i01b_binding` (6 clauses, each its own function, over the observer's non-test sources as `observer_code` reads them): (i) one `struct I01Binding` in i01_request.rs, its fields exactly the two private texts, its attributes exactly one derive of {Debug, PartialEq, Eq}; (iii) every impl header naming I01Binding is i01_request.rs's one `impl I01Binding {`, holding exactly `from_config` and the two getters with bodies `&self.signed_digest` and `&self.signed_nonce`, and no const, type or static; (ii) `\bI01Binding(?:::\s*<\s*>)?\s*\{` once outside the definition and the impl header, inside `fn from_config`, no `Self {` or `Self(` in i01_request.rs, and in no other source; (iv) outside that impl, `.signed_digest` and `.signed_nonce` only as getter calls; (v) no `as` rename and no `type` item naming it; (vi) the word six times, at `struct`, `impl`, and the three exact signatures (from_config's position 3, binding_gate's and check_request's positions 5 and 6) and the one literal. Its say line prints the count | DIB §6 G-I01B-3; B3-8, B3-11 (a) |
| R191 | Gate rule G-I01B-4, `check_i01b_constructor` (13 clauses; each of (b1)-(b6) and (c1)-(c4) its own function, so that exactly one can be disabled): (a) the word `from_config` twice in the crate (`fn from_config(` inside `impl I01Binding {`; `serve`'s pinned statement, outermost); (b) in main.rs `\bserve\s*\(` twice (B2-10) and the word `serve` twice (B3-3), and `observe::run(`'s seven arguments (the fourteen calls, the refused v1 and v2 parses and the imports stay `check_observer_serve`'s and the seal-order grammar's); (b1) the pinned load statement once [I2E-1]; (b2) `document` 5 times: 3 in the outermost statement holding `signed_config::load(`, 1 in the outermost statement holding `parse_v3`, 1 in `drop(document);`, an outermost statement after it [I2E-2 (i)]; (b3) `config` not before `::` 5 times: once each in the outermost statement holding `parse_v3`, `config::check_lifetime(&config, `, the from_config statement's `config.binding()`, `credentials::observer_inputs(&config.credentials)` and `observe::run(`'s second argument [I2E-2 (ii)]; (b4) every match of the load and parse pins an outermost statement, load before parse [I2E-2 (iii)]; (b5) the pinned parse statement once [I2D-4 (1)]; (b6) `parse_v3` twice over every observer source with use declarations kept, its definition inside `impl ObserverConfig {` and once inside `serve` [I2E-2 (iv)]; (c) the private field, the accessor and its body, and `\bObserverConfig(?:::\s*<\s*>)?\s*\{` once outside the definition and impl headers, inside `fn members`, holding `binding: Value::Null` [B3-2]; (c1) no use declaration renames ObserverConfig with `as` and no `type` item at any nesting (associated types included) names it, crate-wide [I2D-1, I2E-5]; (c2) the dot form `\.\s*(?:r#)?binding\b` twice in config.rs, once in the accessor's body and once in `parse_v3`'s [I2D-13]; (c3) in `parse_v3`'s body the word `binding`, dot forms and `field:` names in struct expressions and patterns set aside, twice: the pattern of the one outermost `let binding = ..;` and the right side of the one outermost `config.binding = binding;` after it [I2D-3, I2E-3]; (c4) no word `Self` in config.rs [I2E-7]. Its say line prints the count | DIB §6 G-I01B-4; DESIGN-I01B2 §5, §7; B3-2, B3-3; I2D-1, I2D-3, I2D-4 (1), I2D-13; I2E-1..3, I2E-5, I2E-7 |
| R192 | The self-tests (388, the base's 369 and 19): `I01BindingRuleTests` (18) over a fixture of main.rs's `serve`, config.rs's accessor and `parse_v3`, i01_request.rs's closed binding and the two sources that carry it: the fixture and the real sources pass; DIB §7.1's P3-1..P3-7, SR-2, N2-1, N2-1b and round 3's X3-1..X3-4 refuse under G-I01B-3; §7.2's P4-1..P4-6, N2-2, N2-2b, the two positives and the two wiring cases, and round 3's X4-1, X4-2, X4-3, X4-3b, X4-4, X4-5, X4-6 under G-I01B-4; the 35 NEW-n and H-n rows (`I01B2_ROWS`), one test per sub-clause, each refused with its own sub-clause's message (I2E-4); and the records' own spellings where a row departs from them. `ObserverServeV1ParseTests` gains the v2 parse's refusal (1). I2D-9's sites: `SERVE_STEPS` (fourteen, the wire step `SERVE_STEPS[10]`), the five `check_observer_serve(..) == 14`, the name list, `GOOD_OBSERVER_MAIN`'s parse line, from_config statement, `observe::run(` line and import, the v1 refusal, and `I01bGuardedPinTests`' digests. The mutation proof (the build's scratch `mutation_proof.py`, reading `I01B2_ROWS` and the fixture through `i01b2_tree`) shows each of the 35 refused by the full G-I01B-4 with its own sub-clause's message and passing with only that sub-clause's function a no-op | DESIGN-I01B2 §7; I2D-9, I2D-12; I2E-4 |
| R193 | R-B3-PIN in I01B2: `config.rs` (`173b7adf…`), `i01_request.rs` (`e87c1e44…`) and `i01_service.rs` (`56a07477…`) are re-pinned in `I01B_GUARDED_PINS` at I01B2's bytes; effect-gate's `linux_os.rs` and `linux_net.rs`, `client.rs`, and `OBSERVER_HOME_PINS`' `linux_listen.rs` and `linux_net.rs` keep their pins and bytes; `i01_answer.rs` stays absent. R-TEXT: the PR review reads the three re-pinned files whole, and `serve` and `observe::run` whole beside them | DESIGN-I01B2 §1; R-B3-PIN; R-TEXT |
| R194 | The cfg(test) correction (DIB §8.5, §3.4): test code inside `src/` lives only in strict `#[cfg(test)] mod tests` blocks, which `observer_code` blanks; any other `cfg(test)` item is read as non-test code, so a non-strict `#[cfg(test)] fn` calling `from_config` counts (P4-6), and a call in a strict block passes (the positive) | DESIGN-I01B2 §6, §9 |
| R195 | PV case 27 replayed (Q-I01B2D-3 (a), `observer_config_v3`): PV's own case and W3's derived case on S1's v2 triple (row 74, R181's derivation rule unchanged: the triple's binding with PV's one change, `scope.namespace` → `"other"`), each as a v3 document for its qualification namespace (`unit-namespace`, `planeon-qual`): the unmutated document parses; the mutated one refuses with the namespace check's own text; with the form and the sealed values also broken, it still refuses there, and the same document unmutated refuses at the form (the namespaces first); each document's `qualificationNamespace` equals its binding's `namespace.name`, and the subject's namespace segment matches. `PV_CASES`' row stays; the PV replay's carried sentence says I01B2 replayed case 27. I01B4's carried obligation for negative-27 is discharged | DESIGN-I01B2 §8; Q-I01B2D-3 (a); I2D-8; R181 |
| R196 | The sealed values fail closed (Q-I01B2D-2 (a), judged in round 1): a forged sealed value changes only the A2 render's hash, and HE-004-I01B3 accepts the render only if its hash equals both anchors, ADM-4's loaded hash (from the `Adm4Record`) and the binding's `enforcementPins.admissionFenceDigest` (now from the signed configuration through `config.binding()`); `pinnedManifestHash` is not an anchor, since it is a pub field. Nothing reads `config.sealed` in I01B2 | DESIGN-I01B2 §3; Q-I01B2D-2 (a); I2D-5 |

### Superseded and discharged [I2D-11]

- **R163 is superseded:** `I01Binding` is closed and no test builds it from fields; every binding comes from
  `I01Binding::from_config`, and `serve` builds the production one from the signed configuration's checked member; the
  service passes `Some(&self.binding)`, so a request naming the configuration's binding passes the gate and closes as
  `NotAnswered`.
- **HE-004-I01A2's PR review round 1, R1-4 is discharged:** the required I01Binding pin is G-I01B-3 and G-I01B-4 (R190,
  R191). The chain-versus-binding order stays as recorded (unobservable from HE-004-I01B3).
- **I01B4's other carried items stand** (ADM-4's loaded hash, the HE-008 cases, the 18 W3 rows, R1-6 on v2, W4, C1 and
  C2, the vendored status lines). Of README section 11's live-port duties, MON-I01B4-FAMILY reads: "I01B2 (configuration
  v3 and the binding) and I01B3 (the answer and the send) keep the live parts". I01B2 takes the configuration successor
  (R184) and the binding's pin (R187-R191); the rest are I01B3's.

### Points settled at build (inside DESIGN-I01B2's intent)

- **The 35 rows' spellings (R192):** each row plants its record's form so that only its own sub-clause refuses it, as
  the mutation proof requires; where the record's own spelling also breaks another place, the row keeps that place and
  `test_the_review_records_own_spellings_refuse` holds the record's spelling refused by G-I01B-4: H1 keeps `Ok(document)`
  and reads it once in the arm that returns the literal (the record's `Ok(_)` also drops a `document` word, (b2)); H2 and
  H2b write `let mut document = document;` after the pinned load statement (the record's `let mut document = match ..`
  also breaks the load pin, (b1)); H2c rewrites `Ok(mut document)` in a second match after the pinned load statement;
  NEW-3a parses a literal chosen by `document.is_empty()` (the record's `parse_v3(b"..")` also drops a `document` word);
  H10 wraps the pinned parse statement alone in a bare block (the record's `let (config, record_ref) = { .. }` also adds
  `config` words, (b3)); NEW-4a is the helper alone and NEW-4b the rebinding alone (I2E-4). Some rows do not compile as
  Rust; the rules are textual.
- **The positional counts (R191):** (b2) and (b3) locate the load and parse statements as the outermost statements
  holding `signed_config::load(` and `parse_v3`, so each count is independent of the pins (b1), (b5); with them, the five
  places are the pinned ones. (b4) is vacuous for a pin that does not match, which (b1) or (b5) refuses.
- **(c3)'s readings:** a `field:` name is a `binding` followed by one `:` and preceded by `{` or `,` (I2E-4); a `binding`
  after a dot, with or without `r#`, is (c2)'s. A closure parameter after another, `|x, binding: T|`, reads as a field
  name; it can only stand beside a nested assignment, which (c3)'s outermost-statement clause or (c2)'s count refuses.
- **(c1)'s reading:** renames are read in use declarations crate-wide (`ObserverConfig as` in the use tree), type items at
  any nesting; a qualified path `<T as Trait>` is not a rename.
- **The table's keywords:** CS's `$defs.binding` uses nine keyword names (`type`, `additionalProperties`, `required`,
  `properties`, `const`, `minLength`, `maxLength`, `pattern`, `oneOf`) and seven distinct patterns; `observer_config_v3`
  holds the table to them all. The design's "eight keywords" reads `required` and `properties` as one closed object.
- **G-I01B-3's order:** (i), (iii), (ii), (iv), (v), (vi), so an impl naming I01Binding in another file refuses at (iii)
  (P3-3's message) before (ii) reads its header as a literal.
- **N2-2b's second planting** (a second `config.binding = v;` outside `parse_v3`) refuses at (c2), the dot-form clause the
  restated (c) splits out; its other two refuse at (c).
- **I2D-3's test** asserts `from_config`'s digest and nonce from U2 on, when the closed binding exists; U1 asserted the
  member's identity alone.
- **`from_config` over a non-object, or without `scope.runNonce` text, gives `None`** (`observer_i01_request` holds five
  such values).

### Evidence

At build, `python3 -I -B` text checks: the brief's and the design's digests; CS's `$defs.binding` (nine keyword names,
seven patterns), PV's positive binding and negative 27, S1's triple's binding and admission v4's `sealed`, read before
the test held them; the inventory (`git diff --stat 330e9d83` names exactly the fourteen paths of this section's code
list); and the word check (no email address, absolute local path or legacy term in any of the packet's 2461 added
lines, 2477 with this paragraph).

The heavy evidence, through `capped.zsh` at `-j 2`, one step at a time, on U4's tree (U3's head `d651be4a` with this
section): `cargo test` 753 passed, 0 failed, in 113 binaries (the base: 741 in 112; `observer_config_v3`'s 12 are new,
and the `NotAnswered` case sits in an existing service test), 77 s (143 s at U2, with the compile), with only the
vendored ring warnings; both musl release builds; `he-gate: passed`, with 63 contracts, G-I01B-3's 6 and G-I01B-4's 13
clauses, the fourteen wiring calls, no symbol of the three I01 logic modules among planeon-observer's 2755 (x86_64) and
2837 (aarch64) symbols (G-I01B-1), and G-D1-16's exempt span once on each target; planeon-observer `6a800325…` (x86_64)
and `b2c37007…` (aarch64), planeon-gate `f534bd63…` and `2d62ef0a…`, the values I01B4 recorded; the gate's self-test,
388 tests (the base's 369 and 19), OK; the mutation proof, 35 of 35 rows refused by the full G-I01B-4 with their own
sub-clause's message and passing with only that sub-clause's function a no-op. The span check reads commits, so it runs
on this unit's head, beside the zero-bill scan and `tests/verify`; their results are in the build record. The sim, the
verify and their timings are the author's.

### Code and audit

- `crates/observer/src/config.rs` (R184-R186), `i01_request.rs` (R187), `i01_service.rs` and `observe.rs` (R188),
  `main.rs` (R189); `crates/observer/tests/observer_config_v3.rs` (new, 12 tests), `observer_i01_request.rs`,
  `observer_i01_pv_replay.rs`, `observer_i01_service.rs`, `observer_i01_wait.rs` and `c_support/mod.rs`;
  `tools/gate.py` and `tools/test_gate.py` (R190-R193); this section. No other test file, no `lib.rs`, `capture.rs`,
  `client.rs`, socket file or I01 logic module but `i01_request.rs`, no contract, no `ci/` path, no manifest or lock.
  planeon-gate's sources are untouched.

### Stated residuals

- **R-TEXT** for the three re-pinned files and for `serve` and `observe::run`: the PR review reads them whole. H4e (the
  one `let binding` bound from a value other than the member) is R-TEXT's and I2D-3's test's (I2E-6), and so is an
  input-triggered substitution inside `parse_v3`.
- **The textual rules' limits:** G-I01B-3 and G-I01B-4 read text, not Rust; what they do not read stays code review's in
  R5-1's class, beside the whole-file pins.

### Carried

- **To HE-004-I01B3:** I2D-5's four conditions on the sealed values, verbatim: "(i) the sealed values reach only
  i01_digest's rendered, through DigestSnapshot.configuration built in the pinned derive statement, and nothing else
  reads config.sealed or calls sealed_admission; (ii) adm4_loaded_hash comes from the Adm4Record, never from config;
  (iii) derive compares AdmissionFenceDigest with config.binding()'s enforcementPins.admissionFenceDigest; (iv) `sealed:
  None` maps to an absent sealedAdmission member (malformed, refused), never to a default." Also the 18 W3 rows, B3-4..B3-7,
  B3-9 (b) and (c), B3-10, B3-11 (b) and (d), SR-1, the SERVER-slot statement, the capture.rs entry, the sealed values'
  use (DIB:306) and R1-6 on v2.
- **To HE-008:** signing configuration v3, the binding's expected values and the three sealed values; cases 18, 23 and 24.

### Owner and monitor decisions (verbatim as relayed, 2026-10-25)

> Ruling, monitor under the owner's 2026-10-22 delegation; record it verbatim: **GO (a).** Write the DESIGN-I01B2 section yourself, in DESIGN-I01B1/I01B4's form, from:
> - DIB rev 3 §2-§3;
> - round 3's B3 texts, carried verbatim per I1D-9;
> - I01B4's Carried list.

> - **Q-I01B2D-1: (a).** A typed check in config.rs from CS's $defs.binding, held by a test to CS's text. No new embedded contract; G-D2-2 is unchanged.
> - **Q-I01B2D-2: (a).** `pub sealed: Option<SealedValues>`, None in `fn members`, set in parse_v3. The review must judge your fail-closed argument explicitly: a forged value changes only the render hash, which fails closed. If it finds a path where a forged sealed value is accepted, that's MAJOR, and the choice comes back to me.
> - **Q-I01B2D-3: (a).** Replay both PV's own case 27 and W3's derived case 27, each as a v3 document refused at 13.
> - **Q-I01B2D-4: (a).** Gate material: the owner's per-PR, head-bound merge. On transport approval: if the verifier asks for the owner's approval on the PR head, as it did for #25 and #26, I'll put it to the owner then, whether or not ci/ changes.

> - **I2D-1, I2D-2 and I2D-3 adopted as you recommend:**
>   - the alias/`type` clause, with self-tests X4-7 and X4-8;
>   - the derive is exactly `Clone, Debug`;
>   - `binding` is bound once, with its test.
> - **I2D-4: option (1).** Pin serve's parse statement whole (spacing free). The word parse_v3 occurs exactly twice in the non-test sources, and `document` and `config` are each bound once in serve's body, with self-tests for NEW-3 and NEW-4. It widens gate material by two clauses, which is in scope for this gate-material packet, and it closes an unsigned-binding route at the binary's root.
> - **Q-D1:** add the reviewer's point. The test holds the check's whole table to CS's text, each pattern tested at its boundaries.
> - **I2D-5..14:** fold them as build rules. I2D-14's drop is right; transport approval stays my call if the verifier asks.

> - **I2E-1 and I2E-3:** adopted as written.
> - **I2E-2:** the positional word-count form: (i) document 5, (ii) config-not-followed-by-:: 5 at the named places, (iii) both pinned statements outermost and in order, (iv) the parse_v3 count over observer_code with use declarations kept.
> - **I2E-4..7:** folded as build rules. I2E-5: associated types count as type items, and renames are read crate-wide. I2E-7: "no Self" is a gate check in config.rs.
> - **Self-tests:** every NEW-n and H-n form is a mandatory self-test, each refused with its own clause's message, in one row per sub-clause. Each one must also be proven to pass against the gate without its clause, as R1-1's test was, so every refusal is shown to come from its own clause. H4e stays with R-TEXT and I2D-3's test, as §13 says.

> GO for the HE-004-I01B2 build.

The complete messages are recorded in the operator's `tools/w03/he004/OWNER_DECISIONS.md`.
