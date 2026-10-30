//! I02, the server channel's codec and checks (HE-005B: DESIGN-HE005 revision 5 sections 1 (O12, O19, O20, O21), 3.1
//! and 3.3; the HE-005B plan's item 2; MON-HE005B-PLAN, Q-HE5B-2 (a) and Q-HE5B-3 (a)). A logic module: pure (no I/O,
//! no system call, safe Rust only), no panic, std's ordered collections and i05-protocol's public json, sha256, base64 and
//! schema items with its `FrameError`. Nothing in `main`, `serve`, `seal.rs`, `status.rs` or `linux_listen.rs` names
//! it, so planeon-broker's behaviour stays HE-005A's (G-HE5B-1).
//!
//! - [`decode_datagram`]: one received datagram under a size limit and a schema, in i05-protocol's `decode_frame` order
//!   (`frame.rs:64-85`, then its `check_structure`), built from i05-protocol's public primitives, unchanged: the size
//!   limit (F02), UTF-8 (F06), the strict parse (F03 for a refused constant, F05 for a duplicate key, F06 otherwise),
//!   the canonical re-encoding compared byte for byte (F06), depth at most 16 (F01), no float (F03), no control
//!   character (F04), then the schema (F00). With the limit 16,384 it answers as `decode_frame` does
//!   (`tests/i02_differential.rs`, condition 1 of MON-HE005B-PLAN).
//! - [`decode`]: I02's own limits (O21): a datagram of at most 65,536 bytes under the embedded channel schema, then a
//!   DISPATCH or a RESOURCE_ACTION of more than 16,384 canonical bytes refused F02 ([`check_control_size`]).
//! - [`check_dispatch`]: a DISPATCH, then its binding (Q-HE5B-2 (a)): the binding document, an input, against
//!   `$defs/binding`, its SHA-256 equal to the DISPATCH's `bindingDigest`, and its four broker and worker digests equal
//!   to the configured ones (section 3.1, [`ConfiguredDigests`]); any difference is REFUSED INVALID_AUTHORITY. Nothing
//!   in a DISPATCH selects a file, a uid or an executable: it only selects the bound case's resource set.
//! - [`Transcript`]: the frames after one DISPATCH, a pure state machine over both directions; the broker's five frames
//!   are built through it, so each passes the same checks before it is returned.
//! - [`answer`]: the refusal map, section 3.3's failure classes and I05's BIND_EXECUTION refusals to I02's REFUSED
//!   reasons.
//!
//! Where the bytes of the binding document and the server certificate digest come from is HE-005D's and HE-008's. The
//! R10-defined points are listed in `crates/effect-gate/MODEL_DEFINED.md` (the HE-005B section).

use std::collections::BTreeSet;

use i05_protocol::base64;
use i05_protocol::json::{self, JStr, Object, ParseError, Value};
use i05_protocol::schema::{Schema, SchemaError};
use i05_protocol::sha256::{self, Sha256};
use i05_protocol::FrameError;

/// I02's datagram bound (O21; the readiness guide: every datagram at most 64 KiB).
pub const MAX_DATAGRAM_BYTES: usize = 65_536;
/// The bound of a DISPATCH and a RESOURCE_ACTION, in canonical bytes (O21: at most 16 KiB).
pub const MAX_CONTROL_BYTES: usize = 16_384;
/// The depth bound of every I02 message (the readiness guide: depth 16), as i05-protocol's.
pub const MAX_DEPTH: usize = 16;
/// A receipt chunk's decoded bound (24 KiB), the number of chunks and the receipt's decoded total (4 MiB).
pub const MAX_CHUNK_BYTES: usize = 24_576;
pub const MAX_CHUNKS: i64 = 171;
pub const MAX_RECEIPT_BYTES: usize = 4_194_304;

/// The registered schema versions of a DISPATCH, a broker frame and a binding document.
pub const DISPATCH_VERSION: &str = "planeon.internal.broker-dispatch/v1";
pub const FRAME_VERSION: &str = "planeon.internal.broker-frame/v1";
pub const BINDING_VERSION: &str = "planeon.internal.broker-binding/v1";

/// The previous digest of a transcript's first frame.
pub const ZERO_DIGEST: &str = "sha256:0000000000000000000000000000000000000000000000000000000000000000";

/// The DISPATCH's eight binding fields, which every frame echoes.
pub const ECHO_FIELDS: [&str; 8] = ["bindingDigest", "reservationDigest", "runNonce", "caseId", "requestDigest",
    "observationDigest", "generation", "challenge"];

/// The binding's four members compared with the broker's signed configuration (section 3.1), in
/// [`ConfiguredDigests`]' order.
const CONFIGURED_FIELDS: [&str; 4] = ["brokerManifestDigest", "brokerExecutableDigest", "workerManifestDigest",
    "workerArtifactDigest"];

// ------------------------------------------------------------------------------------------------ schemas

/// The I02 and I03 schemas, all loaded from the one embedded `channel.schema.json`: the whole channel schema, and its
/// `binding` and `workerStart` definitions as schemas of their own (a root `$ref` to each beside the same `$defs`, the
/// subset i05-protocol's `Schema` reads).
#[derive(Clone, Debug)]
pub struct Schemas {
    channel: Schema,
    binding: Schema,
    worker_start: Schema,
}

impl Schemas {
    /// The schemas of the vendored `contracts/broker-handoff-v1/channel.schema.json` (edge record v12, row 80),
    /// embedded here once.
    pub fn embedded() -> Result<Schemas, SchemaError> {
        Schemas::from_json(include_bytes!("../../../contracts/broker-handoff-v1/channel.schema.json"))
    }

    fn from_json(raw: &[u8]) -> Result<Schemas, SchemaError> {
        let text = std::str::from_utf8(raw).map_err(|_| SchemaError(String::from("the I02 schema is not UTF-8")))?;
        let document = json::parse(text).map_err(|_| SchemaError(String::from("the I02 schema is not JSON")))?;
        Ok(Schemas {
            channel: Schema::from_value(&document)?,
            binding: Schema::from_value(&definition(&document, "binding"))?,
            worker_start: Schema::from_value(&definition(&document, "workerStart"))?,
        })
    }

    /// The whole channel schema: a binding, a DISPATCH, one of the eight frames or a START.
    pub fn channel(&self) -> &Schema {
        &self.channel
    }

    /// `$defs/binding`.
    pub fn binding(&self) -> &Schema {
        &self.binding
    }

    /// `$defs/workerStart`.
    pub fn worker_start(&self) -> &Schema {
        &self.worker_start
    }
}

/// A schema document whose root is a reference to one definition, beside the document's `$defs`.
fn definition(document: &Value, name: &str) -> Value {
    let mut reference = String::from("#/$defs/");
    reference.push_str(name);
    let mut root = Object::new();
    if let Some(definitions) = document.get("$defs") {
        root.insert(JStr::new("$defs"), definitions.clone());
    }
    root.insert(JStr::new("$ref"), Value::str(&reference));
    Value::Object(root)
}

// ------------------------------------------------------------------------------------------------ decoding

/// Decodes one received datagram under `limit` and `schema`, in `decode_frame`'s order, returning its `FrameError`
/// codes, so a comparison with it is code for code.
pub fn decode_datagram(raw: &[u8], limit: usize, schema: &Schema) -> Result<Value, FrameError> {
    if raw.len() > limit {
        return Err(FrameError::F02);
    }
    let text = std::str::from_utf8(raw).map_err(|_| FrameError::F06)?;
    let value = json::parse(text).map_err(|error| match error {
        ParseError::Constant => FrameError::F03,
        ParseError::Duplicate => FrameError::F05,
        ParseError::Syntax => FrameError::F06,
    })?;
    let encoded = json::canonical(&value).map_err(|_| FrameError::F06)?;
    if encoded != raw {
        return Err(FrameError::F06);
    }
    if json::depth(&value) > MAX_DEPTH {
        return Err(FrameError::F01);
    }
    if json::contains_float(&value) {
        return Err(FrameError::F03);
    }
    if json::contains_control(&value) {
        return Err(FrameError::F04);
    }
    if !schema.is_valid(&value) {
        return Err(FrameError::F00);
    }
    Ok(value)
}

/// Decodes one I02 datagram with I02's limits: at most 65,536 bytes under the embedded channel schema, then the 16 KiB
/// bound of a DISPATCH and a RESOURCE_ACTION.
pub fn decode(raw: &[u8], schemas: &Schemas) -> Result<Value, FrameError> {
    let value = decode_datagram(raw, MAX_DATAGRAM_BYTES, &schemas.channel)?;
    check_control_size(&value, raw.len())?;
    Ok(value)
}

/// The 16 KiB bound of a DISPATCH and a RESOURCE_ACTION (O21), over a decoded message and its canonical length:
/// either one of more than 16,384 bytes is refused F02.
pub fn check_control_size(value: &Value, canonical_length: usize) -> Result<(), FrameError> {
    let version = text(value, "schemaVersion");
    let control = version == Some(DISPATCH_VERSION)
        || (version == Some(FRAME_VERSION) && text(value, "kind") == Some(Kind::ResourceAction.wire()));
    if control && canonical_length > MAX_CONTROL_BYTES {
        return Err(FrameError::F02);
    }
    Ok(())
}

// ------------------------------------------------------------------------------------------------ DISPATCH

/// The DISPATCH's eight binding fields, in [`ECHO_FIELDS`]' order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Echo {
    values: Vec<String>,
}

impl Echo {
    fn of(value: &Value) -> Option<Echo> {
        let values = ECHO_FIELDS.iter().map(|name| text(value, name).map(String::from)).collect::<Option<Vec<_>>>()?;
        Some(Echo { values })
    }

    /// One field's value, by its wire name.
    pub fn get(&self, name: &str) -> Option<&str> {
        ECHO_FIELDS.iter().zip(self.values.iter()).find(|(field, _)| **field == name).map(|(_, value)| value.as_str())
    }

    fn echoed_by(&self, frame: &Value) -> bool {
        ECHO_FIELDS.iter().zip(self.values.iter()).all(|(name, value)| text(frame, name) == Some(value.as_str()))
    }
}

/// The four binding digests the broker accepts (section 3.1: `brokerManifestDigest`, `brokerExecutableDigest`,
/// `workerManifestDigest`, `workerArtifactDigest`), a plain value that the signed configuration fills (HE-005C).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConfiguredDigests {
    pub broker_manifest: String,
    pub broker_executable: String,
    pub worker_manifest: String,
    pub worker_artifact: String,
}

/// A checked DISPATCH: its echo and the bound case's resource set (the binding's `caseResourceDigests` entry for its
/// `caseId`), the only manifest digests a RESOURCE_ACTION may carry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dispatch {
    echo: Echo,
    case_resources: BTreeSet<String>,
}

impl Dispatch {
    pub fn echo(&self) -> &Echo {
        &self.echo
    }

    pub fn case_resources(&self) -> &BTreeSet<String> {
        &self.case_resources
    }
}

/// Why a datagram is no checked DISPATCH.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum DispatchError {
    /// [`decode`] refuses it; nothing can be echoed, so nothing is answered.
    Frame(FrameError),
    /// It decodes under the channel schema but is a binding, a frame or a START.
    NotDispatch,
    /// A DISPATCH whose binding check fails: it is answered REFUSED INVALID_AUTHORITY with this echo
    /// ([`Transcript::refusing`]).
    Authority(Echo),
}

/// Checks one DISPATCH datagram and its binding (Q-HE5B-2 (a)). `binding` is the binding document's bytes, which must
/// be canonical: they are decoded under `$defs/binding` with I02's limits, so their SHA-256 is the canonical one.
pub fn check_dispatch(raw: &[u8], binding: &[u8], configured: &ConfiguredDigests, schemas: &Schemas)
    -> Result<Dispatch, DispatchError> {
    let value = decode(raw, schemas).map_err(DispatchError::Frame)?;
    if text(&value, "schemaVersion") != Some(DISPATCH_VERSION) {
        return Err(DispatchError::NotDispatch);
    }
    let echo = Echo::of(&value).ok_or(DispatchError::NotDispatch)?;
    match bound_case(binding, &echo, configured, schemas) {
        Some(case_resources) => Ok(Dispatch { echo, case_resources }),
        None => Err(DispatchError::Authority(echo)),
    }
}

/// The binding check's three parts; the bound case's resource set when all hold.
fn bound_case(binding: &[u8], echo: &Echo, configured: &ConfiguredDigests, schemas: &Schemas)
    -> Option<BTreeSet<String>> {
    let document = decode_datagram(binding, MAX_DATAGRAM_BYTES, &schemas.binding).ok()?;
    let digest = sha256::prefixed(binding);
    if echo.get("bindingDigest") != Some(digest.as_str()) {
        return None;
    }
    let expected = [&configured.broker_manifest, &configured.broker_executable, &configured.worker_manifest,
        &configured.worker_artifact];
    for (name, value) in CONFIGURED_FIELDS.iter().zip(expected) {
        if text(&document, name) != Some(value.as_str()) {
            return None;
        }
    }
    let case = document.get("caseResourceDigests")?.get(echo.get("caseId")?)?.as_array()?;
    case.iter().map(|digest| digest.as_str().map(String::from)).collect()
}

// ------------------------------------------------------------------------------------------------ frames

/// Which peer sends a frame kind.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Peer {
    Broker,
    Server,
}

/// The eight frame kinds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Started,
    ResourceAction,
    ResourceResult,
    ReceiptChunk,
    CleanupRecorded,
    Terminal,
    Abort,
    Refused,
}

impl Kind {
    pub fn wire(self) -> &'static str {
        match self {
            Kind::Started => "STARTED",
            Kind::ResourceAction => "RESOURCE_ACTION",
            Kind::ResourceResult => "RESOURCE_RESULT",
            Kind::ReceiptChunk => "RECEIPT_CHUNK",
            Kind::CleanupRecorded => "CLEANUP_RECORDED",
            Kind::Terminal => "TERMINAL",
            Kind::Abort => "ABORT",
            Kind::Refused => "REFUSED",
        }
    }

    pub fn from_wire(name: &str) -> Option<Kind> {
        Some(match name {
            "STARTED" => Kind::Started,
            "RESOURCE_ACTION" => Kind::ResourceAction,
            "RESOURCE_RESULT" => Kind::ResourceResult,
            "RECEIPT_CHUNK" => Kind::ReceiptChunk,
            "CLEANUP_RECORDED" => Kind::CleanupRecorded,
            "TERMINAL" => Kind::Terminal,
            "ABORT" => Kind::Abort,
            "REFUSED" => Kind::Refused,
            _ => return None,
        })
    }

    /// The direction by kind: the broker sends STARTED, RESOURCE_ACTION, RECEIPT_CHUNK, TERMINAL and REFUSED; the
    /// server RESOURCE_RESULT, CLEANUP_RECORDED and ABORT.
    pub fn peer(self) -> Peer {
        match self {
            Kind::Started | Kind::ResourceAction | Kind::ReceiptChunk | Kind::Terminal | Kind::Refused => Peer::Broker,
            Kind::ResourceResult | Kind::CleanupRecorded | Kind::Abort => Peer::Server,
        }
    }
}

/// A RESOURCE_ACTION's verb.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verb {
    Create,
    Get,
    Delete,
}

impl Verb {
    pub fn wire(self) -> &'static str {
        match self {
            Verb::Create => "CREATE",
            Verb::Get => "GET",
            Verb::Delete => "DELETE",
        }
    }
}

/// A TERMINAL's status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TerminalStatus {
    Completed,
    Failed,
    Unavailable,
}

impl TerminalStatus {
    pub fn wire(self) -> &'static str {
        match self {
            TerminalStatus::Completed => "COMPLETED",
            TerminalStatus::Failed => "FAILED",
            TerminalStatus::Unavailable => "UNAVAILABLE",
        }
    }
}

/// A REFUSED frame's reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RefusedReason {
    Unavailable,
    Replay,
    GenerationMismatch,
    CapacityHeld,
    InvalidAuthority,
}

impl RefusedReason {
    pub fn wire(self) -> &'static str {
        match self {
            RefusedReason::Unavailable => "UNAVAILABLE",
            RefusedReason::Replay => "REPLAY",
            RefusedReason::GenerationMismatch => "GENERATION_MISMATCH",
            RefusedReason::CapacityHeld => "CAPACITY_HELD",
            RefusedReason::InvalidAuthority => "INVALID_AUTHORITY",
        }
    }
}

// ------------------------------------------------------------------------------------------------ the transcript

/// Why a frame ends the transcript. Every breach is the transcript's end, with no repair or retry (the readiness
/// guide: no skipped, duplicate or reordered frame; never repair, reuse or retry).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Breach {
    /// [`decode`] refuses the datagram.
    Frame(FrameError),
    /// It decodes but is not one of the eight frames (a binding, a DISPATCH or a START).
    NotFrame,
    /// The caller's execution id is not 64 lowercase hexadecimal digits (256 bits).
    ExecutionIdForm,
    /// The frame's kind is the other peer's.
    Direction,
    /// Its sequence is not the next one (from 1, plus 1 per frame in either direction).
    Sequence,
    /// Its previous digest is not the all-zero digest (first) or the previous frame's canonical SHA-256.
    Chain,
    /// It does not echo the DISPATCH's eight binding fields.
    Echo,
    /// Its execution id is not the transcript's.
    Execution,
    /// The first frame is neither STARTED nor REFUSED (only REFUSED for a refusing transcript).
    FirstFrame,
    /// A second STARTED.
    StartedRepeated,
    /// A REFUSED that is not the first frame.
    RefusedNotFirst,
    /// An action is outstanding when another action, a chunk, CLEANUP_RECORDED or TERMINAL arrives.
    ActionOutstanding,
    /// A RESOURCE_ACTION after CLEANUP_RECORDED.
    ActionAfterCleanup,
    /// A RESOURCE_ACTION after the server's ABORT.
    ActionAfterAbort,
    /// A RESOURCE_ACTION whose manifest digest is outside the bound case's set.
    ManifestOutsideCase,
    /// A RESOURCE_RESULT with no action outstanding.
    NoActionOutstanding,
    /// A RESOURCE_RESULT for another action id than the outstanding one.
    ActionMismatch,
    /// A RECEIPT_CHUNK after CLEANUP_RECORDED.
    ChunkAfterCleanup,
    /// A chunk index that is not the next one (contiguous from 0).
    ChunkIndex,
    /// A chunk's data that is not canonical base64.
    ChunkEncoding,
    /// A chunk of more than 24 KiB decoded.
    ChunkSize,
    /// A 172nd chunk.
    ChunkCount,
    /// More than 4 MiB decoded in all.
    ReceiptTooLarge,
    /// CLEANUP_RECORDED before any chunk (TERMINAL's receipt is at least one byte).
    ChunksIncomplete,
    /// A second CLEANUP_RECORDED.
    CleanupRepeated,
    /// TERMINAL before CLEANUP_RECORDED.
    TerminalBeforeCleanup,
    /// TERMINAL's receipt size is not the chunks' decoded total.
    ReceiptSize,
    /// TERMINAL's receipt digest is not the SHA-256 of the chunks' decoded bytes, in order.
    ReceiptDigest,
    /// TERMINAL's cleanup digest is not CLEANUP_RECORDED's.
    CleanupDigest,
    /// A second ABORT.
    SecondAbort,
    /// The transcript has ended: after TERMINAL, after REFUSED, or after a breach.
    Ended,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// No frame yet: STARTED or REFUSED next.
    First,
    /// No frame yet, for a refused DISPATCH: REFUSED next.
    RefuseOnly,
    /// After STARTED.
    Running,
    /// After CLEANUP_RECORDED.
    Cleaned,
    /// After TERMINAL, REFUSED or a breach.
    Over,
}

/// One accepted frame.
#[derive(Clone, Debug)]
pub struct Accepted {
    kind: Kind,
    sequence: i64,
    frame: Value,
}

impl Accepted {
    pub fn kind(&self) -> Kind {
        self.kind
    }

    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn frame(&self) -> &Value {
        &self.frame
    }
}

/// The frames after one DISPATCH (O12, O20, O21): one execution id chosen by the caller (256-bit); the sequence from
/// 1, plus 1 per frame in either direction, with the all-zero previous digest first and the previous frame's canonical
/// SHA-256 after; every frame echoing the DISPATCH's eight fields; the direction by kind; the first frame STARTED or
/// REFUSED; RESOURCE_RESULT answering the outstanding action, and no action outstanding when another action, a chunk,
/// CLEANUP_RECORDED or TERMINAL arrives; chunk indexes contiguous from 0, each chunk canonical base64 of at most 24
/// KiB, at most 171 chunks and 4 MiB in all; CLEANUP_RECORDED once, with no action outstanding and the chunks
/// complete; TERMINAL only after it, binding the receipt's size and SHA-256 and echoing its cleanup digest; nothing
/// after TERMINAL or REFUSED; at most one ABORT. Any breach is the transcript's end.
pub struct Transcript {
    echo: Echo,
    execution_id: String,
    case_resources: BTreeSet<String>,
    phase: Phase,
    next_sequence: i64,
    last_digest: String,
    outstanding: Option<i64>,
    aborted: bool,
    next_index: i64,
    receipt_size: usize,
    receipt: Sha256,
    cleanup_digest: Option<String>,
}

impl Transcript {
    /// The transcript of a checked DISPATCH; `execution_id` is the broker's choice (64 lowercase hexadecimal digits).
    pub fn new(dispatch: &Dispatch, execution_id: &str) -> Result<Transcript, Breach> {
        Transcript::begin(dispatch.echo.clone(), dispatch.case_resources.clone(), execution_id, Phase::First)
    }

    /// The transcript of a DISPATCH refused at its binding check: its one frame is REFUSED.
    pub fn refusing(echo: &Echo, execution_id: &str) -> Result<Transcript, Breach> {
        Transcript::begin(echo.clone(), BTreeSet::new(), execution_id, Phase::RefuseOnly)
    }

    fn begin(echo: Echo, case_resources: BTreeSet<String>, execution_id: &str, phase: Phase)
        -> Result<Transcript, Breach> {
        if !is_hex64(execution_id) {
            return Err(Breach::ExecutionIdForm);
        }
        Ok(Transcript {
            echo,
            execution_id: String::from(execution_id),
            case_resources,
            phase,
            next_sequence: 1,
            last_digest: String::from(ZERO_DIGEST),
            outstanding: None,
            aborted: false,
            next_index: 0,
            receipt_size: 0,
            receipt: Sha256::new(),
            cleanup_digest: None,
        })
    }

    /// Whether the transcript has ended (TERMINAL, REFUSED or a breach).
    pub fn is_over(&self) -> bool {
        self.phase == Phase::Over
    }

    /// Checks one frame datagram from `from` against the transcript and, if it holds, takes it as the next frame.
    pub fn accept(&mut self, raw: &[u8], from: Peer, schemas: &Schemas) -> Result<Accepted, Breach> {
        if self.phase == Phase::Over {
            return Err(Breach::Ended);
        }
        let result = self.check(raw, from, schemas);
        if result.is_err() {
            self.phase = Phase::Over;
        }
        result
    }

    fn check(&mut self, raw: &[u8], from: Peer, schemas: &Schemas) -> Result<Accepted, Breach> {
        let frame = decode(raw, schemas).map_err(Breach::Frame)?;
        if text(&frame, "schemaVersion") != Some(FRAME_VERSION) {
            return Err(Breach::NotFrame);
        }
        let kind = text(&frame, "kind").and_then(Kind::from_wire).ok_or(Breach::NotFrame)?;
        if kind.peer() != from {
            return Err(Breach::Direction);
        }
        if integer(&frame, "sequence") != Some(self.next_sequence) {
            return Err(Breach::Sequence);
        }
        if text(&frame, "previousDigest") != Some(self.last_digest.as_str()) {
            return Err(Breach::Chain);
        }
        if !self.echo.echoed_by(&frame) {
            return Err(Breach::Echo);
        }
        if text(&frame, "executionId") != Some(self.execution_id.as_str()) {
            return Err(Breach::Execution);
        }
        let payload = frame.get("payload").ok_or(Breach::NotFrame)?;
        self.order(kind, payload)?;
        let sequence = self.next_sequence;
        self.next_sequence = sequence.saturating_add(1);
        self.last_digest = sha256::prefixed(raw);
        Ok(Accepted { kind, sequence, frame })
    }

    fn order(&mut self, kind: Kind, payload: &Value) -> Result<(), Breach> {
        match (self.phase, kind) {
            (Phase::Over, _) => Err(Breach::Ended),
            (Phase::First, Kind::Started) => {
                self.phase = Phase::Running;
                Ok(())
            }
            (Phase::First | Phase::RefuseOnly, Kind::Refused) => {
                self.phase = Phase::Over;
                Ok(())
            }
            (Phase::First | Phase::RefuseOnly, _) => Err(Breach::FirstFrame),
            (Phase::Running | Phase::Cleaned, _) => self.running(kind, payload),
        }
    }

    fn running(&mut self, kind: Kind, payload: &Value) -> Result<(), Breach> {
        let cleaned = self.phase == Phase::Cleaned;
        match kind {
            Kind::Started => Err(Breach::StartedRepeated),
            Kind::Refused => Err(Breach::RefusedNotFirst),
            Kind::ResourceAction => {
                if cleaned {
                    return Err(Breach::ActionAfterCleanup);
                }
                if self.aborted {
                    return Err(Breach::ActionAfterAbort);
                }
                if self.outstanding.is_some() {
                    return Err(Breach::ActionOutstanding);
                }
                let manifest = text(payload, "manifestDigest").ok_or(Breach::NotFrame)?;
                if !self.case_resources.contains(manifest) {
                    return Err(Breach::ManifestOutsideCase);
                }
                self.outstanding = Some(integer(payload, "actionId").ok_or(Breach::NotFrame)?);
                Ok(())
            }
            Kind::ResourceResult => {
                let action = integer(payload, "actionId").ok_or(Breach::NotFrame)?;
                match self.outstanding {
                    None => Err(Breach::NoActionOutstanding),
                    Some(outstanding) if outstanding != action => Err(Breach::ActionMismatch),
                    Some(_) => {
                        self.outstanding = None;
                        Ok(())
                    }
                }
            }
            Kind::ReceiptChunk => {
                if cleaned {
                    return Err(Breach::ChunkAfterCleanup);
                }
                if self.outstanding.is_some() {
                    return Err(Breach::ActionOutstanding);
                }
                let index = integer(payload, "index").ok_or(Breach::NotFrame)?;
                if index != self.next_index {
                    return Err(Breach::ChunkIndex);
                }
                if index >= MAX_CHUNKS {
                    return Err(Breach::ChunkCount);
                }
                let encoded = text(payload, "dataBase64").ok_or(Breach::NotFrame)?;
                let data = canonical_base64(encoded).ok_or(Breach::ChunkEncoding)?;
                if data.len() > MAX_CHUNK_BYTES {
                    return Err(Breach::ChunkSize);
                }
                let size = self.receipt_size.checked_add(data.len()).filter(|size| *size <= MAX_RECEIPT_BYTES);
                let size = size.ok_or(Breach::ReceiptTooLarge)?;
                self.receipt.update(&data);
                self.receipt_size = size;
                self.next_index = index.saturating_add(1);
                Ok(())
            }
            Kind::CleanupRecorded => {
                if cleaned {
                    return Err(Breach::CleanupRepeated);
                }
                if self.outstanding.is_some() {
                    return Err(Breach::ActionOutstanding);
                }
                if self.next_index < 1 {
                    return Err(Breach::ChunksIncomplete);
                }
                let digest = text(payload, "cleanupDigest").ok_or(Breach::NotFrame)?;
                self.cleanup_digest = Some(String::from(digest));
                self.phase = Phase::Cleaned;
                Ok(())
            }
            Kind::Terminal => {
                if !cleaned {
                    return Err(Breach::TerminalBeforeCleanup);
                }
                if self.outstanding.is_some() {
                    return Err(Breach::ActionOutstanding);
                }
                let size = integer(payload, "receiptSize").ok_or(Breach::NotFrame)?;
                if usize::try_from(size).ok() != Some(self.receipt_size) {
                    return Err(Breach::ReceiptSize);
                }
                let digest = self.receipt_digest();
                if text(payload, "receiptDigest") != Some(digest.as_str()) {
                    return Err(Breach::ReceiptDigest);
                }
                if text(payload, "cleanupDigest") != self.cleanup_digest.as_deref() {
                    return Err(Breach::CleanupDigest);
                }
                if payload.get("workerReaped").and_then(Value::as_bool) != Some(true) {
                    return Err(Breach::NotFrame);
                }
                self.phase = Phase::Over;
                Ok(())
            }
            Kind::Abort => {
                if self.aborted {
                    return Err(Breach::SecondAbort);
                }
                self.aborted = true;
                Ok(())
            }
        }
    }

    /// The SHA-256 of the chunks' decoded bytes so far, in order, in the contract's digest form.
    fn receipt_digest(&self) -> String {
        let mut digest = String::from("sha256:");
        digest.push_str(&sha256::hex(&self.receipt.clone().finish()));
        digest
    }

    // -------------------------------------------------------------------------------------------- builders

    /// STARTED, the first frame: the worker's pid and start ticks.
    pub fn started(&mut self, schemas: &Schemas, worker_pid: i64, worker_start_ticks: i64) -> Result<Vec<u8>, Breach> {
        let payload = vec![("workerPid", Value::int(worker_pid)), ("workerStartTicks", Value::int(worker_start_ticks))];
        self.build(schemas, Kind::Started, payload)
    }

    /// RESOURCE_ACTION: one action id, a verb and one manifest digest of the bound case.
    pub fn resource_action(&mut self, schemas: &Schemas, action_id: i64, verb: Verb, manifest_digest: &str)
        -> Result<Vec<u8>, Breach> {
        let payload = vec![("actionId", Value::int(action_id)), ("verb", Value::str(verb.wire())),
            ("manifestDigest", Value::str(manifest_digest))];
        self.build(schemas, Kind::ResourceAction, payload)
    }

    /// RECEIPT_CHUNK: the next index and `data` in canonical base64.
    pub fn receipt_chunk(&mut self, schemas: &Schemas, data: &[u8]) -> Result<Vec<u8>, Breach> {
        let payload = vec![("index", Value::int(self.next_index)), ("dataBase64", Value::str(&base64::encode(data)))];
        self.build(schemas, Kind::ReceiptChunk, payload)
    }

    /// TERMINAL: `status`, the receipt's size and SHA-256 over the chunks so far, CLEANUP_RECORDED's digest and
    /// `workerReaped` true.
    pub fn terminal(&mut self, schemas: &Schemas, status: TerminalStatus) -> Result<Vec<u8>, Breach> {
        let Some(cleanup) = self.cleanup_digest.clone() else {
            return self.end(Breach::TerminalBeforeCleanup);
        };
        let Ok(size) = i64::try_from(self.receipt_size) else {
            return self.end(Breach::ReceiptSize);
        };
        let payload = vec![("status", Value::str(status.wire())), ("receiptSize", Value::int(size)),
            ("receiptDigest", Value::str(&self.receipt_digest())), ("cleanupDigest", Value::str(&cleanup)),
            ("workerReaped", Value::Bool(true))];
        self.build(schemas, Kind::Terminal, payload)
    }

    /// REFUSED, the first and only frame: `reason`.
    pub fn refused(&mut self, schemas: &Schemas, reason: RefusedReason) -> Result<Vec<u8>, Breach> {
        self.build(schemas, Kind::Refused, vec![("reason", Value::str(reason.wire()))])
    }

    fn end<T>(&mut self, breach: Breach) -> Result<T, Breach> {
        if self.phase == Phase::Over {
            return Err(Breach::Ended);
        }
        self.phase = Phase::Over;
        Err(breach)
    }

    /// The next frame of `kind` with `payload`, canonical, taken through [`Transcript::accept`] before it is returned.
    fn build(&mut self, schemas: &Schemas, kind: Kind, payload: Vec<(&str, Value)>) -> Result<Vec<u8>, Breach> {
        if self.phase == Phase::Over {
            return Err(Breach::Ended);
        }
        let mut body = Object::new();
        for (name, value) in payload {
            body.insert(JStr::new(name), value);
        }
        let mut frame = Object::new();
        frame.insert(JStr::new("schemaVersion"), Value::str(FRAME_VERSION));
        for (name, value) in ECHO_FIELDS.iter().zip(self.echo.values.iter()) {
            frame.insert(JStr::new(name), Value::str(value));
        }
        frame.insert(JStr::new("executionId"), Value::str(&self.execution_id));
        frame.insert(JStr::new("sequence"), Value::int(self.next_sequence));
        frame.insert(JStr::new("previousDigest"), Value::str(&self.last_digest));
        frame.insert(JStr::new("kind"), Value::str(kind.wire()));
        frame.insert(JStr::new("payload"), Value::Object(body));
        let Ok(raw) = json::canonical(&Value::Object(frame)) else {
            return self.end(Breach::Frame(FrameError::F06));
        };
        self.accept(&raw, Peer::Broker, schemas).map(|_| raw)
    }
}

// ------------------------------------------------------------------------------------------------ the refusal map

/// I05's BIND_EXECUTION refusal reasons (`contracts/i05-v3/channel.schema.json`; unchanged in v4).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindRefusal {
    NotActive,
    ActionOutstanding,
    ExecutionReplay,
    GenerationMismatch,
    UnknownBinding,
    CertificateMismatch,
    ManifestReused,
    WorkerNotObserved,
    StorageFailure,
}

impl BindRefusal {
    pub fn from_wire(name: &str) -> Option<BindRefusal> {
        Some(match name {
            "NOT_ACTIVE" => BindRefusal::NotActive,
            "ACTION_OUTSTANDING" => BindRefusal::ActionOutstanding,
            "EXECUTION_REPLAY" => BindRefusal::ExecutionReplay,
            "GENERATION_MISMATCH" => BindRefusal::GenerationMismatch,
            "UNKNOWN_BINDING" => BindRefusal::UnknownBinding,
            "CERTIFICATE_MISMATCH" => BindRefusal::CertificateMismatch,
            "MANIFEST_REUSED" => BindRefusal::ManifestReused,
            "WORKER_NOT_OBSERVED" => BindRefusal::WorkerNotObserved,
            "STORAGE_FAILURE" => BindRefusal::StorageFailure,
            _ => return None,
        })
    }
}

/// Section 3.3's failure classes before STARTED, by step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Step 1 or step 4's re-read: the leaf is held (section 3.4).
    Held,
    /// Step 1: the DISPATCH's binding check (Q-HE5B-2 (a)).
    BindingMismatch,
    /// Step 2: the gate's qualification (O10, O11).
    GateQualification,
    /// Step 2: the I05 channel's opening exchange (GENERATION_STATUS) failed or was refused.
    GateChannel,
    /// Step 3: the W5 check (open, measure, compare; the socketpair).
    ScriptCheck,
    /// Step 4: W1.
    LeafCheck,
    /// Steps 5 and 6 (W2, W3), the leaf then shown empty by W6.
    Spawn,
    /// Step 7: the gate refused BIND_EXECUTION with this reason, the leaf then shown empty by W6.
    BindRefused(BindRefusal),
    /// Step 7: no valid BIND_EXECUTION response, the leaf then shown empty by W6.
    BindChannel,
    /// From step 5: W6 cannot show the leaf empty, so the broker enters HOLD (section 3.4).
    LeafNotEmpty,
}

/// The refusal map (section 3.3, H5E-4): a failure before step 5 spawns nothing and answers REFUSED with UNAVAILABLE,
/// INVALID_AUTHORITY or CAPACITY_HELD; a failure from step 5 up to STARTED answers REFUSED UNAVAILABLE once W6 has
/// shown the leaf empty; HOLD sends nothing (`None`). After STARTED a run ends with TERMINAL, never REFUSED.
pub fn answer(failure: Failure) -> Option<RefusedReason> {
    match failure {
        Failure::Held => Some(RefusedReason::CapacityHeld),
        Failure::BindingMismatch => Some(RefusedReason::InvalidAuthority),
        Failure::GateQualification | Failure::GateChannel | Failure::ScriptCheck | Failure::LeafCheck => {
            Some(RefusedReason::Unavailable)
        }
        Failure::Spawn | Failure::BindChannel => Some(RefusedReason::Unavailable),
        Failure::BindRefused(
            BindRefusal::NotActive
            | BindRefusal::ActionOutstanding
            | BindRefusal::ExecutionReplay
            | BindRefusal::GenerationMismatch
            | BindRefusal::UnknownBinding
            | BindRefusal::CertificateMismatch
            | BindRefusal::ManifestReused
            | BindRefusal::WorkerNotObserved
            | BindRefusal::StorageFailure,
        ) => Some(RefusedReason::Unavailable),
        Failure::LeafNotEmpty => None,
    }
}

// ------------------------------------------------------------------------------------------------ helpers

fn text<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn integer(value: &Value, key: &str) -> Option<i64> {
    value.get(key).and_then(Value::as_int).and_then(json::Int::to_i64)
}

/// 64 lowercase hexadecimal digits.
fn is_hex64(candidate: &str) -> bool {
    candidate.len() == 64 && candidate.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Strict base64 that is also canonical: decoded strictly, then re-encoded to the same text (no non-zero trailing
/// bits).
fn canonical_base64(encoded: &str) -> Option<Vec<u8>> {
    let data = base64::decode_strict(encoded.as_bytes())?;
    if base64::encode(&data) == encoded {
        Some(data)
    } else {
        None
    }
}
