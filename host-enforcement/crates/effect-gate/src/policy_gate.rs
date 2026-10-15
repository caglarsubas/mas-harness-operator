//! The I07 v3 PolicyGate (HE-002B): the policy-writer channel of the effect gate, as an in-memory model of its
//! decisions on top of the I05 v3 [`Gate`], which it owns (composition; HE-002B DESIGN §3).
//!
//! It keeps the writer session (one at a time, opened by MAINTENANCE_STATUS, lockstep, fatal versus refused), the
//! generation's one maintenance (NONE, PENDING, OPEN, HELD, ENDED, re-derived from the base A3 fence after every
//! event), the writes and the one outstanding write, whose upstream outcome arrives as its own event (a response, a
//! loss, or the logical expiry of the 10-second bound; the timer itself is HE-003's). Its records go into the base
//! gate's single journal, so the journal digest covers both channels, and a restart rebuilds the writes and the
//! maintenance from that journal alone. Sockets, custody and the apiserver client are HE-003's.
//!
//! The READMEs (I07 v1-v3) decide; where they are silent the pinned I07 v3 model is the specification and each such
//! point is an N-item in MODEL_DEFINED.md, the R10-defined behaviour R13-R18. Like the base gate it never panics: an
//! event outside the preconditions is an [`EventError`] with no state change.
//!
//! HE-002C adds the durable constructors: `create` starts a new generation on file stores, and `open` is the process
//! restart, which rebuilds the writes and the maintenance from the journal file exactly as GATE_RESTART does from the
//! in-process journal (HE-002C DESIGN §8).
//!
//! HE-003A adds what the channel substrate reads (the base gate's `channel_state`, `bound_run` and
//! `connection_open`, and `session_held`, `pending_write`; none changes any state) and the R10-defined
//! `PolicyEvent::WAnswerLate` (HE-003A DESIGN §5.7); no existing event's answer changes.
//!
//! HE-003C (DESIGN §2.1, §6) keeps the rendered request with the outstanding write (`forwarded_write`, read by the
//! upstream port's `sync`), and R16 parses `apiserverAuthority` once as a loopback IP literal with port
//! (`apiserver_address`, the one address both channels connect to). No answer, record or vector changes.

use std::collections::BTreeMap;

use gate_sys::inet::{parse_authority, InetAddress, IpLiteral};
use i05_protocol::json::{Doc, JStr, Value};
use i05_protocol::{decode_frame, frame, sha256, Datagram, FrameError, Schema, ZERO_DIGEST};

use crate::config::{Config, ConfigError};
use crate::file_store::FileStores;
use crate::gate::{BoundRun, ChannelState, Event, EventError, FrameInput, Gate, GateError, Output, UpstreamResponse};
use crate::journal::{Entry, Record, WriteDetails};
use crate::policy::{check_write, render_write, request_digest, write_outcome_is_final, KindsError, PolicyKinds,
                    RenderedWrite, WriteOperation, WriteRequest};
use crate::types::{AbortReason, Classification, DrainAnswer, FatalReason, Invalidation, Maintenance, MaintenanceEnd,
                   MaintenanceReason, SessionEnd, State};

/// The I07 v3 frame version.
pub const WRITER_FRAME_VERSION: &str = "planeon.internal.policy-write-frame/v3";

/// The I07 v3 schema's largest sequence.
const MAX_SEQUENCE: i64 = 2147483647;

/// The `policyWriter` configuration member (R16).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyWriter {
    pub qualification_namespace: String,
    pub apiserver_authority: String,
}

/// A DNS-1123 label: 1 to 63 of `a-z`, `0-9` and `-`, starting and ending with a letter or digit.
fn is_dns_label(text: &str) -> bool {
    let bytes = text.as_bytes();
    let inner = |byte: &u8| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-';
    let edge = |byte: Option<&u8>| byte.is_some_and(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit());
    (1..=63).contains(&bytes.len()) && bytes.iter().all(inner) && edge(bytes.first()) && edge(bytes.last())
}

/// The IPv6 loopback address ::1.
const LOOPBACK_V6: [u8; 16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];

/// R16 (HE-002B R1-4; HE-003C DESIGN §6, Q-HE3C-1 (a) amended): `apiserverAuthority` is an IP literal with port, as
/// gate-sys's `parse_authority` reads it (at most 64 bytes, no name), and loopback: an IPv4 address in 127.0.0.0/8 or
/// the IPv6 address ::1 exactly; an IPv4-mapped form such as `::ffff:127.0.0.1` is refused (fail closed).
fn loopback_authority(text: &str) -> Option<InetAddress> {
    let address = parse_authority(text).ok()?;
    let loopback = match address.ip {
        IpLiteral::V4([first, ..]) => first == 127,
        IpLiteral::V6(octets) => octets == LOOPBACK_V6,
    };
    loopback.then_some(address)
}

impl PolicyWriter {
    /// The member and the parsed apiserver address.
    fn from_member(member: Option<&Value>) -> Result<(PolicyWriter, InetAddress), PolicyGateError> {
        let refuse = |message: &str| Err(PolicyGateError::PolicyWriter(message.to_string()));
        let Some(member) = member.and_then(Value::as_object) else { return refuse("policyWriter is missing or not an object") };
        if member.len() != 2 {
            return refuse("policyWriter must hold exactly qualificationNamespace and apiserverAuthority");
        }
        let (Some(namespace), Some(authority)) = (
            member.get("qualificationNamespace").and_then(Value::as_str),
            member.get("apiserverAuthority").and_then(Value::as_str),
        ) else {
            return refuse("policyWriter must hold exactly qualificationNamespace and apiserverAuthority as text");
        };
        if !is_dns_label(namespace) {
            return refuse("policyWriter.qualificationNamespace is not a DNS-1123 label");
        }
        let Some(address) = loopback_authority(authority) else {
            return refuse("policyWriter.apiserverAuthority is not a loopback IP literal with a port (127.0.0.0/8 or ::1)");
        };
        Ok((PolicyWriter { qualification_namespace: namespace.to_string(), apiserver_authority: authority.to_string() },
            address))
    }
}

/// Why a PolicyGate could not be created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyGateError {
    /// The configuration without `policyWriter`, as the unchanged I05 `Config` refused it.
    Config(ConfigError),
    /// `policyWriter` itself (R16), or a configuration that is not an object.
    PolicyWriter(String),
    Kinds(KindsError),
    Gate(GateError),
    Schema(String),
}

/// What the apiserver exchange of the one write in flight came to, typed (R15).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UpstreamOutcome {
    /// The exchange ended without a response.
    Lost,
    /// The exchange outlived the 10-second limit the gate sets on it (the logical event; the timer is HE-003's).
    Timeout,
    /// A delivered response.
    Response(UpstreamResponse),
}

/// One PolicyGate event: an I05 event for the base gate, or a writer event.
#[derive(Clone, Debug)]
pub enum PolicyEvent {
    Base(Event),
    /// A writer connection. Its challenge is the one the writer will put in its frames; the gate does not judge it
    /// here (the session takes its challenge from its opening frame).
    WConnect { challenge: String },
    WFrame(FrameInput),
    WChannelLost,
    WPeerChanged,
    WUpstream { write_id: u16, outcome: UpstreamOutcome },
    /// R10-defined (HE-003A DESIGN §5.7, owner decision Q-HE3A-2 (b)): the substrate did not send a synchronous answer
    /// (MAINTENANCE_STATUS, WRITE_BEGIN, WRITE_END) because the 2-second bound had passed. The session ends FATAL with
    /// `ANSWER_LATE` and the generation is HELD; without a session it answers `{}` (as W_PEER_CHANGED).
    WAnswerLate,
}

/// Why a writer session ended fatally.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum WriterFatal {
    /// A writer frame while a WRITE_OBJECT awaits its response.
    Lockstep,
    InvalidFrame(FrameError),
    Direction,
    ChainBroken,
    OpeningFrameRequired,
    ChallengeMismatch,
    PeerChanged,
    /// R13: the gate's response would leave the schema.
    ResponseOutOfBounds,
    /// R10-defined (HE-003A DESIGN §5.7): a synchronous answer missed the 2-second bound and was not sent.
    AnswerLate,
}

impl WriterFatal {
    pub fn as_str(self) -> &'static str {
        match self {
            WriterFatal::Lockstep => "LOCKSTEP",
            WriterFatal::InvalidFrame(code) => FatalReason::InvalidFrame(code).as_str(),
            WriterFatal::Direction => "DIRECTION",
            WriterFatal::ChainBroken => "CHAIN_BROKEN",
            WriterFatal::OpeningFrameRequired => "OPENING_FRAME_REQUIRED",
            WriterFatal::ChallengeMismatch => "CHALLENGE_MISMATCH",
            WriterFatal::PeerChanged => "PEER_CHANGED",
            WriterFatal::ResponseOutOfBounds => "RESPONSE_OUT_OF_BOUNDS",
            WriterFatal::AnswerLate => FatalReason::AnswerLate.as_str(),
        }
    }
}

/// What an event produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PolicyOutputKind {
    /// An I05 event's output, unchanged.
    Base(Output),
    /// GATE_RESTART: the base output plus the maintenance it leaves.
    Restart { output: Output, maintenance: Maintenance },
    /// `{"session": "CONNECTED"}`
    Session,
    /// `{"refusedSession": "SESSION_EXISTS"}`
    RefusedSession,
    /// `{"response": payload}`
    Response(Doc),
    /// `{"forwarded": writeId}`: the response waits for the upstream outcome.
    Forwarded(u16),
    /// `{"sessionEnd": how, "maintenance": state}` plus `fatal` for a fatal end.
    SessionEnd { how: SessionEnd, maintenance: Maintenance, fatal: Option<WriterFatal> },
    /// `{"classification": c, "relayed": bool}` plus `response` when the answer reached the writer.
    Upstream { classification: Classification, response: Option<Doc> },
    /// `{"lateUpstream": "NOT_RELAYED"}`
    LateUpstream,
    /// `{}`
    Empty,
}

/// An event's output: what it produced, the I05 drain answer a writer event settled (an I05 event carries its own in
/// the base output), and for a framed response the exact bytes sent to the writer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PolicyOutput {
    pub kind: PolicyOutputKind,
    pub drain: Option<DrainAnswer>,
    pub response_frame: Option<Vec<u8>>,
}

impl PolicyOutput {
    fn of(kind: PolicyOutputKind) -> PolicyOutput {
        PolicyOutput { kind, drain: None, response_frame: None }
    }

    /// The contract's output object.
    pub fn to_doc(&self) -> Doc {
        let mut members: Vec<(&str, Doc)> = match &self.kind {
            PolicyOutputKind::Base(output) => return output.to_doc(),
            PolicyOutputKind::Restart { output, maintenance } => {
                let mut doc = output.to_doc();
                if let Doc::Object(members) = &mut doc {
                    members.push(("maintenance".to_string(), Doc::str(maintenance.as_str())));
                }
                return doc;
            }
            PolicyOutputKind::Session => vec![("session", Doc::str("CONNECTED"))],
            PolicyOutputKind::RefusedSession => vec![("refusedSession", Doc::str("SESSION_EXISTS"))],
            PolicyOutputKind::Response(payload) => vec![("response", payload.clone())],
            PolicyOutputKind::Forwarded(write_id) => vec![("forwarded", Doc::Int(i64::from(*write_id)))],
            PolicyOutputKind::SessionEnd { how, maintenance, fatal } => {
                let mut members = vec![("sessionEnd", Doc::str(how.as_str())), ("maintenance", Doc::str(maintenance.as_str()))];
                if let Some(fatal) = fatal {
                    members.push(("fatal", Doc::str(fatal.as_str())));
                }
                members
            }
            PolicyOutputKind::Upstream { classification, response } => {
                let mut members =
                    vec![("classification", Doc::str(classification.as_str())), ("relayed", Doc::Bool(response.is_some()))];
                if let Some(payload) = response {
                    members.push(("response", payload.clone()));
                }
                members
            }
            PolicyOutputKind::LateUpstream => vec![("lateUpstream", Doc::str("NOT_RELAYED"))],
            PolicyOutputKind::Empty => Vec::new(),
        };
        if let Some(answer) = self.drain {
            members.push(("drain", Doc::str(answer.as_str())));
        }
        Doc::object(members)
    }
}

fn count_doc(count: u64) -> Doc {
    Doc::Int(i64::try_from(count).unwrap_or(i64::MAX))
}

fn ids_doc(ids: &[u16]) -> Doc {
    Doc::Array(ids.iter().map(|id| Doc::Int(i64::from(*id))).collect())
}

/// The write counters (snapshot `writeCounters`); they saturate (R17).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct WriteCounters {
    pub sessions: u64,
    pub writes_forwarded: u64,
    /// Only the maintenance, write ID and table refusals count; a STORAGE_FAILURE refusal does not.
    pub writes_refused: u64,
}

impl WriteCounters {
    fn to_doc(&self) -> Doc {
        Doc::object(vec![
            ("sessions", count_doc(self.sessions)),
            ("writesForwarded", count_doc(self.writes_forwarded)),
            ("writesRefused", count_doc(self.writes_refused)),
        ])
    }
}

/// The writer session: its chain position, its challenge once opened, and whether it began the maintenance.
#[derive(Clone, Debug)]
struct Session {
    opened: bool,
    challenge: Option<String>,
    next_sequence: i64,
    last_digest: String,
    owner: bool,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum WriteStatus {
    Forwarded,
    Terminal,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
struct WriteEntry {
    status: WriteStatus,
    classification: Option<Classification>,
}

impl WriteEntry {
    const FORWARDED: WriteEntry = WriteEntry { status: WriteStatus::Forwarded, classification: None };

    fn terminal(classification: Classification) -> WriteEntry {
        WriteEntry { status: WriteStatus::Terminal, classification: Some(classification) }
    }
}

/// The one write sent upstream and not yet answered, with what its deferred response needs: the request frame's
/// sequence and digest (on the byte path, the received datagram's), and the request digest; and the rendered request
/// itself, which the upstream port sends (HE-003C DESIGN §2.1).
#[derive(Clone, Debug)]
struct PendingWrite {
    write_id: u16,
    operation: WriteOperation,
    request_digest: String,
    sequence: i64,
    frame_digest: String,
    rendered: RenderedWrite,
}

/// A typed writer request; the frame passed the closed schema, so its payload is the operation's request variant.
enum WriterRequest {
    Status,
    Begin { expected_generation: String },
    Object(WriteRequest),
    End,
}

impl WriterRequest {
    fn parse(operation: &str, payload: &Value) -> Option<WriterRequest> {
        Some(match operation {
            "MAINTENANCE_STATUS" => WriterRequest::Status,
            "WRITE_BEGIN" => WriterRequest::Begin { expected_generation: payload.get("expectedGeneration")?.as_str()?.to_string() },
            "WRITE_OBJECT" => WriterRequest::Object(WriteRequest::from_payload(payload)?),
            "WRITE_END" => WriterRequest::End,
            _ => return None,
        })
    }
}

/// An operation's result: a response payload now, or a forwarded write whose response comes later.
enum WriterReply {
    Payload(Doc),
    Forwarded(u16),
}

fn refused(reason: &str) -> Doc {
    Doc::object(vec![("result", Doc::str("REFUSED")), ("reason", Doc::str(reason))])
}

fn is_digest(text: &str) -> bool {
    text.strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
}

fn is_token(text: &str, max: usize, dash: bool) -> bool {
    (1..=max).contains(&text.len()) && text.bytes().all(|byte| byte.is_ascii_alphanumeric() || (dash && byte == b'-'))
}

/// R15: a response the I07 v3 WRITE_OBJECT answer can carry unchanged.
fn response_in_schema(response: &UpstreamResponse) -> bool {
    (100..=599).contains(&response.http_status)
        && is_digest(&response.body_digest)
        && response.uid.as_deref().is_none_or(|uid| is_token(uid, 128, true))
        && response.resource_version.as_deref().is_none_or(|version| is_token(version, 64, false))
}

/// PolicyGate: an owned I05 v3 gate plus the I07 policy-writer channel.
pub struct PolicyGate {
    gate: Gate,
    kinds: PolicyKinds,
    schema: Schema,
    writer: PolicyWriter,
    apiserver_address: InetAddress,
    maintenance: Maintenance,
    maintenance_reason: Option<MaintenanceReason>,
    session: Option<Session>,
    writes: BTreeMap<u16, WriteEntry>,
    pending: Option<PendingWrite>,
    counters: WriteCounters,
}

/// What a PolicyGate holds besides its base gate: the writer member and its parsed address, the kinds table and the
/// I07 schema.
struct Parts {
    writer: PolicyWriter,
    address: InetAddress,
    kinds: PolicyKinds,
    schema: Schema,
}

impl Parts {
    /// The configuration with its `policyWriter` member (R16) and the closed policy-kind table. The rest of the
    /// configuration goes to the unchanged I05 `Config`, returned for the base gate.
    fn read(config_value: &Value, kinds_value: &Value) -> Result<(Config, Parts), PolicyGateError> {
        let Some(root) = config_value.as_object() else {
            return Err(PolicyGateError::PolicyWriter("the configuration is not an object".to_string()));
        };
        let (writer, address) = PolicyWriter::from_member(root.get("policyWriter"))?;
        let mut rest = root.clone();
        rest.remove(&JStr::new("policyWriter"));
        let config = Config::from_value(&Value::Object(rest)).map_err(PolicyGateError::Config)?;
        let kinds = PolicyKinds::from_value(kinds_value).map_err(PolicyGateError::Kinds)?;
        let schema = i05_protocol::i07_v3_schema().map_err(|error| PolicyGateError::Schema(error.0))?;
        Ok((config, Parts { writer, address, kinds, schema }))
    }

    fn around(self, gate: Gate) -> PolicyGate {
        PolicyGate {
            gate,
            kinds: self.kinds,
            schema: self.schema,
            writer: self.writer,
            apiserver_address: self.address,
            maintenance: Maintenance::NotBegun,
            maintenance_reason: None,
            session: None,
            writes: BTreeMap::new(),
            pending: None,
            counters: WriteCounters::default(),
        }
    }
}

impl PolicyGate {
    /// A PolicyGate for a configuration with its `policyWriter` member (R16) and the closed policy-kind table, on
    /// in-memory stores. The rest of the configuration goes to the unchanged I05 `Config`.
    pub fn new(config_value: &Value, kinds_value: &Value) -> Result<PolicyGate, PolicyGateError> {
        let (config, parts) = Parts::read(config_value, kinds_value)?;
        let gate = Gate::new(config).map_err(PolicyGateError::Gate)?;
        Ok(parts.around(gate))
    }

    /// A new generation on file stores (`Gate::create`'s conditions).
    pub fn create(config_value: &Value, kinds_value: &Value, stores: FileStores) -> Result<PolicyGate, PolicyGateError> {
        let (config, parts) = Parts::read(config_value, kinds_value)?;
        let gate = Gate::create(config, stores).map_err(PolicyGateError::Gate)?;
        Ok(parts.around(gate))
    }

    /// The process restart (HE-002C DESIGN §8): the gate as the files leave it, then GATE_RESTART's I07 path (no
    /// outstanding write, the writes and the maintenance rebuilt from the journal, the base restart with a HELD floor
    /// when a write is ambiguous, RESTARTED appended once, no session). The write counters start at zero.
    pub fn open(config_value: &Value, kinds_value: &Value, stores: FileStores)
                -> Result<(PolicyGate, PolicyOutput), PolicyGateError> {
        let (config, parts) = Parts::read(config_value, kinds_value)?;
        let gate = Gate::reopened(config, stores).map_err(PolicyGateError::Gate)?;
        let mut policy = parts.around(gate);
        let output = policy.restart();
        policy.settle_maintenance();
        Ok((policy, output))
    }

    /// The base gate (read only).
    pub fn gate(&self) -> &Gate {
        &self.gate
    }

    pub fn maintenance(&self) -> Maintenance {
        self.maintenance
    }

    pub fn writer(&self) -> &PolicyWriter {
        &self.writer
    }

    /// `apiserverAuthority` as parsed once by R16 (a loopback IP literal with port): the address the upstream port of
    /// both channels connects to (HE-003C DESIGN §6; HE-003D hands it to the port's constructor).
    pub fn apiserver_address(&self) -> InetAddress {
        self.apiserver_address
    }

    /// The sequence the next writer frame must carry: the current session's (opened or not), else 1.
    pub fn writer_next_sequence(&self) -> i64 {
        self.session.as_ref().map_or(1, |session| session.next_sequence)
    }

    /// The digest the next writer frame's `previousDigest` must carry: the current session's, else the zero digest.
    pub fn writer_last_digest(&self) -> &str {
        self.session.as_ref().map_or(ZERO_DIGEST, |session| session.last_digest.as_str())
    }

    /// The base gate's channel state (read only; HE-003A DESIGN §5.1).
    pub fn channel_state(&self) -> ChannelState {
        self.gate.channel_state()
    }

    /// The base gate's bound execution and its expiry (read only; HE-003A DESIGN §5.1).
    pub fn bound_run(&self) -> Option<BoundRun> {
        self.gate.bound_run()
    }

    /// Whether the base gate holds the I04 connection `conn` open (read only; HE-003A DESIGN §6).
    pub fn connection_open(&self, conn: &str) -> bool {
        self.gate.connection_open(conn)
    }

    /// Whether a writer session exists, opened or not (read only; HE-003A DESIGN §5.1, §5.8).
    pub fn session_held(&self) -> bool {
        self.session.is_some()
    }

    /// The forwarded write awaiting its upstream outcome, if any (read only; HE-003A DESIGN §6).
    pub fn pending_write(&self) -> Option<u16> {
        self.pending.as_ref().map(|pending| pending.write_id)
    }

    /// The forwarded write awaiting its upstream outcome and the exact request rendered for it (read only; HE-003C
    /// DESIGN §2.1): the bytes the upstream port sends.
    pub fn forwarded_write(&self) -> Option<(u16, &RenderedWrite)> {
        self.pending.as_ref().map(|pending| (pending.write_id, &pending.rendered))
    }

    /// Applies one event (N7): an I05 event goes to the base gate (which settles its pending drain itself), with the
    /// I07 restart around GATE_RESTART; a writer event is handled here, then a pending I05 drain settles and its
    /// answer rides on this output. After either, the maintenance follows the fence.
    pub fn handle(&mut self, event: PolicyEvent) -> Result<PolicyOutput, EventError> {
        let output = match event {
            PolicyEvent::Base(Event::GateRestart) => self.restart(),
            PolicyEvent::Base(event) => PolicyOutput::of(PolicyOutputKind::Base(self.gate.handle(event)?)),
            PolicyEvent::WConnect { challenge: _ } => {
                let output = self.connect();
                self.with_drain(output)
            }
            PolicyEvent::WUpstream { write_id, outcome } => {
                let output = self.upstream(write_id, outcome)?;
                self.with_drain(output)
            }
            PolicyEvent::WFrame(input) => {
                if self.session.is_none() {
                    return Err(EventError("writer frame without a session")); // R14
                }
                let output = self.writer_frame(input);
                self.with_drain(output)
            }
            PolicyEvent::WChannelLost => {
                let output = self.channel_lost();
                self.with_drain(output)
            }
            PolicyEvent::WPeerChanged => {
                let output = self.peer_changed();
                self.with_drain(output)
            }
            PolicyEvent::WAnswerLate => {
                let output = self.answer_late();
                self.with_drain(output)
            }
        };
        self.settle_maintenance();
        Ok(output)
    }

    /// The contract's final snapshot: the base snapshot with `maintenance`, `maintenanceReason`, `writerSession`,
    /// `pendingWriteId`, `writes` and `writeCounters` (N17).
    pub fn snapshot(&self) -> Doc {
        let mut snapshot = self.gate.snapshot();
        let writes = self
            .writes
            .iter()
            .map(|(write_id, entry)| {
                (write_id.to_string(), Doc::object(vec![
                    ("status", Doc::str(match entry.status {
                        WriteStatus::Forwarded => "FORWARDED",
                        WriteStatus::Terminal => "TERMINAL",
                    })),
                    ("classification", Doc::opt_str(entry.classification.map(Classification::as_str))),
                ]))
            })
            .collect();
        if let Doc::Object(members) = &mut snapshot {
            let session = self.session.as_ref().map(|session| if session.opened { "OPEN" } else { "UNOPENED" });
            let pending = self.pending.as_ref().map_or(Doc::Null, |pending| Doc::Int(i64::from(pending.write_id)));
            members.extend([
                ("maintenance".to_string(), Doc::str(self.maintenance.as_str())),
                ("maintenanceReason".to_string(), Doc::opt_str(self.maintenance_reason.map(MaintenanceReason::as_str))),
                ("writerSession".to_string(), Doc::opt_str(session)),
                ("pendingWriteId".to_string(), pending),
                ("writes".to_string(), Doc::Object(writes)),
                ("writeCounters".to_string(), self.counters.to_doc()),
            ]);
        }
        snapshot
    }

    // ------------------------------------------------------------------------------------------ helpers

    fn with_drain(&mut self, mut output: PolicyOutput) -> PolicyOutput {
        if let Some(answer) = self.gate.settle_drain() {
            output.drain = Some(answer);
        }
        output
    }

    fn write_count(&self) -> u16 {
        u16::try_from(self.writes.len()).unwrap_or(u16::MAX)
    }

    fn ambiguous_writes(&self) -> Vec<u16> {
        self.writes
            .iter()
            .filter(|(_, entry)| entry.classification == Some(Classification::IoAmbiguous))
            .map(|(write_id, _)| *write_id)
            .collect()
    }

    /// Decision 0 after every event (N6): a waiting maintenance opens only if its MAINT_OPEN record is durable; a
    /// waiting or open one is held when the fence is HELD, whatever its MAINT_HELD record's result. A failed
    /// MAINT_OPEN holds the generation, so the second step then holds the maintenance in the same settle.
    fn settle_maintenance(&mut self) {
        if self.maintenance == Maintenance::Pending
            && self.gate.fence() == DrainAnswer::Open
            && self.gate.record(Record::MaintOpen { state: self.gate.state() })
        {
            self.maintenance = Maintenance::Open;
        }
        if matches!(self.maintenance, Maintenance::Pending | Maintenance::Open) && self.gate.fence() == DrainAnswer::Held {
            self.maintenance = Maintenance::Held;
            self.gate.record(Record::MaintHeld { state: self.gate.state() });
        }
    }

    fn end_maintenance(&mut self, end: MaintenanceEnd) {
        self.maintenance = Maintenance::Ended;
        self.maintenance_reason = Some(MaintenanceReason::Ended(end));
        let record = Record::MaintEnded { reason: end, writes: self.write_count(), ambiguous_write_ids: self.ambiguous_writes() };
        // On the session-end path the maintenance has ended whatever the record's result (N9).
        self.gate.record(record);
    }

    /// The gate gives up on the outstanding write (N11): WRITE_TERMINAL IO_AMBIGUOUS `{aborted: reason}` first (its
    /// result does not change anything), the write ambiguous, and the generation HELD by a direct state change.
    fn abort_pending(&mut self, reason: AbortReason) {
        let Some(pending) = self.pending.take() else { return };
        self.gate.record(Record::WriteTerminal {
            write_id: pending.write_id,
            classification: Classification::IoAmbiguous,
            details: WriteDetails::Aborted(reason),
        });
        self.writes.insert(pending.write_id, WriteEntry::terminal(Classification::IoAmbiguous));
        self.gate.set_state(State::Held);
    }

    /// Ends the current session (N9): WRITER_SESSION_ENDED, then, for the owning session of a maintenance that has not
    /// ended, its end. Callers abort an outstanding write first.
    fn end_session(&mut self, how: SessionEnd, fatal: Option<WriterFatal>) -> PolicyOutput {
        let owner = self.session.take().is_some_and(|session| session.owner);
        self.gate.record(Record::WriterSessionEnded { how });
        if owner && self.maintenance != Maintenance::Ended {
            self.end_maintenance(MaintenanceEnd::Session(how));
        }
        PolicyOutput::of(PolicyOutputKind::SessionEnd { how, maintenance: self.maintenance, fatal })
    }

    fn writer_fatal(&mut self, reason: WriterFatal) -> PolicyOutput {
        self.abort_pending(AbortReason::WriterProtocolFailure);
        self.end_session(SessionEnd::Fatal, Some(reason))
    }

    /// Frames a response to the request at `sequence` with digest `request_digest` (N14) and advances the session's
    /// chain; `None` when there is no session or the response would leave the schema (R13).
    fn frame_response(&mut self, sequence: i64, request_digest: &str, operation: &str, payload: &Doc) -> Option<Vec<u8>> {
        let session = self.session.as_mut()?;
        let response = Doc::object(vec![
            ("schemaVersion", Doc::str(WRITER_FRAME_VERSION)),
            ("challenge", Doc::opt_str(session.challenge.as_deref())),
            ("sequence", Doc::Int(sequence.saturating_add(1))),
            ("previousDigest", Doc::str(request_digest)),
            ("direction", Doc::str("GATE_TO_WRITER")),
            ("operation", Doc::str(operation)),
            ("payload", payload.clone()),
        ]);
        let bytes = frame::check_frame_encoded(&response.to_value(), &self.schema).ok()?;
        session.next_sequence = sequence.saturating_add(2);
        session.last_digest = sha256::prefixed(&bytes);
        Some(bytes)
    }

    // ------------------------------------------------------------------------------------------ restart

    /// GATE_RESTART with the I07 channel (HE-002B DESIGN §6, N10): the outstanding exchange is dropped, the writes and the
    /// maintenance reason are rebuilt from the journal alone, the base restart runs with a HELD floor when a write is
    /// ambiguous, and no session survives. No WRITER_SESSION_ENDED or MAINT_ENDED is written; the counters stay.
    fn restart(&mut self) -> PolicyOutput {
        self.pending = None;
        let (writes, reason) = rebuild_writes(self.gate.journal());
        let ambiguous = writes.values().any(|entry| entry.classification == Some(Classification::IoAmbiguous));
        self.writes = writes;
        self.maintenance = Maintenance::Ended;
        self.maintenance_reason = Some(reason);
        let mut output = self.gate.restart_with(ambiguous.then_some(State::Held));
        // As after any I05 event; a restart leaves no drain pending, so this never answers.
        if let Some(answer) = self.gate.settle_drain() {
            output.drain = Some(answer);
        }
        self.session = None;
        PolicyOutput::of(PolicyOutputKind::Restart { output, maintenance: self.maintenance })
    }

    // ------------------------------------------------------------------------------------------ writer events

    fn connect(&mut self) -> PolicyOutput {
        if self.session.is_some() {
            return PolicyOutput::of(PolicyOutputKind::RefusedSession);
        }
        self.session =
            Some(Session { opened: false, challenge: None, next_sequence: 1, last_digest: ZERO_DIGEST.to_string(), owner: false });
        self.counters.sessions = self.counters.sessions.saturating_add(1);
        PolicyOutput::of(PolicyOutputKind::Session)
    }

    fn channel_lost(&mut self) -> PolicyOutput {
        if self.session.is_none() {
            return PolicyOutput::of(PolicyOutputKind::Empty);
        }
        self.abort_pending(AbortReason::WriterChannelLost);
        self.end_session(SessionEnd::Ended, None)
    }

    /// The writer's custody failed (I07 Channel item 2), so the enrolled writer no longer holds this session (N12):
    /// abort the outstanding write, close urgently toward HELD with WRITER_PEER_DEVIATION, hold, end the session FATAL.
    fn peer_changed(&mut self) -> PolicyOutput {
        if self.session.is_none() {
            return PolicyOutput::of(PolicyOutputKind::Empty);
        }
        self.abort_pending(AbortReason::WriterPeerDeviation);
        self.gate.urgent(State::Held, Invalidation::WriterPeerDeviation);
        self.gate.set_state(State::Held);
        self.end_session(SessionEnd::Fatal, Some(WriterFatal::PeerChanged))
    }

    /// The gate missed the 2-second bound on a synchronous answer (HE-003A DESIGN §5.7, R10-defined), in N12's order:
    /// abort the outstanding write (none on these answers; aborted as every other fatal session end aborts it), close
    /// urgently toward HELD with the gate's own reason (`["INVALIDATED", "ANSWER_LATE", "HELD"]`, not
    /// WRITER_PEER_DEVIATION), hold, end the session FATAL (and an owning session's maintenance).
    fn answer_late(&mut self) -> PolicyOutput {
        if self.session.is_none() {
            return PolicyOutput::of(PolicyOutputKind::Empty);
        }
        self.abort_pending(AbortReason::WriterProtocolFailure);
        self.gate.urgent(State::Held, Invalidation::Fatal(FatalReason::AnswerLate));
        self.gate.set_state(State::Held);
        self.end_session(SessionEnd::Fatal, Some(WriterFatal::AnswerLate))
    }

    /// One writer frame of the current session (N13): lockstep first, then the frame checks, direction, chain,
    /// opening rule and challenge, then R13, then the operation.
    fn writer_frame(&mut self, input: FrameInput) -> PolicyOutput {
        if self.pending.is_some() {
            return self.writer_fatal(WriterFatal::Lockstep);
        }
        let checked = match input {
            FrameInput::Value(value) => frame::check_frame_encoded(&value, &self.schema).map(|encoded| (value, encoded)),
            FrameInput::Bytes(raw) => decode_frame(Datagram::Bytes(&raw), &self.schema).map(|value| (value, raw)),
            FrameInput::NotBytes => Err(FrameError::F07),
        };
        let (value, encoded) = match checked {
            Ok(checked) => checked,
            Err(code) => return self.writer_fatal(WriterFatal::InvalidFrame(code)),
        };
        let text = |key: &str| value.get(key).and_then(Value::as_str).map(str::to_string);
        let sequence = value.get("sequence").and_then(Value::as_int).and_then(|sequence| sequence.to_i64());
        let (Some(direction), Some(sequence), Some(previous), Some(challenge), Some(operation)) =
            (text("direction"), sequence, text("previousDigest"), text("challenge"), text("operation"))
        else {
            return self.writer_fatal(WriterFatal::InvalidFrame(FrameError::F00));
        };
        if direction != "WRITER_TO_GATE" || sequence.rem_euclid(2) != 1 {
            return self.writer_fatal(WriterFatal::Direction);
        }
        if sequence != self.writer_next_sequence() || previous != self.writer_last_digest() {
            return self.writer_fatal(WriterFatal::ChainBroken);
        }
        let Some(session) = self.session.as_mut() else { return PolicyOutput::of(PolicyOutputKind::Empty) };
        if !session.opened {
            if operation != "MAINTENANCE_STATUS" {
                return self.writer_fatal(WriterFatal::OpeningFrameRequired);
            }
            session.opened = true;
            session.challenge = Some(challenge);
        } else if session.challenge.as_deref() != Some(challenge.as_str()) {
            return self.writer_fatal(WriterFatal::ChallengeMismatch);
        }
        // R13: a request whose response could not carry sequence + 1 ends the session before anything runs, so a
        // WRITE_OBJECT is never forwarded without a response that can be framed.
        if sequence >= MAX_SEQUENCE {
            return self.writer_fatal(WriterFatal::ResponseOutOfBounds);
        }
        let Some(request) = value.get("payload").and_then(|payload| WriterRequest::parse(&operation, payload)) else {
            return self.writer_fatal(WriterFatal::InvalidFrame(FrameError::F00));
        };
        let digest = sha256::prefixed(&encoded);
        let reply = match request {
            WriterRequest::Status => WriterReply::Payload(self.status()),
            WriterRequest::Begin { expected_generation } => WriterReply::Payload(self.begin(&expected_generation)),
            WriterRequest::Object(request) => self.write_object(request, sequence, &digest),
            WriterRequest::End => WriterReply::Payload(self.end()),
        };
        let payload = match reply {
            WriterReply::Forwarded(write_id) => return PolicyOutput::of(PolicyOutputKind::Forwarded(write_id)),
            WriterReply::Payload(payload) => payload,
        };
        match self.frame_response(sequence, &digest, &operation, &payload) {
            Some(bytes) => PolicyOutput {
                kind: PolicyOutputKind::Response(payload),
                drain: None,
                response_frame: Some(bytes),
            },
            // R13: any other response outside the schema (unreachable: the v3 W1 constraints describe answers this
            // gate never gives) ends the session the same way, after the operation.
            None => self.writer_fatal(WriterFatal::ResponseOutOfBounds),
        }
    }

    /// The upstream outcome of a forwarded write (N15). R15 types the outcome before anything else; an outcome for a
    /// write that is not the outstanding one is late (journalled, never relayed) or, for a write never forwarded, an
    /// invalid event (R14).
    fn upstream(&mut self, write_id: u16, outcome: UpstreamOutcome) -> Result<PolicyOutput, EventError> {
        if let UpstreamOutcome::Response(response) = &outcome {
            if !response_in_schema(response) {
                return Err(EventError("upstream response outside the I07 v3 response patterns"));
            }
        }
        let pending = match self.pending.take() {
            Some(pending) if pending.write_id == write_id => pending,
            other => {
                self.pending = other;
                if !self.writes.contains_key(&write_id) {
                    return Err(EventError("upstream outcome for a write the gate never forwarded"));
                }
                self.gate.record(Record::WriteLateUpstream { write_id });
                return Ok(PolicyOutput::of(PolicyOutputKind::LateUpstream));
            }
        };
        let operation = pending.operation;
        let (classification, details) = match outcome {
            UpstreamOutcome::Lost => (Classification::IoAmbiguous, WriteDetails::Lost),
            UpstreamOutcome::Timeout => (Classification::IoAmbiguous, WriteDetails::Aborted(AbortReason::UpstreamTimeout)),
            UpstreamOutcome::Response(response) if !write_outcome_is_final(operation, response.http_status) => {
                // The outcome is unknown; status and digest stay in the journal for reconciliation only.
                let details = WriteDetails::Reconciliation { http_status: response.http_status, result_digest: response.body_digest };
                (Classification::IoAmbiguous, details)
            }
            UpstreamOutcome::Response(response) => {
                // Object metadata comes only from a success; a rejection's body observes nothing (I07 v2 R5).
                let success = operation.is_success(response.http_status);
                let details = WriteDetails::Delivered {
                    http_status: response.http_status,
                    result_digest: response.body_digest,
                    observed_uid: response.uid.filter(|_| success),
                    observed_resource_version: response.resource_version.filter(|_| success),
                };
                (Classification::DeliveredResult, details)
            }
        };
        let recorded =
            self.gate.record(Record::WriteTerminal { write_id, classification, details: details.clone() });
        // Without a durable terminal record nothing settled: the write is IO_AMBIGUOUS with no details.
        let (classification, delivered) = match (recorded, details) {
            (false, _) => (Classification::IoAmbiguous, None),
            (true, delivered @ WriteDetails::Delivered { .. }) => (classification, Some(delivered)),
            (true, _) => (classification, None),
        };
        let (http_status, result_digest, observed_uid, observed_resource_version) = match &delivered {
            Some(WriteDetails::Delivered { http_status, result_digest, observed_uid, observed_resource_version }) => (
                Doc::Int(*http_status),
                Doc::str(result_digest),
                Doc::opt_str(observed_uid.as_deref()),
                Doc::opt_str(observed_resource_version.as_deref()),
            ),
            _ => (Doc::Null, Doc::Null, Doc::Null, Doc::Null),
        };
        self.writes.insert(write_id, WriteEntry::terminal(classification));
        if classification == Classification::IoAmbiguous {
            self.gate.set_state(State::Held);
        }
        let payload = Doc::object(vec![
            ("result", Doc::str("OK")),
            ("writeId", Doc::Int(i64::from(write_id))),
            ("classification", Doc::str(classification.as_str())),
            ("requestDigest", Doc::str(&pending.request_digest)),
            ("httpStatus", http_status),
            ("resultDigest", result_digest),
            ("observedUid", observed_uid),
            ("observedResourceVersion", observed_resource_version),
        ]);
        if self.session.is_none() {
            // R18: unreachable, since every session end aborts the outstanding write first and a restart drops it.
            return Ok(PolicyOutput::of(PolicyOutputKind::Upstream { classification, response: None }));
        }
        match self.frame_response(pending.sequence, &pending.frame_digest, "WRITE_OBJECT", &payload) {
            Some(bytes) => Ok(PolicyOutput {
                kind: PolicyOutputKind::Upstream { classification, response: Some(payload) },
                drain: None,
                response_frame: Some(bytes),
            }),
            None => {
                // R13 (unreachable after R13's check at WRITE_OBJECT and R15): nothing relayed, the session ends.
                self.writer_fatal(WriterFatal::ResponseOutOfBounds);
                Ok(PolicyOutput::of(PolicyOutputKind::Upstream { classification, response: None }))
            }
        }
    }

    // ------------------------------------------------------------------------------------------ operations

    fn status(&self) -> Doc {
        Doc::object(vec![
            ("result", Doc::str("OK")),
            ("generation", Doc::str(self.gate.generation())),
            ("gateState", Doc::str(self.gate.state().as_str())),
            ("maintenance", Doc::str(self.maintenance.as_str())),
            ("inFlightActionId", self.gate.in_flight_id().map_or(Doc::Null, |id| Doc::Int(i64::from(id)))),
            ("writes", Doc::Int(i64::from(self.write_count()))),
            ("ambiguousWriteIds", ids_doc(&self.ambiguous_writes())),
            ("journalDigest", Doc::Str(self.gate.journal_digest())),
        ])
    }

    /// WRITE_BEGIN (N8): refusals GENERATION_MISMATCH, MAINTENANCE_ENDED; a first WRITE_BEGIN notes the armed set,
    /// records MAINT_REQUESTED (STORAGE_FAILURE when that fails), takes ownership, runs the I05 drain and drops its own
    /// answer; every WRITE_BEGIN then settles the maintenance before answering (a repeated one is a poll).
    fn begin(&mut self, expected_generation: &str) -> Doc {
        if expected_generation != self.gate.generation() {
            return refused("GENERATION_MISMATCH");
        }
        if self.maintenance == Maintenance::Ended {
            return refused("MAINTENANCE_ENDED");
        }
        let mut denied = Vec::new();
        if self.maintenance == Maintenance::NotBegun {
            let armed = self.gate.armed_ids();
            let generation = self.gate.generation().to_string();
            if !self.gate.record(Record::MaintRequested { generation }) {
                return refused("STORAGE_FAILURE");
            }
            if let Some(session) = self.session.as_mut() {
                session.owner = true;
            }
            self.maintenance = Maintenance::Pending;
            let _answered_on_the_settle = self.gate.drain();
            denied = self.gate.denied_since(&armed);
        }
        self.settle_maintenance();
        Doc::object(vec![
            ("result", Doc::str("OK")),
            ("maintenance", Doc::str(self.maintenance.as_str())),
            ("gateState", Doc::str(self.gate.state().as_str())),
            ("deniedActionIds", ids_doc(&denied)),
        ])
    }

    /// WRITE_OBJECT (N8, Decision 3): maintenance, write ID, then the table; a passing write is rendered, recorded
    /// WRITE_FORWARDED (STORAGE_FAILURE forwards nothing) and becomes the outstanding write.
    fn write_object(&mut self, request: WriteRequest, sequence: i64, frame_digest: &str) -> WriterReply {
        let refusal = if self.maintenance != Maintenance::Open {
            Some(if self.maintenance == Maintenance::Held { "MAINTENANCE_HELD" } else { "MAINTENANCE_NOT_OPEN" })
        } else if usize::from(request.write_id) != self.writes.len().saturating_add(1) {
            Some("WRITE_ID_OUT_OF_ORDER")
        } else {
            None
        };
        if let Some(reason) = refusal {
            self.counters.writes_refused = self.counters.writes_refused.saturating_add(1);
            return WriterReply::Payload(refused(reason));
        }
        let namespace = self.writer.qualification_namespace.as_str();
        let row = match check_write(&self.kinds, namespace, &request) {
            Ok(row) => row,
            Err(reason) => {
                self.counters.writes_refused = self.counters.writes_refused.saturating_add(1);
                return WriterReply::Payload(refused(reason.as_str()));
            }
        };
        // A checked, schema-valid write always renders; were it ever not to, it is refused as outside the object rule.
        let Some(rendered) = render_write(row, &request, namespace, &self.writer.apiserver_authority) else {
            self.counters.writes_refused = self.counters.writes_refused.saturating_add(1);
            return WriterReply::Payload(refused("OBJECT_RULE"));
        };
        let digest = request_digest(&rendered);
        let record = Record::WriteForwarded {
            write_id: request.write_id,
            operation: request.operation,
            api_version: row.api_version(),
            kind: row.kind.clone(),
            namespace: request.namespace.clone(),
            name: request.name.clone(),
            request_digest: digest.clone(),
            prior: request.prior.clone(),
        };
        if !self.gate.record(record) {
            return WriterReply::Payload(refused("STORAGE_FAILURE"));
        }
        self.writes.insert(request.write_id, WriteEntry::FORWARDED);
        self.counters.writes_forwarded = self.counters.writes_forwarded.saturating_add(1);
        self.pending = Some(PendingWrite {
            write_id: request.write_id,
            operation: request.operation,
            request_digest: digest,
            sequence,
            frame_digest: frame_digest.to_string(),
            rendered,
        });
        WriterReply::Forwarded(request.write_id)
    }

    /// WRITE_END (N8): MAINTENANCE_NOT_BEGUN, MAINTENANCE_ENDED, then MAINT_ENDED; when that record fails the answer is
    /// STORAGE_FAILURE and the maintenance stays as it was. The generation never returns to ACTIVE (Decision 2).
    fn end(&mut self) -> Doc {
        match self.maintenance {
            Maintenance::NotBegun => return refused("MAINTENANCE_NOT_BEGUN"),
            Maintenance::Ended => return refused("MAINTENANCE_ENDED"),
            _ => {}
        }
        let record = Record::MaintEnded {
            reason: MaintenanceEnd::WriteEnd,
            writes: self.write_count(),
            ambiguous_write_ids: self.ambiguous_writes(),
        };
        if !self.gate.record(record) {
            return refused("STORAGE_FAILURE");
        }
        self.maintenance = Maintenance::Ended;
        self.maintenance_reason = Some(MaintenanceReason::Ended(MaintenanceEnd::WriteEnd));
        Doc::object(vec![
            ("result", Doc::str("OK")),
            ("maintenance", Doc::str(Maintenance::Ended.as_str())),
            ("gateState", Doc::str(self.gate.state().as_str())),
            ("writes", Doc::Int(i64::from(self.write_count()))),
            ("ambiguousWriteIds", ids_doc(&self.ambiguous_writes())),
        ])
    }
}

/// The floor a process restart of the I05 gate takes (HE-002C DESIGN §8): HELD when the journal's I07 rebuild finds an
/// ambiguous write, none otherwise (so none for a journal without I07 records).
pub(crate) fn write_floor(journal: &[Entry]) -> Option<State> {
    let (writes, _) = rebuild_writes(journal);
    writes.values().any(|entry| entry.classification == Some(Classification::IoAmbiguous)).then_some(State::Held)
}

/// The I07 part of a restart, from the journal alone (HE-002B DESIGN §6, N10): a WRITE_FORWARDED makes its write FORWARDED,
/// a WRITE_TERMINAL makes it TERMINAL with its classification (torn entries are skipped and a BIND resets nothing);
/// a write still FORWARDED at the end is IO_AMBIGUOUS. The maintenance reason is the last MAINT_ENDED reason, or
/// GATE_RESTART, when a MAINT_REQUESTED exists, and GENERATION_REBUILT otherwise.
fn rebuild_writes(journal: &[Entry]) -> (BTreeMap<u16, WriteEntry>, MaintenanceReason) {
    let mut writes = BTreeMap::new();
    let (mut begun, mut ended) = (false, None);
    for entry in journal {
        let Entry::Record(record) = entry else { continue };
        match record {
            Record::WriteForwarded { write_id, .. } => {
                writes.insert(*write_id, WriteEntry::FORWARDED);
            }
            Record::WriteTerminal { write_id, classification, .. } => {
                writes.insert(*write_id, WriteEntry::terminal(*classification));
            }
            Record::MaintRequested { .. } => begun = true,
            Record::MaintEnded { reason, .. } => ended = Some(*reason),
            _ => {}
        }
    }
    for entry in writes.values_mut() {
        if entry.status == WriteStatus::Forwarded {
            *entry = WriteEntry::terminal(Classification::IoAmbiguous);
        }
    }
    let reason = match (begun, ended) {
        (false, _) => MaintenanceReason::GenerationRebuilt,
        (true, Some(end)) => MaintenanceReason::Ended(end),
        (true, None) => MaintenanceReason::GateRestart,
    };
    (writes, reason)
}

#[cfg(test)]
mod tests {
    use super::*;
    use i05_protocol::json::{self, Object};

    const VECTORS: &str = include_str!("../../../contracts/i07-v3/vectors.json");
    const KINDS: &str = include_str!("../../../contracts/i07-v3/policy-kinds.json");
    const CHALLENGE: &str = "9999999999999999999999999999999999999999999999999999999999999999";
    const GENERATION: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn parse(text: &str) -> Value {
        json::parse(text).unwrap_or(Value::Null)
    }

    fn active_config() -> Value {
        parse(VECTORS).get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().unwrap_or(Value::Null)
    }

    fn with_member(config: &Value, key: &str, member: Option<Value>) -> Value {
        let mut object = config.as_object().cloned().unwrap_or_default();
        match member {
            Some(member) => object.insert(JStr::new(key), member),
            None => {
                object.remove(&JStr::new(key));
            }
        }
        Value::Object(object)
    }

    fn gate() -> PolicyGate {
        match PolicyGate::new(&active_config(), &parse(KINDS)) {
            Ok(gate) => gate,
            Err(error) => panic!("the ACTIVE configuration builds a PolicyGate: {error:?}"),
        }
    }

    fn object(members: Vec<(&str, Value)>) -> Value {
        let mut object = Object::new();
        for (key, value) in members {
            object.insert(JStr::new(key), value);
        }
        Value::Object(object)
    }

    /// The writer frame a correct writer sends next with this operation and payload.
    fn writer_frame(gate: &PolicyGate, operation: &str, payload: Value) -> PolicyEvent {
        PolicyEvent::WFrame(FrameInput::Value(object(vec![
            ("schemaVersion", Value::str(WRITER_FRAME_VERSION)),
            ("challenge", Value::str(CHALLENGE)),
            ("sequence", Value::int(gate.writer_next_sequence())),
            ("previousDigest", Value::str(gate.writer_last_digest())),
            ("direction", Value::str("WRITER_TO_GATE")),
            ("operation", Value::str(operation)),
            ("payload", payload),
        ])))
    }

    fn role_create(write_id: i64) -> Value {
        parse(&format!(
            "{{\"writeId\":{write_id},\"operation\":\"CREATE\",\"resource\":{{\"group\":\"rbac.authorization.k8s.io\",\
             \"version\":\"v1\",\"resource\":\"roles\"}},\"namespace\":\"planeon-qual\",\"name\":\"planeon-role\",\
             \"object\":{{\"apiVersion\":\"rbac.authorization.k8s.io/v1\",\"kind\":\"Role\",\"metadata\":\
             {{\"name\":\"planeon-role\",\"namespace\":\"planeon-qual\"}},\"rules\":[]}},\"prior\":null}}"
        ))
    }

    fn handle(gate: &mut PolicyGate, event: PolicyEvent) -> PolicyOutput {
        match gate.handle(event) {
            Ok(output) => output,
            Err(error) => panic!("event refused: {error:?}"),
        }
    }

    fn doc(output: &PolicyOutput) -> String {
        String::from_utf8_lossy(&output.to_doc().canonical()).into_owned()
    }

    /// A session with an open maintenance (the fence opens at once on an idle ACTIVE generation).
    fn open_gate() -> PolicyGate {
        let mut gate = gate();
        handle(&mut gate, PolicyEvent::WConnect { challenge: CHALLENGE.to_string() });
        let status = writer_frame(&gate, "MAINTENANCE_STATUS", object(Vec::new()));
        handle(&mut gate, status);
        let begin = writer_frame(&gate, "WRITE_BEGIN", object(vec![("expectedGeneration", Value::str(GENERATION))]));
        handle(&mut gate, begin);
        assert_eq!(gate.maintenance(), Maintenance::Open);
        gate
    }

    fn forwarded_gate() -> PolicyGate {
        let mut gate = open_gate();
        let write = writer_frame(&gate, "WRITE_OBJECT", role_create(1));
        assert_eq!(handle(&mut gate, write).kind, PolicyOutputKind::Forwarded(1));
        gate
    }

    fn last_tags(gate: &PolicyGate, count: usize) -> Vec<String> {
        let journal = gate.gate().journal();
        journal[journal.len().saturating_sub(count)..]
            .iter()
            .map(|entry| String::from_utf8_lossy(&entry.to_doc().canonical()).into_owned())
            .collect()
    }

    fn response(status: i64, uid: Option<&str>, version: Option<&str>, digest: &str) -> UpstreamOutcome {
        UpstreamOutcome::Response(UpstreamResponse {
            http_status: status,
            body_digest: digest.to_string(),
            uid: uid.map(str::to_string),
            resource_version: version.map(str::to_string),
        })
    }

    const DIGEST: &str = "sha256:8888888888888888888888888888888888888888888888888888888888888888";

    #[test]
    fn r13_a_request_at_the_sequence_bound_is_fatal_before_its_operation() {
        let mut gate = open_gate();
        let journal_before = gate.gate().journal().len();
        if let Some(session) = gate.session.as_mut() {
            session.next_sequence = MAX_SEQUENCE;
        }
        let write = writer_frame(&gate, "WRITE_OBJECT", role_create(1));
        let output = handle(&mut gate, write);
        assert_eq!(doc(&output), "{\"fatal\":\"RESPONSE_OUT_OF_BOUNDS\",\"maintenance\":\"ENDED\",\"sessionEnd\":\"FATAL\"}");
        // Nothing was forwarded: only the session end and the owning session's maintenance end were recorded.
        assert_eq!(gate.gate().journal().len(), journal_before + 2);
        assert_eq!(last_tags(&gate, 2), [
            "[\"WRITER_SESSION_ENDED\",\"FATAL\"]".to_string(),
            "[\"MAINT_ENDED\",\"SESSION_FATAL\",0,[]]".to_string(),
        ]);
        assert!(gate.writes.is_empty() && gate.pending.is_none() && gate.counters.writes_forwarded == 0);
        assert_eq!(gate.gate().state(), State::Closed, "the generation itself is untouched");
    }

    #[test]
    fn r13_a_response_outside_the_schema_after_the_operation_ends_the_session() {
        let mut gate = gate();
        handle(&mut gate, PolicyEvent::WConnect { challenge: CHALLENGE.to_string() });
        // A state the gate never reaches (PENDING maintenance on an ACTIVE generation) makes the status answer
        // violate the v3 W1 constraints.
        gate.maintenance = Maintenance::Pending;
        let status = writer_frame(&gate, "MAINTENANCE_STATUS", object(Vec::new()));
        let output = handle(&mut gate, status);
        assert_eq!(doc(&output), "{\"fatal\":\"RESPONSE_OUT_OF_BOUNDS\",\"maintenance\":\"PENDING\",\"sessionEnd\":\"FATAL\"}");
        assert!(output.response_frame.is_none() && gate.session.is_none());
    }

    #[test]
    fn r14_writer_frames_without_a_session_and_unknown_writes_are_invalid_events() {
        let mut gate = gate();
        let before = gate.snapshot();
        let frame = writer_frame(&gate, "MAINTENANCE_STATUS", object(Vec::new()));
        assert_eq!(gate.handle(frame).err(), Some(EventError("writer frame without a session")));
        assert_eq!(gate.handle(PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Lost }).err(),
                   Some(EventError("upstream outcome for a write the gate never forwarded")));
        assert_eq!(gate.snapshot(), before);
        // A loss and a peer change are always valid; without a session they answer {}.
        assert_eq!(doc(&handle(&mut gate, PolicyEvent::WChannelLost)), "{}");
        assert_eq!(doc(&handle(&mut gate, PolicyEvent::WPeerChanged)), "{}");
        assert_eq!(gate.snapshot(), before);
        let mut gate = forwarded_gate();
        let before = gate.snapshot();
        assert!(gate.handle(PolicyEvent::WUpstream { write_id: 2, outcome: UpstreamOutcome::Lost }).is_err());
        assert_eq!(gate.snapshot(), before);
    }

    #[test]
    fn r15_upstream_responses_outside_the_answer_patterns_change_nothing() {
        let mut gate = forwarded_gate();
        let before = gate.snapshot();
        let long_uid = "u".repeat(129);
        let long_version = "1".repeat(65);
        let refused = [
            response(99, None, None, DIGEST),
            response(600, None, None, DIGEST),
            response(-201, None, None, DIGEST),
            response(201, None, None, "sha256:888"),
            response(201, None, None, &DIGEST.to_uppercase()),
            response(201, Some(""), None, DIGEST),
            response(201, Some("a_b"), None, DIGEST),
            response(201, Some(&long_uid), None, DIGEST),
            response(201, None, Some("4-2"), DIGEST),
            response(201, None, Some(&long_version), DIGEST),
            response(201, Some("\n"), Some("42"), DIGEST),
        ];
        for outcome in refused {
            let description = format!("{outcome:?}");
            assert!(gate.handle(PolicyEvent::WUpstream { write_id: 1, outcome }).is_err(), "{description}");
            assert_eq!(gate.snapshot(), before, "{description}");
        }
        // The pattern bounds themselves are accepted and relayed inside the schema.
        let uid = "a-".repeat(64);
        let output = handle(&mut gate, PolicyEvent::WUpstream {
            write_id: 1,
            outcome: response(201, Some(&uid), Some(&"Z".repeat(64)), DIGEST),
        });
        let delivered = Classification::DeliveredResult;
        assert!(matches!(output.kind, PolicyOutputKind::Upstream { classification, response: Some(_) } if classification == delivered));
        assert!(output.response_frame.is_some());
        let mut gate = forwarded_gate();
        let output = handle(&mut gate, PolicyEvent::WUpstream { write_id: 1, outcome: response(599, None, None, DIGEST) });
        let ambiguous = Classification::IoAmbiguous;
        assert!(matches!(output.kind, PolicyOutputKind::Upstream { classification, response: Some(_) } if classification == ambiguous));
    }

    #[test]
    fn r16_policy_writer_is_required_exact_and_checked() {
        let kinds = parse(KINDS);
        let config = active_config();
        let writer = |namespace: Value, authority: Value| {
            object(vec![("qualificationNamespace", namespace), ("apiserverAuthority", authority)])
        };
        let refused = [
            with_member(&config, "policyWriter", None),
            with_member(&config, "policyWriter", Some(Value::str("planeon-qual"))),
            with_member(&config, "policyWriter", Some(object(vec![("qualificationNamespace", Value::str("planeon-qual"))]))),
            with_member(&config, "policyWriter", Some(object(vec![
                ("qualificationNamespace", Value::str("planeon-qual")),
                ("apiserverAuthority", Value::str("127.0.0.1:6443")),
                ("extra", Value::Null),
            ]))),
            with_member(&config, "policyWriter", Some(writer(Value::int(1), Value::str("127.0.0.1:6443")))),
            with_member(&config, "policyWriter", Some(writer(Value::str("Planeon"), Value::str("127.0.0.1:6443")))),
            with_member(&config, "policyWriter", Some(writer(Value::str("-planeon"), Value::str("127.0.0.1:6443")))),
            with_member(&config, "policyWriter", Some(writer(Value::str("planeon-"), Value::str("127.0.0.1:6443")))),
            with_member(&config, "policyWriter", Some(writer(Value::str(&"a".repeat(64)), Value::str("127.0.0.1:6443")))),
            with_member(&config, "policyWriter", Some(writer(Value::str(""), Value::str("127.0.0.1:6443")))),
            with_member(&config, "policyWriter", Some(writer(Value::str("planeon-qual"), Value::str("")))),
            with_member(&config, "policyWriter", Some(writer(Value::str("planeon-qual"), Value::str("127.0.0.1 :6443")))),
            with_member(&config, "policyWriter", Some(writer(Value::str("planeon-qual"), Value::str("127.0.0.1:6443\r\n")))),
            with_member(&config, "policyWriter", Some(writer(Value::str("planeon-qual"), Value::str(&"h".repeat(256))))),
            with_member(&config, "policyWriter", Some(writer(Value::str("planeon-qual"), Value::Null))),
        ];
        for (index, config) in refused.iter().enumerate() {
            assert!(matches!(PolicyGate::new(config, &kinds), Err(PolicyGateError::PolicyWriter(_))), "case {index}");
        }
        // HE-003C (DESIGN §6, Q-HE3C-1 (a) amended): an IP literal with port, at most 64 bytes, and loopback; the
        // longest accepted authorities are the longest loopback literals (no valid literal reaches 64 bytes).
        let longest_v6 = "[0000:0000:0000:0000:0000:0000:0000:0001]:65535";
        let longest_v4 = "127.255.255.255:65535";
        assert_eq!((longest_v6.len(), longest_v4.len()), (47, 21));
        for (authority, address) in [
            (longest_v6, InetAddress { ip: IpLiteral::V6(LOOPBACK_V6), port: 65535 }),
            (longest_v4, InetAddress { ip: IpLiteral::V4([127, 255, 255, 255]), port: 65535 }),
        ] {
            let longest = with_member(&config, "policyWriter",
                                      Some(writer(Value::str(&"a".repeat(63)), Value::str(authority))));
            match PolicyGate::new(&longest, &kinds) {
                Ok(gate) => {
                    assert_eq!(gate.writer().apiserver_authority, authority);
                    assert_eq!(gate.apiserver_address(), address, "parsed once: {authority}");
                }
                Err(error) => panic!("{authority} is accepted: {error:?}"),
            }
        }
        let longest_routable = "[ffff:ffff:ffff:ffff:ffff:ffff:255.255.255.255]:65535";
        let sixty_five = format!("127.0.0.1:{}", "6".repeat(55));
        assert_eq!((longest_routable.len(), sixty_five.len()), (53, 65));
        assert!(parse_authority(longest_routable).is_ok(), "the longest literal parse_authority accepts");
        for authority in ["kubernetes.default.svc:443", "localhost:6443", "127.0.0.1", "[::1]", "10.0.0.1:6443",
                          "128.0.0.1:6443", "[::2]:6443", longest_routable, "[::ffff:127.0.0.1]:6443",
                          "[0:0:0:0:0:ffff:7f00:1]:6443", sixty_five.as_str()] {
            let config = with_member(&config, "policyWriter", Some(writer(Value::str("planeon-qual"), Value::str(authority))));
            assert!(matches!(PolicyGate::new(&config, &kinds), Err(PolicyGateError::PolicyWriter(_))), "{authority}");
        }
        assert_eq!(gate().apiserver_address(), InetAddress { ip: IpLiteral::V4([127, 0, 0, 1]), port: 6443 });
        // The rest of the configuration still goes through the unchanged I05 Config, which refuses policyWriter itself.
        assert!(Config::from_value(&config).is_err());
        assert!(Config::from_value(&with_member(&config, "policyWriter", None)).is_ok());
        let unknown = with_member(&config, "brokerChallenges", Some(Value::Null));
        assert!(matches!(PolicyGate::new(&unknown, &kinds), Err(PolicyGateError::Config(_))));
        assert!(matches!(PolicyGate::new(&config, &Value::Null), Err(PolicyGateError::Kinds(_))));
    }

    #[test]
    fn r17_counters_saturate_and_writes_stay_within_the_write_id_bound() {
        let mut gate = open_gate();
        gate.counters = WriteCounters { sessions: u64::MAX, writes_forwarded: u64::MAX, writes_refused: u64::MAX };
        let refused = writer_frame(&gate, "WRITE_OBJECT", role_create(2));
        assert_eq!(doc(&handle(&mut gate, refused)), "{\"response\":{\"reason\":\"WRITE_ID_OUT_OF_ORDER\",\"result\":\"REFUSED\"}}");
        let write = writer_frame(&gate, "WRITE_OBJECT", role_create(1));
        assert_eq!(handle(&mut gate, write).kind, PolicyOutputKind::Forwarded(1));
        handle(&mut gate, PolicyEvent::WUpstream { write_id: 1, outcome: response(201, None, None, DIGEST) });
        handle(&mut gate, PolicyEvent::WChannelLost);
        handle(&mut gate, PolicyEvent::WConnect { challenge: CHALLENGE.to_string() });
        assert_eq!(gate.counters, WriteCounters { sessions: u64::MAX, writes_forwarded: u64::MAX, writes_refused: u64::MAX });
        let counters = String::from_utf8_lossy(&gate.counters.to_doc().canonical()).into_owned();
        assert_eq!(counters, format!("{{\"sessions\":{0},\"writesForwarded\":{0},\"writesRefused\":{0}}}", i64::MAX));
        // A write ID past 256 is outside the schema (a fatal frame), so the writes map never holds more than 256.
        let mut gate = open_gate();
        let write = writer_frame(&gate, "WRITE_OBJECT", role_create(257));
        assert_eq!(handle(&mut gate, write).kind, PolicyOutputKind::SessionEnd {
            how: SessionEnd::Fatal,
            maintenance: Maintenance::Ended,
            fatal: Some(WriterFatal::InvalidFrame(FrameError::F00)),
        });
        let mut gate = open_gate();
        for write_id in 1..=256u16 {
            gate.writes.insert(write_id, WriteEntry::terminal(Classification::DeliveredResult));
        }
        let status = writer_frame(&gate, "MAINTENANCE_STATUS", object(Vec::new()));
        let output = handle(&mut gate, status);
        assert!(doc(&output).contains("\"writes\":256"), "a full writes map still answers inside the schema");
        let write = writer_frame(&gate, "WRITE_OBJECT", role_create(256));
        assert!(doc(&handle(&mut gate, write)).contains("WRITE_ID_OUT_OF_ORDER"));
    }

    #[test]
    fn r18_an_upstream_answer_without_a_session_is_recorded_and_not_relayed() {
        let mut gate = forwarded_gate();
        // Unreachable through events (every session end aborts the outstanding write first); constructed here.
        gate.session = None;
        let output = handle(&mut gate, PolicyEvent::WUpstream { write_id: 1, outcome: UpstreamOutcome::Lost });
        assert_eq!(doc(&output), "{\"classification\":\"IO_AMBIGUOUS\",\"relayed\":false}");
        assert!(output.response_frame.is_none());
        assert_eq!(last_tags(&gate, 2), ["[\"WRITE_TERMINAL\",1,\"IO_AMBIGUOUS\",{}]".to_string(),
                                         "[\"MAINT_HELD\",\"HELD\"]".to_string()]);
        assert_eq!(gate.gate().state(), State::Held);
        assert!(gate.pending.is_none());
    }

    #[test]
    fn the_deferred_response_chains_to_the_write_object_frame() {
        let mut gate = open_gate();
        let raw = match writer_frame(&gate, "WRITE_OBJECT", role_create(1)) {
            PolicyEvent::WFrame(FrameInput::Value(value)) => json::canonical(&value).unwrap_or_default(),
            _ => Vec::new(),
        };
        let sequence = gate.writer_next_sequence();
        assert_eq!(handle(&mut gate, PolicyEvent::WFrame(FrameInput::Bytes(raw.clone()))).kind, PolicyOutputKind::Forwarded(1));
        let output = handle(&mut gate, PolicyEvent::WUpstream { write_id: 1, outcome: response(201, None, None, DIGEST) });
        let frame = output.response_frame.unwrap_or_default();
        let decoded = decode_frame(Datagram::Bytes(&frame), &gate.schema).unwrap_or(Value::Null);
        assert_eq!(decoded.get("previousDigest").and_then(Value::as_str), Some(sha256::prefixed(&raw).as_str()));
        assert_eq!(decoded.get("sequence").and_then(Value::as_int).and_then(|value| value.to_i64()), Some(sequence + 1));
        assert_eq!(gate.writer_next_sequence(), sequence + 2);
        assert_eq!(gate.writer_last_digest(), sha256::prefixed(&frame));
    }

    #[test]
    fn the_restart_floor_holds_only_with_an_ambiguous_write() {
        let mut gate = forwarded_gate();
        // A restart while the write is outstanding: the rebuild finds WRITE_FORWARDED without WRITE_TERMINAL.
        let output = handle(&mut gate, PolicyEvent::Base(Event::GateRestart));
        assert_eq!(doc(&output), "{\"maintenance\":\"ENDED\",\"restartState\":\"HELD\"}");
        assert_eq!(gate.maintenance_reason, Some(MaintenanceReason::GateRestart));
        assert!(gate.pending.is_none() && gate.session.is_none());
        let mut gate = open_gate();
        let output = handle(&mut gate, PolicyEvent::Base(Event::GateRestart));
        assert_eq!(doc(&output), "{\"maintenance\":\"ENDED\",\"restartState\":\"CLOSED\"}");
    }

    #[test]
    fn the_peer_deviation_reason_is_writer_only() {
        assert_eq!(Invalidation::WriterPeerDeviation.as_str(), "WRITER_PEER_DEVIATION");
        assert_eq!(crate::types::CloseReason::parse("WRITER_PEER_DEVIATION"), None);
    }
}
