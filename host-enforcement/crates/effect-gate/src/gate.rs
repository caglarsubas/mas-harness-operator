//! The I05 v3 gate state machine for one generation and its single channel.
//!
//! Every decision follows the I05 v1-v3 READMEs (Channel 1-6, Decisions 0-12, the durable journal and the failure
//! marker); where they are silent the pinned model is the specification (MODEL_DEFINED.md lists each point). The gate
//! never panics: arithmetic saturates or is checked, lookups are fallible, and an event outside the model's
//! preconditions is refused with [`EventError`] without any state change.
//!
//! The I07 PolicyGate (`policy_gate`) owns a `Gate` and reaches its journal, fence, drain, deny and urgent-close steps
//! through the `pub(crate)` methods below; the public I05 API is unchanged by it.
//!
//! HE-002C puts the journal and the failure marker behind `store::Stores`: `Gate::new` keeps HE-002's in-memory pair,
//! `Gate::create` starts a new generation on file stores and `Gate::open` is the process restart (DESIGN §8).
//!
//! HE-003A adds what the channel substrate reads (`channel_state`, `bound_run`, `connection_open`, none of which
//! changes any state) and the R10-defined `Event::AnswerLate` (HE-003A DESIGN §5.1, §5.7); no existing event's answer
//! changes.

use std::collections::{BTreeMap, BTreeSet};

use i05_protocol::json::{Doc, Value};
use i05_protocol::{
    decode_frame, frame, render_request, sha256, template_digest, Datagram, FrameError, Schema, Verb, FRAME_VERSION,
    ZERO_DIGEST,
};

use crate::config::{Config, PriorBindings};
use crate::file_store::FileStores;
use crate::journal::{journal_doc, ChannelEnd, Entry, Record, TerminalDetails};
use crate::store::{Appended, MemoryStores, Stores};
use crate::types::{Classification, CloseReason, DrainAnswer, FatalReason, Invalidation, State};

/// A connection stamp: the action a server connection was accepted for (C3).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub execution_id: String,
    pub action_id: u16,
}

/// A broker frame as it reaches the gate.
#[derive(Clone, Debug)]
pub enum FrameInput {
    /// A received datagram (production): `decode_frame`, then the frame checks.
    Bytes(Vec<u8>),
    /// A datagram that is not a byte string (the vectors' bytearray and text inputs): F07.
    NotBytes,
    /// A frame value (the contract's replay form): `check_frame`, then the frame checks.
    Value(Value),
}

/// An upstream response to a forwarded request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct UpstreamResponse {
    pub http_status: i64,
    pub body_digest: String,
    pub uid: Option<String>,
    pub resource_version: Option<String>,
}

/// One event: a broker frame, an I04 connection event, an upstream event, an I07 drain request, a lifetime or channel
/// event, a restart, or one of the contract's storage test injections.
#[derive(Clone, Debug)]
pub enum Event {
    Frame(FrameInput),
    Backlog { conn: String },
    Accept { conn: String },
    Request { conn: String, certificate_digest: String, head: String, body_digest: Option<String> },
    UpstreamResponse { conn: String, response: UpstreamResponse },
    UpstreamLost { conn: String },
    /// The 900-second bound of a forwarded exchange expired (Decision 12).
    UpstreamTimeout { conn: String },
    StorageFailNext { torn: bool },
    MarkerFailNext,
    StorageFailAfter { after: u64 },
    DrainRequest,
    Expire,
    ChannelLost,
    SecondChannel,
    PeerChanged,
    GateRestart,
    /// R10-defined (HE-003A DESIGN §5.7, owner decision Q-HE3A-2 (b)): the substrate did not send an answer because
    /// the 2-second bound had passed. Fatal `ANSWER_LATE` (HELD) on an OPEN channel; an `EventError` otherwise.
    AnswerLate,
}

/// The model's channel, as the substrate reads it (HE-003A DESIGN §5.1).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelState {
    Unopened,
    Open,
    Closed,
}

/// The execution the last BIND bound, as the substrate reads it (HE-003A DESIGN §5.1, §5.6): its run nonce keys the
/// signed lifetime, and `expired` is set once EXPIRE was handled for it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BoundRun {
    pub execution_id: String,
    pub run_nonce: String,
    pub expired: bool,
}

/// An event outside the model's preconditions (the pinned model raises there); the gate state is unchanged.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EventError(pub &'static str);

/// Why a second channel connection is refused.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelRefusal {
    ChannelExists,
    GenerationChannelUsed,
}

/// Why a server connection is closed without forwarding.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ConnectionRefusal {
    ConnectionClosed,
    ProtocolViolation,
    NotActive,
    ExecutionExpired,
    StampNone,
    StampMismatch,
    AlreadyConsumed,
    CertificateMismatch,
    RequestMismatch,
    StorageFailure,
}

impl ConnectionRefusal {
    pub fn as_str(self) -> &'static str {
        match self {
            ConnectionRefusal::ConnectionClosed => "CONNECTION_CLOSED",
            ConnectionRefusal::ProtocolViolation => "PROTOCOL_VIOLATION",
            ConnectionRefusal::NotActive => "NOT_ACTIVE",
            ConnectionRefusal::ExecutionExpired => "EXECUTION_EXPIRED",
            ConnectionRefusal::StampNone => "STAMP_NONE",
            ConnectionRefusal::StampMismatch => "STAMP_MISMATCH",
            ConnectionRefusal::AlreadyConsumed => "ALREADY_CONSUMED",
            ConnectionRefusal::CertificateMismatch => "CERTIFICATE_MISMATCH",
            ConnectionRefusal::RequestMismatch => "REQUEST_MISMATCH",
            ConnectionRefusal::StorageFailure => "STORAGE_FAILURE",
        }
    }

    /// The refusals the `correlationRefusals` counter counts.
    fn is_correlation(self) -> bool {
        matches!(
            self,
            ConnectionRefusal::StampNone
                | ConnectionRefusal::CertificateMismatch
                | ConnectionRefusal::RequestMismatch
                | ConnectionRefusal::StampMismatch
                | ConnectionRefusal::AlreadyConsumed
        )
    }
}

/// What an event produced.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OutputKind {
    Nothing,
    Response(Doc),
    Fatal(FatalReason),
    RefusedChannel(ChannelRefusal),
    Stamp(Option<Stamp>),
    Forward { action_id: u16 },
    Close(ConnectionRefusal),
    Upstream { classification: Classification, relayed: bool, aborted: bool },
    LateUpstream,
    ChannelEnd(ChannelEnd),
    RestartState(State),
    Denied(Vec<u16>),
}

/// An event's output: what it produced, the I07 drain answer when this event settled (or answered) a drain, and for a
/// response the exact frame bytes to send.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Output {
    pub kind: OutputKind,
    pub drain: Option<DrainAnswer>,
    pub response_frame: Option<Vec<u8>>,
}

impl Output {
    fn of(kind: OutputKind) -> Output {
        Output { kind, drain: None, response_frame: None }
    }

    /// The contract's output object, e.g. `{"decision": "FORWARD", "actionId": 1}`.
    pub fn to_doc(&self) -> Doc {
        let mut members: Vec<(&str, Doc)> = match &self.kind {
            OutputKind::Nothing => Vec::new(),
            OutputKind::Response(payload) => vec![("response", payload.clone())],
            OutputKind::Fatal(reason) => vec![("fatal", Doc::str(reason.as_str()))],
            OutputKind::RefusedChannel(refusal) => vec![(
                "refusedChannel",
                Doc::str(match refusal {
                    ChannelRefusal::ChannelExists => "CHANNEL_EXISTS",
                    ChannelRefusal::GenerationChannelUsed => "GENERATION_CHANNEL_USED",
                }),
            )],
            OutputKind::Stamp(stamp) => vec![("stamp", stamp.as_ref().map_or(Doc::Null, stamp_doc))],
            OutputKind::Forward { action_id } => {
                vec![("decision", Doc::str("FORWARD")), ("actionId", Doc::Int(i64::from(*action_id)))]
            }
            OutputKind::Close(reason) => vec![("decision", Doc::str("CLOSE")), ("reason", Doc::str(reason.as_str()))],
            OutputKind::Upstream { classification, relayed, aborted } => {
                let mut members = vec![("classification", Doc::str(classification.as_str())), ("relayed", Doc::Bool(*relayed))];
                if *aborted {
                    members.push(("aborted", Doc::str("UPSTREAM_TIMEOUT")));
                }
                members
            }
            OutputKind::LateUpstream => vec![("lateUpstream", Doc::str("NOT_RELAYED"))],
            OutputKind::ChannelEnd(end) => vec![(
                "channelEnd",
                Doc::str(match end {
                    ChannelEnd::BeforeFirstFrame => "UNUSED",
                    ChannelEnd::Orderly => "ORDERLY",
                }),
            )],
            OutputKind::RestartState(state) => vec![("restartState", Doc::str(state.as_str()))],
            OutputKind::Denied(ids) => vec![("denied", ids_doc(ids))],
        };
        if let Some(answer) = self.drain {
            members.push(("drain", Doc::str(answer.as_str())));
        }
        Doc::object(members)
    }
}

fn stamp_doc(stamp: &Stamp) -> Doc {
    Doc::object(vec![("executionId", Doc::str(&stamp.execution_id)), ("actionId", Doc::Int(i64::from(stamp.action_id)))])
}

fn ids_doc(ids: &[u16]) -> Doc {
    Doc::Array(ids.iter().map(|id| Doc::Int(i64::from(*id))).collect())
}

fn count_doc(count: u64) -> Doc {
    Doc::Int(i64::try_from(count).unwrap_or(i64::MAX))
}

/// The gate's counters (GENERATION_STATUS), observations of gate state.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    pub stamps_issued: u64,
    pub consumptions: u64,
    pub correlation_refusals: u64,
    pub flush_closures: u64,
}

impl Counters {
    fn to_doc(&self) -> Doc {
        Doc::object(vec![
            ("stampsIssued", count_doc(self.stamps_issued)),
            ("consumptions", count_doc(self.consumptions)),
            ("correlationRefusals", count_doc(self.correlation_refusals)),
            ("flushClosures", count_doc(self.flush_closures)),
        ])
    }
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Channel {
    Unopened,
    Open,
    Closed,
}

#[derive(Copy, Clone, Debug, PartialEq, Eq)]
enum Status {
    Armed,
    Consumed,
    Terminal,
}

impl Status {
    fn as_str(self) -> &'static str {
        match self {
            Status::Armed => "ARMED",
            Status::Consumed => "CONSUMED",
            Status::Terminal => "TERMINAL",
        }
    }
}

/// What ARM_ACTION armed (absent for an action rebuilt from the journal after a restart).
#[derive(Clone, Debug)]
struct Armed {
    verb: Verb,
    manifest_digest: String,
    uid: Option<String>,
}

#[derive(Clone, Debug)]
struct Delivered {
    http_status: i64,
    result_digest: String,
    observed_uid: Option<String>,
    observed_resource_version: Option<String>,
}

#[derive(Clone, Debug)]
struct Action {
    id: u16,
    status: Status,
    classification: Option<Classification>,
    after_invalidation: bool,
    sealed: bool,
    armed: Option<Armed>,
    conn: Option<String>,
    delivered: Option<Delivered>,
}

impl Action {
    fn rebuilt(id: u16) -> Action {
        Action {
            id,
            status: Status::Armed,
            classification: None,
            after_invalidation: false,
            sealed: false,
            armed: None,
            conn: None,
            delivered: None,
        }
    }

    fn settled(&self) -> bool {
        self.status == Status::Terminal && self.sealed
    }
}

#[derive(Clone, Debug)]
struct Connection {
    stamp: Option<Stamp>,
    open: bool,
    requests: u64,
    consumed: bool,
}

#[derive(Clone, Debug)]
struct Bound {
    execution_id: String,
    run_nonce: String,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum MutationKey {
    Create(String),
    Delete(String),
}

/// A typed broker request (the frame passed the schema, so its payload is the operation's request variant).
enum Request {
    GenerationStatus,
    Bind(BindRequest),
    Arm(ArmRequest),
    Outcome { execution_id: String, action_id: u16 },
    Close(CloseReason),
}

struct BindRequest {
    execution_id: String,
    binding_digest: String,
    reservation_digest: String,
    run_nonce: String,
    case_id: String,
    request_digest: String,
    dispatch_generation: String,
    server_certificate_digest: String,
    worker_pid: i64,
    worker_start_ticks: i64,
    peer_qualification_digest: String,
}

struct ArmRequest {
    execution_id: String,
    action_id: u16,
    verb: Verb,
    manifest_digest: String,
    request_template_digest: String,
    recorded_uid: Option<String>,
}

fn member_text(payload: &Value, key: &str) -> Option<String> {
    payload.get(key).and_then(Value::as_str).map(str::to_string)
}

fn member_int(payload: &Value, key: &str) -> Option<i64> {
    payload.get(key).and_then(Value::as_int).and_then(|value| value.to_i64())
}

fn member_id(payload: &Value, key: &str) -> Option<u16> {
    member_int(payload, key).and_then(|value| u16::try_from(value).ok())
}

impl Request {
    fn parse(operation: &str, payload: &Value) -> Option<Request> {
        Some(match operation {
            "GENERATION_STATUS" => Request::GenerationStatus,
            "BIND_EXECUTION" => Request::Bind(BindRequest {
                execution_id: member_text(payload, "executionId")?,
                binding_digest: member_text(payload, "bindingDigest")?,
                reservation_digest: member_text(payload, "reservationDigest")?,
                run_nonce: member_text(payload, "runNonce")?,
                case_id: member_text(payload, "caseId")?,
                request_digest: member_text(payload, "requestDigest")?,
                dispatch_generation: member_text(payload, "dispatchGeneration")?,
                server_certificate_digest: member_text(payload, "serverCertificateDigest")?,
                worker_pid: member_int(payload, "workerPid")?,
                worker_start_ticks: member_int(payload, "workerStartTicks")?,
                peer_qualification_digest: member_text(payload, "peerQualificationDigest")?,
            }),
            "ARM_ACTION" => Request::Arm(ArmRequest {
                execution_id: member_text(payload, "executionId")?,
                action_id: member_id(payload, "actionId")?,
                verb: Verb::parse(payload.get("verb")?.as_str()?)?,
                manifest_digest: member_text(payload, "manifestDigest")?,
                request_template_digest: member_text(payload, "requestTemplateDigest")?,
                recorded_uid: match payload.get("recordedUid")? {
                    Value::Null => None,
                    other => Some(other.as_str()?.to_string()),
                },
            }),
            "ACTION_OUTCOME" => Request::Outcome {
                execution_id: member_text(payload, "executionId")?,
                action_id: member_id(payload, "actionId")?,
            },
            "CLOSE_GENERATION" => Request::Close(CloseReason::parse(payload.get("reason")?.as_str()?)?),
            _ => return None,
        })
    }
}

/// An operation's result: a response payload, or a fatal channel close it already performed.
enum Reply {
    Payload(Doc),
    Fatal(Output),
}

fn refused(reason: &str) -> Reply {
    Reply::Payload(Doc::object(vec![("result", Doc::str("REFUSED")), ("reason", Doc::str(reason))]))
}

/// Applies a rebuilt record to its action. A record for an action no ARM record introduced is unreachable from the
/// gate's own journal; a rebuild that meets one restarts HELD (R10-defined).
fn update(actions: &mut BTreeMap<u16, Action>, inconsistent: &mut bool, id: u16, apply: impl FnOnce(&mut Action)) {
    match actions.get_mut(&id) {
        Some(action) => apply(action),
        None => *inconsistent = true,
    }
}

/// Why a gate could not be created.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum GateError {
    Schema(String),
    /// `create` on stores that do not hold a new generation: this opening did not create the journal file or append
    /// the index entry, the journal is not empty, or a marker file exists (HE-002C DESIGN §8). Use `open`.
    NotFresh,
    /// The stores belong to another generation than the configuration.
    GenerationMismatch,
}

/// Adds every binding of `from` to `into` (owner decision Q-HE2C-2 (a): the union, so it refuses more, never less).
fn unite(into: &mut PriorBindings, from: &PriorBindings) {
    into.execution_ids.extend(from.execution_ids.iter().cloned());
    into.run_nonces.extend(from.run_nonces.iter().cloned());
    into.manifest_digests.extend(from.manifest_digests.iter().cloned());
    into.manifest_identities.extend(from.manifest_identities.iter().cloned());
}

/// What a process restart derives from the journal alone (HE-002C DESIGN §8): the execution of the last BIND, whether
/// an EXPIRED record for it follows that BIND, and every execution ID and run nonce this generation bound.
struct Derived {
    bound: Option<Bound>,
    expired: bool,
    bound_ids: Vec<String>,
    bound_nonces: Vec<String>,
}

impl Derived {
    fn from_journal(entries: &[Entry]) -> Derived {
        let mut derived = Derived { bound: None, expired: false, bound_ids: Vec::new(), bound_nonces: Vec::new() };
        for entry in entries {
            match entry {
                Entry::Record(Record::Bind { execution_id, run_nonce, .. }) => {
                    derived.bound = Some(Bound { execution_id: execution_id.clone(), run_nonce: run_nonce.clone() });
                    derived.expired = false;
                    derived.bound_ids.push(execution_id.clone());
                    derived.bound_nonces.push(run_nonce.clone());
                }
                Entry::Record(Record::Expired { execution_id }) => {
                    if derived.bound.as_ref().is_some_and(|bound| bound.execution_id == *execution_id) {
                        derived.expired = true;
                    }
                }
                _ => {}
            }
        }
        derived
    }
}

/// The I05 gate for one generation.
pub struct Gate {
    config: Config,
    schema: Schema,
    state: State,
    drain_pending: bool,
    channel: Channel,
    challenge: Option<String>,
    next_sequence: i64,
    last_digest: String,
    bound: Option<Bound>,
    bound_ids: Vec<String>,
    bound_nonces: Vec<String>,
    expired: bool,
    actions: BTreeMap<u16, Action>,
    mutation_keys: BTreeSet<MutationKey>,
    created_uids: BTreeMap<String, BTreeSet<String>>,
    backlog: Vec<String>,
    connections: BTreeMap<String, Connection>,
    counters: Counters,
    stores: Box<dyn Stores>,
    failing: bool,
}

impl Gate {
    /// A gate for a validated configuration, checking frames against the embedded I05 v3 schema, on in-memory stores.
    pub fn new(config: Config) -> Result<Gate, GateError> {
        Gate::with_stores(config, Box::new(MemoryStores::default()))
    }

    /// A new generation on file stores: allowed only when this opening created the journal file and appended the
    /// generation's index entry, the journal is empty and no marker file exists; the gate then starts as `new` does,
    /// with the earlier generations' bindings united into the configuration's.
    pub fn create(config: Config, stores: FileStores) -> Result<Gate, GateError> {
        if config.generation != stores.generation() {
            return Err(GateError::GenerationMismatch);
        }
        if !(stores.journal_created() && stores.indexed_now() && stores.entries().is_empty() && !stores.marker_file_exists()) {
            return Err(GateError::NotFresh);
        }
        Gate::with_stores(config, Box::new(stores))
    }

    /// The I05 process restart: the gate as the stores' files leave it, restarted once (RESTARTED appended), with a
    /// HELD floor when the journal holds an ambiguous I07 write; returns the restart's `RestartState` output.
    pub fn open(config: Config, stores: FileStores) -> Result<(Gate, Output), GateError> {
        let floor = crate::policy_gate::write_floor(stores.entries());
        let mut gate = Gate::reopened(config, stores)?;
        let output = gate.restart_with(floor);
        Ok((gate, output))
    }

    /// The gate on reopened file stores, not yet restarted (PolicyGate's process restart restarts it itself).
    pub(crate) fn reopened(config: Config, stores: FileStores) -> Result<Gate, GateError> {
        if config.generation != stores.generation() {
            return Err(GateError::GenerationMismatch);
        }
        Gate::with_stores(config, Box::new(stores))
    }

    /// A gate on `stores` without a restart: the bound execution, its expiry and this generation's bound IDs and
    /// nonces are derived from the mirror (nothing for an empty one), the stores' earlier bindings are united into
    /// the configuration's, and everything else starts as for a new generation.
    pub(crate) fn with_stores(mut config: Config, stores: Box<dyn Stores>) -> Result<Gate, GateError> {
        let schema = i05_protocol::i05_v3_schema().map_err(|error| GateError::Schema(error.0))?;
        unite(&mut config.prior, stores.prior_bindings());
        let derived = Derived::from_journal(stores.entries());
        Ok(Gate {
            state: config.state,
            config,
            schema,
            drain_pending: false,
            channel: Channel::Unopened,
            challenge: None,
            next_sequence: 1,
            last_digest: ZERO_DIGEST.to_string(),
            bound: derived.bound,
            bound_ids: derived.bound_ids,
            bound_nonces: derived.bound_nonces,
            expired: derived.expired,
            actions: BTreeMap::new(),
            mutation_keys: BTreeSet::new(),
            created_uids: BTreeMap::new(),
            backlog: Vec::new(),
            connections: BTreeMap::new(),
            counters: Counters::default(),
            stores,
            failing: false,
        })
    }

    pub fn state(&self) -> State {
        self.state
    }

    /// The sequence the next broker frame must carry.
    pub fn next_sequence(&self) -> i64 {
        self.next_sequence
    }

    /// The digest the next broker frame's `previousDigest` must carry.
    pub fn last_digest(&self) -> &str {
        &self.last_digest
    }

    pub fn journal(&self) -> &[Entry] {
        self.stores.entries()
    }

    /// The channel's state (read only; HE-003A DESIGN §5.1). After [`Gate::open`] it is CLOSED.
    pub fn channel_state(&self) -> ChannelState {
        match self.channel {
            Channel::Unopened => ChannelState::Unopened,
            Channel::Open => ChannelState::Open,
            Channel::Closed => ChannelState::Closed,
        }
    }

    /// The bound execution and whether it has expired (read only; HE-003A DESIGN §5.1). After [`Gate::open`] both
    /// come from the journal's rebuild.
    pub fn bound_run(&self) -> Option<BoundRun> {
        self.bound.as_ref().map(|bound| BoundRun {
            execution_id: bound.execution_id.clone(),
            run_nonce: bound.run_nonce.clone(),
            expired: self.expired,
        })
    }

    /// Whether the I04 connection `conn` is one the gate holds open (read only; HE-003A DESIGN §6).
    pub fn connection_open(&self, conn: &str) -> bool {
        self.connections.get(conn).is_some_and(|connection| connection.open)
    }

    /// `journalDigest`: the SHA-256 of the canonical journal.
    pub fn journal_digest(&self) -> String {
        sha256::prefixed(&journal_doc(self.stores.entries()).canonical())
    }

    /// Applies one event, then settles any I07 drain still waiting for its fence (M28); the output of the event that
    /// decides the fence carries the drain answer.
    pub fn handle(&mut self, event: Event) -> Result<Output, EventError> {
        let mut output = self.dispatch(event)?;
        if let Some(answer) = self.settle_drain() {
            output.drain = Some(answer);
        }
        Ok(output)
    }

    /// Answers the A3 fence question for a pending I07 write, using nothing but the gate's own state.
    pub fn fence(&self) -> DrainAnswer {
        if self.state == State::Held {
            return DrainAnswer::Held;
        }
        if !matches!(self.state, State::Closed | State::Invalidated) || self.in_flight().is_some() {
            return DrainAnswer::Pending;
        }
        DrainAnswer::Open
    }

    /// The contract's final snapshot: state, drain, channel, bound execution, actions, connections, counters, journal
    /// and failure marker.
    pub fn snapshot(&self) -> Doc {
        let actions = self
            .actions
            .values()
            .map(|action| {
                (action.id.to_string(), Doc::object(vec![
                    ("status", Doc::str(action.status.as_str())),
                    ("classification", Doc::opt_str(action.classification.map(Classification::as_str))),
                    ("admittedBeforeInvalidation", Doc::Bool(action.after_invalidation)),
                    ("sealed", Doc::Bool(action.sealed)),
                ]))
            })
            .collect();
        let connections = self
            .connections
            .iter()
            .map(|(name, connection)| (name.clone(), Doc::str(if connection.open { "OPEN" } else { "CLOSED" })))
            .collect();
        Doc::object(vec![
            ("state", Doc::str(self.state.as_str())),
            ("drainPending", Doc::Bool(self.drain_pending)),
            ("channel", Doc::str(match self.channel {
                Channel::Unopened => "UNOPENED",
                Channel::Open => "OPEN",
                Channel::Closed => "CLOSED",
            })),
            ("boundExecutionId", Doc::opt_str(self.bound.as_ref().map(|bound| bound.execution_id.as_str()))),
            ("actions", Doc::Object(actions)),
            ("connections", Doc::Object(connections)),
            ("counters", self.counters.to_doc()),
            ("journal", journal_doc(self.stores.entries())),
            ("failureMarker", self.stores.marker_doc()),
        ])
    }

    // ------------------------------------------------------------------------------------------ journal and marker

    /// Appends one journal record and reports whether it is durable. When the write fails, the storage-failure path
    /// of M20 has already run by the time this returns, so callers only decide how to refuse or report it.
    pub(crate) fn record(&mut self, record: Record) -> bool {
        if self.stores.append(record) == Appended::Durable {
            return true;
        }
        self.storage_failure();
        false
    }

    fn storage_failure(&mut self) {
        if self.failing {
            return;
        }
        self.failing = true;
        self.state = State::Held;
        self.mark_in_flight_after_invalidation();
        let generation = self.config.generation.clone();
        // The marker's own result changes nothing here: a failed marker write is what the disclosed residual covers.
        let _marker_written = self.stores.write_marker(&generation, CloseReason::StorageFailure.as_str());
        self.record(Record::Invalidated { reason: Invalidation::Close(CloseReason::StorageFailure), state: State::Held });
        self.deny_armed();
        self.failing = false;
    }

    /// GATE_RESTART (M30): action statuses and the generation state are recomputed only from what the journal and
    /// the failure marker hold; the in-memory execution data that M30 lists is left as it is.
    fn rebuild(&mut self) -> State {
        let mut actions: BTreeMap<u16, Action> = BTreeMap::new();
        let mut state = State::Held;
        let mut torn = false;
        let mut inconsistent = false;
        for entry in self.stores.entries() {
            let record = match entry {
                Entry::Torn => {
                    torn = true;
                    continue;
                }
                Entry::Record(record) => record,
            };
            match record {
                Record::Invalidated { state: recorded, .. }
                | Record::Closed { state: recorded, .. }
                | Record::Drained { state: recorded }
                | Record::Restarted { state: recorded } => state = *recorded,
                _ => {}
            }
            match record {
                Record::Bind { .. } => actions.clear(),
                Record::Arm { action_id, .. } => {
                    actions.insert(*action_id, Action::rebuilt(*action_id));
                }
                Record::Consumed { action_id } => update(&mut actions, &mut inconsistent, *action_id, |action| {
                    action.status = Status::Consumed;
                    action.after_invalidation = false;
                }),
                Record::Invalidated { .. } | Record::Expired { .. } => {
                    for action in actions.values_mut().filter(|action| action.status == Status::Consumed) {
                        action.after_invalidation = true;
                    }
                }
                Record::Terminal { action_id, classification, after_invalidation, .. } => {
                    update(&mut actions, &mut inconsistent, *action_id, |action| {
                        action.status = Status::Terminal;
                        action.classification = Some(*classification);
                        action.after_invalidation = *after_invalidation;
                    })
                }
                Record::Denied { action_id } => update(&mut actions, &mut inconsistent, *action_id, |action| {
                    action.status = Status::Terminal;
                    action.classification = Some(Classification::NotForwarded);
                }),
                Record::Sealed { action_id, classification, after_invalidation } => {
                    update(&mut actions, &mut inconsistent, *action_id, |action| {
                        action.status = Status::Terminal;
                        action.classification = Some(*classification);
                        action.sealed = true;
                        action.after_invalidation = *after_invalidation && *classification != Classification::NotForwarded;
                    })
                }
                _ => {}
            }
        }
        let clean = actions
            .values()
            .all(|action| action.settled() && action.classification != Some(Classification::IoAmbiguous));
        for action in actions.values_mut() {
            match action.status {
                // Consumed but never given a TERMINAL record, so its outcome is unknown: IO_AMBIGUOUS, treated as
                // admitted ahead of the restart (C6, base §5).
                Status::Consumed => {
                    action.status = Status::Terminal;
                    action.classification = Some(Classification::IoAmbiguous);
                    action.after_invalidation = true;
                }
                Status::Armed => {
                    action.status = Status::Terminal;
                    action.classification = Some(Classification::NotForwarded);
                }
                Status::Terminal => {}
            }
        }
        self.actions = actions;
        if self.stores.marker_present() || torn || inconsistent {
            return State::Held;
        }
        if clean && matches!(state, State::Closed | State::Invalidated) { state } else { State::Held }
    }

    // ------------------------------------------------------------------------------------------ helpers

    fn armed(&self) -> Option<&Action> {
        self.actions.values().find(|action| action.status == Status::Armed)
    }

    fn in_flight(&self) -> Option<&Action> {
        self.actions.values().find(|action| action.status == Status::Consumed)
    }

    fn mark_in_flight_after_invalidation(&mut self) {
        if let Some(action) = self.actions.values_mut().find(|action| action.status == Status::Consumed) {
            action.after_invalidation = true;
        }
    }

    pub(crate) fn armed_ids(&self) -> Vec<u16> {
        self.actions.values().filter(|action| action.status == Status::Armed).map(|action| action.id).collect()
    }

    /// The consumed action that has no TERMINAL record yet, if any (the status answers' `inFlightActionId`).
    pub(crate) fn in_flight_id(&self) -> Option<u16> {
        self.in_flight().map(|action| action.id)
    }

    /// The generation this gate serves.
    pub(crate) fn generation(&self) -> &str {
        &self.config.generation
    }

    /// A direct state change, without a record of its own (PolicyGate holds the generation this way: N11, N12, N15).
    pub(crate) fn set_state(&mut self, state: State) {
        self.state = state;
    }

    /// Of the action ids that were ARMED when the current operation started, those that are now TERMINAL (M21).
    pub(crate) fn denied_since(&self, armed: &[u16]) -> Vec<u16> {
        armed
            .iter()
            .copied()
            .filter(|id| self.actions.get(id).is_some_and(|action| action.status == Status::Terminal))
            .collect()
    }

    fn stamp_of(&self, action_id: u16) -> Option<Stamp> {
        self.bound.as_ref().map(|bound| Stamp { execution_id: bound.execution_id.clone(), action_id })
    }

    /// Closes every open connection the predicate selects; each counts as a flush closure.
    fn close_connections(&mut self, select: impl Fn(&Connection) -> bool) -> u64 {
        let mut closed = 0u64;
        for connection in self.connections.values_mut() {
            if connection.open && select(connection) {
                connection.open = false;
                closed = closed.saturating_add(1);
            }
        }
        self.counters.flush_closures = self.counters.flush_closures.saturating_add(closed);
        closed
    }

    fn close_unconsumed_stamped(&mut self, stamp: Option<Stamp>) {
        if let Some(stamp) = stamp {
            self.close_connections(|connection| connection.stamp.as_ref() == Some(&stamp) && !connection.consumed);
        }
    }

    /// The deny step of M21 for each action still ARMED: close its stamped connections first, then mark it
    /// NOT_FORWARDED and try to journal DENIED. A failed DENIED write does not undo the in-memory denial.
    fn deny_armed(&mut self) {
        for id in self.armed_ids() {
            if !self.actions.get(&id).is_some_and(|action| action.status == Status::Armed) {
                continue;
            }
            self.close_unconsumed_stamped(self.stamp_of(id));
            if let Some(action) = self.actions.get_mut(&id) {
                action.status = Status::Terminal;
                action.classification = Some(Classification::NotForwarded);
            }
            self.record(Record::Denied { action_id: id });
        }
    }

    /// A4: close A1 first (in memory), record the invalidation, deny unconsumed actions.
    pub(crate) fn urgent(&mut self, state: State, reason: Invalidation) {
        if self.state != State::Held {
            self.state = state;
        }
        self.mark_in_flight_after_invalidation();
        self.record(Record::Invalidated { reason, state: self.state });
        self.deny_armed();
    }

    fn fatal(&mut self, reason: FatalReason) -> Output {
        self.channel = Channel::Closed;
        self.urgent(State::Held, Invalidation::Fatal(reason));
        self.state = State::Held;
        Output::of(OutputKind::Fatal(reason))
    }

    fn orderly(&self) -> bool {
        matches!(self.state, State::Closed | State::Invalidated)
            && self.in_flight().is_none()
            && self.actions.values().all(Action::settled)
    }

    fn any_ambiguous(&self) -> bool {
        self.actions.values().any(|action| action.classification == Some(Classification::IoAmbiguous))
    }

    /// Resolves a waiting I07 drain (M28). With nothing in flight, DRAINING turns into CLOSED, or HELD when some
    /// action is IO_AMBIGUOUS; once the fence is decided, DRAINED is journaled and its answer returned.
    pub(crate) fn settle_drain(&mut self) -> Option<DrainAnswer> {
        if !self.drain_pending {
            return None;
        }
        if self.state == State::Draining && self.in_flight().is_none() {
            self.state = if self.any_ambiguous() { State::Held } else { State::Closed };
        }
        if self.fence() == DrainAnswer::Pending {
            return None;
        }
        self.drain_pending = false;
        self.record(Record::Drained { state: self.state });
        Some(self.fence())
    }

    // ------------------------------------------------------------------------------------------ events

    fn dispatch(&mut self, event: Event) -> Result<Output, EventError> {
        Ok(match event {
            Event::Frame(input) => self.frame(input),
            Event::Backlog { conn } => {
                self.backlog.push(conn);
                Output::of(OutputKind::Nothing)
            }
            Event::Accept { conn } => self.accept(conn)?,
            Event::Request { conn, certificate_digest, head, body_digest } => {
                self.request(&conn, &certificate_digest, &head, body_digest.as_deref())?
            }
            Event::UpstreamResponse { conn, response } => self.upstream(&conn, Some(response))?,
            Event::UpstreamLost { conn } => self.upstream(&conn, None)?,
            Event::UpstreamTimeout { conn } => self.timeout(&conn)?,
            Event::StorageFailNext { torn } => {
                self.stores.fail_next(torn);
                Output::of(OutputKind::Nothing)
            }
            Event::MarkerFailNext => {
                self.stores.marker_fail_next();
                Output::of(OutputKind::Nothing)
            }
            Event::StorageFailAfter { after } => {
                self.stores.fail_after(after);
                Output::of(OutputKind::Nothing)
            }
            Event::DrainRequest => self.drain(),
            Event::Expire => self.expire(),
            Event::ChannelLost => match self.channel {
                // A connection that ends before its first frame uses the generation's one channel.
                Channel::Unopened => {
                    self.channel = Channel::Closed;
                    self.record(Record::ChannelEnded(ChannelEnd::BeforeFirstFrame));
                    Output::of(OutputKind::ChannelEnd(ChannelEnd::BeforeFirstFrame))
                }
                Channel::Closed => Output::of(OutputKind::Nothing),
                Channel::Open if self.orderly() => {
                    self.channel = Channel::Closed;
                    self.record(Record::ChannelEnded(ChannelEnd::Orderly));
                    Output::of(OutputKind::ChannelEnd(ChannelEnd::Orderly))
                }
                Channel::Open => self.fatal(FatalReason::PeerLost),
            },
            Event::SecondChannel => match self.channel {
                Channel::Unopened => return Err(EventError("second channel before the first")),
                Channel::Open => Output::of(OutputKind::RefusedChannel(ChannelRefusal::ChannelExists)),
                Channel::Closed => Output::of(OutputKind::RefusedChannel(ChannelRefusal::GenerationChannelUsed)),
            },
            Event::PeerChanged => {
                if self.channel == Channel::Open {
                    self.fatal(FatalReason::PeerChanged)
                } else {
                    Output::of(OutputKind::Nothing)
                }
            }
            Event::GateRestart => self.restart_with(None),
            Event::AnswerLate => match self.channel {
                // As R1's RESPONSE_OUT_OF_BOUNDS: HELD in every state, INVALIDATED journalled, armed actions denied.
                Channel::Open => self.fatal(FatalReason::AnswerLate),
                Channel::Unopened | Channel::Closed => return Err(EventError("answer late without an open channel")),
            },
        })
    }

    /// GATE_RESTART (M30) with an optional state floor. The public I05 event passes `None`, so without PolicyGate the
    /// floor never applies. PolicyGate passes `Some(State::Held)` when its own journal-only rebuild finds an ambiguous
    /// write (HE-002B DESIGN §3, §6): the restart is then HELD whatever the I05 rebuild found, before RESTARTED records the
    /// state. HELD is the strictest state, so no other floor value changes anything.
    pub(crate) fn restart_with(&mut self, floor: Option<State>) -> Output {
        let rebuilt = self.rebuild();
        self.state = if floor == Some(State::Held) { State::Held } else { rebuilt };
        // Deny-first restart: no channel, stamps, connections or pending drain.
        for connection in self.connections.values_mut() {
            connection.open = false;
        }
        self.backlog.clear();
        self.channel = Channel::Closed;
        self.drain_pending = false;
        // Journal RESTARTED; if the store is still failing, the storage-failure path leaves the generation HELD.
        self.record(Record::Restarted { state: self.state });
        Output::of(OutputKind::RestartState(self.state))
    }

    fn expire(&mut self) -> Output {
        let Some(execution_id) = self.bound.as_ref().map(|bound| bound.execution_id.clone()) else {
            return Output::of(OutputKind::Denied(Vec::new()));
        };
        if self.expired {
            return Output::of(OutputKind::Denied(Vec::new()));
        }
        let armed = self.armed_ids();
        self.expired = true;
        self.mark_in_flight_after_invalidation();
        self.record(Record::Expired { execution_id });
        self.deny_armed();
        Output::of(OutputKind::Denied(self.denied_since(&armed)))
    }

    fn accept(&mut self, conn: String) -> Result<Output, EventError> {
        let Some(position) = self.backlog.iter().position(|queued| *queued == conn) else {
            return Err(EventError("accept outside the backlog"));
        };
        self.backlog.remove(position);
        // C3: the stamp comes from gate state, never from client data.
        let stamp = self.armed().map(|action| action.id).and_then(|id| self.stamp_of(id));
        if stamp.is_some() {
            self.counters.stamps_issued = self.counters.stamps_issued.saturating_add(1);
        }
        self.connections.insert(conn, Connection { stamp: stamp.clone(), open: true, requests: 0, consumed: false });
        Ok(Output::of(OutputKind::Stamp(stamp)))
    }

    fn request(&mut self, conn: &str, certificate: &str, head: &str, body_digest: Option<&str>) -> Result<Output, EventError> {
        let Some(connection) = self.connections.get_mut(conn) else {
            return Err(EventError("request on an unaccepted connection"));
        };
        connection.requests = connection.requests.saturating_add(1);
        let (open, requests, stamp) = (connection.open, connection.requests, connection.stamp.clone());
        let decision = self.admit(open, requests, stamp, certificate, head, body_digest);
        let refusal = match decision {
            Ok(action_id) => match self.consume(conn, action_id) {
                Some(output) => return Ok(output),
                None => ConnectionRefusal::StorageFailure,
            },
            Err(refusal) => refusal,
        };
        if let Some(connection) = self.connections.get_mut(conn) {
            connection.open = false;
        }
        if refusal.is_correlation() {
            self.counters.correlation_refusals = self.counters.correlation_refusals.saturating_add(1);
        }
        Ok(Output::of(OutputKind::Close(refusal)))
    }

    /// A1 and C1-C5 for one request; the armed action it may consume.
    fn admit(&self, open: bool, requests: u64, stamp: Option<Stamp>, certificate: &str, head: &str,
             body_digest: Option<&str>) -> Result<u16, ConnectionRefusal> {
        if !open {
            return Err(ConnectionRefusal::ConnectionClosed);
        }
        if requests > 1 {
            return Err(ConnectionRefusal::ProtocolViolation); // C1 allows a single request per connection
        }
        // NOT_ACTIVE unless an execution is bound, the generation is ACTIVE, no drain waits and the channel is
        // open (M26).
        let Some(bound) = self.bound.as_ref() else { return Err(ConnectionRefusal::NotActive) };
        if self.state != State::Active || self.drain_pending || self.channel != Channel::Open {
            return Err(ConnectionRefusal::NotActive);
        }
        if self.expired {
            return Err(ConnectionRefusal::ExecutionExpired);
        }
        let Some(stamp) = stamp else { return Err(ConnectionRefusal::StampNone) };
        if stamp.execution_id != bound.execution_id {
            return Err(ConnectionRefusal::StampMismatch);
        }
        let action = match self.actions.get(&stamp.action_id) {
            None => return Err(ConnectionRefusal::StampMismatch),
            Some(action) if action.status != Status::Armed => return Err(ConnectionRefusal::AlreadyConsumed),
            Some(action) => action,
        };
        // Lookups of data validated at BIND and ARM fail closed if they ever failed (unreachable).
        let run = self.config.runs.get(&bound.run_nonce).ok_or(ConnectionRefusal::CertificateMismatch)?;
        if certificate != run.server_certificate_digest {
            return Err(ConnectionRefusal::CertificateMismatch);
        }
        let armed = action.armed.as_ref().ok_or(ConnectionRefusal::RequestMismatch)?;
        let manifest = self.config.manifests.get(&armed.manifest_digest).ok_or(ConnectionRefusal::RequestMismatch)?;
        let rendered = render_request(armed.verb, manifest, armed.uid.as_deref(), &self.config.endpoint);
        if rendered.head != head || rendered.body_digest.as_deref() != body_digest {
            return Err(ConnectionRefusal::RequestMismatch); // C4: exact bytes, not a reduction
        }
        Ok(action.id)
    }

    /// A1: record the consumption, then forward; `None` when the CONSUMED record failed.
    fn consume(&mut self, conn: &str, action_id: u16) -> Option<Output> {
        if !self.record(Record::Consumed { action_id }) {
            return None;
        }
        if let Some(action) = self.actions.get_mut(&action_id) {
            action.status = Status::Consumed;
            action.conn = Some(conn.to_string());
            action.after_invalidation = false;
        }
        if let Some(connection) = self.connections.get_mut(conn) {
            connection.consumed = true;
        }
        self.counters.consumptions = self.counters.consumptions.saturating_add(1);
        self.close_unconsumed_stamped(self.stamp_of(action_id)); // C5
        Some(Output::of(OutputKind::Forward { action_id }))
    }

    fn forwarded_on(&self, conn: &str, consumed_only: bool) -> Option<u16> {
        self.actions
            .values()
            .find(|action| {
                action.conn.as_deref() == Some(conn)
                    && if consumed_only { action.status == Status::Consumed } else { action.status != Status::Armed }
            })
            .map(|action| action.id)
    }

    fn upstream(&mut self, conn: &str, response: Option<UpstreamResponse>) -> Result<Output, EventError> {
        let Some(id) = self.forwarded_on(conn, false) else {
            return Err(EventError("upstream event without a forwarded action"));
        };
        let (status, after, armed) = match self.actions.get(&id) {
            Some(action) => (action.status, action.after_invalidation, action.armed.clone()),
            None => return Err(EventError("upstream event without a forwarded action")),
        };
        if status == Status::Terminal {
            // The action already has its TERMINAL classification (it was sealed, cut off by the 900 s bound, or
            // settled by an earlier upstream response or loss): journal LATE_UPSTREAM and relay nothing (M27).
            self.record(Record::LateUpstream { action_id: id });
            return Ok(Output::of(OutputKind::LateUpstream));
        }
        let verb = armed.as_ref().map(|armed| armed.verb);
        let lost = response.is_none();
        let (classification, details, delivered) = match response {
            None => (Classification::IoAmbiguous, TerminalDetails::None, None),
            Some(response) if !verb.is_some_and(|verb| i05_protocol::outcome_is_final(verb, response.http_status)) => {
                // This response does not settle the mutation, so it is IO_AMBIGUOUS; its HTTP status and body digest
                // are recorded only to support reconciliation.
                let details =
                    TerminalDetails::Reconciliation { http_status: response.http_status, result_digest: response.body_digest };
                (Classification::IoAmbiguous, details, None)
            }
            Some(response) => {
                let delivered = Delivered {
                    http_status: response.http_status,
                    result_digest: response.body_digest.clone(),
                    observed_uid: response.uid.clone(),
                    observed_resource_version: response.resource_version.clone(),
                };
                let details = TerminalDetails::Delivered {
                    http_status: response.http_status,
                    result_digest: response.body_digest,
                    observed_uid: response.uid,
                    observed_resource_version: response.resource_version,
                };
                (Classification::DeliveredResult, details, Some(delivered))
            }
        };
        // Journal TERMINAL, with the admitted-before-invalidation flag, first; nothing is relayed unless that write
        // succeeded.
        let recorded = self.record(Record::Terminal { action_id: id, classification, after_invalidation: after, details });
        let (classification, delivered) = if recorded { (classification, delivered) } else { (Classification::IoAmbiguous, None) };
        let created = match (&armed, &delivered) {
            (Some(armed), Some(delivered)) if armed.verb == Verb::Create && delivered.http_status == 201 => {
                delivered.observed_uid.clone().map(|uid| (armed.manifest_digest.clone(), uid))
            }
            _ => None,
        };
        if let Some(action) = self.actions.get_mut(&id) {
            action.status = Status::Terminal;
            action.classification = Some(classification);
            if delivered.is_some() {
                action.delivered = delivered;
            }
        }
        if classification == Classification::IoAmbiguous {
            self.state = State::Held;
        } else if let Some((manifest_digest, uid)) = created {
            // Remember the server-assigned UID of an object this execution created; DELETE accepts only such UIDs (I02).
            self.created_uids.entry(manifest_digest).or_default().insert(uid);
        }
        if let Some(connection) = self.connections.get_mut(conn) {
            connection.open = false; // one response per connection, then close
        }
        Ok(Output::of(OutputKind::Upstream { classification, relayed: recorded && !lost, aborted: false }))
    }

    /// Decision 12: the 900-second bound of a forwarded exchange expired.
    fn timeout(&mut self, conn: &str) -> Result<Output, EventError> {
        let Some(id) = self.forwarded_on(conn, true) else {
            return Err(EventError("timeout without an outstanding exchange"));
        };
        let after = self.actions.get(&id).is_some_and(|action| action.after_invalidation);
        self.record(Record::Terminal {
            action_id: id,
            classification: Classification::IoAmbiguous,
            after_invalidation: after,
            details: TerminalDetails::Aborted,
        });
        if let Some(action) = self.actions.get_mut(&id) {
            action.status = Status::Terminal;
            action.classification = Some(Classification::IoAmbiguous);
        }
        self.state = State::Held;
        if let Some(connection) = self.connections.get_mut(conn) {
            connection.open = false;
        }
        Ok(Output::of(OutputKind::Upstream { classification: Classification::IoAmbiguous, relayed: false, aborted: true }))
    }

    /// Handles I07 WRITE_BEGIN whatever the state (M28): ACTIVE and INSPECTING start the gate's normal drain, any
    /// ARMED action is denied, and the answer waits on the A3 fence.
    pub(crate) fn drain(&mut self) -> Output {
        let armed = self.armed_ids();
        if matches!(self.state, State::Active | State::Inspecting) {
            self.state = State::Draining;
        }
        if !self.drain_pending {
            self.drain_pending = true;
            self.record(Record::DrainStarted);
        }
        self.deny_armed();
        let answer = self.settle_drain();
        let mut output = Output::of(OutputKind::Denied(self.denied_since(&armed)));
        output.drain = Some(answer.unwrap_or(DrainAnswer::Pending));
        output
    }

    // ------------------------------------------------------------------------------------------ I05 frames

    fn frame(&mut self, input: FrameInput) -> Output {
        if self.channel == Channel::Closed {
            return Output::of(OutputKind::RefusedChannel(ChannelRefusal::GenerationChannelUsed));
        }
        let checked = match input {
            FrameInput::Value(value) => frame::check_frame_encoded(&value, &self.schema).map(|encoded| (value, encoded)),
            FrameInput::Bytes(raw) => decode_frame(Datagram::Bytes(&raw), &self.schema).map(|value| (value, raw)),
            FrameInput::NotBytes => Err(FrameError::F07),
        };
        let (value, encoded) = match checked {
            Ok(checked) => checked,
            Err(error) => return self.fatal(FatalReason::InvalidFrame(error)),
        };
        // The frame passed the closed schema, so every envelope member is present and typed.
        let envelope = (
            member_text(&value, "direction"),
            member_int(&value, "sequence"),
            member_text(&value, "previousDigest"),
            member_text(&value, "generation"),
            member_text(&value, "challenge"),
            member_text(&value, "operation"),
        );
        let (Some(direction), Some(sequence), Some(previous), Some(generation), Some(challenge), Some(operation)) = envelope
        else {
            return self.fatal(FatalReason::InvalidFrame(FrameError::F00));
        };
        if direction != "BROKER_TO_GATE" || sequence % 2 != 1 {
            return self.fatal(FatalReason::Direction);
        }
        if sequence != self.next_sequence || previous != self.last_digest {
            return self.fatal(FatalReason::ChainBroken);
        }
        if generation != self.config.generation {
            return self.fatal(FatalReason::GenerationMismatch);
        }
        if self.channel == Channel::Unopened {
            if operation != "GENERATION_STATUS" {
                return self.fatal(FatalReason::OpeningFrameRequired);
            }
            self.channel = Channel::Open;
            self.challenge = Some(challenge);
        } else if self.challenge.as_deref() != Some(challenge.as_str()) {
            return self.fatal(FatalReason::ChallengeMismatch);
        }
        let Some(request) = value.get("payload").and_then(|payload| Request::parse(&operation, payload)) else {
            return self.fatal(FatalReason::InvalidFrame(FrameError::F00));
        };
        let payload = match request {
            Request::GenerationStatus => Reply::Payload(self.generation_status()),
            Request::Bind(bind) => self.bind(bind),
            Request::Arm(arm) => self.arm(arm),
            Request::Outcome { execution_id, action_id } => self.outcome(&execution_id, action_id),
            Request::Close(reason) => Reply::Payload(self.close(reason)),
        };
        let payload = match payload {
            Reply::Payload(payload) => payload,
            Reply::Fatal(output) => return output,
        };
        let response = Doc::object(vec![
            ("schemaVersion", Doc::str(FRAME_VERSION)),
            ("generation", Doc::str(&self.config.generation)),
            ("challenge", Doc::opt_str(self.challenge.as_deref())),
            ("sequence", Doc::Int(sequence.saturating_add(1))),
            ("previousDigest", Doc::Str(sha256::prefixed(&encoded))),
            ("direction", Doc::str("GATE_TO_BROKER")),
            ("operation", Doc::str(&operation)),
            ("payload", payload.clone()),
        ]);
        // R10-defined (DESIGN §10): a response outside a schema bound closes the channel fatally (the model raises).
        let Ok(bytes) = frame::check_frame_encoded(&response.to_value(), &self.schema) else {
            return self.fatal(FatalReason::ResponseOutOfBounds);
        };
        self.next_sequence = sequence.saturating_add(2);
        self.last_digest = sha256::prefixed(&bytes);
        Output { kind: OutputKind::Response(payload), drain: None, response_frame: Some(bytes) }
    }

    fn generation_status(&self) -> Doc {
        Doc::object(vec![
            ("result", Doc::str("OK")),
            ("state", Doc::str(self.state.as_str())),
            ("drainPending", Doc::Bool(self.drain_pending)),
            ("boundExecutionId", Doc::opt_str(self.bound.as_ref().map(|bound| bound.execution_id.as_str()))),
            ("armedActionId", self.armed().map_or(Doc::Null, |action| Doc::Int(i64::from(action.id)))),
            ("inFlightActionId", self.in_flight().map_or(Doc::Null, |action| Doc::Int(i64::from(action.id)))),
            ("counters", self.counters.to_doc()),
            ("journalDigest", Doc::Str(self.journal_digest())),
        ])
    }

    fn bind(&mut self, p: BindRequest) -> Reply {
        if p.peer_qualification_digest != self.config.peer_qualification_digest {
            return Reply::Fatal(self.fatal(FatalReason::PeerQualificationMismatch));
        }
        if self.state != State::Active {
            return refused("NOT_ACTIVE");
        }
        if !self.actions.values().all(Action::settled) {
            return refused("ACTION_OUTSTANDING");
        }
        let prior = &self.config.prior;
        if self.bound_ids.contains(&p.execution_id)
            || self.bound_nonces.contains(&p.run_nonce)
            || prior.execution_ids.contains(&p.execution_id)
            || prior.run_nonces.contains(&p.run_nonce)
        {
            return refused("EXECUTION_REPLAY"); // durable across generations
        }
        if p.dispatch_generation != self.config.generation {
            return refused("GENERATION_MISMATCH");
        }
        let Some(run) = self.config.runs.get(&p.run_nonce) else { return refused("UNKNOWN_BINDING") };
        if run.binding_digest != p.binding_digest || run.case_id != p.case_id || run.request_digest != p.request_digest {
            return refused("UNKNOWN_BINDING");
        }
        if p.server_certificate_digest != run.server_certificate_digest {
            return refused("CERTIFICATE_MISMATCH");
        }
        let mut digests = run.manifests.clone();
        digests.sort();
        let mut identities: Vec<String> =
            digests.iter().filter_map(|digest| self.config.manifests.get(digest)).map(|manifest| manifest.identity()).collect();
        identities.sort();
        if digests.iter().any(|digest| prior.manifest_digests.contains(digest))
            || identities.iter().any(|identity| prior.manifest_identities.contains(identity))
        {
            // A manifest digest, or a kind/namespace/name identity, that an earlier generation bound cannot be bound
            // again (even under a different digest).
            return refused("MANIFEST_REUSED");
        }
        if !self.config.observed_workers.contains(&(p.worker_pid, p.worker_start_ticks)) {
            return refused("WORKER_NOT_OBSERVED");
        }
        let set_digest = sha256::prefixed(&Doc::Array(digests.iter().map(|digest| Doc::str(digest)).collect()).canonical());
        if !self.record(Record::Bind {
            execution_id: p.execution_id.clone(),
            run_nonce: p.run_nonce.clone(),
            reservation_digest: p.reservation_digest,
            manifest_digests: digests,
            manifest_identities: identities,
        }) {
            return refused("STORAGE_FAILURE");
        }
        self.bound = Some(Bound { execution_id: p.execution_id.clone(), run_nonce: p.run_nonce.clone() });
        self.expired = false;
        self.actions.clear();
        self.mutation_keys.clear();
        self.created_uids.clear();
        self.bound_ids.push(p.execution_id.clone());
        self.bound_nonces.push(p.run_nonce);
        Reply::Payload(Doc::object(vec![
            ("result", Doc::str("OK")),
            ("executionId", Doc::Str(p.execution_id)),
            ("caseManifestSetDigest", Doc::Str(set_digest)),
        ]))
    }

    fn arm(&mut self, p: ArmRequest) -> Reply {
        if self.state != State::Active {
            return refused(if self.state == State::Draining { "DRAIN_PENDING" } else { "NOT_ACTIVE" });
        }
        let Some(bound) = self.bound.as_ref().filter(|bound| bound.execution_id == p.execution_id) else {
            return refused("EXECUTION_NOT_BOUND");
        };
        if self.expired {
            return refused("EXECUTION_EXPIRED");
        }
        if !self.actions.values().all(Action::settled) {
            return refused("ACTION_OUTSTANDING");
        }
        if usize::from(p.action_id) != self.actions.len().saturating_add(1) {
            return refused("ACTION_ID_OUT_OF_ORDER");
        }
        let in_run = self.config.runs.get(&bound.run_nonce).is_some_and(|run| run.manifests.contains(&p.manifest_digest));
        let Some(manifest) = self.config.manifests.get(&p.manifest_digest).filter(|_| in_run) else {
            return refused("MANIFEST_OUTSIDE_CASE");
        };
        if (p.verb == Verb::Delete) != p.recorded_uid.is_some() {
            return refused("UID_RULE"); // a recorded UID is required for DELETE and forbidden otherwise
        }
        if p.verb == Verb::Delete {
            let created = self.created_uids.get(&p.manifest_digest);
            if !p.recorded_uid.as_ref().is_some_and(|uid| created.is_some_and(|uids| uids.contains(uid))) {
                return refused("UID_NOT_CREATED"); // the UID has to be one this execution itself created (201)
            }
        }
        let expected = template_digest(p.verb, &manifest.api_version, manifest.kind, &manifest.namespace, &manifest.name,
                                       p.recorded_uid.as_deref(), &p.manifest_digest);
        if p.request_template_digest != expected {
            return refused("TEMPLATE_MISMATCH");
        }
        let key = match p.verb {
            Verb::Create => Some(MutationKey::Create(p.manifest_digest.clone())),
            Verb::Delete => p.recorded_uid.clone().map(MutationKey::Delete),
            Verb::Get => None,
        };
        if key.as_ref().is_some_and(|key| self.mutation_keys.contains(key)) {
            return refused("MUTATION_KEY_REUSED"); // C7
        }
        // C2 flush (M25) before ARM is journaled: unconsumed connections and queued backlog entries are all closed.
        let mut flushed = self.close_connections(|connection| !connection.consumed);
        for conn in std::mem::take(&mut self.backlog) {
            self.connections.insert(conn, Connection { stamp: None, open: false, requests: 0, consumed: false });
            flushed = flushed.saturating_add(1);
            self.counters.flush_closures = self.counters.flush_closures.saturating_add(1);
        }
        if !self.record(Record::Arm {
            action_id: p.action_id,
            verb: p.verb,
            manifest_digest: p.manifest_digest.clone(),
            recorded_uid: p.recorded_uid.clone(),
            template_digest: expected,
        }) {
            return refused("STORAGE_FAILURE");
        }
        if let Some(key) = key {
            self.mutation_keys.insert(key);
        }
        self.actions.insert(p.action_id, Action {
            id: p.action_id,
            status: Status::Armed,
            classification: None,
            after_invalidation: false,
            sealed: false,
            armed: Some(Armed { verb: p.verb, manifest_digest: p.manifest_digest, uid: p.recorded_uid }),
            conn: None,
            delivered: None,
        });
        Reply::Payload(Doc::object(vec![
            ("result", Doc::str("OK")),
            ("actionId", Doc::Int(i64::from(p.action_id))),
            ("flushedConnections", count_doc(flushed)),
        ]))
    }

    fn outcome(&mut self, execution_id: &str, action_id: u16) -> Reply {
        if !self.bound.as_ref().is_some_and(|bound| bound.execution_id == execution_id) {
            return refused("EXECUTION_NOT_BOUND");
        }
        let Some((sealed, status, conn)) =
            self.actions.get(&action_id).map(|action| (action.sealed, action.status, action.conn.clone()))
        else {
            return refused("UNKNOWN_ACTION");
        };
        if !sealed {
            // Seal the action: it can no longer be consumed and its classification is frozen.
            match status {
                Status::Armed => {
                    self.close_unconsumed_stamped(self.stamp_of(action_id));
                    if let Some(action) = self.actions.get_mut(&action_id) {
                        action.status = Status::Terminal;
                        action.classification = Some(Classification::NotForwarded);
                    }
                }
                Status::Consumed => {
                    // Consumed with no TERMINAL yet: cut the upstream exchange off and close the server-side connection.
                    if let Some(connection) = conn.and_then(|conn| self.connections.get_mut(&conn)) {
                        connection.open = false;
                    }
                    if let Some(action) = self.actions.get_mut(&action_id) {
                        action.status = Status::Terminal;
                        action.classification = Some(Classification::IoAmbiguous);
                    }
                    self.state = State::Held;
                }
                Status::Terminal => {}
            }
            let (classification, after) = match self.actions.get(&action_id) {
                Some(action) => (action.classification.unwrap_or(Classification::IoAmbiguous), action.after_invalidation),
                None => return refused("UNKNOWN_ACTION"),
            };
            if !self.record(Record::Sealed { action_id, classification, after_invalidation: after }) {
                return refused("STORAGE_FAILURE");
            }
            if let Some(action) = self.actions.get_mut(&action_id) {
                action.sealed = true;
            }
        }
        let Some(action) = self.actions.get(&action_id) else { return refused("UNKNOWN_ACTION") };
        let classification = action.classification.unwrap_or(Classification::IoAmbiguous);
        let delivered = if classification == Classification::DeliveredResult { action.delivered.as_ref() } else { None };
        Reply::Payload(Doc::object(vec![
            ("result", Doc::str("OK")),
            ("actionId", Doc::Int(i64::from(action_id))),
            ("classification", Doc::str(classification.as_str())),
            ("admittedBeforeInvalidation", Doc::Bool(action.after_invalidation && classification != Classification::NotForwarded)),
            ("httpStatus", delivered.map_or(Doc::Null, |delivered| Doc::Int(delivered.http_status))),
            ("resultDigest", delivered.map_or(Doc::Null, |delivered| Doc::str(&delivered.result_digest))),
            ("observedUid", Doc::opt_str(delivered.and_then(|delivered| delivered.observed_uid.as_deref()))),
            (
                "observedResourceVersion",
                Doc::opt_str(delivered.and_then(|delivered| delivered.observed_resource_version.as_deref())),
            ),
        ]))
    }

    fn close(&mut self, reason: CloseReason) -> Doc {
        let armed = self.armed_ids();
        let reply = |gate: &Gate| {
            Doc::object(vec![
                ("result", Doc::str("OK")),
                ("state", Doc::str(gate.state.as_str())),
                ("deniedActionIds", ids_doc(&gate.denied_since(&armed))),
            ])
        };
        if matches!(self.state, State::Closed | State::Invalidated | State::Held) {
            if reason == CloseReason::ReconciliationRequired && self.state != State::Held {
                self.state = State::Held;
                self.record(Record::Invalidated { reason: Invalidation::Close(reason), state: State::Held });
            }
            self.deny_armed();
            return reply(self);
        }
        if reason == CloseReason::NormalDrain {
            if self.in_flight().is_some() {
                return Doc::object(vec![("result", Doc::str("REFUSED")), ("reason", Doc::str("ACTION_IN_FLIGHT"))]);
            }
            self.state = if self.any_ambiguous() { State::Held } else { State::Closed };
            self.record(Record::Closed { reason, state: self.state });
            self.deny_armed();
            return reply(self);
        }
        // RECONCILIATION_REQUIRED (the broker disagrees or lacks an outcome) leaves the generation HELD; the other
        // urgent reasons invalidate it.
        let target = if reason == CloseReason::ReconciliationRequired { State::Held } else { State::Invalidated };
        self.urgent(target, Invalidation::Close(reason));
        reply(self)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use i05_protocol::json::{self, JStr, Object};

    const VECTORS: &str = include_str!("../../../contracts/i05-v3/vectors.json");

    fn active_gate() -> Gate {
        let vectors = json::parse(VECTORS).unwrap_or(Value::Null);
        let config = vectors.get("configs").and_then(|configs| configs.get("ACTIVE")).cloned().unwrap_or(Value::Null);
        match Config::from_value(&config).map(Gate::new) {
            Ok(Ok(gate)) => gate,
            _ => panic!("the ACTIVE configuration builds a gate"),
        }
    }

    fn broker_frame(gate: &Gate, sequence: i64, operation: &str, payload: Value) -> Value {
        let mut frame = Object::new();
        for (key, value) in [
            ("schemaVersion", Value::str(FRAME_VERSION)),
            ("generation", Value::str(&"a".repeat(64))),
            ("challenge", Value::str(&"c".repeat(64))),
            ("sequence", Value::int(sequence)),
            ("previousDigest", Value::str(gate.last_digest())),
            ("direction", Value::str("BROKER_TO_GATE")),
            ("operation", Value::str(operation)),
            ("payload", payload),
        ] {
            frame.insert(JStr::new(key), value);
        }
        Value::Object(frame)
    }

    fn status(gate: &mut Gate) -> Output {
        let frame = broker_frame(gate, gate.next_sequence(), "GENERATION_STATUS", Value::Object(Object::new()));
        gate.handle(Event::Frame(FrameInput::Value(frame))).unwrap_or_else(|error| panic!("{error:?}"))
    }

    fn last_record(gate: &Gate) -> Option<&Record> {
        match gate.journal().last() {
            Some(Entry::Record(record)) => Some(record),
            _ => None,
        }
    }

    #[test]
    fn a_response_past_the_sequence_bound_closes_fatally() {
        let mut gate = active_gate();
        assert!(matches!(status(&mut gate).kind, OutputKind::Response(_)));
        // The broker's frame may carry 2147483647, the schema maximum; the response would carry 2147483648.
        gate.next_sequence = 2147483647;
        let output = status(&mut gate);
        assert_eq!(output.kind, OutputKind::Fatal(FatalReason::ResponseOutOfBounds));
        assert_eq!(output.to_doc().canonical(), b"{\"fatal\":\"RESPONSE_OUT_OF_BOUNDS\"}");
        assert_eq!(gate.state(), State::Held);
        assert_eq!(last_record(&gate), Some(&Record::Invalidated {
            reason: Invalidation::Fatal(FatalReason::ResponseOutOfBounds),
            state: State::Held,
        }));
        assert!(matches!(status(&mut gate).kind, OutputKind::RefusedChannel(ChannelRefusal::GenerationChannelUsed)));
    }

    #[test]
    fn a_counter_past_its_bound_closes_fatally() {
        let mut gate = active_gate();
        assert!(matches!(status(&mut gate).kind, OutputKind::Response(_)));
        gate.counters.stamps_issued = 2147483648;
        assert_eq!(status(&mut gate).kind, OutputKind::Fatal(FatalReason::ResponseOutOfBounds));
        assert_eq!(gate.state(), State::Held);
    }

    #[test]
    fn counters_saturate_instead_of_overflowing() {
        let mut gate = active_gate();
        gate.counters.flush_closures = u64::MAX;
        gate.backlog.push("c1".to_string());
        assert!(gate.handle(Event::Accept { conn: "c1".into() }).is_ok());
        gate.close_connections(|_| true);
        assert_eq!(gate.counters.flush_closures, u64::MAX);
        assert_eq!(count_doc(u64::MAX), Doc::Int(i64::MAX));
    }

    #[test]
    fn events_outside_the_preconditions_change_nothing() {
        let mut gate = active_gate();
        let before = gate.snapshot();
        let refused = [
            Event::Accept { conn: "c9".into() },
            Event::Request { conn: "c9".into(), certificate_digest: String::new(), head: String::new(), body_digest: None },
            Event::UpstreamResponse {
                conn: "c9".into(),
                response: UpstreamResponse { http_status: 200, body_digest: String::new(), uid: None, resource_version: None },
            },
            Event::UpstreamLost { conn: "c9".into() },
            Event::UpstreamTimeout { conn: "c9".into() },
            Event::SecondChannel,
        ];
        for event in refused {
            assert!(gate.handle(event).is_err());
            assert_eq!(gate.snapshot(), before);
        }
    }

    #[test]
    fn the_bytes_entry_refuses_with_the_decoder_codes() {
        let mut gate = active_gate();
        assert_eq!(gate.handle(Event::Frame(FrameInput::NotBytes)).map(|output| output.kind),
                   Ok(OutputKind::Fatal(FatalReason::InvalidFrame(FrameError::F07))));
        let mut gate = active_gate();
        let frame = broker_frame(&gate, 1, "GENERATION_STATUS", Value::Object(Object::new()));
        let mut raw = json::canonical(&frame).unwrap_or_default();
        raw.push(b'\n');
        assert_eq!(gate.handle(Event::Frame(FrameInput::Bytes(raw))).map(|output| output.kind),
                   Ok(OutputKind::Fatal(FatalReason::InvalidFrame(FrameError::F06))));
        assert_eq!(last_record(&gate), Some(&Record::Invalidated {
            reason: Invalidation::Fatal(FatalReason::InvalidFrame(FrameError::F06)),
            state: State::Held,
        }));
    }

    #[test]
    fn the_response_frame_is_canonical_and_chains() {
        let mut gate = active_gate();
        let frame = broker_frame(&gate, 1, "GENERATION_STATUS", Value::Object(Object::new()));
        let raw = json::canonical(&frame).unwrap_or_default();
        let output = gate.handle(Event::Frame(FrameInput::Bytes(raw.clone()))).unwrap_or_else(|error| panic!("{error:?}"));
        let response = output.response_frame.unwrap_or_default();
        let decoded = decode_frame(Datagram::Bytes(&response), &gate.schema);
        assert!(decoded.is_ok(), "the gate's response is a valid v3 frame");
        let decoded = decoded.unwrap_or(Value::Null);
        assert_eq!(decoded.get("previousDigest").and_then(Value::as_str), Some(sha256::prefixed(&raw).as_str()));
        assert_eq!(decoded.get("sequence").and_then(Value::as_int).and_then(|int| int.to_i64()), Some(2));
        assert_eq!(gate.last_digest(), sha256::prefixed(&response));
        assert_eq!(gate.next_sequence(), 3);
    }

    #[test]
    fn a_rebuild_that_meets_an_unknown_action_restarts_held() {
        let mut gate = active_gate();
        assert_eq!(gate.stores.append(Record::Closed { reason: CloseReason::NormalDrain, state: State::Closed }), Appended::Durable);
        assert_eq!(gate.rebuild(), State::Closed);
        assert_eq!(gate.stores.append(Record::Consumed { action_id: 9 }), Appended::Durable);
        assert_eq!(gate.rebuild(), State::Held);
    }

    #[test]
    fn the_restart_floor_only_ever_holds() {
        // Without a floor the restart is exactly GATE_RESTART's: a clean CLOSED journal restarts CLOSED.
        let mut gate = active_gate();
        assert_eq!(gate.stores.append(Record::Closed { reason: CloseReason::NormalDrain, state: State::Closed }), Appended::Durable);
        assert_eq!(gate.restart_with(None).kind, OutputKind::RestartState(State::Closed));
        // A HELD floor makes the same journal restart HELD, and RESTARTED records the floored state.
        assert_eq!(gate.restart_with(Some(State::Held)).kind, OutputKind::RestartState(State::Held));
        assert_eq!(last_record(&gate), Some(&Record::Restarted { state: State::Held }));
        // No other floor lifts a HELD rebuild (the journal's last state record is now RESTARTED HELD).
        assert_eq!(gate.restart_with(Some(State::Closed)).kind, OutputKind::RestartState(State::Held));
        let mut gate = active_gate();
        assert_eq!(gate.stores.append(Record::Closed { reason: CloseReason::NormalDrain, state: State::Closed }), Appended::Durable);
        assert_eq!(gate.restart_with(Some(State::Invalidated)).kind, OutputKind::RestartState(State::Closed));
    }

    #[test]
    fn the_drain_answer_rides_on_the_settling_event() {
        let mut gate = active_gate();
        assert!(matches!(status(&mut gate).kind, OutputKind::Response(_)));
        let drain = gate.handle(Event::DrainRequest).unwrap_or_else(|error| panic!("{error:?}"));
        // From ACTIVE with nothing in flight the drain closes the generation and settles at once.
        assert_eq!(drain.to_doc().canonical(), b"{\"denied\":[],\"drain\":\"OPEN\"}");
        assert_eq!(gate.state(), State::Closed);
        assert_eq!(gate.fence(), DrainAnswer::Open);
    }
}
