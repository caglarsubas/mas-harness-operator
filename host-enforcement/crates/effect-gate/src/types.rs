//! The closed vocabularies of the I05 gate (states, classifications, close and fatal reasons, drain answers) and of
//! its I07 channel (maintenance states and reasons, session ends, abort reasons).

use i05_protocol::FrameError;

/// The generation's state (Decision 11).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum State {
    Inspecting,
    Active,
    Draining,
    Closed,
    Invalidated,
    Held,
}

impl State {
    pub fn as_str(self) -> &'static str {
        match self {
            State::Inspecting => "INSPECTING",
            State::Active => "ACTIVE",
            State::Draining => "DRAINING",
            State::Closed => "CLOSED",
            State::Invalidated => "INVALIDATED",
            State::Held => "HELD",
        }
    }

    pub fn parse(text: &str) -> Option<State> {
        Some(match text {
            "INSPECTING" => State::Inspecting,
            "ACTIVE" => State::Active,
            "DRAINING" => State::Draining,
            "CLOSED" => State::Closed,
            "INVALIDATED" => State::Invalidated,
            "HELD" => State::Held,
            _ => return None,
        })
    }
}

/// An action's terminal classification.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Classification {
    NotForwarded,
    DeliveredResult,
    IoAmbiguous,
}

impl Classification {
    pub fn as_str(self) -> &'static str {
        match self {
            Classification::NotForwarded => "NOT_FORWARDED",
            Classification::DeliveredResult => "DELIVERED_RESULT",
            Classification::IoAmbiguous => "IO_AMBIGUOUS",
        }
    }
}

/// A CLOSE_GENERATION reason.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum CloseReason {
    NormalDrain,
    Revocation,
    Expiry,
    PeerFailure,
    StorageFailure,
    ObservationFailure,
    ReconciliationRequired,
}

impl CloseReason {
    pub fn as_str(self) -> &'static str {
        match self {
            CloseReason::NormalDrain => "NORMAL_DRAIN",
            CloseReason::Revocation => "REVOCATION",
            CloseReason::Expiry => "EXPIRY",
            CloseReason::PeerFailure => "PEER_FAILURE",
            CloseReason::StorageFailure => "STORAGE_FAILURE",
            CloseReason::ObservationFailure => "OBSERVATION_FAILURE",
            CloseReason::ReconciliationRequired => "RECONCILIATION_REQUIRED",
        }
    }

    pub fn parse(text: &str) -> Option<CloseReason> {
        Some(match text {
            "NORMAL_DRAIN" => CloseReason::NormalDrain,
            "REVOCATION" => CloseReason::Revocation,
            "EXPIRY" => CloseReason::Expiry,
            "PEER_FAILURE" => CloseReason::PeerFailure,
            "STORAGE_FAILURE" => CloseReason::StorageFailure,
            "OBSERVATION_FAILURE" => CloseReason::ObservationFailure,
            "RECONCILIATION_REQUIRED" => CloseReason::ReconciliationRequired,
            _ => return None,
        })
    }
}

/// Why the channel closed without a response (Channel item 5, the model's fatal reasons, and the R10-defined
/// `RESPONSE_OUT_OF_BOUNDS` of DESIGN §10).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum FatalReason {
    InvalidFrame(FrameError),
    Direction,
    ChainBroken,
    GenerationMismatch,
    OpeningFrameRequired,
    ChallengeMismatch,
    PeerQualificationMismatch,
    PeerLost,
    PeerChanged,
    /// R10-defined: the gate's own response would leave a schema bound (a sequence or counter past 2147483647).
    ResponseOutOfBounds,
    /// R10-defined (HE-003A DESIGN §5.7, owner decision Q-HE3A-2 (b)): the gate could not answer a request within the
    /// 2-second bound, so the answer was never sent.
    AnswerLate,
}

impl FatalReason {
    pub fn as_str(self) -> &'static str {
        match self {
            FatalReason::InvalidFrame(FrameError::F00) => "F00_INVALID_FRAME",
            FatalReason::InvalidFrame(FrameError::F01) => "F01_INVALID_FRAME",
            FatalReason::InvalidFrame(FrameError::F02) => "F02_INVALID_FRAME",
            FatalReason::InvalidFrame(FrameError::F03) => "F03_INVALID_FRAME",
            FatalReason::InvalidFrame(FrameError::F04) => "F04_INVALID_FRAME",
            FatalReason::InvalidFrame(FrameError::F05) => "F05_INVALID_FRAME",
            FatalReason::InvalidFrame(FrameError::F06) => "F06_INVALID_FRAME",
            FatalReason::InvalidFrame(FrameError::F07) => "F07_INVALID_FRAME",
            FatalReason::Direction => "DIRECTION",
            FatalReason::ChainBroken => "CHAIN_BROKEN",
            FatalReason::GenerationMismatch => "GENERATION_MISMATCH",
            FatalReason::OpeningFrameRequired => "OPENING_FRAME_REQUIRED",
            FatalReason::ChallengeMismatch => "CHALLENGE_MISMATCH",
            FatalReason::PeerQualificationMismatch => "PEER_QUALIFICATION_MISMATCH",
            FatalReason::PeerLost => "PEER_LOST",
            FatalReason::PeerChanged => "PEER_CHANGED",
            FatalReason::ResponseOutOfBounds => "RESPONSE_OUT_OF_BOUNDS",
            FatalReason::AnswerLate => "ANSWER_LATE",
        }
    }
}

/// The reason an INVALIDATED record carries: an urgent close, the storage-failure path, a fatal channel failure, or
/// (HE-002B) a deviation of the I07 writer peer. The last one is neither a `CloseReason` (a broker CLOSE can never name
/// it) nor a `FatalReason` (no I05 channel failure produces it); only PolicyGate records it.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Invalidation {
    Close(CloseReason),
    Fatal(FatalReason),
    WriterPeerDeviation,
}

impl Invalidation {
    pub fn as_str(self) -> &'static str {
        match self {
            Invalidation::Close(reason) => reason.as_str(),
            Invalidation::Fatal(reason) => reason.as_str(),
            Invalidation::WriterPeerDeviation => "WRITER_PEER_DEVIATION",
        }
    }
}

/// The I07 maintenance of a generation (Decisions 0 and 1): not begun, waiting for the A3 fence, open for writes,
/// held, or ended for good.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Maintenance {
    NotBegun,
    Pending,
    Open,
    Held,
    Ended,
}

impl Maintenance {
    pub fn as_str(self) -> &'static str {
        match self {
            Maintenance::NotBegun => "NONE",
            Maintenance::Pending => "PENDING",
            Maintenance::Open => "OPEN",
            Maintenance::Held => "HELD",
            Maintenance::Ended => "ENDED",
        }
    }
}

/// How a writer session ended: end of file or loss, or a fatal frame or peer deviation.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum SessionEnd {
    Ended,
    Fatal,
}

impl SessionEnd {
    pub fn as_str(self) -> &'static str {
        match self {
            SessionEnd::Ended => "ENDED",
            SessionEnd::Fatal => "FATAL",
        }
    }
}

/// The reason a MAINT_ENDED record carries: the writer's WRITE_END, or the end of the owning session.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum MaintenanceEnd {
    WriteEnd,
    Session(SessionEnd),
}

impl MaintenanceEnd {
    pub fn as_str(self) -> &'static str {
        match self {
            MaintenanceEnd::WriteEnd => "WRITE_END",
            MaintenanceEnd::Session(SessionEnd::Ended) => "SESSION_ENDED",
            MaintenanceEnd::Session(SessionEnd::Fatal) => "SESSION_FATAL",
        }
    }
}

/// Why the maintenance is ENDED (the snapshot's `maintenanceReason`): a recorded end, or a restart that met a begun
/// maintenance without an end record, or none at all (I07 v3 W2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum MaintenanceReason {
    Ended(MaintenanceEnd),
    GateRestart,
    GenerationRebuilt,
}

impl MaintenanceReason {
    pub fn as_str(self) -> &'static str {
        match self {
            MaintenanceReason::Ended(end) => end.as_str(),
            MaintenanceReason::GateRestart => "GATE_RESTART",
            MaintenanceReason::GenerationRebuilt => "GENERATION_REBUILT",
        }
    }
}

/// Why the gate gave up on an outstanding write before its upstream outcome (I07 v2 R4, v3 W2).
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum AbortReason {
    WriterChannelLost,
    WriterPeerDeviation,
    WriterProtocolFailure,
    UpstreamTimeout,
}

impl AbortReason {
    pub fn as_str(self) -> &'static str {
        match self {
            AbortReason::WriterChannelLost => "WRITER_CHANNEL_LOST",
            AbortReason::WriterPeerDeviation => "WRITER_PEER_DEVIATION",
            AbortReason::WriterProtocolFailure => "WRITER_PROTOCOL_FAILURE",
            AbortReason::UpstreamTimeout => "UPSTREAM_TIMEOUT",
        }
    }
}

/// The I07 drain answer.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum DrainAnswer {
    Pending,
    Open,
    Held,
}

impl DrainAnswer {
    pub fn as_str(self) -> &'static str {
        match self {
            DrainAnswer::Pending => "PENDING",
            DrainAnswer::Open => "OPEN",
            DrainAnswer::Held => "HELD",
        }
    }
}
