//! The closed vocabularies of the I05 gate: states, classifications, close and fatal reasons, drain answers.

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
        }
    }
}

/// The reason an INVALIDATED record carries: an urgent close, the storage-failure path, or a fatal channel failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash)]
pub enum Invalidation {
    Close(CloseReason),
    Fatal(FatalReason),
}

impl Invalidation {
    pub fn as_str(self) -> &'static str {
        match self {
            Invalidation::Close(reason) => reason.as_str(),
            Invalidation::Fatal(reason) => reason.as_str(),
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
