//! The store frame (HE-002C DESIGN §4), one per journal record, marker and generation-index entry:
//!
//! ```text
//! frame  = MAGIC SP length SP payload-digest SP header-digest LF payload STATUS LF
//! MAGIC  = FF 00 "HEJ1"; length = 8 lowercase hex digits (1 to 0x00100000); the two digests are lowercase hex SHA-256,
//!          of the payload and of the 80 header bytes before the header digest; STATUS = P, C or R
//! ```
//!
//! The payload is the canonical JSON of the tuple (for records, the bytes `journalDigest` covers). Neither `0xFF` nor
//! `0x00` occurs in a header field, a payload (canonical JSON is UTF-8 and escapes every control character) or a
//! status byte, so every `0xFF` starts an append attempt. The scanner splits the bytes at each `0xFF` and reads every
//! attempt (and any bytes before the first `0xFF`) as one committed frame, optionally followed by one TORN for the
//! bytes after it, or as one TORN. It streams: it holds at most one frame.
//!
//! The strict decoders accept exactly what the gate writes: a payload must be UTF-8 JSON that re-encodes to the same
//! bytes, and a record must be one of the tuples `Record::to_doc` produces, checked by re-encoding the decoded record
//! (R21: anything else is TORN).

use i05_protocol::json::{self, Doc, Value};
use i05_protocol::{sha256, FrameError, Verb};

use crate::journal::{ChannelEnd, Entry, Record, TerminalDetails, WriteDetails};
use crate::policy::{Prior, WriteOperation};
use crate::types::{AbortReason, Classification, CloseReason, FatalReason, Invalidation, MaintenanceEnd, SessionEnd, State};

/// The six bytes every frame starts with.
pub const MAGIC: [u8; 6] = [0xFF, 0x00, b'H', b'E', b'J', b'1'];

/// The header: magic, length, the two digests, their separators and the LF.
pub const HEADER_BYTES: usize = 146;

/// R20: the largest payload.
pub const MAX_PAYLOAD_BYTES: usize = 0x0010_0000;

/// The first phase's status.
pub const PENDING: u8 = b'P';

/// The second phase's status: the only one a scan reads as a record.
pub const COMMITTED: u8 = b'C';

/// A revoked frame (R29).
pub const REVOKED: u8 = b'R';

/// The header bytes the header digest covers.
const DIGESTED_HEADER_BYTES: usize = 80;

fn hex_digest(bytes: &[u8]) -> String {
    sha256::hex(&sha256::digest(bytes))
}

/// The frame for `payload` with `status`; `None` for an empty payload or one above [`MAX_PAYLOAD_BYTES`].
pub fn encode(payload: &[u8], status: u8) -> Option<Vec<u8>> {
    if payload.is_empty() || payload.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    let mut frame = Vec::with_capacity(HEADER_BYTES + payload.len() + 2);
    frame.extend_from_slice(&MAGIC);
    frame.push(b' ');
    frame.extend_from_slice(format!("{:08x}", payload.len()).as_bytes());
    frame.push(b' ');
    frame.extend_from_slice(hex_digest(payload).as_bytes());
    let header_digest = hex_digest(&frame);
    frame.push(b' ');
    frame.extend_from_slice(header_digest.as_bytes());
    frame.push(b'\n');
    frame.extend_from_slice(payload);
    frame.push(status);
    frame.push(b'\n');
    Some(frame)
}

/// One item a scan finds, in file order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Scanned {
    /// A committed frame's payload (not yet decoded).
    Frame(Vec<u8>),
    /// An attempt, a region or a rest that is not a committed frame.
    Torn,
}

/// The current attempt (or the region before the first `0xFF`).
#[derive(Debug, Default)]
enum Attempt {
    /// No byte yet.
    #[default]
    Nothing,
    /// Bytes before the first `0xFF`.
    Leading,
    /// An attempt not decided yet; `total` is the frame length once the header has been read.
    Collecting { bytes: Vec<u8>, total: Option<usize> },
    /// Decided: not a committed frame.
    Torn,
    /// A committed frame with nothing after it so far.
    Committed,
    /// A committed frame followed by more bytes of the same attempt.
    Trailing,
}

/// The streaming scanner: [`Scanner::feed`] the bytes in order, then [`Scanner::finish`] (or [`Scanner::abort`] when
/// the rest cannot be read).
#[derive(Debug, Default)]
pub struct Scanner {
    attempt: Attempt,
    found: Vec<Scanned>,
}

/// The payload length a complete header announces, when the header is well formed, its digest matches and the length
/// is within 1..=[`MAX_PAYLOAD_BYTES`].
fn announced_length(header: &[u8]) -> Option<usize> {
    let separators_hold = header.get(..6)? == MAGIC
        && *header.get(6)? == b' '
        && *header.get(15)? == b' '
        && *header.get(80)? == b' '
        && *header.get(145)? == b'\n';
    let length = header.get(7..15)?;
    let payload_digest = header.get(16..80)?;
    let header_digest = header.get(81..145)?;
    let lower_hex = |field: &[u8]| field.iter().all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(byte));
    if !separators_hold || !lower_hex(length) || !lower_hex(payload_digest) || !lower_hex(header_digest) {
        return None;
    }
    if header_digest != hex_digest(header.get(..DIGESTED_HEADER_BYTES)?).as_bytes() {
        return None;
    }
    let length = usize::from_str_radix(std::str::from_utf8(length).ok()?, 16).ok()?;
    (1..=MAX_PAYLOAD_BYTES).contains(&length).then_some(length)
}

/// The payload of a complete frame whose payload digest matches and whose status is committed.
fn committed_payload(frame: &[u8]) -> Option<Vec<u8>> {
    let end = frame.len().checked_sub(2)?;
    let payload = frame.get(HEADER_BYTES..end)?;
    let committed = frame.get(end..)? == [COMMITTED, b'\n'];
    (committed && frame.get(16..80)? == hex_digest(payload).as_bytes()).then(|| payload.to_vec())
}

impl Scanner {
    /// Feeds the next bytes of the file.
    pub fn feed(&mut self, bytes: &[u8]) {
        let mut rest = bytes;
        while !rest.is_empty() {
            match rest.iter().position(|byte| *byte == 0xFF) {
                Some(0) => {
                    self.end_attempt();
                    self.attempt = Attempt::Collecting { bytes: vec![0xFF], total: None };
                    rest = rest.get(1..).unwrap_or_default();
                }
                Some(at) => {
                    let (inside, next) = rest.split_at_checked(at).unwrap_or((rest, &[]));
                    self.extend(inside);
                    rest = next;
                }
                None => {
                    self.extend(rest);
                    rest = &[];
                }
            }
        }
    }

    /// The items found, once every byte was fed.
    pub fn finish(mut self) -> Vec<Scanned> {
        self.end_attempt();
        self.found
    }

    /// The items found when the rest of the file cannot be read (R27) or lies beyond R20's bound: the attempt in
    /// progress and the unread rest are one TORN.
    pub fn abort(mut self) -> Vec<Scanned> {
        self.found.push(Scanned::Torn);
        self.found
    }

    fn end_attempt(&mut self) {
        match std::mem::take(&mut self.attempt) {
            Attempt::Nothing | Attempt::Committed => {}
            Attempt::Leading | Attempt::Collecting { .. } | Attempt::Torn | Attempt::Trailing => self.found.push(Scanned::Torn),
        }
    }

    /// Bytes of the current attempt (they hold no `0xFF`).
    fn extend(&mut self, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        self.attempt = match std::mem::take(&mut self.attempt) {
            Attempt::Nothing | Attempt::Leading => Attempt::Leading,
            Attempt::Torn => Attempt::Torn,
            Attempt::Committed | Attempt::Trailing => Attempt::Trailing,
            Attempt::Collecting { bytes: collected, total } => self.collect(collected, total, bytes),
        };
    }

    /// Adds bytes to an undecided attempt until its header, then its whole frame, is there.
    fn collect(&mut self, mut collected: Vec<u8>, mut total: Option<usize>, bytes: &[u8]) -> Attempt {
        let mut rest = bytes;
        loop {
            let target = total.unwrap_or(HEADER_BYTES);
            let wanted = target.saturating_sub(collected.len()).min(rest.len());
            let (taken, next) = rest.split_at_checked(wanted).unwrap_or((rest, &[]));
            collected.extend_from_slice(taken);
            rest = next;
            if collected.len() < target {
                return Attempt::Collecting { bytes: collected, total };
            }
            match total {
                None => match announced_length(&collected).and_then(|length| length.checked_add(HEADER_BYTES + 2)) {
                    Some(frame_length) => total = Some(frame_length),
                    None => return Attempt::Torn,
                },
                Some(_) => {
                    return match committed_payload(&collected) {
                        Some(payload) => {
                            self.found.push(Scanned::Frame(payload));
                            if rest.is_empty() { Attempt::Committed } else { Attempt::Trailing }
                        }
                        None => Attempt::Torn,
                    };
                }
            }
        }
    }
}

/// Scans bytes held in memory.
pub fn scan_bytes(bytes: &[u8]) -> Vec<Scanned> {
    let mut scanner = Scanner::default();
    scanner.feed(bytes);
    scanner.finish()
}

/// Journal entries from a scan: a committed frame whose payload decodes is its record, anything else TORN.
pub fn journal_entries(found: Vec<Scanned>) -> Vec<Entry> {
    found
        .into_iter()
        .map(|item| match item {
            Scanned::Frame(payload) => decode_record(&payload).map_or(Entry::Torn, Entry::Record),
            Scanned::Torn => Entry::Torn,
        })
        .collect()
}

// ------------------------------------------------------------------------------------------ payloads

/// The generation index's payload, `["GENERATION", generation]`.
pub fn generation_payload(generation: &str) -> Vec<u8> {
    Doc::Array(vec![Doc::str("GENERATION"), Doc::str(generation)]).canonical()
}

/// The failure marker's payload, `["MARKER", generation, reason]`.
pub fn marker_payload(generation: &str, reason: &str) -> Vec<u8> {
    Doc::Array(vec![Doc::str("MARKER"), Doc::str(generation), Doc::str(reason)]).canonical()
}

/// The JSON value of a payload that is UTF-8 JSON in its canonical encoding.
fn canonical_value(payload: &[u8]) -> Option<Value> {
    let value = json::parse(std::str::from_utf8(payload).ok()?).ok()?;
    (json::canonical(&value).ok()? == payload).then_some(value)
}

/// A generation index entry's generation.
pub fn decode_generation(payload: &[u8]) -> Option<String> {
    match canonical_value(payload)?.as_array()? {
        [tag, generation] if tag.as_str() == Some("GENERATION") => text(generation),
        _ => None,
    }
}

/// A marker's generation and reason.
pub fn decode_marker(payload: &[u8]) -> Option<(String, String)> {
    match canonical_value(payload)?.as_array()? {
        [tag, generation, reason] if tag.as_str() == Some("MARKER") => Some((text(generation)?, text(reason)?)),
        _ => None,
    }
}

fn text(value: &Value) -> Option<String> {
    value.as_str().map(str::to_string)
}

fn optional_text(value: &Value) -> Option<Option<String>> {
    match value {
        Value::Null => Some(None),
        other => Some(Some(text(other)?)),
    }
}

fn texts(value: &Value) -> Option<Vec<String>> {
    value.as_array()?.iter().map(text).collect()
}

fn integer(value: &Value) -> Option<i64> {
    value.as_int()?.to_i64()
}

fn small(value: &Value) -> Option<u16> {
    u16::try_from(integer(value)?).ok()
}

fn state(value: &Value) -> Option<State> {
    State::parse(value.as_str()?)
}

fn named<T: Copy>(value: &Value, candidates: &[T], name: impl Fn(T) -> &'static str) -> Option<T> {
    let wanted = value.as_str()?;
    candidates.iter().copied().find(|candidate| name(*candidate) == wanted)
}

const CLASSIFICATIONS: [Classification; 3] =
    [Classification::NotForwarded, Classification::DeliveredResult, Classification::IoAmbiguous];

const FATAL_REASONS: [FatalReason; 17] = [
    FatalReason::InvalidFrame(FrameError::F00),
    FatalReason::InvalidFrame(FrameError::F01),
    FatalReason::InvalidFrame(FrameError::F02),
    FatalReason::InvalidFrame(FrameError::F03),
    FatalReason::InvalidFrame(FrameError::F04),
    FatalReason::InvalidFrame(FrameError::F05),
    FatalReason::InvalidFrame(FrameError::F06),
    FatalReason::InvalidFrame(FrameError::F07),
    FatalReason::Direction,
    FatalReason::ChainBroken,
    FatalReason::GenerationMismatch,
    FatalReason::OpeningFrameRequired,
    FatalReason::ChallengeMismatch,
    FatalReason::PeerQualificationMismatch,
    FatalReason::PeerLost,
    FatalReason::PeerChanged,
    FatalReason::ResponseOutOfBounds,
];

const MAINTENANCE_ENDS: [MaintenanceEnd; 3] =
    [MaintenanceEnd::WriteEnd, MaintenanceEnd::Session(SessionEnd::Ended), MaintenanceEnd::Session(SessionEnd::Fatal)];

const SESSION_ENDS: [SessionEnd; 2] = [SessionEnd::Ended, SessionEnd::Fatal];

const ABORT_REASONS: [AbortReason; 4] = [
    AbortReason::WriterChannelLost,
    AbortReason::WriterPeerDeviation,
    AbortReason::WriterProtocolFailure,
    AbortReason::UpstreamTimeout,
];

fn classification(value: &Value) -> Option<Classification> {
    named(value, &CLASSIFICATIONS, Classification::as_str)
}

fn invalidation(value: &Value) -> Option<Invalidation> {
    let name = value.as_str()?;
    if name == Invalidation::WriterPeerDeviation.as_str() {
        return Some(Invalidation::WriterPeerDeviation);
    }
    if let Some(reason) = CloseReason::parse(name) {
        return Some(Invalidation::Close(reason));
    }
    named(value, &FATAL_REASONS, FatalReason::as_str).map(Invalidation::Fatal)
}

fn terminal_details(value: &Value) -> Option<TerminalDetails> {
    let members = value.as_object()?.len();
    Some(match members {
        0 => TerminalDetails::None,
        1 if value.get("aborted")?.as_str() == Some("UPSTREAM_TIMEOUT") => TerminalDetails::Aborted,
        2 => TerminalDetails::Reconciliation {
            http_status: integer(value.get("httpStatus")?)?,
            result_digest: text(value.get("resultDigest")?)?,
        },
        4 => TerminalDetails::Delivered {
            http_status: integer(value.get("httpStatus")?)?,
            result_digest: text(value.get("resultDigest")?)?,
            observed_uid: optional_text(value.get("observedUid")?)?,
            observed_resource_version: optional_text(value.get("observedResourceVersion")?)?,
        },
        _ => return None,
    })
}

fn write_details(value: &Value) -> Option<WriteDetails> {
    let members = value.as_object()?.len();
    Some(match members {
        0 => WriteDetails::Lost,
        1 => WriteDetails::Aborted(named(value.get("aborted")?, &ABORT_REASONS, AbortReason::as_str)?),
        2 => WriteDetails::Reconciliation {
            http_status: integer(value.get("httpStatus")?)?,
            result_digest: text(value.get("resultDigest")?)?,
        },
        4 => WriteDetails::Delivered {
            http_status: integer(value.get("httpStatus")?)?,
            result_digest: text(value.get("resultDigest")?)?,
            observed_uid: optional_text(value.get("observedUid")?)?,
            observed_resource_version: optional_text(value.get("observedResourceVersion")?)?,
        },
        _ => return None,
    })
}

fn prior(value: &Value) -> Option<Option<Prior>> {
    if value.is_null() {
        return Some(None);
    }
    Some(Some(Prior {
        uid: text(value.get("uid")?)?,
        resource_version: text(value.get("resourceVersion")?)?,
        projection_digest: text(value.get("projectionDigest")?)?,
    }))
}

/// A journal record's payload back to its record (§5.3, R21).
pub fn decode_record(payload: &[u8]) -> Option<Record> {
    let value = canonical_value(payload)?;
    let (tag, fields) = value.as_array()?.split_first()?;
    let record = match (tag.as_str()?, fields) {
        ("BIND", [execution_id, run_nonce, reservation_digest, digests, identities]) => Record::Bind {
            execution_id: text(execution_id)?,
            run_nonce: text(run_nonce)?,
            reservation_digest: text(reservation_digest)?,
            manifest_digests: texts(digests)?,
            manifest_identities: texts(identities)?,
        },
        ("ARM", [action_id, verb, manifest_digest, recorded_uid, template_digest]) => Record::Arm {
            action_id: small(action_id)?,
            verb: Verb::parse(verb.as_str()?)?,
            manifest_digest: text(manifest_digest)?,
            recorded_uid: optional_text(recorded_uid)?,
            template_digest: text(template_digest)?,
        },
        ("CONSUMED", [action_id]) => Record::Consumed { action_id: small(action_id)? },
        ("TERMINAL", [action_id, class, after, details]) => Record::Terminal {
            action_id: small(action_id)?,
            classification: classification(class)?,
            after_invalidation: after.as_bool()?,
            details: terminal_details(details)?,
        },
        ("SEALED", [action_id, class, after]) => Record::Sealed {
            action_id: small(action_id)?,
            classification: classification(class)?,
            after_invalidation: after.as_bool()?,
        },
        ("DENIED", [action_id]) => Record::Denied { action_id: small(action_id)? },
        ("INVALIDATED", [reason, recorded]) => Record::Invalidated { reason: invalidation(reason)?, state: state(recorded)? },
        ("CLOSED", [reason, recorded]) => {
            Record::Closed { reason: CloseReason::parse(reason.as_str()?)?, state: state(recorded)? }
        }
        ("DRAINED", [recorded]) => Record::Drained { state: state(recorded)? },
        ("DRAIN_STARTED", []) => Record::DrainStarted,
        ("CHANNEL_ENDED", [end]) => Record::ChannelEnded(match end.as_str()? {
            "BEFORE_FIRST_FRAME" => ChannelEnd::BeforeFirstFrame,
            "ORDERLY" => ChannelEnd::Orderly,
            _ => return None,
        }),
        ("EXPIRED", [execution_id]) => Record::Expired { execution_id: text(execution_id)? },
        ("LATE_UPSTREAM", [action_id]) => Record::LateUpstream { action_id: small(action_id)? },
        ("RESTARTED", [recorded]) => Record::Restarted { state: state(recorded)? },
        ("MAINT_REQUESTED", [generation]) => Record::MaintRequested { generation: text(generation)? },
        ("MAINT_OPEN", [recorded]) => Record::MaintOpen { state: state(recorded)? },
        ("MAINT_HELD", [recorded]) => Record::MaintHeld { state: state(recorded)? },
        ("WRITE_FORWARDED", [write_id, operation, api_version, kind, namespace, name, request_digest, written_prior]) => {
            Record::WriteForwarded {
                write_id: small(write_id)?,
                operation: WriteOperation::parse(operation.as_str()?)?,
                api_version: text(api_version)?,
                kind: text(kind)?,
                namespace: optional_text(namespace)?,
                name: text(name)?,
                request_digest: text(request_digest)?,
                prior: prior(written_prior)?,
            }
        }
        ("WRITE_TERMINAL", [write_id, class, details]) => Record::WriteTerminal {
            write_id: small(write_id)?,
            classification: classification(class)?,
            details: write_details(details)?,
        },
        ("MAINT_ENDED", [reason, writes, ambiguous]) => Record::MaintEnded {
            reason: named(reason, &MAINTENANCE_ENDS, MaintenanceEnd::as_str)?,
            writes: small(writes)?,
            ambiguous_write_ids: ambiguous.as_array()?.iter().map(small).collect::<Option<Vec<u16>>>()?,
        },
        ("WRITER_SESSION_ENDED", [how]) => Record::WriterSessionEnded { how: named(how, &SESSION_ENDS, SessionEnd::as_str)? },
        ("WRITE_LATE_UPSTREAM", [write_id]) => Record::WriteLateUpstream { write_id: small(write_id)? },
        _ => return None,
    };
    // Exactly the gate's own tuple: no extra member, no other spelling.
    (record.to_doc().canonical() == payload).then_some(record)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// One tuple of every payload kind with the SHA-256 of its committed frame, computed independently of this
    /// crate from the DESIGN §4 grammar.
    const PINNED: [(&str, &str); 24] = [
        (r#"["BIND","e-1","run-one","sha256:r",["sha256:m1","sha256:m2"],["Pod/q/p"]]"#,
         "3dddc361615197e1d404cb1309cc04024378cc4b8c74abd11d3c1dd0197b7559"),
        (r#"["ARM",1,"CREATE","sha256:m1",null,"sha256:t"]"#, "a51dc1f26b370e6cd363ba1c80dfbe98b296a3610845532313b8042f86ee473e"),
        (r#"["CONSUMED",1]"#, "6373dcc4d19e4fef1f86bc77429eecf091eb611eab2dfb25d0be2e31d12e511e"),
        (r#"["TERMINAL",1,"DELIVERED_RESULT",false,{"httpStatus":201,"observedResourceVersion":"41","observedUid":"u-1","resultDigest":"sha256:b"}]"#,
         "159a98ce9edef8ef943c31dc367a7b77b20bb72c7d6d53fb1c88beaa676a861e"),
        (r#"["SEALED",1,"IO_AMBIGUOUS",true]"#, "cfa089b4e75624e82c23a132ee19b931f7f9a8c553e10c7b745b163ce989e3af"),
        (r#"["DENIED",2]"#, "e29567836d58f83f7d23803ca92e73efd469f47468fe29984c98e07f4be1e4ec"),
        (r#"["INVALIDATED","F06_INVALID_FRAME","HELD"]"#, "faaa17a9bc7cba091c0a34cdb7d718a5f8000e58dc94246107fba8b0b2e643a2"),
        (r#"["CLOSED","NORMAL_DRAIN","CLOSED"]"#, "ae21efb56baa8fe17eff7cb572cb365001d4e04da876e5ddc8f79d5435b85c96"),
        (r#"["DRAINED","CLOSED"]"#, "76ed27b1f84f5688a1e3acd8a7aa8b5b605c2b6e937d8b464ff93b31f137e154"),
        (r#"["DRAIN_STARTED"]"#, "7610b089b846c5930a61ea1432021929fab62793169be8e5ba07a0d6a6fe7919"),
        (r#"["CHANNEL_ENDED","BEFORE_FIRST_FRAME"]"#, "0d7fda21b258763f4a240df4a6878535e7213d0b5cd319e5535260899e3f92e1"),
        (r#"["EXPIRED","e-1"]"#, "8bee5c529b5a19a75db210d174469882298e87251c894d2d00c0f0c7a11e203e"),
        (r#"["LATE_UPSTREAM",3]"#, "0841c5c90b37b37040580cc545344d86ded3d7916d5d1be489335d5d1071ec85"),
        (r#"["RESTARTED","HELD"]"#, "7437f91e0cddda63060bd025d3a3cf19fbcb9e40536a8473c6cbecd05cd77190"),
        (r#"["MAINT_REQUESTED","g-1"]"#, "65f42ce11ae30e55608cdc27606604d2eb8356876fc8c3b0577fdde4e70af1dd"),
        (r#"["MAINT_OPEN","CLOSED"]"#, "41d4d36568af6be65bbf557df686928f05d72d09bb1dd96a7c39572f64a0958c"),
        (r#"["MAINT_HELD","HELD"]"#, "0ac921a602b1ec6831fc6107c04c9e14c69ff82411dd2a0bdb57c4ccfce39cef"),
        (r#"["WRITE_FORWARDED",1,"UPDATE","rbac.authorization.k8s.io/v1","Role","q","r","sha256:q",{"projectionDigest":"sha256:p","resourceVersion":"41","uid":"u-1"}]"#,
         "763dd5632965113e632cb68be350971729d68117d54e842a44a9cbc703861327"),
        (r#"["WRITE_TERMINAL",1,"IO_AMBIGUOUS",{"aborted":"WRITER_CHANNEL_LOST"}]"#,
         "203193f9bc7f2286766202900d8ec2eabc9708424162f6f231a1364e26ae3fc1"),
        (r#"["MAINT_ENDED","SESSION_FATAL",2,[1,2]]"#, "24c6ded316c0931191a4884f46375a731e5570c87aeeccbf7a941cb75c701bea"),
        (r#"["WRITER_SESSION_ENDED","ENDED"]"#, "5ed906481afe7840d41491500b3c4427d18a94d8f8afc1e8f570f8d3c8b02b24"),
        (r#"["WRITE_LATE_UPSTREAM",4]"#, "285d08170c1403742f6e8967500d7be68905b1a8bae82fec80bbe9ecf7f189c8"),
        (r#"["GENERATION","g-1"]"#, "49977c1b3d723aaf65e993419c3c4f671a6a5c3ee326a377500feb20d1d3ff3f"),
        (r#"["MARKER","g-1","STORAGE_FAILURE"]"#, "0dfc8c6e59a230c5a402041d2d748a0ee071f45bf350e9e9ee190275765f01a5"),
    ];

    /// `["DRAIN_STARTED"]` (17 payload bytes, a 165-byte frame), byte for byte.
    const DRAIN_STARTED_FRAME: &str = "ff0048454a312030303030303031312039643165313663623961353138646635643132333834\
        3164366161643738353536633737376132396162323061646333623639386366356434656565353334632033653837396266333638\
        35353931383430383665636265626637363931353438306134333730396238396231656139653763666531313831623663633238\
        63630a5b22445241494e5f53544152544544225d430a";

    fn s(text: &str) -> String {
        text.to_string()
    }

    /// The records of [`PINNED`]'s first 22 rows, in order.
    fn pinned_records() -> Vec<Record> {
        vec![
            Record::Bind {
                execution_id: s("e-1"),
                run_nonce: s("run-one"),
                reservation_digest: s("sha256:r"),
                manifest_digests: vec![s("sha256:m1"), s("sha256:m2")],
                manifest_identities: vec![s("Pod/q/p")],
            },
            Record::Arm {
                action_id: 1,
                verb: Verb::Create,
                manifest_digest: s("sha256:m1"),
                recorded_uid: None,
                template_digest: s("sha256:t"),
            },
            Record::Consumed { action_id: 1 },
            Record::Terminal {
                action_id: 1,
                classification: Classification::DeliveredResult,
                after_invalidation: false,
                details: TerminalDetails::Delivered {
                    http_status: 201,
                    result_digest: s("sha256:b"),
                    observed_uid: Some(s("u-1")),
                    observed_resource_version: Some(s("41")),
                },
            },
            Record::Sealed { action_id: 1, classification: Classification::IoAmbiguous, after_invalidation: true },
            Record::Denied { action_id: 2 },
            Record::Invalidated { reason: Invalidation::Fatal(FatalReason::InvalidFrame(FrameError::F06)), state: State::Held },
            Record::Closed { reason: CloseReason::NormalDrain, state: State::Closed },
            Record::Drained { state: State::Closed },
            Record::DrainStarted,
            Record::ChannelEnded(ChannelEnd::BeforeFirstFrame),
            Record::Expired { execution_id: s("e-1") },
            Record::LateUpstream { action_id: 3 },
            Record::Restarted { state: State::Held },
            Record::MaintRequested { generation: s("g-1") },
            Record::MaintOpen { state: State::Closed },
            Record::MaintHeld { state: State::Held },
            Record::WriteForwarded {
                write_id: 1,
                operation: WriteOperation::Update,
                api_version: s("rbac.authorization.k8s.io/v1"),
                kind: s("Role"),
                namespace: Some(s("q")),
                name: s("r"),
                request_digest: s("sha256:q"),
                prior: Some(Prior { uid: s("u-1"), resource_version: s("41"), projection_digest: s("sha256:p") }),
            },
            Record::WriteTerminal {
                write_id: 1,
                classification: Classification::IoAmbiguous,
                details: WriteDetails::Aborted(AbortReason::WriterChannelLost),
            },
            Record::MaintEnded { reason: MaintenanceEnd::Session(SessionEnd::Fatal), writes: 2, ambiguous_write_ids: vec![1, 2] },
            Record::WriterSessionEnded { how: SessionEnd::Ended },
            Record::WriteLateUpstream { write_id: 4 },
        ]
    }

    /// Records whose shapes the pinned rows do not cover.
    fn more_records() -> Vec<Record> {
        vec![
            Record::Arm {
                action_id: 65535,
                verb: Verb::Delete,
                manifest_digest: s("sha256:m"),
                recorded_uid: Some(s("u \"quoted\" \\ \u{1}")),
                template_digest: s("sha256:t"),
            },
            Record::Arm { action_id: 2, verb: Verb::Get, manifest_digest: s("é"), recorded_uid: None, template_digest: s("t") },
            Record::Terminal {
                action_id: 1,
                classification: Classification::IoAmbiguous,
                after_invalidation: true,
                details: TerminalDetails::Reconciliation { http_status: 503, result_digest: s("sha256:x") },
            },
            Record::Terminal {
                action_id: 1,
                classification: Classification::IoAmbiguous,
                after_invalidation: false,
                details: TerminalDetails::None,
            },
            Record::Terminal {
                action_id: 1,
                classification: Classification::IoAmbiguous,
                after_invalidation: false,
                details: TerminalDetails::Aborted,
            },
            Record::Terminal {
                action_id: 1,
                classification: Classification::DeliveredResult,
                after_invalidation: false,
                details: TerminalDetails::Delivered {
                    http_status: -1,
                    result_digest: s(""),
                    observed_uid: None,
                    observed_resource_version: None,
                },
            },
            Record::Sealed { action_id: 0, classification: Classification::NotForwarded, after_invalidation: false },
            Record::Invalidated { reason: Invalidation::Close(CloseReason::StorageFailure), state: State::Held },
            Record::Invalidated { reason: Invalidation::WriterPeerDeviation, state: State::Held },
            Record::Invalidated { reason: Invalidation::Fatal(FatalReason::ResponseOutOfBounds), state: State::Invalidated },
            Record::Closed { reason: CloseReason::ReconciliationRequired, state: State::Inspecting },
            Record::Drained { state: State::Draining },
            Record::ChannelEnded(ChannelEnd::Orderly),
            Record::Restarted { state: State::Active },
            Record::WriteForwarded {
                write_id: 256,
                operation: WriteOperation::Create,
                api_version: s("v1"),
                kind: s("Namespace"),
                namespace: None,
                name: s("planeon-qual"),
                request_digest: s("sha256:q"),
                prior: None,
            },
            Record::WriteTerminal {
                write_id: 2,
                classification: Classification::DeliveredResult,
                details: WriteDetails::Delivered {
                    http_status: 409,
                    result_digest: s("sha256:b"),
                    observed_uid: None,
                    observed_resource_version: None,
                },
            },
            Record::WriteTerminal {
                write_id: 3,
                classification: Classification::IoAmbiguous,
                details: WriteDetails::Reconciliation { http_status: 408, result_digest: s("sha256:b") },
            },
            Record::WriteTerminal { write_id: 4, classification: Classification::IoAmbiguous, details: WriteDetails::Lost },
            Record::MaintEnded { reason: MaintenanceEnd::WriteEnd, writes: 0, ambiguous_write_ids: Vec::new() },
            Record::MaintEnded { reason: MaintenanceEnd::Session(SessionEnd::Ended), writes: 1, ambiguous_write_ids: vec![1] },
            Record::WriterSessionEnded { how: SessionEnd::Fatal },
        ]
    }

    fn committed(record: &Record) -> Vec<u8> {
        encode(&record.to_doc().canonical(), COMMITTED).unwrap_or_default()
    }

    fn hex(bytes: &[u8]) -> String {
        sha256::hex(bytes)
    }

    #[test]
    fn every_payload_kind_has_its_pinned_frame() {
        let records = pinned_records();
        assert_eq!(records.len(), 22, "every record variant");
        let mut payloads: Vec<Vec<u8>> = records.iter().map(|record| record.to_doc().canonical()).collect();
        payloads.push(generation_payload("g-1"));
        payloads.push(marker_payload("g-1", "STORAGE_FAILURE"));
        for (payload, (text, digest)) in payloads.iter().zip(PINNED) {
            assert_eq!(String::from_utf8_lossy(payload), text);
            let frame = encode(payload, COMMITTED).unwrap_or_default();
            assert_eq!(frame.len(), HEADER_BYTES + payload.len() + 2);
            assert_eq!(hex_digest(&frame), digest, "{text}");
        }
        let drain = encode(br#"["DRAIN_STARTED"]"#, COMMITTED).unwrap_or_default();
        assert_eq!(drain.len(), 165);
        assert_eq!(hex(&drain), DRAIN_STARTED_FRAME.replace(' ', ""));
    }

    #[test]
    fn decoding_inverts_encoding() {
        for record in pinned_records().into_iter().chain(more_records()) {
            let payload = record.to_doc().canonical();
            assert_eq!(decode_record(&payload), Some(record.clone()));
            assert_eq!(journal_entries(scan_bytes(&committed(&record))), [Entry::Record(record)]);
        }
        assert_eq!(decode_generation(&generation_payload("g.1_x-2")), Some(s("g.1_x-2")));
        assert_eq!(decode_marker(&marker_payload("g", "STORAGE_FAILURE")), Some((s("g"), s("STORAGE_FAILURE"))));
        assert_eq!(decode_generation(&marker_payload("g", "STORAGE_FAILURE")), None);
        assert_eq!(decode_marker(&generation_payload("g")), None);
        assert_eq!(decode_record(&generation_payload("g")), None);
    }

    #[test]
    fn the_decoder_accepts_only_the_gate_tuples() {
        let refused: [&[u8]; 16] = [
            br#"["DRAIN_STARTED" ]"#,
            br#"[ "DRAIN_STARTED"]"#,
            br#"["DRAIN_STARTED",1]"#,
            br#"["NOPE"]"#,
            br#"["CONSUMED",65536]"#,
            br#"["CONSUMED",-1]"#,
            br#"["CONSUMED",1.0]"#,
            br#"["CONSUMED","1"]"#,
            br#"["SEALED",1,"IO_AMBIGUOUS",1]"#,
            br#"["RESTARTED","held"]"#,
            br#"["TERMINAL",1,"IO_AMBIGUOUS",false,{"aborted":"UPSTREAM_TIMEOUT","x":1}]"#,
            br#"["TERMINAL",1,"IO_AMBIGUOUS",false,{"httpStatus":503,"resultDigests":"x"}]"#,
            br#"["WRITE_TERMINAL",1,"IO_AMBIGUOUS",{"aborted":"UPSTREAM_TIMEOUT","httpStatus":1,"x":2,"y":3}]"#,
            br#"["INVALIDATED","F08_INVALID_FRAME","HELD"]"#,
            br#"{"BIND":1}"#,
            b"[\"DRAIN_STARTED\"]\n",
        ];
        for payload in refused {
            assert_eq!(decode_record(payload), None, "{}", String::from_utf8_lossy(payload));
        }
        assert_eq!(decode_record(&[0xC3]), None, "not UTF-8");
        assert_eq!(decode_record(br#"["CONSUMED",65535]"#), Some(Record::Consumed { action_id: 65535 }));
    }

    /// Three frames of different kinds, back to back, and their records.
    fn three() -> (Vec<Vec<u8>>, Vec<Entry>) {
        let records = [
            Record::DrainStarted,
            pinned_records().swap_remove(1),
            pinned_records().swap_remove(3),
        ];
        (records.iter().map(committed).collect(), records.into_iter().map(Entry::Record).collect())
    }

    fn scan(bytes: &[u8]) -> Vec<Entry> {
        journal_entries(scan_bytes(bytes))
    }

    #[test]
    fn a_changed_byte_tears_exactly_its_own_frame() {
        let (frames, records) = three();
        let file: Vec<u8> = frames.concat();
        assert_eq!(scan(&file), records);
        let mut start = 0;
        let mut checked = 0;
        for (index, frame) in frames.iter().enumerate() {
            let mut expected = records.clone();
            expected[index] = Entry::Torn;
            for position in start..start + frame.len() {
                let original = file[position];
                for value in [original ^ 0x01, 0x00] {
                    if value == original || value == 0xFF {
                        continue;
                    }
                    let mut changed = file.clone();
                    changed[position] = value;
                    assert_eq!(scan(&changed), expected, "frame {index}, byte {position}, value {value:#04x}");
                    checked += 1;
                }
            }
            start += frame.len();
        }
        assert!(checked > 2 * file.len() - 20, "{checked} mutations");
    }

    #[test]
    fn a_new_ff_byte_tears_its_frame_in_two() {
        let (frames, records) = three();
        let file: Vec<u8> = frames.concat();
        let start = frames[0].len();
        for position in start + 1..start + frames[1].len() {
            let mut changed = file.clone();
            changed[position] = 0xFF;
            let expected = vec![records[0].clone(), Entry::Torn, Entry::Torn, records[2].clone()];
            assert_eq!(scan(&changed), expected, "byte {position}");
        }
    }

    #[test]
    fn every_truncation_is_one_torn_attempt() {
        let (frames, records) = three();
        for frame in &frames {
            for length in 1..frame.len() {
                assert_eq!(scan(&frame[..length]), [Entry::Torn], "{length} of {}", frame.len());
            }
            assert_eq!(scan(&frame[..HEADER_BYTES]), [Entry::Torn], "a header without its payload");
        }
        // A torn attempt followed by a whole frame: the next append starts at the torn bytes' end.
        let mut file = frames[1][..frames[1].len() / 2].to_vec();
        file.extend_from_slice(&frames[2]);
        assert_eq!(scan(&file), [Entry::Torn, records[2].clone()]);
    }

    #[test]
    fn pending_revoked_and_odd_regions_are_torn() {
        let payload = Record::DrainStarted.to_doc().canonical();
        let pending = encode(&payload, PENDING).unwrap_or_default();
        let revoked = encode(&payload, REVOKED).unwrap_or_default();
        let done = encode(&payload, COMMITTED).unwrap_or_default();
        let record = Entry::Record(Record::DrainStarted);
        assert_eq!(scan(&pending), [Entry::Torn]);
        assert_eq!(scan(&revoked), [Entry::Torn]);
        assert_eq!(scan(&[pending.clone(), revoked.clone()].concat()), [Entry::Torn, Entry::Torn], "two adjacent torn attempts");
        assert_eq!(scan(&[pending, done.clone(), revoked].concat()), [Entry::Torn, record.clone(), Entry::Torn]);
        assert_eq!(scan(&[0xFF, 0x00, b'H']), [Entry::Torn], "a partial magic");
        assert_eq!(scan(&[0xFF]), [Entry::Torn]);
        let mut zero_filled = done.clone();
        zero_filled.extend_from_slice(&[0u8; 4096]);
        assert_eq!(scan(&zero_filled), [record.clone(), Entry::Torn], "a committed frame followed by zero fill");
        assert_eq!(scan(&[0u8; 4096]), [Entry::Torn], "zero fill alone");
        assert_eq!(scan(b"leading bytes"), [Entry::Torn], "a leading region without 0xFF");
        assert_eq!(scan(&[b"leading".as_slice(), &done].concat()), [Entry::Torn, record]);
        assert_eq!(scan(&[]), Vec::<Entry>::new());
        // Valid digests around a payload the decoder refuses (R21).
        let undecodable = encode(br#"["NOPE"]"#, COMMITTED).unwrap_or_default();
        assert_eq!(scan_bytes(&undecodable), [Scanned::Frame(br#"["NOPE"]"#.to_vec())]);
        assert_eq!(scan(&undecodable), [Entry::Torn]);
        assert_eq!(scan(&encode(&[0xC3, 0xA9], COMMITTED).unwrap_or_default()), [Entry::Torn]);
    }

    #[test]
    fn the_length_field_is_bounded() {
        assert_eq!(encode(&[], COMMITTED), None);
        assert_eq!(encode(&vec![b'1'; MAX_PAYLOAD_BYTES + 1], COMMITTED), None);
        assert!(encode(&vec![b'1'; MAX_PAYLOAD_BYTES], COMMITTED).is_some());
        // Headers that announce 0 or 1 MiB + 1 payload bytes, with a matching header digest.
        for length in [0usize, MAX_PAYLOAD_BYTES + 1] {
            let mut header = MAGIC.to_vec();
            header.extend_from_slice(format!(" {length:08x} {}", hex_digest(b"x")).as_bytes());
            let digest = hex_digest(&header);
            header.extend_from_slice(format!(" {digest}\n").as_bytes());
            header.extend_from_slice(b"xC\n");
            assert_eq!(scan_bytes(&header), [Scanned::Torn], "length {length}");
        }
        // Uppercase hex is not the format, even with matching digests.
        let frame = encode(b"[1]", COMMITTED).unwrap_or_default();
        let text = String::from_utf8_lossy(&frame[6..]).to_uppercase();
        let mut upper = MAGIC.to_vec();
        upper.extend_from_slice(text.as_bytes());
        assert_eq!(scan_bytes(&upper), [Scanned::Torn]);
    }

    #[test]
    fn feeding_in_pieces_changes_nothing() {
        let (frames, records) = three();
        let mut file: Vec<u8> = frames.concat();
        file.extend_from_slice(b"tail");
        file.extend_from_slice(&frames[0][..40]);
        let whole = scan(&file);
        assert_eq!(whole[..3], records[..]);
        assert_eq!(whole.len(), 5);
        for size in [1usize, 2, 7, 64, 145, 146, 147] {
            let mut scanner = Scanner::default();
            for piece in file.chunks(size) {
                scanner.feed(piece);
            }
            assert_eq!(journal_entries(scanner.finish()), whole, "pieces of {size}");
        }
    }

    #[test]
    fn an_aborted_scan_ends_with_one_torn() {
        let (frames, records) = three();
        let mut scanner = Scanner::default();
        scanner.feed(&frames[0]);
        scanner.feed(&frames[1][..20]);
        assert_eq!(journal_entries(scanner.abort()), [records[0].clone(), Entry::Torn]);
        let mut scanner = Scanner::default();
        scanner.feed(&frames[0]);
        assert_eq!(journal_entries(scanner.abort()), [records[0].clone(), Entry::Torn]);
    }
}
