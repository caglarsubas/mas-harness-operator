//! The durable journal as typed records (I05 v1 and v2 "Durable journal", and the I07 records of I07 v1-v3), their
//! exact canonical tuple form (which the journal digest covers), the in-memory store with the contract's three test
//! injections, and the failure marker. The injection queue lives in `store::FaultPlan` (HE-002C, moved unchanged);
//! the byte format and the file-backed stores are `frame` and `file_store`.

use i05_protocol::json::Doc;
use i05_protocol::Verb;

use crate::policy::{Prior, WriteOperation};
use crate::store::FaultPlan;
use crate::types::{AbortReason, Classification, CloseReason, Invalidation, MaintenanceEnd, SessionEnd, State};

/// A TERMINAL record's details.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalDetails {
    /// A settled response: `{httpStatus, resultDigest, observedUid, observedResourceVersion}`.
    Delivered { http_status: i64, result_digest: String, observed_uid: Option<String>, observed_resource_version: Option<String> },
    /// An unknown mutation outcome kept for reconciliation: `{httpStatus, resultDigest}`.
    Reconciliation { http_status: i64, result_digest: String },
    /// A lost exchange, or a TERMINAL record written after its write failed: `{}`.
    None,
    /// The 900-second upstream bound expired: `{aborted: UPSTREAM_TIMEOUT}` (Decision 12).
    Aborted,
}

/// A WRITE_TERMINAL record's details (HE-002B DESIGN §5, N19).
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum WriteDetails {
    /// A settling response: `{httpStatus, resultDigest, observedUid, observedResourceVersion}`, the observed members
    /// null unless the status is the operation's success.
    Delivered { http_status: i64, result_digest: String, observed_uid: Option<String>, observed_resource_version: Option<String> },
    /// A response that leaves the outcome unknown, kept for reconciliation: `{httpStatus, resultDigest}`.
    Reconciliation { http_status: i64, result_digest: String },
    /// A LOST upstream outcome: `{}`.
    Lost,
    /// The gate gave the exchange up: `{aborted: reason}`.
    Aborted(AbortReason),
}

impl WriteDetails {
    pub fn to_doc(&self) -> Doc {
        match self {
            WriteDetails::Delivered { http_status, result_digest, observed_uid, observed_resource_version } => {
                Doc::object(vec![
                    ("httpStatus", Doc::Int(*http_status)),
                    ("resultDigest", Doc::str(result_digest)),
                    ("observedUid", Doc::opt_str(observed_uid.as_deref())),
                    ("observedResourceVersion", Doc::opt_str(observed_resource_version.as_deref())),
                ])
            }
            WriteDetails::Reconciliation { http_status, result_digest } => Doc::object(vec![
                ("httpStatus", Doc::Int(*http_status)),
                ("resultDigest", Doc::str(result_digest)),
            ]),
            WriteDetails::Lost => Doc::Object(Vec::new()),
            WriteDetails::Aborted(reason) => Doc::object(vec![("aborted", Doc::str(reason.as_str()))]),
        }
    }
}

/// How the channel ended without a fatal failure.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum ChannelEnd {
    BeforeFirstFrame,
    Orderly,
}

/// One journal record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    Bind {
        execution_id: String,
        run_nonce: String,
        reservation_digest: String,
        manifest_digests: Vec<String>,
        manifest_identities: Vec<String>,
    },
    Arm { action_id: u16, verb: Verb, manifest_digest: String, recorded_uid: Option<String>, template_digest: String },
    Consumed { action_id: u16 },
    Terminal { action_id: u16, classification: Classification, after_invalidation: bool, details: TerminalDetails },
    Sealed { action_id: u16, classification: Classification, after_invalidation: bool },
    Denied { action_id: u16 },
    Invalidated { reason: Invalidation, state: State },
    Closed { reason: CloseReason, state: State },
    Drained { state: State },
    DrainStarted,
    ChannelEnded(ChannelEnd),
    Expired { execution_id: String },
    LateUpstream { action_id: u16 },
    Restarted { state: State },
    /// I07: WRITE_BEGIN starts the generation's maintenance (before its drain).
    MaintRequested { generation: String },
    /// I07: the fence is OPEN while the maintenance waits.
    MaintOpen { state: State },
    /// I07: the fence is HELD while the maintenance waits or is open.
    MaintHeld { state: State },
    /// I07: a write's durable intent, before its first upstream byte.
    WriteForwarded {
        write_id: u16,
        operation: WriteOperation,
        api_version: String,
        kind: String,
        namespace: Option<String>,
        name: String,
        request_digest: String,
        prior: Option<Prior>,
    },
    /// I07: a write's terminal classification, before the writer hears of it.
    WriteTerminal { write_id: u16, classification: Classification, details: WriteDetails },
    /// I07: the maintenance ended, with its write count and ambiguous writes.
    MaintEnded { reason: MaintenanceEnd, writes: u16, ambiguous_write_ids: Vec<u16> },
    /// I07: a writer session ended.
    WriterSessionEnded { how: SessionEnd },
    /// I07: an upstream outcome for a write that is no longer outstanding.
    WriteLateUpstream { write_id: u16 },
}

/// A journal position: a record, or the placeholder a torn write leaves.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Entry {
    Record(Record),
    Torn,
}

fn strings(items: &[String]) -> Doc {
    Doc::Array(items.iter().map(|item| Doc::str(item)).collect())
}

fn id(action_id: u16) -> Doc {
    Doc::Int(i64::from(action_id))
}

impl Record {
    /// The record's canonical tuple, e.g. `["ARM", 1, "CREATE", "sha256:…", null, "sha256:…"]`.
    pub fn to_doc(&self) -> Doc {
        let tag = |name: &str| Doc::str(name);
        Doc::Array(match self {
            Record::Bind { execution_id, run_nonce, reservation_digest, manifest_digests, manifest_identities } => vec![
                tag("BIND"),
                Doc::str(execution_id),
                Doc::str(run_nonce),
                Doc::str(reservation_digest),
                strings(manifest_digests),
                strings(manifest_identities),
            ],
            Record::Arm { action_id, verb, manifest_digest, recorded_uid, template_digest } => vec![
                tag("ARM"),
                id(*action_id),
                Doc::str(verb.as_str()),
                Doc::str(manifest_digest),
                Doc::opt_str(recorded_uid.as_deref()),
                Doc::str(template_digest),
            ],
            Record::Consumed { action_id } => vec![tag("CONSUMED"), id(*action_id)],
            Record::Terminal { action_id, classification, after_invalidation, details } => vec![
                tag("TERMINAL"),
                id(*action_id),
                Doc::str(classification.as_str()),
                Doc::Bool(*after_invalidation),
                details.to_doc(),
            ],
            Record::Sealed { action_id, classification, after_invalidation } => {
                vec![tag("SEALED"), id(*action_id), Doc::str(classification.as_str()), Doc::Bool(*after_invalidation)]
            }
            Record::Denied { action_id } => vec![tag("DENIED"), id(*action_id)],
            Record::Invalidated { reason, state } => {
                vec![tag("INVALIDATED"), Doc::str(reason.as_str()), Doc::str(state.as_str())]
            }
            Record::Closed { reason, state } => vec![tag("CLOSED"), Doc::str(reason.as_str()), Doc::str(state.as_str())],
            Record::Drained { state } => vec![tag("DRAINED"), Doc::str(state.as_str())],
            Record::DrainStarted => vec![tag("DRAIN_STARTED")],
            Record::ChannelEnded(end) => vec![
                tag("CHANNEL_ENDED"),
                Doc::str(match end {
                    ChannelEnd::BeforeFirstFrame => "BEFORE_FIRST_FRAME",
                    ChannelEnd::Orderly => "ORDERLY",
                }),
            ],
            Record::Expired { execution_id } => vec![tag("EXPIRED"), Doc::str(execution_id)],
            Record::LateUpstream { action_id } => vec![tag("LATE_UPSTREAM"), id(*action_id)],
            Record::Restarted { state } => vec![tag("RESTARTED"), Doc::str(state.as_str())],
            Record::MaintRequested { generation } => vec![tag("MAINT_REQUESTED"), Doc::str(generation)],
            Record::MaintOpen { state } => vec![tag("MAINT_OPEN"), Doc::str(state.as_str())],
            Record::MaintHeld { state } => vec![tag("MAINT_HELD"), Doc::str(state.as_str())],
            Record::WriteForwarded { write_id, operation, api_version, kind, namespace, name, request_digest, prior } => vec![
                tag("WRITE_FORWARDED"),
                id(*write_id),
                Doc::str(operation.as_str()),
                Doc::str(api_version),
                Doc::str(kind),
                Doc::opt_str(namespace.as_deref()),
                Doc::str(name),
                Doc::str(request_digest),
                prior.as_ref().map_or(Doc::Null, Prior::to_doc),
            ],
            Record::WriteTerminal { write_id, classification, details } => {
                vec![tag("WRITE_TERMINAL"), id(*write_id), Doc::str(classification.as_str()), details.to_doc()]
            }
            Record::MaintEnded { reason, writes, ambiguous_write_ids } => vec![
                tag("MAINT_ENDED"),
                Doc::str(reason.as_str()),
                id(*writes),
                Doc::Array(ambiguous_write_ids.iter().map(|write_id| id(*write_id)).collect()),
            ],
            Record::WriterSessionEnded { how } => vec![tag("WRITER_SESSION_ENDED"), Doc::str(how.as_str())],
            Record::WriteLateUpstream { write_id } => vec![tag("WRITE_LATE_UPSTREAM"), id(*write_id)],
        })
    }
}

impl TerminalDetails {
    pub fn to_doc(&self) -> Doc {
        match self {
            TerminalDetails::Delivered { http_status, result_digest, observed_uid, observed_resource_version } => {
                Doc::object(vec![
                    ("httpStatus", Doc::Int(*http_status)),
                    ("resultDigest", Doc::str(result_digest)),
                    ("observedUid", Doc::opt_str(observed_uid.as_deref())),
                    ("observedResourceVersion", Doc::opt_str(observed_resource_version.as_deref())),
                ])
            }
            TerminalDetails::Reconciliation { http_status, result_digest } => Doc::object(vec![
                ("httpStatus", Doc::Int(*http_status)),
                ("resultDigest", Doc::str(result_digest)),
            ]),
            TerminalDetails::None => Doc::Object(Vec::new()),
            TerminalDetails::Aborted => Doc::object(vec![("aborted", Doc::str("UPSTREAM_TIMEOUT"))]),
        }
    }
}

impl Entry {
    pub fn to_doc(&self) -> Doc {
        match self {
            Entry::Record(record) => record.to_doc(),
            Entry::Torn => Doc::Array(vec![Doc::str("TORN")]),
        }
    }
}

/// The canonical form of a whole journal, `[[…], …]`, which `journalDigest` covers.
pub fn journal_doc(entries: &[Entry]) -> Doc {
    Doc::Array(entries.iter().map(Entry::to_doc).collect())
}

/// The in-memory journal store with the contract's test injections (model events, never channel frames):
/// `STORAGE_FAIL_NEXT` (optionally torn) queues one failure; `STORAGE_FAIL_AFTER {after: k}` makes the (k+1)-th record
/// attempted from then on fail, counting every attempt (failed ones and those inside the storage-failure path
/// included), with one such injection pending at a time; when its count runs out, its failure joins the back of the
/// queue, behind pending `STORAGE_FAIL_NEXT` failures (model-defined queue order).
#[derive(Clone, Debug, Default)]
pub struct Journal {
    entries: Vec<Entry>,
    plan: FaultPlan,
}

impl Journal {
    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    pub fn fail_next(&mut self, torn: bool) {
        self.plan.fail_next(torn);
    }

    pub fn fail_after(&mut self, after: u64) {
        self.plan.fail_after(after);
    }

    /// One record attempt (fsync and read back in a durable store); `false` when the write failed.
    pub fn attempt(&mut self, record: Record) -> bool {
        match self.plan.record_failure() {
            Some(torn) => {
                if torn {
                    self.entries.push(Entry::Torn);
                }
                false
            }
            None => {
                self.entries.push(Entry::Record(record));
                true
            }
        }
    }

    /// The canonical form of the whole journal, `[[…], …]`, which `journalDigest` covers.
    pub fn to_doc(&self) -> Doc {
        journal_doc(&self.entries)
    }
}

/// The failure marker store (a separate failure domain): at most one record for the generation, never removed.
#[derive(Clone, Debug, Default)]
pub struct Marker {
    record: Option<(String, &'static str)>,
    plan: FaultPlan,
}

impl Marker {
    pub fn fail_next(&mut self) {
        self.plan.marker_fail_next();
    }

    pub fn is_present(&self) -> bool {
        self.record.is_some()
    }

    /// Writes the marker unless it is already present; `false` when the write failed.
    pub fn write(&mut self, generation: &str, reason: &'static str) -> bool {
        if self.record.is_some() {
            return true;
        }
        if self.plan.marker_failure() {
            return false;
        }
        self.record = Some((generation.to_string(), reason));
        true
    }

    /// `[[generation, reason]]` or `[]`.
    pub fn to_doc(&self) -> Doc {
        Doc::Array(
            self.record
                .iter()
                .map(|(generation, reason)| Doc::Array(vec![Doc::str(generation), Doc::str(reason)]))
                .collect(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn attempts(journal: &mut Journal, count: usize) -> Vec<bool> {
        (0..count).map(|_| journal.attempt(Record::DrainStarted)).collect()
    }

    #[test]
    fn fail_after_counts_every_attempt() {
        let mut journal = Journal::default();
        journal.fail_after(2);
        assert_eq!(attempts(&mut journal, 4), [true, true, false, true]);
        journal.fail_after(0);
        assert_eq!(attempts(&mut journal, 2), [false, true]);
    }

    #[test]
    fn a_second_fail_after_replaces_the_first() {
        let mut journal = Journal::default();
        journal.fail_after(0);
        journal.fail_after(2);
        assert_eq!(attempts(&mut journal, 4), [true, true, false, true]);
        journal.fail_after(2);
        journal.fail_after(0);
        assert_eq!(attempts(&mut journal, 3), [false, true, true]);
    }

    #[test]
    fn fail_after_queues_behind_fail_next() {
        let mut journal = Journal::default();
        journal.fail_next(false);
        journal.fail_next(false);
        journal.fail_after(0);
        assert_eq!(attempts(&mut journal, 4), [false, false, false, true]);
    }

    #[test]
    fn a_torn_failure_leaves_a_placeholder() {
        let mut journal = Journal::default();
        journal.fail_next(true);
        journal.fail_next(false);
        assert_eq!(attempts(&mut journal, 3), [false, false, true]);
        assert_eq!(journal.entries(), [Entry::Torn, Entry::Record(Record::DrainStarted)]);
    }

    #[test]
    fn marker_is_written_once() {
        let mut marker = Marker::default();
        marker.fail_next();
        assert!(!marker.write("g", "STORAGE_FAILURE"));
        assert!(marker.write("g", "STORAGE_FAILURE"));
        marker.fail_next();
        assert!(marker.write("g", "STORAGE_FAILURE"), "a present marker is not rewritten");
        assert_eq!(marker.to_doc().canonical(), b"[[\"g\",\"STORAGE_FAILURE\"]]");
    }
}
