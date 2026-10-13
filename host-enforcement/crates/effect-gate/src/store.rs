//! The gate's two stores behind one interface (HE-002C DESIGN §3.1): the journal, seen in-process through its
//! mirror, and the failure marker. `Gate` holds them as `Box<dyn Stores>`: the in-memory pair of HE-002
//! ([`MemoryStores`]) for `Gate::new`, or the files of `file_store::FileStores` for the durable constructors.
//!
//! The fault plan carries the contract's three test injections (model events, never channel frames), with the queue
//! logic HE-002's `Journal` had, moved here unchanged, plus the file-level failure points of DESIGN §11 that the
//! append protocol's unit cases arm. Production opens file stores without a plan, so the injections are no-ops there.

use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::collections::VecDeque;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::PoisonError;

use i05_protocol::json::Doc;

use crate::config::PriorBindings;
use crate::journal::{Entry, Journal, Marker, Record};

/// What one journal append came to.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Appended {
    /// Written, synced, read back and committed.
    Durable,
    /// Not durable; `torn` when the attempt may have left bytes, so the mirror holds a TORN placeholder for it.
    Failed { torn: bool },
}

/// The journal and the failure marker of one generation.
pub trait Stores: Send {
    /// One record attempt. The mirror changes exactly as HE-002's in-memory journal does: a durable record is added,
    /// a torn failure adds one TORN, a clean failure adds nothing.
    fn append(&mut self, record: Record) -> Appended;

    /// The mirror: the in-process view of the journal, which every journal digest and in-process rebuild reads.
    fn entries(&self) -> &[Entry];

    fn marker_present(&self) -> bool;

    /// Writes the marker unless one is present; `false` when the write failed.
    fn write_marker(&mut self, generation: &str, reason: &'static str) -> bool;

    /// The snapshot's `failureMarker`: `[[generation, reason]]`, `[]`, or R22's `[[generation, "UNREADABLE"]]`.
    fn marker_doc(&self) -> Doc;

    /// `STORAGE_FAIL_NEXT`.
    fn fail_next(&mut self, torn: bool);

    /// `STORAGE_FAIL_AFTER {after}`.
    fn fail_after(&mut self, after: u64);

    /// `MARKER_FAIL_NEXT`.
    fn marker_fail_next(&mut self);

    /// The bindings found in earlier generations' journals (DESIGN §7); empty for the in-memory stores.
    fn prior_bindings(&self) -> &PriorBindings;
}

/// HE-002's in-memory journal and marker, unchanged in behaviour.
#[derive(Clone, Debug, Default)]
pub struct MemoryStores {
    journal: Journal,
    marker: Marker,
    prior: PriorBindings,
}

impl Stores for MemoryStores {
    fn append(&mut self, record: Record) -> Appended {
        let before = self.journal.entries().len();
        if self.journal.attempt(record) {
            Appended::Durable
        } else {
            Appended::Failed { torn: self.journal.entries().len() > before }
        }
    }

    fn entries(&self) -> &[Entry] {
        self.journal.entries()
    }

    fn marker_present(&self) -> bool {
        self.marker.is_present()
    }

    fn write_marker(&mut self, generation: &str, reason: &'static str) -> bool {
        self.marker.write(generation, reason)
    }

    fn marker_doc(&self) -> Doc {
        self.marker.to_doc()
    }

    fn fail_next(&mut self, torn: bool) {
        self.journal.fail_next(torn);
    }

    fn fail_after(&mut self, after: u64) {
        self.journal.fail_after(after);
    }

    fn marker_fail_next(&mut self) {
        self.marker.fail_next();
    }

    fn prior_bindings(&self) -> &PriorBindings {
        &self.prior
    }
}

/// A file-level failure point of one append (DESIGN §5 and §11). Each makes the named step fail as if the system
/// call had returned an error; the store then classifies the failure exactly as it would a real one.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum FilePoint {
    /// Half of the pending frame is written, then the write fails.
    PartialFrame,
    /// The pending frame's write fails before any byte.
    FirstWrite,
    /// The pending frame's sync fails.
    FirstSync,
    /// The pending frame's read-back fails.
    FirstReadBack,
    /// The commit byte's write fails.
    CommitWrite,
    /// The commit byte's sync fails (after its write succeeded).
    CommitSync,
    /// The commit byte's read-back fails.
    CommitReadBack,
    /// The revocation's write fails.
    Revoke,
    /// The marker write fails before the marker file is touched (`MARKER_FAIL_NEXT`).
    MarkerWrite,
}

/// The file a point is armed for.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum StoreFile {
    Journal,
    Marker,
    Index,
}

/// The contract's injections and the armed file-level points.
///
/// `STORAGE_FAIL_NEXT` (optionally torn) queues one failure; `STORAGE_FAIL_AFTER {after: k}` makes the (k+1)-th
/// record attempted from then on fail, counting every attempt (failed ones and those inside the storage-failure path
/// included), with one such injection pending at a time; when its count runs out its failure joins the back of the
/// queue, behind pending `STORAGE_FAIL_NEXT` failures (model-defined queue order, M19). `MARKER_FAIL_NEXT` fails the
/// next marker write. On the file stores a queued failure is a `FirstWrite` (clean) or a `PartialFrame` (torn), and
/// `MARKER_FAIL_NEXT` a `MarkerWrite`; armed points apply to the next append of their file and are then cleared.
#[derive(Clone, Debug, Default)]
pub struct FaultPlan {
    pending_failures: VecDeque<bool>,
    fail_after: Option<u64>,
    marker_failures: u64,
    points: BTreeMap<StoreFile, BTreeSet<FilePoint>>,
}

impl FaultPlan {
    pub fn fail_next(&mut self, torn: bool) {
        self.pending_failures.push_back(torn);
    }

    pub fn fail_after(&mut self, after: u64) {
        self.fail_after = Some(after);
    }

    pub fn marker_fail_next(&mut self) {
        self.marker_failures = self.marker_failures.saturating_add(1);
    }

    /// Arms `point` for the next append of `file`.
    pub fn arm(&mut self, file: StoreFile, point: FilePoint) {
        self.points.entry(file).or_default().insert(point);
    }

    /// One record attempt against the contract's injections: `Some(torn)` when the attempt fails.
    pub(crate) fn record_failure(&mut self) -> Option<bool> {
        match self.fail_after {
            Some(0) => {
                self.fail_after = None;
                self.pending_failures.push_back(false);
            }
            Some(remaining) => self.fail_after = Some(remaining - 1),
            None => {}
        }
        self.pending_failures.pop_front()
    }

    /// One marker write against `MARKER_FAIL_NEXT`: `true` when it fails.
    pub(crate) fn marker_failure(&mut self) -> bool {
        if self.marker_failures > 0 {
            self.marker_failures -= 1;
            return true;
        }
        false
    }

    /// The points armed for `file`'s next append, which are cleared.
    pub(crate) fn take(&mut self, file: StoreFile) -> BTreeSet<FilePoint> {
        self.points.remove(&file).unwrap_or_default()
    }
}

/// A fault plan shared between the stores and the test that drives them, so that injections still pending when the
/// stores are dropped carry across a process restart to the stores opened next with the same handle.
#[derive(Clone, Debug, Default)]
pub struct FaultHandle(Arc<Mutex<FaultPlan>>);

impl FaultHandle {
    /// Runs `change` on the plan. A poisoned lock is recovered: the plan holds no invariant a panic could break.
    pub fn with<T>(&self, change: impl FnOnce(&mut FaultPlan) -> T) -> T {
        let mut plan = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        change(&mut plan)
    }
}
