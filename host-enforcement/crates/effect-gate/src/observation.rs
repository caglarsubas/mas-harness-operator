//! The gate's observation of the BIND's worker (HE-003A3 DESIGN section 4; I05 v4, owner decisions Q-A3-3, Q-A3-4,
//! Q-A3-7 and Q-A3-13 (a)): portable, safe Rust and host-tested.
//!
//! - [`WorkerObserver`] is the gate's seam. `Gate::bind` asks it once per BIND that passed every check before it, at
//!   the place of HE-003D's static list check (after MANIFEST_REUSED, before the BIND record); `NotObserved` is the
//!   existing non-fatal, retryable `WORKER_NOT_OBSERVED`, and nothing durable is written for it. [`Unobserved`], the
//!   default of every gate, observes nothing, so a gate built without an observer never accepts a BIND.
//! - [`KernelObserver`] is the five-step observation, written once: the steps, the two byte parsers, the numeric
//!   conversions, the bounds re-check and the mapping of every failure to its step's cause. It reads the kernel only
//!   through [`KernelReads`], four calls: the probe-worker leaf's member file, `pidfd_open`, the worker's `stat` file
//!   in the proc filesystem, and a poll of the pidfd with a zero timeout. effect-gate's `linux_os` implements them with
//!   gate-sys's calls and holds nothing else; the `fake_kernel` module implements them over the vectors' process table,
//!   so every replay runs these steps and parsers.
//! - [`ObservationLog`] is the local diagnostic log: the last 64 observations and a count of the ones dropped. It is
//!   in memory only: not durable, not in the snapshot, not on the wire and never printed.
//!
//! The steps, in order (a failure stops the observation; the pidfd closes on every path, when it is dropped):
//! 1. [`Step::Membership`]: the leaf's member file lists the BIND's `workerPid`. An unreadable, over-long or malformed
//!    file is `Unreadable`; a pid it does not list is `NotListed`. A `workerPid` that is not a `pid_t` of at least 1 can
//!    never be listed (`NotListed`).
//! 2. [`Step::PidfdOpen`]: `pidfd_open(workerPid)`. ESRCH is `Gone`; any other failure is `OpenFailed`.
//! 3. [`Step::StartTime`]: the start time (field 22) of the worker's `stat` file equals `workerStartTicks`. ENOENT or
//!    ESRCH is `Gone`; any other failure, an over-long file or one the strict parser refuses is `Unreadable`; another
//!    value (a negative `workerStartTicks` included) is `StartDiffers`.
//! 4. [`Step::Recheck`]: the leaf's member file still lists the pid (read afresh), with the causes of step 1.
//! 5. [`Step::Liveness`]: the zero-timeout poll of the pidfd reports no event. A poll failure is `PollFailed`; any
//!    event is `Exited`.
//!
//! The vectors' step and cause labels are never this module's text: the replays compare through their own table
//! (IR5-1). The errno values are Linux's, the same on both musl targets (and on the macOS host).

use std::collections::VecDeque;

/// The longest member file the observation reads (I05 v4 rule 5); a longer one is unreadable.
pub const LEAF_PROCS_LIMIT: usize = 65_536;

/// The longest `stat` file the observation reads (I05 v4 rule 5); a longer one is unreadable.
pub const STAT_LIMIT: usize = 4096;

/// `ENOENT` (no such file or directory): the worker's directory in the proc filesystem is gone.
pub const ENOENT: i32 = 2;

/// `ESRCH` (no such process).
pub const ESRCH: i32 = 3;

/// The entries the local diagnostic log keeps; an older entry is dropped and counted.
pub const LOG_ENTRIES: usize = 64;

/// One step of the observation, in its order.
#[derive(Copy, Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Step {
    /// 1: the probe-worker leaf's member file lists the pid.
    Membership,
    /// 2: a pidfd for the pid.
    PidfdOpen,
    /// 3: the start time in the pid's `stat` file.
    StartTime,
    /// 4: the member file still lists the pid.
    Recheck,
    /// 5: the held process has not exited.
    Liveness,
}

/// Why an observation stopped at its step (R10's own causes; the step tells the reads apart).
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Cause {
    /// A file could not be read, was longer than its bound or did not parse (steps 1, 3 and 4).
    Unreadable,
    /// The member file does not list the pid (steps 1 and 4).
    NotListed,
    /// The process does not exist (ESRCH at step 2; ENOENT or ESRCH at step 3).
    Gone,
    /// `pidfd_open` failed otherwise (step 2).
    OpenFailed,
    /// The start time differs from the BIND's (step 3).
    StartDiffers,
    /// The poll failed (step 5).
    PollFailed,
    /// The poll reported an event: the held process exited (step 5).
    Exited,
}

/// What one observation found.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum Observation {
    Observed,
    NotObserved { step: Step, cause: Cause },
}

/// The gate's seam: one observation of the worker a BIND names, read afresh at every call.
pub trait WorkerObserver {
    fn observe(&mut self, pid: i64, start_ticks: i64) -> Observation;
}

/// The default observer of every gate: it reads nothing and observes nothing (step 1, unreadable), so every BIND is
/// refused `WORKER_NOT_OBSERVED`, HE-003D's production behaviour.
#[derive(Copy, Clone, Debug, Default, PartialEq, Eq)]
pub struct Unobserved;

impl WorkerObserver for Unobserved {
    fn observe(&mut self, _pid: i64, _start_ticks: i64) -> Observation {
        Observation::NotObserved { step: Step::Membership, cause: Cause::Unreadable }
    }
}

/// Why one kernel call failed: its OS errno, a file longer than its bound, or a failure without an errno (a refused
/// name, an error the OS gave no number). Each maps to its step's cause in the driver, never to a panic.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum KernelFail {
    Os(i32),
    TooLong,
    NoErrno,
}

/// What the zero-timeout poll of a pidfd reports.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub enum PidState {
    /// No event: the process has not exited.
    Alive,
    /// An event (readable, hang-up, error or invalid): counted as exited.
    Exited,
}

/// The four kernel calls of the observation. An implementation reads afresh at every call and caches nothing; it
/// returns the bytes it read (the driver re-checks the bounds) and every failure with its errno or marker (the driver
/// maps them). The pidfd closes when it is dropped.
pub trait KernelReads {
    type Pidfd;
    /// The probe-worker leaf's member file, read whole (at most [`LEAF_PROCS_LIMIT`] bytes).
    fn read_leaf_procs(&mut self) -> Result<Vec<u8>, KernelFail>;
    /// `pidfd_open(pid, 0)`.
    fn pidfd_open(&mut self, pid: i32) -> Result<Self::Pidfd, KernelFail>;
    /// The process's `stat` file, read whole (at most [`STAT_LIMIT`] bytes).
    fn read_stat(&mut self, pid: i32) -> Result<Vec<u8>, KernelFail>;
    /// A zero-timeout poll of `pidfd` for readability.
    fn poll_zero(&mut self, pidfd: &Self::Pidfd) -> Result<PidState, KernelFail>;
}

/// The five-step observation over a [`KernelReads`] (see the module documentation).
pub struct KernelObserver<K> {
    reads: K,
}

impl<K: KernelReads> KernelObserver<K> {
    pub fn new(reads: K) -> KernelObserver<K> {
        KernelObserver { reads }
    }
}

fn stopped(step: Step, cause: Cause) -> Observation {
    Observation::NotObserved { step, cause }
}

/// Step 1 or 4 on what the member file read returned: `None` when the pid is listed, else the cause.
fn listing(read: Result<Vec<u8>, KernelFail>, pid: i64) -> Option<Cause> {
    let Ok(bytes) = read else { return Some(Cause::Unreadable) };
    match parse_leaf_procs(&bytes) {
        None => Some(Cause::Unreadable),
        Some(tgids) if tgids.iter().any(|tgid| *tgid != 0 && i64::from(*tgid) == pid) => None,
        Some(_) => Some(Cause::NotListed),
    }
}

impl<K: KernelReads> WorkerObserver for KernelObserver<K> {
    fn observe(&mut self, pid: i64, start_ticks: i64) -> Observation {
        if let Some(cause) = listing(self.reads.read_leaf_procs(), pid) {
            return stopped(Step::Membership, cause);
        }
        // Listed, so 1 <= pid <= i32::MAX; the conversion cannot fail here and is checked anyway.
        let Some(number) = i32::try_from(pid).ok().filter(|number| *number >= 1) else {
            return stopped(Step::Membership, Cause::NotListed);
        };
        let pidfd = match self.reads.pidfd_open(number) {
            Ok(pidfd) => pidfd,
            Err(KernelFail::Os(ESRCH)) => return stopped(Step::PidfdOpen, Cause::Gone),
            Err(_) => return stopped(Step::PidfdOpen, Cause::OpenFailed),
        };
        match self.reads.read_stat(number) {
            Ok(bytes) => match parse_stat_start(&bytes) {
                Some(start) if u64::try_from(start_ticks).ok() == Some(start) => {}
                Some(_) => return stopped(Step::StartTime, Cause::StartDiffers),
                None => return stopped(Step::StartTime, Cause::Unreadable),
            },
            Err(KernelFail::Os(ENOENT | ESRCH)) => return stopped(Step::StartTime, Cause::Gone),
            Err(_) => return stopped(Step::StartTime, Cause::Unreadable),
        }
        if let Some(cause) = listing(self.reads.read_leaf_procs(), pid) {
            return stopped(Step::Recheck, cause);
        }
        match self.reads.poll_zero(&pidfd) {
            Ok(PidState::Alive) => Observation::Observed,
            Ok(PidState::Exited) => stopped(Step::Liveness, Cause::Exited),
            Err(_) => stopped(Step::Liveness, Cause::PollFailed),
        }
    }
}

/// The thread-group IDs of a member file (I05 v4 rule 5): every line ends with a newline and is ASCII digits with no
/// sign and no leading zero (`0` itself included, which never matches a worker); duplicates and any order are
/// accepted; an empty file lists nothing. `None` for a file longer than [`LEAF_PROCS_LIMIT`] bytes, any other byte or
/// shape, or a number past `i32`.
pub fn parse_leaf_procs(bytes: &[u8]) -> Option<Vec<i32>> {
    if bytes.len() > LEAF_PROCS_LIMIT {
        return None;
    }
    let body = match bytes {
        [] => return Some(Vec::new()),
        [body @ .., b'\n'] => body,
        _ => return None,
    };
    let mut tgids = Vec::new();
    for line in body.split(|byte| *byte == b'\n') {
        let canonical = match line {
            [b'0'] => true,
            [first, ..] => *first != b'0',
            [] => false,
        };
        if !canonical || !line.iter().all(u8::is_ascii_digit) {
            return None;
        }
        tgids.push(std::str::from_utf8(line).ok()?.parse::<i32>().ok()?);
    }
    Some(tgids)
}

/// The start time (field 22) of a `stat` file, parsed whole (I05 v4 rule 5; the strict parser of Q-A3-10 (a), beside
/// HE-003A's peer reader): after the last `)`, which a `(` precedes, come fields 3 onwards, each preceded by exactly one
/// space and holding no space or newline, and the file ends with exactly one newline; the start time is the twentieth
/// of them, ASCII decimal digits. `None` for a file longer than [`STAT_LIMIT`] bytes, any other shape, or a start time
/// past `u64`.
pub fn parse_stat_start(bytes: &[u8]) -> Option<u64> {
    if bytes.len() > STAT_LIMIT {
        return None;
    }
    let close = bytes.iter().rposition(|byte| *byte == b')')?;
    if !bytes.get(..close)?.contains(&b'(') {
        return None;
    }
    let rest = bytes.get(close + 1..)?.strip_suffix(b"\n")?;
    let rest = rest.strip_prefix(b" ")?;
    let mut start = None;
    for (index, field) in rest.split(|byte| *byte == b' ').enumerate() {
        if field.is_empty() || field.contains(&b'\n') {
            return None;
        }
        if index == 19 {
            start = Some(field);
        }
    }
    let start = start?;
    if !start.iter().all(u8::is_ascii_digit) {
        return None;
    }
    std::str::from_utf8(start).ok()?.parse().ok()
}

/// One entry of the local diagnostic log: the BIND's values and what the observation found.
#[derive(Copy, Clone, Debug, PartialEq, Eq)]
pub struct Logged {
    pub pid: i64,
    pub start_ticks: i64,
    pub observation: Observation,
}

/// The gate's local diagnostic log (Q-A3-7 (a)): the last [`LOG_ENTRIES`] observations, oldest first, and the number
/// of older entries dropped to keep that bound (saturating). Best effort and in memory only.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ObservationLog {
    entries: VecDeque<Logged>,
    dropped: u64,
}

impl ObservationLog {
    /// Appends one entry, dropping and counting the oldest when the log is full.
    pub(crate) fn record(&mut self, entry: Logged) {
        if self.entries.len() >= LOG_ENTRIES {
            self.entries.pop_front();
            self.dropped = self.dropped.saturating_add(1);
        }
        self.entries.push_back(entry);
    }

    /// The kept entries, oldest first.
    pub fn entries(&self) -> Vec<Logged> {
        self.entries.iter().copied().collect()
    }

    /// The entries dropped so far.
    pub fn dropped(&self) -> u64 {
        self.dropped
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(pid: i64) -> Logged {
        Logged { pid, start_ticks: 7, observation: Observation::Observed }
    }

    #[test]
    fn the_log_keeps_the_last_64_and_counts_the_dropped() {
        let mut log = ObservationLog::default();
        for pid in 1..=64 {
            log.record(entry(pid));
        }
        assert_eq!((log.entries().len(), log.dropped()), (64, 0));
        log.record(entry(65));
        log.record(entry(66));
        let kept = log.entries();
        assert_eq!((kept.len(), log.dropped()), (64, 2));
        assert_eq!((kept[0].pid, kept[63].pid), (3, 66));
        log.dropped = u64::MAX;
        log.record(entry(67));
        assert_eq!(log.dropped(), u64::MAX);
    }

    #[test]
    fn unobserved_refuses_at_the_first_step() {
        let mut observer = Unobserved;
        for (pid, start) in [(4100, 900001), (0, 0), (i64::MAX, i64::MIN)] {
            assert_eq!(observer.observe(pid, start),
                       Observation::NotObserved { step: Step::Membership, cause: Cause::Unreadable });
        }
    }
}
