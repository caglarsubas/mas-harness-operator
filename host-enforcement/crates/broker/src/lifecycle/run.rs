//! The startup run (DESIGN-HE005 delta C3 revision 2, "The run"; section 3.3 with the frozen seam note's section 4 step
//! assignment and section 6 error mapping). Its case comes from the signed configuration only, with no request input.
//!
//! 1. Step 1: the standing HOLD. In C the start derivation is this step's check: a HOLD at start ends the run here with
//!    `CapacityHeld`, before gate qualification (C3-5, SM-R3-1).
//! 2. Step 2: the gate's qualification (`GateQualifier`). C's stand-in answers `Unavailable`, so in C the run ends here:
//!    nothing written to the leaf, nothing spawned (section 3.3's rule for a failure before step 5).
//! 3. Step 3, W5, before any leaf write: open the script, measure it, compare (algorithm 1, SHA-256, and the signed
//!    digest), then the socketpair. A failure spawns nothing and leaves the leaf untouched (`NotSpawned`).
//! 4. The derived HOLD before W1 (section 3.4), with no write.
//! 5. Step 4, W1: `cgroup.type` reads `domain`, `cgroup.events` `populated 0`, `cgroup.procs` empty (any of the three
//!    otherwise is `W1NotEmpty`, the leaf not an empty domain leaf); write Freeze; the bounded wait for `frozen 1`.
//!    A failure after the freeze write takes W1's failure path (SM-R1-13, SM-R2-3).
//! 6. Step 5, W2: `plan` with the signed uid, then `spawn`. A plan or spawn error leaves no child (`W2Spawn`); a parent
//!    mask not restored is `W2MaskRestore`. Either goes to W6.
//! 7. Step 6, W3: membership, credentials, `Groups:`, the label, the `stat` line's pid and start ticks, and the
//!    descriptors against `W3Expect`. A failure goes to W6 with no thaw.
//! 8. Step 7, BIND (`Binder`): accepted for this child's pid and start ticks, or W6 with no thaw. C's stand-in answers
//!    `Unavailable`; after W6 the run ends `Unavailable` (C3-7).
//! 9. Step 8, W4: the thaw, reached only with W3's pass and the accepted BIND's ticket (G-HE5C-5).
//! 10. After W4 (C3-8): NP-9's one bracket, then the window until the worker's own end (its reap) or
//!     `operationDeadlineSeconds` from the run's start, with no frame; then W6. In C, with no frames, the window's start
//!     stands for the reply boundary NP-9 brackets; D moves the bracket to the first reply boundary.
//!
//! C's choice rule (SM-R3-9): a W6 entered from a failure ends `Cleaned(its step)`; one entered at the worker's own end
//! or at the deadline after W4 ends `Ended(reaped)`; one entered from the Binder's `Unavailable` ends `Unavailable`. A W6
//! that ends `Held` gives `Held(step)`, sets the standing HOLD and hands the child to the standing state.

use std::io;

use broker_sys::{LeafWrite, Reaped, W3Expect};

use crate::config::{BrokerConfig, VERITY_SHA256};
use crate::lifecycle::hold::{self, Standing};
use crate::lifecycle::leaf;
use crate::lifecycle::np9::{self, Bracket};
use crate::lifecycle::ops::{Clock, LeafFile, LeafOps, ProcFile, SpawnOps};
use crate::lifecycle::outcome::{Outcome, Step};
use crate::lifecycle::seams::{BindAnswer, BindTicket, Binder, GateAnswer, GateQualifier};
use crate::lifecycle::text;
use crate::lifecycle::w6::{self, W6End};
use crate::lifecycle::wait::{self, FREEZE_WAIT_MS};

#[cfg(target_os = "linux")]
use broker_sys::Child;

#[cfg(target_os = "linux")]
use crate::lifecycle::clock::MonotonicClock;
#[cfg(target_os = "linux")]
use crate::lifecycle::leaf::LeafHandles;
#[cfg(target_os = "linux")]
use crate::lifecycle::spawn::LinuxSpawn;

/// Why W6 was entered, which decides a released W6's outcome (C's choice rule).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    Failed(Step),
    Unavailable,
    WorkerEnd,
    Deadline,
}

/// W3's pass (G-HE5C-5): made only by `w3`, and taken by `w4_thaw`, so W4's thaw follows a passed W3. It carries the
/// start ticks W3 read, which BIND names.
struct W3Passed {
    start_ticks: u64,
}

/// The startup run over the seams (see the module documentation). Generic over the seams, statically dispatched; in
/// production `startup_run` drives it over the Linux implementations and C's stand-ins.
pub fn startup<L, S, K, Q, B>(leaf: &mut L, spawn: &mut S, clock: &K, mut qualifier: Q, mut binder: B, config: &BrokerConfig,
                              standing: &mut Standing<S::Child>) -> Outcome
where
    L: LeafOps,
    S: SpawnOps,
    K: Clock,
    Q: GateQualifier,
    B: Binder,
{
    let start_ms = clock.now_ms();
    if let Some(step) = standing.held() {
        return Outcome::CapacityHeld(step);
    }
    let gate = match qualifier.qualify() {
        GateAnswer::Qualified(ticket) => ticket,
        GateAnswer::Unavailable => return Outcome::Unavailable,
    };
    let (script, (_parent_end, child_end)) = match w5(spawn, config) {
        Ok(found) => found,
        Err(step) => return Outcome::NotSpawned(step),
    };
    if let Some(step) = hold::derive(leaf, standing.held().is_some()) {
        standing.hold(step);
        return Outcome::CapacityHeld(step);
    }
    if let Err(outcome) = w1(leaf, clock, standing) {
        return outcome;
    }
    let (child, expect) = match w2(spawn, config.worker_uid(), child_end, script) {
        Ok(found) => found,
        Err((step, child)) => return after_w6(leaf, spawn, clock, standing, child, None, Entry::Failed(step)),
    };
    let passed = match w3(spawn, &child, &expect) {
        Ok(passed) => passed,
        Err(step) => return after_w6(leaf, spawn, clock, standing, Some(child), None, Entry::Failed(step)),
    };
    let pid = spawn.child_pid(&child);
    let bound = match binder.bind(&gate, pid, passed.start_ticks) {
        BindAnswer::Bound(ticket) if ticket.pid == pid && ticket.start_ticks == passed.start_ticks => ticket,
        BindAnswer::Bound(_) => {
            return after_w6(leaf, spawn, clock, standing, Some(child), None, Entry::Failed(Step::Bind));
        }
        BindAnswer::Unavailable => return after_w6(leaf, spawn, clock, standing, Some(child), None, Entry::Unavailable),
    };
    if w4_thaw(leaf, &passed, &bound).is_err() {
        return after_w6(leaf, spawn, clock, standing, Some(child), None, Entry::Failed(Step::W4Thaw));
    }
    let deadline_ms = start_ms.saturating_add(config.operation_deadline_seconds().saturating_mul(1_000));
    match np9::bracket(leaf, clock, deadline_ms) {
        Bracket::Taken { .. } | Bracket::Skipped(_) => {}
        Bracket::Failed(step) => return after_w6(leaf, spawn, clock, standing, Some(child), None, Entry::Failed(step)),
        Bracket::Expired => return after_w6(leaf, spawn, clock, standing, Some(child), None, Entry::Deadline),
    }
    let reaped = wait::poll(clock, deadline_ms, || spawn.reap(&child).ok().flatten());
    let entry = if reaped.is_some() { Entry::WorkerEnd } else { Entry::Deadline };
    after_w6(leaf, spawn, clock, standing, Some(child), reaped, entry)
}

/// Step 3, W5 (section 3.2; seam section 4): the opened script, measured and compared, and the socketpair (parent end,
/// child end). The measured script is the one W2's plan takes (G-HE5C-4's agent half).
fn w5<S: SpawnOps>(spawn: &mut S, config: &BrokerConfig) -> Result<(S::Script, (S::ChannelEnd, S::ChannelEnd)), Step> {
    let script = spawn.open_script().map_err(|_| Step::W5Open)?;
    let (algorithm, digest) = spawn.measure(&script).map_err(|_| Step::W5Measure)?;
    if algorithm != VERITY_SHA256 || &digest != config.worker_script_verity_digest() {
        return Err(Step::W5Compare);
    }
    let pair = spawn.channel_pair().map_err(|_| Step::Pair)?;
    Ok((script, pair))
}

/// Step 4, W1 (section 3.3 step 4; seam section 4). `Err` holds the outcome.
fn w1<L: LeafOps, K: Clock, C>(leaf: &mut L, clock: &K, standing: &mut Standing<C>) -> Result<(), Outcome> {
    let leaf_type = leaf.read(LeafFile::Type).map_err(|_| Outcome::NotSpawned(Step::W1Read))?;
    let events = leaf.read(LeafFile::Events).ok().and_then(|bytes| text::events(&bytes));
    let events = events.ok_or(Outcome::NotSpawned(Step::W1Read))?;
    let procs = leaf.read(LeafFile::Procs).map_err(|_| Outcome::NotSpawned(Step::W1Read))?;
    if !text::is_domain(&leaf_type) || events.populated || !text::procs_empty(&procs) {
        return Err(Outcome::NotSpawned(Step::W1NotEmpty));
    }
    if leaf.write(LeafWrite::Freeze).is_err() {
        return Err(w1_failure(leaf, standing, Step::W1Freeze));
    }
    let bound = clock.now_ms().saturating_add(FREEZE_WAIT_MS);
    let seen = wait::poll(clock, bound, || match leaf.read(LeafFile::Events).ok().and_then(|bytes| text::events(&bytes)) {
        None => Some(false),
        Some(events) if events.frozen => Some(true),
        Some(_) => None,
    });
    match seen {
        Some(true) => Ok(()),
        Some(false) => Err(w1_failure(leaf, standing, Step::W1Read)),
        None => Err(w1_failure(leaf, standing, Step::W1NotFrozen)),
    }
}

/// W1's failure path (SM-R1-13, SM-R2-3, SM-R3-3): it thaws only after re-reading `populated 0`. A re-read that is not
/// `populated 0` or fails is `CapacityHeld(W1NotEmptyOnReread)`, and a failed failure-thaw `CapacityHeld(W1FailThaw)`:
/// either way the leaf is left as it is, with no thaw, under the standing HOLD. Otherwise `NotSpawned(step)`.
fn w1_failure<L: LeafOps, C>(leaf: &mut L, standing: &mut Standing<C>, step: Step) -> Outcome {
    let empty = leaf.read(LeafFile::Events).ok().and_then(|bytes| text::events(&bytes)).is_some_and(|events| !events.populated);
    if !empty {
        standing.hold(Step::W1NotEmptyOnReread);
        return Outcome::CapacityHeld(Step::W1NotEmptyOnReread);
    }
    if leaf.write(LeafWrite::Thaw).is_err() {
        standing.hold(Step::W1FailThaw);
        return Outcome::CapacityHeld(Step::W1FailThaw);
    }
    Outcome::NotSpawned(step)
}

/// Step 5, W2 (section 3.3 step 5; seam section 2 `spawn`): the child and `W3Expect`, or the step and the child, if one
/// exists.
fn w2<S: SpawnOps>(spawn: &mut S, worker_uid: u32, child_end: S::ChannelEnd, script: S::Script)
    -> Result<(S::Child, W3Expect), (Step, Option<S::Child>)> {
    let (plan, expect) = spawn.plan(worker_uid, child_end, script).map_err(|_| (Step::W2Spawn, None))?;
    let child = spawn.spawn(plan).map_err(|_| (Step::W2Spawn, None))?;
    if !spawn.mask_restored(&child) {
        return Err((Step::W2MaskRestore, Some(child)));
    }
    Ok((child, expect))
}

/// Step 6, W3 (section 3.3 step 6; section 3.2; seam sections 3 and 4): the frozen child, still uid 0 in the broker's
/// domain, read through its process directory and its descriptor table.
fn w3<S: SpawnOps>(spawn: &mut S, child: &S::Child, expect: &W3Expect) -> Result<W3Passed, Step> {
    let pid = spawn.child_pid(child);
    let cgroup = spawn.proc_read(child, ProcFile::Cgroup).map_err(|_| Step::W3Read)?;
    if !text::in_leaf(&cgroup, leaf::membership()) {
        return Err(Step::W3Membership);
    }
    let status = spawn.proc_read(child, ProcFile::Status).map_err(|_| Step::W3Read)?;
    if !text::ids_are_root(&status, b"Uid:") || !text::ids_are_root(&status, b"Gid:") {
        return Err(Step::W3Credentials);
    }
    if !text::groups_empty(&status) {
        return Err(Step::W3Groups);
    }
    let label = spawn.proc_read(child, ProcFile::AttrCurrent).map_err(|_| Step::W3Read)?;
    if !text::label_matches(&label, text::BROKER_LABEL.as_bytes()) {
        return Err(Step::W3Label);
    }
    let stat = spawn.proc_read(child, ProcFile::Stat).map_err(|_| Step::W3Read)?;
    let (stat_pid, start_ticks) = text::stat_identity(&stat).ok_or(Step::W3Read)?;
    if stat_pid != pid {
        return Err(Step::W3Membership);
    }
    let table = spawn.fd_table(child).map_err(|_| Step::W3Read)?;
    if !text::descriptors_hold(table, expect) {
        return Err(Step::W3Descriptors);
    }
    Ok(W3Passed { start_ticks })
}

/// Step 8, W4 (section 3.3 step 8; G-HE5C-5; G-HE5C-9's past-step-7 marker): the leaf's thaw, reached only with W3's
/// pass and the accepted BIND's ticket; called once, from the run's arm after both. #[inline(never)] keeps it its own
/// symbol.
#[inline(never)]
fn w4_thaw<L: LeafOps>(leaf: &mut L, _passed: &W3Passed, _bound: &BindTicket) -> io::Result<()> {
    leaf.write(LeafWrite::Thaw)
}

/// W6, then the outcome by C's choice rule (see the module documentation).
fn after_w6<L, S, K>(leaf: &mut L, spawn: &mut S, clock: &K, standing: &mut Standing<S::Child>, child: Option<S::Child>,
                     reaped: Option<Reaped>, entry: Entry) -> Outcome
where
    L: LeafOps,
    S: SpawnOps,
    K: Clock,
{
    let report = w6::sequence(leaf, spawn, clock, child.as_ref(), reaped);
    let step = match (report.end, entry) {
        (W6End::Released(_), Entry::Failed(step)) => return Outcome::Cleaned(step),
        (W6End::Released(_), Entry::Unavailable) => return Outcome::Unavailable,
        (W6End::Released(Some(reaped)), Entry::WorkerEnd | Entry::Deadline) => return Outcome::Ended(reaped),
        // A W6 entered at the worker's end or the deadline always has a child, so it releases only after the reap;
        // were it ever to release with none, the run holds (fail-safe).
        (W6End::Released(None), Entry::WorkerEnd | Entry::Deadline) => Step::W6Reap,
        (W6End::Held(step), _) => step,
    };
    standing.hold(step);
    if let Some(child) = child {
        standing.keep(child);
    }
    Outcome::Held(step)
}

/// serve's HOLD derivation at start (section 3.4; C3-5; SM-R2-2): over the opened leaf, with no write; a failed open of
/// either handle counts as `HoldRead`. The serve-owned standing state, with the flag set on HOLD; it never returns early.
#[cfg(target_os = "linux")]
pub fn derive_hold(opened: &io::Result<LeafHandles>) -> Standing<Child> {
    let mut standing = Standing::new();
    let found = match opened {
        Ok(handles) => hold::derive(&mut handles.leaf_ops(), false),
        Err(_) => Some(Step::HoldRead),
    };
    if let Some(step) = found {
        standing.hold(step);
    }
    standing
}

/// serve's one startup run (delta C3): the Linux implementations over the opened leaf, with the clock's origin taken
/// here, before any step reads it, and the two seams serve passes (C's stand-ins). Its outcome is never serve's return.
#[cfg(target_os = "linux")]
pub fn startup_run<Q: GateQualifier, B: Binder>(opened: &io::Result<LeafHandles>, config: &BrokerConfig,
                                                standing: &mut Standing<Child>, qualifier: Q, binder: B) -> Outcome {
    let Ok(handles) = opened else {
        standing.hold(Step::HoldRead);
        return Outcome::CapacityHeld(Step::HoldRead);
    };
    let clock = MonotonicClock::start();
    let mut spawn = LinuxSpawn::new(handles.leaf_dir(), config.worker_script_path());
    startup(&mut handles.leaf_ops(), &mut spawn, &clock, qualifier, binder, config, standing)
}
