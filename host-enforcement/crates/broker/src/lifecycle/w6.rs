//! W6 (DESIGN-HE005 section 3.3 step 13; the frozen seam note, section 6, "W6's sequence", SM-R1-6, SM-R2-7, SM-R2-8
//! (a), SM-R3-7). W6 is entered from any failure at step 5 or later, from expiry or invalidation, or from an early end,
//! and runs in this order; each write error is recorded but never ends the sequence:
//!
//! 1. write Freeze;
//! 2. write Kill;
//! 3. the wait for the leaf shown empty (`populated 0` and `cgroup.procs` empty), re-read every 100 ms;
//! 4. if a child exists, is not reaped yet and the leaf was shown empty: the WNOHANG reap, polled every 100 ms;
//! 5. if the leaf was shown empty, and either the reap completed or no child exists: the release (write Thaw).
//!
//! Steps 3 and 4 together run within `W6_BOUND_MS`, counted from W6's entry, never from the operation's deadline. A leaf
//! never shown empty is never released. `Held` is the end when the leaf is not shown empty in the bound (`W6NotEmpty`),
//! when the reap misses it after the leaf is shown empty (`W6Reap`; deliberately stricter than section 3.4: with no
//! reap there is no TERMINAL, O20), and when the release fails (`W6Release`). The caller keeps the child and sets the
//! standing HOLD on `Held`.

use broker_sys::{LeafWrite, Reaped};

use crate::lifecycle::ops::{Clock, LeafFile, LeafOps, SpawnOps};
use crate::lifecycle::outcome::Step;
use crate::lifecycle::text;
use crate::lifecycle::wait;

const W6_BOUND_MS: u64 = 10_000;

/// How W6 ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum W6End {
    /// The leaf shown empty and released; the worker's reaped status when a child existed.
    Released(Option<Reaped>),
    /// The leaf not shown empty, the reap not completed, or the release failed (see the module documentation).
    Held(Step),
}

/// W6's report: how it ended, the first write error it recorded (W6Freeze or W6Kill), and its entry time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct W6Report {
    pub end: W6End,
    pub recorded: Option<Step>,
    pub entry_ms: u64,
}

/// The leaf shown empty: `cgroup.events` reads `populated 0` and `cgroup.procs` lists no process. A read failure is not
/// shown empty.
fn shown_empty<L: LeafOps>(leaf: &mut L) -> bool {
    let unpopulated = leaf.read(LeafFile::Events).ok().and_then(|bytes| text::events(&bytes)).is_some_and(|events| !events.populated);
    unpopulated && leaf.read(LeafFile::Procs).is_ok_and(|bytes| text::procs_empty(&bytes))
}

/// W6's sequence (see the module documentation). `child` is the spawned worker, if one exists; `reaped` is its status
/// when the run already reaped it at its own end.
pub fn sequence<L, S, K>(leaf: &mut L, spawn: &mut S, clock: &K, child: Option<&S::Child>, reaped: Option<Reaped>)
    -> W6Report
where
    L: LeafOps,
    S: SpawnOps,
    K: Clock,
{
    let entry_ms = clock.now_ms();
    let bound = entry_ms.saturating_add(W6_BOUND_MS);
    let mut recorded = None;
    if leaf.write(LeafWrite::Freeze).is_err() {
        recorded = Some(Step::W6Freeze);
    }
    if leaf.write(LeafWrite::Kill).is_err() && recorded.is_none() {
        recorded = Some(Step::W6Kill);
    }
    let held = |step: Step| W6Report { end: W6End::Held(step), recorded, entry_ms };
    if wait::poll(clock, bound, || shown_empty(&mut *leaf).then_some(())).is_none() {
        return held(Step::W6NotEmpty);
    }
    let reaped = match (child, reaped) {
        (Some(child), None) => match wait::poll(clock, bound, || spawn.reap(child).ok().flatten()) {
            Some(found) => Some(found),
            None => return held(Step::W6Reap),
        },
        (_, already) => already,
    };
    if leaf.write(LeafWrite::Thaw).is_err() {
        return held(Step::W6Release);
    }
    W6Report { end: W6End::Released(reaped), recorded, entry_ms }
}
