//! NP-9's bracket (DESIGN-HE005 section 3.6, O9, H5D-5, H5E-9, H5E-15; the frozen seam note, sections 4 and 6). One
//! bracket per signed period P: the broker
//!
//! 1. writes Freeze;
//! 2. waits, bounded (`FREEZE_WAIT_MS`), for `cgroup.events` to show `frozen 1`;
//! 3. holds at least `NP9_HOLD_MS` (70 s, MODEL_DEFINED R126: 60 + 5 + 2 + 3 s) from that read;
//! 4. thaws (D then replies).
//!
//! If `frozen 1` is not reached in time, the bracket is skipped: it thaws only the freeze it took, and the period's
//! bracket moves to the next run. A run is not bracketed when its remaining time is under `NP9_HOLD_MS` plus its
//! reserved remainder `NP9_RESERVE_MS`, counting every known expiry (in C, `operationDeadlineSeconds` alone; D adds the
//! signed expiries, SM-R2-15). An expiry inside the bracket goes to W6 with no thaw (O9). A freeze-write, `cgroup.events`
//! read or thaw-write error is `Np9Freeze`, `Np9Events` or `Np9Thaw`, a failure after step 5 that goes to W6 (SM-R2-3).
//! The bracket never runs around a relay, never thaws a leaf W1-W4 or W6 holds, and never freezes one they hold: in C
//! it runs once, after W4's thaw, with no frame (delta C3, C3-8).

use broker_sys::LeafWrite;

use crate::lifecycle::ops::{Clock, LeafFile, LeafOps};
use crate::lifecycle::outcome::Step;
use crate::lifecycle::text;
use crate::lifecycle::wait::{self, FREEZE_WAIT_MS};

/// The least hold from `frozen 1` (section 3.6, H5E-9; MODEL_DEFINED R126).
pub const NP9_HOLD_MS: u64 = 70_000;
/// The run's reserved remainder past a bracket (R10-defined): W6's bound (10 s, `w6.rs`) and one freeze wait (2 s), so a
/// bracket never leaves W6 without its whole bound before the deadline.
pub const NP9_RESERVE_MS: u64 = 12_000;

/// Why a bracket was skipped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Skip {
    /// The run's remaining time is under `NP9_HOLD_MS` plus `NP9_RESERVE_MS`; nothing was written.
    Remaining,
    /// `frozen 1` was not reached in time; the bracket's own freeze was thawed.
    NotFrozen,
}

/// How a bracket ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bracket {
    /// Held from the `frozen 1` read at `frozen_ms` and thawed at `thawed_ms`.
    Taken { frozen_ms: u64, thawed_ms: u64 },
    Skipped(Skip),
    /// A failure after step 5: W6 follows.
    Failed(Step),
    /// The deadline was reached inside the bracket: W6 follows, with no thaw.
    Expired,
}

/// One bracket (see the module documentation) before `deadline_ms`, a `Clock` time. G-HE5C-9's past-step-7 marker:
/// called once, from the run's arm after an accepted BIND and W4's thaw; #[inline(never)] keeps it its own symbol.
#[inline(never)]
pub fn bracket<L: LeafOps, K: Clock>(leaf: &mut L, clock: &K, deadline_ms: u64) -> Bracket {
    let now = clock.now_ms();
    if deadline_ms.saturating_sub(now) < NP9_HOLD_MS.saturating_add(NP9_RESERVE_MS) {
        return Bracket::Skipped(Skip::Remaining);
    }
    if leaf.write(LeafWrite::Freeze).is_err() {
        return Bracket::Failed(Step::Np9Freeze);
    }
    let bound = clock.now_ms().saturating_add(FREEZE_WAIT_MS);
    let seen = wait::poll(clock, bound, || match leaf.read(LeafFile::Events).ok().and_then(|bytes| text::events(&bytes)) {
        None => Some(None),
        Some(events) if events.frozen => Some(Some(clock.now_ms())),
        Some(_) => None,
    });
    let frozen_ms = match seen {
        Some(Some(at)) => at,
        Some(None) => return Bracket::Failed(Step::Np9Events),
        None => {
            return match leaf.write(LeafWrite::Thaw) {
                Ok(()) => Bracket::Skipped(Skip::NotFrozen),
                Err(_) => Bracket::Failed(Step::Np9Thaw),
            };
        }
    };
    let hold_end = frozen_ms.saturating_add(NP9_HOLD_MS);
    loop {
        let now = clock.now_ms();
        if now >= deadline_ms {
            return Bracket::Expired;
        }
        if now >= hold_end {
            break;
        }
        wait::nap(clock, hold_end.min(deadline_ms).saturating_sub(now));
    }
    if leaf.write(LeafWrite::Thaw).is_err() {
        return Bracket::Failed(Step::Np9Thaw);
    }
    Bracket::Taken { frozen_ms, thawed_ms: clock.now_ms() }
}
