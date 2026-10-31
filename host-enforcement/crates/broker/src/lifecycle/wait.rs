//! The lifecycle's bounded waits over `Clock` (the frozen seam note, sections 4 and 6). No outcome comes from an errno
//! (SM-R2-14): every sleep error counts as an early wake, and each wait re-reads the clock, so it stays within its
//! bound. Each sleep is the smaller of its step and the time left, and no check lands past the bound.

use crate::lifecycle::ops::Clock;

/// Every poll's step: W6's re-read and reap periods (seam section 6: every 100 ms), and the other waits'.
pub const POLL_MS: u64 = 100;
/// The bound of a wait for `frozen 1`, W1's (section 3.3 step 4) and NP-9's (section 3.6 step 2): R10-defined, on
/// O21's 2 s control-answer scale.
pub const FREEZE_WAIT_MS: u64 = 2_000;

/// Polls `check` until it answers, or until `bound` (a `Clock` time) passes: its answer, or `None`. Before each check
/// the clock is read: past the bound, there is no further check; at the bound, the check is the last.
pub fn poll<K: Clock, T>(clock: &K, bound: u64, mut check: impl FnMut() -> Option<T>) -> Option<T> {
    loop {
        let now = clock.now_ms();
        if now > bound {
            return None;
        }
        if let Some(found) = check() {
            return Some(found);
        }
        if now >= bound {
            return None;
        }
        nap(clock, bound.saturating_sub(now).min(POLL_MS));
    }
}

/// One sleep of `ms` (at most `u32::MAX`); an error is an early wake, and the caller re-reads the clock.
pub fn nap<K: Clock>(clock: &K, ms: u64) {
    let _ = clock.sleep_ms(u32::try_from(ms).unwrap_or(u32::MAX));
}
