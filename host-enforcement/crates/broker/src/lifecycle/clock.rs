//! The production `Clock` (the frozen seam note, section 3, SM-R1-1; Linux only): milliseconds from one origin, read
//! through std's `Instant` (`clock_gettime`, CLOCK_MONOTONIC), and sleeps through broker-sys's `sleep_monotonic`, one
//! `clock_nanosleep` each, whose early wake is an error the waits count as a wake (SM-R2-14). No std thread sleep.

use std::io;
use std::time::Instant;

use crate::lifecycle::ops::Clock;

/// Milliseconds since the origin taken by [`MonotonicClock::start`].
pub struct MonotonicClock {
    origin: Instant,
}

impl MonotonicClock {
    /// The origin, taken once, when serve's startup run begins, before any step reads the clock.
    pub fn start() -> MonotonicClock {
        MonotonicClock { origin: Instant::now() }
    }
}

impl Clock for MonotonicClock {
    fn now_ms(&self) -> u64 {
        u64::try_from(self.origin.elapsed().as_millis()).unwrap_or(u64::MAX)
    }

    fn sleep_ms(&self, ms: u32) -> io::Result<()> {
        broker_sys::sleep_monotonic(ms)
    }
}
