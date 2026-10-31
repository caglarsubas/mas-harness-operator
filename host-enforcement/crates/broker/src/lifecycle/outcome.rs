//! The lifecycle's pinned outcome (the frozen seam note, section 6; delta C3's G-HE5C-10). Each `io::Error` maps to the
//! step it came from, never to its errno. `Outcome` is non-zero-sized and inhabited (C3-2).

use broker_sys::Reaped;

/// The step a failure or a HOLD came from (seam section 6, exactly).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step { HoldRead, HoldPopulated, HoldFrozen, HoldStanding, W5Open, W5Measure, W5Compare, Pair, W1Read, W1NotEmpty,
                W1Freeze, W1NotFrozen, W1NotEmptyOnReread, W1FailThaw, W2Spawn, W2MaskRestore, W3Read, W3Membership,
                W3Credentials, W3Groups, W3Label, W3Descriptors, Bind, W4Thaw, Np9Freeze, Np9Events, Np9Thaw,
                W6Freeze, W6Kill, W6NotEmpty, W6Reap, W6Release }

/// How a run ended (seam section 6, exactly). D maps each to its frame: `CapacityHeld` to REFUSED CAPACITY_HELD,
/// `NotSpawned` and `Cleaned` to REFUSED UNAVAILABLE, `Held` to none (I02 closed), `Ended` through steps 12-14.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// A derived HOLD, W1's not-empty re-read or a failed failure-thaw; sets the standing HOLD.
    CapacityHeld(Step),
    /// W5, the pair or W1 failed: nothing spawned, the leaf untouched or thawed empty.
    NotSpawned(Step),
    /// Failed at W2 or later, before STARTED; W6 showed the leaf empty and released it.
    Cleaned(Step),
    /// W6 could not show the leaf empty or reap within W6_BOUND, or the release failed: the standing HOLD; serve keeps
    /// the child; no thaw.
    Held(Step),
    /// The worker reaped and the leaf shown empty and released.
    Ended(Reaped),
    /// C's stand-ins (delta C3, G-HE5C-10), until D replaces them.
    Unavailable,
}
