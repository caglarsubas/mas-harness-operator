//! The capacity broker's lifecycle over the frozen seam (HE-005C: DESIGN-HE005 revision 5 sections 3.2-3.6; the frozen
//! seam note DESIGN-HE005.SEAM-C revision 4, `ad6d3a75`, sections 3, 4 and 6, with its errata MON-SEAM-E1 and
//! MON-SEAM-E2; delta C3 revision 2). Every decision is here, on the agent side of the seam: the step order, the
//! parsing and the comparisons, the sort, the timing, HOLD, NP-9 and the outcome. The raw calls are broker-sys's safe
//! API, the reads gate-sys's `Dir`; nothing here names a descriptor item or a std thread.
//!
//! - `outcome`: the pinned `Step` and `Outcome` (seam section 6).
//! - `ops`: the seam's three traits, `LeafOps`, `SpawnOps` and `Clock`, exactly as seam section 3 states them.
//! - `seams`: delta C3's two stand-in seams, `GateQualifier` (section 3.3 step 2) and `Binder` (step 7), their answers
//!   and C's two stand-ins, which answer `Unavailable` through `core::hint::black_box`.
//! - `text`: the readers of the leaf's and the child's files (pure).
//! - `wait`: the bounded polls over `Clock`.
//! - `hold`: the HOLD derivation and the serve-owned standing state (section 3.4; seam section 6).
//! - `w6`: W6's sequence within `W6_BOUND_MS` (seam section 6).
//! - `np9`: NP-9's bracket (section 3.6).
//! - `run`: the startup run (delta C3) over the seams, W5, W1-W4 and the window after W4; and, on Linux, the two entries
//!   `serve` calls (the HOLD derivation at start and the startup run).
//! - `leaf`: the leaf's one private root constant, the one opening function `serve` calls, and, on Linux, the production
//!   `LeafOps`.
//! - `proc`: the child's process-directory reads, through the one start-up exception expression.
//! - `spawn` (Linux only): the production `SpawnOps`, the one file that embeds the two WORKER programs.
//! - `clock` (Linux only): the production `Clock`, std's `Instant` and broker-sys's monotonic sleep.
//!
//! Every seam is statically dispatched in non-test code (no `dyn`, C3-1). The R10-defined behaviour is listed in
//! `crates/effect-gate/MODEL_DEFINED.md` (the HE-005C section).

#[cfg(target_os = "linux")]
pub mod clock;
pub mod hold;
pub mod leaf;
pub mod np9;
pub mod ops;
pub mod outcome;
pub mod proc;
pub mod run;
pub mod seams;
#[cfg(target_os = "linux")]
pub mod spawn;
pub mod text;
pub mod w6;
pub mod wait;
